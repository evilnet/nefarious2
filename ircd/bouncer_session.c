/*
 * IRC - Internet Relay Chat, ircd/bouncer_session.c
 * Copyright (C) 2025 Nefarious Development
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
/** @file
 * @brief Built-in bouncer session registry implementation.
 *
 * Sessions are distributed across all servers via P10 BS tokens,
 * following the same BURST model as nicks and channels.
 */
#include "config.h"

#include "bouncer_session.h"
#include "IPcheck.h"
#include "capab.h"
#include "channel.h"
#include "class.h"
#include "client.h"
#include "history.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_osdep.h"
#include "ircd_features.h"
#include "ircd_geoip.h"
#include "ircd_log.h"
#include "listener.h"
#include "list.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "random.h"
#include "ircd_string.h"
#include "match.h"
#include "metadata.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "send.h"
#include "hash.h"
#include "querycmds.h"
#include "userload.h"
#include "replay.h"
#include "s_auth.h"
#include "s_bsd.h"
#include "parse.h"
#include "s_conf.h"
#include "s_debug.h"
#include "handlers.h"
#include "s_misc.h"
#include "s_user.h"
#include "msgq.h"
#include "struct.h"
#include "motd.h"
#include "version.h"

#include <assert.h>
#include <errno.h>
#include <sys/uio.h>
#include <mdbx.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/uio.h>
#include <unistd.h>

#ifdef USE_SSL
#include "ssl.h"
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#endif

/* ---------------------------------------------------------------- */
/* Hash tables                                                       */
/* ---------------------------------------------------------------- */

/** Token hash table - for O(1) RESUME lookups. */
static struct BouncerSession *tokenHash[BOUNCE_TOKEN_HASHSIZE];

/** Account hash table - for per-account enumeration. */
static struct AccountSessions *accountHash[BOUNCE_ACCOUNT_HASHSIZE];

/** Per-server sequence counter for session IDs. */
static unsigned int sessionSeq = 0;

/* Forward declarations for MDBX persistence (defined after bounce_snapshot_channels) */
static int bounce_db_put(struct BouncerSession *session);
static int bounce_db_del(const char *sessid);

/* ---------------------------------------------------------------- */
/* Connection stats accumulation helpers                              */
/* ---------------------------------------------------------------- */

/** Aggregate ghost's Connection counters into session totals and zero them.
 * Called when the primary connection is truly gone (hold, dying primary). */
static void bounce_accumulate_and_reset_primary(struct BouncerSession *session,
                                                 struct Client *ghost)
{
  struct Connection *con = cli_connect(ghost);
  session->hs_agg_sendB    += con_sendB(con);
  session->hs_agg_receiveB += con_receiveB(con);
  session->hs_agg_sendM    += con_sendM(con);
  session->hs_agg_receiveM += con_receiveM(con);
  con_sendB(con) = con_receiveB(con) = 0;
  con_sendM(con) = con_receiveM(con) = 0;
}

/* ---------------------------------------------------------------- */
/* Connection history helpers                                        */
/* ---------------------------------------------------------------- */

/** Record a connect event in the session's connection history.
 * Deduplicates by IP — if the IP already exists, updates its last_connect
 * time and increments the count. Otherwise adds a new entry (evicting
 * the oldest if the history is full).
 * @param[in] session Bouncer session.
 * @param[in] ip Remote IP string.
 * @param[in] host Resolved hostname (may be same as ip).
 */
static void bounce_history_connect(struct BouncerSession *session,
                                    const char *ip, const char *host)
{
  struct BounceConnHistory *h;
  int i;

  /* Look for existing entry with same IP */
  for (i = 0; i < session->hs_histcount; i++) {
    h = &session->hs_history[i];
    if (0 == strcmp(h->bch_ip, ip)) {
      h->bch_last_connect = (int64_t)CurrentTime;
      h->bch_last_disconnect = 0;
      h->bch_count++;
      /* Update hostname in case it changed */
      ircd_strncpy(h->bch_host, host, HOSTLEN + 1);
      /* Move to front (most recent first) */
      if (i > 0) {
        struct BounceConnHistory tmp = *h;
        memmove(&session->hs_history[1], &session->hs_history[0],
                i * sizeof(struct BounceConnHistory));
        session->hs_history[0] = tmp;
      }
      return;
    }
  }

  /* New IP — make room at front */
  if (session->hs_histcount < BOUNCER_MAX_CONN_HISTORY)
    session->hs_histcount++;
  /* Shift existing entries down (drop oldest if full) */
  if (session->hs_histcount > 1)
    memmove(&session->hs_history[1], &session->hs_history[0],
            (session->hs_histcount - 1) * sizeof(struct BounceConnHistory));

  /* Fill in new entry at front */
  h = &session->hs_history[0];
  memset(h, 0, sizeof(*h));
  ircd_strncpy(h->bch_ip, ip, SOCKIPLEN + 1);
  ircd_strncpy(h->bch_host, host, HOSTLEN + 1);
  h->bch_last_connect = (int64_t)CurrentTime;
  h->bch_last_disconnect = 0;
  h->bch_count = 1;
}

/** Record a disconnect event for the given IP in connection history.
 * Sets last_disconnect timestamp on the matching entry.
 * @param[in] session Bouncer session.
 * @param[in] ip Remote IP string.
 */
static void bounce_history_disconnect(struct BouncerSession *session,
                                       const char *ip)
{
  int i;
  for (i = 0; i < session->hs_histcount; i++) {
    if (0 == strcmp(session->hs_history[i].bch_ip, ip)) {
      session->hs_history[i].bch_last_disconnect = (int64_t)CurrentTime;
      return;
    }
  }
}

/* ---------------------------------------------------------------- */
/* Periodic dirty session persistence                                 */
/* ---------------------------------------------------------------- */

static struct Timer dirty_persist_timer;
static int dirty_persist_timer_active;

/* Forward declarations for persistence functions */
static int bounce_db_put(struct BouncerSession *session);
static int is_local_session(struct BouncerSession *session);

/** Timer callback: persist all dirty ACTIVE sessions.
 * Iterates all sessions, snapshots and persists those marked dirty,
 * then clears the dirty flag and reschedules the timer.
 *
 * IMPORTANT: Use timer_chg() to reschedule, NOT timer_init() + timer_add().
 * timer_init() clears GEN_MARKED which corrupts the event system state.
 * timer_chg() properly handles reschedule during callback by setting
 * GEN_READD and letting timer_run() re-enqueue after callback returns.
 */
static void bounce_dirty_persist_cb(struct Event *ev)
{
  int i;
  struct BouncerSession *s;
  int count = 0;
  int interval;

  /* ET_DESTROY is sent when the timer is being shut down (e.g., during
   * server shutdown or feature disable). Just mark inactive and return. */
  if (ev_type(ev) == ET_DESTROY) {
    dirty_persist_timer_active = 0;
    return;
  }

  if (!feature_bool(FEAT_BOUNCER_PERSIST) || !metadata_lmdb_is_available()) {
    dirty_persist_timer_active = 0;
    return;
  }

  for (i = 0; i < BOUNCE_TOKEN_HASHSIZE; i++) {
    for (s = tokenHash[i]; s; s = s->hs_tnext) {
      if (!is_local_session(s))
        continue;

      /* Only persist ACTIVE sessions that are dirty */
      if (s->hs_state != BOUNCE_ACTIVE || !s->hs_dirty || !s->hs_client)
        continue;

      /* Snapshot current channel state from live client */
      bounce_snapshot_channels(s, s->hs_client);

      /* Persist to MDBX */
      if (bounce_db_put(s) == 0) {
        s->hs_dirty = 0;
        count++;
      }
      /* On failure, leave dirty flag set to retry next interval */
    }
  }

  if (count > 0) {
    Debug((DEBUG_INFO, "bouncer_persist: periodic — persisted %d dirty sessions", count));
  }

  /* Reschedule timer using timer_chg() which properly handles
   * reschedule during callback (sets GEN_READD flag). */
  interval = feature_int(FEAT_BOUNCER_PERSIST_INTERVAL);
  if (interval > 0) {
    timer_chg(&dirty_persist_timer, TT_RELATIVE, interval);
  } else {
    dirty_persist_timer_active = 0;
  }
}

/** Start the periodic dirty persist timer if not already running. */
static void bounce_start_dirty_persist_timer(void)
{
  int interval;

  if (dirty_persist_timer_active)
    return;

  if (!feature_bool(FEAT_BOUNCER_PERSIST))
    return;

  interval = feature_int(FEAT_BOUNCER_PERSIST_INTERVAL);
  if (interval <= 0)
    return;

  timer_add(timer_init(&dirty_persist_timer), bounce_dirty_persist_cb,
            NULL, TT_RELATIVE, interval);
  dirty_persist_timer_active = 1;
}

/** Mark a bouncer session as dirty (needs periodic persist).
 * Called from channel.c on JOIN/PART/KICK and MODE changes.
 * @param[in] cptr Client whose session to mark dirty.
 */
void bounce_mark_dirty(struct Client *cptr)
{
  struct BouncerSession *session;

  if (!cptr)
    return;

  session = bounce_get_session(cptr);
  if (!session || session->hs_state != BOUNCE_ACTIVE)
    return;

  session->hs_dirty = 1;

  /* Ensure the persist timer is running */
  bounce_start_dirty_persist_timer();
}

/* ---------------------------------------------------------------- */
/* Hash functions                                                    */
/* ---------------------------------------------------------------- */

/** Compute hash for a token string. */
static unsigned int token_hash(const char *token)
{
  unsigned int h = 0;
  while (*token)
    h = h * 31 + (unsigned char)*token++;
  return h % BOUNCE_TOKEN_HASHSIZE;
}

/** Compute hash for an account name (case-insensitive). */
static unsigned int account_hash(const char *account)
{
  unsigned int h = 0;
  while (*account)
    h = h * 31 + (unsigned char)ToLower(*account++);
  return h % BOUNCE_ACCOUNT_HASHSIZE;
}

/* ---------------------------------------------------------------- */
/* Token generation                                                  */
/* ---------------------------------------------------------------- */

/** Base64 alphabet for token encoding. */
static const char b64chars[] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/** Generate a cryptographically random session token.
 * Format: <2-char server numeric><62 random base64 chars>
 * @param[out] buf Buffer of at least BOUNCER_TOKEN_LEN+1 bytes.
 */
static void generate_token(char *buf)
{
  const char *yxx = cli_yxx(&me);
  unsigned char raw[48]; /* 48 bytes = 64 base64 chars, we use 62 */
  int i;

  /* Prefix with server numeric (2 chars) */
  buf[0] = yxx[0];
  buf[1] = yxx[1];

#ifdef USE_SSL
  if (RAND_bytes(raw, sizeof(raw)) != 1) {
    /* Fallback: use ircrandom if RAND_bytes fails */
    for (i = 0; i < (int)sizeof(raw); i++)
      raw[i] = (unsigned char)(ircrandom() & 0xFF);
  }
#else
  for (i = 0; i < (int)sizeof(raw); i++)
    raw[i] = (unsigned char)(ircrandom() & 0xFF);
#endif

  /* Encode 62 chars of base64 */
  for (i = 0; i < 62; i++)
    buf[2 + i] = b64chars[raw[i % sizeof(raw)] % 64];

  buf[BOUNCER_TOKEN_LEN] = '\0';
}

/** Generate a session ID from server numeric + sequence.
 * Format: "XX-NNNNN" where XX is 2-char server numeric.
 * @param[out] buf Buffer of at least BOUNCER_SESSID_LEN bytes.
 */
static void generate_sessid(char *buf)
{
  const char *yxx = cli_yxx(&me);
  ircd_snprintf(0, buf, BOUNCER_SESSID_LEN, "%c%c-%u",
                yxx[0], yxx[1], ++sessionSeq);
}

/* ---------------------------------------------------------------- */
/* Account sessions management                                       */
/* ---------------------------------------------------------------- */

/** Find or create an AccountSessions entry. */
static struct AccountSessions *account_sessions_get(const char *account,
                                                    int create)
{
  unsigned int h = account_hash(account);
  struct AccountSessions *as;

  for (as = accountHash[h]; as; as = as->as_hnext) {
    if (0 == ircd_strcmp(as->as_account, account))
      return as;
  }

  if (!create)
    return NULL;

  as = (struct AccountSessions *)MyCalloc(1, sizeof(*as));
  ircd_strncpy(as->as_account, account, ACCOUNTLEN + 1);
  as->as_sessions = NULL;
  as->as_count = 0;
  as->as_hnext = accountHash[h];
  accountHash[h] = as;
  return as;
}

/** Remove an AccountSessions entry if empty. */
static void account_sessions_cleanup(struct AccountSessions *as)
{
  unsigned int h;
  struct AccountSessions **pp;

  if (!as || as->as_count > 0)
    return;

  h = account_hash(as->as_account);
  for (pp = &accountHash[h]; *pp; pp = &(*pp)->as_hnext) {
    if (*pp == as) {
      *pp = as->as_hnext;
      MyFree(as);
      return;
    }
  }
}

/** Add a session to the account list. */
static void account_add_session(struct AccountSessions *as,
                                struct BouncerSession *session)
{
  session->hs_anext = as->as_sessions;
  session->hs_aprev_p = &as->as_sessions;
  if (as->as_sessions)
    as->as_sessions->hs_aprev_p = &session->hs_anext;
  as->as_sessions = session;
  as->as_count++;
}

/** Remove a session from its account list. */
static void account_remove_session(struct BouncerSession *session)
{
  struct AccountSessions *as;

  /* Unlink from doubly-linked account chain */
  if (session->hs_anext)
    session->hs_anext->hs_aprev_p = session->hs_aprev_p;
  *(session->hs_aprev_p) = session->hs_anext;

  /* Decrement count and clean up if empty */
  as = bounce_find_by_account(session->hs_account);
  if (as) {
    as->as_count--;
    account_sessions_cleanup(as);
  }
}

/* ---------------------------------------------------------------- */
/* Token hash management                                             */
/* ---------------------------------------------------------------- */

/** Add a session to the token hash. */
static void token_hash_add(struct BouncerSession *session)
{
  unsigned int h = token_hash(session->hs_token);
  session->hs_tnext = tokenHash[h];
  tokenHash[h] = session;
}

/** Remove a session from the token hash. */
static void token_hash_remove(struct BouncerSession *session)
{
  unsigned int h = token_hash(session->hs_token);
  struct BouncerSession **pp;

  for (pp = &tokenHash[h]; *pp; pp = &(*pp)->hs_tnext) {
    if (*pp == session) {
      *pp = session->hs_tnext;
      session->hs_tnext = NULL;
      return;
    }
  }
}

/* Forward declaration */
static struct BouncerSession *bounce_find_by_token_sessid(const char *account,
                                                          const char *sessid);

/* ---------------------------------------------------------------- */
/* Hold timer callback                                               */
/* ---------------------------------------------------------------- */

/** Timer callback: session hold has expired. */
static void bounce_hold_expire(struct Event *ev)
{
  struct BouncerSession *session;
  struct Client *ghost;

  assert(0 != ev_timer(ev));
  assert(0 != t_data(ev_timer(ev)));

  /* ET_DESTROY is sent by timer_run() after ET_EXPIRE, or by timer_del()
   * when the timer is cancelled (e.g., during bounce_attach).
   *
   * If the session was marked BOUNCE_DESTROYING by the ET_EXPIRE handler,
   * this is where we actually free it.  The timer struct is embedded in the
   * session, so we CANNOT free the session during ET_EXPIRE — timer_run()
   * still accesses the timer struct after the ET_EXPIRE callback returns.
   *
   * For timer_del() cancellations (bounce_attach), the session is still
   * BOUNCE_HOLDING, so we just return. */
  if (ev_type(ev) == ET_DESTROY) {
    session = (struct BouncerSession *)t_data(ev_timer(ev));
    if (session && session->hs_state == BOUNCE_DESTROYING) {
      /* Timer is already dead — clean up without calling timer_del. */
      token_hash_remove(session);
      account_remove_session(session);
      bounce_db_del(session->hs_sessid);
      Debug((DEBUG_INFO, "Bouncer: destroyed session %s for %s (deferred)",
             session->hs_sessid, session->hs_account));
      MyFree(session);
    }
    return;
  }

  session = (struct BouncerSession *)t_data(ev_timer(ev));

  if (session->hs_state != BOUNCE_HOLDING)
    return; /* Already resumed or destroyed */

  Debug((DEBUG_INFO, "Bouncer: hold expired for %s session %s",
         session->hs_account, session->hs_sessid));

  /* Get the ghost client before any session changes.
   * Note: hs_client stores the ghost during HOLDING state.
   */
  ghost = session->hs_client;

  if (session->hs_alias_count > 0) {
    /* Aliases exist — promote instead of destroy.
     * Promote removes ghost from channels (silent), sends BX P + BS T.
     * Session continues under the promoted alias's server. */
    Debug((DEBUG_INFO, "Bouncer: hold expired with %d aliases, promoting for %s",
           session->hs_alias_count, session->hs_account));
    bounce_promote_alias(session);
    /* Session now points to promoted alias as hs_client.
     * Exit ghost with FLAG_KILLED — BX P already told the network. */
    if (ghost && IsBouncerHold(ghost)) {
      ClearBouncerHold(ghost);
      SetFlag(ghost, FLAG_KILLED);
      exit_client(ghost, ghost, &me, "Session transferred");
    }
  } else {
    /* No aliases — session truly expired.
     * Mark DESTROYING and null hs_client so exit_client's cleanup path
     * in exit_one_client (s_misc.c) won't try to destroy it again.
     * The actual free is deferred to the ET_DESTROY handler above. */
    bounce_broadcast(session, 'X', NULL);
    session->hs_state = BOUNCE_DESTROYING;
    session->hs_client = NULL;
    if (ghost && IsBouncerHold(ghost)) {
      ClearBouncerHold(ghost);
      exit_client(ghost, ghost, &me, "Session expired");
    }
  }
}

/* ---------------------------------------------------------------- */
/* Public API                                                        */
/* ---------------------------------------------------------------- */

/** Initialize the bouncer session subsystem. */
void bounce_init(void)
{
  memset(tokenHash, 0, sizeof(tokenHash));
  memset(accountHash, 0, sizeof(accountHash));
  sessionSeq = 0;
}

/** Check if bouncer feature is enabled. */
int bounce_enabled(void)
{
  return feature_bool(FEAT_BOUNCER_ENABLE);
}

/** Check if bouncer is enabled for a specific client.
 * Returns 1 if the client's connection class has CRFLAG_BOUNCER set,
 * or if the global bouncer feature is enabled.
 */
int bounce_enabled_for(struct Client *cptr)
{
  if (cptr) {
    struct ConnectionClass *cls = get_client_class_conf(cptr);
    if (cls && FlagHas(&cls->restrictflags, CRFLAG_BOUNCER))
      return 1;
  }
  return bounce_enabled();
}

/** Get number of sessions for an account. */
int bounce_count(const char *account)
{
  struct AccountSessions *as = bounce_find_by_account(account);
  return as ? as->as_count : 0;
}

/** Check if an account has any bouncer sessions. */
int bounce_has_sessions(const char *account)
{
  struct AccountSessions *as = bounce_find_by_account(account);
  return (as && as->as_count > 0) ? 1 : 0;
}

/** Find the best HOLDING session for an account.
 * Selection priority:
 *   1. HOLDING sessions only
 *   2. Same-server preference (local ghost avoids cross-server transfer)
 *   3. Most recent disconnect_time as tiebreaker
 */
struct BouncerSession *bounce_find_best_held(const char *account)
{
  struct AccountSessions *as = bounce_find_by_account(account);
  struct BouncerSession *sess;
  struct BouncerSession *best = NULL;

  if (!as)
    return NULL;

  for (sess = as->as_sessions; sess; sess = sess->hs_anext) {
    if (sess->hs_state != BOUNCE_HOLDING)
      continue;

    if (!best) {
      best = sess;
      continue;
    }

    /* Prefer local ghost (same server) to avoid cross-server transfer */
    if (sess->hs_client && MyUser(sess->hs_client) &&
        !(best->hs_client && MyUser(best->hs_client))) {
      best = sess;
      continue;
    }

    /* Among same locality, prefer most recently disconnected */
    if (sess->hs_disconnect_time > best->hs_disconnect_time)
      best = sess;
  }

  return best;
}

/** Check if a bouncer session has any non-TLS connection.
 * Used for session-wide TLS enforcement: one plaintext connection
 * means the entire session is treated as non-TLS for +Z purposes.
 * @param[in] cptr Client to check (must be the primary).
 * @return 1 if any connection (primary or alias) lacks TLS, 0 otherwise.
 */
int bounce_session_has_plaintext(struct Client *cptr)
{
#ifdef USE_SSL
  struct BouncerSession *session;

  session = bounce_get_session(cptr);
  if (!session || session->hs_state != BOUNCE_ACTIVE)
    return 0;

  /* Check primary */
  if (session->hs_client && !cli_socket(session->hs_client).ssl)
    return 1;

  /* Check aliases — remote clients, so check FLAG_SSL (set from their
   * actual socket on the remote server) rather than a local socket. */
  if (session->hs_alias_count > 0) {
    int i;
    for (i = 0; i < session->hs_alias_count; i++) {
      struct Client *alias = findNUser(session->hs_aliases[i].ba_numeric);
      if (alias && IsBouncerAlias(alias) && !IsSSL(alias))
        return 1;
    }
  }

  return 0;
#else
  return 0;
#endif
}

/** SASL-triggered automatic resume.
 * Called from register_user() after SASL auth sets the account
 * but before the client is introduced to the network.
 *
 * Three outcomes:
 *   1. Held session found → resume it (return 1)
 *   2. Active session found → attach as alias (return 2)
 *   3. No session → auto-create one (return 0)
 *
 * @param[in] cptr Newly authenticated client.
 * @param[out] out_session Set to the session if resumed or created.
 * @return 1 if resumed a held session, 2 if attached as alias, 0 otherwise.
 */
int bounce_auto_resume(struct Client *cptr, struct BouncerSession **out_session,
                       time_t *out_since_time)
{
  struct BouncerSession *session;
  const char *account;
  char hold_val[64];
  int max_sessions;
  int class_bouncer = 0;
  struct ConnectionClass *cls;

  if (out_since_time)
    *out_since_time = 0;

  *out_session = NULL;

  /* Check if client's connection class forces bouncer behavior */
  cls = get_client_class_conf(cptr);
  if (cls && FlagHas(&cls->restrictflags, CRFLAG_BOUNCER))
    class_bouncer = 1;

  if (!class_bouncer && (!bounce_enabled() || !feature_bool(FEAT_BOUNCER_AUTO_RESUME)))
    return 0;

  if (!IsAccount(cptr))
    return 0;

  account = cli_account(cptr);

  /* Check per-account hold preference via metadata.
   * Explicit opt-out (bouncer/hold=0) is always respected, even on
   * bouncer-class ports — no session will be created or resumed. */
  if (metadata_account_get(account, "bouncer/hold", hold_val) == 0) {
    if (hold_val[0] == '0')
      return 0; /* User opted out */
  } else if (!class_bouncer && !feature_bool(FEAT_BOUNCER_DEFAULT_HOLD)) {
    return 0; /* No preference set and network default is no-hold */
  }

  /* Try to find a held session to resume */
  session = bounce_find_best_held(account);
  if (session) {
    /* Check if session is on a remote server */
    if (0 != strcmp(session->hs_origin, cli_yxx(&me))) {
      struct Client *managing_server = FindNServer(session->hs_origin);
      /* Resolve ghost from numeric if hs_client is NULL (e.g., BS D
       * arrived before ghost numeric was resolvable). */
      if (!session->hs_client && session->hs_ghost_numeric[0]) {
        char full_numeric[6];
        ircd_snprintf(0, full_numeric, sizeof(full_numeric), "%s%s",
                      session->hs_origin, session->hs_ghost_numeric);
        session->hs_client = findNUser(full_numeric);
      }
      if (managing_server && session->hs_client
          && session->hs_alias_count < BOUNCER_MAX_ALIASES) {
        *out_session = session;
        log_write(LS_USER, L_INFO, 0,
                  "Bouncer: HELD alias_remote path for %s session %s (primary on %s)",
                  account, session->hs_sessid, cli_name(managing_server));
        return BOUNCE_RESUME_ALIAS_REMOTE;
      }
      log_write(LS_USER, L_INFO, 0,
                "Bouncer: HELD remote alias unavailable for %s session %s "
                "(managing_server=%p hs_client=%p alias_count=%u)",
                account, session->hs_sessid, (void*)managing_server,
                (void*)session->hs_client, session->hs_alias_count);
      /* Alias not possible — fall through to try other sessions */
    } else {
    /* Local session — proceed with normal resume */
    char original_nick[NICKLEN + 1];

    /* Save original nick in case we need to swap */
    ircd_strncpy(original_nick, cli_name(cptr), NICKLEN + 1);

    /* If the ghost has a different nick, swap to it before network introduction */
    if (session->hs_client &&
        ircd_strcmp(cli_name(cptr), cli_name(session->hs_client)) != 0) {
      /* Adopt ghost's nick — must update hash table BEFORE changing cli_name,
       * since hChangeClient uses the current cli_name to remove from the
       * old hash bucket.  Without this, the client stays in the hash table
       * under its original nick while cli_name holds the ghost's nick,
       * causing hRemClient to fail when the ghost is later exit'd. */
      hChangeClient(cptr, cli_name(session->hs_client));
      ircd_strncpy(cli_name(cptr), cli_name(session->hs_client), NICKLEN + 1);
    }

    /* Adopt ghost's nick timestamp so we win nick collisions.
     *
     * Note: This code path is only used for cross-server resume (ghost on
     * remote server) or when socket transplant fails. For local ghosts,
     * register_user() uses bounce_revive() for seamless socket transplant.
     *
     * With same user@host, older timestamp wins — without this, the ghost
     * (with original session timestamp) beats the new client (with fresh
     * connection timestamp), causing the new client to be killed and
     * channel memberships to be lost.
     *
     * Use ghost's timestamp if available, otherwise use session creation time
     * (for cross-server resume where ghost is on a remote server). */
    if (session->hs_client) {
      cli_lastnick(cptr) = cli_lastnick(session->hs_client);
    } else {
      cli_lastnick(cptr) = session->hs_created;
    }

    /* Compute the replay "since" time from the ghost's idle time.
     * Messages arriving after the user's last activity may not have been
     * read, even if they were delivered to the connected client.
     * Fall back to disconnect time if idle time is unavailable. */
    if (out_since_time) {
      time_t idle = 0;
      if (session->hs_client && cli_user(session->hs_client))
        idle = cli_user(session->hs_client)->last;
      *out_since_time = (idle > 0) ? idle : session->hs_disconnect_time;
    }

    /* Attach to the session — transfers channels, exits ghost */
    if (bounce_attach(session, cptr) == 0) {
      /* Notify client of nick change if it happened */
      if (ircd_strcmp(original_nick, cli_name(cptr)) != 0) {
        sendcmdto_one(cptr, CMD_NICK, cptr, "%s", cli_name(cptr));
      }

      bounce_broadcast(session, 'A', cli_yxx(cptr));
      *out_session = session;
      return 1;
    }
    } /* end else (local session) */
  }

  /* Check for ACTIVE session — either orphaned (reclaim as primary) or
   * with an existing primary (attach as alias connection).
   * An orphaned session is ACTIVE but has no primary (hs_client == NULL).
   * This can happen after server restart or when primary exits before
   * aliases and the session persists.  These sessions count toward the
   * per-account limit, so we must reclaim them rather than creating new ones. */
  session = bounce_find_any_session(account);
  if (session && session->hs_state == BOUNCE_ACTIVE) {
    log_write(LS_USER, L_INFO, 0,
              "Bouncer: ACTIVE session %s found for %s "
              "(origin=%s me=%s hs_client=%p alias_count=%u)",
              session->hs_sessid, account, session->hs_origin,
              cli_yxx(&me), (void*)session->hs_client,
              session->hs_alias_count);
    /* Check if session is on a remote server */
    if (0 != strcmp(session->hs_origin, cli_yxx(&me))) {
      struct Client *managing_server = FindNServer(session->hs_origin);
      if (managing_server && session->hs_client
          && session->hs_alias_count < BOUNCER_MAX_ALIASES) {
        *out_session = session;
        log_write(LS_USER, L_INFO, 0,
                  "Bouncer: ACTIVE alias_remote path for %s session %s (primary on %s)",
                  account, session->hs_sessid, cli_name(managing_server));
        return BOUNCE_RESUME_ALIAS_REMOTE;
      }
      log_write(LS_USER, L_INFO, 0,
                "Bouncer: ACTIVE remote alias unavailable for %s "
                "(managing_server=%p hs_client=%p alias_count=%u)",
                account, (void*)managing_server,
                (void*)session->hs_client, session->hs_alias_count);
    }
    if (!session->hs_client) {
      /* Orphaned ACTIVE session — reclaim as primary */
      log_write(LS_USER, L_INFO, 0,
                "Bouncer: reclaiming orphaned ACTIVE session %s for %s",
                session->hs_sessid, cli_name(cptr));
      if (bounce_attach(session, cptr) == 0) {
        bounce_broadcast(session, 'A', cli_yxx(cptr));
        *out_session = session;
        return 1;
      }
      log_write(LS_USER, L_INFO, 0,
                "Bouncer: orphan reclaim (bounce_attach) FAILED for %s session %s",
                account, session->hs_sessid);
    } else {
      /* ACTIVE session with primary — attach as alias connection */
      if (session->hs_alias_count < BOUNCER_MAX_ALIASES) {
#ifdef USE_SSL
        /* Respect BOUNCER_REQUIRE_TLS for aliases too */
        if (feature_bool(FEAT_BOUNCER_REQUIRE_TLS) && !cli_socket(cptr).ssl) {
          log_write(LS_USER, L_INFO, 0,
                    "Bouncer: skipping alias for plaintext client of %s (REQUIRE_TLS)",
                    account);
        } else
#endif
        {
          log_write(LS_USER, L_INFO, 0,
                    "Bouncer: ACTIVE alias_local path for %s session %s",
                    account, session->hs_sessid);
          *out_session = session;
          return BOUNCE_RESUME_ALIAS_LOCAL;
        }
      }
      /* ACTIVE session with live primary but no alias slot available
       * (max reached, or TLS policy).  Letting this connection proceed
       * to register_user's NICK N broadcast would collide with the
       * primary (same user@host) on any upstream hub that already has
       * the primary.  Reject instead. */
      log_write(LS_USER, L_INFO, 0,
                "Bouncer: REJECT_DUPLICATE for %s session %s "
                "(alias_count=%u)",
                account, session->hs_sessid,
                session->hs_alias_count);
      *out_session = session;
      return BOUNCE_RESUME_REJECT_DUPLICATE;
    }
  }

  /* No held session — auto-create only if account has NO sessions at all.
   * If sessions already exist (all ACTIVE), this is just a second connection
   * to the same account — don't create a duplicate session. */
  if (bounce_count(account) == 0) {
    max_sessions = feature_int(FEAT_BOUNCER_MAX_SESSIONS);
    if (max_sessions > 0) {
      if (bounce_create(cptr, &session) == 0) {
        bounce_broadcast(session, 'C', NULL);
        /* BS A is sent later from register_user() after SetLocalNumNick()
         * allocates the primary's P10 numeric.  At this point cli_yxx(cptr)
         * is still empty because the numeric hasn't been assigned yet. */
        *out_session = session;
      }
    }
  }

  return 0;
}

/** Create a new session for an authenticated client. */
int bounce_create(struct Client *cptr, struct BouncerSession **out)
{
  struct BouncerSession *session;
  struct AccountSessions *as;
  int max_sessions;

  assert(0 != cptr);
  assert(0 != out);
  *out = NULL;

  if (!bounce_enabled_for(cptr))
    return -1;

  if (!IsAccount(cptr))
    return -1;

  /* Enforce per-account limit */
  max_sessions = feature_int(FEAT_BOUNCER_MAX_SESSIONS);
  if (bounce_count(cli_account(cptr)) >= max_sessions)
    return -1;

  /* Allocate and initialize */
  session = (struct BouncerSession *)MyCalloc(1, sizeof(*session));
  ircd_strncpy(session->hs_account, cli_account(cptr), ACCOUNTLEN + 1);
  generate_sessid(session->hs_sessid);
  generate_token(session->hs_token);
  session->hs_name[0] = '\0';
  session->hs_state = BOUNCE_ACTIVE;
  session->hs_client = cptr;
  ircd_strncpy(session->hs_origin, cli_yxx(&me), sizeof(session->hs_origin) - 1);
  session->hs_hold_override = -1; /* Use default */
  session->hs_effective_away = 0;
  session->hs_effective_away_msg[0] = '\0';
  session->hs_chancount = 0;
  session->hs_created = CurrentTime;
  session->hs_last_active = CurrentTime;
  session->hs_disconnect_time = 0;
  session->hs_attach_count = 0;
  session->hs_connect_count = 1; /* Initial connection counts */
  session->hs_total_active = 0;

  /* Add to hash tables */
  token_hash_add(session);
  as = account_sessions_get(session->hs_account, 1);
  account_add_session(as, session);

  /* Record initial connect event in connection history */
  bounce_history_connect(session, cli_sock_ip(cptr), cli_sockhost(cptr));

  /* Persist to MDBX (session created but no channels yet) */
  bounce_db_put(session);

  *out = session;
  return 0;
}

/** Look up a session by token. */
struct BouncerSession *bounce_find_by_token(const char *token)
{
  unsigned int h;
  struct BouncerSession *s;

  if (!token || !*token)
    return NULL;

  h = token_hash(token);
  for (s = tokenHash[h]; s; s = s->hs_tnext) {
    if (0 == strcmp(s->hs_token, token))
      return s;
  }
  return NULL;
}

/** Look up sessions for an account. */
struct AccountSessions *bounce_find_by_account(const char *account)
{
  unsigned int h;
  struct AccountSessions *as;

  if (!account || !*account)
    return NULL;

  h = account_hash(account);
  for (as = accountHash[h]; as; as = as->as_hnext) {
    if (0 == ircd_strcmp(as->as_account, account))
      return as;
  }
  return NULL;
}

/** Walk every session known to this server and invoke a callback.
 *
 * Iteration order: account hash bucket, then per-account list.  The
 * callback must not free, destroy, or rehash the session — modifying
 * the iteration target invalidates the walk.
 *
 * @param[in] cb   Callback invoked once per session.
 * @param[in] data Opaque pointer passed through to callback.
 */
void bounce_walk_sessions(void (*cb)(struct BouncerSession *, void *),
                          void *data)
{
  int i;
  struct AccountSessions *as;
  struct BouncerSession *s;

  if (!cb)
    return;

  for (i = 0; i < BOUNCE_ACCOUNT_HASHSIZE; i++) {
    for (as = accountHash[i]; as; as = as->as_hnext) {
      for (s = as->as_sessions; s; s = s->hs_anext) {
        cb(s, data);
      }
    }
  }
}

/** Attach a client to an existing session (resume).
 *
 * For same-server resume: if a ghost exists locally, transfer its channel
 * memberships to the new client and destroy the ghost.
 *
 * For cross-server resume: the ghost is on another server, so initiate
 * a P10 BT (Bouncer Transfer) to migrate channels across servers.
 */
int bounce_attach(struct BouncerSession *session, struct Client *cptr)
{
  struct Client *ghost;
  struct Membership *member;
  struct Membership *next_member;

  assert(0 != session);
  assert(0 != cptr);

  if (session->hs_state == BOUNCE_ACTIVE && session->hs_client)
    return -1; /* Already attached */

  /* Cancel hold timer if running */
  if (t_active(&session->hs_hold_timer))
    timer_del(&session->hs_hold_timer);

  ghost = session->hs_client;

#ifdef USE_SSL
  /* Gate: Refuse attach if ghost is in +Z channels and new client is plaintext.
   * Transferring +Z channel membership to a non-TLS client would violate +Z. */
  if (ghost && cli_user(ghost) && !IsSSL(cptr)) {
    for (member = cli_user(ghost)->channel; member; member = member->next_channel) {
      if (member->channel->mode.exmode & EXMODE_SSLONLY) {
        Debug((DEBUG_INFO,
               "Bouncer: refusing attach for %s - plaintext client, ghost in +Z channel %s",
               cli_name(cptr), member->channel->chname));
        return -1;  /* Caller handles fallback to normal registration */
      }
    }
  }
#endif

  /* Same-server resume: ghost exists locally, transfer channel memberships */
  if (ghost && IsBouncerHold(ghost) && MyUser(ghost)) {
    /* Transfer each channel membership from ghost to new client */
    for (member = cli_user(ghost)->channel; member; member = next_member) {
      next_member = member->next_channel;

      /* Add new client to channel with ghost's modes (op, voice, etc.)
       * but without the HOLDING flag */
      unsigned int modes = member->status & ~CHFL_HOLDING;
      add_user_to_channel(member->channel, cptr, modes, OpLevel(member));

      /* Remove ghost from channel (silently - no PART message) */
      remove_user_from_channel(ghost, member->channel);
    }

    /* Clean up the ghost client - it no longer has channels.
     * Let QUIT propagate to remote servers.  cptr is about to be
     * introduced by register_user() with a new numeric; if we suppress
     * the ghost's QUIT here, remote servers retain the ghost under its
     * old numeric and the incoming NICK N for cptr collides with it on
     * same nick/user@host. */
    ClearBouncerHold(ghost);
    exit_client(ghost, ghost, &me, "Session resumed");
  }
  /* Cross-server resume: ghost is on another server, initiate transfer */
  else if (session->hs_state == BOUNCE_HOLDING &&
           session->hs_ghost_numeric[0] != '\0') {
    /* Broadcast BT to have all servers transfer the ghost's channels */
    bounce_initiate_transfer(session, cptr, session->hs_ghost_numeric);
    /* bounce_initiate_transfer updates session state, so return early */
    return 0;
  }

  session->hs_state = BOUNCE_ACTIVE;
  session->hs_client = cptr;
  session->hs_attach_count++;
  session->hs_connect_count++;
  session->hs_last_active = CurrentTime;
  session->hs_disconnect_time = 0;

  /* Record connect event in connection history */
  bounce_history_connect(session, cli_sock_ip(cptr), cli_sockhost(cptr));

  /* Session is live again — remove persisted state (re-persisted at next hold or shutdown) */
  bounce_db_del(session->hs_sessid);

  /* Recompute session union caps for the new primary + existing aliases */
  bounce_recompute_session_caps(cptr);

  return 0;
}

/** Compute adaptive hold time for a session based on usage history.
 * Sessions with more connections (resumes + alias attaches) earn longer
 * hold times.  This rewards active use — a mobile device connecting as an
 * alias counts the same as a full resume from HOLDING.
 */
static time_t bounce_compute_hold_time(struct BouncerSession *session)
{
  time_t base = feature_int(FEAT_BOUNCER_SESSION_HOLD);  /* default 4h */
  time_t max  = feature_int(FEAT_BOUNCER_MAX_HOLD);      /* default 14d */
  time_t computed;
  int decay_pct;

  /* Never-used sessions get base hold only */
  if (session->hs_connect_count == 0)
    return base;

  /* Scale by connection count: each connection adds 25% of base, capped at max */
  computed = base + (base * session->hs_connect_count / 4);

  /* Additional bonus for cumulative active time: 1h per 24h active */
  if (session->hs_total_active > 0)
    computed += (session->hs_total_active / 86400) * 3600;

  /* Idle decay: configurable via BOUNCER_HOLD_DECAY_PERCENT (0 = disabled) */
  decay_pct = feature_int(FEAT_BOUNCER_HOLD_DECAY_PERCENT);
  if (decay_pct > 0 && session->hs_disconnect_time > 0) {
    time_t idle = CurrentTime - session->hs_disconnect_time;
    time_t decay_start = computed * decay_pct / 100;
    if (idle > decay_start) {
      time_t over = idle - decay_start;
      time_t decay_unit = computed / 4;
      if (decay_unit > 0) {
        int halvings = over / decay_unit;
        if (halvings > 0) {
          time_t remaining = computed - idle;
          int i;
          for (i = 0; i < halvings && remaining > base; i++)
            remaining = remaining / 2;
          computed = idle + ((remaining > base) ? remaining : base);
        }
      }
    }
  }

  return (computed > max) ? max : computed;
}

/** Public wrapper for adaptive hold time computation. */
time_t bounce_compute_hold_time_ext(struct BouncerSession *session)
{
  return bounce_compute_hold_time(session);
}

/** Detach a client from its session (disconnect). */
int bounce_detach(struct BouncerSession *session)
{
  time_t hold_time;

  assert(0 != session);

  /* Update activity counters before detach */
  if (session->hs_last_active > 0)
    session->hs_total_active += CurrentTime - session->hs_last_active;

  session->hs_client = NULL;
  session->hs_disconnect_time = CurrentTime;

  /* Check if hold is enabled for this session */
  if (session->hs_hold_override == 0) {
    /* Explicit no-hold override */
    bounce_broadcast(session, 'X', NULL);
    bounce_destroy(session);
    return 0;
  }

  if (session->hs_hold_override < 0 &&
      !feature_bool(FEAT_BOUNCER_DEFAULT_HOLD)) {
    /* No override, and network default is no-hold */
    bounce_broadcast(session, 'X', NULL);
    bounce_destroy(session);
    return 0;
  }

  /* Enter HOLDING state */
  session->hs_state = BOUNCE_HOLDING;

  /* Start hold timer with adaptive duration */
  hold_time = bounce_compute_hold_time(session);
  timer_init(&session->hs_hold_timer);
  timer_add(&session->hs_hold_timer, bounce_hold_expire,
            (void *)session, TT_RELATIVE, hold_time);

  return 0;
}

/** Destroy a session entirely. */
void bounce_destroy(struct BouncerSession *session)
{
  assert(0 != session);

  /* Cancel timer if active */
  if (t_active(&session->hs_hold_timer))
    timer_del(&session->hs_hold_timer);

  /* Remove from hash tables */
  token_hash_remove(session);
  account_remove_session(session);

  /* Remove persisted state */
  bounce_db_del(session->hs_sessid);

  Debug((DEBUG_INFO, "Bouncer: destroyed session %s for %s",
         session->hs_sessid, session->hs_account));

  MyFree(session);
}

/** Set a session's user-assigned name. */
void bounce_setname(struct BouncerSession *session, const char *name)
{
  assert(0 != session);
  if (name)
    ircd_strncpy(session->hs_name, name, BOUNCER_NAME_LEN - 1);
  else
    session->hs_name[0] = '\0';
}

/** Snapshot current channel memberships into a session. */
void bounce_snapshot_channels(struct BouncerSession *session,
                              struct Client *cptr)
{
  struct Membership *member;
  int i = 0;

  assert(0 != session);
  assert(0 != cptr);

  for (member = cli_user(cptr)->channel;
       member && i < BOUNCER_MAX_CHANNELS;
       member = member->next_channel) {
    ircd_strncpy(session->hs_channels[i].name,
                 member->channel->chname, CHANNELLEN);
    session->hs_channels[i].modes = member->status;
    session->hs_channels[i].join_tv_sec = member->join_tv.tv_sec;
    session->hs_channels[i].join_tv_usec = member->join_tv.tv_usec;
    memcpy(session->hs_channels[i].join_msgid, member->join_msgid, 16);
    i++;
  }
  session->hs_chancount = i;
}

/* ---------------------------------------------------------------- */
/* MDBX persistence (FEAT_BOUNCER_PERSIST)                            */
/* ---------------------------------------------------------------- */

/** Check if a session is local (originated on this server). */
static int is_local_session(struct BouncerSession *session)
{
  return (0 == strcmp(session->hs_origin, cli_yxx(&me)));
}

/** Persist a bouncer session to MDBX.
 * Only persists local sessions. Guarded by FEAT_BOUNCER_PERSIST.
 * @param[in] session Session to persist.
 * @return 0 on success, -1 on error.
 */
static int bounce_db_put(struct BouncerSession *session)
{
  MDBX_env *env;
  MDBX_dbi dbi;
  MDBX_txn *txn;
  MDBX_val key, data;
  struct BounceSessionRecord rec;
  struct Client *ghost = session->hs_client;
  int rc;

  if (!feature_bool(FEAT_BOUNCER_PERSIST) || !metadata_lmdb_is_available())
    return 0;

  if (!is_local_session(session))
    return 0;

  env = metadata_get_env();
  dbi = metadata_get_bouncer_dbi();
  if (!env)
    return -1;

  /* Build record */
  memset(&rec, 0, sizeof(rec));
  rec.bsr_version = BOUNCER_DB_VERSION;
  ircd_strncpy(rec.bsr_account, session->hs_account, ACCOUNTLEN + 1);
  ircd_strncpy(rec.bsr_sessid, session->hs_sessid, BOUNCER_SESSID_LEN);
  ircd_strncpy(rec.bsr_token, session->hs_token, BOUNCER_TOKEN_LEN + 1);
  ircd_strncpy(rec.bsr_name, session->hs_name, BOUNCER_NAME_LEN);
  ircd_strncpy(rec.bsr_origin, session->hs_origin, NICKLEN + 1);
  rec.bsr_hold_override = session->hs_hold_override;
  rec.bsr_created = (int64_t)session->hs_created;
  rec.bsr_disconnect_time = (int64_t)session->hs_disconnect_time;
  rec.bsr_last_active = (int64_t)session->hs_last_active;
  /* Persist the user's idle time (last PRIVMSG).  Prefer the live client's
   * value; fall back to the session-level copy for HOLDING ghosts. */
  if (ghost && cli_user(ghost) && cli_user(ghost)->last > 0)
    rec.bsr_last_msg_time = (int64_t)cli_user(ghost)->last;
  else
    rec.bsr_last_msg_time = (int64_t)session->hs_last_msg_time;
  rec.bsr_total_active = (int64_t)session->hs_total_active;
  rec.bsr_attach_count = session->hs_attach_count;
  rec.bsr_connect_count = session->hs_connect_count;
  if (ghost) {
    ircd_strncpy(rec.bsr_nick, cli_name(ghost), NICKLEN + 1);
    if (cli_user(ghost)) {
      ircd_strncpy(rec.bsr_username, cli_user(ghost)->username, USERLEN + 1);
      ircd_strncpy(rec.bsr_realhost, cli_user(ghost)->realhost, HOSTLEN + 1);
      ircd_strncpy(rec.bsr_host, cli_user(ghost)->host, HOSTLEN + 1);
      ircd_strncpy(rec.bsr_realname, cli_info(ghost), REALLEN + 1);
    }
    if (IsAccount(ghost)) {
      ircd_strncpy(rec.bsr_account_name, cli_account(ghost), ACCOUNTLEN + 1);
      rec.bsr_acc_create = (int64_t)cli_user(ghost)->acc_create;
    }

    /* Last connection metadata (for historical display on restored ghosts) */
    memcpy(&rec.bsr_ip, &cli_ip(ghost), sizeof(rec.bsr_ip));
    ircd_strncpy(rec.bsr_sock_ip, cli_sock_ip(ghost), SOCKIPLEN + 1);
    ircd_strncpy(rec.bsr_sockhost, cli_sockhost(ghost), HOSTLEN + 1);
    if (cli_listener(ghost))
      rec.bsr_listener_port = cli_listener(ghost)->addr.port;
  }

  /* Channel memberships (from session snapshot) */
  rec.bsr_chancount = (uint16_t)session->hs_chancount;
  {
    int i;
    for (i = 0; i < session->hs_chancount && i < BOUNCER_MAX_CHANNELS; i++) {
      ircd_strncpy(rec.bsr_channels[i].name,
                   session->hs_channels[i].name, CHANNELLEN + 1);
      rec.bsr_channels[i].modes = session->hs_channels[i].modes;
      rec.bsr_channels[i].join_tv_sec = session->hs_channels[i].join_tv_sec;
      rec.bsr_channels[i].join_tv_usec = session->hs_channels[i].join_tv_usec;
      memcpy(rec.bsr_channels[i].join_msgid,
             session->hs_channels[i].join_msgid, 16);
    }
  }

  /* Session-level aggregate counters */
  rec.bsr_agg_sendB    = session->hs_agg_sendB;
  rec.bsr_agg_receiveB = session->hs_agg_receiveB;
  rec.bsr_agg_sendM    = session->hs_agg_sendM;
  rec.bsr_agg_receiveM = session->hs_agg_receiveM;

  /* Connection history */
  rec.bsr_histcount = (uint16_t)session->hs_histcount;
  memcpy(rec.bsr_history, session->hs_history,
         session->hs_histcount * sizeof(struct BounceConnHistory));

  /* Write to MDBX */
  rc = mdbx_txn_begin(env, NULL, 0, &txn);
  if (rc != MDBX_SUCCESS) {
    log_write(LS_SYSTEM, L_ERROR, 0, "bouncer_persist: txn_begin failed: %s",
              mdbx_strerror(rc));
    return -1;
  }

  key.iov_base = session->hs_sessid;
  key.iov_len = strlen(session->hs_sessid);
  data.iov_base = &rec;
  data.iov_len = sizeof(rec);

  rc = mdbx_put(txn, dbi, &key, &data, 0);
  if (rc != MDBX_SUCCESS) {
    log_write(LS_SYSTEM, L_ERROR, 0, "bouncer_persist: put(%s) failed: %s",
              session->hs_sessid, mdbx_strerror(rc));
    mdbx_txn_abort(txn);
    return -1;
  }

  rc = mdbx_txn_commit(txn);
  if (rc != MDBX_SUCCESS) {
    log_write(LS_SYSTEM, L_ERROR, 0, "bouncer_persist: commit failed: %s",
              mdbx_strerror(rc));
    return -1;
  }

  Debug((DEBUG_INFO, "Bouncer: persisted session %s for %s",
         session->hs_sessid, session->hs_account));
  return 0;
}

/** Delete a bouncer session from MDBX.
 * @param[in] sessid Session ID to delete.
 * @return 0 on success, -1 on error.
 */
static int bounce_db_del(const char *sessid)
{
  MDBX_env *env;
  MDBX_dbi dbi;
  MDBX_txn *txn;
  MDBX_val key;
  int rc;

  if (!feature_bool(FEAT_BOUNCER_PERSIST) || !metadata_lmdb_is_available())
    return 0;

  env = metadata_get_env();
  dbi = metadata_get_bouncer_dbi();
  if (!env)
    return -1;

  rc = mdbx_txn_begin(env, NULL, 0, &txn);
  if (rc != MDBX_SUCCESS) {
    log_write(LS_SYSTEM, L_ERROR, 0, "bouncer_persist: txn_begin failed: %s",
              mdbx_strerror(rc));
    return -1;
  }

  key.iov_base = (void *)sessid;
  key.iov_len = strlen(sessid);

  rc = mdbx_del(txn, dbi, &key, NULL);
  if (rc != MDBX_SUCCESS && rc != MDBX_NOTFOUND) {
    log_write(LS_SYSTEM, L_ERROR, 0, "bouncer_persist: del(%s) failed: %s",
              sessid, mdbx_strerror(rc));
    mdbx_txn_abort(txn);
    return -1;
  }

  rc = mdbx_txn_commit(txn);
  if (rc != MDBX_SUCCESS) {
    log_write(LS_SYSTEM, L_ERROR, 0, "bouncer_persist: commit failed: %s",
              mdbx_strerror(rc));
    return -1;
  }

  Debug((DEBUG_INFO, "Bouncer: deleted persisted session %s", sessid));
  return 0;
}

/** Persist all local bouncer sessions to MDBX before shutdown.
 * ACTIVE sessions are snapshotted (channels from live client) first.
 * Called from server_die()/server_restart() before flush_connections().
 */
void bounce_db_shutdown(void)
{
  int i;
  struct BouncerSession *s;
  int count = 0;

  if (!feature_bool(FEAT_BOUNCER_PERSIST) || !metadata_lmdb_is_available())
    return;

  for (i = 0; i < BOUNCE_TOKEN_HASHSIZE; i++) {
    for (s = tokenHash[i]; s; s = s->hs_tnext) {
      if (!is_local_session(s))
        continue;

      /* Snapshot ACTIVE sessions — they have a live client with channels */
      if (s->hs_state == BOUNCE_ACTIVE && s->hs_client) {
        bounce_snapshot_channels(s, s->hs_client);
        s->hs_disconnect_time = CurrentTime;
      }

      bounce_db_put(s);
      count++;
    }
  }

  log_write(LS_SYSTEM, L_INFO, 0, "bouncer_persist: shutdown — persisted %d sessions", count);
}

/** Create a ghost client from a persisted session record.
 * The ghost has no socket (fd=-1), is registered in global structures,
 * and is flagged as BOUNCER_HOLD.
 * @param[in] rec Persisted session record.
 * @return Ghost client, or NULL on failure.
 */
static struct Client *bounce_create_ghost(struct BounceSessionRecord *rec)
{
  struct Client *ghost;
  struct User *user;

  /* Allocate local client (NULL from = local, gets its own Connection with fd=-1) */
  ghost = make_client(NULL, STAT_UNKNOWN);
  if (!ghost)
    return NULL;

  /* Create User struct */
  user = make_user(ghost);
  if (!user) {
    /* make_user shouldn't fail, but guard anyway */
    return NULL;
  }

  /* Set identity from record */
  ircd_strncpy(cli_name(ghost), rec->bsr_nick, NICKLEN + 1);
  ircd_strncpy(user->username, rec->bsr_username, USERLEN + 1);
  ircd_strncpy(user->realhost, rec->bsr_realhost, HOSTLEN + 1);
  ircd_strncpy(user->host, rec->bsr_host, HOSTLEN + 1);
  ircd_strncpy(cli_info(ghost), rec->bsr_realname, REALLEN + 1);

  /* Set account */
  ircd_strncpy(user->account, rec->bsr_account_name, ACCOUNTLEN + 1);
  user->acc_create = (time_t)rec->bsr_acc_create;
  user->server = &me;

  /* Restore last connection metadata (historical, reconciled on revive) */
  memcpy(&cli_ip(ghost), &rec->bsr_ip, sizeof(cli_ip(ghost)));
  ircd_strncpy(cli_sock_ip(ghost), rec->bsr_sock_ip, SOCKIPLEN + 1);
  ircd_strncpy(cli_sockhost(ghost), rec->bsr_sockhost, HOSTLEN + 1);

  /* Assign local numeric */
  if (!SetLocalNumNick(ghost)) {
    log_write(LS_SYSTEM, L_ERROR, 0, "bouncer_persist: no numerics for ghost %s",
              rec->bsr_nick);
    /* Can't properly free a half-initialized client here — just return NULL.
     * The Connection and User will leak but this is a startup-only edge case
     * that indicates the server is at capacity anyway. */
    return NULL;
  }

  /* Set as registered user.
   * Must set both cli_status (via SetUser) AND cli_handler (via con_handler).
   * cli_status determines IsUser/IsRegistered checks.
   * cli_handler determines which message handler is used (UNREG vs CLIENT). */
  SetUser(ghost);
  cli_handler(ghost) = CLIENT_HANDLER;
  SetAccount(ghost);
  SetHiddenHost(ghost);
  SetBouncerHold(ghost);

  /* Set creation timestamp to original time (wins nick collisions: older wins) */
  cli_lastnick(ghost) = (time_t)rec->bsr_created;

  /* Register in global structures */
  add_client_to_list(ghost);
  hAddClient(ghost);

  return ghost;
}

/** Restore channel memberships for a ghost client from a persisted record.
 * @param[in] ghost Ghost client.
 * @param[in] rec Session record with channel data.
 */
static void bounce_restore_channels(struct Client *ghost,
                                    struct BounceSessionRecord *rec)
{
  int i;

  for (i = 0; i < rec->bsr_chancount && i < BOUNCER_MAX_CHANNELS; i++) {
    struct Channel *chptr;
    unsigned int modes;

    if (rec->bsr_channels[i].name[0] == '\0')
      continue;

    chptr = get_channel(ghost, rec->bsr_channels[i].name, CGT_CREATE);
    if (!chptr)
      continue;

    modes = rec->bsr_channels[i].modes | CHFL_HOLDING;
    add_user_to_channel(chptr, ghost, modes, 0);

    /* Restore persisted join metadata (add_user_to_channel zeroes these) */
    if (rec->bsr_channels[i].join_tv_sec) {
      struct Membership *memb = find_member_link(chptr, ghost);
      if (memb) {
        memb->join_tv.tv_sec  = (time_t)rec->bsr_channels[i].join_tv_sec;
        memb->join_tv.tv_usec = (suseconds_t)rec->bsr_channels[i].join_tv_usec;
        memcpy(memb->join_msgid, rec->bsr_channels[i].join_msgid, 16);
      }
    }
  }
}

/** Restore bouncer sessions from MDBX after restart.
 * Creates ghost clients, joins them to channels, registers sessions
 * in hash tables. Runs before listeners open, so no collision possible.
 * @return Number of sessions restored, or -1 on error.
 */
int bounce_db_restore(void)
{
  MDBX_env *env;
  MDBX_dbi dbi;
  MDBX_txn *txn;
  MDBX_cursor *cursor;
  MDBX_val key, data;
  int rc;
  int restored = 0;
  int expired = 0;
  unsigned int max_seq = 0;
  time_t max_hold;

  if (!feature_bool(FEAT_BOUNCER_PERSIST) || !metadata_lmdb_is_available())
    return 0;

  env = metadata_get_env();
  dbi = metadata_get_bouncer_dbi();
  if (!env)
    return -1;

  max_hold = feature_int(FEAT_BOUNCER_MAX_HOLD);

  /* Read-only txn to scan all records */
  rc = mdbx_txn_begin(env, NULL, MDBX_RDONLY, &txn);
  if (rc != MDBX_SUCCESS) {
    log_write(LS_SYSTEM, L_ERROR, 0, "bouncer_persist: restore txn_begin failed: %s",
              mdbx_strerror(rc));
    return -1;
  }

  rc = mdbx_cursor_open(txn, dbi, &cursor);
  if (rc != MDBX_SUCCESS) {
    log_write(LS_SYSTEM, L_ERROR, 0, "bouncer_persist: cursor_open failed: %s",
              mdbx_strerror(rc));
    mdbx_txn_abort(txn);
    return -1;
  }

  while ((rc = mdbx_cursor_get(cursor, &key, &data, MDBX_NEXT)) == MDBX_SUCCESS) {
    struct BounceSessionRecord *rec;
    struct BouncerSession *session;
    struct Client *ghost;
    struct AccountSessions *as;
    time_t elapsed;
    time_t remaining;
    unsigned int seq;
    const char *dash;

    if (data.iov_len != sizeof(struct BounceSessionRecord))
      continue; /* wrong size, skip */

    rec = (struct BounceSessionRecord *)data.iov_base;

    if (rec->bsr_version != BOUNCER_DB_VERSION)
      continue; /* version mismatch, skip */

    /* Check expiry */
    elapsed = CurrentTime - (time_t)rec->bsr_disconnect_time;
    if (elapsed > max_hold) {
      expired++;
      continue;
    }

    /* Track max session sequence number */
    dash = strchr(rec->bsr_sessid, '-');
    if (dash) {
      seq = (unsigned int)strtoul(dash + 1, NULL, 10);
      if (seq > max_seq)
        max_seq = seq;
    }

    /* Create ghost client */
    ghost = bounce_create_ghost(rec);
    if (!ghost) {
      log_write(LS_SYSTEM, L_WARNING, 0, "bouncer_persist: failed to create ghost for %s",
                rec->bsr_sessid);
      continue;
    }

    /* Restore channel memberships */
    bounce_restore_channels(ghost, rec);

    /* Allocate and populate BouncerSession */
    session = (struct BouncerSession *)MyCalloc(1, sizeof(*session));
    ircd_strncpy(session->hs_account, rec->bsr_account, ACCOUNTLEN + 1);
    ircd_strncpy(session->hs_sessid, rec->bsr_sessid, BOUNCER_SESSID_LEN);
    ircd_strncpy(session->hs_token, rec->bsr_token, BOUNCER_TOKEN_LEN + 1);
    ircd_strncpy(session->hs_name, rec->bsr_name, BOUNCER_NAME_LEN);
    ircd_strncpy(session->hs_origin, rec->bsr_origin, NICKLEN + 1);
    session->hs_hold_override = rec->bsr_hold_override;
    session->hs_state = BOUNCE_HOLDING;
    session->hs_client = ghost;
    ircd_strncpy(session->hs_ghost_numeric, cli_yxx(ghost),
                 sizeof(session->hs_ghost_numeric) - 1);
    session->hs_ghost_numeric[sizeof(session->hs_ghost_numeric) - 1] = '\0';
    session->hs_effective_away = 0;
    session->hs_effective_away_msg[0] = '\0';
    session->hs_created = (time_t)rec->bsr_created;
    session->hs_last_active = (time_t)rec->bsr_last_active;
    session->hs_last_msg_time = (time_t)rec->bsr_last_msg_time;
    session->hs_disconnect_time = (time_t)rec->bsr_disconnect_time;
    /* Restore ghost's idle time so auto-replay works after restart */
    if (ghost && cli_user(ghost) && session->hs_last_msg_time > 0)
      cli_user(ghost)->last = session->hs_last_msg_time;
    session->hs_attach_count = rec->bsr_attach_count;
    session->hs_connect_count = rec->bsr_connect_count;
    session->hs_total_active = (time_t)rec->bsr_total_active;

    /* Session-level aggregate counters */
    session->hs_agg_sendB    = rec->bsr_agg_sendB;
    session->hs_agg_receiveB = rec->bsr_agg_receiveB;
    session->hs_agg_sendM    = rec->bsr_agg_sendM;
    session->hs_agg_receiveM = rec->bsr_agg_receiveM;

    /* Connection history */
    session->hs_histcount = rec->bsr_histcount;
    if (session->hs_histcount > BOUNCER_MAX_CONN_HISTORY)
      session->hs_histcount = BOUNCER_MAX_CONN_HISTORY;
    memcpy(session->hs_history, rec->bsr_history,
           session->hs_histcount * sizeof(struct BounceConnHistory));

    /* Copy channel snapshot for consistency */
    session->hs_chancount = rec->bsr_chancount;
    {
      int i;
      for (i = 0; i < rec->bsr_chancount && i < BOUNCER_MAX_CHANNELS; i++) {
        ircd_strncpy(session->hs_channels[i].name,
                     rec->bsr_channels[i].name, CHANNELLEN);
        session->hs_channels[i].modes = rec->bsr_channels[i].modes;
      }
    }

    /* Register in hash tables */
    token_hash_add(session);
    as = account_sessions_get(session->hs_account, 1);
    account_add_session(as, session);

    /* Start hold timer with remaining time.
     * Use adaptive hold (based on attach_count/total_active), not MAX_HOLD.
     * MAX_HOLD is the absolute ceiling for the expiry check above;
     * the actual timer should match what bounce_hold_client() would use.
     */
    {
      time_t adaptive_hold = bounce_compute_hold_time(session);
      remaining = adaptive_hold - elapsed;
      if (remaining < 10)
        remaining = 10; /* minimum 10s grace period */
    }
    timer_init(&session->hs_hold_timer);
    timer_add(&session->hs_hold_timer, bounce_hold_expire,
              (void *)session, TT_RELATIVE, remaining);

    restored++;
    log_write(LS_SYSTEM, L_INFO, 0, "bouncer_persist: restored session %s (%s) ghost=%s remaining=%Tu",
              session->hs_sessid, session->hs_account, cli_name(ghost), remaining);
  }

  mdbx_cursor_close(cursor);
  mdbx_txn_abort(txn);

  /* Update sessionSeq to avoid collision */
  if (max_seq >= sessionSeq)
    sessionSeq = max_seq + 1;

  /* Clean up expired records in a write txn */
  if (expired > 0) {
    MDBX_txn *wtxn;
    MDBX_cursor *wcursor;

    rc = mdbx_txn_begin(env, NULL, 0, &wtxn);
    if (rc == MDBX_SUCCESS) {
      rc = mdbx_cursor_open(wtxn, dbi, &wcursor);
      if (rc == MDBX_SUCCESS) {
        while ((rc = mdbx_cursor_get(wcursor, &key, &data, MDBX_NEXT)) == MDBX_SUCCESS) {
          struct BounceSessionRecord *rec = (struct BounceSessionRecord *)data.iov_base;
          if (data.iov_len != sizeof(struct BounceSessionRecord) ||
              rec->bsr_version != BOUNCER_DB_VERSION ||
              CurrentTime - (time_t)rec->bsr_disconnect_time > max_hold) {
            mdbx_cursor_del(wcursor, 0);
          }
        }
        mdbx_cursor_close(wcursor);
      }
      mdbx_txn_commit(wtxn);
    }
    log_write(LS_SYSTEM, L_INFO, 0, "bouncer_persist: cleaned up %d expired records", expired);
  }

  log_write(LS_SYSTEM, L_INFO, 0, "bouncer_persist: restored %d sessions, sessionSeq=%u",
            restored, sessionSeq);
  return restored;
}

/* ---------------------------------------------------------------- */
/* P10 BURST / sync                                                  */
/* ---------------------------------------------------------------- */

/** Build BURST-style mode suffix for a channel membership.
 * Appends mode characters after a ':' delimiter (e.g., ":ov" for op+voice).
 * Channels with no modes get no suffix.
 * @param[in] modes Channel membership flags (CHFL_CHANOP, CHFL_VOICE, etc.)
 * @param[out] buf Output buffer (must hold at least 5 bytes: ":ovh\0").
 */
static void build_mode_suffix(unsigned int modes, char *buf)
{
  char *p = buf;

  /* Strip internal-only flags that aren't channel privilege modes */
  modes &= (CHFL_CHANOP | CHFL_HALFOP | CHFL_VOICE);
  if (!modes) {
    *p = '\0';
    return;
  }
  *p++ = ':';
  if (modes & CHFL_CHANOP)
    *p++ = 'o';
  if (modes & CHFL_HALFOP)
    *p++ = 'h';
  if (modes & CHFL_VOICE)
    *p++ = 'v';
  *p = '\0';
}

/** Parse BURST-style mode suffix from a channel token.
 * Splits on the LAST ':' in the token (handles channels with ':' in name).
 * @param[in] token Channel token (e.g., "#test:room:ov" or "#test").
 * @param[out] name_out Buffer for channel name (CHANNELLEN+1).
 * @param[out] modes_out Parsed CHFL_* mode flags.
 */
static void parse_channel_modes(const char *token, char *name_out,
                                unsigned int *modes_out)
{
  const char *last_colon;
  const char *p;
  unsigned int modes = 0;
  int has_modes = 0;

  last_colon = strrchr(token, ':');
  if (last_colon && last_colon > token) {
    /* Verify everything after ':' is a valid mode char */
    for (p = last_colon + 1; *p; p++) {
      switch (*p) {
        case 'o': modes |= CHFL_CHANOP; break;
        case 'h': modes |= CHFL_HALFOP; break;
        case 'v': modes |= CHFL_VOICE; break;
        default:
          /* Not a valid mode suffix — the ':' is part of the channel name */
          goto no_modes;
      }
    }
    /* Valid mode suffix found */
    has_modes = 1;
  }

no_modes:
  if (has_modes) {
    size_t namelen = last_colon - token;
    if (namelen > CHANNELLEN)
      namelen = CHANNELLEN;
    memcpy(name_out, token, namelen);
    name_out[namelen] = '\0';
    *modes_out = modes;
  } else {
    ircd_strncpy(name_out, token, CHANNELLEN + 1);
    *modes_out = 0;
  }
}

/** Build channel list string for BS protocol messages.
 * Uses BURST-style mode format: #chan1:ov,#chan2:o,#chan3
 * @param[in] session Session to serialize channels from.
 * @param[out] buf Output buffer.
 * @param[in] buflen Buffer size.
 */
static void build_channel_string(struct BouncerSession *session,
                                 char *buf, size_t buflen)
{
  int i;
  size_t pos = 0;
  char modesuf[5]; /* ":ovh\0" */

  buf[0] = '\0';
  for (i = 0; i < session->hs_chancount && pos < buflen - 1; i++) {
    if (i > 0 && pos < buflen - 1)
      buf[pos++] = ',';
    build_mode_suffix(session->hs_channels[i].modes, modesuf);
    pos += ircd_snprintf(0, buf + pos, buflen - pos, "%s%s",
                         session->hs_channels[i].name, modesuf);
  }
}

/** Send all local sessions as BS C messages during server BURST. */
void bounce_burst(struct Client *cptr)
{
  int i;
  struct BouncerSession *s;
  char chanbuf[512];

  /* No gate check — sessions may exist via CRFLAG_BOUNCER class even when
   * the global bouncer feature is off.  Empty hash = no-op loop. */

  for (i = 0; i < BOUNCE_TOKEN_HASHSIZE; i++) {
    for (s = tokenHash[i]; s; s = s->hs_tnext) {
      build_channel_string(s, chanbuf, sizeof(chanbuf));

      if (s->hs_state == BOUNCE_HOLDING) {
        sendcmdto_one(&me, CMD_BOUNCER_SESSION,
                      cptr,
                      "C %s %s %s holding %Tu %Tu %u %Tu :%s",
                      s->hs_account, s->hs_sessid, s->hs_token,
                      s->hs_created, s->hs_disconnect_time,
                      s->hs_attach_count, s->hs_total_active,
                      chanbuf);
      } else {
        sendcmdto_one(&me, CMD_BOUNCER_SESSION,
                      cptr,
                      "C %s %s %s active %Tu %u %Tu :%s",
                      s->hs_account, s->hs_sessid, s->hs_token,
                      s->hs_created,
                      s->hs_attach_count, s->hs_total_active,
                      chanbuf);
      }
      /* Follow with BS A so the receiver can resolve hs_client
       * for alias support.  Applies to both HOLDING (ghost) and
       * ACTIVE (live primary) sessions — without this, leaves
       * can't activate the alias path for held sessions and get
       * nick collisions instead. */
      if (s->hs_client)
        sendcmdto_one(&me, CMD_BOUNCER_SESSION,
                      cptr,
                      "A %s %s %s",
                      s->hs_account, s->hs_sessid,
                      cli_yxx(s->hs_client));

      /* Burst existing aliases via BX C so the new server learns about
       * alias Client identities before the channel BURST references
       * them as members.  Aliases are filtered out of the NICK burst
       * in s_serv.c (see `!IsBouncerAlias(acptr)` check) because
       * aliases are introduced via BX C, not N token.  Without this
       * pass, a server connecting after aliases were auto-created
       * receives channel BURST entries referring to numerics it was
       * never introduced to — the receiver logs the alias as
       * unresolvable and drops JOIN/MODE events for it.  Only ACTIVE
       * sessions have aliases worth bursting; HOLDING sessions have
       * at most a ghost primary and no aliases.  Requires s->hs_client
       * so we can compose the full primary YYXXX numeric for the BX C. */
      if (s->hs_state == BOUNCE_ACTIVE && s->hs_client
          && s->hs_alias_count > 0) {
        char primary_full[6];
        int a;
        ircd_snprintf(0, primary_full, sizeof(primary_full), "%s%s",
                      cli_yxx(cli_user(s->hs_client)->server),
                      cli_yxx(s->hs_client));
        for (a = 0; a < s->hs_alias_count; a++) {
          struct Client *alias;
          struct Membership *memb;
          char alias_chans[512];
          int chans_len = 0;
          const char *alias_modes;

          alias = findNUser(s->hs_aliases[a].ba_numeric);
          if (!alias || !IsBouncerAlias(alias))
            continue;

          /* Build the alias's joined-channel list so the receiver
           * can re-add the alias to the same channels with
           * CHFL_ALIAS.  Walk cli_user(alias)->channel directly
           * (not the primary's channels) — aliases can diverge
           * from the primary over time via KICK or PART. */
          alias_chans[0] = '\0';
          for (memb = cli_user(alias)->channel; memb;
               memb = memb->next_channel) {
            if (IsZombie(memb) || IsDelayedJoin(memb))
              continue;
            if (chans_len > 0
                && chans_len < (int)sizeof(alias_chans) - 1)
              alias_chans[chans_len++] = ' ';
            chans_len += ircd_snprintf(0, alias_chans + chans_len,
                                       sizeof(alias_chans) - chans_len,
                                       "%s", memb->channel->chname);
          }

          alias_modes = umode_str(alias);
          sendcmdto_one(&me, CMD_BOUNCER_TRANSFER, cptr,
                        "C %s %s %s %s %s%s :%s",
                        primary_full,
                        s->hs_aliases[a].ba_numeric,
                        s->hs_account,
                        s->hs_sessid,
                        *alias_modes ? "+" : "+",
                        alias_modes,
                        alias_chans);
        }
      }
    }
  }
}

/** Broadcast a session state change to all other servers. */
void bounce_broadcast(struct BouncerSession *session, char subcmd,
                      const char *extra)
{
  char chanbuf[512];

  switch (subcmd) {
  case 'C': /* Create */
    build_channel_string(session, chanbuf, sizeof(chanbuf));
    sendcmdto_serv_butone(&me, CMD_BOUNCER_SESSION,
                          NULL,
                          "C %s %s %s active %Tu %u %Tu :%s",
                          session->hs_account, session->hs_sessid,
                          session->hs_token, session->hs_created,
                          session->hs_attach_count,
                          session->hs_total_active,
                          chanbuf);
    break;

  case 'A': /* Attach */
    sendcmdto_serv_butone(&me, CMD_BOUNCER_SESSION,
                          NULL,
                          "A %s %s %s",
                          session->hs_account, session->hs_sessid,
                          extra ? extra : "");
    break;

  case 'D': /* Detach */
    build_channel_string(session, chanbuf, sizeof(chanbuf));
    sendcmdto_serv_butone(&me, CMD_BOUNCER_SESSION,
                          NULL,
                          "D %s %s %s %Tu :%s",
                          session->hs_account, session->hs_sessid,
                          session->hs_ghost_numeric,
                          session->hs_disconnect_time,
                          chanbuf);
    break;

  case 'X': /* Destroy */
    sendcmdto_serv_butone(&me, CMD_BOUNCER_SESSION,
                          NULL,
                          "X %s %s",
                          session->hs_account, session->hs_sessid);
    break;

  case 'U': /* Update */
    sendcmdto_serv_butone(&me, CMD_BOUNCER_SESSION,
                          NULL,
                          "U %s %s %s",
                          session->hs_account, session->hs_sessid,
                          extra ? extra : "");
    break;
  }
}

/** Handle incoming BS P10 message from another server.
 *
 * Subcommands:
 *   BS C <account> <sessid> <token> <state> <created> [<disconnect-time>] :<channels>
 *   BS A <account> <sessid> <client-numeric>
 *   BS D <account> <sessid> <disconnect-time> :<channels>
 *   BS X <account> <sessid>
 *   BS U <account> <sessid> <field>=<value>
 *   BS T <account> <sessid> <new-origin>  (session ownership transfer)
 */
int bounce_handle_bs(struct Client *cptr, struct Client *sptr,
                     int parc, char *parv[])
{
  const char *subcmd;
  const char *account;
  const char *sessid;
  struct BouncerSession *session;
  struct AccountSessions *as;

  if (parc < 4)
    return 0;

  subcmd = parv[1];
  account = parv[2];
  sessid = parv[3];

  switch (subcmd[0]) {
  case 'C': /* Create */
  {
    const char *token;
    const char *state_str;
    const char *channels;
    time_t created;
    time_t disconnect_time = 0;
    unsigned int attach_count = 0;
    time_t total_active = 0;
    time_t hold_time;
    int is_holding;

    if (parc < 7)
      return 0;

    token = parv[4];
    state_str = parv[5];
    created = (time_t)atol(parv[6]);
    is_holding = (0 == ircd_strcmp(state_str, "holding"));

    /* Parse variable-position params depending on state.
     * Trailing param (parv[parc-1]) is always channels.
     * Holding: created disconnect_time [attach_count total_active] :channels
     * Active:  created [attach_count total_active] :channels
     */
    if (is_holding) {
      if (parc >= 8)
        disconnect_time = (time_t)atol(parv[7]);
      if (parc >= 10) {
        attach_count = (unsigned int)atol(parv[8]);
        total_active = (time_t)atol(parv[9]);
      }
    } else {
      if (parc >= 9) {
        attach_count = (unsigned int)atol(parv[7]);
        total_active = (time_t)atol(parv[8]);
      }
    }

    /* Channel list is the trailing parameter */
    channels = parv[parc - 1];

    /* Check if session already exists (BURST dedup) */
    if (bounce_find_by_token(token))
      return 0;

    /* Create session from remote data */
    session = (struct BouncerSession *)MyCalloc(1, sizeof(*session));
    ircd_strncpy(session->hs_account, account, ACCOUNTLEN + 1);
    ircd_strncpy(session->hs_sessid, sessid, BOUNCER_SESSID_LEN - 1);
    ircd_strncpy(session->hs_token, token, BOUNCER_TOKEN_LEN + 1);
    session->hs_name[0] = '\0';
    session->hs_client = NULL; /* Remote session */
    ircd_strncpy(session->hs_origin, cli_yxx(sptr),
                 sizeof(session->hs_origin) - 1);
    session->hs_hold_override = -1;
    session->hs_effective_away = 0;
    session->hs_effective_away_msg[0] = '\0';
    session->hs_created = created;
    session->hs_last_active = created;
    session->hs_attach_count = attach_count;
    session->hs_total_active = total_active;

    if (is_holding) {
      session->hs_state = BOUNCE_HOLDING;
      session->hs_disconnect_time = disconnect_time;
      /* No hold timer on remote replicas — the managing server owns the
       * timer and sends BS X when it expires.  Running a local timer risks
       * premature replica destruction (race with managing server). */
    } else {
      session->hs_state = BOUNCE_ACTIVE;
      session->hs_disconnect_time = 0;
    }

    /* Parse channel list (BURST-style: #chan1:ov,#chan2:o,#chan3) */
    if (channels && *channels) {
      char chanlist[512];
      char *tok, *saveptr;
      int i = 0;

      ircd_strncpy(chanlist, channels, sizeof(chanlist) - 1);
      for (tok = strtok_r(chanlist, ",", &saveptr);
           tok && i < BOUNCER_MAX_CHANNELS;
           tok = strtok_r(NULL, ",", &saveptr)) {
        parse_channel_modes(tok, session->hs_channels[i].name,
                           &session->hs_channels[i].modes);
        i++;
      }
      session->hs_chancount = i;
    }

    /* Add to local registry */
    token_hash_add(session);
    as = account_sessions_get(session->hs_account, 1);
    account_add_session(as, session);

    /* Forward to other servers — preserve all parameters verbatim so
     * downstream servers get full metadata (attach_count, total_active). */
    if (is_holding) {
      sendcmdto_serv_butone(sptr, CMD_BOUNCER_SESSION,
                            cptr,
                            "C %s %s %s holding %Tu %Tu %u %Tu :%s",
                            account, sessid, token,
                            created, disconnect_time,
                            attach_count, total_active,
                            channels ? channels : "");
    } else {
      sendcmdto_serv_butone(sptr, CMD_BOUNCER_SESSION,
                            cptr,
                            "C %s %s %s active %Tu %u %Tu :%s",
                            account, sessid, token,
                            created,
                            attach_count, total_active,
                            channels ? channels : "");
    }
    break;
  }

  case 'A': /* Attach */
  {
    session = bounce_find_by_token_sessid(account, sessid);
    if (!session)
      return 0;

    /* Resolve primary client from numeric so remote servers can use
     * session->hs_client for alias creation.
     * BS A sends the 3-char client numeric (XXX); combine with the
     * session origin (YY) to get the full YYXXX for findNUser(). */
    if (parc >= 5 && parv[4][0]) {
      char full_numeric[6];
      struct Client *primary;
      ircd_snprintf(0, full_numeric, sizeof(full_numeric), "%s%s",
                    session->hs_origin, parv[4]);
      primary = findNUser(full_numeric);
      if (primary && IsUser(primary))
        session->hs_client = primary;
    }

    /* During burst, BS A just associates the session with its ghost
     * numeric — the session keeps its burst state (HOLDING stays
     * HOLDING).  Outside burst, BS A means a real client attached —
     * transition to ACTIVE and cancel the hold timer. */
    if (!IsBurstOrBurstAck(sptr)) {
      /* Cancel hold timer */
      if (t_active(&session->hs_hold_timer))
        timer_del(&session->hs_hold_timer);

      session->hs_state = BOUNCE_ACTIVE;
      session->hs_last_active = CurrentTime;
      session->hs_disconnect_time = 0;
    }

    /* Forward */
    sendcmdto_serv_butone(sptr, CMD_BOUNCER_SESSION,
                          cptr,
                          "A %s %s %s",
                          account, sessid,
                          (parc >= 5) ? parv[4] : "");
    break;
  }

  case 'D': /* Detach */
  {
    const char *ghost_numeric;
    time_t disc_time;
    const char *channels;
    int hold_time;

    /* BS D <account> <sessid> <ghost-numeric> <disc-time> :<channels> */
    if (parc < 6)
      return 0;

    session = bounce_find_by_token_sessid(account, sessid);
    if (!session)
      return 0;

    ghost_numeric = parv[4];
    disc_time = (time_t)atol(parv[5]);
    channels = parv[parc - 1];

    session->hs_state = BOUNCE_HOLDING;
    session->hs_disconnect_time = disc_time;
    ircd_strncpy(session->hs_ghost_numeric, ghost_numeric,
                 sizeof(session->hs_ghost_numeric) - 1);
    session->hs_ghost_numeric[sizeof(session->hs_ghost_numeric) - 1] = '\0';

    /* Resolve ghost client from numeric so that bounce_auto_resume()
     * can check hs_client for the alias path.  Without this, a new
     * client connecting to a different server can't take the alias path
     * because hs_client would be NULL. */
    {
      char full_numeric[6];
      struct Client *ghost;
      ircd_snprintf(0, full_numeric, sizeof(full_numeric), "%s%s",
                    session->hs_origin, ghost_numeric);
      ghost = findNUser(full_numeric);
      session->hs_client = (ghost && IsUser(ghost)) ? ghost : NULL;
    }

    /* Update channels if provided (BURST-style: #chan1:ov,#chan2:o,#chan3) */
    if (channels && *channels) {
      char chanlist[512];
      char *tok, *saveptr;
      int i = 0;

      ircd_strncpy(chanlist, channels, sizeof(chanlist) - 1);
      for (tok = strtok_r(chanlist, ",", &saveptr);
           tok && i < BOUNCER_MAX_CHANNELS;
           tok = strtok_r(NULL, ",", &saveptr)) {
        parse_channel_modes(tok, session->hs_channels[i].name,
                           &session->hs_channels[i].modes);
        i++;
      }
      session->hs_chancount = i;
    }

    /* No hold timer on remote replicas — the managing server owns the
     * timer and sends BS X when it expires.  Running a local timer risks
     * premature replica destruction (race with managing server). */

    /* Forward */
    sendcmdto_serv_butone(sptr, CMD_BOUNCER_SESSION,
                          cptr,
                          "D %s %s %s %Tu :%s",
                          account, sessid, ghost_numeric, disc_time,
                          channels ? channels : "");
    break;
  }

  case 'X': /* Destroy session */
  {
    /* BS X <account> <sessid> — destroy session */
    session = bounce_find_by_token_sessid(account, sessid);
    if (session)
      bounce_destroy(session);

    /* Forward */
    sendcmdto_serv_butone(sptr, CMD_BOUNCER_SESSION,
                          cptr,
                          "X %s %s",
                          account, sessid);
    break;
  }

  case 'U': /* Update */
  {
    const char *field;

    if (parc < 5)
      return 0;

    field = parv[4];
    session = bounce_find_by_token_sessid(account, sessid);
    if (!session)
      return 0;

    /* Parse field=value */
    if (0 == strncmp(field, "name=", 5))
      bounce_setname(session, field + 5);

    /* Forward */
    sendcmdto_serv_butone(sptr, CMD_BOUNCER_SESSION,
                          cptr,
                          "U %s %s %s",
                          account, sessid, field);
    break;
  }

  case 'T': /* Transfer ownership (SQUIT promotion) */
  {
    /* BS T <account> <sessid> <new-origin>
     * Updates hs_origin so BS S and other origin-gated operations
     * route to the new managing server.
     */
    const char *new_origin;

    if (parc < 5)
      break;

    new_origin = parv[4];
    session = bounce_find_by_token_sessid(account, sessid);
    if (session) {
      ircd_strncpy(session->hs_origin, new_origin,
                    sizeof(session->hs_origin) - 1);
      Debug((DEBUG_INFO, "BS T: session %s/%s ownership transferred to %s",
             account, sessid, new_origin));
    }

    /* Forward */
    sendcmdto_serv_butone(sptr, CMD_BOUNCER_SESSION,
                          cptr,
                          "T %s %s %s",
                          account, sessid, new_origin);
    break;
  }

  default:
    break;
  }

  return 0;
}

/* ---------------------------------------------------------------- */
/* Internal helper: find session by account + sessid                 */
/* ---------------------------------------------------------------- */

/** Find a session by account + session ID (for P10 messages). */
static struct BouncerSession *bounce_find_by_token_sessid(const char *account,
                                                          const char *sessid)
{
  struct AccountSessions *as = bounce_find_by_account(account);
  struct BouncerSession *s;

  if (!as)
    return NULL;

  for (s = as->as_sessions; s; s = s->hs_anext) {
    if (0 == strcmp(s->hs_sessid, sessid))
      return s;
  }
  return NULL;
}


/* ---------------------------------------------------------------- */
/* SQUIT alias promotion                                             */
/* ---------------------------------------------------------------- */

/** Promote an alias to primary for a bouncer session.
 * Extracts the promotion logic shared by disconnect handlers and SQUIT.
 *
 * Tiebreaker: oldest connection (lowest cli_firsttime) wins.  This is
 * deterministic across all servers, ensuring consistent promotion during
 * SQUIT when multiple servers independently promote.
 *
 * After promotion, callers MUST call exit_client() on the old primary
 * to propagate S2S QUIT and free the numeric.  The old primary is already
 * removed from all channels here, so exit_client produces no visible QUIT.
 *
 * @param[in] session Session whose primary is departing.
 * @return 0 on success, -1 if no aliases available.
 */
int bounce_promote_alias(struct BouncerSession *session)
{
  int j, k;
  const char *winner_numeric = NULL;
  const char *winner_server = NULL;
  struct Client *alias;
  struct Client *old_primary;
  char old_numeric[6];
  char saved_winner[6];  /* Copy of winner_numeric — pointer invalidated by memmove */
  char saved_server[3];  /* Copy of winner_server — same issue */
  struct Membership *member;
  int winner_idx = -1;
  time_t oldest_time = 0;

  if (session->hs_alias_count <= 0)
    return -1;

  /* A1: Save old primary reference before any changes.
   * May be NULL in SQUIT path (nulled by bounce_prepare_squit_promotions). */
  old_primary = session->hs_client;
  if (old_primary)
    ircd_snprintf(0, old_numeric, sizeof(old_numeric), "%s%s",
                  cli_yxx(cli_user(old_primary)->server), cli_yxx(old_primary));

  /* A0: Tiebreaker — oldest connection (lowest cli_firsttime) */
  for (j = 0; j < session->hs_alias_count; j++) {
    struct Client *candidate = findNUser(session->hs_aliases[j].ba_numeric);
    if (!candidate || !IsBouncerAlias(candidate))
      continue;
    if (!winner_numeric || cli_firsttime(candidate) < oldest_time) {
      oldest_time = cli_firsttime(candidate);
      winner_server = session->hs_aliases[j].ba_server;
      winner_numeric = session->hs_aliases[j].ba_numeric;
      winner_idx = j;
    }
  }

  if (!winner_numeric || winner_idx < 0)
    return -1;

  /* Save winner_numeric and winner_server — they're pointers into
   * hs_aliases[] which will be invalidated by the memmove that removes
   * the winner from the array. */
  ircd_strncpy(saved_winner, winner_numeric, sizeof(saved_winner));
  ircd_strncpy(saved_server, winner_server, sizeof(saved_server));
  winner_numeric = saved_winner;
  winner_server = saved_server;

  alias = findNUser(winner_numeric);
  if (!alias || !IsBouncerAlias(alias))
    return -1;

  Debug((DEBUG_INFO, "bounce_promote_alias: promoting alias %s (server %s) "
         "for session %s/%s",
         winner_numeric, winner_server,
         session->hs_account, session->hs_sessid));

  /* Promote: clear CHFL_ALIAS on all channel memberships, restore modes */
  for (member = cli_user(alias)->channel; member;
       member = member->next_channel) {
    if (IsMemberAlias(member)) {
      struct Channel *chptr = member->channel;

      member->status &= ~CHFL_ALIAS;

      /* Restore mode flags from session replica */
      for (k = 0; k < session->hs_chancount; k++) {
        if (0 == ircd_strcmp(session->hs_channels[k].name, chptr->chname)) {
          member->status |= session->hs_channels[k].modes;
          break;
        }
      }

      /* Fix counters: was tracked in aliases, now in users */
      if (chptr->aliases > 0)
        --chptr->aliases;
      ++chptr->users;
      ++((cli_user(alias))->joined);
      if (!IsSSL(alias) && !IsChannelService(alias))
        ++chptr->nonsslusers;
      if (IsAccount(alias))
        ++chptr->authusers;
    }
  }

  /* Clear alias flags — promoted alias becomes a normal primary.
   * Do NOT set IsBouncerHold: the promoted alias is a live connection,
   * not a ghost.  bounce_should_hold() needs to be able to create a
   * ghost if the promoted alias later disconnects. */
  ClearBouncerAlias(alias);
  cli_user(alias)->alias_primary = NULL;

  /* Update nick timestamp for collision resolution */
  cli_lastnick(alias) = CurrentTime;

  /* Add to nick hash (aliases aren't in nick hash) */
  hAddClient(alias);

  /* Add promoted alias to UserStats.
   *
   * Local aliases (MyUser true) were already counted in UserStats.clients
   * and UserStats.local_clients at register_user (s_user.c:415,
   * Count_unknownbecomesclient).  The alias-setup branch returns at
   * s_user.c:555 before the inv_clients / opers bumps later in
   * register_user, so those counters were NOT picked up at register
   * time and DO need to be incremented here.
   *
   * Remote aliases (created via BX C in bounce_alias_create) bypass all
   * UserStats accounting on this server, so all of clients,
   * local_clients-equivalent (n/a — they're remote), inv_clients and
   * opers need to be picked up here.
   *
   * The cli_serv(...->server)->clients counter is per-server; for &me
   * it's unused (m_check.c reads UserStats.local_clients instead) but
   * for remote servers it's the canonical count, so always bump.  */
  if (!MyUser(alias)) {
    ++UserStats.clients;
    if (UserStats.clients > UserStats.clients_max) {
      UserStats.clients_max = UserStats.clients;
      save_tunefile();
    }
  }
  ++(cli_serv(cli_user(alias)->server)->clients);
  /* UserStats.local_clients: local aliases already counted at register;
   * remote aliases are not local.  Either way, do not bump here. */
  if (IsInvisible(alias))
    ++UserStats.inv_clients;
  if (IsOper(alias) && !IsHideOper(alias) && !IsChannelService(alias) && !IsBot(alias))
    ++UserStats.opers;

  /* Remove promoted alias from hs_aliases[] */
  if (winner_idx < session->hs_alias_count - 1)
    memmove(&session->hs_aliases[winner_idx],
            &session->hs_aliases[winner_idx + 1],
            (session->hs_alias_count - 1 - winner_idx)
              * sizeof(struct BounceAlias));
  session->hs_alias_count--;

  /* Cancel hold timer if running — every HOLDING→ACTIVE transition must do this.
   * Without this, timer_init() on a still-queued timer corrupts the list. */
  if (t_active(&session->hs_hold_timer))
    timer_del(&session->hs_hold_timer);

  /* Update session to point to promoted alias.
   * Transition to ACTIVE — the promoted alias is a live connection. */
  session->hs_client = alias;
  session->hs_state = BOUNCE_ACTIVE;
  session->hs_last_active = CurrentTime;
  session->hs_disconnect_time = 0;
  {
    int was_local = is_local_session(session);
    ircd_strncpy(session->hs_origin, cli_yxx(cli_user(alias)->server),
                  sizeof(session->hs_origin) - 1);
    /* Session moved to a different server — delete stale MDBX record.
     * Without this, both servers persist the session and both restore
     * a ghost on restart, causing a nick collision on link. */
    if (was_local && !is_local_session(session))
      bounce_db_del(session->hs_sessid);
  }

  /* A2: Update remaining aliases' alias_primary to point to new primary.
   * Must happen BEFORE A4 (remove old_primary from channels) so that
   * bounce_sync_alias_part() finds no aliases pointing to old_primary. */
  for (j = 0; j < session->hs_alias_count; j++) {
    struct Client *sibling = findNUser(session->hs_aliases[j].ba_numeric);
    if (sibling && IsBouncerAlias(sibling))
      cli_user(sibling)->alias_primary = alias;
  }

  /* A0b/A3: Broadcast BX P + BS T to all servers.
   * In SQUIT path old_primary is NULL — use winner_numeric as fallback
   * (remote handlers will find old_client=NULL and forward as no-op).
   * BS T uses winner_server for consistency when multiple servers
   * independently promote during SQUIT. */
  sendcmdto_serv_butone(&me, CMD_BOUNCER_TRANSFER, NULL,
                        "P %s %s %s %s",
                        old_primary ? old_numeric : winner_numeric,
                        winner_numeric,
                        session->hs_sessid, cli_name(alias));
  sendcmdto_serv_butone(&me, CMD_BOUNCER_SESSION, NULL,
                        "T %s %s %s",
                        session->hs_account, session->hs_sessid,
                        winner_server);

  /* A4: Remove old primary from channels silently.
   * After this, callers' exit_client() produces no visible QUIT
   * (sendcmdto_common_channels_butone is a no-op with no channels). */
  if (old_primary)
    remove_user_from_all_channels(old_primary);

  return 0;
}

/** Prepare bouncer sessions for SQUIT promotion.
 * Called from exit_client() BEFORE exit_downlinks().
 *
 * For each session whose managing server (hs_origin) matches the departing
 * server: remove co-located alias entries, and if any aliases survive on
 * other servers, set hs_promoting to suppress bounce_sync_alias_part()
 * during the subsequent exit_downlinks() pass.
 *
 * @param[in] server The departing server.
 */
void bounce_prepare_squit_promotions(struct Client *server)
{
  int i, j;
  struct BouncerSession *session;
  const char *departed_yxx = cli_yxx(server);

  for (i = 0; i < BOUNCE_TOKEN_HASHSIZE; i++) {
    for (session = tokenHash[i]; session; session = session->hs_tnext) {
      /* Only sessions managed by the departing server */
      if (0 != ircd_strcmp(session->hs_origin, departed_yxx))
        continue;

      /* Remove alias entries hosted on the departing server */
      j = 0;
      while (j < session->hs_alias_count) {
        if (0 == ircd_strcmp(session->hs_aliases[j].ba_server, departed_yxx)) {
          /* Shift remaining entries down */
          if (j < session->hs_alias_count - 1)
            memmove(&session->hs_aliases[j], &session->hs_aliases[j + 1],
                    (session->hs_alias_count - 1 - j) * sizeof(struct BounceAlias));
          session->hs_alias_count--;
          /* Don't increment j — shifted entry now at j */
        } else {
          j++;
        }
      }

      /* If any aliases survive, mark for promotion */
      if (session->hs_alias_count > 0) {
        session->hs_promoting = 1;
        /* Null hs_client BEFORE exit_downlinks frees the old primary.
         * bounce_promote_alias() checks old_primary for NULL to handle
         * the SQUIT path correctly (skip numeric construction, skip
         * channel removal since exit_downlinks already cleaned up). */
        session->hs_client = NULL;
        Debug((DEBUG_INFO, "bounce_prepare_squit: session %s/%s has %d "
               "surviving aliases, marking for promotion",
               session->hs_account, session->hs_sessid,
               session->hs_alias_count));
      } else {
        /* No surviving aliases — session enters HOLDING from MDBX on reconnect */
        session->hs_client = NULL;
        Debug((DEBUG_INFO, "bounce_prepare_squit: session %s/%s has no "
               "surviving aliases", session->hs_account, session->hs_sessid));
      }
    }
  }
}

/** Execute SQUIT promotions for bouncer sessions.
 * Called from exit_client() AFTER exit_downlinks().
 *
 * For each session marked hs_promoting, delegates to bounce_promote_alias()
 * for the actual promotion logic (tiebreaker, counter fixup, broadcast).
 *
 * @param[in] server The departing server (for logging).
 */
void bounce_execute_squit_promotions(struct Client *server)
{
  int i;
  struct BouncerSession *session;

  for (i = 0; i < BOUNCE_TOKEN_HASHSIZE; i++) {
    for (session = tokenHash[i]; session; session = session->hs_tnext) {
      if (!session->hs_promoting)
        continue;

      session->hs_promoting = 0;

      if (bounce_promote_alias(session) != 0) {
        /* No viable alias — session becomes orphaned */
        session->hs_client = NULL;
        Debug((DEBUG_INFO, "bounce_execute_squit: no alias to promote "
               "for session %s/%s",
               session->hs_account, session->hs_sessid));
      }
    }
  }
}

/* ---------------------------------------------------------------- */
/* Hold mode                                                         */
/* ---------------------------------------------------------------- */

/** Check if a client should enter bouncer hold mode on disconnect.
 * Returns the session if:
 * - Bouncer feature is enabled
 * - Client has an account
 * - Client has an active session attached
 * - Hold is enabled (per-session, account, or default)
 */
struct BouncerSession *bounce_should_hold(struct Client *cptr)
{
  struct AccountSessions *as;
  struct BouncerSession *s;
  int class_bouncer = 0;
  struct ConnectionClass *cls;

  /* Forced exits: never hold a /KILL'd user */
  if (HasFlag(cptr, FLAG_KILLED))
    return NULL;
  if (!bounce_enabled_for(cptr))
    return NULL;
  if (!IsAccount(cptr))
    return NULL;
  if (!MyUser(cptr))
    return NULL;  /* Only local clients can enter hold on this server */

  /* Check if client's connection class forces bouncer behavior */
  cls = get_client_class_conf(cptr);
  if (cls && FlagHas(&cls->restrictflags, CRFLAG_BOUNCER))
    class_bouncer = 1;

  /* Find an ACTIVE session attached to this client */
  as = bounce_find_by_account(cli_account(cptr));
  if (!as)
    return NULL;

  for (s = as->as_sessions; s; s = s->hs_anext) {
    if (s->hs_client == cptr && s->hs_state == BOUNCE_ACTIVE) {
      /* Check hold preference: session override > user mode/metadata > default */
      int should_hold;
      if (s->hs_hold_override >= 0) {
        should_hold = s->hs_hold_override;
      } else if (IsBncHoldPref(cptr)) {
        /* User has +b mode set (synced with $bouncer/hold metadata) */
        should_hold = 1;
      } else {
        /* Check persistent metadata — cli_metadata may not be populated
         * after a restart; metadata_account_get reads from mdbx. */
        char hold_val[64];
        if (metadata_account_get(cli_account(cptr), "bouncer/hold", hold_val) == 0) {
          should_hold = (hold_val[0] != '0');
        } else {
          /* Bouncer class defaults to hold; normal class follows feature flag */
          should_hold = class_bouncer || feature_bool(FEAT_BOUNCER_DEFAULT_HOLD);
        }
      }

      if (should_hold)
        return s;
      break;  /* Found client's session but hold disabled */
    }
  }

  return NULL;
}

/** Transition a client to bouncer HOLDING state (ghost mode).
 * This is called from s_bsd.c when a disconnect is detected and
 * bounce_should_hold() returned a session.
 */
int bounce_hold_client(struct Client *cptr, const char *comment)
{
  struct BouncerSession *session;
  struct Membership *member;
  int hold_time;

  session = bounce_should_hold(cptr);
  if (!session)
    return -1;

  /* Mark client as a ghost */
  SetBouncerHold(cptr);

  /* Snapshot channel memberships into session */
  bounce_snapshot_channels(session, cptr);

  /* Mark all channel memberships as HOLDING */
  for (member = cli_user(cptr)->channel; member; member = member->next_channel)
    SetMemberHolding(member);

  /* Save the user's idle time (last PRIVMSG) for auto-replay and persistence.
   * After a restart, the ghost's user->last is lost; this session-level
   * copy survives via MDBX so replay knows how far back to go. */
  if (cli_user(cptr) && cli_user(cptr)->last > 0)
    session->hs_last_msg_time = cli_user(cptr)->last;

  /* Transition session to HOLDING state.
   * Keep hs_client pointing to the ghost for cleanup on expiry.
   * Save ghost numeric for cross-server transfer.
   */
  session->hs_state = BOUNCE_HOLDING;
  session->hs_disconnect_time = CurrentTime;
  ircd_strncpy(session->hs_ghost_numeric, cli_yxx(cptr), sizeof(session->hs_ghost_numeric) - 1);
  session->hs_ghost_numeric[sizeof(session->hs_ghost_numeric) - 1] = '\0';
  /* hs_client still points to cptr (now a ghost) */

  /* Start hold timer */
  hold_time = feature_int(FEAT_BOUNCER_SESSION_HOLD);
  timer_init(&session->hs_hold_timer);
  timer_add(&session->hs_hold_timer, bounce_hold_expire,
            (void *)session, TT_RELATIVE, hold_time);

  /* Broadcast detach to all servers (sends channel list for cross-server) */
  bounce_broadcast(session, 'D', NULL);

  /* Close the socket but keep the client structure alive.
   * Note: We do NOT call exit_client() here - that would destroy the client.
   * We only want to close the socket connection.
   */
  close_connection(cptr);

  /* Log the hold */
  log_write(LS_USER, L_TRACE, 0, "Bouncer HOLD: %s (%s@%s) session %s - %s",
            cli_name(cptr), cli_user(cptr)->username,
            cli_user(cptr)->realhost, session->hs_sessid, comment);

  /* Note: The client structure remains in memory, in all channels,
   * with FLAG_BOUNCER_HOLD set. It will not receive messages but
   * is visible (as a ghost) in WHO/NAMES until resumed or expired.
   */

  /* Roll primary connection's data counters into session aggregates.
   * The ghost's counters become stale once the socket is gone; zero
   * them so a future revive starts fresh. */
  bounce_accumulate_and_reset_primary(session, cptr);

  /* Record disconnect event in connection history */
  bounce_history_disconnect(session, cli_sock_ip(cptr));

  /* Persist with full ghost identity + channels */
  bounce_db_put(session);

  return 0;
}

/** Revive a ghost client by transplanting a socket from a temp client.
 *
 * Instead of creating a new client and transferring channels from ghost,
 * this transplants the temp client's socket directly onto the ghost Client
 * struct, keeping the ghost's nick, numeric, and channel memberships.
 *
 * This avoids nick collisions on legacy networks because no new client
 * is introduced to the network — the ghost simply "wakes up" with the
 * new socket attached.
 *
 * Handles two cases:
 * 1. HOLDING session: Ghost disconnected and holding. Normal revive.
 * 2. ACTIVE relay-only: Ghost has no local socket (cli_fd == -1), only
 *    remote aliases provide connectivity. A local client connecting
 *    to the managing server becomes the primary via socket transplant.
 *
 * @param[in] session The HOLDING or ACTIVE relay-only session.
 * @param[in] temp The temporary client whose socket will be transplanted.
 *                 This client will be freed (locally, no network messages).
 * @return 0 on success, -1 on error.
 */
int bounce_revive(struct BouncerSession *session, struct Client *temp)
{
  struct Client *ghost;
  struct Connection *ghost_con;
  struct Connection *temp_con;
  struct Membership *member;
  int fd;
  int was_holding;

  if (!session)
    return -1;

  ghost = session->hs_client;
  if (!ghost || !MyUser(ghost))
    return -1;

  if (session->hs_state == BOUNCE_HOLDING) {
    /* Normal revive from hold state */
    if (!IsBouncerHold(ghost))
      return -1;
    was_holding = 1;
  } else if (session->hs_state == BOUNCE_ACTIVE) {
    /* Relay-only promotion: ghost has no local socket, remote alias(es)
     * provide connectivity. Local client should become primary. */
    if (cli_fd(ghost) >= 0)
      return -1;  /* Ghost has a local socket — use alias-attach instead */
    was_holding = 0;
  } else {
    return -1;
  }

  if (!temp || !MyConnect(temp))
    return -1;

  ghost_con = cli_connect(ghost);
  temp_con = cli_connect(temp);

  if (!ghost_con || !temp_con)
    return -1;

#ifdef USE_SSL
  /* Gate: Refuse revival if ghost is in +Z channels and temp is plaintext.
   * A non-TLS connection cannot be in SSL-only channels. */
  if (!con_socket(temp_con).ssl && cli_user(ghost)) {
    for (member = cli_user(ghost)->channel; member; member = member->next_channel) {
      if (member->channel->mode.exmode & EXMODE_SSLONLY) {
        Debug((DEBUG_INFO,
               "Bouncer: refusing revival for %s - plaintext connection, ghost in +Z channel %s",
               cli_name(ghost), member->channel->chname));
        /* Send a helpful error to the temp client */
        sendrawto_one(temp,
          ":%s NOTE BOUNCER TLS_REQUIRED "
          ":Cannot resume session - session is in SSL-only (+Z) channels. "
          "Connect with TLS to resume.",
          cli_name(&me));
        return -1;  /* Fall back to normal registration */
      }
    }
  }
#endif

  Debug((DEBUG_INFO, "Bouncer: reviving ghost %s with socket from temp %s (fd %d)",
         cli_name(ghost), cli_name(temp), cli_fd(temp)));

  if (was_holding) {
    /* Mark session as ACTIVE before canceling timer.
     * This prevents a race where an already-queued ET_EXPIRE event
     * (processed after timer_del but before we reach the state update
     * at the end of this function) could trigger bounce_hold_expire
     * to destroy the session while we're still reviving it. */
    session->hs_state = BOUNCE_ACTIVE;

    /* Cancel hold timer if running */
    if (t_active(&session->hs_hold_timer))
      timer_del(&session->hs_hold_timer);
  }

  /* Step 1: Steal the temp client's fd and SSL.
   * Clear s_data BEFORE socket_del to prevent stale callbacks.
   * IMPORTANT: Also save and NULL the SSL pointer BEFORE socket_del,
   * because socket_del triggers ET_DESTROY which calls ssl_free().
   * If we don't NULL it first, the SSL context gets freed before we
   * can transfer it to the ghost.
   * EQUALLY CRITICAL: use socket_del_keepfd so the engine unregisters
   * fd (epoll_ctl DEL runs while s_fd is still valid) but ET_DESTROY's
   * close() is skipped (s_fd is zeroed between eng_closing and the
   * destroy event in the synchronous event model).  Clearing s_fd
   * before socket_del (as a plain socket_del variant) breaks eng_closing,
   * leaving the fd registered in epoll — subsequent socket_add on the
   * ghost fails with EEXIST, revive returns -1, and register_user falls
   * back to bounce_attach which silently kills the ghost and introduces
   * a new NICK, colliding with the ghost that's still alive on remote
   * servers (user@host kill from upstream hub). */
  fd = cli_fd(temp);
  s_data(&cli_socket(temp)) = NULL;
#ifdef USE_SSL
  {
    SSL *temp_ssl = con_socket(temp_con).ssl;
    con_socket(temp_con).ssl = NULL;  /* Prevent ssl_free from freeing it */
    socket_del_keepfd(&cli_socket(temp));
    cli_fd(temp) = -1;

    /* Step 2: Ghost's old fd should be -1 from close_connection() during hold.
     * Just verify and update LocalClientArray if somehow it wasn't. */
    if (cli_fd(ghost) >= 0) {
      LocalClientArray[cli_fd(ghost)] = 0;
      close(cli_fd(ghost));
    }

    /* Free ghost's old SSL object (should be NULL from close_connection) */
    if (con_socket(ghost_con).ssl) {
      SSL_free(con_socket(ghost_con).ssl);
      con_socket(ghost_con).ssl = NULL;
    }
    /* Transfer temp's SSL object to ghost */
    con_socket(ghost_con).ssl = temp_ssl;
  }
#else
  socket_del_keepfd(&cli_socket(temp));
  cli_fd(temp) = -1;

  /* Step 2: Ghost's old fd should be -1 from close_connection() during hold.
   * Just verify and update LocalClientArray if somehow it wasn't. */
  if (cli_fd(ghost) >= 0) {
    LocalClientArray[cli_fd(ghost)] = 0;
    close(cli_fd(ghost));
  }
#endif

  /* Step 3: Transplant the fd into the ghost's Connection */
  s_fd(&con_socket(ghost_con)) = fd;

  /* Step 4: Update LocalClientArray */
  LocalClientArray[fd] = ghost;

  /* Step 5: Initialize ghost socket if not already active.
   * For persisted ghosts (restored from MDBX on startup), socket_add was
   * never called, so the socket lacks s_data/s_func/GEN_ACTIVE.
   * For normal ghosts that went into holding, the socket is already
   * initialized from when they originally connected.
   * Use socket_add for uninitialized sockets, socket_reattach for active ones.
   *
   * NOTE: If GEN_DESTROY is set, there may be pending ET_DESTROY event(s)
   * queued from previous socket_del calls (e.g., from prior revival cycles
   * where the user disconnected and re-entered HOLD mode). These stale events
   * are safely handled by atomic s_data claiming in client_sock_callback -
   * the first ET_DESTROY atomically claims s_data, subsequent events see NULL
   * and return early, preventing double-free. */
  Debug((DEBUG_INFO, "Bouncer: ghost %s socket gh_flags=0x%x GEN_ACTIVE=%d s_data=%p",
         cli_name(ghost), cli_socket(ghost).s_header.gh_flags,
         !!(cli_socket(ghost).s_header.gh_flags & GEN_ACTIVE),
         s_data(&cli_socket(ghost))));
  if (!(cli_socket(ghost).s_header.gh_flags & GEN_ACTIVE)) {
    /* Persisted or re-held ghost: socket not active, use socket_add.
     * Note: Any pending stale ET_DESTROY events from previous socket_del
     * calls are handled by the atomic s_data claiming in client_sock_callback. */
    Debug((DEBUG_INFO, "Bouncer: using socket_add for uninitialized ghost socket"));
    if (!socket_add(&cli_socket(ghost), client_sock_callback,
                    (void *)ghost_con, SS_CONNECTED, SOCK_EVENT_READABLE, fd)) {
      Debug((DEBUG_ERROR, "Bouncer: socket_add failed during ghost revival for %s",
             cli_name(ghost)));
      close(fd);
      s_fd(&con_socket(ghost_con)) = -1;
      LocalClientArray[fd] = 0;
      return -1;
    }
    /* CRITICAL: Restore FREEFLAG_SOCKET on the connection.  A previous stale
     * ET_DESTROY may have cleared it.  Without this flag, free_client will go
     * the immediate deallocation path and free the connection, but there could
     * still be pending stale ET_DESTROY events that will then access freed
     * memory.  With FREEFLAG_SOCKET set, free_client properly queues socket_del
     * and waits for ET_DESTROY to free the connection. */
    con_freeflag(ghost_con) |= FREEFLAG_SOCKET;
  } else {
    /* Normal ghost: socket was active, just reattach fd */
    Debug((DEBUG_INFO, "Bouncer: using socket_reattach for active ghost socket"));
    if (!socket_reattach(&cli_socket(ghost), fd)) {
      Debug((DEBUG_ERROR, "Bouncer: socket_reattach failed during ghost revival for %s",
             cli_name(ghost)));
      close(fd);
      s_fd(&con_socket(ghost_con)) = -1;
      LocalClientArray[fd] = 0;
      return -1;
    }
  }

  /* Step 6: Reset socket interest and clear stale flags.
   * FLAG_BLOCKED may be left over from the previous connection (before
   * HOLDING). If not cleared, send_queued() returns immediately and
   * the welcome sequence never gets written — the client hangs. */
  ClrFlag(ghost, FLAG_BLOCKED);
  ClrFlag(ghost, FLAG_DEADSOCKET);
  socket_events(&cli_socket(ghost), SOCK_EVENT_READABLE);

  /* Step 6a: Transfer connection identity from temp to ghost.
   * The ghost's IP, sockhost, port, listener, and confs may be stale
   * (from the original connection) or zeroed (MDBX-restored ghost).
   * Update them to reflect the actual reconnecting client's socket. */
  memcpy(&cli_ip(ghost), &cli_ip(temp), sizeof(cli_ip(ghost)));
  ircd_strncpy(con_sock_ip(ghost_con), con_sock_ip(temp_con), SOCKIPLEN + 1);
  ircd_strncpy(cli_sockhost(ghost), cli_sockhost(temp), HOSTLEN + 1);
  cli_port(ghost) = cli_port(temp);
  memcpy(&cli_connectip(ghost), &cli_connectip(temp), sizeof(cli_connectip(ghost)));
  ircd_strncpy(cli_connecthost(ghost), cli_connecthost(temp), HOSTLEN + 1);

  /* Re-apply GeoIP data based on the new connection's IP */
  geoip_apply(ghost);

  /* Transfer listener reference (temp's ref count transfers to ghost) */
  if (con_listener(ghost_con))
    release_listener(con_listener(ghost_con));
  con_listener(ghost_con) = con_listener(temp_con);
  con_listener(temp_con) = NULL;

  /* Transfer I-line confs from temp to ghost.
   * Ghost may have stale confs (from original connection) or none
   * (MDBX-restored). Detach ghost's old confs, then move temp's. */
  det_confs_butmask(ghost, 0);
  con_confs(ghost_con) = con_confs(temp_con);
  con_confs(temp_con) = NULL;

  /* Step 6b: Reset data counters and update connection identity.
   * Ghost's data counters may be stale from a prior connection (or from
   * MDBX restore). Roll them into session aggregates, then zero so the
   * new connection starts fresh. Also update the primary connection
   * timestamp and ID to reflect this new connection. */
  bounce_accumulate_and_reset_primary(session, ghost);
  cli_firsttime(ghost) = cli_firsttime(temp);
  /* Record connect event in connection history */
  bounce_history_connect(session, con_sock_ip(ghost_con),
                         cli_sockhost(ghost));

  /* Step 7: Transfer sendQ/recvQ from temp to ghost */
  MsgQClear(&con_sendQ(ghost_con));
  con_sendQ(ghost_con) = con_sendQ(temp_con);
  msgq_init(&con_sendQ(temp_con));

  DBufClear(&con_recvQ(ghost_con));
  con_recvQ(ghost_con) = con_recvQ(temp_con);
  memset(&con_recvQ(temp_con), 0, sizeof(con_recvQ(temp_con)));

  /* Step 8: Copy CAP state from temp to ghost */
  memcpy(con_capab(ghost_con), con_capab(temp_con), sizeof(struct CapSet));
  memcpy(con_active_own(ghost_con), con_active_own(temp_con), sizeof(struct CapSet));
  memcpy(con_active(ghost_con), con_active_own(temp_con), sizeof(struct CapSet));
  con_capab_version(ghost_con) = con_capab_version(temp_con);

  /* Step 9: Update timing */
  con_lasttime(ghost_con) = con_lasttime(temp_con);
  con_since(ghost_con) = con_since(temp_con);

#ifdef USE_SSL
  /* Step 10: Update FLAG_SSL and channel nonsslusers counters */
  {
    int was_ssl = IsSSL(ghost);
    int now_ssl = (con_socket(ghost_con).ssl != NULL);
    if (now_ssl && !was_ssl) {
      SetSSL(ghost);
      if (cli_user(ghost)) {
        for (member = cli_user(ghost)->channel; member; member = member->next_channel)
          if (member->channel->nonsslusers > 0)
            member->channel->nonsslusers--;
      }
    } else if (!now_ssl && was_ssl) {
      ClearSSL(ghost);
      if (cli_user(ghost)) {
        for (member = cli_user(ghost)->channel; member; member = member->next_channel)
          member->channel->nonsslusers++;
      }
    }
  }
#endif

  /* Step 11: Clear holding flags on ghost */
  if (was_holding) {
    ClearBouncerHold(ghost);
    /* Step 12: Clear CHFL_HOLDING on all channel memberships */
    if (cli_user(ghost)) {
      for (member = cli_user(ghost)->channel; member; member = member->next_channel) {
        ClearMemberHolding(member);
      }
    }
  }
  ClrFlag(ghost, FLAG_DEADSOCKET);

  /* Step 13: Update session state (hs_state already set to ACTIVE earlier) */
  session->hs_client = ghost;
  session->hs_attach_count++;
  session->hs_connect_count++;
  session->hs_last_active = CurrentTime;
  session->hs_disconnect_time = 0;

  /* Session is live again — remove persisted state (only HOLDING sessions persist) */
  if (was_holding)
    bounce_db_del(session->hs_sessid);

  /* Recompute session union caps */
  bounce_recompute_session_caps(ghost);

  /* Broadcast session attach to other servers */
  bounce_broadcast(session, 'A', cli_yxx(ghost));

  log_write(LS_USER, L_TRACE, 0,
            "Bouncer: ghost %s %s via socket transplant for session %s",
            cli_name(ghost),
            was_holding ? "revived" : "promoted to primary",
            session->hs_sessid);

  return 0;
}

/** Free a temporary client after socket transplant.
 *
 * The temp client's socket has been stolen by bounce_revive().
 * This function frees the temp client WITHOUT:
 * - Sending QUIT to network (it was never introduced)
 * - Closing the fd (it was stolen)
 * - Double-freeing auth request
 *
 * @param[in] temp Temporary client to free.
 */
void bounce_free_temp_client(struct Client *temp)
{
  if (!temp)
    return;

  Debug((DEBUG_INFO, "Bouncer: freeing temp client %s after socket transplant",
         cli_name(temp)));

  /* Detach auth request to prevent double-free.
   * check_auth_finished() will try to destroy it later otherwise. */
  if (cli_auth(temp)) {
    auth_detach_client(cli_auth(temp));
    cli_auth(temp) = NULL;
  }

  /* fd should already be -1 from bounce_revive() */
  assert(cli_fd(temp) == -1);
  SetFlag(temp, FLAG_DEADSOCKET);

  /* Balance accounting from registration before tearing down.  By the time
   * we get here the temp has run through Count_unknownbecomesclient
   * (--unknowns; ++local_clients; ++clients) and IPcheck_local_connect
   * (entry->connected++).  remove_client_from_list/free_client touch none
   * of those counters, and we're skipping exit_one_client entirely, so
   * without explicit decrements every successful revive leaks +1 each in
   * UserStats.local_clients, UserStats.clients, and the per-IP IPcheck slot.
   * Must run while cli_status is still STAT_USER and cli_user is intact —
   * Count_clientdisconnects reads cli_sockhost via the macro. */
  if (MyConnect(temp) && IsUser(temp))
    Count_clientdisconnects(temp, UserStats);
  if (IsIPChecked(temp)) {
    IPcheck_disconnect(temp);
    ClearIPChecked(temp);
  }

  /* Remove from nick hash if present.
   * Temp client was added by m_nick during registration. */
  if (cli_name(temp)[0])
    hRemClient(temp);

  /* Prevent QUIT broadcast and WHOWAS history - client was never introduced
   * to network. Must be done before remove_client_from_list.
   * - server = NULL prevents sendcmdto_serv_butone in free_user
   * - Clearing STAT_USER prevents add_history call which crashes on NULL server */
  if (cli_user(temp)) {
    cli_user(temp)->server = NULL;
  }
  cli_status(temp) = STAT_UNKNOWN;

  /* Remove from global client list and free client.
   * Note: remove_client_from_list calls free_client internally. */
  remove_client_from_list(temp);
}

/* ---------------------------------------------------------------- */
/* Alias channel auto-sync                                           */
/* ---------------------------------------------------------------- */

/** Sync alias join: when primary joins a channel, add local aliases.
 * Called from add_user_to_channel() for non-alias members.
 * Iterates the primary's session aliases and adds any local ones
 * to the channel with CHFL_ALIAS.
 */
void bounce_sync_alias_join(struct Channel *chptr, struct Client *who)
{
  struct AccountSessions *as;
  struct BouncerSession *session;
  int i;

  if (!IsAccount(who) || IsBouncerAlias(who))
    return;

  as = bounce_find_by_account(cli_user(who)->account);
  if (!as)
    return;

  for (session = as->as_sessions; session; session = session->hs_anext) {
    for (i = 0; i < session->hs_alias_count; i++) {
      struct Client *alias = findNUser(session->hs_aliases[i].ba_numeric);
      if (alias && IsBouncerAlias(alias)
          && cli_alias_primary(alias) == who
          && !find_member_link(chptr, alias)) {
        /* Skip +Z channels for non-TLS aliases */
        if ((chptr->mode.exmode & EXMODE_SSLONLY) && !IsSSL(alias)) {
          sendcmdto_one(&me, CMD_NOTICE, alias,
            "%C :Not joining %s \xe2\x80\x94 channel requires TLS (+Z) "
            "but your connection is plaintext. Reconnect with TLS to join.",
            alias, chptr->chname);
          continue;
        }
        /* Copy primary's channel mode flags so operator commands and
         * @#channel delivery work for the alias. */
        {
          struct Membership *pmem = find_member_link(chptr, who);
          unsigned int aflags = CHFL_ALIAS;
          unsigned short aoplevel = MAXOPLEVEL;
          if (pmem) {
            aflags |= (pmem->status & (CHFL_CHANOP | CHFL_HALFOP | CHFL_VOICE));
            aoplevel = OpLevel(pmem);
          }
          add_user_to_channel(chptr, alias, aflags, aoplevel);
        }
      }
    }
  }
}

/** Send post-join replies (TOPIC, MARKREAD, NAMES) to all local aliases
 * of the given primary in the channel.  Each alias gets do_names called
 * with its own client so per-connection caps (UHNAMES etc.) are respected.
 * Must be called AFTER the JOIN echo so clients see JOIN before NAMES.
 */
void bounce_send_alias_join_replies(struct Channel *chptr, struct Client *who)
{
  struct Membership *member;

  if (!chptr || !who || !IsAccount(who) || IsBouncerAlias(who))
    return;

  /* Send to the primary itself if local. */
  if (MyConnect(who)) {
    if (chptr->topic[0]) {
      send_reply(who, RPL_TOPIC, chptr->chname, chptr->topic);
      send_reply(who, RPL_TOPICWHOTIME, chptr->chname, chptr->topic_nick,
                 chptr->topic_time);
    }
    send_markread_on_join(who, chptr->chname);
    if (!HasCap(who, CAP_DRAFT_NOIMPLICITNAMES))
      do_names(who, chptr, NAMES_ALL|NAMES_EON);
  }

  /* Send to each local alias with per-connection caps. */
  for (member = chptr->members; member; member = member->next_member) {
    struct Client *acli = member->user;
    if (!IsMemberAlias(member) || !MyConnect(acli))
      continue;
    if (cli_alias_primary(acli) != who)
      continue;
    if (chptr->topic[0]) {
      send_reply(acli, RPL_TOPIC, chptr->chname, chptr->topic);
      send_reply(acli, RPL_TOPICWHOTIME, chptr->chname, chptr->topic_nick,
                 chptr->topic_time);
    }
    send_markread_on_join(acli, chptr->chname);
    if (!HasCap(acli, CAP_DRAFT_NOIMPLICITNAMES))
      do_names(acli, chptr, NAMES_ALL|NAMES_EON);
  }

}

/** Sync alias part: when primary leaves a channel, remove local aliases.
 * Called from remove_user_from_channel() for non-alias members.
 * Iterates channel members and removes any aliases of the departing primary.
 */
void bounce_sync_alias_part(struct Channel *chptr, struct Client *who)
{
  struct BouncerSession *sess;
  struct Membership *member, *next;

  if (IsBouncerAlias(who))
    return;

  /* During SQUIT promotion, aliases must stay in channels so the
   * promoted alias inherits channel memberships without a gap. */
  if (IsAccount(who)) {
    sess = bounce_get_session(who);
    if (sess && sess->hs_promoting)
      return;
  }

  for (member = chptr->members; member; member = next) {
    next = member->next_member;
    if (IsMemberAlias(member) && cli_alias_primary(member->user) == who) {
      remove_user_from_channel(member->user, chptr);
    }
  }
}

/** Sync channel mode flags from primary to all aliases in the channel.
 * Called after the primary's CHFL_CHANOP/HALFOP/VOICE status changes
 * (e.g. from mode_process_clients() or CLEARMODE) so that aliases
 * inherit the same operator/voice status for command permissions and
 * @#channel message delivery.
 */
void bounce_sync_alias_chanmodes(struct Channel *chptr, struct Client *primary)
{
  struct Membership *member;
  struct Membership *primary_member;
  unsigned int mode_bits;
  unsigned short oplevel;

  if (!chptr || !primary || !IsAccount(primary) || IsBouncerAlias(primary))
    return;

  primary_member = find_member_link(chptr, primary);
  if (!primary_member)
    return;

  mode_bits = primary_member->status & (CHFL_CHANOP | CHFL_HALFOP | CHFL_VOICE);
  oplevel = OpLevel(primary_member);

  for (member = chptr->members; member; member = member->next_member) {
    if (!IsMemberAlias(member))
      continue;
    if (cli_alias_primary(member->user) != primary)
      continue;
    /* Replace mode bits, preserve CHFL_ALIAS and other flags */
    member->status = (member->status & ~(CHFL_CHANOP | CHFL_HALFOP | CHFL_VOICE))
                   | mode_bits;
    SetOpLevel(member, oplevel);
  }
}

/* ---------------------------------------------------------------- */
/* PM forwarding to aliases                                          */
/* ---------------------------------------------------------------- */

/** Forward a private message or notice to all aliases of the target.
 * When a PM/NOTICE is delivered to a bouncer primary, this function
 * forwards it to all alias connections so every bouncer connection
 * receives the message.
 *
 * @param[in] from    Client that sent the message.
 * @param[in] target  Target client (must be the primary, not an alias).
 * @param[in] cmd     Long command name (MSG_PRIVATE or MSG_NOTICE).
 * @param[in] tok     Short command token (TOK_PRIVATE or TOK_NOTICE).
 * @param[in] text    Message text.
 */
void bounce_forward_pm_to_aliases(struct Client *from, struct Client *target,
                                  const char *cmd, const char *tok,
                                  const char *text, const char *msgid)
{
  struct BouncerSession *sess;
  int i;

  /* Only forward for bouncer primaries with aliases */
  if (!IsAccount(target) || IsBouncerAlias(target))
    return;

  sess = bounce_get_session(target);
  if (!sess || sess->hs_alias_count <= 0)
    return;

  for (i = 0; i < sess->hs_alias_count; i++) {
    struct Client *alias = findNUser(sess->hs_aliases[i].ba_numeric);
    if (alias && alias != target && IsBouncerAlias(alias))
      sendcmdto_one_tags_ext(from, cmd, tok, alias, msgid,
                             "%C :%s", alias, text);
  }
}

/* ---------------------------------------------------------------- */
/* PM echo: mirror outgoing PMs to other session members              */
/* ---------------------------------------------------------------- */

/** Echo an outgoing PM/NOTICE to all other members of the sender's session.
 * When any session member (primary or alias) sends a PM, the other members
 * need to see it so the conversation appears complete on all connections.
 *
 * For local members: direct client-format delivery.
 * For remote members: BX E token (see bounce_alias_echo handler).
 *
 * @param[in] sender  Client that sent the PM (primary or alias).
 * @param[in] target  PM recipient (external user).
 * @param[in] cmd     Long command name (e.g. "PRIVMSG").
 * @param[in] tok     Short command token (e.g. "P").
 * @param[in] text    Message text.
 * @param[in] msgid   Message ID for tags (may be NULL or empty).
 */
void bounce_echo_pm_to_session(struct Client *sender, struct Client *target,
                               const char *cmd, const char *tok,
                               const char *text, const char *msgid)
{
  struct Client *primary;
  struct BouncerSession *sess;
  int i;

  /* Determine session primary */
  if (IsBouncerAlias(sender) && cli_user(sender)
      && cli_user(sender)->alias_primary)
    primary = cli_user(sender)->alias_primary;
  else
    primary = sender;

  if (!IsAccount(primary))
    return;

  sess = bounce_get_session(primary);
  if (!sess || sess->hs_alias_count <= 0)
    return;

  /* Guard: skip echo for self-PMs (target is a session member) */
  if (target == primary)
    return;
  for (i = 0; i < sess->hs_alias_count; i++) {
    struct Client *a = findNUser(sess->hs_aliases[i].ba_numeric);
    if (a && a == target)
      return;
  }

  /* Normalize empty msgid */
  if (msgid && !*msgid)
    msgid = NULL;

  /* Echo to primary (if sender is not the primary) */
  if (sender != primary) {
    if (MyConnect(primary)) {
      sendcmdto_one_tags_ext(primary, cmd, tok, primary, msgid,
                             "%s :%s", cli_name(target), text);
    } else {
      char nn[6];
      ircd_snprintf(0, nn, sizeof(nn), "%s%s", NumNick(primary));
      sendcmdto_one(&me, CMD_BOUNCER_TRANSFER, primary,
          "E %s %s%s %s %s %s :%s",
          nn, NumNick(primary), tok, cli_name(target),
          msgid ? msgid : "*", text);
    }
  }

  /* Echo to aliases (except the sender) */
  for (i = 0; i < sess->hs_alias_count; i++) {
    struct Client *alias = findNUser(sess->hs_aliases[i].ba_numeric);
    if (!alias || !IsBouncerAlias(alias) || alias == sender)
      continue;

    if (MyConnect(alias)) {
      sendcmdto_one_tags_ext(primary, cmd, tok, alias, msgid,
                             "%s :%s", cli_name(target), text);
    } else {
      sendcmdto_one(&me, CMD_BOUNCER_TRANSFER, alias,
          "E %s %s%s %s %s %s :%s",
          sess->hs_aliases[i].ba_numeric,
          NumNick(primary), tok, cli_name(target),
          msgid ? msgid : "*", text);
    }
  }
}

/* ---------------------------------------------------------------- */
/* BX U emission: broadcast alias identity updates                    */
/* ---------------------------------------------------------------- */

/** Broadcast BX U identity updates to all aliases of a primary.
 * Called when a user's visible identity changes (sethost, setname,
 * fakehost, etc.) to keep alias Clients in sync.
 *
 * @param[in] primary The primary client whose identity changed.
 * @param[in] field   Field name (host, realname, fakehost, etc.).
 * @param[in] value   New value for the field.
 */
void bounce_emit_alias_update(struct Client *primary, const char *field,
                              const char *value)
{
  struct BouncerSession *sess;
  int i;

  if (!IsAccount(primary) || IsBouncerAlias(primary))
    return;

  sess = bounce_get_session(primary);
  if (!sess || sess->hs_alias_count <= 0)
    return;

  for (i = 0; i < sess->hs_alias_count; i++) {
    sendcmdto_serv_butone(&me, CMD_BOUNCER_TRANSFER, NULL,
                          "U %s %s=%s",
                          sess->hs_aliases[i].ba_numeric, field, value);
  }
}

/** User mode flags that should be synchronized between primary and aliases.
 * These are the user-visible mode flags (o, w, i, g, etc.) plus internal
 * oper tracking flags.  Internal state flags like FLAG_BOUNCER_ALIAS,
 * FLAG_IPCHECK, etc. are NOT synchronized.
 */
static const int umode_sync_flags[] = {
  FLAG_OPER, FLAG_LOCOP, FLAG_INVISIBLE, FLAG_WALLOP,
  FLAG_DEAF, FLAG_CHSERV, FLAG_DEBUG, FLAG_WHOIS_NOTICE,
  FLAG_HIDE_OPER, FLAG_NOIDLE, FLAG_NOCHAN, FLAG_COMMONCHANSONLY,
  FLAG_ACCOUNTONLY, FLAG_BOT, FLAG_PRIVDEAF, FLAG_ADMIN,
  FLAG_XTRAOP, FLAG_NOLINK, FLAG_MULTILINE_EXPAND, FLAG_NOSTORAGE,
  FLAG_OPERED_LOCAL, FLAG_OPERED_REMOTE,
  FLAG_CLOAKIP, FLAG_CLOAKHOST, FLAG_SSL,
  -1
};

/** Copy user mode flags from one client to another.
 * Only copies the flags listed in umode_sync_flags[].
 * @param[in]  from Source client (usually the primary).
 * @param[out] to   Destination client (usually an alias).
 */
static void bounce_copy_umodes(struct Client *from, struct Client *to)
{
  int i;
  for (i = 0; umode_sync_flags[i] >= 0; i++) {
    if (HasFlag(from, umode_sync_flags[i]))
      SetFlag(to, umode_sync_flags[i]);
    else
      ClrFlag(to, umode_sync_flags[i]);
  }
}

/** Synchronize user mode flags from the primary to all its aliases.
 * Call after any mode change on the primary.
 * @param[in] primary The primary client whose modes changed.
 */
void bounce_sync_alias_umodes(struct Client *primary)
{
  struct BouncerSession *sess;
  int i;

  if (!IsUser(primary) || IsBouncerAlias(primary))
    return;

  sess = bounce_get_session(primary);
  if (!sess || sess->hs_alias_count <= 0)
    return;

  for (i = 0; i < sess->hs_alias_count; i++) {
    struct Client *alias = findNUser(sess->hs_aliases[i].ba_numeric);
    if (alias && IsBouncerAlias(alias)) {
      bounce_copy_umodes(primary, alias);
      if (MyConnect(alias)) {
        /* Local alias: sync oper privileges, handler, and snomask directly */
        if (IsOper(primary)) {
          memcpy(&cli_privs(alias), &cli_privs(primary), sizeof(cli_privs(alias)));
          cli_handler(alias) = OPER_HANDLER;
        }
        set_snomask(alias, cli_snomask(primary), SNO_SET);
      } else {
        /* Remote alias: tell its server to set snomask via BX K */
        sendcmdto_one(&me, CMD_BOUNCER_TRANSFER, alias,
                      "K %s %u", sess->hs_aliases[i].ba_numeric,
                      cli_snomask(primary));
      }
    }
  }
}

/* ---------------------------------------------------------------- */
/* Cross-server transfer (BT token)                                  */
/* ---------------------------------------------------------------- */

/** Handle BT (Bouncer Transfer) P10 message.
 * Format: BT <old-numeric> <new-numeric> <session-id>
 *
 * BX subcommand dispatch for multi-server bouncer presence.
 *
 * Subcommands:
 *   BX C <primary> <alias> <account> <sessid> [<modes>] :<channels>  -- Create alias
 *   BX X <alias>                                           -- Destroy alias
 *   BX P <old> <new> <sessid> <nick>                       -- Promote/transfer
 *   BX N <primary> <new_nick> <ts>                         -- Nick sync
 *   BX U <alias> <field>=<value>                           -- Identity update
 */

/* Forward declarations for BX subcommand handlers */
static int bounce_alias_create(struct Client *cptr, struct Client *sptr, int parc, char *parv[]);
static int bounce_alias_destroy(struct Client *cptr, struct Client *sptr, int parc, char *parv[]);
static int bounce_alias_promote(struct Client *cptr, struct Client *sptr, int parc, char *parv[]);
static int bounce_alias_nicksync(struct Client *cptr, struct Client *sptr, int parc, char *parv[]);
static int bounce_alias_update(struct Client *cptr, struct Client *sptr, int parc, char *parv[]);
static int bounce_alias_echo(struct Client *cptr, struct Client *sptr, int parc, char *parv[]);
static int bounce_alias_snomask(struct Client *cptr, struct Client *sptr, int parc, char *parv[]);

int bounce_handle_bt(struct Client *cptr, struct Client *sptr,
                     int parc, char *parv[])
{
  char subcmd;

  if (parc < 2)
    return 0;

  subcmd = parv[1][0];

  switch (subcmd) {
  case 'C':
    return bounce_alias_create(cptr, sptr, parc, parv);
  case 'X':
    return bounce_alias_destroy(cptr, sptr, parc, parv);
  case 'P':
    return bounce_alias_promote(cptr, sptr, parc, parv);
  case 'N':
    return bounce_alias_nicksync(cptr, sptr, parc, parv);
  case 'U':
    return bounce_alias_update(cptr, sptr, parc, parv);
  case 'E':
    return bounce_alias_echo(cptr, sptr, parc, parv);
  case 'K':
    return bounce_alias_snomask(cptr, sptr, parc, parv);
  default:
    Debug((DEBUG_INFO, "BX: unknown subcommand '%c' from %C", subcmd, sptr));
    /* Forward unknown subcommands for future compatibility */
    sendcmdto_serv_butone(sptr, CMD_BOUNCER_TRANSFER, cptr,
                          "%s", parv[1]);
    return 0;
  }
}

/* ---------------------------------------------------------------- */
/* BX P: Promote/transfer — dual-mode handler                       */
/* ---------------------------------------------------------------- */

/** Handle BX P (Promote/Transfer).
 *
 * Dual-mode:
 *   - If new_client is a bouncer alias (CHFL_ALIAS in channels):
 *     Clear CHFL_ALIAS, apply mode flags from old's memberships.
 *   - If new_client has no channel memberships (legacy/sequential swap):
 *     Transfer memberships from old to new, rename new to nick.
 *
 * Wire format: <server> BX P <old_numeric> <new_numeric> <sessid> <nick>
 */
static int bounce_alias_promote(struct Client *cptr, struct Client *sptr,
                                int parc, char *parv[])
{
  struct Client *old_client;
  struct Client *new_client;
  const char *old_numeric;
  const char *new_numeric;
  const char *sessid;
  const char *nick;
  struct Membership *member;
  struct Membership *next_member;

  if (parc < 6)
    return protocol_violation(sptr, "BX P requires 4 parameters");

  old_numeric = parv[2];
  new_numeric = parv[3];
  sessid = parv[4];
  nick = parv[5];

  old_client = findNUser(old_numeric);
  new_client = findNUser(new_numeric);

  if (!old_client || !new_client) {
    Debug((DEBUG_INFO, "BX P: client not found - old=%s new=%s",
           old_numeric, new_numeric));
    /* Forward anyway for other servers */
    sendcmdto_serv_butone(sptr, CMD_BOUNCER_TRANSFER, cptr,
                          "P %s %s %s %s", old_numeric, new_numeric, sessid, nick);
    return 0;
  }

  /* SQUIT path: when old_primary was NULL, originating server sends
   * winner_numeric for both params.  If this server already promoted
   * independently, old_client == new_client — nothing to do. */
  if (old_client == new_client) {
    sendcmdto_serv_butone(sptr, CMD_BOUNCER_TRANSFER, cptr,
                          "P %s %s %s %s", old_numeric, new_numeric, sessid, nick);
    return 0;
  }

  if (IsBouncerAlias(new_client)) {
    /* Alias path: new_client is already in channels with CHFL_ALIAS.
     * Copy mode flags from old's memberships, clear CHFL_ALIAS. */
    for (member = cli_user(old_client)->channel; member; member = next_member) {
      next_member = member->next_channel;
      struct Membership *alias_member = find_member_link(member->channel, new_client);
      if (alias_member && IsMemberAlias(alias_member)) {
        /* Transfer modes from old to alias, clear CHFL_ALIAS */
        unsigned int modes = member->status & ~(CHFL_HOLDING | CHFL_ALIAS);
        alias_member->status = modes;
        /* Adjust counters: alias becomes real member */
        member->channel->aliases--;
        member->channel->users++;
        if (!IsSSL(new_client) && !IsChannelService(new_client))
          member->channel->nonsslusers++;
        if (IsAccount(new_client))
          member->channel->authusers++;
        ++(cli_user(new_client))->joined;
      }
    }
    ClearBouncerAlias(new_client);
    cli_user(new_client)->alias_primary = NULL;
    /* C1: Add promoted alias to nick hash (aliases aren't in nick hash) */
    hAddClient(new_client);
  } else {
    /* Swap path: new_client has no channel memberships.
     * Transfer memberships from old to new (legacy/sequential). */
    for (member = cli_user(old_client)->channel; member; member = next_member) {
      next_member = member->next_channel;
      unsigned int modes = member->status & ~CHFL_HOLDING;
      add_user_to_channel(member->channel, new_client, modes, OpLevel(member));
      remove_user_from_channel(old_client, member->channel);
    }
    /* Nick should already match — don't propagate a desync from the wire. */
    if (ircd_strcmp(cli_name(new_client), nick)) {
      Debug((DEBUG_ERROR, "BX P: nick mismatch (swap) — local '%s' vs wire '%s', keeping local",
             cli_name(new_client), nick));
    }
  }

  /* C2: Update session via string-based lookup (reliable even when
   * hs_client is NULL, e.g. during SQUIT). */
  {
    struct BouncerSession *bsess = bounce_find_by_token_sessid(
        cli_account(old_client), sessid);
    if (bsess) {
      int k;
      /* Point session to new primary.
       * Transition to ACTIVE — the promoted alias is a live connection.
       * Without this, the session stays HOLDING on remote replicas and
       * exit_one_client destroys it instead of re-holding on disconnect. */
      bsess->hs_client = new_client;
      bsess->hs_state = BOUNCE_ACTIVE;
      bsess->hs_last_active = CurrentTime;
      bsess->hs_disconnect_time = 0;
      /* Update remaining aliases' alias_primary */
      for (k = 0; k < bsess->hs_alias_count; k++) {
        struct Client *sibling = findNUser(bsess->hs_aliases[k].ba_numeric);
        if (sibling && IsBouncerAlias(sibling))
          cli_user(sibling)->alias_primary = new_client;
      }
      /* Remove promoted alias from hs_aliases[] */
      for (k = 0; k < bsess->hs_alias_count; k++) {
        if (findNUser(bsess->hs_aliases[k].ba_numeric) == new_client) {
          if (k < bsess->hs_alias_count - 1)
            memmove(&bsess->hs_aliases[k], &bsess->hs_aliases[k + 1],
                    (bsess->hs_alias_count - 1 - k)
                      * sizeof(struct BounceAlias));
          bsess->hs_alias_count--;
          break;
        }
      }
    }
  }

  /* C3: Remove old_client from channels silently, then exit with
   * FLAG_KILLED to suppress S2S QUIT propagation to upstream servers
   * that don't understand alias promotion (they'd desync if they saw
   * the QUIT).  The originating server's S2S QUIT arrives later (TCP
   * ordering) and is harmlessly ignored (numeric already freed). */
  remove_user_from_all_channels(old_client);
  SetFlag(old_client, FLAG_KILLED);
  exit_client(old_client, old_client, &me, "Session transferred");

  /* Forward to other servers */
  sendcmdto_serv_butone(sptr, CMD_BOUNCER_TRANSFER, cptr,
                        "P %s %s %s %s", old_numeric, new_numeric, sessid, nick);

  return 0;
}

/* ---------------------------------------------------------------- */
/* Local alias setup (trigger for BX C)                              */
/* ---------------------------------------------------------------- */

/** Set up a local alias for a remote bouncer session.
 *
 * Called from register_user() when bounce_auto_resume() returns
 * BOUNCE_RESUME_ALIAS_REMOTE.  Converts the registering client in place
 * into a first-class alias: removes from nick hash, copies identity from
 * the primary, allocates a local P10 numeric, adds to primary's channels
 * with CHFL_ALIAS, broadcasts BX C, and sends the welcome sequence.
 *
 * The alias is NOT introduced via N token — other servers learn about it
 * through the BX C message.
 *
 * @param[in] sptr    The registering client to convert into an alias.
 * @param[in] session The remote bouncer session (replica on this server).
 * @return 0 on success, -1 on failure.
 */
int bounce_setup_local_alias(struct Client *sptr, struct BouncerSession *session)
{
  struct Client *primary;
  struct User *user;
  struct Membership *member;
  struct BounceAlias *ba;
  char chanlist_buf[512];
  int chanlist_len = 0;
  char *parv[2] = { NULL, NULL };

  assert(sptr != NULL);
  assert(session != NULL);

  /* The primary must exist on the network (remote Client from N token) */
  primary = session->hs_client;
  if (!primary || !IsUser(primary)) {
    log_write(LS_USER, L_INFO, 0,
              "bounce_setup_local_alias: no primary for session %s "
              "(primary=%p IsUser=%d)",
              session->hs_sessid, (void*)primary,
              primary ? IsUser(primary) : 0);
    return -1;
  }

  user = cli_user(sptr);
  if (!user) {
    log_write(LS_USER, L_INFO, 0,
              "bounce_setup_local_alias: sptr has no User struct (session %s)",
              session->hs_sessid);
    return -1;
  }

  log_write(LS_USER, L_INFO, 0,
            "bounce_setup_local_alias: converting %s to alias of %s (session %s)",
            cli_name(sptr), cli_name(primary), session->hs_sessid);

  /* --- Step 0: Complete IPcheck connect ---
   * The alias keeps its own real socket IP (not overwritten from primary),
   * so IPcheck_connect_succeeded() can find the registry entry normally.
   * IPcheck_disconnect() is called in the alias exit path. */
  if (IsIPChecked(sptr))
    IPcheck_connect_succeeded(sptr);

  /* --- Step 1: Remove from nick hash ---
   * The client was added during NICK registration.  Aliases must NOT be
   * in the nick hash — FindUser() should return the primary, not the alias. */
  hRemClient(sptr);

  /* --- Step 2: Overwrite identity from primary ---
   * Same pattern as bounce_alias_create() for remote aliases. */
  ircd_strncpy(cli_name(sptr), cli_name(primary), NICKLEN);
  ircd_strncpy(user->username, cli_user(primary)->username, USERLEN);
  ircd_strncpy(user->host, cli_user(primary)->host, HOSTLEN);
  /* Do NOT overwrite realhost — the alias has its own real connection host,
   * needed for oper WHOIS, gline matching, and stays correct on promotion. */
  ircd_strncpy(cli_info(sptr), cli_info(primary), REALLEN);
  ircd_strncpy(user->account, cli_user(primary)->account, ACCOUNTLEN);
  user->acc_create = cli_user(primary)->acc_create;

  /* Copy cloaked/fake host (controls what other users see).
   * Do NOT overwrite cli_ip — the alias has its own real socket IP,
   * needed for IPcheck, ban matching, and logging. */
  ircd_strncpy(user->cloakip, cli_user(primary)->cloakip, HOSTLEN);
  ircd_strncpy(user->cloakhost, cli_user(primary)->cloakhost, HOSTLEN);
  ircd_strncpy(user->fakehost, cli_user(primary)->fakehost, HOSTLEN);

  /* --- Step 3: Set alias flags --- */
  SetBouncerAlias(sptr);
  SetUser(sptr);
  SetAccount(sptr);
  if (IsHiddenHost(primary))
    SetHiddenHost(sptr);
  user->alias_primary = primary;
  user->server = &me;  /* Required before SetLocalNumNick (asserts this) */
  cli_lastnick(sptr) = cli_lastnick(primary);
  cli_handler(sptr) = CLIENT_HANDLER;

  /* Copy user mode flags from primary (oper, wallops, invisible, etc.) */
  bounce_copy_umodes(primary, sptr);

  /* Copy oper privileges from primary so HasPriv() works correctly.
   * Without this, umode_str() strips +o (PRIV_PROPAGATE check) and
   * oper commands are denied on the alias connection. */
  if (IsOper(primary)) {
    memcpy(&cli_privs(sptr), &cli_privs(primary), sizeof(cli_privs(sptr)));
    cli_handler(sptr) = OPER_HANDLER;
    /* Sync snomask so alias is in opsarray for server notice delivery.
     * Only works when primary is local (has real snomask). Remote primary
     * case is handled by BX K from the primary's server. */
    if (cli_snomask(primary))
      set_snomask(sptr, cli_snomask(primary), SNO_SET);
  }

  /* Re-assert the alias's own SSL state — bounce_copy_umodes copies the
   * primary's FLAG_SSL, but local aliases have their own TLS connection. */
#ifdef USE_SSL
  if (cli_socket(sptr).ssl)
    SetSSL(sptr);
  else
    ClearSSL(sptr);
#endif

  /* --- Step 4: Allocate local P10 numeric --- */
  if (!SetLocalNumNick(sptr)) {
    log_write(LS_USER, L_INFO, 0,
              "bounce_setup_local_alias: SetLocalNumNick failed (numeric pool "
              "exhausted) for session %s", session->hs_sessid);
    /* Restore nick hash entry since we removed it in step 1 */
    hAddClient(sptr);
    return -1;
  }

  /* --- Step 5: User cloaking --- */
  user_setcloaked(sptr);
  if (IsHiddenHost(sptr))
    hide_hostmask(sptr);

  /* --- Step 6: Track alias in session replica ---
   * Construct full YYXXX numerics: server YY + client XXX. */
  {
    char alias_full[6];   /* YYXXX + NUL */
    char primary_full[6];
    ircd_snprintf(0, alias_full, sizeof(alias_full), "%s%s",
                  cli_yxx(&me), cli_yxx(sptr));
    ircd_snprintf(0, primary_full, sizeof(primary_full), "%s%s",
                  cli_yxx(cli_user(primary)->server), cli_yxx(primary));

    if (session->hs_alias_count < BOUNCER_MAX_ALIASES) {
      ba = &session->hs_aliases[session->hs_alias_count++];
      ircd_strncpy(ba->ba_numeric, alias_full, sizeof(ba->ba_numeric));
      ircd_strncpy(ba->ba_server, cli_yxx(&me), sizeof(ba->ba_server));
    }

    /* --- Step 7: Add to primary's channels with CHFL_ALIAS ---
     * Also build the channel list string for the BX C message. */
    chanlist_buf[0] = '\0';
    for (member = cli_user(primary)->channel; member; member = member->next_channel) {
      struct Channel *chptr = member->channel;

      if (IsZombie(member) || IsDelayedJoin(member))
        continue;

      /* Skip +Z channels for non-TLS aliases */
      if ((chptr->mode.exmode & EXMODE_SSLONLY) && !IsSSL(sptr)) {
        sendcmdto_one(&me, CMD_NOTICE, sptr,
          "%C :Not joining %s \xe2\x80\x94 channel requires TLS (+Z) "
          "but your connection is plaintext. Reconnect with TLS to join.",
          sptr, chptr->chname);
        continue;
      }

      if (!find_member_link(chptr, sptr)) {
        /* Copy primary's channel mode flags (member is the primary's membership) */
        unsigned int aflags = CHFL_ALIAS
                            | (member->status & (CHFL_CHANOP | CHFL_HALFOP | CHFL_VOICE));
        struct Membership *amemb;
        add_user_to_channel(chptr, sptr, aflags, OpLevel(member));
        /* Inherit primary's JOIN msgid/timestamp for bouncer replay */
        amemb = find_member_link(chptr, sptr);
        if (amemb && member->join_msgid[0]) {
          memcpy(amemb->join_msgid, member->join_msgid, sizeof(amemb->join_msgid));
          amemb->join_tv = member->join_tv;
        }
      }

      /* Append to channel list for BX C (only joined channels) */
      if (chanlist_len > 0 && chanlist_len < (int)sizeof(chanlist_buf) - 1)
        chanlist_buf[chanlist_len++] = ' ';
      chanlist_len += ircd_snprintf(0, chanlist_buf + chanlist_len,
                                    sizeof(chanlist_buf) - chanlist_len,
                                    "%s", chptr->chname);
    }

    /* --- Step 8: Broadcast BX C to network --- */
    {
      char *alias_modes = umode_str(sptr);
      sendcmdto_serv_butone(&me, CMD_BOUNCER_TRANSFER, NULL,
                             "C %s %s %s %s %s%s :%s",
                             primary_full,
                             alias_full,
                             session->hs_account,
                             session->hs_sessid,
                             *alias_modes ? "+" : "+",
                             alias_modes,
                             chanlist_buf);
    }
  } /* end YYXXX numeric scope */

  /* --- Step 9: Send welcome sequence to the alias client ---
   * The client expects 001-005 + MOTD on connect. */
  send_reply(sptr, RPL_WELCOME,
             feature_str(FEAT_NETWORK),
             feature_str(FEAT_PROVIDER) ? " via " : "",
             feature_str(FEAT_PROVIDER) ? feature_str(FEAT_PROVIDER) : "",
             cli_name(sptr));
  send_reply(sptr, RPL_YOURHOST, cli_name(&me), version);
  send_reply(sptr, RPL_CREATED, creation);
  send_reply(sptr, RPL_MYINFO, cli_name(&me), version, infousermodes,
             infochanmodes, infochanmodeswithparams);
  send_supported(sptr);

#ifdef USE_SSL
  if (cli_socket(sptr).ssl)
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :You are connected to %s with %s",
                  sptr, cli_name(&me), ssl_get_cipher(cli_socket(sptr).ssl));
#endif

  m_lusers(sptr, sptr, 1, parv);
  motd_signon(sptr);

  /* Informational NOTE */
  sendrawto_one(sptr,
    ":%s NOTE BOUNCER ALIAS_ATTACHED :Attached to session %s as alias on %s",
    cli_name(&me), session->hs_sessid, cli_name(&me));

  /* --- Step 10: Send channel state (JOINs, TOPICs, NAMES) --- */
  bounce_send_channel_state(sptr);

  /* Auto-replay missed messages for legacy clients.
   * Clients with draft/chathistory do their own replay via CHATHISTORY command.
   *
   * Two paths:
   * 1. Local MDBX available: use async replay_start_bouncer().
   * 2. No local store but federation available: use chathistory_auto_replay_fed()
   *    which issues CHATHISTORY LATEST * queries to storage servers.
   *    Follows IRCv3 chathistory client pseudocode pattern. */
  if (feature_bool(FEAT_BOUNCER_AUTO_REPLAY)
      && !CapOwnHas(sptr, CAP_DRAFT_CHATHISTORY)) {
    time_t since = session->hs_last_active;
    if (since == 0)
      since = session->hs_created;

    if (history_is_available()) {
      /* Local store: async replay from MDBX */
      if (since > 0 && since < CurrentTime)
        replay_start_bouncer(sptr, since, 0);
    } else {
      /* No local store: federate to storage servers */
      int limit = feature_int(FEAT_BOUNCER_AUTO_REPLAY_LIMIT);
      if (limit <= 0)
        limit = 100;
      chathistory_auto_replay_fed(sptr, since, limit);
    }
  }

  /* IPcheck already completed in Step 0 above, before IP overwrite. */

  log_write(LS_SYSTEM, L_INFO, 0,
            "Bouncer: alias %s (%s@%s) created for session %s on %s [%s]",
            cli_name(sptr), user->username, user->realhost,
            session->hs_sessid, cli_name(&me), cli_sock_ip(sptr));

  return 0;
}

/* ---------------------------------------------------------------- */
/* BX C: Create alias                                                */
/* ---------------------------------------------------------------- */

/** Handle BX C (Create Alias).
 *
 * Wire format: <server> BX C <primary_numeric> <alias_numeric> <account> <sessid> :<channels>
 *
 * Creates a remote struct Client for the alias numeric on this server.
 * The alias is NOT added to the nick hash — FindUser() returns the primary.
 * The alias is added to each of the primary's channels with CHFL_ALIAS.
 */
static int bounce_alias_create(struct Client *cptr, struct Client *sptr,
                               int parc, char *parv[])
{
  struct Client *primary = NULL;
  struct Client *alias;
  struct Client *alias_server;
  struct User *user;
  struct BouncerSession *session = NULL;
  const char *primary_numeric;
  const char *alias_numeric;
  const char *account;
  const char *sessid;
  const char *chanlist;
  const char *alias_modes = NULL;
  char *chan_copy;
  char *chan_name;
  char *chan_tok;

  if (parc < 7)
    return protocol_violation(sptr, "BX C requires 5 parameters");

  primary_numeric = parv[2];
  alias_numeric = parv[3];
  account = parv[4];
  sessid = parv[5];
  if (parc >= 8) {
    /* New format: BX C <primary> <alias> <account> <sessid> <modes> :<channels> */
    alias_modes = parv[6];
    chanlist = parv[parc - 1];
  } else {
    /* Old format: BX C <primary> <alias> <account> <sessid> :<channels> */
    chanlist = parv[6];
  }

  /* Find the primary client */
  primary = findNUser(primary_numeric);
  if (!primary) {
    Debug((DEBUG_INFO, "BX C: primary %s not found", primary_numeric));
    goto forward;
  }

  /* Find the server that hosts the alias (from the 2-char numeric prefix) */
  {
    char svr_yy[3];
    svr_yy[0] = alias_numeric[0];
    svr_yy[1] = alias_numeric[1];
    svr_yy[2] = '\0';
    alias_server = FindNServer(svr_yy);
  }
  if (!alias_server) {
    Debug((DEBUG_INFO, "BX C: alias server not found for %s", alias_numeric));
    goto forward;
  }

  /* Check if alias numeric already exists */
  alias = findNUser(alias_numeric);
  Debug((DEBUG_INFO, "BX C: processing alias=%s primary=%s account=%s chanlist='%s' existing=%s",
         alias_numeric, primary_numeric, account,
         chanlist ? chanlist : "?",
         alias ? cli_name(alias) : "NULL"));
  if (alias) {
    if (IsBouncerAlias(alias)) {
      /* Already an alias — duplicate BX C, skip creation */
      Debug((DEBUG_INFO, "BX C: alias %s already exists as alias", alias_numeric));
      goto forward;
    }
    /* Existing non-alias client — convert to alias in place.
     * This happens when BX C arrives for a client that was introduced
     * via N token (e.g., local alias setup already done, or burst ordering). */
    Debug((DEBUG_INFO, "BX C: converting existing client %s (%s) to alias of %s",
           alias_numeric, cli_name(alias), cli_name(primary)));
    user = cli_user(alias);
    if (!user)
      goto forward;
    hRemClient(alias);
    ircd_strncpy(cli_name(alias), cli_name(primary), NICKLEN);
    ircd_strncpy(user->username, cli_user(primary)->username, USERLEN);
    ircd_strncpy(user->host, cli_user(primary)->host, HOSTLEN);
    ircd_strncpy(user->realhost, cli_user(primary)->realhost, HOSTLEN);
    ircd_strncpy(cli_info(alias), cli_info(primary), REALLEN);
    ircd_strncpy(user->account, account, ACCOUNTLEN);
    user->acc_create = cli_user(primary)->acc_create;
    user->alias_primary = primary;
    memcpy(&cli_ip(alias), &cli_ip(primary), sizeof(cli_ip(alias)));
    ircd_strncpy(user->cloakip, cli_user(primary)->cloakip, HOSTLEN);
    ircd_strncpy(user->cloakhost, cli_user(primary)->cloakhost, HOSTLEN);
    ircd_strncpy(user->fakehost, cli_user(primary)->fakehost, HOSTLEN);
    SetBouncerAlias(alias);
    if (IsHiddenHost(primary))
      SetHiddenHost(alias);
    cli_lastnick(alias) = cli_lastnick(primary);
    /* Copy user mode flags from primary (oper, wallops, invisible, etc.) */
    bounce_copy_umodes(primary, alias);
    goto track_alias;
  }

  /* Create a remote client sharing the alias server's connection */
  alias = make_client(alias_server, STAT_UNKNOWN);
  if (!alias)
    goto forward;

  user = make_user(alias);
  if (!user)
    goto forward;

  /* Copy identity from primary */
  ircd_strncpy(cli_name(alias), cli_name(primary), NICKLEN);
  ircd_strncpy(user->username, cli_user(primary)->username, USERLEN);
  ircd_strncpy(user->host, cli_user(primary)->host, HOSTLEN);
  ircd_strncpy(user->realhost, cli_user(primary)->realhost, HOSTLEN);
  ircd_strncpy(cli_info(alias), cli_info(primary), REALLEN);
  ircd_strncpy(user->account, account, ACCOUNTLEN);
  user->acc_create = cli_user(primary)->acc_create;
  user->server = alias_server;
  user->alias_primary = primary;

  /* Copy IP and cloaked/fake host from primary */
  memcpy(&cli_ip(alias), &cli_ip(primary), sizeof(cli_ip(alias)));
  ircd_strncpy(user->cloakip, cli_user(primary)->cloakip, HOSTLEN);
  ircd_strncpy(user->cloakhost, cli_user(primary)->cloakhost, HOSTLEN);
  ircd_strncpy(user->fakehost, cli_user(primary)->fakehost, HOSTLEN);

  /* Register in P10 numeric space — NOT in nick hash */
  SetRemoteNumNick(alias, alias_numeric);

  /* Set client state.
   * Do NOT set cli_handler here — the remote alias shares the server
   * link's Connection, so cli_handler(alias) would overwrite
   * con_handler on the server link (SERVER_HANDLER → CLIENT_HANDLER),
   * causing all subsequent S2S messages to dispatch through CLIENT
   * handlers (crash: m_privmsg asserts cptr==sptr). */
  SetUser(alias);
  SetAccount(alias);
  if (IsHiddenHost(primary))
    SetHiddenHost(alias);
  SetBouncerAlias(alias);
  cli_lastnick(alias) = cli_lastnick(primary);
  /* Copy user mode flags from primary (oper, wallops, invisible, etc.) */
  bounce_copy_umodes(primary, alias);

  /* Add to global client list */
  add_client_to_list(alias);

track_alias:

  /* Apply mode string from BX C if present — overrides modes copied from
   * the local view of the primary, which may be stale or incomplete.
   * e.g. alias created on originating server after /OPER, but the
   * primary on this server hasn't received the mode change yet. */
  if (alias_modes && *alias_modes)
    user_apply_umode_str(alias, alias_modes);

  /* Track alias in session replica */
  session = bounce_find_by_token_sessid(account, sessid);
  if (session && session->hs_alias_count < BOUNCER_MAX_ALIASES) {
    struct BounceAlias *ba = &session->hs_aliases[session->hs_alias_count++];
    ircd_strncpy(ba->ba_numeric, alias_numeric, sizeof(ba->ba_numeric));
    ircd_strncpy(ba->ba_server, alias_numeric, sizeof(ba->ba_server));
  }

  /* Add alias to each of the primary's channels with CHFL_ALIAS */
  if (chanlist && *chanlist) {
    Debug((DEBUG_INFO, "BX C: chanlist='%s' for alias %s primary %s",
           chanlist, alias_numeric, primary_numeric));
    chan_copy = MyMalloc(strlen(chanlist) + 1);
    strcpy(chan_copy, chanlist);
    for (chan_name = ircd_strtok(&chan_tok, chan_copy, " ");
         chan_name;
         chan_name = ircd_strtok(&chan_tok, NULL, " ")) {
      struct Channel *chptr = FindChannel(chan_name);
      if (!chptr) {
        Debug((DEBUG_INFO, "BX C: channel '%s' not found on this server", chan_name));
        continue;
      }
      if (!find_member_link(chptr, primary)) {
        Debug((DEBUG_INFO, "BX C: primary %s (%s) not in channel %s",
               primary_numeric, cli_name(primary), chan_name));
        continue;
      }
      /* Skip +Z channels for non-TLS aliases */
      if ((chptr->mode.exmode & EXMODE_SSLONLY) && !IsSSL(alias)) {
        Debug((DEBUG_INFO, "BX C: skipping +Z channel %s (alias not SSL)", chan_name));
        continue;
      }
      /* Copy primary's channel mode flags so alias inherits op/voice status */
      {
        struct Membership *pmem = find_member_link(chptr, primary);
        unsigned int aflags = CHFL_ALIAS;
        unsigned short aoplevel = MAXOPLEVEL;
        if (pmem) {
          aflags |= (pmem->status & (CHFL_CHANOP | CHFL_HALFOP | CHFL_VOICE));
          aoplevel = OpLevel(pmem);
        }
        add_user_to_channel(chptr, alias, aflags, aoplevel);
      }
      Debug((DEBUG_INFO, "BX C: added alias %s to channel %s (members=%d aliases=%d)",
             alias_numeric, chan_name, chptr->users, chptr->aliases));
    }
    MyFree(chan_copy);
  } else {
    Debug((DEBUG_INFO, "BX C: empty chanlist for alias %s", alias_numeric));
  }

  /* If primary is local and opered, send BX K so the alias's server
   * adds it to opsarray for server notice delivery. */
  if (MyUser(primary) && cli_snomask(primary)) {
    sendcmdto_serv_butone(&me, CMD_BOUNCER_TRANSFER, cptr,
                          "K %s %u", alias_numeric, cli_snomask(primary));
  }

  Debug((DEBUG_INFO, "BX C: created alias %s for primary %s (%s)",
         alias_numeric, primary_numeric, cli_name(primary)));

forward:
  /* Forward to other servers — include modes if present */
  if (alias_modes && *alias_modes)
    sendcmdto_serv_butone(sptr, CMD_BOUNCER_TRANSFER, cptr,
                          "C %s %s %s %s %s :%s",
                          primary_numeric, alias_numeric, account, sessid,
                          alias_modes, chanlist);
  else
    sendcmdto_serv_butone(sptr, CMD_BOUNCER_TRANSFER, cptr,
                          "C %s %s %s %s :%s",
                          primary_numeric, alias_numeric, account, sessid, chanlist);

  /* Session move: if the primary is a local HOLDING ghost, promote the
   * alias to primary BEFORE exiting the ghost.  This ensures the ghost's
   * channels are silently removed by promote (remove_user_from_all_channels)
   * while hs_client still points to the ghost.  After promote, the ghost
   * has no channels, so exit_one_client sends no visible QUIT.
   *
   * Wire ordering: BX C (forwarded above) → BX P + BS T (from promote)
   * → ghost exits with FLAG_KILLED (no S2S D token).
   * Result: other IRC clients see no QUIT/JOIN — seamless transfer. */
  if (session && session->hs_state == BOUNCE_HOLDING
      && primary && MyConnect(primary) && IsBouncerHold(primary)) {
    Debug((DEBUG_INFO, "BX C: session move — promoting alias, retiring ghost %s",
           cli_name(primary)));
    /* Promote BEFORE exit: promote removes ghost from channels (silent),
     * sends BX P + BS T.  Then exit ghost — no channels, no visible QUIT. */
    bounce_promote_alias(session);
    /* Suppress S2S quit — BX P already told the network. */
    SetFlag(primary, FLAG_KILLED);
    exit_client(primary, primary, &me, "Session transferred");
  }

  return 0;
}

/* ---------------------------------------------------------------- */
/* BX X: Destroy alias                                               */
/* ---------------------------------------------------------------- */

/** Remove an alias from the session replica's hs_aliases[] array.
 * Walks all sessions for the primary's account to find the matching entry.
 */
void bounce_alias_untrack(struct Client *alias)
{
  struct AccountSessions *as;
  struct BouncerSession *session;
  char full_numeric[6];
  int i;

  /* Use alias's own account — avoids use-after-free on cli_alias_primary
   * when the primary has already been freed (SQUIT ordering). */
  if (!IsAccount(alias))
    return;

  as = bounce_find_by_account(cli_user(alias)->account);
  if (!as)
    return;

  /* Reconstruct full YYXXX numeric: cli_yxx(server)=YY + cli_yxx(alias)=XXX */
  ircd_snprintf(0, full_numeric, sizeof(full_numeric), "%s%s",
                cli_yxx(cli_user(alias)->server), cli_yxx(alias));

  for (session = as->as_sessions; session; session = session->hs_anext) {
    for (i = 0; i < session->hs_alias_count; i++) {
      if (0 == strcmp(session->hs_aliases[i].ba_numeric, full_numeric)) {
        /* Shift remaining entries down */
        if (i < session->hs_alias_count - 1)
          memmove(&session->hs_aliases[i], &session->hs_aliases[i + 1],
                  (session->hs_alias_count - 1 - i) * sizeof(struct BounceAlias));
        session->hs_alias_count--;
        return;
      }
    }
  }
}

/** Handle BX X (Destroy Alias).
 *
 * Wire format: <server> BX X <alias_numeric>
 *
 * Removes the alias Client from all channels and destroys it.
 * Unlike normal client exit, aliases are torn down silently:
 * no QUIT to channels, no chathistory events, no IPcheck, no nick hash.
 */
static int bounce_alias_destroy(struct Client *cptr, struct Client *sptr,
                                int parc, char *parv[])
{
  struct Client *alias;
  const char *alias_numeric;

  if (parc < 3)
    return protocol_violation(sptr, "BX X requires alias_numeric");

  alias_numeric = parv[2];
  alias = findNUser(alias_numeric);

  if (!alias || !IsBouncerAlias(alias)) {
    Debug((DEBUG_INFO, "BX X: alias %s not found or not alias", alias_numeric));
    goto forward;
  }

  Debug((DEBUG_INFO, "BX X: destroying alias %s (%s) for primary %s",
         alias_numeric, cli_name(alias),
         cli_alias_primary(alias) ? cli_name(cli_alias_primary(alias)) : "?"));

  /* Remove alias from session replica tracking */
  bounce_alias_untrack(alias);

  /* Remove from all channels silently.
   * Note: counter behavior (users vs aliases) is symmetrically wrong
   * here and in BX C until counter guards are added to
   * add_user_to_channel/remove_member_from_channel. */
  remove_user_from_all_channels(alias);

  /* Remove from P10 numeric space */
  RemoveYXXClient(cli_user(alias)->server, cli_yxx(alias));

  /* Remove from global client list — frees User and Client structs.
   * Skip hRemClient: alias was never added to the nick hash. */
  remove_client_from_list(alias);

forward:
  sendcmdto_serv_butone(sptr, CMD_BOUNCER_TRANSFER, cptr,
                        "X %s", alias_numeric);
  return 0;
}

/* ---------------------------------------------------------------- */
/* BX N: Nick sync                                                   */
/* ---------------------------------------------------------------- */

/** Handle BX N (Nick Sync).
 *
 * Wire format: <server> BX N <primary_numeric> <new_nick> <ts>
 *
 * Updates all aliases of the primary to match the new nick.
 */
static int bounce_alias_nicksync(struct Client *cptr, struct Client *sptr,
                                 int parc, char *parv[])
{
  struct Client *primary;
  const char *primary_numeric;
  const char *new_nick;
  struct AccountSessions *as;
  struct BouncerSession *session;
  int i;

  if (parc < 5)
    return protocol_violation(sptr, "BX N requires 3 parameters");

  primary_numeric = parv[2];
  new_nick = parv[3];
  /* parv[4] = ts (for collision resolution) */

  primary = findNUser(primary_numeric);
  if (!primary || !IsAccount(primary))
    goto forward;

  /* Find all aliases of this primary and update their nicks.
   * Aliases are NOT in the nick hash, so no hRemClient/hAddClient needed. */
  as = bounce_find_by_account(cli_user(primary)->account);
  if (!as)
    goto forward;

  for (session = as->as_sessions; session; session = session->hs_anext) {
    for (i = 0; i < session->hs_alias_count; i++) {
      struct Client *alias = findNUser(session->hs_aliases[i].ba_numeric);
      if (alias && IsBouncerAlias(alias) && cli_alias_primary(alias) == primary) {
        ircd_strncpy(cli_name(alias), new_nick, NICKLEN);
      }
    }
  }

forward:
  sendcmdto_serv_butone(sptr, CMD_BOUNCER_TRANSFER, cptr,
                        "N %s %s %s", parv[2], parv[3], parv[4]);
  return 0;
}

/* ---------------------------------------------------------------- */
/* BX U: Identity update                                             */
/* ---------------------------------------------------------------- */

/** Handle BX U (Identity Update).
 *
 * Wire format: <server> BX U <alias_numeric> <field>=<value>
 *
 * Updates an alias's identity fields (host, realname, etc.)
 */
static int bounce_alias_update(struct Client *cptr, struct Client *sptr,
                               int parc, char *parv[])
{
  struct Client *alias;
  const char *alias_numeric;
  const char *field_value;
  char *eq;
  char field[32];
  const char *value;

  if (parc < 4)
    return protocol_violation(sptr, "BX U requires 2 parameters");

  alias_numeric = parv[2];
  field_value = parv[3];

  alias = findNUser(alias_numeric);
  if (!alias || !IsBouncerAlias(alias))
    goto forward;

  /* Parse field=value */
  eq = strchr(field_value, '=');
  if (!eq)
    goto forward;

  {
    size_t flen = eq - field_value;
    if (flen >= sizeof(field))
      flen = sizeof(field) - 1;
    memcpy(field, field_value, flen);
    field[flen] = '\0';
    value = eq + 1;
  }

  /* Apply update based on field name */
  if (0 == ircd_strcmp(field, "host")) {
    ircd_strncpy(cli_user(alias)->host, value, HOSTLEN);
  } else if (0 == ircd_strcmp(field, "realhost")) {
    ircd_strncpy(cli_user(alias)->realhost, value, HOSTLEN);
  } else if (0 == ircd_strcmp(field, "realname")) {
    ircd_strncpy(cli_info(alias), value, REALLEN);
  } else if (0 == ircd_strcmp(field, "fakehost")) {
    ircd_strncpy(cli_user(alias)->fakehost, value, HOSTLEN);
  } else if (0 == ircd_strcmp(field, "cloakhost")) {
    ircd_strncpy(cli_user(alias)->cloakhost, value, HOSTLEN);
  } else if (0 == ircd_strcmp(field, "cloakip")) {
    ircd_strncpy(cli_user(alias)->cloakip, value, HOSTLEN);
  } else if (0 == ircd_strcmp(field, "username")) {
    ircd_strncpy(cli_user(alias)->username, value, USERLEN);
  } else if (0 == ircd_strcmp(field, "account")) {
    ircd_strncpy(cli_user(alias)->account, value, ACCOUNTLEN);
    if (value[0] != '\0')
      SetAccount(alias);
    else
      ClearAccount(alias);
  } else {
    Debug((DEBUG_INFO, "BX U: unknown field '%s' for alias %s", field, alias_numeric));
  }

forward:
  sendcmdto_serv_butone(sptr, CMD_BOUNCER_TRANSFER, cptr,
                        "U %s %s", parv[2], parv[3]);
  return 0;
}

/** Handle BX E: deliver a PM echo to a local session member.
 * When a session member sends a PM, the originating server sends BX E to
 * other servers hosting session members so they see the outgoing message.
 *
 * Wire format: <server> BX E <target_nn> <from_nn> <tok> <pm_target> <msgid> :<text>
 *
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message (a server).
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
static int bounce_alias_echo(struct Client *cptr, struct Client *sptr,
                             int parc, char *parv[])
{
  struct Client *target, *from;
  const char *tok_char, *target_nick, *msgid, *text;
  const char *msg_cmd, *msg_tok;

  if (parc < 8)
    return protocol_violation(sptr, "BX E requires 7 parameters");

  target = findNUser(parv[2]);
  if (!target || !IsUser(target))
    return 0;

  /* Forward if target is not on this server */
  if (!MyConnect(target)) {
    sendcmdto_one(sptr, CMD_BOUNCER_TRANSFER, target,
        "E %s %s %s %s %s :%s",
        parv[2], parv[3], parv[4], parv[5], parv[6], parv[7]);
    return 0;
  }

  from = findNUser(parv[3]);
  if (!from)
    return 0;

  tok_char = parv[4];
  target_nick = parv[5];
  msgid = parv[6];
  text = parv[7];

  if (strcmp(msgid, "*") == 0)
    msgid = NULL;

  if (tok_char[0] == 'P') {
    msg_cmd = MSG_PRIVATE;
    msg_tok = TOK_PRIVATE;
  } else {
    msg_cmd = MSG_NOTICE;
    msg_tok = TOK_NOTICE;
  }

  /* Deliver the echo to the local client */
  sendcmdto_one_tags_ext(from, msg_cmd, msg_tok, target, msgid,
                         "%s :%s", target_nick, text);
  return 0;
}

/* ---------------------------------------------------------------- */
/* BX K: Sync snomask to alias                                       */
/* ---------------------------------------------------------------- */

/** Set the snomask on a bouncer alias.
 * Sent by the primary's server (which has the authoritative oper state)
 * to ensure aliases on other servers are added to opsarray and receive
 * server notices (oper notices, glines, connection notices, etc.).
 *
 * Format: BX K <alias_numeric> <snomask_decimal>
 */
static int bounce_alias_snomask(struct Client *cptr, struct Client *sptr,
                                int parc, char *parv[])
{
  struct Client *alias;
  unsigned int snomask;

  if (parc < 4)
    return protocol_violation(sptr, "BX K requires 2 parameters");

  alias = findNUser(parv[2]);
  if (!alias || !IsBouncerAlias(alias))
    goto forward;

  snomask = (unsigned int)atoi(parv[3]);

  /* Only set snomask on local aliases — remote ones will receive
   * the forwarded BX K and handle it themselves. */
  if (MyConnect(alias)) {
    set_snomask(alias, snomask, SNO_SET);
    Debug((DEBUG_INFO, "BX K: set snomask %u on alias %s (%s)",
           snomask, cli_name(alias), parv[2]));
  }

forward:
  sendcmdto_serv_butone(sptr, CMD_BOUNCER_TRANSFER, cptr,
                        "K %s %s", parv[2], parv[3]);
  return 0;
}

/** Initiate a cross-server bouncer transfer.
 * Called when BOUNCER RESUME is received and the ghost is on another server.
 * Broadcasts BX P to network to transfer the ghost's channels to the new client.
 */
void bounce_initiate_transfer(struct BouncerSession *session,
                              struct Client *new_client,
                              const char *old_numeric)
{
  /* Broadcast the transfer request (BX P subcommand) */
  sendcmdto_serv_butone(&me, CMD_BOUNCER_TRANSFER, NULL,
                        "P %s %s %s %s",
                        old_numeric, cli_yxx(new_client),
                        session->hs_sessid, cli_name(new_client));

  /* Update session state */
  session->hs_state = BOUNCE_ACTIVE;
  session->hs_client = new_client;
  session->hs_last_active = CurrentTime;
  session->hs_disconnect_time = 0;

  /* Cancel hold timer */
  if (t_active(&session->hs_hold_timer))
    timer_del(&session->hs_hold_timer);
}

/** Find the bouncer session for a client. */
struct BouncerSession *bounce_get_session(struct Client *cptr)
{
  struct AccountSessions *as;
  struct BouncerSession *s;

  if (!cptr || !IsAccount(cptr))
    return NULL;

  as = bounce_find_by_account(cli_account(cptr));
  if (!as)
    return NULL;

  for (s = as->as_sessions; s; s = s->hs_anext) {
    if (s->hs_client == cptr)
      return s;
  }
  return NULL;
}

/** Find any session for an account (ACTIVE or HOLDING). */
struct BouncerSession *bounce_find_any_session(const char *account)
{
  struct AccountSessions *as = bounce_find_by_account(account);
  if (!as)
    return NULL;
  return as->as_sessions; /* Return first session, regardless of state */
}

/** Compute effective away state across all session connections.
 *
 * Implements the draft/pre-away aggregation rules:
 * 1. Filter out AWAY * connections (they "don't exist")
 * 2. Of remaining:
 *    - ANY present → effective state is PRESENT (no AWAY broadcast)
 *    - ALL have explicit AWAY messages → effective is AWAY (most recent msg)
 *    - NO connections remain → effective is AWAY (empty message)
 *
 * @param[in] session Bouncer session to compute for.
 * @param[out] effective_state Set to 0 (present), 1 (away), 2 (away-star-only).
 * @param[out] effective_msg Buffer for the effective away message (AWAYLEN+1).
 * @return 1 if effective state changed from previous, 0 if unchanged.
 */
int bounce_compute_effective_away(struct BouncerSession *session,
                                   int *effective_state,
                                   char *effective_msg)
{
  struct Client *primary;
  int has_present = 0;
  int has_away = 0;
  const char *latest_away_msg = NULL;
  int i;

  assert(0 != session);
  assert(0 != effective_state);
  assert(0 != effective_msg);

  primary = session->hs_client;
  effective_msg[0] = '\0';

  /* Check primary connection's per-connection away state.
   * con_pre_away tracks the primary's own away state (0=present, 1=away, 2=away-star),
   * independent of alias commands.  con_pre_away_msg stores the primary's per-connection
   * away message.  cli_user(primary)->away reflects the EFFECTIVE state and is updated
   * by the caller after this computation. */
  if (primary && MyUser(primary)) {
    int primary_state = con_pre_away(cli_connect(primary));
    if (primary_state == 2) {
      /* AWAY * — invisible to aggregation */
    } else if (primary_state == 1) {
      has_away = 1;
      if (con_pre_away_msg(cli_connect(primary))[0])
        latest_away_msg = con_pre_away_msg(cli_connect(primary));
    } else {
      /* Present */
      has_present = 1;
    }
  }

  /* Check alias connections */
  for (i = 0; i < session->hs_alias_count; i++) {
    struct Client *alias = findNUser(session->hs_aliases[i].ba_numeric);
    if (!alias || !IsBouncerAlias(alias))
      continue;
    if (MyUser(alias)) {
      int alias_state = con_pre_away(cli_connect(alias));
      if (alias_state == 2) {
        /* AWAY * — invisible to aggregation */
      } else if (alias_state == 1) {
        has_away = 1;
        if (con_pre_away_msg(cli_connect(alias))[0])
          latest_away_msg = con_pre_away_msg(cli_connect(alias));
      } else {
        has_present = 1;
      }
    } else {
      /* Remote alias — check its user away state */
      if (cli_user(alias) && cli_user(alias)->away)
        has_away = 1;
      else
        has_present = 1;
    }
  }

  /* Apply aggregation rules */
  if (has_present) {
    *effective_state = 0; /* PRESENT — at least one non-AWAY* connection is present */
    effective_msg[0] = '\0';
  } else if (has_away) {
    *effective_state = 1; /* AWAY — all non-AWAY* connections are away */
    if (latest_away_msg)
      ircd_strncpy(effective_msg, latest_away_msg, AWAYLEN + 1);
  } else {
    *effective_state = 2; /* All connections are AWAY * — effectively hidden */
    effective_msg[0] = '\0';
  }

  return 1; /* Always return 1; caller tracks change detection */
}

/** Get the total number of connections for a session. */
int bounce_connection_count(struct BouncerSession *session)
{
  if (!session)
    return 0;
  if (session->hs_state != BOUNCE_ACTIVE || !session->hs_client)
    return 0;
  /* Primary (1) + aliases */
  return 1 + session->hs_alias_count;
}

/** Recompute cli_active from cli_active_own.
 * With the alias system, each alias has its own Client with its own caps,
 * so the primary's cli_active simply mirrors cli_active_own.
 *
 * @param[in] primary The primary client.
 */
void bounce_recompute_session_caps(struct Client *primary)
{
  if (!primary || !MyConnect(primary))
    return;

  /* cli_active == cli_active_own (aliases have their own Client caps) */
  *cli_active(primary) = *cli_active_own(primary);
}

/** Build a union CapSet from the primary connection's active capabilities.
 * With the alias system, each alias has its own Client and own caps,
 * so we just return the primary's caps.
 *
 * @param[in] session Bouncer session.
 * @param[out] out CapSet to populate with the primary's caps.
 */
void bounce_build_union_caps(struct BouncerSession *session, struct CapSet *out)
{
  unsigned int i;
  unsigned int nwords = sizeof(out->bits) / sizeof(out->bits[0]);

  assert(0 != session);
  assert(0 != out);

  /* Just return primary's active caps */
  if (session->hs_client && MyConnect(session->hs_client)) {
    struct CapSet *primary_caps = cli_active(session->hs_client);
    for (i = 0; i < nwords; i++)
      out->bits[i] = primary_caps->bits[i];
  } else {
    for (i = 0; i < nwords; i++)
      out->bits[i] = 0;
  }
}

/** Replay channel state to a client after held session resume.
 *
 * After bounce_attach() transfers memberships from ghost to the new
 * client, the client has channels in its membership list but has
 * never received JOIN/TOPIC/NAMES for them.  This function sends
 * the state the client needs to display the channels.
 *
 * @param[in] cptr  The client that just resumed a held session.
 */
void bounce_send_channel_state(struct Client *cptr)
{
  struct Membership *member;

  assert(0 != cptr);
  if (!cli_user(cptr))
    return;

  for (member = cli_user(cptr)->channel; member; member = member->next_channel) {
    struct Channel *chptr = member->channel;

    if (IsZombie(member) || IsDelayedJoin(member))
      continue;

    /* Send JOIN with original msgid and timestamp.  First try the
     * in-memory values (set when the JOIN happened this session), then
     * fall back to querying chathistory for the last JOIN by this nick. */
    {
      char hist_msgid[HISTORY_MSGID_LEN];
      char hist_ts[HISTORY_TIMESTAMP_LEN];
      const char *join_msgid = NULL;
      const char *join_ts = NULL;

      hist_msgid[0] = '\0';
      hist_ts[0] = '\0';

      if (member->join_msgid[0]) {
        /* In-memory: JOIN happened while server was running */
        join_msgid = member->join_msgid;
      }

      /* If no in-memory msgid (e.g. after restart/BURST), query history */
      if (!join_msgid && history_is_available()) {
        if (history_find_last_join(chptr->chname, cli_name(cptr),
                                   hist_msgid, sizeof(hist_msgid),
                                   hist_ts, sizeof(hist_ts))) {
          join_msgid = hist_msgid;
          join_ts = hist_ts;
        }
      }

      /* Set time override: prefer in-memory timeval, then history timestamp */
      if (member->join_tv.tv_sec) {
        char timebuf[40];
        struct tm tm;
        gmtime_r(&member->join_tv.tv_sec, &tm);
        ircd_snprintf(0, timebuf, sizeof(timebuf),
                      "%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ",
                      tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                      tm.tm_hour, tm.tm_min, tm.tm_sec,
                      (long)(member->join_tv.tv_usec / 1000));
        sendcmdto_set_client_time(timebuf);
      } else if (join_ts && join_ts[0]) {
        /* History stores Unix "seconds.milliseconds" — convert to ISO 8601 */
        char timebuf[40];
        struct tm tm;
        unsigned long sec = 0;
        unsigned long ms = 0;
        time_t t;
        sscanf(join_ts, "%lu.%lu", &sec, &ms);
        t = (time_t)sec;
        gmtime_r(&t, &tm);
        ircd_snprintf(0, timebuf, sizeof(timebuf),
                      "%04d-%02d-%02dT%02d:%02d:%02d.%03luZ",
                      tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                      tm.tm_hour, tm.tm_min, tm.tm_sec, ms);
        sendcmdto_set_client_time(timebuf);
      }

      if (CapRecipientHas(cptr, CAP_EXTJOIN))
        sendcmdto_one_tags_ext(cptr, CMD_JOIN, cptr, join_msgid,
                               "%H %s :%s", chptr,
                               IsAccount(cptr) ? cli_account(cptr) : "*",
                               cli_info(cptr));
      else
        sendcmdto_one_tags_ext(cptr, CMD_JOIN, cptr, join_msgid,
                               ":%H", chptr);

      sendcmdto_set_client_time(NULL);
    }

    if (chptr->topic[0]) {
      send_reply(cptr, RPL_TOPIC, chptr->chname, chptr->topic);
      send_reply(cptr, RPL_TOPICWHOTIME, chptr->chname, chptr->topic_nick,
                 chptr->topic_time);
    }

    send_markread_on_join(cptr, chptr->chname);

    if (!CapRecipientHas(cptr, CAP_DRAFT_NOIMPLICITNAMES))
      do_names(cptr, chptr, NAMES_ALL|NAMES_EON);
  }
}
