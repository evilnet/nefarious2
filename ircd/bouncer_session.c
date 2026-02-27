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
#include "capab.h"
#include "class.h"
#include "channel.h"
#include "client.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_osdep.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "listener.h"
#include "list.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "random.h"
#include "ircd_string.h"
#include "metadata.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "send.h"
#include "hash.h"
#include "s_auth.h"
#include "s_bsd.h"
#include "parse.h"
#include "s_conf.h"
#include "s_debug.h"
#include "handlers.h"
#include "s_misc.h"
#include "s_user.h"
#include "struct.h"
#include "version.h"

#include <assert.h>
#include <errno.h>
#include <mdbx.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#ifdef USE_SSL
#include "ssl.h"
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

/** Aggregate a shadow's lifetime counters into session totals.
 * Called when a shadow is removed (disconnect). */
static void bounce_accumulate_shadow(struct BouncerSession *session,
                                      struct ShadowConnection *shadow)
{
  session->hs_agg_sendB    += shadow->sh_sendB;
  session->hs_agg_receiveB += shadow->sh_receiveB;
  session->hs_agg_sendM    += shadow->sh_sendM;
  session->hs_agg_receiveM += shadow->sh_receiveM;
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
/* Deferred shadow free list                                         */
/* ---------------------------------------------------------------- */

/** List of shadow structs pending deferred free.
 *
 * When bounce_promote_shadow() runs inside an engine_loop event callback,
 * epoll may have returned events for BOTH the primary and shadow sockets
 * in the same batch.  Freeing the shadow immediately would leave a dangling
 * pointer in the events array — engine_loop would read freed memory when
 * processing the shadow's stale event.
 *
 * Instead, shadows are queued here and freed during timer_run(), which
 * runs AFTER all events in the current batch are processed.
 */
/* Forward declarations */
static void shadow_flush_sendq(struct ShadowConnection *shadow);
static void shadow_send_raw(struct ShadowConnection *shadow,
                             struct Client *primary,
                             const char *fmt, ...);

static struct ShadowConnection *deferred_free_head;
static struct Timer deferred_free_timer;
static int deferred_free_timer_active;

/** Timer callback: free all deferred shadow structs. */
static void deferred_shadow_free_cb(struct Event *ev)
{
  struct ShadowConnection *s, *next;
  for (s = deferred_free_head; s; s = next) {
    next = s->sh_next;
    if (s->sh_listener) {
      release_listener(s->sh_listener);
      s->sh_listener = NULL;
    }
    MyFree(s);
  }
  deferred_free_head = NULL;
  deferred_free_timer_active = 0;
}

/** Queue a shadow struct for deferred free (after current event batch). */
static void bounce_defer_shadow_free(struct ShadowConnection *shadow)
{
  shadow->sh_next = deferred_free_head;
  deferred_free_head = shadow;
  if (!deferred_free_timer_active) {
    timer_add(timer_init(&deferred_free_timer), deferred_shadow_free_cb,
              NULL, TT_ABSOLUTE, CurrentTime);
    deferred_free_timer_active = 1;
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

  /* ET_DESTROY is sent when timer_del() cancels the timer (e.g., during
   * bounce_attach).  Only the real expiry (ET_EXPIRE) should destroy
   * the session and exit the ghost.  Ignoring ET_DESTROY prevents a
   * use-after-free where bounce_attach → timer_del → ET_DESTROY →
   * bounce_hold_expire destroys the ghost that bounce_attach still
   * needs to transfer channels from. */
  if (ev_type(ev) == ET_DESTROY)
    return;

  session = (struct BouncerSession *)t_data(ev_timer(ev));

  if (session->hs_state != BOUNCE_HOLDING)
    return; /* Already resumed or destroyed */

  Debug((DEBUG_INFO, "Bouncer: hold expired for %s session %s",
         session->hs_account, session->hs_sessid));

  /* Get the ghost client before destroying session.
   * Note: hs_client stores the ghost during HOLDING state.
   */
  ghost = session->hs_client;

  /* Broadcast destruction to all servers */
  bounce_broadcast(session, 'X', NULL);

  /* Destroy session first (before exit_client) */
  bounce_destroy(session);

  /* Now exit the ghost client - this sends QUIT to channels and cleans up.
   * The ghost has FLAG_BOUNCER_HOLD set, but exit_one_client doesn't
   * know about that - it will just remove from channels normally.
   */
  if (ghost && IsBouncerHold(ghost)) {
    ClearBouncerHold(ghost);
    exit_client(ghost, ghost, &me, "Session expired");
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
 * @return 1 if any connection (primary or shadow) lacks TLS, 0 otherwise.
 */
int bounce_session_has_plaintext(struct Client *cptr)
{
#ifdef USE_SSL
  struct BouncerSession *session;
  struct ShadowConnection *shadow;

  session = bounce_get_session(cptr);
  if (!session || session->hs_state != BOUNCE_ACTIVE)
    return 0;

  /* Check primary */
  if (session->hs_client && !cli_socket(session->hs_client).ssl)
    return 1;

  /* Check all live shadows */
  for (shadow = session->hs_shadows; shadow; shadow = shadow->sh_next) {
    if (!(shadow->sh_flags & SHADOW_FLAGS_DEAD) && !shadow->sh_socket.ssl)
      return 1;
  }

  return 0;
#else
  return 0;
#endif
}

/** Check shadow liveness — send PINGs to idle shadows, timeout dead ones.
 * Called from check_pings() for bouncer primaries.  Each shadow has its
 * own independent PING cycle so clients can detect server unreachability.
 * @param[in] cptr Primary client of bouncer session.
 * @param[in] max_ping Ping interval in seconds.
 */
void bounce_check_shadow_pings(struct Client *cptr, int max_ping)
{
  struct BouncerSession *session;
  struct ShadowConnection *shadow;

  session = bounce_get_session(cptr);
  if (!session || session->hs_state != BOUNCE_ACTIVE || !session->hs_shadows)
    return;

  for (shadow = session->hs_shadows; shadow; shadow = shadow->sh_next) {
    if (shadow->sh_flags & SHADOW_FLAGS_DEAD)
      continue;

    /* Timeout: no data in max_ping*2 — mark dead */
    if (CurrentTime - shadow->sh_lasttime >= (time_t)(max_ping * 2)) {
      Debug((DEBUG_INFO, "Bouncer: shadow #%u for %s ping timeout (%ld seconds)",
             shadow->sh_id, cli_name(cptr),
             (long)(CurrentTime - shadow->sh_lasttime)));
      shadow->sh_flags |= SHADOW_FLAGS_DEAD;
      continue;
    }

    /* Idle: no data in max_ping — send PING if not already sent */
    if (CurrentTime - shadow->sh_lasttime >= (time_t)max_ping &&
        !(shadow->sh_flags & SHADOW_FLAGS_PINGSENT)) {
      struct MsgBuf *mb;
      mb = msgq_make(cptr, MSG_PING " :%s", cli_name(&me));
      if (mb) {
        msgq_add(&shadow->sh_sendQ, mb, 0);
        socket_events(&shadow->sh_socket,
                      SOCK_EVENT_READABLE | SOCK_EVENT_WRITABLE);
        msgq_clean(mb);
      }
      shadow->sh_flags |= SHADOW_FLAGS_PINGSENT;
      /* Reset lasttime like check_pings does for primaries — don't penalize
       * the shadow for the time we were late in noticing. */
      shadow->sh_lasttime = CurrentTime - max_ping;
    }
  }
}

/** SASL-triggered automatic resume.
 * Called from register_user() after SASL auth sets the account
 * but before the client is introduced to the network.
 *
 * Three outcomes:
 *   1. Held session found → resume it (return 1)
 *   2. Active session found → convert cptr to shadow connection (return 2)
 *   3. No session → auto-create one (return 0)
 *
 * @param[in] cptr Newly authenticated client.
 * @param[out] out_session Set to the session if resumed or created.
 * @return 1 if resumed a held session, 2 if converted to shadow, 0 otherwise.
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
  }

  /* Check for ACTIVE session — either orphaned (reclaim as primary) or
   * with an existing primary (attach as shadow connection).
   * An orphaned session is ACTIVE but has no primary (hs_client == NULL).
   * This can happen after server restart or when primary exits before
   * shadows and the session persists.  These sessions count toward the
   * per-account limit, so we must reclaim them rather than creating new ones. */
  session = bounce_find_any_session(account);
  if (session && session->hs_state == BOUNCE_ACTIVE) {
    if (!session->hs_client) {
      /* Orphaned ACTIVE session — reclaim as primary */
      Debug((DEBUG_INFO, "Bouncer: reclaiming orphaned ACTIVE session %s for %s",
             session->hs_sessid, cli_name(cptr)));
      if (bounce_attach(session, cptr) == 0) {
        bounce_broadcast(session, 'A', cli_yxx(cptr));
        *out_session = session;
        return 1;
      }
    } else {
      /* ACTIVE session with primary — attach as shadow connection */
#ifdef USE_SSL
      /* If BOUNCER_REQUIRE_TLS is set, skip shadow for plaintext clients */
      if (feature_bool(FEAT_BOUNCER_REQUIRE_TLS) && !cli_socket(cptr).ssl) {
        Debug((DEBUG_INFO, "Bouncer: skipping shadow for plaintext client %s (REQUIRE_TLS)",
               cli_name(cptr)));
        goto skip_shadow;
      }
      /* Gate A: Block plaintext shadow if primary is in any +Z channel.
       * One non-TLS connection compromises the entire session's +Z access.
       * The client falls through to normal registration with a NOTE. */
      if (!cli_socket(cptr).ssl && cli_user(session->hs_client)) {
        struct Membership *m;
        for (m = cli_user(session->hs_client)->channel; m; m = m->next_channel) {
          if (m->channel->mode.exmode & EXMODE_SSLONLY) {
            Debug((DEBUG_INFO,
                   "Bouncer: blocking plaintext shadow for %s (session in +Z channel %s)",
                   cli_name(cptr), m->channel->chname));
            sendrawto_one(cptr,
              ":%s NOTE BOUNCER TLS_REQUIRED "
              ":Cannot attach to session - active session is in SSL-only (+Z) "
              "channels. Connect with TLS to attach.",
              cli_name(&me));
            goto skip_shadow;
          }
        }
      }
#endif
      /* Convert this registering client into a shadow connection.
       * The Client struct will be freed; only the socket fd survives. */
      struct ShadowConnection *shadow;
      int fd;
      int new_fd;
      char sock_ip[SOCKIPLEN + 1];

      /* Extract fd and IP from the client's connection */
      fd = cli_fd(cptr);
      ircd_strncpy(sock_ip, cli_sock_ip(cptr), SOCKIPLEN + 1);

      /* dup() the fd so the shadow gets a clean fd not registered with the
       * event engine.  The original fd stays with the client's socket and
       * will be closed normally by exit_client() → close_connection(), which
       * also removes it from epoll.  Both fds share the underlying TCP
       * socket, so it stays alive as long as either fd is open. */
      new_fd = dup(fd);
      if (new_fd < 0) {
        Debug((DEBUG_ERROR, "Bouncer: dup(%d) failed for shadow conversion: %m", fd));
      } else {
        /* Create the shadow connection with the dup'd fd */
        shadow = bounce_add_shadow(session, new_fd, sock_ip);
        if (shadow) {
          /* Copy CAP state from the registering client to the shadow.
           * con_capab() and con_active() return pointers to CapSet structs. */
          memcpy(&shadow->sh_capab, con_capab(cli_connect(cptr)),
                 sizeof(struct CapSet));
          memcpy(&shadow->sh_active, con_active(cli_connect(cptr)),
                 sizeof(struct CapSet));
          shadow->sh_capab_version = con_capab_version(cli_connect(cptr));

          /* Copy pre-away state if any */
          shadow->sh_away_state = con_pre_away(cli_connect(cptr));
          if (shadow->sh_away_state == 1) {
            ircd_strncpy(shadow->sh_away_msg,
                         con_pre_away_msg(cli_connect(cptr)), AWAYLEN);
          }

#ifdef USE_SSL
          /* Transfer TLS state: steal SSL object from client, rebind to dup'd fd.
           * SSL_set_fd() creates a new BIO for the new fd; the old fd's BIO is
           * replaced.  After this, the SSL object operates on new_fd exclusively. */
          if (cli_socket(cptr).ssl) {
            shadow->sh_socket.ssl = cli_socket(cptr).ssl;
            if (SSL_set_fd(shadow->sh_socket.ssl, new_fd) != 1) {
              Debug((DEBUG_ERROR, "Bouncer: SSL_set_fd(%d) failed for shadow #%u",
                     new_fd, shadow->sh_id));
              /* SSL_set_fd failed — return SSL to client, remove broken shadow */
              shadow->sh_socket.ssl = NULL;
              bounce_remove_shadow(shadow);
              shadow = NULL;
              /* Fall through — shadow creation failed */
            } else {
              ssl_set_nonblocking(shadow->sh_socket.ssl);
              cli_socket(cptr).ssl = NULL;  /* Prevent exit_client from freeing */
              Debug((DEBUG_INFO, "Bouncer: transferred SSL to shadow #%u fd=%d",
                     shadow->sh_id, new_fd));
            }
          }
#endif

          if (shadow) {
            /* Capture connection metadata for later promotion.
             * The Client struct will be freed by exit_client after we
             * return, so copy everything we'll need to restore the
             * primary's identity if this shadow gets promoted. */
            shadow->sh_port = cli_port(cptr);
            ircd_strncpy(shadow->sh_sockhost, cli_sockhost(cptr), HOSTLEN + 1);
            memcpy(&shadow->sh_ip, &cli_ip(cptr), sizeof(struct irc_in_addr));
            memcpy(&shadow->sh_connectip, &cli_connectip(cptr), sizeof(struct irc_in_addr));
            ircd_strncpy(shadow->sh_connecthost, cli_connecthost(cptr), HOSTLEN + 1);
            shadow->sh_listener = con_listener(cli_connect(cptr));
            if (shadow->sh_listener)
              shadow->sh_listener->ref_count++;  /* Own ref; exit_client releases cptr's */

            /* Record connect event in connection history */
            bounce_history_connect(session, sock_ip, cli_sockhost(cptr));

            /* Notify existing connections about the new shadow.
             * Mirrors X3/AuthServ's "authed to your account" warning. */
            {
              struct Client *primary = session->hs_client;
              struct ShadowConnection *s;

              /* Notify primary */
              sendrawto_one(primary, ":%s NOTICE %s :Warning: %s (%s@%s) connected to your session.",
                            cli_name(&me), cli_name(primary),
                            cli_name(cptr), cli_user(cptr)->username, sock_ip);

              /* Notify existing shadows (skip the newly added one) */
              for (s = session->hs_shadows; s; s = s->sh_next) {
                if (s != shadow && !(s->sh_flags & SHADOW_FLAGS_DEAD))
                  shadow_send_raw(s, primary,
                                  ":%s NOTICE %s :Warning: %s (%s@%s) connected to your session.",
                                  cli_name(&me), cli_name(primary),
                                  cli_name(cptr), cli_user(cptr)->username, sock_ip);
              }
            }

            /* Recompute session union caps now that this shadow's caps are in play */
            bounce_recompute_session_caps(session->hs_client);

            Debug((DEBUG_INFO, "Bouncer: converted %s to shadow #%u on session %s",
                   cli_name(cptr), shadow->sh_id, session->hs_sessid));

            *out_session = session;

            /* Send registration sequence to the shadow.
             * This happens AFTER the Client is freed in register_user(),
             * so we queue it via bounce_send_shadow_welcome(). */

            return 2; /* Signal: converted to shadow, do not introduce to network */
          }
        } else {
          /* Failed to create shadow — close the dup'd fd */
          close(new_fd);
        }
      }
    }
  }
#ifdef USE_SSL
skip_shadow:
#endif

  /* No held session — auto-create only if account has NO sessions at all.
   * If sessions already exist (all ACTIVE), this is just a second connection
   * to the same account — don't create a duplicate session. */
  if (bounce_count(account) == 0) {
    max_sessions = feature_int(FEAT_BOUNCER_MAX_SESSIONS);
    if (max_sessions > 0) {
      if (bounce_create(cptr, &session) == 0) {
        bounce_broadcast(session, 'C', NULL);
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
  session->hs_shadows = NULL;
  session->hs_shadow_count = 0;
  session->hs_client_id_seq = 1; /* Primary gets ID 1 */
  session->hs_primary_id = 1;
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

    /* Clean up the ghost client - it no longer has channels */
    ClearBouncerHold(ghost);
    /* Use exit_client to properly clean up the ghost.
     * Pass a "silent" flag via FLAG_KILLED to suppress QUIT broadcast.
     */
    SetFlag(ghost, FLAG_KILLED);
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

  /* Recompute session union caps for the new primary + existing shadows */
  bounce_recompute_session_caps(cptr);

  return 0;
}

/** Compute adaptive hold time for a session based on usage history.
 * Sessions with more connections (resumes + shadow attaches) earn longer
 * hold times.  This rewards active use — a mobile device connecting as a
 * shadow counts the same as a full resume from HOLDING.
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
  struct ShadowConnection *shadow, *next;

  assert(0 != session);

  /* Cancel timer if active */
  if (t_active(&session->hs_hold_timer))
    timer_del(&session->hs_hold_timer);

  /* Clean up all shadow connections */
  for (shadow = session->hs_shadows; shadow; shadow = next) {
    next = shadow->sh_next;
    if (current_shadow == shadow)
      current_shadow = NULL;
    /* Best-effort flush of pending data (KILL/ERROR/etc.) before closing */
    if (MsgQLength(&shadow->sh_sendQ) > 0 && shadow->sh_fd >= 0)
      shadow_flush_sendq(shadow);
    /* Clear s_data BEFORE socket_del to prevent the synchronous
     * ET_DESTROY handler from freeing the shadow (which would make
     * the MsgQClear/dbuf_delete below use-after-free). */
    s_data(&shadow->sh_socket) = NULL;
    if (shadow->sh_listener) {
      release_listener(shadow->sh_listener);
      shadow->sh_listener = NULL;
    }
#ifdef USE_SSL
    ssl_free(&shadow->sh_socket);
    shadow->sh_socket.ssl = NULL;
#endif
    socket_del(&shadow->sh_socket);
    if (shadow->sh_fd >= 0) {
      close(shadow->sh_fd);
      shadow->sh_fd = -1;
    }
    MsgQClear(&shadow->sh_sendQ);
    dbuf_delete(&shadow->sh_recvQ, DBufLength(&shadow->sh_recvQ));
    /* Defer free: a stale epoll event may still reference
     * &shadow->sh_socket in the current engine_loop batch. */
    bounce_defer_shadow_free(shadow);
  }
  session->hs_shadows = NULL;
  session->hs_shadow_count = 0;

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
  struct Client *ghost;
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

  /* Ghost client identity (if client exists) */
  ghost = session->hs_client;
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
    session->hs_shadows = NULL;
    session->hs_shadow_count = 0;
    session->hs_client_id_seq = 1;
    session->hs_primary_id = 0;
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

/** Build channel list string for BS protocol messages.
 * @param[in] session Session to serialize channels from.
 * @param[out] buf Output buffer.
 * @param[in] buflen Buffer size.
 */
static void build_channel_string(struct BouncerSession *session,
                                 char *buf, size_t buflen)
{
  int i;
  size_t pos = 0;

  buf[0] = '\0';
  for (i = 0; i < session->hs_chancount && pos < buflen - 1; i++) {
    if (i > 0 && pos < buflen - 1)
      buf[pos++] = ',';
    pos += ircd_snprintf(0, buf + pos, buflen - pos, "%s",
                         session->hs_channels[i].name);
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
    session->hs_shadows = NULL;
    session->hs_shadow_count = 0;
    session->hs_client_id_seq = 0;
    session->hs_primary_id = 0;
    session->hs_effective_away = 0;
    session->hs_effective_away_msg[0] = '\0';
    session->hs_created = created;
    session->hs_last_active = created;
    session->hs_attach_count = attach_count;
    session->hs_total_active = total_active;

    if (is_holding) {
      session->hs_state = BOUNCE_HOLDING;
      session->hs_disconnect_time = disconnect_time;

      /* Start local hold timer with adaptive duration */
      hold_time = bounce_compute_hold_time(session);
      timer_init(&session->hs_hold_timer);
      timer_add(&session->hs_hold_timer, bounce_hold_expire,
                (void *)session, TT_RELATIVE, hold_time);
    } else {
      session->hs_state = BOUNCE_ACTIVE;
      session->hs_disconnect_time = 0;
    }

    /* Parse channel list */
    if (channels && *channels) {
      char chanlist[512];
      char *tok, *saveptr;
      int i = 0;

      ircd_strncpy(chanlist, channels, sizeof(chanlist) - 1);
      for (tok = strtok_r(chanlist, ",", &saveptr);
           tok && i < BOUNCER_MAX_CHANNELS;
           tok = strtok_r(NULL, ",", &saveptr)) {
        ircd_strncpy(session->hs_channels[i].name, tok, CHANNELLEN + 1);
        session->hs_channels[i].modes = 0;
        i++;
      }
      session->hs_chancount = i;
    }

    /* Add to local registry */
    token_hash_add(session);
    as = account_sessions_get(session->hs_account, 1);
    account_add_session(as, session);

    /* Forward to other servers (standard P10 propagation) */
    sendcmdto_serv_butone(sptr, CMD_BOUNCER_SESSION,
                          cptr,
                          "C %s %s %s %s %s %s :%s",
                          account, sessid, token, state_str,
                          parv[6],
                          (parc >= 8 && disconnect_time) ? parv[7] : "",
                          channels ? channels : "");
    break;
  }

  case 'A': /* Attach */
  {
    session = bounce_find_by_token_sessid(account, sessid);
    if (!session)
      return 0;

    /* Cancel hold timer */
    if (t_active(&session->hs_hold_timer))
      timer_del(&session->hs_hold_timer);

    session->hs_state = BOUNCE_ACTIVE;
    session->hs_last_active = CurrentTime;
    session->hs_disconnect_time = 0;

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
    session->hs_client = NULL;
    session->hs_disconnect_time = disc_time;
    ircd_strncpy(session->hs_ghost_numeric, ghost_numeric,
                 sizeof(session->hs_ghost_numeric) - 1);
    session->hs_ghost_numeric[sizeof(session->hs_ghost_numeric) - 1] = '\0';

    /* Update channels if provided */
    if (channels && *channels) {
      char chanlist[512];
      char *tok, *saveptr;
      int i = 0;

      ircd_strncpy(chanlist, channels, sizeof(chanlist) - 1);
      for (tok = strtok_r(chanlist, ",", &saveptr);
           tok && i < BOUNCER_MAX_CHANNELS;
           tok = strtok_r(NULL, ",", &saveptr)) {
        ircd_strncpy(session->hs_channels[i].name, tok, CHANNELLEN + 1);
        session->hs_channels[i].modes = 0;
        i++;
      }
      session->hs_chancount = i;
    }

    /* Start hold timer */
    hold_time = feature_int(FEAT_BOUNCER_SESSION_HOLD);
    timer_init(&session->hs_hold_timer);
    timer_add(&session->hs_hold_timer, bounce_hold_expire,
              (void *)session, TT_RELATIVE, hold_time);

    /* Forward */
    sendcmdto_serv_butone(sptr, CMD_BOUNCER_SESSION,
                          cptr,
                          "D %s %s %s %Tu :%s",
                          account, sessid, ghost_numeric, disc_time,
                          channels ? channels : "");
    break;
  }

  case 'X': /* Destroy */
  {
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
/* Phase 2: Hold mode                                                */
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
 * @param[in] session The HOLDING session to revive.
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

  if (!session || session->hs_state != BOUNCE_HOLDING)
    return -1;

  ghost = session->hs_client;
  if (!ghost || !MyUser(ghost) || !IsBouncerHold(ghost))
    return -1;

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

  /* Mark session as ACTIVE before canceling timer.
   * This prevents a race where an already-queued ET_EXPIRE event
   * (processed after timer_del but before we reach the state update
   * at the end of this function) could trigger bounce_hold_expire
   * to destroy the session while we're still reviving it. */
  session->hs_state = BOUNCE_ACTIVE;

  /* Cancel hold timer if running */
  if (t_active(&session->hs_hold_timer))
    timer_del(&session->hs_hold_timer);

  /* Step 1: Steal the temp client's fd and SSL.
   * Clear s_data BEFORE socket_del to prevent stale callbacks.
   * IMPORTANT: Also save and NULL the SSL pointer BEFORE socket_del,
   * because socket_del triggers ET_DESTROY which calls ssl_free().
   * If we don't NULL it first, the SSL context gets freed before we
   * can transfer it to the ghost. */
  fd = cli_fd(temp);
  s_data(&cli_socket(temp)) = NULL;
#ifdef USE_SSL
  {
    SSL *temp_ssl = con_socket(temp_con).ssl;
    con_socket(temp_con).ssl = NULL;  /* Prevent ssl_free from freeing it */
    socket_del(&cli_socket(temp));
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
  socket_del(&cli_socket(temp));
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
  session->hs_primary_id = ++session->hs_client_id_seq;

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
  ClearBouncerHold(ghost);
  ClrFlag(ghost, FLAG_DEADSOCKET);

  /* Step 12: Clear CHFL_HOLDING on all channel memberships */
  if (cli_user(ghost)) {
    for (member = cli_user(ghost)->channel; member; member = member->next_channel) {
      ClearMemberHolding(member);
    }
  }

  /* Step 13: Update session state (hs_state already set to ACTIVE earlier) */
  session->hs_client = ghost;
  session->hs_attach_count++;
  session->hs_connect_count++;
  session->hs_last_active = CurrentTime;
  session->hs_disconnect_time = 0;

  /* Session is live again — remove persisted state */
  bounce_db_del(session->hs_sessid);

  /* Recompute session union caps */
  bounce_recompute_session_caps(ghost);

  /* Broadcast session attach to other servers */
  bounce_broadcast(session, 'A', cli_yxx(ghost));

  log_write(LS_USER, L_TRACE, 0,
            "Bouncer: ghost %s revived via socket transplant for session %s",
            cli_name(ghost), session->hs_sessid);

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
/* Cross-server transfer (BT token)                                  */
/* ---------------------------------------------------------------- */

/** Handle BT (Bouncer Transfer) P10 message.
 * Format: BT <old-numeric> <new-numeric> <session-id>
 *
 * This message is broadcast when a user resumes their bouncer session
 * on a different server than where the ghost exists. All servers
 * receiving this message transfer channel memberships from the old
 * client (ghost) to the new client.
 */
int bounce_handle_bt(struct Client *cptr, struct Client *sptr,
                     int parc, char *parv[])
{
  struct Client *old_client;
  struct Client *new_client;
  const char *old_numeric;
  const char *new_numeric;
  const char *sessid;
  struct Membership *member;
  struct Membership *next_member;

  if (parc < 4)
    return 0;

  old_numeric = parv[1];
  new_numeric = parv[2];
  sessid = parv[3];

  /* Find both clients by numeric */
  old_client = findNUser(old_numeric);
  new_client = findNUser(new_numeric);

  if (!old_client || !new_client) {
    Debug((DEBUG_INFO, "BT: client not found - old=%s new=%s",
           old_numeric, new_numeric));
    /* Forward anyway for other servers */
    sendcmdto_serv_butone(sptr, CMD_BOUNCER_TRANSFER, cptr,
                          "%s %s %s", old_numeric, new_numeric, sessid);
    return 0;
  }

  /* Transfer channel memberships from old to new */
  for (member = cli_user(old_client)->channel; member; member = next_member) {
    next_member = member->next_channel;

    /* Add new client with old client's modes */
    unsigned int modes = member->status & ~CHFL_HOLDING;
    add_user_to_channel(member->channel, new_client, modes, OpLevel(member));

    /* Remove old client silently */
    remove_user_from_channel(old_client, member->channel);
  }

  /* Clear bouncer flags from old client */
  if (IsBouncerHold(old_client))
    ClearBouncerHold(old_client);

  /* Exit the old client silently (FLAG_KILLED suppresses QUIT broadcast) */
  SetFlag(old_client, FLAG_KILLED);
  exit_client(old_client, old_client, &me, "Session transferred");

  /* Forward to other servers */
  sendcmdto_serv_butone(sptr, CMD_BOUNCER_TRANSFER, cptr,
                        "%s %s %s", old_numeric, new_numeric, sessid);

  return 0;
}

/** Initiate a cross-server bouncer transfer.
 * Called when BOUNCER RESUME is received and the ghost is on another server.
 * Broadcasts BT to network to transfer the ghost's channels to the new client.
 */
void bounce_initiate_transfer(struct BouncerSession *session,
                              struct Client *new_client,
                              const char *old_numeric)
{
  /* Broadcast the transfer request */
  sendcmdto_serv_butone(&me, CMD_BOUNCER_TRANSFER, NULL,
                        "%s %s %s",
                        old_numeric, cli_yxx(new_client), session->hs_sessid);

  /* Update session state */
  session->hs_state = BOUNCE_ACTIVE;
  session->hs_client = new_client;
  session->hs_last_active = CurrentTime;
  session->hs_disconnect_time = 0;

  /* Cancel hold timer */
  if (t_active(&session->hs_hold_timer))
    timer_del(&session->hs_hold_timer);
}

/* ---------------------------------------------------------------- */
/* Shadow connection management (multi-client support)               */
/* ---------------------------------------------------------------- */

/** Global pointer to the shadow that originated the current command.
 * Used for reply routing in send.c — when a shadow sends a command,
 * replies are directed to the shadow instead of (or in addition to)
 * the primary connection. NULL when the primary is the source.
 */
struct ShadowConnection *current_shadow = NULL;

/** Flush a shadow connection's sendQ to its socket.
 * Analogous to deliver_it() for normal clients, but operates directly
 * on a ShadowConnection's fd and MsgQ.
 */
static void shadow_flush_sendq(struct ShadowConnection *shadow)
{
  unsigned int bytes_written = 0;
  unsigned int bytes_count = 0;
  IOResult result;

  if (shadow->sh_flags & SHADOW_FLAGS_DEAD)
    return;

  if (MsgQLength(&shadow->sh_sendQ) == 0)
    return;

#ifdef USE_SSL
  if (shadow->sh_socket.ssl) {
    struct Client *primary = (shadow->sh_session && shadow->sh_session->hs_client)
                             ? shadow->sh_session->hs_client : NULL;
    if (!primary) { shadow->sh_flags |= SHADOW_FLAGS_DEAD; return; }
    result = ssl_sendv(&shadow->sh_socket, primary,
                       &shadow->sh_sendQ, &bytes_count, &bytes_written);
  } else
#endif
  {
    result = os_sendv_nonb(shadow->sh_fd, &shadow->sh_sendQ,
                           &bytes_count, &bytes_written);
  }

  switch (result) {
  case IO_SUCCESS:
    shadow->sh_flags &= ~SHADOW_FLAGS_BLOCKED;
    if (bytes_written > 0) {
      msgq_delete(&shadow->sh_sendQ, bytes_written);
      shadow->sh_sendB += bytes_written;
    }
    if (bytes_written < bytes_count)
      shadow->sh_flags |= SHADOW_FLAGS_BLOCKED;
    break;
  case IO_BLOCKED:
    shadow->sh_flags |= SHADOW_FLAGS_BLOCKED;
    break;
  case IO_FAILURE:
    shadow->sh_flags |= SHADOW_FLAGS_DEAD;
    break;
  }
}

/** Handle a CAP command from a shadow connection locally.
 *
 * Shadow CAP commands must be processed here rather than forwarded to
 * parse_client(primary), because CAP modifies per-connection state.
 * Forwarding would modify the primary's caps instead of the shadow's.
 *
 * Supports the REQ and LIST subcommands. LS is not meaningful post-
 * registration but is handled for completeness. END is a no-op.
 *
 * @param[in] shadow The shadow connection that sent CAP.
 * @param[in] primary The session's primary client.
 * @param[in] args The CAP arguments (everything after "CAP ").
 */
static void
shadow_handle_cap(struct ShadowConnection *shadow, struct Client *primary,
                  const char *args)
{
  char buf[BUFSIZE];
  struct MsgBuf *mb;
  const char *subcmd;
  const char *caplist;

  if (!args || !*args)
    return;

  /* Parse subcmd */
  ircd_strncpy(buf, args, sizeof(buf) - 1);
  buf[sizeof(buf) - 1] = '\0';
  subcmd = buf;

  /* Skip to end of subcmd */
  caplist = subcmd;
  while (*caplist && !IsSpace(*caplist))
    caplist++;
  if (*caplist) {
    /* Null-terminate subcmd, advance caplist past space */
    buf[caplist - buf] = '\0';
    caplist++;
    /* Skip leading colon if present */
    if (*caplist == ':')
      caplist++;
  } else {
    caplist = NULL;
  }

  if (0 == ircd_strcmp(subcmd, "REQ") && caplist && *caplist) {
    /* Process CAP REQ for the shadow */
    const char *cl = caplist;
    struct CapSet set, rem;
    int neg, cap_id;
    unsigned long flags;
    int any_unknown = 0;

    memset(&set, 0, sizeof(set));
    memset(&rem, 0, sizeof(rem));

    while (cl) {
      if (!cap_lookup(&cl, &neg, &cap_id, &flags)) {
        any_unknown = 1;
        continue;
      }

      if (neg) {
        if (flags & CAPFL_STICKY)
          continue;
        CapSet(&rem, cap_id);
      } else {
        if (flags & CAPFL_PROHIBIT)
          continue;
        CapSet(&set, cap_id);
      }
    }

    if (any_unknown) {
      /* NAK the entire request per CAP spec */
      mb = msgq_make(primary, ":%s CAP %s NAK :%s\r\n",
                     cli_name(&me), cli_name(primary), caplist);
    } else {
      /* Apply changes to shadow's caps */
      unsigned int i;
      unsigned int nwords = sizeof(shadow->sh_active.bits) / sizeof(shadow->sh_active.bits[0]);
      for (i = 0; i < nwords; i++) {
        shadow->sh_active.bits[i] |= set.bits[i];
        shadow->sh_active.bits[i] &= ~rem.bits[i];
        shadow->sh_capab.bits[i] |= set.bits[i];
        shadow->sh_capab.bits[i] &= ~rem.bits[i];
      }

      /* Recompute session union */
      bounce_recompute_session_caps(primary);

      /* ACK to shadow */
      mb = msgq_make(primary, ":%s CAP %s ACK :%s\r\n",
                     cli_name(&me), cli_name(primary), caplist);
    }

    if (mb) {
      msgq_add(&shadow->sh_sendQ, mb, 0);
      msgq_clean(mb);
    }
  }
  else if (0 == ircd_strcmp(subcmd, "LIST")) {
    /* Send shadow's active caps back */
    /* For simplicity, just ACK with empty list — shadow already knows its caps */
    mb = msgq_make(primary, ":%s CAP %s LIST :\r\n",
                   cli_name(&me), cli_name(primary));
    if (mb) {
      msgq_add(&shadow->sh_sendQ, mb, 0);
      msgq_clean(mb);
    }
  }
  else if (0 == ircd_strcmp(subcmd, "END")) {
    /* No-op for post-registration shadow */
  }
  /* LS, other subcmds: silently ignore for shadows */
}

/** Read data from a shadow connection and forward commands to primary.
 *
 * Reads bytes from the shadow's socket, buffers them, extracts complete
 * lines (terminated by \r\n), and dispatches each line through
 * parse_client() with the primary Client as cptr.
 *
 * The global current_shadow is set before dispatch so that reply routing
 * can direct responses to this shadow.
 *
 * @param[in] shadow Shadow connection to read from.
 * @return 0 on success, -1 if shadow should be removed.
 */
static int shadow_read_packet(struct ShadowConnection *shadow)
{
  struct BouncerSession *session = shadow->sh_session;
  struct Client *primary;
  char readbuf[BUFSIZE];
  int length;
  IOResult result;
  char *s, *end;

  if (!session || session->hs_state != BOUNCE_ACTIVE || !session->hs_client)
    return -1;

  primary = session->hs_client;

#ifdef USE_SSL
shadow_ssl_read_again:
#endif
  /* Read from shadow's socket */
#ifdef USE_SSL
  if (shadow->sh_socket.ssl)
    result = ssl_recv(&shadow->sh_socket, primary, readbuf,
                      sizeof(readbuf) - 1, (unsigned int *)&length);
  else
#endif
    result = os_recv_nonb(shadow->sh_fd, readbuf, sizeof(readbuf) - 1,
                          (unsigned int *)&length);

  switch (result) {
  case IO_SUCCESS:
    if (length <= 0)
      return -1; /* EOF */
    break;
  case IO_BLOCKED:
    return 0; /* Nothing to read right now */
  case IO_FAILURE:
    return -1; /* Socket error */
  }

  shadow->sh_lasttime = CurrentTime;
  shadow->sh_flags &= ~SHADOW_FLAGS_PINGSENT;
  shadow->sh_receiveB += length;

  /* Append to shadow's parse buffer */
  if (shadow->sh_count + length >= BUFSIZE) {
    /* Buffer overflow — discard excess */
    length = BUFSIZE - shadow->sh_count - 1;
    if (length <= 0)
      return 0;
  }
  memcpy(shadow->sh_buffer + shadow->sh_count, readbuf, length);
  shadow->sh_count += length;
  shadow->sh_buffer[shadow->sh_count] = '\0';

  /* Extract and process complete lines */
  s = shadow->sh_buffer;
  while ((end = strchr(s, '\n')) != NULL) {
    /* Null-terminate this line (strip \r\n) */
    *end = '\0';
    if (end > s && *(end - 1) == '\r')
      *(end - 1) = '\0';

    if (*s != '\0') {
      int line_len = strlen(s);
      shadow->sh_receiveM++;

      /* Handle QUIT from shadow — disconnect this shadow only */
      if (line_len >= 4 && 0 == ircd_strncmp(s, "QUIT", 4) &&
          (s[4] == '\0' || s[4] == ' ')) {
        shadow->sh_flags |= SHADOW_FLAGS_DEAD;
        return -1;
      }

      /* Handle PING locally for the shadow — respond with PONG */
      if (line_len >= 4 && 0 == ircd_strncmp(s, "PING", 4)) {
        struct MsgBuf *mb;
        const char *param = (s[4] == ' ') ? s + 5 : cli_name(&me);
        /* msgq_make appends \r\n, so don't include it in the format */
        mb = msgq_make(primary, ":%s PONG %s :%s",
                       cli_name(&me), cli_name(&me), param);
        if (mb) {
          msgq_add(&shadow->sh_sendQ, mb, 0);
          socket_events(&shadow->sh_socket, SOCK_EVENT_READABLE | SOCK_EVENT_WRITABLE);
          msgq_clean(mb);
        }
        shadow->sh_lasttime = CurrentTime;
        shadow->sh_flags &= ~SHADOW_FLAGS_PINGSENT;
        s = end + 1;
        continue;
      }

      /* Handle PONG locally — update shadow liveness, don't forward to primary */
      if (line_len >= 4 && 0 == ircd_strncmp(s, "PONG", 4)) {
        shadow->sh_lasttime = CurrentTime;
        shadow->sh_flags &= ~SHADOW_FLAGS_PINGSENT;
        s = end + 1;
        continue;
      }

      /* Handle CAP from shadow — process locally instead of forwarding
       * to primary, since CAP modifies the *connection's* capabilities.
       * If forwarded via parse_client(primary), it would modify the
       * primary's caps instead of the shadow's. */
      if (line_len >= 3 && 0 == ircd_strncmp(s, "CAP", 3) &&
          (s[3] == '\0' || s[3] == ' ')) {
        shadow_handle_cap(shadow, primary, s + (s[3] == ' ' ? 4 : 3));
        s = end + 1;
        continue;
      }

      /* Forward command to primary Client.
       * Set current_shadow so reply routing directs responses to this shadow.
       */
      current_shadow = shadow;
      {
        char line_copy[BUFSIZE];
        ircd_strncpy(line_copy, s, sizeof(line_copy) - 1);
        line_copy[sizeof(line_copy) - 1] = '\0';
        parse_client(primary, line_copy, line_copy + strlen(line_copy));
      }
      current_shadow = NULL;

      /* Check if primary was killed by the command */
      if (IsDead(primary)) {
        return -1;
      }
    }

    s = end + 1;
  }

  /* Compact remaining partial data to start of buffer */
  if (s > shadow->sh_buffer) {
    unsigned int remaining = shadow->sh_count - (s - shadow->sh_buffer);
    if (remaining > 0)
      memmove(shadow->sh_buffer, s, remaining);
    shadow->sh_count = remaining;
    shadow->sh_buffer[remaining] = '\0';
  }

#ifdef USE_SSL
  /* Drain SSL internal buffer — OpenSSL may have decrypted multiple IRC
   * commands from a single TLS record.  Without this, commands buffered
   * inside OpenSSL stall until the next network read triggers epoll. */
  if (shadow->sh_socket.ssl && ssl_pending(&shadow->sh_socket) > 0)
    goto shadow_ssl_read_again;
#endif

  return 0;
}

/** Socket event callback for shadow connections.
 * Handles readable/writable/error events on shadow sockets.
 */
static void shadow_sock_callback(struct Event *ev)
{
  struct ShadowConnection *shadow;

  assert(0 != ev_socket(ev));

  shadow = (struct ShadowConnection *)s_data(ev_socket(ev));

  /* Guard against stale events for already-promoted/removed shadows.
   * bounce_promote_shadow() clears s_data before socket_del(); if a stale
   * event slips through (e.g. same epoll_wait batch), shadow will be NULL. */
  if (!shadow) {
    if (ev_type(ev) != ET_DESTROY)
      Debug((DEBUG_INFO, "Bouncer: ignoring stale shadow event (type=%d, s_data=NULL)",
             ev_type(ev)));
    return;
  }

  switch (ev_type(ev)) {
  case ET_DESTROY:
    /* Socket is being destroyed — free the shadow struct if still valid.
     * bounce_remove_shadow() defers the free to here so the event engine
     * never accesses freed memory in the epoll dispatch loop.
     * bounce_promote_shadow() and bounce_destroy() clear s_data before
     * socket_del() and use bounce_defer_shadow_free() instead. */
    if (shadow) {
#ifdef USE_SSL
      ssl_free(&shadow->sh_socket);
#endif
      if (shadow->sh_listener) {
        release_listener(shadow->sh_listener);
        shadow->sh_listener = NULL;
      }
      MyFree(shadow);
    }
    return;

  case ET_READ:
    /* Read and forward commands from shadow to primary */
    if (shadow_read_packet(shadow) < 0) {
      struct BouncerSession *sess = shadow->sh_session;
      /* Flush any pending data (e.g. KILL/ERROR messages) before
       * closing — the shadow's sendQ may have been populated by
       * send_buffer's dup loop but never written to the fd yet. */
      if (MsgQLength(&shadow->sh_sendQ) > 0)
        shadow_flush_sendq(shadow);
      shadow->sh_flags |= SHADOW_FLAGS_DEAD;
      bounce_remove_shadow(shadow);
      /* Fix #23: If removing this shadow leaves the session orphaned
       * (no primary client and no remaining shadows), destroy it.
       * This happens when the primary QUITs while shadows are still
       * connected — exit_one_client NULLs hs_client but can't destroy
       * because shadows exist.  When the last shadow disconnects,
       * nobody was destroying the orphaned session. */
      if (sess && !sess->hs_client && !sess->hs_shadows) {
        bounce_broadcast(sess, 'X', NULL);
        bounce_destroy(sess);
      }
      return;
    }
    break;

  case ET_WRITE:
    /* Flush shadow sendQ to its socket */
    shadow_flush_sendq(shadow);
    /* Keep requesting writes if data remains (even if blocked — we need
     * the write event to know when the OS buffer drains). */
    if (MsgQLength(&shadow->sh_sendQ) > 0) {
      socket_events(&shadow->sh_socket, SOCK_EVENT_READABLE | SOCK_EVENT_WRITABLE);
    } else {
      /* sendQ drained — stop requesting writable events */
      socket_events(&shadow->sh_socket, SOCK_EVENT_READABLE);
    }
    break;

  case ET_ERROR:
  {
    /* Shadow connection error — remove it */
    struct BouncerSession *sess = shadow->sh_session;
    /* Best-effort flush of pending data before closing */
    if (MsgQLength(&shadow->sh_sendQ) > 0)
      shadow_flush_sendq(shadow);
    shadow->sh_flags |= SHADOW_FLAGS_DEAD;
    bounce_remove_shadow(shadow);
    /* Fix #23: destroy orphaned session (see ET_READ comment) */
    if (sess && !sess->hs_client && !sess->hs_shadows) {
      bounce_broadcast(sess, 'X', NULL);
      bounce_destroy(sess);
    }
    break;
  }

  case ET_EOF:
  {
    /* Shadow disconnected */
    struct BouncerSession *sess = shadow->sh_session;
    shadow->sh_flags |= SHADOW_FLAGS_DEAD;
    bounce_remove_shadow(shadow);
    /* Fix #23: destroy orphaned session (see ET_READ comment) */
    if (sess && !sess->hs_client && !sess->hs_shadows) {
      bounce_broadcast(sess, 'X', NULL);
      bounce_destroy(sess);
    }
    break;
  }

  default:
    break;
  }
}

/** Add a shadow connection to a bouncer session.
 *
 * Creates a new ShadowConnection with its own socket, sendQ, recvQ,
 * and CAP state. The shadow is NOT added to the nick hash or channel
 * lists — it piggybacks on the primary Client's identity.
 */
struct ShadowConnection *bounce_add_shadow(struct BouncerSession *session,
                                            int fd,
                                            const char *sock_ip)
{
  struct ShadowConnection *shadow;
  int max_shadows;

  assert(0 != session);
  assert(session->hs_state == BOUNCE_ACTIVE);

  /* Enforce per-session shadow limit */
  max_shadows = feature_int(FEAT_BOUNCER_MAX_SHADOWS);
  if (max_shadows > 0 && session->hs_shadow_count >= max_shadows)
    return NULL;

  /* Allocate and initialize */
  shadow = (struct ShadowConnection *)MyCalloc(1, sizeof(*shadow));
  shadow->sh_id = ++session->hs_client_id_seq;
  shadow->sh_fd = fd;
  shadow->sh_session = session;
  shadow->sh_lasttime = CurrentTime;
  shadow->sh_since = CurrentTime;
  shadow->sh_connected = CurrentTime;
  shadow->sh_away_state = 0;  /* Present by default */
  shadow->sh_away_msg[0] = '\0';
  shadow->sh_flags = 0;
  shadow->sh_count = 0;
  shadow->sh_buffer[0] = '\0';
  shadow->sh_label[0] = '\0';
  shadow->sh_label_responded = 0;
  shadow->sh_capab_version = 0;

  /* Copy remote IP */
  if (sock_ip)
    ircd_strncpy(shadow->sh_sock_ip, sock_ip, SOCKIPLEN + 1);
  else
    shadow->sh_sock_ip[0] = '\0';

  /* Initialize sendQ and recvQ */
  msgq_init(&shadow->sh_sendQ);
  /* DBuf is zero-initialized by MyCalloc */

  /* Initialize CAP sets to zero (no caps negotiated yet) */
  memset(&shadow->sh_capab, 0, sizeof(shadow->sh_capab));
  memset(&shadow->sh_active, 0, sizeof(shadow->sh_active));

  /* Register shadow socket with event engine */
  if (!socket_add(&shadow->sh_socket, shadow_sock_callback,
                  (void *)shadow, SS_CONNECTED, SOCK_EVENT_READABLE, fd)) {
    Debug((DEBUG_ERROR, "Bouncer: failed to add shadow socket fd=%d", fd));
    MyFree(shadow);
    close(fd);
    return NULL;
  }

  /* Add to session's shadow list (prepend) */
  shadow->sh_next = session->hs_shadows;
  session->hs_shadows = shadow;
  session->hs_shadow_count++;
  session->hs_connect_count++;

  Debug((DEBUG_INFO, "Bouncer: added shadow #%u to session %s (fd=%d, ip=%s, total=%d)",
         shadow->sh_id, session->hs_sessid, fd,
         sock_ip ? sock_ip : "?", session->hs_shadow_count));

  return shadow;
}

/** Remove a shadow connection from its session.
 * Cleans up the shadow's sendQ, recvQ, socket, and frees the struct.
 */
void bounce_remove_shadow(struct ShadowConnection *shadow)
{
  struct BouncerSession *session;
  struct ShadowConnection **pp;

  assert(0 != shadow);
  session = shadow->sh_session;
  assert(0 != session);

  /* Unlink from session's shadow list */
  for (pp = &session->hs_shadows; *pp; pp = &(*pp)->sh_next) {
    if (*pp == shadow) {
      *pp = shadow->sh_next;
      session->hs_shadow_count--;
      break;
    }
  }

  Debug((DEBUG_INFO, "Bouncer: removing shadow #%u from session %s (remaining=%d)",
         shadow->sh_id, session->hs_sessid, session->hs_shadow_count));

  /* Roll shadow's lifetime data counters into session aggregates */
  bounce_accumulate_shadow(session, shadow);

  /* Record disconnect event in connection history */
  bounce_history_disconnect(session, shadow->sh_sock_ip);

  /* Recompute session union caps — this shadow's caps are no longer part of the session */
  if (session->hs_client && MyConnect(session->hs_client))
    bounce_recompute_session_caps(session->hs_client);

  /* Clear current_shadow if this shadow is the active command source */
  if (current_shadow == shadow)
    current_shadow = NULL;

  /* Release listener reference before cleanup */
  if (shadow->sh_listener) {
    release_listener(shadow->sh_listener);
    shadow->sh_listener = NULL;
  }

  /* Mark dead, clean up queues, and trigger socket destruction.
   * socket_del() marks the socket GEN_DESTROY; the event system will
   * deliver ET_DESTROY to shadow_sock_callback later.  We defer the
   * actual free(shadow) to that ET_DESTROY handler so the event engine
   * never touches freed memory.  Clean up sendQ/recvQ here since they
   * are no longer needed, but leave the shadow struct alive. */
  shadow->sh_flags |= SHADOW_FLAGS_DEAD;

  /* Clean up sendQ and recvQ */
  MsgQClear(&shadow->sh_sendQ);
  dbuf_delete(&shadow->sh_recvQ, DBufLength(&shadow->sh_recvQ));

  /* Free SSL before closing fd — SSL_free sends close_notify on the socket */
#ifdef USE_SSL
  ssl_free(&shadow->sh_socket);
  shadow->sh_socket.ssl = NULL;
#endif

  /* socket_del clears pending events; close fd after so the fd isn't
   * reused before the engine stops tracking it. */
  socket_del(&shadow->sh_socket);
  if (shadow->sh_fd >= 0) {
    close(shadow->sh_fd);
    shadow->sh_fd = -1;
  }

  /* If session has no more connections (primary gone + no shadows),
   * the session may need to enter HOLDING. This is handled by the
   * caller (Phase F: bounce_promote_shadow or exit_one_client). */
}

/** Promote the first shadow to primary connection.
 *
 * When the primary disconnects but shadows remain, we transplant the
 * first shadow's socket into the Client's Connection struct so the
 * Client stays alive with the shadow's socket driving it.
 *
 * The caller must have already closed/cleaned up the primary's old socket
 * (e.g. via close_connection or equivalent cleanup).  This function:
 *  1. Removes the first shadow from the list
 *  2. Transfers its fd into the Client's Connection
 *  3. Re-registers the socket with the event engine (client callback)
 *  4. Copies CAP state from shadow to Connection
 *  5. Frees the shadow struct
 *
 * Returns 0 on success, -1 if no shadows available.
 */
int bounce_promote_shadow(struct BouncerSession *session)
{
  struct ShadowConnection *shadow;
  struct Client *cptr;
  struct Connection *con;
  int old_fd, fd;

  assert(0 != session);

  shadow = session->hs_shadows;
  if (!shadow)
    return -1; /* No shadows to promote */

  cptr = session->hs_client;
  assert(0 != cptr);
  con = cli_connect(cptr);
  assert(0 != con);

#ifdef USE_SSL
  /* Prefer a TLS shadow if the primary had TLS, to preserve +z usermode
   * and +Z (SSL-only) channel access.  Falls back to first shadow if
   * no TLS shadow exists. */
  if (IsSSL(cptr)) {
    struct ShadowConnection *s;
    for (s = session->hs_shadows; s; s = s->sh_next) {
      if (s->sh_socket.ssl) { shadow = s; break; }
    }
  }

  /* Refuse promotion if it would put a non-TLS connection in +Z channels.
   * Primary was TLS, best shadow is plaintext, user is in +Z → HOLDING. */
  if (IsSSL(cptr) && !shadow->sh_socket.ssl && cli_user(cptr)) {
    struct Membership *m;
    for (m = cli_user(cptr)->channel; m; m = m->next_channel) {
      if (m->channel->mode.exmode & EXMODE_SSLONLY) {
        Debug((DEBUG_INFO,
               "Bouncer: refusing promotion for %s - no TLS shadow, in +Z channel %s",
               cli_name(cptr), m->channel->chname));
        return -1;  /* Session goes to HOLDING */
      }
    }
  }
#endif

  /* Unlink chosen shadow from list (may not be the first element
   * when TLS preference selected a different shadow). */
  {
    struct ShadowConnection **pp;
    for (pp = &session->hs_shadows; *pp; pp = &(*pp)->sh_next) {
      if (*pp == shadow) {
        *pp = shadow->sh_next;
        break;
      }
    }
  }
  session->hs_shadow_count--;
  shadow->sh_next = NULL;

  Debug((DEBUG_INFO, "Bouncer: promoting shadow #%u (fd %d) to primary for session %s",
         shadow->sh_id, shadow->sh_fd, session->hs_sessid));

  /* Step 1: Remove shadow's socket from the event engine WHILE the fd
   * is still valid.  engine_delete calls epoll_ctl(EPOLL_CTL_DEL) to
   * explicitly remove the fd from the epoll interest list, preventing
   * stale epoll events from referencing the freed shadow struct.
   *
   * Clear s_data BEFORE socket_del() because in non-threaded mode,
   * socket_del() synchronously fires ET_DESTROY → shadow_sock_callback.
   * If s_data is still set, the callback will MyFree(shadow) and we'd
   * access freed memory. */
  s_data(&shadow->sh_socket) = NULL;
  socket_del(&shadow->sh_socket);

  /* Step 2: Steal the shadow's fd — no dup() needed since engine_delete
   * already removed it from the epoll interest list.  The fd transfers
   * directly to the primary's Connection. */
  fd = shadow->sh_fd;
  shadow->sh_fd = -1; /* prevent cleanup from closing the transferred fd */

  /* Step 3: Close the primary's old fd.  The caller has NOT called
   * close_connection() — doing so would call socket_del() on the
   * primary's socket, which corrupts gh_ref when the event engine
   * still holds references from the current event callback.  Instead,
   * we close the fd directly (kernel removes it from epoll) and use
   * socket_reattach() below to swap in the new fd. */
  old_fd = cli_fd(cptr);
  if (old_fd >= 0) {
    LocalClientArray[old_fd] = 0;
    close(old_fd);
  }

#ifdef USE_SSL
  /* Free the primary's old SSL object (if any).  This must happen AFTER
   * close(old_fd) — SSL_free implicitly calls SSL_shutdown which needs
   * the fd to be gone so the close_notify isn't actually sent. */
  if (con_socket(con).ssl) {
    SSL_free(con_socket(con).ssl);
    con_socket(con).ssl = NULL;
  }
  /* Transfer shadow's SSL object to the primary's Connection.
   * NULL out shadow's copy so deferred free doesn't double-free. */
  con_socket(con).ssl = shadow->sh_socket.ssl;
  shadow->sh_socket.ssl = NULL;
#endif

  /* Step 4: Transplant the stolen fd into the Client's Connection. */
  s_fd(&con_socket(con)) = fd;
  ClrFlag(cptr, FLAG_DEADSOCKET);
  ClrFlag(cptr, FLAG_BLOCKED);

  /* Step 5: Transfer sendQ/recvQ contents.
   * Move any pending data from shadow's queues to the Connection. */
  MsgQClear(&con_sendQ(con));
  /* Swap the MsgQ — move shadow's queued data to connection */
  con_sendQ(con) = shadow->sh_sendQ;
  /* Zero out shadow's sendQ so cleanup doesn't free the moved data */
  msgq_init(&shadow->sh_sendQ);

  /* Transfer recvQ (struct copy moves buffer pointers) */
  DBufClear(&con_recvQ(con));
  con_recvQ(con) = shadow->sh_recvQ;
  memset(&shadow->sh_recvQ, 0, sizeof(shadow->sh_recvQ));

  /* Step 6: Copy CAP state from shadow to Connection.
   * The shadow's caps become this connection's own negotiated caps.
   * cli_active (the union) will be recomputed after promotion. */
  memcpy(con_capab(con), &shadow->sh_capab, sizeof(struct CapSet));
  memcpy(con_active_own(con), &shadow->sh_active, sizeof(struct CapSet));
  memcpy(con_active(con), &shadow->sh_active, sizeof(struct CapSet));
  con_capab_version(con) = shadow->sh_capab_version;

  /* Step 6b: Transfer connection identity from shadow to primary.
   * The primary's IP, sockhost, port, listener may be stale (from the
   * old primary connection). Update them to reflect the promoted shadow's
   * actual connection properties. Mirrors bounce_revive() Step 6a. */
  memcpy(&cli_ip(cptr), &shadow->sh_ip, sizeof(struct irc_in_addr));
  ircd_strncpy(con_sock_ip(con), shadow->sh_sock_ip, SOCKIPLEN + 1);
  ircd_strncpy(con_sockhost(con), shadow->sh_sockhost, HOSTLEN + 1);
  con->con_port = shadow->sh_port;
  memcpy(&cli_connectip(cptr), &shadow->sh_connectip, sizeof(struct irc_in_addr));
  ircd_strncpy(cli_connecthost(cptr), shadow->sh_connecthost, HOSTLEN + 1);

  /* Transfer listener reference (shadow's ref transfers to primary) */
  if (con_listener(con))
    release_listener(con_listener(con));
  con_listener(con) = shadow->sh_listener;
  shadow->sh_listener = NULL; /* Prevent deferred free from releasing */

  /* Step 7: Update LocalClientArray */
  LocalClientArray[fd] = cptr;

  /* Step 8: Re-register socket with event engine using socket_reattach.
   * This preserves the socket's GenHeader (gh_ref, gh_flags, list linkage)
   * which is critical — the event engine currently holds references to
   * this socket from the in-progress event callback.  socket_reattach
   * only updates the fd and re-registers with the epoll engine. */
  if (!socket_reattach(&cli_socket(cptr), fd)) {
    Debug((DEBUG_ERROR, "Bouncer: socket_reattach failed during shadow promotion for %s",
           cli_name(cptr)));
    /* Socket registration failed — close fd and let caller handle it. */
    close(fd);
    s_fd(&con_socket(con)) = -1;
    LocalClientArray[fd] = 0;
    SetFlag(cptr, FLAG_DEADSOCKET);
    bounce_defer_shadow_free(shadow);
    return -1;
  }

  /* Step 9: Reset socket interest to readable only (we may have been
   * writable from the old connection's pending sendQ). */
  socket_events(&cli_socket(cptr), SOCK_EVENT_READABLE);

#ifdef USE_SSL
  /* Step 9b: Update FLAG_SSL and channel nonsslusers counters.
   * A TLS→plaintext promotion clears +z and increments nonsslusers.
   * A plaintext→TLS promotion sets +z and decrements nonsslusers.
   * This ensures +Z (SSL-only) channel enforcement stays correct. */
  {
    int was_ssl = IsSSL(cptr);
    int now_ssl = (con_socket(con).ssl != NULL);
    if (now_ssl && !was_ssl) {
      SetSSL(cptr);
      if (cli_user(cptr)) {
        struct Membership *m;
        for (m = cli_user(cptr)->channel; m; m = m->next_channel)
          if (m->channel->nonsslusers > 0)
            m->channel->nonsslusers--;
      }
    } else if (!now_ssl && was_ssl) {
      ClearSSL(cptr);
      if (cli_user(cptr)) {
        struct Membership *m;
        for (m = cli_user(cptr)->channel; m; m = m->next_channel)
          m->channel->nonsslusers++;
      }
    }
  }
#endif

  /* Step 10: Update timing */
  con_lasttime(con) = shadow->sh_lasttime;
  con_since(con) = shadow->sh_since;

  /* Step 10b: Accumulate the dying primary's data counters into session
   * aggregates, then set the ghost's counters FROM the promoted shadow's
   * lifetime total.  The promoted connection carries its full history
   * (accumulated while it was a shadow) into the primary role. */
  bounce_accumulate_and_reset_primary(session, cptr);
  con_sendB(con) = shadow->sh_sendB;
  con_receiveB(con) = shadow->sh_receiveB;
  con_sendM(con) = shadow->sh_sendM;
  con_receiveM(con) = shadow->sh_receiveM;
  cli_firsttime(cptr) = shadow->sh_connected;

  /* Step 11: Update session primary ID */
  session->hs_primary_id = shadow->sh_id;

  /* Step 12: Clean up the shadow struct (queues already moved).
   * s_data was already cleared before socket_del() in step 2 to prevent
   * the synchronous ET_DESTROY handler from freeing the shadow.
   *
   * IMPORTANT: Do NOT MyFree(shadow) here.  We are inside an engine_loop
   * event callback (processing the primary's disconnect).  If epoll_wait
   * returned events for both the primary and shadow sockets in the same
   * batch, the shadow's event is still in the events array with
   * evt->data.ptr pointing to &shadow->sh_socket.  Freeing the shadow
   * now would cause engine_loop to read freed memory when it processes
   * that stale event.  Instead, defer the free to timer_run() which
   * executes after all events in the current batch are processed. */
  bounce_defer_shadow_free(shadow);

  /* Recompute session union caps for the new primary + remaining shadows */
  bounce_recompute_session_caps(cptr);

  log_write(LS_USER, L_TRACE, 0, "Bouncer: shadow promoted to primary for %s session %s",
            cli_name(cptr), session->hs_sessid);

  return 0;
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
  struct ShadowConnection *sh;
  int has_present = 0;
  int has_away = 0;
  int old_effective;
  const char *latest_away_msg = NULL;
  time_t latest_away_time = 0;

  assert(0 != session);
  assert(0 != effective_state);
  assert(0 != effective_msg);

  primary = session->hs_client;
  effective_msg[0] = '\0';

  /* Remember old state for change detection.
   * We store the effective state in hs_hold_override's upper bits.
   * Actually, let's use a simpler approach: just compute and let caller compare. */

  /* Check primary connection's per-connection away state.
   * con_pre_away tracks the primary's own away state (0=present, 1=away, 2=away-star),
   * independent of shadow commands.  con_pre_away_msg stores the primary's per-connection
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

  /* Check all shadow connections */
  for (sh = session->hs_shadows; sh; sh = sh->sh_next) {
    if (sh->sh_flags & SHADOW_FLAGS_DEAD)
      continue;
    if (sh->sh_away_state == 2) {
      /* AWAY * — invisible to aggregation */
      continue;
    } else if (sh->sh_away_state == 1) {
      /* Explicit away */
      has_away = 1;
      /* Use most recently set away message */
      if (sh->sh_away_msg[0] && sh->sh_since > latest_away_time) {
        latest_away_msg = sh->sh_away_msg;
        latest_away_time = sh->sh_since;
      }
    } else {
      /* Present */
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
  /* Primary (1) + shadows */
  return 1 + session->hs_shadow_count;
}

/** Helper: write a raw IRC line to a shadow's sendQ.
 * Uses the primary client as the msgq_make dest (for formatting),
 * then queues to the shadow's sendQ.
 */
static void shadow_send_raw(struct ShadowConnection *shadow,
                             struct Client *primary,
                             const char *fmt, ...)
{
  char buf[BUFSIZE];
  struct MsgBuf *mb;
  va_list ap;
  int len;

  va_start(ap, fmt);
  len = vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);

  if (len <= 0 || len >= (int)sizeof(buf))
    return;

  /* Strip trailing \r\n — msgq_make adds its own \r\n termination.
   * Callers may include \r\n in their format strings; without stripping,
   * the MsgBuf would contain double \r\n. */
  while (len > 0 && (buf[len - 1] == '\r' || buf[len - 1] == '\n')) {
    buf[--len] = '\0';
  }

  if (len == 0)
    return;

  mb = msgq_make(primary, "%s", buf);
  if (mb) {
    msgq_add(&shadow->sh_sendQ, mb, 0);
    msgq_clean(mb);
  }
}

/** Recompute cli_active as the union of all session connections' caps.
 * For bouncer sessions: cli_active = con_active_own | sh1.sh_active | sh2.sh_active | ...
 * For non-bouncer clients: cli_active = con_active_own (no shadows to merge).
 *
 * Called after any cap change on primary (CAP REQ/ACK/CLEAR) or shadow
 * (CAP intercept in shadow_read_packet), and on shadow attach/detach.
 *
 * @param[in] primary The primary client.
 */
void bounce_recompute_session_caps(struct Client *primary)
{
  struct BouncerSession *session;
  struct ShadowConnection *sh;

  if (!primary || !MyConnect(primary))
    return;

  /* Start with this connection's own negotiated caps */
  *cli_active(primary) = *cli_active_own(primary);

  /* If no bouncer session, we're done — cli_active == cli_active_own */
  session = bounce_get_session(primary);
  if (!session)
    return;

  /* OR in each shadow's caps */
  for (sh = session->hs_shadows; sh; sh = sh->sh_next) {
    if (!(sh->sh_flags & SHADOW_FLAGS_DEAD))
      CapSetOR(cli_active(primary), &sh->sh_active);
  }
}

/** Build a union CapSet from the primary connection and all shadow
 * connections' active capabilities.
 *
 * Used for formatting outbound messages with the maximal set of tags
 * that any connection (primary or shadow) might need. The send_buffer()
 * shadow duplication loop then strips tags per-connection, ensuring
 * each connection only receives tags it negotiated.
 *
 * This solves the CAP state divergence problem: when the primary has
 * fewer caps than a shadow, the message would otherwise be formatted
 * without tags the shadow needs (since tag filtering is subtractive).
 *
 * @param[in] session Bouncer session.
 * @param[out] out CapSet to populate with the union of all connections' caps.
 */
void bounce_build_union_caps(struct BouncerSession *session, struct CapSet *out)
{
  struct ShadowConnection *sh;
  unsigned int i;
  unsigned int nwords = sizeof(out->bits) / sizeof(out->bits[0]);

  assert(0 != session);
  assert(0 != out);

  /* Start with primary's active caps */
  if (session->hs_client && MyConnect(session->hs_client)) {
    struct CapSet *primary_caps = cli_active(session->hs_client);
    for (i = 0; i < nwords; i++)
      out->bits[i] = primary_caps->bits[i];
  } else {
    for (i = 0; i < nwords; i++)
      out->bits[i] = 0;
  }

  /* OR in each shadow's active caps */
  for (sh = session->hs_shadows; sh; sh = sh->sh_next) {
    if (sh->sh_flags & SHADOW_FLAGS_DEAD)
      continue;
    for (i = 0; i < nwords; i++)
      out->bits[i] |= sh->sh_active.bits[i];
  }
}

/** Send IRC registration welcome sequence to a newly attached shadow.
 *
 * This gives the shadow connection a full registration sequence so that
 * standard IRC client libraries work without modification. The shadow
 * receives RPL_WELCOME through MOTD, appearing as a normal connection
 * to the session's nick.
 *
 * @param[in] shadow The newly created shadow connection.
 */
void bounce_send_shadow_welcome(struct ShadowConnection *shadow)
{
  struct BouncerSession *session;
  struct Client *primary;
  const char *nick;

  assert(0 != shadow);
  session = shadow->sh_session;
  assert(0 != session);
  primary = session->hs_client;
  assert(0 != primary);

  nick = cli_name(primary);

  /* 001 RPL_WELCOME */
  shadow_send_raw(shadow, primary,
    ":%s 001 %s :Welcome to the %s IRC Network %s\r\n",
    cli_name(&me), nick, feature_str(FEAT_NETWORK), nick);

  /* 002 RPL_YOURHOST */
  shadow_send_raw(shadow, primary,
    ":%s 002 %s :Your host is %s, running version %s\r\n",
    cli_name(&me), nick, cli_name(&me), version);

  /* 003 RPL_CREATED */
  shadow_send_raw(shadow, primary,
    ":%s 003 %s :This server was created %s\r\n",
    cli_name(&me), nick, creation);

  /* 004 RPL_MYINFO */
  shadow_send_raw(shadow, primary,
    ":%s 004 %s %s %s %s %s %s\r\n",
    cli_name(&me), nick, cli_name(&me), version,
    infousermodes, infochanmodes, infochanmodeswithparams);

  /* 005 RPL_ISUPPORT — required for clients to know channel modes,
   * PREFIX, CHANMODES, etc.  Route via current_shadow so send_reply()
   * delivers to the shadow's sendQ through the intercept path. */
  current_shadow = shadow;
  send_supported(primary);
  current_shadow = NULL;

  /* 375 RPL_MOTDSTART + 376 RPL_ENDOFMOTD (minimal) */
  shadow_send_raw(shadow, primary,
    ":%s 375 %s :- %s Message of the Day -\r\n",
    cli_name(&me), nick, cli_name(&me));
  shadow_send_raw(shadow, primary,
    ":%s 376 %s :End of /MOTD command.\r\n",
    cli_name(&me), nick);

  /* NOTE: bouncer shadow attached (informational) */
  shadow_send_raw(shadow, primary,
    ":%s NOTE BOUNCER SHADOW_ATTACHED :Attached to session %s as connection #%u\r\n",
    cli_name(&me), session->hs_sessid, shadow->sh_id);

  /* Replay channel state: the shadow needs to know which channels
   * the primary is in so the client can display them.  For each
   * channel, send JOIN + TOPIC (if set) + NAMES. */
  if (cli_user(primary)) {
    struct Membership *member;
    for (member = cli_user(primary)->channel; member; member = member->next_channel) {
      struct Channel *chptr = member->channel;

      /* Skip invisible memberships */
      if (IsZombie(member) || IsDelayedJoin(member))
        continue;

      /* Send JOIN — use extended-join format if shadow negotiated it */
      if (CapHas(&shadow->sh_active, CAP_EXTJOIN))
        shadow_send_raw(shadow, primary,
          ":%s!%s@%s JOIN %s %s :%s\r\n",
          nick, cli_user(primary)->username, cli_user(primary)->host,
          chptr->chname,
          IsAccount(primary) ? cli_account(primary) : "*",
          cli_info(primary));
      else
        shadow_send_raw(shadow, primary,
          ":%s!%s@%s JOIN :%s\r\n",
          nick, cli_user(primary)->username, cli_user(primary)->host,
          chptr->chname);

      /* Route TOPIC and NAMES replies to this shadow via current_shadow.
       * send_reply() / do_names() use sendto_one() which checks
       * current_shadow and routes to the shadow's sendQ. */
      current_shadow = shadow;

      if (chptr->topic[0]) {
        send_reply(primary, RPL_TOPIC, chptr->chname, chptr->topic);
        send_reply(primary, RPL_TOPICWHOTIME, chptr->chname, chptr->topic_nick,
                   chptr->topic_time);
      }

      /* Send MARKREAD — CapActive now returns the union, so if this
       * shadow has read-marker, the check inside send_markread_on_join
       * will pass.  current_shadow routes the output to the shadow. */
      send_markread_on_join(primary, chptr->chname);

      /* Send NAMES — do_names uses CapRecipientHas for format decisions,
       * which checks current_shadow's caps when current_shadow is set.
       * CapRecipientHas checks current_shadow->sh_active for us. */
      if (!CapRecipientHas(primary, CAP_DRAFT_NOIMPLICITNAMES))
        do_names(primary, chptr, NAMES_ALL|NAMES_EON);

      current_shadow = NULL;
    }
  }

  /* Auto-replay recent history for the new shadow connection.
   * Use the primary's idle time as the "since" timestamp — replay
   * messages that arrived while the session was idle.
   * For active sessions there is no disconnect_time; the idle time
   * (user->last = last PRIVMSG from any connection) is a reasonable
   * proxy.  If no message was ever sent, fall back to signon time. */
  if (feature_bool(FEAT_BOUNCER_AUTO_REPLAY) && cli_user(primary)
      && !CapHas(&shadow->sh_active, CAP_DRAFT_CHATHISTORY)) {
    time_t since = cli_user(primary)->last;
    if (since == 0)
      since = cli_firsttime(primary);
    if (since > 0 && since < CurrentTime) {
      current_shadow = shadow;
      bouncer_auto_replay(primary, session, since);
      current_shadow = NULL;
    }
  }

  /* Flush the welcome messages immediately.
   * Previously we relied on socket_events to trigger ET_WRITE, but there
   * seems to be a race or ordering issue that delays the flush by ~60s
   * (until check_pings sends a PING and triggers socket_events again).
   * Calling shadow_flush_sendq directly ensures the welcome is sent now. */
  shadow_flush_sendq(shadow);

  /* Request writable notification for any remaining data (if blocked) */
  if (MsgQLength(&shadow->sh_sendQ) > 0)
    socket_events(&shadow->sh_socket, SOCK_EVENT_READABLE | SOCK_EVENT_WRITABLE);
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

    /* Send JOIN to the client — use CapRecipientHas for format decisions
     * so the wire format matches the actual recipient's caps (not the union). */
    if (CapRecipientHas(cptr, CAP_EXTJOIN))
      sendcmdto_one(cptr, CMD_JOIN, cptr, "%H %s :%s", chptr,
                    IsAccount(cptr) ? cli_account(cptr) : "*",
                    cli_info(cptr));
    else
      sendcmdto_one(cptr, CMD_JOIN, cptr, ":%H", chptr);

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
