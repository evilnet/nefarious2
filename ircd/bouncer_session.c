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
#include "querycmds.h"
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

/* Forward declarations for cross-server relay (Phase 1) */
static void relay_shadow_read_callback(struct Event *ev);
static void relay_shadow_write(struct RelayShadowEntry *entry, const char *data);
static void relay_replay_history(struct RelayShadowEntry *entry, const char *target, int limit);
static void relay_send_names(struct RelayShadowEntry *entry, const char *channame);
static void relay_send_topic(struct RelayShadowEntry *entry, const char *channame);
static void bounce_remove_remote_shadow(struct ShadowConnection *shadow);
static struct RelayShadowEntry *bounce_find_relay_pending(const char *account,
                                                          const char *sessid);
/* bounce_add_pending_relay declared in bouncer_session.h */
extern struct RelayShadowEntry *bounce_find_relay(const char *relay_id);

/* Relay hash table and hash function — declared here for use in
 * bounce_handle_bs which appears before the relay management section. */
static struct RelayShadowEntry *relayHash[RELAY_SHADOW_HASHSIZE];
static struct RelayShadowEntry *pendingRelays;
static unsigned int relay_id_seq;

static unsigned int relay_hash(const char *id)
{
  unsigned int h = 0;
  for (; *id; id++)
    h = h * 31 + (unsigned char)*id;
  return h % RELAY_SHADOW_HASHSIZE;
}

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
#ifdef USE_SSL
    if (s->sh_ssl_flush) {
      MyFree(s->sh_ssl_flush);
      s->sh_ssl_flush = NULL;
    }
#endif
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

    /* Remote shadows are pinged by the relay server (B-side) which owns
     * the actual TCP connection.  Skip them here on the managing server. */
    if (shadow->sh_flags & SHADOW_FLAGS_REMOTE)
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
    /* Check if session is on a remote server */
    if (0 != strcmp(session->hs_origin, cli_yxx(&me))) {
      struct Client *managing_server = FindNServer(session->hs_origin);
      if (managing_server) {
        *out_session = session;
        /* Prefer alias path if enabled — gives first-class multi-server presence.
         * Requires session replica with primary info and alias slots available. */
        if (feature_bool(FEAT_BOUNCER_ALIASES) && session->hs_client
            && session->hs_alias_count < BOUNCER_MAX_ALIASES) {
          Debug((DEBUG_INFO, "Bouncer: alias path for %s session %s (primary on %s)",
                 account, session->hs_sessid, cli_name(managing_server)));
          return BOUNCE_RESUME_ALIAS_REMOTE;
        }
        Debug((DEBUG_INFO, "Bouncer: relay path for %s session %s via %s",
               account, session->hs_sessid, cli_name(managing_server)));
        return BOUNCE_RESUME_RELAY_REMOTE;
      }
      /* Managing server not found — fall through to try other sessions */
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
   * with an existing primary (attach as shadow connection).
   * An orphaned session is ACTIVE but has no primary (hs_client == NULL).
   * This can happen after server restart or when primary exits before
   * shadows and the session persists.  These sessions count toward the
   * per-account limit, so we must reclaim them rather than creating new ones. */
  session = bounce_find_any_session(account);
  if (session && session->hs_state == BOUNCE_ACTIVE) {
    /* Check if session is on a remote server */
    if (0 != strcmp(session->hs_origin, cli_yxx(&me))) {
      struct Client *managing_server = FindNServer(session->hs_origin);
      if (managing_server) {
        *out_session = session;
        /* Prefer alias path for active sessions with known primary */
        if (feature_bool(FEAT_BOUNCER_ALIASES) && session->hs_client
            && session->hs_alias_count < BOUNCER_MAX_ALIASES) {
          Debug((DEBUG_INFO, "Bouncer: alias path for %s active session %s (primary on %s)",
                 account, session->hs_sessid, cli_name(managing_server)));
          return BOUNCE_RESUME_ALIAS_REMOTE;
        }
        Debug((DEBUG_INFO, "Bouncer: relay path for %s active session %s via %s",
               account, session->hs_sessid, cli_name(managing_server)));
        return BOUNCE_RESUME_RELAY_REMOTE;
      }
    }
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

      /* --- Local alias path (preferred over shadows when enabled) --- */
      if (feature_bool(FEAT_BOUNCER_ALIASES)
          && session->hs_client
          && session->hs_alias_count < BOUNCER_MAX_ALIASES) {
#ifdef USE_SSL
        /* Respect BOUNCER_REQUIRE_TLS for aliases too */
        if (feature_bool(FEAT_BOUNCER_REQUIRE_TLS) && !cli_socket(cptr).ssl) {
          Debug((DEBUG_INFO, "Bouncer: skipping local alias for plaintext client %s (REQUIRE_TLS)",
                 cli_name(cptr)));
          goto skip_shadow;
        }
#endif
        Debug((DEBUG_INFO, "Bouncer: local alias path for %s session %s",
               account, session->hs_sessid));
        *out_session = session;
        return BOUNCE_RESUME_ALIAS_LOCAL;
      }

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
       * The Client struct will be freed; only the socket fd survives.
       *
       * Socket transfer follows the same pattern as bounce_revive():
       * steal fd+SSL from the client via socket_del, then give the
       * original fd to the shadow.  This avoids SSL_set_fd() which
       * would create new BIOs on the dup'd fd. */
      struct ShadowConnection *shadow;
      int fd;
      char sock_ip[SOCKIPLEN + 1];
#ifdef USE_SSL
      SSL *saved_ssl;
      char *auth_flush_data = NULL;
      unsigned int auth_flush_len = 0;
#endif
      int max_sh;

      /* Early max-shadows check — must happen BEFORE we steal the fd,
       * because stealing is not easily reversible. */
      max_sh = feature_int(FEAT_BOUNCER_MAX_SHADOWS);
      if (max_sh > 0 && session->hs_shadow_count >= max_sh)
        goto skip_shadow;

      /* Flush any pending writes before stealing the SSL object.
       *
       * With pipelining clients (e.g. goguma sends 21 individual CAP REQ
       * commands + AUTHENTICATE + CAP END in one burst), the auth phase
       * generates many responses that may not all flush in one shot.
       * If the P10 SASL callback fires before the event loop processes
       * the client's write-ready event, FLAG_BLOCKED is still set and
       * the client's MsgQ has queued data with corresponding SSL pending
       * write state (wpend_tot/wpend_buf).  Transferring the SSL in that
       * state causes "bad write retry" when the shadow's first SSL_write
       * uses a different buffer.
       *
       * Clear FLAG_BLOCKED and flush here.  If the socket is writable,
       * the pending writes complete and wpend clears.  If not, set
       * SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER so the pending write can
       * complete even with a different buffer pointer — the SSL record
       * layer writes from its internal wbuf (already-encrypted data),
       * not from the application buffer.  We then flush the pending
       * state after transferring the SSL to the shadow. */
      ClrFlag(cptr, FLAG_BLOCKED);
      send_queued(cptr);
      if (IsDead(cptr))
        goto skip_shadow;
#ifdef USE_SSL
      if (MsgQLength(&(cli_sendQ(cptr))) > 0 && cli_socket(cptr).ssl) {
        /* Snapshot the unflushed sendQ data.  We need this to build a
         * coalesced buffer later (auth prefix + welcome messages) so
         * the shadow's first SSL_write satisfies wpend_tot <= len.
         * Must happen BEFORE stealing the SSL/fd. */
        struct iovec snap_iov[128];
        unsigned int snap_bytes = 0;
        int snap_count = msgq_mapiov(&cli_sendQ(cptr), snap_iov, 128, &snap_bytes);
        if (snap_count > 0 && snap_bytes > 0) {
          auth_flush_data = (char *)MyMalloc(snap_bytes);
          if (auth_flush_data) {
            unsigned int off = 0;
            int i;
            for (i = 0; i < snap_count && off < snap_bytes; i++) {
              unsigned int n = snap_iov[i].iov_len;
              if (off + n > snap_bytes) n = snap_bytes - off;
              memcpy(auth_flush_data + off, snap_iov[i].iov_base, n);
              off += n;
            }
            auth_flush_len = off;
          }
        }
        SSL_set_mode(cli_socket(cptr).ssl, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
        Debug((DEBUG_INFO, "Bouncer: %u bytes unflushed for %s, "
               "set ACCEPT_MOVING_WRITE_BUFFER",
               snap_bytes, cli_name(cptr)));
      }
#endif

      /* Extract fd and IP from the client's connection */
      fd = cli_fd(cptr);
      ircd_strncpy(sock_ip, cli_sock_ip(cptr), SOCKIPLEN + 1);

      /* Step 1: Steal fd and SSL from client (same pattern as bounce_revive).
       * Save and NULL the SSL pointer BEFORE socket_del, because
       * socket_del triggers ET_DESTROY which calls ssl_free(). */
#ifdef USE_SSL
      saved_ssl = cli_socket(cptr).ssl;
      cli_socket(cptr).ssl = NULL;
#endif
      s_data(&cli_socket(cptr)) = NULL;  /* Prevent stale callbacks */
      socket_del(&cli_socket(cptr));
      LocalClientArray[fd] = 0;
      cli_fd(cptr) = -1;  /* Mark client as fd-less (like bounce_revive) */

      /* Step 2: Create shadow with the original fd.
       * socket_add inside bounce_add_shadow registers fd with the
       * event engine (safe because socket_del above deregistered it).
       * After the max_shadows check above, failure here means OOM or
       * socket_add failure — both catastrophic.  The connection is lost. */
      shadow = bounce_add_shadow(session, fd, sock_ip);
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
          /* Transfer SSL — no SSL_set_fd needed since the SSL's BIOs
           * already reference fd, and the shadow now owns fd. */
          if (saved_ssl) {
            shadow->sh_socket.ssl = saved_ssl;
            saved_ssl = NULL;  /* Shadow owns it now */

            /* If we saved unflushed auth data, store it on the shadow.
             * shadow_flush_sendq will coalesce this with the welcome
             * messages and do a single large SSL_write that satisfies
             * the wpend_tot <= len check for the pending TLS record. */
            if (auth_flush_data) {
              shadow->sh_ssl_flush = auth_flush_data;
              shadow->sh_ssl_flush_len = auth_flush_len;
              shadow->sh_ssl_flush_auth = auth_flush_len;
              shadow->sh_flags |= SHADOW_FLAGS_SSL_PENDING;
              auth_flush_data = NULL;  /* Shadow owns it now */
              Debug((DEBUG_INFO, "Bouncer: saved %u bytes auth data for "
                     "shadow #%u SSL pending flush",
                     auth_flush_len, shadow->sh_id));
            }

            Debug((DEBUG_INFO, "Bouncer: transferred SSL to shadow #%u fd=%d",
                   shadow->sh_id, fd));
          }
#endif

          {
            /* Capture connection metadata for later promotion.
             * The Client struct will be freed after we return, so copy
             * everything we'll need to restore the primary's identity
             * if this shadow gets promoted. */
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
        /* Shadow creation failed — fd and SSL are orphaned, clean up */
#ifdef USE_SSL
        if (saved_ssl)
          SSL_free(saved_ssl);
        if (auth_flush_data)
          MyFree(auth_flush_data);
#endif
        close(fd);
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
    if (shadow->sh_ssl_flush) {
      MyFree(shadow->sh_ssl_flush);
      shadow->sh_ssl_flush = NULL;
    }
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
        /* Follow with BS A so the receiver can resolve hs_client
         * for alias support.  Only for local sessions with a live
         * primary — remote replicas have hs_client=NULL. */
        if (s->hs_client)
          sendcmdto_one(&me, CMD_BOUNCER_SESSION,
                        cptr,
                        "A %s %s %s",
                        s->hs_account, s->hs_sessid,
                        cli_yxx(s->hs_client));
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

    /* Cancel hold timer */
    if (t_active(&session->hs_hold_timer))
      timer_del(&session->hs_hold_timer);

    session->hs_state = BOUNCE_ACTIVE;
    session->hs_last_active = CurrentTime;
    session->hs_disconnect_time = 0;

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

  case 'X': /* Destroy or XS (Shadow destroy) */
  {
    if (subcmd[1] == 'S') {
      /* BS XS <account> <sessid> <relay_id> — remote shadow disconnected (B→A) */
      const char *relay_id;
      struct ShadowConnection *sh;

      if (parc < 5)
        return 0;

      relay_id = parv[4];
      session = bounce_find_by_token_sessid(account, sessid);
      if (!session)
        return 0;

      /* Find and remove the remote shadow by relay_id */
      for (sh = session->hs_shadows; sh; sh = sh->sh_next) {
        if ((sh->sh_flags & SHADOW_FLAGS_REMOTE) &&
            0 == strcmp(sh->sh_relay_id, relay_id)) {
          bounce_remove_remote_shadow(sh);
          break;
        }
      }

      /* If the last shadow was removed from a relay-only ghost (no local
       * fd, no remaining shadows), transition back to HOLDING.  The ghost
       * was revived from HOLDING by BS S and has been relay-only since;
       * now that the relay is gone, it returns to holding state with a
       * fresh hold timer. */
      if (session->hs_client && !session->hs_shadows
          && cli_fd(session->hs_client) == -1
          && session->hs_state == BOUNCE_ACTIVE) {
        int hold_time = feature_int(FEAT_BOUNCER_SESSION_HOLD);

        SetBouncerHold(session->hs_client);

        /* Re-mark channel memberships as HOLDING */
        if (cli_user(session->hs_client)) {
          struct Membership *member;
          for (member = cli_user(session->hs_client)->channel;
               member; member = member->next_channel)
            SetMemberHolding(member);
        }

        session->hs_state = BOUNCE_HOLDING;
        session->hs_disconnect_time = CurrentTime;
        session->hs_last_active = CurrentTime;

        timer_init(&session->hs_hold_timer);
        timer_add(&session->hs_hold_timer, bounce_hold_expire,
                  (void *)session, TT_RELATIVE, hold_time);

        bounce_broadcast(session, 'D', NULL);
        bounce_db_put(session);

        Debug((DEBUG_INFO, "Bouncer: relay-only session %s back to HOLDING "
               "(last remote shadow removed)", session->hs_sessid));
      }

      /* Forward */
      sendcmdto_serv_butone(sptr, CMD_BOUNCER_SESSION,
                            cptr,
                            "XS %s %s %s",
                            account, sessid, relay_id);
    } else {
      /* BS X <account> <sessid> — destroy session */
      session = bounce_find_by_token_sessid(account, sessid);
      if (session)
        bounce_destroy(session);

      /* Forward */
      sendcmdto_serv_butone(sptr, CMD_BOUNCER_SESSION,
                            cptr,
                            "X %s %s",
                            account, sessid);
    }
    break;
  }

  case 'S': /* Shadow establish (B→A): relay server has a user connection */
  {
    /* BS S <account> <sessid> <capab_hex> <is_ssl> <sock_ip> */
    unsigned long capab_hex;
    int is_ssl;
    const char *sock_ip;
    struct ShadowConnection *remote_shadow;
    char chanbuf[512];

    if (parc < 7)
      return 0;

    capab_hex = strtoul(parv[4], NULL, 16);
    is_ssl = atoi(parv[5]);
    sock_ip = parv[6];

    /* Find the session — it must exist on this server as managing server */
    session = bounce_find_by_token_sessid(account, sessid);
    if (!session) {
      Debug((DEBUG_INFO, "BS S: session %s/%s not found", account, sessid));
      return 0;
    }

    /* Only the managing server processes BS S */
    if (0 != strcmp(session->hs_origin, cli_yxx(&me))) {
      /* Not our session — forward to the actual managing server */
      sendcmdto_serv_butone(sptr, CMD_BOUNCER_SESSION, cptr,
                            "S %s %s %s %d %s",
                            account, sessid, parv[4], is_ssl, sock_ip);
      return 0;
    }

    /* TLS enforcement: reject non-TLS relay if session is in +Z channels */
    if (!is_ssl && session->hs_client) {
      /* Check if session has +Z channel memberships */
      if (bounce_session_has_plaintext(session->hs_client)) {
        /* Already has plaintext — another non-TLS is fine.
         * But if all existing connections are TLS and user tries
         * non-TLS, check +Z channels. */
      }
      /* TODO: Full +Z enforcement — for now, allow all connections.
       * Gate A equivalent will be added when channel +Z checking
       * is integrated with remote shadow creation. */
    }

    /* Create remote shadow on managing server */
    remote_shadow = bounce_add_remote_shadow(session, sptr, capab_hex,
                                             is_ssl, sock_ip);
    if (!remote_shadow) {
      Debug((DEBUG_INFO, "BS S: failed to create remote shadow for %s", sessid));
      return 0;
    }

    /* If session is HOLDING, revive the ghost */
    if (session->hs_state == BOUNCE_HOLDING && session->hs_client) {
      /* Cancel hold timer */
      if (t_active(&session->hs_hold_timer))
        timer_del(&session->hs_hold_timer);

      /* Clear hold flags on ghost */
      ClearBouncerHold(session->hs_client);
      ClrFlag(session->hs_client, FLAG_DEADSOCKET);

      /* Clear stale caps from the ghost's previous connection.
       * The ghost has no primary socket — only remote shadows provide
       * capabilities.  Without this, CapOwnHas(ghost, CAP_ECHOMSG)
       * returns true from the old connection's caps, causing spurious
       * echo-message delivery. */
      memset(cli_active_own(session->hs_client), 0, sizeof(struct CapSet));
      memset(cli_active(session->hs_client), 0, sizeof(struct CapSet));

      /* Clear CHFL_HOLDING on channel memberships */
      if (cli_user(session->hs_client)) {
        struct Membership *member;
        for (member = cli_user(session->hs_client)->channel;
             member; member = member->next_channel) {
          ClearMemberHolding(member);
        }
      }

      session->hs_state = BOUNCE_ACTIVE;
      session->hs_disconnect_time = 0;
      session->hs_last_active = CurrentTime;
      session->hs_attach_count++;
      session->hs_connect_count++;

      /* Delete persisted state */
      if (feature_bool(FEAT_BOUNCER_PERSIST))
        bounce_db_del(session->hs_sessid);

      /* Broadcast attach to network */
      bounce_broadcast(session, 'A', cli_yxx(session->hs_client));
    }

    /* Recompute union caps with the new remote shadow included */
    if (session->hs_client)
      bounce_recompute_session_caps(session->hs_client);

    /* Send BS W (acknowledge) + BS N (channel state) to relay server.
     * The relay server (B) generates the full welcome (001-005, MOTD)
     * locally from its own server info.  We only send channel state. */
    sendcmdto_one(&me, CMD_BOUNCER_SESSION, sptr,
                  "W %s %s %s %s",
                  account, sessid, remote_shadow->sh_relay_id,
                  session->hs_client ? cli_name(session->hs_client) : "*");

    /* BS N with channel list for state replay */
    build_channel_string(session, chanbuf, sizeof(chanbuf));
    sendcmdto_one(&me, CMD_BOUNCER_SESSION, sptr,
                  "N %s %s %s CHANNELS :%s",
                  account, sessid, remote_shadow->sh_relay_id,
                  chanbuf);

    /* Do NOT forward BS S — it's point-to-point between relay server and managing server */
    break;
  }

  case 'W': /* Shadow welcome/ack (A→B): managing server acknowledges relay */
  {
    /* BS W <account> <sessid> <relay_id> <nick> */
    const char *relay_id;
    const char *nick;

    if (parc < 6)
      return 0;

    relay_id = parv[4];
    nick = parv[5];

    /* This server is the relay server (B).
     * We need to find our pending relay connection and finalize it.
     * The relay connection was set up during register_user() when we
     * detected a cross-server session and sent BS S. At that point we
     * saved the dup'd fd and client info in a pending relay entry. */

    /* Look up pending relay by sessid + source server */
    {
      struct RelayShadowEntry *entry = bounce_find_relay_pending(account, sessid);
      if (!entry) {
        Debug((DEBUG_INFO, "BS W: no pending relay for %s/%s relay_id=%s",
               account, sessid, relay_id));
        return 0;
      }

      /* Finalize the relay entry with the assigned relay_id and nick */
      ircd_strncpy(entry->rs_relay_id, relay_id, sizeof(entry->rs_relay_id) - 1);
      ircd_strncpy(entry->rs_nick, nick, NICKLEN);

      /* Re-register in relay hash with the real relay_id */
      {
        unsigned int h = relay_hash(relay_id);
        entry->rs_next = relayHash[h];
        relayHash[h] = entry;
      }

      if (entry->rs_shadow)
        ircd_strncpy(entry->rs_shadow->sh_relay_id, relay_id,
                     sizeof(entry->rs_shadow->sh_relay_id) - 1);

      Debug((DEBUG_INFO, "BS W: finalized relay %s for %s/%s nick=%s",
             relay_id, account, sessid, nick));

      /* Send full welcome sequence to the relay socket.
       * All numerics use B's (this server's) name since the client
       * connected here.  ISUPPORT reflects this server's capabilities. */
      if (entry->rs_shadow && entry->rs_shadow->sh_fd >= 0) {
        char buf[512];
        struct SLink *line;

        /* 001 RPL_WELCOME */
        ircd_snprintf(0, buf, sizeof(buf),
                      ":%s 001 %s :Welcome to the %s IRC Network %s",
                      cli_name(&me), nick, feature_str(FEAT_NETWORK), nick);
        relay_shadow_write(entry, buf);

        /* 002 RPL_YOURHOST */
        ircd_snprintf(0, buf, sizeof(buf),
                      ":%s 002 %s :Your host is %s, running version %s",
                      cli_name(&me), nick, cli_name(&me), version);
        relay_shadow_write(entry, buf);

        /* 003 RPL_CREATED */
        ircd_snprintf(0, buf, sizeof(buf),
                      ":%s 003 %s :This server was created %s",
                      cli_name(&me), nick, creation);
        relay_shadow_write(entry, buf);

        /* 004 RPL_MYINFO */
        ircd_snprintf(0, buf, sizeof(buf),
                      ":%s 004 %s %s %s %s %s %s",
                      cli_name(&me), nick, cli_name(&me), version,
                      infousermodes, infochanmodes, infochanmodeswithparams);
        relay_shadow_write(entry, buf);

        /* 005 RPL_ISUPPORT */
        for (line = get_isupport_lines(); line; line = line->next) {
          ircd_snprintf(0, buf, sizeof(buf),
                        ":%s 005 %s %s :are supported by this server",
                        cli_name(&me), nick, line->value.cp);
          relay_shadow_write(entry, buf);
        }

        /* Minimal MOTD */
        ircd_snprintf(0, buf, sizeof(buf),
                      ":%s 375 %s :- %s Message of the Day -",
                      cli_name(&me), nick, cli_name(&me));
        relay_shadow_write(entry, buf);
        ircd_snprintf(0, buf, sizeof(buf),
                      ":%s 376 %s :End of /MOTD command.",
                      cli_name(&me), nick);
        relay_shadow_write(entry, buf);

        /* NOTE: bouncer relay attached (informational) */
        ircd_snprintf(0, buf, sizeof(buf),
                      ":%s NOTE BOUNCER SHADOW_ATTACHED :Attached to session %s via relay through %s",
                      cli_name(&me), sessid, cli_name(sptr));
        relay_shadow_write(entry, buf);
      }
    }

    /* Do NOT forward BS W — point-to-point */
    break;
  }

  case 'N': /* Welcome numerics (A→B): managing server sends 004/005/CHANNELS */
  {
    /* BS N <account> <sessid> <relay_id> <type> [params...] */
    const char *relay_id;
    const char *ntype;
    struct RelayShadowEntry *entry;

    if (parc < 6)
      return 0;

    relay_id = parv[4];
    ntype = parv[5];

    entry = bounce_find_relay(relay_id);
    if (!entry || !entry->rs_shadow || entry->rs_shadow->sh_fd < 0) {
      Debug((DEBUG_INFO, "BS N: relay %s not found", relay_id));
      return 0;
    }

    if (0 == strcmp(ntype, "004") && parc >= 11) {
      /* 004: <servername> <version> <usermodes> <chanmodes> <chanmodes_w_params>
       * Rewrite source to B's server name */
      char buf[512];
      ircd_snprintf(0, buf, sizeof(buf),
                    ":%s 004 %s %s %s %s %s %s",
                    cli_name(&me), entry->rs_nick,
                    parv[6], parv[7], parv[8], parv[9], parv[10]);
      relay_shadow_write(entry, buf);
    }
    else if (0 == strcmp(ntype, "005")) {
      /* 005: ISUPPORT tokens — rewrite source to B's server name */
      char buf[512];
      int i;
      size_t pos;

      pos = ircd_snprintf(0, buf, sizeof(buf), ":%s 005 %s",
                          cli_name(&me), entry->rs_nick);
      for (i = 6; i < parc; i++) {
        pos += ircd_snprintf(0, buf + pos, sizeof(buf) - pos,
                             " %s", parv[i]);
      }
      relay_shadow_write(entry, buf);
    }
    else if (0 == strcmp(ntype, "CHANNELS")) {
      /* Channel list for state replay — trailing param is channel list */
      const char *channels = parv[parc - 1];
      int chan_count = 0;
      if (channels && *channels) {
        char chanlist[512];
        char *tok, *saveptr;
        char buf[512];
        char name[CHANNELLEN + 1];
        unsigned int modes;

        ircd_strncpy(chanlist, channels, sizeof(chanlist) - 1);
        for (tok = strtok_r(chanlist, ",", &saveptr);
             tok;
             tok = strtok_r(NULL, ",", &saveptr)) {
          parse_channel_modes(tok, name, &modes);
          chan_count++;

          /* Send JOIN */
          ircd_snprintf(0, buf, sizeof(buf),
                        ":%s JOIN %s", entry->rs_nick, name);
          relay_shadow_write(entry, buf);

          /* Send mode prefix if applicable */
          if (modes & CHFL_CHANOP) {
            ircd_snprintf(0, buf, sizeof(buf),
                          ":%s MODE %s +o %s",
                          cli_name(&me), name, entry->rs_nick);
            relay_shadow_write(entry, buf);
          }
          if (modes & CHFL_HALFOP) {
            ircd_snprintf(0, buf, sizeof(buf),
                          ":%s MODE %s +h %s",
                          cli_name(&me), name, entry->rs_nick);
            relay_shadow_write(entry, buf);
          }
          if (modes & CHFL_VOICE) {
            ircd_snprintf(0, buf, sizeof(buf),
                          ":%s MODE %s +v %s",
                          cli_name(&me), name, entry->rs_nick);
            relay_shadow_write(entry, buf);
          }

          /* Send TOPIC and NAMES from local channel state */
          relay_send_topic(entry, name);
          relay_send_names(entry, name);
        }
      }

      /* Replay local chathistory for each channel */
      if (feature_bool(FEAT_BOUNCER_AUTO_REPLAY) && channels && *channels) {
        int replay_limit = feature_int(FEAT_BOUNCER_AUTO_REPLAY_LIMIT);
        char replay_chanlist[512];
        char *rtok, *rsaveptr;

        if (replay_limit <= 0)
          replay_limit = 50;

        ircd_strncpy(replay_chanlist, channels, sizeof(replay_chanlist) - 1);
        for (rtok = strtok_r(replay_chanlist, ",", &rsaveptr);
             rtok;
             rtok = strtok_r(NULL, ",", &rsaveptr)) {
          char rname[CHANNELLEN + 1];
          unsigned int rmodes;
          parse_channel_modes(rtok, rname, &rmodes);
          relay_replay_history(entry, rname, replay_limit);
        }
      }

      /* Session resume summary */
      {
        char buf[512];
        ircd_snprintf(0, buf, sizeof(buf),
                      ":%s NOTICE %s :Session resumed. You are in %d channel(s).",
                      cli_name(&me), entry->rs_nick, chan_count);
        relay_shadow_write(entry, buf);
      }
    }

    /* Do NOT forward BS N — point-to-point */
    break;
  }

  case 'R': /* Relay input (B→A): user typed something on relay socket */
  {
    /* BS R <account> <sessid> <relay_id> :<raw IRC line> */
    const char *relay_id;
    const char *raw_line;
    struct ShadowConnection *sh;

    if (parc < 6)
      return 0;

    relay_id = parv[4];
    raw_line = parv[parc - 1]; /* trailing param */

    session = bounce_find_by_token_sessid(account, sessid);
    if (!session || !session->hs_client) {
      Debug((DEBUG_INFO, "BS R: session %s/%s not found or no client", account, sessid));
      return 0;
    }

    /* Only the managing server processes BS R */
    if (0 != strcmp(session->hs_origin, cli_yxx(&me)))
      return 0;

    /* Find the remote shadow by relay_id */
    for (sh = session->hs_shadows; sh; sh = sh->sh_next) {
      if ((sh->sh_flags & SHADOW_FLAGS_REMOTE) &&
          0 == strcmp(sh->sh_relay_id, relay_id))
        break;
    }
    if (!sh) {
      Debug((DEBUG_INFO, "BS R: relay %s not found in session %s", relay_id, sessid));
      return 0;
    }

    /* Filter out QUIT — relay client disconnect is handled by BS XS.
     * Feeding QUIT to the parser would kill the primary client. */
    if (0 == ircd_strncmp(raw_line, "QUIT", 4) &&
        (raw_line[4] == '\0' || raw_line[4] == ' ' || raw_line[4] == '\r'))
      break;

    /* Set current_shadow so reply routing sends output to this shadow via BS O */
    current_shadow = sh;

    /* Parse and dispatch the IRC command as if the session's client sent it.
     * This reuses the existing parser — source routing is correct because
     * the client (hs_client) lives on this server. */
    {
      char parsebuf[BUFSIZE];
      ircd_strncpy(parsebuf, raw_line, sizeof(parsebuf) - 1);
      parse_client(session->hs_client, parsebuf, parsebuf + strlen(parsebuf));
    }

    current_shadow = NULL;

    /* Do NOT forward BS R — point-to-point */
    break;
  }

  case 'O': /* Output relay (A→B): managing server sends output to relay socket */
  {
    /* BS O <account> <sessid> <relay_id> N <numeric> <params...> :<trailing>
     * BS O <account> <sessid> <relay_id> M :<fully formatted IRC line> */
    const char *relay_id;
    const char *mode;
    struct RelayShadowEntry *entry;

    if (parc < 7)
      return 0;

    relay_id = parv[4];
    mode = parv[5];

    entry = bounce_find_relay(relay_id);
    if (!entry || !entry->rs_shadow || entry->rs_shadow->sh_fd < 0)
      return 0;

    if (mode[0] == 'N') {
      /* Numeric mode: reconstruct with B's server name */
      char buf[BUFSIZE];
      int i;
      size_t pos;

      /* parv[6] is the numeric code, remaining are params */
      pos = ircd_snprintf(0, buf, sizeof(buf), ":%s %s %s",
                          cli_name(&me), parv[6], entry->rs_nick);
      for (i = 7; i < parc; i++) {
        if (i == parc - 1)
          pos += ircd_snprintf(0, buf + pos, sizeof(buf) - pos,
                               " :%s", parv[i]);
        else
          pos += ircd_snprintf(0, buf + pos, sizeof(buf) - pos,
                               " %s", parv[i]);
      }
      relay_shadow_write(entry, buf);
    }
    else if (mode[0] == 'M') {
      /* Message mode: pass through verbatim (trailing param) */
      relay_shadow_write(entry, parv[parc - 1]);
    }

    /* Do NOT forward BS O — point-to-point */
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
/* Cross-server shadow relay management (Phase 1)                    */
/* ---------------------------------------------------------------- */

/* relayHash, pendingRelays, relay_id_seq, relay_hash() — defined at top of file */

/** Generate a unique relay_id for a new remote shadow.
 * Format: "R<server_yy><seq>" — compact, unique per server.
 */
static void generate_relay_id(char *buf, size_t buflen)
{
  ircd_snprintf(0, buf, buflen, "R%s%u", cli_yxx(&me), ++relay_id_seq);
}

/** Add a remote shadow to a session on the managing server (A-side).
 * Creates a ShadowConnection with SHADOW_FLAGS_REMOTE — no local fd,
 * I/O flows via BS R (input) and BS O (output) through the relay server.
 */
struct ShadowConnection *bounce_add_remote_shadow(
    struct BouncerSession *session, struct Client *relay_server,
    unsigned long capab_hex, int is_ssl, const char *sock_ip)
{
  struct ShadowConnection *shadow;

  if (!session || !relay_server)
    return NULL;

  if (session->hs_shadow_count >= BOUNCER_MAX_SHADOWS) {
    Debug((DEBUG_INFO, "bounce_add_remote_shadow: max shadows reached for %s",
           session->hs_sessid));
    return NULL;
  }

  shadow = (struct ShadowConnection *)MyCalloc(1, sizeof(*shadow));
  shadow->sh_id = ++session->hs_client_id_seq;
  shadow->sh_fd = -1; /* No local fd for remote shadows */
  shadow->sh_session = session;
  shadow->sh_flags = SHADOW_FLAGS_REMOTE;
  shadow->sh_relay_server = relay_server;
  shadow->sh_is_ssl = is_ssl;
  shadow->sh_connected = CurrentTime;
  shadow->sh_lasttime = CurrentTime;

  /* Set capabilities from hex bitfield */
  memset(&shadow->sh_capab, 0, sizeof(shadow->sh_capab));
  memset(&shadow->sh_active, 0, sizeof(shadow->sh_active));
  /* TODO: decode capab_hex into CapSet when cap negotiation relay is added */

  if (sock_ip)
    ircd_strncpy(shadow->sh_sock_ip, sock_ip, SOCKIPLEN);

  /* Generate relay_id */
  generate_relay_id(shadow->sh_relay_id, sizeof(shadow->sh_relay_id));

  /* Link into session's shadow list */
  shadow->sh_next = session->hs_shadows;
  session->hs_shadows = shadow;
  session->hs_shadow_count++;

  Debug((DEBUG_INFO, "bounce_add_remote_shadow: added relay %s for session %s via %s",
         shadow->sh_relay_id, session->hs_sessid, cli_name(relay_server)));

  return shadow;
}

/* ---------------------------------------------------------------- */
/* SQUIT alias promotion                                             */
/* ---------------------------------------------------------------- */

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
 * For each session marked hs_promoting: compute the deterministic
 * tiebreaker (lowest ba_server numeric), promote the winning alias
 * to primary, restore mode flags from session replica, and if the
 * winner is local, broadcast BX P + BS T.
 *
 * @param[in] server The departing server (for logging).
 */
void bounce_execute_squit_promotions(struct Client *server)
{
  int i, j, k;
  struct BouncerSession *session;

  for (i = 0; i < BOUNCE_TOKEN_HASHSIZE; i++) {
    for (session = tokenHash[i]; session; session = session->hs_tnext) {
      const char *winner_numeric = NULL;
      const char *winner_server = NULL;
      struct Client *alias;
      struct Membership *member;
      int winner_idx = -1;

      if (!session->hs_promoting)
        continue;

      /* Determine winner: lowest ba_server numeric (lexicographic) */
      for (j = 0; j < session->hs_alias_count; j++) {
        if (!winner_server ||
            ircd_strcmp(session->hs_aliases[j].ba_server, winner_server) < 0) {
          winner_server = session->hs_aliases[j].ba_server;
          winner_numeric = session->hs_aliases[j].ba_numeric;
          winner_idx = j;
        }
      }

      if (!winner_numeric || winner_idx < 0) {
        session->hs_promoting = 0;
        session->hs_client = NULL;
        continue;
      }

      /* Find the winning alias Client */
      alias = findNUser(winner_numeric);
      if (!alias || !IsBouncerAlias(alias)) {
        Debug((DEBUG_INFO, "bounce_promote: alias %s not found for session %s",
               winner_numeric, session->hs_sessid));
        session->hs_promoting = 0;
        session->hs_client = NULL;
        continue;
      }

      Debug((DEBUG_INFO, "bounce_promote: promoting alias %s (server %s) "
             "for session %s/%s",
             winner_numeric, winner_server,
             session->hs_account, session->hs_sessid));

      /* Promote: clear CHFL_ALIAS on all channel memberships, restore modes */
      for (member = cli_user(alias)->channel; member;
           member = member->next_channel) {
        if (IsMemberAlias(member)) {
          struct Channel *chptr = member->channel;

          /* Clear alias flag */
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

      /* Clear alias flags, set as bouncer primary */
      ClearBouncerAlias(alias);
      SetBouncerHold(alias);
      cli_user(alias)->alias_primary = NULL;

      /* Update nick timestamp for collision resolution —
       * ensures promoted alias wins over stale ghosts from reconnect */
      cli_lastnick(alias) = CurrentTime;

      /* Add to nick hash (aliases aren't in nick hash) */
      hAddClient(alias);

      /* Add promoted alias to UserStats — alias was never counted,
       * but old primary's exit already decremented the count */
      ++UserStats.clients;
      if (UserStats.clients > UserStats.clients_max) {
        UserStats.clients_max = UserStats.clients;
        save_tunefile();
      }
      ++(cli_serv(cli_user(alias)->server)->clients);
      if (MyUser(alias)) {
        ++UserStats.local_clients;
        if (UserStats.local_clients > UserStats.local_clients_max) {
          UserStats.local_clients_max = UserStats.local_clients;
          save_tunefile();
        }
      }
      if (IsInvisible(alias))
        ++UserStats.inv_clients;

      /* Remove promoted alias from hs_aliases[] */
      if (winner_idx < session->hs_alias_count - 1)
        memmove(&session->hs_aliases[winner_idx],
                &session->hs_aliases[winner_idx + 1],
                (session->hs_alias_count - 1 - winner_idx)
                  * sizeof(struct BounceAlias));
      session->hs_alias_count--;

      /* Update session to point to promoted alias */
      session->hs_client = alias;
      ircd_strncpy(session->hs_origin, cli_yxx(cli_user(alias)->server),
                    sizeof(session->hs_origin) - 1);
      session->hs_promoting = 0;

      /* If promoted alias is on this server, broadcast BX P + BS T */
      if (MyUser(alias)) {
        sendcmdto_serv_butone(&me, CMD_BOUNCER_TRANSFER, NULL,
                              "P %s %s %s %s",
                              winner_numeric, winner_numeric,
                              session->hs_sessid, cli_name(alias));
        sendcmdto_serv_butone(&me, CMD_BOUNCER_SESSION, NULL,
                              "T %s %s %s",
                              session->hs_account, session->hs_sessid,
                              cli_yxx(&me));
      }
    }
  }
}

/** Clean up all bouncer state referencing a departing server.
 * Called from exit_client() when a server SQUITs.
 *
 * A-side: removes remote shadows whose sh_relay_server matches the
 * departing server.
 * B-side: destroys relay entries whose rs_server matches the departing
 * server, and cleans up pending relays.
 */
void bounce_cleanup_server(struct Client *server)
{
  int i;
  struct BouncerSession *session;
  struct ShadowConnection *sh, **pp;
  struct RelayShadowEntry *entry, *entry_next;

  if (!server)
    return;

  /* A-side: remove remote shadows referencing this relay server */
  for (i = 0; i < BOUNCE_TOKEN_HASHSIZE; i++) {
    for (session = tokenHash[i]; session; session = session->hs_tnext) {
      pp = &session->hs_shadows;
      while (*pp) {
        sh = *pp;
        if ((sh->sh_flags & SHADOW_FLAGS_REMOTE) &&
            sh->sh_relay_server == server) {
          *pp = sh->sh_next;
          session->hs_shadow_count--;
          Debug((DEBUG_INFO, "bounce_cleanup_server: removed remote shadow %s "
                 "for session %s (server %s departing)",
                 sh->sh_relay_id, session->hs_sessid, cli_name(server)));
          MyFree(sh);
        } else {
          pp = &sh->sh_next;
        }
      }
    }
  }

  /* B-side: destroy relay entries referencing this managing server */
  for (i = 0; i < RELAY_SHADOW_HASHSIZE; i++) {
    entry = relayHash[i];
    while (entry) {
      entry_next = entry->rs_next;
      if (entry->rs_server == server) {
        Debug((DEBUG_INFO, "bounce_cleanup_server: destroying relay %s "
               "(managing server %s departing)",
               entry->rs_relay_id, cli_name(server)));
        bounce_destroy_relay(entry, 0); /* no notify — server is gone */
      }
      entry = entry_next;
    }
  }

  /* B-side: clean up pending relays referencing this managing server */
  {
    struct RelayShadowEntry **rpp = &pendingRelays;
    while (*rpp) {
      entry = *rpp;
      if (entry->rs_server == server) {
        *rpp = entry->rs_next;
        Debug((DEBUG_INFO, "bounce_cleanup_server: removing pending relay for %s "
               "(managing server %s departing)",
               entry->rs_account, cli_name(server)));
        if (entry->rs_shadow) {
          MsgQClear(&entry->rs_shadow->sh_sendQ);
          DBufClear(&entry->rs_shadow->sh_recvQ);
#ifdef USE_SSL
          ssl_free(&entry->rs_shadow->sh_socket);
          entry->rs_shadow->sh_socket.ssl = NULL;
#endif
          if (entry->rs_shadow->sh_fd >= 0) {
            /* Same deferred-free pattern as bounce_destroy_relay:
             * socket_del may fire ET_DESTROY synchronously, freeing
             * shadow+entry via the callback. */
            int saved_fd = entry->rs_shadow->sh_fd;
            entry->rs_shadow->sh_fd = -1;
            socket_del(&entry->rs_shadow->sh_socket);
            close(saved_fd);
            /* ET_DESTROY frees shadow and entry */
          } else {
            MyFree(entry->rs_shadow);
            MyFree(entry);
          }
        } else {
          MyFree(entry);
        }
      } else {
        rpp = &entry->rs_next;
      }
    }
  }
}

/** Remove a remote shadow from its session (A-side cleanup). */
static void bounce_remove_remote_shadow(struct ShadowConnection *shadow)
{
  struct BouncerSession *session;
  struct ShadowConnection **pp;

  if (!shadow || !(shadow->sh_flags & SHADOW_FLAGS_REMOTE))
    return;

  session = shadow->sh_session;
  if (!session)
    return;

  /* Roll shadow's lifetime data counters into session aggregates */
  bounce_accumulate_shadow(session, shadow);

  /* Unlink from session's shadow list */
  for (pp = &session->hs_shadows; *pp; pp = &(*pp)->sh_next) {
    if (*pp == shadow) {
      *pp = shadow->sh_next;
      session->hs_shadow_count--;
      break;
    }
  }

  MyFree(shadow);
}

/** Find a pending relay entry by account + sessid (B-side).
 * Used when BS W arrives to finalize a pending relay.
 */
static struct RelayShadowEntry *bounce_find_relay_pending(const char *account,
                                                          const char *sessid)
{
  struct RelayShadowEntry *entry, **pp;

  for (pp = &pendingRelays; *pp; pp = &(*pp)->rs_next) {
    entry = *pp;
    if (0 == strcmp(entry->rs_account, account) &&
        0 == strcmp(entry->rs_sessid, sessid)) {
      /* Remove from pending list — caller will add to relay hash */
      *pp = entry->rs_next;
      entry->rs_next = NULL;
      return entry;
    }
  }
  return NULL;
}

/** Create a pending relay entry (B-side, during register_user).
 * The entry goes on the pending list until BS W arrives with the relay_id.
 */
struct RelayShadowEntry *bounce_add_pending_relay(
    int fd, const char *account, const char *sessid,
    struct Client *server, int is_ssl, const char *sock_ip,
    void *ssl)
{
  struct RelayShadowEntry *entry;
  struct ShadowConnection *shadow;

  if (fd < 0 || !server)
    return NULL;

  /* Create the ShadowConnection for the relay socket */
  shadow = (struct ShadowConnection *)MyCalloc(1, sizeof(*shadow));
  shadow->sh_fd = fd;
  shadow->sh_flags = SHADOW_FLAGS_RELAY_LOCAL;
  shadow->sh_relay_server = server;
  shadow->sh_is_ssl = is_ssl;
  shadow->sh_connected = CurrentTime;
  shadow->sh_lasttime = CurrentTime;
  shadow->sh_session = NULL;
  shadow->sh_relay_id[0] = '\0'; /* Will be assigned by BS W */
#ifdef USE_SSL
  shadow->sh_socket.ssl = ssl;
#endif

  if (sock_ip)
    ircd_strncpy(shadow->sh_sock_ip, sock_ip, SOCKIPLEN);

  msgq_init(&shadow->sh_sendQ);
  /* sh_recvQ already zeroed by MyCalloc — valid empty DBuf */
  shadow->sh_count = 0;

  /* Create the relay entry */
  entry = (struct RelayShadowEntry *)MyCalloc(1, sizeof(*entry));
  entry->rs_relay_id[0] = '\0'; /* Pending — no relay_id yet */
  ircd_strncpy(entry->rs_account, account, ACCOUNTLEN);
  ircd_strncpy(entry->rs_sessid, sessid, BOUNCER_SESSID_LEN - 1);
  entry->rs_server = server;
  entry->rs_shadow = shadow;
  entry->rs_is_ssl = is_ssl;

  /* Register with event loop for reads while pending.
   * We don't forward input until BS W arrives (no relay_id yet),
   * but we need to drain the socket to prevent blocking.
   * The read callback handles the pending state. */
  if (!socket_add(&shadow->sh_socket, relay_shadow_read_callback,
                  (void *)entry, SS_CONNECTED, SOCK_EVENT_READABLE, fd)) {
    Debug((DEBUG_ERROR, "bounce_add_pending_relay: socket_add failed"));
#ifdef USE_SSL
    ssl_free(&shadow->sh_socket);
    shadow->sh_socket.ssl = NULL;
#endif
    MyFree(shadow);
    MyFree(entry);
    return NULL;
  }

  /* Add to pending list */
  entry->rs_next = pendingRelays;
  pendingRelays = entry;

  Debug((DEBUG_INFO, "bounce_add_pending_relay: created pending relay for %s@%s via %s",
         account, sessid, cli_name(server)));

  return entry;
}

/** Find a relay shadow entry by relay_id on this server (B-side). */
struct RelayShadowEntry *bounce_find_relay(const char *relay_id)
{
  unsigned int h;
  struct RelayShadowEntry *entry;

  if (!relay_id || !*relay_id)
    return NULL;

  h = relay_hash(relay_id);
  for (entry = relayHash[h]; entry; entry = entry->rs_next) {
    if (0 == strcmp(entry->rs_relay_id, relay_id))
      return entry;
  }
  return NULL;
}

/** Create a relay shadow entry on the relay server (B-side).
 * Creates a local ShadowConnection with SHADOW_FLAGS_RELAY_LOCAL that
 * owns the dup'd user socket fd, and registers it in the relay hash.
 */
struct RelayShadowEntry *bounce_create_relay(
    int fd, const char *account, const char *sessid,
    const char *relay_id, struct Client *server,
    const char *nick, int is_ssl, const char *sock_ip)
{
  struct RelayShadowEntry *entry;
  struct ShadowConnection *shadow;
  unsigned int h;

  if (fd < 0 || !relay_id || !server)
    return NULL;

  /* Create the ShadowConnection for the relay socket */
  shadow = (struct ShadowConnection *)MyCalloc(1, sizeof(*shadow));
  shadow->sh_fd = fd;
  shadow->sh_flags = SHADOW_FLAGS_RELAY_LOCAL;
  shadow->sh_relay_server = server;
  shadow->sh_is_ssl = is_ssl;
  shadow->sh_connected = CurrentTime;
  shadow->sh_lasttime = CurrentTime;
  shadow->sh_session = NULL; /* Not attached to a local session */
  ircd_strncpy(shadow->sh_relay_id, relay_id, sizeof(shadow->sh_relay_id) - 1);

  if (sock_ip)
    ircd_strncpy(shadow->sh_sock_ip, sock_ip, SOCKIPLEN);

  msgq_init(&shadow->sh_sendQ);
  /* sh_recvQ already zeroed by MyCalloc — valid empty DBuf */
  shadow->sh_count = 0;

  /* Create the relay entry */
  entry = (struct RelayShadowEntry *)MyCalloc(1, sizeof(*entry));
  ircd_strncpy(entry->rs_relay_id, relay_id, sizeof(entry->rs_relay_id) - 1);
  ircd_strncpy(entry->rs_account, account, ACCOUNTLEN);
  ircd_strncpy(entry->rs_sessid, sessid, BOUNCER_SESSID_LEN - 1);
  entry->rs_server = server;
  entry->rs_shadow = shadow;
  entry->rs_is_ssl = is_ssl;
  if (nick)
    ircd_strncpy(entry->rs_nick, nick, NICKLEN);

  /* Register with event loop — the relay socket needs read events.
   * We use SS_CONNECTED since the socket is already established. */
  if (!socket_add(&shadow->sh_socket, relay_shadow_read_callback,
                  (void *)entry, SS_CONNECTED, SOCK_EVENT_READABLE, fd)) {
    Debug((DEBUG_ERROR, "bounce_create_relay: socket_add failed for relay %s", relay_id));
    MyFree(shadow);
    MyFree(entry);
    return NULL;
  }

  /* Add to relay hash */
  h = relay_hash(relay_id);
  entry->rs_next = relayHash[h];
  relayHash[h] = entry;

  Debug((DEBUG_INFO, "bounce_create_relay: created relay %s for %s@%s via %s",
         relay_id, account, sessid, cli_name(server)));

  return entry;
}

/** Destroy a relay shadow entry and its ShadowConnection (B-side). */
void bounce_destroy_relay(struct RelayShadowEntry *entry, int notify)
{
  struct ShadowConnection *shadow;
  struct RelayShadowEntry **pp;
  unsigned int h;

  if (!entry)
    return;

  shadow = entry->rs_shadow;

  /* Remove from relay hash */
  h = relay_hash(entry->rs_relay_id);
  for (pp = &relayHash[h]; *pp; pp = &(*pp)->rs_next) {
    if (*pp == entry) {
      *pp = entry->rs_next;
      break;
    }
  }

  /* Notify managing server if requested */
  if (notify && entry->rs_server) {
    sendcmdto_one(&me, CMD_BOUNCER_SESSION, entry->rs_server,
                  "XS %s %s %s",
                  entry->rs_account, entry->rs_sessid, entry->rs_relay_id);
  }

  /* Clean up the shadow connection */
  if (shadow) {
    MsgQClear(&shadow->sh_sendQ);
    DBufClear(&shadow->sh_recvQ);

    if (shadow->sh_fd >= 0) {
      /* Socket is registered with the event engine.  socket_del() marks
       * GEN_DESTROY but the engine may still hold references (gh_ref > 0)
       * from the current event dispatch.  Freeing the shadow now would
       * destroy the embedded Socket struct while the engine still accesses
       * it — classic use-after-free.  Defer MyFree to ET_DESTROY callback
       * which fires after the last gen_ref_dec drops gh_ref to 0.
       *
       * If gh_ref == 0, socket_del fires ET_DESTROY synchronously, which
       * frees shadow+entry via the callback before returning here.  Save
       * the fd and SSL pointer first so we don't touch freed memory. */
      int saved_fd = shadow->sh_fd;
#ifdef USE_SSL
      SSL *saved_ssl = shadow->sh_socket.ssl;
      shadow->sh_socket.ssl = NULL;
#endif
      shadow->sh_fd = -1;
      socket_del(&shadow->sh_socket);
      close(saved_fd);
#ifdef USE_SSL
      /* SSL_free after close — SSL_shutdown inside SSL_free won't send
       * close_notify over a dead fd (same pattern as bounce_promote_shadow). */
      if (saved_ssl)
        SSL_free(saved_ssl);
#endif
      return; /* Memory freed by ET_DESTROY (now or deferred) */
    }

#ifdef USE_SSL
    ssl_free(&shadow->sh_socket);
#endif
    MyFree(shadow);
  }

  MyFree(entry);
}

/** I/O callback for relay socket reads (B-side).
 * Reads user input from the relay socket, wraps it in BS R, and sends
 * to the managing server.
 */
static void relay_shadow_read_callback(struct Event *ev)
{
  struct RelayShadowEntry *entry = (struct RelayShadowEntry *)s_data(ev_socket(ev));
  struct ShadowConnection *shadow;
  int len;
  char *line_start;
  char *newline;

  if (!entry || !entry->rs_shadow)
    return;

  shadow = entry->rs_shadow;

  switch (ev_type(ev)) {
  case ET_READ:
  case ET_EOF:
#ifdef USE_SSL
  relay_read_again:
#endif
    /* Read available data — use SSL_read for TLS connections */
#ifdef USE_SSL
    if (shadow->sh_socket.ssl) {
      ERR_clear_error();
      len = SSL_read(shadow->sh_socket.ssl,
                     shadow->sh_buffer + shadow->sh_count,
                     sizeof(shadow->sh_buffer) - shadow->sh_count - 1);
      if (len <= 0) {
        int err = SSL_get_error(shadow->sh_socket.ssl, len);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
          return; /* Retry later */
        /* Connection closed or error */
        bounce_destroy_relay(entry, 1);
        return;
      }
    } else
#endif
    {
      len = read(shadow->sh_fd, shadow->sh_buffer + shadow->sh_count,
                 sizeof(shadow->sh_buffer) - shadow->sh_count - 1);
      if (len <= 0) {
        if (len == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
          bounce_destroy_relay(entry, 1);
          return;
        }
        return; /* EAGAIN, try later */
      }
    }

    shadow->sh_count += len;
    shadow->sh_buffer[shadow->sh_count] = '\0';
    shadow->sh_lasttime = CurrentTime;

    /* Extract complete lines and send as BS R */
    line_start = shadow->sh_buffer;
    while ((newline = strchr(line_start, '\n')) != NULL) {
      *newline = '\0';
      /* Strip trailing \r if present */
      if (newline > line_start && *(newline - 1) == '\r')
        *(newline - 1) = '\0';

      /* Handle PING during pending/active state */
      if (0 == ircd_strncmp(line_start, "PING ", 5) ||
          0 == ircd_strncmp(line_start, "PING\r", 5) ||
          0 == ircd_strcmp(line_start, "PING")) {
        /* Respond to PING locally — don't relay */
        char pongbuf[512];
        const char *pingarg = (line_start[4] == ' ') ? line_start + 5 : cli_name(&me);
        ircd_snprintf(0, pongbuf, sizeof(pongbuf),
                      ":%s PONG %s :%s",
                      cli_name(&me), cli_name(&me), pingarg);
        relay_shadow_write(entry, pongbuf);
        line_start = newline + 1;
        continue;
      }

      /* Send to managing server if relay_id is assigned */
      if (entry->rs_relay_id[0] && entry->rs_server && *line_start) {
        sendcmdto_one(&me, CMD_BOUNCER_SESSION, entry->rs_server,
                      "R %s %s %s :%s",
                      entry->rs_account, entry->rs_sessid,
                      entry->rs_relay_id, line_start);
      }
      /* If relay_id not yet assigned (pending BS W), discard input.
       * The user hasn't received welcome yet, so no meaningful commands. */

      line_start = newline + 1;
    }

    /* Move remaining partial data to start of buffer */
    if (line_start > shadow->sh_buffer) {
      shadow->sh_count = strlen(line_start);
      if (shadow->sh_count > 0)
        memmove(shadow->sh_buffer, line_start, shadow->sh_count + 1);
    }

    /* Buffer overflow protection */
    if (shadow->sh_count >= sizeof(shadow->sh_buffer) - 1) {
      Debug((DEBUG_INFO, "relay_shadow_read_callback: buffer overflow for relay %s",
             entry->rs_relay_id));
      bounce_destroy_relay(entry, 1);
      return;
    }

    if (ev_type(ev) == ET_EOF) {
      bounce_destroy_relay(entry, 1);
      return;
    }

#ifdef USE_SSL
    /* Drain SSL internal buffer — OpenSSL may have decrypted multiple
     * commands from a single TLS record. */
    if (shadow->sh_socket.ssl && ssl_pending(&shadow->sh_socket) > 0)
      goto relay_read_again;
#endif
    break;

  case ET_DESTROY:
    /* Event engine is done with this socket — safe to free memory.
     * bounce_destroy_relay() deferred the free because gh_ref > 0
     * when called from inside an event callback. */
    if (entry) {
      if (entry->rs_shadow) {
        MyFree(entry->rs_shadow);
        entry->rs_shadow = NULL;
      }
      MyFree(entry);
    }
    break;

  case ET_WRITE:
  {
    /* Flush queued data from shadow sendQ to the relay socket */
    unsigned int bytes_count = 0, bytes_written = 0;
    IOResult result;

    if (MsgQLength(&shadow->sh_sendQ) == 0) {
      socket_events(&shadow->sh_socket, SOCK_EVENT_READABLE);
      break;
    }

#ifdef USE_SSL
    if (shadow->sh_socket.ssl) {
      /* SSL: coalesce sendQ into linear buffer and SSL_write.
       * Can't use ssl_sendv — it requires a Client for error reporting. */
      struct iovec iov[128];
      char wbuf[BUFSIZE * 4];
      unsigned int wlen = 0;
      int iov_count, i, written;

      iov_count = msgq_mapiov(&shadow->sh_sendQ, iov, 128, &bytes_count);
      for (i = 0; i < iov_count && wlen < sizeof(wbuf); i++) {
        unsigned int chunk = iov[i].iov_len;
        if (wlen + chunk > sizeof(wbuf))
          chunk = sizeof(wbuf) - wlen;
        memcpy(wbuf + wlen, iov[i].iov_base, chunk);
        wlen += chunk;
      }

      ERR_clear_error();
      written = SSL_write(shadow->sh_socket.ssl, wbuf, wlen);
      if (written > 0) {
        msgq_delete(&shadow->sh_sendQ, written);
        shadow->sh_sendB += written;
      } else {
        int err = SSL_get_error(shadow->sh_socket.ssl, written);
        if (err != SSL_ERROR_WANT_WRITE && err != SSL_ERROR_WANT_READ) {
          bounce_destroy_relay(entry, 1);
          return;
        }
      }
    } else
#endif
    {
      result = os_sendv_nonb(shadow->sh_fd, &shadow->sh_sendQ,
                             &bytes_count, &bytes_written);
      if (result == IO_SUCCESS) {
        msgq_delete(&shadow->sh_sendQ, bytes_written);
        shadow->sh_sendB += bytes_written;
      } else if (result == IO_FAILURE) {
        bounce_destroy_relay(entry, 1);
        return;
      }
      /* IO_BLOCKED: retry on next ET_WRITE */
    }

    /* Keep requesting writes if data remains */
    if (MsgQLength(&shadow->sh_sendQ) > 0)
      socket_events(&shadow->sh_socket, SOCK_EVENT_READABLE | SOCK_EVENT_WRITABLE);
    else
      socket_events(&shadow->sh_socket, SOCK_EVENT_READABLE);
    break;
  }

  case ET_ERROR:
    bounce_destroy_relay(entry, 1);
    break;

  default:
    break;
  }
}

/** Write output to a relay socket (B-side).
 * Queues data on the shadow's sendQ and requests a writable event.
 * The ET_WRITE handler in relay_shadow_read_callback flushes the queue.
 * @param[in] entry Relay entry to write to.
 * @param[in] data The formatted IRC line to send to the user.
 */
static void relay_shadow_write(struct RelayShadowEntry *entry, const char *data)
{
  struct ShadowConnection *shadow;
  struct MsgBuf *mb;

  if (!entry || !entry->rs_shadow)
    return;

  shadow = entry->rs_shadow;
  if (shadow->sh_fd < 0 || (shadow->sh_flags & SHADOW_FLAGS_DEAD))
    return;

  /* msgq_make appends \r\n automatically */

  /* Queue on sendQ and request writable event for async flush */
  mb = msgq_make(0, "%s", data);
  if (mb) {
    msgq_add(&shadow->sh_sendQ, mb, 0);
    shadow->sh_sendM++;
    msgq_clean(mb);
    socket_events(&shadow->sh_socket, SOCK_EVENT_READABLE | SOCK_EVENT_WRITABLE);
  }
}

/** Send TOPIC (332/333) for a channel to a relay shadow.
 * @param[in] entry    Relay shadow entry.
 * @param[in] channame Channel name to send topic for.
 */
static void relay_send_topic(struct RelayShadowEntry *entry,
                              const char *channame)
{
  struct Channel *chptr;
  char buf[BUFSIZE];

  if (!entry || !channame)
    return;

  chptr = FindChannel(channame);
  if (!chptr || !chptr->topic[0])
    return;

  ircd_snprintf(0, buf, sizeof(buf), ":%s 332 %s %s :%s",
                cli_name(&me), entry->rs_nick, chptr->chname, chptr->topic);
  relay_shadow_write(entry, buf);

  ircd_snprintf(0, buf, sizeof(buf), ":%s 333 %s %s %s %lu",
                cli_name(&me), entry->rs_nick, chptr->chname,
                chptr->topic_nick, (unsigned long)chptr->topic_time);
  relay_shadow_write(entry, buf);
}

/** Send NAMES (353/366) for a channel to a relay shadow.
 * Mirrors do_names() but writes through relay_shadow_write()
 * since we don't have a local Client* for the relay user.
 * @param[in] entry    Relay shadow entry.
 * @param[in] channame Channel name to send names for.
 */
static void relay_send_names(struct RelayShadowEntry *entry,
                              const char *channame)
{
  struct Channel *chptr;
  struct Membership *member;
  char buf[BUFSIZE];
  char prefix[8];
  int idx, mlen, needs_space;

  if (!entry || !channame)
    return;

  chptr = FindChannel(channame);
  if (!chptr)
    return;

  /* ":<server> 353 <nick> = <channel> :" */
  mlen = strlen(cli_name(&me)) + 1 + 3 + 1 + strlen(entry->rs_nick) + 1
       + 2 + strlen(chptr->chname) + 2;

  /* Channel type prefix */
  {
    char chantype = '*';
    if (PubChannel(chptr))
      chantype = '=';
    else if (SecretChannel(chptr))
      chantype = '@';

    ircd_snprintf(0, buf, sizeof(buf), ":%s 353 %s %c %s :",
                  cli_name(&me), entry->rs_nick, chantype, chptr->chname);
  }
  idx = strlen(buf);
  needs_space = 0;

  for (member = chptr->members; member; member = member->next_member) {
    struct Client *c2ptr = member->user;
    int plen = 0;
    int nlen;

    if (IsZombie(member))
      continue;
    if (IsDelayedJoin(member))
      continue;

    /* Build status prefix */
    if (IsChanOp(member))
      prefix[plen++] = '@';
    if (IsHalfOp(member))
      prefix[plen++] = '%';
    if (HasVoice(member))
      prefix[plen++] = '+';
    if (IsMemberHolding(member))
      prefix[plen++] = '~';
    prefix[plen] = '\0';

    nlen = strlen(cli_name(c2ptr));

    /* Check if adding this nick would overflow — flush if needed */
    if (idx + needs_space + plen + nlen + 4 > BUFSIZE) {
      relay_shadow_write(entry, buf);
      ircd_snprintf(0, buf, sizeof(buf), ":%s 353 %s %c %s :",
                    cli_name(&me), entry->rs_nick,
                    PubChannel(chptr) ? '=' : (SecretChannel(chptr) ? '@' : '*'),
                    chptr->chname);
      idx = strlen(buf);
      needs_space = 0;
    }

    if (needs_space)
      buf[idx++] = ' ';
    needs_space = 1;

    memcpy(buf + idx, prefix, plen);
    idx += plen;
    memcpy(buf + idx, cli_name(c2ptr), nlen);
    idx += nlen;
    buf[idx] = '\0';
  }

  /* Flush remaining names */
  if (needs_space)
    relay_shadow_write(entry, buf);

  /* RPL_ENDOFNAMES */
  ircd_snprintf(0, buf, sizeof(buf), ":%s 366 %s %s :End of /NAMES list.",
                cli_name(&me), entry->rs_nick, chptr->chname);
  relay_shadow_write(entry, buf);
}

/** Replay local chathistory to a relay shadow for a single channel.
 * Queries the local MDBX chathistory DB and writes formatted messages
 * directly to the relay socket.  This avoids depending on the session
 * holder (A-side) for history — the leaf has its own DB and can also
 * use chathistory federation for channels it doesn't have locally.
 *
 * @param[in] entry  Relay shadow entry to write to.
 * @param[in] target Channel name to replay.
 * @param[in] limit  Max messages to replay.
 */
static void relay_replay_history(struct RelayShadowEntry *entry,
                                 const char *target, int limit)
{
  struct HistoryMessage *messages = NULL, *msg;
  int count;
  char buf[BUFSIZE];
  char iso_time[32];
  static const char *type_cmd[] = {
    "PRIVMSG", "NOTICE", "JOIN", "PART", "QUIT",
    "KICK", "MODE", "TOPIC", "TAGMSG", NULL /* GAP */
  };

  if (!entry || !entry->rs_shadow || !history_is_available())
    return;

  /* Replay last N messages — no floor timestamp since we don't know
   * when the session was last active from the leaf's perspective.
   * Use "0" as the after_timestamp to get the most recent messages. */
  count = history_query_latest_after(target, limit, "0", &messages);
  if (count <= 0 || !messages)
    return;

  for (msg = messages; msg; msg = msg->next) {
    const char *cmd;
    const char *content;

    /* Skip gap markers */
    if (msg->type == HISTORY_GAP)
      continue;

    cmd = (msg->type <= HISTORY_TAGMSG) ? type_cmd[msg->type] : "PRIVMSG";
    content = msg->dyn_content ? msg->dyn_content : msg->content;

    /* Convert timestamp to ISO 8601 for @time= tag */
    if (history_unix_to_iso(msg->timestamp, iso_time, sizeof(iso_time)) != 0)
      continue;

    /* Format: @time=<iso>;msgid=<id> :<sender> <CMD> <target> :<content> */
    if (msg->type == HISTORY_TAGMSG || !content || !*content) {
      ircd_snprintf(0, buf, sizeof(buf),
                    "@time=%s;msgid=%s :%s %s %s",
                    iso_time, msg->msgid, msg->sender, cmd, target);
    } else {
      ircd_snprintf(0, buf, sizeof(buf),
                    "@time=%s;msgid=%s :%s %s %s :%s",
                    iso_time, msg->msgid, msg->sender, cmd, target, content);
    }
    relay_shadow_write(entry, buf);
  }

  history_free_messages(messages);
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
 * Handles two cases:
 * 1. HOLDING session: Ghost disconnected and holding. Normal revive.
 * 2. ACTIVE relay-only: Ghost has no local socket (cli_fd == -1), only
 *    remote shadows provide connectivity. A local client connecting
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
    /* Relay-only promotion: ghost has no local socket, remote shadow(s)
     * provide connectivity. Local client should become primary. */
    if (cli_fd(ghost) >= 0)
      return -1;  /* Ghost has a local socket — use shadow-attach instead */
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
        add_user_to_channel(chptr, alias, CHFL_ALIAS, MAXOPLEVEL);
      }
    }
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
  } else {
    /* Swap path: new_client has no channel memberships.
     * Transfer memberships from old to new (legacy/sequential). */
    for (member = cli_user(old_client)->channel; member; member = next_member) {
      next_member = member->next_channel;
      unsigned int modes = member->status & ~CHFL_HOLDING;
      add_user_to_channel(member->channel, new_client, modes, OpLevel(member));
      remove_user_from_channel(old_client, member->channel);
    }
    /* Rename new client to the session's nick */
    if (ircd_strcmp(cli_name(new_client), nick)) {
      /* Hash re-key: remove from old name, set new, add back */
      hRemClient(new_client);
      ircd_strncpy(cli_name(new_client), nick, NICKLEN);
      hAddClient(new_client);
    }
  }

  /* Clear bouncer flags from old client */
  if (IsBouncerHold(old_client))
    ClearBouncerHold(old_client);

  /* Exit the old client silently */
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
    Debug((DEBUG_INFO, "bounce_setup_local_alias: no primary for session %s",
           session->hs_sessid));
    return -1;
  }

  user = cli_user(sptr);
  if (!user)
    return -1;

  Debug((DEBUG_INFO, "bounce_setup_local_alias: converting %s to alias of %s (session %s)",
         cli_name(sptr), cli_name(primary), session->hs_sessid));

  /* --- Step 1: Remove from nick hash ---
   * The client was added during NICK registration.  Aliases must NOT be
   * in the nick hash — FindUser() should return the primary, not the alias. */
  hRemClient(sptr);

  /* --- Step 2: Overwrite identity from primary ---
   * Same pattern as bounce_alias_create() for remote aliases. */
  ircd_strncpy(cli_name(sptr), cli_name(primary), NICKLEN);
  ircd_strncpy(user->username, cli_user(primary)->username, USERLEN);
  ircd_strncpy(user->host, cli_user(primary)->host, HOSTLEN);
  ircd_strncpy(user->realhost, cli_user(primary)->realhost, HOSTLEN);
  ircd_strncpy(cli_info(sptr), cli_info(primary), REALLEN);
  ircd_strncpy(user->account, cli_user(primary)->account, ACCOUNTLEN);
  user->acc_create = cli_user(primary)->acc_create;

  /* Copy IP and cloaked/fake host */
  memcpy(&cli_ip(sptr), &cli_ip(primary), sizeof(cli_ip(sptr)));
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
    Debug((DEBUG_INFO, "bounce_setup_local_alias: no numerics available for alias"));
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

      if (!find_member_link(chptr, sptr))
        add_user_to_channel(chptr, sptr, CHFL_ALIAS, MAXOPLEVEL);

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
   * Uses local MDBX store; on non-storing servers, history_is_available()
   * returns 0 and no replay occurs (capable clients federate via CHATHISTORY).
   *
   * Use session's hs_last_active as the replay baseline — it's the
   * authoritative "last activity" time, persisted in MDBX and replicated
   * via BS C.  cli_user(primary)->last is 0 for remote primaries. */
  if (feature_bool(FEAT_BOUNCER_AUTO_REPLAY)
      && !CapOwnHas(sptr, CAP_DRAFT_CHATHISTORY)) {
    time_t since = session->hs_last_active;
    if (since == 0)
      since = session->hs_created;
    if (since > 0 && since < CurrentTime)
      bouncer_auto_replay(sptr, session, since);
  }

  if (IsIPChecked(sptr))
    IPcheck_connect_succeeded(sptr);

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
  struct Client *primary;
  struct Client *alias;
  struct Client *alias_server;
  struct User *user;
  struct BouncerSession *session;
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
      add_user_to_channel(chptr, alias, CHFL_ALIAS, MAXOPLEVEL);
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
  /* Coalesced flush path for SSL pending auth-phase writes.
   *
   * When a pipelining client had unflushed auth responses, the SSL object
   * carries pending write state (wpend_tot/wpend_buf in wbuf).  The
   * pending TLS record is already encrypted in wbuf — ssl3_write_pending
   * writes from wbuf, not from the application buffer.
   *
   * After ssl3_write_pending completes, OpenSSL continues writing from
   * buf + wpend_ret for (len - wpend_ret) bytes.  By placing the original
   * auth data first in the coalesced buffer, buf[wpend_ret..] correctly
   * contains the remaining auth data + welcome messages.  The client
   * receives: pending TLS record (auth) + new records (remaining auth +
   * welcome) = complete auth responses + welcome sequence. */
  if ((shadow->sh_flags & SHADOW_FLAGS_SSL_PENDING) && shadow->sh_ssl_flush) {
    /* Build the coalesced buffer on first attempt.  On retries (after
     * WANT_WRITE), reuse the same heap buffer — OpenSSL expects the
     * same len for wnum-based progress tracking.  ACCEPT_MOVING_WRITE_BUFFER
     * allows the buf pointer to differ between retries. */
    if (shadow->sh_ssl_flush_len == shadow->sh_ssl_flush_auth) {
      /* Phase 1 → Phase 2: coalesce auth prefix with sendQ welcome data */
      unsigned int sendq_len = MsgQLength(&shadow->sh_sendQ);
      unsigned int new_len = shadow->sh_ssl_flush_auth + sendq_len;
      char *new_buf;
      struct iovec ciov[128];
      unsigned int ciov_bytes = 0;
      int ciov_count;
      unsigned int off;
      int i;

      new_buf = (char *)MyMalloc(new_len);
      if (!new_buf) {
        shadow->sh_flags |= SHADOW_FLAGS_DEAD;
        return;
      }

      /* Copy auth prefix */
      memcpy(new_buf, shadow->sh_ssl_flush, shadow->sh_ssl_flush_auth);

      /* Copy sendQ iovecs (welcome messages) */
      ciov_count = msgq_mapiov(&shadow->sh_sendQ, ciov, 128, &ciov_bytes);
      off = shadow->sh_ssl_flush_auth;
      for (i = 0; i < ciov_count && off < new_len; i++) {
        unsigned int n = ciov[i].iov_len;
        if (off + n > new_len) n = new_len - off;
        memcpy(new_buf + off, ciov[i].iov_base, n);
        off += n;
      }

      MyFree(shadow->sh_ssl_flush);
      shadow->sh_ssl_flush = new_buf;
      shadow->sh_ssl_flush_len = new_len;
      /* sh_ssl_flush_auth unchanged — marks the auth/sendQ boundary */

      Debug((DEBUG_INFO, "Bouncer: built coalesced flush buf for shadow #%u: "
             "%u auth + %u sendQ = %u total",
             shadow->sh_id, shadow->sh_ssl_flush_auth, sendq_len, new_len));
    }

    /* Attempt the coalesced SSL_write */
    {
      int res = SSL_write(shadow->sh_socket.ssl, shadow->sh_ssl_flush,
                          shadow->sh_ssl_flush_len);
      if (res > 0) {
        /* Success: pending TLS record flushed + new data written.
         * Delete the sendQ portion (welcome messages) that was included
         * in the coalesced buffer.  Any messages added to the sendQ
         * after the coalesced buffer was built remain untouched. */
        unsigned int sendq_consumed = shadow->sh_ssl_flush_len
                                      - shadow->sh_ssl_flush_auth;
        if (sendq_consumed > 0)
          msgq_delete(&shadow->sh_sendQ, sendq_consumed);
        shadow->sh_sendB += res;

        /* Clean up flush state */
        MyFree(shadow->sh_ssl_flush);
        shadow->sh_ssl_flush = NULL;
        shadow->sh_ssl_flush_len = 0;
        shadow->sh_ssl_flush_auth = 0;
        shadow->sh_flags &= ~SHADOW_FLAGS_SSL_PENDING;
        shadow->sh_flags &= ~SHADOW_FLAGS_BLOCKED;

        Debug((DEBUG_INFO, "Bouncer: SSL coalesced flush OK for shadow #%u "
               "(%d bytes)", shadow->sh_id, res));

        /* If more data remains (added after coalesced build), flush normally */
        if (MsgQLength(&shadow->sh_sendQ) > 0)
          goto normal_flush;
        return;
      } else {
        int err = SSL_get_error(shadow->sh_socket.ssl, res);
        if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
          shadow->sh_flags |= SHADOW_FLAGS_BLOCKED;
          Debug((DEBUG_INFO, "Bouncer: SSL coalesced flush blocked for "
                 "shadow #%u (err=%d)", shadow->sh_id, err));
          return;
        } else {
          /* Fatal SSL error */
          Debug((DEBUG_ERROR, "Bouncer: SSL coalesced flush failed for "
                 "shadow #%u (res=%d err=%d)", shadow->sh_id, res, err));
          MyFree(shadow->sh_ssl_flush);
          shadow->sh_ssl_flush = NULL;
          shadow->sh_flags |= SHADOW_FLAGS_DEAD;
          return;
        }
      }
    }
  }

normal_flush:
#endif

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
      if (shadow->sh_ssl_flush) {
        MyFree(shadow->sh_ssl_flush);
        shadow->sh_ssl_flush = NULL;
      }
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

  /* Free SSL and pending flush state */
#ifdef USE_SSL
  if (shadow->sh_ssl_flush) {
    MyFree(shadow->sh_ssl_flush);
    shadow->sh_ssl_flush = NULL;
  }
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
/** Transition a session to relay-only mode when the primary disconnects
 * but remote shadows still exist.  Closes the primary's socket, clears
 * stale caps, and keeps the session ACTIVE without a local fd.
 * The ghost continues to function via BS R/O through the relay server.
 *
 * Returns 0 on success, -1 if no remote shadows found.
 */
int bounce_relay_only_transition(struct BouncerSession *session, struct Client *cptr)
{
  struct ShadowConnection *sh;
  int found_remote = 0;

  if (!session || !cptr)
    return -1;

  /* Verify a non-dead remote shadow exists */
  for (sh = session->hs_shadows; sh; sh = sh->sh_next) {
    if ((sh->sh_flags & SHADOW_FLAGS_REMOTE) && !(sh->sh_flags & SHADOW_FLAGS_DEAD)) {
      found_remote = 1;
      break;
    }
  }
  if (!found_remote)
    return -1;

  Debug((DEBUG_INFO,
         "Bouncer: primary disconnect, relay-only mode for %s session %s",
         cli_name(cptr), session->hs_sessid));

  /* Close the primary's socket (fd, confs, listener, queues) */
  close_connection(cptr);
  ClrFlag(cptr, FLAG_DEADSOCKET);

  /* Clear stale caps from the dead primary connection.
   * The ghost has no local socket — only remote shadow caps matter. */
  memset(cli_active_own(cptr), 0, sizeof(struct CapSet));
  memset(cli_active(cptr), 0, sizeof(struct CapSet));

  /* Roll primary counters into session aggregates */
  bounce_accumulate_and_reset_primary(session, cptr);
  bounce_history_disconnect(session, cli_sock_ip(cptr));

  session->hs_last_active = CurrentTime;

  /* Recompute union caps with only the remote shadow(s) */
  bounce_recompute_session_caps(cptr);

  return 0;
}

/** Promote the first eligible (non-remote) shadow to primary.
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

  /* Find a LOCAL shadow to promote.  Remote shadows (SHADOW_FLAGS_REMOTE)
   * have no local fd or socket — they use BS R/O through the relay server
   * and cannot be promoted to primary. */
  shadow = NULL;
  {
    struct ShadowConnection *s;
    for (s = session->hs_shadows; s; s = s->sh_next) {
      if (!(s->sh_flags & SHADOW_FLAGS_REMOTE) && !(s->sh_flags & SHADOW_FLAGS_DEAD)) {
        shadow = s;
        break;
      }
    }
  }
  if (!shadow)
    return -1; /* No local shadows to promote (may still have remote shadows) */

  cptr = session->hs_client;
  assert(0 != cptr);
  con = cli_connect(cptr);
  assert(0 != con);

#ifdef USE_SSL
  /* Prefer a TLS shadow if the primary had TLS, to preserve +z usermode
   * and +Z (SSL-only) channel access.  Falls back to first local shadow if
   * no TLS shadow exists. */
  if (IsSSL(cptr)) {
    struct ShadowConnection *s;
    for (s = session->hs_shadows; s; s = s->sh_next) {
      if (!(s->sh_flags & SHADOW_FLAGS_REMOTE) && s->sh_socket.ssl) { shadow = s; break; }
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

  /* Step 8: Re-register socket with event engine.
   * For relay-only ghosts (revived from HOLDING via BS S without a local
   * socket), the primary's socket was socket_del'd during hold entry and
   * never re-initialized — GEN_ACTIVE is not set.  Use socket_add in that
   * case.  For normal ghosts with an active socket, use socket_reattach
   * which preserves the GenHeader (gh_ref, gh_flags, list linkage). */
  if (!(cli_socket(cptr).s_header.gh_flags & GEN_ACTIVE)) {
    /* Ghost socket was inactive (relay-only) — use socket_add */
    Debug((DEBUG_INFO, "Bouncer: using socket_add for inactive ghost socket in shadow promotion"));
    if (!socket_add(&cli_socket(cptr), client_sock_callback,
                    (void *)con, SS_CONNECTED, SOCK_EVENT_READABLE, fd)) {
      Debug((DEBUG_ERROR, "Bouncer: socket_add failed during shadow promotion for %s",
             cli_name(cptr)));
      close(fd);
      s_fd(&con_socket(con)) = -1;
      LocalClientArray[fd] = 0;
      SetFlag(cptr, FLAG_DEADSOCKET);
      bounce_defer_shadow_free(shadow);
      return -1;
    }
    con_freeflag(con) |= FREEFLAG_SOCKET;
  } else {
    /* Normal ghost with active socket — use socket_reattach */
    if (!socket_reattach(&cli_socket(cptr), fd)) {
      Debug((DEBUG_ERROR, "Bouncer: socket_reattach failed during shadow promotion for %s",
             cli_name(cptr)));
      close(fd);
      s_fd(&con_socket(con)) = -1;
      LocalClientArray[fd] = 0;
      SetFlag(cptr, FLAG_DEADSOCKET);
      bounce_defer_shadow_free(shadow);
      return -1;
    }
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

      if (!CapRecipientHas(primary, CAP_DRAFT_NOIMPLICITNAMES))
        do_names(primary, chptr, NAMES_ALL|NAMES_EON);

      current_shadow = NULL;
    }
  }

  /* Auto-replay recent history for the new shadow connection.
   * Use session's hs_last_active as the replay baseline — it's the
   * authoritative "last activity" time, consistent with alias path. */
  if (feature_bool(FEAT_BOUNCER_AUTO_REPLAY) && cli_user(primary)
      && !CapHas(&shadow->sh_active, CAP_DRAFT_CHATHISTORY)) {
    time_t since = session->hs_last_active;
    if (since == 0)
      since = session->hs_created;
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
