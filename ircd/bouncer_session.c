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
#include "bouncer_converge.h"
#include "bouncer_wire.h"
#include "bouncer_count.h"
#include "bouncer_rebind_auth.h"
#include "account_id.h"
#include "exit_reason.h"
#include "websocket.h"
#include "chathistory_ephemeral.h"
#include "chathistory_presence.h"
#include "session_markread.h"
#include "webpush.h"
#include "IPcheck.h"
#include "capab.h"
#include "channel.h"
#include "class.h"
#include "authtoken.h"
#include "client.h"
#include "history.h"
#include "ircd.h"
#include "db_cursor.h"
#include "db_env.h"
#include "db_txn.h"
#include "db_types.h"
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
#include "m_batch.h"
#include "match.h"
#include "metadata.h"
#include "msg.h"
#include "persistence_profile.h"
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
#include "s_serv.h"
#include "s_user.h"
#include "msgq.h"
#include "struct.h"
#include "motd.h"
#include "version.h"
#include "watch.h"

#include <assert.h>
#include <errno.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <stdarg.h>
#include <stddef.h>
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
      /* Per redesign C.2: persistence is keyed on actual local holding,
       * not historical hs_origin. */
      if (!session_has_local_holder(s))
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

/** Apply a runtime change to FEAT_BOUNCER_PERSIST_INTERVAL to the live timer.
 * If the timer is armed, re-arm it for the new interval so the next fire
 * happens at the updated cadence rather than waiting for the previously
 * scheduled tick.  No-op when the timer isn't running (no dirty sessions). */
void bounce_dirty_persist_restart_timer(void)
{
  int interval;

  if (!dirty_persist_timer_active)
    return;

  interval = feature_int(FEAT_BOUNCER_PERSIST_INTERVAL);
  if (interval <= 0) {
    timer_del(&dirty_persist_timer);
    dirty_persist_timer_active = 0;
    return;
  }

  /* TT_RELATIVE accepts timer_chg (only TT_PERIODIC is asserted against). */
  timer_chg(&dirty_persist_timer, TT_RELATIVE, interval);
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

/** Test whether @a sessid is already in use locally — i.e. assigned to
 * any active Client or persisted bouncer session record this server
 * knows about.  Returns 1 on collision (don't mint this value), 0 if
 * safe to use.  Called from generate_sessid()'s retry loop; cheap
 * because session minting is rare.  See "UUID collision defense"
 * comment on generate_sessid() for the threat model. */
static int sessid_in_use_locally(const char *sessid)
{
  struct Client *acptr;

  /* Active clients on this server's view of the network. */
  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr)) {
    if (!IsUser(acptr) || !cli_session_id(acptr)[0])
      continue;
    if (0 == strcmp(cli_session_id(acptr), sessid))
      return 1;
  }

  /* Persisted bouncer sessions (HOLDING records keyed by sessid).
   * Catches the rare case of minting a value that collides with an
   * existing offline session record. */
  if (feature_bool(FEAT_BOUNCER_PERSIST) && metadata_lmdb_is_available()) {
    struct db_env *env = metadata_get_env();
    struct db_cf  *cf  = metadata_get_bouncer_cf();
    if (env && cf
        && db_exists(env, cf, sessid, strlen(sessid), NULL) == DB_OK)
      return 1;
  }

  return 0;
}

/** Generate a UUID v7 (RFC 9562 §5.7) and write a compact 22-char
 * base64 encoding of its 16 raw bytes to @a buf.
 *
 * Wire format: 22 base64 chars + nul.  16 bytes × 8 bits / 6 bits/char
 * = 21.33, rounded up to 22; the top 4 bits of the last char are zero
 * (the 8-bit input doesn't align with the 6-bit chars at the tail).
 * No padding.  Alphabet: A-Z a-z 0-9 + / (standard base64, matches
 * generate_token() in this file).
 *
 * UUID v7 raw byte layout (per RFC 9562):
 *   - Bits   0..47: Unix timestamp in milliseconds (big-endian).
 *   - Bits  48..51: version = 0111 (7).
 *   - Bits  52..63: server numeric (12 bits — see "UUID collision
 *                   defense" below).  RFC defines this as random;
 *                   we substitute deterministic data without breaking
 *                   uniqueness because the random space at bits 66+
 *                   still dominates same-server collision probability.
 *   - Bits  64..65: variant = 10 (RFC 4122).
 *   - Bits  66..127: random.
 *
 * ## UUID collision defense
 *
 * "A UUID collision may be extremely unlikely, but it's never 0."  Two
 * layers of defense:
 *
 *   1. **Cross-server determinism via embedded P10 server numeric.**
 *      Bits 52..63 carry `cli_yxx(&me)` (the local server's 12-bit
 *      P10 numeric, which is unique on the network by P10 design).
 *      Two different servers can therefore *never* produce the same
 *      UUID — their numerics differ, so the bit patterns differ.
 *      This eliminates the entire cross-server collision vector,
 *      not just makes it improbable.
 *
 *   2. **Same-server retry against an active+persisted collision
 *      check.**  After encoding, sessid_in_use_locally() walks active
 *      Clients and the bouncer-persist CF; on collision we regenerate.
 *      The retry is bounded (8 attempts); a sustained collision implies
 *      a broken RNG and we log loudly.  Same-server statistical
 *      collision in 62 random bits is already astronomical (birthday
 *      floor ≈ 2^31 same-ms mints) but this closes the residual gap.
 *
 * The "ephemeral sessid in chathistory record collides with future
 * ephemeral mint" leak vector is *not* addressed here — it's
 * structurally prevented by the policy invariant that ephemeral sessid
 * is display-only and never an authorization key.  See
 * project_chathistory_design_intent.md and the ephemeral plan.
 *
 * Per redesign A.1: globally unique session identity.  Sortable by
 * creation time via the timestamp prefix (the leading bytes encode
 * first in big-endian-emitted base64), useful for debugging and audit.
 *
 * @param[out] buf Buffer of at least 23 bytes (22 chars + nul).
 */
void generate_sessid(char *buf)
{
  unsigned char b[16];
  uint64_t ms;
  struct timeval tv;
  int i, j;
  unsigned int triplet;
  unsigned int retries = 0;

  do {
    /* Get current time in milliseconds since the Unix epoch. */
    gettimeofday(&tv, NULL);
    ms = (uint64_t)tv.tv_sec * 1000ULL + (uint64_t)(tv.tv_usec / 1000);

    /* Random fill — overwritten in the timestamp / version / numeric /
     * variant positions below.  Bytes 8-15 retain 62 random bits after
     * the 2-bit variant marker. */
#ifdef USE_SSL
    if (RAND_bytes(b, sizeof(b)) != 1) {
      for (i = 0; i < (int)sizeof(b); i++)
        b[i] = (unsigned char)(ircrandom() & 0xFF);
    }
#else
    for (i = 0; i < (int)sizeof(b); i++)
      b[i] = (unsigned char)(ircrandom() & 0xFF);
#endif

    /* Timestamp: 48 bits big-endian into bytes 0-5. */
    b[0] = (unsigned char)((ms >> 40) & 0xFF);
    b[1] = (unsigned char)((ms >> 32) & 0xFF);
    b[2] = (unsigned char)((ms >> 24) & 0xFF);
    b[3] = (unsigned char)((ms >> 16) & 0xFF);
    b[4] = (unsigned char)((ms >> 8) & 0xFF);
    b[5] = (unsigned char)(ms & 0xFF);

    /* Version 7 in high nibble of byte 6 + 12-bit server numeric in
     * low nibble of byte 6 (top 4 bits of numeric) + byte 7 (bottom
     * 8 bits of numeric).  This is what guarantees deterministic
     * cross-server uniqueness — see function comment. */
    {
      const char *yxx = cli_yxx(&me);
      unsigned int numeric =
          (yxx && yxx[0] && yxx[1]) ? base64toint(yxx) : 0;
      b[6] = (unsigned char)(0x70 | ((numeric >> 8) & 0x0F));
      b[7] = (unsigned char)(numeric & 0xFF);
    }

    /* RFC 4122 variant: high two bits of byte 8 are 10. */
    b[8] = (unsigned char)(0x80 | (b[8] & 0x3F));

    /* Encode 16 bytes as 22 base64 chars: 5 full triplets (15 bytes →
     * 20 chars) followed by the trailing byte (8 bits → 2 chars, with
     * 4 zero bits of slack in the second char). */
    for (i = 0, j = 0; i < 15; i += 3) {
      triplet = ((unsigned int)b[i]     << 16)
              | ((unsigned int)b[i + 1] <<  8)
              |  (unsigned int)b[i + 2];
      buf[j++] = b64chars[(triplet >> 18) & 0x3F];
      buf[j++] = b64chars[(triplet >> 12) & 0x3F];
      buf[j++] = b64chars[(triplet >>  6) & 0x3F];
      buf[j++] = b64chars[ triplet        & 0x3F];
    }
    buf[j++] = b64chars[(b[15] >> 2) & 0x3F];
    buf[j++] = b64chars[(b[15] << 4) & 0x3F];
    buf[j]   = '\0';

    if (!sessid_in_use_locally(buf))
      return;
  } while (++retries < 8);

  log_write(LS_SYSTEM, L_WARNING, 0,
            "generate_sessid: %u same-server collisions in a row — RNG suspect",
            retries);
  /* Returning with the last-generated sessid; cross-server uniqueness
   * still holds via the numeric encoding, so this is at worst a local-
   * server identity confusion (the cross-sessid convergence path in
   * bounce_handle_bsc can still reconcile). */
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
static void bounce_arm_hold_timer(struct BouncerSession *session, time_t min_delay);
static void bounce_emit_connect_count(struct BouncerSession *session);
static void bounce_emit_total_active(struct BouncerSession *session);
static void bounce_repair_realname(struct Client *ghost, const char *realname);
static enum bounce_demote_bar demote_eligibility_for(enum bounce_demote_stage stage,
                                                     struct Client *face,
                                                     struct BouncerSession *session,
                                                     struct Client *new_primary);
static void bounce_announce_alias(struct BouncerSession *session,
                                  struct Client *alias, struct Client *primary);
static void unmirrored_clear(const char *account, const char *sessid);
static void bounce_send_bsc(struct BouncerSession *s, struct Client *link);
static void bounce_send_primary_bsa(struct BouncerSession *s, struct Client *link);

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

  /* The timer fires at the points the decayed hold can change, not only
   * at the deadline: while time remains, re-arm and wait. */
  if (bounce_hold_remaining(session) > 0) {
    bounce_arm_hold_timer(session, 1);
    return;
  }

  Debug((DEBUG_INFO, "Bouncer: hold expired for %s session %s",
         session->hs_account, session->hs_sessid));

  /* Get the ghost client before any session changes.
   * Note: hs_client stores the ghost during HOLDING state.
   */
  ghost = session->hs_client;

  /* Only the holder ends a session.  A primary that is not a ghost we
   * hold -- a client of another server (a peer's announcement installed
   * it over ours while the timer still ran), or a live one -- means the
   * session moved since this timer was armed: a BS X from here would make
   * every peer destroy its record under that primary, and a promote would
   * make a second primary.  Its holder runs the session's lifetime. */
  switch (bounce_hold_expiry_action(ghost != NULL,
                                    ghost && MyConnect(ghost) && IsBouncerHold(ghost),
                                    session->hs_alias_count)) {
  case BOUNCE_HOLD_KEEP:
    log_write(LS_USER, L_INFO, 0,
              "Bouncer: hold of %s's session %s ran out, but its primary %s "
              "is %s%s: not ending it here", session->hs_account,
              session->hs_sessid, cli_name(ghost),
              MyConnect(ghost) ? "live here" : "on ",
              MyConnect(ghost) ? ""
                : (bounce_primary_server(session)
                     ? cli_name(bounce_primary_server(session)) : "?"));
    /* A live primary of ours under a record that says HOLDING: the record
     * is what is wrong.  It is active again, so the primary's next
     * disconnect holds it (only an active session's primary is held). */
    if (MyConnect(ghost) && IsUser(ghost) && !IsBouncerAlias(ghost)) {
      session->hs_state = BOUNCE_ACTIVE;
      session->hs_disconnect_time = 0;
      session->hs_last_active = CurrentTime;
      /* Its attached stretch runs from now: its next hold accrues it
       * (bounce_accrue_active). */
      if (!session->hs_attach_time)
        session->hs_attach_time = CurrentTime;
    }
    return;
  case BOUNCE_HOLD_DROP:
    /* No primary anywhere we know of and nothing to promote: our record
     * goes.  No BS X -- a primary we do not know of may still hold the
     * session elsewhere; a peer's record of a ghost we held went with the
     * ghost's own exit. */
    Debug((DEBUG_INFO, "Bouncer: hold of session %s ran out with no "
           "primary and no alias; dropping our record", session->hs_sessid));
    session->hs_state = BOUNCE_DESTROYING;
    return;
  case BOUNCE_HOLD_PROMOTE:
  case BOUNCE_HOLD_END:
    break;
  }

  if (session->hs_alias_count > 0) {
    /* Aliases exist — promote instead of destroy.
     * Promote removes ghost from channels (silent), sends BX P + BS T.
     * Session continues under the promoted alias's server. */
    int promoted;
    Debug((DEBUG_INFO, "Bouncer: hold expired with %d aliases, promoting for %s",
           session->hs_alias_count, session->hs_account));
    promoted = bounce_promote_alias(session, 0);
    /* Exit ghost.  FLAG_BOUNCER_INTERNAL_DESTROY is set ONLY when promote
     * actually broadcast BX P — that's the wire event legacy uses (numeric
     * swap) and IRCv3-aware peers use (membership transfer) to retire
     * the old numeric.  When promote fails (no usable winner alias,
     * etc.), no BX P went out, so we MUST allow exit_client's normal
     * Q broadcast to fire so peers (legacy and IRCv3-aware alike) can
     * clean up the held-ghost phantom.
     *
     * Use the bouncer-internal-destroy flag rather than FLAG_KILLED:
     * this is internal cleanup, not a network KILL, and per invariant
     * #12 a network KILL would end the entire session — which is not
     * what we want here (we're doing a successful promote-and-retire). */
    if (ghost && IsBouncerHold(ghost)) {
      ClearBouncerHold(ghost);
      if (promoted == 0)
        SetBouncerInternalDestroy(ghost);
      exit_client(ghost, ghost, &me,
                  promoted == 0 ? "Session transferred" : "Session expired");
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

/* ---------------------------------------------------------------- */
/* M4b reconciler helpers                                            */
/* ---------------------------------------------------------------- */

/** Cookie + callback for the persistence_profile_list walk used by
 * bounce_account_wants_channel.  Stops walking at the first match. */
struct wants_channel_ctx {
  const char *account;
  const char *channel;
  const char *exclude_profile;
  int found;
};

static void wants_channel_cb(const char *name, const char *parent, void *cookie)
{
  struct wants_channel_ctx *ctx = cookie;
  (void)parent;
  if (ctx->found)
    return; /* already matched; remaining iterations are no-ops */
  if (ctx->exclude_profile
      && ircd_strcmp(name, ctx->exclude_profile) == 0)
    return;
  if (persistence_profile_channels_effective_has(ctx->account, name,
                                                  ctx->channel) == 1)
    ctx->found = 1;
}

int bounce_account_wants_channel(const char *account, const char *channel,
                                  const char *exclude_profile)
{
  struct wants_channel_ctx ctx;
  char hold[METADATA_VALUE_LEN];
  int account_held;

  if (!account || !channel || !*account || !*channel)
    return 0;

  /* Non-held accounts aren't bouncer sessions — profiles are
   * irrelevant.  Return 0 so the caller falls back to normal IRC
   * semantics (no PART suppression, no /JOIN-already-member dance). */
  if (metadata_account_get(account, "draft/persistence/hold", hold) == 0)
    account_held = (hold[0] != '0');
  else
    account_held = feature_bool(FEAT_BOUNCER_DEFAULT_HOLD);
  if (!account_held)
    return 0;

  ctx.account = account;
  ctx.channel = channel;
  ctx.exclude_profile = exclude_profile;
  ctx.found = 0;
  persistence_profile_list(account, wants_channel_cb, &ctx);
  return ctx.found;
}

/** Apply a CHFL_ALIAS visibility-membership change locally for one
 * alias on one channel.  Caller is responsible for broadcasting
 * BX V to peers separately (so the same code path handles both the
 * originator and the BX V receiver).
 *
 * @param[in] alias An alias client (IsBouncerAlias).
 * @param[in] chptr Channel.
 * @param[in] add Non-zero to add CHFL_ALIAS membership; zero to remove.
 */
static void bounce_visibility_apply_local(struct Client *alias,
                                           struct Channel *chptr,
                                           int add)
{
  struct Membership *primary_mem;
  struct Client *primary;

  if (!alias || !chptr)
    return;
  if (!IsBouncerAlias(alias))
    return;

  if (add) {
    if (find_member_link(chptr, alias))
      return; /* already a member */
    primary = cli_alias_primary(alias);
    primary_mem = primary ? find_member_link(chptr, primary) : NULL;
    {
      unsigned int aflags = CHFL_ALIAS;
      unsigned short aoplevel = MAXOPLEVEL;
      if (primary_mem) {
        aflags |= (primary_mem->status
                   & (CHFL_CHANOP | CHFL_HALFOP | CHFL_VOICE));
        aoplevel = OpLevel(primary_mem);
      }
      add_user_to_channel(chptr, alias, aflags, aoplevel);
    }
  } else {
    if (!find_member_link(chptr, alias))
      return; /* not a member; nothing to remove */
    remove_user_from_channel(alias, chptr);
  }

  /* User-facing echo on the alias's home server only — synthetic
   * JOIN or PART so the local client gets UI feedback. */
  if (MyConnect(alias) && IsUser(alias)) {
    if (add)
      sendcmdto_one_tags(alias, CMD_JOIN, alias, ":%H", chptr);
    else
      sendcmdto_one_tags(alias, CMD_PART, alias, ":%H", chptr);
  }
}

void bounce_visibility_membership(const char *alias_full,
                                   const char *channel, int add)
{
  struct Client *alias;
  struct Channel *chptr;

  if (!alias_full || !channel || !*alias_full || !*channel)
    return;

  /* Broadcast to peers first so they apply concurrently. */
  sendcmdto_serv_butone_v3(&me, CMD_BOUNCER_TRANSFER, NULL,
                        "V %s %c%s", alias_full, add ? '+' : '-', channel);

  alias = findNUser(alias_full);
  chptr = FindChannel(channel);
  if (alias && chptr)
    bounce_visibility_apply_local(alias, chptr, add);
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

/** Recover a session's hs_client from its recorded ghost numeric.
 *
 * A replica's hs_client can legitimately be NULL while hs_ghost_numeric is
 * still valid: BS C deliberately leaves the pointer NULL, and both
 * bounce_null_hs_client_pointing_at() (Client free — the primary's server
 * SQUITs and relinks, or a collision kill) and a refused
 * bounce_hs_client_assign_checked() install leave it NULL while the numeric
 * was written unconditionally.  Without this recovery the caller cannot tell
 * "primary lives elsewhere" from "no primary at all" and manufactures a
 * PARALLEL PRIMARY for a session that already has one.
 *
 * Composition risk (audit site): the numeric is built from hs_origin +
 * hs_ghost_numeric, and hs_origin can diverge from where the ghost actually
 * lives after a cross-server rebind — the hazard hard-invariant 3 warns about
 * for BS-token handlers.  This is NOT a BS-token handler (no live sender
 * exists at registration time), and the two fields stay aligned for the cases
 * that reach here: HOLDING-on-this-server has hs_origin == cli_yxx(&me) by
 * construction, HOLDING/ACTIVE-as-replica is created with hs_origin == the
 * BS C sender's prefix, matching its hs_ghost_numeric source.  A mis-composed
 * numeric therefore either fails to resolve (safe) or resolves to a client of
 * ANOTHER account, which bounce_hs_client_assign_checked refuses.  The
 * residual case — resolving a different connection of the SAME account —
 * still yields an ALIAS outcome, which is strictly better than the
 * parallel-primary this prevents.
 *
 * If you change how BS A / BS D / BS C store ghost_numeric, or add a path
 * that mutates hs_origin without updating hs_ghost_numeric, audit this
 * function and BOTH of its callers.
 *
 * @param[in,out] session Session whose hs_client may be recovered.
 * @param[in] site_label Short tag for the refusal log line.
 */
static void bounce_resolve_hs_client_from_ghost(struct BouncerSession *session,
                                                const char *site_label)
{
  char full_numeric[6];
  struct Client *candidate;

  if (!session || session->hs_client || !session->hs_ghost_numeric[0])
    return;

  ircd_snprintf(0, full_numeric, sizeof(full_numeric), "%s%s",
                session->hs_origin, session->hs_ghost_numeric);
  candidate = findNUser(full_numeric);
  bounce_hs_client_assign_checked(session, candidate, site_label);
}

/** Effective alias-admission limit: FEAT_BOUNCER_MAX_ALIASES clamped to
 * the compiled array size.  Applies ONLY to local admission decisions in
 * bounce_auto_resume — array-write guards that RECORD aliases admitted
 * elsewhere (setup_local_alias, alias_create, demote) stay on the macro,
 * because refusing to track a peer-created alias would diverge session
 * state, and the cap (<= array size) can never overflow them anyway. */
static int bounce_max_aliases(void)
{
  int v = feature_int(FEAT_BOUNCER_MAX_ALIASES);
  if (v < 0)
    v = 0;
  return (v > BOUNCER_MAX_ALIASES) ? BOUNCER_MAX_ALIASES : v;
}

/** Whether @a c is a member of @a session here that speaks for its
 * account: the primary under the session's account, or one of its aliases
 * (an alias numeric is checked against the session, as
 * bounce_sync_alias_identity checks it). */
static int bounce_member_of_account(struct BouncerSession *session,
                                    struct Client *c, int alias)
{
  if (!c || !cli_user(c) || !IsAccount(c)
      || 0 != ircd_strcmp(cli_user(c)->account, session->hs_account))
    return 0;
  if (!alias)
    return !IsBouncerAlias(c);
  return IsBouncerAlias(c) && cli_user(c)->alias_primary
         && cli_user(c)->alias_primary == session->hs_client;
}

const char *bounce_session_kc_id(struct BouncerSession *session)
{
  int i;

  if (!session)
    return "";
  if (account_id_valid(session->hs_kc_id))
    return session->hs_kc_id;
  /* A replica that has not heard BX U kcid= (an older peer): the members
   * this server knows, as their introductions carried the id. */
  if (bounce_member_of_account(session, session->hs_client, 0)
      && account_id_valid(cli_user(session->hs_client)->kc_id))
    return cli_user(session->hs_client)->kc_id;
  for (i = 0; i < session->hs_alias_count; i++) {
    struct Client *a = findNUser(session->hs_aliases[i].ba_numeric);
    if (bounce_member_of_account(session, a, 1)
        && account_id_valid(cli_user(a)->kc_id))
      return cli_user(a)->kc_id;
  }
  return "";
}

/** Tell the peers the Keycloak id a session belongs to (BX U kcid=), keyed
 * by its primary like cc= and ta=. */
static void bounce_emit_session_kc_id(struct BouncerSession *session)
{
  char full_numeric[16];
  struct Client *primary = session->hs_client;

  if (!account_id_valid(session->hs_kc_id) || !primary || !cli_user(primary)
      || !cli_user(primary)->server || !cli_yxx(primary)[0])
    return;   /* before SetLocalNumNick: the BS A after it carries it */
  ircd_snprintf(0, full_numeric, sizeof(full_numeric), "%s%s",
                cli_yxx(cli_user(primary)->server), cli_yxx(primary));
  sendcmdto_serv_butone_v3(&me, CMD_BOUNCER_TRANSFER, NULL,
                        "U %s kcid=%s", full_numeric, session->hs_kc_id);
}

/** Give the session's members here that carry no id the session's. */
static void bounce_session_fill_member_ids(struct BouncerSession *session)
{
  int i;

  if (!account_id_valid(session->hs_kc_id))
    return;
  if (bounce_member_of_account(session, session->hs_client, 0)
      && !cli_user(session->hs_client)->kc_id[0])
    ircd_strncpy(cli_user(session->hs_client)->kc_id, session->hs_kc_id,
                 sizeof(cli_user(session->hs_client)->kc_id));
  for (i = 0; i < session->hs_alias_count; i++) {
    struct Client *a = findNUser(session->hs_aliases[i].ba_numeric);
    if (bounce_member_of_account(session, a, 1) && !cli_user(a)->kc_id[0])
      ircd_strncpy(cli_user(a)->kc_id, session->hs_kc_id,
                   sizeof(cli_user(a)->kc_id));
  }
}

int bounce_account_kc_conflict(const char *account, const char *kc_id)
{
  struct AccountSessions *as = account ? bounce_find_by_account(account) : NULL;
  struct BouncerSession *s;

  for (s = as ? as->as_sessions : NULL; s; s = s->hs_anext)
    if (bounce_rebind_kc_conflict(bounce_session_kc_id(s), kc_id))
      return 1;
  return 0;
}

/** The primary of a peer's session @a sessid of @a account, introduced
 * from the direction of @a cptr (the burst sends users before sessions):
 * BS C carries no Keycloak id, its primary does.  NULL if not seen. */
static struct Client *bounce_peer_session_primary(struct Client *cptr,
                                                  const char *account,
                                                  const char *sessid)
{
  struct Client *peer;

  for (peer = GlobalClientList; peer; peer = cli_next(peer)) {
    if (IsUser(peer) && !IsBouncerAlias(peer) && IsAccount(peer)
        && cli_from(peer) == cptr
        && 0 == ircd_strcmp(cli_user(peer)->account, account)
        && 0 == strcmp(cli_session_id(peer), sessid))
      return peer;
  }
  return NULL;
}

void bounce_session_adopt_kc_id(struct BouncerSession *session, const char *id)
{
  const char *members;

  if (!session || !account_id_valid(id) || session->hs_kc_id[0])
    return;
  /* A member that already speaks for another id: never re-tied. */
  members = bounce_session_kc_id(session);
  if (members[0] && strcmp(members, id))
    return;
  log_write(LS_USER, L_INFO, 0, "Bouncer: session %s of %s adopts Keycloak id %s",
            session->hs_sessid, session->hs_account, id);
  ircd_strncpy(session->hs_kc_id, id, sizeof(session->hs_kc_id));
  bounce_session_fill_member_ids(session);
  bounce_db_put(session);
  bounce_emit_session_kc_id(session);
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
   * Explicit opt-out (draft/persistence/hold=0) is always respected, even on
   * bouncer-class ports — no session will be created or resumed.
   *
   * `draft/persistence/hold` is METADATA_VIS_PRIVATE — it doesn't propagate S2S,
   * so peer servers don't see the preference set elsewhere on the
   * network.  But the *existence* of a session for this account on
   * the local server is itself a sufficient signal: an active or held
   * session means hold was enabled by SOME server and broadcast via
   * BS C, and the design intent is "any peer holding the session can
   * route alias attaches into it."  So when we see no local metadata
   * preference, we still bypass the early-return if an account-side
   * session exists — that path then routes through the alias-attach
   * branches below. */
  if (metadata_account_get(account, "draft/persistence/hold", hold_val) == 0) {
    if (hold_val[0] == '0')
      return 0; /* User opted out */
  } else if (!class_bouncer && !feature_bool(FEAT_BOUNCER_DEFAULT_HOLD)
             && !bounce_has_sessions(account)) {
    return 0; /* No preference set, network default is no-hold,
                 and no session exists for this account. */
  }

  /* A session belongs to one Keycloak user (user, 2026-10-23: a new id
   * never attaches to an old session).  Before any path below attaches
   * this login -- a held revive, a remote or local alias, an orphan
   * reclaim -- every session of the account is checked: the previous
   * user's leftover, held here with nothing connected, ends (as
   * register_user's revive check ends it); one still in use refuses the
   * login -- registering beside it would collide, as REJECT_DUPLICATE
   * notes. */
  {
    struct AccountSessions *as;
    struct BouncerSession *s;

  recheck_kc:
    as = bounce_find_by_account(account);
    for (s = as ? as->as_sessions : NULL; s; s = s->hs_anext) {
      struct Client *stale;
      int unused;

      /* The branches below fill in a remote session's primary from its
       * ghost before attaching; read the id after the same step. */
      if (!s->hs_client || !MyConnect(s->hs_client))
        bounce_resolve_hs_client_from_ghost(s, "Keycloak-id check");
      stale = s->hs_client;
      /* Ended only by a login Keycloak itself just confirmed: a deleted
       * user's cached login or still-valid token never ends the current
       * owner's session (user, 2026-10-23). */
      unused = s->hs_state == BOUNCE_HOLDING && s->hs_alias_count == 0
               && stale && MyConnect(stale) && IsBouncerHold(stale)
               && cli_saslkcidlive(cptr);

      switch (bounce_kc_join(bounce_session_kc_id(s), cli_user(cptr)->kc_id,
                             unused)) {
      case BKJ_JOIN:
        break;
      case BKJ_END_STALE:
        log_write(LS_USER, L_INFO, 0,
                  "Bouncer: ending %s's session %s: it carries Keycloak id %s, "
                  "the login %s", account, s->hs_sessid, bounce_session_kc_id(s),
                  cli_user(cptr)->kc_id);
        bounce_kill_session(s, "Session ended: its Keycloak account was replaced");
        ClearBouncerHold(stale);
        exit_client(stale, stale, &me,
                    "Session ended: its Keycloak account was replaced");
        goto recheck_kc;   /* the session list changed */
      case BKJ_REFUSE:
        log_write(LS_USER, L_INFO, 0,
                  "Bouncer: refusing %s for %s: session %s carries Keycloak id "
                  "%s, the login %s", cli_name(cptr), account, s->hs_sessid,
                  bounce_session_kc_id(s), cli_user(cptr)->kc_id);
        *out_session = s;
        return BOUNCE_RESUME_REJECT_KC_CONFLICT;
      }
    }
  }

  /* Try to find a held session to resume */
 retry_resume:
  session = bounce_find_best_held(account);
  if (session) {
    /* Per redesign C.2: hs_origin is historical-only.  The runtime
     * "is the primary on a remote server?" question is answered by
     * checking whether hs_client (the held ghost or live primary) is
     * locally connected.  A held ghost made by bounce_create_ghost()
     * has MyConnect()==TRUE because make_client(NULL,...) allocates a
     * Connection; so this branch fires only when the session has no
     * local Client* at all (hs_client NULL or its MyConnect is false). */
    if (!session->hs_client || !MyConnect(session->hs_client)) {
      struct Client *managing_server;
      /* Resolve ghost from numeric if hs_client is NULL (e.g., BS D
       * arrived before ghost numeric was resolvable) — see
       * bounce_resolve_hs_client_from_ghost for the composition-risk
       * audit note. */
      bounce_resolve_hs_client_from_ghost(session, "HELD resume");
      /* The server holding the session is its primary's: the origin the
       * record noted goes stale (a rebind keeps it, a merge moves it). */
      managing_server = bounce_primary_server(session);
      if (managing_server && session->hs_client
          && session->hs_alias_count < bounce_max_aliases()) {
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
      /* Nothing anywhere we can reach holds this record: no local
       * holder, no client, no ghost numeric to resolve.  It is garbage
       * (a replica that outlived its holder), and leaving it would
       * block this login twice over -- no alias path, and the create
       * gate below counts it as the account's session.  Drop it and
       * look again; a peer that really holds the session re-announces
       * it and convergence sorts the two out by state. */
      if (!session_has_local_holder(session) && !session->hs_client
          && !session->hs_ghost_numeric[0]
          && session->hs_alias_count == 0) {
        log_write(LS_USER, L_INFO, 0,
                  "Bouncer: discarding unattachable replica %s for %s",
                  session->hs_sessid, account);
        bounce_destroy(session);
        goto retry_resume;
      }
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
    /* Per redesign C.2: hs_origin is historical-only.  Use runtime
     * Client locality — primary is "remote" iff hs_client lives on
     * another server (or is NULL). */
    if (!session->hs_client || !MyConnect(session->hs_client)) {
      struct Client *managing_server;
      /* Same recovery the HELD branch does.  Without it an ACTIVE session
       * whose hs_client went NULL (primary's server SQUIT+relink, collision
       * kill, or a refused BS A install) fell straight through to the
       * orphan-reclaim below and made this connection a SECOND primary for a
       * session that still has one elsewhere — the identical failure shape as
       * the pre-e9b3b34 attach bug, reached by a different route. */
      bounce_resolve_hs_client_from_ghost(session, "ACTIVE resume");
      /* Where the primary is, as in the HELD branch.  A stale origin
       * naming a server no longer linked sent a session with a live
       * remote primary down the local-alias path below. */
      managing_server = bounce_primary_server(session);
      if (managing_server && session->hs_client
          && session->hs_alias_count < bounce_max_aliases()) {
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
      if (session->hs_alias_count < bounce_max_aliases()) {
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
    /* Steady-state BS C race guard: if a link that can carry a BS C (an
     * IRCv3-aware one; see bounce_peer_has_inbound_data) has unread
     * inbound bytes, the in-flight data might carry a BS C announcing the
     * very session for this account.  Creating a fresh local session
     * now would race ahead and produce a parallel primary, which
     * downstream resolves via classic-collision kills.  Defer the
     * decision; bounce_drain_pending_registrations re-runs us once
     * the peer data has been processed (the BS C handler triggers
     * the drain). */
    {
      struct Client *link = bounce_peer_has_inbound_data();
      if (link) {
        log_write(LS_USER, L_INFO, 0,
                  "Bouncer: deferring the registration of %s (%s): the account "
                  "has no session yet, and the link to %s has unread bytes "
                  "that may carry its BS C",
                  cli_name(cptr), account, cli_name(link));
        return BOUNCE_RESUME_DEFER_PEER_INBOUND;
      }
    }
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
  if (cli_user(cptr) && account_id_valid(cli_user(cptr)->kc_id))
    ircd_strncpy(session->hs_kc_id, cli_user(cptr)->kc_id, sizeof(session->hs_kc_id));
  /* Adopt the Client's pre-existing sessid (minted at make_client) so
   * cli_session_id and hs_sessid agree.  Defensive mint if the Client
   * came via a path that didn't populate cli_session_id. */
  if (cli_session_id(cptr)[0])
    ircd_strncpy(session->hs_sessid, cli_session_id(cptr), BOUNCER_SESSID_LEN);
  else {
    generate_sessid(session->hs_sessid);
    presence_purge_session(cli_session_id(cptr));
    ircd_strncpy(cli_session_id(cptr), session->hs_sessid, S2S_SESSID_BUFSIZE);
  }
  generate_token(session->hs_token);
  session->hs_name[0] = '\0';
  session->hs_state = BOUNCE_ACTIVE;
  session->hs_client = cptr;
  ircd_strncpy(session->hs_origin, cli_yxx(&me), sizeof(session->hs_origin));
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
  session->hs_attach_time = CurrentTime;

  /* Add to hash tables */
  token_hash_add(session);
  as = account_sessions_get(session->hs_account, 1);
  account_add_session(as, session);

  /* Record initial connect event in connection history */
  bounce_history_connect(session, cli_sock_ip(cptr), cli_sockhost(cptr));

  /* Phase 3 hs_enforced: when a CRFLAG_BOUNCER class creates this
   * session, mark it enforced — the user can't DETACH it while a
   * class-enforced connection holds it open. */
  {
    struct ConnectionClass *cls = get_client_class_conf(cptr);
    if (cls && FlagHas(&cls->restrictflags, CRFLAG_BOUNCER))
      session->hs_enforced = 1;
  }

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

/** Prune alias entries whose ba_numeric no longer resolves to a Client.
 *
 * Stale alias entries accumulate when:
 *   - A peer restarts and rejoins with new numeric pool: the OLD numeric
 *     tracked in hs_aliases never gets a BX X (peer doesn't know the old
 *     numeric anymore) so the entry persists.
 *   - SQUIT cleanup misses an entry (rare but possible).
 *   - Restored from DB and the recorded numeric isn't valid post-restart.
 *
 * Called from end-of-burst to validate the alias list against the
 * post-burst nick hash.  After the peer's burst completes any aliases
 * the peer claims are in the hash; any entry we hold whose numeric
 * isn't there is stale and gets dropped.
 */
void bounce_prune_stale_aliases(void)
{
  int h;
  struct AccountSessions *as;
  struct BouncerSession *s;

  for (h = 0; h < BOUNCE_ACCOUNT_HASHSIZE; h++) {
    for (as = accountHash[h]; as; as = as->as_hnext) {
      for (s = as->as_sessions; s; s = s->hs_anext) {
        int i = 0;
        while (i < s->hs_alias_count) {
          struct Client *cli =
              findNUser(s->hs_aliases[i].ba_numeric);
          if (!cli || !IsUser(cli) || !IsBouncerAlias(cli)
              || !cli_user(cli)
              || 0 != ircd_strcmp(cli_user(cli)->account, s->hs_account)) {
            Debug((DEBUG_INFO,
                   "Bouncer: pruning stale alias %s on %s (account %s, "
                   "session %s) — no matching live alias Client",
                   s->hs_aliases[i].ba_numeric,
                   s->hs_aliases[i].ba_server,
                   s->hs_account, s->hs_sessid));
            if (i < s->hs_alias_count - 1)
              memmove(&s->hs_aliases[i], &s->hs_aliases[i + 1],
                      (s->hs_alias_count - 1 - i)
                      * sizeof(struct BounceAlias));
            s->hs_alias_count--;
            /* don't advance i — shifted entry now at i */
          } else {
            i++;
          }
        }
      }
    }
  }
}

/** The session @a c is the primary of, as bounce_session_of_primary()
 * finds it, and whether more than one session claims @a c as its primary.
 * Without an hs_client match it returns the FIRST session listing @a c on
 * its alias roster: a caller acts on the result as @a c's own session
 * only when its hs_client is @a c.
 *
 * @param[in]  c          The client.
 * @param[out] ambiguous  Set to 1 when two or more sessions name @a c as
 *                        their hs_client (the result is then NULL), else 0.
 * @return The session, or NULL.
 */
static struct BouncerSession *session_of_primary(struct Client *c,
                                                 int *ambiguous)
{
  struct AccountSessions *as;
  struct BouncerSession *s, *primary_of = NULL, *roster_of = NULL;
  int claims = 0;
  char full[6];

  *ambiguous = 0;
  if (!c || !IsAccount(c) || !cli_user(c))
    return NULL;
  as = bounce_find_by_account(cli_account(c));
  if (!as)
    return NULL;
  full[0] = '\0';
  if (cli_user(c)->server)
    ircd_snprintf(0, full, sizeof(full), "%s%s",
                  cli_yxx(cli_user(c)->server), cli_yxx(c));

  for (s = as->as_sessions; s; s = s->hs_anext) {
    int i;
    if (s->hs_client == c) {
      if (!primary_of)
        primary_of = s;
      claims++;
      continue;
    }
    if (roster_of || !full[0])
      continue;
    for (i = 0; i < s->hs_alias_count; i++)
      if (0 == strcmp(s->hs_aliases[i].ba_numeric, full)) {
        roster_of = s;
        break;
      }
  }

  if (claims > 1) {
    Debug((DEBUG_INFO, "bounce_session_of_primary: %d sessions of %s name "
           "%s (%s) as their primary; none chosen", claims, cli_account(c),
           cli_name(c), full));
    *ambiguous = 1;
    return NULL;
  }
  return primary_of ? primary_of : roster_of;
}

/** Does @a s list @a c on its alias roster (by its full numeric)? */
static int session_roster_has(struct BouncerSession *s, struct Client *c)
{
  char full[6];
  int i;

  if (!s || !c || !cli_user(c) || !cli_user(c)->server)
    return 0;
  ircd_snprintf(0, full, sizeof(full), "%s%s",
                cli_yxx(cli_user(c)->server), cli_yxx(c));
  for (i = 0; i < s->hs_alias_count; i++)
    if (0 == strcmp(s->hs_aliases[i].ba_numeric, full))
      return 1;
  return 0;
}

/** Drop every entry of @a s's alias roster that names @a c. */
static void session_roster_drop(struct BouncerSession *s, struct Client *c)
{
  int k;

  if (!s || !c)
    return;
  for (k = 0; k < s->hs_alias_count; ) {
    if (findNUser(s->hs_aliases[k].ba_numeric) == c) {
      if (k < s->hs_alias_count - 1)
        memmove(&s->hs_aliases[k], &s->hs_aliases[k + 1],
                (s->hs_alias_count - 1 - k) * sizeof(struct BounceAlias));
      s->hs_alias_count--;
    } else {
      k++;
    }
  }
}

/** Note that @a server announced @a s "holding" in a BS C that came over
 * @a link (struct BouncerSession hs_peer_holding). */
static void bounce_peer_holding_note(struct BouncerSession *s,
                                     struct Client *server, struct Client *link)
{
  if (!s || !server || !link || !cli_serv(link))
    return;
  ircd_strncpy(s->hs_peer_holding, cli_yxx(server), sizeof(s->hs_peer_holding));
  s->hs_peer_holding_serial = cli_serv(link)->link_serial;
}

/** @a server announced @a s otherwise than holding: forget its "holding". */
static void bounce_peer_holding_clear(struct BouncerSession *s,
                                      struct Client *server)
{
  if (s && server && s->hs_peer_holding[0]
      && 0 == strcmp(s->hs_peer_holding, cli_yxx(server)))
    s->hs_peer_holding[0] = '\0';
}

/** Is @a c, a client of another server, that server's held copy of @a s:
 * did its server announce the session "holding", over the link @a c is
 * behind as it is established now? */
static int bounce_peer_holds(struct BouncerSession *s, struct Client *c)
{
  struct Client *link;

  if (!s || !c || !s->hs_peer_holding[0] || MyConnect(c) || !cli_user(c)
      || !cli_user(c)->server)
    return 0;
  link = cli_from(c);
  return 0 == strcmp(s->hs_peer_holding, cli_yxx(cli_user(c)->server))
         && link && cli_serv(link)
         && cli_serv(link)->link_serial == s->hs_peer_holding_serial;
}

/** Note that @a server announced @a s under @a sessid, which ours beat
 * (struct BouncerSession hs_peer_sessid): it takes our id, and its
 * clients keep @a sessid on our side. */
static void bounce_peer_sessid_note(struct BouncerSession *s, const char *sessid,
                                    struct Client *server)
{
  if (!s || !sessid || !*sessid || !server || 0 == strcmp(sessid, s->hs_sessid))
    return;
  ircd_strncpy(s->hs_peer_sessid, sessid, sizeof(s->hs_peer_sessid));
  ircd_strncpy(s->hs_peer_sessid_server, cli_yxx(server),
               sizeof(s->hs_peer_sessid_server));
}

/** Is @a c in session @a s by its session id: the record's own, or, for a
 * client of the server that announced the session under another id
 * before taking ours, that id (hs_peer_sessid)? */
static int bounce_in_session_by_id(struct BouncerSession *s, struct Client *c)
{
  if (!s || !c || !cli_session_id(c)[0])
    return 0;
  if (0 == strcmp(cli_session_id(c), s->hs_sessid))
    return 1;
  return s->hs_peer_sessid[0]
         && 0 == strcmp(cli_session_id(c), s->hs_peer_sessid)
         && cli_user(c) && cli_user(c)->server
         && 0 == strcmp(cli_yxx(cli_user(c)->server), s->hs_peer_sessid_server);
}

/** Is the server @a yy announced is @a victim or behind it, or no longer
 * known at all? */
static int server_leaves_with(const char *yy, struct Client *victim)
{
  struct Client *s = (yy && *yy) ? FindNServer(yy) : NULL;

  if (!s)
    return 1;
  for (; s && IsServer(s); s = cli_serv(s)->up)
    if (s == victim)
      return 1;
  return 0;
}

/** See include/bouncer_session.h. */
void bounce_peer_sessid_clear_for_server(struct Client *victim)
{
  int i;
  struct BouncerSession *s;

  for (i = 0; i < BOUNCE_TOKEN_HASHSIZE; i++)
    for (s = tokenHash[i]; s; s = s->hs_tnext)
      if (s->hs_peer_sessid[0]
          && server_leaves_with(s->hs_peer_sessid_server, victim))
        s->hs_peer_sessid[0] = '\0';
}

/** Our record @a s takes the session id @a sessid: the id it is persisted
 * under, the mark that left @a sessid unmirrored, and the id every
 * connection the record names carries (its primary and its aliases). */
static void bounce_session_take_id(struct BouncerSession *s, const char *sessid)
{
  struct Client *c;
  int ai;

  if (!s || !sessid || !*sessid || 0 == strcmp(s->hs_sessid, sessid))
    return;
  bounce_db_del(s->hs_sessid);
  ircd_strncpy(s->hs_sessid, sessid, sizeof(s->hs_sessid));
  unmirrored_clear(s->hs_account, sessid);
  if (s->hs_peer_sessid[0] && 0 == strcmp(s->hs_peer_sessid, sessid))
    s->hs_peer_sessid[0] = '\0';
  c = s->hs_client;
  if (c && IsUser(c) && 0 != strcmp(cli_session_id(c), sessid)) {
    presence_purge_session(cli_session_id(c));
    ircd_strncpy(cli_session_id(c), sessid, S2S_SESSID_BUFSIZE);
  }
  for (ai = 0; ai < s->hs_alias_count; ai++) {
    c = findNUser(s->hs_aliases[ai].ba_numeric);
    if (c && IsUser(c) && 0 != strcmp(cli_session_id(c), sessid)) {
      presence_purge_session(cli_session_id(c));
      ircd_strncpy(cli_session_id(c), sessid, S2S_SESSID_BUFSIZE);
    }
  }
  /* Re-persisted under the new id if we still hold it here. */
  if (session_has_local_holder(s))
    bounce_db_put(s);
}

/** See include/bouncer_session.h. */
struct BouncerSession *bounce_session_of_primary(struct Client *c)
{
  int ambiguous;
  return session_of_primary(c, &ambiguous);
}

/** See include/bouncer_session.h. */
int bounce_session_has_live_alias(struct BouncerSession *s)
{
  int i;

  /* The aliases bounce_kill_session would exit: those it finds. */
  if (s)
    for (i = 0; i < s->hs_alias_count; i++)
      if (findNUser(s->hs_aliases[i].ba_numeric))
        return 1;
  return 0;
}

/** See include/bouncer_session.h. */
int bounce_session_held(struct BouncerSession *s, struct Client *c)
{
  return c && IsBouncerHold(c) && !bounce_session_has_live_alias(s);
}

/** Held as the verdict and the hold mark read it, from the object @a s
 * a lookup returned and whether that lookup was ambiguous. */
static int nick_side_held_in(struct BouncerSession *s, int ambiguous,
                             struct Client *c)
{
  /* Two sessions name the client as their primary: no one session to
   * end, so it is not read as held (nor, having no one session, as a
   * primary): every verdict then leaves it to the classic rules or
   * keeps it, and never ends or demotes a session for it. */
  if (ambiguous)
    return 0;
  return bounce_session_held(s, c);
}

/** See include/bouncer_session.h. */
struct BouncerSession *bounce_nick_side_lookup(struct Client *c, int *held,
                                               int *primary)
{
  int ambiguous;
  struct BouncerSession *s = session_of_primary(c, &ambiguous);

  if (held)
    *held = nick_side_held_in(s, ambiguous, c);
  if (primary)
    *primary = s && s->hs_client == c;
  return s;
}

/** See include/bouncer_session.h. */
int bounce_nick_side_held(struct Client *cptr)
{
  int held;
  bounce_nick_side_lookup(cptr, &held, NULL);
  return held;
}

/** Post-burst reconcile: detect multi-primary-same-session states and
 * merge them by demoting the newer primary to an alias of the older.
 *
 * Triggered after a peer's EB so all of the peer's N tokens are in the
 * client hash and cli_session_id values from ,S compact tags have been
 * adopted.  Both sides run the same algorithm on the same inputs →
 * deterministic convergence; no coordination protocol needed.
 *
 * Scope: only acts on local primaries (hs_client where MyConnect is
 * true).  Cross-side demote is handled by the peer's own symmetric run.
 *
 * Same-session test: a candidate co-primary's cli_session_id must
 * match the local session's hs_sessid.  This is set on remote clients
 * from the N message's ,S compact tag (bouncer-aware peer's emit-side
 * runs bounce_set_n_sessid_hint), so a remote primary belonging to
 * the same bouncer session has the same sessid; a non-bouncer
 * account-bearing client minted its own sessid and won't match —
 * legitimately independent presences are left alone.  Two sessions of
 * one account made on either side of a split converge on the lower id at
 * BS C, after their primaries' N: the side whose id won still sees the
 * other side's primary under the id that side had, which it noted
 * (hs_peer_sessid), and that matches too -- else only the side that took
 * the other's id could find the merge, and the two live primaries would
 * stay when the merge is its peer's to make.  Only a candidate
 * the demote would accept counts (bounce_demote_eligibility): above all,
 * its home server must be IRCv3-aware, as a legacy home has no sessions
 * and never runs this pass.
 *
 * Who keeps the primary slot: bounce_nick_verdict(), the verdict the
 * same-nick merge in m_nick.c reaches at N time (for two live session
 * primaries, the older cli_lastnick, then the lower full numeric).
 */
void bounce_post_burst_reconcile(void)
{
  int h;
  struct AccountSessions *as;
  struct BouncerSession *s, *next_s;
  struct Client *acptr, *peer_primary;
  struct Client *local_primary;
  int multiple_candidates;

  /* Burst-settle for restored holds: this is where BX R's clear used
   * to live before its Phase 5 retirement.  Once no burst is in
   * flight, a restored session no live peer claimed during the burst
   * is firm -- it must stop counting as convergence-pending, or the
   * NEXT link's burst gets gated the full 30s fallback too. */
  if (!bounce_burst_in_progress()) {
    int cleared = 0;
    for (h = 0; h < BOUNCE_ACCOUNT_HASHSIZE; h++)
      for (as = accountHash[h]; as; as = as->as_hnext)
        for (s = as->as_sessions; s; s = s->hs_anext)
          if (s->hs_restore_pending) {
            s->hs_restore_pending = 0;
            cleared++;
          }
    if (cleared)
      bounce_release_idle_gates();
  }

  for (h = 0; h < BOUNCE_ACCOUNT_HASHSIZE; h++) {
    for (as = accountHash[h]; as; as = as->as_hnext) {
      for (s = as->as_sessions; s; s = next_s) {
        next_s = s->hs_anext;

        if (!s->hs_client || !MyConnect(s->hs_client)
            || IsBouncerAlias(s->hs_client) || !IsUser(s->hs_client))
          continue;
        local_primary = s->hs_client;

        /* Walk the client list for a co-session primary candidate.
         * Match rule: same account, in our session by its session id
         * (bounce_in_session_by_id: ours, or the id its server announced
         * the session under before taking ours), IsUser, !IsBouncerAlias,
         * !IsBouncerHold, not ourselves. */
        peer_primary = NULL;
        multiple_candidates = 0;
        for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr)) {
          if (acptr == local_primary) continue;
          if (!IsUser(acptr) || !IsAccount(acptr)) continue;
          if (IsBouncerAlias(acptr) || IsBouncerHold(acptr)) continue;
          if (0 != ircd_strcmp(cli_account(acptr), s->hs_account)) continue;
          if (!bounce_in_session_by_id(s, acptr)) continue;
          /* Only a candidate our primary could be demoted into counts:
           * the demote's own decision.  A different Keycloak user is
           * never merged in (user, 2026-10-23: sessions of different ids
           * stay apart after a split; the peer reads our ids the same
           * way).  And a candidate homed on a legacy server is never
           * merged in, as D.2 skips a legacy introducer (m_nick.c): a
           * legacy home never runs the symmetric pass, so the "we win"
           * side would wait for a demote that never comes, and "we lose"
           * would hand the session to a client that is not in it.  Its
           * session id proves nothing either: a legacy server sends
           * none, and the one it carries was stamped by whichever fork
           * server relayed its N. */
          if (demote_eligibility_for(BOUNCE_DEMOTE_PLAN, local_primary, s,
                                     acptr) != BOUNCE_DEMOTE_OK)
            continue;
          if (peer_primary) {
            multiple_candidates = 1;
            break;
          }
          peer_primary = acptr;
        }

        if (multiple_candidates) {
          Debug((DEBUG_INFO,
                 "bounce_post_burst_reconcile: multiple co-session "
                 "primaries for session %s account %s — ambiguous, "
                 "skipping merge",
                 s->hs_sessid, s->hs_account));
          continue;
        }
        if (!peer_primary)
          continue;

        /* Who keeps the primary slot: the verdict both ends compute from
         * the same facts.  The candidate carries our session id, so it is
         * no outsider; a different Keycloak user never passed the
         * candidate test above; and this pass runs after a burst, never
         * for a gated link.  A held ghost of ours never gets here (the
         * candidate test refuses a held face), and the verdict would
         * leave it alone too: classic.  Ours is read held from s, the
         * session the demote acts on.
         *
         * The candidate is held when its server announced this session
         * "holding" (BS C): its copy of the session yields to ours there,
         * our live primary taking its place, so ours is never demoted
         * into it -- live beats held.  That is what a held ghost with a
         * live alias is too: it carries a "p" hold mark (read live at a
         * same-nick meeting), yet the yield ends it.  A hold flag is our
         * own and a remote client never shows one.  Otherwise its state is
         * not known here. */
        {
          struct bounce_nick_side ours, theirs;
          char our_full[6], their_full[6];
          int peer_holds = bounce_peer_holds(s, peer_primary);
          enum bounce_nick_verdict verdict;

          ircd_snprintf(0, our_full, sizeof(our_full), "%s%s",
                        cli_yxx(cli_user(local_primary)->server),
                        cli_yxx(local_primary));
          ircd_snprintf(0, their_full, sizeof(their_full), "%s%s",
                        cli_yxx(cli_user(peer_primary)->server),
                        cli_yxx(peer_primary));
          memset(&ours, 0, sizeof ours);
          ours.held        = bounce_session_held(s, local_primary);
          ours.state_known = 1;
          ours.lastnick    = cli_lastnick(local_primary);
          ours.sessid      = s->hs_sessid;
          ours.numeric     = our_full;
          memset(&theirs, 0, sizeof theirs);
          theirs.state_known = peer_holds;
          theirs.held        = peer_holds;
          theirs.non_member  = 0;
          theirs.lastnick    = cli_lastnick(peer_primary);
          theirs.sessid      = cli_session_id(peer_primary);
          theirs.numeric     = their_full;

          verdict = bounce_nick_verdict(&ours, &theirs,
                                        s->hs_client == local_primary,
                                        0 /* kc_conflict */,
                                        0 /* link_gated */);
          if (peer_holds)
            log_write(LS_USER, L_INFO, 0,
                      "Bouncer post-burst reconcile: %s (ours, %s) and %s "
                      "of %s, which holds %s's session %s: %s",
                      our_full, ours.held ? "held" : "live", their_full,
                      cli_name(cli_user(peer_primary)->server), s->hs_account,
                      s->hs_sessid, bounce_nick_verdict_name(verdict));
          if (verdict == BNV_DEMOTE_LOCAL) {
            struct bounce_transition_params p;
            memset(&p, 0, sizeof p);
            p.demoted_alias = local_primary;
            p.peer_primary  = peer_primary;
            if (0 == bounce_session_transition(s, BST_DEMOTE_TO_ALIAS, &p)) {
              sendto_opmask_butone(0, SNO_OLDSNO,
                "Bouncer post-burst reconcile: demoted local primary "
                "%C to alias of %C (account %s, session %s)",
                local_primary, peer_primary,
                s->hs_account, s->hs_sessid);
            }
            /* local_primary is now an alias; session struct may have
             * moved or its hs_client changed.  Refresh next_s defensively. */
            next_s = s->hs_anext;
          }
          /* Otherwise we keep (the peer reaches the symmetric verdict and
           * demotes on its end, or its held copy yields at BS C) or
           * nothing merges.  No local action. */
        }
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

  /* Active client attach — clear restore-pending so any incoming
   * BX R sees us as firm. */
  session->hs_restore_pending = 0;

  /* Convergence-completion event: any peer that was waiting on a
   * pending-restore session can release its gate now. */
  bounce_release_idle_gates();

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
  /* Session-identity continuity follows the bouncer session, not the
   * underlying socket: the freshly-minted cli_session_id from
   * make_client is superseded by the bouncer's durable sessid. */
  presence_purge_session(cli_session_id(cptr));
  ircd_strncpy(cli_session_id(cptr), session->hs_sessid, S2S_SESSID_BUFSIZE);
  session->hs_attach_count++;
  session->hs_connect_count++;
  session->hs_last_active = CurrentTime;
  session->hs_attach_time = CurrentTime;
  session->hs_disconnect_time = 0;
  bounce_emit_connect_count(session);
  /* The session's Keycloak id: adopted from this login when it had none
   * (the transition), else given to this connection when it carries none.
   * A different one never attaches (bounce_auto_resume's gate). */
  if (cli_user(cptr) && account_id_valid(cli_user(cptr)->kc_id))
    bounce_session_adopt_kc_id(session, cli_user(cptr)->kc_id);
  bounce_session_fill_member_ids(session);

  /* Record connect event in connection history */
  bounce_history_connect(session, cli_sock_ip(cptr), cli_sockhost(cptr));

  /* Session is live again — remove persisted state (re-persisted at next hold or shutdown) */
  bounce_db_del(session->hs_sessid);

  /* Recompute session union caps for the new primary + existing aliases */
  bounce_recompute_session_caps(cptr);

  /* Membership changed (HOLDING ghost replaced by live primary) — refresh
   * effective away so any prior auto-away or stale aggregate clears. */
  bounce_recompute_session_away(session);

  return 0;
}

/** Compute adaptive hold time for a session based on usage history.
 * Sessions with more connections (resumes + alias attaches) earn longer
 * hold times.  This rewards active use — a mobile device connecting as an
 * alias counts the same as a full resume from HOLDING.
 */
/** The hold a session has earned, before idle decay: base, plus a
 * quarter of base per connection, plus an hour per 24 h attached, capped
 * at BOUNCER_MAX_HOLD.  A session that never connected gets base. */
static time_t bounce_hold_earned(struct BouncerSession *session)
{
  time_t base = feature_int(FEAT_BOUNCER_SESSION_HOLD);  /* default 4h */
  time_t max  = feature_int(FEAT_BOUNCER_MAX_HOLD);      /* default 14d */
  time_t computed;

  if (session->hs_connect_count == 0)
    return base;

  computed = base + (base * session->hs_connect_count / 4);

  if (session->hs_total_active > 0)
    computed += (session->hs_total_active / 86400) * 3600;

  return (computed > max) ? max : computed;
}

/** The hold a holding session gets, after idle decay (spec: the
 * adaptive hold, "Idle decay").  After BOUNCER_HOLD_DECAY_PERCENT of the
 * earned hold has passed idle, the part that remained at that point
 * halves for every further quarter of the earned hold spent idle; the
 * total never drops below base.  Before the grace point, or with decay
 * off, this is the earned hold.  For an active session it is what the
 * session would get if it were held now. */
static time_t bounce_compute_hold_time(struct BouncerSession *session)
{
  time_t base = feature_int(FEAT_BOUNCER_SESSION_HOLD);
  time_t earned = bounce_hold_earned(session);
  int decay_pct = feature_int(FEAT_BOUNCER_HOLD_DECAY_PERCENT);

  if (decay_pct > 0 && session->hs_state == BOUNCE_HOLDING
      && session->hs_disconnect_time > 0) {
    time_t idle = CurrentTime - session->hs_disconnect_time;
    time_t decay_start = earned * decay_pct / 100;
    time_t decay_unit = earned / 4;
    if (idle > decay_start && decay_unit > 0) {
      time_t remaining = earned - decay_start;
      time_t halvings = (idle - decay_start) / decay_unit;
      time_t computed;
      while (halvings-- > 0 && remaining > 0)
        remaining /= 2;
      computed = decay_start + remaining;
      return computed < base ? base : computed;
    }
  }
  return earned;
}

/** Seconds until a holding session expires, by the decayed hold; 0 when
 * it is not holding or is overdue.  The single source for the timer,
 * BOUNCER LIST/INFO and /CHECK, so they cannot disagree. */
time_t bounce_hold_remaining(struct BouncerSession *session)
{
  time_t deadline;

  if (session->hs_state != BOUNCE_HOLDING || session->hs_disconnect_time <= 0)
    return 0;
  deadline = session->hs_disconnect_time + bounce_compute_hold_time(session);
  return deadline > CurrentTime ? deadline - CurrentTime : 0;
}

/** Add the stretch since the primary got its socket to the session's
 * active time.  Called at hold; the DB save adds the open stretch
 * without closing it. */
static void bounce_accrue_active(struct BouncerSession *session)
{
  if (session->hs_attach_time > 0 && CurrentTime > session->hs_attach_time)
    session->hs_total_active += CurrentTime - session->hs_attach_time;
  session->hs_attach_time = 0;
}

/** Arm (or re-arm, from inside bounce_hold_expire) the hold timer.  With
 * decay on, the hold shrinks while the session sits idle, so the timer
 * fires at the next point the decayed hold can change -- the grace
 * point, then each decay-unit boundary -- and bounce_hold_expire()
 * re-evaluates; without decay it fires at the deadline.  min_delay
 * bounds how soon (restore gives a settling period). */
static void bounce_arm_hold_timer(struct BouncerSession *session, time_t min_delay)
{
  time_t remaining = bounce_hold_remaining(session);
  time_t delay = remaining;
  int decay_pct = feature_int(FEAT_BOUNCER_HOLD_DECAY_PERCENT);

  if (decay_pct > 0 && remaining > 0 && session->hs_disconnect_time > 0) {
    time_t earned = bounce_hold_earned(session);
    time_t idle = CurrentTime - session->hs_disconnect_time;
    time_t decay_start = earned * decay_pct / 100;
    time_t decay_unit = earned / 4;
    time_t next;
    if (idle < decay_start)
      next = decay_start - idle;
    else if (decay_unit > 0)
      next = decay_unit - ((idle - decay_start) % decay_unit);
    else
      next = remaining;
    if (next < delay)
      delay = next;
  }
  if (delay < min_delay)
    delay = min_delay;
  if (delay < 1)
    delay = 1;

  if (!t_active(&session->hs_hold_timer))
    timer_init(&session->hs_hold_timer);
  timer_add(&session->hs_hold_timer, bounce_hold_expire,
            (void *)session, TT_RELATIVE, delay);
}

/** Public wrapper for adaptive hold time computation. */
time_t bounce_compute_hold_time_ext(struct BouncerSession *session)
{
  return bounce_compute_hold_time(session);
}


/** Destroy a session entirely. */
void bounce_destroy(struct BouncerSession *session)
{
  assert(0 != session);

  /* Cancel timers if active */
  if (t_active(&session->hs_hold_timer))
    timer_del(&session->hs_hold_timer);
  if (t_active(&session->hs_promote_timer))
    timer_del(&session->hs_promote_timer);

  /* Remove from hash tables */
  token_hash_remove(session);
  account_remove_session(session);

  /* Remove persisted state */
  bounce_db_del(session->hs_sessid);

  Debug((DEBUG_INFO, "Bouncer: destroyed session %s for %s",
         session->hs_sessid, session->hs_account));

  MyFree(session);
}

/** A local connection of an ended session that carries on: its own
 * session id from now on, unless it already has one. */
static void bounce_give_own_sessid(struct Client *c, const char *ended)
{
  if (!c || !MyUser(c) || IsBouncerAlias(c) || !ended[0]
      || 0 != strcmp(cli_session_id(c), ended))
    return;
  presence_purge_session(cli_session_id(c));
  generate_sessid(cli_session_id(c));
  Debug((DEBUG_INFO, "Bouncer: %s left session %s; its own id is %s",
         cli_name(c), ended, cli_session_id(c)));
}

/** See include/bouncer_session.h. */
void bounce_end_session_keep_clients(struct BouncerSession *session,
                                     struct Client *caller)
{
  struct Client *primary;
  char ended[BOUNCER_SESSID_LEN];

  if (!session)
    return;
  primary = session->hs_client;
  ircd_strncpy(ended, session->hs_sessid, sizeof(ended));

  /* Detach the primary before the destroy so exit_one_client does not
   * operate on a destroyed session later. */
  session->hs_client = NULL;
  bounce_broadcast(session, 'X', NULL);
  bounce_destroy(session);

  /* The id stays with the ended session: kept, it is stamped on the next
   * N of a client in no session (the hint's fallback is the client's own
   * id), which a peer reads as membership.  PM history keyed by the old
   * id still names the account's holder of the nick; presence of a
   * logged-in client is kept by account. */
  bounce_give_own_sessid(primary, ended);
  if (caller != primary)
    bounce_give_own_sessid(caller, ended);
}

/** Force-destroy a session due to a network KILL (invariant #12).
 *
 * Terminates every alias of the session, broadcasts BX X to clear
 * peer state, and destroys the BouncerSession.  The primary's own
 * exit is handled by the caller (m_kill → exit_client_msg); this
 * helper just cleans up the rest of the session's connections and
 * state so the caller's subsequent exit_one_client lookup misses
 * cleanly (hs_client cleared, session freed).
 *
 * Used by m_kill.c::do_kill() in the local-cptr-local-victim case
 * where FLAG_KILLED isn't set on the victim (no S2S relay), so the
 * usual FLAG_KILLED-gated cleanup in exit_one_client can't tell the
 * exit is a KILL.  In every other KILL path (S2S-relayed KILL, or
 * local oper killing a remote user) FLAG_KILLED IS set and the
 * existing cleanup handles destroy — this helper is the gap-fill.
 *
 * @param session The session being killed.  Caller's primary
 *                Client must be `session->hs_client` (asserted).
 * @param comment KILL reason to propagate as the exit message for
 *                aliases; defaults to "Session killed" when NULL.
 */
void bounce_kill_session(struct BouncerSession *session, const char *comment)
{
  int i;

  assert(0 != session);

  Debug((DEBUG_INFO, "Bouncer: kill-destroy session %s for %s (aliases=%d)",
         session->hs_sessid, session->hs_account, session->hs_alias_count));

  /* Exit every alias.  Iterate top-down so the array compaction
   * inside bounce_remove_alias (driven by exit_client → exit_one_client
   * → bouncer cleanup) doesn't shift entries we haven't visited yet. */
  if (session->hs_alias_count > 0) {
    for (i = session->hs_alias_count - 1; i >= 0; i--) {
      struct Client *alias = findNUser(session->hs_aliases[i].ba_numeric);
      /* Only aliases, and never the primary: the caller exits it, and a
       * roster entry naming it would exit it twice. */
      if (alias && alias != session->hs_client && IsBouncerAlias(alias))
        exit_client(alias, alias, &me,
                    comment && *comment ? (char *)comment : "Session killed");
    }
  }

  /* Clear hs_client so the primary's subsequent exit_one_client pass
   * (in m_kill's exit_client_msg) sees the session as already
   * unanchored and skips its own cleanup branch. */
  session->hs_client = NULL;

  /* Broadcast 'X' so IRCv3-aware peers tear down their session view. */
  bounce_broadcast(session, 'X', NULL);

  bounce_destroy(session);
}

/** See include/bouncer_session.h. */
void bounce_retire_held_session(struct BouncerSession *s, struct Client *ghost,
                                struct Client *link, const char *reason)
{
  const char *why = (reason && *reason) ? reason : "Bouncer session moved";

  if (!ghost && s)
    ghost = s->hs_client;
  /* The session first: its aliases (none live, or the caller would not
   * retire it), then BS X toward the aware links.  The ghost leaves
   * after, with BX X toward the aware links and a Q toward the legacy
   * ones (exit_client), so a caller that then accepts an incoming N
   * relays it to a legacy link only after that link heard the Q. */
  if (s)
    bounce_kill_session(s, why);
  if (ghost)
    exit_client(link, ghost, &me, why);
}

/** Set a session's user-assigned name. */
void bounce_setname(struct BouncerSession *session, const char *name)
{
  assert(0 != session);
  if (name)
    ircd_strncpy(session->hs_name, name, BOUNCER_NAME_LEN);
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
                 member->channel->chname, CHANNELLEN + 1);
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

/** See include/bouncer_session.h. */
struct Client *bounce_primary_server(struct BouncerSession *session)
{
  struct Client *primary = session ? session->hs_client : NULL;

  if (!primary || !IsUser(primary) || !cli_user(primary))
    return NULL;
  return cli_user(primary)->server;
}

/* is_local_session / bounce_session_is_local retired in Phase 5.  Per
 * redesign C.2 hs_origin is historical-only metadata; behavior gates
 * use session_has_local_holder() instead. */

/** Per redesign C.2: runtime "do we hold this session?" check.
 *
 * A session is held locally when this server has any Client* for it —
 * the primary (live or held ghost), or any alias on the local server. */
int session_has_local_holder(struct BouncerSession *session)
{
  int i;
  const char *me_yxx;

  if (!session)
    return 0;

  /* Primary lives on this server (live or held ghost — both have a
   * local Connection so MyConnect() is true). */
  if (session->hs_client && MyConnect(session->hs_client))
    return 1;

  /* Any persisted alias hosted here. */
  me_yxx = cli_yxx(&me);
  for (i = 0; i < session->hs_alias_count; i++) {
    if (0 == strcmp(session->hs_aliases[i].ba_server, me_yxx))
      return 1;
  }

  return 0;
}

/** Per redesign C.2 + design intent #135 + #254: do we have any
 * locally-held bouncer sessions on this server?
 *
 * Returns non-zero iff at least one session has a local holder
 * (primary or alias).  Used by server_estab to decide whether a
 * legacy peer's burst needs to be gated for convergence — when no
 * held sessions exist, there's no risk of two faces colliding on
 * the legacy peer's wire, and the burst can run normally.
 */
int bounce_have_local_sessions(void)
{
  unsigned int i;
  struct BouncerSession *s;

  for (i = 0; i < BOUNCE_TOKEN_HASHSIZE; i++) {
    for (s = tokenHash[i]; s; s = s->hs_tnext) {
      if (session_has_local_holder(s))
        return 1;
    }
  }
  return 0;
}

/* ---------------------------------------------------------------- */
/* Session state transition funnel — invariant + dispatch            */
/* ---------------------------------------------------------------- */

/** Verify the session invariant.  Non-fatal: logs drift to LS_USER
 * and returns negative.  Returns 0 if invariant holds.
 *
 * Takes a non-const session because the heap-aliasing check below
 * defensively nulls hs_client on detected mismatch — see the -6 branch. */
int bounce_session_assert_invariant(struct BouncerSession *session,
                                    const char *site)
{
  struct Client *p;
  int i;

  if (!session) {
    log_write(LS_USER, L_WARNING, 0,
              "session_invariant[%s]: NULL session", site ? site : "?");
    return -1;
  }

  p = session->hs_client;

  /* hs_client must be NULL only mid-transition or just-destroyed.  At
   * rest, sessions in ACTIVE / HOLDING should have a Client. */
  if (!p) {
    /* Tolerated — funnel callers may pass through NULL during a
     * two-step transition.  Aliases must still be self-consistent. */
  } else {
    /* If hs_client is set, it must be a User in one of the expected
     * states for the session state. */
    if (!IsUser(p)) {
      log_write(LS_USER, L_WARNING, 0,
                "session_invariant[%s]: session %s hs_client %s is not a User",
                site ? site : "?", session->hs_sessid,
                cli_name(p) ? cli_name(p) : "?");
      return -2;
    }
    /* The canonical primary must NOT be flagged as alias.  An alias as
     * hs_client means a prior demote/promote left the wrong pointer. */
    if (IsBouncerAlias(p)) {
      log_write(LS_USER, L_WARNING, 0,
                "session_invariant[%s]: session %s hs_client %s is "
                "IsBouncerAlias (should be primary or held ghost)",
                site ? site : "?", session->hs_sessid, cli_name(p));
      return -3;
    }
    /* The pointed-to Client's account must match the session's account.
     * Mismatch indicates a heap-aliased dangling pointer: the original
     * primary was freed without sweeping hs_client, and the slot got
     * reused for a different account.  This was the observed prod-test
     * failure mode (foreign remote NICK landing in a held-ghost's heap
     * slot after burst-time yield). */
    if (!IsAccount(p)
        || 0 != ircd_strcmp(cli_account(p), session->hs_account)) {
      /* A deauthed-but-live client is NOT a recycled heap slot: the
       * account was cleared under it on purpose (webhook / AC U) while
       * hs_client still points at a perfectly valid Client.  Nulling
       * defensively in that case can leave bounce_hold_expire with a
       * NULL ghost and an immortal accountless client holding a nick.
       * Tag the two cases apart so the field can tell us which occurs.
       * See B-5 in
       * .claude/para/projects/keycloak-webhook-audit-2026-09.md */
      log_write(LS_USER, L_WARNING, 0,
                "session_invariant[%s]: session %s (account=%s) hs_client "
                "%s has account=%s — %s; nulling defensively",
                site ? site : "?", session->hs_sessid, session->hs_account,
                cli_name(p),
                IsAccount(p) ? cli_account(p) : "<none>",
                IsUser(p) && !IsAccount(p)
                  ? "LIVE-DEAUTHED live client"
                  : "heap-aliased dangling pointer");
      /* Defensive null — can't recover the right primary from here, but
       * we can at least stop pointing at the wrong Client.  Next
       * resume_check will hit the orphan-reclaim branch. */
      session->hs_client = NULL;
      return -6;
    }
    /* HOLDING state implies hs_client is a held ghost (this server). */
    if (session->hs_state == BOUNCE_HOLDING && !IsBouncerHold(p)) {
      log_write(LS_USER, L_WARNING, 0,
                "session_invariant[%s]: session %s state=HOLDING but "
                "hs_client %s !IsBouncerHold",
                site ? site : "?", session->hs_sessid, cli_name(p));
      return -4;
    }
    /* ACTIVE state implies hs_client is a live (non-held) primary. */
    if (session->hs_state == BOUNCE_ACTIVE && IsBouncerHold(p)) {
      log_write(LS_USER, L_WARNING, 0,
                "session_invariant[%s]: session %s state=ACTIVE but "
                "hs_client %s IsBouncerHold (still ghost)",
                site ? site : "?", session->hs_sessid, cli_name(p));
      return -5;
    }
  }

  /* Every alias entry must resolve to an IsBouncerAlias Client whose
   * alias_primary points at hs_client (or NULL during transition). */
  for (i = 0; i < session->hs_alias_count; i++) {
    const struct BounceAlias *ba = &session->hs_aliases[i];
    struct Client *a = findNUser(ba->ba_numeric);
    if (!a)
      continue; /* Alias is on a remote/disconnected server; can't validate locally. */
    if (!IsBouncerAlias(a)) {
      log_write(LS_USER, L_WARNING, 0,
                "session_invariant[%s]: session %s alias %s is not "
                "IsBouncerAlias (it's %s)",
                site ? site : "?", session->hs_sessid, ba->ba_numeric,
                cli_name(a));
      return -6;
    }
    if (p && cli_alias_primary(a) != p) {
      log_write(LS_USER, L_WARNING, 0,
                "session_invariant[%s]: session %s alias %s "
                "alias_primary != hs_client",
                site ? site : "?", session->hs_sessid, ba->ba_numeric);
      return -7;
    }
  }

  return 0;
}

/** State transition funnel.  Phase-7 work-in-progress: the kinds and
 * the invariant assertion are in place; per-kind implementations
 * delegate to the existing entry-point functions while we convert
 * call sites to go through this dispatch.  Eventually the existing
 * entry points become static and only the funnel is the public API. */
int bounce_session_transition(struct BouncerSession *session,
                              enum bounce_transition_kind kind,
                              const struct bounce_transition_params *params)
{
  int rc = -1;

  if (!session || !params)
    return -1;

  bounce_session_assert_invariant(session, "transition.entry");

  switch (kind) {
  case BST_REVIVE:
    /* Caller still uses bounce_revive() directly; will be migrated
     * here in step 2 of the funnel rollout. */
    rc = -2;
    break;
  case BST_ATTACH_LOCAL_ALIAS:
    /* Caller still uses bounce_setup_local_alias(). */
    rc = -2;
    break;
  case BST_DEMOTE_TO_ALIAS:
    if (params->demoted_alias && params->peer_primary) {
      if (0 == bounce_demote_live_primary_to_alias(params->demoted_alias,
                                                    params->peer_primary,
                                                    session))
        rc = bounce_finish_live_primary_demote(params->demoted_alias,
                                                params->peer_primary,
                                                session,
                                                params->legacy_done);
    }
    break;
  case BST_REBIND_TO_REMOTE:
    /* bounce_rebind() handles this today. */
    rc = -2;
    break;
  case BST_PROMOTE_ALIAS:
    rc = bounce_promote_alias(session, 0);
    break;
  case BST_RECEIVE_REMOTE_PRIMARY:
    if (params->new_primary) {
      session->hs_client = params->new_primary;
      session->hs_state = BOUNCE_ACTIVE;
      rc = 0;
    }
    break;
  case BST_DESTROY:
    bounce_broadcast(session, 'X', NULL);
    bounce_destroy(session);
    rc = 0;
    /* session is freed; can't run exit invariant. */
    return rc;
  }

  bounce_session_assert_invariant(session, "transition.exit");
  return rc;
}

/** Is any bouncer-relevant convergence work in flight that should defer
 * a newly-linked peer's burst-emit?
 *
 * Two signals:
 *   1. Any session with hs_restore_pending — restored from MDBX,
 *      awaiting first BX R / attach / yield to settle.
 *   2. Any other peer currently IsBurst — that peer's N's may still
 *      flip our local primary/alias state before we emit to the new
 *      linker.
 *
 * exclude_peer (typically the newly-linking peer being evaluated) is
 * skipped on the IsBurst check so a self-reference doesn't count.
 *
 * Both signals are observed at server_estab gate-set time and at every
 * subsequent convergence-completion event (attach, revive, EB), so the
 * gate releases as soon as the wait is over rather than running the
 * timer fallback.
 */
int bounce_convergence_pending(struct Client *exclude_peer)
{
  int h;
  struct AccountSessions *as;
  struct BouncerSession *s;
  struct DLink *dlp;

  for (h = 0; h < BOUNCE_ACCOUNT_HASHSIZE; h++)
    for (as = accountHash[h]; as; as = as->as_hnext)
      for (s = as->as_sessions; s; s = s->hs_anext)
        if (s->hs_restore_pending) {
          /* Defensive ceiling: an unclaimed restored hold must not
           * gate bursts forever.  Lazily expire it here -- this is
           * the one place every gate decision flows through. */
          if (s->hs_restore_deadline && CurrentTime >= s->hs_restore_deadline) {
            s->hs_restore_pending = 0;
            continue;
          }
          return 1;
        }

  if (cli_serv(&me)) {
    for (dlp = cli_serv(&me)->down; dlp; dlp = dlp->next) {
      struct Client *peer = dlp->value.cptr;
      if (!peer || peer == exclude_peer || !IsServer(peer))
        continue;
      if (IsBurst(peer))
        return 1;
    }
  }

  return 0;
}

/** Walk gated peers; release any whose convergence wait is complete.
 *
 * Called event-driven from convergence-completion sites (hs_restore_
 * pending cleared, ClearBurst on a peer).  The 1-second timer remains
 * as a fallback for stalled-convergence cases.
 *
 * For each gated peer, re-check bounce_convergence_pending — if it
 * now returns 0, clear the gate and run server_finish_burst.  Safe
 * iteration via cached `next`; server_finish_burst doesn't add/remove
 * down-list entries.
 */
void bounce_release_idle_gates(void)
{
  struct DLink *dlp;
  struct DLink *next;

  if (!cli_serv(&me))
    return;

  for (dlp = cli_serv(&me)->down; dlp; dlp = next) {
    struct Client *peer;
    next = dlp->next;
    peer = dlp->value.cptr;
    if (!peer || !IsServer(peer))
      continue;
    if (!IsBurstGated(peer))
      continue;
    if (bounce_convergence_pending(peer))
      continue;

    Debug((DEBUG_INFO,
           "Bouncer: convergence settled, releasing gate on %s "
           "(deadline was %lds away)",
           cli_name(peer),
           (long)(cli_burst_gate_deadline(peer) - CurrentTime)));
    cli_burst_gate_deadline(peer) = 0;
    ClearBurstGated(peer);
    server_finish_burst(peer);
  }
}

/** The deferred gate release: bounce_release_idle_gates() at the next
 * timer run, after the line being handled now. */
static struct Timer gate_release_timer;

static void bounce_gate_release_cb(struct Event *ev)
{
  if (ev_type(ev) != ET_EXPIRE)
    return;
  bounce_release_idle_gates();
}

/** See include/bouncer_session.h. */
void bounce_schedule_gate_release(void)
{
  if (t_active(&gate_release_timer))
    return;
  timer_add(timer_init(&gate_release_timer), bounce_gate_release_cb, NULL,
            TT_RELATIVE, 0);
}

/** Force-release legacy-peer burst gates whose grace deadline has
 * passed.  Called once per second from a periodic timer.
 *
 * Per design intent #135 + #254: legacy peers must see exactly one
 * face per bouncer session.  When two BX-aware servers each restore
 * a held ghost for the same account during a partition, both want to
 * burst their primary as N to a shared legacy peer — that's the
 * cascade-kill scenario.  server_estab gates the legacy-peer burst
 * to give BX R convergence time to settle (loser's primary becomes
 * IsBouncerAlias, which the N-burst filter at server_finish_burst
 * skips, so only the winner's face propagates).  This tick is the
 * fallback timer that releases the gate if BX R never settles
 * (e.g., no BX-aware peer ever links).
 */
void bounce_legacy_burst_gate_tick(void)
{
  struct DLink *dlp;
  struct DLink *next;

  if (!cli_serv(&me))
    return;

  for (dlp = cli_serv(&me)->down; dlp; dlp = next) {
    struct Client *peer;
    next = dlp->next;
    peer = dlp->value.cptr;
    if (!peer || !IsServer(peer))
      continue;
    if (!IsBurstGated(peer))
      continue;
    if (cli_burst_gate_deadline(peer) == 0)
      continue; /* gate set without deadline (shouldn't happen) */
    if (cli_burst_gate_deadline(peer) > CurrentTime)
      continue; /* not yet expired */

    Debug((DEBUG_INFO,
           "Bouncer: burst gate expired for %s — releasing",
           cli_name(peer)));
    cli_burst_gate_deadline(peer) = 0;
    ClearBurstGated(peer);
    server_finish_burst(peer);
  }
}

/** Event-callback wrapper for the periodic 1-second tick.  Registered
 * from ircd.c as a TT_PERIODIC timer. */
void bounce_legacy_burst_gate_callback(struct Event *ev)
{
  (void)ev;
  bounce_legacy_burst_gate_tick();
}


/* ---------------------------------------------------------------- */
/* Legacy-face records                                               */
/* ---------------------------------------------------------------- */

const char *bounce_session_legacy_face_for(struct BouncerSession *session,
                                            const char *peer_yxx)
{
  int i;
  if (!session || !peer_yxx || !*peer_yxx)
    return NULL;
  for (i = 0; i < session->hs_legacy_intro_count; i++) {
    if (0 == strcmp(session->hs_legacy_intros[i].bli_peer, peer_yxx))
      return session->hs_legacy_intros[i].bli_face;
  }
  return NULL;
}

const char *bounce_account_legacy_face_for(const char *account,
                                            const char *peer_yxx)
{
  struct AccountSessions *as;
  struct BouncerSession  *s;
  const char             *face;

  if (!account || !*account || !peer_yxx || !*peer_yxx)
    return NULL;
  as = bounce_find_by_account(account);
  if (!as)
    return NULL;
  for (s = as->as_sessions; s; s = s->hs_anext) {
    face = bounce_session_legacy_face_for(s, peer_yxx);
    if (face)
      return face;
  }
  return NULL;
}

void bounce_session_record_legacy_intro(struct BouncerSession *session,
                                         const char *peer_yxx,
                                         const char *face_yxx)
{
  int i;
  if (!session || !peer_yxx || !*peer_yxx || !face_yxx || !*face_yxx)
    return;
  for (i = 0; i < session->hs_legacy_intro_count; i++) {
    if (0 == strcmp(session->hs_legacy_intros[i].bli_peer, peer_yxx))
      return;  /* already recorded */
  }
  if (session->hs_legacy_intro_count >= BOUNCER_LEGACY_INTRO_MAX)
    return;
  ircd_strncpy(session->hs_legacy_intros[session->hs_legacy_intro_count].bli_peer,
               peer_yxx, NICKLEN + 1);
  ircd_strncpy(session->hs_legacy_intros[session->hs_legacy_intro_count].bli_face,
               face_yxx, 6);    /* bli_face is char[6]; full 5-char YYXXX + NUL */
  session->hs_legacy_intro_count++;
}

void bounce_session_clear_legacy_face(struct BouncerSession *session,
                                       const char *face_yxx)
{
  int i, j;
  if (!session || !face_yxx || !*face_yxx)
    return;
  for (i = 0; i < session->hs_legacy_intro_count; ) {
    if (0 == strcmp(session->hs_legacy_intros[i].bli_face, face_yxx)) {
      for (j = i; j < session->hs_legacy_intro_count - 1; j++)
        session->hs_legacy_intros[j] = session->hs_legacy_intros[j + 1];
      session->hs_legacy_intro_count--;
    } else {
      i++;
    }
  }
}

void bounce_clear_legacy_faces_for_peer(const char *peer_yxx)
{
  int i, j, k;
  struct BouncerSession *s;
  if (!peer_yxx || !*peer_yxx)
    return;
  for (i = 0; i < BOUNCE_TOKEN_HASHSIZE; i++) {
    for (s = tokenHash[i]; s; s = s->hs_tnext) {
      for (j = 0; j < s->hs_legacy_intro_count; ) {
        if (0 == strcmp(s->hs_legacy_intros[j].bli_peer, peer_yxx)) {
          for (k = j; k < s->hs_legacy_intro_count - 1; k++)
            s->hs_legacy_intros[k] = s->hs_legacy_intros[k + 1];
          s->hs_legacy_intro_count--;
        } else {
          j++;
        }
      }
    }
  }
}

/* ---------------------------------------------------------------- */
/* Session ids BS C left unmirrored                                   */
/* ---------------------------------------------------------------- */

/** Another server's session that BS C saw and did not mirror here: kept
 * apart from ours (ours is held with a live connection), or a holding
 * one that loses to our live one and is about to end on its server.
 * Memory only.  BX C's account fallback never files an alias of such a
 * session into ours (bounce_alias_filing): it is not one of ours.  A
 * rename of ours into it (BS C at a later link burst, or a held ghost of
 * ours yielding to its primary at N time) clears the mark; a session made
 * fresh after one of the two ends does not (registered). */
struct BounceUnmirrored {
  struct BounceUnmirrored *bu_next;
  char bu_account[ACCOUNTLEN + 1];
  char bu_sessid[BOUNCER_SESSID_LEN];
  char bu_origin[3];             /**< YY of the server that announced it */
};
static struct BounceUnmirrored *unmirrored_list;

static struct BounceUnmirrored **unmirrored_find(const char *account,
                                                 const char *sessid)
{
  struct BounceUnmirrored **pp;

  if (!account || !sessid)
    return NULL;
  for (pp = &unmirrored_list; *pp; pp = &(*pp)->bu_next)
    if (0 == strcmp((*pp)->bu_sessid, sessid)
        && 0 == ircd_strcmp((*pp)->bu_account, account))
      return pp;
  return NULL;
}

/** Record that BS C left @a sessid of @a account (announced by @a origin)
 * unmirrored here. */
static void unmirrored_mark(const char *account, const char *sessid,
                            struct Client *origin)
{
  struct BounceUnmirrored *bu;

  if (!account || !sessid || !*sessid || unmirrored_find(account, sessid))
    return;
  bu = (struct BounceUnmirrored *)MyCalloc(1, sizeof(*bu));
  ircd_strncpy(bu->bu_account, account, sizeof(bu->bu_account));
  ircd_strncpy(bu->bu_sessid, sessid, sizeof(bu->bu_sessid));
  ircd_strncpy(bu->bu_origin, origin ? cli_yxx(origin) : "",
               sizeof(bu->bu_origin));
  bu->bu_next = unmirrored_list;
  unmirrored_list = bu;
}

/** Forget the mark for @a sessid of @a account: the session ended (BS X),
 * or it is now mirrored or ours. */
static void unmirrored_clear(const char *account, const char *sessid)
{
  struct BounceUnmirrored **pp = unmirrored_find(account, sessid);

  if (pp) {
    struct BounceUnmirrored *bu = *pp;
    *pp = bu->bu_next;
    MyFree(bu);
  }
}

static int unmirrored_marked(const char *account, const char *sessid)
{
  return unmirrored_find(account, sessid) != NULL;
}

/** See include/bouncer_session.h. */
void bounce_unmirrored_clear_for_server(struct Client *victim)
{
  struct BounceUnmirrored **pp = &unmirrored_list;

  while (*pp) {
    struct BounceUnmirrored *bu = *pp;
    struct Client *s = bu->bu_origin[0] ? FindNServer(bu->bu_origin) : NULL;
    int gone = (s == NULL);

    /* The announcing server is the departing one, or behind it. */
    for (; s && !gone && IsServer(s); s = cli_serv(s)->up)
      if (s == victim)
        gone = 1;
    if (gone) {
      *pp = bu->bu_next;
      MyFree(bu);
    } else {
      pp = &bu->bu_next;
    }
  }
}

/** Where the session recorded `old_face` toward `peer_yxx`, record
 * `new_face` in its place; no-op otherwise.
 * bounce_session_record_legacy_intro keeps an existing entry (the burst
 * records only a first introduction); a BX P swap changes the face the
 * peer holds, so the entry must change with it.  A missing entry stays
 * missing (it already means "the peer may hold any face"), and an entry
 * naming another face is not this swap's. */
static void bounce_session_swap_legacy_face(struct BouncerSession *session,
                                            const char *peer_yxx,
                                            const char *old_face,
                                            const char *new_face)
{
  int i;
  if (!session || !peer_yxx || !*peer_yxx || !old_face || !*old_face
      || !new_face || !*new_face)
    return;
  for (i = 0; i < session->hs_legacy_intro_count; i++) {
    if (0 == strcmp(session->hs_legacy_intros[i].bli_peer, peer_yxx)
        && 0 == strcmp(session->hs_legacy_intros[i].bli_face, old_face)) {
      ircd_strncpy(session->hs_legacy_intros[i].bli_face, new_face,
                   sizeof(session->hs_legacy_intros[i].bli_face));
      return;
    }
  }
}

/** See include/bouncer_session.h. */
void bounce_legacy_face_change(struct Client *face, struct BouncerSession *sess,
                               struct Client *except_link,
                               const char *new_numeric, const char *reason)
{
  struct DLink *dlp;
  char face_full[6];

  if (!face || !IsUser(face) || !cli_user(face) || !cli_user(face)->server
      || !cli_serv(&me))
    return;
  if (new_numeric && strlen(new_numeric) != 5)
    return;
  ircd_snprintf(0, face_full, sizeof(face_full), "%s%s",
                cli_yxx(cli_user(face)->server), cli_yxx(face));
  if (new_numeric && 0 == strcmp(new_numeric, face_full))
    return;                     /* nothing changes for any link */

  /* One line per link, never a serv_butone sender: those rewrite an
   * alias source to its primary for a legacy next hop, and a caller may
   * already have made the face an alias (finish-demote), so the Q would
   * leave the link as a QUIT of the surviving user.  sendcmdto_one adds
   * no tag region toward a legacy link, but its untagged branch clears
   * the S2S overrides (cptr, msgid, sessid, time): a caller that needs
   * one for a later send must arm it after this call.
   *
   * Every legacy link that may know the face is told, whatever the
   * session's burst records say: a face also reaches a link by the
   * plain N relay, which records nothing, and a record can be stale.  A
   * stock server drops a Q from a numeric it does not know and leaves a
   * BX P for an unknown old numeric alone, so telling a link that never
   * knew the face costs nothing. */
  for (dlp = cli_serv(&me)->down; dlp; dlp = dlp->next) {
    struct Client *peer = dlp->value.cptr;

    if (!peer || !IsServer(peer) || peer == except_link)
      continue;
    if (!bounce_legacy_link_knows(IsIRCv3Aware(peer), IsBurstGated(peer),
                                  !MyConnect(face) && cli_from(face) == peer))
      continue;

    if (new_numeric) {
      /* The link renumbers its user in place (the stock BX P handler's
       * numeric swap); a record of the old face for it now names the
       * new numeric. */
      sendcmdto_one(&me, CMD_BOUNCER_TRANSFER, peer, "P %s %s %s %s",
                    face_full, new_numeric,
                    (sess && sess->hs_sessid[0]) ? sess->hs_sessid : "*",
                    cli_name(face));
      bounce_session_swap_legacy_face(sess, cli_yxx(peer), face_full,
                                      new_numeric);
      Debug((DEBUG_INFO, "Bouncer: legacy face %s swapped to %s toward %s "
             "(BX P)", face_full, new_numeric, cli_name(peer)));
    } else {
      sendcmdto_one(face, CMD_QUIT, peer, ":%s",
                    (reason && *reason) ? reason : "Bouncer session moved");
      Debug((DEBUG_INFO, "Bouncer: legacy face %s retracted toward %s (%s)",
             face_full, cli_name(peer),
             (reason && *reason) ? reason : "Bouncer session moved"));
    }
  }

  /* No link holds the old face any more: drop every record of it, in
   * this session and in any other of the account (a record names the
   * session the burst found at the time).  A swap's replaced entries
   * carry new_numeric and stay. */
  if (sess)
    bounce_session_clear_legacy_face(sess, face_full);
  if (IsAccount(face)) {
    struct AccountSessions *as = bounce_find_by_account(cli_account(face));
    struct BouncerSession *s;
    for (s = as ? as->as_sessions : NULL; s; s = s->hs_anext)
      if (s != sess)
        bounce_session_clear_legacy_face(s, face_full);
  }
}

/** See include/bouncer_session.h. */
void bounce_null_alias_primary_pointing_at(struct Client *gone)
{
  struct Client *cptr;

  if (!gone)
    return;

  for (cptr = GlobalClientList; cptr; cptr = cli_next(cptr)) {
    if (!IsBouncerAlias(cptr) || !cli_user(cptr))
      continue;
    if (cli_user(cptr)->alias_primary == gone)
      cli_user(cptr)->alias_primary = NULL;
  }
}

void bounce_null_hs_client_pointing_at(struct Client *cli)
{
  int i;
  struct BouncerSession *s;
  const char *home = NULL;

  if (!cli)
    return;
  /* A client of another server under a session id: when its server
   * announced that session holding, this is that server's held copy
   * going (its yield, its expiry, a KILL) -- the server no longer holds
   * the session, and the reconcile must not read it so
   * (bounce_peer_holds). */
  if (!MyConnect(cli) && IsUser(cli) && !IsBouncerAlias(cli) && cli_user(cli)
      && cli_user(cli)->server && cli_session_id(cli)[0])
    home = cli_yxx(cli_user(cli)->server);
  for (i = 0; i < BOUNCE_TOKEN_HASHSIZE; i++) {
    for (s = tokenHash[i]; s; s = s->hs_tnext) {
      if (s->hs_client == cli)
        s->hs_client = NULL;
      if (home && s->hs_peer_holding[0]
          && 0 == strcmp(s->hs_peer_holding, home)
          && bounce_in_session_by_id(s, cli))
        s->hs_peer_holding[0] = '\0';
    }
  }
}

/** Guarded `session->hs_client = candidate` for assignment paths that
 * resolve a Client via numeric lookup (findNUser, BS A/H/D handlers,
 * the HELD-resume composed-numeric site at bounce_resume_check).
 *
 * Refuses the install if candidate's account does not match the session's
 * account.  Numeric reuse across the network (or a stale persisted
 * ghost_numeric after restart) can cause a lookup to return a perfectly
 * valid Client that simply belongs to someone else; that misassignment
 * was the M2/M3 class in the audit.
 *
 * Returns 1 if the install was accepted, 0 if refused.  When refused the
 * session's hs_client is left at its prior value (typically NULL); the
 * caller can treat that as "no primary resolvable yet" and fall through
 * to the orphan-reclaim branch on the next reconnect.
 *
 * @param[in,out] session The session being modified.
 * @param[in]     candidate Client about to be installed as hs_client.
 * @param[in]     site_label Short tag for the log line on mismatch
 *                ("BS A", "BS H", "HELD resume", "BS D" ...).
 */
int bounce_hs_client_assign_checked(struct BouncerSession *session,
                                    struct Client *candidate,
                                    const char *site_label)
{
  if (!session)
    return 0;
  if (!candidate) {
    session->hs_client = NULL;
    return 1;
  }
  if (!IsAccount(candidate)
      || 0 != ircd_strcmp(cli_account(candidate), session->hs_account)) {
    log_write(LS_USER, L_WARNING, 0,
              "Bouncer: refusing %s hs_client install for session %s "
              "(account=%s) — candidate %s has account=%s",
              site_label ? site_label : "?",
              session->hs_sessid, session->hs_account,
              cli_name(candidate),
              IsAccount(candidate) ? cli_account(candidate) : "<none>");
    return 0;
  }
  /* Never a primary of another Keycloak user (user, 2026-10-23): a peer's
   * BS A for a session kept apart after a split would otherwise point ours
   * at it. */
  if (cli_user(candidate)
      && bounce_rebind_kc_conflict(session->hs_kc_id, cli_user(candidate)->kc_id)) {
    log_write(LS_USER, L_INFO, 0,
              "Bouncer: refusing %s hs_client install for session %s: it "
              "belongs to Keycloak id %s, %s carries %s",
              site_label ? site_label : "?", session->hs_sessid,
              session->hs_kc_id, cli_name(candidate), cli_user(candidate)->kc_id);
    return 0;
  }
  session->hs_client = candidate;
  return 1;
}

/** Persist a bouncer session to MDBX.
 * Only persists local sessions. Guarded by FEAT_BOUNCER_PERSIST.
 * @param[in] session Session to persist.
 * @return 0 on success, -1 on error.
 */
static int bounce_db_put(struct BouncerSession *session)
{
  struct db_env *env;
  struct db_cf  *cf;
  struct db_writebatch *wb;
  struct BounceSessionRecord rec;
  struct Client *ghost = session->hs_client;
  int rc;

  if (!feature_bool(FEAT_BOUNCER_PERSIST) || !metadata_lmdb_is_available())
    return 0;

  /* Per redesign C.2: persist iff we hold a Client locally; hs_origin
   * is historical-only and not authoritative here. */
  if (!session_has_local_holder(session))
    return 0;

  env = metadata_get_env();
  cf  = metadata_get_bouncer_cf();
  if (!env || !cf)
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
  if (session->hs_state == BOUNCE_ACTIVE && session->hs_attach_time > 0
      && CurrentTime > session->hs_attach_time)
    rec.bsr_total_active += (int64_t)(CurrentTime - session->hs_attach_time);
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

  /* Alias roster (per redesign B.2 + B.6).  Persisted as expectations
   * to verify on next link establishment, not authoritative live
   * state — peers' BS A bursts confirm or repudiate. */
  rec.bsr_aliascount = (uint16_t)session->hs_alias_count;
  if (rec.bsr_aliascount > BOUNCER_MAX_ALIASES)
    rec.bsr_aliascount = BOUNCER_MAX_ALIASES;
  {
    int i;
    for (i = 0; i < rec.bsr_aliascount; i++) {
      ircd_strncpy(rec.bsr_aliases[i].bsar_numeric,
                   session->hs_aliases[i].ba_numeric,
                   sizeof(rec.bsr_aliases[i].bsar_numeric));
      ircd_strncpy(rec.bsr_aliases[i].bsar_server,
                   session->hs_aliases[i].ba_server,
                   sizeof(rec.bsr_aliases[i].bsar_server));
      rec.bsr_aliases[i].bsar_caps = session->hs_aliases[i].ba_caps;
      rec.bsr_aliases[i].bsar_last_active =
        (int64_t)session->hs_aliases[i].ba_last_active;
    }
  }

  /* Oper grant (v9+).  Empty hs_oper_name means not opered — the
   * record fields stay zero by default; on revive bounce_apply_oper_grant
   * is a no-op when bsr_oper_name is empty. */
  ircd_strncpy(rec.bsr_oper_name, session->hs_oper_name,
               sizeof(rec.bsr_oper_name));
  rec.bsr_oper_granted_at = (int64_t)session->hs_oper_granted_at;

  /* Server notice mask (v11+): the live one while a socket holds the
   * session, otherwise the one bounce_hold_client() kept (the held
   * socket's own was zeroed by close_connection()). */
  if (ghost && MyConnect(ghost) && !IsBouncerHold(ghost)) {
    rec.bsr_snomask = HasFlag(ghost, FLAG_SERVNOTICE) ? cli_snomask(ghost) : 0;
    rec.bsr_snomask_known = 1;
  } else {
    rec.bsr_snomask = session->hs_snomask;
    rec.bsr_snomask_known = session->hs_snomask_known ? 1 : 0;
  }

  /* The Keycloak user the session belongs to (v12+). */
  if (account_id_valid(bounce_session_kc_id(session)))
    ircd_strncpy(rec.bsr_kc_id, bounce_session_kc_id(session), sizeof(rec.bsr_kc_id));

  /* Write through the abstraction */
  wb = db_writebatch_new(env);
  if (!wb)
    return -1;
  rc = db_writebatch_put(wb, cf,
                         session->hs_sessid, strlen(session->hs_sessid),
                         &rec, sizeof rec);
  if (rc != DB_OK) {
    log_write(LS_SYSTEM, L_ERROR, 0, "bouncer_persist: put(%s) failed: %s",
              session->hs_sessid, db_strerror(rc));
    db_writebatch_destroy(wb);
    return -1;
  }
  rc = db_writebatch_commit(wb, /*sync_durably=*/0);
  db_writebatch_destroy(wb);
  if (rc != DB_OK) {
    log_write(LS_SYSTEM, L_ERROR, 0, "bouncer_persist: commit failed: %s",
              db_strerror(rc));
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
  struct db_env *env;
  struct db_cf  *cf;
  struct db_writebatch *wb;
  int rc;

  if (!feature_bool(FEAT_BOUNCER_PERSIST) || !metadata_lmdb_is_available())
    return 0;

  env = metadata_get_env();
  cf  = metadata_get_bouncer_cf();
  if (!env || !cf)
    return -1;

  wb = db_writebatch_new(env);
  if (!wb)
    return -1;
  rc = db_writebatch_del(wb, cf, sessid, strlen(sessid));
  if (rc != DB_OK && rc != DB_NOTFOUND) {
    log_write(LS_SYSTEM, L_ERROR, 0, "bouncer_persist: del(%s) failed: %s",
              sessid, db_strerror(rc));
    db_writebatch_destroy(wb);
    return -1;
  }
  rc = db_writebatch_commit(wb, /*sync_durably=*/0);
  db_writebatch_destroy(wb);
  if (rc != DB_OK) {
    log_write(LS_SYSTEM, L_ERROR, 0, "bouncer_persist: commit failed: %s",
              db_strerror(rc));
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
      /* Per redesign C.2: shutdown-persist sessions we hold locally. */
      if (!session_has_local_holder(s))
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

/* ---------------------------------------------------------------- */
/* Client counters across a conversion                               */
/* ---------------------------------------------------------------- */

/* A user holds a fixed set of the core client counters -- UserStats.clients,
 * local_clients, local_announced_clients, announced_clients and its
 * server's count -- and its exit releases exactly that set, by the facts it
 * reads then: Count_clientdisconnects for a client of ours,
 * Count_remoteclientquits for another server's non-alias, nothing for
 * another server's alias (bouncer_count.h).  The bouncer changes those
 * facts in place: a primary's socket drops and it is held, a login revives
 * the ghost, a live primary is demoted to an alias, an alias is promoted, a
 * client another server introduced is converted into an alias, a held ghost
 * becomes another server's client.  Every such conversion snapshots what
 * the client held before (count_held) and moves the difference once the
 * client is what it is now (bounce_count_converted): each count is taken
 * once, moved with the client, and released once, by whichever path ends
 * it. */

/** What @a c holds in the core client counters now: what its exit would
 * release. */
static void count_held(struct Client *c, struct bounce_counts *out)
{
  bounce_count_held(MyConnect(c), IsBouncerAlias(c), !IsNoLcDecrement(c),
                    out);
}

static void count_dec(unsigned int *ctr, const char *what, struct Client *c,
                      const char *site)
{
  if (*ctr > 0)
    --*ctr;
  else
    log_write(LS_USER, L_WARNING, 0, "Bouncer counters: %s is already 0 "
              "when %s gives a count up (%s)", what, cli_name(c), site);
}

static void count_move(unsigned int *ctr, unsigned int *max, int delta,
                       const char *what, struct Client *c, const char *site)
{
  if (delta < 0) {
    count_dec(ctr, what, c, site);
  } else if (delta > 0) {
    ++*ctr;
    if (*ctr > *max) {
      *max = *ctr;
      save_tunefile();
    }
  }
}

/** A conversion changed @a c in place: before it, @a c held @a was, with
 * @a was_server its server then; it holds what its state says now, with
 * its server now.  Moves the difference.  The server's own count (&me's)
 * is never kept: MAP, STATS and CHECK read local_clients for it.
 * @param[in] c          The converted client.
 * @param[in] was        count_held(c) before the conversion.
 * @param[in] was_server Its server before the conversion.
 * @param[in] site       Short label for the log line of a count already 0.
 */
static void bounce_count_converted(struct Client *c,
                                   const struct bounce_counts *was,
                                   struct Client *was_server,
                                   const char *site)
{
  struct bounce_counts now, d;
  struct Client *server = cli_user(c) ? cli_user(c)->server : NULL;

  count_held(c, &now);
  bounce_count_delta(was, &now, &d);
  count_move(&UserStats.clients, &UserStats.clients_max, d.clients,
             "clients", c, site);
  count_move(&UserStats.local_clients, &UserStats.local_clients_max,
             d.local_clients, "local_clients", c, site);
  count_move(&UserStats.local_announced_clients,
             &UserStats.local_announced_clients_max, d.local_announced,
             "local_announced_clients", c, site);
  count_move(&UserStats.announced_clients, &UserStats.announced_clients_max,
             d.announced, "announced_clients", c, site);
  /* Its server's count: given up on the server it had, taken on the one it
   * has (the same server unless it moved). */
  if (was->server_clients && was_server && was_server != &me
      && cli_serv(was_server))
    count_dec(&cli_serv(was_server)->clients, "its server's count", c, site);
  if (now.server_clients && server && server != &me && cli_serv(server))
    ++cli_serv(server)->clients;
}

/** Create a ghost client from a persisted session record.
 * The ghost has no socket (fd=-1), is registered in global structures,
 * and is flagged as BOUNCER_HOLD.
 * @param[in] rec Persisted session record.
 * @return Ghost client, or NULL on failure.
 */
/* Forward decl — definition is further down, alongside the umode-sync
 * helpers it groups with logically.  Used by both bounce_db_restore
 * (revive) and bounce_promote_alias (in-server promote) to re-grant
 * oper to the new primary from the session's stored grant. */
static void bounce_apply_oper_grant(struct Client *cptr,
                                     struct BouncerSession *sess);
/* Forward decl — defined alongside its siblings further down.  Used
 * by bounce_handle_bs's case 'O' to apply (or clear) a session's
 * oper grant on every locally-attached member when the change
 * arrives over BS O from another server. */
static void bounce_apply_remote_oper_grant(struct BouncerSession *sess,
                                            const char *opername,
                                            time_t granted_at);

static struct Client *bounce_create_ghost(struct BounceSessionRecord *rec)
{
  struct Client *ghost;
  struct User *user;

  /* Allocate local client (NULL from = local, gets its own Connection with fd=-1) */
  ghost = make_client(NULL, STAT_UNKNOWN);
  if (!ghost)
    return NULL;
  /* Never registered: the zeroed fake-lag cache would read as "off". */
  cli_lag_min(ghost) = -2;
  cli_lag_factor(ghost) = -2;

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
  /* The Keycloak id (v12+): the restore burst introduces the ghost with
   * it, as the live client was. */
  if (account_id_valid(rec->bsr_kc_id))
    ircd_strncpy(user->kc_id, rec->bsr_kc_id, sizeof(user->kc_id));
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
  /* P1 A3 residue: ghost restore from the bouncer DB at startup.  Init
   * order is contractual (metadata_lmdb_init precedes bounce_db_restore —
   * see ircd.c) so the store is up here.  This load is required because
   * ghost REVIVE does NOT transfer cli_metadata from the reviving temp
   * client onto the ghost that survives — without it, a restored ghost
   * has empty cli_metadata until a lazy GET finds it (or forever, if one
   * never comes before the next restart). */
  if (user->account[0])
    metadata_load_account(ghost, user->account);
  SetHiddenHost(ghost);
  SetBouncerHold(ghost);
  /* No socket: its local_clients count is settled (never taken).  Cleared
   * by bounce_revive when a socket attaches. */
  SetNoLcDecrement(ghost);

  /* Set creation timestamp to original time (wins nick collisions: older wins) */
  cli_lastnick(ghost) = (time_t)rec->bsr_created;

  /* The ghost is a held ghost of ours from here on: a registered user the
   * network knows by N (its hold kept it announced), with no live socket.
   * unknowns is not touched: it was never a connection here. */
  {
    static const struct bounce_counts none = { 0, 0, 0, 0, 0 };
    bounce_count_converted(ghost, &none, &me, "restore");
  }

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
  struct db_env *env;
  struct db_cf  *cf;
  struct db_iter *it;
  int rc;
  int restored = 0;
  int expired = 0;
  int migrated_v7 = 0;
  int migrated = 0;   /* v8..v11 records read through a frozen layout */
  time_t max_hold;

  if (!feature_bool(FEAT_BOUNCER_PERSIST) || !metadata_lmdb_is_available())
    return 0;

  env = metadata_get_env();
  cf  = metadata_get_bouncer_cf();
  if (!env || !cf)
    return -1;

  /* Don't restore persisted sessions when the bouncer feature is globally
   * disabled.  Restoring would create ghost clients with no enabled
   * subsystem to manage their lifecycle — they'd sit in HOLDING forever,
   * collide with peer N introductions on the same account, and require
   * /bouncer reset (or a full session destroy) to clean up.  The records
   * stay on disk; if the feature is re-enabled later, restore picks them
   * up at next boot. */
  if (!bounce_enabled()) {
    log_write(LS_SYSTEM, L_INFO, 0,
              "bouncer_persist: skipping restore — FEAT_BOUNCER_ENABLE is off");
    return 0;
  }

  max_hold = feature_int(FEAT_BOUNCER_MAX_HOLD);

  /* Iterate through all persisted records */
  it = db_iter_open(env, cf, /*snap=*/NULL);
  if (!it) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "bouncer_persist: db_iter_open failed: %s",
              db_env_last_error(env) ? db_env_last_error(env) : "unknown");
    return -1;
  }

  for (rc = db_iter_seek_first(it);
       rc == DB_OK && db_iter_valid(it);
       rc = db_iter_next(it)) {
    size_t vlen;
    const void *vbuf = db_iter_value(it, &vlen);
    struct BounceSessionRecord rec_buf;
    struct BounceSessionRecord *rec;
    struct BouncerSession *session;
    struct Client *ghost;
    struct AccountSessions *as;
    time_t elapsed;
    time_t remaining;
    uint32_t version;

    /* Records start with a uint32 version field at offset 0 in every
     * schema version.  Read it without struct overlay to dispatch on
     * version regardless of total record size. */
    if (vlen < sizeof(uint32_t))
      continue;
    memcpy(&version, vbuf, sizeof(version));

    if (version == BOUNCER_DB_VERSION) {
      /* v12: current schema, parse directly from on-disk bytes. */
      if (vlen != sizeof(struct BounceSessionRecord))
        continue;
      rec = (struct BounceSessionRecord *)vbuf;
    } else if (version == 11) {
      /* v11: v12 without the trailing bsr_kc_id, which stays empty (the
       * revive adopts the login's id). */
      (void)sizeof(char[(sizeof(struct BounceSessionRecord_v11)
                         == offsetof(struct BounceSessionRecord, bsr_kc_id))
                        ? 1 : -1]);
      if (vlen != sizeof(struct BounceSessionRecord_v11))
        continue;
      memset(&rec_buf, 0, sizeof(rec_buf));
      memcpy(&rec_buf, vbuf, sizeof(struct BounceSessionRecord_v11));
      rec_buf.bsr_version = BOUNCER_DB_VERSION;
      rec = &rec_buf;
      migrated++;
      log_write(LS_SYSTEM, L_INFO, 0,
                "bouncer_persist: migrated v11 record (account=%s) → v%d",
                rec->bsr_account, BOUNCER_DB_VERSION);
    } else if (version == 10) {
      /* v10: v12 without the trailing snomask and id fields, which stay zero
       * (no mask recorded: the oper grant falls back to the O:line's). */
      /* Compile-time check: a v10 record is a prefix of a v11 one. */
      (void)sizeof(char[(sizeof(struct BounceSessionRecord_v10)
                         == offsetof(struct BounceSessionRecord, bsr_snomask))
                        ? 1 : -1]);
      if (vlen != sizeof(struct BounceSessionRecord_v10))
        continue;
      memset(&rec_buf, 0, sizeof(rec_buf));
      memcpy(&rec_buf, vbuf, sizeof(struct BounceSessionRecord_v10));
      rec_buf.bsr_version = BOUNCER_DB_VERSION;
      rec = &rec_buf;
      migrated++;
      log_write(LS_SYSTEM, L_INFO, 0,
                "bouncer_persist: migrated v10 record (account=%s) → v%d",
                rec->bsr_account, BOUNCER_DB_VERSION);
    } else if (version == 9) {
      /* v9: identical to v10 except bsr_aliases[] was sized 4.  Read
       * with the frozen v9 struct and copy field-by-field; the alias
       * roster copies up to the old array size, the rest of the
       * (larger) v10 array stays zero. */
      const struct BounceSessionRecord_v9 *v9;
      unsigned int ai;
      if (vlen != sizeof(struct BounceSessionRecord_v9))
        continue;
      v9 = (const struct BounceSessionRecord_v9 *)vbuf;
      memset(&rec_buf, 0, sizeof(rec_buf));
      rec_buf.bsr_version = BOUNCER_DB_VERSION;
      ircd_strncpy(rec_buf.bsr_account, v9->bsr_account, ACCOUNTLEN + 1);
      ircd_strncpy(rec_buf.bsr_sessid, v9->bsr_sessid, BOUNCER_SESSID_LEN);
      ircd_strncpy(rec_buf.bsr_token, v9->bsr_token, BOUNCER_TOKEN_LEN + 1);
      ircd_strncpy(rec_buf.bsr_name, v9->bsr_name, BOUNCER_NAME_LEN);
      ircd_strncpy(rec_buf.bsr_origin, v9->bsr_origin, NICKLEN + 1);
      rec_buf.bsr_hold_override = v9->bsr_hold_override;
      rec_buf.bsr_created = v9->bsr_created;
      rec_buf.bsr_disconnect_time = v9->bsr_disconnect_time;
      rec_buf.bsr_last_active = v9->bsr_last_active;
      rec_buf.bsr_last_msg_time = v9->bsr_last_msg_time;
      rec_buf.bsr_total_active = v9->bsr_total_active;
      rec_buf.bsr_attach_count = v9->bsr_attach_count;
      rec_buf.bsr_connect_count = v9->bsr_connect_count;
      ircd_strncpy(rec_buf.bsr_nick, v9->bsr_nick, NICKLEN + 1);
      ircd_strncpy(rec_buf.bsr_username, v9->bsr_username, USERLEN + 1);
      ircd_strncpy(rec_buf.bsr_realhost, v9->bsr_realhost, HOSTLEN + 1);
      ircd_strncpy(rec_buf.bsr_host, v9->bsr_host, HOSTLEN + 1);
      ircd_strncpy(rec_buf.bsr_realname, v9->bsr_realname, REALLEN + 1);
      ircd_strncpy(rec_buf.bsr_account_name, v9->bsr_account_name,
                   ACCOUNTLEN + 1);
      rec_buf.bsr_acc_create = v9->bsr_acc_create;
      memcpy(&rec_buf.bsr_ip, &v9->bsr_ip, sizeof(rec_buf.bsr_ip));
      ircd_strncpy(rec_buf.bsr_sock_ip, v9->bsr_sock_ip, SOCKIPLEN + 1);
      ircd_strncpy(rec_buf.bsr_sockhost, v9->bsr_sockhost, HOSTLEN + 1);
      rec_buf.bsr_listener_port = v9->bsr_listener_port;
      rec_buf.bsr_agg_sendB = v9->bsr_agg_sendB;
      rec_buf.bsr_agg_receiveB = v9->bsr_agg_receiveB;
      rec_buf.bsr_agg_sendM = v9->bsr_agg_sendM;
      rec_buf.bsr_agg_receiveM = v9->bsr_agg_receiveM;
      rec_buf.bsr_histcount = v9->bsr_histcount;
      memcpy(rec_buf.bsr_history, v9->bsr_history, sizeof(rec_buf.bsr_history));
      rec_buf.bsr_chancount = v9->bsr_chancount;
      memcpy(rec_buf.bsr_channels, v9->bsr_channels,
             sizeof(rec_buf.bsr_channels));
      rec_buf.bsr_aliascount = v9->bsr_aliascount;
      if (rec_buf.bsr_aliascount > 4)
        rec_buf.bsr_aliascount = 4;
      for (ai = 0; ai < rec_buf.bsr_aliascount; ai++)
        rec_buf.bsr_aliases[ai] = v9->bsr_aliases[ai];
      ircd_strncpy(rec_buf.bsr_oper_name, v9->bsr_oper_name, NICKLEN + 1);
      rec_buf.bsr_oper_granted_at = v9->bsr_oper_granted_at;
      rec = &rec_buf;
      migrated++;
      log_write(LS_SYSTEM, L_INFO, 0,
                "bouncer_persist: migrated v9 record (account=%s) → v%d",
                rec->bsr_account, BOUNCER_DB_VERSION);
    } else if (version == 8) {
      /* v8: legacy schema.  Read with the frozen v8 struct, then build
       * a v9 record in-place; v9 only adds oper-grant fields (left
       * zero — pre-v9 sessions weren't opered as far as we know). */
      const struct BounceSessionRecord_v8 *v8;
      if (vlen != sizeof(struct BounceSessionRecord_v8))
        continue;
      v8 = (const struct BounceSessionRecord_v8 *)vbuf;
      memset(&rec_buf, 0, sizeof(rec_buf));
      /* All v8 fields appear in v9 with the same names/types — copy
       * field-by-field rather than a struct-overlay memcpy because the
       * outer struct's layout has the oper fields appended after
       * bsr_aliases. */
      rec_buf.bsr_version = BOUNCER_DB_VERSION;
      ircd_strncpy(rec_buf.bsr_account, v8->bsr_account, ACCOUNTLEN + 1);
      ircd_strncpy(rec_buf.bsr_sessid, v8->bsr_sessid, BOUNCER_SESSID_LEN);
      ircd_strncpy(rec_buf.bsr_token, v8->bsr_token, BOUNCER_TOKEN_LEN + 1);
      ircd_strncpy(rec_buf.bsr_name, v8->bsr_name, BOUNCER_NAME_LEN);
      ircd_strncpy(rec_buf.bsr_origin, v8->bsr_origin, NICKLEN + 1);
      rec_buf.bsr_hold_override = v8->bsr_hold_override;
      rec_buf.bsr_created = v8->bsr_created;
      rec_buf.bsr_disconnect_time = v8->bsr_disconnect_time;
      rec_buf.bsr_last_active = v8->bsr_last_active;
      rec_buf.bsr_last_msg_time = v8->bsr_last_msg_time;
      rec_buf.bsr_total_active = v8->bsr_total_active;
      rec_buf.bsr_attach_count = v8->bsr_attach_count;
      rec_buf.bsr_connect_count = v8->bsr_connect_count;
      ircd_strncpy(rec_buf.bsr_nick, v8->bsr_nick, NICKLEN + 1);
      ircd_strncpy(rec_buf.bsr_username, v8->bsr_username, USERLEN + 1);
      ircd_strncpy(rec_buf.bsr_realhost, v8->bsr_realhost, HOSTLEN + 1);
      ircd_strncpy(rec_buf.bsr_host, v8->bsr_host, HOSTLEN + 1);
      ircd_strncpy(rec_buf.bsr_realname, v8->bsr_realname, REALLEN + 1);
      ircd_strncpy(rec_buf.bsr_account_name, v8->bsr_account_name,
                   ACCOUNTLEN + 1);
      rec_buf.bsr_acc_create = v8->bsr_acc_create;
      memcpy(&rec_buf.bsr_ip, &v8->bsr_ip, sizeof(rec_buf.bsr_ip));
      ircd_strncpy(rec_buf.bsr_sock_ip, v8->bsr_sock_ip, SOCKIPLEN + 1);
      ircd_strncpy(rec_buf.bsr_sockhost, v8->bsr_sockhost, HOSTLEN + 1);
      rec_buf.bsr_listener_port = v8->bsr_listener_port;
      rec_buf.bsr_agg_sendB = v8->bsr_agg_sendB;
      rec_buf.bsr_agg_receiveB = v8->bsr_agg_receiveB;
      rec_buf.bsr_agg_sendM = v8->bsr_agg_sendM;
      rec_buf.bsr_agg_receiveM = v8->bsr_agg_receiveM;
      rec_buf.bsr_histcount = v8->bsr_histcount;
      memcpy(rec_buf.bsr_history, v8->bsr_history, sizeof(rec_buf.bsr_history));
      rec_buf.bsr_chancount = v8->bsr_chancount;
      memcpy(rec_buf.bsr_channels, v8->bsr_channels,
             sizeof(rec_buf.bsr_channels));
      rec_buf.bsr_aliascount = v8->bsr_aliascount;
      memcpy(rec_buf.bsr_aliases, v8->bsr_aliases,
             sizeof(rec_buf.bsr_aliases));
      /* bsr_oper_name + bsr_oper_granted_at left zero — pre-v9 sessions
       * had no session-level oper grant. */
      rec = &rec_buf;
      migrated++;
      log_write(LS_SYSTEM, L_INFO, 0,
                "bouncer_persist: migrated v8 record (account=%s) → current",
                rec->bsr_account);
    } else if (version == 7) {
      /* v7: legacy schema.  Read with the frozen v7 struct, then
       * construct a v8 record in-place by copying matching fields and
       * minting a UUID v7 for the new sessid format (per redesign
       * A.1).  New v8-only fields (alias roster) default to empty —
       * peers' BS A bursts repopulate them on next link. */
      const struct BounceSessionRecord_v7 *v7;
      if (vlen != sizeof(struct BounceSessionRecord_v7))
        continue;
      v7 = (const struct BounceSessionRecord_v7 *)vbuf;
      memset(&rec_buf, 0, sizeof(rec_buf));
      rec_buf.bsr_version = BOUNCER_DB_VERSION;
      ircd_strncpy(rec_buf.bsr_account, v7->bsr_account, ACCOUNTLEN + 1);
      /* Mint a fresh UUID v7 for the v7→v8 sessid migration (per G.1). */
      generate_sessid(rec_buf.bsr_sessid);
      ircd_strncpy(rec_buf.bsr_token, v7->bsr_token, BOUNCER_TOKEN_LEN + 1);
      ircd_strncpy(rec_buf.bsr_name, v7->bsr_name, BOUNCER_NAME_LEN);
      ircd_strncpy(rec_buf.bsr_origin, v7->bsr_origin, NICKLEN + 1);
      rec_buf.bsr_hold_override = v7->bsr_hold_override;
      rec_buf.bsr_created = v7->bsr_created;
      rec_buf.bsr_disconnect_time = v7->bsr_disconnect_time;
      rec_buf.bsr_last_active = v7->bsr_last_active;
      rec_buf.bsr_last_msg_time = v7->bsr_last_msg_time;
      rec_buf.bsr_total_active = v7->bsr_total_active;
      rec_buf.bsr_attach_count = v7->bsr_attach_count;
      rec_buf.bsr_connect_count = v7->bsr_connect_count;
      ircd_strncpy(rec_buf.bsr_nick, v7->bsr_nick, NICKLEN + 1);
      ircd_strncpy(rec_buf.bsr_username, v7->bsr_username, USERLEN + 1);
      ircd_strncpy(rec_buf.bsr_realhost, v7->bsr_realhost, HOSTLEN + 1);
      ircd_strncpy(rec_buf.bsr_host, v7->bsr_host, HOSTLEN + 1);
      ircd_strncpy(rec_buf.bsr_realname, v7->bsr_realname, REALLEN + 1);
      ircd_strncpy(rec_buf.bsr_account_name, v7->bsr_account_name,
                   ACCOUNTLEN + 1);
      rec_buf.bsr_acc_create = v7->bsr_acc_create;
      memcpy(&rec_buf.bsr_ip, &v7->bsr_ip, sizeof(rec_buf.bsr_ip));
      ircd_strncpy(rec_buf.bsr_sock_ip, v7->bsr_sock_ip, SOCKIPLEN + 1);
      ircd_strncpy(rec_buf.bsr_sockhost, v7->bsr_sockhost, HOSTLEN + 1);
      rec_buf.bsr_listener_port = v7->bsr_listener_port;
      rec_buf.bsr_agg_sendB = v7->bsr_agg_sendB;
      rec_buf.bsr_agg_receiveB = v7->bsr_agg_receiveB;
      rec_buf.bsr_agg_sendM = v7->bsr_agg_sendM;
      rec_buf.bsr_agg_receiveM = v7->bsr_agg_receiveM;
      rec_buf.bsr_histcount = v7->bsr_histcount;
      memcpy(rec_buf.bsr_history, v7->bsr_history, sizeof(rec_buf.bsr_history));
      rec_buf.bsr_chancount = v7->bsr_chancount;
      memcpy(rec_buf.bsr_channels, v7->bsr_channels,
             sizeof(rec_buf.bsr_channels));
      /* bsr_aliascount + bsr_aliases[] left zeroed — peers refill. */
      rec = &rec_buf;
      migrated_v7++;
      log_write(LS_SYSTEM, L_INFO, 0,
                "bouncer_persist: migrated v7 record (account=%s) → "
                "v%d sessid=%s",
                rec->bsr_account, BOUNCER_DB_VERSION, rec->bsr_sessid);
    } else {
      continue; /* unknown version, skip */
    }

    /* Check expiry */
    elapsed = CurrentTime - (time_t)rec->bsr_disconnect_time;
    if (elapsed > max_hold) {
      expired++;
      continue;
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
    /* Cleared by attach/revive, by the post-burst settle in
     * bounce_post_burst_reconcile, or by the deadline below.  (The
     * original burst-time BX R clear went away with BX R's Phase 5
     * retirement -- leaving a session nothing ever claimed gating
     * EVERY subsequent server link's burst the full 30s fallback,
     * which broke anything cross-server within 30s of a link.) */
    session->hs_restore_pending = 1;
    session->hs_restore_deadline = CurrentTime + BOUNCE_LEGACY_GATE_SECS;
    session->hs_client = ghost;
    /* Sync ghost's cli_session_id to the bouncer's durable hs_sessid
     * NOW — at make_client time bounce_create_ghost minted a fresh
     * cli_session_id, which is the value bounce_set_n_sessid_hint
     * propagates to peers via the ,S compact tag on any subsequent
     * N introduction.  We do bursts BEFORE the ghost reaches
     * bounce_revive (which has its own sync), so if we delay the sync
     * to revive, peers receive the ghost's N during burst with the
     * fresh-minted sessid and never observe the persisted one — every
     * downstream code path keyed on cli_session_id <=> hs_sessid
     * agreement (post-burst reconcile, alias attribution, etc.) then
     * silently misses. */
    ircd_strncpy(cli_session_id(ghost), session->hs_sessid, S2S_SESSID_BUFSIZE);
    ircd_strncpy(session->hs_ghost_numeric, cli_yxx(ghost),
                 sizeof(session->hs_ghost_numeric));
    session->hs_ghost_numeric[sizeof(session->hs_ghost_numeric) - 1] = '\0';  /* redundant: strlcpy already terminates */
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
    if (account_id_valid(rec->bsr_kc_id))
      ircd_strncpy(session->hs_kc_id, rec->bsr_kc_id, sizeof(session->hs_kc_id));

    /* Restore the session-anchored oper grant (v9+).  bsr_oper_name is
     * empty for v8-and-earlier records (migration leaves it zero) and
     * for sessions that weren't opered when persisted — in both cases
     * bounce_apply_oper_grant below short-circuits cleanly. */
    ircd_strncpy(session->hs_oper_name, rec->bsr_oper_name,
                 sizeof(session->hs_oper_name));
    session->hs_oper_granted_at = (time_t)rec->bsr_oper_granted_at;
    /* The session's own server notice mask (v11+), which the grant below
     * restores in place of the O:line default. */
    session->hs_snomask = rec->bsr_snomask;
    session->hs_snomask_known = rec->bsr_snomask_known ? 1 : 0;

    /* If the session had an oper grant when persisted, re-apply it to
     * the just-created ghost so the held identity carries oper rights
     * across restart.  No-op when the grant is empty or no local
     * O:line matches hs_oper_name. */
    if (session->hs_oper_name[0])
      bounce_apply_oper_grant(ghost, session);

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

    /* Restore persisted alias roster (per redesign B.2 + B.6).
     *
     * Local aliases (ba_server == our numeric) reference Client structs
     * that are GONE after restart — their sockets closed, the numerics
     * are released back to the pool.  Restoring them produces stale
     * entries (findNUser returns NULL) that accumulate across cycles
     * because shutdown order persists with hs_aliases populated, then
     * close_connections empties them locally — but the persisted record
     * keeps the pre-cleanup snapshot.  Skip those.
     *
     * Remote aliases (ba_server != us) reference Client structs that
     * peer servers will re-introduce via burst N's.  Keep them — peer
     * BS A bursts confirm liveness, missing aliases are pruned at
     * convergence time. */
    session->hs_alias_count = 0;
    {
      int i;
      const char *me_yxx = cli_yxx(&me);
      for (i = 0; i < rec->bsr_aliascount && i < BOUNCER_MAX_ALIASES; i++) {
        if (0 == strcmp(rec->bsr_aliases[i].bsar_server, me_yxx))
          continue;  /* local alias — Client is gone, skip */
        ircd_strncpy(session->hs_aliases[session->hs_alias_count].ba_numeric,
                     rec->bsr_aliases[i].bsar_numeric,
                     sizeof(session->hs_aliases[0].ba_numeric));
        ircd_strncpy(session->hs_aliases[session->hs_alias_count].ba_server,
                     rec->bsr_aliases[i].bsar_server,
                     sizeof(session->hs_aliases[0].ba_server));
        session->hs_aliases[session->hs_alias_count].ba_caps =
          rec->bsr_aliases[i].bsar_caps;
        session->hs_aliases[session->hs_alias_count].ba_caps_known =
          (rec->bsr_aliases[i].bsar_caps != 0);
        session->hs_aliases[session->hs_alias_count].ba_last_active =
          (time_t)rec->bsr_aliases[i].bsar_last_active;
        session->hs_alias_count++;
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
    bounce_arm_hold_timer(session, 10); /* minimum 10s settling period */
    remaining = bounce_hold_remaining(session);

    restored++;
    log_write(LS_SYSTEM, L_INFO, 0, "bouncer_persist: restored session %s (%s) ghost=%s remaining=%Tu",
              session->hs_sessid, session->hs_account, cli_name(ghost), remaining);
  }

  db_iter_close(it);

  /* Clean up expired and unknown-version records: collect their sessids
   * during a read pass, then delete via a writebatch.  Two passes
   * (read-collect, write-batch) because the abstraction doesn't expose
   * delete-during-iteration.  v7 records are NOT deleted here even if
   * successfully migrated — the next bounce_db_put for the session
   * (e.g., on next persist sweep) overwrites them with the v8 form
   * keyed by the new UUID sessid; the old v7 key remains until cleaned
   * up explicitly.  Below loop also evicts those stale v7 keys. */
  if (expired > 0 || migrated_v7 > 0) {
    struct db_iter *eit = db_iter_open(env, cf, /*snap=*/NULL);
    struct db_writebatch *ewb = db_writebatch_new(env);
    if (eit && ewb) {
      int erc;
      for (erc = db_iter_seek_first(eit);
           erc == DB_OK && db_iter_valid(eit);
           erc = db_iter_next(eit)) {
        size_t klen, vlen;
        const void *kbuf = db_iter_key(eit, &klen);
        const void *vbuf = db_iter_value(eit, &vlen);
        uint32_t version;
        int should_delete = 0;
        if (vlen < sizeof(uint32_t)) {
          should_delete = 1;
        } else {
          memcpy(&version, vbuf, sizeof(version));
          if (version == 7 && vlen == sizeof(struct BounceSessionRecord_v7)) {
            const struct BounceSessionRecord_v7 *v7 = vbuf;
            /* Evict v7 records — successfully-migrated ones live under
             * new UUID keys now; expired/unmigrated ones aren't worth
             * keeping. */
            (void)v7;
            should_delete = 1;
          } else if (version == BOUNCER_DB_VERSION
                     && vlen == sizeof(struct BounceSessionRecord)) {
            const struct BounceSessionRecord *r = vbuf;
            if (CurrentTime - (time_t)r->bsr_disconnect_time > max_hold)
              should_delete = 1;
          } else {
            /* Unknown version or wrong size — evict. */
            should_delete = 1;
          }
        }
        if (should_delete)
          db_writebatch_del(ewb, cf, kbuf, klen);
      }
      db_iter_close(eit);
      db_writebatch_commit(ewb, /*sync_durably=*/0);
    } else {
      if (eit) db_iter_close(eit);
    }
    if (ewb) db_writebatch_destroy(ewb);
    log_write(LS_SYSTEM, L_INFO, 0,
              "bouncer_persist: cleaned up %d expired + %d migrated-v7 records",
              expired, migrated_v7);
  }

  /* If we migrated any records, persist them in the current form now (v7
   * under the new UUID keys, later versions over their old ones).
   * Otherwise the migrated state is in-memory only: a held session is
   * never marked dirty, and the eviction pass above deletes every record
   * that is not the current version whenever anything expired -- one
   * more restart before a revive would then lose the session. */
  if (migrated_v7 > 0 || migrated > 0) {
    struct AccountSessions *as_iter;
    struct BouncerSession *s;
    unsigned int b;
    for (b = 0; b < BOUNCE_ACCOUNT_HASHSIZE; b++) {
      for (as_iter = accountHash[b]; as_iter; as_iter = as_iter->as_hnext) {
        for (s = as_iter->as_sessions; s; s = s->hs_anext)
          (void)bounce_db_put(s);
      }
    }
  }

  log_write(LS_SYSTEM, L_INFO, 0,
            "bouncer_persist: restored %d sessions (%d migrated from v7, "
            "%d from v8-v11)", restored, migrated_v7, migrated);
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

/** Announce our session @a s on the link @a link: one BS C, its state as
 * it is now, and note what was announced there (hs_announced_*). */
static void bounce_send_bsc(struct BouncerSession *s, struct Client *link)
{
  char chanbuf[512];

  build_channel_string(s, chanbuf, sizeof(chanbuf));
  if (s->hs_state == BOUNCE_HOLDING) {
    sendcmdto_one(&me, CMD_BOUNCER_SESSION, link,
                  "C %s %s %s holding %Tu %Tu %u %Tu :%s",
                  s->hs_account, s->hs_sessid, s->hs_token,
                  s->hs_created, s->hs_disconnect_time,
                  s->hs_attach_count, s->hs_total_active,
                  chanbuf);
  } else {
    sendcmdto_one(&me, CMD_BOUNCER_SESSION, link,
                  "C %s %s %s active %Tu %u %Tu :%s",
                  s->hs_account, s->hs_sessid, s->hs_token,
                  s->hs_created,
                  s->hs_attach_count, s->hs_total_active,
                  chanbuf);
  }
  s->hs_announced_serial = cli_serv(link) ? cli_serv(link)->link_serial : 0;
  s->hs_announced_holding = (s->hs_state == BOUNCE_HOLDING);
  ircd_strncpy(s->hs_announced_sessid, s->hs_sessid,
               sizeof(s->hs_announced_sessid));
}

/** Announce our live primary of session @a s on the link @a link, outside
 * a burst: its BS A, as an attach sends it.  A held copy the peer has of
 * the session yields to it (bounce_bsa_yields()). */
static void bounce_send_primary_bsa(struct BouncerSession *s, struct Client *link)
{
  struct Client *p = s->hs_client;

  if (p && MyConnect(p) && IsUser(p) && !IsBouncerAlias(p) && !IsBouncerHold(p))
    sendcmdto_one(&me, CMD_BOUNCER_SESSION, link, "A %s %s %s %lu 0",
                  s->hs_account, s->hs_sessid, cli_yxx(p),
                  (unsigned long)s->hs_last_active);
}

/** Announce our session @a s on the link @a link as a link burst does: its
 * BS C, the counts and the oper grant replicas keep, its primary's BS A
 * when the primary (live or a held ghost) is ours, and its Keycloak id.
 * The aliases' BX C lines are the burst's own (bounce_burst()).
 *
 * Outside a burst (@a burst 0) a BS A says a client attached, and its
 * receiver makes its record active: for a held ghost of ours the line is
 * the BS D a hold sends instead. */
static void bounce_announce_session_to(struct BouncerSession *s,
                                       struct Client *link, int burst)
{
  bounce_send_bsc(s, link);
  /* The connection count is not on the BS C line (positional, kept
   * as is for older peers); it rides on BX U like la= and aw=. */
  if (s->hs_client && cli_user(s->hs_client) && cli_user(s->hs_client)->server)
  {
    sendcmdto_one(&me, CMD_BOUNCER_TRANSFER, link, "U %s%s cc=%u",
                  cli_yxx(cli_user(s->hs_client)->server),
                  cli_yxx(s->hs_client), s->hs_connect_count);
    /* BS C does not update a replica that already exists: ta= does,
     * by the larger figure. */
    sendcmdto_one(&me, CMD_BOUNCER_TRANSFER, link, "U %s%s ta=%Tu",
                  cli_yxx(cli_user(s->hs_client)->server),
                  cli_yxx(s->hs_client), s->hs_total_active);
  }
  /* Follow with BS O if this session carries an oper grant, so
   * the newly-linked peer records it on its session.  Without
   * the burst replay, a grant set before the link existed would
   * never reach the new peer, and the peer would silently demote
   * the session if it later took over as primary or restarted.
   * Empty grant: nothing to send (default state). */
  if (s->hs_oper_name[0])
    sendcmdto_one(&me, CMD_BOUNCER_SESSION,
                  link,
                  "O %s %s %Tu %s",
                  s->hs_account, s->hs_sessid,
                  s->hs_oper_granted_at, s->hs_oper_name);

  /* Follow with BS A so the receiver can resolve hs_client
   * for alias support.  Applies to both HOLDING (ghost) and
   * ACTIVE (live primary) sessions — without this, leaves
   * can't activate the alias path for held sessions and get
   * nick collisions instead.
   *
   * Extended format (per redesign C.3 + B.1): carries the primary's
   * last_active and caps so the receiver can populate per-connection
   * activity for D.2 tiebreaking.  Primary doesn't track per-conn
   * caps separately (caps live on session-level umode flags); pass
   * 0.  Receiver parses last_active into hs_last_active when the
   * numeric matches the primary (not in hs_aliases roster).
   *
   * Only for a primary of ours.  The line carries the 3-character
   * numeric, which the receiver reads as one of ours (we are the
   * sender): a primary of another server -- our record follows a
   * peer's live primary after our held copy yielded to it, or mirrors
   * a third server's session -- would be read as whichever client of
   * ours has that numeric.  Its own server announces it to its links. */
  if (s->hs_client && MyConnect(s->hs_client) && !burst
      && IsBouncerHold(s->hs_client)) {
    char chanbuf[512];
    build_channel_string(s, chanbuf, sizeof(chanbuf));
    sendcmdto_one(&me, CMD_BOUNCER_SESSION, link, "D %s %s %s %Tu :%s",
                  s->hs_account, s->hs_sessid, cli_yxx(s->hs_client),
                  s->hs_disconnect_time, chanbuf);
  } else if (s->hs_client && MyConnect(s->hs_client))
    sendcmdto_one(&me, CMD_BOUNCER_SESSION,
                  link,
                  "A %s %s %s %lu 0",
                  s->hs_account, s->hs_sessid,
                  cli_yxx(s->hs_client),
                  (unsigned long)s->hs_last_active);

  /* The Keycloak user the session belongs to (a new peer's attach
   * gate and merges read it).  After BS A: the receiver files it under
   * the session whose primary BS A just resolved. */
  if (account_id_valid(s->hs_kc_id) && s->hs_client
      && cli_user(s->hs_client) && cli_user(s->hs_client)->server)
    sendcmdto_one(&me, CMD_BOUNCER_TRANSFER, link, "U %s%s kcid=%s",
                  cli_yxx(cli_user(s->hs_client)->server),
                  cli_yxx(s->hs_client), s->hs_kc_id);
}

/** Send all local sessions as BS C messages during server BURST. */
void bounce_burst(struct Client *cptr)
{
  int i;
  struct BouncerSession *s;

  /* BS / BX are IRCv3-aware extensions — legacy peers (X3, vanilla ircu)
   * log PARSE ERROR on receipt.  No-op burst for non-aware peers. */
  if (!IsIRCv3Aware(cptr))
    return;

  /* No gate check — sessions may exist via CRFLAG_BOUNCER class even when
   * the global bouncer feature is off.  Empty hash = no-op loop. */

  for (i = 0; i < BOUNCE_TOKEN_HASHSIZE; i++) {
    for (s = tokenHash[i]; s; s = s->hs_tnext) {
      bounce_announce_session_to(s, cptr, 1);

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
          size_t chans_len = 0;
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
            if (chans_len > 0)
              str_appendf(alias_chans, sizeof(alias_chans), &chans_len, " ");
            /* Per redesign F.2: ride-along JOIN msgid as
             * "<chan>@<msgid>" so receivers replicate single-msgid
             * invariant on alias rejoin during burst. */
            if (memb->join_msgid[0])
              str_appendf(alias_chans, sizeof(alias_chans), &chans_len,
                          "%s@%s", memb->channel->chname, memb->join_msgid);
            else
              str_appendf(alias_chans, sizeof(alias_chans), &chans_len,
                          "%s", memb->channel->chname);
          }

          alias_modes = umode_str(alias);
          {
            const char *alias_profile =
              s->hs_aliases[a].ba_active_profile[0]
                ? s->hs_aliases[a].ba_active_profile
                : PERSISTENCE_PROFILE_DEFAULT;
            sendcmdto_one(&me, CMD_BOUNCER_TRANSFER, cptr,
                          "C %s %s %s %s %s%s %s :%s",
                          primary_full,
                          s->hs_aliases[a].ba_numeric,
                          s->hs_account,
                          s->hs_sessid,
                          *alias_modes ? "+" : "+",
                          alias_modes,
                          alias_profile,
                          alias_chans);
          }

          /* Emit current caps for aliases hosted locally — peers
           * receive BX C without caps via the standard burst path,
           * so without this they fall back to IsMultiline proxy and
           * may pick the wrong dispatch (BX M vs BX E) for routing.
           * Only authoritative for locally-hosted aliases; ba_caps
           * for remote-hosted aliases is replicated state and could
           * be stale. */
          if (0 == strcmp(s->hs_aliases[a].ba_server, cli_yxx(&me))
              && s->hs_aliases[a].ba_caps_known) {
            char hex[12];
            ircd_snprintf(0, hex, sizeof(hex), "%x",
                          s->hs_aliases[a].ba_caps);
            sendcmdto_one(&me, CMD_BOUNCER_TRANSFER, cptr,
                          "U %s caps=%s",
                          s->hs_aliases[a].ba_numeric, hex);
          }
          /* And its own away state (AWAY * in particular), which the
           * peer's attention rule must not read off the mirror. */
          if (0 == strcmp(s->hs_aliases[a].ba_server, cli_yxx(&me))
              && alias && MyConnect(alias) && cli_connect(alias)
              && con_pre_away(cli_connect(alias)) != 0)
            sendcmdto_one(&me, CMD_BOUNCER_TRANSFER, cptr,
                          "U %s aw=%d",
                          s->hs_aliases[a].ba_numeric,
                          con_pre_away(cli_connect(alias)));

          /* Per redesign C.3 + B.1 + B.6: emit BS A per alias to carry
           * per-alias last_active + caps so the receiver can populate
           * its alias-roster ba_last_active + ba_caps for D.2
           * tiebreaking and BX M dispatch.  Only emit for locally-
           * hosted aliases — remote-hosted aliases will be bursted by
           * their home server's BS A. */
          if (0 == strcmp(s->hs_aliases[a].ba_server, cli_yxx(&me))) {
            /* ba_numeric is YYXXX; BS A carries the XXX suffix.  The
             * receiver constructs full = sptr's YY + XXX which is
             * correct since sender == alias's home. */
            sendcmdto_one(&me, CMD_BOUNCER_SESSION, cptr,
                          "A %s %s %s %lu %x",
                          s->hs_account, s->hs_sessid,
                          s->hs_aliases[a].ba_numeric + 2,
                          (unsigned long)s->hs_aliases[a].ba_last_active,
                          s->hs_aliases[a].ba_caps);
          }
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
    sendcmdto_serv_butone_v3(&me, CMD_BOUNCER_SESSION,
                          NULL,
                          "C %s %s %s active %Tu %u %Tu :%s",
                          session->hs_account, session->hs_sessid,
                          session->hs_token, session->hs_created,
                          session->hs_attach_count,
                          session->hs_total_active,
                          chanbuf);
    break;

  case 'A': /* Attach */
  {
    /* Per redesign C.3 + B.1: extended BS A carries the attaching
     * connection's per-conn last_active + caps.  Look up the matching
     * alias entry in hs_aliases by full numeric (our YY + extra XXX);
     * if found, use ba_last_active + ba_caps.  Otherwise treat as a
     * primary attach — use session-level hs_last_active, caps=0. */
    time_t la = session->hs_last_active;
    unsigned int caps = 0;
    if (extra && *extra) {
      char full_numeric[6];
      int i;
      ircd_snprintf(0, full_numeric, sizeof(full_numeric), "%s%s",
                    cli_yxx(&me), extra);
      for (i = 0; i < session->hs_alias_count; i++) {
        if (0 == strcmp(session->hs_aliases[i].ba_numeric, full_numeric)) {
          la = session->hs_aliases[i].ba_last_active;
          caps = session->hs_aliases[i].ba_caps;
          break;
        }
      }
    }
    sendcmdto_serv_butone_v3(&me, CMD_BOUNCER_SESSION,
                          NULL,
                          "A %s %s %s %lu %x",
                          session->hs_account, session->hs_sessid,
                          extra ? extra : "",
                          (unsigned long)la, caps);
    bounce_emit_session_kc_id(session);
    break;
  }

  case 'D': /* Detach */
    build_channel_string(session, chanbuf, sizeof(chanbuf));
    sendcmdto_serv_butone_v3(&me, CMD_BOUNCER_SESSION,
                          NULL,
                          "D %s %s %s %Tu :%s",
                          session->hs_account, session->hs_sessid,
                          session->hs_ghost_numeric,
                          session->hs_disconnect_time,
                          chanbuf);
    break;

  case 'X': /* Destroy */
    sendcmdto_serv_butone_v3(&me, CMD_BOUNCER_SESSION,
                          NULL,
                          "X %s %s",
                          session->hs_account, session->hs_sessid);
    break;

  case 'U': /* Update */
    sendcmdto_serv_butone_v3(&me, CMD_BOUNCER_SESSION,
                          NULL,
                          "U %s %s %s",
                          session->hs_account, session->hs_sessid,
                          extra ? extra : "");
    break;

  case 'O': /* Oper grant set/clear.  @a extra is the opername; pass
             * NULL or empty to clear.  Receivers apply the grant to
             * any local session members and persist it on the local
             * session record so server-restart restores it. */
    if (extra && *extra)
      sendcmdto_serv_butone_v3(&me, CMD_BOUNCER_SESSION,
                            NULL,
                            "O %s %s %Tu %s",
                            session->hs_account, session->hs_sessid,
                            session->hs_oper_granted_at, extra);
    else
      sendcmdto_serv_butone_v3(&me, CMD_BOUNCER_SESSION,
                            NULL,
                            "O %s %s",
                            session->hs_account, session->hs_sessid);
    break;
  }
}

/** Our held copy of @a s yields to @a peer, the live primary of the same
 * session on the server @a sptr, behind our link @a cptr (the live copy
 * wins, user 2026-10-24).  The caller has decided that it yields
 * (bounce_same_session_yields(), bounce_bsa_yields()): at the peer's BS C
 * when its copy is live there, or at its BS A when its copy goes live.
 *
 * The primary slot takes the peer's primary first (account and Keycloak
 * checked): a refused install yields nothing.  Then our record is
 * active, follows the peer's primary (origin, numeric), and is no longer
 * persisted; our session's live connections follow the peer's primary,
 * and the aware links learn ours as its aliases (a held session's aliases
 * are not in our burst).  An alias carries its primary's nick, and the
 * peer's primary may have another one: a local alias takes it, its own
 * socket told first (":old!user@host NICK new").  Last our ghost leaves
 * as a held ghost does: BX X toward the aware links, a Q toward the
 * legacy ones, which know the peer's primary by its own N.
 *
 * Burst-order invariant (see project_bx_r_yield_burst_order): by the
 * time we process the peer's BS C or BS A, our own N for the ghost has
 * already shipped over the same link, so the peer has it as a Client; the
 * exit's normal Q/BX X cleans that up (suppressing it, formerly via
 * FLAG_KILLED, left a stale ghost in NAMES).
 *
 * @param[in,out] s    Our record of the session.
 * @param[in]     peer The peer's live primary of it.
 * @param[in]     cptr The link the announcement came over.
 * @param[in]     sptr The server that announced it.
 * @param[in]     site "BS C" or "BS A", for the log.
 * @return 1 if our copy yielded, 0 if nothing changed.
 */
static int bounce_held_copy_yields(struct BouncerSession *s,
                                   struct Client *peer, struct Client *cptr,
                                   struct Client *sptr, const char *site)
{
  struct Client *ours = s->hs_client;
  struct Client *ghost = (ours && MyConnect(ours) && IsBouncerHold(ours))
                         ? ours : NULL;
  int i;

  if (!bounce_hs_client_assign_checked(s, peer, site)) {
    log_write(LS_USER, L_INFO, 0,
              "Bouncer reconcile: not yielding held session %s to %s: "
              "its primary %s could not be installed", s->hs_sessid,
              cli_name(sptr), cli_name(peer));
    return 0;
  }
  log_write(LS_USER, L_INFO, 0,
            "Bouncer reconcile: held session %s of %s yields to %s's "
            "live primary %s%s%s (%s)", s->hs_sessid, s->hs_account,
            cli_name(sptr), cli_name(peer), ghost ? "; ghost " : "",
            ghost ? cli_name(ghost) : "", site);
  if (t_active(&s->hs_hold_timer))
    timer_del(&s->hs_hold_timer);
  s->hs_state = BOUNCE_ACTIVE;
  s->hs_disconnect_time = 0;
  s->hs_last_active = CurrentTime;
  s->hs_restore_pending = 0;
  ircd_strncpy(s->hs_origin, cli_yxx(cli_user(peer)->server),
               sizeof(s->hs_origin));
  ircd_strncpy(s->hs_ghost_numeric, cli_yxx(peer),
               sizeof(s->hs_ghost_numeric));
  /* The peer's copy is live. */
  bounce_peer_holding_clear(s, sptr);
  /* The persisted record was of our ghost. */
  bounce_db_del(s->hs_sessid);

  for (i = 0; i < s->hs_alias_count; i++) {
    struct Client *alias = findNUser(s->hs_aliases[i].ba_numeric);
    if (!alias || !IsBouncerAlias(alias) || !cli_user(alias))
      continue;
    cli_user(alias)->alias_primary = peer;
    if (!MyConnect(alias))
      continue;
    if (0 != ircd_strcmp(cli_name(alias), cli_name(peer))) {
      sendcmdto_one(alias, CMD_NICK, alias, "%s", cli_name(peer));
      Debug((DEBUG_INFO, "Bouncer reconcile: alias %s renamed to %s "
             "with its new primary", cli_name(alias), cli_name(peer)));
      ircd_strncpy(cli_name(alias), cli_name(peer), NICKLEN + 1);
    }
    bounce_announce_alias(s, alias, peer);
  }

  if (ghost)
    exit_client(cptr, ghost, &me, "Bouncer session moved");
  /* A restored ghost held burst gates; the release runs after this line. */
  bounce_schedule_gate_release();
  return 1;
}

/** Handle incoming BS P10 message from another server.
 *
 * Subcommands:
 *   BS C <account> <sessid> <token> <state> <created> [<disconnect-time>] :<channels>
 *   BS A <account> <sessid> <client-numeric>
 *   BS D <account> <sessid> <disconnect-time> :<channels>
 *   BS X <account> <sessid>
 *   BS U <account> <sessid> <field>=<value>
 *   BS O <account> <sessid> [<granted_at> <opername>]  (oper grant set/clear)
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

    /* Reconcile against an existing local session for the same token.
     *
     * One session, held here and live on the peer: a restart restored
     * our ghost from MDBX while the peer had the session live, or our
     * primary's socket dropped during a split while the peer promoted an
     * alias of it, and the user's nick there moved on (a same-nick
     * meeting is decided at N time).  The live copy wins (user,
     * 2026-10-24), whichever server either record names as the session's
     * origin -- that only says where it was created or last moved.  Our
     * ghost leaves, and our record follows the peer's primary, which the
     * burst introduced before this BS C: our aliases become its aliases.
     * Without the yield both faces stay up, and our hold expiry ends the
     * session under the live user.
     *
     * It yields only to a primary we can see under this session's id, so
     * a primary this server refused at N time (a same-nick meeting it
     * kept) never takes the session from our ghost afterwards; never to a
     * different Keycloak user (kept apart, user 2026-10-23); and never
     * with a live primary of ours (bounce_same_session_yields()).
     *
     * Same-state replicas (both holding or both active) are simple
     * dedup: keep what we have.
     *
     * A record of ours with the same id under another token is the same
     * session too: two copies that met with two ids converged on one at
     * an earlier burst (the rename keeps each record's own token), and
     * every later burst announces each under the one id.  It goes through
     * the same rules -- else a held copy of ours never yields to the
     * peer's live one there, and the post-burst reconcile, not told the
     * peer's copy is held, demotes our live primary into it. */
    {
      struct BouncerSession *existing = bounce_find_by_token(token);
      int same_id = 0;
      if (!existing) {
        existing = bounce_find_by_token_sessid(account, sessid);
        same_id = existing != NULL;
      }
      if (existing) {
        struct Client *ours = existing->hs_client;
        struct Client *peer = bounce_peer_session_primary(cptr, account, sessid);
        int ours_live = ours && MyConnect(ours) && !IsBouncerHold(ours);
        int kc_conflict = peer && bounce_rebind_kc_conflict(
                                    bounce_session_kc_id(existing),
                                    cli_user(peer)->kc_id);

        /* The peer's copy, as the post-burst reconcile reads it: held
         * there, or not (bounce_peer_holds). */
        if (is_holding)
          bounce_peer_holding_note(existing, sptr, cptr);
        else
          bounce_peer_holding_clear(existing, sptr);

        if (existing->hs_state == BOUNCE_HOLDING && !is_holding
            && session_has_local_holder(existing)
            && !bounce_same_session_yields(1, ours_live, 1, peer != NULL,
                                           kc_conflict)) {
          log_write(LS_USER, L_INFO, 0,
                    "Bouncer reconcile: not yielding held session %s to %s: %s",
                    sessid, cli_name(sptr),
                    ours_live ? "its primary is live here"
                    : kc_conflict ? "Keycloak ids differ"
                    : "its live primary is not known here");
        }
        if (bounce_same_session_yields(existing->hs_state == BOUNCE_HOLDING
                                         && session_has_local_holder(existing),
                                       ours_live, !is_holding, peer != NULL,
                                       kc_conflict))
          bounce_held_copy_yields(existing, peer, cptr, sptr, "BS C");
        /* A copy announced under its own token goes on, as it always has
         * (a server behind us may not have it). */
        if (same_id)
          goto bsc_forward;
        return 0;
      }
    }

    /* Cross-sessid convergence: if we have an existing local session
     * for this account with a DIFFERENT sessid, don't create a
     * duplicate.  Instead, deterministically pick a winning sessid
     * (the lower by strcmp -- on the base64 form, so not always the older
     * UUID v7; both ends compare the same strings) and rename our local
     * session to that sessid if peer's wins.
     * Both sides see the same sessids, both compute the same winner,
     * both end up agreeing on a single sessid for the logical session.
     *
     * Per redesign D.3: convergence is deterministic — same inputs +
     * same algorithm → same answer on both sides.  No coordination
     * protocol needed. */
    {
      struct AccountSessions *as_existing =
          bounce_find_by_account(account);
      if (as_existing && as_existing->as_sessions) {
        struct BouncerSession *local, *s2;
        struct BouncerSession *followed = NULL, *held_here = NULL;
        /* The announced session's primary, introduced earlier from the
         * announcing side under this id (the burst sends users before
         * sessions); NULL outside a burst, where a fresh session's BS C
         * goes out before its primary's N. */
        struct Client *peer = bounce_peer_session_primary(cptr, account, sessid);
        enum bounce_session_outcome outcome;

        /* The record the announcement is compared with
         * (bounce_bsc_compare_with): one that carries the id already
         * (it took it before: nothing to converge); else the one whose
         * primary is the announced session's primary (a merge at N time
         * made ours its connections); else the first one we hold here;
         * else the first.  The account's first record, whatever it was,
         * compared the peer's session with another of ours once an
         * account had two. */
        if (peer) {
          followed = bounce_session_of_primary(peer);
          if (followed && followed->hs_client != peer)
            followed = NULL;
        }
        for (s2 = as_existing->as_sessions; s2 && !held_here; s2 = s2->hs_anext)
          if (session_has_local_holder(s2))
            held_here = s2;
        switch (bounce_bsc_compare_with(
                  bounce_find_by_token_sessid(account, sessid) != NULL,
                  followed != NULL, held_here != NULL)) {
        case BOUNCE_BSC_SAME_ID:
          goto bsc_forward;
        case BOUNCE_BSC_FOLLOWED:
          local = followed;
          break;
        case BOUNCE_BSC_HELD_HERE:
          local = held_here;
          break;
        case BOUNCE_BSC_FIRST:
        default:
          local = as_existing->as_sessions;
          break;
        }

        /* A session of a different Keycloak user (the account was
         * recreated while the network was split) is neither merged into
         * ours nor retires it, and is not mirrored here (user,
         * 2026-10-23).  BS C carries no id: the peer session's primary,
         * introduced earlier in the burst, does.  The peer does the same
         * with ours.  Outside a burst a fresh session's BS C goes out
         * before its primary's N, so this finds nothing; what follows
         * then retires a held session of ours (ending it, not tying it)
         * or renames by age -- neither re-ties an id. */
        if (peer && bounce_rebind_kc_conflict(bounce_session_kc_id(local),
                                              cli_user(peer)->kc_id)) {
          log_write(LS_USER, L_INFO, 0,
                    "BS C: %s's session %s from %s belongs to Keycloak id "
                    "%s, ours (%s) to %s: kept apart", account, sessid,
                    cli_name(sptr), cli_user(peer)->kc_id, local->hs_sessid,
                    bounce_session_kc_id(local));
          goto bsc_forward;
        }

        /* The peer's copy, as the post-burst reconcile reads it: held
         * there, or not (bounce_peer_holds), for a client of the peer
         * admitted under either id (bounce_in_session_by_id). */
        if (is_holding)
          bounce_peer_holding_note(local, sptr, cptr);
        else
          bounce_peer_holding_clear(local, sptr);

        /* Our record follows the announced session's primary: a merge at
         * N time made our connections that session's (our live primary
         * lost a same-nick merge and is its alias, or our held ghost
         * yielded to it), and our record still carries its own id.  One
         * session, one id: the one the peer ends with when it reads what
         * we announced on its link (bounce_follow_keeps_id).  Ours stays
         * only when the peer takes it; then the peer's clients keep this
         * id on our side, and we note it.  Else ours takes the peer's id,
         * every connection with it, and the later BS A, BS D, BX P and
         * BS X of either server name a record the other has. */
        if (local == followed) {
          int announced = cli_serv(cptr)
                          && local->hs_announced_serial == cli_serv(cptr)->link_serial
                          && 0 == strcmp(local->hs_announced_sessid, local->hs_sessid);
          if (bounce_follow_keeps_id(announced, local->hs_announced_holding,
                                     local->hs_announced_sessid, is_holding,
                                     sessid)) {
            log_write(LS_USER, L_INFO, 0,
                      "BS C: our record %s of %s follows %s's primary %s, "
                      "announced under %s: %s takes our id", local->hs_sessid,
                      account, cli_name(sptr), cli_name(peer), sessid,
                      cli_name(sptr));
            bounce_peer_sessid_note(local, sessid, sptr);
          } else {
            log_write(LS_USER, L_INFO, 0,
                      "BS C: our record %s of %s follows %s's primary %s: it "
                      "takes the session's id %s", local->hs_sessid, account,
                      cli_name(sptr), cli_name(peer), sessid);
            bounce_session_take_id(local, sessid);
          }
          goto bsc_forward;
        }

        /* Outside a burst the announcement is a session the peer just
         * made (a login there that found none of ours, or a connection in
         * no session turning +b) while ours is live
         * (bounce_bsc_fresh_apart): the two stay apart until the next
         * link burst.  Renaming either into the other's id here would put
         * two live primaries under one id with no reconcile to merge
         * them, and the lines keyed by that id (a promote's BX P) would
         * move one server's record onto the other's primary.  Not
         * mirrored, so BX C never files the peer's aliases into ours. */
        if (bounce_bsc_fresh_apart(IsBurstOrBurstAck(sptr),
                                   local->hs_state == BOUNCE_HOLDING,
                                   is_holding)) {
          log_write(LS_USER, L_INFO, 0,
                    "BS C: %s's new session %s of %s stays apart from ours %s "
                    "until the next link burst", cli_name(sptr), sessid,
                    account, local->hs_sessid);
          unmirrored_mark(account, sessid, sptr);
          goto bsc_forward;
        }

        /* State outranks age: the record with a live primary is the
         * account's one identity.  When ours is HOLDING (a held ghost or
         * a clientless replica) and the peer's is active, ours is
         * retired here -- a held ghost leaves with a normal Q and a BS X
         * (invariant 7), a bare replica is just dropped -- and the peer's
         * session is built below.  When the peer's is the holding one
         * and ours is active, ours simply wins; the peer applies the
         * same rule to our BS C and retires its own.  Only equal states
         * fall through to the sessid-age rename/skip below.
         *
         * Ours is retired only when nothing of it is live: a held ghost
         * whose session still has a live alias (or a live primary under
         * a holding record) is held only in name, and retiring it would
         * exit those devices (bounce_kill_session exits every alias).
         * It is read with the predicate the same-nick verdict reads, on
         * this session, the one the retire would end.  Such a session is
         * kept apart: it keeps its id and the peer's is not mirrored
         * here, as the peer, reading our announced "holding", keeps its
         * own and skips ours (bounce_session_converge).  Taking the
         * peer's id instead would make our record the one the peer's
         * BS A and BS D for its own primary resolve to here.  The peer's
         * id is marked unmirrored, so BX C never files its aliases into
         * ours.  Nothing here merges the two while they stay as they
         * are: they meet again at a later link burst, by these rules.
         * When the peer's ends first, its BS X names the id marked here,
         * and we announce ours to it again (bounce_bsx_reannounces): it
         * mirrors ours, and a login there attaches to it. */
        {
          int local_live =
            (local->hs_client && MyConnect(local->hs_client))
              ? !bounce_session_held(local, local->hs_client)
              : bounce_session_has_live_alias(local);
          outcome = bounce_session_converge(local->hs_state == BOUNCE_HOLDING,
                                            session_has_local_holder(local),
                                            local_live, local->hs_sessid,
                                            is_holding, sessid);

          if (outcome == BSO_RETIRE) {
            log_write(LS_USER, L_INFO, 0,
                      "Bouncer reconcile: retiring held session %s for %s "
                      "-- %s announces live session %s",
                      local->hs_sessid, account, cli_name(sptr), sessid);
            bounce_retire_held_session(local, local->hs_client, cptr,
                                       "Bouncer session moved");
            goto bsc_create;
          }
          if (outcome == BSO_DROP_REPLICA) {
            Debug((DEBUG_INFO, "BS C: dropping clientless holding replica "
                   "%s for %s -- %s announces live session %s",
                   local->hs_sessid, account, cli_name(sptr), sessid));
            bounce_destroy(local);
            goto bsc_create;
          }
          if (local->hs_state == BOUNCE_HOLDING && !is_holding) {
            log_write(LS_USER, L_INFO, 0,
                      "Bouncer reconcile: not retiring held session %s for "
                      "%s -- it still has a live connection here; kept apart "
                      "from %s's live session %s", local->hs_sessid, account,
                      cli_name(sptr), sessid);
            unmirrored_mark(account, sessid, sptr);
            goto bsc_forward;
          }
          if (local->hs_state == BOUNCE_ACTIVE && is_holding) {
            Debug((DEBUG_INFO, "BS C: local live session %s for %s wins over "
                   "peer's holding %s; skipping replica",
                   local->hs_sessid, account, sessid));
            /* Not mirrored, and never renamed into: an alias of it is
             * not ours (its server ends it, or keeps it apart). */
            unmirrored_mark(account, sessid, sptr);
            goto bsc_forward;
          }
        }

        if (outcome == BSO_RENAME) {
          /* Peer's sessid is the lower (strcmp) — peer wins.
           * Rename our local session to peer's sessid so future BX C
           * / BS A by-sessid lookups resolve to our state; every
           * connection the record names takes it too (they must agree
           * post-convergence). */
          Debug((DEBUG_INFO,
                 "BS C: cross-sessid convergence — renaming local "
                 "session %s → %s for account %s (peer wins)",
                 local->hs_sessid, sessid, account));
          bounce_session_take_id(local, sessid);
        } else {
          /* We win — the peer renames when it processes our BS C (in the
           * same burst: it reads ours after its own users, by the same
           * rule), and its clients keep the id they were introduced
           * under on our side: noted, so the post-burst reconcile still
           * finds them.  Skip creating duplicate; forward peer's BS C
           * downstream. */
          Debug((DEBUG_INFO,
                 "BS C: cross-sessid convergence — local session %s "
                 "wins over peer's %s (account %s); skipping replica",
                 local->hs_sessid, sessid, account));
          if (IsBurstOrBurstAck(sptr))
            bounce_peer_sessid_note(local, sessid, sptr);
        }
        goto bsc_forward;
      }
    }

    /* Create session from remote data */
  bsc_create:
    unmirrored_clear(account, sessid);
    session = (struct BouncerSession *)MyCalloc(1, sizeof(*session));
    ircd_strncpy(session->hs_account, account, ACCOUNTLEN + 1);
    ircd_strncpy(session->hs_sessid, sessid, BOUNCER_SESSID_LEN);
    ircd_strncpy(session->hs_token, token, BOUNCER_TOKEN_LEN + 1);
    session->hs_name[0] = '\0';
    session->hs_client = NULL; /* Remote session */
    ircd_strncpy(session->hs_origin, cli_yxx(sptr),
                 sizeof(session->hs_origin));
    session->hs_hold_override = -1;
    session->hs_effective_away = 0;
    session->hs_effective_away_msg[0] = '\0';
    session->hs_created = created;
    session->hs_last_active = created;
    session->hs_attach_count = attach_count;
    session->hs_total_active = total_active;

    if (is_holding) {
      session->hs_state = BOUNCE_HOLDING;
      session->hs_enforced = 0; /* Phase 3: cleared on transition to HOLDING */
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

      ircd_strncpy(chanlist, channels, sizeof(chanlist));
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

bsc_forward:
    /* Forward to other servers — preserve all parameters verbatim so
     * downstream servers get full metadata (attach_count, total_active). */
    if (is_holding) {
      sendcmdto_serv_butone_v3(sptr, CMD_BOUNCER_SESSION,
                            cptr,
                            "C %s %s %s holding %Tu %Tu %u %Tu :%s",
                            account, sessid, token,
                            created, disconnect_time,
                            attach_count, total_active,
                            channels ? channels : "");
    } else {
      sendcmdto_serv_butone_v3(sptr, CMD_BOUNCER_SESSION,
                            cptr,
                            "C %s %s %s active %Tu %u %Tu :%s",
                            account, sessid, token,
                            created,
                            attach_count, total_active,
                            channels ? channels : "");
    }
    /* A new session just landed (or an existing one was renamed via
     * cross-sessid).  If any pending registrations were deferred at
     * bounce_auto_resume waiting for exactly this signal (steady-state
     * BS C race guard, BOUNCE_RESUME_DEFER_PEER_INBOUND), retry them
     * now — bounce_auto_resume's second pass will find the session
     * and take the alias-attach path instead of creating a parallel
     * primary. */
    bounce_drain_pending_registrations();
    break;
  }

  case 'A': /* Attach */
  {
    enum bounce_bsa_action bsa;
    struct Client *slot;
    int slot_ours;

    session = bounce_find_by_token_sessid(account, sessid);
    if (!session)
      return 0;
    slot = session->hs_client;
    slot_ours = slot && MyConnect(slot) && IsUser(slot) && !IsBouncerAlias(slot);
    /* What the line does to our record.  An old form names no client: a
     * primary attached there, which changes nothing while our own client
     * holds the slot either. */
    bsa = slot_ours ? BOUNCE_BSA_IGNORE : BOUNCE_BSA_NUMERIC;

    /* Resolve primary client from numeric so remote servers can use
     * session->hs_client for alias creation.
     * BS A sends the 3-char client numeric (XXX) relative to the
     * *sender's* server prefix (sptr's YY).  Combine with sptr's YY
     * for findNUser().
     *
     * The earlier version of this code prepended session->hs_origin
     * which is the *recorded historical* origin and may be stale
     * after a cross-server rebind (bounce_rebind_ghost_to_remote_primary
     * explicitly preserves hs_origin "as-is" per its comment).  When
     * stale, the resolution targets the wrong server's local numeric
     * space.  If a leftover ghost happens to occupy that numeric
     * (e.g. another session restored at startup from MDBX with a
     * different account), session->hs_client gets pointed at it, and
     * a subsequent register_user drain for the rebound primary's
     * account revives the wrong ghost — silently hijacking the
     * connecting user's socket onto an unrelated account's ghost.
     *
     * Same handler at the alias-roster lookup below already uses
     * cli_yxx(sptr); this site should match.
     *
     * Update hs_ghost_numeric to the new XXX too (unless the line
     * changes nothing of ours, below) — after a
     * managing-server restart the ghost gets a freshly-assigned
     * numeric, and the persisted hs_ghost_numeric on this side is
     * stale.  bounce_auto_resume's fallback path (when hs_client
     * happens to be NULL) reads hs_ghost_numeric to do its own
     * findNUser; without this refresh, that lookup would resolve to
     * the old (now-recycled or non-existent) numeric and reattach
     * fails, forcing /bouncer reset.
     *
     * What the line may change is bounce_bsa_action()'s: never an alias
     * or a client our record lists as one in the slot (a burst sends a
     * BS A per alias of the sender, for its activity: those update only
     * their roster entry below), never a client of ours, and nothing at
     * all while our own live primary or held ghost holds the slot -- a
     * peer's burst announces its copy of the session, and only we decide
     * what our client is (BS C's yield, the same-nick decisions, the
     * post-burst reconcile).  Then the numeric we keep stays too. */
    if (parc >= 5 && parv[4][0]) {
      char full_numeric[6];
      struct Client *primary;
      int resolved, cand_alias, cand_roster, cand_ours;
      ircd_snprintf(0, full_numeric, sizeof(full_numeric), "%s%s",
                    cli_yxx(sptr), parv[4]);
      primary = findNUser(full_numeric);
      resolved = primary && IsUser(primary);
      /* A primary of another Keycloak user is a session kept apart after
       * a split that shares this sessid: none of its BS A applies here
       * (user, 2026-10-23). */
      if (resolved && cli_user(primary)
          && bounce_rebind_kc_conflict(session->hs_kc_id, cli_user(primary)->kc_id)) {
        log_write(LS_USER, L_INFO, 0, "BS A: session %s of %s belongs to Keycloak "
                  "id %s, %s's attach carries %s: not applied", session->hs_sessid,
                  session->hs_account, session->hs_kc_id, cli_name(sptr),
                  cli_user(primary)->kc_id);
        goto bsa_forward;
      }
      cand_alias = resolved && IsBouncerAlias(primary);
      cand_roster = resolved && session_roster_has(session, primary);
      cand_ours = resolved && MyConnect(primary);
      bsa = bounce_bsa_action(resolved, cand_alias, cand_roster, cand_ours,
                              slot_ours);
      /* An install the account or Keycloak check refuses changes nothing
       * either. */
      if (bsa == BOUNCE_BSA_INSTALL
          && !bounce_hs_client_assign_checked(session, primary, "BS A"))
        bsa = BOUNCE_BSA_IGNORE;
      if (bsa != BOUNCE_BSA_IGNORE)
        ircd_strncpy(session->hs_ghost_numeric, parv[4],
                     sizeof(session->hs_ghost_numeric));

      /* Outside a burst the line says a member attached to the sender's
       * copy: it is live there.  While ours is only held here -- our held
       * ghost in the slot -- the live copy wins, as at BS C: our copy
       * yields to the client the line names, a live member of the session
       * we can see behind that link (in it by its session id, or by the
       * id its server announced it under before taking ours). */
      if (bsa == BOUNCE_BSA_IGNORE && slot_ours && IsBouncerHold(slot)) {
        int member = resolved && !cand_alias && !cand_roster && !cand_ours
                     && cli_from(primary) == cptr
                     && bounce_in_session_by_id(session, primary);
        int kc_conflict = resolved && cli_user(primary)
                          && bounce_rebind_kc_conflict(bounce_session_kc_id(session),
                                                       cli_user(primary)->kc_id);
        if (bounce_bsa_yields(IsBurstOrBurstAck(sptr), 1, member,
                              session->hs_state == BOUNCE_HOLDING
                                && session_has_local_holder(session),
                              kc_conflict)
            && bounce_held_copy_yields(session, primary, cptr, sptr, "BS A"))
          bsa = BOUNCE_BSA_INSTALL;
      }

      /* A line that changed nothing of ours says why (a yield above logs
       * its own line instead). */
      if (bsa == BOUNCE_BSA_IGNORE && cand_alias)
        /* A burst's per-alias line: its roster entry only, below. */
        Debug((DEBUG_INFO, "BS A: %s names alias %s for session %s: its "
               "roster entry only", cli_name(sptr), full_numeric,
               session->hs_sessid));
      else if (bsa == BOUNCE_BSA_IGNORE)
        log_write(LS_USER, L_INFO, 0, "BS A: %s names %s for %s's session %s: "
                  "not installed, %s%s", cli_name(sptr),
                  resolved ? cli_name(primary) : full_numeric,
                  session->hs_account, session->hs_sessid,
                  cand_roster ? "it is on our alias roster"
                  : cand_ours ? "it is a client of ours"
                  : slot_ours ? (IsBouncerHold(slot)
                                 ? "our held ghost holds the primary slot: "
                                 : "our live primary holds the primary slot: ")
                  : "the account or Keycloak check refused it",
                  (!cand_roster && !cand_ours && slot_ours) ? cli_name(slot) : "");
    }

    /* Outside a burst the sender announces that a client attached: its
     * copy of the session is live there now, whatever ours is. */
    if (!IsBurstOrBurstAck(sptr))
      bounce_peer_holding_clear(session, sptr);

    /* Per redesign C.3 + B.1 + B.6: extended BS A carries per-conn
     * last_active + caps after the numeric.  Find the matching alias
     * entry in hs_aliases by full numeric (sptr's YY + parv[4] XXX);
     * if found, update ba_last_active + ba_caps.  If not found, the
     * attaching client is the primary — update session-level
     * hs_last_active.  Older 3-arg form (parc < 7) doesn't carry the
     * new fields; receiver leaves existing values intact. */
    if (parc >= 7 && parv[4][0]) {
      time_t la = (time_t)strtoul(parv[5], NULL, 10);
      unsigned int caps = (unsigned int)strtoul(parv[6], NULL, 16);
      char full_numeric[6];
      int i;
      int matched_alias = 0;
      ircd_snprintf(0, full_numeric, sizeof(full_numeric), "%s%s",
                    cli_yxx(sptr), parv[4]);
      for (i = 0; i < session->hs_alias_count; i++) {
        if (0 == strcmp(session->hs_aliases[i].ba_numeric, full_numeric)) {
          session->hs_aliases[i].ba_last_active = la;
          session->hs_aliases[i].ba_caps = caps;
          session->hs_aliases[i].ba_caps_known = (caps != 0);
          matched_alias = 1;
          break;
        }
      }
      if (!matched_alias && bsa != BOUNCE_BSA_IGNORE) {
        /* Not in alias roster — primary attach.  Caps for primary not
         * separately tracked (they're on the Client's umode flags).  A
         * line that changed nothing of ours (an alias's, or one naming
         * the peer's copy while our client holds the slot) is not our
         * primary's activity. */
        session->hs_last_active = la;
      }
    }

    /* During burst, BS A just associates the session with its ghost
     * numeric — the session keeps its burst state (HOLDING stays
     * HOLDING).  Outside burst, BS A means a real client attached —
     * transition to ACTIVE and cancel the hold timer.  Not while our own
     * client holds the slot: a held ghost of ours keeps its timer (its
     * hold ends our copy), a live one is active already. */
    if (!IsBurstOrBurstAck(sptr) && bsa != BOUNCE_BSA_IGNORE) {
      /* Cancel hold timer */
      if (t_active(&session->hs_hold_timer))
        timer_del(&session->hs_hold_timer);

      session->hs_state = BOUNCE_ACTIVE;
      session->hs_last_active = CurrentTime;
      session->hs_disconnect_time = 0;
    }

  bsa_forward:
    /* Forward — preserve extended fields when present (per C.3) */
    if (parc >= 7) {
      sendcmdto_serv_butone_v3(sptr, CMD_BOUNCER_SESSION,
                            cptr,
                            "A %s %s %s %s %s",
                            account, sessid, parv[4], parv[5], parv[6]);
    } else {
      sendcmdto_serv_butone_v3(sptr, CMD_BOUNCER_SESSION,
                            cptr,
                            "A %s %s %s",
                            account, sessid,
                            (parc >= 5) ? parv[4] : "");
    }
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

    /* Resolve ghost client from numeric so that bounce_auto_resume()
     * can check hs_client for the alias path.  Without this, a new
     * client connecting to a different server can't take the alias path
     * because hs_client would be NULL.
     *
     * Use cli_yxx(sptr) as the prefix — the wire ghost_numeric is the
     * 3-char numeric on the *sending* server.  session->hs_origin is
     * historical metadata and may be stale after a cross-server rebind
     * (see BS A handler above for the full discussion).
     *
     * What the line may change is bounce_bsd_action()'s, decided before
     * anything is written: a ghost of another Keycloak user (a session
     * kept apart that shares the id) changes nothing here; and while our
     * own live primary or held ghost holds the slot, the line announces
     * only that the sender holds its copy -- our record's slot, state,
     * numeric, disconnect time and channels stay ours. */
    {
      char full_numeric[6];
      struct Client *ghost;
      struct Client *slot = session->hs_client;
      int resolved;

      ircd_snprintf(0, full_numeric, sizeof(full_numeric), "%s%s",
                    cli_yxx(sptr), ghost_numeric);
      ghost = findNUser(full_numeric);
      resolved = ghost && IsUser(ghost);
      switch (bounce_bsd_action(resolved && cli_user(ghost)
                                  && bounce_rebind_kc_conflict(session->hs_kc_id,
                                                               cli_user(ghost)->kc_id),
                                slot && MyConnect(slot) && IsUser(slot)
                                  && !IsBouncerAlias(slot))) {
      case BOUNCE_BSD_FORWARD:
        log_write(LS_USER, L_INFO, 0, "BS D: session %s of %s belongs to "
                  "Keycloak id %s, %s's held ghost carries %s: not applied",
                  session->hs_sessid, session->hs_account, session->hs_kc_id,
                  cli_name(sptr), cli_user(ghost)->kc_id);
        goto bsd_forward;
      case BOUNCE_BSD_NOTE:
        bounce_peer_holding_note(session, sptr, cptr);
        log_write(LS_USER, L_INFO, 0, "BS D: %s holds its copy of %s's session "
                  "%s (%s); our %s %s holds the primary slot: not changed",
                  cli_name(sptr), session->hs_account, session->hs_sessid,
                  resolved ? cli_name(ghost) : full_numeric,
                  IsBouncerHold(slot) ? "held ghost" : "live primary",
                  cli_name(slot));
        /* Our copy is live and the sender's just went held: the live copy
         * wins, but this line says nothing of ours, so the sender's held
         * ghost would keep its nick until its hold ran out.  Our
         * primary's BS A, outside a burst, makes that held copy yield to
         * it (bounce_bsa_yields).  Only toward a link with the hold mark:
         * a build without the BS A install guard would install our
         * primary over its held ghost instead. */
        if (bounce_bsd_reannounces(BOUNCE_BSD_NOTE, !IsBouncerHold(slot),
                                   IsHoldMark(cptr))) {
          log_write(LS_USER, L_INFO, 0, "BS D: our live primary %s of %s's "
                    "session %s: announcing it to %s", cli_name(slot),
                    session->hs_account, session->hs_sessid, cli_name(cptr));
          bounce_send_primary_bsa(session, cptr);
        }
        goto bsd_forward;
      case BOUNCE_BSD_APPLY:
        break;
      }
      /* The sender holds its copy now (bounce_peer_holds). */
      bounce_peer_holding_note(session, sptr, cptr);

      session->hs_state = BOUNCE_HOLDING;
      session->hs_enforced = 0; /* Phase 3: cleared on transition to HOLDING */
      session->hs_disconnect_time = disc_time;
      ircd_strncpy(session->hs_ghost_numeric, ghost_numeric,
                   sizeof(session->hs_ghost_numeric));
      if (resolved)
        bounce_hs_client_assign_checked(session, ghost, "BS H");
      else
        session->hs_client = NULL;
    }

    /* Update channels if provided (BURST-style: #chan1:ov,#chan2:o,#chan3) */
    if (channels && *channels) {
      char chanlist[512];
      char *tok, *saveptr;
      int i = 0;

      ircd_strncpy(chanlist, channels, sizeof(chanlist));
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

  bsd_forward:
    /* Forward */
    sendcmdto_serv_butone_v3(sptr, CMD_BOUNCER_SESSION,
                          cptr,
                          "D %s %s %s %Tu :%s",
                          account, sessid, ghost_numeric, disc_time,
                          channels ? channels : "");
    break;
  }

  case 'X': /* Destroy session */
  {
    /* BS X <account> <sessid> — destroy session.  An id we kept apart
     * from ours (unmirrored): the peer's session that stood beside ours
     * has ended. */
    int was_apart = unmirrored_marked(account, sessid);

    unmirrored_clear(account, sessid);
    session = bounce_find_by_token_sessid(account, sessid);
    if (session) {
      struct Client *primary = session->hs_client;

      if (bounce_bsx_keeps(primary != NULL,
                           primary && MyConnect(primary) && IsUser(primary)
                             && !IsBouncerAlias(primary),
                           primary && HasFlag(primary, FLAG_KILLED))) {
        /* We hold the session: its primary is ours, live or a held ghost.
         * The sender ended its own copy -- a held copy's hold ran out, a
         * client of a session sharing this id lost a nick collision, a
         * member there ended it -- and that ends nothing of ours; our
         * KILL path, our hold timer and our own users end it.  Not relayed
         * either: no server behind us is told to end what we hold. */
        log_write(LS_USER, L_INFO, 0,
                  "Bouncer: %s ended %s's session %s, whose primary %s is %s "
                  "here: kept", cli_name(sptr), account, sessid,
                  cli_name(primary), IsBouncerHold(primary) ? "held" : "live");
        bounce_peer_holding_clear(session, sptr);
        break;
      }
      Debug((DEBUG_INFO, "Bouncer: destroy@bs-x-handler sess=%s from=%C",
             session->hs_sessid, sptr));
      bounce_destroy(session);
    }

    /* Forward */
    sendcmdto_serv_butone_v3(sptr, CMD_BOUNCER_SESSION,
                          cptr,
                          "X %s %s",
                          account, sessid);

    /* The peer's session that stood beside ours has ended.  The peer has
     * no copy of ours (it skipped our announcement while its own stood),
     * so its next login of the account would make a session of its own
     * beside ours again.  Announced again on that link, ours is mirrored
     * there and the login attaches to it as an alias: one session, one
     * primary (bounce_bsx_reannounces).  Only toward a link that
     * announces the hold mark. */
    if (was_apart && !session) {
      struct AccountSessions *as_ours = bounce_find_by_account(account);
      struct BouncerSession *s2;
      int held_here = 0;

      for (s2 = as_ours ? as_ours->as_sessions : NULL; s2; s2 = s2->hs_anext)
        if (session_has_local_holder(s2))
          held_here = 1;
      if (bounce_bsx_reannounces(was_apart, held_here, IsHoldMark(cptr))) {
        for (s2 = as_ours->as_sessions; s2; s2 = s2->hs_anext) {
          if (!session_has_local_holder(s2))
            continue;
          /* A Debug line: the common case is a peer's holding session
           * that lost to our live one at a link burst and ended there,
           * after the peer had mirrored ours already, so the line
           * changes nothing on it. */
          Debug((DEBUG_INFO, "BS X: %s ended %s's session %s, kept apart "
                 "from ours %s: announcing ours to %s again", cli_name(sptr),
                 account, sessid, s2->hs_sessid, cli_name(cptr)));
          bounce_announce_session_to(s2, cptr, 0);
        }
      }
    }
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
    sendcmdto_serv_butone_v3(sptr, CMD_BOUNCER_SESSION,
                          cptr,
                          "U %s %s %s",
                          account, sessid, field);
    break;
  }

  case 'O': /* Oper grant set or clear (cross-server propagation) */
  {
    /* Wire forms:
     *   BS O <account> <sessid> <granted_at> <opername>  (set)
     *   BS O <account> <sessid>                          (clear)
     */
    time_t granted_at = 0;
    const char *opername = NULL;

    if (parc >= 6) {
      granted_at = (time_t)atol(parv[4]);
      opername = parv[5];
    } else if (parc != 4) {
      break;  /* malformed */
    }

    session = bounce_find_by_token_sessid(account, sessid);
    if (session)
      bounce_apply_remote_oper_grant(session, opername, granted_at);

    /* Forward to other peers (this server bounces it onward like the
     * other BS subcommands). */
    if (opername && *opername)
      sendcmdto_serv_butone_v3(sptr, CMD_BOUNCER_SESSION,
                            cptr,
                            "O %s %s %Tu %s",
                            account, sessid, granted_at, opername);
    else
      sendcmdto_serv_butone_v3(sptr, CMD_BOUNCER_SESSION,
                            cptr,
                            "O %s %s",
                            account, sessid);
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
                    sizeof(session->hs_origin));
      Debug((DEBUG_INFO, "BS T: session %s/%s ownership transferred to %s",
             account, sessid, new_origin));
    }

    /* Forward */
    sendcmdto_serv_butone_v3(sptr, CMD_BOUNCER_SESSION,
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
 * @param[in] session     Session whose primary is departing.
 * @param[in] local_only  Non-zero: only consider local-server aliases.
 *                        Returns -1 (caller falls through to
 *                        bounce_hold_client) if no local alias exists.
 *                        Used by m_quit.c to do an immediate promote
 *                        only when the chosen alias is on this server
 *                        — same-server alias state is synchronously
 *                        authoritative, so the BX P broadcast can't
 *                        race a concurrent BX X from the alias's
 *                        home server (we ARE the home server).
 * @return 0 on success, -1 if no eligible alias.
 */
int bounce_promote_alias(struct BouncerSession *session, int local_only)
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
  time_t winner_activity = 0;
  const char *me_yxx;

  if (session->hs_alias_count <= 0)
    return -1;

  /* A1: Save old primary reference before any changes.
   * May be NULL in SQUIT path (nulled by bounce_prepare_squit_promotions). */
  old_primary = session->hs_client;
  if (old_primary)
    ircd_snprintf(0, old_numeric, sizeof(old_numeric), "%s%s",
                  cli_yxx(cli_user(old_primary)->server), cli_yxx(old_primary));

  /* A0: the connection the user was actually using wins -- most recent
   * activity (local: the idle clock; remote: the replicated ba_last_active,
   * kept live by BX U la=), ties broken by the oldest connection (lowest
   * cli_firsttime), which was the whole rule while activity only
   * replicated at link time.  When `local_only` is set, candidates on
   * remote servers are skipped — the caller has decided that a
   * cross-server promote is unsafe in its call context (typical:
   * m_quit's immediate-promote path, which can't safely emit BX P
   * against an alias whose home server may be concurrently emitting
   * BX X for it). */
  me_yxx = cli_yxx(&me);
  for (j = 0; j < session->hs_alias_count; j++) {
    struct Client *candidate = findNUser(session->hs_aliases[j].ba_numeric);
    time_t activity;
    if (!candidate || !IsBouncerAlias(candidate))
      continue;
    if (local_only
        && 0 != ircd_strcmp(session->hs_aliases[j].ba_server, me_yxx))
      continue;
    activity = session->hs_aliases[j].ba_last_active;
    if (MyConnect(candidate) && cli_user(candidate)
        && cli_user(candidate)->last > activity)
      activity = cli_user(candidate)->last;
    if (!winner_numeric
        || activity > winner_activity
        || (activity == winner_activity && cli_firsttime(candidate) < oldest_time)) {
      winner_activity = activity;
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
  {
    struct bounce_counts was;

    count_held(alias, &was);
    ClearBouncerAlias(alias);
    /* A primary now, announced: an alias of ours was counted as a socket
     * and a registered user only, an alias another server introduced by
     * BX C nowhere (it is that server's user now, in its count). */
    bounce_count_converted(alias, &was, cli_user(alias)->server, "promote");
  }
  cli_user(alias)->alias_primary = NULL;

  /* Preserve cli_lastnick across the promote.  Earlier this site reset
   * cli_lastnick to CurrentTime under the rationale "ensures promoted
   * alias wins over stale ghosts from reconnect" — but that defense
   * only worked under the classic same-user@host rule (newer wins) and
   * destroyed the session's age signal in every cross-server compare.
   *
   * The same-account override in m_nick.c flips collision resolution
   * to older-wins for matching accounts (so a bouncer session that's
   * existed for 20 minutes correctly beats a freshly-attached peer
   * connection on the other side of a link).  Bumping to CurrentTime
   * here would invert that — the just-promoted alias would lose every
   * cross-server collision against any peer with a stable older TS.
   *
   * The alias's lastnick at this point is the value inherited from
   * primary at bounce_setup_local_alias time (line 6172 in this file),
   * which is the session's original age.  Keep it. */

  /* Add to nick hash (aliases aren't in nick hash) */
  hAddClient(alias);

  /* opers / inv_clients: ClearBouncerAlias above made @a alias a real primary,
   * so reconcile its counting.  Flag-keyed + idempotent: a LOCAL alias was
   * already counted when created (no-op here); a REMOTE alias was never counted
   * (copy_umodes skipped the ineligible remote alias) and is bumped now that it
   * is an eligible primary.  Replaces the old unconditional ++ which double-
   * counted local aliases. */
  userstats_count_sync(alias);

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
  {
    /* Per redesign C.2: detect "we held the primary locally → we no
     * longer hold any local Client" via runtime checks, not hs_origin.
     * Snapshot pre-update; the swap to `alias` happens next. */
    int we_were_holding_primary = (old_primary && MyConnect(old_primary));
    /* Close the attached stretch of the outgoing primary (nothing when
     * the session was held: the hold closed it) and open the new one if
     * the promoted alias is ours; a remote one starts its own stretch on
     * its server when BX P arrives. */
    bounce_accrue_active(session);
    session->hs_attach_time = MyConnect(alias) ? CurrentTime : 0;
    session->hs_client = alias;
    session->hs_state = BOUNCE_ACTIVE;
    session->hs_last_active = CurrentTime;
    session->hs_disconnect_time = 0;
    ircd_strncpy(session->hs_origin, cli_yxx(cli_user(alias)->server),
                  sizeof(session->hs_origin));
    /* Session moved to a different server — delete stale MDBX record.
     * Without this, both servers persist the session and both restore
     * a ghost on restart, causing a nick collision on link. */
    if (we_were_holding_primary && !session_has_local_holder(session))
      bounce_db_del(session->hs_sessid);
    /* If the session has an oper grant and the new primary isn't yet
     * opered (e.g. alias predated the grant, or grant survived a
     * primary-disconnect-and-cleanup gap), re-grant from the local
     * O:line matching hs_oper_name.  No-op when the alias is already
     * opered (Step 1's sync helper kept it in lockstep) or when the
     * new primary is remote (the remote server runs its own grant
     * recovery against its own O:line config). */
    bounce_apply_oper_grant(alias, session);
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
  sendcmdto_serv_butone_v3(&me, CMD_BOUNCER_SESSION, NULL,
                        "T %s %s %s",
                        session->hs_account, session->hs_sessid,
                        winner_server);
  /* The outgoing stretch was just accrued: the new holder gets the total. */
  bounce_emit_total_active(session);

  /* A4: Remove old primary from channels silently.
   * After this, callers' exit_client() produces no visible QUIT
   * (sendcmdto_common_channels_butone is a no-op with no channels). */
  if (old_primary)
    remove_user_from_all_channels(old_primary);

  return 0;
}

/** Timer callback for cross-server deferred promote.
 *
 * Fires from the 0-tick timer armed by
 * `bounce_schedule_cross_server_promote`.  Re-evaluates the alias
 * list (which may have shifted in the intervening tick — concurrent
 * BX X messages have had a chance to land) and promotes any-server
 * winner.  If the session has revived (state == ACTIVE) between
 * schedule and fire, this is a no-op.  If no alias remains alive,
 * the session stays HOLDING and the regular hold-expire path will
 * eventually destroy or promote it.
 */
static void bounce_finish_cross_server_promote(struct Event *ev)
{
  struct BouncerSession *session;
  struct Client *ghost;
  int promoted;

  assert(0 != ev_timer(ev));
  assert(0 != t_data(ev_timer(ev)));

  if (ev_type(ev) == ET_DESTROY)
    return;

  session = (struct BouncerSession *)t_data(ev_timer(ev));
  if (!session)
    return;

  /* Session may have revived via SASL (BOUNCE_ACTIVE), been moved
   * (BOUNCE_DESTROYING), or had its primary returned by some other
   * path between schedule and fire.  Only promote from a still-
   * holding session. */
  if (session->hs_state != BOUNCE_HOLDING) {
    Debug((DEBUG_INFO,
           "Bouncer: deferred-promote skipped — session %s no longer "
           "HOLDING (state=%d)", session->hs_sessid, session->hs_state));
    return;
  }

  ghost = session->hs_client;
  if (!ghost || !IsBouncerHold(ghost)) {
    Debug((DEBUG_INFO,
           "Bouncer: deferred-promote skipped — session %s ghost gone",
           session->hs_sessid));
    return;
  }

  if (session->hs_alias_count <= 0) {
    Debug((DEBUG_INFO,
           "Bouncer: deferred-promote skipped — session %s has no aliases "
           "(all dropped while deferred); hold-expire will handle",
           session->hs_sessid));
    return;
  }

  /* Now safe to promote.  Pick any alias — by this tick, in-flight
   * BX X for any pre-selected winner has had its chance to land and
   * the alias_count reflects current truth. */
  promoted = bounce_promote_alias(session, 0 /* any */);
  if (promoted == 0) {
    /* Promote succeeded.  Exit ghost cleanly — same pattern as
     * bounce_hold_expire's promote-and-retire branch. */
    ClearBouncerHold(ghost);
    SetBouncerInternalDestroy(ghost);
    exit_client(ghost, ghost, &me, "Session transferred");
    Debug((DEBUG_INFO,
           "Bouncer: deferred-promote completed for session %s",
           session->hs_sessid));
  } else {
    Debug((DEBUG_INFO,
           "Bouncer: deferred-promote — no eligible alias for session %s; "
           "leaving HOLDING (hold-expire will handle)",
           session->hs_sessid));
  }
}

void bounce_schedule_cross_server_promote(struct BouncerSession *session)
{
  assert(0 != session);

  if (t_active(&session->hs_promote_timer))
    return; /* already scheduled; idempotent */

  Debug((DEBUG_INFO,
         "Bouncer: scheduling cross-server promote for session %s "
         "(aliases=%d) at next tick",
         session->hs_sessid, session->hs_alias_count));

  timer_init(&session->hs_promote_timer);
  timer_add(&session->hs_promote_timer, bounce_finish_cross_server_promote,
            (void *)session, TT_RELATIVE, 0);
}

/** The uplink of server @a srv (bounce_server_at_or_behind()'s walk). */
static const void *server_uplink(const void *srv)
{
  struct Client *s = (struct Client *)srv;

  return (s && cli_serv(s)) ? (const void *)cli_serv(s)->up : NULL;
}

/** Is @a srv the server @a departing, or a server behind it?  Both are
 * server Clients; NULL is behind nothing. */
static int bounce_server_behind(const struct Client *srv,
                                const struct Client *departing)
{
  return bounce_server_at_or_behind(srv, departing, server_uplink);
}

/** Prepare bouncer sessions for SQUIT promotion.
 * Called from exit_client() BEFORE exit_downlinks().
 *
 * A session is readied when its primary leaves with the split: a client
 * of the departing server or of a server behind it.  Where the primary
 * is decides, not the origin the record noted -- that one goes stale
 * (a ghost rebind keeps it, a merge points it at the server merged
 * into), and deciding by it left an alias here without a primary when
 * the primary had moved to the departing server, and ended a record
 * whose primary is our own live client or held ghost.  Only a session
 * with no primary at all (a replica whose primary never resolved) still
 * goes by its origin (bounce_squit_prepares()).
 *
 * A readied session drops the roster entries of aliases behind the
 * departing server; if any alias survives, hs_promoting suppresses
 * bounce_sync_alias_part() during the exit_downlinks() pass and
 * bounce_execute_squit_promotions() promotes one.
 *
 * @param[in] server The departing server.
 */
void bounce_prepare_squit_promotions(struct Client *server)
{
  int i, j;
  struct BouncerSession *session, *next;
  const char *departed_yxx = cli_yxx(server);

  for (i = 0; i < BOUNCE_TOKEN_HASHSIZE; i++) {
    for (session = tokenHash[i]; session; session = next) {
      struct Client *primary = session->hs_client;

      next = session->hs_tnext;   /* the no-alias branch may destroy `session` */
      if (!bounce_squit_prepares(primary != NULL,
                                 primary && MyConnect(primary),
                                 bounce_server_behind(bounce_primary_server(session),
                                                      server),
                                 bounce_server_behind(FindNServer(session->hs_origin),
                                                      server)))
        continue;

      /* Remove the alias entries behind the departing server */
      j = 0;
      while (j < session->hs_alias_count) {
        if (bounce_server_behind(FindNServer(session->hs_aliases[j].ba_server),
                                 server)) {
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

      /* If any aliases survive, mark for promotion.
       *
       * Do NOT null hs_client here.  The original ordering called
       * execute_squit_promotions AFTER exit_downlinks (which would
       * free the primary), and the nulling was necessary to avoid a
       * dangling-pointer dereference inside promote.  With the new
       * ordering (execute BEFORE exit_downlinks, see s_misc.c),
       * promote runs while the primary is still alive — keeping
       * hs_client lets promote take its normal old_primary path:
       *   - construct old_numeric for BX P broadcast
       *   - remove_user_from_all_channels(old_primary), which is the
       *     critical step that prevents exit_downlinks's eventual
       *     exit_one_client(primary) from broadcasting a phantom-self
       *     QUIT to the promoted alias's user. */
      if (session->hs_alias_count > 0) {
        session->hs_promoting = 1;
        Debug((DEBUG_INFO, "bounce_prepare_squit: session %s/%s has %d "
               "surviving aliases, marking for promotion",
               session->hs_account, session->hs_sessid,
               session->hs_alias_count));
      } else {
        /* No surviving aliases — session enters HOLDING from MDBX on
         * reconnect.  hs_client gets cleared here because there's no
         * promote to consume it; exit_downlinks will free the primary
         * and we don't want a dangling pointer in the session record. */
        session->hs_client = NULL;
        Debug((DEBUG_INFO, "bounce_prepare_squit: session %s/%s has no "
               "surviving aliases", session->hs_account, session->hs_sessid));
        /* A replica with nothing local behind it is now unreachable
         * state: no holder here, and its primary (or, for one that never
         * had a primary here, its origin) just left.  Keeping it
         * made it immortal -- the next link burst re-exported it as
         * "holding", the peer seeded a fresh replica from ours, and the
         * pair kept each other alive across restarts while blocking
         * every login for the account (the pool00 zombie, 2026-09-16).
         * Every server applies this rule to its own replicas, so no BS X
         * is needed; if the departed server still holds the session it
         * announces it again on relink and we build a fresh replica. */
        if (!session_has_local_holder(session)) {
          Debug((DEBUG_INFO, "bounce_prepare_squit: dropping replica "
                 "%s/%s: its primary left with %s", session->hs_account,
                 session->hs_sessid, departed_yxx));
          bounce_destroy(session);
        }
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

      if (bounce_promote_alias(session, 0) != 0) {
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
        /* User has +b mode set (synced with $draft/persistence/hold metadata) */
        should_hold = 1;
      } else {
        /* Check persistent metadata — cli_metadata may not be populated
         * after a restart; metadata_account_get reads from mdbx. */
        char hold_val[64];
        if (metadata_account_get(cli_account(cptr), "draft/persistence/hold", hold_val) == 0) {
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

/** Tell the peers a session's active time (BX U ta=): a replica learns it
 * only from the BS C that created it, so the server that becomes the
 * holder by a promotion or a move armed the earned hold from a stale
 * figure (deferred-items B3).  Sent where it grows (the hold, a
 * promotion, a split-merge demote) and in the burst; receivers keep the
 * larger, so order and stale bursts cannot lower it. */
static void bounce_emit_total_active(struct BouncerSession *session)
{
  char full_numeric[16];
  struct Client *primary = session->hs_client;

  if (!primary || !cli_user(primary) || !cli_user(primary)->server)
    return;
  ircd_snprintf(0, full_numeric, sizeof(full_numeric), "%s%s",
                cli_yxx(cli_user(primary)->server), cli_yxx(primary));
  sendcmdto_serv_butone_v3(&me, CMD_BOUNCER_TRANSFER, NULL,
                        "U %s ta=%Tu", full_numeric, session->hs_total_active);
}

/** Tell the BX-aware peers a session's connection count (BX U cc=), so a
 * replica that later becomes the holder arms the same earned hold. */
static void bounce_emit_connect_count(struct BouncerSession *session)
{
  char full_numeric[16];
  struct Client *primary = session->hs_client;

  if (!primary || !cli_user(primary) || !cli_user(primary)->server)
    return;
  ircd_snprintf(0, full_numeric, sizeof(full_numeric), "%s%s",
                cli_yxx(cli_user(primary)->server), cli_yxx(primary));
  sendcmdto_serv_butone_v3(&me, CMD_BOUNCER_TRANSFER, NULL,
                        "U %s cc=%u", full_numeric, session->hs_connect_count);
}

/** Transition a client to bouncer HOLDING state (ghost mode).
 * This is called from s_bsd.c when a disconnect is detected and
 * bounce_should_hold() returned a session.
 */
const char *bounce_last_hold_reason(struct Client *cptr)
{
  struct BouncerSession *session = bounce_get_session(cptr);
  if (!session || !session->hs_hold_reason[0])
    return NULL;
  return session->hs_hold_reason;
}

int bounce_hold_client(struct Client *cptr, const char *comment)
{
  struct BouncerSession *session;
  struct Membership *member;

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
  session->hs_enforced = 0; /* Phase 3: cleared on transition to HOLDING */
  session->hs_disconnect_time = CurrentTime;
  /* Record WHY -- holds suppress QUIT and never reach the connexit
   * notice, so without this the cause of death is destroyed.  Echoed
   * to the user at resume (replay_send_summary) and shown in /CHECK. */
  ircd_strncpy(session->hs_hold_reason, comment ? comment : "unknown",
               sizeof(session->hs_hold_reason) - 1);
  log_write(LS_USER, L_INFO, 0, "Bouncer hold for %s (%s): %s",
            session->hs_account, cli_name(cptr),
            comment ? comment : "unknown");
  ircd_strncpy(session->hs_ghost_numeric, cli_yxx(cptr), sizeof(session->hs_ghost_numeric));
  session->hs_ghost_numeric[sizeof(session->hs_ghost_numeric) - 1] = '\0';  /* redundant: strlcpy already terminates */
  /* hs_client still points to cptr (now a ghost) */

  /* The stretch this socket was attached becomes active time, then the
   * hold is the earned one (spec: adaptive hold), not the flat base. */
  bounce_accrue_active(session);
  bounce_arm_hold_timer(session, 1);
  bounce_emit_total_active(session);

  /* Broadcast detach to all servers (sends channel list for cross-server) */
  bounce_broadcast(session, 'D', NULL);

  /* WebSocket farewell (best effort): tell the client WHY before the
   * socket drops, so browsers see a labeled close instead of a bare
   * 1006 indistinguishable from a network cut.  Dead sockets (write
   * errors, EOF) can't be written to -- skip. */
  if (IsWebSocket(cptr) && !IsDead(cptr) && cli_fd(cptr) >= 0)
    websocket_send_close(cptr, 1000, comment ? comment : "held");

  /* close_connection() below zeroes the server notice mask and leaves
   * the modes, +s included, on the ghost.  Keep the mask with the
   * session: the revive gives it back, and persisted it is what the oper
   * grant restores after a restart. */
  session->hs_snomask = HasFlag(cptr, FLAG_SERVNOTICE) ? cli_snomask(cptr) : 0;
  session->hs_snomask_known = 1;

  /* Close the socket but keep the client structure alive.
   * Note: We do NOT call exit_client() here - that would destroy the client.
   * We only want to close the socket connection.
   */
  close_connection(cptr);

  /* The socket is gone: a held ghost of ours from here on.  It gives up
   * its local_clients count now (RPL_LUSERME counts live sockets), and
   * FLAG_NO_LC_DECREMENT says so to its exit and to a revive; it stays a
   * registered user the network knows by N (no Q was sent: that is what
   * holding means). */
  {
    struct bounce_counts was;

    count_held(cptr, &was);
    SetNoLcDecrement(cptr);
    bounce_count_converted(cptr, &was, &me, "hold");
  }

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

  /* Active client is taking over the session — it's no longer a
   * tentative restore.  Clear the reconcile-pending flag so any
   * incoming BX R for this session treats us as firm. */
  session->hs_restore_pending = 0;

  /* Convergence-completion event: any peer that was waiting on a
   * pending-restore session can release its gate now. */
  bounce_release_idle_gates();

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
    /* Cancel deferred-promote timer too — the session has been revived
     * (a new client attached), so the promote is no longer wanted. */
    if (t_active(&session->hs_promote_timer))
      timer_del(&session->hs_promote_timer);
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
      cli_fd(ghost) = -1;
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
    cli_fd(ghost) = -1;
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

  /* IPcheck rebalance for IP transplant.
   *
   * The original primary's connect ran IPcheck on its OLD IP (entry-
   * >connected ++).  bounce_hold_client did not symmetrically
   * IPcheck_disconnect when its socket closed, so the OLD IP entry
   * still holds that +1.  After this memcpy, cli_ip(ghost) points at
   * the temp's NEW IP — and a later exit_one_client(ghost) would call
   * IPcheck_disconnect against the NEW IP and miss the orphaned OLD
   * IP +1 entirely.  Worse, if the NEW IP's entry was reaped by
   * ip_registry_expire (no `connected` clients for 600 s) between
   * revive and exit, the IPcheck_disconnect on the NEW IP fires
   * `assert(entry)` in ip_registry_disconnect and SIGABRTs the whole
   * server.  See project_bouncer_ipcheck_assert.md.
   *
   * Release the orphaned OLD IP entry here, before we overwrite
   * cli_ip.  The NEW IP entry's +1 is donated by temp — we skip
   * IPcheck_disconnect(temp) below, just ClearIPChecked(temp).  Ghost
   * ends up accurately accounted on the NEW IP. */
  if (IsIPChecked(ghost)) {
    IPcheck_disconnect(ghost);
    ClearIPChecked(ghost);
  }
  memcpy(&cli_ip(ghost), &cli_ip(temp), sizeof(cli_ip(ghost)));
  if (IsIPChecked(temp))
    SetIPChecked(ghost);
  ircd_strncpy(con_sock_ip(ghost_con), con_sock_ip(temp_con), SOCKIPLEN + 1);
  ircd_strncpy(cli_sockhost(ghost), cli_sockhost(temp), HOSTLEN + 1);
  cli_port(ghost) = cli_port(temp);
  memcpy(&cli_connectip(ghost), &cli_connectip(temp), sizeof(cli_connectip(ghost)));
  ircd_strncpy(cli_connecthost(ghost), cli_connecthost(temp), HOSTLEN + 1);

  /* Refresh connection-derived identity fields that the original ghost
   * inherited from a prior session.  cli_user->realhost is the resolved
   * PTR / IAuth-spoofhost of the *current* connection; without
   * refreshing it here, shun_lookup (parse.c:1587) and other match
   * paths that consult realhost evaluate against the first connection's
   * value forever, even across IP changes / 16 resumes.  /CHECK exposes
   * this as `Real User/Host: user@stale.host (current.ip)`. */
  if (cli_user(ghost) && cli_user(temp))
    ircd_strncpy(cli_user(ghost)->realhost,
                 cli_user(temp)->realhost, HOSTLEN + 1);

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

  /* The class values cached on the ghost's Connection belong to the class
   * it registered under -- or, for a ghost restored from the DB, to no
   * class at all: a zeroed Connection caches fake lag 0, which reads as
   * "fake lag off", and a restored ghost never passes register_user()'s
   * reset.  The reviving socket brought its own confs: look them up
   * again, as register_user() and OPER do. */
  con_lag_min(ghost_con) = -2;
  con_lag_factor(ghost_con) = -2;
  con_max_sendq(ghost_con) = 0;
  con_max_recvq(ghost_con) = 0;

  /* Step 6b: Reset data counters and update connection identity.
   * Ghost's data counters may be stale from a prior connection (or from
   * MDBX restore). Roll them into session aggregates, then zero so the
   * new connection starts fresh. Also update the primary connection
   * timestamp and ID to reflect this new connection. */
  bounce_accumulate_and_reset_primary(session, ghost);
  cli_firsttime(ghost) = cli_firsttime(temp);

  /* The new socket's pre-registration AWAY (draft/pre-away).  Only when
   * it declared one: a socket that said nothing leaves the ghost's own
   * state as it was (an AWAY set before the hold survives the revive). */
  if (con_pre_away(temp_con)) {
    con_pre_away(ghost_con) = con_pre_away(temp_con);
    ircd_strncpy(con_pre_away_msg(ghost_con), con_pre_away_msg(temp_con),
                 AWAYLEN + 1);
  }
  /* Record connect event in connection history */
  bounce_history_connect(session, con_sock_ip(ghost_con),
                         cli_sockhost(ghost));

  /* Step 7: Transfer sendQ/recvQ from temp to ghost.
   * send_queues membership must follow the queues (send.c:1019 assert
   * class): temp may be listed with the replies queued to it this same
   * tick — after the move its queue is empty, so drop it (its
   * Connection is about to be discarded, and nothing later would).
   * The ghost may be listed from a pre-hold life (active-path revive)
   * or may now hold temp's undelivered bytes — reconcile it against
   * the transplanted queue and arm a write event so those bytes
   * actually flush on the new socket. */
  MsgQClear(&con_sendQ(ghost_con));
  con_sendQ(ghost_con) = con_sendQ(temp_con);
  msgq_init(&con_sendQ(temp_con));
  client_drop_sendq(temp_con);
  client_reconcile_sendq(ghost);

  DBufClear(&con_recvQ(ghost_con));
  con_recvQ(ghost_con) = con_recvQ(temp_con);
  memset(&con_recvQ(temp_con), 0, sizeof(con_recvQ(temp_con)));

  /* WebSocket frame/fragment reassembly state rides with the recvQ:
   * a frame split across the transplant would otherwise be dropped
   * (#104, latent -- CAP END is complete when revive runs -- but the
   * queues and their decoder state must move together).  The handshake
   * buffer (con_ws_hs_buf) is NOT carried: the handshake is decided
   * before SASL completes, and temp's teardown frees it. */
  memcpy(con_ws_frame_buf(ghost_con), con_ws_frame_buf(temp_con),
         sizeof(con_ws_frame_buf(ghost_con)));
  con_ws_frame_len(ghost_con) = con_ws_frame_len(temp_con);
  con_ws_frame_len(temp_con) = 0;
  memcpy(con_ws_frag_buf(ghost_con), con_ws_frag_buf(temp_con),
         sizeof(con_ws_frag_buf(ghost_con)));
  con_ws_frag_len(ghost_con) = con_ws_frag_len(temp_con);
  con_ws_frag_opcode(ghost_con) = con_ws_frag_opcode(temp_con);
  con_ws_frag_len(temp_con) = 0;
  con_ws_frag_opcode(temp_con) = 0;
  /* Outbound partial-frame remainder follows the socket: the ghost's
   * old one (if any) died with its old socket; temp's rides along. */
  if (con_ws_txrem(ghost_con))
    MyFree(con_ws_txrem(ghost_con));
  con_ws_txrem(ghost_con) = con_ws_txrem(temp_con);
  con_ws_txrem_len(ghost_con) = con_ws_txrem_len(temp_con);
  con_ws_txrem_pos(ghost_con) = con_ws_txrem_pos(temp_con);
  con_ws_txrem(temp_con) = NULL;
  con_ws_txrem_len(temp_con) = con_ws_txrem_pos(temp_con) = 0;

  /* Step 8: Copy CAP state from temp to ghost */
  memcpy(con_capab(ghost_con), con_capab(temp_con), sizeof(struct CapSet));
  memcpy(con_active_own(ghost_con), con_active_own(temp_con), sizeof(struct CapSet));
  memcpy(con_active(ghost_con), con_active_own(temp_con), sizeof(struct CapSet));
  con_capab_version(ghost_con) = con_capab_version(temp_con);

  /* draft/persistence M2: copy the per-connection active-profile name.
   * The reviving client may have done PERSISTENCE ATTACH pre-CAP-END;
   * that value lives on temp_con and must follow the transplanted
   * socket onto ghost_con.  Without this, ATTACH appears to "stick"
   * during pre-CAP-END but reverts to default once the bouncer takes
   * over the connection. */
  ircd_strncpy(con_active_profile(ghost_con), con_active_profile(temp_con),
               sizeof(con_active_profile(ghost_con)));
  /* Same for the ATTACH catch-up cursor (client's last-seen msgid): it
   * was stored on temp_con pre-CAP-END and is consumed at the replay
   * trigger after the transplant. */
  ircd_strncpy(con_attach_cursor(ghost_con), con_attach_cursor(temp_con),
               sizeof(con_attach_cursor(ghost_con)));

  /* Step 9: Update timing */
  con_lasttime(ghost_con) = con_lasttime(temp_con);
  con_since(ghost_con) = con_since(temp_con);
  /* A revive is activity: the person just opened a client.  Without this
   * the ghost keeps its pre-hold idle clock, so the account still looks
   * unattended to webpush during its own connect (every welcome NOTICE
   * pushed) and WHOIS idle spans the hold.  The auto-replay "since" was
   * taken from the old clock before we got here (register_user Try 1). */
  if (cli_user(ghost)) {
    cli_user(ghost)->last = CurrentTime;
    bounce_record_activity(ghost);
  }

#ifdef USE_SSL
  /* Step 10: Update FLAG_SSL and channel nonsslusers counters */
  {
    int was_ssl = IsSSL(ghost) ? 1 : 0;   /* flag beyond bit 31: never store the mask in an int */
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

  /* Step 10b: WebSocket-ness follows the SOCKET, exactly like FLAG_SSL
   * above (#104).  The handshake set these on temp only; without the
   * mirror, a WS login reviving a TCP-born ghost writes raw IRC bytes
   * into the WebSocket stream from 001 on (undici/browsers die with
   * 'Expected RSV1 to be clear', close 1006, and reconnect-loop into
   * the same poisoned ghost), and the mirror case frames bytes onto a
   * raw socket.  Set/clear symmetric so a stale value never survives
   * in either direction; deliver_it()/read_packet() key framing on
   * these flags. */
  if (IsWebSocket(temp)) SetWebSocket(ghost); else ClearWebSocket(ghost);
  if (IsWSText(temp)) SetWSText(ghost); else ClearWSText(ghost);
  if (IsWSAutodetect(temp)) SetWSAutodetect(ghost); else ClearWSAutodetect(ghost);
  ircd_strncpy(cli_wsorigin(ghost), cli_wsorigin(temp),
               sizeof(cli_wsorigin(ghost)) - 1);

  /* Step 11: Clear holding flags on ghost.  Also on the relay-only
   * (ACTIVE) path when the ghost still carries them: a revived client
   * that kept FLAG_BOUNCER_HOLD reads as held to everything after
   * (deauth classified it as a held ghost and exited it; deferred-items
   * B4, a hardening -- no reproduced case). */
  if (was_holding || IsBouncerHold(ghost)) {
    ClearBouncerHold(ghost);
    /* Step 12: Clear CHFL_HOLDING on all channel memberships */
    if (cli_user(ghost)) {
      for (member = cli_user(ghost)->channel; member; member = member->next_channel) {
        ClearMemberHolding(member);
      }
    }
  }
  ClrFlag(ghost, FLAG_DEADSOCKET);

  /* The ghost has a live socket again (the Step 6-7 transplant): a live
   * user of ours, counted in local_clients, and its exit releases that
   * count.  The temp client releases its own registration counts in
   * bounce_free_temp_client (Count_clientdisconnects): one socket, one
   * count. */
  {
    struct bounce_counts was;

    count_held(ghost, &was);
    ClearNoLcDecrement(ghost);
    bounce_count_converted(ghost, &was, &me, "revive");
  }

  /* Step 13: Update session state (hs_state already set to ACTIVE earlier) */
  session->hs_client = ghost;
  session->hs_attach_count++;
  session->hs_connect_count++;
  session->hs_last_active = CurrentTime;
  session->hs_attach_time = CurrentTime;
  session->hs_disconnect_time = 0;
  bounce_emit_connect_count(session);

  /* The held socket's server notice mask went with it (close_connection
   * zeroes it; bounce_hold_client kept it, BX K may have changed it since):
   * give the session's back, or the revived connection keeps +s with a
   * zero mask -- no server notices, and MODE <me> answers
   * "008 <me> 0 :: Server notice mask (0x0)" (field report 2026-10-21).
   * +s follows the mask.  Before register_user's send_umode_signon, so the
   * 008 there reports it. */
  if (session->hs_snomask_known) {
    set_snomask(ghost, session->hs_snomask, SNO_SET);
    if (cli_snomask(ghost))
      SetServNotice(ghost);
    else
      ClearServNotice(ghost);
  }

  /* The reused Connection still records how the previous socket died:
   * a later death of this one reported that socket's SSL error (even on
   * plain TCP) or its dead_link() reason. */
  con_error(ghost_con) = 0;
  con_sslerror(ghost_con) = NULL;
  con_exit_reason(ghost_con)[0] = '\0';

  /* A realname dead_link() wrote over before 2026-10 ("Write error: ...")
   * was kept, persisted and replayed as the user's name: the reviving
   * connection's USER line has the real one (user decision 2026-10-21). */
  if (cli_user(temp) && exit_reason_is_clobbered_info(cli_info(ghost))
      && cli_info(temp)[0] && !exit_reason_is_clobbered_info(cli_info(temp)))
    bounce_repair_realname(ghost, cli_info(temp));

  /* The login just proved its Keycloak id: a session without one (a record
   * from before the id was kept, an X3 login) adopts it (user decision
   * 2026-10-21) -- the ghost, its aliases here, the network.  A session
   * with a different id never gets here -- register_user refuses that
   * revive. */
  if (cli_user(temp) && account_id_valid(cli_user(temp)->kc_id))
    bounce_session_adopt_kc_id(session, cli_user(temp)->kc_id);
  bounce_session_fill_member_ids(session);

  /* Phase 3 hs_enforced: a reviving client on a CRFLAG_BOUNCER class
   * re-enforces the session.  temp_con (now transplanted) is the
   * Connection that holds the class. */
  {
    struct ConnectionClass *cls = get_client_class_conf(ghost);
    if (cls && FlagHas(&cls->restrictflags, CRFLAG_BOUNCER))
      session->hs_enforced = 1;
  }

  /* Sync ghost's cli_session_id to the bouncer's durable hs_sessid.
   * MDBX-restored ghosts come from bounce_create_ghost, which mints a
   * fresh cli_session_id at make_client time; it doesn't match the
   * persisted hs_sessid.  Without this sync the post-revive ghost
   * carries a sessid that disagrees with the BouncerSession it's
   * bound to — same hazard as bounce_attach's sync at line 1486 (per
   * the contract in list.c:240-246: "on resume, overwrites it with
   * the bouncer's stored sessid so session-id continuity follows the
   * bouncer session, not the underlying socket"). */
  ircd_strncpy(cli_session_id(ghost), session->hs_sessid, S2S_SESSID_BUFSIZE);

  /* Session is live again — remove persisted state (only HOLDING sessions persist) */
  if (was_holding)
    bounce_db_del(session->hs_sessid);

  /* Recompute session union caps */
  bounce_recompute_session_caps(ghost);

  /* Broadcast session attach to other servers.  Hold ghosts are
   * bursted as standard N to all peers (legacy and IRCv3-aware
   * alike — see server_finish_burst), and pre-burst BX R reconcile
   * resolves any cross-server collision before either side's N
   * tokens fire.  Peers already have a Client struct for the ghost's
   * numeric AND its channel memberships from channel B; the
   * hold→active transition is local-only state on this server.  No
   * post-revive N or JOIN replay needed; BS A links the session to
   * hs_client, and that's it. */
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
   * UserStats.local_clients and UserStats.clients.
   * Must run while cli_status is still STAT_USER and cli_user is intact —
   * Count_clientdisconnects reads cli_sockhost via the macro.
   *
   * IPcheck is NOT decremented here — bounce_revive transferred the
   * temp's +1 to the ghost (Step 6a) by SetIPChecked(ghost) on the
   * new IP without releasing temp's entry.  Decrementing here would
   * double-release: ghost's later exit would underflow / miss the
   * entry.  Just clear the flag so any later code doesn't think temp
   * still owns an entry. */
  if (MyConnect(temp) && IsUser(temp))
    Count_clientdisconnects(temp, UserStats);
  if (IsIPChecked(temp))
    ClearIPChecked(temp);

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

/** Reuse a held local ghost's Client for a client another server
 * introduced in our ghost's session: re-key its hash entry, switch its
 * server, numeric and Connection to that server's, and clear the hold
 * flag (a remote client never carries it).  Channel memberships stay --
 * no QUIT, no JOIN.  Wire-invisible to IRCv3-aware peers; a legacy link
 * that may know the ghost's face by N is told of the renumbering with one
 * BX P each (bounce_legacy_face_change).  The counters move from the
 * local domain to the introducing server's, once.
 *
 * @param[in] keep_held 0: the introduced client is the session's live
 *                      primary; the session goes active.  1: it is the
 *                      session's held ghost on that server; our record
 *                      becomes a held replica of it.
 */
static void rebind_ghost(struct BouncerSession *session, struct Client *ghost,
                         struct Client *server, const char *new_numeric,
                         time_t new_lastnick, const char *username,
                         const char *host, const struct irc_in_addr *new_ip,
                         const char *info, int keep_held)
{
  struct Membership *member;
  struct Connection *old_con;
  struct bounce_counts was;
  int i;

  /* What the ghost holds as a held ghost of ours, before it becomes a
   * client of the introducing server. */
  count_held(ghost, &was);

  /* Tell legacy links that may still know the ghost's old numeric that
   * it swapped to new_numeric, while ghost still carries the numeric
   * they know (the helper reads cli_user(ghost)->server/cli_yxx(ghost)
   * to build it) and before hRemClient/RemoveYXXClient below release
   * it.  This is the only thing the rebind sends: no QUIT, no JOIN,
   * nothing else goes out anywhere — one BX P per legacy link that
   * may know the face (none when there is no such link), and nothing
   * toward an IRCv3-aware peer.  A legacy link (L) and X3 behind it
   * swap the numeric in place; no collision, no KILL on the user's
   * next line. */
  bounce_legacy_face_change(ghost, session, NULL, new_numeric, NULL);

  /* Cancel the hold timer: the session goes active, or the introducing
   * server holds it now and runs its own. */
  if (t_active(&session->hs_hold_timer))
    timer_del(&session->hs_hold_timer);

  /* Drop ghost from nick hash and release its local numeric. */
  hRemClient(ghost);
  RemoveYXXClient(&me, cli_yxx(ghost));

  /* Free the ghost's own Connection. The ghost now shares the server's
   * Connection so cli_from(ghost) routes outgoing messages through the
   * server link, like any other remote client. */
  old_con = cli_connect(ghost);
  if (old_con) {
    if (cli_fd(ghost) >= 0) {
      LocalClientArray[cli_fd(ghost)] = 0;
      close(cli_fd(ghost));
      cli_fd(ghost) = -1;
    }
    /* free_connection asserts con_client(con) == NULL */
    con_client(old_con) = NULL;
    free_connection(old_con);
  }
  cli_connect(ghost) = cli_connect(server);

  /* Local-only flags no longer apply. */
  ClrFlag(ghost, FLAG_DEADSOCKET);
  if (IsIPChecked(ghost))
    ClearIPChecked(ghost);

  /* Update identity from the N introduction. */
  cli_user(ghost)->server = server;

  /* The ghost is the introducing server's client now: a registered user
   * the network knows by N, in that server's count, and no longer one of
   * ours (its local_announced_clients count goes; it gave its socket's
   * count up when it was held, or never took one as a restored ghost --
   * FLAG_NO_LC_DECREMENT, cleared here as a remote client never reads
   * it).  Count_remoteclientquits releases the rest when it ends. */
  ClearNoLcDecrement(ghost);
  bounce_count_converted(ghost, &was, &me, "rebind");

  ircd_strncpy(cli_username(ghost), username, USERLEN + 1);
  ircd_strncpy(cli_user(ghost)->username, username, USERLEN + 1);
  ircd_strncpy(cli_user(ghost)->host, host, HOSTLEN + 1);
  ircd_strncpy(cli_user(ghost)->realhost, host, HOSTLEN + 1);
  ircd_strncpy(cli_info(ghost), info, REALLEN + 1);
  if (new_ip)
    memcpy(&cli_ip(ghost), new_ip, sizeof(cli_ip(ghost)));
  cli_lastnick(ghost) = new_lastnick;

  /* Register hub-assigned numeric in the introducing server's client_list. */
  SetRemoteNumNick(ghost, new_numeric);

  /* Clear ghost flag and re-key the nick hash entry. */
  ClearBouncerHold(ghost);
  hAddClient(ghost);

  /* Channels were marked HOLDING in bounce_hold_client; clear the flag
   * so messages route through them again. Memberships, modes and
   * counters are otherwise untouched. */
  for (member = cli_user(ghost)->channel; member; member = member->next_channel)
    ClearMemberHolding(member);

  if (!keep_held) {
    /* Update session state.  The session's hs_origin is left as-is: it
     * is historical, and nothing that decides reads it while the session
     * has a primary (a split goes by where the primary is). */
    session->hs_state = BOUNCE_ACTIVE;
    session->hs_client = ghost;
    session->hs_last_active = CurrentTime;
    session->hs_disconnect_time = 0;
  } else {
    /* The session stays held, held now by the introducing server: our
     * record becomes a replica of it, as a BS C "holding" plus BS A from
     * that server would have built it -- its primary slot the client
     * just rebound (a remote client, as a replica's is), the ghost
     * numeric and origin that server's, and no hold timer here (the
     * holder runs it and ends the session with BS X). */
    session->hs_client = ghost;
    ircd_strncpy(session->hs_origin, cli_yxx(server),
                 sizeof(session->hs_origin));
    ircd_strncpy(session->hs_ghost_numeric, new_numeric + 2,
                 sizeof(session->hs_ghost_numeric));
  }

  /* Update local aliases' alias_primary pointer (struct address didn't
   * change, but be defensive — the session might have been restored
   * with stale state). */
  for (i = 0; i < session->hs_alias_count; i++) {
    struct Client *alias = findNUser(session->hs_aliases[i].ba_numeric);
    if (alias && IsBouncerAlias(alias))
      cli_user(alias)->alias_primary = ghost;
  }

  /* Persisted record represented a HOLDING ghost held here; it is
   * active now, or held by the introducing server. */
  bounce_db_del(session->hs_sessid);
}

/** Rebind a held local ghost to be a remote primary on another server.
 *
 * Hub side: client connected, session is ACTIVE, primary is alive.
 * Leaf side: ghost was restored from MDBX (or never disconnected from leaf
 * after a netsplit). When the hub's burst introduces N for the live
 * primary, the leaf's standard P10 nick-collision path would kill both
 * because ghost and primary share user@host. They aren't independent
 * clients — they're one logical user in two representational states.
 *
 * Reuse the ghost's Client struct: re-key its hash entry, switch its
 * server/numeric/Connection ownership, and clear hold flags. Channel
 * memberships are untouched — no QUIT, no JOIN echo. Wire-invisible
 * to IRCv3-aware peers (only local state mutates); a legacy link that
 * may know the ghost's face by N is told of the renumbering with one
 * BX P each (bounce_legacy_face_change), since it has no other way to
 * learn it — the normal N-forward never reaches it either (the N that
 * triggered this rebind resolves locally instead of being relayed).
 */
int bounce_rebind_ghost_to_remote_primary(struct Client *ghost,
                                          struct Client *server,
                                          const char *new_numeric,
                                          time_t new_lastnick,
                                          const char *username,
                                          const char *host,
                                          const struct irc_in_addr *new_ip,
                                          const char *info,
                                          time_t incoming_acc_ts,
                                          const char *incoming_kc_id)
{
  struct BouncerSession *session;
  enum BounceRebindAuth rebind_auth = BRA_NONE;

  if (!ghost || !server || !new_numeric || !*new_numeric)
    return -1;
  if (!IsBouncerHold(ghost) || !MyConnect(ghost))
    return -1;
  if (!cli_user(ghost) || !cli_user(ghost)->account[0])
    return -1;

  session = bounce_find_best_held(cli_user(ghost)->account);
  if (!session || session->hs_client != ghost) {
    log_write(LS_USER, L_WARNING, 0,
              "bounce_rebind: no matching held session for ghost %s account %s",
              cli_name(ghost), cli_user(ghost)->account);
    return -1;
  }

  /* Authorization gate: rebind is allowed only when the introducing
   * message carries a ,S<sessid> compact tag whose value matches this
   * session's hs_sessid.  Sessid is a UUIDv7 — only servers that genuinely
   * hold (or replicate) the session know it, and they stamp it only on a
   * member's N, so the match is non-spoofable across BX-aware peers.
   *
   * Without it, any peer reintroducing a user via N during burst — even a
   * peer that doesn't run bouncer at all — could hijack the ghost as soon
   * as the +r account matched.
   *
   * There used to be an origin arm: the introducing server matching the
   * session's recorded hs_origin.  It is retired too: that origin goes
   * stale (a ghost rebind keeps it, a merge or a BS C yield moves it to
   * the peer), and a line whose session id is not ours says the client is
   * in another session or in none, so matching on the origin handed our
   * held session to a client that is not in it.  A meeting with a client
   * in no session is the collision rules' to decide, as it is on the
   * verdict path.
   *
   * There used to be a third arm: the incoming account timestamp matching
   * the ghost's acc_create.  It is retired (bouncer_rebind_auth.c).  It was
   * a receiver-side fallback (219ab03) meant to go once the sender-side
   * sessid hint (8cf493c) proved itself, and it is too coarse to authorize
   * anything: it matches any connection that shares the account, and the
   * same account is stamped with different timestamps depending on how
   * the user logged in.  It and the origin match are still computed so
   * the refusal below can log them.
   *
   * Per redesign A.2/C.2: sessid is the canonical session identity;
   * hs_origin is historical-only metadata. */
  {
    struct Client *link = cli_from(server) ? cli_from(server) : server;
    const char *wire_sessid = cli_s2s_sessid(link);
    int origin_match = (0 == strcmp(session->hs_origin, cli_yxx(server)));
    int sessid_match = (wire_sessid && wire_sessid[0]
                        && 0 == strcmp(wire_sessid, session->hs_sessid));
    int acc_ts_match = (incoming_acc_ts != 0
                        && cli_user(ghost)->acc_create != 0
                        && incoming_acc_ts == cli_user(ghost)->acc_create);

    rebind_auth = bounce_rebind_auth(origin_match, sessid_match, acc_ts_match);

    if (rebind_auth == BRA_NONE) {
      Debug((DEBUG_INFO,
             "bounce_rebind: refusing — session %s: the introduction from %s "
             "carries no matching session id (wire ,S='%s'); origin %s and "
             "account TS incoming=%ld ghost=%ld not consulted (account %s)",
             session->hs_sessid, cli_yxx(server),
             wire_sessid ? wire_sessid : "", session->hs_origin,
             (long)incoming_acc_ts, (long)cli_user(ghost)->acc_create,
             cli_user(ghost)->account));
      return -1;
    }

    Debug((DEBUG_INFO,
           "bounce_rebind: authorizing via %s — session %s origin %s, "
           "introducing server %s, account %s",
           bounce_rebind_auth_name(rebind_auth), session->hs_sessid,
           session->hs_origin, cli_yxx(server), cli_user(ghost)->account));
  }

  /* Whatever authorized it, a Keycloak id that differs from the ghost's is
   * a different user under the same name: refused, and the collision
   * handling the caller falls back to decides (bouncer_rebind_auth.h). */
  if (bounce_rebind_kc_conflict(cli_user(ghost)->kc_id, incoming_kc_id)) {
    log_write(LS_USER, L_INFO, 0,
              "Bouncer rebind refused: ghost %s (account %s) carries Keycloak "
              "id %s, the introduction from %s carries %s",
              cli_name(ghost), cli_user(ghost)->account, cli_user(ghost)->kc_id,
              cli_name(server), incoming_kc_id);
    return -1;
  }

  Debug((DEBUG_INFO,
         "bounce_rebind: ghost %s account %s -> remote primary %s on %s",
         cli_name(ghost), cli_user(ghost)->account, new_numeric,
         cli_name(server)));

  rebind_ghost(session, ghost, server, new_numeric, new_lastnick, username,
               host, new_ip, info, 0);

  log_write(LS_USER, L_TRACE, 0,
            "Bouncer rebind: ghost %s rebound to remote primary %s on %s "
            "(session %s, authorized via %s)", cli_name(ghost), new_numeric,
            cli_name(server), session->hs_sessid,
            bounce_rebind_auth_name(rebind_auth));

  return 0;
}

/** See include/bouncer_session.h. */
int bounce_drop_held_ghost(struct BouncerSession *session, struct Client *ghost,
                           struct Client *server, const char *new_numeric,
                           time_t new_lastnick, const char *username,
                           const char *host, const struct irc_in_addr *new_ip,
                           const char *info, const char *incoming_kc_id,
                           int incoming_held)
{
  if (!session || !ghost || !server || !new_numeric
      || strlen(new_numeric) != 5)
    return -1;
  /* The caller decided on this session: our ghost holds its primary
   * slot.  Never a rebind without the session. */
  if (session->hs_client != ghost || !IsBouncerHold(ghost)
      || !MyConnect(ghost) || !cli_user(ghost) || !cli_user(ghost)->account[0])
    return -1;
  /* A Keycloak id that differs from the ghost's is a different user. */
  if (bounce_rebind_kc_conflict(cli_user(ghost)->kc_id, incoming_kc_id))
    return -1;

  rebind_ghost(session, ghost, server, new_numeric, new_lastnick, username,
               host, new_ip, info, incoming_held);
  /* Settled: a restored session waiting on this meeting no longer holds
   * a burst gate up.  The release runs after this line. */
  session->hs_restore_pending = 0;
  bounce_schedule_gate_release();

  log_write(LS_USER, L_INFO, 0,
            "Bouncer drop: ghost %s became %s on %s, the session's %s "
            "(session %s)", cli_name(ghost), new_numeric, cli_name(server),
            incoming_held ? "held ghost there" : "live primary",
            session->hs_sessid);
  return 0;
}

/* ---------------------------------------------------------------- */
/* Live primary → alias demotion (split-merge)                       */
/* ---------------------------------------------------------------- */

/** Tell the IRCv3-aware links that @a alias, a connection of ours, is an
 * alias of @a primary in @a session: one BX C, carrying the channels the
 * alias is in (each with the JOIN's msgid).  A receiver files the alias
 * under the session id, else under the session @a primary holds. */
static void bounce_announce_alias(struct BouncerSession *session,
                                  struct Client *alias, struct Client *primary)
{
  char primary_full[6];
  char alias_full[6];
  char chanlist_buf[512];
  char *alias_modes;
  struct Membership *m;
  size_t len = 0;

  ircd_snprintf(0, primary_full, sizeof(primary_full), "%s%s",
                cli_yxx(cli_user(primary)->server), cli_yxx(primary));
  ircd_snprintf(0, alias_full, sizeof(alias_full), "%s%s",
                cli_yxx(&me), cli_yxx(alias));

  chanlist_buf[0] = '\0';
  for (m = cli_user(alias)->channel; m; m = m->next_channel) {
    if (!m->channel)
      continue;
    if (len > 0)
      str_appendf(chanlist_buf, sizeof(chanlist_buf), &len, " ");
    /* Per redesign F.2: per-channel JOIN msgid rides along as
     * "<chan>@<msgid>" so receivers can populate the alias's
     * Membership::join_msgid.  Single-msgid invariant: the alias's
     * cross-server join echo carries the same msgid as the primary's
     * original JOIN. */
    if (m->join_msgid[0])
      str_appendf(chanlist_buf, sizeof(chanlist_buf), &len,
                  "%s@%s", m->channel->chname, m->join_msgid);
    else
      str_appendf(chanlist_buf, sizeof(chanlist_buf), &len,
                  "%s", m->channel->chname);
  }

  alias_modes = umode_str(alias);
  sendcmdto_serv_butone_v3(&me, CMD_BOUNCER_TRANSFER, NULL,
                           "C %s %s %s %s %s%s :%s",
                           primary_full, alias_full,
                           session->hs_account, session->hs_sessid,
                           *alias_modes ? "+" : "+", alias_modes,
                           chanlist_buf);
}

/** See include/bouncer_session.h. */
enum bounce_demote_bar bounce_demote_eligibility(enum bounce_demote_stage stage,
                                                 struct Client *face,
                                                 struct BouncerSession *session,
                                                 struct Client *new_home,
                                                 const char *new_account,
                                                 const char *new_kc_id)
{
  struct bounce_demote_facts f;
  const char *face_account = NULL;

  memset(&f, 0, sizeof f);
  if (face && IsUser(face) && cli_user(face) && IsAccount(face)) {
    f.face_account_user = 1;
    face_account = cli_account(face);
  }
  f.face_alias = face && IsBouncerAlias(face);
  f.face_held  = face && IsBouncerHold(face);
  f.face_dying = face && (IsDead(face) || HasFlag(face, FLAG_KILLED));
  f.session_found = (session != NULL);
  f.session_account = session && face_account
                      && 0 == ircd_strcmp(session->hs_account, face_account);
  if (!session)
    f.session_slot = BOUNCE_SLOT_OTHER;   /* unread: no session refuses first */
  else if (!session->hs_client)
    f.session_slot = BOUNCE_SLOT_EMPTY;
  else if (session->hs_client == face)
    f.session_slot = BOUNCE_SLOT_FACE;
  else
    f.session_slot = BOUNCE_SLOT_OTHER;
  f.new_home_known = (new_home != NULL);
  f.new_home_aware = new_home && IsIRCv3Aware(new_home);
  f.new_account = new_account && *new_account && face_account
                  && 0 == ircd_strcmp(new_account, face_account);
  /* A missing id on either side never vetoes. */
  f.kc_id_conflict = session
                     && bounce_rebind_kc_conflict(bounce_session_kc_id(session),
                                                  new_kc_id);
  return bounce_demote_check(stage, &f);
}

/** The eligibility wrapper for a new primary that exists as a Client. */
static enum bounce_demote_bar demote_eligibility_for(enum bounce_demote_stage stage,
                                                     struct Client *face,
                                                     struct BouncerSession *session,
                                                     struct Client *new_primary)
{
  struct Client *home = (new_primary && cli_user(new_primary))
                        ? cli_user(new_primary)->server : NULL;
  return bounce_demote_eligibility(stage, face, session, home,
                                   (new_primary && IsAccount(new_primary))
                                     ? cli_account(new_primary) : NULL,
                                   (new_primary && cli_user(new_primary))
                                     ? cli_user(new_primary)->kc_id : NULL);
}

int bounce_demote_live_primary_to_alias(struct Client *acptr,
                                        struct Client *new_primary,
                                        struct BouncerSession *session)
{
  struct Membership *member;
  char alias_full[6];
  struct Client *new_primary_server;
  enum bounce_demote_bar bar;

  /* The same decision the callers made before asking (a same-nick merge
   * decides before the new primary's N is relayed): never into a primary
   * homed on a legacy server, never a dying face (its own exit holds the
   * session, an alias exit would broadcast BX X and end it), and only
   * the session's own live primary, under the account the finish
   * checks. */
  bar = demote_eligibility_for(BOUNCE_DEMOTE_PLAN, acptr, session, new_primary);
  if (bar != BOUNCE_DEMOTE_OK) {
    Debug((DEBUG_INFO, "bounce_demote_live: not demoting %s: %s",
           acptr ? cli_name(acptr) : "(none)", bounce_demote_bar_name(bar)));
    return -1;
  }
  new_primary_server = cli_user(new_primary)->server;

  Debug((DEBUG_INFO,
         "bounce_demote_live: %s (account %s, session %s) demoting to "
         "alias of remote primary on %s",
         cli_name(acptr), cli_user(acptr)->account,
         session->hs_sessid, cli_name(new_primary_server)));

  /* Flip channel memberships from primary to alias.  Adjust the
   * channel-side counters (users / aliases / nonsslusers / authusers)
   * AND the user->joined counter — the inverse of bounce_promote_alias's
   * promotion path.  Missing the joined decrement leaves stale state
   * that crashes free_user's `0 == user->joined` assertion when the
   * client eventually exits, since remove_member_from_channel skips
   * the joined decrement for alias members on the way out. */
  for (member = cli_user(acptr)->channel; member;
       member = member->next_channel) {
    struct Channel *chptr = member->channel;
    if (!IsMemberAlias(member)) {
      member->status |= CHFL_ALIAS;
      if (chptr->users > 0)
        --chptr->users;
      ++chptr->aliases;
      if (cli_user(acptr)->joined > 0)
        --(cli_user(acptr)->joined);
      if (!IsSSL(acptr) && !IsChannelService(acptr)) {
        if (chptr->nonsslusers > 0)
          --chptr->nonsslusers;
      }
      if (IsAccount(acptr) && chptr->authusers > 0)
        --chptr->authusers;
    }
  }

  /* Promote the Client to alias: flag, NULL alias_primary (caller
   * patches via bounce_finish_live_primary_demote), drop from nick
   * hash (aliases share their primary's nick and aren't hashed). */
  {
    struct bounce_counts was;

    count_held(acptr, &was);
    SetBouncerAlias(acptr);
    /* An alias of ours from here on, whether or not the finish takes the
     * session: still a socket and a registered user, no longer announced
     * (the new primary is the session's announced user).  Its exit, as an
     * alias, releases the rest. */
    bounce_count_converted(acptr, &was, &me, "demote");
  }
  cli_user(acptr)->alias_primary = NULL;
  hRemClient(acptr);

  /* Session moves to peer's authority.  hs_origin → introducing
   * server's numeric, hs_client → NULL pending caller patch.  Add
   * acptr to hs_aliases.  Drop persisted MDBX record — we no longer
   * own the session as primary. */
  ircd_strncpy(session->hs_origin, cli_yxx(new_primary_server),
               sizeof(session->hs_origin));
  session->hs_origin[sizeof(session->hs_origin) - 1] = '\0';  /* redundant: strlcpy already terminates */
  /* The demoted connection's attached stretch is active time; the new
   * primary's server keeps its own (sent once the new primary is
   * adopted, bounce_adopt_new_primary). */
  bounce_accrue_active(session);
  session->hs_client = NULL;

  if (session->hs_alias_count < BOUNCER_MAX_ALIASES) {
    struct BounceAlias *ba = &session->hs_aliases[session->hs_alias_count++];
    ircd_snprintf(0, alias_full, sizeof(alias_full), "%s%s",
                  cli_yxx(&me), cli_yxx(acptr));
    ircd_strncpy(ba->ba_numeric, alias_full, sizeof(ba->ba_numeric));
    ircd_strncpy(ba->ba_server, cli_yxx(&me), sizeof(ba->ba_server));
    ba->ba_caps = 0;
    ba->ba_caps_known = 0;
    ba->ba_away = 0;
    ba->ba_away_known = 0;
  }

  bounce_db_del(session->hs_sessid);

  return 0;
}

int bounce_finish_live_primary_demote(struct Client *demoted_alias,
                                      struct Client *new_primary,
                                      struct BouncerSession *session,
                                      int legacy_done)
{
  enum bounce_demote_bar bar;

  /* The demote's own decision, at its second step: the face is the alias
   * the demote made, the slot is empty, and the new primary carries the
   * account. */
  bar = demote_eligibility_for(BOUNCE_DEMOTE_FINISH, demoted_alias, session,
                               new_primary);
  if (bar != BOUNCE_DEMOTE_OK) {
    Debug((DEBUG_INFO, "bounce_finish_live: not finishing %s: %s",
           demoted_alias ? cli_name(demoted_alias) : "(none)",
           bounce_demote_bar_name(bar)));
    return -1;
  }

  session->hs_client = new_primary;
  cli_user(demoted_alias)->alias_primary = new_primary;
  /* The demoted connection is a connection of this session: it carries
   * the session's id, which the alias filing, the reconcile and history's
   * same-session lookups key on. */
  if (0 != strcmp(cli_session_id(demoted_alias), session->hs_sessid)) {
    presence_purge_session(cli_session_id(demoted_alias));
    ircd_strncpy(cli_session_id(demoted_alias), session->hs_sessid,
                 S2S_SESSID_BUFSIZE);
  }
  bounce_emit_total_active(session);

  /* Adopt the primary's nick.  Aliases share the primary's nick for
   * outgoing message attribution and identity-routing.  Without this:
   *   - demoted_alias's cli_name stays at the old (now-stale) nick
   *   - hRemClient (in bounce_demote_live_primary_to_alias) left the
   *     old nick unhashed → /WHOIS <old_nick> on this server returns
   *     no-such-nick, even though the user is still connected
   *   - any PRIVMSG the user sends goes out attributed to the old nick,
   *     which exists on no other server's view (the network now sees
   *     them as the primary's nick)
   *
   * Same pattern as bounce_setup_local_alias which renames at attach
   * time.  Send the NICK echo to the local fd so the user's client
   * UI updates.  No need to broadcast NICK to channel members — the
   * BX C above is the network-side identity update; channel members
   * on this server see the alias as a CHFL_ALIAS membership which is
   * already filtered out of /NAMES rendering.
   *
   * The echo goes first, while the alias still carries its old nick: its
   * source is the alias's own prefix, and a client takes a NICK as its
   * own rename only when that prefix is its current nick
   * (":old_nick!user@host NICK new_nick"). */
  if (MyConnect(demoted_alias)
      && 0 != ircd_strcmp(cli_name(demoted_alias), cli_name(new_primary))) {
    char old_nick[NICKLEN + 1];
    ircd_strncpy(old_nick, cli_name(demoted_alias), NICKLEN + 1);
    sendcmdto_one(demoted_alias, CMD_NICK, demoted_alias, "%s",
                  cli_name(new_primary));
    ircd_strncpy(cli_name(demoted_alias), cli_name(new_primary), NICKLEN + 1);
    Debug((DEBUG_INFO,
           "bounce_finish_live: renamed local alias %s -> %s "
           "(primary on %s)",
           old_nick, cli_name(demoted_alias),
           cli_name(cli_user(new_primary)->server)));
  }

  /* Broadcast BX C so other peers learn about the newly-aliased
   * local connection — they'll create a remote-alias replica with
   * primary pointing at new_primary, channel memberships reflecting
   * the demoted_alias's channel list. */
  bounce_announce_alias(session, demoted_alias, new_primary);
  {
    /* Legacy peers: present the demote as a QUIT for the old primary.
     *
     * BX C is bouncer-aware-only; legacy peers see it as Unknown and
     * drop it.  Without further signal they'd retain the demoted client
     * as a regular primary — and when the winner side's primary N
     * arrives via mesh forwarding, legacy's m_nick fires same-user@host
     * collision rules and one or both sides die.  Retract the demoted
     * face from the legacy links that may know it ("Promoted to alias"
     * reason — legacy interprets as a normal QUIT, removes from its
     * view).  bounce_legacy_face_change skips aware links and links
     * still under the burst gate (their N hasn't been emitted yet; when
     * the gate releases the IsBouncerAlias filter on the N loop skips
     * this client), and clears the records of this face so a later emit
     * (a relay-path N, the next burst) may introduce a fresh one.
     *
     * A legacy link already knows the new primary: it learned every
     * client of ours and every one we relayed by its N (the burst toward
     * it suppresses none), and the only N we withhold from it -- the
     * incoming primary of a lost same-nick merge, or the one a held ghost
     * yields to -- reaches it as a renumbering of the face it holds
     * (BX P).  So retracting the demoted face leaves it with the survivor.
     *
     * The local Client struct stays alive on this server (it's now an
     * alias and continues to handle the user's connection).  Q here is
     * purely a peer-state retraction, not a destroy.  legacy_done: the
     * caller already swapped this face to the new primary (BX P), so
     * the legacy links hold the session's face and get nothing more. */
    if (!legacy_done) {
      char reason[NICKLEN + 32];
      ircd_snprintf(0, reason, sizeof(reason), "Promoted to alias of %s",
                    cli_name(new_primary));
      bounce_legacy_face_change(demoted_alias, session, NULL, NULL, reason);
    }
  }

  return 0;
}

/** See include/bouncer_session.h. */
int bounce_yield_held_ghost(struct BouncerSession *session, struct Client *ghost,
                            struct Client *new_primary, struct Client *link,
                            const char *incoming_sessid)
{
  struct BouncerSession *target = session;
  char new_full[6];
  int i;

  if (!session || !ghost || !new_primary || session->hs_client != ghost
      || !IsUser(new_primary) || !cli_user(new_primary)
      || !cli_user(new_primary)->server)
    return -1;
  ircd_snprintf(0, new_full, sizeof(new_full), "%s%s",
                cli_yxx(cli_user(new_primary)->server), cli_yxx(new_primary));

  /* The two are one session from here on, under one id
   * (bounce_yield_id): a record of the incoming id here already takes our
   * connections, and ours ends -- never a record of another Keycloak
   * user; outside a burst ours takes the incoming id now.  When the
   * incoming primary came in its server's link burst ours keeps its id
   * for now: that burst announces the incoming session (BS C) after its
   * users, and our record, which follows the incoming primary from here,
   * then ends with the id the peer ends with (bounce_follow_keeps_id) --
   * our own burst announced ours, and the peer may rename into it. */
  if (incoming_sessid && *incoming_sessid) {
    int same = 0 == strcmp(incoming_sessid, session->hs_sessid);
    struct BouncerSession *other =
      same ? NULL : bounce_find_by_token_sessid(session->hs_account,
                                                incoming_sessid);
    int other_kc_conflict;

    if (other == session)
      other = NULL;
    other_kc_conflict = other
      && bounce_rebind_kc_conflict(bounce_session_kc_id(session),
                                   bounce_session_kc_id(other));
    switch (bounce_yield_id(same,
                            IsBurstOrBurstAck(cli_user(new_primary)->server),
                            other != NULL, other_kc_conflict)) {
    case BOUNCE_YIELD_MERGE: {
      /* Our session's connections join it, each once (one it lists
       * already stays as it is, and the incoming primary is its primary,
       * never its alias), and ours ends. */
      char new_numeric[6];
      ircd_snprintf(0, new_numeric, sizeof(new_numeric), "%s%s",
                    cli_yxx(cli_user(new_primary)->server), cli_yxx(new_primary));
      for (i = 0; i < session->hs_alias_count; i++) {
        int j, listed = 0;
        if (0 == strcmp(session->hs_aliases[i].ba_numeric, new_numeric))
          continue;
        for (j = 0; j < other->hs_alias_count && !listed; j++)
          listed = 0 == strcmp(other->hs_aliases[j].ba_numeric,
                               session->hs_aliases[i].ba_numeric);
        if (listed)
          continue;
        if (other->hs_alias_count < BOUNCER_MAX_ALIASES)
          other->hs_aliases[other->hs_alias_count++] = session->hs_aliases[i];
        else
          log_write(LS_USER, L_WARNING, 0, "Bouncer yield: session %s is full; "
                    "alias %s of %s not moved", other->hs_sessid,
                    session->hs_aliases[i].ba_numeric, session->hs_sessid);
      }
      session->hs_alias_count = 0;
      session->hs_client = NULL;
      bounce_broadcast(session, 'X', NULL);
      bounce_destroy(session);
      target = other;
      unmirrored_clear(target->hs_account, incoming_sessid);
      break;
    }
    case BOUNCE_YIELD_TAKE_ID:
      bounce_session_take_id(session, incoming_sessid);
      break;
    case BOUNCE_YIELD_KEEP_ID:
      if (other_kc_conflict)
        log_write(LS_USER, L_INFO, 0, "Bouncer yield: session %s of %s, the "
                  "incoming one's id, belongs to Keycloak id %s, ours %s to "
                  "%s: not joined", other->hs_sessid, session->hs_account,
                  bounce_session_kc_id(other), session->hs_sessid,
                  bounce_session_kc_id(session));
      break;
    }
  }
  /* The incoming primary's copy of the session is live. */
  bounce_peer_holding_clear(target, cli_user(new_primary)->server);

  /* The legacy links know the session by the ghost's face, and the
   * incoming N was withheld from them: they renumber the face to the new
   * primary in place (BX P, naming the session's id now), sent while the
   * ghost still has the numeric they know. */
  bounce_legacy_face_change(ghost, target, link, new_full, NULL);

  /* The primary slot is the incoming primary's: the session is live
   * again, held by its server; no hold timer runs here. */
  if (t_active(&target->hs_hold_timer))
    timer_del(&target->hs_hold_timer);
  target->hs_state = BOUNCE_ACTIVE;
  target->hs_client = new_primary;
  target->hs_disconnect_time = 0;
  target->hs_last_active = CurrentTime;
  target->hs_restore_pending = 0;
  ircd_strncpy(target->hs_origin, cli_yxx(cli_user(new_primary)->server),
               sizeof(target->hs_origin));
  ircd_strncpy(target->hs_ghost_numeric, cli_yxx(new_primary),
               sizeof(target->hs_ghost_numeric));
  bounce_db_del(target->hs_sessid);

  /* Its live connections follow the incoming primary, and the aware
   * links learn ours as its aliases (a held session's aliases are not in
   * our burst, so the peer never heard of them). */
  for (i = 0; i < target->hs_alias_count; i++) {
    struct Client *alias = findNUser(target->hs_aliases[i].ba_numeric);
    if (!alias || !IsBouncerAlias(alias) || !cli_user(alias))
      continue;
    cli_user(alias)->alias_primary = new_primary;
    if (0 != strcmp(cli_session_id(alias), target->hs_sessid)) {
      presence_purge_session(cli_session_id(alias));
      ircd_strncpy(cli_session_id(alias), target->hs_sessid,
                   S2S_SESSID_BUFSIZE);
    }
    if (MyConnect(alias))
      bounce_announce_alias(target, alias, new_primary);
  }

  log_write(LS_USER, L_INFO, 0,
            "Bouncer yield: held ghost %s left; session %s follows %s on %s",
            cli_name(ghost), target->hs_sessid, new_full,
            cli_name(cli_user(new_primary)->server));

  /* The ghost leaves without a Q: the legacy links already hold the new
   * primary under its face, and an aware link learns it is gone by BX X
   * (exit_client).  Nothing names it any more. */
  SetBouncerInternalDestroy(ghost);
  exit_client(link, ghost, &me, "Bouncer session moved");

  /* Settled: the release of a burst gate this waited for runs after the
   * line being handled. */
  bounce_schedule_gate_release();
  return 0;
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
  /* M4b: when the account is held, filter aliases by whether their
   * effective profile wants this channel.  Non-held accounts keep
   * the legacy "all aliases mirror primary" behaviour. */
  int account_held = 0;
  {
    char hold[METADATA_VALUE_LEN];
    if (IsAccount(who) && cli_user(who)) {
      if (metadata_account_get(cli_user(who)->account, "draft/persistence/hold", hold) == 0)
        account_held = (hold[0] != '0');
      else
        account_held = feature_bool(FEAT_BOUNCER_DEFAULT_HOLD);
    }
  }

  if (!IsAccount(who) || IsBouncerAlias(who))
    return;

  as = bounce_find_by_account(cli_user(who)->account);
  if (!as)
    return;

  for (session = as->as_sessions; session; session = session->hs_anext) {
    for (i = 0; i < session->hs_alias_count; i++) {
      struct Client *alias = findNUser(session->hs_aliases[i].ba_numeric);
      struct Membership *pmem;
      struct Membership *amem;
      unsigned int aflags = CHFL_ALIAS;
      unsigned short aoplevel = MAXOPLEVEL;

      if (!(alias && IsBouncerAlias(alias)
            && cli_alias_primary(alias) == who
            && !find_member_link(chptr, alias)))
        continue;

      /* M4b filter: when held, only add aliases whose effective
       * profile wants this channel.  This is what makes per-profile
       * channel-list divergence actually divergent at the membership
       * level — otherwise bounce_sync_alias_join would undo every
       * BX V -#chan immediately.
       *
       * Permissive-default rule (matches M3): an empty effective
       * channel list means "no filter" — the alias mirrors the
       * primary like in the pre-M4b behaviour.  Only filter when
       * the alias's profile has a non-empty effective list AND the
       * channel is not in it. */
      if (account_held) {
        const char *prof = session->hs_aliases[i].ba_active_profile[0]
                             ? session->hs_aliases[i].ba_active_profile
                             : PERSISTENCE_PROFILE_DEFAULT;
        char eff[METADATA_VALUE_LEN];
        if (persistence_profile_channels_effective(cli_user(who)->account,
                                                    prof, eff,
                                                    sizeof(eff)) == 0
            && eff[0]
            && persistence_profile_channels_effective_has(
                 cli_user(who)->account, prof, chptr->chname) != 1)
          continue;
      }

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
      pmem = find_member_link(chptr, who);
      if (pmem) {
        aflags |= (pmem->status & (CHFL_CHANOP | CHFL_HALFOP | CHFL_VOICE));
        aoplevel = OpLevel(pmem);
      }
      add_user_to_channel(chptr, alias, aflags, aoplevel);
      amem = find_member_link(chptr, alias);

      /* Inherit primary's join_msgid/join_tv so chathistory dedup
       * treats the alias's join echo as the same logical event as
       * the primary's.  Without this, a late-arriving alias attach
       * gets a fresh msgid and chathistory replay shows two distinct
       * JOIN entries for what is one connection event. */
      if (amem && pmem && pmem->join_msgid[0]) {
        memcpy(amem->join_msgid, pmem->join_msgid, sizeof(amem->join_msgid));
        amem->join_tv = pmem->join_tv;
      }

      /* (BX J retired in Phase 5.  Mid-session alias auto-attach
       * after BX C-with-chanlist relies on the standard P10 join
       * propagation that fires when add_user_to_channel runs through
       * the regular code path; the prior BX J wire was a fallback
       * for burst-race scenarios that no longer apply with the
       * tightened burst gate.) */

      /* Send post-join replies to the freshly-attached alias.  Without
       * this the alias's client sees no NAMES/TOPIC for the channel,
       * which manifests as an "empty room".  This path runs when the
       * primary joins a channel AFTER alias setup completed (e.g.
       * channel B burst arrives after bounce_setup_local_alias's
       * bounce_send_channel_state already iterated an empty channel
       * list on the alias side).
       *
       * Send the JOIN echo with the primary's join_msgid + timestamp
       * (set above) so clients that key off JOIN msgid for chathistory
       * see a stable identity. */
      if (MyConnect(alias)) {
        const char *join_msgid = (pmem && pmem->join_msgid[0])
                                 ? pmem->join_msgid : NULL;
        if (pmem && pmem->join_tv.tv_sec) {
          char timebuf[40];
          struct tm tm;
          gmtime_r(&pmem->join_tv.tv_sec, &tm);
          ircd_snprintf(0, timebuf, sizeof(timebuf),
                        "%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ",
                        tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                        tm.tm_hour, tm.tm_min, tm.tm_sec,
                        (long)(pmem->join_tv.tv_usec / 1000));
          sendcmdto_set_client_time(timebuf);
        }
        if (CapRecipientHas(alias, CAP_EXTJOIN))
          sendcmdto_one_tags_ext(alias, CMD_JOIN, alias, join_msgid,
                                 "%H %s :%s", chptr,
                                 IsAccount(alias) ? cli_account(alias) : "*",
                                 cli_info(alias));
        else
          sendcmdto_one_tags_ext(alias, CMD_JOIN, alias, join_msgid,
                                 ":%H", chptr);
        sendcmdto_set_client_time(NULL);
        if (chptr->topic[0]) {
          send_reply(alias, RPL_TOPIC, chptr->chname, chptr->topic);
          send_reply(alias, RPL_TOPICWHOTIME, chptr->chname,
                     chptr->topic_nick, chptr->topic_time);
        }
        send_markread_on_join(alias, chptr->chname);
        if (!CapRecipientHas(alias, CAP_NOIMPLICITNAMES) &&
            !CapRecipientHas(alias, CAP_NOIMPLICITNAMES_LEGACY))
          do_names(alias, chptr, NAMES_ALL|NAMES_EON);
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
    if (!HasNoImplicitNames(who))
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
    if (!HasNoImplicitNames(acli))
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
 * The forward is the same event as the delivery to the primary, so every
 * copy carries its msgid and time: a local alias gets them as client tags
 * (with the sender's client-only tags, as the primary did), a remote
 * alias as the S2S tag region its server takes them from.  A remote
 * alias's next hop is always IRCv3-aware (the fork sends BX C only to
 * aware peers, so an alias is known only behind them), so that region
 * goes out whenever P10_MESSAGE_TAGS is on; with it off the line goes
 * bare and the alias's server mints its own msgid.
 *
 * Every server on the message's path runs this for the aliases in its
 * own replica of the session, so a remote alias is sent a copy only by
 * the path server where the alias's direction leaves the path:
 *  - an alias behind \a inbound is served by a server before this one;
 *  - when the target is remote, an alias in the target's direction is
 *    served further along (at the latest by the target's own server).
 * Sending in either case gave the alias the message twice.
 *
 * Every copy is sourced from the sender's session primary, as the
 * primary's own delivery is, except a remote copy whose alias lies in
 * that primary's direction: the alias's server would get it over a link
 * other than the source's own and drop it as a fake direction (with a
 * third fork direction; the server that skips the alias by the rules
 * above counts on this copy), so that copy is sourced from \a from.
 * Its direction is never the alias's (a remote \a from came over
 * \a inbound, whose aliases are skipped above), and an alias \a from is
 * known wherever the alias is (BX C introduces it to every aware server).
 *
 * @param[in] from        The original sender, never rewritten to its
 *                        session primary (this function does that).
 * @param[in] target      Target client (must be the primary, not an alias).
 * @param[in] inbound     Server link the message arrived on, or NULL when
 *                        its sender is local.
 * @param[in] cmd         Long command name (MSG_PRIVATE or MSG_NOTICE).
 * @param[in] tok         Short command token (TOK_PRIVATE or TOK_NOTICE).
 * @param[in] text        Message text.
 * @param[in] msgid       The message's msgid (NULL or empty when msgids
 *                        are off).
 * @param[in] event_ms    The message's one time, in epoch milliseconds.
 * @param[in] client_tags The sender's client-only tags, or NULL.
 */
void bounce_forward_pm_to_aliases(struct Client *from, struct Client *target,
                                  struct Client *inbound,
                                  const char *cmd, const char *tok,
                                  const char *text, const char *msgid,
                                  uint64_t event_ms, const char *client_tags)
{
  struct BouncerSession *sess;
  struct Client *primary;
  int i;

  /* Only forward for bouncer primaries with aliases */
  if (!IsAccount(target) || IsBouncerAlias(target))
    return;

  sess = bounce_get_session(target);
  if (!sess || sess->hs_alias_count <= 0)
    return;

  if (msgid && !*msgid)
    msgid = NULL;

  primary = (IsBouncerAlias(from) && cli_user(from)->alias_primary)
            ? cli_user(from)->alias_primary : from;

  for (i = 0; i < sess->hs_alias_count; i++) {
    struct Client *alias = findNUser(sess->hs_aliases[i].ba_numeric);
    struct Client *src;

    if (!alias || alias == target || !IsBouncerAlias(alias))
      continue;

    if (MyConnect(alias)) {
      /* The event's own time on the @time tag, and its msgid on the
       * tags of a client-tag delivery; cleared again right after, so it
       * cannot stamp a later send. */
      if (msgid)
        sendcmdto_set_client_event(msgid, event_ms);
      sendcmdto_one_tags_with_client(primary, cmd, tok, alias, msgid,
                                     client_tags, "%C :%s", alias, text);
      sendcmdto_set_client_msgid(NULL);
      continue;
    }

    if (inbound && cli_from(alias) == inbound)
      continue;
    if (!MyConnect(target) && cli_from(alias) == cli_from(target))
      continue;

    src = primary;
    if (src != from && !MyUser(src) && cli_from(src) == cli_from(alias))
      src = from;

    /* Armed per alias: the send consumes the overrides.  With msgids off
     * the inbound line's own tags (if any) are relayed. */
    sendcmdto_set_s2s_cptr(inbound);
    if (msgid)
      sendcmdto_set_s2s_tags(event_ms, msgid);
    sendcmdto_one_tags_with_client(src, cmd, tok, alias, msgid,
                                   client_tags, "%C :%s", alias, text);
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

  /* The echo is a message sourced from the user's own nick.  Only a
   * connection that negotiated echo-message can place it (ZNC's
   * znc.in/self-message solves the same problem by opt-in); a client
   * without it files a PRIVMSG to a non-channel target under its
   * SOURCE, i.e. a query window with the user's own nick.  Local
   * members are gated here, remote ones on the receiving server
   * (bounce_alias_echo / deliver_s2s_bxm_batch) and pre-filtered by
   * the replicated BX_CAP_ECHO_MESSAGE where known. */
  /* Echo to primary (if sender is not the primary) */
  if (sender != primary) {
    if (MyConnect(primary)) {
      if (CapActive(primary, CAP_ECHOMSG))
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
      if (CapActive(alias, CAP_ECHOMSG))
        sendcmdto_one_tags_ext(primary, cmd, tok, alias, msgid,
                               "%s :%s", cli_name(target), text);
    } else {
      if (sess->hs_aliases[i].ba_caps_known
          && !(sess->hs_aliases[i].ba_caps & BX_CAP_ECHO_MESSAGE))
        continue;
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
/** See include/bouncer_session.h. */
int bounce_account_deauth_apply(struct Client *acptr)
{
  struct AccountSessions *as;
  struct BouncerSession *sess;
  const char *account;

  assert(0 != acptr);
  assert(0 != cli_user(acptr));
  assert(0 != cli_user(acptr)->account[0]);
  account = cli_user(acptr)->account;

  /* Tell the aliases FIRST, for every session of the account:
   * bounce_emit_alias_update walks a session's roster through
   * bounce_get_session(), so it must run before the sessions are
   * destroyed below and before ClearAccount (it bails on
   * !IsAccount(primary)).  With it after the destroy loop the emit found
   * no session and cleared nothing -- on both callers.  And the loop
   * below takes every session of the account, not only acptr's, so a
   * sibling session's aliases would be left unheard if only acptr's
   * were told. */
  as = bounce_find_by_account(account);
  for (sess = as ? as->as_sessions : NULL; sess; sess = sess->hs_anext) {
    struct Client *primary = sess->hs_client;
    if (primary && IsAccount(primary) && !IsBouncerAlias(primary))
      bounce_emit_alias_update(primary, "account", "");
  }

  /* Destroy every session of the account before clearing it.  Re-lookup
   * each iteration because bounce_destroy() may free the AccountSessions
   * struct when the last session is removed.
   *
   * When acptr is the ghost of a held session, the account going away
   * leaves nothing to revive into: the session's aliases are exited the
   * way a KILL of the ghost would take them.  The ghost itself is the
   * caller's to exit (see the return value) -- the caller is still using
   * it, and only its own server may exit it (exit_client() on a remote
   * client is B-2; the home server gets the same AC U). */
  while ((sess = bounce_find_any_session(account)) != NULL) {
    if (sess->hs_client == acptr && IsBouncerHold(acptr) && MyConnect(acptr)) {
      int i;
      for (i = sess->hs_alias_count - 1; i >= 0; i--) {
        struct Client *alias = findNUser(sess->hs_aliases[i].ba_numeric);
        if (alias)
          exit_client(alias, alias, &me, "Account deauthorized");
      }
    }
    sess->hs_client = NULL;
    bounce_destroy(sess);
  }

  /* Clear all persisted metadata for this account from the store and
   * free in-memory metadata entries.  Must happen while the account
   * string is still set so the lookup key is valid. */
  metadata_clear_client(acptr);

  /* Decrement authusers for all channels this user is in.
   * channel_account_adjust skips CHFL_ALIAS memberships, so a deauth
   * addressed at an alias numeric cannot steal counts the alias never
   * added. */
  channel_account_adjust(acptr, -1);

  /* Strict-presence anchor transfer: account -> session, closing the
   * account-anchored open interval (deauth previously left it open
   * forever -- unbounded forward visibility). */
  presence_anchor_transfer(acptr, cli_user(acptr)->account, 0,
                           cli_session_id(acptr), 1);

  ClearAccount(acptr);
  ircd_strncpy(cli_user(acptr)->account, "", ACCOUNTLEN + 1);
  cli_user(acptr)->acc_create = 0;      /* the removed account's, not the next one's */
  cli_user(acptr)->kc_id[0] = '\0';

  /* A local held ghost now has neither account nor session (a sibling's
   * deauth may have taken the session first; the ghost still has to go,
   * or it holds the nick forever with no timer to end it). */
  return (IsBouncerHold(acptr) && MyConnect(acptr)) ? 1 : 0;
}

/** See include/bouncer_session.h. */
void bounce_apply_alias_field(struct Client *alias, enum BounceAliasField id,
                              const char *value)
{
  assert(0 != alias);
  assert(0 != cli_user(alias));
  assert(0 != value);

  switch (id) {
  case BX_ALIAS_FIELD_HOST:
    ircd_strncpy(cli_user(alias)->host, value, HOSTLEN + 1);
    break;
  case BX_ALIAS_FIELD_REALHOST:
    ircd_strncpy(cli_user(alias)->realhost, value, HOSTLEN + 1);
    break;
  case BX_ALIAS_FIELD_REALNAME:
    ircd_strncpy(cli_info(alias), value, REALLEN + 1);
    break;
  case BX_ALIAS_FIELD_FAKEHOST:
    ircd_strncpy(cli_user(alias)->fakehost, value, HOSTLEN + 1);
    break;
  case BX_ALIAS_FIELD_CLOAKHOST:
    ircd_strncpy(cli_user(alias)->cloakhost, value, HOSTLEN + 1);
    break;
  case BX_ALIAS_FIELD_CLOAKIP:
    ircd_strncpy(cli_user(alias)->cloakip, value, HOSTLEN + 1);
    break;
  case BX_ALIAS_FIELD_USERNAME:
    ircd_strncpy(cli_user(alias)->username, value, USERLEN + 1);
    break;

  case BX_ALIAS_FIELD_ACCOUNT: {
    /* Both directions: "" clears, anything else sets.  This case was
     * absent from the local-apply block, so every account set (SASL
     * success, AC R, AC M) and every clear (AC U, webhook deauth) was
     * lost for aliases on the primary's own server.
     *
     * The account's identity travels with its name: the timestamp and the
     * Keycloak id come from the primary, never from the account the alias
     * had before.  Left alone, the next burst announced
     * newaccount:oldts:oldid, which X3 takes for a recreated account and
     * resets.  On a server where this update arrives before the AC that
     * changes the primary, the AC path catches up
     * (bounce_sync_alias_identity). */
    struct Client *primary = cli_user(alias)->alias_primary;

    ircd_strncpy(cli_user(alias)->account, value, ACCOUNTLEN + 1);
    if (value[0] != '\0') {
      SetAccount(alias);
      if (primary && cli_user(primary)
          && 0 == ircd_strcmp(cli_user(primary)->account, value)) {
        cli_user(alias)->acc_create = cli_user(primary)->acc_create;
        ircd_strncpy(cli_user(alias)->kc_id, cli_user(primary)->kc_id,
                     sizeof(cli_user(alias)->kc_id));
      } else {
        cli_user(alias)->acc_create = 0;
        cli_user(alias)->kc_id[0] = '\0';
      }
      Debug((DEBUG_DEBUG, "Alias %s follows account \"%s\" with id \"%s\"",
             cli_name(alias), value, cli_user(alias)->kc_id));
    } else {
      ClearAccount(alias);
      cli_user(alias)->acc_create = 0;
      cli_user(alias)->kc_id[0] = '\0';
    }
    break;
  }

  case BX_ALIAS_FIELD_CAPS: {
    /* Update the BounceAlias entry's ba_caps for this alias.  Walk
     * the alias's account's sessions, find the matching entry by
     * full YYXXX numeric, set ba_caps + ba_caps_known.  Sender-side
     * BX M dispatch consults this to pick BX M vs BX E. */
    unsigned long caps = strtoul(value, NULL, 16);
    if (IsAccount(alias)) {
      struct AccountSessions *as =
        bounce_find_by_account(cli_user(alias)->account);
      if (as) {
        char full_numeric[6];
        struct BouncerSession *sess;
        int i;
        ircd_snprintf(0, full_numeric, sizeof(full_numeric), "%s%s",
                      cli_yxx(cli_user(alias)->server), cli_yxx(alias));
        for (sess = as->as_sessions; sess; sess = sess->hs_anext) {
          for (i = 0; i < sess->hs_alias_count; i++) {
            if (0 == strcmp(sess->hs_aliases[i].ba_numeric, full_numeric)) {
              sess->hs_aliases[i].ba_caps = (unsigned int)caps;
              sess->hs_aliases[i].ba_caps_known = 1;
              /* Persist updated caps (per redesign B.6 lifecycle hook)
               * so post-restart we know each alias's caps without
               * waiting for peer's BX U on next link. */
              bounce_db_put(sess);
            }
          }
        }
      }
    }
    break;
  }

  case BX_ALIAS_FIELD_UNKNOWN:
  case BX_ALIAS_FIELD_COUNT:
    break;
  }
}

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
    struct Client *alias = findNUser(sess->hs_aliases[i].ba_numeric);

    /* Local aliases on this (primary's) server: apply the field update
     * directly. The S2S broadcast below skips us for loop-prevention,
     * so without this pass our own local aliases stay stale. */
    if (alias && IsBouncerAlias(alias) && MyConnect(alias))
      bounce_apply_alias_field(alias, bounce_alias_field_id(field), value);

    /* The account field rides AC U's coherence rules: if the network
     * cannot be told the account was cleared (legacy accounts have no
     * AC unregister form), do not tell the aliases either -- a
     * half-applied clear leaves one session's connections disagreeing
     * about their own account. */
    if (bounce_alias_field_id(field) == BX_ALIAS_FIELD_ACCOUNT
        && value[0] == '\0'
        && !feature_bool(FEAT_EXTENDED_ACCOUNTS))
      continue;

    sendcmdto_serv_butone_v3(&me, CMD_BOUNCER_TRANSFER, NULL,
                          "U %s %s=%s",
                          sess->hs_aliases[i].ba_numeric, field, value);
  }
}

/** Bring this server's aliases of @a primary (its own connections and the
 * replicas of others) to the primary's account timestamp and Keycloak id
 * when they name its account.  The primary's server sends BX U account=
 * before the AC that changes the primary, so on the other servers the
 * alias took the primary's previous ts/id; the AC path calls this once the
 * primary is updated, and either order ends the same. */
void bounce_sync_alias_identity(struct Client *primary)
{
  struct BouncerSession *sess;
  int i;

  if (!primary || !cli_user(primary) || !IsAccount(primary)
      || IsBouncerAlias(primary))
    return;
  sess = bounce_get_session(primary);
  if (!sess)
    return;
  for (i = 0; i < sess->hs_alias_count; i++) {
    struct Client *alias = findNUser(sess->hs_aliases[i].ba_numeric);
    if (!alias || !IsBouncerAlias(alias) || !cli_user(alias)
        || cli_user(alias)->alias_primary != primary
        || 0 != ircd_strcmp(cli_user(alias)->account, cli_user(primary)->account))
      continue;
    cli_user(alias)->acc_create = cli_user(primary)->acc_create;
    ircd_strncpy(cli_user(alias)->kc_id, cli_user(primary)->kc_id,
                 sizeof(cli_user(alias)->kc_id));
  }
}

/** Compute the BX_CAP_* bitmask for a client from its active caps. */
static unsigned int
bounce_compute_bx_caps(struct Client *cptr)
{
  unsigned int caps = 0;
  if (CapActive(cptr, CAP_DRAFT_MULTILINE))
    caps |= BX_CAP_DRAFT_MULTILINE;
  if (CapActive(cptr, CAP_BATCH))
    caps |= BX_CAP_BATCH;
  if (CapActive(cptr, CAP_ECHOMSG))
    caps |= BX_CAP_ECHO_MESSAGE;
  return caps;
}

/** Broadcast a BX U caps=<hex> for a local client whose cap state
 * changed.  Called from m_cap.c (cap_req / cap_ack / cap_clear) right
 * after bounce_recompute_session_caps, and also from
 * bounce_alias_create's local-alias setup so newly-created aliases
 * publish their initial caps without waiting for a CAP REQ.
 *
 * The receiver uses the caps to pick BX M vs BX E in
 * emit_bxm_to_remote_member.  Updates the local-server view of its
 * own ba_caps too — keeps everyone (including the originator's
 * aliases on the same server) coherent.
 */
void bounce_emit_alias_caps(struct Client *cptr)
{
  unsigned int caps;
  char full_numeric[6];
  char hex[12];
  struct AccountSessions *as;
  struct BouncerSession *sess;
  int i;

  if (!cptr || !MyConnect(cptr) || !IsUser(cptr))
    return;
  if (!IsAccount(cptr))
    return;

  /* Only emit for clients participating in a bouncer session — primary
   * with hs_aliases, OR a bouncer alias.  Plain non-bouncer users
   * don't need their caps tracked across S2S. */
  as = bounce_find_by_account(cli_user(cptr)->account);
  if (!as || !as->as_sessions)
    return;
  if (!IsBouncerAlias(cptr)) {
    /* Primary — only emit if there are aliases that would care. */
    int has_any = 0;
    for (sess = as->as_sessions; sess; sess = sess->hs_anext) {
      if (sess->hs_alias_count > 0) {
        has_any = 1;
        break;
      }
    }
    if (!has_any)
      return;
  }

  caps = bounce_compute_bx_caps(cptr);
  ircd_snprintf(0, full_numeric, sizeof(full_numeric), "%s%s",
                cli_yxx(cli_user(cptr)->server), cli_yxx(cptr));
  ircd_snprintf(0, hex, sizeof(hex), "%x", caps);

  /* Update our own session-replica view first.  The S2S broadcast
   * below skips us via butone, so without this our own server's
   * ba_caps for this alias would stay stale. */
  for (sess = as->as_sessions; sess; sess = sess->hs_anext) {
    for (i = 0; i < sess->hs_alias_count; i++) {
      if (0 == strcmp(sess->hs_aliases[i].ba_numeric, full_numeric)) {
        sess->hs_aliases[i].ba_caps = caps;
        sess->hs_aliases[i].ba_caps_known = 1;
      }
    }
  }

  sendcmdto_serv_butone_v3(&me, CMD_BOUNCER_TRANSFER, NULL,
                        "U %s caps=%s", full_numeric, hex);
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
  FLAG_CLOAKIP, FLAG_CLOAKHOST,
  /* Not FLAG_SSL: each connection's TLS is its own.  Synced, a plaintext
   * member's mode change took +z from a TLS alias (alias setup re-asserts
   * it once, the live sync never did). */
  /* FLAG_SERVNOTICE gates ALL server-notice delivery via
   * sendto_opmask_butone's opsarray walk.  Without it, an alias has
   * an inherited snomask but lands in NO bucket, so /OPER + cross-
   * server SNO_NETWORK / SNO_OLDSNO traffic is silently dropped on
   * that connection.  Sync alongside FLAG_WALLOP/FLAG_DEBUG so all
   * three oper-routing flags travel together. */
  FLAG_SERVNOTICE,
  -1
};

/** Copy user mode flags from one client to another.
 * Only copies the flags listed in umode_sync_flags[].
 *
 * On MyConnect destinations, mirror set_user_mode's UserStats.opers /
 * UserStats.inv_clients bookkeeping for FLAG_OPER and FLAG_INVISIBLE
 * transitions (s_user.c:2440+).  Without this, an alias created with
 * +o or +i via the raw SetFlag here is never counted, leaving the
 * later exit_one_client normal-path decrement (s_misc.c:492-499) free
 * to underflow the network-wide counter.
 *
 * @param[in]  from Source client (usually the primary).
 * @param[out] to   Destination client (usually an alias).
 */
static void bounce_copy_umodes(struct Client *from, struct Client *to)
{
  int i;

  for (i = 0; umode_sync_flags[i] >= 0; i++) {
    /* +s is known only where the connection is: P10 never carries it,
     * so a remote Client's flag says nothing (its server sends the mask
     * and the flag by BX K).  Copied from a remote source it would clear
     * +s on every local member at each umode change of the primary. */
    if (umode_sync_flags[i] == FLAG_SERVNOTICE && !MyConnect(from))
      continue;
    if (HasFlag(from, umode_sync_flags[i]))
      SetFlag(to, umode_sync_flags[i]);
    else
      ClrFlag(to, umode_sync_flags[i]);
  }

  /* Reconcile UserStats oper/inv counting to @a to's new mode + alias state.
   * Idempotent and flag-keyed (FLAG_COUNTED_*), so it is correct regardless of
   * MyConnect / registration timing / which path set +o|+i, and self-balances the
   * convert-in-place case (an already-counted client converted to a remote alias
   * becomes ineligible and releases its prior count). */
  userstats_count_sync(to);
}

/** The server notice mask of session member @a cptr as this server knows
 * it: a live local connection's own (0 without +s), a local held ghost's
 * as bounce_hold_client() saved it.  A remote Client's is not known here
 * -- its cli_snomask is its uplink link's Connection field, and P10 never
 * carries +s -- so *known is 0 and its own server is the one to say.
 * @param[in] cptr Session member.
 * @param[in] sess Its session.
 * @param[out] known Set to 1 when the returned mask is meaningful.
 * @return The mask.
 */
static unsigned int bounce_member_snomask(struct Client *cptr,
                                          struct BouncerSession *sess,
                                          int *known)
{
  *known = 0;
  if (!cptr || !MyConnect(cptr) || !IsUser(cptr))
    return 0;
  if (IsBouncerHold(cptr)) {
    if (!sess || !sess->hs_snomask_known)
      return 0;
    *known = 1;
    return sess->hs_snomask;
  }
  *known = 1;
  return HasFlag(cptr, FLAG_SERVNOTICE) ? cli_snomask(cptr) : 0;
}

/** Take a Lamport stamp for a change of @a sess's mask made on this
 * server: the clock, but past the last stamp seen, so a change made after
 * one received is ordered after it whatever the servers' clocks say. */
static void bounce_stamp_snomask(struct BouncerSession *sess)
{
  time_t ts = CurrentTime;

  if (ts <= sess->hs_snomask_ts)
    ts = sess->hs_snomask_ts + 1;
  sess->hs_snomask_ts = ts;
  ircd_strncpy(sess->hs_snomask_origin, cli_yxx(&me),
               sizeof(sess->hs_snomask_origin));
}

/** Is a change of @a sess's mask stamped @a ts by server @a origin later
 * than the last one taken?  The lower server numeric wins a tie, the same
 * answer on every server, so crossing changes converge. */
static int bounce_snomask_later(const struct BouncerSession *sess,
                                time_t ts, const char *origin)
{
  if (ts != sess->hs_snomask_ts)
    return ts > sess->hs_snomask_ts;
  return strcmp(origin, sess->hs_snomask_origin) < 0;
}

/** Tell the BX-aware server of remote session member @a target the
 * session's mask and its stamp (BX K), routed toward it.  The numeric is
 * the full YYXXX: the receiver resolves it with bx_find_user_strict. */
static void bounce_send_member_snomask(struct Client *target,
                                       struct BouncerSession *sess)
{
  struct Client *peer;

  if (!target || MyConnect(target) || !cli_user(target)
      || !cli_user(target)->server)
    return;
  peer = cli_from(target);
  if (!peer || !IsServer(peer) || !IsIRCv3Aware(peer))
    return;
  sendcmdto_one(&me, CMD_BOUNCER_TRANSFER, target, "K %s%s %u %Tu",
                cli_yxx(cli_user(target)->server), cli_yxx(target),
                sess->hs_snomask, sess->hs_snomask_ts);
}

/** Give live local session member @a cptr the session's mask @a mask:
 * +s iff it is non-zero.  With @a tell, the client hears what changed --
 * for a mask that arrived by BX K, which it did not ask for and has no
 * other way to learn (send_umode_signon ran before it arrived).  The
 * session sync among one server's own members stays silent, as it is
 * for every other mode (deferred-items register). */
static void bounce_put_member_snomask(struct Client *cptr, unsigned int mask,
                                      int tell)
{
  int had = HasFlag(cptr, FLAG_SERVNOTICE) ? 1 : 0;
  unsigned int old = cli_snomask(cptr);

  assert(MyConnect(cptr));
  /* As set_user_mode: HIS_SNOTICES_OPER_ONLY keeps a non-oper from
   * taking +s, not from keeping it (a -o leaves it, clamped). */
  if (mask && !had && feature_bool(FEAT_HIS_SNOTICES_OPER_ONLY)
      && !IsAnOper(cptr))
    mask = 0;
  /* set_snomask() clamps a non-oper's mask to SNO_USER. */
  set_snomask(cptr, mask, SNO_SET);
  if (cli_snomask(cptr))
    SetServNotice(cptr);
  else
    ClearServNotice(cptr);

  if (!tell)
    return;
  if (had != (HasFlag(cptr, FLAG_SERVNOTICE) ? 1 : 0))
    sendcmdto_one(cptr, CMD_MODE, cptr, "%s %s", cli_name(cptr),
                  HasFlag(cptr, FLAG_SERVNOTICE) ? "+s" : "-s");
  if (cli_snomask(cptr) && cli_snomask(cptr) != old)
    send_reply(cptr, RPL_SNOMASK, cli_snomask(cptr), cli_snomask(cptr));
}

/** Clamp live local member @a cptr's mask to what it may still hold --
 * after it lost +o by a path that does not carry the mask (a remote
 * primary's -o arrives as a flag; a BS O clear): set_user_mode's -o keeps
 * +s and strips the oper-only bits, and so does this. */
static void bounce_reclamp_snomask(struct Client *cptr)
{
  if (!cptr || !MyConnect(cptr) || IsBouncerHold(cptr))
    return;
  set_snomask(cptr, cli_snomask(cptr), SNO_SET); /* clamps a non-oper's to SNO_USER */
  if (!cli_snomask(cptr))
    ClearServNotice(cptr);
}

/** Take what being an oper gave local connection @a cptr -- privileges,
 * OPER_HANDLER, the opername -- once it is no oper.  The session sync
 * used to copy them onto the other connections at +o and never take them
 * back at -o: they kept running oper commands, and the ones that assert
 * IsAnOper (KILL, CLOSE, CONNECT ...) aborted the server (deferred-items
 * B2, 2026-10-21).  The mode flags and the counters are the caller's
 * (bounce_copy_umodes / userstats_count_sync); this is the rest. */
static void bounce_strip_oper_privs(struct Client *cptr)
{
  if (!cptr || !MyConnect(cptr) || IsAnOper(cptr))
    return;
  client_set_privs(cptr, NULL);   /* clears every privilege */
  clear_privs(cptr);
  if (cli_handler(cptr) == OPER_HANDLER)
    cli_handler(cptr) = CLIENT_HANDLER;
  if (cli_user(cptr) && cli_user(cptr)->opername) {
    MyFree(cli_user(cptr)->opername);
    cli_user(cptr)->opername = NULL;
  }
}

/** Give revived @a ghost its real realname back, spread as SETNAME is
 * (m_setname.c): the BX-aware servers by SETNAME, the legacy ones by SI
 * (stock ms_svsinfo takes it from any server), this server's aliases, and
 * the channel members that asked for setname. */
static void bounce_repair_realname(struct Client *ghost, const char *realname)
{
  log_write(LS_USER, L_INFO, 0, "Bouncer: %s's realname \"%s\" was an old "
            "exit reason; repaired to \"%s\" from the reviving connection",
            cli_name(ghost), cli_info(ghost), realname);
  ircd_strncpy(cli_info(ghost), realname, REALLEN + 1);
  sendcmdto_serv_butone_v3(ghost, CMD_SETNAME, NULL, ":%s", cli_info(ghost));
  sendcmdto_legacy_serv_butone(&me, CMD_SVSINFO, NULL, "%C :%s", ghost,
                               cli_info(ghost));
  bounce_emit_alias_update(ghost, "realname", cli_info(ghost));
  sendcmdto_common_channels_capab_butone(ghost, CMD_SETNAME, ghost,
                                         CAP_SETNAME, CAP_NONE,
                                         ":%s", cli_info(ghost));
}

/** Look up the global O:line config item by name (CONF_OPERATOR only).
 * Returns NULL if no matching opername is configured locally.  Used by
 * the session-grant restoration path on alias promotion: when the new
 * primary inherits IsOper from the session's hs_oper_grant, we re-apply
 * privs/snomask/handler from the local O:line keyed by the stored
 * opername.  This is a simpler lookup than find_conf_exact() because
 * we trust the grant — no host/password verification is needed; the
 * grant came from an earlier successful /OPER on a session member. */
static struct ConfItem *find_oper_conf_by_name(const char *opername)
{
  struct ConfItem *aconf;
  if (!opername || !*opername)
    return NULL;
  for (aconf = GlobalConfList; aconf; aconf = aconf->next) {
    if ((aconf->status & CONF_OPERATOR) && aconf->name
        && 0 == strcmp(aconf->name, opername))
      return aconf;
  }
  return NULL;
}

/** Re-apply the session's oper grant to @a cptr, which has just become
 * a local primary (via promote or revival).  No-op if the session has
 * no grant, @a cptr isn't local, or no local O:line matches the grant
 * opername (config may have changed since the grant was made — fail
 * open: the new primary stays non-oper, the session retains the grant
 * for any future server that does have a matching O:line). */
static void bounce_apply_oper_grant(struct Client *cptr,
                                     struct BouncerSession *sess)
{
  struct ConfItem *aconf;
  if (!cptr || !sess || !MyConnect(cptr) || !IsUser(cptr))
    return;
  if (!sess->hs_oper_name[0])
    return;
  if (IsOper(cptr))
    return;   /* already opered — sync path will have populated privs */
  aconf = find_oper_conf_by_name(sess->hs_oper_name);
  if (!aconf)
    return;
  /* client_set_privs() early-returns if the client isn't already
   * IsAnOper.  do_oper() works around this by SetOper/ClearOper
   * bracketing the call; mirror that here.  Without the bracket, no
   * privs land on @a cptr, HasPriv(PRIV_PROPAGATE) is false below, the
   * else branch runs SetLocOp, and the resumed session comes back as
   * LocalOp (+O) instead of global oper (+o) — silently demoted on
   * every restart.  mo_oper short-circuits subsequent /OPER attempts
   * to a bare RPL_YOUREOPER (m_oper.c:557), so the user has no way to
   * recover their original grant. */
  SetOper(cptr);
  client_set_privs(cptr, aconf);
  ClearOper(cptr);
  if (HasPriv(cptr, PRIV_PROPAGATE)) {
    SetOper(cptr);
    if (HasPriv(cptr, PRIV_ADMIN))
      SetAdmin(cptr);
    /* Count the grant (flag-keyed source of truth, matched at exit/-o). */
    userstats_count_sync(cptr);
  } else {
    SetLocOp(cptr);
  }
  cli_handler(cptr) = OPER_HANDLER;
  /* Mirror do_oper (m_oper.c:222-229): the oper umode flags and snomask
   * are part of the oper grant, not just FLAG_OPER + privs.  Without
   * them the granted user has no server-notice routing, no wallops
   * delivery, and no debug snomask — they're opered but can't see any
   * of the SNO_NETWORK / SNO_OLDSNO traffic (SQUIT, Net break, KILL
   * notices) that opers normally rely on.  Applies to BS O receivers,
   * ghost revivals, and any other non-/OPER grant entry. */
  SetFlag(cptr, FLAG_WALLOP);
  SetFlag(cptr, FLAG_DEBUG);
  {
    unsigned int mask;

    if (sess->hs_snomask_known) {
      /* The oper's own mask, kept with the session (saved at hold,
       * persisted, carried by BX K): what they had, not the O:line
       * default -- and no +s if they had turned it off (user,
       * 2026-10-21: the mask comes back wherever +o does). */
      mask = sess->hs_snomask & SNO_ALL;
    } else {
      /* None recorded (a pre-v11 record): the O:line's, added to what
       * the client holds, as do_oper does; the session records it, so a
       * BX C answer and a later hold carry it. */
      mask = (ConfSnoMask(aconf) | aconf->snomask) & SNO_ALL;
      if (!mask)
        mask = feature_int(FEAT_SNOMASK_OPERDEFAULT);
      if (!IsBouncerHold(cptr))
        mask |= cli_snomask(cptr);
      sess->hs_snomask = mask;
      sess->hs_snomask_known = 1;
      bounce_stamp_snomask(sess);
    }
    if (mask)
      SetFlag(cptr, FLAG_SERVNOTICE);
    else
      ClrFlag(cptr, FLAG_SERVNOTICE);
    /* A held ghost (restored from the DB) stays out of the opsarray, as
     * every held ghost is: the revive gives it the session's mask. */
    if (!IsBouncerHold(cptr))
      set_snomask(cptr, mask, SNO_SET);
  }
  if (cli_user(cptr)) {
    if (cli_user(cptr)->opername)
      MyFree(cli_user(cptr)->opername);
    DupString(cli_user(cptr)->opername, sess->hs_oper_name);
  }
}

/** Inverse of bounce_apply_oper_grant — clear oper state on a local
 * Client.  Mirrors set_user_mode's -o bookkeeping (s_user.c:2417+) so
 * UserStats.opers tracks across cross-server grant clears.  No-op for
 * remote Clients (the P10 MODE -o path handles those) and for
 * Clients that aren't currently opered. */
static void bounce_clear_oper_locally(struct Client *cptr)
{
  if (!cptr || !MyConnect(cptr) || !IsUser(cptr))
    return;
  if (!IsOper(cptr) && !IsLocOp(cptr))
    return;
  ClearOper(cptr);
  ClearLocOp(cptr);
  ClearAdmin(cptr);
  /* Reconcile the counter now that +o is cleared (flag-keyed: decrements iff
   * this client was actually counted). */
  userstats_count_sync(cptr);
  bounce_strip_oper_privs(cptr);
  /* The oper-only notice bits go with +o (set_user_mode's -o strips them
   * the same way). */
  bounce_reclamp_snomask(cptr);
}

/** Apply or clear a session's oper grant on every locally-attached
 * member (primary if local, plus all local aliases).  Called from the
 * BS O receive path; @a opername NULL or empty clears the grant. */
static void bounce_apply_remote_oper_grant(struct BouncerSession *sess,
                                            const char *opername,
                                            time_t granted_at)
{
  struct Client *primary;
  int i;

  if (!sess)
    return;

  /* Update the session record itself so /CHECK and a future server
   * restart see the right state. */
  if (opername && *opername) {
    ircd_strncpy(sess->hs_oper_name, opername, sizeof(sess->hs_oper_name));
    sess->hs_oper_granted_at = granted_at ? granted_at : CurrentTime;
  } else {
    sess->hs_oper_name[0] = '\0';
    sess->hs_oper_granted_at = 0;
  }
  /* Mark dirty AND arm the persist timer.  Without arming, an
   * abrupt termination between this BS O receive and the next
   * dirty event (channel JOIN/PART/etc.) would lose the cross-
   * server grant propagation here.  bounce_mark_dirty gates on
   * BOUNCE_ACTIVE; this code path can run for HOLDING sessions
   * too (peer broadcasts an oper grant while our local primary is
   * in hold), so call the timer-arm directly. */
  sess->hs_dirty = 1;
  bounce_start_dirty_persist_timer();

  /* Apply to local primary, if any.  Remote primaries are handled by
   * the P10 MODE +o / -o that arrives in the same TCP stream from the
   * originating server. */
  primary = sess->hs_client;
  if (primary && MyConnect(primary)) {
    if (sess->hs_oper_name[0])
      bounce_apply_oper_grant(primary, sess);
    else
      bounce_clear_oper_locally(primary);
  }
  /* Plus every local alias. */
  for (i = 0; i < sess->hs_alias_count; i++) {
    struct Client *alias = findNUser(sess->hs_aliases[i].ba_numeric);
    if (!alias || !IsBouncerAlias(alias) || !MyConnect(alias))
      continue;
    if (sess->hs_oper_name[0])
      bounce_apply_oper_grant(alias, sess);
    else
      bounce_clear_oper_locally(alias);
  }
}

/** Sync umode (and oper privileges, handler, snomask) across all
 * members of @a source's bouncer session, treating @a source as the
 * canonical state.  Used by /OPER, /DEOPER, and the general
 * umode-change paths so that flag changes on any one connection of a
 * session propagate to the primary and sibling aliases.
 *
 * The earlier `bounce_sync_alias_umodes` assumed the caller was the
 * primary and short-circuited when the caller was a bouncer alias —
 * which meant /OPER on an alias never reached the primary or sibling
 * aliases.  Now any session member can be the source; the function
 * walks primary + alias_count and propagates from source to all
 * others.
 *
 * Cross-server BX K (snomask) emission is gated on IsIRCv3Aware:
 * legacy peers don't see bouncer aliases at all, and BX is a v3
 * extension; emitting to legacy would be wasted bytes at best and a
 * misrouted command at worst. */
void bounce_sync_session_umodes(struct Client *source,
                                const struct Flags *source_before,
                                struct Client *told)
{
  struct BouncerSession *sess;
  struct Client *primary;
  /* The other live local members, as they were before the copy: each is
   * told its own change afterwards (deferred-items, Rubin's #124 review:
   * a device already attached when X3 opers the session, or another
   * device runs OPER, was never told). */
  struct { struct Client *c; struct Flags flags; unsigned int mask; }
    before[BOUNCER_MAX_ALIASES + 1];
  int nbefore = 0;
  int i;

  if (!source || !IsUser(source))
    return;

  sess = bounce_get_session(source);
  if (!sess)
    return;

  primary = sess->hs_client;

  for (i = -1; i < sess->hs_alias_count && nbefore < BOUNCER_MAX_ALIASES + 1; i++) {
    struct Client *m = (i < 0) ? primary : findNUser(sess->hs_aliases[i].ba_numeric);
    if (!m || m == source || !IsUser(m) || !MyConnect(m) || IsBouncerHold(m)
        || (i >= 0 && !IsBouncerAlias(m)))
      continue;
    before[nbefore].c = m;
    before[nbefore].flags = cli_flags(m);
    before[nbefore].mask = cli_snomask(m);
    nbefore++;
  }

  /* Apply source's umode flags and privs to one target Client.  Self
   * (source == target) is skipped — bounce_copy_umodes would be wasted
   * work.  The server notice mask is bounce_sync_session_snomask's. */
#define APPLY_TO(target) do {                                              \
  struct Client *_t = (target);                                            \
  if (_t && _t != source && IsUser(_t)) {                                  \
    bounce_copy_umodes(source, _t);                                        \
    if (MyConnect(_t)) {                                                   \
      if (IsAnOper(source)) {                                              \
        memcpy(&cli_privs(_t), &cli_privs(source), sizeof(cli_privs(_t))); \
        cli_handler(_t) = OPER_HANDLER;                                    \
      } else                                                               \
        bounce_strip_oper_privs(_t);                                       \
    }                                                                      \
  }                                                                        \
} while (0)

  /* Primary covers the case where source is an alias.  When source IS
   * the primary, APPLY_TO short-circuits on source==target. */
  APPLY_TO(primary);

  /* Every alias except source. */
  for (i = 0; i < sess->hs_alias_count; i++) {
    struct Client *alias = findNUser(sess->hs_aliases[i].ba_numeric);
    if (alias && IsBouncerAlias(alias))
      APPLY_TO(alias);
  }

#undef APPLY_TO

  bounce_sync_session_snomask(source);

  /* Tell each member what changed for it (its own before/after, so a
   * second application -- BS O then MODE, a clamp then BX K -- tells
   * nothing), except the connection the change was already echoed to.
   * Here, not between a send_umode() and a read of its umodeBuf. */
  for (i = 0; i < nbefore; i++) {
    struct Client *m = before[i].c;
    if (m == told || !MyConnect(m) || IsDead(m))
      continue;
    send_umode(m, m, &before[i].flags, ALL_UMODES);
    if (cli_snomask(m) && cli_snomask(m) != before[i].mask)
      send_reply(m, RPL_SNOMASK, cli_snomask(m), cli_snomask(m));
  }
  if (source_before && source != told && MyConnect(source)
      && !IsBouncerHold(source) && !IsDead(source))
    send_umode(source, source, (struct Flags *)source_before, ALL_UMODES);
}

/** The server notice mask half of a session sync.
 *
 * A mask is known only where its connection is (bounce_member_snomask).
 * From a local @a source, the mask it holds is the session's: the
 * session keeps it (stamped, marked dirty for a restart), the other local
 * members get it, and the other members' servers get it by BX K -- only
 * when it changed (a new alias learns it from the BX C answer).  From a
 * remote source (a server MODE for a remote primary; set_user_mode acting
 * on one) nothing is known here: its own server sends BX K, and the local
 * members only have theirs clamped to what they still may hold, since a
 * -o of the primary arrives as a flag without the mask.
 * @param[in] source Session member whose state changed.
 */
void bounce_sync_session_snomask(struct Client *source)
{
  struct BouncerSession *sess;
  struct Client *member;
  unsigned int mask;
  int known;
  int changed = 0;
  int i;

  if (!source || !IsUser(source))
    return;
  sess = bounce_get_session(source);
  if (!sess)
    return;

  mask = bounce_member_snomask(source, sess, &known);
  if (known && !IsBouncerHold(source)
      && (!sess->hs_snomask_known || sess->hs_snomask != mask)) {
    sess->hs_snomask = mask;
    sess->hs_snomask_known = 1;
    bounce_stamp_snomask(sess);
    changed = 1;
    bounce_mark_dirty(source);
  }

  for (i = -1; i < sess->hs_alias_count; i++) {
    member = (i < 0) ? sess->hs_client
                     : findNUser(sess->hs_aliases[i].ba_numeric);
    if (!member || member == source || !IsUser(member))
      continue;
    if (i >= 0 && !IsBouncerAlias(member))
      continue;
    if (MyConnect(member)) {
      if (IsBouncerHold(member))
        continue;   /* its mask went with its socket; the session has it */
      if (known)
        bounce_put_member_snomask(member, mask, 0);
      else
        bounce_reclamp_snomask(member);
    } else if (known && changed) {
      bounce_send_member_snomask(member, sess);
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
static int bounce_alias_multiline_echo(struct Client *cptr, struct Client *sptr, int parc, char *parv[]);
static int bounce_alias_snomask(struct Client *cptr, struct Client *sptr, int parc, char *parv[]);
static int bounce_alias_visibility(struct Client *cptr, struct Client *sptr, int parc, char *parv[]);
/* BX R / BX F / BX J retired in Phase 5 (cluster-B coordination protocol
 * removed per redesign D.3 — deterministic convergence supersedes it).
 * Receivers drop silently; we no longer emit them. */

/* Pending BX queue helpers — defers BX subcommands targeting an alias
 * whose BX C hasn't been processed yet on this server (burst race).
 * See implementation block below the BX subcommand handlers. */
static void expire_pending_bx(void);
static int  defer_bx_for_alias(const char *alias_numeric,
                                struct Client *cptr, struct Client *sptr,
                                int parc, char *parv[]);
static void drain_pending_bx_for_alias(const char *alias_numeric);

/* BX M state cleanup for a destroyed alias.  Defined alongside
 * s2s_bxm_cleanup_link further down in the BX M section. */
static void s2s_bxm_cleanup_alias(struct Client *alias);

/* Recursion guard for the pending-BX drain.  Set across replay span
 * so BX handlers know not to re-defer or re-broadcast.  Defined here
 * because BX K / BX U handlers — which appear earlier in the file
 * than the pending-BX implementation block — read it. */
static int bx_drain_in_progress = 0;

int bounce_handle_bt(struct Client *cptr, struct Client *sptr,
                     int parc, char *parv[])
{
  char subcmd;

  if (parc < 2)
    return 0;

  /* Opportunistic TTL sweep of the pending-BX queue.  Cheap (linear scan
   * of a small fixed array) and good enough — we only need expired
   * entries gone before they pile up across a long-quiet period. */
  expire_pending_bx();

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
  case 'M':
    return bounce_alias_multiline_echo(cptr, sptr, parc, parv);
  case 'K':
    return bounce_alias_snomask(cptr, sptr, parc, parv);
  case 'V':
    return bounce_alias_visibility(cptr, sptr, parc, parv);
  case 'R': /* retired Phase 5 — silent drop */
  case 'J': /* retired Phase 5 — silent drop */
  case 'F': /* retired Phase 5 — silent drop */
    return 0;
  default:
    Debug((DEBUG_INFO, "BX: unknown subcommand '%c' from %C", subcmd, sptr));
    /* Forward unknown subcommands for future compatibility */
    sendcmdto_serv_butone_v3(sptr, CMD_BOUNCER_TRANSFER, cptr,
                          "%s", parv[1]);
    return 0;
  }
}

/** Resolve a wire numeric to a user ONLY if it is a syntactically
 * valid 5-char P10 user numeric.  findNUser()'s non-5-char else-branch
 * mis-resolves short/malformed numerics to an arbitrary client_list
 * slot, so every BX handler that mutates/converts/exits the resolved
 * Client must gate on exact length first (F-BW2). */
static struct Client *bx_find_user_strict(const char *numeric)
{
  if (!numeric || strlen(numeric) != 5)
    return NULL;
  return findNUser(numeric);
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

  old_client = bx_find_user_strict(old_numeric);
  new_client = bx_find_user_strict(new_numeric);

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
    {
      struct bounce_counts was;

      count_held(new_client, &was);
      ClearBouncerAlias(new_client);
      /* A primary now, announced: the alias of ours a peer promotes is our
       * live user (announced again); an alias another server introduced by
       * BX C is that server's user (it gets the counts that server's N
       * would have given it).  old_client's exit below releases its own. */
      bounce_count_converted(new_client, &was, cli_user(new_client)->server,
                             "BX P");
    }
    cli_user(new_client)->alias_primary = NULL;
    /* C1: Add promoted alias to nick hash (aliases aren't in nick hash) */
    hAddClient(new_client);
    /* Reconcile opers/inv counting: ClearBouncerAlias made new_client an eligible
     * primary.  Flag-keyed + idempotent — a remote alias (was uncounted) is bumped
     * now (without this it exits +o uncounted -> opers underflow assert), the
     * alias's home leaf (already counted) is a no-op.  old_client is exited below
     * (count released by userstats_count_clear in exit_one_client). */
    userstats_count_sync(new_client);
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
   * hs_client is NULL, e.g. during SQUIT).  When the id misses -- a merge
   * left our record of the session under another id than the promoting
   * server's -- the record whose primary is the old client and which lists
   * the new one as its alias is that session too (bouncer_wire.h,
   * bounce_promote_session). */
  {
    struct BouncerSession *exact = bounce_find_by_token_sessid(
        cli_account(old_client), sessid);
    struct BouncerSession *by_old = NULL;
    struct BouncerSession *bsess = NULL;
    int ambiguous = 0, on_roster = 0;

    if (!exact) {
      by_old = session_of_primary(old_client, &ambiguous);
      if (by_old && by_old->hs_client != old_client)
        by_old = NULL;    /* a roster match: not the old primary's session */
      on_roster = by_old && session_roster_has(by_old, new_client);
    }
    switch (bounce_promote_session(exact != NULL, by_old != NULL || ambiguous,
                                   ambiguous, on_roster)) {
    case BOUNCE_PROMOTE_EXACT:
      bsess = exact;
      break;
    case BOUNCE_PROMOTE_PRIMARY:
      bsess = by_old;
      log_write(LS_USER, L_INFO, 0,
                "BX P: session %s not here; promoting %s to primary of our "
                "record %s of %s, whose primary was %s",
                sessid, new_numeric, by_old->hs_sessid, by_old->hs_account,
                old_numeric);
      break;
    case BOUNCE_PROMOTE_NONE:
      break;
    }
    /* A record whose primary slot holds our own client is ours to decide,
     * as at BS A and BS D (bounce_bxp_session_action): a BX P naming that
     * client as the old one renumbers it, and any other names another
     * server's copy of the session -- our live primary stays, and our
     * held ghost yields to the sender's live copy. */
    if (bsess) {
      struct Client *slot = bsess->hs_client;
      int slot_ours = slot && MyConnect(slot) && IsUser(slot)
                      && !IsBouncerAlias(slot);
      int kc_conflict = cli_user(new_client)
                        && bounce_rebind_kc_conflict(bounce_session_kc_id(bsess),
                                                     cli_user(new_client)->kc_id);
      /* The promoted client is a primary here now, never an alias of this
       * session as well, whichever client the record keeps in its slot:
       * every roster entry naming it goes (a session ending exits each
       * roster entry it finds, and would exit a primary twice). */
      session_roster_drop(bsess, new_client);
      switch (bounce_bxp_session_action(slot_ours, slot_ours && IsBouncerHold(slot),
                                        slot == old_client,
                                        bsess->hs_state == BOUNCE_HOLDING
                                          && session_has_local_holder(bsess),
                                        kc_conflict)) {
      case BOUNCE_BXP_APPLY:
        break;
      case BOUNCE_BXP_KEEP:
        log_write(LS_USER, L_INFO, 0,
                  "BX P: %s promotes %s in %s's session %s; our %s %s holds "
                  "its primary slot: not changed", cli_name(sptr),
                  cli_name(new_client), bsess->hs_account, bsess->hs_sessid,
                  IsBouncerHold(slot) ? "held ghost" : "live primary",
                  cli_name(slot));
        bsess = NULL;
        break;
      case BOUNCE_BXP_YIELD:
        bounce_held_copy_yields(bsess, new_client, cptr, sptr, "BX P");
        bsess = NULL;
        break;
      }
    }
    /* Through the checked install: never a primary of another account or
     * Keycloak user (a session kept apart after a split can share this
     * sessid). */
    if (bsess && bounce_hs_client_assign_checked(bsess, new_client, "BX P")) {
      int k;
      /* Point session to new primary.
       * Transition to ACTIVE — the promoted alias is a live connection.
       * Without this, the session stays HOLDING on remote replicas and
       * exit_one_client destroys it instead of re-holding on disconnect. */
      bsess->hs_state = BOUNCE_ACTIVE;
      bsess->hs_last_active = CurrentTime;
      bsess->hs_disconnect_time = 0;
      /* The promoted connection is ours: its attached stretch starts now
       * and accrues when this server holds the session. */
      bsess->hs_attach_time = MyConnect(new_client) ? CurrentTime : 0;
      /* The session is held where its new primary is (BS T says the same,
       * but only to a record of the id it names). */
      ircd_strncpy(bsess->hs_origin, cli_yxx(cli_user(new_client)->server),
                   sizeof(bsess->hs_origin));
      /* Update remaining aliases' alias_primary */
      for (k = 0; k < bsess->hs_alias_count; k++) {
        struct Client *sibling = findNUser(bsess->hs_aliases[k].ba_numeric);
        if (sibling && IsBouncerAlias(sibling))
          cli_user(sibling)->alias_primary = new_client;
      }
    }
  }

  /* C3: Remove old_client from channels silently, then exit with
   * FLAG_BOUNCER_INTERNAL_DESTROY to suppress S2S QUIT propagation —
   * BX P (the actual wire event for this transfer) has already gone
   * out and upstream servers don't need a Q on top of it (they'd
   * desync if they saw the QUIT).  The originating server's S2S QUIT
   * arrives later (TCP ordering) and is harmlessly ignored (numeric
   * already freed).
   *
   * Bouncer-internal-destroy flag rather than FLAG_KILLED: this is
   * internal cleanup tied to a successful BX P, not a network KILL.
   * Per invariant #12, network KILL would end the entire session
   * which is the opposite of what BX P-mediated transfer wants. */
  remove_user_from_all_channels(old_client);
  SetBouncerInternalDestroy(old_client);
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
  struct bounce_counts was_counted;
  char chanlist_buf[512];
  size_t chanlist_len = 0;
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

  /* --- Reserve the local P10 numeric FIRST (the only fallible step) ---
   * SetLocalNumNick() is the sole operation in alias setup that can fail
   * (numeric pool exhausted).  Do it BEFORE any nick-hash removal,
   * identity overwrite, alias-flag set, or count adjustment below, so a
   * failure leaves sptr a pristine, plain, non-alias user.  register_user
   * (s_user.c) then SetFlag(FLAG_KILLED)+exit_client's it down the normal
   * non-alias teardown — the exact state/behaviour of the sibling
   * BOUNCE_RESUME_REJECT_DUPLICATE rejection.  This avoids the
   * poisoned-half-alias: no whole-session KILL cascade (invariant #6,
   * exit_one_client alias branch), no announced/oper/inv imbalance
   * (invariant #9), and no dangling nick-hash entry.
   *
   * Any future early-failure return added below this point MUST release
   * the reserved numeric (RemoveYXXClient(&me, cli_yxx(sptr))) before
   * returning, or the client_list slot leaks.
   *
   * user->server is already &me for a local registrant (set during
   * authentication); set it explicitly here because SetLocalNumNick()
   * asserts cli_user(sptr)->server == &me. */
  user->server = &me;
  if (!SetLocalNumNick(sptr)) {
    log_write(LS_USER, L_INFO, 0,
              "bounce_setup_local_alias: SetLocalNumNick failed (numeric pool "
              "exhausted) for session %s", session->hs_sessid);
    /* Nothing to unwind: no hRemClient, no identity overwrite, no alias
     * flags, and no count decrements have run yet. */
    return -1;
  }

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
  ircd_strncpy(cli_name(sptr), cli_name(primary), NICKLEN + 1);
  ircd_strncpy(user->username, cli_user(primary)->username, USERLEN + 1);
  ircd_strncpy(user->host, cli_user(primary)->host, HOSTLEN + 1);
  /* Do NOT overwrite realhost — the alias has its own real connection host,
   * needed for oper WHOIS, gline matching, and stays correct on promotion. */
  ircd_strncpy(cli_info(sptr), cli_info(primary), REALLEN + 1);
  ircd_strncpy(user->account, cli_user(primary)->account, ACCOUNTLEN + 1);
  user->acc_create = cli_user(primary)->acc_create;
  ircd_strncpy(user->kc_id, cli_user(primary)->kc_id, sizeof(user->kc_id));

  /* Copy cloaked/fake host (controls what other users see).
   * Do NOT overwrite cli_ip — the alias has its own real socket IP,
   * needed for IPcheck, ban matching, and logging. */
  ircd_strncpy(user->cloakip, cli_user(primary)->cloakip, HOSTLEN + 1);
  ircd_strncpy(user->cloakhost, cli_user(primary)->cloakhost, HOSTLEN + 1);
  ircd_strncpy(user->fakehost, cli_user(primary)->fakehost, HOSTLEN + 1);

  /* Inherit the session's sessid so this alias's cli_session_id agrees
   * with the primary's and with the bouncer session record.  Supersedes
   * the freshly-minted value from make_client. */
  presence_purge_session(cli_session_id(sptr));
  ircd_strncpy(cli_session_id(sptr), session->hs_sessid, S2S_SESSID_BUFSIZE);

  /* --- Step 3: Set alias flags --- */
  count_held(sptr, &was_counted);
  SetBouncerAlias(sptr);
  SetUser(sptr);
  SetAccount(sptr);
  if (IsHiddenHost(primary))
    SetHiddenHost(sptr);
  user->alias_primary = primary;
  cli_lastnick(sptr) = cli_lastnick(primary);
  cli_handler(sptr) = CLIENT_HANDLER;

  /* It registered as a live user of ours (Count_unknownbecomesclient)
   * and is an alias from here on: still a socket and a registered user,
   * no longer announced -- the network learns it by BX C, never by N. */
  bounce_count_converted(sptr, &was_counted, &me, "alias setup");

  /* Copy user mode flags from primary (oper, wallops, invisible, etc.) */
  bounce_copy_umodes(primary, sptr);

  /* Copy oper privileges from primary so HasPriv() works correctly.
   * Without this, umode_str() strips +o (PRIV_PROPAGATE check) and
   * oper commands are denied on the alias connection. */
  if (IsAnOper(primary)) {   /* a local oper (+O) too */
    memcpy(&cli_privs(sptr), &cli_privs(primary), sizeof(cli_privs(sptr)));
    cli_handler(sptr) = OPER_HANDLER;
  }

  /* The session's server notice mask, where this server knows it (a local
   * primary; bounce_member_snomask) -- +s follows it.  An alias of a
   * remote primary learns it from the primary's server: its BX C answer
   * is a BX K. */
  {
    int known;
    unsigned int mask = bounce_member_snomask(primary, session, &known);
    if (known) {
      set_snomask(sptr, mask, SNO_SET);
      if (cli_snomask(sptr))
        SetServNotice(sptr);
      else
        ClearServNotice(sptr);
    }
  }

  /* Re-assert the alias's own SSL state — bounce_copy_umodes copies the
   * primary's FLAG_SSL, but local aliases have their own TLS connection. */
#ifdef USE_SSL
  if (cli_socket(sptr).ssl)
    SetSSL(sptr);
  else
    ClearSSL(sptr);
#endif

  /* --- Step 5: User cloaking ---
   * (The old Step 4 numeric allocation was hoisted to the top of the
   * function, before any identity/flag mutation, so a numeric-pool
   * failure can no longer leave a half-transformed poisoned alias.) */
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
      /* Phase 4 M4b: snapshot the connecting alias's active-profile
       * name from cli_active_profile (set by PERSISTENCE ATTACH
       * pre-CAP-END).  Empty string means "default" at the reconciler. */
      ircd_strncpy(ba->ba_active_profile, cli_active_profile(sptr),
                   sizeof(ba->ba_active_profile));
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

      /* Append to channel list for BX C (only joined channels).
       * Per redesign F.2: ride-along JOIN msgid as "<chan>@<msgid>"
       * so peers can keep msgid parity for the alias's join echo. */
      if (chanlist_len > 0)
        str_appendf(chanlist_buf, sizeof(chanlist_buf), &chanlist_len, " ");
      if (member->join_msgid[0])
        str_appendf(chanlist_buf, sizeof(chanlist_buf), &chanlist_len,
                    "%s@%s", chptr->chname, member->join_msgid);
      else
        str_appendf(chanlist_buf, sizeof(chanlist_buf), &chanlist_len,
                    "%s", chptr->chname);
    }

    /* --- Step 8: Broadcast BX C to network ---
     * M4b: extended with active_profile positional after modes.  Old
     * peers parse the modes-version and ignore the profile token;
     * new peers consume both.
     *
     * BX C goes only to IRCv3-aware peers (sendcmdto_serv_butone_v3):
     * modern peers process it via bounce_alias_create, which creates their
     * copy of sptr as an alias of `primary`.  A legacy peer (evilnet/nefarious2
     * master with m_bouncer_transfer.c) acts only on BX P and relays
     * everything else unexamined, so BX C is pure noise to it.  Nor does
     * a legacy peer know sptr at all: register_user() takes this alias
     * path and returns before its N broadcast (s_user.c), so no N for
     * sptr ever left this server and no legacy peer counted it.
     *
     * So nothing goes to the legacy links: there is no face of theirs to
     * change.
     *
     * The emission is sourced from &me — the server itself, not the
     * alias — so the alias→primary egress rewrite (invariant #10) does
     * not apply here. */
    {
      char *alias_modes = umode_str(sptr);
      const char *alias_profile = cli_active_profile(sptr)[0]
                                    ? cli_active_profile(sptr)
                                    : PERSISTENCE_PROFILE_DEFAULT;
      sendcmdto_serv_butone_v3(&me, CMD_BOUNCER_TRANSFER, NULL,
                             "C %s %s %s %s %s%s %s :%s",
                             primary_full,
                             alias_full,
                             session->hs_account,
                             session->hs_sessid,
                             *alias_modes ? "+" : "+",
                             alias_modes,
                             alias_profile,
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

  /* draft/authtoken service list: mirror of the register_user emit */
  if (CapActive(sptr, CAP_BATCH) && CapActive(sptr, CAP_DRAFT_AUTHTOKEN))
    authtoken_send_servicelist(sptr);

#ifdef USE_SSL
  if (cli_socket(sptr).ssl)
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :You are connected to %s with %s",
                  sptr, cli_name(&me), ssl_get_cipher(cli_socket(sptr).ssl));
#endif

  m_lusers(sptr, sptr, 1, parv);

  /* IRCv3 draft/persistence: mirror normal-path emit so freshly-set-up
   * aliases also see the unsolicited STATUS line between 005 and
   * MOTD-END.  Same rationale as the local-revive path in
   * register_user(); without this aliases never learn their effective
   * hold state at attach time. */
  if (CapActive(sptr, CAP_DRAFT_PERSISTENCE) && IsAccount(sptr))
    persistence_send_status(sptr);

  motd_signon(sptr);

  /* Post-registration fakelag credit: modern clients burst init
   * commands (MONITOR, METADATA SUB, WHO, MODE...) right after 001;
   * the default ~10s cli_since headroom covers only ~5 of them.
   * A credit the first charges absorb (fakelag_charge()) -- every
   * command is still CHARGED (credit, not exemption), the one-shot
   * grace just raises the initial burst budget; recvq byte caps still
   * bound the wire.  Not a clock set below now: read_packet() floors
   * the clock to the last read time and would erase that.
   * Authenticated clients only: an anonymous connection (the
   * drive-by/WS-flood surface) keeps the classic ~5-command burst. */
  {
    int grace = feature_int(FEAT_POSTREG_GRACE);
    if (grace > 0 && IsAccount(sptr))
      cli_lagcredit(sptr) = grace;
  }

  /* IRCv3 draft/metadata-2: mirror normal-path self-burst.  Aliases
   * inherit the primary's account-scoped metadata at attach time, so
   * the new local socket should learn its keys without an explicit
   * METADATA SUB round-trip. */
  metadata_burst_self_to_client(sptr);

  /* Step 3 copied the primary's user modes, privileges and snomask onto
   * the alias; tell its client what it is attached as, the way
   * register_user() does for a fresh connection. */
  send_umode_signon(sptr);

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
  /* The FEAT_* gate stays as the operator-level kill switch.  The
   * per-user PERSISTENCE REPLAY SET (account-global or active-profile)
   * gates on top of it via persistence_replay_enabled_for. */
  if (feature_bool(FEAT_BOUNCER_AUTO_REPLAY)
      && (!CapOwnHas(sptr, CAP_DRAFT_CHATHISTORY)
          || cli_attach_cursor(sptr)[0])
      && persistence_replay_enabled_for(sptr)) {
    time_t since = session->hs_last_active;
    if (since == 0)
      since = session->hs_created;

    if (history_is_available()) {
      /* Local store: async replay from MDBX.  An explicit ATTACH
       * cursor requests server-driven catch-up even for chathistory-
       * capable clients (they msgid-dedup); replay_start_catchup
       * resolves the cursor, else falls back to `since`. */
      if (since > 0 && since < CurrentTime)
        replay_start_catchup(sptr, since, 0);
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

  /* New session connection — re-aggregate effective away. A present
   * alias attaching to an away primary should flip the session to
   * present (and broadcast away-notify) even though no /away was typed. */
  bounce_recompute_session_away(session);

  /* Publish initial cap state to the network so other servers can
   * decide BX M vs BX E for this alias without waiting for a
   * subsequent CAP REQ from the client. */
  bounce_emit_alias_caps(sptr);

  /* Note: the alias's active draft/persistence profile is replicated
   * to peers in the BX C wire emit above (M4b — positional param
   * after modes), not via a separate update.  Q1: profile is fixed
   * at registration, so no UPDATE wire is needed. */

  /* Phase 3 hs_enforced: an alias attaching on a CRFLAG_BOUNCER
   * class enforces the session. */
  {
    struct ConnectionClass *cls = get_client_class_conf(sptr);
    if (cls && FlagHas(&cls->restrictflags, CRFLAG_BOUNCER))
      session->hs_enforced = 1;
  }

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
  const char *alias_profile = NULL;  /* M4b */
  char *chan_copy;
  char *chan_name;
  char *chan_tok;

  if (parc < 7)
    return protocol_violation(sptr, "BX C requires 5 parameters");

  primary_numeric = parv[2];
  alias_numeric = parv[3];
  account = parv[4];
  sessid = parv[5];
  if (parc >= 9) {
    /* M4b format: BX C <primary> <alias> <account> <sessid> <modes>
     *             <profile> :<channels> */
    alias_modes = parv[6];
    alias_profile = parv[7];
    chanlist = parv[parc - 1];
  } else if (parc >= 8) {
    /* New format: BX C <primary> <alias> <account> <sessid> <modes> :<channels> */
    alias_modes = parv[6];
    chanlist = parv[parc - 1];
  } else {
    /* Old format: BX C <primary> <alias> <account> <sessid> :<channels> */
    chanlist = parv[6];
  }

  /* F-BW2: both numerics must be well-formed 5-char P10 user numerics
   * before we resolve or byte-index them (the svr_yy extraction below
   * reads alias_numeric[1] directly). */
  if (strlen(primary_numeric) != 5 || strlen(alias_numeric) != 5) {
    Debug((DEBUG_INFO, "BX C: malformed numeric primary=%s alias=%s",
           primary_numeric, alias_numeric));
    goto forward;
  }

  /* Find the primary client */
  primary = bx_find_user_strict(primary_numeric);
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
  alias = bx_find_user_strict(alias_numeric);
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
    /* Existing non-alias client -- convert it to an alias in place.
     *
     * The client was introduced by N, as a primary of its server, and its
     * server now announces it as an alias of `primary`: two live primaries
     * of one session met after a split under different nicks, and the
     * post-burst reconcile demoted the newer one on its own server (a
     * same-nick meeting is decided before the keeper accepts the other's
     * N, so the alias it makes is new here).  The everyday flows never
     * reach this branch: an alias is introduced by BX C alone, and the
     * burst sends no N for one.
     *
     * The legacy links know the client by its N, under its own nick.  It
     * leaves them as a QUIT ("Promoted to alias of <primary>"), sent while
     * it still has the numeric they know: they hold the primary's own
     * face, which they learned when it was introduced.  A BX P naming both
     * numerics would have them drop the face without telling anything
     * behind them (X3 kept a phantom of it).  Local users who share a
     * channel with the old nick are told by the QUIT below. */
    /* Only a client of the line's own direction: its server is the one
     * that demoted it and announces it, and that server is behind the
     * link the BX C came over.  A client of ours, or of another
     * direction, is not this BX C's to convert. */
    if (cli_from(alias) != cptr) {
      log_write(LS_USER, L_INFO, 0, "BX C: %s names %s (%s) as an alias of %s, "
                "but that client is not behind %s: not converted",
                cli_name(sptr), alias_numeric, cli_name(alias), cli_name(primary),
                cli_name(cptr));
      goto forward;
    }
    Debug((DEBUG_INFO, "BX C: converting existing client %s (%s) to alias of %s",
           alias_numeric, cli_name(alias), cli_name(primary)));
    user = cli_user(alias);
    if (!user)
      goto forward;
    /* F-BW1: refuse convert-in-place unless the existing client already
     * belongs to this session's account.  The block below overwrites
     * its entire identity; without this a malformed/hostile BX C
     * hijacks an unrelated user's Client slot.  Aliases are
     * account-anchored, so a legitimate convert target always has the
     * matching account set; a mismatch is drop-worthy and reported. */
    if (!IsAccount(alias) || 0 != ircd_strcmp(user->account, account)) {
      sendto_opmask_butone(0, SNO_NETWORK,
          "BX C convert-in-place REFUSED (account mismatch): alias=%s "
          "old_nick=%s old_acct=%s bx_acct=%s primary=%s",
          alias_numeric, cli_name(alias),
          IsAccount(alias) ? user->account : "*", account, primary_numeric);
      goto forward;
    }
    {
      char reason[NICKLEN + 32];
      ircd_snprintf(0, reason, sizeof(reason), "Promoted to alias of %s",
                    cli_name(primary));
      bounce_legacy_face_change(alias, bounce_find_by_token_sessid(account, sessid),
                                cptr, NULL, reason);
    }
    /* Client-visible cleanup: this client was N-introduced with its OWN
     * nick and is about to be relabeled to the primary's nick and absorbed
     * as a hidden alias.  Local clients sharing a channel with the old nick
     * would keep it cached forever (a ghost): emit a QUIT for the old nick
     * to its common channels FIRST so they clean it up.  Local-only
     * (sendcmdto_common_channels_butone targets local clients), so each
     * aware server does this for its own clients when it processes the
     * BX C; the legacy links had their QUIT above.  Skip when the nick is
     * unchanged (no delta). */
    if (0 != ircd_strcmp(cli_name(alias), cli_name(primary)))
      sendcmdto_common_channels_butone(alias, CMD_QUIT, NULL, ":Session converging");
    {
      /* What it holds as the user its server introduced by N, and that
       * server, before the conversion overwrites anything. */
      struct Client *original_server = user->server;
      struct bounce_counts was;

      count_held(alias, &was);
      hRemClient(alias);
      ircd_strncpy(cli_name(alias), cli_name(primary), NICKLEN + 1);
      ircd_strncpy(user->username, cli_user(primary)->username, USERLEN + 1);
      ircd_strncpy(user->host, cli_user(primary)->host, HOSTLEN + 1);
      ircd_strncpy(user->realhost, cli_user(primary)->realhost, HOSTLEN + 1);
      ircd_strncpy(cli_info(alias), cli_info(primary), REALLEN + 1);
      ircd_strncpy(user->account, account, ACCOUNTLEN + 1);
      user->acc_create = cli_user(primary)->acc_create;
      ircd_strncpy(user->kc_id, cli_user(primary)->kc_id, sizeof(user->kc_id));
      user->alias_primary = primary;
      memcpy(&cli_ip(alias), &cli_ip(primary), sizeof(cli_ip(alias)));
      ircd_strncpy(user->cloakip, cli_user(primary)->cloakip, HOSTLEN + 1);
      ircd_strncpy(user->cloakhost, cli_user(primary)->cloakhost, HOSTLEN + 1);
      ircd_strncpy(user->fakehost, cli_user(primary)->fakehost, HOSTLEN + 1);
      /* Inherit the session's sessid so this alias's cli_session_id
       * agrees with the primary's and with the bouncer session record. */
      presence_purge_session(cli_session_id(alias));
      ircd_strncpy(cli_session_id(alias), sessid, S2S_SESSID_BUFSIZE);
      SetBouncerAlias(alias);
      if (IsHiddenHost(primary))
        SetHiddenHost(alias);
      cli_lastnick(alias) = cli_lastnick(primary);
      /* Copy user mode flags from primary (oper, wallops, invisible, etc.) */
      bounce_copy_umodes(primary, alias);

      /* An alias another server introduced is counted nowhere here (a BX C
       * for a new one counts nothing either): the user its N counted --
       * a registered user, announced, in its server's count -- gives every
       * count up, and its exit as an alias releases nothing more. */
      bounce_count_converted(alias, &was, original_server, "convert");
    }
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
  ircd_strncpy(cli_name(alias), cli_name(primary), NICKLEN + 1);
  ircd_strncpy(user->username, cli_user(primary)->username, USERLEN + 1);
  ircd_strncpy(user->host, cli_user(primary)->host, HOSTLEN + 1);
  ircd_strncpy(user->realhost, cli_user(primary)->realhost, HOSTLEN + 1);
  ircd_strncpy(cli_info(alias), cli_info(primary), REALLEN + 1);
  ircd_strncpy(user->account, account, ACCOUNTLEN + 1);
  user->acc_create = cli_user(primary)->acc_create;
  ircd_strncpy(user->kc_id, cli_user(primary)->kc_id, sizeof(user->kc_id));
  user->server = alias_server;
  user->alias_primary = primary;

  /* Copy IP and cloaked/fake host from primary */
  memcpy(&cli_ip(alias), &cli_ip(primary), sizeof(cli_ip(alias)));
  ircd_strncpy(user->cloakip, cli_user(primary)->cloakip, HOSTLEN + 1);
  ircd_strncpy(user->cloakhost, cli_user(primary)->cloakhost, HOSTLEN + 1);
  ircd_strncpy(user->fakehost, cli_user(primary)->fakehost, HOSTLEN + 1);

  /* Inherit the session's sessid so this alias's cli_session_id agrees
   * with the primary's and with the bouncer session record.  Remote
   * aliases share the alias_server's Connection (from != NULL path in
   * make_client), so cli_session_id was not minted at allocation — we
   * populate it explicitly from the BX C-announced sessid here. */
  presence_purge_session(cli_session_id(alias));
  ircd_strncpy(cli_session_id(alias), sessid, S2S_SESSID_BUFSIZE);

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

  /* Track alias in session replica: the session of the id the BX C
   * names; else the session whose primary the BX C names (a merge can
   * leave the two servers' ids apart); else our session of the account.
   *
   * The account fallback covers the cross-sessid race: peer's BX C may
   * arrive with peer's *original* sessid (emitted before peer received
   * our BS C and renamed to our lex-lower sessid), and an account has
   * one local session once that rename has converged.  It never stands
   * in for an id BS C left unmirrored here (kept apart from ours, or a
   * holding loser of ours): that id is never renamed into ours, so an
   * alias of it is another session's, not ours (bounce_alias_filing). */
  session = bounce_find_by_token_sessid(account, sessid);
  {
    struct BouncerSession *of_primary = NULL;
    struct AccountSessions *as = NULL;
    int by_account = 0;
    int unmirrored = 0;

    if (!session) {
      /* The session the primary is the primary of; one that only lists
       * it on its roster is not its session. */
      of_primary = primary ? bounce_session_of_primary(primary) : NULL;
      if (of_primary && (of_primary->hs_client != primary
                         || 0 != ircd_strcmp(of_primary->hs_account, account)))
        of_primary = NULL;
      as = bounce_find_by_account(account);
      unmirrored = unmirrored_marked(account, sessid);
      /* ... nor a session of another Keycloak user than this alias's
       * primary: sessions kept apart after a split leave two per
       * account (user, 2026-10-23), and the alias is then tracked in
       * neither rather than in the wrong one. */
      if (!of_primary && !unmirrored && as && as->as_sessions && primary
          && cli_user(primary)
          && bounce_rebind_kc_conflict(bounce_session_kc_id(as->as_sessions),
                                       cli_user(primary)->kc_id)) {
        log_write(LS_USER, L_INFO, 0,
                  "BX C: sessid %s not found; account fallback session %s "
                  "belongs to another Keycloak id: alias %s not tracked",
                  sessid, as->as_sessions->hs_sessid, alias_numeric);
      } else if (as && as->as_sessions) {
        by_account = 1;
      }
    }
    switch (bounce_alias_filing(session != NULL, of_primary != NULL,
                                by_account, unmirrored)) {
    case BOUNCE_FILE_EXACT:
      break;
    case BOUNCE_FILE_PRIMARY:
      session = of_primary;
      Debug((DEBUG_INFO, "BX C: sessid %s not found, using session %s of "
             "primary %s for alias %s", sessid, session->hs_sessid,
             primary_numeric, alias_numeric));
      break;
    case BOUNCE_FILE_ACCOUNT:
      session = as->as_sessions;
      Debug((DEBUG_INFO,
             "BX C: sessid %s not found, using account-fallback "
             "session %s for alias %s",
             sessid, session->hs_sessid, alias_numeric));
      break;
    case BOUNCE_FILE_NONE:
      if (unmirrored && by_account)
        log_write(LS_USER, L_INFO, 0,
                  "BX C: session %s of %s is kept apart from ours here: "
                  "alias %s not tracked", sessid, account, alias_numeric);
      session = NULL;
      break;
    }
  }
  /* Whichever was chosen, never a session of another Keycloak user: one
   * kept apart after a split can share the sessid of another Keycloak
   * user's (user, 2026-10-23). */
  if (session && primary && cli_user(primary)
      && bounce_rebind_kc_conflict(bounce_session_kc_id(session),
                                   cli_user(primary)->kc_id)) {
    log_write(LS_USER, L_INFO, 0, "BX C: session %s belongs to Keycloak id %s, "
              "alias %s's primary carries %s: alias not tracked",
              session->hs_sessid, bounce_session_kc_id(session), alias_numeric,
              cli_user(primary)->kc_id);
    session = NULL;
  }
  if (session && session->hs_alias_count < BOUNCER_MAX_ALIASES) {
    struct BounceAlias *ba = &session->hs_aliases[session->hs_alias_count++];
    ircd_strncpy(ba->ba_numeric, alias_numeric, sizeof(ba->ba_numeric));
    ircd_strncpy(ba->ba_server, alias_numeric, sizeof(ba->ba_server));
    ba->ba_last_active = CurrentTime;
    ba->ba_caps = 0;
    ba->ba_caps_known = 0;
    ba->ba_away = 0;
    ba->ba_away_known = 0;
    /* M4b: record the alias's active draft/persistence profile,
     * received as the positional field after modes.  Old peers
     * don't send this; default to empty (= "default" at the
     * reconciler).  Treat literal "default" verbatim — same as
     * empty for resolution purposes but more readable in logs. */
    if (alias_profile && *alias_profile
        && ircd_strcmp(alias_profile, PERSISTENCE_PROFILE_DEFAULT) != 0)
      ircd_strncpy(ba->ba_active_profile, alias_profile,
                   sizeof(ba->ba_active_profile));
    else
      ba->ba_active_profile[0] = '\0';
    /* Persist the updated roster (per redesign B.2 + 1b lifecycle
     * hook) so alias presence survives restart and feeds peers'
     * deterministic-dedup convergence on next link establishment. */
    bounce_db_put(session);
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
      struct Channel *chptr;
      const char *chan_msgid = NULL;
      char *at;
      /* Per redesign F.2: each token is "<chan>" or "<chan>@<msgid>".
       * Split on '@' to separate channel name from optional msgid. */
      at = strchr(chan_name, '@');
      if (at) {
        *at = '\0';
        chan_msgid = at + 1;
      }
      chptr = FindChannel(chan_name);
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
        struct Membership *amem;
        unsigned int aflags = CHFL_ALIAS;
        unsigned short aoplevel = MAXOPLEVEL;
        if (pmem) {
          aflags |= (pmem->status & (CHFL_CHANOP | CHFL_HALFOP | CHFL_VOICE));
          aoplevel = OpLevel(pmem);
        }
        add_user_to_channel(chptr, alias, aflags, aoplevel);
        /* Single-msgid invariant: alias's Membership inherits the JOIN
         * msgid that rode along on the BX C wire (or, if absent, falls
         * back to the primary's local membership msgid). */
        amem = find_member_link(chptr, alias);
        if (amem) {
          if (chan_msgid && *chan_msgid) {
            ircd_strncpy(amem->join_msgid, chan_msgid,
                         sizeof(amem->join_msgid));
          } else if (pmem && pmem->join_msgid[0]) {
            memcpy(amem->join_msgid, pmem->join_msgid,
                   sizeof(amem->join_msgid));
          }
          if (pmem && pmem->join_tv.tv_sec)
            amem->join_tv = pmem->join_tv;
        }
      }
      Debug((DEBUG_INFO, "BX C: added alias %s to channel %s msgid=%s (members=%d aliases=%d)",
             alias_numeric, chan_name,
             chan_msgid ? chan_msgid : "(none)",
             chptr->users, chptr->aliases));
    }
    MyFree(chan_copy);
  } else {
    Debug((DEBUG_INFO, "BX C: empty chanlist for alias %s", alias_numeric));
  }

  /* The primary is ours: the alias's server learns the session's server
   * notice mask (and so +s) from us -- the only server that knows it.
   * Toward the alias, i.e. back over cptr (this used to go to every link
   * BUT cptr and never arrived), and before the session move below
   * promotes the alias and retires a held ghost, whose own mask
   * close_connection() zeroed: bounce_member_snomask() reads the saved
   * one for it. */
  if (MyUser(primary) && session) {
    int known;
    unsigned int mask = bounce_member_snomask(primary, session, &known);
    if (known && (!session->hs_snomask_known || session->hs_snomask != mask)) {
      /* A live primary whose mask was never synced (+s set before the
       * session existed): the session takes it now, stamped here. */
      session->hs_snomask = mask;
      session->hs_snomask_known = 1;
      bounce_stamp_snomask(session);
    }
    if (known && mask)
      bounce_send_member_snomask(alias, session);
  }

  Debug((DEBUG_INFO, "BX C: created alias %s for primary %s (%s)",
         alias_numeric, primary_numeric, cli_name(primary)));

forward:
  /* Forward to other servers — include modes if present */
  if (alias_modes && *alias_modes)
    sendcmdto_serv_butone_v3(sptr, CMD_BOUNCER_TRANSFER, cptr,
                          "C %s %s %s %s %s :%s",
                          primary_numeric, alias_numeric, account, sessid,
                          alias_modes, chanlist);
  else
    sendcmdto_serv_butone_v3(sptr, CMD_BOUNCER_TRANSFER, cptr,
                          "C %s %s %s %s :%s",
                          primary_numeric, alias_numeric, account, sessid, chanlist);

  /* Nothing goes to the legacy links here.  An alias they never knew
   * (introduced by BX C alone) changes nothing of theirs; a client they
   * knew by its N, converted in place above, left them with a QUIT. */

  /* Session move: if the primary is a local HOLDING ghost, promote the
   * alias to primary BEFORE exiting the ghost.  This ensures the ghost's
   * channels are silently removed by promote (remove_user_from_all_channels)
   * while hs_client still points to the ghost.  After promote, the ghost
   * has no channels, so exit_one_client sends no visible QUIT.
   *
   * Wire ordering: BX C (forwarded above) → BX P + BS T (from promote)
   * → ghost exits with FLAG_BOUNCER_INTERNAL_DESTROY (no S2S D token).
   * Result: other IRC clients see no QUIT/JOIN — seamless transfer.
   *
   * FLAG_BOUNCER_INTERNAL_DESTROY is gated on promote success: if
   * promote returns nonzero, no BX P went out and exit_client's Q
   * broadcast must fire so peers can clean up the held-ghost phantom.
   *
   * Bouncer-internal-destroy flag rather than FLAG_KILLED: this is
   * internal cleanup, not a network KILL.  Per invariant #12, network
   * KILL would end the entire session which is wrong for a successful
   * session-move. */
  if (session && session->hs_state == BOUNCE_HOLDING
      && primary && MyConnect(primary) && IsBouncerHold(primary)) {
    int promoted;
    Debug((DEBUG_INFO, "BX C: session move — promoting alias, retiring ghost %s",
           cli_name(primary)));
    promoted = bounce_promote_alias(session, 0);
    if (promoted == 0)
      SetBouncerInternalDestroy(primary);
    exit_client(primary, primary, &me,
                promoted == 0 ? "Session transferred" : "Session expired");
  }

  /* Drain any BX subcommands that were deferred waiting for this
   * alias's BX C.  alias_numeric here is the full YYXXX as it was
   * encoded on the wire — same form the deferred entries were
   * keyed by. */
  drain_pending_bx_for_alias(alias_numeric);

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

  /* Free any buffered BX M batches addressed to this alias.  Without
   * this, mid-batch alias destruction (alias quits between BX M+ and
   * BX M-) leaves the slot pinned until the next link-drop sweep or
   * MAXCONNECTIONS pressure. */
  s2s_bxm_cleanup_alias(alias);

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
        /* Persist the updated (shrunk) roster.  Alias is no longer
         * tracked; on next restart the session won't expect it. */
        bounce_db_put(session);
        /* Membership shrunk — re-aggregate effective away. A present
         * alias departing may flip the session back to away (if all
         * remaining connections are away). */
        bounce_recompute_session_away(session);
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
  struct Client *target;
  const char *target_numeric;
  int was_alias;

  if (parc < 3)
    return protocol_violation(sptr, "BX X requires client numeric");

  target_numeric = parv[2];
  target = bx_find_user_strict(target_numeric);

  /* BX X is the silent-destroy command for any bouncer-managed client:
   * alias or held ghost.  The two are distinguishable on the originating
   * server (IsBouncerAlias vs IsBouncerHold are local-only flags), but
   * over the wire BX X is just "destroy this numeric without firing a
   * user-visible QUIT."  Receiving peers may not have either flag set
   * (held ghosts arrive via burst N as regular remote users — the flag
   * is local to the originating server only); the only check we can
   * meaningfully do here is that the numeric resolves to a Client. */
  if (!target) {
    Debug((DEBUG_INFO, "BX X: client %s not found", target_numeric));
    goto forward;
  }

  was_alias = IsBouncerAlias(target);

  /* A held ghost (or any N-introduced client) goes silently here and on
   * every aware link, but a legacy link learned it by N and gets no BX
   * X: the forward below is aware-only, and a legacy server would drop
   * it anyway.  Retract the face toward the legacy links that know it,
   * while it still has its numeric.  An alias was never N-introduced. */
  if (!was_alias)
    bounce_legacy_face_change(target, bounce_get_session(target), cptr, NULL,
                              "Bouncer session moved");

  /* F-DS1: on the alias's OWNING server, BX X targets our OWN local
   * alias (MyConnect, real socket) — not a remote stub.  The bare
   * removal below assumed the target was always remote and left the
   * fd-indexed LocalClientArray slot dangling at a soon-to-be-pooled
   * Client (which then crashes every LocalClientArray walk — the send.c
   * WALL_ broadcast / DESYNCH loops NULL-deref con_client), and also
   * leaked the IPcheck entry and the local-client / oper / invis counts.
   * Mirror the canonical local-alias teardown (the exit_one_client
   * IsBouncerAlias branch in s_misc.c): release accounting, then
   * close_connection() to clear the array slot, shut the socket and
   * queue the Connection free.
   *
   * The counts are released as exit_one_client releases them: the
   * client of ours by Count_clientdisconnects; another server's client
   * that is not an alias -- a held ghost, which its server introduced by
   * N like any user of its own -- by Count_remoteclientquits; another
   * server's alias holds none (BX C counted nothing, and a client
   * converted into one gave its counts up then).  Without the remote
   * branch a held ghost a peer ends this way stays counted here, in
   * clients, announced_clients and its server's MAP line.
   * userstats_count_clear is flag-keyed: a no-op for an uncounted alias. */
  if (MyConnect(target)) {
    if (IsIPChecked(target))
      IPcheck_disconnect(target);
    Count_clientdisconnects(target, UserStats);
  } else if (!was_alias) {
    Count_remoteclientquits(UserStats, target);
  }
  userstats_count_clear(target);
  if (MyUser(target))
    del_list_watch(target);
  if (MyConnect(target))
    close_connection(target);

  Debug((DEBUG_INFO, "BX X: destroying %s %s (%s)%s%s",
         was_alias ? "alias" : "client",
         target_numeric, cli_name(target),
         was_alias && cli_alias_primary(target) ? " for primary " : "",
         was_alias && cli_alias_primary(target)
           ? cli_name(cli_alias_primary(target)) : ""));

  /* Alias-only: remove from session replica tracking.  Held ghosts
   * aren't tracked in hs_aliases. */
  if (was_alias)
    bounce_alias_untrack(target);

  /* Remove from all channels silently.
   * Note: counter behavior (users vs aliases) is symmetrically wrong
   * here and in BX C until counter guards are added to
   * add_user_to_channel/remove_member_from_channel. */
  remove_user_from_all_channels(target);

  /* Held ghosts ARE in the nick hash (introduced via N); aliases are not.
   * hRemClient is needed for ghosts, harmless extra for aliases (returns
   * an error code we don't act on). */
  if (!was_alias)
    hRemClient(target);

  /* Remove from P10 numeric space */
  RemoveYXXClient(cli_user(target)->server, cli_yxx(target));

  /* Remove from global client list — frees User and Client structs. */
  remove_client_from_list(target);

forward:
  sendcmdto_serv_butone_v3(sptr, CMD_BOUNCER_TRANSFER, cptr,
                        "X %s", target_numeric);
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

  primary = bx_find_user_strict(primary_numeric);
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
        /* If the alias is on our server, notify its socket BEFORE we
         * overwrite cli_name — same lockstep echo as the local-rename
         * pass in set_nick_name (s_user.c).  Without this, an alias
         * whose remote primary rules over the rename sees no signal of
         * its own nick change and the client UI drifts. */
        if (MyConnect(alias))
          sendcmdto_one(alias, CMD_NICK, alias, ":%s", new_nick);
        ircd_strncpy(cli_name(alias), new_nick, NICKLEN + 1);
      }
    }
  }

forward:
  sendcmdto_serv_butone_v3(sptr, CMD_BOUNCER_TRANSFER, cptr,
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
  int is_replay = bx_drain_in_progress;

  if (parc < 4)
    return protocol_violation(sptr, "BX U requires 2 parameters");

  alias_numeric = parv[2];
  field_value = parv[3];

  /* la=<unix time>: a connection's activity (quiet -> active transition
   * on its own server).  Applies to aliases AND primaries -- the numeric
   * may name a primary, which the alias guard below would otherwise
   * defer forever waiting for a BX C that never comes. */
  /* aw=<0|1|2>: a connection's OWN away state (0 present, 1 away,
   * 2 AWAY *), replicated so the attention rule and the away aggregation
   * on other servers see the connection, not the session's mirror.
   * Applies to aliases AND primaries, like la=. */
  if (0 == strncmp(field_value, "aw=", 3)) {
    struct Client *who = bx_find_user_strict(alias_numeric);
    int aw = atoi(field_value + 3);
    if (who && IsUser(who) && IsAccount(who) && aw >= 0 && aw <= 2) {
      struct AccountSessions *as = bounce_find_by_account(cli_user(who)->account);
      struct BouncerSession *sess;
      int i;
      for (sess = as ? as->as_sessions : NULL; sess; sess = sess->hs_anext) {
        if (!IsBouncerAlias(who)) {
          if (sess->hs_client == who) {
            sess->hs_primary_away = aw;
            sess->hs_primary_away_known = 1;
          }
          continue;
        }
        for (i = 0; i < sess->hs_alias_count; i++)
          if (0 == strcmp(sess->hs_aliases[i].ba_numeric, alias_numeric)) {
            sess->hs_aliases[i].ba_away = aw;
            sess->hs_aliases[i].ba_away_known = 1;
          }
      }
    }
    goto forward;
  }
  if (0 == strncmp(field_value, "la=", 3)) {
    struct Client *who = bx_find_user_strict(alias_numeric);
    time_t la = (time_t)strtoul(field_value + 3, NULL, 10);
    if (who && IsUser(who) && IsAccount(who) && la > 0) {
      struct AccountSessions *as = bounce_find_by_account(cli_user(who)->account);
      struct BouncerSession *sess;
      int i;
      for (sess = as ? as->as_sessions : NULL; sess; sess = sess->hs_anext) {
        if (!IsBouncerAlias(who)) {
          if (sess->hs_client == who && la > sess->hs_last_active)
            sess->hs_last_active = la;
          continue;
        }
        for (i = 0; i < sess->hs_alias_count; i++)
          if (0 == strcmp(sess->hs_aliases[i].ba_numeric, alias_numeric)
              && la > sess->hs_aliases[i].ba_last_active)
            sess->hs_aliases[i].ba_last_active = la;
      }
    }
    goto forward;
  }
  if (0 == strncmp(field_value, "ta=", 3)) {
    /* A session's active time (bounce_emit_total_active): it only grows,
     * so the larger figure wins whatever the order. */
    struct Client *who = bx_find_user_strict(alias_numeric);
    time_t ta = (time_t)strtoul(field_value + 3, NULL, 10);
    if (who && IsUser(who) && IsAccount(who) && !IsBouncerAlias(who)) {
      struct AccountSessions *as = bounce_find_by_account(cli_user(who)->account);
      struct BouncerSession *sess;
      for (sess = as ? as->as_sessions : NULL; sess; sess = sess->hs_anext)
        if (sess->hs_client == who && ta > sess->hs_total_active)
          sess->hs_total_active = ta;
    }
    goto forward;
  }
  if (0 == strncmp(field_value, "kcid=", 5)) {
    /* The Keycloak user a session belongs to (bounce_emit_session_kc_id).
     * A replica without one takes it; one with a different id keeps its
     * own (never re-tied, user 2026-10-23) and says so. */
    struct Client *who = bx_find_user_strict(alias_numeric);
    const char *id = field_value + 5;
    if (who && IsUser(who) && IsAccount(who) && !IsBouncerAlias(who)
        && account_id_valid(id)) {
      struct AccountSessions *as = bounce_find_by_account(cli_user(who)->account);
      struct BouncerSession *sess;
      for (sess = as ? as->as_sessions : NULL; sess; sess = sess->hs_anext) {
        const char *have;
        if (sess->hs_client != who)
          continue;
        have = bounce_session_kc_id(sess);
        if (!sess->hs_kc_id[0] && (!have[0] || !strcmp(have, id))) {
          ircd_strncpy(sess->hs_kc_id, id, sizeof(sess->hs_kc_id));
          bounce_session_fill_member_ids(sess);
        } else if (strcmp(have, id))
          log_write(LS_USER, L_INFO, 0, "Bouncer: BX U kcid=%s for session %s "
                    "of %s, which belongs to %s: kept", id, sess->hs_sessid,
                    sess->hs_account, have);
      }
      /* The member itself, when it carries none: if no session matched
       * yet (a replica's primary comes with BS A), the id is still known
       * here through it. */
      if (!cli_user(who)->kc_id[0])
        ircd_strncpy(cli_user(who)->kc_id, id, sizeof(cli_user(who)->kc_id));
    }
    goto forward;
  }
  if (0 == strncmp(field_value, "cc=", 3)) {
    struct Client *who = bx_find_user_strict(alias_numeric);
    unsigned int cc = (unsigned int)strtoul(field_value + 3, NULL, 10);
    if (who && IsUser(who) && IsAccount(who) && !IsBouncerAlias(who) && cc > 0) {
      struct AccountSessions *as = bounce_find_by_account(cli_user(who)->account);
      struct BouncerSession *sess;
      for (sess = as ? as->as_sessions : NULL; sess; sess = sess->hs_anext)
        if (sess->hs_client == who)
          sess->hs_connect_count = cc;
    }
    goto forward;
  }

  alias = bx_find_user_strict(alias_numeric);
  if (!alias || !IsBouncerAlias(alias)) {
    /* Burst race: defer the local identity update for replay when
     * BX C arrives.  Forward immediately on first arrival so other
     * servers can process; replay skips forward (already broadcast). */
    if (!is_replay)
      defer_bx_for_alias(alias_numeric, cptr, sptr, parc, parv);
    if (!is_replay)
      sendcmdto_serv_butone_v3(sptr, CMD_BOUNCER_TRANSFER, cptr,
                            "U %s %s", parv[2], parv[3]);
    return 0;
  }

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
  {
    enum BounceAliasField fid = bounce_alias_field_id(field);
    if (fid == BX_ALIAS_FIELD_UNKNOWN)
      Debug((DEBUG_INFO, "BX U: unknown field '%s' for alias %s",
             field, alias_numeric));
    else
      bounce_apply_alias_field(alias, fid, value);
  }

forward:
  /* Forward only on first arrival.  Replay skips since the original
   * arrival already broadcast — re-running here would duplicate. */
  if (!is_replay)
    sendcmdto_serv_butone_v3(sptr, CMD_BOUNCER_TRANSFER, cptr,
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

  target = bx_find_user_strict(parv[2]);
  if (!target || !IsUser(target)) {
    /* Burst race: BX C for this alias may not have arrived yet.  Defer
     * and replay when it does; falls through to silent drop only if
     * the queue is full or we're inside a drain replay. */
    if (defer_bx_for_alias(parv[2], cptr, sptr, parc, parv) == 0)
      return 0;
    return 0;
  }

  /* Forward if target is not on this server */
  if (!MyConnect(target)) {
    sendcmdto_one(sptr, CMD_BOUNCER_TRANSFER, target,
        "E %s %s %s %s %s :%s",
        parv[2], parv[3], parv[4], parv[5], parv[6], parv[7]);
    return 0;
  }

  /* A session echo only makes sense to a connection that negotiated
   * echo-message (see bounce_echo_pm_to_session). */
  if (!CapActive(target, CAP_ECHOMSG))
    return 0;

  from = bx_find_user_strict(parv[3]);
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
/* Pending BX queue: defer BX subcommands until BX C arrives        */
/* ---------------------------------------------------------------- */

/** Burst race: a BX subcommand can arrive on this server before the
 * matching BX C (alias-create) has been processed.  findNUser
 * returns NULL for the target alias and the message would be dropped.
 *
 * Defer the message into a small bounded queue instead.  When BX C
 * for the matching alias arrives, drain replays the deferred messages
 * through bounce_handle_bt — by then findNUser succeeds and the
 * handler proceeds to deliver locally or forward onward as
 * appropriate.
 *
 * Applies to BX E, BX M (all four variants), BX K, BX U.  BX P and
 * BX X are one-shot semantics where dropping is correct.  BX C
 * itself obviously can't be deferred.
 */

#define BX_PENDING_TTL 30   /* seconds before deferred entries expire */

struct PendingBxEntry {
  char alias_numeric[6];        /**< target alias YYXXX, drain key */
  char cptr_yxx[3];             /**< incoming link server numeric */
  char sptr_yxx[3];             /**< message-source server numeric */
  int  parc;
  char *parv[MAXPARA + 1];      /**< deep-copied; NULL-terminated */
  time_t buffered_at;
  char subcmd_char;             /**< 'E'/'M'/'K'/'U' for diagnostics */
};

static struct PendingBxEntry *pending_bx[MAXCONNECTIONS];

/* bx_drain_in_progress is defined up near the forward declarations
 * because BX K / BX U handlers (which appear earlier in the file)
 * also read it to skip duplicate forwards during replay.  See
 * defer_bx_for_alias and drain_pending_bx_for_alias for the lifetime. */

/** Free a pending entry's deep-copied parv and the entry itself. */
static void
free_pending_bx_entry(struct PendingBxEntry *entry)
{
  int i;
  if (!entry)
    return;
  for (i = 0; i <= MAXPARA; i++) {
    if (entry->parv[i])
      MyFree(entry->parv[i]);
  }
  MyFree(entry);
}

/** Walk the pending array, free entries older than TTL. */
static void
expire_pending_bx(void)
{
  int i;
  time_t cutoff = CurrentTime - BX_PENDING_TTL;
  for (i = 0; i < MAXCONNECTIONS; i++) {
    if (pending_bx[i] && pending_bx[i]->buffered_at < cutoff) {
      Debug((DEBUG_INFO,
             "BX: pending entry for alias %s (subcmd %c) expired",
             pending_bx[i]->alias_numeric, pending_bx[i]->subcmd_char));
      free_pending_bx_entry(pending_bx[i]);
      pending_bx[i] = NULL;
    }
  }
}

/** Buffer a BX subcommand whose target alias couldn't be resolved.
 * Returns 0 on success (caller should return without dropping), -1 if
 * we couldn't buffer (caller falls through to the silent-drop path).
 *
 * If we're inside a drain replay (bx_drain_in_progress != 0), refuse
 * to re-buffer to avoid infinite loops on alias-destroyed-mid-burst.
 *
 * Eviction policy when the array is full: drop the oldest entry.  The
 * window is short (BX_PENDING_TTL = 30s) so under sustained pressure
 * the FIFO behaviour is the right tradeoff — older entries are most
 * likely to be stale anyway.
 */
static int
defer_bx_for_alias(const char *alias_numeric,
                   struct Client *cptr, struct Client *sptr,
                   int parc, char *parv[])
{
  int i, oldest_i = -1;
  time_t oldest_t = CurrentTime;
  struct PendingBxEntry *entry;

  if (bx_drain_in_progress)
    return -1;
  if (!alias_numeric || !*alias_numeric || parc < 2)
    return -1;

  /* Find empty slot, or oldest entry to evict. */
  for (i = 0; i < MAXCONNECTIONS; i++) {
    if (!pending_bx[i]) {
      oldest_i = i;
      break;
    }
    if (pending_bx[i]->buffered_at <= oldest_t) {
      oldest_t = pending_bx[i]->buffered_at;
      oldest_i = i;
    }
  }
  if (oldest_i < 0)
    return -1;
  if (pending_bx[oldest_i])
    free_pending_bx_entry(pending_bx[oldest_i]);

  entry = (struct PendingBxEntry *)MyMalloc(sizeof(*entry));
  memset(entry, 0, sizeof(*entry));
  ircd_strncpy(entry->alias_numeric, alias_numeric,
               sizeof(entry->alias_numeric));
  /* Server numerics are 2 chars + null (3 bytes).  cptr is always a
   * server for S2S BX traffic; sptr is too. */
  if (cptr && IsServer(cptr))
    ircd_strncpy(entry->cptr_yxx, cli_yxx(cptr), sizeof(entry->cptr_yxx));
  if (sptr && IsServer(sptr))
    ircd_strncpy(entry->sptr_yxx, cli_yxx(sptr), sizeof(entry->sptr_yxx));
  entry->parc = (parc > MAXPARA) ? MAXPARA : parc;
  for (i = 0; i < entry->parc; i++) {
    if (parv[i])
      DupString(entry->parv[i], parv[i]);
    else
      entry->parv[i] = NULL;
  }
  entry->parv[entry->parc] = NULL;
  entry->buffered_at = CurrentTime;
  entry->subcmd_char = (parv[1] && parv[1][0]) ? parv[1][0] : '?';

  pending_bx[oldest_i] = entry;
  Debug((DEBUG_INFO,
         "BX: deferred subcmd %c for unknown alias %s (slot %d)",
         entry->subcmd_char, alias_numeric, oldest_i));
  return 0;
}

/** Replay deferred BX entries whose alias_numeric matches.  Called
 * from bounce_alias_create after the new alias's local Client is set
 * up; by then findNUser succeeds for the alias and replay can either
 * deliver locally or forward as appropriate.
 *
 * Replays MUST be issued in insertion order so a BX M start token
 * (M+) runs before its continuation tokens — create_s2s_bxm_batch
 * keys on the start frame and continuations dropped before the start
 * are unrecoverable.  The pending array uses FIFO eviction at insert
 * time but slot indices are reused, so iterating by slot index can
 * interleave the order.  Walk by buffered_at instead: repeatedly
 * pick the oldest matching entry, replay, free, until none remain.
 */
static void
drain_pending_bx_for_alias(const char *alias_numeric)
{
  if (!alias_numeric || !*alias_numeric)
    return;

  bx_drain_in_progress = 1;
  for (;;) {
    int i;
    int oldest_i = -1;
    time_t oldest_t = 0;
    struct PendingBxEntry *entry;
    struct Client *cptr;
    struct Client *sptr;

    /* Find the oldest entry matching this alias. */
    for (i = 0; i < MAXCONNECTIONS; i++) {
      if (!pending_bx[i])
        continue;
      if (strcmp(pending_bx[i]->alias_numeric, alias_numeric) != 0)
        continue;
      if (oldest_i < 0 || pending_bx[i]->buffered_at < oldest_t) {
        oldest_t = pending_bx[i]->buffered_at;
        oldest_i = i;
      }
    }
    if (oldest_i < 0)
      break;

    entry = pending_bx[oldest_i];
    pending_bx[oldest_i] = NULL;

    /* Re-resolve cptr / sptr from server numerics — the original
     * Client*'s could be stale if a server SQUITed in the meantime. */
    cptr = entry->cptr_yxx[0] ? FindNServer(entry->cptr_yxx) : NULL;
    sptr = entry->sptr_yxx[0] ? FindNServer(entry->sptr_yxx) : NULL;

    if (cptr && sptr) {
      Debug((DEBUG_INFO,
             "BX: replaying deferred subcmd %c for alias %s (buffered_at %lu)",
             entry->subcmd_char, alias_numeric,
             (unsigned long)entry->buffered_at));
      bounce_handle_bt(cptr, sptr, entry->parc, entry->parv);
    } else {
      Debug((DEBUG_INFO,
             "BX: dropping deferred subcmd %c for alias %s "
             "(source server gone)",
             entry->subcmd_char, alias_numeric));
    }
    free_pending_bx_entry(entry);
  }
  bx_drain_in_progress = 0;
}

/** Free deferred entries pinned to a dying server link.  Called from
 * exit_one_client when a directly-connected server exits; matches
 * either the cptr_yxx or sptr_yxx field. */
void pending_bx_cleanup_link(struct Client *link)
{
  int i;
  const char *yxx;
  if (!link || !IsServer(link))
    return;
  yxx = cli_yxx(link);
  if (!yxx || !*yxx)
    return;

  for (i = 0; i < MAXCONNECTIONS; i++) {
    if (pending_bx[i]
        && (strcmp(pending_bx[i]->cptr_yxx, yxx) == 0
            || strcmp(pending_bx[i]->sptr_yxx, yxx) == 0)) {
      free_pending_bx_entry(pending_bx[i]);
      pending_bx[i] = NULL;
    }
  }
}

/* ---------------------------------------------------------------- */
/* BX M: Multiline alias echo across S2S                            */
/* ---------------------------------------------------------------- */

/** Per-link multiline-echo buffer state.  Mirrors the shape of
 * S2SMultilineBatch in m_batch.c but keyed on (link, batch_id) so
 * concurrent batches arriving on different links can't collide.
 *
 * Wire format:
 *   BX M+<bid> <alias_num> <from_num><tok> <target_nick> <msgid> [@<ctags>] :<line>
 *   BX M <bid> <alias_num> :<line>
 *   BX Mc<bid> <alias_num> :<line>           (concat continuation)
 *   BX M-<bid> <alias_num> :<paste_url>      (end)
 *
 * Where alias_num is the final destination (sender's session member
 * receiving the echo), and target_nick is the original PM target —
 * the wire %C the alias's IRC client uses to route the conversation
 * into the correct query window.
 */
struct S2SBxmBatch {
  struct Client *link;          /**< incoming S2S link (cptr) */
  char batch_id[16];
  char alias_numeric[6];        /**< receiving session member */
  char from_numeric[6];         /**< sender_primary, source for wire :from */
  char target_nick[NICKLEN + 1];/**< original PM target — wire %C */
  char msgid[64];               /**< base msgid, "" if absent */
  char client_tags[512];        /**< @-prefixed ctags from start opener */
  int  is_notice;               /**< 1 if NOTICE batch, 0 if PRIVMSG */
  char paste_url[256];          /**< from -end token */
  struct SLink *messages;       /**< SLink<concat-flag-byte + text> */
  int  msg_count;
  unsigned int total_bytes;
  time_t start_time;
};

static struct S2SBxmBatch *s2s_bxm_batches[MAXCONNECTIONS];

/** Look up a buffered BX M batch by link + batch_id. */
static struct S2SBxmBatch *
find_s2s_bxm_batch(struct Client *link, const char *batch_id)
{
  int i;
  for (i = 0; i < MAXCONNECTIONS; i++) {
    struct S2SBxmBatch *b = s2s_bxm_batches[i];
    if (b && b->link == link && strcmp(b->batch_id, batch_id) == 0)
      return b;
  }
  return NULL;
}

/** A BX M batch whose '-' end token never arrives (the alias vanished on
 * a peer we cannot see, the batch was abandoned mid-stream) would otherwise
 * pin its slot until the link Client is freed.  Same window as m_batch.c's
 * S2S_ML_BATCH_TIMEOUT_S. */
#define S2S_BXM_BATCH_TIMEOUT_S 60
static void free_s2s_bxm_batch(struct S2SBxmBatch *b);

/** Allocate a new BX M batch slot.  Returns NULL if no slot is free.
 * Reaps timed-out batches first (F-MB3 shape). */
static struct S2SBxmBatch *
create_s2s_bxm_batch(struct Client *link, const char *batch_id,
                     const char *alias_num, const char *from_num,
                     const char *target_nick, const char *msgid,
                     const char *client_tags, int is_notice)
{
  int i;
  struct S2SBxmBatch *b;

  for (i = 0; i < MAXCONNECTIONS; i++)
    if (s2s_bxm_batches[i] &&
        CurrentTime - s2s_bxm_batches[i]->start_time > S2S_BXM_BATCH_TIMEOUT_S) {
      log_write(LS_SYSTEM, L_WARNING, 0,
                "S2S BX M batch %s timed out (%ld s) -- reaping",
                s2s_bxm_batches[i]->batch_id,
                (long)(CurrentTime - s2s_bxm_batches[i]->start_time));
      free_s2s_bxm_batch(s2s_bxm_batches[i]);
    }
  for (i = 0; i < MAXCONNECTIONS; i++)
    if (!s2s_bxm_batches[i])
      break;
  if (i >= MAXCONNECTIONS)
    return NULL;

  b = (struct S2SBxmBatch *)MyMalloc(sizeof(*b));
  memset(b, 0, sizeof(*b));
  b->link = link;
  /* ircd_strncpy uses strlcpy semantics — pass full buffer size, NOT
   * sizeof-1.  Numerics are exactly 5 chars (YYXXX) and need a 6-byte
   * buffer with full sizeof to copy correctly. */
  ircd_strncpy(b->batch_id, batch_id, sizeof(b->batch_id));
  ircd_strncpy(b->alias_numeric, alias_num, sizeof(b->alias_numeric));
  ircd_strncpy(b->from_numeric, from_num, sizeof(b->from_numeric));
  ircd_strncpy(b->target_nick, target_nick, sizeof(b->target_nick));
  if (msgid && strcmp(msgid, "*") != 0)
    ircd_strncpy(b->msgid, msgid, sizeof(b->msgid));
  if (client_tags && *client_tags)
    ircd_strncpy(b->client_tags, client_tags, sizeof(b->client_tags));
  b->is_notice = is_notice;
  b->start_time = CurrentTime;
  s2s_bxm_batches[i] = b;
  return b;
}

/** Append a line to the buffered batch.  is_concat=1 carries the
 * draft/multiline-concat marker forward to delivery. */
static void
add_s2s_bxm_message(struct S2SBxmBatch *b, const char *text, int is_concat)
{
  size_t len;
  struct SLink *lp;
  char *buf;

  if (!b || !text)
    return;

  len = strlen(text);
  buf = (char *)MyMalloc(len + 2);
  buf[0] = is_concat ? 1 : 0;
  memcpy(buf + 1, text, len);
  buf[len + 1] = '\0';

  lp = make_link();
  lp->value.cp = buf;
  lp->next = NULL;

  if (!b->messages) {
    b->messages = lp;
  } else {
    struct SLink *tail = b->messages;
    while (tail->next)
      tail = tail->next;
    tail->next = lp;
  }
  b->msg_count++;
  b->total_bytes += (unsigned int)len;
}

/** Free a buffered batch and clear its slot. */
static void
free_s2s_bxm_batch(struct S2SBxmBatch *b)
{
  int i;
  struct SLink *lp, *next;

  if (!b)
    return;

  for (lp = b->messages; lp; lp = next) {
    next = lp->next;
    if (lp->value.cp)
      MyFree(lp->value.cp);
    free_link(lp);
  }

  for (i = 0; i < MAXCONNECTIONS; i++)
    if (s2s_bxm_batches[i] == b) {
      s2s_bxm_batches[i] = NULL;
      break;
    }
  MyFree(b);
}

/** Free any S2S BX M batches buffered against \a link.
 *
 * Called from exit_one_client when a directly-connected server exits,
 * so partially-accumulated batches whose terminating BX M- token will
 * never arrive don't leak their slots in s2s_bxm_batches[].
 */
void s2s_bxm_cleanup_link(struct Client *link)
{
  int i;
  if (!link)
    return;
  for (i = 0; i < MAXCONNECTIONS; i++) {
    if (s2s_bxm_batches[i] && s2s_bxm_batches[i]->link == link)
      free_s2s_bxm_batch(s2s_bxm_batches[i]);
  }
}

/** Free any S2S BX M batches buffered with \a alias as the destination.
 *
 * Called from bounce_alias_untrack when an alias is destroyed mid-batch
 * (alias quits between BX M+ and BX M-) so the buffered slot doesn't
 * sit until the next link-drop sweep or MAXCONNECTIONS pressure.  The
 * batch's alias_numeric is the full YYXXX form built from the alias's
 * server and own numerics — same construction bounce_alias_untrack uses
 * to look up the session entry.
 */
static void s2s_bxm_cleanup_alias(struct Client *alias)
{
  char full_numeric[6];
  int i;

  if (!alias || !cli_user(alias) || !cli_user(alias)->server)
    return;

  ircd_snprintf(0, full_numeric, sizeof(full_numeric), "%s%s",
                cli_yxx(cli_user(alias)->server), cli_yxx(alias));

  for (i = 0; i < MAXCONNECTIONS; i++) {
    if (s2s_bxm_batches[i]
        && strcmp(s2s_bxm_batches[i]->alias_numeric, full_numeric) == 0)
      free_s2s_bxm_batch(s2s_bxm_batches[i]);
  }
}

/** Deliver a completed BX M batch to the local alias.
 *
 * If the alias has draft/multiline + batch caps, emit a real BATCH
 * wrapper with wire target = target_nick (so the alias's IRC client
 * routes the conversation into the correct query window).
 *
 * Otherwise fall back to send_multiline_fallback() — bounded preview
 * + truncation NOTICE — which already accepts (route_to, wire_target)
 * separately.
 */
static void
deliver_s2s_bxm_batch(struct S2SBxmBatch *b)
{
  struct Client *alias;
  struct Client *from;
  struct Client *wire_target;
  const char *cmd_str;
  struct SLink *lp;

  if (!b)
    return;

  alias = bx_find_user_strict(b->alias_numeric);
  if (!alias) {
    Debug((DEBUG_INFO,
           "BX M: deliver dropped — alias %s not found locally",
           b->alias_numeric));
    return;
  }
  if (!MyConnect(alias)) {
    Debug((DEBUG_INFO,
           "BX M: deliver dropped — alias %s is not local (MyConnect=0)",
           b->alias_numeric));
    return;
  }
  if (!IsUser(alias)) {
    Debug((DEBUG_INFO,
           "BX M: deliver dropped — alias %s is not a user",
           b->alias_numeric));
    return;
  }
  if (!CapActive(alias, CAP_ECHOMSG)) {
    /* A session echo only makes sense to a connection that negotiated
     * echo-message (see bounce_echo_pm_to_session). */
    Debug((DEBUG_INFO,
           "BX M: deliver dropped — alias %s has no echo-message",
           b->alias_numeric));
    return;
  }
  /* Don't require IsBouncerAlias here — the sender's primary-echo
   * path targets the bouncer session's PRIMARY (which is not an
   * IsBouncerAlias) when the sender itself is an alias.  Any local
   * user numeric the sender chose to address via BX M is a legitimate
   * delivery target; sender-side filtering already restricts BX M
   * emission to session members (hs_aliases + primary). */

  from = bx_find_user_strict(b->from_numeric);
  if (!from)
    from = &me;  /* sender vanished mid-batch: route to the &me-safe fallback below */

  /* The wire %C target on the inner messages is the original PM
   * target — resolve to a Client* for the helpers that take it. */
  wire_target = FindUser(b->target_nick);
  cmd_str = b->is_notice ? MSG_NOTICE : MSG_PRIVATE;

  /* The multiline BATCH path derefs cli_user(from) (batch-id, host, inner
   * prefixes) and REQUIRES a real user source per the multiline spec — so it
   * must NOT run when the sender vanished (from == &me, cli_user NULL).  Gate on
   * IsUser(from); a vanished sender falls through to send_multiline_fallback,
   * which is server-source-safe (renders &me as the source, no cli_user deref). */
  if (IsUser(from) && CapActive(alias, CAP_DRAFT_MULTILINE) && CapActive(alias, CAP_BATCH)) {
    char alias_batchid[16];
    ircd_snprintf(0, alias_batchid, sizeof(alias_batchid), "%s%u",
                  NumNick(from), con_batch_seq(cli_connect(alias))++);

    /* BATCH +id draft/multiline <target_nick> opener.  Per IRCv3
     * multiline spec, the opener uses the user as source so the
     * receiving client can target the conversation correctly — server
     * source on the BATCH wrapper around user-originated content
     * causes some clients to route the batch into status instead of
     * the conversation window.  Client-only tags from the originating
     * BATCH +id pass through if present.  All inner messages share
     * the same user prefix. */
    {
      const char *from_host = IsHiddenHost(from) ? cli_user(from)->host
                                                  : cli_user(from)->realhost;
      if (b->client_tags[0]) {
        sendrawto_one(alias,
                      "@%s :%s!%s@%s BATCH +%s draft/multiline %s",
                      b->client_tags,
                      cli_name(from), cli_user(from)->username, from_host,
                      alias_batchid, b->target_nick);
      } else {
        sendcmdto_one(from, CMD_BATCH_CMD, alias,
                      "+%s draft/multiline %s",
                      alias_batchid, b->target_nick);
      }

      /* Inner messages carry @batch=<id>; wire :from is from_user, wire
       * %s target is target_nick — alias's client routes accordingly. */
      for (lp = b->messages; lp; lp = lp->next) {
        int concat = lp->value.cp[0];
        const char *text = lp->value.cp + 1;
        if (concat) {
          sendrawto_one(alias,
                        "@batch=%s;draft/multiline-concat :%s!%s@%s %s %s :%s",
                        alias_batchid, cli_name(from),
                        cli_user(from)->username, from_host,
                        cmd_str, b->target_nick, text);
        } else {
          sendrawto_one(alias,
                        "@batch=%s :%s!%s@%s %s %s :%s",
                        alias_batchid, cli_name(from),
                        cli_user(from)->username, from_host,
                        cmd_str, b->target_nick, text);
        }
      }

      sendcmdto_one(from, CMD_BATCH_CMD, alias, "-%s", alias_batchid);
    }
  } else {
    /* Bounded fallback: preview + truncation NOTICE.  route_to=alias,
     * wire_target=resolved target_nick so the truncated lines land in
     * the alias's correct query window. */
    send_multiline_fallback(from, alias, wire_target,
                            b->msgid[0] ? b->msgid : NULL,
                            b->messages, b->msg_count,
                            0 /* not channel */, NULL /* chptr */,
                            b->paste_url[0] ? b->paste_url : NULL,
                            b->client_tags[0] ? b->client_tags : NULL,
                            b->is_notice);
  }
}

/** Re-emit a BX M line unchanged toward the alias's actual server.
 * Used when the local server is an intermediate hop.  Mirrors the
 * BX E forward at bounce_alias_echo above. */
static void
forward_bxm_line(struct Client *sptr, struct Client *next_hop,
                 int parc, char *parv[])
{
  /* parv[0] is sender prefix, parv[1] is "M".  Re-emit parv[2..] as
   * the BX M payload.  Length-bounded paste-url end can have an empty
   * trailing param so we always pass at least up to whatever parv[]
   * carried.  The exact set of trailing params depends on whether
   * this is start / continuation / concat / end. */
  switch (parc) {
  case 5:
    sendcmdto_one(sptr, CMD_BOUNCER_TRANSFER, next_hop,
                  "M %s %s :%s", parv[2], parv[3], parv[4]);
    break;
  case 8:
    sendcmdto_one(sptr, CMD_BOUNCER_TRANSFER, next_hop,
                  "M %s %s %s %s %s :%s",
                  parv[2], parv[3], parv[4], parv[5], parv[6], parv[7]);
    break;
  case 9:
    sendcmdto_one(sptr, CMD_BOUNCER_TRANSFER, next_hop,
                  "M %s %s %s %s %s %s :%s",
                  parv[2], parv[3], parv[4], parv[5], parv[6], parv[7],
                  parv[8]);
    break;
  default:
    /* Unexpected param count — drop silently rather than emit a
     * malformed forward. */
    break;
  }
}

/** Handle BX M (multiline alias echo).
 *
 * parv[0] = source prefix (server)
 * parv[1] = "M"
 * parv[2] = batch_id with prefix ('+'<bid>, <bid>, 'c'<bid>, '-'<bid>)
 * parv[3] = alias_numeric (final destination)
 *
 * Start (parv[2] starts with '+'):
 *   parv[4] = from_numeric (sender_primary)
 *   parv[5] = command token char ('P' or 'O')
 *   parv[6] = target_nick
 *   parv[7] = msgid or "*"
 *   parv[8] = optional "@<ctags>", with first line in parv[9],
 *             OR first line if no ctags
 *
 * End (parv[2] starts with '-'):
 *   parv[4] = paste_url or "" (trailing)
 *
 * Continuation / concat:
 *   parv[4] = line text
 */
static int
bounce_alias_multiline_echo(struct Client *cptr, struct Client *sptr,
                            int parc, char *parv[])
{
  const char *bid_with_prefix;
  const char *bid;
  char prefix;
  struct Client *alias;
  struct S2SBxmBatch *batch;

  if (parc < 5)
    return protocol_violation(sptr, "BX M requires at least 4 parameters");

  bid_with_prefix = parv[2];
  prefix = bid_with_prefix[0];
  bid = (prefix == '+' || prefix == '-' || prefix == 'c')
        ? bid_with_prefix + 1
        : bid_with_prefix;

  if (!*bid)
    return 0;  /* malformed; drop */

  alias = bx_find_user_strict(parv[3]);
  if (!alias || !IsUser(alias)) {
    /* Burst race: defer until BX C arrives.  Applies to all BX M
     * variants (start / cont / concat / end) — the alias_numeric is
     * always parv[3] regardless of prefix, and replay-in-order means
     * M+ runs before its continuations. */
    defer_bx_for_alias(parv[3], cptr, sptr, parc, parv);
    return 0;
  }

  /* Forward through if alias is on another server. */
  if (!MyConnect(alias)) {
    forward_bxm_line(sptr, alias, parc, parv);
    return 0;
  }

  switch (prefix) {
  case '+': {
    /* Start.  Need from_num, tok, target_nick, msgid, then optional
     * @ctags + first line, or just first line. */
    const char *from_num, *tok_str, *target_nick, *msgid_str;
    const char *client_tags = "";
    const char *first_line = "";
    int is_notice;

    if (parc < 9)
      return protocol_violation(sptr,
          "BX M+ requires from/tok/target/msgid/text params");

    from_num    = parv[4];
    tok_str     = parv[5];
    target_nick = parv[6];
    msgid_str   = parv[7];

    if (parc >= 10 && parv[8][0] == '@') {
      client_tags = parv[8] + 1;
      first_line  = parv[9];
    } else {
      first_line  = parv[8];
    }

    is_notice = (tok_str[0] == 'O');

    /* Drop pre-existing batch with same id (collision) before opening. */
    if ((batch = find_s2s_bxm_batch(cptr, bid)))
      free_s2s_bxm_batch(batch);

    batch = create_s2s_bxm_batch(cptr, bid, parv[3], from_num,
                                 target_nick, msgid_str, client_tags,
                                 is_notice);
    if (!batch)
      return 0;  /* no slot available */

    if (!EmptyString(first_line))
      add_s2s_bxm_message(batch, first_line, 0);
    return 0;
  }

  case '-':
    batch = find_s2s_bxm_batch(cptr, bid);
    if (!batch)
      return 0;
    /* parv[4] is paste_url (possibly empty).  ircd_strncpy uses full
     * buffer size (strlcpy semantics). */
    if (parc >= 5 && !EmptyString(parv[4]))
      ircd_strncpy(batch->paste_url, parv[4], sizeof(batch->paste_url));
    deliver_s2s_bxm_batch(batch);
    free_s2s_bxm_batch(batch);
    return 0;

  case 'c':
  default: {
    /* Concat or plain continuation.  parv[4] is the line text. */
    int is_concat = (prefix == 'c');
    batch = find_s2s_bxm_batch(cptr, bid);
    if (!batch)
      return 0;
    if (parc >= 5 && !EmptyString(parv[4]))
      add_s2s_bxm_message(batch, parv[4], is_concat);
    return 0;
  }
  }
}


/* ---------------------------------------------------------------- */
/* Pending registration during burst                                 */
/* ---------------------------------------------------------------- */

/* When an account-bearing local user finishes SASL while a peer link
 * is mid-burst, registering immediately would create a fresh standalone
 * primary that races the peer's in-flight N for the same account.
 * Each side ends up with a primary, m_nick collision kills one (or
 * both), session state diverges.
 *
 * Defer the register_user call until all bursts are done.  By then
 * peer's N for this account (if any) has been processed, the local
 * session table reflects reality, and bounce_auto_resume can find the
 * correct alias target instead of falling through to standalone-primary
 * creation. */
struct PendingRegistration {
  struct Client            *client;
  struct PendingRegistration *next;
};
static struct PendingRegistration *pending_registrations = NULL;

int bounce_burst_in_progress(void)
{
  int i;
  for (i = 0; i <= HighestFd; i++) {
    struct Client *cli = LocalClientArray[i];
    if (cli && IsServer(cli) && IsBurst(cli))
      return 1;
  }
  return 0;
}

/** Does a link that can carry a BS C have unread inbound bytes (kernel
 * recvbuf or parsed-but-unprocessed dbuf)?  Returns the first such link,
 * or NULL.
 *
 * Used to detect the steady-state BS C race: peer X creates a fresh
 * bouncer session, broadcasts BS C; meanwhile a second SASL'd client
 * arrives on local server Y for the same account.  If Y's
 * bounce_auto_resume runs BEFORE Y has read the BS C off the wire,
 * Y sees no session and creates a parallel primary — split-brain.
 *
 * bounce_burst_in_progress() catches the link-establishment burst
 * case via IsBurst.  This helper catches the steady-state case where
 * IsBurst is clear but data may still be in the kernel buffer
 * unprocessed.
 *
 * Strategy: FIONREAD for the kernel recvbuf + DBufLength for any
 * already-parsed-but-not-yet-dispatched bytes.  Cheap (one ioctl per
 * peer) and avoids reentrant read_packet calls.
 *
 * Only an IRCv3-aware (fork) link counts.  A BS C goes to aware links
 * only (sendcmdto_serv_butone_v3, bounce_burst), so none ever arrives over
 * a legacy link, and a legacy link's unread bytes are no reason to hold a
 * login: before this they did, and a server whose links are all legacy
 * (prod F1 today) kept such a login waiting -- "waiting for peer session
 * announcement", no 001 -- until the next netjoin's end of burst.
 */
struct Client *bounce_peer_has_inbound_data(void)
{
  struct DLink *dlp;

  if (!cli_serv(&me))
    return NULL;

  for (dlp = cli_serv(&me)->down; dlp; dlp = dlp->next) {
    struct Client *peer = dlp->value.cptr;
    int avail;
    if (!peer || !IsServer(peer) || !IsIRCv3Aware(peer))
      continue;
    if (cli_fd(peer) < 0)
      continue;
    if (DBufLength(&cli_recvQ(peer)) > 0)
      return peer;
    if (ioctl(cli_fd(peer), FIONREAD, &avail) == 0 && avail > 0)
      return peer;
  }
  return NULL;
}

int bounce_defer_registration(struct Client *cli)
{
  struct PendingRegistration *p;
  if (!cli)
    return -1;
  p = MyMalloc(sizeof *p);
  if (!p)
    return -1;
  p->client = cli;
  p->next = pending_registrations;
  pending_registrations = p;
  log_write(LS_USER, L_INFO, 0,
            "Bouncer: registration of %s (fd %d) deferred until the next end "
            "of burst or BS C", cli_name(cli)[0] ? cli_name(cli) : "*",
            cli_fd(cli));
  return 0;
}

/** Take every entry for @a cli off the queue (remove_client_from_list()
 * calls this for every client it frees).  Every one, not the first:
 * bounce_defer_registration() does not look for an existing entry, so
 * nothing keeps a client from being queued twice, and an entry left
 * behind would point at freed memory. */
void bounce_remove_pending_registration(struct Client *cli)
{
  struct PendingRegistration **pp = &pending_registrations;
  while (*pp) {
    if ((*pp)->client == cli) {
      struct PendingRegistration *gone = *pp;
      *pp = gone->next;
      MyFree(gone);
      continue;
    }
    pp = &(*pp)->next;
  }
}

int bounce_is_pending_registration(const struct Client *cli)
{
  const struct PendingRegistration *p;
  if (!cli)
    return 0;
  for (p = pending_registrations; p; p = p->next) {
    if (p->client == cli)
      return 1;
  }
  return 0;
}

void bounce_drain_pending_registrations(void)
{
  struct PendingRegistration *list = pending_registrations;
  pending_registrations = NULL;
  while (list) {
    struct PendingRegistration *next = list->next;
    struct Client *cli = list->client;
    /* Skip clients that died waiting (KILL, timeout, SQUIT-via-burst
     * etc.).  ALSO skip clients that haven't received NICK yet — the
     * s_auth.c:725 defer fires the moment SASL completes during a
     * burst, regardless of whether the client has sent NICK.  If we
     * register_user(no-nick) here, the s_user.c:615 assertion
     * `*(cli_name(sptr))` fires before any guard.  These half-
     * registered clients will get their register_user call naturally
     * once NICK arrives (m_nick.c → register_user), so dropping the
     * deferred entry is the right move — natural NICK processing may
     * re-defer if burst is still in progress. */
    if (cli && !IsDead(cli) && cli_fd(cli) >= 0
        && !HasFlag(cli, FLAG_KILLED)
        && cli_name(cli)[0] != '\0') {
      log_write(LS_USER, L_INFO, 0,
                "Bouncer: draining the deferred registration of %s (fd %d)",
                cli_name(cli), cli_fd(cli));
      register_user(cli, cli);
    } else {
      log_write(LS_USER, L_INFO, 0,
                "Bouncer: dropping the deferred registration of %s (%s)",
                cli && cli_name(cli)[0] ? cli_name(cli) : "*",
                (cli && cli_name(cli)[0] == '\0') ? "no NICK yet"
                                                  : "no longer eligible");
    }
    MyFree(list);
    list = next;
  }
}
/* ---------------------------------------------------------------- */
/* BX K: Sync snomask to alias                                       */
/* ---------------------------------------------------------------- */

/** Set a session member's server notice mask (and so +s).
 * Sent by the server where the session's mask is known -- where the
 * member that changed it, or the primary a new alias attached to, is
 * connected -- to each other member's server, routed toward the member,
 * so every server delivers its own server notices to its own members.
 *
 * Format: BX K <member_numeric YYXXX> <snomask_decimal>
 *
 * The member may be an alias or the primary.  A live local member gets
 * the mask, +s iff it is non-zero, and is told; a local held ghost's mask
 * went with its socket, so the session keeps it for the revive.  Nothing
 * is synced onward from here: the sender addresses every member itself.
 */
static int bounce_alias_snomask(struct Client *cptr, struct Client *sptr,
                                int parc, char *parv[])
{
  struct Client *target;
  struct BouncerSession *sess;
  unsigned int snomask;
  time_t ts;
  int is_replay = bx_drain_in_progress;

  if (parc < 4)
    return protocol_violation(sptr, "BX K requires 2 parameters");

  /* Older fork servers sent the 3-char client half of the numeric; it
   * resolves nowhere, and deferring it only filled the pending table and
   * broadcast it into every link. */
  if (strlen(parv[2]) != 5) {
    Debug((DEBUG_INFO, "BX K: dropping short numeric %s", parv[2]));
    return 0;
  }

  target = bx_find_user_strict(parv[2]);
  if (!target || !IsUser(target)) {
    /* Burst race: defer the local snomask-set for replay when BX C
     * arrives for this alias.  Forward to the other BX-aware servers on
     * first arrival (they may have BX C state already); replay skips
     * the forward since the original arrival already broadcast. */
    if (!is_replay) {
      defer_bx_for_alias(parv[2], cptr, sptr, parc, parv);
      sendcmdto_serv_butone_v3(sptr, CMD_BOUNCER_TRANSFER, cptr,
                               "K %s %s%s%s", parv[2], parv[3],
                               parc > 4 ? " " : "", parc > 4 ? parv[4] : "");
    }
    return 0;
  }

  if (!MyConnect(target)) {
    /* On its way to the member's server, first arrival only.  Never back
     * where it came from: a relay that broadcasts (an older server) would
     * otherwise bounce it between us. */
    if (!is_replay && cli_from(target) != cptr)
      sendcmdto_one(sptr, CMD_BOUNCER_TRANSFER, target, "K %s %s%s%s",
                    parv[2], parv[3],
                    parc > 4 ? " " : "", parc > 4 ? parv[4] : "");
    return 0;
  }

  sess = bounce_get_session(target);
  if (!sess || (!IsBouncerAlias(target) && sess->hs_client != target))
    return 0;   /* not a session member here */

  snomask = (unsigned int)strtoul(parv[3], NULL, 10);
  ts = (parc > 4) ? (time_t)strtoul(parv[4], NULL, 10) : 0;
  if (!bounce_snomask_later(sess, ts, cli_yxx(sptr))) {
    /* An older change crossing a newer one: whoever made the newer one
     * has sent it everywhere, this one included. */
    Debug((DEBUG_INFO, "BX K: %s %u stamp %Tu from %s is older than %Tu",
           parv[2], snomask, ts, cli_name(sptr), sess->hs_snomask_ts));
    return 0;
  }
  sess->hs_snomask_ts = ts;
  ircd_strncpy(sess->hs_snomask_origin, cli_yxx(sptr),
               sizeof(sess->hs_snomask_origin));

  if (IsBouncerHold(target)) {
    /* Its mask went with its socket: the revive applies the session's. */
    sess->hs_snomask = snomask;
    sess->hs_snomask_known = 1;
    sess->hs_dirty = 1;
    bounce_start_dirty_persist_timer();
  } else {
    bounce_put_member_snomask(target, snomask, 1);
    sess->hs_snomask = HasFlag(target, FLAG_SERVNOTICE) ? cli_snomask(target) : 0;
    sess->hs_snomask_known = 1;
    bounce_mark_dirty(target);
  }
  Debug((DEBUG_INFO, "BX K: snomask %u on %s (%s)", snomask,
         cli_name(target), parv[2]));
  return 0;
}

/* ---------------------------------------------------------------- */
/* BX V: Visibility (M4b)                                            */
/* ---------------------------------------------------------------- */

/** Handle BX V (Visibility membership).
 *
 * Wire format: <server> BX V <alias_numeric> <sign><channel>
 *   where <sign> is '+' (add CHFL_ALIAS membership) or '-' (remove).
 *
 * Carries an alias-scoped channel-membership change driven by the
 * Phase 4 reconciler.  When a profile loses a channel (auto-shrink
 * via /PART, or PROFILE SET -#x) and the union still wants the
 * channel (another profile has it / account-hold-sticky), the
 * affected aliases' CHFL_ALIAS memberships are removed via BX V
 * without disturbing the primary's network membership.  Symmetric
 * +<channel> for /JOIN-already-member: alias gains CHFL_ALIAS
 * membership locally + on each peer.
 *
 * Distinct from BX C (creates alias + bulk channel list) and BX X
 * (destroys alias entirely).  BX V is per-channel scoped.
 */
static int bounce_alias_visibility(struct Client *cptr, struct Client *sptr,
                                    int parc, char *parv[])
{
  struct Client *alias;
  struct Channel *chptr;
  const char *signed_chan;
  int add;
  int is_replay = bx_drain_in_progress;

  if (parc < 4)
    return protocol_violation(sptr, "BX V requires 2 parameters");

  signed_chan = parv[3];
  if (signed_chan[0] != '+' && signed_chan[0] != '-')
    return protocol_violation(sptr, "BX V channel arg must be +#chan or -#chan");
  add = (signed_chan[0] == '+');

  alias = bx_find_user_strict(parv[2]);
  if (!alias || !IsBouncerAlias(alias)) {
    /* Burst race: alias not yet present locally.  Defer for replay
     * when BX C arrives.  Forward on first arrival. */
    if (!is_replay)
      defer_bx_for_alias(parv[2], cptr, sptr, parc, parv);
    if (!is_replay)
      sendcmdto_serv_butone_v3(sptr, CMD_BOUNCER_TRANSFER, cptr,
                            "V %s %s", parv[2], parv[3]);
    return 0;
  }

  chptr = FindChannel(signed_chan + 1);
  if (chptr)
    bounce_visibility_apply_local(alias, chptr, add);

  /* Forward only on first arrival. */
  if (!is_replay)
    sendcmdto_serv_butone_v3(sptr, CMD_BOUNCER_TRANSFER, cptr,
                          "V %s %s", parv[2], parv[3]);
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
  struct BouncerSession *fallback = NULL;
  const char *me_yxx;

  if (!cptr || !IsAccount(cptr))
    return NULL;

  as = bounce_find_by_account(cli_account(cptr));
  if (!as)
    return NULL;

  /* Cross-sessid split-brain leaves multiple sessions for the same
   * account, both with hs_client pointing at the same primary
   * (the one that won reconcile + the post-BS-C replica from peer).
   * The first in linked-list order wins, but list is prepended on
   * add — so the LATEST-created session shadows ours.  Prefer the
   * session where we have a local presence (an alias on this server)
   * since that's the one /CHECK / channel-state / persistence
   * actually care about.  Fall back to first hs_client match. */
  me_yxx = cli_yxx(&me);

  /* If cptr is an alias (locally demoted, or a peer's primary
   * represented locally as an alias), follow the alias→primary link
   * first so we look for hs_client == primary, not == alias. */
  if (IsBouncerAlias(cptr) && cli_alias_primary(cptr))
    cptr = cli_alias_primary(cptr);

  for (s = as->as_sessions; s; s = s->hs_anext) {
    int i;

    /* Primary match (current/usual case for the canonical hs_client). */
    if (s->hs_client == cptr) {
      if (!fallback)
        fallback = s;
      for (i = 0; i < s->hs_alias_count; i++) {
        if (0 == strcmp(s->hs_aliases[i].ba_server, me_yxx))
          return s;
      }
      continue;
    }

    /* Alias match: cptr is recorded as a session alias (full numeric
     * compare against ba_numeric).  This catches /CHECK on a demoted
     * primary, on a peer's primary that we mirror as alias, and any
     * other "Client struct that participates in the session as an
     * alias" lookup.  Without this, bounce_get_session returned NULL
     * for those Clients and the caller (m_check, etc.) thought the
     * Client wasn't in any session despite hs_aliases[] saying it was. */
    {
      char full[6];
      if (cli_user(cptr) && cli_user(cptr)->server) {
        ircd_snprintf(0, full, sizeof(full), "%s%s",
                      cli_yxx(cli_user(cptr)->server), cli_yxx(cptr));
        for (i = 0; i < s->hs_alias_count; i++) {
          if (0 == strcmp(s->hs_aliases[i].ba_numeric, full)) {
            if (!fallback)
              fallback = s;
            break;
          }
        }
      }
    }
  }
  return fallback;
}

/** Find any session for an account (ACTIVE or HOLDING). */
struct BouncerSession *bounce_find_any_session(const char *account)
{
  struct AccountSessions *as = bounce_find_by_account(account);
  if (!as)
    return NULL;
  return as->as_sessions; /* Return first session, regardless of state */
}

/** Stage the hold mark (,H) of our own client's N beside the session id
 * the hint has just armed.  Only the client's home server stamps a mark,
 * and only on an N that carries an account: a server relaying another
 * server's client copies the mark that client's N arrived with
 * (register_user), or sends none.
 *
 * The mark is made of the predicates the same-nick verdict reads for
 * this client here, from the one bounce_nick_side_lookup() call the hint
 * makes (bounce_session_of_primary(): the session the client is the
 * primary or held ghost of, else one that lists it on its alias roster;
 * none when two sessions name it as their primary), so a peer decides
 * from the facts we would:
 *  - held: a held ghost whose session has no live alias (a held ghost
 *    with one counts as live); a client two sessions name is not held;
 *  - primary: the client is @a bs's hs_client (the verdict's
 *    local_is_session_primary).
 * So the ,S beside a held or primary mark is the session's id, and the
 * ,S beside an outsider mark is the client's own id, except:
 *  - a held ghost no session names: h beside its own id;
 *  - a client a session lists only on its alias roster: n beside that
 *    session's id (an alias comes by BX C, never by N, so only a stale
 *    roster entry puts an N-introduced client there);
 *  - a session with an empty id: h or p beside the client's own id.
 * A client two sessions name as their primary gets n beside its own id,
 * which may equal one of theirs (an attach copies the session's id).
 *
 * @param[in] cptr    Our client.
 * @param[in] held    bounce_nick_side_lookup()'s held fact for it.
 * @param[in] primary Its primary fact, from the same call.
 * @return The mark staged, or 0 when none is.
 */
static char bounce_stage_hold_mark(struct Client *cptr, int held, int primary)
{
  char mark;

  if (!MyConnect(cptr) || !IsAccount(cptr))
    return 0;
  mark = bounce_hold_stamp(held, primary);
  sendcmdto_set_s2s_held(mark);
  return mark;
}

/** Set the S2S sessid override for an outgoing N introduction.
 *
 * Stages the client's session id for the ,S compact-tag segment of the
 * next S2S emit: its bouncer session's hs_sessid when it is a member of
 * one, else its own cli_session_id.  Per redesign A.2: bouncer-aware
 * peers use this hint at-N-time for convergence dispatch in m_nick and
 * in the post-burst reconcile.  For a client of ours with an account it
 * also stages the hold mark (,H) beside it: one lookup for both.
 */
char bounce_set_n_sessid_hint(struct Client *cptr)
{
  struct BouncerSession *bs;
  int held = 0, primary = 0;

  if (!cptr || !IsUser(cptr))
    return 0;

  /* Only a member of the session carries its id: the primary, the held
   * ghost, or a connection on the session's alias roster -- what
   * bounce_session_of_primary() finds, the session the same-nick verdict
   * acts on, so the id and the hold mark come from one lookup.  A client
   * two sessions name as their primary carries its own id: neither is
   * the one.  A peer that receives this id treats the
   * client as part of the session: the ghost-rebind auth gate reads it
   * off the wire, and the receiver adopts it as the client's
   * cli_session_id, which the post-burst reconcile and PM history's
   * same-session lookups match on.  Naming a non-member here hands the
   * session to it.
   *
   * 8cf493c added an account fallback: a client in no session took the
   * id of any session of its account.  It served a local user who had
   * registered while a peer it could not reach held its account's
   * session: the user stayed sessionless, and at the relink its burst N
   * needed the held ghost's id for the peer's rebind, which the fallback
   * read from the replica of that session this server still kept from
   * before the split.  841f3ce made that case rare: SQUIT now destroys a
   * replica of the departed server with no local holder, and
   * bounce_auto_resume discards an unattachable replica, so a login that
   * sees one gets a session of its own.  It can still happen: a replica
   * whose primary never resolved (no hs_client, only hs_ghost_numeric)
   * goes at a split only by the origin it recorded, which can be stale,
   * and is neither discarded nor cleaned up when the ghost exits, so a
   * login beside it registers sessionless.  Without the fallback that login
   * meets the peer's held ghost as a non-member: classic collision.
   * What the fallback mostly reached was the harmful case: a
   * same-account client that is NOT in the session -- an alt on a legacy
   * server whose N we relay, or a connection that never joined -- was
   * stamped with the session's id, and a fork peer then merged the live
   * session into it. */
  bs = NULL;
  if (IsAccount(cptr)) {
    bs = bounce_nick_side_lookup(cptr, &held, &primary);
    if (bs && bs->hs_sessid[0]) {
      sendcmdto_set_s2s_sessid(bs->hs_sessid);
      return bounce_stage_hold_mark(cptr, held, primary);
    }
  }

  /* Fall back to the unified per-Client session ID populated at
   * make_client.  After Phase A this is always non-empty for clients
   * that went through make_client — locally-minted for non-bouncer
   * authed clients and ephemerals.  When we relay an N for a client
   * whose origin server sent ,S (bouncer-aware peer),
   * format_s2s_tags_with_client prefers cli_s2s_sessid over this
   * override — so this fallback only fires when the upstream didn't
   * carry a sessid, letting our minted value propagate downstream. */
  if (cli_session_id(cptr)[0]) {
    sendcmdto_set_s2s_sessid(cli_session_id(cptr));
    return bounce_stage_hold_mark(cptr, held, primary);
  }
  return 0;
}

/** See include/bouncer_session.h. */
int bounce_hold_marks_trusted(struct Client *home)
{
  struct Client *s;
  int hops = 0, hops_with_h = 0, reached_us = 0, sent_h = 0;

  if (!home)
    return 0;
  /* Walk from the client's home toward us, to our direct link. */
  for (s = home; s && IsServer(s) && !IsMe(s); s = cli_serv(s)->up) {
    hops++;
    if (IsHoldMark(s))
      hops_with_h++;
    if (cli_serv(s)->up && IsMe(cli_serv(s)->up)) {
      reached_us = 1;
      sent_h = IsHoldMarkSent(s);
      break;
    }
  }
  return bounce_hold_marks_trusted_path(hops, hops_with_h, reached_us, sent_h,
                                        feature_bool(FEAT_P10_MESSAGE_TAGS));
}

/** See include/bouncer_session.h. */
void bounce_note_burst_stamp(struct Client *c, struct Client *link, char mark)
{
  if (!c || !link || !MyConnect(c) || !cli_connect(c))
    return;
  con_burst_stamp_link(cli_connect(c)) = link;
  con_burst_stamp_serial(cli_connect(c)) =
    cli_serv(link) ? cli_serv(link)->link_serial : 0;
  con_burst_stamp(cli_connect(c)) = mark;
}

/** See include/bouncer_session.h. */
char bounce_burst_stamp_for(struct Client *c, struct Client *link)
{
  if (!c || !link || !MyConnect(c) || !cli_connect(c))
    return 0;
  /* The link, and this establishment of it: a Client pointer is reused
   * by a later link. */
  if (cli_burst_stamp_link(c) != link || !cli_serv(link)
      || cli_burst_stamp_serial(c) != cli_serv(link)->link_serial)
    return 0;
  /* Our burst to the link went out (it is not gated: a gated link has had
   * no N from us this time, and the record is an older link's), and the
   * link is still bursting to us: what its server read about our client
   * is what we stamped then. */
  if (!IsBurst(link) || IsBurstGated(link))
    return 0;
  return cli_burst_stamp(c);
}

/** Purge per-Client ephemeral session-scoped state on exit.
 *
 * See bouncer_session.h for the contract.  Dispatches to each ephemeral
 * subsystem that maintains session-anchored state.  No-op for clients
 * whose state is owned by a persistent backing (bouncer-attached
 * accounts continue to hold their state in the bouncer record /
 * account-anchored CFs).
 *
 * METADATA state is keyed by Client* (cli_metadata) and freed alongside
 * the Client struct itself, so no explicit purge hook is needed there.
 */
void ephemeral_purge_session(struct Client *cli)
{
  if (!cli || !IsUser(cli))
    return;
  if (cli_session_id(cli)[0]) {
    presence_purge_session(cli_session_id(cli));
    readmarker_ephemeral_purge(cli_session_id(cli));
  }
  /* Phase C: free the per-Client PM ring.  Safe to call even when the
   * ring was never allocated (no-op).  Doesn't need cli_session_id
   * because the ring is keyed by Client* directly. */
  chathistory_ephemeral_purge(cli);
}

/** Record per-connection activity for bouncer-aware tiebreaking.
 *
 * Per redesign B.1: D.2's primary-identity tiebreaker operates on
 * per-connection granularity (oldest cli_firsttime → highest
 * last_active → lex on numeric).  This requires tracking last_active
 * per connection — primary's value lives on session->hs_last_active,
 * each alias's on its hs_aliases[i].ba_last_active entry.
 *
 * Called from the general idle-update chokepoints so every non-trivial
 * activity from a bouncer connection bumps the right slot.
 */
void bounce_note_away_state(struct Client *who, int state)
{
  char full_numeric[16];
  if (!who || !MyConnect(who) || !IsUser(who) || !IsAccount(who)
      || !cli_user(who) || !cli_user(who)->server)
    return;
  if (!bounce_has_sessions(cli_user(who)->account))
    return;
  ircd_snprintf(0, full_numeric, sizeof(full_numeric), "%s%s",
                cli_yxx(cli_user(who)->server), cli_yxx(who));
  sendcmdto_serv_butone_v3(&me, CMD_BOUNCER_TRANSFER, NULL,
                        "U %s aw=%d", full_numeric, state);
}

int bounce_activity_quiet(const char *account)
{
  long long idle = account ? webpush_idle_window(account) : 0;
  long long quiet = BOUNCE_ACTIVITY_QUIET;
  if (idle > 0 && idle / 2 < quiet)
    quiet = idle / 2;
  return quiet < 1 ? 1 : (int)quiet;
}

void bounce_record_activity(struct Client *from)
{
  struct AccountSessions *as;
  struct BouncerSession *sess;

  if (!from || !IsUser(from) || !IsAccount(from))
    return;

  as = bounce_find_by_account(cli_account(from));
  if (!as)
    return;

  if (IsBouncerAlias(from)) {
    /* Alias: walk the account's sessions, find the matching alias
     * entry by full YYXXX numeric, bump ba_last_active. */
    char full_numeric[6];
    int i;
    if (!cli_user(from) || !cli_user(from)->server)
      return;
    ircd_snprintf(0, full_numeric, sizeof(full_numeric), "%s%s",
                  cli_yxx(cli_user(from)->server), cli_yxx(from));
    for (sess = as->as_sessions; sess; sess = sess->hs_anext) {
      for (i = 0; i < sess->hs_alias_count; i++) {
        if (0 == strcmp(sess->hs_aliases[i].ba_numeric, full_numeric)) {
          sess->hs_aliases[i].ba_last_active = CurrentTime;
          /* Quiet -> active transition: tell the replicas.  Every
           * consumer of a remote connection's activity (promotion,
           * session idle, webpush attention) reads the replicated
           * value; before this it was frozen at link-burst time. */
          if (MyConnect(from)
              && CurrentTime - sess->hs_aliases[i].ba_last_active_emitted
                 >= bounce_activity_quiet(cli_user(from)->account)) {
            sess->hs_aliases[i].ba_last_active_emitted = CurrentTime;
            sendcmdto_serv_butone_v3(&me, CMD_BOUNCER_TRANSFER, NULL,
                                  "U %s la=%lu", full_numeric,
                                  (unsigned long)CurrentTime);
          }
          return;
        }
      }
    }
  } else {
    /* Primary: find session whose hs_client is this client, bump
     * hs_last_active.  Reuse bounce_get_session's matching logic. */
    for (sess = as->as_sessions; sess; sess = sess->hs_anext) {
      if (sess->hs_client == from) {
        sess->hs_last_active = CurrentTime;
        /* Same transition rule as aliases; only worth a line when the
         * session has other connections whose servers may read it. */
        if (MyConnect(from) && sess->hs_alias_count > 0
            && cli_user(from) && cli_user(from)->server
            && CurrentTime - sess->hs_last_active_emitted
               >= bounce_activity_quiet(cli_user(from)->account)) {
          sess->hs_last_active_emitted = CurrentTime;
          sendcmdto_serv_butone_v3(&me, CMD_BOUNCER_TRANSFER, NULL,
                                "U %s%s la=%lu",
                                cli_yxx(cli_user(from)->server), cli_yxx(from),
                                (unsigned long)CurrentTime);
        }
        return;
      }
    }
  }
}

time_t bounce_session_last_active(struct BouncerSession *session)
{
  time_t best = 0;
  int i;

  if (!session)
    return 0;
  if (session->hs_client && MyConnect(session->hs_client)
      && cli_user(session->hs_client) && cli_user(session->hs_client)->last > best)
    best = cli_user(session->hs_client)->last;
  if (session->hs_last_active > best)
    best = session->hs_last_active;
  for (i = 0; i < session->hs_alias_count; i++) {
    struct Client *alias = findNUser(session->hs_aliases[i].ba_numeric);
    time_t la = session->hs_aliases[i].ba_last_active;
    if (alias && MyConnect(alias) && cli_user(alias) && cli_user(alias)->last > la)
      la = cli_user(alias)->last;
    if (la > best)
      best = la;
  }
  return best;
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
    } else if (session->hs_aliases[i].ba_away_known) {
      /* Remote alias with its own state replicated (BX U aw=). */
      if (session->hs_aliases[i].ba_away == 2) {
        /* AWAY * — invisible to aggregation */
      } else if (session->hs_aliases[i].ba_away == 1) {
        has_away = 1;
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

/** Re-aggregate effective away across a session and broadcast on change. */
void bounce_recompute_session_away(struct BouncerSession *session)
{
  int new_effective = 0;
  char new_msg[AWAYLEN + 1];
  int prev_effective;
  int msg_changed;
  const char *eff_msg;
  struct Client *primary;
  int i;

  if (!session || !session->hs_client)
    return;

  primary = session->hs_client;
  /* Defensive: if exit_one_client failed to null hs_client when the
   * primary was freed (pre-existing burst-desync can leave hs_client !=
   * dying bcptr, so the session-owner cleanup branch skips), MyConnect /
   * cli_user reads below would deref freed memory.  IsUser is a cheap
   * sanity gate — a freed Client has cli_status zeroed in the typical
   * free path.  Not bulletproof against full UAF (reused memory could
   * pass), but pairs with the tokenHash sweep in exit_one_client. */
  if (!IsUser(primary) || !cli_user(primary)) {
    session->hs_client = NULL;
    return;
  }
  prev_effective = session->hs_effective_away;
  bounce_compute_effective_away(session, &new_effective, new_msg);

  if (new_effective == 0)
    eff_msg = "";
  else if (new_effective == 1)
    eff_msg = new_msg[0] ? new_msg : "";
  else
    eff_msg = "*"; /* the star itself; substituted per viewer at emission */

  msg_changed = (new_effective == 1 && prev_effective == 1)
                && 0 != ircd_strcmp(eff_msg, session->hs_effective_away_msg);

  if (new_effective == prev_effective && !msg_changed)
    return;

  /* Mirror onto every local session connection's cli_user->away. */
  if (MyConnect(primary))
    user_set_away(cli_user(primary), new_effective ? (char *)eff_msg : NULL);
  for (i = 0; i < session->hs_alias_count; i++) {
    struct Client *al = findNUser(session->hs_aliases[i].ba_numeric);
    if (al && IsBouncerAlias(al) && MyConnect(al))
      user_set_away(cli_user(al), new_effective ? (char *)eff_msg : NULL);
  }

  /* Broadcast.  Pick the source carefully:
   *
   * - If primary is local, use primary directly.
   * - If primary is remote, using primary as `from` would send primary's
   *   numeric to primary's own home server, producing a "Fake direction"
   *   protocol violation.  Substitute a local alias as the from instead;
   *   the auto-rewrite branch in sendcmdto_serv_butone then does split
   *   delivery (alias numeric to primary's direction, primary numeric
   *   elsewhere), which is the correct alias-aware S2S routing.
   * - If primary is remote and we have no local alias, skip the
   *   broadcast — there's no local connection authoritative enough to
   *   speak for the session here.  Primary's home server will handle.
   *
   * butone=NULL: every channel member of primary needs to know,
   * including primary's own IRC client. */
  {
    struct Client *broadcaster = MyConnect(primary) ? primary : NULL;
    if (!broadcaster) {
      int j;
      for (j = 0; j < session->hs_alias_count; j++) {
        struct Client *al = findNUser(session->hs_aliases[j].ba_numeric);
        if (al && IsBouncerAlias(al) && MyConnect(al)) {
          broadcaster = al;
          break;
        }
      }
    }

    if (broadcaster) {
      char away_msgid[64] = "";
      uint64_t away_time_ms = 0;
      if (feature_bool(FEAT_MSGID)) {
        struct timeval tv;
        generate_msgid(away_msgid, sizeof(away_msgid));
        gettimeofday(&tv, NULL);
        away_time_ms = (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
        sendcmdto_set_s2s_tags(away_time_ms, away_msgid);
        sendcmdto_want_s2s_tags(1);
      }

      /* eff_msg is "" for new_effective == 0, so one call covers present,
       * a normal away message, and the all-connections-AWAY-* case; the
       * star gets FEAT_AWAY_STAR_MSG for legacy peers downstream, same as
       * every other AWAY broadcast (away_send_to_servers). */
      away_send_to_servers(broadcaster, NULL, eff_msg);
      if (away_msgid[0])
        sendcmdto_set_client_msgid(away_msgid);
      if (new_effective == 0)
        sendcmdto_common_channels_capab_butone(primary, CMD_AWAY, NULL,
                                               CAP_AWAYNOTIFY, CAP_NONE, "");
      else
        away_notify_common(primary, NULL, eff_msg);
      sendcmdto_set_client_msgid(NULL);
    }
  }

  session->hs_effective_away = new_effective;
  ircd_strncpy(session->hs_effective_away_msg, eff_msg, AWAYLEN + 1);
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
  int wrap_in_persistence_batch;

  assert(0 != cptr);
  if (!cli_user(cptr))
    return;

  /* Wrap the JOIN/TOPIC/NAMES burst in a draft/persistence batch
   * whenever the client has negotiated `batch` and has at least one
   * channel to restore.  The cap gate is `batch` only — the batch
   * envelope is what requires client understanding, and unknown batch
   * types are tolerated per the batch spec.  Clients that additionally
   * negotiate `draft/persistence` know to treat the batch contents as
   * restoration rather than live activity; clients with only `batch`
   * still benefit from the grouping signal.
   * cli_batch_id is expected to be clear here (callers run during
   * registration before any other batch could be open);
   * send_batch_start would overwrite it otherwise. */
  wrap_in_persistence_batch =
      MyConnect(cptr)
      && CapRecipientHas(cptr, CAP_BATCH)
      && cli_user(cptr)->channel != NULL
      && cli_batch_id(cptr)[0] == '\0';

  if (wrap_in_persistence_batch)
    send_batch_start(cptr, "draft/persistence");

  for (member = cli_user(cptr)->channel; member; member = member->next_channel) {
    struct Channel *chptr = member->channel;

    if (IsZombie(member) || IsDelayedJoin(member))
      continue;

    /* draft/persistence M3 filter: skip channels not visible to this
     * client's active profile.  Empty / unset list = all visible. */
    if (!persistence_channel_visible(cptr, chptr->chname))
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

    /* no-implicit-names: ratified 2026-03-18; accept legacy draft/ form too. */
    if (!CapRecipientHas(cptr, CAP_NOIMPLICITNAMES) &&
        !CapRecipientHas(cptr, CAP_NOIMPLICITNAMES_LEGACY))
      do_names(cptr, chptr, NAMES_ALL|NAMES_EON);
  }

  if (wrap_in_persistence_batch)
    send_batch_end(cptr);
}
