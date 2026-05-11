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
#include "chathistory_presence.h"
#include "session_markread.h"
#include "IPcheck.h"
#include "capab.h"
#include "channel.h"
#include "class.h"
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

#include <assert.h>
#include <errno.h>
#include <sys/uio.h>
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
    int promoted;
    Debug((DEBUG_INFO, "Bouncer: hold expired with %d aliases, promoting for %s",
           session->hs_alias_count, session->hs_account));
    promoted = bounce_promote_alias(session);
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
    /* Per redesign C.2: hs_origin is historical-only.  The runtime
     * "is the primary on a remote server?" question is answered by
     * checking whether hs_client (the held ghost or live primary) is
     * locally connected.  A held ghost made by bounce_create_ghost()
     * has MyConnect()==TRUE because make_client(NULL,...) allocates a
     * Connection; so this branch fires only when the session has no
     * local Client* at all (hs_client NULL or its MyConnect is false). */
    if (!session->hs_client || !MyConnect(session->hs_client)) {
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
    /* Per redesign C.2: hs_origin is historical-only.  Use runtime
     * Client locality — primary is "remote" iff hs_client lives on
     * another server (or is NULL). */
    if (!session->hs_client || !MyConnect(session->hs_client)) {
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
  /* Adopt the Client's pre-existing sessid (minted at make_client) so
   * cli_session_id and hs_sessid agree.  Defensive mint if the Client
   * came via a path that didn't populate cli_session_id. */
  if (cli_session_id(cptr)[0])
    ircd_strncpy(session->hs_sessid, cli_session_id(cptr), BOUNCER_SESSID_LEN);
  else {
    generate_sessid(session->hs_sessid);
    ircd_strncpy(cli_session_id(cptr), session->hs_sessid, S2S_SESSID_BUFSIZE);
  }
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
  ircd_strncpy(cli_session_id(cptr), session->hs_sessid, S2S_SESSID_BUFSIZE);
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
    Debug((DEBUG_INFO, "Bouncer: destroy@detach-no-hold-override sess=%s",
           session->hs_sessid));
    bounce_broadcast(session, 'X', NULL);
    bounce_destroy(session);
    return 0;
  }

  if (session->hs_hold_override < 0 &&
      !feature_bool(FEAT_BOUNCER_DEFAULT_HOLD)) {
    /* No override, and network default is no-hold */
    Debug((DEBUG_INFO, "Bouncer: destroy@detach-default-no-hold sess=%s",
           session->hs_sessid));
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
 * and returns negative.  Returns 0 if invariant holds. */
int bounce_session_assert_invariant(const struct BouncerSession *session,
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
                                                    cli_user(params->peer_primary)
                                                      ? cli_user(params->peer_primary)->server
                                                      : NULL))
        rc = bounce_finish_live_primary_demote(params->demoted_alias,
                                                params->peer_primary);
    }
    break;
  case BST_REBIND_TO_REMOTE:
    /* bounce_rebind() handles this today. */
    rc = -2;
    break;
  case BST_PROMOTE_ALIAS:
    rc = bounce_promote_alias(session);
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
 * from ircd.c as a TT_PERIODIC timer.  Also drives the frontier-
 * introducer pending-canon list. */
void bounce_legacy_burst_gate_callback(struct Event *ev)
{
  (void)ev;
  bounce_legacy_burst_gate_tick();
  bounce_pending_canon_tick();
}

/* ---------------------------------------------------------------- */
/* Frontier introducer: pending-canon list                           */
/* ---------------------------------------------------------------- */

/* When a bouncer-account user finishes registration on a BX-aware
 * server, register_user emits N to BX-aware peers immediately (so the
 * BX-aware ring can converge via D.2 at-N-time) but DEFERS the N
 * emission to legacy peers.  After a brief settle window, if the
 * client is still primary (not demoted to alias by the convergence),
 * we emit N to legacy peers retroactively.  Per design intent #135
 * + #254: legacy peers see exactly one face per session, and that
 * face is the post-convergence canonical primary. */
struct PendingCanon {
  struct Client *cli;
  time_t deadline;
  struct PendingCanon *next;
};
static struct PendingCanon *pending_canons = NULL;

#define BOUNCE_PENDING_CANON_SECS 5

void bounce_pending_canon_register(struct Client *cli)
{
  struct PendingCanon *p;
  if (!cli) return;
  p = MyMalloc(sizeof *p);
  if (!p) return;
  p->cli      = cli;
  p->deadline = CurrentTime + BOUNCE_PENDING_CANON_SECS;
  p->next     = pending_canons;
  pending_canons = p;
}

void bounce_pending_canon_unregister(struct Client *cli)
{
  struct PendingCanon **pp = &pending_canons;
  while (*pp) {
    if ((*pp)->cli == cli) {
      struct PendingCanon *gone = *pp;
      *pp = gone->next;
      MyFree(gone);
      return;
    }
    pp = &(*pp)->next;
  }
}

/** Emit an N introduction toward locally-connected legacy (non-IRCv3-
 * aware, non-services) peers for a single client.  Mirrors set_nick_name's
 * pair of broadcasts (IPv6-aware variant + legacy-IP variant) but targets
 * only legacy peers via direct sendcmdto_one.
 *
 * Per-peer legacy-face suppression: if the client's bouncer session
 * already has a face recorded toward a peer, skip that peer.  Otherwise
 * emit and record.  Result: legacy peers see exactly one N per session.
 * Subsequent calls for other clients of the same session no-op for peers
 * that already have a face. */
void bounce_emit_legacy_n_intro(struct Client *cli)
{
  struct DLink *lp;
  char *tmpstr;
  char ip6_b64[25];
  char ip4_b64[25];
  struct User *user;
  struct BouncerSession *bs;

  if (!cli || !IsUser(cli) || IsBouncerAlias(cli))
    return;
  user = cli_user(cli);
  if (!user)
    return;

  tmpstr = umode_str(cli);
  iptobase64(ip6_b64, &cli_ip(cli), sizeof(ip6_b64), 1);
  iptobase64(ip4_b64, &cli_ip(cli), sizeof(ip4_b64), 0);

  if (!cli_serv(&me))
    return;

  /* Look up session for face-tracking.  May be NULL for non-bouncer
   * clients; in that case fall through with no per-peer suppression
   * (treat as a regular client). */
  bs = bounce_get_session(cli);
  if (!bs && IsAccount(cli))
    bs = bounce_find_any_session(cli_account(cli));

  for (lp = cli_serv(&me)->down; lp; lp = lp->next) {
    struct Client *peer = lp->value.cptr;
    const char *ip_b64;

    if (!peer || !IsServer(peer)) continue;
    if (IsIRCv3Aware(peer)) continue;     /* not legacy */
    if (IsService(peer))    continue;     /* services exempt */
    if (IsBurstGated(peer)) continue;     /* burst gate still active; will be drained later */

    /* Skip if this peer already has a face for the session. */
    if (bs && bounce_session_legacy_face_for(bs, cli_yxx(peer))) {
      Debug((DEBUG_INFO,
             "Bouncer: skipping legacy N to %s for %s — session %s "
             "already has face %s",
             cli_name(peer), cli_name(cli), bs->hs_sessid,
             bounce_session_legacy_face_for(bs, cli_yxx(peer))));
      continue;
    }

    ip_b64 = IsIPv6(peer) ? ip6_b64 : ip4_b64;
    /* No bounce_set_n_sessid_hint here — this loop is gated to legacy
     * peers only (IsIRCv3Aware skipped above), which strip @-prefixed
     * tags at parse.  An override set here would never be consumed and
     * would leak into the next IRCv3-aware emission with a stale
     * sessid pointed at an unrelated client. */
    sendcmdto_one(user->server, CMD_NICK, peer,
                  "%s %d %Tu %s %s %s%s%s%s %s%s :%s",
                  cli_name(cli), cli_hopcount(cli) + 1,
                  cli_lastnick(cli),
                  user->username, user->realhost,
                  *tmpstr ? "+" : "", tmpstr, *tmpstr ? " " : "",
                  ip_b64, NumNick(cli), cli_info(cli));

    if (bs) {
      char face_buf[6];
      ircd_snprintf(0, face_buf, sizeof(face_buf), "%s%s",
                    cli_yxx(user->server), cli_yxx(cli));
      bounce_session_record_legacy_intro(bs, cli_yxx(peer), face_buf);
    }
  }
}

void bounce_pending_canon_tick(void)
{
  struct PendingCanon **pp = &pending_canons;
  while (*pp) {
    struct PendingCanon *p = *pp;
    int drop = 0;
    if (!p->cli || IsDead(p->cli) || HasFlag(p->cli, FLAG_KILLED)) {
      drop = 1;
    } else if (IsBouncerAlias(p->cli)) {
      /* Convergence demoted us — IsBouncerAlias filter handles
       * future emissions; nothing to release for legacy. */
      drop = 1;
    } else if (p->deadline <= CurrentTime) {
      Debug((DEBUG_INFO,
             "Bouncer: emitting deferred legacy N for %s "
             "(canonical primary, frontier-introducer release)",
             cli_name(p->cli)));
      bounce_emit_legacy_n_intro(p->cli);
      drop = 1;
    }
    if (drop) {
      *pp = p->next;
      MyFree(p);
    } else {
      pp = &p->next;
    }
  }
}

/* ---------------------------------------------------------------- */
/* Legacy-face suppression                                           */
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
               peer_yxx, NICKLEN);
  ircd_strncpy(session->hs_legacy_intros[session->hs_legacy_intro_count].bli_face,
               face_yxx, 5);
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

  /* Account the ghost as a local client. The intent (per BOUNCER STATUS audit
   * comment in m_bouncer.c) is that holding ghosts are counted in
   * UserStats.local_clients until the session is destroyed. The original
   * primary's disconnect already ran Count_clientdisconnects when its socket
   * closed; without the matching ++ here we under-count by 1 per ghost.
   *
   * unknowns is NOT touched: the ghost was never a STAT_UNKNOWN TCP
   * connection on this server (it's spawned synthetically). When the ghost
   * eventually exits via exit_one_client → IsUser branch →
   * Count_clientdisconnects, only local_clients/clients are decremented,
   * so this is balanced. */
  ++UserStats.local_clients;
  ++UserStats.clients;
  if (UserStats.local_clients > UserStats.local_clients_max) {
    UserStats.local_clients_max = UserStats.local_clients;
    save_tunefile();
  }
  if (UserStats.clients > UserStats.clients_max) {
    UserStats.clients_max = UserStats.clients;
    save_tunefile();
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
      /* v9: current schema, parse directly from on-disk bytes. */
      if (vlen != sizeof(struct BounceSessionRecord))
        continue;
      rec = (struct BounceSessionRecord *)vbuf;
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
      log_write(LS_SYSTEM, L_INFO, 0,
                "bouncer_persist: migrated v8 record (account=%s) → v9",
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
    session->hs_restore_pending = 1;  /* cleared by burst-time BX R or by attach */
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

    /* Restore the session-anchored oper grant (v9+).  bsr_oper_name is
     * empty for v8-and-earlier records (migration leaves it zero) and
     * for sessions that weren't opered when persisted — in both cases
     * bounce_apply_oper_grant below short-circuits cleanly. */
    ircd_strncpy(session->hs_oper_name, rec->bsr_oper_name,
                 sizeof(session->hs_oper_name));
    session->hs_oper_granted_at = (time_t)rec->bsr_oper_granted_at;

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

  /* If we migrated any v7 records, persist their v8 forms now under the
   * new UUID keys.  Otherwise the migrated state is in-memory only and
   * would be lost without the runtime triggering a session-write. */
  if (migrated_v7 > 0) {
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
            "bouncer_persist: restored %d sessions (%d migrated from v7)",
            restored, migrated_v7);
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

  /* BS / BX are IRCv3-aware extensions — legacy peers (X3, vanilla ircu)
   * log PARSE ERROR on receipt.  No-op burst for non-aware peers. */
  if (!IsIRCv3Aware(cptr))
    return;

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
       * nick collisions instead.
       *
       * Extended format (per redesign C.3 + B.1): carries the primary's
       * last_active and caps so the receiver can populate per-connection
       * activity for D.2 tiebreaking.  Primary doesn't track per-conn
       * caps separately (caps live on session-level umode flags); pass
       * 0.  Receiver parses last_active into hs_last_active when the
       * numeric matches the primary (not in hs_aliases roster). */
      if (s->hs_client)
        sendcmdto_one(&me, CMD_BOUNCER_SESSION,
                      cptr,
                      "A %s %s %s %lu 0",
                      s->hs_account, s->hs_sessid,
                      cli_yxx(s->hs_client),
                      (unsigned long)s->hs_last_active);

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
            /* Per redesign F.2: ride-along JOIN msgid as
             * "<chan>@<msgid>" so receivers replicate single-msgid
             * invariant on alias rejoin during burst. */
            if (memb->join_msgid[0])
              chans_len += ircd_snprintf(0, alias_chans + chans_len,
                                         sizeof(alias_chans) - chans_len,
                                         "%s@%s", memb->channel->chname,
                                         memb->join_msgid);
            else
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

    /* Reconcile against an existing local session for the same token.
     *
     * Original goal: stale local-origin HOLDING vs remote ACTIVE — leaf
     * restored a ghost from MDBX while hub already had the session live.
     * Without reconcile, leaf would keep its stale ghost and every
     * reconnect would revive it instead of attaching as alias to hub's
     * active session.
     *
     * Authorization gate: only yield to BS C from a peer whose origin
     * matches the existing session's recorded origin.  Without this,
     * any peer that obtained the token (legitimately or not) can claim
     * to be the new authority and force-destroy our ghost — same
     * hijack shape as f6f05e5's rebind fix.  In a single-bouncer-server
     * topology this branch should never fire at all (only one server
     * has the token); the gate makes that explicit.
     *
     * Same-state replicas (both holding or both active) are simple
     * dedup: keep what we have. */
    {
      struct BouncerSession *existing = bounce_find_by_token(token);
      if (existing) {
        /* Per redesign C.2: "do we hold this locally?" is a runtime
         * question — session_has_local_holder reads actual Client
         * presence rather than the historical hs_origin attribute. */
        int existing_local = session_has_local_holder(existing);
        if (existing_local && existing->hs_state == BOUNCE_HOLDING
            && !is_holding) {
          /* Only the session's recorded origin may claim ownership.
           * For a local-origin HOLDING session, the recorded origin is
           * us — so any incoming BS C "active" claim from a peer is
           * unauthorized.  Skip the destructive reconcile.  If a real
           * migration is needed it must go through the BS T transfer
           * handshake, which is auditable and explicit. */
          if (0 != strcmp(existing->hs_origin, cli_yxx(sptr))) {
            log_write(LS_USER, L_WARNING, 0,
                      "Bouncer reconcile: refusing to yield local HOLDING "
                      "session %s to %s — origin mismatch (origin=%s, "
                      "introducing=%s); use BS T for legitimate migration",
                      sessid, cli_name(sptr), existing->hs_origin,
                      cli_yxx(sptr));
            return 0;
          }
          {
            struct Client *ghost = existing->hs_client;
            log_write(LS_USER, L_INFO, 0,
                      "Bouncer reconcile: dropping stale local HOLDING ghost "
                      "for session %s — remote %s is ACTIVE",
                      sessid, cli_name(sptr));
            /* Repoint origin to authoritative server, transition to ACTIVE,
             * and drop hs_client (the ghost) so we become a remote replica. */
            ircd_strncpy(existing->hs_origin, cli_yxx(sptr),
                         sizeof(existing->hs_origin) - 1);
            existing->hs_origin[sizeof(existing->hs_origin) - 1] = '\0';
            existing->hs_state = BOUNCE_ACTIVE;
            existing->hs_disconnect_time = 0;
            existing->hs_client = NULL;
            if (t_active(&existing->hs_hold_timer))
              timer_del(&existing->hs_hold_timer);
            /* Drop the persisted record — we're no longer the origin. */
            bounce_db_del(existing->hs_sessid);
            /* Exit the ghost so it doesn't linger as a phantom user.
             *
             * Burst-order invariant (see project_bx_r_yield_burst_order):
             * server_estab emits BS C reconciles before the N loop, but
             * by the time we (loser) process the peer's authoritative
             * BS C, our own N for the ghost has already shipped over the
             * same link.  The peer therefore HAS the ghost as a Client
             * struct.  Letting exit_client broadcast Q normally cleans
             * up the peer's phantom — suppressing it (formerly via
             * FLAG_KILLED) leaves a stale ghost client visible in NAMES
             * and propagating to subsequently linked servers. */
            if (ghost)
              exit_client(cptr, ghost, &me, "Bouncer session moved");
          }
        }
        return 0;
      }
    }

    /* Cross-sessid convergence: if we have an existing local session
     * for this account with a DIFFERENT sessid, don't create a
     * duplicate.  Instead, deterministically pick a winning sessid
     * (UUID v7 lex-lower wins — the older creation timestamp) and
     * rename our local session to that sessid if peer's wins.
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
        struct BouncerSession *local = as_existing->as_sessions;
        /* If sessid already matches some local session, normal
         * single-session-per-account path handles it (we don't get
         * here since bounce_find_by_token would have caught it). */
        if (0 == strcmp(local->hs_sessid, sessid))
          goto bsc_forward;

        if (strcmp(sessid, local->hs_sessid) < 0) {
          /* Peer's sessid is lex-lower (older UUID v7) — peer wins.
           * Rename our local session to peer's sessid so future BX C
           * / BS A by-sessid lookups resolve to our state. */
          Debug((DEBUG_INFO,
                 "BS C: cross-sessid convergence — renaming local "
                 "session %s → %s for account %s (peer wins)",
                 local->hs_sessid, sessid, account));
          bounce_db_del(local->hs_sessid);
          ircd_strncpy(local->hs_sessid, sessid,
                       sizeof(local->hs_sessid) - 1);
          local->hs_sessid[sizeof(local->hs_sessid) - 1] = '\0';
          /* Keep cli_session_id of the bound primary in sync with the
           * renamed bouncer sessid — they must agree post-convergence.
           * Aliases are tracked in hs_aliases[] which records numerics
           * rather than Client pointers; this resolves each alias's
           * Client and updates its cli_session_id in lockstep. */
          if (local->hs_client && IsUser(local->hs_client))
            ircd_strncpy(cli_session_id(local->hs_client), sessid,
                         S2S_SESSID_BUFSIZE);
          {
            int ai;
            for (ai = 0; ai < local->hs_alias_count; ai++) {
              struct Client *al =
                findNUser(local->hs_aliases[ai].ba_numeric);
              if (al && IsUser(al))
                ircd_strncpy(cli_session_id(al), sessid,
                             S2S_SESSID_BUFSIZE);
            }
          }
          /* Re-persist under new sessid if we still hold it locally. */
          if (session_has_local_holder(local))
            bounce_db_put(local);
        } else {
          /* We win — peer will rename when it processes our BS C.
           * Skip creating duplicate; forward peer's BS C downstream. */
          Debug((DEBUG_INFO,
                 "BS C: cross-sessid convergence — local session %s "
                 "wins over peer's %s (account %s); skipping replica",
                 local->hs_sessid, sessid, account));
        }
        goto bsc_forward;
      }
    }

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
     * session origin (YY) to get the full YYXXX for findNUser().
     *
     * Always update hs_ghost_numeric to the new XXX too — after a
     * managing-server restart the ghost gets a freshly-assigned
     * numeric, and the persisted hs_ghost_numeric on this side is
     * stale.  bounce_auto_resume's fallback path (when hs_client
     * happens to be NULL) reads hs_ghost_numeric to do its own
     * findNUser; without this refresh, that lookup would resolve to
     * the old (now-recycled or non-existent) numeric and reattach
     * fails, forcing /bouncer reset. */
    if (parc >= 5 && parv[4][0]) {
      char full_numeric[6];
      struct Client *primary;
      ircd_snprintf(0, full_numeric, sizeof(full_numeric), "%s%s",
                    session->hs_origin, parv[4]);
      primary = findNUser(full_numeric);
      if (primary && IsUser(primary))
        session->hs_client = primary;
      ircd_strncpy(session->hs_ghost_numeric, parv[4],
                   sizeof(session->hs_ghost_numeric) - 1);
      session->hs_ghost_numeric[sizeof(session->hs_ghost_numeric) - 1] = '\0';
    }

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
      if (!matched_alias) {
        /* Not in alias roster — primary attach.  Caps for primary not
         * separately tracked (they're on the Client's umode flags). */
        session->hs_last_active = la;
      }
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
    sendcmdto_serv_butone_v3(sptr, CMD_BOUNCER_SESSION,
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
    if (session) {
      Debug((DEBUG_INFO, "Bouncer: destroy@bs-x-handler sess=%s from=%C",
             session->hs_sessid, sptr));
      bounce_destroy(session);
    }

    /* Forward */
    sendcmdto_serv_butone_v3(sptr, CMD_BOUNCER_SESSION,
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
    sendcmdto_serv_butone_v3(sptr, CMD_BOUNCER_SESSION,
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
  {
    /* Per redesign C.2: detect "we held the primary locally → we no
     * longer hold any local Client" via runtime checks, not hs_origin.
     * Snapshot pre-update; the swap to `alias` happens next. */
    int we_were_holding_primary = (old_primary && MyConnect(old_primary));
    session->hs_client = alias;
    session->hs_state = BOUNCE_ACTIVE;
    session->hs_last_active = CurrentTime;
    session->hs_disconnect_time = 0;
    ircd_strncpy(session->hs_origin, cli_yxx(cli_user(alias)->server),
                  sizeof(session->hs_origin) - 1);
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

  /* Active client is taking over the session — it's no longer a
   * tentative restore.  Clear the reconcile-pending flag so any
   * incoming BX R for this session treats us as firm. */
  session->hs_restore_pending = 0;

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
 * memberships are untouched — no QUIT, no JOIN echo. Wire-level
 * invisible to peers (only local state mutates).
 */
int bounce_rebind_ghost_to_remote_primary(struct Client *ghost,
                                          struct Client *server,
                                          const char *new_numeric,
                                          time_t new_lastnick,
                                          const char *username,
                                          const char *host,
                                          const struct irc_in_addr *new_ip,
                                          const char *info)
{
  struct BouncerSession *session;
  struct Membership *member;
  struct Connection *old_con;
  int i;

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

  /* Authorization gate: rebind is allowed if either
   *   (a) introducing server matches the session's recorded hs_origin
   *       (legacy path; legacy peers do not carry the ,S sessid hint),
   *       OR
   *   (b) the introducing message carries a ,S<sessid> compact tag whose
   *       value matches this session's hs_sessid.  Sessid is a UUIDv7 —
   *       only servers that genuinely hold (or replicate) the session
   *       know it, so the match is non-spoofable across BX-aware peers.
   *
   * Without (a), any peer reintroducing a user via N during burst — even
   * a peer that doesn't run bouncer at all — could hijack the ghost as
   * soon as the +r account matched.  Without (b), held ghosts on this
   * side reject continuation claims from BX-aware peers whose hs_origin
   * we never observed (e.g. both sides restored the same session from
   * MDBX with origin pointing at themselves), and the m_nick fallthrough
   * collides+kills the peer's primary, cascading destroy via Invariant
   * #12 (kill-of-session-member ⇒ session destroy).
   *
   * Per redesign A.2/C.2: sessid is the canonical session identity;
   * hs_origin is historical-only metadata.  Sessid-match supersedes
   * origin-match where present. */
  {
    struct Client *link = cli_from(server) ? cli_from(server) : server;
    const char *wire_sessid = cli_s2s_sessid(link);
    int origin_match = (0 == strcmp(session->hs_origin, cli_yxx(server)));
    int sessid_match = (wire_sessid && wire_sessid[0]
                        && 0 == strcmp(wire_sessid, session->hs_sessid));

    if (!origin_match && !sessid_match) {
      Debug((DEBUG_INFO,
             "bounce_rebind: refusing — session %s origin %s != introducing "
             "server %s and no sessid-tag match (wire ,S='%s', account %s); "
             "peer is not the canonical primary",
             session->hs_sessid, session->hs_origin, cli_yxx(server),
             wire_sessid ? wire_sessid : "", cli_user(ghost)->account));
      return -1;
    }

    if (!origin_match && sessid_match) {
      Debug((DEBUG_INFO,
             "bounce_rebind: authorizing via sessid-tag match — session %s "
             "origin %s, introducing server %s carries matching ,S=%s "
             "(account %s)",
             session->hs_sessid, session->hs_origin, cli_yxx(server),
             wire_sessid, cli_user(ghost)->account));
    }
  }

  Debug((DEBUG_INFO,
         "bounce_rebind: ghost %s account %s -> remote primary %s on %s",
         cli_name(ghost), cli_user(ghost)->account, new_numeric,
         cli_name(server)));

  /* Cancel hold timer — session transitions back to ACTIVE. */
  if (t_active(&session->hs_hold_timer))
    timer_del(&session->hs_hold_timer);

  /* Drop ghost from nick hash and release its local numeric. */
  hRemClient(ghost);
  RemoveYXXClient(&me, cli_yxx(ghost));

  /* Counter rebalance: ghost was local in bounce_create_ghost
   * (++local_clients, ++clients). It now becomes remote: undo the
   * local_clients increment, leave clients alone (still 1 client),
   * and credit the introducing server's per-server count. */
  if (UserStats.local_clients > 0)
    --UserStats.local_clients;
  ++(cli_serv(server)->clients);

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

  /* Update session state. The session's hs_origin (the authoritative server
   * for this session) is left as-is — hub may or may not have taken ownership
   * via the prior auto-resume, and that bookkeeping is not affected by the
   * leaf-side representation rebind. */
  session->hs_state = BOUNCE_ACTIVE;
  session->hs_client = ghost;
  session->hs_last_active = CurrentTime;
  session->hs_disconnect_time = 0;

  /* Update local aliases' alias_primary pointer (struct address didn't
   * change, but be defensive — the session might have been restored
   * with stale state). */
  for (i = 0; i < session->hs_alias_count; i++) {
    struct Client *alias = findNUser(session->hs_aliases[i].ba_numeric);
    if (alias && IsBouncerAlias(alias))
      cli_user(alias)->alias_primary = ghost;
  }

  /* Persisted record represented a HOLDING ghost; session is ACTIVE now. */
  bounce_db_del(session->hs_sessid);

  log_write(LS_USER, L_TRACE, 0,
            "Bouncer rebind: ghost %s rebound to remote primary %s on %s "
            "(session %s)", cli_name(ghost), new_numeric, cli_name(server),
            session->hs_sessid);

  return 0;
}

/* ---------------------------------------------------------------- */
/* Live primary → alias demotion (split-merge)                       */
/* ---------------------------------------------------------------- */

int bounce_demote_live_primary_to_alias(struct Client *acptr,
                                        struct Client *new_primary_server)
{
  struct BouncerSession *session;
  struct Membership *member;
  char alias_full[6];

  if (!acptr || !new_primary_server)
    return -1;
  if (!IsUser(acptr) || !IsAccount(acptr))
    return -1;
  if (IsBouncerAlias(acptr) || IsBouncerHold(acptr))
    return -1;
  /* Refuse to demote a dying socket: alias-exit path skips hold logic
   * and broadcasts BX X, which would destroy the session network-wide.
   * Letting exit_client run on the still-primary Client takes the
   * normal hold path (transition to HOLDING ghost), preserving the
   * session for peer's view. */
  if (IsDead(acptr) || HasFlag(acptr, FLAG_KILLED))
    return -1;

  session = bounce_get_session(acptr);
  if (!session || session->hs_client != acptr)
    return -1;

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
  SetBouncerAlias(acptr);
  cli_user(acptr)->alias_primary = NULL;
  hRemClient(acptr);

  /* Session moves to peer's authority.  hs_origin → introducing
   * server's numeric, hs_client → NULL pending caller patch.  Add
   * acptr to hs_aliases.  Drop persisted MDBX record — we no longer
   * own the session as primary. */
  ircd_strncpy(session->hs_origin, cli_yxx(new_primary_server),
               sizeof(session->hs_origin) - 1);
  session->hs_origin[sizeof(session->hs_origin) - 1] = '\0';
  session->hs_client = NULL;

  if (session->hs_alias_count < BOUNCER_MAX_ALIASES) {
    struct BounceAlias *ba = &session->hs_aliases[session->hs_alias_count++];
    ircd_snprintf(0, alias_full, sizeof(alias_full), "%s%s",
                  cli_yxx(&me), cli_yxx(acptr));
    ircd_strncpy(ba->ba_numeric, alias_full, sizeof(ba->ba_numeric));
    ircd_strncpy(ba->ba_server, cli_yxx(&me), sizeof(ba->ba_server));
    ba->ba_caps = 0;
    ba->ba_caps_known = 0;
  }

  bounce_db_del(session->hs_sessid);

  return 0;
}

int bounce_finish_live_primary_demote(struct Client *demoted_alias,
                                      struct Client *new_primary)
{
  struct BouncerSession *session;

  if (!demoted_alias || !new_primary)
    return -1;
  if (!IsAccount(demoted_alias) || !IsAccount(new_primary))
    return -1;
  if (0 != ircd_strcmp(cli_user(demoted_alias)->account,
                       cli_user(new_primary)->account))
    return -1;

  session = bounce_find_any_session(cli_user(demoted_alias)->account);
  if (!session || session->hs_client != NULL)
    return -1;

  session->hs_client = new_primary;
  cli_user(demoted_alias)->alias_primary = new_primary;

  /* Broadcast BX C so other peers learn about the newly-aliased
   * local connection — they'll create a remote-alias replica with
   * primary pointing at new_primary, channel memberships reflecting
   * the demoted_alias's channel list. */
  {
    char primary_full[6];
    char alias_full[6];
    char chanlist_buf[512];
    char *alias_modes;
    struct Membership *m;
    int len = 0;

    ircd_snprintf(0, primary_full, sizeof(primary_full), "%s%s",
                  cli_yxx(cli_user(new_primary)->server),
                  cli_yxx(new_primary));
    ircd_snprintf(0, alias_full, sizeof(alias_full), "%s%s",
                  cli_yxx(&me), cli_yxx(demoted_alias));

    chanlist_buf[0] = '\0';
    for (m = cli_user(demoted_alias)->channel; m; m = m->next_channel) {
      if (!m->channel)
        continue;
      if (len > 0 && len < (int)sizeof(chanlist_buf) - 1)
        chanlist_buf[len++] = ' ';
      /* Per redesign F.2: per-channel JOIN msgid rides along as
       * "<chan>@<msgid>" so receivers can populate the alias's
       * Membership::join_msgid.  Single-msgid invariant: the alias's
       * cross-server join echo carries the same msgid as the primary's
       * original JOIN. */
      if (m->join_msgid[0])
        len += ircd_snprintf(0, chanlist_buf + len,
                             sizeof(chanlist_buf) - len,
                             "%s@%s", m->channel->chname, m->join_msgid);
      else
        len += ircd_snprintf(0, chanlist_buf + len,
                             sizeof(chanlist_buf) - len,
                             "%s", m->channel->chname);
    }

    alias_modes = umode_str(demoted_alias);
    sendcmdto_serv_butone(&me, CMD_BOUNCER_TRANSFER, NULL,
                          "C %s %s %s %s %s%s :%s",
                          primary_full, alias_full,
                          session->hs_account, session->hs_sessid,
                          *alias_modes ? "+" : "+", alias_modes,
                          chanlist_buf);

    /* Legacy peers: present the demote as a QUIT for the old primary.
     *
     * BX C is bouncer-aware-only; legacy peers see it as Unknown and
     * drop it.  Without further signal they'd retain the demoted client
     * as a regular primary — and when the winner side's primary N
     * arrives via mesh forwarding, legacy's m_nick fires same-user@host
     * collision rules and one or both sides die.  Send Q for the
     * demoted client over LEGACY links only ("Promoted to alias" reason
     * — legacy interprets as a normal QUIT, removes from its view).
     *
     * Skip legacy peers still under the burst gate — their N hasn't
     * been emitted yet (server_estab gated their server_finish_burst),
     * so a retraction Q would be for a phantom they never saw.  When
     * the gate releases later, the IsBouncerAlias filter on the N loop
     * skips this client correctly.
     *
     * The local Client struct stays alive on this server (it's now an
     * alias and continues to handle the user's connection).  Q here is
     * purely a peer-state retraction, not a destroy. */
    {
      struct DLink *dlp;
      char demoted_face[6];
      ircd_snprintf(0, demoted_face, sizeof(demoted_face), "%s%s",
                    cli_yxx(&me), cli_yxx(demoted_alias));
      for (dlp = cli_serv(&me)->down; dlp; dlp = dlp->next) {
        if (IsIRCv3Aware(dlp->value.cptr))
          continue;
        if (IsBurstGated(dlp->value.cptr))
          continue;
        sendcmdto_one(demoted_alias, CMD_QUIT, dlp->value.cptr,
                      ":Promoted to alias of %s", cli_name(new_primary));
      }
      /* Clear the legacy-face record(s) for this demoted face: the Q
       * just retracted it from legacy peers' view, so the next emit
       * (pending-canon tick for the new primary, or a relay-path emit)
       * is authorized to introduce a fresh face.  Without this clear,
       * the recorded BjAAA face stays in hs_legacy_intros forever and
       * future emits skip — legacy ends up with no representation of
       * the session at all. */
      bounce_session_clear_legacy_face(session, demoted_face);
    }
  }

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
    struct Client *alias = findNUser(sess->hs_aliases[i].ba_numeric);

    /* Local aliases on this (primary's) server: apply the field update
     * directly. The S2S broadcast below skips us for loop-prevention,
     * so without this pass our own local aliases stay stale. */
    if (alias && IsBouncerAlias(alias) && MyConnect(alias)) {
      if (0 == ircd_strcmp(field, "host"))
        ircd_strncpy(cli_user(alias)->host, value, HOSTLEN);
      else if (0 == ircd_strcmp(field, "realhost"))
        ircd_strncpy(cli_user(alias)->realhost, value, HOSTLEN);
      else if (0 == ircd_strcmp(field, "realname"))
        ircd_strncpy(cli_info(alias), value, REALLEN);
      else if (0 == ircd_strcmp(field, "fakehost"))
        ircd_strncpy(cli_user(alias)->fakehost, value, HOSTLEN);
      else if (0 == ircd_strcmp(field, "cloakhost"))
        ircd_strncpy(cli_user(alias)->cloakhost, value, HOSTLEN);
      else if (0 == ircd_strcmp(field, "cloakip"))
        ircd_strncpy(cli_user(alias)->cloakip, value, HOSTLEN);
      else if (0 == ircd_strcmp(field, "username"))
        ircd_strncpy(cli_user(alias)->username, value, USERLEN);
    }

    sendcmdto_serv_butone(&me, CMD_BOUNCER_TRANSFER, NULL,
                          "U %s %s=%s",
                          sess->hs_aliases[i].ba_numeric, field, value);
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

  sendcmdto_serv_butone(&me, CMD_BOUNCER_TRANSFER, NULL,
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
  client_set_privs(cptr, aconf);
  if (HasPriv(cptr, PRIV_PROPAGATE)) {
    SetOper(cptr);
    if (HasPriv(cptr, PRIV_ADMIN))
      SetAdmin(cptr);
  } else {
    SetLocOp(cptr);
  }
  cli_handler(cptr) = OPER_HANDLER;
  if (cli_user(cptr)) {
    if (cli_user(cptr)->opername)
      MyFree(cli_user(cptr)->opername);
    DupString(cli_user(cptr)->opername, sess->hs_oper_name);
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
void bounce_sync_session_umodes(struct Client *source)
{
  struct BouncerSession *sess;
  struct Client *primary;
  int i;

  if (!source || !IsUser(source))
    return;

  sess = bounce_get_session(source);
  if (!sess)
    return;

  primary = sess->hs_client;

  /* Apply source's umode/privs/snomask to one target Client.  Self
   * (source == target) is skipped — bounce_copy_umodes would be wasted
   * work. */
#define APPLY_TO(target) do {                                              \
  struct Client *_t = (target);                                            \
  if (_t && _t != source && IsUser(_t)) {                                  \
    bounce_copy_umodes(source, _t);                                        \
    if (MyConnect(_t)) {                                                   \
      if (IsOper(source)) {                                                \
        memcpy(&cli_privs(_t), &cli_privs(source), sizeof(cli_privs(_t))); \
        cli_handler(_t) = OPER_HANDLER;                                    \
      }                                                                    \
      set_snomask(_t, cli_snomask(source), SNO_SET);                       \
    } else {                                                               \
      struct Client *_peer = cli_from(_t);                                 \
      if (_peer && IsServer(_peer) && IsIRCv3Aware(_peer)) {               \
        sendcmdto_one(&me, CMD_BOUNCER_TRANSFER, _t,                       \
                      "K %s %u", cli_yxx(_t),                              \
                      cli_snomask(source));                                \
      }                                                                    \
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
  case 'R': /* retired Phase 5 — silent drop */
  case 'J': /* retired Phase 5 — silent drop */
  case 'F': /* retired Phase 5 — silent drop */
    return 0;
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

  /* Inherit the session's sessid so this alias's cli_session_id agrees
   * with the primary's and with the bouncer session record.  Supersedes
   * the freshly-minted value from make_client. */
  ircd_strncpy(cli_session_id(sptr), session->hs_sessid, S2S_SESSID_BUFSIZE);

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

      /* Append to channel list for BX C (only joined channels).
       * Per redesign F.2: ride-along JOIN msgid as "<chan>@<msgid>"
       * so peers can keep msgid parity for the alias's join echo. */
      if (chanlist_len > 0 && chanlist_len < (int)sizeof(chanlist_buf) - 1)
        chanlist_buf[chanlist_len++] = ' ';
      if (member->join_msgid[0])
        chanlist_len += ircd_snprintf(0, chanlist_buf + chanlist_len,
                                      sizeof(chanlist_buf) - chanlist_len,
                                      "%s@%s", chptr->chname, member->join_msgid);
      else
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

  /* New session connection — re-aggregate effective away. A present
   * alias attaching to an away primary should flip the session to
   * present (and broadcast away-notify) even though no /away was typed. */
  bounce_recompute_session_away(session);

  /* Publish initial cap state to the network so other servers can
   * decide BX M vs BX E for this alias without waiting for a
   * subsequent CAP REQ from the client. */
  bounce_emit_alias_caps(sptr);

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
    /* Inherit the session's sessid so this alias's cli_session_id
     * agrees with the primary's and with the bouncer session record. */
    ircd_strncpy(cli_session_id(alias), sessid, S2S_SESSID_BUFSIZE);
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

  /* Inherit the session's sessid so this alias's cli_session_id agrees
   * with the primary's and with the bouncer session record.  Remote
   * aliases share the alias_server's Connection (from != NULL path in
   * make_client), so cli_session_id was not minted at allocation — we
   * populate it explicitly from the BX C-announced sessid here. */
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

  /* Track alias in session replica.
   *
   * Cross-sessid race: peer's BX C may arrive with peer's *original*
   * sessid (emitted before peer received our BS C and renamed to our
   * lex-lower sessid).  Exact sessid match would miss the local
   * session in that window.  Fall back to account-based lookup —
   * BX C carries the account, and a single account has one local
   * session post-convergence (cross-sessid rename converges sessid
   * across the BX-aware ring), so account match is unambiguous here. */
  session = bounce_find_by_token_sessid(account, sessid);
  if (!session) {
    struct AccountSessions *as = bounce_find_by_account(account);
    if (as && as->as_sessions) {
      session = as->as_sessions;
      Debug((DEBUG_INFO,
             "BX C: sessid %s not found, using account-fallback "
             "session %s for alias %s",
             sessid, session->hs_sessid, alias_numeric));
    }
  }
  if (session && session->hs_alias_count < BOUNCER_MAX_ALIASES) {
    struct BounceAlias *ba = &session->hs_aliases[session->hs_alias_count++];
    ircd_strncpy(ba->ba_numeric, alias_numeric, sizeof(ba->ba_numeric));
    ircd_strncpy(ba->ba_server, alias_numeric, sizeof(ba->ba_server));
    ba->ba_last_active = CurrentTime;
    ba->ba_caps = 0;
    ba->ba_caps_known = 0;
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
    promoted = bounce_promote_alias(session);
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
  target = findNUser(target_numeric);

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
  sendcmdto_serv_butone(sptr, CMD_BOUNCER_TRANSFER, cptr,
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
  int is_replay = bx_drain_in_progress;

  if (parc < 4)
    return protocol_violation(sptr, "BX U requires 2 parameters");

  alias_numeric = parv[2];
  field_value = parv[3];

  alias = findNUser(alias_numeric);
  if (!alias || !IsBouncerAlias(alias)) {
    /* Burst race: defer the local identity update for replay when
     * BX C arrives.  Forward immediately on first arrival so other
     * servers can process; replay skips forward (already broadcast). */
    if (!is_replay)
      defer_bx_for_alias(alias_numeric, cptr, sptr, parc, parv);
    if (!is_replay)
      sendcmdto_serv_butone(sptr, CMD_BOUNCER_TRANSFER, cptr,
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
  } else if (0 == ircd_strcmp(field, "caps")) {
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
        ircd_snprintf(0, full_numeric, sizeof(full_numeric), "%s%s",
                      cli_yxx(cli_user(alias)->server), cli_yxx(alias));
        struct BouncerSession *sess;
        int i;
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
  } else {
    Debug((DEBUG_INFO, "BX U: unknown field '%s' for alias %s", field, alias_numeric));
  }

forward:
  /* Forward only on first arrival.  Replay skips since the original
   * arrival already broadcast — re-running here would duplicate. */
  if (!is_replay)
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
               sizeof(entry->alias_numeric) - 1);
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

/** Allocate a new BX M batch slot.  Returns NULL if no slot is free. */
static struct S2SBxmBatch *
create_s2s_bxm_batch(struct Client *link, const char *batch_id,
                     const char *alias_num, const char *from_num,
                     const char *target_nick, const char *msgid,
                     const char *client_tags, int is_notice)
{
  int i;
  struct S2SBxmBatch *b;

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

  alias = findNUser(b->alias_numeric);
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
  /* Don't require IsBouncerAlias here — the sender's primary-echo
   * path targets the bouncer session's PRIMARY (which is not an
   * IsBouncerAlias) when the sender itself is an alias.  Any local
   * user numeric the sender chose to address via BX M is a legitimate
   * delivery target; sender-side filtering already restricts BX M
   * emission to session members (hs_aliases + primary). */

  from = findNUser(b->from_numeric);
  if (!from)
    from = &me;  /* graceful fallback if from-user vanished mid-batch */

  /* The wire %C target on the inner messages is the original PM
   * target — resolve to a Client* for the helpers that take it. */
  wire_target = FindUser(b->target_nick);
  cmd_str = b->is_notice ? MSG_NOTICE : MSG_PRIVATE;

  if (CapActive(alias, CAP_DRAFT_MULTILINE) && CapActive(alias, CAP_BATCH)) {
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
                      "@%s:%s!%s@%s BATCH +%s draft/multiline %s",
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

  alias = findNUser(parv[3]);
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
  Debug((DEBUG_INFO, "Bouncer: deferring registration for %s until burst settles",
         cli_name(cli)));
  return 0;
}

void bounce_remove_pending_registration(struct Client *cli)
{
  struct PendingRegistration **pp = &pending_registrations;
  while (*pp) {
    if ((*pp)->client == cli) {
      struct PendingRegistration *gone = *pp;
      *pp = gone->next;
      MyFree(gone);
      return;
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
    /* Skip clients that died waiting (KILL, timeout, SQUIT-via-burst etc.) */
    if (cli && !IsDead(cli) && cli_fd(cli) >= 0
        && !HasFlag(cli, FLAG_KILLED)) {
      Debug((DEBUG_INFO, "Bouncer: draining deferred registration for %s",
             cli_name(cli)));
      register_user(cli, cli);
    } else {
      Debug((DEBUG_INFO, "Bouncer: dropping deferred registration for %s "
             "(client no longer eligible)",
             cli ? cli_name(cli) : "?"));
    }
    MyFree(list);
    list = next;
  }
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
  int is_replay = bx_drain_in_progress;

  if (parc < 4)
    return protocol_violation(sptr, "BX K requires 2 parameters");

  alias = findNUser(parv[2]);
  if (!alias || !IsBouncerAlias(alias)) {
    /* Burst race: defer the local snomask-set for replay when BX C
     * arrives for this alias.  Forward to other servers immediately
     * on first arrival (they may have BX C state already); replay
     * skips forward since the original arrival already broadcast. */
    if (!is_replay)
      defer_bx_for_alias(parv[2], cptr, sptr, parc, parv);
    if (!is_replay)
      sendcmdto_serv_butone(sptr, CMD_BOUNCER_TRANSFER, cptr,
                            "K %s %s", parv[2], parv[3]);
    return 0;
  }

  snomask = (unsigned int)atoi(parv[3]);

  /* Only set snomask on local aliases — remote ones will receive
   * the forwarded BX K and handle it themselves. */
  if (MyConnect(alias)) {
    set_snomask(alias, snomask, SNO_SET);
    Debug((DEBUG_INFO, "BX K: set snomask %u on alias %s (%s)",
           snomask, cli_name(alias), parv[2]));
  }

  /* Forward only on first arrival.  Replay re-running the broadcast
   * would duplicate it on the network. */
  if (!is_replay)
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

/** Set the S2S sessid override for an outgoing N introduction.
 *
 * Looks up the client's bouncer session (if any) and stages the
 * sessid for inclusion as the ,S compact-tag segment on the next
 * S2S emit.  No-op for non-bouncer clients (no session → no override
 * → no ,S segment in tag).  Per redesign A.2: bouncer-aware peers
 * use this hint at-N-time for convergence dispatch in m_nick.
 */
void bounce_set_n_sessid_hint(struct Client *cptr)
{
  if (!cptr || !IsUser(cptr))
    return;

  /* Use the unified per-Client session ID populated at make_client.
   * After Phase A this is always non-empty for clients that went
   * through make_client — bouncer-attached clients hold hs_sessid here,
   * non-bouncer authed clients hold their locally-minted sessid,
   * ephemerals hold their locally-minted sessid.  When we relay an N
   * for a client whose origin server sent ,S (bouncer-aware peer),
   * format_s2s_tags_with_client prefers cli_s2s_sessid over this
   * override — so this fallback only fires when the upstream didn't
   * carry a sessid (legacy peer, or non-bouncer client before this
   * generalization), letting our minted value propagate downstream. */
  if (cli_session_id(cptr)[0])
    sendcmdto_set_s2s_sessid(cli_session_id(cptr));
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
  /* TODO Phase C: chathistory_ephemeral_purge(cli); */
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
        return;
      }
    }
  }
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
  prev_effective = session->hs_effective_away;
  bounce_compute_effective_away(session, &new_effective, new_msg);

  if (new_effective == 0)
    eff_msg = "";
  else if (new_effective == 1)
    eff_msg = new_msg[0] ? new_msg : "";
  else
    eff_msg = feature_str(FEAT_AWAY_STAR_MSG)
                ? feature_str(FEAT_AWAY_STAR_MSG) : "*";

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
      }

      if (new_effective == 0) {
        sendcmdto_serv_butone(broadcaster, CMD_AWAY, NULL, "");
        if (away_msgid[0])
          sendcmdto_set_client_msgid(away_msgid);
        sendcmdto_common_channels_capab_butone(primary, CMD_AWAY, NULL,
                                               CAP_AWAYNOTIFY, CAP_NONE, "");
      } else {
        sendcmdto_serv_butone(broadcaster, CMD_AWAY, NULL, ":%s", eff_msg);
        if (away_msgid[0])
          sendcmdto_set_client_msgid(away_msgid);
        sendcmdto_common_channels_capab_butone(primary, CMD_AWAY, NULL,
                                               CAP_AWAYNOTIFY, CAP_NONE,
                                               ":%s", eff_msg);
      }
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

    /* no-implicit-names: ratified 2026-03-18; accept legacy draft/ form too. */
    if (!CapRecipientHas(cptr, CAP_NOIMPLICITNAMES) &&
        !CapRecipientHas(cptr, CAP_NOIMPLICITNAMES_LEGACY))
      do_names(cptr, chptr, NAMES_ALL|NAMES_EON);
  }
}
