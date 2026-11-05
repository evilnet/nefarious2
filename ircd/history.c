/*
 * IRC - Internet Relay Chat, ircd/history.c
 * Copyright (C) 2024 Nefarious Development Team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
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
 * @brief Message history storage using LMDB.
 *
 * LMDB (Lightning Memory-Mapped Database) provides zero-copy reads
 * and MVCC for lock-free concurrent reads. Perfect for chathistory
 * where reads vastly outnumber writes.
 *
 * Key structure: "target\0timestamp\0msgid"
 * This allows efficient range queries by target and timestamp.
 *
 * Implements storage backend for IRCv3 draft/chathistory extension.
 * Specification: https://ircv3.net/specs/extensions/chathistory
 */
#include "config.h"

#include "chathistory_presence.h"
#include "db_cursor.h"
#include "db_env.h"
#include "db_txn.h"
#include "db_types.h"
#include "history.h"
#include "history_record.h"
#include "history_trim.h"
#include "history_trim_codec.h"
#include "redact_index.h"
#include "ml_content.h"
#include "client.h"
#include "channel.h"
#include "ircd.h"
#include "hash.h"
#include "crdt_hlc.h"
#include "db_casefold.h"
#include "ircd_alloc.h"
#include "ircd_compress.h"
#include "ircd_events.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "numeric.h"
#include "s_debug.h"
#include "s_stats.h"
#include "send.h"
#include "struct.h"

#include <string.h>
#ifdef USE_ZSTD
#include <zstd.h>
#endif
#include <stdlib.h>
#include <time.h>
#include <stdint.h>
#include <sys/time.h>
#include "history_stamp.h"

/** Storage environment opened through the db_* abstraction.
 * Owns RocksDB env + per-CF handles; closed via db_env_close. */
static struct db_env *history_db_env = NULL;
static struct db_cf  *history_cf_messages = NULL;
static struct db_cf  *history_cf_msgid = NULL;
static struct db_cf  *history_cf_targets = NULL;
static struct db_cf  *history_cf_quotas = NULL;
static struct db_cf  *history_cf_reply = NULL;
static struct db_cf  *history_cf_redact = NULL;   /* redaction catch-up index (redact_index.h) */
/* The trimmer's indexes (history_trim.h): every stored row also writes a
 * by_time row and a by_owner row in its own batch. */
static struct db_cf  *history_cf_by_time = NULL;
static struct db_cf  *history_cf_by_owner = NULL;

/** The trimmer's slice timer (history_trim_arm adds it, only when it is
 * not already queued). */
static struct Timer history_trim_timer;
/** A pass starts at the next slice (history_trim_kick). */
static int history_trim_pass_pending = 0;
/** history_trim_start ran: the slice timer is initialised. */
static int history_trim_started = 0;

/** Hint a history CF's compaction once this many of its keys were
 * deleted since its last hint, whatever deleted them
 * (htrim_params.compact_min_rows): a steady age-out pass deletes about
 * what one maintenance interval stored, so a per-pass trigger would never
 * fire on prod, and a low-volume CF's tombstones sit behind its 64 MB
 * memtable for days. */
#define HISTORY_TRIM_COMPACT_MIN_ROWS 10000

/** Failed stores, emergency evictions and a climbing background-error
 * count are logged at most once in this many seconds. */
#define HISTORY_FAIL_LOG_SECS 60

/** The CFs the trimmer deletes every row of in time, which RocksDB marks
 * for compaction when an SST file holds a dense run of tombstones
 * (db_env_opts.deletion_heavy_cfs): at least HISTORY_DELETION_TRIGGER
 * deletes in some HISTORY_DELETION_WINDOW consecutive entries.  Age-out
 * and eviction delete oldest first, so each CF's tombstones come in runs
 * (the head of by_time, of each owner in by_owner, of each target in
 * messages and reply_index; msgids are time-ordered), and a window of
 * 4096 half full of them is such a run, not the scattered deletes of a
 * busy target; ml_content holds multiline rows only. */
static const char *const history_deletion_heavy_cfs[] = {
  "messages", "msgid_index", "reply_index", "by_time", "by_owner", NULL
};
#define HISTORY_DELETION_WINDOW  4096
#define HISTORY_DELETION_TRIGGER 2048

/** Flag indicating if history is available */
static int history_available = 0;

/** The default-CF row that says the per-channel quota counters (the
 * quotas CF, write-only since the trim engine's owner accounting) were
 * cleared.  The CF itself stays opened and defined: older binaries still
 * open it. */
#define HISTORY_META_QUOTAS_RETIRED "schema/quotas-retired"
/** What history_init did about them, logged by history_trim_start on the
 * main thread: 1 cleared them this start, -1 could not (the reason in
 * history_retire_err; the next start tries again), 0 nothing to do. */
static int history_retire_state = 0;
static char history_retire_err[200];

/** Callback for channel removal notifications (for CH A - broadcasts) */
static history_channels_removed_cb channel_removed_callback = NULL;

/** Callback for coverage changes (CH A R); history_set_coverage_callback. */
static history_coverage_cb coverage_callback = NULL;

/** Maximum number of named databases.  Currently: 8 history CFs
 * (messages, msgid_index, targets, quotas, reply_index, redact_index,
 * by_time, by_owner) + 2 ml_content CFs (ml_content, ml_paste_secrets)
 * + the default CF (marker/meta rows) = 11; the presence CF lives on the
 * metadata env.  16 leaves headroom. */
#define HISTORY_MAX_DBS 16

/** Key separator character */
#define KEY_SEP '\0'

/** Room for any key prefix history.c bounds an iterator to (a target, a
 * reply parent, a msgid). */
#define HISTORY_PREFIX_MAX (CHANNELLEN + HISTORY_TIMESTAMP_LEN + HISTORY_MSGID_LEN + 8)

/* Forward declarations */
static void history_retire_quotas(struct db_cf *meta);
static uint64_t history_trim_clock(void);
static void history_trim_emptied(const char **targets, int count);
static int history_trim_parse(const void *val, size_t vlen,
                              struct htrim_row_info *out);

/** An iterator over exactly the keys that start with @a prefix
 * (@a plen bytes): lower bound @a prefix, upper bound its successor (the
 * last byte plus one, trailing 0xff bytes dropped first).
 *
 * Every lookup that seeks inside one target's, parent's or msgid's range
 * goes through here.  On an unbounded iterator a seek that finds nothing
 * at or after its key lands on the next LIVE key, and RocksDB walks every
 * tombstone in between -- after retention age-out, a whole dead run of
 * one server's or one target's rows (the bed, 2026-11-04: a CH W dedup
 * miss walked ~40k msgid_index tombstones, three minutes on the main
 * loop).  With bounds a forward step stops at the upper bound and a
 * backward one at the lower, deleted entries included, so a miss costs
 * at most the range's own tombstones.  Seeks keep their meaning inside
 * the range; a seek below it lands on its first key.
 * @return the iterator, or NULL (no successor, an over-long prefix, or
 * the open failed). */
static struct db_iter *history_prefix_iter(struct db_cf *cf,
                                           struct db_snapshot *snap,
                                           const void *prefix, size_t plen)
{
  const unsigned char *p = (const unsigned char *)prefix;
  char upper[HISTORY_PREFIX_MAX];
  size_t n = plen;

  while (n > 0 && p[n - 1] == 0xff)
    n--;
  if (n == 0 || n > sizeof upper)
    return NULL;
  memcpy(upper, prefix, n);
  upper[n - 1] = (char)(p[n - 1] + 1);
  return db_iter_open_bounded(history_db_env, cf, snap, prefix, plen, upper, n);
}

/** Build a lookup key from target and timestamp: fold(target) \0 ts \0
 * msgid.  The codec owns the encoding (history_trim_codec.h): the trim
 * engine rebuilds this key to delete a row, so there is one builder.
 * @param[out] key Output buffer.
 * @param[in] keysize Size of output buffer.
 * @param[in] target Channel or nick.
 * @param[in] timestamp Unix timestamp (or NULL for just target).
 * @param[in] msgid Message ID (or NULL).
 * @return Length of key, or -1 if it doesn't fit.
 */
static int build_key(char *key, int keysize, const char *target,
                     const char *timestamp, const char *msgid)
{
  return keysize > 0 ? htc_msg_key(key, (size_t)keysize, target, timestamp, msgid) : -1;
}

/** Build the targets-index key: the bare target name, folded like the
 * message keys.
 * @return Length of key, or -1 if it doesn't fit.
 */
static int build_target_key(char *key, int keysize, const char *target)
{
  int len = strlen(target);
  if (len >= keysize) return -1;
  db_casefold_bytes(key, target, len);
  return len;
}

/** The live channel incarnation for a storage target: the channel's
 * creationtime, or 0 for PM pair keys and for a channel that does not
 * currently exist.  Stamped into every stored row and compared on read
 * (2026-09-08: a channel recreated on the losing side of a split is a
 * different incarnation; the burst wipes it, and its rows must not become
 * the surviving channel's history). */
time_t history_live_incarnation(const char *target)
{
  struct Channel *chptr;
  if (!target || !IsChannelName(target))
    return 0;
  chptr = FindChannel(target);
  return chptr ? chptr->creationtime : 0;
}

/** Does a stored row belong to the live incarnation?  Unstamped rows
 * (before 2026-09-08) and targets with no live channel always do. */
static int row_incarnation_ok(const struct HistoryMessage *msg, time_t live)
{
  return live == 0 || msg->incarnation == 0 || msg->incarnation == live;
}

/** Parse target and timestamp from a key (htc_msg_key_parse).
 * @param[in] key Key data.
 * @param[in] keylen Key length.
 * @param[out] target Output for target (at least CHANNELLEN+1).
 * @param[out] timestamp Output for timestamp (at least HISTORY_TIMESTAMP_LEN).
 * @param[out] msgid Output for msgid (at least HISTORY_MSGID_LEN).
 * @return 0 on success, -1 on error.
 */
static int parse_key(const char *key, int keylen,
                     char *target, char *timestamp, char *msgid)
{
  return keylen >= 0
      ? htc_msg_key_parse(key, (size_t)keylen, target, CHANNELLEN + 1,
                          timestamp, HISTORY_TIMESTAMP_LEN,
                          msgid, HISTORY_MSGID_LEN)
      : -1;
}

/** Extract +reply= value from a client_tags string.
 *
 * Accepts both the ratified +reply tag (IRCv3 #535, ratified 2026-02-13)
 * and the legacy +draft/reply form for backward compat with clients
 * that haven't updated yet. If both are present, the ratified form wins.
 *
 * @param[in] client_tags Semicolon-separated tag list (e.g.
 *   "+draft/react=X;+reply=MSGID" or "+draft/reply=MSGID").
 * @param[out] buf Buffer for the extracted msgid.
 * @param[in] buflen Size of buf.
 * @return Pointer to buf on success, NULL if neither form is present.
 */
static const char *extract_reply_tag(const char *client_tags, char *buf, size_t buflen)
{
  static const struct {
    const char *needle;
    size_t      len;
  } needles[] = {
    { "+reply=",       7 },   /* ratified — checked first */
    { "+draft/reply=", 13 },  /* legacy draft form */
  };
  size_t i;

  if (!client_tags || !client_tags[0])
    return NULL;

  for (i = 0; i < sizeof(needles) / sizeof(needles[0]); i++) {
    const char *p = client_tags;
    while ((p = strstr(p, needles[i].needle)) != NULL) {
      /* Ensure it's at the start or after a separator. */
      if (p != client_tags && *(p - 1) != ';') {
        p += needles[i].len;
        continue;
      }
      p += needles[i].len;
      {
        const char *end = strchr(p, ';');
        size_t len = end ? (size_t)(end - p) : strlen(p);
        if (len == 0 || len >= buflen)
          return NULL;
        memcpy(buf, p, len);
        buf[len] = '\0';
        return buf;
      }
    }
  }
  return NULL;
}

/** Index a parent→child reply relationship.
 * @param[in] txn Active write transaction.
 * @param[in] target Channel or nick.
 * @param[in] parent_msgid The msgid being referenced.
 * @param[in] timestamp Timestamp of the child message.
 * @param[in] child_msgid Msgid of the child (reaction/redact).
 */
/* Build a flat reply-index key:
 *   target\0parent_msgid\0timestamp\0child_msgid
 * (htc_reply_child_key: the trim engine deletes a row's own entries as a
 * child, so the codec holds the one builder).
 * Returns the length on success, -1 if the buffer is too small. */
static int build_reply_index_key(char *buf, size_t bufsize,
                                 const char *target,
                                 const char *parent_msgid,
                                 const char *timestamp,
                                 const char *child_msgid)
{
  return htc_reply_child_key(buf, bufsize, target, parent_msgid,
                             timestamp, child_msgid);
}

/* Build the prefix used to scan all children of (target, parent_msgid):
 *   target\0parent_msgid\0
 * (htc_reply_prefix: the head of every key build_reply_index_key builds,
 * from the same codec).
 * Returns length on success, -1 if buffer too small. */
static int build_reply_index_prefix(char *buf, size_t bufsize,
                                    const char *target,
                                    const char *parent_msgid)
{
  return htc_reply_prefix(buf, bufsize, target, parent_msgid);
}

/* Stage a reply-index put on @a wb.  Flat-key encoding: the key embeds
 * the child msgid + timestamp; value is empty.  Walking all children of
 * a parent is a prefix scan on target\0parent_msgid\0. */
static void reply_index_put(struct db_writebatch *wb, const char *target,
                            const char *parent_msgid,
                            const char *timestamp, const char *child_msgid)
{
  char keybuf[CHANNELLEN + HISTORY_MSGID_LEN + HISTORY_TIMESTAMP_LEN + HISTORY_MSGID_LEN + 8];
  int klen = build_reply_index_key(keybuf, sizeof(keybuf),
                                   target, parent_msgid,
                                   timestamp, child_msgid);
  if (klen < 0) return;
  db_writebatch_put(wb, history_cf_reply, keybuf, (size_t)klen, "", 0);
}

/*
 * Timestamp Conversion Functions
 *
 * Internal storage and S2S use Unix timestamps (seconds.milliseconds).
 * Client-facing @time= tags use ISO 8601 per IRCv3 spec.
 */

char *history_format_timestamp(char *buf, size_t buflen)
{
  /* "Now" for a store stamp is the HLC's physical time, not the wall
   * clock: it is monotone across received S2S tags, and right after a
   * generate_msgid() it is that msgid's mint time. */
  history_format_ms(buf, buflen, hlc_global()->physical_ms);
  return buf;
}

uint64_t history_event_time_ms(struct Client *link)
{
  if (link && cli_s2s_time_ms(link))
    return cli_s2s_time_ms(link);
  return hlc_global()->physical_ms;
}

void history_format_ms(char *buf, size_t buflen, uint64_t ms)
{
  ircd_snprintf(0, buf, buflen, "%lu.%03lu",
                (unsigned long)(ms / 1000), (unsigned long)(ms % 1000));
}

void history_format_iso_ms(char *buf, size_t buflen, uint64_t ms)
{
  time_t sec = (time_t)(ms / 1000);
  struct tm tm;

  gmtime_r(&sec, &tm);
  ircd_snprintf(0, buf, buflen, "%04d-%02d-%02dT%02d:%02d:%02d.%03luZ",
                tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                tm.tm_hour, tm.tm_min, tm.tm_sec,
                (unsigned long)(ms % 1000));
}

uint64_t history_parse_ms(const char *ts)
{
  return htc_parse_ms(ts);
}

int history_unix_to_iso(const char *unix_ts, char *iso_buf, size_t iso_buflen)
{
  unsigned long secs;
  unsigned int millis = 0;
  char *dot;
  time_t t;
  struct tm tm;

  if (!unix_ts || !iso_buf || iso_buflen < 25)
    return -1;

  secs = strtoul(unix_ts, &dot, 10);
  if (dot && *dot == '.') {
    millis = strtoul(dot + 1, NULL, 10);
    /* Ensure exactly 3 digits */
    if (millis > 999) millis = 999;
  }

  t = (time_t)secs;
  if (!gmtime_r(&t, &tm))
    return -1;

  ircd_snprintf(0, iso_buf, iso_buflen,
                "%04d-%02d-%02dT%02d:%02d:%02d.%03uZ",
                tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                tm.tm_hour, tm.tm_min, tm.tm_sec, millis);
  return 0;
}

int history_iso_to_unix(const char *iso_ts, char *unix_buf, size_t unix_buflen)
{
  struct tm tm;
  time_t t;
  unsigned int millis = 0;
  const char *p;
  char *end;

  if (!iso_ts || !unix_buf || unix_buflen < 15)
    return -1;

  /* Parse ISO 8601: YYYY-MM-DDThh:mm:ss[.sss]Z */
  memset(&tm, 0, sizeof(tm));

  /* Parse date */
  tm.tm_year = strtol(iso_ts, &end, 10) - 1900;
  if (!end || *end != '-') return -1;
  p = end + 1;

  tm.tm_mon = strtol(p, &end, 10) - 1;
  if (!end || *end != '-') return -1;
  p = end + 1;

  tm.tm_mday = strtol(p, &end, 10);
  if (!end || *end != 'T') return -1;
  p = end + 1;

  /* Parse time */
  tm.tm_hour = strtol(p, &end, 10);
  if (!end || *end != ':') return -1;
  p = end + 1;

  tm.tm_min = strtol(p, &end, 10);
  if (!end || *end != ':') return -1;
  p = end + 1;

  tm.tm_sec = strtol(p, &end, 10);

  /* Parse the optional fraction as a DECIMAL fraction: ".5" is 500 ms,
   * ".12" is 120 ms, ".123456" is 123 ms.  strtoul on the digits read
   * ".5" as 5 ms and clamped ".123456" to 999 (audit 2026-09-06). */
  if (end && *end == '.') {
    const char *d = end + 1;
    unsigned int scale = 100;
    millis = 0;
    while (*d >= '0' && *d <= '9') {
      if (scale)
        millis += (unsigned int)(*d - '0') * scale;
      scale /= 10;
      d++;
    }
    end = (char *)d;
  }

  /* Convert to Unix time */
  t = timegm(&tm);
  if (t == (time_t)-1)
    return -1;

  ircd_snprintf(0, unix_buf, unix_buflen, "%lu.%03u",
                (unsigned long)t, millis);
  return 0;
}

int history_init(const char *dbpath)
{
  struct db_env_opts env_opts;
  struct db_cf_opts  cf_opts;
  int rc;

  if (history_available)
    return 0; /* Already initialized */

  memset(&env_opts, 0, sizeof env_opts);
  if (feature_bool(FEAT_CHATHISTORY_DB_NOSYNC)) {
    env_opts.sync_period_seconds = (unsigned int)feature_int(FEAT_CHATHISTORY_DB_SYNC_INTERVAL);
    log_write(LS_SYSTEM, L_INFO, 0,
              "history: deferred-sync mode, %u second flush interval",
              env_opts.sync_period_seconds);
  }
  env_opts.deletion_heavy_cfs = history_deletion_heavy_cfs;
  env_opts.deletion_window    = HISTORY_DELETION_WINDOW;
  env_opts.deletion_trigger   = HISTORY_DELETION_TRIGGER;

  rc = db_env_open(dbpath, &env_opts, HISTORY_MAX_DBS, &history_db_env);
  if (rc != DB_OK) {
    log_write(LS_SYSTEM, L_ERROR, 0, "history: db_env_open(%s) failed: %s",
              dbpath, db_strerror(rc));
    return -1;
  }

  /* Open the column families.  reply_index uses flat-key encoding —
   * each (parent, child) pair gets its own unique key. */
  memset(&cf_opts, 0, sizeof cf_opts);
  if (db_cf_open(history_db_env, "messages", &cf_opts, &history_cf_messages) != DB_OK
      || db_cf_open(history_db_env, "msgid_index", &cf_opts, &history_cf_msgid) != DB_OK
      || db_cf_open(history_db_env, "targets", &cf_opts, &history_cf_targets) != DB_OK
      || db_cf_open(history_db_env, "quotas", &cf_opts, &history_cf_quotas) != DB_OK
      || db_cf_open(history_db_env, "reply_index", &cf_opts, &history_cf_reply) != DB_OK
      || db_cf_open(history_db_env, "redact_index", &cf_opts, &history_cf_redact) != DB_OK
      || db_cf_open(history_db_env, "by_time", &cf_opts, &history_cf_by_time) != DB_OK
      || db_cf_open(history_db_env, "by_owner", &cf_opts, &history_cf_by_owner) != DB_OK) {
    log_write(LS_SYSTEM, L_ERROR, 0, "history: db_cf_open failed: %s",
              db_env_last_error(history_db_env));
    db_env_close(history_db_env);
    history_db_env = NULL;
    return -1;
  }

  /* Stores written before the key builders folded names are rewritten
   * to folded keys once, before anything reads them (db_casefold.h).
   * A failure leaves the store as it was; the next open retries.
   * by_time and by_owner are not listed: their keys start with binary
   * (a be64 time, an owner key) and are written folded from birth. */
  {
    struct db_casefold_cf cfs[] = {
      { history_cf_messages, "messages",    1u },   /* target\0ts\0msgid */
      { history_cf_msgid,    "msgid_index", 2u },   /* msgid\0target */
      { history_cf_targets,  "targets",     DB_CASEFOLD_ALL },
      { history_cf_quotas,   "quotas",      3u },   /* channel\0account */
      { history_cf_reply,    "reply_index", 1u },   /* target\0parent\0ts\0child */
    };
    if (db_casefold_migrate(history_db_env, "history", cfs,
                            sizeof(cfs) / sizeof(cfs[0])) != 0)
      log_write(LS_SYSTEM, L_WARNING, 0,
                "history: case-fold key migration did not complete; "
                "rows keyed under an unfolded spelling stay invisible "
                "until the next start (%s)",
                db_env_last_error(history_db_env)
                  ? db_env_last_error(history_db_env) : "no backend detail");
  }

  /* Open multiline content databases (shares this env) */
  if (ml_content_init(history_db_env) != 0) {
    log_write(LS_SYSTEM, L_WARNING, 0,
              "history: ml_content_init failed, multiline content store unavailable");
    /* Non-fatal — history still works, just without separate multiline storage */
  }

  /* The trim engine over this env's CFs.  db_cf_open hands back the
   * handles ml_content_init opened (and the default CF, where the
   * engine's meta rows live); without the multiline store no row has
   * content or paste rows, so the engine gets no handle for them. */
  {
    struct htrim_store st;
    memset(&st, 0, sizeof st);
    st.env      = history_db_env;
    st.messages = history_cf_messages;
    st.msgid    = history_cf_msgid;
    st.targets  = history_cf_targets;
    st.reply    = history_cf_reply;
    st.redact   = history_cf_redact;
    st.by_time  = history_cf_by_time;
    st.by_owner = history_cf_by_owner;
    if (ml_content_available()
        && (db_cf_open(history_db_env, "ml_content", &cf_opts, &st.ml_content) != DB_OK
            || db_cf_open(history_db_env, "ml_paste_secrets", &cf_opts, &st.ml_paste) != DB_OK)) {
      st.ml_content = NULL;
      st.ml_paste = NULL;
    }
    if (db_cf_open(history_db_env, "default", NULL, &st.meta) != DB_OK)
      st.meta = NULL;
    /* The per-channel quota counters are retired: cleared once. */
    history_retire_quotas(st.meta);
    /* The parse callback decodes rows for the backfill. */
    if (htrim_init(&st, history_trim_parse, history_trim_clock,
                   history_trim_emptied) != 0) {
      log_write(LS_SYSTEM, L_ERROR, 0,
                "history: trim engine init failed; history unavailable");
      ml_content_shutdown(history_db_env);
      db_env_close(history_db_env);
      history_db_env = NULL;
      return -1;
    }
  }

  /* Strict-presence init moved to ircd.c: the account records now live
   * on the METADATA env (#6 replication), which initializes after this
   * function. */

  history_available = 1;
  log_write(LS_SYSTEM, L_INFO, 0, "history: storage initialized at %s", dbpath);

  /* Pre-fault database pages into OS page cache for faster initial queries */
  db_env_warmup(history_db_env);

  return 0;
}

void history_shutdown(void)
{
  if (!history_available)
    return;

  /* Force sync before shutdown if NOSYNC mode was used */
  if (feature_bool(FEAT_CHATHISTORY_DB_NOSYNC)) {
    log_write(LS_SYSTEM, L_INFO, 0, "history: final sync before shutdown");
    db_env_sync(history_db_env);
  }

  if (t_active(&history_trim_timer))
    timer_del(&history_trim_timer);
  history_trim_pass_pending = 0;
  history_trim_started = 0;
  htrim_stamp_alive((uint64_t)time(NULL) * 1000ULL);
  htrim_shutdown();

  presence_shutdown();
  ml_content_shutdown(history_db_env);
  db_cf_close(history_db_env, history_cf_messages);
  db_cf_close(history_db_env, history_cf_msgid);
  db_cf_close(history_db_env, history_cf_targets);
  db_cf_close(history_db_env, history_cf_quotas);
  db_cf_close(history_db_env, history_cf_reply);
  db_cf_close(history_db_env, history_cf_by_time);
  db_cf_close(history_db_env, history_cf_by_owner);
  db_env_close(history_db_env);
  history_db_env = NULL;
  history_cf_messages = NULL;
  history_cf_msgid = NULL;
  history_cf_targets = NULL;
  history_cf_redact = NULL;
  history_cf_quotas = NULL;
  history_cf_reply = NULL;
  history_cf_by_time = NULL;
  history_cf_by_owner = NULL;
  history_available = 0;

  log_write(LS_SYSTEM, L_INFO, 0, "history: storage shutdown complete");
}

struct db_env *history_get_env(void)
{
  return history_db_env;
}

/* ---------------------------------------------------------------- */
/* The trim scheduler                                                 */
/*                                                                    */
/* One budgeted htrim_run_slice per tick.  While the engine reports   */
/* work, the slice timer re-arms TT_RELATIVE 1 s (ircd timers have    */
/* whole-second resolution); otherwise the maintenance tick           */
/* (history_purge_callback, CHATHISTORY_MAINTENANCE_INTERVAL) starts  */
/* the next pass.                                                     */
/* ---------------------------------------------------------------- */

/** Clear the retired quota counters once: when the default-CF row
 * HISTORY_META_QUOTAS_RETIRED is absent, one range delete over the whole
 * quotas CF, then the row.  history_init (a worker thread): records the
 * outcome for history_trim_start to log. */
static void history_retire_quotas(struct db_cf *meta)
{
  struct db_writebatch *wb;
  const char *err;
  int rc;

  history_retire_state = 0;
  if (!meta || !history_cf_quotas)
    return;
  rc = db_exists(history_db_env, meta, HISTORY_META_QUOTAS_RETIRED,
                 strlen(HISTORY_META_QUOTAS_RETIRED), NULL);
  if (rc == DB_OK)
    return;                                     /* an earlier start did it */
  if (rc == DB_NOTFOUND)
    rc = db_delete_range(history_db_env, history_cf_quotas, "", 0,
                         "\xff\xff\xff\xff", 4);
  if (rc == DB_OK) {
    wb = db_writebatch_new(history_db_env);
    rc = wb ? db_writebatch_put(wb, meta, HISTORY_META_QUOTAS_RETIRED,
                                strlen(HISTORY_META_QUOTAS_RETIRED), "1", 1)
            : DB_ERR_MEMORY;
    if (rc == DB_OK)
      rc = db_writebatch_commit(wb, /*sync_durably=*/0);
    db_writebatch_destroy(wb);
  }
  if (rc == DB_OK) {
    history_retire_state = 1;
    return;
  }
  err = db_env_last_error(history_db_env);
  ircd_snprintf(0, history_retire_err, sizeof history_retire_err, "%s (%s)",
                db_strerror(rc), err ? err : "no backend detail");
  history_retire_state = -1;
}

/** The trim engine's clock: monotonic microseconds. */
static uint64_t history_trim_clock(void)
{
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
    return 0;
  return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000ULL;
}

/** Targets a trim slice emptied: tell the network (CH A -), as the old
 * empty-target cleanup did.  Called after a slice's commit: from the
 * slice timer, and from the burst-loss prune (history_purge_incarnation,
 * inside the burst's channel wipeout -- as the old prune's cleanup was)
 * -- never from inside a store. */
static void history_trim_emptied(const char **targets, int count)
{
  if (channel_removed_callback && count > 0)
    channel_removed_callback(targets, count);
}

/** CHATHISTORY_TRIM_SLICE_MS clamped to 1..1000: the main-loop time one
 * slice may take. */
static unsigned int trim_slice_ms(void)
{
  int v = feature_int(FEAT_CHATHISTORY_TRIM_SLICE_MS);
  if (v < 1)
    v = 1;
  if (v > 1000)
    v = 1000;
  return (unsigned int)v;
}

static void history_trim_timer_cb(struct Event *ev);

/** Arm the 1 s slice timer -- only when it is not already queued: a
 * timer_add on a queued timer trips timer_enqueue's assert (and corrupts
 * the queue with asserts off).  From inside the timer's own callback the
 * timer is off the queue and marked, so timer_add only flags it for
 * re-queueing.  Every arming path goes through here. */
static void history_trim_arm(void)
{
  if (t_onqueue(&history_trim_timer))
    return;
  timer_add(&history_trim_timer, history_trim_timer_cb, 0, TT_RELATIVE, 1);
}

static void history_trim_timer_cb(struct Event *ev)
{
  int pass_start;

  if (ev_type(ev) != ET_EXPIRE)
    return;
  pass_start = history_trim_pass_pending;
  history_trim_pass_pending = 0;
  history_trim_tick(pass_start);
}

/** Consecutive failed slices; the 1 s retry stops after this many. */
#define HISTORY_TRIM_RETRIES 5
static int history_trim_fail_streak = 0;

/** The history env's background-error count last reported, and when. */
static uint64_t history_bg_errors = 0;
static time_t history_bg_errors_at = 0;

/** Each trim tick: RocksDB's count of failed background flushes and
 * compactions ("rocksdb.background-errors", kept on the default CF).  A
 * store whose background work failed can stay read-only, failing every
 * write until the IRCd restarts (nothing here reopens it), so a change
 * of the count is said once: one L_ERROR and one oper notice.  RocksDB's
 * C API does not expose the background error itself; the line names the
 * env's last write error (the last failed foreground op the wrapper
 * recorded), which is often that error coming back on a write, but need
 * not be.  A count still climbing (a flush retried in the background) is
 * said at most once a minute, the latest count then. */
static void history_check_background_errors(void)
{
  uint64_t n = 0;
  const char *err;

  if (db_property_u64(history_db_env, NULL, "rocksdb.background-errors", &n) != DB_OK
      || n == history_bg_errors)
    return;
  if (n && history_bg_errors_at
      && CurrentTime - history_bg_errors_at < HISTORY_FAIL_LOG_SECS)
    return;                                     /* said this minute already */
  history_bg_errors = n;
  if (!n)
    return;
  history_bg_errors_at = CurrentTime;
  err = db_env_last_error(history_db_env);
  log_write(LS_SYSTEM, L_ERROR, 0,
            "history: the chathistory store reports %llu background error%s "
            "(failed flushes or compactions); last write error: %s; history "
            "writes may fail until the server restarts",
            (unsigned long long)n, n == 1 ? "" : "s", err ? err : "none recorded");
  sendto_opmask_butone(0, SNO_OLDSNO,
                       "Chathistory store: %llu background error%s; last write "
                       "error: %s; history writes may fail until restart",
                       (unsigned long long)n, n == 1 ? "" : "s",
                       err ? err : "none recorded");
}

void history_trim_tick(int pass_start)
{
  struct htrim_params p;
  int mb, rc;

  if (!history_available)
    return;
  history_check_background_errors();

  memset(&p, 0, sizeof p);
  p.now_ms         = (uint64_t)time(NULL) * 1000ULL;
  p.retention_days = feature_int(FEAT_CHATHISTORY_RETENTION);
  mb               = feature_int(FEAT_HISTORY_MAP_SIZE_MB);
  p.cap_bytes      = mb > 0 ? (uint64_t)mb << 20 : 0;
  p.high_pct       = feature_int(FEAT_CHATHISTORY_HIGH_WATERMARK);
  p.low_pct        = feature_int(FEAT_CHATHISTORY_LOW_WATERMARK);
  p.quota_on       = feature_bool(FEAT_CHATHISTORY_USER_QUOTA);
  p.share_pct      = feature_int(FEAT_CHATHISTORY_USER_QUOTA_PCT);
  p.slice_ms       = trim_slice_ms();
  p.compact_min_rows = HISTORY_TRIM_COMPACT_MIN_ROWS;

  /* A pass start: the alive stamp the next start's index-gap check reads,
   * and an age-out pass -- resuming where the walk stopped, or back at the
   * oldest row indexed behind it since (a late store, a backfill). */
  if (pass_start) {
    htrim_stamp_alive(p.now_ms);
    htrim_pass_start(&p);
    /* Coverage grows as days pass: the floor ages a whole day with no
     * slice moving it.  The callback re-reads history_coverage_days()
     * and tells peers only a change. */
    if (coverage_callback)
      coverage_callback();
  }

  /* 1: work remains, run again in a second.  0: idle until the next
   * maintenance tick.  -1: retry in a second, up to HISTORY_TRIM_RETRIES
   * failures in a row, then only at the maintenance ticks (a persistent
   * failure is not repeated every second); logged once per streak. */
  rc = htrim_run_slice(&p);
  if (rc >= 0) {
    if (history_trim_fail_streak > 0)
      log_write(LS_SYSTEM, L_INFO, 0,
                "history: trim slices running again after %d failed",
                history_trim_fail_streak);
    history_trim_fail_streak = 0;
    if (rc == 1)
      history_trim_arm();
    return;
  }
  if (history_trim_fail_streak++ == 0)
    log_write(LS_SYSTEM, L_ERROR, 0,
              "history: trim %s; retrying each second up to %d times, then "
              "at each maintenance tick", htrim_last_error(),
              HISTORY_TRIM_RETRIES);
  if (history_trim_fail_streak <= HISTORY_TRIM_RETRIES)
    history_trim_arm();
}

void history_trim_slice_budget_changed(void)
{
  /* The longest slice so far was measured under the old budget. */
  htrim_reset_max_slice();
}

void history_trim_kick(void)
{
  if (!history_available)
    return;
  history_trim_pass_pending = 1;
  history_trim_arm();
}

void history_trim_start(uint64_t newest_row_ms)
{
  int interval;

  if (!history_available)
    return;
  /* What history_init (a worker thread) did about the retired quota
   * counters, logged here on the main thread. */
  if (history_retire_state > 0)
    log_write(LS_SYSTEM, L_INFO, 0,
              "history: quota counters retired (the quotas CF stays for older "
              "binaries)");
  else if (history_retire_state < 0)
    log_write(LS_SYSTEM, L_WARNING, 0,
              "history: cannot clear the retired quota counters: %s; the next "
              "start tries again", history_retire_err);
  history_retire_state = 0;
  /* Rows newer than the last alive stamp plus two maintenance intervals
   * (a crash can leave a whole interval of rows after the last stamp)
   * were stored while this binary was not running: the backfill runs
   * again from the first row.  Then this start is itself a stamp -- unless
   * the reset did not reach the store: a fresh stamp would then hide the
   * gap from the next start if this one died before the re-run's first
   * slice committed. */
  interval = feature_int(FEAT_CHATHISTORY_MAINTENANCE_INTERVAL);
  if (interval < 60)
    interval = 60;
  if (htrim_check_index_gap(newest_row_ms, 2000ULL * (uint64_t)interval) < 0)
    log_write(LS_SYSTEM, L_ERROR, 0,
              "history: trim index-gap reset did not reach the store; no alive "
              "stamp this start, so the next start finds the gap again");
  else
    htrim_stamp_alive((uint64_t)time(NULL) * 1000ULL);
  /* A never-armed (or long-expired) timer: a fresh generator. */
  if (!t_onqueue(&history_trim_timer) && !t_active(&history_trim_timer))
    timer_init(&history_trim_timer);
  history_trim_started = 1;
  /* The boot accounting scan has work from the first second. */
  history_trim_arm();
}

/** A log line at most once a minute (HISTORY_FAIL_LOG_SECS); the next
 * one counts the events in between. */
struct history_ratelog {
  time_t        last;
  unsigned long quiet;     /**< events not logged since the last line */
};

/** @return 1 when a line may go out now -- @a more then says how many
 * events went unlogged since the previous line ("" for none) -- or 0
 * when this event is only counted. */
static int history_ratelog_due(struct history_ratelog *rl, char *more, size_t size)
{
  if (rl->last && CurrentTime - rl->last < HISTORY_FAIL_LOG_SECS) {
    rl->quiet++;
    return 0;
  }
  if (rl->quiet)
    ircd_snprintf(0, more, size, " (%lu more since the last such line)", rl->quiet);
  else
    more[0] = '\0';
  rl->quiet = 0;
  rl->last = CurrentTime;
  return 1;
}

/** A store gave up after its storage op @a what failed with @a rc:
 * L_ERROR, at most one line a minute -- a store stuck after a background
 * error fails every write, which must show on prod without flooding the
 * log (history_trim_tick reports the background-error count itself). */
static void history_store_failed(const char *what, const char *target,
                                  const char *msgid, int rc)
{
  static struct history_ratelog rl;
  char more[64];
  const char *err;

  if (!history_ratelog_due(&rl, more, sizeof more))
    return;
  err = db_env_last_error(history_db_env);
  log_write(LS_SYSTEM, L_ERROR, 0,
            "history: cannot store %s in %s: %s failed: %s (%s)%s", msgid, target,
            what, db_strerror(rc), err ? err : "no backend detail", more);
}

/** A row the trim-record limits refuse (a field too long for the by_time
 * value or an owner key -- history_trim_row_prepare's -1): the row is not
 * stored at all, not just unindexed.  Debug() alone is compiled out of a
 * production build, so a legitimate refusal (an oversized field, not a
 * bug) would otherwise be invisible there.  L_NOTICE, at most one line a
 * minute (HISTORY_FAIL_LOG_SECS, the same rate as history_store_failed);
 * the next one counts the refusals in between. */
static void history_trim_refused(const char *target, const char *msgid,
                                 const char *timestamp)
{
  static struct history_ratelog rl;
  char more[64];

  if (!history_ratelog_due(&rl, more, sizeof more))
    return;
  log_write(LS_SYSTEM, L_NOTICE, 0,
            "history: refused to store %s in %s (ts '%s'): a field does not "
            "fit the trim record%s",
            msgid, target, timestamp, more);
}

/** HISTORY_MAP_SIZE_MB as the cap in bytes (0 = no cap), and the
 * watermarks by the planner's rule (htc_plan_sanitize). */
static uint64_t history_trim_cap(int *high, int *low)
{
  int mb = feature_int(FEAT_HISTORY_MAP_SIZE_MB);

  *high = feature_int(FEAT_CHATHISTORY_HIGH_WATERMARK);
  *low = feature_int(FEAT_CHATHISTORY_LOW_WATERMARK);
  htc_plan_sanitize(high, low);
  return mb > 0 ? (uint64_t)mb << 20 : 0;
}

/** After a counted store: a store that takes the total strictly above the
 * cap's high watermark starts the slices now, not at the next maintenance
 * tick.  An armed timer stays as it is (history_trim_arm). */
static void history_trim_cap_kick(void)
{
  int high, low;
  uint64_t cap;

  if (!history_trim_started)
    return;
  cap = history_trim_cap(&high, &low);
  if (cap && htc_acct_total(htrim_acct()) > cap * (uint64_t)high / 100)
    history_trim_arm();
}

/** A store found the env full (DB_ERR_FULL): one budgeted slice of THE
 * delete of the oldest rows overall (htrim_emergency), then the store
 * retries once.  The slice checks no target and reports none from inside
 * the store: the next trim slice (armed here) cleans up the targets it
 * emptied and sends their CH A -, tells the coverage callback when the
 * floor moved, and runs the targets sweep it armed.  Within a second of
 * one that failed or deleted nothing the engine skips it (0: no retry).
 * Logged at most once a minute.
 * @return the rows deleted (the store retries when > 0), or -1. */
static int history_emergency_evict(void)
{
  static struct history_ratelog rl;
  char more[64];
  int n = htrim_emergency(trim_slice_ms());

  if (n > 0 && history_trim_started)
    history_trim_arm();
  if (history_ratelog_due(&rl, more, sizeof more)) {
    if (n < 0)
      log_write(LS_SYSTEM, L_ERROR, 0,
                "history: storage full, and the emergency eviction failed: %s%s",
                htrim_last_error(), more);
    else if (n == 0)
      log_write(LS_SYSTEM, L_WARNING, 0,
                "history: storage full, and the emergency eviction deleted "
                "nothing (no indexed rows, or within a second of one that "
                "failed or found none)%s", more);
    else
      log_write(LS_SYSTEM, L_WARNING, 0,
                "history: storage full: the emergency eviction deleted %d of the "
                "oldest rows%s", n, more);
  }
  return n;
}

/* ---------------------------------------------------------------- */
/* msgid index — multi-target scheme                                  */
/*                                                                    */
/* One msgid can legitimately exist under multiple targets: a QUIT or */
/* NICK event stores one row per common channel, all sharing the      */
/* broadcast msgid (one msgid per event across all delivery paths).   */
/* The old index keyed rows on the bare msgid, so the last-written    */
/* channel silently overwrote the rest, and evicting ONE channel's    */
/* copy deleted the shared index row out from under every other       */
/* channel's still-live rows (anchors died network-visibly).          */
/*                                                                    */
/* New scheme: key = "msgid\0target", value = "timestamp" — naturally */
/* multi-row, exact per-target deletes, no read-modify-write.  Rows   */
/* written before this change (key = bare msgid, value =              */
/* "target\0timestamp\0") remain readable via a legacy fallback and  */
/* age out through retention.                                          */
/* ---------------------------------------------------------------- */

/** Build the new-scheme index key "msgid\0target" (htc_msgid_key).
 * @return Key length, or -1 if it doesn't fit. */
static int build_msgid_index_key(char *buf, size_t bufsize,
                                 const char *msgid, const char *target)
{
  return htc_msgid_key(buf, bufsize, msgid, target);
}

/** Parse a LEGACY index value ("target\0timestamp[\0]") into
 * @a timestamp (and optionally @a target_out).
 * @return 0 on success, -1 on malformed. */
static int parse_legacy_msgid_val(const struct db_val *val, char *timestamp,
                                  char *target_out, size_t target_sz)
{
  const char *sep = memchr(val->base, KEY_SEP, val->len);
  size_t copy_len;
  if (!sep)
    return -1;
  if (target_out) {
    size_t tl = (size_t)(sep - (const char *)val->base);
    if (tl >= target_sz)
      return -1;
    memcpy(target_out, val->base, tl);
    target_out[tl] = '\0';
  }
  sep++;
  copy_len = (const char *)val->base + val->len - sep;
  if (copy_len > 0 && sep[copy_len - 1] == KEY_SEP)
    copy_len--;
  if (copy_len == 0 || copy_len >= HISTORY_TIMESTAMP_LEN)
    return -1;
  memcpy(timestamp, sep, copy_len);
  timestamp[copy_len] = '\0';
  return 0;
}

/** Resolve @a msgid to a timestamp (and optionally the target) via the
 * index: exact new-scheme row when @a target is given; otherwise the
 * first new-scheme row by prefix scan; legacy bare-key row as the
 * fallback either way.
 * @return 0 found, 1 not found, -1 error. */
static int msgid_index_resolve(const char *msgid, const char *target,
                               struct db_snapshot *snap, char *timestamp,
                               char *target_out, size_t target_sz)
{
  struct db_val val = { NULL, 0 };
  char keybuf[HISTORY_MSGID_LEN + 1 + CHANNELLEN + 2];
  int klen;
  int rc;
  size_t mlen = strlen(msgid);

  if (target && target[0]) {
    klen = build_msgid_index_key(keybuf, sizeof(keybuf), msgid, target);
    if (klen > 0) {
      rc = db_get(history_db_env, history_cf_msgid, keybuf, (size_t)klen,
                  snap, &val);
      if (rc == DB_OK) {
        if (val.len == 0 || val.len >= HISTORY_TIMESTAMP_LEN) {
          db_val_free(&val);
          return -1;
        }
        memcpy(timestamp, val.base, val.len);
        timestamp[val.len] = '\0';
        if (target_out)
          ircd_strncpy(target_out, target, target_sz);
        db_val_free(&val);
        return 0;
      }
      if (rc != DB_NOTFOUND)
        return -1;
    }
  } else {
    /* No target: first new-scheme row wins (any channel resolves the
     * shared timestamp -- multi-channel events stamp all rows from one
     * gettimeofday).  The iterator holds exactly [msgid\0, msgid\x01):
     * a miss must not walk on into the next msgid's range (an aged-out
     * server's msgids sit in long contiguous dead runs). */
    struct db_iter *it = NULL;
    if (mlen + 1 < sizeof(keybuf)) {
      memcpy(keybuf, msgid, mlen);
      keybuf[mlen] = '\0';
      it = history_prefix_iter(history_cf_msgid, snap, keybuf, mlen + 1);
    }
    if (it) {
      {
        if (db_iter_seek(it, keybuf, mlen + 1) == DB_OK
            && db_iter_valid(it)) {
          size_t klen2, vlen2;
          const void *kb = db_iter_key(it, &klen2);
          const void *vb = db_iter_value(it, &vlen2);
          if (kb && klen2 > mlen + 1
              && memcmp(kb, msgid, mlen) == 0
              && ((const char *)kb)[mlen] == '\0'
              && vb && vlen2 > 0 && vlen2 < HISTORY_TIMESTAMP_LEN) {
            memcpy(timestamp, vb, vlen2);
            timestamp[vlen2] = '\0';
            if (target_out) {
              size_t tl = klen2 - mlen - 1;
              if (tl < target_sz) {
                memcpy(target_out, (const char *)kb + mlen + 1, tl);
                target_out[tl] = '\0';
              } else {
                target_out[0] = '\0';
              }
            }
            db_iter_close(it);
            return 0;
          }
        }
      }
      db_iter_close(it);
    }
  }

  /* Legacy fallback: bare-msgid key, "target\0timestamp" value. */
  memset(&val, 0, sizeof(val));
  rc = db_get(history_db_env, history_cf_msgid, msgid, mlen, snap, &val);
  if (rc == DB_NOTFOUND)
    return 1;
  if (rc != DB_OK)
    return -1;
  rc = parse_legacy_msgid_val(&val, timestamp, target_out, target_sz);
  db_val_free(&val);
  return (rc == 0) ? 0 : -1;
}

/** Stage a target's TARGETS-index stamp on \a wb, keeping the later of
 * the stamp held and \a timestamp.  max(), not a blind overwrite: a row
 * arriving late with an OLDER stamp (S2S lag, CH W, a relayed QUIT, a
 * multiline batch from another server) must not move the target's
 * "latest" backwards.  Every store path goes through here.
 * @return DB_OK, or the failing db status / -1 for a bad target.
 */
static int stage_target_stamp(struct db_writebatch *wb, const char *target,
                              const char *timestamp)
{
  char tkey[CHANNELLEN + 2];
  struct db_val cur = { NULL, 0 };
  int newer = 1;
  int tlen = build_target_key(tkey, sizeof(tkey), target);

  if (tlen < 0)
    return -1;
  if (db_get(history_db_env, history_cf_targets, tkey, (size_t)tlen,
             NULL, &cur) == DB_OK && cur.base && cur.len > 0) {
    newer = history_stamp_newer(timestamp, strlen(timestamp),
                                (const char *)cur.base, cur.len);
    db_val_free(&cur);
  }
  if (!newer)
    return DB_OK;
  return db_writebatch_put(wb, history_cf_targets, tkey, (size_t)tlen,
                           timestamp, strlen(timestamp));
}

/* ---------------------------------------------------------------- */
/* The trim index on the store path (history_trim.h)                  */
/*                                                                    */
/* Every stored row also writes a by_time row (be64(ms) ‖ target ‖    */
/* msgid -> its record) and a by_owner row (owner ‖ by_time key ->    */
/* its size), staged on the row's own batch, and is counted against   */
/* its owner once the batch commits.                                  */
/* ---------------------------------------------------------------- */

/** One row's trim index, from prepare to the post-commit count. */
struct history_trim_row {
  struct htc_rec rec;
  uint64_t       ms;                   /**< htc_parse_ms(rec.ts) */
  size_t         bt_klen;
  char           bo_key[HTC_BO_KEY_MAX];
  size_t         bo_klen;
  int            stage;                /**< 0: the by_time row exists already */
};

/** Prepare @a tr for the row (@a timestamp, @a target, @a msgid).
 * The record's ts and the by_time key's ms both come from @a timestamp,
 * the row's own stored time: the delete rebuilds the messages key from
 * rec.ts and the redact_index key from the by_time key's first 8 bytes.
 *
 * Re-store: when the by_time row for this exact (ms, target, msgid)
 * already exists, the row was indexed and counted before (a peer
 * replaying a message under its original tags, a REDACT catch-up whose
 * idempotence check could not read) -- its index rows and its count stay
 * as they are, so the row is never counted twice and the delete always
 * subtracts exactly what was added.  Keyed on by_time, not the messages
 * row: a messages row written before the index existed is not indexed
 * yet, and is indexed and counted here (the backfill then skips it).
 * @return 0, or -1: the row cannot be indexed, so it must not be stored
 * (a field that does not fit the record, or by_time unreadable). */
static int history_trim_row_prepare(struct history_trim_row *tr,
                                    const char *timestamp,
                                    const char *target, const char *msgid,
                                    const char *owner, unsigned char flags,
                                    const char *reply_parent,
                                    const char *redact_parent)
{
  char bt[HTC_BT_KEY_MAX];
  int btl, rc;

  memset(tr, 0, sizeof *tr);
  if (!owner || !*owner)
    owner = HTC_OWNER_NONE;
  if (!timestamp || !target || !msgid
      || strlen(timestamp) >= sizeof tr->rec.ts
      || strlen(owner) >= sizeof tr->rec.owner
      || strlen(reply_parent) >= sizeof tr->rec.reply_parent
      || strlen(redact_parent) >= sizeof tr->rec.redact_parent)
    return -1;

  tr->ms = htc_parse_ms(timestamp);
  btl = htc_bt_key(bt, sizeof bt, tr->ms, target, msgid);
  if (btl < 0)
    return -1;
  tr->bt_klen = (size_t)btl;
  strcpy(tr->rec.ts, timestamp);
  strcpy(tr->rec.owner, owner);
  strcpy(tr->rec.reply_parent, reply_parent);
  strcpy(tr->rec.redact_parent, redact_parent);
  tr->rec.flags = flags;

  rc = db_exists(history_db_env, history_cf_by_time, bt, (size_t)btl, NULL);
  if (rc == DB_OK)
    tr->stage = 0;
  else if (rc == DB_NOTFOUND)
    tr->stage = 1;
  else
    return -1;
  return 0;
}

/** Stage @a tr's by_time and by_owner rows on @a wb (the row's batch):
 * the size is the messages key + value as stored, the multiline blob as
 * staged (@a ml_vlen) and the two index rows.
 * @return 0, or -1 (do not commit @a wb). */
static int history_trim_row_stage(struct db_writebatch *wb,
                                  struct history_trim_row *tr,
                                  const char *target, const char *msgid,
                                  size_t msg_klen, size_t msg_vlen,
                                  size_t ml_vlen)
{
  if (!tr->stage)
    return 0;
  tr->rec.bytes = htc_row_bytes(msg_klen, msg_vlen, ml_vlen, tr->bt_klen,
                                strlen(tr->rec.owner));
  return htrim_stage_index(wb, tr->ms, target, msgid, &tr->rec,
                           tr->bo_key, sizeof tr->bo_key, &tr->bo_klen);
}

/** Count @a tr against its owner once its batch committed; a store over
 * the cap's high watermark kicks the trim slices. */
static void history_trim_row_stored(const struct history_trim_row *tr)
{
  if (!tr->stage)
    return;
  htrim_note_stored(tr->rec.owner, tr->bo_key, tr->bo_klen, tr->rec.bytes);
  history_trim_cap_kick();
}

/** What the trim record takes from a decoded row, as the store path takes
 * it: the account, the reply parent, a REDACT's parent (its content's
 * first word, as history_store_message reads it), and the multiline flag
 * by ml_content_resolve's rule (a HISTORY_MULTILINE row, or a legacy
 * PRIVMSG whose whole content is the 3-byte sentinel). */
static void history_trim_row_info(const struct HistoryMessage *m,
                                  struct htrim_row_info *out)
{
  memset(out, 0, sizeof *out);
  ircd_strncpy(out->account, m->account, sizeof out->account);
  if (!extract_reply_tag(m->client_tags, out->reply_parent, sizeof out->reply_parent))
    out->reply_parent[0] = '\0';
  if (m->type == HISTORY_REDACT) {
    const char *space = strchr(m->content, ' ');
    size_t len = space ? (size_t)(space - m->content) : strlen(m->content);
    out->flags |= HTC_F_REDACT;
    if (len > 0 && len < sizeof out->redact_parent) {
      memcpy(out->redact_parent, m->content, len);
      out->redact_parent[len] = '\0';
    }
  }
  if (m->type == HISTORY_MULTILINE
      || (m->type == HISTORY_PRIVMSG && m->content[0] == '\x1E'
          && m->content[1] == 'm' && m->content[2] == 'l' && m->content[3] == '\0'))
    out->flags |= HTC_F_ML;
}

/** The trim engine's parse callback (the backfill): decode a messages
 * value with history_deserialize_record -- a legacy row a '|' shifted
 * comes back repaired, its account empty -- and take what
 * history_trim_row_info takes.
 * @return 0, or -1 (the backfill indexes the row as owner "-"). */
static int history_trim_parse(const void *val, size_t vlen,
                              struct htrim_row_info *out)
{
  struct HistoryMessage m;

  memset(&m, 0, sizeof m);
  if (!val || history_deserialize_record(val, vlen, &m) != 0)
    return -1;
  history_trim_row_info(&m, out);
  return 0;
}

const char *history_owner_of(char *buf, size_t size, struct Client *sptr)
{
  int n = -1;

  if (!buf || size == 0)
    return HTC_OWNER_NONE;
  if (sptr && IsUser(sptr) && cli_user(sptr))
    n = htc_owner_key(buf, size, cli_user(sptr)->account, &cli_ip(sptr),
                      cli_user(sptr)->server ? cli_name(cli_user(sptr)->server) : NULL);
  else if (sptr && (IsServer(sptr) || IsMe(sptr)))
    n = htc_owner_key(buf, size, NULL, NULL, cli_name(sptr));
  if (n < 0)
    ircd_strncpy(buf, HTC_OWNER_NONE, size);
  return buf;
}

int history_store_message(const char *msgid, const char *timestamp,
                          const char *target, const char *original_target,
                          const char *sender, const char *account,
                          enum HistoryMessageType type,
                          const char *content, const char *client_tags,
                          const char *owner)
{
  struct db_writebatch *wb = NULL;
  char keybuf[CHANNELLEN + HISTORY_TIMESTAMP_LEN + HISTORY_MSGID_LEN + 8];
  char idxkeybuf[CHANNELLEN + HISTORY_TIMESTAMP_LEN + HISTORY_MSGID_LEN + 8];
  int keylen, idx_keylen, vallen;
  int rc;
  int retry = 0;
  const void *vbuf;
  size_t       vlen;
  /* The parents this row names: a +reply tag, and (REDACT) the redacted
   * msgid -- the reply_index entries, the redact_index row and the trim
   * record all take them from here. */
  char reply_parent[HISTORY_MSGID_LEN];
  char redact_parent[HISTORY_MSGID_LEN];
  const char *redact_reason = "";
  struct history_trim_row trow;
  /* The storage op that failed, logged once the store gives up. */
  const char *failed = NULL;
  int db_rc = DB_OK;

  size_t content_len = content ? strlen(content) : 0;
  size_t tags_len = client_tags ? strlen(client_tags) : 0;
  /* 2x the escapable fields (content, tags, sender, account): worst-case
   * every byte escapes. */
  size_t bufsize = 2 * content_len + 2 * tags_len
      + 2 * (HISTORY_SENDER_LEN + ACCOUNTLEN) + 32;
  if (bufsize < HISTORY_VALUE_BUFSIZE)
    bufsize = HISTORY_VALUE_BUFSIZE;

  char valbuf_stack[HISTORY_VALUE_BUFSIZE];
  char *valbuf = (bufsize > sizeof(valbuf_stack))
      ? (char *)MyMalloc(bufsize) : valbuf_stack;
#ifdef USE_ZSTD
  unsigned char comp_stack[HISTORY_VALUE_BUFSIZE + 64];
  size_t comp_bufsize = bufsize + 64;
  unsigned char *compressed = (comp_bufsize > sizeof(comp_stack))
      ? (unsigned char *)MyMalloc(comp_bufsize) : comp_stack;
  size_t compressed_len;
#endif

  if (!history_available) {
    rc = -1;
    goto store_cleanup;
  }

  keylen = build_key(keybuf, sizeof(keybuf), target, timestamp, msgid);
  if (keylen < 0) {
    rc = -1;
    goto store_cleanup;
  }
  idx_keylen = build_key(idxkeybuf, sizeof(idxkeybuf), target, timestamp, NULL);
  if (idx_keylen < 0) {
    rc = -1;
    goto store_cleanup;
  }

  /* Log the key being stored (with nulls as dots) */
  {
    char key_preview[128];
    int preview_len = keylen < 120 ? keylen : 120;
    memcpy(key_preview, keybuf, preview_len);
    key_preview[preview_len] = '\0';
    for (int i = 0; i < preview_len; i++) {
      if (key_preview[i] == '\0') key_preview[i] = '.';
    }
    log_write(LS_SYSTEM, L_INFO, 0,
              "history_store_message: storing key='%s' (len=%d) target='%s' ts='%s' msgid='%s'",
              key_preview, keylen, target, timestamp, msgid);
  }

  vallen = history_serialize_record(valbuf, bufsize, type, sender, account, content,
                             client_tags, original_target,
                             history_live_incarnation(target));
  if (vallen < 0) {
    rc = -1;
    goto store_cleanup;
  }
  if ((size_t)vallen >= bufsize)
    vallen = bufsize - 1;

#ifdef USE_ZSTD
  if (compress_data((unsigned char *)valbuf, vallen,
                    compressed, comp_bufsize, &compressed_len) >= 0) {
    vbuf = compressed;
    vlen = compressed_len;
  } else {
    vbuf = valbuf;
    vlen = (size_t)vallen;
  }
#else
  vbuf = valbuf;
  vlen = (size_t)vallen;
#endif

  reply_parent[0] = redact_parent[0] = '\0';
  if (!extract_reply_tag(client_tags, reply_parent, sizeof(reply_parent)))
    reply_parent[0] = '\0';
  if (type == HISTORY_REDACT && content && content[0]) {
    const char *space = strchr(content, ' ');
    size_t len = space ? (size_t)(space - content) : strlen(content);
    if (len > 0 && len < sizeof(redact_parent)) {
      memcpy(redact_parent, content, len);
      redact_parent[len] = '\0';
      redact_reason = space ? space + 1 : "";
      if (*redact_reason == ':') redact_reason++;
    }
  }

  /* The prepare -- the re-store check on by_time and the record -- runs
   * again on the retry after an emergency eviction: that slice may have
   * deleted this row's own by_time row (a re-stored old row is among the
   * oldest overall), and a retry that kept the first check's "indexed
   * already" would put the messages row back unindexed and uncounted. */
store_retry:
  if (history_trim_row_prepare(&trow, timestamp, target, msgid, owner,
                               redact_parent[0] ? HTC_F_REDACT : 0,
                               reply_parent, redact_parent) != 0) {
    Debug((DEBUG_DEBUG, "history: no trim index for %s/%s (ts '%s')",
           target, msgid, timestamp));
    history_trim_refused(target, msgid, timestamp);
    rc = -1;
    goto store_cleanup;
  }

  wb = db_writebatch_new(history_db_env);
  if (!wb) {
    rc = -1;
    goto store_cleanup;
  }

  /* Main message store — APPEND-optimised since msgids are
   * monotonic per channel.  libmdbx's MDBX_APPEND skips B-tree
   * walk on max-key inserts; RocksDB's memtable already handles
   * ordered inserts efficiently and treats put_append as a normal put. */
  rc = db_writebatch_put_append(wb, history_cf_messages,
                                keybuf, (size_t)keylen, vbuf, vlen);
  if (rc != DB_OK) {
    Debug((DEBUG_DEBUG, "history: writebatch_put failed: %s", db_strerror(rc)));
    failed = "message put";
    db_rc = rc;
    db_writebatch_destroy(wb);
    wb = NULL;
    if (rc == DB_ERR_FULL && retry == 0) {
      retry = 1;
      if (history_emergency_evict() > 0)
        goto store_retry;
    }
    rc = -1;
    goto store_cleanup;
  }

  /* msgid index: "msgid\0target" -> timestamp (multi-target scheme) */
  {
    char midxkey[HISTORY_MSGID_LEN + 1 + CHANNELLEN + 2];
    int midxlen = build_msgid_index_key(midxkey, sizeof(midxkey),
                                        msgid, target);
    if (midxlen < 0) { rc = -1; goto store_wb_fail; }
    rc = db_writebatch_put(wb, history_cf_msgid,
                           midxkey, (size_t)midxlen,
                           timestamp, strlen(timestamp));
    if (rc != DB_OK) {
      failed = "msgid index put";
      db_rc = rc;
      goto store_wb_fail;
    }
  }

  /* target → last-timestamp (folded key, like the message rows).
   * Message rows bump it: TARGETS is "ordered by the time of the latest
   * message" (spec), and bumping on JOIN/PART/KICK/MODE floated churning
   * channels to the top and listed event-only channels as conversations
   * (audit 2026-09-06 #23/#28).  A REDACT and a TOPIC change bump it too
   * (user decision 2026-10-20): both change what a reader of the
   * conversation sees, and a client that orders its catch-up with
   * TARGETS and skips a target whose stamp it already holds would
   * otherwise keep a deleted message on screen, or miss the topic, in
   * a channel quiet since.  KICK stays out. */
  if (type == HISTORY_PRIVMSG || type == HISTORY_NOTICE
      || type == HISTORY_TAGMSG || type == HISTORY_MULTILINE
      || type == HISTORY_GAP
      || type == HISTORY_REDACT || type == HISTORY_TOPIC) {
    rc = stage_target_stamp(wb, target, timestamp);
    if (rc != DB_OK) {
      failed = "targets stamp";
      db_rc = rc;
      goto store_wb_fail;
    }
  }

  /* Index reply references for draft/chathistory-context lookups.
   * Flat-key encoding (target\0parent\0timestamp\0child) makes this
   * backend-agnostic — no DUPSORT needed. */
  if (reply_parent[0])
    reply_index_put(wb, target, reply_parent, timestamp, msgid);
  if (redact_parent[0]) {
    reply_index_put(wb, target, redact_parent, timestamp, msgid);
    /* Catch-up index (design B): time-ordered so an absent store can
     * ask for redactions since T on return.  Same batch as the row; keyed
     * at the row's own time (trow.ms), which the trim delete reads back
     * off the by_time key. */
    {
      struct rdx_val rv;
      unsigned char rkey[RDX_KEY_MAX];
      char rval[RDX_VAL_MAX];
      int rkl, rvl;
      memset(&rv, 0, sizeof rv);
      ircd_strncpy(rv.target, target, sizeof rv.target);
      ircd_strncpy(rv.parent_msgid, redact_parent, sizeof rv.parent_msgid);
      ircd_strncpy(rv.sender, sender ? sender : "", sizeof rv.sender);
      ircd_strncpy(rv.account, account ? account : "", sizeof rv.account);
      ircd_strncpy(rv.reason, redact_reason, sizeof rv.reason);
      rkl = rdx_key_build(rkey, sizeof rkey, trow.ms, msgid);
      rvl = rdx_val_pack(rval, sizeof rval, &rv);
      if (rkl > 0 && rvl > 0 && history_cf_redact)
        db_writebatch_put(wb, history_cf_redact, rkey, (size_t)rkl, rval, (size_t)rvl);
    }
  }

  /* The trim index: by_time + by_owner, in this batch. */
  if (history_trim_row_stage(wb, &trow, target, msgid,
                             (size_t)keylen, vlen, 0) != 0) {
    failed = "trim index";
    db_rc = DB_ERR_OTHER;
    rc = -1;
    goto store_wb_fail;
  }

  rc = db_writebatch_commit(wb, /*sync_durably=*/0);
  if (rc != DB_OK) {
    Debug((DEBUG_DEBUG, "history: writebatch_commit failed: %s", db_strerror(rc)));
    failed = "commit";
    db_rc = rc;
    db_writebatch_destroy(wb);
    wb = NULL;
    if (rc == DB_ERR_FULL && retry == 0) {
      retry = 1;
      if (history_emergency_evict() > 0)
        goto store_retry;
    }
    rc = -1;
    goto store_cleanup;
  }
  db_writebatch_destroy(wb);
  wb = NULL;
  history_trim_row_stored(&trow);

  rc = 0;
  goto store_cleanup;

store_wb_fail:
  Debug((DEBUG_DEBUG, "history: writebatch op failed: %s", db_strerror(rc)));
  db_writebatch_destroy(wb);
  wb = NULL;
  if (rc == DB_ERR_FULL && retry == 0) {
    retry = 1;
    if (history_emergency_evict() > 0)
      goto store_retry;
  }
  rc = -1;

store_cleanup:
  if (rc != 0 && failed)
    history_store_failed(failed, target, msgid, db_rc);
  if (wb) db_writebatch_destroy(wb);
  if (valbuf != valbuf_stack) MyFree(valbuf);
#ifdef USE_ZSTD
  if (compressed != comp_stack) MyFree(compressed);
#endif
  return rc;
}

int history_store_multiline(const char *msgid, const char *timestamp,
                            const char *target, const char *original_target,
                            const char *sender,
                            const char *account, const char *content,
                            size_t content_len, const char *paste_secret,
                            const char *owner)
{
  struct db_writebatch *wb = NULL;
  char keybuf[CHANNELLEN + HISTORY_TIMESTAMP_LEN + HISTORY_MSGID_LEN + 8];
  char idxkeybuf[CHANNELLEN + HISTORY_TIMESTAMP_LEN + HISTORY_MSGID_LEN + 8];
  int keylen, idx_keylen, vallen;
  int rc;
  int retry = 0;
  const void *vbuf;
  size_t       vlen;
  size_t       ml_staged;
  struct history_trim_row trow;
  /* The storage op that failed, logged once the store gives up. */
  const char *failed = NULL;
  int db_rc = DB_OK;

  char valbuf[HISTORY_VALUE_BUFSIZE];
#ifdef USE_ZSTD
  unsigned char comp_buf[HISTORY_VALUE_BUFSIZE + 64];
  size_t compressed_len;
#endif

  if (!history_available)
    return -1;

  keylen = build_key(keybuf, sizeof(keybuf), target, timestamp, msgid);
  if (keylen < 0) return -1;
  idx_keylen = build_key(idxkeybuf, sizeof(idxkeybuf), target, timestamp, NULL);
  if (idx_keylen < 0) return -1;

  vallen = history_serialize_record(valbuf, sizeof(valbuf), HISTORY_MULTILINE,
                             sender, account, ML_CONTENT_SENTINEL, NULL,
                             original_target, history_live_incarnation(target));
  if (vallen < 0) return -1;
  if ((size_t)vallen >= sizeof(valbuf)) vallen = sizeof(valbuf) - 1;

#ifdef USE_ZSTD
  if (compress_data((unsigned char *)valbuf, vallen,
                    comp_buf, sizeof(comp_buf), &compressed_len) >= 0) {
    vbuf = comp_buf;
    vlen = compressed_len;
  } else {
    vbuf = valbuf;
    vlen = (size_t)vallen;
  }
#else
  vbuf = valbuf;
  vlen = (size_t)vallen;
#endif

  /* A multiline row names no parent (no client tags are stored).  The
   * prepare runs again on the retry after an emergency eviction, as in
   * history_store_message. */
store_ml_retry:
  if (history_trim_row_prepare(&trow, timestamp, target, msgid, owner,
                               HTC_F_ML, "", "") != 0) {
    Debug((DEBUG_DEBUG, "history: no trim index for multiline %s/%s (ts '%s')",
           target, msgid, timestamp));
    history_trim_refused(target, msgid, timestamp);
    if (failed)
      history_store_failed(failed, target, msgid, db_rc);
    return -1;
  }

  wb = db_writebatch_new(history_db_env);
  if (!wb) {
    if (failed)
      history_store_failed(failed, target, msgid, db_rc);
    return -1;
  }

  /* Stage the multiline content put on the same writebatch so it
   * lands atomically with the history.messages / msgid_index / targets
   * puts below. */
  if (ml_content_store(wb, msgid, sender, target,
                       content, content_len, paste_secret, &ml_staged) != 0) {
    db_writebatch_destroy(wb);
    wb = NULL;
    if (failed)                                 /* a retry: the first failure */
      history_store_failed(failed, target, msgid, db_rc);
    return -1;
  }

  rc = db_writebatch_put_append(wb, history_cf_messages,
                                keybuf, (size_t)keylen, vbuf, vlen);
  if (rc != DB_OK) {
    failed = "message put";
    db_rc = rc;
    goto store_ml_fail;
  }

  {
    char midxkey[HISTORY_MSGID_LEN + 1 + CHANNELLEN + 2];
    int midxlen = build_msgid_index_key(midxkey, sizeof(midxkey),
                                        msgid, target);
    if (midxlen < 0) { rc = -1; goto store_ml_fail; }
    rc = db_writebatch_put(wb, history_cf_msgid,
                           midxkey, (size_t)midxlen,
                           timestamp, strlen(timestamp));
    if (rc != DB_OK) {
      failed = "msgid index put";
      db_rc = rc;
      goto store_ml_fail;
    }
  }

  /* Same max() rule as single messages: a batch relayed late from
   * another server must not move the target's latest time back. */
  rc = stage_target_stamp(wb, target, timestamp);
  if (rc != DB_OK) {
    failed = "targets stamp";
    db_rc = rc;
    goto store_ml_fail;
  }

  /* The trim index: by_time + by_owner, in this batch; the row's size
   * counts the content blob as ml_content_store staged it. */
  if (history_trim_row_stage(wb, &trow, target, msgid,
                             (size_t)keylen, vlen, ml_staged) != 0) {
    failed = "trim index";
    db_rc = DB_ERR_OTHER;
    rc = -1;
    goto store_ml_fail;
  }

  rc = db_writebatch_commit(wb, /*sync_durably=*/0);
  db_writebatch_destroy(wb);
  wb = NULL;
  if (rc != DB_OK) {
    failed = "commit";
    db_rc = rc;
    if (rc == DB_ERR_FULL && retry == 0) {
      retry = 1;
      if (history_emergency_evict() > 0)
        goto store_ml_retry;
    }
    history_store_failed(failed, target, msgid, db_rc);
    return -1;
  }
  history_trim_row_stored(&trow);
  return 0;

store_ml_fail:
  db_writebatch_destroy(wb);
  wb = NULL;
  if (rc == DB_ERR_FULL && retry == 0) {
    retry = 1;
    if (history_emergency_evict() > 0)
      goto store_ml_retry;
  }
  if (failed)
    history_store_failed(failed, target, msgid, db_rc);
  return -1;
}

int history_has_msgid(const char *msgid)
{
  int rc;

  if (!history_available)
    return -1;

  if (!msgid || !msgid[0])
    return 0;

  {
    char ts[HISTORY_TIMESTAMP_LEN];
    rc = msgid_index_resolve(msgid, NULL, NULL, ts, NULL, 0);
  }
  if (rc == 0)  return 1;
  if (rc == 1)  return 0;
  return -1;
}

/** Internal query implementation with direction support.
 * @param[in] target Channel or nick to query.
 * @param[in] start_key Starting key for cursor.
 * @param[in] start_keylen Length of starting key.
 * @param[in] direction Query direction.
 * @param[in] limit Maximum messages to return.
 * @param[out] result Pointer to result list head.
 * @return Number of messages returned, or -1 on error.
 */
/** Apply a query-time row filter to a freshly built row.
 *
 * Returns 1 when the row is kept.  Otherwise the row is freed and the
 * iterator advanced for the caller: 0 = keep walking (the iterator was
 * either stepped or SOUGHT to the boundary the hook named), -1 = stop
 * the walk (hook said nothing further is visible, or scan_max hit --
 * the latter sets filter->truncated).  @a rc receives the iterator
 * status after the advance.
 *
 * A boundary seek is only honoured when it moves in the walk direction
 * (forward: strictly later than the row; reverse: strictly earlier), so
 * a confused hook can never pin the walk in place. */
static int history_filter_row(struct HistoryRowFilter *filter,
                              struct HistoryMessage *msg, int reverse,
                              const char *target, struct db_iter *it,
                              int *rc)
{
  int64_t skip_to = 0;
  int64_t row_t;
  int verdict;
  int scan_max;

  if (!filter || (!filter->fn && !filter->type_mask && !filter->veto))
    return 1;

  filter->scanned++;
  if (filter->type_mask && !(filter->type_mask & (1u << msg->type)))
    verdict = 0;   /* type the requester cannot receive: skip, uncounted */
  else if (filter->veto && filter->veto(msg, filter->veto_ctx))
    verdict = 0;   /* content the requester never sees: skip, uncounted */
  else if (filter->fn)
    verdict = filter->fn(msg, reverse, filter->ctx, &skip_to);
  else
    verdict = 1;
  if (verdict == 1)
    return 1;

  row_t = (int64_t)history_parse_ms(msg->timestamp);
  msg->next = NULL;
  history_free_messages(msg);

  if (verdict < 0)
    return -1;

  scan_max = filter->scan_max > 0 ? filter->scan_max : HISTORY_FILTER_SCAN_MAX;
  if (filter->scanned >= scan_max) {
    filter->truncated = 1;
    return -1;
  }

  if (skip_to > 0 && (reverse ? skip_to < row_t : skip_to > row_t)) {
    char seekbuf[CHANNELLEN + HISTORY_TIMESTAMP_LEN + 8];
    char tsbuf[HISTORY_TIMESTAMP_LEN];
    int seeklen;

    /* Keys carry millisecond stamps ("%lu.%03u") and so do boundaries.
     * Forward: land on the first row at or after the boundary
     * millisecond.  Reverse: position at the first row past it, then
     * step back onto the last row within it. */
    history_format_ms(tsbuf, sizeof(tsbuf),
                      (uint64_t)(reverse ? skip_to + 1 : skip_to));
    seeklen = build_key(seekbuf, sizeof(seekbuf), target, tsbuf, NULL);
    if (seeklen > 0) {
      *rc = db_iter_seek(it, seekbuf, seeklen);
      if (reverse) {
        if (*rc == DB_NOTFOUND)
          *rc = db_iter_seek_last(it);
        else if (*rc == DB_OK)
          *rc = db_iter_prev(it);
      }
      return 0;
    }
  }

  *rc = reverse ? db_iter_prev(it) : db_iter_next(it);
  return 0;
}

static int history_query_internal(const char *target,
                                  const char *start_key, int start_keylen,
                                  enum HistoryDirection direction,
                                  int limit, struct HistoryMessage **result,
                                  const char *floor_key, int floor_keylen,
                                  struct HistoryRowFilter *filter)
{
  struct db_snapshot *snap = NULL;
  struct db_iter *it = NULL;
  struct HistoryMessage *head = NULL, *tail = NULL, *msg;
  char target_prefix[CHANNELLEN + 2];
  int target_prefix_len;
  int count = 0;
  time_t live_inc = history_live_incarnation(target);
  int rc;
  int reverse;

  *result = NULL;

  if (!history_available)
    return -1;

  /* Build target prefix for boundary checking */
  target_prefix_len = build_key(target_prefix, sizeof(target_prefix),
                                target, NULL, NULL);
  if (target_prefix_len < 0)
    return -1;

  /* Open a read snapshot.  history_query_internal returns a coherent
   * point-in-time view, so we pin a snapshot for the iter and (under
   * libmdbx) reuse its read txn for ml_content_resolve so multiline
   * content sees the same state as the message rows. */
  snap = db_snapshot_new(history_db_env);
  if (!snap)
    return -1;

  /* Bounded to the target's own keys (history_prefix_iter): LATEST and
   * BEFORE-from-now seek past the target's last row, and an unbounded
   * seek landed on the next target, walking every tombstone of that
   * target's aged-out head -- then the step back walked them again.  The
   * range checks below still hold; a seek past the range is DB_NOTFOUND
   * and falls back to the range's last key, as the CF's end did. */
  it = history_prefix_iter(history_cf_messages, snap, target_prefix,
                           (size_t)target_prefix_len);
  if (!it) {
    db_snapshot_destroy(snap);
    return -1;
  }

  reverse = (direction == HISTORY_DIR_BEFORE || direction == HISTORY_DIR_LATEST);

  /* Position iterator */
  if (reverse) {
    /* For BEFORE/LATEST, we want to go backwards from the reference. */
    rc = db_iter_seek(it, start_key, start_keylen);
    log_write(LS_SYSTEM, L_INFO, 0, "history_query_internal: seek rc=%d (%s)",
              rc, rc == DB_OK ? "found" : (rc == DB_NOTFOUND ? "not found" : "error"));
    if (rc == DB_NOTFOUND) {
      /* Past end of CF — fall back to the last key. */
      rc = db_iter_seek_last(it);
      log_write(LS_SYSTEM, L_INFO, 0, "history_query_internal: seek_last rc=%d", rc);
    } else if (rc == DB_OK) {
      /* Move back one since seek lands on >= start_key */
      rc = db_iter_prev(it);
      log_write(LS_SYSTEM, L_INFO, 0, "history_query_internal: prev rc=%d", rc);
    }
  } else {
    /* For AFTER, go forwards from strictly after the reference. */
    rc = db_iter_seek(it, start_key, start_keylen);
    log_write(LS_SYSTEM, L_INFO, 0, "history_query_internal: AFTER seek rc=%d", rc);
    /* Skip any messages that match the reference key prefix
     * (AFTER means strictly after, not including the reference). */
    while (rc == DB_OK && db_iter_valid(it)) {
      size_t klen;
      const void *kbase = db_iter_key(it, &klen);
      if (klen < (size_t)start_keylen ||
          memcmp(kbase, start_key, start_keylen) != 0)
        break;
      rc = db_iter_next(it);
    }
  }

  /* Log iterator position */
  if (rc == DB_OK && db_iter_valid(it)) {
    size_t klen;
    const void *kbase = db_iter_key(it, &klen);
    char key_preview[64];
    size_t preview_len = klen < 60 ? klen : 60;
    memcpy(key_preview, kbase, preview_len);
    key_preview[preview_len] = '\0';
    for (size_t i = 0; i < preview_len; i++) {
      if (key_preview[i] == '\0') key_preview[i] = '.';
    }
    log_write(LS_SYSTEM, L_INFO, 0, "history_query_internal: positioned at key='%s' (len=%zu)",
              key_preview, klen);
  } else {
    log_write(LS_SYSTEM, L_INFO, 0, "history_query_internal: no position, rc=%d", rc);
  }

  /* Iterate and collect messages */
  while (rc == DB_OK && db_iter_valid(it) && count < limit) {
    size_t klen, vlen;
    const void *kbase = db_iter_key(it, &klen);
    const void *vbase = db_iter_value(it, &vlen);

    /* Check if still in target's range */
    if (klen < (size_t)target_prefix_len ||
        memcmp(kbase, target_prefix, target_prefix_len) != 0) {
      char key_preview[64];
      size_t preview_len = klen < 60 ? klen : 60;
      memcpy(key_preview, kbase, preview_len);
      key_preview[preview_len] = '\0';
      for (size_t i = 0; i < preview_len; i++) {
        if (key_preview[i] == '\0') key_preview[i] = '.';
      }
      log_write(LS_SYSTEM, L_INFO, 0, "history_query_internal: key='%s' outside target range, breaking",
                key_preview);
      /* Keys are sorted, so once outside target prefix we are done. */
      break;
    }

    /* Floor check for backward iteration: stop if we've walked past
     * the floor timestamp (used by auto-replay to get the most recent
     * N messages but no older than the since-timestamp). */
    if (reverse && floor_key && floor_keylen > 0) {
      /* Compare on the shorter length so a key can never dodge the
       * floor by being short: floors are full row keys since the
       * msgid-as-key change, and a row whose msgid is shorter than
       * the floor's used to fail the length test and walk on past the
       * floor (re-review 2026-09-07 R4; the ascending BETWEEN bound
       * below already does this). */
      size_t n = klen < (size_t)floor_keylen ? klen : (size_t)floor_keylen;
      if (memcmp(kbase, floor_key, n) <= 0)
        break;
    }

    /* Allocate message */
    msg = (struct HistoryMessage *)MyMalloc(sizeof(struct HistoryMessage));
    if (!msg)
      break;
    memset(msg, 0, sizeof(*msg));

    /* Parse key to get target, timestamp, msgid */
    if (parse_key((void *)kbase, klen,
                  msg->target, msg->timestamp, msg->msgid) != 0) {
      MyFree(msg);
      rc = reverse ? db_iter_prev(it) : db_iter_next(it);
      continue;
    }

#ifdef USE_ZSTD
    /* Preserve raw compressed data for federation passthrough */
    if (is_compressed((const unsigned char *)vbase, vlen)) {
      msg->raw_content = (unsigned char *)MyMalloc(vlen);
      if (msg->raw_content) {
        memcpy(msg->raw_content, vbase, vlen);
        msg->raw_content_len = vlen;
      }
    }
#endif

    /* Parse value */
    if (history_deserialize_record((void *)vbase, vlen, msg) != 0) {
      if (msg->raw_content)
        MyFree(msg->raw_content);
      MyFree(msg);
      rc = reverse ? db_iter_prev(it) : db_iter_next(it);
      continue;
    }

    /* A row from a wiped channel incarnation is not this channel's
     * history: skip it without counting. */
    if (!row_incarnation_ok(msg, live_inc)) {
      history_free_messages(msg);
      rc = reverse ? db_iter_prev(it) : db_iter_next(it);
      continue;
    }

    /* Resolve multiline content from ml_content store if needed.
     * Reads through the same snapshot as this iterator for a coherent
     * point-in-time view. */
    ml_content_resolve(snap, msg);

    /* Query-time filter (presence-aware paging): skipped rows do not
     * count toward the limit; the helper advances/seeks the iterator. */
    {
      int keep = history_filter_row(filter, msg, reverse, target, it, &rc);
      if (keep < 0)
        break;
      if (keep == 0)
        continue;
    }

    /* Add to list */
    msg->next = NULL;
    if (reverse) {
      /* Prepend (we're going backwards) */
      msg->next = head;
      head = msg;
      if (!tail)
        tail = msg;
    } else {
      /* Append */
      if (tail)
        tail->next = msg;
      else
        head = msg;
      tail = msg;
    }
    count++;

    rc = reverse ? db_iter_prev(it) : db_iter_next(it);
  }

  db_iter_close(it);
  db_snapshot_destroy(snap);

  log_write(LS_SYSTEM, L_INFO, 0, "history_query_internal: returning count=%d for target='%s'",
            count, target);

  *result = head;
  return count;
}

int history_query_before(const char *target, enum HistoryRefType ref_type,
                         const char *reference, int limit,
                         struct HistoryMessage **result,
                         struct HistoryRowFilter *filter)
{
  char keybuf[CHANNELLEN + HISTORY_TIMESTAMP_LEN + HISTORY_MSGID_LEN + 8];
  char timestamp[HISTORY_TIMESTAMP_LEN];
  const char *msgid = NULL;
  int keylen;

  *result = NULL;

  /* Convert reference to Unix timestamp format.  A msgid reference
   * keeps the msgid: the cursor is the ROW, not its millisecond, so
   * same-millisecond siblings on the far side of it stay reachable
   * (audit 2026-09-06). */
  if (ref_type == HISTORY_REF_MSGID) {
    msgid = reference;
    if (history_msgid_to_timestamp(reference, timestamp) != 0)
      return 0; /* msgid not found, return empty */
    reference = timestamp;
  } else if (ref_type == HISTORY_REF_TIMESTAMP) {
    /* Client sends ISO 8601, convert to Unix for lookup */
    if (history_iso_to_unix(reference, timestamp, sizeof(timestamp)) == 0)
      reference = timestamp;
    /* If conversion fails, assume it's already Unix format */
  }

  /* Build starting key */
  keylen = build_key(keybuf, sizeof(keybuf), target, reference, msgid);
  if (keylen < 0)
    return -1;

  log_write(LS_SYSTEM, L_INFO, 0, "history_query_before: target='%s' timestamp='%s' keylen=%d",
            target, reference, keylen);

  return history_query_internal(target, keybuf, keylen,
                                HISTORY_DIR_BEFORE, limit, result,
                                NULL, 0, filter);
}

int history_query_after(const char *target, enum HistoryRefType ref_type,
                        const char *reference, int limit,
                        struct HistoryMessage **result,
                        struct HistoryRowFilter *filter)
{
  char keybuf[CHANNELLEN + HISTORY_TIMESTAMP_LEN + HISTORY_MSGID_LEN + 8];
  char timestamp[HISTORY_TIMESTAMP_LEN];
  const char *msgid = NULL;
  int keylen;

  *result = NULL;

  /* Convert reference to Unix timestamp format.  A msgid reference
   * keeps the msgid: the cursor is the ROW, not its millisecond, so
   * same-millisecond siblings on the far side of it stay reachable
   * (audit 2026-09-06). */
  if (ref_type == HISTORY_REF_MSGID) {
    msgid = reference;
    if (history_msgid_to_timestamp(reference, timestamp) != 0)
      return 0;
    reference = timestamp;
  } else if (ref_type == HISTORY_REF_TIMESTAMP) {
    /* Client sends ISO 8601, convert to Unix for lookup */
    if (history_iso_to_unix(reference, timestamp, sizeof(timestamp)) == 0)
      reference = timestamp;
    /* If conversion fails, assume it's already Unix format */
  }

  keylen = build_key(keybuf, sizeof(keybuf), target, reference, msgid);
  if (keylen < 0)
    return -1;

  return history_query_internal(target, keybuf, keylen,
                                HISTORY_DIR_AFTER, limit, result,
                                NULL, 0, filter);
}

int history_query_latest(const char *target, enum HistoryRefType ref_type,
                         const char *reference, int limit,
                         struct HistoryMessage **result,
                         struct HistoryRowFilter *filter)
{
  char keybuf[CHANNELLEN + HISTORY_TIMESTAMP_LEN + 8];
  char floorbuf[CHANNELLEN + HISTORY_TIMESTAMP_LEN + HISTORY_MSGID_LEN + 8];
  char timestamp[HISTORY_TIMESTAMP_LEN];
  const char *msgid = NULL;
  int keylen, floorlen;

  *result = NULL;

  if (ref_type == HISTORY_REF_NONE) {
    /* LATEST * - start from end of target's range */
    keylen = build_key(keybuf, sizeof(keybuf), target, "32503680000.000", NULL);
    if (keylen < 0)
      return -1;
    return history_query_internal(target, keybuf, keylen,
                                  HISTORY_DIR_LATEST, limit, result,
                                  NULL, 0, filter);
  }

  /* Convert reference to Unix timestamp format */
  if (ref_type == HISTORY_REF_MSGID) {
    msgid = reference;   /* floor is the ROW: same-ms rows after it stay */
    if (history_msgid_to_timestamp(reference, timestamp) != 0)
      return 0;
    reference = timestamp;
  } else if (ref_type == HISTORY_REF_TIMESTAMP) {
    /* Client sends ISO 8601, convert to Unix for lookup */
    if (history_iso_to_unix(reference, timestamp, sizeof(timestamp)) == 0)
      reference = timestamp;
    /* If conversion fails, assume it's already Unix format */
  }

  /* LATEST with anchor: walk backwards from the end, stop at anchor.
   * Per IRCv3 spec, LATEST <target> <msgid> <limit> returns the most
   * recent messages AFTER the anchor, up to limit. */
  keylen = build_key(keybuf, sizeof(keybuf), target, "32503680000.000", NULL);
  floorlen = build_key(floorbuf, sizeof(floorbuf), target, reference, msgid);
  if (keylen < 0 || floorlen < 0)
    return -1;

  return history_query_internal(target, keybuf, keylen,
                                HISTORY_DIR_LATEST, limit, result,
                                floorbuf, floorlen, filter);
}

int history_query_latest_after(const char *target, int limit,
                               const char *after_timestamp,
                               const char *after_msgid,
                               struct HistoryMessage **result,
                               struct HistoryRowFilter *filter)
{
  char keybuf[CHANNELLEN + HISTORY_TIMESTAMP_LEN + 8];
  char floorbuf[CHANNELLEN + HISTORY_TIMESTAMP_LEN + HISTORY_MSGID_LEN + 8];
  char timestamp[HISTORY_TIMESTAMP_LEN];
  const char *floor_ts;
  int keylen, floorlen;

  *result = NULL;

  /* Convert after_timestamp if ISO 8601 */
  if (history_iso_to_unix(after_timestamp, timestamp, sizeof(timestamp)) == 0)
    floor_ts = timestamp;
  else
    floor_ts = after_timestamp;

  /* Start key: far future (scan backward from end of target's range) */
  keylen = build_key(keybuf, sizeof(keybuf), target, "32503680000.000", NULL);
  if (keylen < 0)
    return -1;

  /* Floor key: stop backward walk at (or before) the since-timestamp.
   * With a msgid the floor is that exact row, so same-millisecond rows
   * minted after it are still replayed (re-review 2026-09-07 R3: the
   * bouncer ATTACH cursor used to lose them). */
  floorlen = build_key(floorbuf, sizeof(floorbuf), target, floor_ts,
                       (after_msgid && after_msgid[0]) ? after_msgid : NULL);
  if (floorlen < 0)
    return -1;

  return history_query_internal(target, keybuf, keylen,
                                HISTORY_DIR_LATEST, limit, result,
                                floorbuf, floorlen, filter);
}

int history_find_last_join(const char *channel, const char *nick,
                           char *out_msgid, size_t msgid_len,
                           char *out_timestamp, size_t timestamp_len)
{
  struct db_iter *it;
  char keybuf[CHANNELLEN + HISTORY_TIMESTAMP_LEN + 8];
  char target_prefix[CHANNELLEN + 2];
  int target_prefix_len, keylen, rc;
  int found = 0;
  size_t nick_len;

  if (!history_available || !channel || !nick)
    return 0;

  nick_len = strlen(nick);

  /* Build target prefix for boundary checking */
  target_prefix_len = build_key(target_prefix, sizeof(target_prefix),
                                channel, NULL, NULL);
  if (target_prefix_len < 0)
    return 0;

  /* Start from end of channel's key range */
  keylen = build_key(keybuf, sizeof(keybuf), channel, "32503680000.000", NULL);
  if (keylen < 0)
    return 0;

  /* The channel's own keys only (history_prefix_iter): the far-future
   * seek finds nothing in range and falls back to its last key, instead
   * of walking the next channel's aged-out head and back. */
  it = history_prefix_iter(history_cf_messages, NULL, target_prefix,
                           (size_t)target_prefix_len);
  if (!it)
    return 0;

  /* Position at or after the far-future key, then step back. */
  rc = db_iter_seek(it, keybuf, keylen);
  if (rc == DB_NOTFOUND)
    rc = db_iter_seek_last(it);
  else if (rc == DB_OK)
    rc = db_iter_prev(it);

  /* Walk backward through channel history looking for this user's last JOIN.
   * JOIN events are channel metadata, so they're relatively frequent —
   * typically found within a few hundred entries at most. Cap the scan
   * to avoid pathological cases. */
  {
    int scanned = 0;
    int max_scan = 2000;

    while (rc == DB_OK && db_iter_valid(it) && scanned < max_scan) {
      size_t klen, vlen;
      const void *kbase = db_iter_key(it, &klen);
      const void *vbase = db_iter_value(it, &vlen);
      const char *val;
      const char *pipe1;
      int type;

      /* Check if still in channel's range */
      if (klen < (size_t)target_prefix_len ||
          memcmp(kbase, target_prefix, target_prefix_len) != 0)
        break;

      scanned++;
      val = (const char *)vbase;

      /* Quick reject: compressed data won't start with a digit.
       * JOIN events are short and shouldn't be compressed, but skip
       * compressed entries rather than decompressing them all. */
      if (is_compressed((const unsigned char *)val, vlen)) {
        rc = db_iter_prev(it);
        continue;
      }

      /* Value format: type|sender|account|content, sender escaped
       * (history_record.c).  HISTORY_JOIN = 2, so we need "2|nick!..." */
      pipe1 = memchr(val, '|', vlen);
      if (!pipe1) {
        rc = db_iter_prev(it);
        continue;
      }

      type = atoi(val);
      if (type != HISTORY_JOIN) {
        rc = db_iter_prev(it);
        continue;
      }

      /* Check sender: starts with "nick!" */
      {
        /* Decode the header as deserialize_message does (unescaped, and
         * a legacy row a '|' nick shifted is re-split) before comparing.
         * Escaping the nick instead would not do: ircd_strncmp folds '|'
         * with backslash, and a client now named foo\x must still find
         * its JOIN stored as foo|x. */
        char sender[HISTORY_SENDER_LEN];
        char account[ACCOUNTLEN + 1];
        size_t sender_len;

        if (history_split_header(pipe1 + 1, vlen - (pipe1 + 1 - val),
                                 sender, sizeof(sender),
                                 account, sizeof(account), NULL) < 0) {
          rc = db_iter_prev(it);
          continue;
        }
        sender_len = strlen(sender);
        if (sender_len > nick_len && sender[nick_len] == '!' &&
            ircd_strncmp(sender, nick, nick_len) == 0) {
          /* Found it — extract msgid and timestamp from the key */
          char tmp_target[CHANNELLEN + 1];
          char tmp_ts[HISTORY_TIMESTAMP_LEN];
          char tmp_msgid[HISTORY_MSGID_LEN];
          if (parse_key((void *)kbase, klen,
                        tmp_target, tmp_ts, tmp_msgid) == 0) {
            if (out_msgid && msgid_len > 0) {
              ircd_strncpy(out_msgid, tmp_msgid, msgid_len);
            }
            if (out_timestamp && timestamp_len > 0) {
              ircd_strncpy(out_timestamp, tmp_ts, timestamp_len);
            }
            found = 1;
          }
          break;
        }
      }

      rc = db_iter_prev(it);
    }
  }

  db_iter_close(it);
  return found;
}

int history_query_around(const char *target, enum HistoryRefType ref_type,
                         const char *reference, int limit,
                         struct HistoryMessage **result,
                         struct HistoryRowFilter *filter)
{
  struct HistoryMessage *before = NULL, *after = NULL, *ref_msg = NULL;
  int half = limit / 2;
  int count_before, count_after, count_ref = 0;

  *result = NULL;

  /* For msgid references, also look up the reference message itself.
   * BEFORE and AFTER both exclude the reference, but AROUND should include it.
   */
  if (ref_type == HISTORY_REF_MSGID) {
    int rc = history_lookup_message(target, reference, &ref_msg);
    if (rc == 0 && ref_msg) {
      /* The reference row is subject to the same visibility rules as
       * the rows around it: type mask, veto, then the presence hook. */
      if (filter) {
        int64_t skip_to = 0;
        int keep = 1;
        filter->scanned++;
        if (filter->type_mask && !(filter->type_mask & (1u << ref_msg->type)))
          keep = 0;
        else if (filter->veto && filter->veto(ref_msg, filter->veto_ctx))
          keep = 0;
        else if (filter->fn && filter->fn(ref_msg, 0, filter->ctx, &skip_to) != 1)
          keep = 0;
        if (!keep) {
          history_free_messages(ref_msg);
          ref_msg = NULL;
        }
      }
      if (ref_msg) {
        count_ref = 1;
        log_write(LS_SYSTEM, L_INFO, 0, "history_query_around: found reference msg at ts=%s",
                  ref_msg->timestamp);
      }
    }
  }

  /* Get messages before reference */
  count_before = history_query_before(target, ref_type, reference, half, &before,
                                      filter);
  if (count_before < 0) {
    history_free_messages(before);
    history_free_messages(ref_msg);
    return -1;
  }

  /* Get messages after reference (reduce limit by ref_msg if found).
   * AFTER excludes the reference millisecond; for a TIMESTAMP reference
   * the rows AT that millisecond belong to this page (the client asked
   * for the neighbourhood of that instant), so anchor the after-walk one
   * millisecond earlier (keys are millisecond-granular). */
  if (ref_type == HISTORY_REF_TIMESTAMP) {
    char unix_ts[HISTORY_TIMESTAMP_LEN], prev_ts[HISTORY_TIMESTAMP_LEN];
    uint64_t ms;
    if (history_iso_to_unix(reference, unix_ts, sizeof(unix_ts)) != 0)
      ircd_strncpy(unix_ts, reference, sizeof(unix_ts));
    ms = history_parse_ms(unix_ts);
    history_format_ms(prev_ts, sizeof(prev_ts), ms > 0 ? ms - 1 : 0);
    count_after = history_query_after(target, HISTORY_REF_TIMESTAMP, prev_ts,
                                      limit - count_before - count_ref, &after,
                                      filter);
  } else
  count_after = history_query_after(target, ref_type, reference,
                                    limit - count_before - count_ref, &after,
                                    filter);
  if (count_after < 0) {
    history_free_messages(before);
    history_free_messages(ref_msg);
    history_free_messages(after);
    return -1;
  }

  /* Concatenate lists: before + ref_msg + after */
  if (before) {
    struct HistoryMessage *tail = before;
    while (tail->next)
      tail = tail->next;
    if (ref_msg) {
      tail->next = ref_msg;
      ref_msg->next = after;
    } else {
      tail->next = after;
    }
    *result = before;
  } else if (ref_msg) {
    ref_msg->next = after;
    *result = ref_msg;
  } else {
    *result = after;
  }

  return count_before + count_ref + count_after;
}

/** Stage THE delete (htrim_delete_row) of the stored messages row @a key
 * (@a klen bytes) -- (@a target, @a ts, @a msgid) parsed off it, @a m its
 * decoded value -- on @a s, under @a path:
 *   - a row the trim index holds (its by_time record parses) goes with
 *     that record, counted: it was counted when it was indexed;
 *   - any other row (stored by an older binary, the backfill not there
 *     yet) with a record built from the row as the backfill builds one
 *     (owner from its account, else "-"), uncounted: it was never counted.
 * The record's ts is the key's own, so the delete rebuilds exactly @a key.
 * @return 0 staged; 1 skipped -- a key the delete would not rebuild byte
 *         for byte, or a field the record cannot hold (the row stays);
 *         -1 a read failed or @a s is poisoned (abort @a s). */
static int history_trim_delete_stored(struct htrim_slice *s, enum htrim_path path,
                                      const void *key, size_t klen,
                                      const char *target, const char *ts,
                                      const char *msgid,
                                      const struct HistoryMessage *m)
{
  char bt[HTC_BT_KEY_MAX], mk[HTC_MSG_KEY_MAX];
  struct db_val v = { NULL, 0 };
  struct htrim_row_info info;
  struct htc_rec rec;
  int btl, mkl, rc, counted = 0;

  if (strlen(ts) >= sizeof rec.ts)
    return 1;
  mkl = htc_msg_key(mk, sizeof mk, target, ts, msgid);
  if (mkl < 0 || (size_t)mkl != klen || memcmp(mk, key, klen) != 0)
    return 1;
  btl = htc_bt_key(bt, sizeof bt, htc_parse_ms(ts), target, msgid);
  if (btl < 0)
    return 1;

  rc = db_get(history_db_env, history_cf_by_time, bt, (size_t)btl, NULL, &v);
  if (rc == DB_OK && htc_rec_parse(v.base, v.len, &rec) == 0)
    counted = 1;
  db_val_free(&v);
  if (rc != DB_OK && rc != DB_NOTFOUND)
    return -1;
  /* A by_time row whose record does not parse is still deleted (its key
   * is this row's); its by_owner row, under an owner the record no longer
   * names, is left to the cap's orphan-entry step. */
  if (!counted) {
    history_trim_row_info(m, &info);
    memset(&rec, 0, sizeof rec);
    rec.flags = info.flags;
    if (htc_owner_key(rec.owner, sizeof rec.owner, info.account, NULL, NULL) < 0)
      ircd_strncpy(rec.owner, HTC_OWNER_NONE, sizeof rec.owner);
    ircd_strncpy(rec.reply_parent, info.reply_parent, sizeof rec.reply_parent);
    ircd_strncpy(rec.redact_parent, info.redact_parent, sizeof rec.redact_parent);
  }
  ircd_strncpy(rec.ts, ts, sizeof rec.ts);
  return htrim_delete_row(s, path, bt, (size_t)btl, &rec, counted) == 0 ? 0 : -1;
}

/** Prune a channel incarnation that lost a burst: every row of
 * @a channel stamped with @a incarnation (the losing creationtime).
 * Called from the burst wipeout on the losing side, which is the only
 * side that ever stored them (stores do not sync; federation is
 * on-demand), so every store holding them prunes.  Rows stamped 0
 * (pre-2026-09-08) are left alone.  The read-time incarnation filter
 * remains as belt and braces.  See docs/features/chathistory.md.
 *
 * Every row goes through the trim engine's one delete
 * (history_trim_delete_stored), all of them in one unbudgeted slice: one
 * batch, the owner totals moved only once it commits, and the channel's
 * targets key dropped (CH A -) if that left it empty.  A row's replies
 * and reactions are not deleted with it (no cascade): those stored in the
 * same incarnation are pruned by this same walk, any other stays.
 * @return rows deleted, or -1. */
int history_purge_incarnation(const char *channel, time_t incarnation)
{
  struct db_iter *it;
  struct htrim_slice *s;
  char startbuf[CHANNELLEN + HISTORY_TIMESTAMP_LEN + 8];
  char prefix[CHANNELLEN + 2];
  char ts[HISTORY_TIMESTAMP_LEN];
  char msg_target[CHANNELLEN + 1], msg_timestamp[HISTORY_TIMESTAMP_LEN], msg_msgid[HISTORY_MSGID_LEN];
  int startlen, prefixlen, deleted, skipped = 0, rc;

  if (!history_available || !channel || !IsChannelName(channel) || incarnation <= 0)
    return 0;

  ircd_snprintf(0, ts, sizeof(ts), "%lu.000", (unsigned long)incarnation);
  startlen = build_key(startbuf, sizeof(startbuf), channel, ts, NULL);
  prefixlen = build_key(prefix, sizeof(prefix), channel, NULL, NULL);
  if (startlen < 0 || prefixlen < 0)
    return -1;

  s = htrim_slice_begin(0);
  if (!s)
    return -1;
  htrim_slice_set_phase(s, HTRIM_PH_INCARNATION);
  it = history_prefix_iter(history_cf_messages, NULL, prefix, (size_t)prefixlen);
  if (!it) {
    htrim_slice_abort(s);
    return -1;
  }

  /* Rows of this incarnation cannot predate its creation: start there
   * and stop at the end of the channel's range. */
  for (rc = db_iter_seek(it, startbuf, startlen);
       rc == DB_OK && db_iter_valid(it);
       rc = db_iter_next(it)) {
    size_t klen, vlen;
    const void *kbase = db_iter_key(it, &klen);
    const void *vbase;
    struct HistoryMessage pm;
    int drc;

    if (klen < (size_t)prefixlen || memcmp(kbase, prefix, prefixlen) != 0)
      break;   /* past this channel */
    if (parse_key((void *)kbase, klen, msg_target, msg_timestamp, msg_msgid) != 0)
      continue;
    vbase = db_iter_value(it, &vlen);
    memset(&pm, 0, sizeof(pm));
    if (!vbase || history_deserialize_record((void *)vbase, vlen, &pm) != 0)
      continue;
    if (pm.incarnation != incarnation)
      continue;

    drc = history_trim_delete_stored(s, HTRIM_PATH_INCARNATION, kbase, klen,
                                     msg_target, msg_timestamp, msg_msgid, &pm);
    if (drc < 0) {
      db_iter_close(it);
      htrim_slice_abort(s);
      log_write(LS_SYSTEM, L_ERROR, 0,
                "history_purge_incarnation: %s: cannot stage a delete: %s", channel,
                db_env_last_error(history_db_env) ? db_env_last_error(history_db_env) : "?");
      return -1;
    }
    if (drc > 0)
      skipped++;
  }
  db_iter_close(it);

  deleted = htrim_slice_commit(s);
  if (deleted < 0) {
    log_write(LS_SYSTEM, L_ERROR, 0, "history_purge_incarnation: %s: commit failed: %s",
              channel,
              db_env_last_error(history_db_env) ? db_env_last_error(history_db_env) : "?");
    return -1;
  }
  if (deleted > 0 || skipped > 0)
    log_write(LS_SYSTEM, L_INFO, 0,
              "chathistory: pruned %d row(s) of %s incarnation %lu (lost the burst)%s",
              deleted, channel, (unsigned long)incarnation,
              skipped ? "; rows with keys the trim delete cannot rebuild were left" : "");
  return deleted;
}

/** Resolve BETWEEN's two selectors to store keys and decide the walk
 * direction.  Bounds are ROWS when given as msgids (full key),
 * milliseconds when given as timestamps (prefix).  Both selectors are
 * EXCLUSIVE, and the page is counted from the FIRST selector: a
 * newer-first request pages backwards from it (spec: "counted starting
 * from and excluding the first message selector ... may be forwards or
 * backwards in time").  The old walk swapped the selectors and always
 * returned the OLDEST rows of the window, with the start row included
 * (2026-09-06).
 * @return 0 on success, 1 when a msgid selector cannot be resolved
 *         (caller answers "no rows"), -1 on a key-build error. */
static int between_build_keys(const char *target,
                              enum HistoryRefType ref_type1, const char *reference1,
                              enum HistoryRefType ref_type2, const char *reference2,
                              char *keybuf, size_t keybuf_size, int *keylen,
                              char *endbuf, size_t endbuf_size, int *endlen,
                              int *descending)
{
  char timestamp1[HISTORY_TIMESTAMP_LEN], timestamp2[HISTORY_TIMESTAMP_LEN];
  const char *ref1, *ref2, *msgid1 = NULL, *msgid2 = NULL;

  if (ref_type1 == HISTORY_REF_MSGID) {
    msgid1 = reference1;
    if (history_msgid_to_timestamp(reference1, timestamp1) != 0)
      return 1;
    ref1 = timestamp1;
  } else if (ref_type1 == HISTORY_REF_TIMESTAMP) {
    if (history_iso_to_unix(reference1, timestamp1, sizeof(timestamp1)) == 0)
      ref1 = timestamp1;
    else
      ref1 = reference1;  /* Assume already Unix format */
  } else {
    ref1 = reference1;
  }

  if (ref_type2 == HISTORY_REF_MSGID) {
    msgid2 = reference2;
    if (history_msgid_to_timestamp(reference2, timestamp2) != 0)
      return 1;
    ref2 = timestamp2;
  } else if (ref_type2 == HISTORY_REF_TIMESTAMP) {
    if (history_iso_to_unix(reference2, timestamp2, sizeof(timestamp2)) == 0)
      ref2 = timestamp2;
    else
      ref2 = reference2;
  } else {
    ref2 = reference2;
  }

  *keylen = build_key(keybuf, keybuf_size, target, ref1, msgid1);
  if (*keylen < 0)
    return -1;
  *endlen = build_key(endbuf, endbuf_size, target, ref2, msgid2);
  if (*endlen < 0)
    return -1;
  {
    int minlen = *keylen < *endlen ? *keylen : *endlen;
    int cmp = memcmp(keybuf, endbuf, minlen);
    if (cmp == 0)
      cmp = *keylen - *endlen;
    *descending = cmp > 0;
  }
  return 0;
}

int history_between_descending(const char *target,
                               enum HistoryRefType ref_type1, const char *reference1,
                               enum HistoryRefType ref_type2, const char *reference2)
{
  char keybuf[CHANNELLEN + HISTORY_TIMESTAMP_LEN + HISTORY_MSGID_LEN + 8];
  char endbuf[CHANNELLEN + HISTORY_TIMESTAMP_LEN + HISTORY_MSGID_LEN + 8];
  int keylen, endlen, descending;

  if (between_build_keys(target, ref_type1, reference1, ref_type2, reference2,
                         keybuf, sizeof(keybuf), &keylen,
                         endbuf, sizeof(endbuf), &endlen, &descending) != 0)
    return -1;
  return descending;
}

int history_query_between(const char *target,
                          enum HistoryRefType ref_type1, const char *reference1,
                          enum HistoryRefType ref_type2, const char *reference2,
                          int limit, struct HistoryMessage **result,
                          struct HistoryRowFilter *filter)
{
  char keybuf[CHANNELLEN + HISTORY_TIMESTAMP_LEN + HISTORY_MSGID_LEN + 8];
  char end_prefix[CHANNELLEN + HISTORY_TIMESTAMP_LEN + HISTORY_MSGID_LEN + 8];
  char target_prefix[CHANNELLEN + 2];
  int keylen, end_prefix_len, target_prefix_len;
  int descending;
  struct db_snapshot *snap = NULL;
  struct db_iter *it = NULL;
  struct HistoryMessage *head = NULL, *tail = NULL, *msg;
  int count = 0;
  time_t live_inc = history_live_incarnation(target);
  int rc;

  *result = NULL;

  if (!history_available)
    return -1;

  /* Resolve both selectors to keys and pick the direction (shared with
   * history_between_descending so the federation origin and responder
   * agree with the walk -- re-review 2026-09-07 R8/R9). */
  rc = between_build_keys(target, ref_type1, reference1, ref_type2, reference2,
                          keybuf, sizeof(keybuf), &keylen,
                          end_prefix, sizeof(end_prefix), &end_prefix_len,
                          &descending);
  if (rc != 0)
    return rc < 0 ? -1 : 0;
  target_prefix_len = build_key(target_prefix, sizeof(target_prefix), target, NULL, NULL);
  if (target_prefix_len < 0)
    return -1;
  if (descending) {
    /* Walk backwards from just before the first selector down to (and
     * excluding) the second: the reverse walk's floor is the exclusive
     * lower bound, in row or millisecond terms as given.  Result stays
     * chronological (the reverse walk prepends). */
    return history_query_internal(target, keybuf, keylen, HISTORY_DIR_BEFORE,
                                  limit, result, end_prefix, end_prefix_len,
                                  filter);
  }

  /* Open a snapshot so the iter and ml_content_resolve see a coherent view. */
  snap = db_snapshot_new(history_db_env);
  if (!snap)
    return -1;

  /* The target's own keys only (history_prefix_iter): a window past
   * the target's last row never walks on into the next target. */
  it = history_prefix_iter(history_cf_messages, snap, target_prefix,
                           (size_t)target_prefix_len);
  if (!it) {
    db_snapshot_destroy(snap);
    return -1;
  }

  rc = db_iter_seek(it, keybuf, keylen);
  /* Exclusive start: skip the first selector itself -- the whole
   * millisecond for a timestamp, just the row for a msgid. */
  while (rc == DB_OK && db_iter_valid(it)) {
    size_t klen;
    const void *kbase = db_iter_key(it, &klen);
    if (klen < (size_t)keylen || memcmp(kbase, keybuf, keylen) != 0)
      break;
    rc = db_iter_next(it);
  }

  while (rc == DB_OK && db_iter_valid(it) && count < limit) {
    size_t klen, vlen;
    const void *kbase = db_iter_key(it, &klen);
    const void *vbase = db_iter_value(it, &vlen);

    /* Still this target's range?  The walk is a plain forward iteration
     * from <target>\0<from>; without this guard it ran on into whatever
     * pair sorted next.  The end check below used to be skipped for keys
     * shorter than the end prefix, so a guest pair (22-char session id)
     * followed by the account's short account:account pairs returned
     * those pairs' rows, with no window at all, until the limit -- every
     * goguma backlog fetch is a BETWEEN (2026-09-05). */
    if (klen < (size_t)target_prefix_len ||
        memcmp(kbase, target_prefix, target_prefix_len) != 0)
      break;

    /* Past the end of the window?  Compare on the shorter length so a
     * key can never dodge the check by being short. */
    if (memcmp(kbase, end_prefix,
               klen < (size_t)end_prefix_len ? klen : (size_t)end_prefix_len) >= 0)
      break;

    /* Parse and add message */
    msg = (struct HistoryMessage *)MyMalloc(sizeof(struct HistoryMessage));
    if (!msg)
      break;
    memset(msg, 0, sizeof(*msg));

    if (parse_key((void *)kbase, klen,
                  msg->target, msg->timestamp, msg->msgid) != 0 ||
        history_deserialize_record((void *)vbase, vlen, msg) != 0) {
      MyFree(msg);
      rc = db_iter_next(it);
      continue;
    }

    if (!row_incarnation_ok(msg, live_inc)) {
      history_free_messages(msg);
      rc = db_iter_next(it);
      continue;
    }

    /* Resolve multiline content via the snapshot for coherent reads. */
    ml_content_resolve(snap, msg);

    /* Query-time filter (presence-aware paging); forward walk.  The
     * end-prefix check above re-runs on whatever row a seek lands on. */
    {
      int keep = history_filter_row(filter, msg, 0, target, it, &rc);
      if (keep < 0)
        break;
      if (keep == 0)
        continue;
    }

    msg->next = NULL;
    if (tail)
      tail->next = msg;
    else
      head = msg;
    tail = msg;
    count++;

    rc = db_iter_next(it);
  }

  db_iter_close(it);
  db_snapshot_destroy(snap);

  *result = head;
  return count;
}

uint64_t history_newest_activity_ms(void)
{
  struct db_iter *it;
  uint64_t newest = 0;
  int rc;

  if (!history_available)
    return 0;
  it = db_iter_open(history_db_env, history_cf_targets, NULL);
  if (!it)
    return 0;
  rc = db_iter_seek_first(it);
  while (rc == DB_OK && db_iter_valid(it)) {
    size_t vlen;
    const void *vbase = db_iter_value(it, &vlen);
    char ts[HISTORY_TIMESTAMP_LEN];
    if (vbase && vlen > 0 && vlen < sizeof(ts)) {
      uint64_t ms;
      memcpy(ts, vbase, vlen);
      ts[vlen] = '\0';
      ms = history_parse_ms(ts);
      if (ms > newest)
        newest = ms;
    }
    rc = db_iter_next(it);
  }
  db_iter_close(it);
  return newest;
}

int history_query_targets(const char *timestamp1, const char *timestamp2,
                          int include_newer, int limit,
                          struct HistoryTarget **result,
                          history_target_filter_fn filter, void *filter_ctx)
{
  struct db_iter *it;
  struct HistoryTarget *head = NULL, *tail = NULL, *tgt;
  char unix_ts1[HISTORY_TIMESTAMP_LEN];
  char unix_ts2[HISTORY_TIMESTAMP_LEN];
  const char *ts1, *ts2;
  int count = 0;
  int rc;

  *result = NULL;

  if (!history_available)
    return -1;

  /* Convert client ISO timestamps to Unix for comparison */
  if (history_iso_to_unix(timestamp1, unix_ts1, sizeof(unix_ts1)) == 0)
    ts1 = unix_ts1;
  else
    ts1 = timestamp1;  /* Assume already Unix format */

  if (history_iso_to_unix(timestamp2, unix_ts2, sizeof(unix_ts2)) == 0)
    ts2 = unix_ts2;
  else
    ts2 = timestamp2;  /* Assume already Unix format */

  /* Ensure ts1 < ts2 */
  if (strcmp(ts1, ts2) > 0) {
    const char *tmp = ts1;
    ts1 = ts2;
    ts2 = tmp;
  }

  it = db_iter_open(history_db_env, history_cf_targets, NULL);
  if (!it)
    return -1;

  /* Iterate all targets */
  rc = db_iter_seek_first(it);
  while (rc == DB_OK && db_iter_valid(it) && count < limit) {
    size_t klen, vlen;
    const void *kbase = db_iter_key(it, &klen);
    const void *vbase = db_iter_value(it, &vlen);

    /* Check if target's last message is in range */
    char last_ts[HISTORY_TIMESTAMP_LEN];
    if (vlen >= sizeof(last_ts)) {
      rc = db_iter_next(it);
      continue;
    }
    memcpy(last_ts, vbase, vlen);
    last_ts[vlen] = '\0';

    /* include_newer: also return targets whose latest is ABOVE the
     * window.  A federated requester needs those as VETO rows -- a
     * remote server holding a newer latest pushes the network-wide
     * latest out of the window, so the target must NOT be listed
     * (#565 latest-message matching is a network-wide property).
     * The requester re-filters to the window after the merge. */
    if (strcmp(last_ts, ts1) >= 0
        && (include_newer || strcmp(last_ts, ts2) <= 0)) {
      tgt = (struct HistoryTarget *)MyMalloc(sizeof(struct HistoryTarget));
      if (!tgt)
        break;
      memset(tgt, 0, sizeof(*tgt));

      if (klen > CHANNELLEN) {
        MyFree(tgt);
        rc = db_iter_next(it);
        continue;
      }
      memcpy(tgt->target, kbase, klen);
      tgt->target[klen] = '\0';
      ircd_strncpy(tgt->last_timestamp, last_ts, sizeof(tgt->last_timestamp));
      tgt->next = NULL;

      /* The caller's filter runs inside the walk so only ITS targets
       * count toward the limit (2026-09-05: a 30-day TARGETS on a server
       * with ~3000 targets listed one, because the first 3x<limit>
       * window-matching keys in key order were other people's). */
      if (filter && !filter(tgt->target, tgt->last_timestamp, filter_ctx)) {
        MyFree(tgt);
        rc = db_iter_next(it);
        continue;
      }

      if (tail)
        tail->next = tgt;
      else
        head = tgt;
      tail = tgt;
      count++;
    }

    rc = db_iter_next(it);
  }

  db_iter_close(it);

  *result = head;
  return count;
}

void history_free_messages(struct HistoryMessage *list)
{
  struct HistoryMessage *msg, *next;

  for (msg = list; msg; msg = next) {
    next = msg->next;
    if (msg->dyn_content)
      MyFree(msg->dyn_content);
    if (msg->raw_content)
      MyFree(msg->raw_content);
    MyFree(msg);
  }
}

void history_free_targets(struct HistoryTarget *list)
{
  struct HistoryTarget *tgt, *next;

  for (tgt = list; tgt; tgt = next) {
    next = tgt->next;
    MyFree(tgt);
  }
}

int history_enumerate_channels(history_channel_callback callback, void *data)
{
  struct db_iter *it;
  char target[CHANNELLEN + 1];
  int count = 0;
  int rc;

  if (!history_available || !callback)
    return -1;

  it = db_iter_open(history_db_env, history_cf_targets, NULL);
  if (!it)
    return -1;

  /* Iterate all targets */
  for (rc = db_iter_seek_first(it);
       rc == DB_OK && db_iter_valid(it);
       rc = db_iter_next(it)) {
    size_t klen;
    const void *kbase = db_iter_key(it, &klen);

    if (klen > 0 && klen <= CHANNELLEN) {
      memcpy(target, kbase, klen);
      target[klen] = '\0';

      /* Only call back for channels (start with # or &) */
      if (target[0] == '#' || target[0] == '&') {
        count++;
        if (callback(target, data) != 0)
          break;  /* Callback requested stop */
      }
    }
  }

  db_iter_close(it);

  return count;
}

int history_has_channel(const char *target)
{
  int rc;

  if (!history_available || !target)
    return -1;

  {
    char tkey[CHANNELLEN + 2];
    int tlen = build_target_key(tkey, sizeof(tkey), target);
    if (tlen < 0)
      return -1;
    rc = db_exists(history_db_env, history_cf_targets,
                   tkey, (size_t)tlen, /*snap=*/NULL);
  }
  if (rc == DB_OK)        return 1;
  if (rc == DB_NOTFOUND)  return 0;
  return -1;
}

int history_channel_has_messages(const char *target)
{
  struct db_iter *it;
  char prefix[CHANNELLEN + 2];
  int prefix_len;
  int rc;
  int result = 0;

  if (!history_available || !target)
    return -1;

  /* Build prefix key: "target\0" (folded, like the rows) */
  prefix_len = build_key(prefix, sizeof(prefix), target, NULL, NULL);
  if (prefix_len < 0)
    return -1;

  /* Any key in the target's range.  Seek the LAST one: a target's head
   * is where age-out leaves its tombstones, its tail is live (the trim
   * engine's emptiness check does the same). */
  it = history_prefix_iter(history_cf_messages, NULL, prefix, (size_t)prefix_len);
  if (!it)
    return -1;

  rc = db_iter_seek_last(it);
  if (rc == DB_OK && db_iter_valid(it)) {
    size_t klen;
    const void *kbase = db_iter_key(it, &klen);
    if (klen >= (size_t)prefix_len &&
        memcmp(kbase, prefix, prefix_len) == 0)
      result = 1;
  } else if (rc != DB_NOTFOUND)
    result = -1;

  db_iter_close(it);
  return result;
}

void history_set_channel_removed_callback(history_channels_removed_cb cb)
{
  channel_removed_callback = cb;
}

/** The trim engine's coverage callback: it fires after a slice's commit
 * that moved or cleared the floor (an emergency's, inside a store, at the
 * next slice), never inside a store. */
static void history_coverage_forward(void)
{
  if (coverage_callback)
    coverage_callback();
}

void history_set_coverage_callback(history_coverage_cb cb)
{
  coverage_callback = cb;
  htrim_set_coverage_cb(cb ? history_coverage_forward : NULL);
}

int history_coverage_days(void)
{
  /* htc_effective_days never claims less than 1 day once a floor is set:
   * 0 and -1 mean "unlimited" to the peers' server_retention_covers, so a
   * floor under a day old must not read as either. */
  return htc_effective_days(feature_int(FEAT_CHATHISTORY_RETENTION),
                            history_available ? htrim_coverage_floor_ms() : 0,
                            (uint64_t)time(NULL) * 1000ULL);
}

/* ---- redaction catch-up index: scan + watermark (design B) ---------- */

/* The watermark lives in the index CF under a key that sorts LAST
 * (time prefix all-ones) so a forward scan from any real time never
 * reaches it before the rows, and is skipped by name if it does. */
static const unsigned char rdx_wm_key[10] =
  { 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,'w','m' };

int history_redact_index_scan(uint64_t since_ms, int limit,
                              history_rdx_cb cb, void *ctx, int *truncated)
{
  struct db_iter *it;
  unsigned char start[RDX_KEY_MAX];
  int n = 0, rc, skl;
  if (truncated) *truncated = 0;
  if (!history_db_env || !history_cf_redact || !cb)
    return -1;
  skl = rdx_key_build(start, sizeof start, since_ms, "!");   /* "!" < every msgid char */
  if (skl < 0)
    return -1;
  skl = 8;                                    /* seek on the time prefix alone */
  it = db_iter_open(history_db_env, history_cf_redact, NULL);
  if (!it)
    return -1;
  for (rc = db_iter_seek(it, start, (size_t)skl);
       rc == DB_OK && db_iter_valid(it);
       rc = db_iter_next(it)) {
    size_t klen, vlen;
    const void *k = db_iter_key(it, &klen);
    const void *v = db_iter_value(it, &vlen);
    uint64_t t;
    char rmsgid[RDX_MSGID_MAX];
    struct rdx_val val;
    if (klen == sizeof rdx_wm_key && memcmp(k, rdx_wm_key, sizeof rdx_wm_key) == 0)
      continue;
    if (rdx_key_parse(k, klen, &t, rmsgid, sizeof rmsgid) != 0)
      continue;
    if (rdx_val_parse(v, vlen, &val) != 0)
      continue;
    if (limit > 0 && n >= limit) {
      if (truncated) *truncated = 1;
      break;
    }
    cb(t, rmsgid, &val, ctx);
    n++;
  }
  db_iter_close(it);
  return n;
}

uint64_t history_redact_watermark_get(void)
{
  struct db_iter *it;
  uint64_t wm = 0;
  if (!history_db_env || !history_cf_redact)
    return 0;
  it = db_iter_open(history_db_env, history_cf_redact, NULL);
  if (!it)
    return 0;
  if (db_iter_seek(it, rdx_wm_key, sizeof rdx_wm_key) == DB_OK && db_iter_valid(it)) {
    size_t klen, vlen;
    const void *k = db_iter_key(it, &klen);
    const void *v = db_iter_value(it, &vlen);
    if (klen == sizeof rdx_wm_key && memcmp(k, rdx_wm_key, klen) == 0 && v && vlen < 32) {
      char tmp[32];
      memcpy(tmp, v, vlen); tmp[vlen] = '\0';
      wm = (uint64_t)strtoull(tmp, NULL, 10);
    }
  }
  db_iter_close(it);
  return wm;
}

int history_redact_watermark_set(uint64_t ms)
{
  struct db_writebatch *wb;
  char tmp[32];
  int rc;
  if (!history_db_env || !history_cf_redact)
    return -1;
  wb = db_writebatch_new(history_db_env);
  if (!wb)
    return -1;
  ircd_snprintf(0, tmp, sizeof tmp, "%llu", (unsigned long long)ms);
  db_writebatch_put(wb, history_cf_redact, rdx_wm_key, sizeof rdx_wm_key, tmp, strlen(tmp));
  rc = db_writebatch_commit(wb, /*sync_durably=*/0);
  db_writebatch_destroy(wb);
  return rc == DB_OK ? 0 : -1;
}

int history_pm_target_has_sessid(const char *target, const char *sessid)
{
  struct HistoryMessage *messages = NULL;
  struct HistoryMessage *m;
  int count;
  int found = 0;
  char needles[2][64];
  int n_needles = 2;

  if (!target || !*target || !sessid || !*sessid)
    return 0;
  if (!history_available)
    return 0;

  /* The vendor-tag forms prepended at store time: see ircd_relay.c
   * store_private_history's Phase 5a block.  Current records carry the
   * evilnet-org form; records stored before 2026-08-29 carry the
   * legacy afternet form (both namespaces are reserved from client
   * tags at capture -- is_reserved_vendor_tag -- so neither is
   * forgeable in NEW records; pre-reservation legacy poison is the
   * same accepted residue as 3ab3038's). */
  ircd_snprintf(0, needles[0], sizeof(needles[0]),
                "+evilnet.github.io/sid=%s", sessid);
  ircd_snprintf(0, needles[1], sizeof(needles[1]),
                "+afternet.org/sid=%s", sessid);

  /* Scan up to 100 most recent records under target.  PM records
   * involving an ephemeral participant always carry that participant's
   * sessid (recorded at store time), so the latest record is
   * sufficient unless the conversation has churned through >100 newer
   * messages between someone else and the same nick-pair — which
   * shouldn't happen because the pair-key only matches the two
   * specific nicks involved. */
  count = history_query_latest(target, HISTORY_REF_NONE, NULL,
                                100, &messages, NULL);
  if (count <= 0 || !messages)
    return 0;

  for (m = messages; m; m = m->next) {
    const char *hit;
    int ni;
    /* Anchor the match to a tag-list boundary (start of string, or
     * immediately after a ';' separator): the server prepends its sid
     * tag at position 0, so an unanchored strstr would also accept the
     * needle as a substring of a longer client-supplied tag value.
     * (Both vendor namespaces are reserved from client tags at
     * capture, so a client cannot plant either needle in new
     * records.) */
    if (!m->client_tags[0])
      continue;
    for (ni = 0; ni < n_needles && !found; ni++) {
      for (hit = strstr(m->client_tags, needles[ni]); hit;
           hit = strstr(hit + 1, needles[ni])) {
        if (hit == m->client_tags || hit[-1] == ';') {
          found = 1;
          break;
        }
      }
    }
    if (found)
      break;
  }

  history_free_messages(messages);
  return found;
}

int history_msgid_to_timestamp(const char *msgid, char *timestamp)
{
  struct db_val val = { NULL, 0 };
  const char *sep;
  int rc;

  if (!history_available) {
    log_write(LS_SYSTEM, L_INFO, 0, "history_msgid_to_timestamp: history not available (msgid=%s)", msgid);
    return -1;
  }

  (void)val; (void)sep;
  rc = msgid_index_resolve(msgid, NULL, NULL, timestamp, NULL, 0);
  if (rc == 1) {
    /* Not in the index (never stored, evicted, aged out).  The msgid
     * itself carries its mint time since the 2026-09 repack -- decode
     * it so cursors and refs degrade to a time anchor instead of
     * failing.  Legacy/garbage ids decode to 0 and keep the old
     * failure path. */
    uint64_t ms = msgid_decode_time_ms(msgid);
    if (ms != 0) {
      ircd_snprintf(0, timestamp, HISTORY_TIMESTAMP_LEN, "%llu.%03llu",
                    (unsigned long long)(ms / 1000),
                    (unsigned long long)(ms % 1000));
      return 0;
    }
    log_write(LS_SYSTEM, L_INFO, 0,
              "history_msgid_to_timestamp: msgid=%s NOT FOUND in cf_msgid index "
              "and not time-decodable (legacy format)", msgid);
    return -1;
  }
  if (rc != 0) {
    log_write(LS_SYSTEM, L_INFO, 0,
              "history_msgid_to_timestamp: index resolve failed for msgid=%s",
              msgid);
    return -1;
  }
  return 0;
}

int history_lookup_message(const char *target, const char *msgid,
                            struct HistoryMessage **msg)
{
  struct db_snapshot *snap;
  struct db_val val = { NULL, 0 };
  struct HistoryMessage *m;
  char keybuf[CHANNELLEN + HISTORY_TIMESTAMP_LEN + HISTORY_MSGID_LEN + 8];
  char timestamp[HISTORY_TIMESTAMP_LEN];
  int keylen;
  int rc;

  *msg = NULL;

  if (!history_available)
    return -1;

  /* Pin a snapshot so the msgid_index lookup, the message lookup, and
   * ml_content_resolve all see the same point-in-time view. */
  snap = db_snapshot_new(history_db_env);
  if (!snap)
    return -1;

  /* Resolve the msgid to a timestamp under the pinned snapshot,
   * preferring this target's own index row (multi-target scheme).
   * On an index miss, fall back to the msgid's intrinsic time -- the
   * main-CF row may still exist even when its index row was lost. */
  rc = msgid_index_resolve(msgid, target, snap, timestamp, NULL, 0);
  if (rc == 1) {
    uint64_t ms = msgid_decode_time_ms(msgid);
    if (ms == 0) {
      db_snapshot_destroy(snap);
      return 1; /* Not found */
    }
    ircd_snprintf(0, timestamp, sizeof(timestamp), "%llu.%03llu",
                  (unsigned long long)(ms / 1000),
                  (unsigned long long)(ms % 1000));
    rc = 0;
  }
  if (rc != 0) {
    db_snapshot_destroy(snap);
    return -1;
  }

  /* Build key for main database lookup: target\0timestamp\0msgid */
  keylen = build_key(keybuf, sizeof(keybuf), target, timestamp, msgid);
  if (keylen < 0) {
    db_snapshot_destroy(snap);
    return -1;
  }

  rc = db_get(history_db_env, history_cf_messages,
              keybuf, keylen, snap, &val);
  if (rc == DB_NOTFOUND) {
    db_snapshot_destroy(snap);
    return 1; /* Not found */
  }
  if (rc != DB_OK) {
    db_snapshot_destroy(snap);
    return -1;
  }

  /* Allocate and populate message structure */
  m = (struct HistoryMessage *)MyMalloc(sizeof(struct HistoryMessage));
  if (!m) {
    db_val_free(&val);
    db_snapshot_destroy(snap);
    return -1;
  }
  memset(m, 0, sizeof(*m));

  /* Parse the message */
  if (history_deserialize_record(val.base, val.len, m) != 0) {
    MyFree(m);
    db_val_free(&val);
    db_snapshot_destroy(snap);
    return -1;
  }
  db_val_free(&val);

  /* Fill in the key fields */
  ircd_strncpy(m->msgid, msgid, sizeof(m->msgid));
  ircd_strncpy(m->target, target, sizeof(m->target));
  ircd_strncpy(m->timestamp, timestamp, sizeof(m->timestamp));
  m->next = NULL;

  /* Resolve multiline content via the same snapshot. */
  ml_content_resolve(snap, m);

  db_snapshot_destroy(snap);
  *msg = m;
  return 0;
}

int history_is_available(void)
{
  return history_available;
}

int history_attach_context(const char *target, struct HistoryMessage *messages)
{
  struct db_snapshot *snap;
  struct db_iter *ri_it;
  struct HistoryMessage *msg;
  int added = 0;
  int rc;

  if (!history_available || !messages)
    return 0;

  /* Pin a snapshot so the reply-index walks and main-DBI gets see the
   * same point-in-time view. */
  snap = db_snapshot_new(history_db_env);
  if (!snap)
    return 0;

  /* One iterator per message, bounded to exactly that message's
   * children (history_prefix_iter): most messages have none, and an
   * unbounded seek for a childless parent walked on through whatever
   * came next -- the dead run of another server's aged-out children in
   * this target, or the next target's. */
  for (msg = messages; msg; msg = msg->next) {
    char prefix[CHANNELLEN + HISTORY_MSGID_LEN + 4];
    int plen;

    /* Skip context messages themselves (don't attach context to context) */
    if (msg->is_context)
      continue;

    /* Build prefix to scan all children of (target, msg->msgid):
     *   target\0msgid\0
     * Each child has its own flat key:
     *   target\0parent\0timestamp\0child_msgid */
    plen = build_reply_index_prefix(prefix, sizeof(prefix), target, msg->msgid);
    if (plen < 0)
      continue;
    ri_it = history_prefix_iter(history_cf_reply, snap, prefix, (size_t)plen);
    if (!ri_it)
      continue;

    rc = db_iter_seek_first(ri_it);
    while (rc == DB_OK && db_iter_valid(ri_it)) {
      size_t klen;
      const void *kbase = db_iter_key(ri_it, &klen);
      const char *child_part;
      const char *sep;
      size_t ts_len, mid_len;
      char child_ts[HISTORY_TIMESTAMP_LEN];
      char child_mid[HISTORY_MSGID_LEN];

      if (klen <= (size_t)plen ||
          memcmp(kbase, prefix, plen) != 0)
        break;

      /* The bytes after prefix are: timestamp\0child_msgid */
      child_part = (const char *)kbase + plen;
      sep = memchr(child_part, KEY_SEP, klen - plen);
      if (!sep)
        goto next_child;

      ts_len  = sep - child_part;
      mid_len = (const char *)kbase + klen - (sep + 1);

      if (ts_len < sizeof(child_ts) && mid_len < sizeof(child_mid) && mid_len > 0) {
        char main_keybuf[CHANNELLEN + HISTORY_TIMESTAMP_LEN + HISTORY_MSGID_LEN + 8];
        int main_keylen;
        struct HistoryMessage *ctx;
        int dup_found = 0;
        struct HistoryMessage *dup;
        struct db_val main_val = { NULL, 0 };
        int grc;

        memcpy(child_ts, child_part, ts_len);
        child_ts[ts_len] = '\0';
        memcpy(child_mid, sep + 1, mid_len);
        child_mid[mid_len] = '\0';

        /* Check if this child msgid is already in the primary list (avoid dup) */
        for (dup = messages; dup; dup = dup->next) {
          if (strcmp(dup->msgid, child_mid) == 0) {
            dup_found = 1;
            break;
          }
        }
        if (dup_found)
          goto next_child;

        /* Fetch the full message from main CF */
        main_keylen = build_key(main_keybuf, sizeof(main_keybuf), target, child_ts, child_mid);
        if (main_keylen < 0)
          goto next_child;

        grc = db_get(history_db_env, history_cf_messages,
                     main_keybuf, main_keylen, snap, &main_val);
        if (grc != DB_OK)
          goto next_child;

        ctx = (struct HistoryMessage *)MyCalloc(1, sizeof(struct HistoryMessage));
        if (history_deserialize_record(main_val.base, main_val.len, ctx) != 0) {
          MyFree(ctx);
          db_val_free(&main_val);
          goto next_child;
        }
        db_val_free(&main_val);

        /* Context is an ANNOTATION of its parent -- the spec's "reacts,
         * redacts, edits": a TAGMSG or a REDACT row.  A reply is a
         * message in its own right, with its own place in the stream; it
         * is in the index (it carries +reply) but must not ride along as
         * context: spliced after its parent it arrived out of order,
         * uncounted, and then again as itself on the page that held it
         * (2026-09-05). */
        if (ctx->type != HISTORY_TAGMSG && ctx->type != HISTORY_REDACT) {
          MyFree(ctx);
          goto next_child;
        }

        /* Fill in key fields */
        ircd_strncpy(ctx->target, target, sizeof(ctx->target));
        ircd_strncpy(ctx->timestamp, child_ts, sizeof(ctx->timestamp));
        ircd_strncpy(ctx->msgid, child_mid, sizeof(ctx->msgid));
        ctx->is_context = 1;

        /* Splice in after the parent AND after the context already hung
         * on it: the index walks children in time order, and inserting
         * each at msg->next reversed them. */
        {
          struct HistoryMessage *at = msg;
          while (at->next && at->next->is_context)
            at = at->next;
          ctx->next = at->next;
          at->next = ctx;
        }
        added++;
      }
next_child:
      rc = db_iter_next(ri_it);
    }
    db_iter_close(ri_it);
  }

  db_snapshot_destroy(snap);
  return added;
}

int history_redact_message(const char *target, const char *msgid)
{
  /* Earlier implementation cleared the stored content and deleted the
   * multiline payload here.  Design intent (per audit framing) is to
   * retain the original message for operator-visible audit until
   * normal retention eviction removes it, while filtering it out of
   * regular CHATHISTORY replay via the reply-index relationship to
   * its REDACT child (handled in the replay path).
   *
   * The function is preserved as a no-op for now — callers don't need
   * to change, and a future commit can add explicit "mark
   * inaccessible" metadata here (e.g. a per-record flag) if we want
   * to distinguish audit-visible-but-hidden from genuinely-purged.
   *
   * @return 0 (success): the redact relationship is captured by the
   *         child REDACT record stored separately by the caller, so
   *         no per-record mutation is required here.
   */
  (void)target;
  (void)msgid;
  return 0;
}

int history_message_is_redacted(const char *target, const char *msgid)
{
  struct db_snapshot *snap;
  struct db_iter *ri_it;
  char prefix[CHANNELLEN + HISTORY_MSGID_LEN + 4];
  int plen;
  int rc;
  int redacted = 0;

  if (!history_available || !target || !msgid || !*msgid)
    return -1;

  /* A redaction is a REDACT context row whose reply-index parent is the
   * message (history_store_message links it; history_redact_message
   * itself keeps the row as a placeholder).  Walk the children and look
   * for one of that type. */
  plen = build_reply_index_prefix(prefix, sizeof(prefix), target, msgid);
  if (plen < 0)
    return -1;

  snap = db_snapshot_new(history_db_env);
  if (!snap)
    return -1;
  /* Exactly this message's children (history_prefix_iter): an unredacted,
   * childless message must not walk on into its neighbours' ranges. */
  ri_it = history_prefix_iter(history_cf_reply, snap, prefix, (size_t)plen);
  if (!ri_it) {
    db_snapshot_destroy(snap);
    return -1;
  }

  for (rc = db_iter_seek_first(ri_it);
       rc == DB_OK && db_iter_valid(ri_it) && !redacted;
       rc = db_iter_next(ri_it)) {
    size_t klen;
    const void *kbase = db_iter_key(ri_it, &klen);
    const char *child_part;
    const char *sep;
    size_t ts_len, mid_len;
    char child_ts[HISTORY_TIMESTAMP_LEN];
    char child_mid[HISTORY_MSGID_LEN];
    char main_keybuf[CHANNELLEN + HISTORY_TIMESTAMP_LEN + HISTORY_MSGID_LEN + 8];
    int main_keylen;
    struct db_val main_val = { NULL, 0 };
    struct HistoryMessage child;

    if (klen <= (size_t)plen || memcmp(kbase, prefix, plen) != 0)
      break;

    /* After the prefix: timestamp\0child_msgid */
    child_part = (const char *)kbase + plen;
    sep = memchr(child_part, KEY_SEP, klen - plen);
    if (!sep)
      continue;
    ts_len = sep - child_part;
    mid_len = (const char *)kbase + klen - (sep + 1);
    if (ts_len >= sizeof(child_ts) || mid_len == 0 || mid_len >= sizeof(child_mid))
      continue;
    memcpy(child_ts, child_part, ts_len);
    child_ts[ts_len] = '\0';
    memcpy(child_mid, sep + 1, mid_len);
    child_mid[mid_len] = '\0';

    main_keylen = build_key(main_keybuf, sizeof(main_keybuf), target, child_ts, child_mid);
    if (main_keylen < 0)
      continue;
    if (db_get(history_db_env, history_cf_messages, main_keybuf, main_keylen,
               snap, &main_val) != DB_OK)
      continue;
    memset(&child, 0, sizeof(child));
    if (history_deserialize_record(main_val.base, main_val.len, &child) == 0
        && child.type == HISTORY_REDACT)
      redacted = 1;
    db_val_free(&main_val);
  }

  db_iter_close(ri_it);
  db_snapshot_destroy(snap);
  return redacted;
}

/** Build a readmarker key from account and target.
 * @param[out] key Output buffer.
 * @param[in] keysize Size of output buffer.
 * @param[in] account Account name.
 * @param[in] target Channel or nick.
 * @return Length of key, or -1 on error.
 */
/* Read marker functions removed - now in metadata.c (metadata_readmarker_get/set) */

/** \brief Force sync/flush the history database to disk.
 * Backend-agnostic — db_env_sync dispatches to mdbx_env_sync_ex or
 * rocksdb_flush_wal as appropriate.
 * \return 0 on success, -1 on error */
int
history_sync(void)
{
  if (!history_available)
    return -1;
  return db_env_sync(history_db_env);
}

/** Backend label string for /STATS H reports. */
static const char *history_backend_name(void)
{
  return "RocksDB";
}

void
history_report_stats(struct Client *to, const struct StatDesc *sd, char *param)
{
  struct db_env_stats env_stats;
  struct db_cf_stats cf_stats;

  (void)sd;

  /* STATS chathistory <server> <owner|me>: one owner's accounted bytes.
   * "me" names the asker's own bucket; anything else is an owner key,
   * folded like the stored ones (a:Bob and a:bob are one owner). */
  if (param && *param) {
    char key[HTC_OWNER_MAX];
    const struct htc_acct *acct = htrim_acct();
    if (!ircd_strcmp(param, "me"))
      history_owner_of(key, sizeof key, to);
    else {
      size_t len = strlen(param);
      if (len >= sizeof key)
        len = sizeof key - 1;
      db_casefold_bytes(key, param, len);
      key[len] = '\0';
    }
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "H :  Owner %s = %llu bytes", key,
               (unsigned long long)(history_available && acct
                                    ? htc_acct_owner(acct, key) : 0));
    return;
  }

  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
             "H :CHATHISTORY Statistics");
  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
             "H :  Backend: %s (%s)",
             history_backend_name(),
             history_available ? "available" : "unavailable");

  if (!history_available)
    return;

  /* Env-wide stats — backend-agnostic via abstraction. */
  if (db_env_stats(history_db_env, &env_stats) == DB_OK) {
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "H :  On-disk: %lu MB, ~%lu keys total",
               (unsigned long)(env_stats.on_disk_bytes / (1024 * 1024)),
               (unsigned long)env_stats.approx_keys_total);
    if (env_stats.pending_compaction > 0)
      send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
                 "H :  Pending compaction: %lu MB",
                 (unsigned long)(env_stats.pending_compaction / (1024 * 1024)));
    if (env_stats.level0_files > 0)
      send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
                 "H :  L0 files: %u", env_stats.level0_files);
    if (env_stats.active_readers > 0)
      send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
                 "H :  Active readers: %u", env_stats.active_readers);
  }

  {
    /* The cap: the logical size the trimmer accounts (plan note 7), its
     * watermarks as the planner reads them, and the largest owners. */
    const struct htc_acct *acct = htrim_acct();
    struct htc_owner_total top[5];
    char owners[300];
    size_t n, i, o = 0;
    int high, low;
    uint64_t cap = history_trim_cap(&high, &low);
    uint64_t total = htc_acct_total(acct);

    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "H :  Logical size: %llu bytes of cap %llu bytes (%llu%%), "
               "high=%d%% low=%d%%, eviction %s",
               (unsigned long long)total, (unsigned long long)cap,
               (unsigned long long)(cap ? total * 100 / cap : 0), high, low,
               htrim_draining() ? "draining" : "idle");
    owners[0] = '\0';
    n = acct ? htc_acct_top(acct, top, sizeof top / sizeof top[0]) : 0;
    for (i = 0; i < n; i++) {
      int w = ircd_snprintf(0, owners + o, sizeof owners - o, " %s=%llu",
                            top[i].owner, (unsigned long long)top[i].bytes);
      if (w < 0 || (size_t)w >= sizeof owners - o) {
        owners[o] = '\0';                       /* the last one did not fit */
        break;
      }
      o += (size_t)w;
    }
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "H :  Top owners:%s", o ? owners : " none");
  }
  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
             "H :  Retention: %d days",
             feature_int(FEAT_CHATHISTORY_RETENTION));
  {
    /* What CH A S / R tell peers, and the floor that bounds it. */
    uint64_t floor_ms = htrim_coverage_floor_ms();
    uint64_t now_ms = (uint64_t)time(NULL) * 1000ULL;
    char floor[32];

    if (floor_ms)
      ircd_snprintf(0, floor, sizeof(floor), "%llus old",
                    (unsigned long long)(now_ms > floor_ms
                                         ? (now_ms - floor_ms) / 1000 : 0));
    else
      ircd_strncpy(floor, "none", sizeof(floor));
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "H :  Coverage: %d days advertised (configured %d, floor %s)",
               history_coverage_days(), feature_int(FEAT_CHATHISTORY_RETENTION),
               floor);
  }
  if (htrim_backfill_done())
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "H :  Trim: backfill done, accounting %s",
               htrim_acct_loaded() ? "loaded" : "scanning");
  else
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "H :  Trim: backfill running (%zu rows), accounting %s",
               htrim_backfill_rows(),
               htrim_acct_loaded() ? "loaded" : "scanning");
  {
    /* Age-out: whether a pass is still open, and how old the first row
     * the last age-out slice read was (the head of the time index then);
     * slice times rounded up to whole ms. */
    const struct htrim_stats *tst = htrim_stats();
    uint64_t now_ms = (uint64_t)time(NULL) * 1000ULL;
    char age[24];

    if (tst->oldest_seen_ms)
      ircd_snprintf(0, age, sizeof(age), "%llu",
                    (unsigned long long)(now_ms > tst->oldest_seen_ms
                                         ? (now_ms - tst->oldest_seen_ms) / 1000 : 0));
    else
      ircd_strncpy(age, "unknown", sizeof(age));
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "H :  Backlog: age-out %s, oldest indexed row %ss old",
               htrim_ageout_pending() ? "yes" : "no", age);
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "H :  Last slice: %llu ms (%s), max %llu ms (%s)",
               (unsigned long long)((tst->last_slice_us + 999) / 1000),
               htrim_phase_name(tst->last_phase),
               (unsigned long long)((tst->max_slice_us + 999) / 1000),
               htrim_phase_name(tst->max_phase));
    /* Where the longest slice's time went: staging (the walk), the batch
     * commit, the touched-target cleanup, and its emptiness seeks. */
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "H :  Max slice: %llu ms (%s): walk %llu us, commit %llu us, "
               "cleanup %llu us, hint %llu us, %u seeks",
               (unsigned long long)((tst->max_slice_us + 999) / 1000),
               htrim_phase_name(tst->max_phase),
               (unsigned long long)tst->max_walk_us,
               (unsigned long long)tst->max_commit_us,
               (unsigned long long)tst->max_cleanup_us,
               (unsigned long long)tst->max_hint_us, tst->max_seeks);
  }
  if (history_available) {
    /* Tombstones still in memtables (active + immutable), per trimmed CF:
     * a compaction hint flushes its CF first, so these fall after one. */
    struct db_cf *mcf[5];
    static const char *const mname[5] = {
      "messages", "msgid_index", "reply_index", "by_time", "by_owner"
    };
    char buf[200];
    size_t o = 0, i;

    mcf[0] = history_cf_messages;
    mcf[1] = history_cf_msgid;
    mcf[2] = history_cf_reply;
    mcf[3] = history_cf_by_time;
    mcf[4] = history_cf_by_owner;
    buf[0] = '\0';
    for (i = 0; i < 5; i++) {
      struct db_cf_stats cs;
      int w;
      if (!mcf[i] || db_cf_stats(history_db_env, mcf[i], &cs) != DB_OK)
        continue;
      w = ircd_snprintf(0, buf + o, sizeof buf - o, " %s=%lu", mname[i],
                        (unsigned long)(cs.mem_deletes + cs.imm_deletes));
      if (w < 0 || (size_t)w >= sizeof buf - o) {
        buf[o] = '\0';
        break;
      }
      o += (size_t)w;
    }
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "H :  Memtable deletes:%s", o ? buf : " unknown");
  }
  {
    const struct htrim_stats *tst = htrim_stats();
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "H :  Deleted: ageout=%llu owner=%llu oldest=%llu emergency=%llu "
               "backfill=%llu incarnation=%llu",
               (unsigned long long)tst->deleted[HTRIM_PATH_AGEOUT],
               (unsigned long long)tst->deleted[HTRIM_PATH_OWNER],
               (unsigned long long)tst->deleted[HTRIM_PATH_OLDEST],
               (unsigned long long)tst->deleted[HTRIM_PATH_EMERGENCY],
               (unsigned long long)tst->deleted[HTRIM_PATH_BACKFILL],
               (unsigned long long)tst->deleted[HTRIM_PATH_INCARNATION]);
  }

  /* Per-CF stats — backend-agnostic. */
  if (db_cf_stats(history_db_env, history_cf_messages, &cf_stats) == DB_OK)
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "H :  Messages: ~%lu keys, %lu KB, depth %u",
               (unsigned long)cf_stats.approx_keys,
               (unsigned long)(cf_stats.on_disk_bytes / 1024),
               cf_stats.depth);
  if (db_cf_stats(history_db_env, history_cf_targets, &cf_stats) == DB_OK)
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "H :  Channels: ~%lu",
               (unsigned long)cf_stats.approx_keys);
  if (db_cf_stats(history_db_env, history_cf_msgid, &cf_stats) == DB_OK)
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "H :  MsgID index: ~%lu entries",
               (unsigned long)cf_stats.approx_keys);
  {
    /* The trim engine's own two CFs: how many keys they hold, so an
     * operator can see the index grow (and shrink under eviction)
     * without cross-referencing the messages count by hand. */
    struct db_cf_stats bt_stats, bo_stats;
    unsigned long bt_keys = 0, bo_keys = 0;

    if (db_cf_stats(history_db_env, history_cf_by_time, &bt_stats) == DB_OK)
      bt_keys = (unsigned long)bt_stats.approx_keys;
    if (db_cf_stats(history_db_env, history_cf_by_owner, &bo_stats) == DB_OK)
      bo_keys = (unsigned long)bo_stats.approx_keys;
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "H :  Trim index: by_time ~%lu keys, by_owner ~%lu keys",
               bt_keys, bo_keys);
  }

}

/** \brief Defragment the history database.
 * Moves pages from the end of the DB file to free pages near the beginning,
 * then truncates, reducing file size.
 * \param time_limit_seconds  Maximum wall-clock time to spend (0 = no limit)
 * \return 0 on success, negative on error */
int
history_defrag(unsigned int time_limit_seconds)
{
  int rc;
  (void)time_limit_seconds;  /* libmdbx-specific knob; abstraction's
                              * compact takes no time limit.  RocksDB
                              * compaction is self-paced anyway. */

  if (!history_available)
    return -1;

  rc = db_env_compact(history_db_env, /*cf=*/NULL);
  log_write(LS_SYSTEM, L_INFO, 0,
            "history: compact rc=%d (%s)", rc, db_strerror(rc));
  return (rc == DB_OK) ? 0 : -1;
}

/** \brief Report defrag results for history DB */
void
history_report_defrag(struct Client *to)
{
  int rc;

  if (!history_available) {
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "D :  History: unavailable");
    return;
  }

  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
             "D :  History: compacting...");
  rc = db_env_compact(history_db_env, /*cf=*/NULL);
  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
             "D :  History: compact %s (%s)",
             rc == DB_OK ? "done" : "failed",
             db_strerror(rc));
}


void
history_report_gc(struct Client *to)
{
  struct db_env_stats env_stats;

  if (!history_available) {
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "X :  GC: history unavailable");
    return;
  }

  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
             "X :  Compaction (RocksDB):");
  if (db_env_stats(history_db_env, &env_stats) == DB_OK) {
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "X :    Pending: %lu MB (%lu bytes)",
               (unsigned long)(env_stats.pending_compaction / (1024 * 1024)),
               (unsigned long)env_stats.pending_compaction);
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "X :    L0 files: %u", env_stats.level0_files);
  }
  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
             "X :    Background compactor self-paces; no operator GC needed");
}

void
history_report_store_info(struct Client *to)
{
  struct db_env_stats env_stats;
  struct db_cf_stats cf_stats;

  if (!history_available) {
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "X :  History: unavailable");
    return;
  }

  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
             "X :  History Environment (RocksDB):");

  if (db_env_stats(history_db_env, &env_stats) == DB_OK) {
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "X :    On-disk: %lu MB total",
               (unsigned long)(env_stats.on_disk_bytes / (1024 * 1024)));
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "X :    Approx keys (env-wide): %lu",
               (unsigned long)env_stats.approx_keys_total);
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "X :    Pending compaction: %lu MB  L0 files: %u",
               (unsigned long)(env_stats.pending_compaction / (1024 * 1024)),
               env_stats.level0_files);
  }

  if (db_cf_stats(history_db_env, history_cf_messages, &cf_stats) == DB_OK)
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "X :    messages: ~%lu keys, %lu KB, max-level %u",
               (unsigned long)cf_stats.approx_keys,
               (unsigned long)(cf_stats.on_disk_bytes / 1024),
               cf_stats.depth);
  if (db_cf_stats(history_db_env, history_cf_targets, &cf_stats) == DB_OK)
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "X :    targets: ~%lu keys, %lu KB",
               (unsigned long)cf_stats.approx_keys,
               (unsigned long)(cf_stats.on_disk_bytes / 1024));
  if (db_cf_stats(history_db_env, history_cf_msgid, &cf_stats) == DB_OK)
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "X :    msgid_index: ~%lu keys, %lu KB",
               (unsigned long)cf_stats.approx_keys,
               (unsigned long)(cf_stats.on_disk_bytes / 1024));
  if (db_cf_stats(history_db_env, history_cf_by_time, &cf_stats) == DB_OK)
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "X :    by_time: ~%lu keys, %lu KB",
               (unsigned long)cf_stats.approx_keys,
               (unsigned long)(cf_stats.on_disk_bytes / 1024));
  if (db_cf_stats(history_db_env, history_cf_by_owner, &cf_stats) == DB_OK)
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "X :    by_owner: ~%lu keys, %lu KB",
               (unsigned long)cf_stats.approx_keys,
               (unsigned long)(cf_stats.on_disk_bytes / 1024));
}
