/* include/history_trim_codec.h
 * Chathistory trimming -- the pure codec: message/by_time/by_owner key
 * encoding, the by_time record, the owner-key classifier and the stored
 * row-size formula.
 *
 * Deliberately pure (libc, res.h for struct irc_in_addr, db_casefold.h
 * for name folding; no other IRCd deps, plain malloc/free), so the
 * CMocka suite gates every byte layout without a running ircd or a
 * database.  This module owns EVERY key encoding the trim engine needs:
 *
 *   - htc_msg_key / htc_msg_key_parse are THE implementation of the
 *     messages-CF key (history.c's build_key / parse_key become
 *     one-line wrappers over these).
 *   - htc_msgid_key mirrors history.c's msgid_index key
 *     ("msgid\0fold(target)").
 *   - htc_reply_child_key mirrors history.c's reply_index key
 *     ("target\0parent\0ts\0msgid"), htc_reply_prefix its scan prefix
 *     ("target\0parent\0"); history.c's builders wrap both.
 *   - the redact_index key is built by rdx_key_build() (include/
 *     redact_index.h), which is already pure -- this module adds
 *     nothing for it.
 *   - htc_bt_key / htc_bo_key are the new by_time / by_owner index
 *     keys this project adds.
 *
 * Builders return the encoded length, or -1 if the output would not
 * fit in the caller's buffer. Parsers return 0 on success, -1 on a
 * malformed or truncated input.
 */
#ifndef INCLUDED_history_trim_codec_h
#define INCLUDED_history_trim_codec_h

#ifndef INCLUDED_stdint_h
#include <stdint.h>
#define INCLUDED_stdint_h
#endif
#ifndef INCLUDED_stddef_h
#include <stddef.h>
#define INCLUDED_stddef_h
#endif

struct irc_in_addr;

#define HTC_OWNER_MAX  80
#define HTC_MSGID_MAX  64
#define HTC_TS_MAX     20
#define HTC_TARGET_MAX 201
#define HTC_BT_KEY_MAX (8 + HTC_TARGET_MAX + HTC_MSGID_MAX)
#define HTC_BO_KEY_MAX (HTC_OWNER_MAX + HTC_BT_KEY_MAX)
#define HTC_MSG_KEY_MAX (HTC_TARGET_MAX + HTC_TS_MAX + HTC_MSGID_MAX + 2)
#define HTC_REC_MAX (6 + HTC_TS_MAX + HTC_OWNER_MAX + 2 * HTC_MSGID_MAX + 3)

#define HTC_F_REDACT 0x01
#define HTC_F_ML     0x02

#define HTC_OWNER_NONE "-"

/** Fixed bytes of storage overhead per row that the row-size formula
 * charges on top of the raw key/value lengths it is given (RocksDB
 * per-entry/per-key overhead, kept as one tuned constant rather than
 * derived -- see htc_row_bytes). */
#define HTC_ROW_FIXED 48

/** The by_time record (value of a by_time row; record format v1):
 * version(1) ‖ flags(1) ‖ be32(bytes) ‖ ts \0 owner \0 reply_parent \0
 * redact_parent (no trailing NUL). */
struct htc_rec {
  uint32_t      bytes;
  unsigned char flags;
  char          ts[HTC_TS_MAX];
  char          owner[HTC_OWNER_MAX];
  char          reply_parent[HTC_MSGID_MAX];
  char          redact_parent[HTC_MSGID_MAX];
};

/** today's history_parse_ms (ircd/history.c), verbatim: parse a
 * "<secs>[.<fractional>]" timestamp string to milliseconds. Up to
 * three fractional digits are honored (more are ignored); malformed
 * or NULL/empty input yields 0. */
uint64_t htc_parse_ms(const char *ts);

/** Classify a row's owner for the by_owner index:
 *   - account non-empty and not "*"      -> "a:" + fold(account)
 *   - else a valid, non-unspecified ip   -> "i:" + 8 hex (IPv4 /32) or
 *                                           16 hex (IPv6 /64) digits
 *   - else server non-empty              -> "s:" + fold(server)
 *   - else                                -> "-"
 * @return the owner-string length (excluding the NUL written after
 * it), or -1 if it doesn't fit in @a size. */
int htc_owner_key(char *buf, size_t size, const char *account,
                   const struct irc_in_addr *ip, const char *server);

/** Build the messages-CF key: fold(target) \0 ts \0 msgid. @a ts NULL
 * stops after fold(target) \0; @a msgid NULL (or "") stops after
 * fold(target) \0 ts \0. THE implementation of history.c's build_key
 * -- byte-identical by construction. */
int htc_msg_key(char *buf, size_t size, const char *target,
                 const char *ts, const char *msgid);

/** Parse a messages-CF key built by htc_msg_key. Any of the output
 * pointers may be NULL to skip that component. */
int htc_msg_key_parse(const void *key, size_t klen,
                       char *target, size_t tsz,
                       char *ts, size_t tssz,
                       char *msgid, size_t msz);

/** Build the msgid_index key: msgid \0 fold(target) (no trailing
 * NUL). Byte-identical to history.c's build_msgid_index_key. */
int htc_msgid_key(char *buf, size_t size, const char *msgid,
                   const char *target);

/** Build the reply_index key: fold(target) \0 parent \0 ts \0 msgid
 * (no trailing NUL). Byte-identical to history.c's
 * build_reply_index_key. */
int htc_reply_child_key(char *buf, size_t size, const char *target,
                         const char *parent, const char *ts,
                         const char *msgid);

/** Build the reply_index scan prefix of every child of (target,
 * parent): fold(target) \0 parent \0 -- the head of each
 * htc_reply_child_key for that pair, and history.c's
 * build_reply_index_prefix. */
int htc_reply_prefix(char *buf, size_t size, const char *target,
                      const char *parent);

/** Build the by_time key: be64(ms) ‖ fold(target) ‖ \0 ‖ msgid (no
 * trailing NUL; @a msgid NULL/"" stops after the \0). */
int htc_bt_key(char *buf, size_t size, uint64_t ms, const char *target,
                const char *msgid);

/** Parse a by_time key built by htc_bt_key. Any output pointer may be
 * NULL to skip that component. */
int htc_bt_key_parse(const void *key, size_t klen, uint64_t *ms,
                      char *target, size_t tsz, char *msgid, size_t msz);

/** Encode an 8-byte big-endian bound for @a ms: "every by_time row
 * strictly before ms" is every key less than this bound (a bare
 * be64(ms) sorts before any by_time key carrying that same ms, since
 * such a key is longer with an equal 8-byte prefix). */
void htc_be64(unsigned char out[8], uint64_t ms);

/** Build a by_owner key: owner \0 bt_key (bt_key copied verbatim,
 * @a bt_klen bytes). */
int htc_bo_key(char *buf, size_t size, const char *owner,
                const void *bt_key, size_t bt_klen);

/** Build a by_owner scan prefix: owner \0 (isolates @a owner's rows
 * from an owner string that merely starts with it). */
int htc_bo_prefix(char *buf, size_t size, const char *owner);

/** Split a by_owner key back into its owner and bt_key. @a bt_key is
 * set to point inside @a key (not copied); @a owner may be NULL to
 * skip it. */
int htc_bo_split(const void *key, size_t klen, char *owner, size_t osz,
                  const void **bt_key, size_t *bt_klen);

/** Pack a by_time record (struct htc_rec) to its v1 wire form. */
int htc_rec_pack(char *buf, size_t size, const struct htc_rec *r);

/** Parse a v1 by_time record. Rejects any other version byte, a value
 * shorter than the fixed header, or a value missing any of the three
 * NUL field separators. */
int htc_rec_parse(const void *v, size_t vlen, struct htc_rec *out);

/** Pack/parse the by_owner value: a bare big-endian uint32 byte count. */
void htc_size_pack(unsigned char out[4], uint32_t bytes);
int htc_size_parse(const void *v, size_t vlen, uint32_t *bytes);

/** The accounting delta a stored row (message + its by_time + by_owner
 * rows) charges against the owner's/global total: the raw key/value
 * lengths given, plus HTC_ROW_FIXED bytes of fixed per-row overhead.
 * Saturates at UINT32_MAX rather than wrapping on huge inputs. */
uint32_t htc_row_bytes(size_t msg_klen, size_t msg_vlen, size_t ml_vlen,
                        size_t bt_klen, size_t owner_len);

/* ---------------------------------------------------------------------
 * Owner accounting table: owner -> bytes, plus a running global total.
 * Opaque; create with htc_acct_new(), always release with
 * htc_acct_free(). A chained hash on the owner string, grown (bucket
 * array doubled, every entry rehashed in place) whenever an insert
 * would push the load factor above 1 (count == nbuckets).
 * ------------------------------------------------------------------- */
struct htc_acct;

/** One entry of htc_acct_top()'s output: an owner and its current
 * byte total. */
struct htc_owner_total {
  char     owner[HTC_OWNER_MAX];
  uint64_t bytes;
};

struct htc_acct *htc_acct_new(void);
void htc_acct_free(struct htc_acct *a);

/** Drop every owner and reset the global total to 0 (keeps the table
 * itself, so a reused htc_acct need not be freed/re-created). */
void htc_acct_clear(struct htc_acct *a);

/** Add (or, with a negative @a delta, subtract from) @a owner's byte
 * total and the global total together. Clamps at 0: a delta that
 * would drive an owner negative leaves it at 0 instead, and an owner
 * at 0 is dropped from the table (so htc_acct_count/htc_acct_top never
 * see it again). A negative delta against an owner not currently in
 * the table is a no-op -- there is nothing to clamp. */
void htc_acct_add(struct htc_acct *a, const char *owner, int64_t delta);

/** @return @a owner's current byte total, or 0 if it has none. */
uint64_t htc_acct_owner(const struct htc_acct *a, const char *owner);

/** @return the global total across every owner (the figure
 * htc_acct_add has been maintaining incrementally, not a re-sum). */
uint64_t htc_acct_total(const struct htc_acct *a);

/** @return the number of owners currently holding a nonzero total. */
size_t htc_acct_count(const struct htc_acct *a);

/** Fill @a out with the @a n owners holding the largest totals, largest
 * first, ties broken by owner ascending.
 * @return the number written (min(@a n, htc_acct_count(@a a))). */
size_t htc_acct_top(const struct htc_acct *a, struct htc_owner_total *out,
                     size_t n);

/* ---------------------------------------------------------------------
 * The fair-eviction planner.
 * ------------------------------------------------------------------- */
#define HTC_PLAN_MAX_STEPS 32

/** Planner inputs: the live cap/watermark/quota config for one pass. */
struct htc_plan_params {
  uint64_t cap;
  int      high_pct;
  int      low_pct;
  int      quota_on;
  int      share_pct;
  int      draining;
};

/** One eviction step: trim @a owner down by @a trim bytes. */
struct htc_plan_step {
  char     owner[HTC_OWNER_MAX];
  uint64_t trim;
};

/** The planner's output for one pass. @a active false means there is
 * nothing to do (@a nsteps 0, @a oldest 0). @a truncated true means
 * more owners were over their share than @a steps could hold -- the
 * caller must NOT fall back to evicting oldest-overall in that case
 * (that would delete compliant owners' rows while over-share owners
 * remain untouched), which is why @a oldest is forced to 0 whenever
 * @a truncated is set, even if @a nsteps also came out 0. */
struct htc_plan {
  int                  active;
  int                  truncated;
  uint64_t             target;
  uint64_t             share;
  size_t               nsteps;
  struct htc_plan_step steps[HTC_PLAN_MAX_STEPS];
  uint64_t             oldest;
};

/** Whether @a p's share step is on: quota on and share_pct in 1..99.
 * The planner lists owner steps only then, and an owner step already in
 * progress may go on only then (a SET that turns the share off, or to
 * an out-of-range percentage, ends it). */
int htc_share_active(const struct htc_plan_params *p);

/** The share @a owner is held to while evicting under @a p. Returns
 * @a p's flat per-owner share (cap * share_pct / 100) for every owner
 * today, ignoring @a owner entirely -- this is the one hook a future
 * per-owner exemption/override would change; htc_plan_eviction never
 * computes a share any other way. */
uint64_t htc_owner_share(const struct htc_plan_params *p, const char *owner);

/** The watermarks the planner uses for @a *high_pct / @a *low_pct (any
 * SET value may be out of range), in place: high outside 1..100 -> 85,
 * low outside 1..100 -> 75, then low >= high -> high - 10 (0 when high
 * <= 10).  Every caller that turns the watermarks into bytes (the trim
 * engine's "over high" check, STATS) goes through this one rule. */
void htc_plan_sanitize(int *high_pct, int *low_pct);

/** Plan one eviction pass against @a a's current totals under @a p.
 * See the module comment above htc_plan_eviction() in
 * history_trim_codec.c for the exact algorithm (watermark sanitizing,
 * the active decision, the quota step, the oldest-overall fallback). */
void htc_plan_eviction(const struct htc_acct *a,
                        const struct htc_plan_params *p,
                        struct htc_plan *out);

/* ---------------------------------------------------------------------
 * Effective coverage days.
 * ------------------------------------------------------------------- */

/** The retention window CHATHISTORY's coverage should actually claim:
 * @a configured_days as configured, but never more than how far back
 * @a floor_ms (the oldest row actually retained; 0 if unknown) really
 * reaches from @a now_ms, and never less than 1. */
int htc_effective_days(int configured_days, uint64_t floor_ms, uint64_t now_ms);

#endif /* INCLUDED_history_trim_codec_h */
