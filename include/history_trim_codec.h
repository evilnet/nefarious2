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
 *     ("target\0parent\0ts\0msgid").
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

#endif /* INCLUDED_history_trim_codec_h */
