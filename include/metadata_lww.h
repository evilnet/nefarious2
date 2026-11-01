/*
 * IRC - Internet Relay Chat, include/metadata_lww.h
 *
 * The pure last-writer-wins rule for cross-server account metadata, the
 * HLC stamp text it orders by, and the MD wire codec built on top of it.
 * No ircd dependencies, so the cmocka suite
 * (ircd/test/metadata_lww_cmocka.c) compiles it standalone.
 *
 * Wire shape this module encodes/decodes (see the W4 plan): a stamped
 * account metadata row travels as
 *
 *   MD =<account> <stamp> <key> <flags> [:piece]
 *
 * where <stamp> is "L<clock>" or "D<clock>" (md_clock_encode /
 * md_clock_decode), <clock> is the HLC stamp text "<ms>.<logical>.<node>"
 * (md_stamp_format / md_stamp_parse), and <flags> is one of `*` (public),
 * `P` (private) or `D` (tombstone, no value, no `+`), each optionally
 * suffixed `+` to say more chunk pieces follow on later lines
 * (md_flags_parse / md_chunk_feed).  A row with no clock entry at all
 * (never stamped) compares as stamp "0.0.0" -- callers that need that
 * default construct a zeroed struct md_stamp rather than calling
 * md_stamp_parse on anything.
 *
 * None of this module decides whether a given key or target is
 * STAMPED-targeted account metadata at all -- m_metadata.c's existing
 * dispatch does that.  It only answers, given two candidate versions of
 * one row, which one a receiver keeps (md_lww_take), and how the pieces
 * of the row move on the wire.
 */
#ifndef INCLUDED_metadata_lww_h
#define INCLUDED_metadata_lww_h

#ifndef INCLUDED_stdint_h
#include <stdint.h>
#define INCLUDED_stdint_h
#endif
#ifndef INCLUDED_stddef_h
#include <stddef.h>
#define INCLUDED_stddef_h
#endif

/** A hybrid-logical-clock stamp: millisecond wall time, a logical tick
 * that breaks ties within the same millisecond, and the originating
 * node's id that breaks ties within the same (ms, logical) pair.  Field
 * order here is also comparison order (see md_stamp_cmp). */
struct md_stamp {
  uint64_t ms;
  uint16_t logical;
  uint16_t node;
};

/** Buffer big enough for the longest stamp text md_stamp_parse()
 * accepts (MD_STAMP_BUFSIZE - 1 = 31 characters) plus the NUL, and so
 * for md_stamp_format() of any stamp it returned.  The theoretical worst
 * case -- a 20-digit ms and two 5-digit fields, 32 characters -- is
 * refused by md_stamp_parse() rather than truncated downstream (chunk
 * identity, clock row); a stamp anywhere near UINT64_MAX milliseconds
 * is not a real scenario this wire format serves. */
#define MD_STAMP_BUFSIZE 32

/** Parse the decimal stamp text "<ms>.<logical>.<node>" in @a text into
 * @a out. Rejects anything that is not exactly three all-digit fields
 * (no sign, no leading '+', no trailing garbage) separated by exactly
 * two '.' characters, where the second or third field does not fit
 * in a uint16_t, or whose text is MD_STAMP_BUFSIZE characters or longer
 * (it would not fit the buffers sized from MD_STAMP_BUFSIZE).
 * @return 0 on success, -1 if malformed.
 */
extern int md_stamp_parse(const char *text, struct md_stamp *out);

/** Format @a s as decimal "<ms>.<logical>.<node>" into @a buf (capacity
 * @a len, NUL-terminated on success).
 * @return the number of characters written (excluding the NUL), or -1
 * if @a buf is too small or an argument is NULL.
 */
extern int md_stamp_format(char *buf, size_t len, const struct md_stamp *s);

/** Order two stamps by (ms, logical, node), in that field order.
 * @return <0 if @a a sorts before @a b, >0 if after, 0 if equal.
 */
extern int md_stamp_cmp(const struct md_stamp *a, const struct md_stamp *b);

/** Whether @a s claims to be more than @a max_forward_ms ahead of
 * @a now_ms. Compares by subtraction (never by adding @a max_forward_ms
 * to @a s, which could overflow); a stamp at or behind @a now_ms is
 * never "ahead". @a max_forward_ms is the already-normalised allowed
 * clock-skew forward slack -- computing or clamping that normalised
 * value is not this function's job (see hlc_max_forward_ms(), owned
 * elsewhere).
 * @return 1 if @a s is more than @a max_forward_ms ahead of @a now_ms,
 * 0 otherwise.
 */
extern int md_stamp_ahead(const struct md_stamp *s, uint64_t now_ms,
                           uint64_t max_forward_ms);

/** One candidate version of a metadata row, as the LWW rule compares it:
 * its stamp, whether it is a tombstone (deleted, no value), its
 * visibility, and -- for a live (non-tombstone) row -- its value bytes.
 * @a value/@a vlen are unused (and may be NULL/0) when @a tombstone is
 * set. */
struct md_version {
  struct md_stamp st;
  int tombstone;
  int vis;
  const char *value;
  size_t vlen;
};

/** The pure last-writer-wins rule: does @a incoming replace @a local?
 *
 * @a local may be NULL to mean "no row here yet", in which case
 * @a incoming is always taken. Otherwise the newer stamp wins outright.
 * On equal stamps: two tombstones keep the existing row (no-op either
 * way); one tombstone against one live row, the live row wins
 * regardless of which side it is on; two live rows compare their value
 * bytes (memcmp over the shorter length, then the longer value wins a
 * common-prefix tie) and the larger value wins; two identical live rows
 * (or the trivial self-compare) keep the existing row.
 *
 * @return 1 if @a incoming should replace @a local, 0 if @a local should
 * be kept.
 */
extern int md_lww_take(const struct md_version *local,
                        const struct md_version *incoming);

/** Encode @a s/@a tombstone as the wire clock token "L<stamp>" (live) or
 * "D<stamp>" (tombstone) into @a buf (capacity @a len, NUL-terminated on
 * success).
 * @return the number of characters written (excluding the NUL), or -1
 * if @a buf is too small or an argument is NULL.
 */
extern int md_clock_encode(char *buf, size_t len, const struct md_stamp *s,
                            int tombstone);

/** Decode a wire clock token of exactly @a len bytes at @a buf (need not
 * be NUL-terminated beyond @a len) back into @a s/@a tombstone. Requires
 * the first byte to be 'L' or 'D' and the remainder to be a valid
 * md_stamp_parse() stamp.
 * @return 0 on success, -1 if malformed.
 */
extern int md_clock_decode(const char *buf, size_t len, struct md_stamp *s,
                            int *tombstone);

/** Validate a metadata key for the wire, per m_metadata.c's existing
 * is_valid_key() rule for an ordinary key (1-63 bytes, [A-Za-z0-9_./-],
 * no leading digit) and a separate, looser rule for a key under the
 * case-insensitive prefix "draft/persistence/" (1-127 bytes total, any
 * byte 0x21-0x7e, but may not start with ':').
 * @return 1 if @a key is valid, 0 otherwise.
 */
extern int md_wire_key_valid(const char *key);

/** What kind of target an MD command's first parameter names. */
enum md_target_kind {
  MD_T_NICK,             /**< An ordinary nick/client target. */
  MD_T_CHANNEL,          /**< "#..." or "&..." -- a channel. */
  MD_T_ACCOUNT,          /**< "*<account>" -- an account, unstamped. */
  MD_T_ACCOUNT_STAMPED,  /**< "=<account>" -- an account, LWW-stamped. */
  MD_T_SESSION,          /**< "!<session-id>" -- a bouncer session. */
  MD_T_PULL,             /**< Exactly "?" -- a pull request. */
  MD_T_PULL_END,         /**< Exactly "." -- a pull end marker. */
  MD_T_INVALID           /**< Empty, or a bare sigil with nothing after
                           *   it, or "?"/"." with trailing bytes. */
};

/** Classify an MD command's first parameter (parv[1]) by its leading
 * sigil. See enum md_target_kind for the rules.
 */
extern enum md_target_kind md_target_classify(const char *parv1);

/** Parse a stamped-account MD row's flags token: `*` (public, live),
 * `P` (private, live), `D` (tombstone -- no value, no continuation), or
 * `*`/`P` suffixed `+` to say more chunk pieces follow (`D+` is not
 * valid: a tombstone carries no value to chunk).
 * @param[out] vis       0 (public) or 1 (private); meaningless (but
 *                        still written, deterministically) when the
 *                        token is `D`.
 * @param[out] tombstone 1 if the token is `D`, 0 otherwise.
 * @param[out] more      1 if the token ends `+` (more pieces follow).
 * @return 0 on success, -1 if @a tok is not one of the five valid forms.
 */
extern int md_flags_parse(const char *tok, int *vis, int *tombstone,
                           int *more);

/** Chunk-reassembly state for one stamped-account row's value, across
 * one or more wire lines joined by the `+` continuation flag. Each
 * field here except @a value/@a len/@a active/@a dropped identifies
 * which (account, stamp, key, vis) the pending accumulation belongs to,
 * so a line that does not match restarts cleanly instead of silently
 * concatenating two different rows' pieces. */
struct md_chunk {
  char account[16];
  char key[128];
  char stamp[MD_STAMP_BUFSIZE];
  int vis;
  int active;    /**< 1 while a `+`-continued accumulation is pending. */
  int dropped;   /**< 1 if THIS feed call discarded a mismatched pending
                  *   accumulation before starting fresh. Reset to 0 at
                  *   the start of every feed call. */
  size_t len;    /**< Bytes accumulated in @a value so far. */
  char value[1024];
  /** 1 while the rest of one row is being discarded (an overflow, an
   * abandoned accumulation, an inconsistent or refused piece): every
   * further piece of the row named by @a poison_account /
   * @a poison_stamp / @a poison_key is swallowed, up to and including
   * its more=0 piece, so no tail of it is ever handed back as the whole
   * value. */
  int poisoned;
  char poison_account[16];
  char poison_key[128];
  char poison_stamp[MD_STAMP_BUFSIZE];
};

enum { MD_CHUNK_ERROR = -1, MD_CHUNK_PENDING = 0, MD_CHUNK_DONE = 1 };

/** Feed one wire line's piece into @a c's reassembly state.
 *
 * A row is identified by (account, stamp, key); every piece of it must
 * also agree on @a vis.  Rules, in order:
 *  - An identity field that does not fit its buffer (@a account over 15
 *    bytes, i.e. ACCOUNTLEN; @a stamp of MD_STAMP_BUFSIZE bytes or more;
 *    @a key of 128 or more) is refused: MD_CHUNK_ERROR, state untouched.
 *    It is never truncated into a name that could match another row.
 *  - A piece of the poisoned row (see struct md_chunk) is swallowed:
 *    MD_CHUNK_ERROR; its more=0 piece also ends the poison.
 *  - A piece of the pending row that disagrees on @a vis: the pending
 *    value and the rest of the row are discarded (poisoned, unless this
 *    piece is the row's more=0 one), MD_CHUNK_ERROR.
 *  - A piece of a different row while one is pending: the pending value
 *    is discarded (@a c->dropped is set to 1) and the rest of THAT row
 *    poisoned; accumulation restarts fresh from @a piece.
 *  - Otherwise @a piece starts or extends the pending value.
 *    Accumulating past 1023 bytes total discards the value and returns
 *    MD_CHUNK_ERROR; when @a more is set the rest of the row is
 *    poisoned too, so its remaining pieces never assemble a tail.
 *
 * @return MD_CHUNK_PENDING if @a more is set (wait for the next line),
 * MD_CHUNK_DONE if this completes the value (@a c->value/@a c->len hold
 * it), or MD_CHUNK_ERROR when nothing is to be merged from this piece.
 */
extern int md_chunk_feed(struct md_chunk *c, const char *account,
                          const char *stamp, const char *key, int vis,
                          int more, const char *piece);

/** A caller refused one piece of row (@a account, @a stamp, @a key)
 * without feeding it (e.g. a malformed flags token, whose `+` it cannot
 * read): discard that row's pending value if it is the one pending, and
 * poison the rest of the row, so the pieces after the refused one are
 * never merged as the whole value.  A different row's pending value is
 * left alone.  An identity that does not fit (see md_chunk_feed) is
 * ignored: md_chunk_feed refuses every piece of such a row anyway.
 */
extern void md_chunk_abandon(struct md_chunk *c, const char *account,
                              const char *stamp, const char *key);

/** Parse an MD PULL request's trailing parameters: parv[2] a decimal
 * sequence number, parv[3] exactly "A" or "R" (the pull scope), and
 * parv[4] a comma-separated list of 1-16 non-empty account names, each
 * at most 15 bytes. @a parv[4] is split in place (commas overwritten
 * with NUL bytes) and @a accounts is filled with pointers into it, up
 * to @a max entries.
 *
 * @param[in]  parc     Must be at least 5 (parv[0..4] all present).
 * @param[out] seq      The parsed sequence number.
 * @param[out] scope    'A' or 'R'.
 * @param[out] accounts Filled with up to @a max pointers into parv[4].
 * @param[in]  max      Capacity of @a accounts.
 * @return the number of names (1-16) on success, or -1 if any field is
 * malformed.
 */
extern int md_pull_parse(int parc, char *parv[], unsigned long *seq,
                          char *scope, char *accounts[], int max);

#endif /* INCLUDED_metadata_lww_h */
