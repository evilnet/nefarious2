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

/** Whether two versions of one row say the same thing, stamps aside: both
 * tombstones, or both live with the same visibility and value bytes.  A
 * taken row that says the same as the one it replaces changes nothing
 * anyone sees: its stamp is stored and relayed, nobody is told
 * (ms_metadata_stamped(), owner 2026-11-13).
 * @return 1 if they say the same, 0 if not (or either is NULL). */
extern int md_version_same_content(const struct md_version *a,
                                   const struct md_version *b);

/** Whether a row @a in taken over @a local (NULL: no row) changes nothing a
 * subscriber has seen: the same content (md_version_same_content()), or a
 * tombstone where there was no row -- nobody ever saw a value to lose.
 * Only the METADATA notification depends on it: memory and mode flags are
 * applied whatever it says (for a mode-synced key a tombstone over no row
 * turns a default mode off, and that change is applied and echoed).
 * @return 1 if nothing changed for a subscriber, else 0. */
extern int md_row_unchanged(const struct md_version *local,
                            const struct md_version *in);

/** The CLEAR floor (owner, 2026-11-13): an account cleared at Tc keeps
 * "cleared at Tc" in its store, and an incoming live row older than Tc is
 * taken as a tombstone at Tc instead -- a value written before the CLEAR,
 * held by a server this one did not reach, does not come back.
 *
 * Is @a floor (NULL: none) in force at @a now_s?  It expires with the
 * tombstones (METADATA_TOMBSTONE_TTL, @a ttl_s; 0: never), measured from
 * its own time, as the tombstone purge measures them.
 * @return 1 if in force. */
extern int md_floor_in_force(const struct md_stamp *floor, uint64_t now_s,
                             uint64_t ttl_s);

/** How much older than the floor a row must be before the floor converts
 * it (review c1): the clock skew the tree accepts between servers.  A
 * stamp more than FEAT_HLC_MAX_FORWARD_MS (default 60000) ahead of a
 * receiver's clock is refused (md_stamp_ahead(), ms_metadata_stamped()),
 * so servers that exchange rows run within that of each other; a server
 * whose clock lags by up to that much, and has seen no newer stamp, can
 * stamp a write made just AFTER the CLEAR below the CLEAR's stamp.  Rows
 * from a split -- what the floor is for -- are far older.  What it gives
 * up: a key this server never held, written on another server within
 * this margin BEFORE the CLEAR, survives the CLEAR (a key this server
 * held is deleted by the CLEAR's own tombstone, which any older row
 * loses to).  A constant, not the feature: the floor's decision must not
 * move with a REHASH. */
#define MD_FLOOR_MARGIN_MS 60000

/** Does the floor turn @a in into a tombstone at the floor's stamp?  Only
 * a live row (a tombstone is never converted), only a key a CLEAR deletes
 * (@a clearable: not a server-managed or internal key), only one older
 * than the floor by more than MD_FLOOR_MARGIN_MS (a row written after the
 * CLEAR stands, even from a server whose clock lags), only a floor in
 * force (md_floor_in_force()).
 * @return 1 to convert. */
extern int md_floor_converts(const struct md_stamp *floor,
                             const struct md_version *in, int clearable,
                             uint64_t now_s, uint64_t ttl_s);

/** Does a CLEAR at @a tc raise the floor @a floor (NULL: none)?  It only
 * ever goes up.
 * @return 1 to write @a tc. */
extern int md_floor_raises(const struct md_stamp *floor,
                           const struct md_stamp *tc);

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

/** How many interrupted rows one link's chunk state remembers to
 * discard at once (struct md_chunk's poison slots).  A compliant sender
 * never interleaves two rows' pieces on one link, so only a
 * non-compliant one ever fills more than one; past this many live
 * poisons a slot is reused in turn and that row's poison is forgotten. */
#define MD_CHUNK_POISON_SLOTS 4

/** One row whose remaining pieces are being discarded (see struct
 * md_chunk). */
struct md_chunk_poison {
  int used;
  char account[16];
  char key[128];
  char stamp[MD_STAMP_BUFSIZE];
};

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
  /** Rows whose rest is being discarded (an overflow, an abandoned
   * accumulation, an inconsistent or refused piece): every further piece
   * of a row named in a used slot is swallowed, up to and including its
   * more=0 piece (which frees the slot), so no tail of it is ever handed
   * back as the whole value.  One slot per row, so a row interrupted
   * while another row's poison is live keeps its own (W4 push-1 fix-wave
   * N3(a)); when every slot is in use they are reused in turn (@a
   * poison_next). */
  struct md_chunk_poison poison[MD_CHUNK_POISON_SLOTS];
  int poison_next;   /**< slot reused when every slot is in use */
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
 *  - A piece of a poisoned row (see struct md_chunk) is swallowed:
 *    MD_CHUNK_ERROR, and the pending row (if another) is left alone;
 *    its more=0 piece also ends that row's poison.
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
 * without feeding it (e.g. a malformed or missing flags token):
 * discard that row's pending value if it is the one pending and, when
 * @a more says pieces of the row follow the refused one, poison the
 * rest of the row, so they are never merged as the whole value.  When
 * @a more is 0 the refused piece was the row's last (or only) one:
 * nothing follows to discard, and poisoning would swallow the next
 * delivery of the same row instead (W4 push-1 fix-wave N3(b)).  The
 * caller decides @a more from what it can read of the line (see
 * ms_metadata_stamped).  A different row's pending value is left alone.
 * An identity that does not fit (see md_chunk_feed) is ignored:
 * md_chunk_feed refuses every piece of such a row anyway.
 */
extern void md_chunk_abandon(struct md_chunk *c, const char *account,
                              const char *stamp, const char *key, int more);

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

/** Bounded top-N-by-stamp selection (fix round 1, 2026-11-02): where a
 * new row's stamp belongs among the up to @a cap rows a caller is
 * keeping, newest first out of however many a full account walk visits
 * -- the same "keep the newest, evict the oldest" shape
 * mdsync_marker_cb (ircd/metadata_sync.c) already uses for read
 * markers, generalized to compare by struct md_stamp (md_stamp_cmp)
 * instead of a timestamp string, and factored out here, pure, so it is
 * cmocka-testable on its own.
 *
 * This function touches no memory of its own: @a kept is read-only,
 * ascending by stamp (index 0 = oldest), length @a count. It decides
 * only WHERE @a incoming's stamp would land; the caller -- which alone
 * knows the shape of the payload (key, value, visibility, tombstone
 * flag) riding alongside each stamp -- performs the identical shift on
 * ITS OWN parallel array using the returned index, then writes the new
 * payload there (and, when @a count < @a cap, increments it):
 *
 *   - @a count < @a cap (room to spare): returns the insertion index
 *     in [0, count] among the ascending kept stamps; the caller shifts
 *     kept[idx..count-1] up by one to open the slot.
 *   - @a count == @a cap and @a incoming is not newer than kept[0] (the
 *     current oldest/smallest, ties included): returns -1 -- discard,
 *     the caller's array is left untouched.
 *   - @a count == @a cap and @a incoming IS newer than kept[0]: returns
 *     the index in [0, cap) incoming's payload belongs at once the
 *     caller has shifted kept[0..idx-1] down by one (evicting the old
 *     kept[0]).
 *
 * @param[in] kept Ascending-by-stamp array of the rows currently held.
 * @param[in] count Number of entries in @a kept (0 <= count <= cap).
 * @param[in] cap Capacity of the caller's array (> 0).
 * @param[in] incoming The candidate row's stamp.
 * @return an insertion index as described above, or -1 to discard.
 */
extern int md_topn_place(const struct md_stamp *kept, int count, int cap,
                         const struct md_stamp *incoming);

/** md_topn_place plus the bookkeeping, over an index array instead of
 * the payloads (push-2 final fix wave, M-4): the caller keeps its
 * payloads (key, value, visibility, tombstone) in a pool of @a cap
 * slots that never move, and @a slot[i] names the pool slot of the row
 * at ordered position i.  This shifts only @a kept (the stamps) and
 * @a slot, never a payload, and returns the pool slot the caller writes
 * @a incoming's payload into:
 *
 *   - below the cap, the next unused slot (*@a count before the call;
 *     the slots in use are always 0..count-1), and *@a count grows;
 *   - at the cap, the slot of the row it evicts (the oldest, kept[0]);
 *   - -1 when @a incoming is not newer than the oldest kept row (ties
 *     included), or on a bad argument: nothing changes.
 *
 * @param[in,out] kept Ascending-by-stamp stamps of the rows held.
 * @param[in,out] slot Pool slot of each held row, by ordered position.
 * @param[in,out] count Number of rows held (0 <= *count <= cap).
 * @param[in] cap Capacity of @a kept, @a slot and the caller's pool.
 * @param[in] incoming The candidate row's stamp.
 * @return the pool slot to fill, or -1 to discard.
 */
extern int md_topn_insert(struct md_stamp *kept, int *slot, int *count,
                          int cap, const struct md_stamp *incoming);

/** Does an account-store row with key @a key travel between servers
 * (pull replies, burst rows) and belong to a user's METADATA CLEAR?
 * (push-2 final fix wave, M-2.)  Not the internal keys:
 *   - "last_present" (any case): each server's own observation of when
 *     the account was last present, a TTL row account_conn.c writes and
 *     reads locally;
 *   - any key the wire validator refuses (md_wire_key_valid).
 * @return 1 if @a key is replicated, 0 if it stays on this server.
 */
extern int md_key_replicable(const char *key);

#endif /* INCLUDED_metadata_lww_h */
