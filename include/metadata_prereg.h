/*
 * IRC - Internet Relay Chat, include/metadata_prereg.h
 *
 * What a client's before-connect METADATA writes do to its account when it
 * logs in during registration (draft/metadata-2: the registration burst
 * carries "any metadata stored by the server or by services, plus any
 * metadata set by the client during connection registration").
 *
 * The rule (owner, 2026-11-13): a key the client set before registration
 * wins over the account's stored value for that key, applied as if the
 * client had sent the same METADATA SET right after logging in -- stored on
 * the account, sent to the network, announced to subscribers, in the
 * registration burst.  Keys it did not touch come from the account.  It is
 * applied once, when registration ends, only for a client that ends it
 * metadata-aware (the metadata capability and batch) and logged in.
 *
 * Each write carries the stamp it was given when its SET was accepted
 * (one event, one time): the account's row for the key wins instead when
 * it is newer by the cross-server LWW rule (md_lww_take) -- another write
 * made after the client's SET.  A write the account here already reads
 * (the same value, or a delete of a key it does not hold) still goes into
 * the store and to every fork peer under the SET's stamp, as the SET after
 * login would: a peer may hold an older write this server missed, and the
 * login's own pull of the account's rows would otherwise bring it back.
 *
 * No ircd dependencies, so the cmocka suite
 * (ircd/test/metadata_prereg_cmocka.c) compiles it standalone, the merge
 * loop included (md_prereg_merge(), its outward calls through ops).
 */
#ifndef INCLUDED_metadata_prereg_h
#define INCLUDED_metadata_prereg_h

#ifndef INCLUDED_metadata_lww_h
#include "metadata_lww.h"
#endif

/** Key buffer size of a note (metadata.h's METADATA_KEY_LEN). */
#define MD_PREREG_KEY_LEN 64
/** Largest stored value read back (metadata.h's METADATA_VALUE_LEN). */
#define MD_PREREG_VALUE_LEN 1024

/** One METADATA write a client of ours made to itself before registration
 * (before-connect): the last write per key, in the order of those last
 * writes (cli_metadata_prereg).  Kept beside its in-memory list (which a
 * login during registration replaces with the account's rows) until
 * registration ends. */
struct MetadataPrereg {
  char key[MD_PREREG_KEY_LEN];          /**< Key name */
  char *value;                          /**< Value, or NULL: a delete */
  int visibility;                       /**< Visibility level of a set */
  struct md_stamp st;                   /**< When its SET was accepted */
  struct MetadataPrereg *next;          /**< Next write */
};

/** What happens to one before-connect write at the merge. */
enum md_prereg_verdict {
  MD_PREREG_APPLY = 0,    /**< written to the account, as a SET after login:
                           *   stored, the account's connections and
                           *   subscribers told, sent to every fork peer */
  MD_PREREG_STAMP,        /**< the account here already reads this (the same
                           *   value; a delete of a key it does not hold) under
                           *   an older stamp or none: stored and sent under
                           *   the SET's stamp, nobody told (nothing changed
                           *   for anyone here) */
  MD_PREREG_SAME,         /**< the account holds exactly this under a stamp
                           *   no older than the SET's: nothing */
  MD_PREREG_ABSENT,       /**< a delete of a key already deleted here, no
                           *   earlier than the SET: nothing */
  MD_PREREG_SUPERSEDED,   /**< the account's row is newer than the SET (a
                           *   write made after it): the row stands */
  MD_PREREG_LIMIT_KEYS,   /**< a new key the account has no room for
                           *   (METADATA_MAX_KEYS): refused, reported */
  MD_PREREG_LIMIT_VALUE,  /**< the value is over METADATA_MAX_VALUE_BYTES
                           *   (lowered by a rehash since the SET): refused,
                           *   reported */
  MD_PREREG_ERROR         /**< the store failed: reported */
};

/** Whether a client's before-connect writes are merged into its account
 * when registration ends: only when it is logged in then AND ends
 * registration metadata-aware.  A client that is not metadata-aware never
 * was (its writes are discarded); one with no account keeps them as its
 * own, as before.
 * @return non-zero to merge. */
extern int md_prereg_should_merge(int logged_in, int metadata_aware);

/** One before-connect write @a w (a tombstone is a delete) against the
 * account's row for the same key, @a stored (NULL: no row; a tombstone:
 * deleted).  Applied in the order the client sent them (the last write
 * per key), so @a user_keys -- the account's user-managed key count,
 * updated here for each APPLY that adds or removes a live key -- carries
 * from one to the next, as a SET after another would see it.
 * Order of the checks: what the account here already reads (STAMP when
 * the SET is the newer, else nothing), then the LWW rule, then the limits.
 * @param[in] stored The account's row, or NULL.
 * @param[in] w The write, its stamp the time its SET was accepted.
 * @param[in] no_row_is_state Non-zero for a key whose having no row is a
 *   state of its own (a mode-synced key: no row leaves a connection's
 *   default mode, a tombstone turns the mode off), so a delete of it with
 *   no row changes what the account's connections are: APPLY.
 * @param[in,out] user_keys The account's user-managed key count.
 * @param[in] max_keys METADATA_MAX_KEYS (negative: 0).
 * @param[in] max_value_bytes METADATA_MAX_VALUE_BYTES.
 * @return the verdict (never MD_PREREG_ERROR). */
extern enum md_prereg_verdict md_prereg_decide(const struct md_version *stored,
                                               const struct md_version *w,
                                               int no_row_is_state,
                                               int *user_keys, int max_keys,
                                               size_t max_value_bytes);

/** The merge's outward calls, made for each write in order. */
struct md_prereg_ops {
  /** The account's row for @a key into @a out (value in @a valbuf of
   * @a vlen bytes): 0 a row (live or tombstone), 1 none, -1 error.  NULL:
   * no store (every key reads as no row). */
  int (*row)(void *ctx, const char *key, struct md_version *out,
             char *valbuf, size_t vlen);
  /** Store @a w under its own stamp by the LWW rule: 1 written, 0 the
   * stored row kept, -1 error.  NULL: no store. */
  int (*store)(void *ctx, const char *key, const struct md_version *w);
  /** The account's connections here and the subscribers who may see the
   * key: it changed (APPLY only). */
  void (*apply)(void *ctx, const char *key, const struct md_version *w);
  /** Every fork peer: the row (APPLY and STAMP). */
  void (*send)(void *ctx, const char *key, const struct md_version *w);
  /** The client: the write was refused (LIMIT_KEYS, LIMIT_VALUE) or the
   * store failed (ERROR). */
  void (*refuse)(void *ctx, const char *key, enum md_prereg_verdict why);
  /** Non-zero when @a key's having no row is a state of its own
   * (md_prereg_decide()'s no_row_is_state).  NULL: never. */
  int (*no_row_is_state)(void *ctx, const char *key);
};

/** Merge the before-connect writes @a list into the account: each write
 * in order, md_prereg_decide() against ops->row, then for APPLY
 * store + apply + send, for STAMP store + send, for a refusal refuse.  A
 * store that keeps its own row (another write landed since the decision)
 * sends and tells nothing.
 * @param[in] list The writes.
 * @param[in] user_keys The account's user-managed key count.
 * @param[in] max_keys METADATA_MAX_KEYS (INT_MAX: no cap to apply).
 * @param[in] max_value_bytes METADATA_MAX_VALUE_BYTES.
 * @param[in] ops The outward calls.
 * @param[in] ctx Passed to every call.
 * @return the number of writes applied (APPLY). */
extern int md_prereg_merge(const struct MetadataPrereg *list, int user_keys,
                           int max_keys, size_t max_value_bytes,
                           const struct md_prereg_ops *ops, void *ctx);

/** Whether one more note fits: a new note for @a key (one not noted yet;
 * a key already noted is replaced, which may move it from sets to deletes)
 * is refused when the notes of its kind -- sets, or deletes -- already
 * number @a max_keys.  The account never holds more than METADATA_MAX_KEYS
 * user keys, so no more sets or deletes than that can matter; the bound on
 * what a registering client can make us keep.
 * @param[in] list The notes.
 * @param[in] key The key written.
 * @param[in] is_delete Non-zero for a delete.
 * @param[in] max_keys METADATA_MAX_KEYS (negative: 0).
 * @return non-zero if it fits. */
extern int md_prereg_fits(const struct MetadataPrereg *list, const char *key,
                          int is_delete, int max_keys);

/** Whether deletes of all @a n keys @a keys (distinct) fit at once, under
 * md_prereg_fits()'s bound -- a CLEAR before registration, recorded in
 * full or not at all.
 * @return non-zero if they fit. */
extern int md_prereg_deletes_fit(const struct MetadataPrereg *list,
                                 const char *const *keys, int n, int max_keys);

#endif /* INCLUDED_metadata_prereg_h */
