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
 * made after the client's SET.
 *
 * No ircd dependencies, so the cmocka suite
 * (ircd/test/metadata_prereg_cmocka.c) compiles it standalone.
 */
#ifndef INCLUDED_metadata_prereg_h
#define INCLUDED_metadata_prereg_h

#ifndef INCLUDED_metadata_lww_h
#include "metadata_lww.h"
#endif

/** What happens to one before-connect write at the merge. */
enum md_prereg_verdict {
  MD_PREREG_APPLY = 0,    /**< written to the account, as a SET after login */
  MD_PREREG_SAME,         /**< the account holds exactly this (value and
                           *   visibility): nothing written or announced */
  MD_PREREG_ABSENT,       /**< a delete of a key the account does not hold:
                           *   nothing */
  MD_PREREG_SUPERSEDED,   /**< the account's row is newer than the SET (a
                           *   write made after it): the row stands */
  MD_PREREG_LIMIT_KEYS,   /**< a new key the account has no room for
                           *   (METADATA_MAX_KEYS): refused, reported */
  MD_PREREG_LIMIT_VALUE   /**< the value is over METADATA_MAX_VALUE_BYTES
                           *   (lowered by a rehash since the SET): refused,
                           *   reported */
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
 * Order of the checks: an identical value or an absent delete first
 * (nothing to do), then the LWW rule, then the limits.
 * @param[in] stored The account's row, or NULL.
 * @param[in] w The write, its stamp the time its SET was accepted.
 * @param[in,out] user_keys The account's user-managed key count.
 * @param[in] max_keys METADATA_MAX_KEYS (negative: 0).
 * @param[in] max_value_bytes METADATA_MAX_VALUE_BYTES.
 * @return the verdict. */
extern enum md_prereg_verdict md_prereg_decide(const struct md_version *stored,
                                               const struct md_version *w,
                                               int *user_keys, int max_keys,
                                               size_t max_value_bytes);

#endif /* INCLUDED_metadata_prereg_h */
