/*
 * IRC - Internet Relay Chat, include/sessid_index.h
 *
 * A pure (no ircd dependencies) session-id -> owner index.  One id can
 * name several owners at once -- a bouncer primary and its aliases, or
 * two kept-apart sessions that briefly share an id -- so the index is a
 * multimap: insertion order within one key is unspecified, and callers
 * decide what a multi-match means.
 *
 * Each indexed owner supplies its own storage node (struct SessidLink),
 * normally embedded in the owning struct (list.c embeds one in struct
 * Client as cli_sesslink).  The node records which key it is filed
 * under so sessid_index_unlink() can find its chain without the caller
 * re-deriving the key from state that may already have changed (the
 * Client's cli_session_id field, say).
 *
 * No ircd dependencies, so the cmocka suite
 * (ircd/test/sessid_index_cmocka.c) compiles it standalone; list.c
 * (client_set_session_id / client_find_by_session_id) is the ircd-aware
 * wrapper that ties it to struct Client.
 */
#ifndef INCLUDED_sessid_index_h
#define INCLUDED_sessid_index_h

#ifndef INCLUDED_sys_types_h
#include <sys/types.h>         /* size_t */
#define INCLUDED_sys_types_h
#endif

/** Key buffer size: == S2S_SESSID_BUFSIZE (client.h), checked by a
 * static assertion in list.c so the two never drift apart. */
#define SESSID_INDEX_KEYLEN 40

/** One owner's filing in the index.  Zero-initialized is a valid,
 * unlinked state (sl_linked == 0); sessid_index_unlink() on a
 * zero-initialized link is a no-op. */
struct SessidLink {
  struct SessidLink *sl_next;        /**< Next node in this key's chain. */
  void               *sl_owner;      /**< Caller-supplied owner pointer. */
  char                sl_key[SESSID_INDEX_KEYLEN]; /**< The key this node
                                           is filed under (empty = not
                                           filed). */
  unsigned char       sl_linked;      /**< Nonzero while filed in a chain. */
};

/** File (or re-file) @a link under @a key, owned by @a owner.
 *
 * Unlinks @a link from its current chain first if it is already linked
 * (using the key it was filed under, not @a key).  Always copies @a key
 * into @a link regardless of outcome.  Links @a link into @a key's
 * chain only when @a key is non-empty -- an empty key is deliberately
 * not indexed, so a client with no session id yet (or one explicitly
 * cleared) never matches a lookup.
 *
 * Calling this twice with the same @a key is idempotent: the first call
 * unlinks nothing (not yet linked) and links; the second finds @a link
 * already linked under the same key, unlinks, copies the identical key
 * back in, and re-links -- a wasted walk, not a bug.
 *
 * @param[in,out] link   Storage node (caller-owned, typically embedded).
 * @param[in]     owner  Opaque owner pointer stored in the node.
 * @param[in]     key    Key to file under (NULL treated as empty).
 */
extern void sessid_index_set(struct SessidLink *link, void *owner,
                              const char *key);

/** Remove @a link from the index if it is currently linked.
 * A no-op (never dereferences @a link's chain pointers) when
 * sl_linked is already 0 -- including a freshly zero-initialized or
 * never-set link.
 * @param[in,out] link  Storage node to remove.
 */
extern void sessid_index_unlink(struct SessidLink *link);

/** Find every owner currently filed under @a key.
 *
 * Exact, case-sensitive match against the key each node is filed
 * under.  Fills @a owners with up to @a max owner pointers (in the
 * chain's order, which is unspecified) but always returns the total
 * number of owners filed under @a key, even when that exceeds @a max --
 * the same "fill truncated, count exact" contract as ircd_strncpy's
 * return value, but for element count rather than bytes.
 *
 * @param[in]  key     Key to look up (NULL or empty always matches
 *                      nothing: empty keys are never indexed).
 * @param[out] owners  Array to fill, or NULL (with @a max treated as 0)
 *                      to just count.
 * @param[in]  max     Capacity of @a owners.
 * @return Total number of owners filed under @a key.
 */
extern size_t sessid_index_find(const char *key, void **owners, size_t max);

/** Count owners filed under @a key for which @a pred returns nonzero,
 * without needing storage for the owner pointers themselves.
 *
 * This is the filtered counterpart to sessid_index_find(key, NULL, 0):
 * that call counts every owner under @a key; this one counts only
 * those @a pred accepts (e.g. "is this owner a live IsUser client").
 * Walks the same chain once; @a pred is invoked only for owners whose
 * node is filed under @a key, in the chain's (unspecified) order.
 *
 * @param[in] key   Key to look up.
 * @param[in] pred  Predicate invoked with each matching owner; returns
 *                  nonzero to count it. Must not be NULL.
 * @return Count of owners under @a key for which @a pred returned
 *         nonzero.
 */
extern size_t sessid_index_count_if(const char *key,
                                     int (*pred)(void *owner));

#endif /* INCLUDED_sessid_index_h */
