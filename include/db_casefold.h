/** @file db_casefold.h
 * @brief Case-folded store keys: the fold helpers every key builder
 *        uses, and the one-time rewrite of stores written before the
 *        builders folded.
 *
 * Channel, nick and account names are case-insensitive under the ircd
 * casemapping (rfc1459: "#Linux", "#linux" and "#LINUX" are one
 * channel, and so are "#a[b]" and "#a{b}"), but a key-value store
 * compares bytes.  Writers key rows under whatever spelling they hold
 * (the channel's creation spelling, the account's canonical case) and
 * readers arrive with the client's spelling, so every key builder that
 * embeds a name folds it with ToLower before the key touches the
 * store.  A lookup then matches regardless of who typed what, a
 * channel re-created in a different case keeps its rows, and the two
 * sides of a netsplit that created a channel under different spellings
 * key the same rows.
 *
 * Keys are NUL-separated components; only the components that carry a
 * name are folded.  A msgid or a timestamp is case-sensitive data and
 * stays as written.
 *
 * db_casefold_migrate rewrites the keys of an existing store once, at
 * open, before anything reads it: every row whose key is not in folded
 * form is moved to the folded key.  It marks the env when done and is
 * a no-op afterwards.  It is also idempotent without the marker, so an
 * interrupted run is simply resumed at the next open.
 */
#ifndef INCLUDED_db_casefold_h
#define INCLUDED_db_casefold_h

#ifndef INCLUDED_stddef_h
#include <stddef.h>
#define INCLUDED_stddef_h
#endif

struct db_env;
struct db_cf;

/** Every component of the key is a name. */
#define DB_CASEFOLD_ALL 0xFFFFFFFFu

/** Fold @a n bytes of @a src into @a dst with the ircd casemapping.
 * @a dst may equal @a src. */
extern void db_casefold_bytes(char *dst, const char *src, size_t n);

/** Copy @a key to @a out, folding the NUL-separated components whose
 * bit is set in @a mask (bit i = component i; components past bit 31
 * fold only under DB_CASEFOLD_ALL).
 * @return the key length, or -1 if @a outsz cannot hold it. */
extern int db_casefold_key(unsigned int mask, const void *key, size_t klen,
                           char *out, size_t outsz);

/** One column family to migrate: its handle, a name for the log, and
 * the component mask its key builder folds. */
struct db_casefold_cf {
  struct db_cf *cf;
  const char   *name;
  unsigned int  mask;
};

/** Move every row of @a cfs whose key is not in folded form to its
 * folded key.  Runs once per env (marker row in the env's default
 * column family); later calls return at once.  When a row already
 * exists at the folded key it is kept and the unfolded duplicate is
 * dropped.  Rows move in bounded batches, so memory stays flat on any
 * store size.
 * @param env   The environment; @a cfs must already be open in it.
 * @param label Env name for the log ("history", "metadata").
 * @return 0 when the store is in folded form (migrated now or before),
 *         -1 on a storage error (no marker written; the next open
 *         retries, every step being idempotent). */
extern int db_casefold_migrate(struct db_env *env, const char *label,
                               const struct db_casefold_cf *cfs,
                               size_t ncfs);

#endif /* INCLUDED_db_casefold_h */
