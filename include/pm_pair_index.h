/*
 * IRC - Internet Relay Chat, include/pm_pair_index.h
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
 * @brief The PM pairs each identity takes part in (W5 Task 11): the
 *   pm_pairs column family of the history env.
 *
 * A PM conversation is stored under the pair key "a:b" (the two parties'
 * identities -- an account, or for an unauthenticated party a session id
 * -- in casemapping order).  TARGETS lists a requester's own targets, so
 * it needs the pairs one identity is a half of without walking every
 * target on the server.  This index holds one row per half of every pair:
 *
 *   key   "<identity>\0<pair key>", both components folded through
 *         db_casefold_bytes (the targets CF keys the pair folded too);
 *   value "1".
 *
 * The pair's stamp stays in the targets CF; a walk here yields pair keys
 * and the caller reads each stamp there (an index row whose pair has no
 * targets row is an orphan and is skipped, and the next rebuild drops it).
 *
 * No ircd dependency beyond the db_* API and db_casefold: unit-tested on
 * the in-memory store (ircd/test/pm_pair_index_cmocka.c).
 */
#ifndef INCLUDED_pm_pair_index_h
#define INCLUDED_pm_pair_index_h

#ifndef INCLUDED_stddef_h
#include <stddef.h>
#define INCLUDED_stddef_h
#endif

struct db_env;
struct db_cf;
struct db_writebatch;

/** Room for any index key: a session-id identity (<= 39 bytes), the NUL,
 * and a pair key of two session ids (<= 81 bytes); with slack. */
#define PM_PAIR_INDEX_KEYLEN 160

/** Rows staged per batch by pm_pair_index_rebuild. */
#define PM_PAIR_INDEX_BATCH 1000

/** Is @a pair (@a len bytes) a PM pair key: exactly one ':', both halves
 * non-empty, and not a channel name (no leading '#' or '&')?
 * @param[out] colon The offset of the ':' (may be NULL).
 * @return 0 for a pair key, -1 otherwise. */
extern int pm_pair_split(const char *pair, size_t len, size_t *colon);

/** Build the index key "<identity>\0<pair key>", both folded.
 * @return The key length, or -1 if it does not fit @a outsz. */
extern int pm_pair_index_key(char *out, size_t outsz,
                             const char *identity, size_t ilen,
                             const char *pair, size_t plen);

/** Stage the pair's two rows (one under each half) on @a wb.
 * @return 0, or -1 (not a pair key, or a staging error). */
extern int pm_pair_index_stage(struct db_writebatch *wb, struct db_cf *idx,
                               const char *pair, size_t plen);

/** Stage the deletes of the pair's two rows on @a wb.
 * @return 0, or -1 (not a pair key, or a staging error). */
extern int pm_pair_index_unstage(struct db_writebatch *wb, struct db_cf *idx,
                                 const char *pair, size_t plen);

/** Called with each pair key of a walk (folded, not NUL-terminated);
 * nonzero stops the walk. */
typedef int (*pm_pair_fn)(const char *pair, size_t plen, void *ctx);

/** Call @a fn with every pair key @a identity (any case) is a half of,
 * in key order.
 * @return The pairs walked, or -1 on a storage error. */
extern int pm_pair_index_walk(struct db_env *env, struct db_cf *idx,
                              const char *identity, pm_pair_fn fn, void *ctx);

/** Bring the index in line with @a targets: a row under each half of every
 * pair key there, and no row whose pair key is gone.  Writes only what is
 * missing or orphaned, in batches of at most PM_PAIR_INDEX_BATCH rows.
 * Runs at every open (an older build opens the CF and ignores it, so a
 * downgrade and re-upgrade leaves it behind).
 * @return 0, or -1 on a storage error (whole batches committed before it
 *         stay; every step is idempotent, so the next open completes it). */
extern int pm_pair_index_rebuild(struct db_env *env, struct db_cf *targets,
                                 struct db_cf *idx);

#endif /* INCLUDED_pm_pair_index_h */
