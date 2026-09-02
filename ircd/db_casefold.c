/** @file db_casefold.c
 * @brief Case-folded store keys (see db_casefold.h).
 *
 * The rewrite walks each column family on an iterator, which reads the
 * store as it was when the iterator opened, so the folded rows it
 * writes are never revisited.  Collision checks read the live store,
 * so a row moved in an earlier batch is seen by a later one.  Two
 * unfolded rows in one batch that fold to the same key land in key
 * order and the later one wins; a row that already sits at the folded
 * key wins over both.
 *
 * Dependency-light on purpose: only the db_* abstraction, the
 * casemapping table and log_write, so the cmocka suite can run it
 * against an in-memory fake of the store.
 */
#include "config.h"

#include "db_casefold.h"
#include "db_cursor.h"
#include "db_env.h"
#include "db_txn.h"
#include "db_types.h"
#include "ircd_chattr.h"
#include "ircd_log.h"

#include <limits.h>
#include <string.h>

/** Marker row in the env's default column family. */
#define CASEFOLD_MARKER_KEY "schema/casefold"
#define CASEFOLD_MARKER_VAL "1"
/** Commit after this many staged operations. */
#define CASEFOLD_BATCH_OPS 512
/** Longest key the rewrite handles; longer keys are left in place. */
#define CASEFOLD_MAX_KEY 2048
/** Collisions logged one by one before only the count is kept. */
#define CASEFOLD_LOG_COLLISIONS 20

void db_casefold_bytes(char *dst, const char *src, size_t n)
{
  size_t i;

  /* ToLower indexes its table from CHAR_MIN, i.e. by a plain char.  The
   * bytes go in as char: an unsigned char above 127 would index past
   * the table. */
  for (i = 0; i < n; i++)
    dst[i] = ToLower(src[i]);
}

int db_casefold_key(unsigned int mask, const void *key, size_t klen,
                    char *out, size_t outsz)
{
  const char *k = key;
  unsigned int comp = 0;
  int fold;
  size_t i;

  if (!key || !out || klen > outsz || klen > (size_t)INT_MAX)
    return -1;

  fold = (mask & 1u) != 0;
  for (i = 0; i < klen; i++) {
    if (k[i] == '\0') {
      out[i] = '\0';
      comp++;
      fold = (comp < 32) ? ((mask >> comp) & 1u) != 0
                         : (mask == DB_CASEFOLD_ALL);
    } else {
      out[i] = fold ? ToLower(k[i]) : k[i];
    }
  }
  return (int)klen;
}

/** Render a key for the log: NUL separators shown as '.', truncated. */
static const char *key_preview(const void *key, size_t klen,
                               char *buf, size_t bufsz)
{
  const char *k = key;
  size_t n = (klen < bufsz - 1) ? klen : bufsz - 1;
  size_t i;

  for (i = 0; i < n; i++)
    buf[i] = (k[i] == '\0') ? '.' : k[i];
  buf[n] = '\0';
  return buf;
}

/** @return 1 if the env is marked as folded, 0 if not, -1 on error. */
static int marker_present(struct db_env *env, struct db_cf *marker_cf)
{
  struct db_val v = { NULL, 0 };
  int present;
  int rc = db_get(env, marker_cf, CASEFOLD_MARKER_KEY,
                  sizeof(CASEFOLD_MARKER_KEY) - 1, NULL, &v);

  if (rc == DB_NOTFOUND)
    return 0;
  if (rc != DB_OK)
    return -1;
  present = (v.len == sizeof(CASEFOLD_MARKER_VAL) - 1
             && memcmp(v.base, CASEFOLD_MARKER_VAL, v.len) == 0);
  db_val_free(&v);
  return present;
}

/** Move one column family's unfolded rows.
 * @return 0, or -1 on a storage error (the batch in flight is dropped). */
static int migrate_cf(struct db_env *env, const char *label,
                      const struct db_casefold_cf *spec)
{
  struct db_iter *it;
  struct db_writebatch *wb;
  char folded[CASEFOLD_MAX_KEY];
  char preview[96];
  unsigned long seen = 0, moved = 0, collisions = 0, skipped = 0;
  int failed = 0;
  int rc;

  it = db_iter_open(env, spec->cf, NULL);
  if (!it)
    return -1;
  wb = db_writebatch_new(env);
  if (!wb) {
    db_iter_close(it);
    return -1;
  }

  for (rc = db_iter_seek_first(it);
       rc == DB_OK && db_iter_valid(it);
       rc = db_iter_next(it)) {
    size_t klen = 0, vlen = 0;
    const void *kbase = db_iter_key(it, &klen);
    const void *vbase = db_iter_value(it, &vlen);
    int erc;

    seen++;
    if (!kbase || klen == 0)
      continue;
    if (db_casefold_key(spec->mask, kbase, klen, folded, sizeof(folded)) < 0) {
      skipped++;
      continue;
    }
    if (memcmp(folded, kbase, klen) == 0)
      continue;   /* already in folded form */

    erc = db_exists(env, spec->cf, folded, klen, NULL);
    if (erc == DB_OK) {
      /* A row already lives at the folded key: keep it, drop this one. */
      collisions++;
      if (collisions <= CASEFOLD_LOG_COLLISIONS)
        log_write(LS_SYSTEM, L_WARNING, 0,
                  "casefold %s/%s: '%s' already exists in folded form; "
                  "dropping the unfolded duplicate", label, spec->name,
                  key_preview(kbase, klen, preview, sizeof(preview)));
      if (db_writebatch_del(wb, spec->cf, kbase, klen) != DB_OK) {
        failed = 1;
        break;
      }
    } else if (erc == DB_NOTFOUND) {
      if (db_writebatch_put(wb, spec->cf, folded, klen,
                            vbase ? vbase : "", vbase ? vlen : 0) != DB_OK
          || db_writebatch_del(wb, spec->cf, kbase, klen) != DB_OK) {
        failed = 1;
        break;
      }
      moved++;
    } else {
      failed = 1;
      break;
    }

    if (db_writebatch_count(wb) >= CASEFOLD_BATCH_OPS
        && db_writebatch_commit(wb, 0) != DB_OK) {
      failed = 1;
      break;
    }
  }

  /* The walk must have ended at the end of the CF, not on an error. */
  if (!failed && rc != DB_OK && rc != DB_NOTFOUND)
    failed = 1;

  if (!failed && db_writebatch_count(wb) > 0
      && db_writebatch_commit(wb, 0) != DB_OK)
    failed = 1;

  db_writebatch_destroy(wb);
  db_iter_close(it);

  if (failed) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "casefold %s/%s: storage error after %lu rows (%lu moved); "
              "retried at the next open", label, spec->name, seen, moved);
    return -1;
  }
  log_write(LS_SYSTEM, L_INFO, 0,
            "casefold %s/%s: %lu rows walked, %lu moved to folded keys, "
            "%lu unfolded duplicates dropped, %lu skipped",
            label, spec->name, seen, moved, collisions, skipped);
  return 0;
}

int db_casefold_migrate(struct db_env *env, const char *label,
                        const struct db_casefold_cf *cfs, size_t ncfs)
{
  struct db_cf *marker_cf = NULL;
  struct db_writebatch *wb;
  size_t i;
  int rc;

  if (!env)
    return -1;
  if (db_cf_open(env, "default", NULL, &marker_cf) != DB_OK || !marker_cf)
    return -1;

  rc = marker_present(env, marker_cf);
  if (rc < 0)
    return -1;
  if (rc > 0)
    return 0;

  for (i = 0; i < ncfs; i++) {
    if (!cfs[i].cf)
      continue;
    if (migrate_cf(env, label, &cfs[i]) != 0)
      return -1;
  }

  /* Durable marker: the sync also flushes the moves before it. */
  wb = db_writebatch_new(env);
  if (!wb)
    return -1;
  if (db_writebatch_put(wb, marker_cf, CASEFOLD_MARKER_KEY,
                        sizeof(CASEFOLD_MARKER_KEY) - 1,
                        CASEFOLD_MARKER_VAL,
                        sizeof(CASEFOLD_MARKER_VAL) - 1) != DB_OK
      || db_writebatch_commit(wb, 1) != DB_OK) {
    db_writebatch_destroy(wb);
    return -1;
  }
  db_writebatch_destroy(wb);

  log_write(LS_SYSTEM, L_INFO, 0,
            "casefold %s: store keys are in folded form", label);
  return 0;
}
