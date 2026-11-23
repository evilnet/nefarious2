/*
 * metadata_store_cmocka.c - the metadata store's account reads, on the
 * REAL ../metadata.o over the in-memory storage fake (fake_db.o).
 *
 *  - metadata_account_has_rows(): METADATA GET's test of an offline
 *    target.  It must say "yes" for exactly the accounts
 *    metadata_account_list() returns a row for -- every case below asks
 *    both -- while stopping at the first such row: no walk of the rest.
 *  - metadata_account_purge_expired(): each purge it runs is governed by
 *    its own setting -- the tombstones by METADATA_TOMBSTONE_TTL, whatever
 *    METADATA_CACHE_TTL says.
 *
 * metadata_lmdb_init() opens its environment with db_env_open(), which
 * the fake refuses (it has no on-disk env): the link wraps it
 * (-Wl,--wrap=db_env_open) to hand out a fake environment instead, and
 * db_iter_next() is wrapped to count the steps a read takes.  The
 * rest of the ircd metadata.o reaches is named at the end of this file;
 * none of it is on the paths under test.
 */
#include "config.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

#include "client.h"
#include "crdt_hlc.h"
#include "db_cursor.h"
#include "db_env.h"
#include "db_txn.h"
#include "db_types.h"
#include "fake_db.h"
#include "ircd.h"
#include "ircd_features.h"
#include "metadata.h"
#include "metadata_lww.h"
#include "metadata_sync.h"

/* ------------------------------------------------------------------ */
/* The settings and the clock                                          */
/* ------------------------------------------------------------------ */

time_t CurrentTime = 1700000000;
static int cache_ttl;             /**< METADATA_CACHE_TTL */
static int tombstone_ttl;         /**< METADATA_TOMBSTONE_TTL */

int feature_int(enum Feature feat)
{
  switch (feat) {
  case FEAT_METADATA_CACHE_TTL:     return cache_ttl;
  case FEAT_METADATA_TOMBSTONE_TTL: return tombstone_ttl;
  case FEAT_METADATA_MAX_KEYS:      return 20;
  default:                          return 0;
  }
}

int feature_bool(enum Feature feat) { return 0; }

/* ------------------------------------------------------------------ */
/* The store                                                           */
/* ------------------------------------------------------------------ */

static struct db_env *env;

int __wrap_db_env_open(const char *path, const struct db_env_opts *opts,
                       unsigned int max_cfs, struct db_env **out)
{
  env = fake_db_new();
  *out = env;
  return env ? DB_OK : DB_ERR_OTHER;
}

void db_cf_close(struct db_env *e, struct db_cf *cf) {}

const char *db_strerror(int rc) { return "fake"; }

/* Every step of an iterator metadata.o takes (-Wl,--wrap=db_iter_next). */
static unsigned int steps;
int __real_db_iter_next(struct db_iter *it);
int __wrap_db_iter_next(struct db_iter *it)
{
  steps++;
  return __real_db_iter_next(it);
}

static struct db_cf *cf_named(const char *name)
{
  struct db_cf *cf = NULL;

  assert_int_equal(db_cf_open(env, name, NULL, &cf), DB_OK);
  return cf;
}

/** Put one raw row: @a account \0 @a key -> @a value, in CF @a cfname. */
static void put_raw(const char *cfname, const char *account, const char *key,
                    const void *value, size_t vlen)
{
  struct db_writebatch *wb = db_writebatch_new(env);
  char k[512];
  size_t alen = strlen(account), klen = strlen(key);

  assert_true(alen + 1 + klen <= sizeof(k));
  memcpy(k, account, alen);
  k[alen] = '\0';
  memcpy(k + alen + 1, key, klen);
  assert_non_null(wb);
  assert_int_equal(db_writebatch_put(wb, cf_named(cfname), k, alen + 1 + klen,
                                     value, vlen), DB_OK);
  assert_int_equal(db_writebatch_commit(wb, 0), DB_OK);
  db_writebatch_destroy(wb);
}

static void put_value(const char *account, const char *key, const char *value)
{
  put_raw("metadata", account, key, value, strlen(value));
}

/** A clock row: live (a value row's stamp) or a tombstone. */
static void put_clock(const char *account, const char *key, uint64_t ms,
                      int tombstone)
{
  struct md_stamp st;
  char buf[MD_STAMP_BUFSIZE + 2];
  int n;

  memset(&st, 0, sizeof(st));
  st.ms = ms;
  st.node = 1;
  n = md_clock_encode(buf, sizeof(buf), &st, tombstone);
  assert_true(n > 0);
  put_raw("metadata_clock", account, key, buf, (size_t)n);
}

static int listed(const char *account)
{
  struct MetadataEntry *list = metadata_account_list(account), *e, *n;
  int any = list != NULL;

  for (e = list; e; e = n) {
    n = e->next;
    metadata_free_entry(e);
  }
  return any;
}

/** has_rows answers exactly what list does, and returns @a want. */
static void assert_has_rows(const char *account, int want)
{
  assert_int_equal(listed(account), want);
  assert_int_equal(metadata_account_has_rows(account), want);
}

static int setup(void **state)
{
  cache_ttl = 0;
  tombstone_ttl = 0;
  env = NULL;
  assert_int_equal(metadata_lmdb_init("unused"), 0);
  assert_non_null(env);
  return 0;
}

static int teardown(void **state)
{
  metadata_lmdb_shutdown();
  fake_db_free(env);
  env = NULL;
  return 0;
}

/* ------------------------------------------------------------------ */
/* metadata_account_has_rows                                           */
/* ------------------------------------------------------------------ */

/** A permanent row, a TTL row within its life, a legacy bare row. */
static void an_account_with_rows_has_rows(void **state)
{
  put_value("ann", "avatar", "T0|P:http://x/a.png");
  assert_has_rows("ann", 1);
  put_value("bob", "url", "T1699999990|http://x");
  cache_ttl = 100;
  assert_has_rows("bob", 1);
  put_value("cat", "bio", "legacy bare value");
  assert_has_rows("cat", 1);
}

/** Nothing under the name -- the neighbours' rows are not its own: a
 * name that is a prefix of another, or sorts just before or after it. */
static void an_account_without_rows_has_none(void **state)
{
  put_value("ann", "avatar", "T0|P:x");
  put_value("anna", "avatar", "T0|P:x");
  put_value("am", "avatar", "T0|P:x");
  assert_has_rows("an", 0);
  assert_has_rows("annb", 0);
  assert_has_rows("nobody", 0);
  assert_has_rows("ann", 1);
}

/** Tombstones live in the clock CF, never as value rows: an account whose
 * keys were all deleted has none. */
static void an_account_with_only_tombstones_has_none(void **state)
{
  put_clock("dan", "avatar", 1699999000000ULL, 1);
  put_clock("dan", "$cleared", 1699999000000ULL, 1);
  assert_has_rows("dan", 0);
}

/** A server-managed key is a row like any other (list does not filter
 * them), so it counts. */
static void a_server_managed_row_counts(void **state)
{
  put_value("eve", "draft/persistence/profile", "T0|x");
  assert_has_rows("eve", 1);
}

/** The name is folded, as the keys are. */
static void the_name_is_folded(void **state)
{
  put_value("ann", "avatar", "T0|P:x");
  assert_has_rows("ANN", 1);
  assert_has_rows("Ann", 1);
}

/** Rows list skips do not count -- an expired cache row, a value that does
 * not decode, a key too long for an entry -- and a skipped row first does
 * not hide a listed one after it. */
static void rows_list_skips_do_not_count(void **state)
{
  char longkey[METADATA_KEY_LEN + 8];

  memset(longkey, 'k', METADATA_KEY_LEN);
  longkey[METADATA_KEY_LEN] = '\0';

  cache_ttl = 100;
  put_value("fay", "a-old", "T1000|stale");     /* expired */
  put_value("fay", "b-bad", "T12x|value");      /* does not decode */
  put_value("fay", "c-bad", "T12");             /* no separator */
  put_raw("metadata", "fay", longkey, "T0|x", 4); /* key too long */
  assert_has_rows("fay", 0);

  put_value("fay", "z-live", "T0|x");           /* after all of them */
  assert_has_rows("fay", 1);

  /* The same rows with expiry off: the old one counts again. */
  cache_ttl = 0;
  assert_has_rows("fay", 1);
}

/** No store: no rows, and no crash. */
static void without_a_store_there_are_none(void **state)
{
  put_value("ann", "avatar", "T0|P:x");
  metadata_lmdb_shutdown();
  assert_has_rows("ann", 0);
  assert_has_rows(NULL, 0);
  assert_int_equal(metadata_lmdb_init("unused"), 0);   /* teardown's */
}

/** A name longer than any key prefix the store builds has none. */
static void an_overlong_name_has_none(void **state)
{
  char name[CHANNELLEN + 8];

  memset(name, 'n', CHANNELLEN + 1);
  name[CHANNELLEN + 1] = '\0';
  assert_has_rows(name, 0);
}

/** One seek: the first listed row ends it, however many follow (the
 * listing steps over every one of them). */
static void it_stops_at_the_first_row(void **state)
{
  struct db_cf *cf = cf_named("metadata");
  unsigned int opens, firsts;
  char key[16];
  int i;

  for (i = 0; i < 50; i++) {
    snprintf(key, sizeof(key), "key%02d", i);
    put_value("gus", key, "T0|x");
  }
  put_value("guy", "avatar", "T0|x");
  opens = fake_db_iter_opens(cf);
  firsts = fake_db_seek_firsts(cf);
  steps = 0;
  assert_int_equal(metadata_account_has_rows("gus"), 1);
  assert_int_equal(fake_db_iter_opens(cf), opens + 1);
  assert_int_equal(fake_db_seek_firsts(cf), firsts);
  assert_int_equal(steps, 0);
  assert_int_equal(listed("gus"), 1);
  assert_int_equal(steps, 50);
}

/* ------------------------------------------------------------------ */
/* metadata_account_purge_expired                                      */
/* ------------------------------------------------------------------ */

/** The tombstones go by METADATA_TOMBSTONE_TTL alone: with the cache
 * expiry off (METADATA_CACHE_TTL 0) an old one -- the CLEAR floor too --
 * is still purged, a young one kept. */
static void tombstones_are_purged_with_the_cache_expiry_off(void **state)
{
  struct db_cf *clock = cf_named("metadata_clock");

  cache_ttl = 0;
  tombstone_ttl = 3600;
  put_clock("hal", "avatar", (uint64_t)(CurrentTime - 7200) * 1000, 1);
  put_clock("hal", "$cleared", (uint64_t)(CurrentTime - 7200) * 1000, 1);
  put_clock("hal", "url", (uint64_t)(CurrentTime - 60) * 1000, 1);
  put_clock("hal", "bio", (uint64_t)(CurrentTime - 7200) * 1000, 0);  /* live */
  assert_int_equal(fake_db_rows(clock), 4);
  assert_int_equal(metadata_account_purge_expired(), 2);
  assert_int_equal(fake_db_rows(clock), 2);
}

/** METADATA_TOMBSTONE_TTL 0 keeps them all, whatever the cache expiry. */
static void tombstone_ttl_0_keeps_them(void **state)
{
  struct db_cf *clock = cf_named("metadata_clock");

  cache_ttl = 100;
  tombstone_ttl = 0;
  put_clock("ida", "avatar", 1000, 1);
  assert_int_equal(metadata_account_purge_expired(), 0);
  assert_int_equal(fake_db_rows(clock), 1);
}

/** The cache rows go by METADATA_CACHE_TTL alone. */
static void cache_rows_go_by_the_cache_ttl(void **state)
{
  struct db_cf *md = cf_named("metadata");

  put_value("jay", "old", "T1000|x");
  put_value("jay", "perm", "T0|x");
  cache_ttl = 0;
  tombstone_ttl = 3600;
  assert_int_equal(metadata_account_purge_expired(), 0);
  assert_int_equal(fake_db_rows(md), 2);
  cache_ttl = 100;
  assert_int_equal(metadata_account_purge_expired(), 1);
  assert_int_equal(fake_db_rows(md), 1);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test_setup_teardown(an_account_with_rows_has_rows, setup, teardown),
    cmocka_unit_test_setup_teardown(an_account_without_rows_has_none, setup, teardown),
    cmocka_unit_test_setup_teardown(an_account_with_only_tombstones_has_none, setup, teardown),
    cmocka_unit_test_setup_teardown(a_server_managed_row_counts, setup, teardown),
    cmocka_unit_test_setup_teardown(the_name_is_folded, setup, teardown),
    cmocka_unit_test_setup_teardown(rows_list_skips_do_not_count, setup, teardown),
    cmocka_unit_test_setup_teardown(without_a_store_there_are_none, setup, teardown),
    cmocka_unit_test_setup_teardown(an_overlong_name_has_none, setup, teardown),
    cmocka_unit_test_setup_teardown(it_stops_at_the_first_row, setup, teardown),
    cmocka_unit_test_setup_teardown(tombstones_are_purged_with_the_cache_expiry_off, setup, teardown),
    cmocka_unit_test_setup_teardown(tombstone_ttl_0_keeps_them, setup, teardown),
    cmocka_unit_test_setup_teardown(cache_rows_go_by_the_cache_ttl, setup, teardown),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}

/* ------------------------------------------------------------------ */
/* The rest of the ircd                                                */
/* ------------------------------------------------------------------ */

/* What metadata.o reaches beyond the store: the client side (memory,
 * notifications, replies), the clock, bouncer sessions.  The paths under
 * test reach none of it. */
static void never(const char *what) __attribute__((noreturn));
static void never(const char *what)
{
  print_error("%s() reached: not the store path under test\n", what);
  abort();
}

struct Client *GlobalClientList;
const char *batch_current_id(struct Client *cli) { never("batch_current_id"); }
struct BouncerSession *bounce_get_session(struct Client *cptr) { never("bounce_get_session"); }
int bounce_umode_flag_synced(int flag) { never("bounce_umode_flag_synced"); }
const char *get_visibility_str(struct MetadataEntry *entry) { never("get_visibility_str"); }
struct HLC hlc_global_event(void) { never("hlc_global_event"); }
int hlc_global_receive(const struct HLC *remote, uint64_t max_forward_ms, uint64_t *ahead_ms) { never("hlc_global_receive"); }
uint64_t hlc_max_forward_ms(void) { never("hlc_max_forward_ms"); }
void mdsync_on_attach(struct Client *cptr, const char *account) { never("mdsync_on_attach"); }
void metadata_emit_versioned(struct Client *src, struct Client *one, struct Client *butone, const char *account, const char *key, const struct md_version *v) { never("metadata_emit_versioned"); }
void metadata_notify_subscribers_butone(const char *target, const char *key, const char *value, int visibility, struct Client *butone) { never("metadata_notify_subscribers_butone"); }
void send_batch_end(struct Client *to) { never("send_batch_end"); }
int send_batch_start(struct Client *to, const char *type) { never("send_batch_start"); }
void send_fail(struct Client *to, const char *command, const char *code, const char *context, const char *description) { never("send_fail"); }
void sendrawto_one(struct Client *to, const char *pattern, ...) { never("sendrawto_one"); }
int send_reply(struct Client *to, int reply, ...) { never("send_reply"); }
int umode_class_default(struct Client *cptr, int flag) { never("umode_class_default"); }
void umode_sync_apply(struct Client *cptr, int flag, int on) { never("umode_sync_apply"); }
void umode_sync_apply_butone(struct Client *cptr, int flag, int on, struct Client *untold) { never("umode_sync_apply_butone"); }
