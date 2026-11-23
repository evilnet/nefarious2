/*
 * metadata_store_cmocka.c - the metadata store, on the REAL ../metadata.o
 * over the in-memory storage fake (fake_db.o).
 *
 *  - metadata_account_purge_expired(): each purge it runs is governed by
 *    its own setting -- the tombstones by METADATA_TOMBSTONE_TTL, whatever
 *    METADATA_CACHE_TTL says.  The periodic callback (ircd.c) runs it
 *    whenever the store is up and leaves those decisions to it.
 *
 * metadata_lmdb_init() opens its environment with db_env_open(), which
 * the fake refuses (it has no on-disk env): the link wraps it
 * (-Wl,--wrap=db_env_open) to hand out a fake environment instead.  The
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
