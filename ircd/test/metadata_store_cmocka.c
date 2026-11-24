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
 *  - the tombstones and the CLEAR floor live at least STALE_AFTER (the
 *    stale-data limit, stale_lifetime()) whatever METADATA_TOMBSTONE_TTL
 *    says, so a server back within the limit can still be told of the
 *    deletions it missed; METADATA_TOMBSTONE_TTL 0 still keeps them.
 *  - metadata_clock_seed(): at start-up the clock is moved past every
 *    stamp the store holds (within HLC_MAX_FORWARD_MS), so a write made
 *    right after a restart is never stamped below the row it replaces.
 *    The clock here is the REAL ../crdt_hlc.o.
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

#include "channel.h"
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
#include "stale.h"

/* ------------------------------------------------------------------ */
/* The settings and the clock                                          */
/* ------------------------------------------------------------------ */

time_t CurrentTime = 1700000000;
static int cache_ttl;             /**< METADATA_CACHE_TTL */
static int tombstone_ttl;         /**< METADATA_TOMBSTONE_TTL */
static int stale_after;           /**< STALE_AFTER */
static int max_forward;           /**< HLC_MAX_FORWARD_MS */

int feature_int(enum Feature feat)
{
  switch (feat) {
  case FEAT_METADATA_CACHE_TTL:     return cache_ttl;
  case FEAT_METADATA_TOMBSTONE_TTL: return tombstone_ttl;
  case FEAT_METADATA_MAX_KEYS:      return 20;
  case FEAT_HLC_MAX_FORWARD_MS:     return max_forward;
  default:                          return 0;
  }
}

int feature_bool(enum Feature feat) { return 0; }

/* ircd_features.c's accessor: the setting, clamped as it is there. */
time_t stale_limit(void) { return stale_limit_clamp(stale_after); }

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

/** A clock row with the whole stamp @a st: live or a tombstone. */
static void put_clock_st(const char *account, const char *key,
                         const struct md_stamp *st, int tombstone)
{
  char buf[MD_STAMP_BUFSIZE + 2];
  int n;

  n = md_clock_encode(buf, sizeof(buf), st, tombstone);
  assert_true(n > 0);
  put_raw("metadata_clock", account, key, buf, (size_t)n);
}

/** A clock row: live (a value row's stamp) or a tombstone. */
static void put_clock(const char *account, const char *key, uint64_t ms,
                      int tombstone)
{
  struct md_stamp st;

  memset(&st, 0, sizeof(st));
  st.ms = ms;
  st.node = 1;
  put_clock_st(account, key, &st, tombstone);
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
  stale_after = 60;   /* the smallest limit; the cases below that need
                       * another set it */
  max_forward = 0;    /* unbounded, as crdt_hlc reads 0 */
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

/* ------------------------------------------------------------------ */
/* STALE_AFTER: the tombstones and the floor live at least the limit    */
/* ------------------------------------------------------------------ */

#define DAY 86400

/** A tombstone younger than the limit is kept, though older than a
 * shorter METADATA_TOMBSTONE_TTL; one older than both is purged. */
static void a_tombstone_lives_at_least_the_limit(void **state)
{
  struct db_cf *clock = cf_named("metadata_clock");

  tombstone_ttl = 3600;
  stale_after = 14 * DAY;
  put_clock("kim", "avatar", (uint64_t)(CurrentTime - 7200) * 1000, 1);
  put_clock("kim", "url", (uint64_t)(CurrentTime - 13 * DAY) * 1000, 1);
  put_clock("kim", "$cleared", (uint64_t)(CurrentTime - 13 * DAY) * 1000, 1);
  put_clock("kim", "bio", (uint64_t)(CurrentTime - 15 * DAY) * 1000, 1);
  put_clock("kim", "$x", (uint64_t)(CurrentTime - 15 * DAY) * 1000, 1);
  assert_int_equal(metadata_account_purge_expired(), 2);
  assert_int_equal(fake_db_rows(clock), 3);
}

/** A METADATA_TOMBSTONE_TTL longer than the limit is kept as it is. */
static void a_longer_tombstone_ttl_is_kept(void **state)
{
  struct db_cf *clock = cf_named("metadata_clock");

  tombstone_ttl = 30 * DAY;
  stale_after = 14 * DAY;
  put_clock("lee", "avatar", (uint64_t)(CurrentTime - 20 * DAY) * 1000, 1);
  put_clock("lee", "url", (uint64_t)(CurrentTime - 31 * DAY) * 1000, 1);
  assert_int_equal(metadata_account_purge_expired(), 1);
  assert_int_equal(fake_db_rows(clock), 1);
}

/** METADATA_TOMBSTONE_TTL 0 still keeps them all, whatever the limit. */
static void tombstone_ttl_0_keeps_them_past_the_limit(void **state)
{
  struct db_cf *clock = cf_named("metadata_clock");

  tombstone_ttl = 0;
  stale_after = 60;
  put_clock("max", "avatar", (uint64_t)(CurrentTime - 100 * DAY) * 1000, 1);
  assert_int_equal(metadata_account_purge_expired(), 0);
  assert_int_equal(fake_db_rows(clock), 1);
}

/** A limit set below a minute is read as a minute. */
static void a_limit_below_a_minute_is_a_minute(void **state)
{
  struct db_cf *clock = cf_named("metadata_clock");

  tombstone_ttl = 1;
  stale_after = 1;
  put_clock("ned", "avatar", (uint64_t)(CurrentTime - 30) * 1000, 1);
  put_clock("ned", "url", (uint64_t)(CurrentTime - 61) * 1000, 1);
  assert_int_equal(metadata_account_purge_expired(), 1);
  assert_int_equal(fake_db_rows(clock), 1);
}

/** The CLEAR floor is in force for as long as its tombstone lives: past a
 * shorter METADATA_TOMBSTONE_TTL while younger than the limit, and it
 * still turns an older live write into a deletion; past both, neither. */
static void the_clear_floor_lives_at_least_the_limit(void **state)
{
  struct md_stamp floor;
  struct md_version in;

  tombstone_ttl = 3600;
  stale_after = 14 * DAY;
  put_clock("oz", "$cleared", (uint64_t)(CurrentTime - 13 * DAY) * 1000, 1);
  assert_true(metadata_account_floor_in_force("oz"));
  memset(&in, 0, sizeof(in));
  in.st.ms = (uint64_t)(CurrentTime - 20 * DAY) * 1000;
  in.st.node = 2;
  assert_true(metadata_floor_converts("oz", "avatar", &in, &floor));

  put_clock("pat", "$cleared", (uint64_t)(CurrentTime - 15 * DAY) * 1000, 1);
  assert_false(metadata_account_floor_in_force("pat"));
  assert_false(metadata_floor_converts("pat", "avatar", &in, &floor));

  /* METADATA_TOMBSTONE_TTL 0: for ever. */
  tombstone_ttl = 0;
  assert_true(metadata_account_floor_in_force("pat"));
}

/* ------------------------------------------------------------------ */
/* metadata_clock_seed: the clock starts past what the store holds      */
/* ------------------------------------------------------------------ */

/** Rows stamped ahead of the wall clock (a peer's clock this server had
 * adopted before it restarted): a stamp minted after the seed sorts after
 * every one of them -- the newest is a tombstone of another account, and
 * a channel's clock row lives in the same column family. */
static void the_clock_starts_past_every_stored_stamp(void **state)
{
  uint64_t now = hlc_wall_clock_ms();
  struct md_stamp a = { now + 10000, 3, 9 };
  struct md_stamp newest = { now + 30000, 7, 9 };
  struct md_stamp chan = { now + 20000, 0, 9 };
  struct md_stamp st;

  hlc_init(5);
  put_clock_st("ann", "avatar", &a, 0);
  put_clock_st("bob", "url", &newest, 1);
  put_clock_st("#chan", "topicx", &chan, 0);
  st = metadata_stamp_now();
  assert_true(md_stamp_cmp(&st, &newest) < 0);   /* the bug: below it */

  assert_int_equal(metadata_clock_seed(), 0);
  st = metadata_stamp_now();
  assert_true(md_stamp_cmp(&st, &newest) > 0);
  assert_int_equal(st.node, 5);
}

/** A stamp further ahead than HLC_MAX_FORWARD_MS (a store written under
 * a wrong clock) moves the clock no further than the bound -- the most
 * a peer's reading could move it. */
static void the_seed_is_bounded_like_a_peer(void **state)
{
  uint64_t before = hlc_wall_clock_ms(), after;
  struct md_stamp far = { before + 3600000, 0, 9 };
  struct md_stamp st;

  max_forward = 60000;
  hlc_init(5);
  put_clock_st("cat", "bio", &far, 0);
  assert_int_equal(metadata_clock_seed(), 0);
  st = metadata_stamp_now();
  after = hlc_wall_clock_ms();
  assert_true(st.ms >= before + 60000);
  assert_true(st.ms <= after + 60000);
}

/** A clock row that does not decode is passed over; the rest still
 * count. */
static void bad_rows_are_passed_over(void **state)
{
  uint64_t now = hlc_wall_clock_ms();
  struct md_stamp ok = { now + 5000, 1, 9 };
  struct md_stamp st;

  hlc_init(5);
  put_raw("metadata_clock", "dan", "bad", "Lx.y.z", 6);
  put_raw("metadata_clock", "dan", "worse", "", 0);
  put_clock_st("dan", "avatar", &ok, 0);
  assert_int_equal(metadata_clock_seed(), 0);
  st = metadata_stamp_now();
  assert_true(md_stamp_cmp(&st, &ok) > 0);
}

/** A store whose stamps are all behind the wall clock leaves it be. */
static void old_rows_leave_the_clock_be(void **state)
{
  uint64_t now = hlc_wall_clock_ms();
  struct md_stamp old = { now - 5000, 0, 9 };
  struct md_stamp st;

  hlc_init(5);
  put_clock_st("eve", "avatar", &old, 0);
  assert_int_equal(metadata_clock_seed(), 0);
  st = metadata_stamp_now();
  assert_true(st.ms >= now);
  assert_true(st.ms <= hlc_wall_clock_ms());
}

/** No store: nothing to read, the clock is left alone. */
static void without_a_store_the_seed_does_nothing(void **state)
{
  metadata_lmdb_shutdown();
  assert_int_equal(metadata_clock_seed(), -1);
  assert_int_equal(metadata_lmdb_init("unused"), 0);   /* teardown's */
}

/* ------------------------------------------------------------------ */
/* The key cap (owner, 2026-11-24): it is for a target's own keys;     */
/* mode keys, IRCv3 registry keys and server-managed keys stand apart  */
/* ------------------------------------------------------------------ */

static void the_key_classes(void **state)
{
  (void)state;
  assert_true(metadata_key_counts("custom", 0));
  assert_true(metadata_key_counts("avatar2", 0));
  assert_false(metadata_key_counts("avatar", 0));
  assert_false(metadata_key_counts("Display-Name", 0));
  assert_false(metadata_key_counts("pronouns", 0));
  assert_false(metadata_key_counts("umode.invisible", 0));
  assert_false(metadata_key_counts("chathistory.pm", 0));
  assert_false(metadata_key_counts("draft/persistence/hold", 0));
  assert_false(metadata_key_counts("draft/persistence/x", 1));
  /* A channel has its own registry list, and no modes in metadata. */
  assert_false(metadata_key_counts("avatar", 1));
  assert_false(metadata_key_counts("display-name", 1));
  assert_true(metadata_key_counts("pronouns", 1));
  assert_true(metadata_key_counts("umode.invisible", 1));
  assert_false(metadata_key_counts(NULL, 0));
}

static void the_cap_counts_an_accounts_own_keys(void **state)
{
  (void)state;
  put_value("gus", "custom1", "a");
  put_value("gus", "custom2", "a");
  put_value("gus", "avatar", "a");
  put_value("gus", "pronouns", "a");
  put_value("gus", "umode.invisible", "1");
  put_value("gus", "chathistory.pm", "0");
  put_value("gus", "draft/persistence/hold", "1");
  assert_int_equal(metadata_account_count_keys("gus", 20), 2);
}

static void a_channel_counts_by_the_channel_list(void **state)
{
  (void)state;
  put_value("#chan", "topicx", "a");
  put_value("#chan", "avatar", "a");
  put_value("#chan", "display-name", "a");
  put_value("#chan", "pronouns", "a");
  put_value("#chan", "umode.invisible", "1");
  assert_int_equal(metadata_account_count_keys("#chan", 20), 3);
}

/* The count stops past the caller's limit, not the cap's: a peer's rows are
 * held to the key ceiling (4x the cap), which a count stopped at the cap
 * could never reach. */
static void the_count_runs_to_the_callers_limit(void **state)
{
  char key[16];
  int i;

  (void)state;
  for (i = 0; i < 30; i++) {
    snprintf(key, sizeof(key), "k%02d", i);
    put_value("gus", key, "a");
  }
  assert_int_equal(metadata_account_count_keys("gus", 80), 30);
  assert_int_equal(metadata_account_count_keys("gus", 20), 21);
  assert_int_equal(metadata_account_count_keys("gus", 29), 30);
  assert_int_equal(metadata_account_count_keys("gus", -1), 1);
}

/* max-keys: "the maximum number of keys a client is allowed to set on its
 * own nickname" -- the cap (20 here) and every key outside it a client may
 * set on itself: 7 registry keys, 7 mode keys (draft/persistence/hold is
 * the server's). */
static void the_advertised_total(void **state)
{
  (void)state;
  assert_int_equal(metadata_max_keys_total(), 34);
}

/* ------------------------------------------------------------------ */
/* Channel metadata, LWW-stamped (audit 2026-11-23 item 1; owner's     */
/* rulings 2026-11-24): the account rule, in memory for every channel, */
/* in the store too for a +R one                                       */
/* ------------------------------------------------------------------ */

static struct Channel *new_chan(const char *name, int registered)
{
  struct Channel *c = calloc(1, sizeof(*c) + strlen(name));

  assert_non_null(c);
  strcpy(c->chname, name);
  if (registered)
    c->mode.mode |= MODE_REGISTERED;
  return c;
}

static void drop_chan(struct Channel *c)
{
  metadata_free_channel(c);
  free(c);
}

/** @a secs before CurrentTime, in stamp milliseconds. */
static uint64_t ago(int secs)
{
  return ((uint64_t)CurrentTime - secs) * 1000;
}

static struct md_version live_at(uint64_t ms, const char *value)
{
  struct md_version v;

  memset(&v, 0, sizeof(v));
  v.st.ms = ms;
  v.st.node = 7;
  v.vis = METADATA_VIS_PUBLIC;
  v.value = value;
  v.vlen = strlen(value);
  return v;
}

static struct md_version dead_at(uint64_t ms)
{
  struct md_version v;

  memset(&v, 0, sizeof(v));
  v.st.ms = ms;
  v.st.node = 7;
  v.tombstone = 1;
  return v;
}

static const char *chan_value(struct Channel *c, const char *key)
{
  struct MetadataEntry *e;

  for (e = c->metadata; e; e = e->next)
    if (!strcmp(e->key, key))
      return e->value;
  return NULL;
}

static void a_newer_channel_row_wins(void **state)
{
  struct Channel *c = new_chan("#lww", 0);
  struct md_version v;
  int ov;

  (void)state;
  v = live_at(ago(100), "a");
  assert_int_equal(metadata_channel_merge(c, "k", &v, &ov), 1);
  assert_string_equal(chan_value(c, "k"), "a");
  v = live_at(ago(200), "b");                  /* older: kept */
  assert_int_equal(metadata_channel_merge(c, "k", &v, &ov), 0);
  assert_string_equal(chan_value(c, "k"), "a");
  v = live_at(ago(50), "c");
  assert_int_equal(metadata_channel_merge(c, "k", &v, &ov), 1);
  assert_string_equal(chan_value(c, "k"), "c");
  v = live_at(ago(40), "c");                   /* newer, same value */
  assert_int_equal(metadata_channel_merge(c, "k", &v, &ov), 2);
  drop_chan(c);
}

static void a_channel_tombstone_blocks_an_older_row(void **state)
{
  struct Channel *c = new_chan("#tomb", 0);
  struct md_version v;
  int ov;

  (void)state;
  v = live_at(ago(100), "a");
  assert_int_equal(metadata_channel_merge(c, "k", &v, &ov), 1);
  v = dead_at(ago(90));
  assert_int_equal(metadata_channel_merge(c, "k", &v, &ov), 1);
  assert_null(chan_value(c, "k"));
  v = live_at(ago(95), "b");                   /* older than the delete */
  assert_int_equal(metadata_channel_merge(c, "k", &v, &ov), 0);
  assert_null(chan_value(c, "k"));
  v = live_at(ago(80), "c");
  assert_int_equal(metadata_channel_merge(c, "k", &v, &ov), 1);
  assert_string_equal(chan_value(c, "k"), "c");
  drop_chan(c);
}

/* Ruling (c): a row with no stamp (the legacy form) is 0.0.0. */
static void an_unstamped_channel_row_loses(void **state)
{
  struct Channel *c = new_chan("#zero", 0);
  struct md_version v;
  int ov;

  (void)state;
  v = live_at(0, "z");
  v.st.node = 0;
  assert_int_equal(metadata_channel_merge(c, "k", &v, &ov), 1);   /* nothing to beat */
  v = live_at(ago(100), "a");
  assert_int_equal(metadata_channel_merge(c, "k", &v, &ov), 1);
  v = live_at(0, "y");
  v.st.node = 0;
  assert_int_equal(metadata_channel_merge(c, "k", &v, &ov), 0);
  assert_string_equal(chan_value(c, "k"), "a");
  drop_chan(c);
}

/* A +R channel's store keeps the row's own stamp, and a channel object
 * that has not loaded the store is still held to it. */
static void a_registered_channel_stores_the_rows_stamp(void **state)
{
  struct Channel *c = new_chan("#reg", 1);
  struct md_version v, out;
  char buf[64];
  int ov;

  (void)state;
  v = live_at(ago(100), "a");
  assert_int_equal(metadata_channel_merge(c, "k", &v, &ov), 1);
  assert_int_equal(metadata_account_get_version("#reg", "k", &out, buf, sizeof(buf)), 0);
  assert_int_equal(out.st.ms, ago(100));
  assert_int_equal(out.st.node, 7);
  v = dead_at(ago(50));
  assert_int_equal(metadata_channel_merge(c, "k", &v, &ov), 1);
  assert_int_equal(metadata_account_get_version("#reg", "k", &out, buf, sizeof(buf)), 0);
  assert_true(out.tombstone);
  assert_int_equal(out.st.ms, ago(50));
  drop_chan(c);

  c = new_chan("#reg", 1);                     /* memory empty */
  v = live_at(ago(70), "x");
  assert_int_equal(metadata_channel_merge(c, "k", &v, &ov), 0);
  assert_null(chan_value(c, "k"));
  drop_chan(c);
}

static void a_channel_tombstone_expires(void **state)
{
  struct Channel *c = new_chan("#exp", 0);
  struct md_version v;
  int ov;

  (void)state;
  tombstone_ttl = 3600;
  v = dead_at(ago(7200));                      /* past its lifetime */
  /* A delete of a key never held: taken, nothing to tell (2). */
  assert_int_equal(metadata_channel_merge(c, "k", &v, &ov), 2);
  v = live_at(ago(8000), "old");
  assert_int_equal(metadata_channel_merge(c, "k", &v, &ov), 1);
  assert_string_equal(chan_value(c, "k"), "old");
  v = dead_at(ago(600));                       /* within it */
  assert_int_equal(metadata_channel_merge(c, "j", &v, &ov), 2);
  v = live_at(ago(700), "older");
  assert_int_equal(metadata_channel_merge(c, "j", &v, &ov), 0);
  drop_chan(c);
}

/* Ruling (b): a channel that loses on TS keeps nothing -- memory, its
 * tombstones and a +R channel's stored rows, with no tombstone left
 * behind that could beat the winner's rows. */
static void a_ts_lost_channel_keeps_nothing(void **state)
{
  struct Channel *c = new_chan("#lost", 1);
  struct md_version v, out;
  char buf[64];
  int ov;

  (void)state;
  v = live_at(ago(100), "a");
  assert_int_equal(metadata_channel_merge(c, "k1", &v, &ov), 1);
  v = dead_at(ago(90));
  assert_int_equal(metadata_channel_merge(c, "k2", &v, &ov), 2);
  metadata_channel_forget(c);
  assert_null(c->metadata);
  assert_int_equal(metadata_account_get_version("#lost", "k1", &out, buf, sizeof(buf)), 1);
  assert_int_equal(metadata_account_get_version("#lost", "k2", &out, buf, sizeof(buf)), 1);
  v = live_at(ago(500), "w");                  /* the winner's, older */
  assert_int_equal(metadata_channel_merge(c, "k2", &v, &ov), 1);
  assert_string_equal(chan_value(c, "k2"), "w");
  drop_chan(c);
}

/* +R: loading the store brings each row's stamp, tombstones included. */
static void a_loaded_channel_keeps_the_stored_stamps(void **state)
{
  struct Channel *c = new_chan("#hyd", 1);
  struct md_stamp st;
  struct md_version v;
  int ov;

  (void)state;
  memset(&st, 0, sizeof(st));
  st.node = 3;
  st.ms = ago(100);
  assert_int_equal(metadata_account_put_versioned("#hyd", "k1", "v1", 0, &st), 0);
  st.ms = ago(90);
  assert_int_equal(metadata_account_put_versioned("#hyd", "k2", NULL, 0, &st), 0);
  metadata_channel_load(c);
  assert_string_equal(chan_value(c, "k1"), "v1");
  assert_int_equal(c->metadata->st.ms, ago(100));
  v = live_at(ago(150), "older");
  assert_int_equal(metadata_channel_merge(c, "k1", &v, &ov), 0);
  v = live_at(ago(95), "older");
  assert_int_equal(metadata_channel_merge(c, "k2", &v, &ov), 0);
  drop_chan(c);
}

/* A write made here is stamped after every stamp this server has seen. */
static void a_channel_write_here_is_the_newest(void **state)
{
  struct Channel *c = new_chan("#mine", 0);
  struct md_version v, out;
  int ov;

  (void)state;
  v = live_at((uint64_t)CurrentTime * 1000 + 5000, "theirs");
  assert_int_equal(metadata_channel_merge(c, "k", &v, &ov), 1);
  assert_int_equal(metadata_channel_write(c, "k", "mine", METADATA_VIS_PUBLIC, &out), 1);
  assert_true(md_stamp_cmp(&out.st, &v.st) > 0);
  assert_string_equal(chan_value(c, "k"), "mine");
  assert_int_equal(metadata_channel_write(c, "k", NULL, METADATA_VIS_PUBLIC, &out), 1);
  assert_true(out.tombstone);
  assert_null(chan_value(c, "k"));
  drop_chan(c);
}

/* A CLEAR's floor: a row of a clearable key written before it goes. */
static void a_channel_clear_floor_converts_older_rows(void **state)
{
  struct Channel *c = new_chan("#flr", 0);
  struct md_stamp st, floor;
  struct md_version v;

  (void)state;
  memset(&st, 0, sizeof(st));
  st.ms = ago(100);
  st.node = 7;
  metadata_channel_floor_raise(c, &st);
  v = live_at(ago(300), "before");
  assert_int_equal(metadata_channel_floor_converts(c, "k", &v, &floor), 1);
  assert_int_equal(floor.ms, ago(100));
  v = live_at(ago(50), "after");
  assert_int_equal(metadata_channel_floor_converts(c, "k", &v, &floor), 0);
  v = live_at(ago(300), "server's");
  assert_int_equal(metadata_channel_floor_converts(c, "draft/persistence/x", &v, &floor), 0);
  drop_chan(c);
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
    cmocka_unit_test_setup_teardown(a_tombstone_lives_at_least_the_limit, setup, teardown),
    cmocka_unit_test_setup_teardown(a_longer_tombstone_ttl_is_kept, setup, teardown),
    cmocka_unit_test_setup_teardown(tombstone_ttl_0_keeps_them_past_the_limit, setup, teardown),
    cmocka_unit_test_setup_teardown(a_limit_below_a_minute_is_a_minute, setup, teardown),
    cmocka_unit_test_setup_teardown(the_clear_floor_lives_at_least_the_limit, setup, teardown),
    cmocka_unit_test_setup_teardown(the_clock_starts_past_every_stored_stamp, setup, teardown),
    cmocka_unit_test_setup_teardown(the_seed_is_bounded_like_a_peer, setup, teardown),
    cmocka_unit_test_setup_teardown(bad_rows_are_passed_over, setup, teardown),
    cmocka_unit_test_setup_teardown(old_rows_leave_the_clock_be, setup, teardown),
    cmocka_unit_test_setup_teardown(without_a_store_the_seed_does_nothing, setup, teardown),
    cmocka_unit_test(the_key_classes),
    cmocka_unit_test_setup_teardown(the_cap_counts_an_accounts_own_keys, setup, teardown),
    cmocka_unit_test_setup_teardown(a_channel_counts_by_the_channel_list, setup, teardown),
    cmocka_unit_test(the_advertised_total),
    cmocka_unit_test_setup_teardown(a_newer_channel_row_wins, setup, teardown),
    cmocka_unit_test_setup_teardown(a_channel_tombstone_blocks_an_older_row, setup, teardown),
    cmocka_unit_test_setup_teardown(an_unstamped_channel_row_loses, setup, teardown),
    cmocka_unit_test_setup_teardown(a_registered_channel_stores_the_rows_stamp, setup, teardown),
    cmocka_unit_test_setup_teardown(a_channel_tombstone_expires, setup, teardown),
    cmocka_unit_test_setup_teardown(a_ts_lost_channel_keeps_nothing, setup, teardown),
    cmocka_unit_test_setup_teardown(a_loaded_channel_keeps_the_stored_stamps, setup, teardown),
    cmocka_unit_test_setup_teardown(a_channel_write_here_is_the_newest, setup, teardown),
    cmocka_unit_test_setup_teardown(a_channel_clear_floor_converts_older_rows, setup, teardown),
    cmocka_unit_test_setup_teardown(the_count_runs_to_the_callers_limit, setup, teardown),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}

/* ------------------------------------------------------------------ */
/* The rest of the ircd                                                */
/* ------------------------------------------------------------------ */

/* What metadata.o reaches beyond the store: the client side (memory,
 * notifications, replies), bouncer sessions (the clock is the real one).  The paths under
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
