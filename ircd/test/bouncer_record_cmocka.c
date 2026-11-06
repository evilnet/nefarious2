/* cmocka suite for the persisted bouncer record decoder
 * (include/bouncer_record.h): each old version, laid out as its own build
 * wrote it, migrates to the current record. */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

#include "config.h"
#include "../../include/bouncer_record.h"

/* Record bytes in a heap block of exactly the record's size, so a read
 * past the end trips ASan or valgrind. */
static void *exact_copy(const void *rec, size_t len)
{
  void *buf = malloc(len);
  assert_non_null(buf);
  memcpy(buf, rec, len);
  return buf;
}

static void fill_alias(struct BounceSessionAliasRecord *a, int i)
{
  snprintf(a->bsar_numeric, sizeof(a->bsar_numeric), "B%cAAA", 'A' + i);
  snprintf(a->bsar_server, sizeof(a->bsar_server), "B%c", 'A' + i);
  a->bsar_caps = 0x10 + i;
  a->bsar_last_active = 1700000100 + i;
}

static void test_layout_sizes(void **state)
{
  (void)state;
  /* What each version's build wrote (LP64).  v8 was 14608 while its
   * alias array followed the live BOUNCER_MAX_ALIASES (16) instead of the
   * 4 it was written with. */
  assert_int_equal(bounce_record_size(7), 14192);
  assert_int_equal(bounce_record_size(8), 14320);
  assert_int_equal(bounce_record_size(9), 14360);
  assert_int_equal(bounce_record_size(10), 14648);
  assert_int_equal(bounce_record_size(11), 14656);
  assert_int_equal(bounce_record_size(BOUNCER_DB_VERSION), 14680);
  assert_int_equal(bounce_record_size(6), 0);
  assert_int_equal(bounce_record_size(BOUNCER_DB_VERSION + 1), 0);
}

/* test_layout_sizes (above) and bouncer_record.c's BR_CHECK pin each
 * frozen struct's overall sizeof -- but both read that size off the same
 * struct the test builds records with, so a field moved inside a frozen
 * struct without changing its total size (a reordered or differently
 * padded field, balanced by one elsewhere) would pass every existing
 * check while still corrupting every field read after the move.  Pin a
 * handful of field offsets as literal numbers -- independent of the
 * struct's own sizeof -- so such a move fails here even when the total
 * size does not.  Values measured on this tree's LP64 layout. */
static void test_frozen_layout_offsets(void **state)
{
  (void)state;

  /* v7 */
  assert_int_equal(offsetof(struct BounceSessionRecord_v7, bsr_token), 36);

  /* v8 */
  assert_int_equal(offsetof(struct BounceSessionRecord_v8, bsr_channels), 2216);
  assert_int_equal(offsetof(struct BounceSessionRecord_v8, bsr_aliascount), 14216);
  assert_int_equal(offsetof(struct BounceSessionRecord_v8, bsr_aliases), 14224);
  assert_int_equal(sizeof(struct BounceSessionRecord_v8), 14320);

  /* v9 */
  assert_int_equal(offsetof(struct BounceSessionRecord_v9, bsr_oper_name), 14320);
}

static void test_v8_migrates(void **state)
{
  struct BounceSessionRecord_v8 *v8 = calloc(1, sizeof(*v8));
  struct BounceSessionRecord *out = calloc(1, sizeof(*out));
  uint32_t version;
  void *buf;
  int i;

  (void)state;
  assert_non_null(v8);
  assert_non_null(out);
  v8->bsr_version = 8;
  strcpy(v8->bsr_account, "alice");
  strcpy(v8->bsr_sessid, "AZJZm0fQd3S2pLkGg0kN1w");
  strcpy(v8->bsr_token, "tok");
  strcpy(v8->bsr_name, "laptop");
  strcpy(v8->bsr_origin, "AB");
  v8->bsr_created = 1700000000;
  v8->bsr_disconnect_time = 1700000050;
  v8->bsr_attach_count = 3;
  strcpy(v8->bsr_nick, "alice");
  strcpy(v8->bsr_username, "~alice");
  strcpy(v8->bsr_realhost, "host.example");
  strcpy(v8->bsr_host, "alice.users.example");
  strcpy(v8->bsr_realname, "Alice");
  v8->bsr_histcount = 1;
  strcpy(v8->bsr_history[0].bch_ip, "192.0.2.1");
  v8->bsr_chancount = 2;
  strcpy(v8->bsr_channels[0].name, "#one");
  strcpy(v8->bsr_channels[1].name, "#two");
  v8->bsr_channels[1].modes = 4;
  v8->bsr_aliascount = 4;
  for (i = 0; i < 4; i++)
    fill_alias(&v8->bsr_aliases[i], i);

  buf = exact_copy(v8, sizeof(*v8));
  assert_int_equal(bounce_record_decode(buf, sizeof(*v8), out, &version),
                   BOUNCE_REC_MIGRATED);
  assert_int_equal(version, 8);
  assert_int_equal(out->bsr_version, BOUNCER_DB_VERSION);
  assert_string_equal(out->bsr_account, "alice");
  assert_string_equal(out->bsr_sessid, "AZJZm0fQd3S2pLkGg0kN1w");
  assert_string_equal(out->bsr_token, "tok");
  assert_string_equal(out->bsr_name, "laptop");
  assert_int_equal(out->bsr_created, 1700000000);
  assert_int_equal(out->bsr_disconnect_time, 1700000050);
  assert_int_equal(out->bsr_attach_count, 3);
  assert_string_equal(out->bsr_nick, "alice");
  assert_string_equal(out->bsr_host, "alice.users.example");
  assert_int_equal(out->bsr_histcount, 1);
  assert_string_equal(out->bsr_history[0].bch_ip, "192.0.2.1");
  assert_int_equal(out->bsr_chancount, 2);
  assert_string_equal(out->bsr_channels[1].name, "#two");
  assert_int_equal(out->bsr_channels[1].modes, 4);
  assert_int_equal(out->bsr_aliascount, 4);
  for (i = 0; i < 4; i++) {
    assert_string_equal(out->bsr_aliases[i].bsar_numeric,
                        v8->bsr_aliases[i].bsar_numeric);
    assert_string_equal(out->bsr_aliases[i].bsar_server,
                        v8->bsr_aliases[i].bsar_server);
    assert_int_equal(out->bsr_aliases[i].bsar_caps, 0x10 + i);
    assert_int_equal(out->bsr_aliases[i].bsar_last_active, 1700000100 + i);
  }
  for (; i < BOUNCER_MAX_ALIASES; i++)
    assert_int_equal(out->bsr_aliases[i].bsar_numeric[0], '\0');
  /* v8 had no oper grant, snomask or Keycloak id. */
  assert_int_equal(out->bsr_oper_name[0], '\0');
  assert_int_equal(out->bsr_oper_granted_at, 0);
  assert_int_equal(out->bsr_snomask_known, 0);
  assert_int_equal(out->bsr_kc_id[0], '\0');

  free(buf);
  free(v8);
  free(out);
}

static void test_v8_alias_count_is_clamped(void **state)
{
  struct BounceSessionRecord_v8 *v8 = calloc(1, sizeof(*v8));
  struct BounceSessionRecord *out = calloc(1, sizeof(*out));
  uint32_t version;

  (void)state;
  v8->bsr_version = 8;
  strcpy(v8->bsr_nick, "bob");
  v8->bsr_aliascount = 200;   /* more than the 4 a v8 record holds */
  v8->bsr_histcount = 200;
  v8->bsr_chancount = 200;
  assert_int_equal(bounce_record_decode(v8, sizeof(*v8), out, &version),
                   BOUNCE_REC_MIGRATED);
  assert_int_equal(out->bsr_aliascount, 4);
  assert_int_equal(out->bsr_histcount, 10);
  assert_int_equal(out->bsr_chancount, 50);
  free(v8);
  free(out);
}

static void test_v9_migrates(void **state)
{
  struct BounceSessionRecord_v9 *v9 = calloc(1, sizeof(*v9));
  struct BounceSessionRecord *out = calloc(1, sizeof(*out));
  uint32_t version;
  void *buf;

  (void)state;
  v9->bsr_version = 9;
  strcpy(v9->bsr_account, "carol");
  strcpy(v9->bsr_oper_name, "carol-oper");
  v9->bsr_oper_granted_at = 1700000200;
  v9->bsr_aliascount = 1;
  fill_alias(&v9->bsr_aliases[0], 0);
  buf = exact_copy(v9, sizeof(*v9));
  assert_int_equal(bounce_record_decode(buf, sizeof(*v9), out, &version),
                   BOUNCE_REC_MIGRATED);
  assert_int_equal(version, 9);
  assert_string_equal(out->bsr_account, "carol");
  assert_string_equal(out->bsr_oper_name, "carol-oper");
  assert_int_equal(out->bsr_oper_granted_at, 1700000200);
  assert_int_equal(out->bsr_aliascount, 1);
  assert_string_equal(out->bsr_aliases[0].bsar_numeric, "BAAAA");
  free(buf);
  free(v9);
  free(out);
}

static void test_v7_leaves_sessid_to_caller(void **state)
{
  struct BounceSessionRecord_v7 *v7 = calloc(1, sizeof(*v7));
  struct BounceSessionRecord *out = calloc(1, sizeof(*out));
  uint32_t version;
  void *buf;

  (void)state;
  v7->bsr_version = 7;
  strcpy(v7->bsr_account, "dave");
  strcpy(v7->bsr_sessid, "AB-12345");
  v7->bsr_chancount = 1;
  strcpy(v7->bsr_channels[0].name, "#seven");
  buf = exact_copy(v7, sizeof(*v7));
  assert_int_equal(bounce_record_decode(buf, sizeof(*v7), out, &version),
                   BOUNCE_REC_MIGRATED_V7);
  assert_int_equal(version, 7);
  assert_int_equal(out->bsr_version, BOUNCER_DB_VERSION);
  assert_string_equal(out->bsr_account, "dave");
  assert_int_equal(out->bsr_sessid[0], '\0');
  assert_int_equal(out->bsr_chancount, 1);
  assert_string_equal(out->bsr_channels[0].name, "#seven");
  assert_int_equal(out->bsr_aliascount, 0);
  free(buf);
  free(v7);
  free(out);
}

static void test_v10_v11_and_current(void **state)
{
  struct BounceSessionRecord *rec = calloc(1, sizeof(*rec));
  struct BounceSessionRecord *out = calloc(1, sizeof(*out));
  uint32_t version;
  void *buf;

  (void)state;
  strcpy(rec->bsr_account, "erin");
  rec->bsr_aliascount = 16;
  fill_alias(&rec->bsr_aliases[15], 15);
  rec->bsr_snomask = 0x55;
  rec->bsr_snomask_known = 1;
  strcpy(rec->bsr_kc_id, "kcid");

  rec->bsr_version = 10;
  buf = exact_copy(rec, sizeof(struct BounceSessionRecord_v10));
  assert_int_equal(bounce_record_decode(buf, sizeof(struct BounceSessionRecord_v10),
                                        out, &version), BOUNCE_REC_MIGRATED);
  assert_int_equal(out->bsr_version, BOUNCER_DB_VERSION);
  assert_string_equal(out->bsr_account, "erin");
  assert_string_equal(out->bsr_aliases[15].bsar_numeric, "BPAAA");
  assert_int_equal(out->bsr_snomask_known, 0);
  assert_int_equal(out->bsr_kc_id[0], '\0');
  free(buf);

  rec->bsr_version = 11;
  buf = exact_copy(rec, sizeof(struct BounceSessionRecord_v11));
  assert_int_equal(bounce_record_decode(buf, sizeof(struct BounceSessionRecord_v11),
                                        out, &version), BOUNCE_REC_MIGRATED);
  assert_int_equal(out->bsr_snomask, 0x55);
  assert_int_equal(out->bsr_kc_id[0], '\0');
  free(buf);

  rec->bsr_version = BOUNCER_DB_VERSION;
  buf = exact_copy(rec, sizeof(*rec));
  assert_int_equal(bounce_record_decode(buf, sizeof(*rec), out, &version),
                   BOUNCE_REC_CURRENT);
  assert_memory_equal(out, rec, sizeof(*rec));
  free(buf);
  free(rec);
  free(out);
}

static void test_wrong_size_and_unknown(void **state)
{
  struct BounceSessionRecord *out = calloc(1, sizeof(*out));
  unsigned char *buf = calloc(1, 16 * 1024);
  uint32_t version = 8;

  (void)state;
  memcpy(buf, &version, sizeof(version));
  /* The size the v8 struct had while its aliases followed the live
   * constant: no v8 build wrote this. */
  assert_int_equal(bounce_record_decode(buf, 14608, out, &version),
                   BOUNCE_REC_BAD_SIZE);
  assert_int_equal(version, 8);

  version = 6;
  memcpy(buf, &version, sizeof(version));
  assert_int_equal(bounce_record_decode(buf, 14192, out, &version),
                   BOUNCE_REC_UNKNOWN);
  assert_int_equal(version, 6);

  assert_int_equal(bounce_record_decode(buf, 3, out, &version),
                   BOUNCE_REC_UNKNOWN);
  assert_int_equal(version, 0);
  free(buf);
  free(out);
}

static void test_unterminated_strings_stay_bounded(void **state)
{
  struct BounceSessionRecord_v8 *v8 = calloc(1, sizeof(*v8));
  struct BounceSessionRecord *out = calloc(1, sizeof(*out));
  uint32_t version;

  (void)state;
  v8->bsr_version = 8;
  memset(v8->bsr_nick, 'n', sizeof(v8->bsr_nick));         /* no NUL */
  memset(v8->bsr_account, 'a', sizeof(v8->bsr_account));   /* no NUL */
  assert_int_equal(bounce_record_decode(v8, sizeof(*v8), out, &version),
                   BOUNCE_REC_MIGRATED);
  assert_int_equal(strlen(out->bsr_nick), sizeof(out->bsr_nick) - 1);
  assert_int_equal(strlen(out->bsr_account), sizeof(out->bsr_account) - 1);
  free(v8);
  free(out);
}

/* ---- Crash restore: the stamp an ACTIVE record carries, and the one
 * restore/eviction rule (user decision 2026-11-06: an ACTIVE session
 * survives an unclean restart, restored as held). ---- */

#define NOW      ((int64_t)1793923200)   /* 2026-11-06 00:00:00 UTC */
#define MAX_HOLD ((int64_t)1209600)      /* 14 days, the feature default */
#define BASE     ((int64_t)14400)        /* BOUNCER_SESSION_HOLD default */

/* The feature defaults: 4 h base, 14 d ceiling, decay from 50 %. */
static const struct bounce_hold_rule DEFAULT_RULE = { BASE, MAX_HOLD, 50 };

/* The restart's clock, the previous run last alive at @a last_alive. */
static struct bounce_restore_clock clock_at(int64_t last_alive)
{
  struct bounce_restore_clock c;

  memset(&c, 0, sizeof(c));
  c.now = NOW;
  c.max_hold = MAX_HOLD;
  c.last_alive = last_alive;
  c.hold = DEFAULT_RULE;
  return c;
}

/* A current-layout record with the fields the restore rule reads. */
static struct BounceSessionRecord *rec_with(int64_t disconnect_time,
                                            int64_t last_active,
                                            uint32_t connect_count,
                                            int64_t total_active)
{
  struct BounceSessionRecord *r = calloc(1, sizeof(*r));

  assert_non_null(r);
  r->bsr_version = BOUNCER_DB_VERSION;
  r->bsr_disconnect_time = disconnect_time;
  r->bsr_last_active = last_active;
  r->bsr_connect_count = connect_count;
  r->bsr_total_active = total_active;
  return r;
}

/* bounce_record_restore() on a record of @a disconnect_time alone. */
static enum BounceRestoreVerdict restore_time(int64_t disconnect_time,
                                              int64_t last_alive,
                                              int64_t *since)
{
  struct bounce_restore_clock c = clock_at(last_alive);
  struct BounceSessionRecord *r = rec_with(disconnect_time, 0, 0, 0);
  enum BounceRestoreVerdict v = bounce_record_restore(r, &c, since);

  free(r);
  return v;
}

/* A session an unclean exit must bring back: every fact holds. */
static struct bounce_stamp_facts restorable(void)
{
  struct bounce_stamp_facts f;

  memset(&f, 0, sizeof(f));
  f.active = 1;
  f.primary_live = 1;
  f.logged_in = 1;
  f.bouncer_on = 1;
  f.wants_hold = 1;
  f.remote_devices = 0;
  return f;
}

/* What a binary from before the marker computes at restore (the restore
 * loop's and the eviction pass's `CurrentTime - disconnect > max_hold`). */
static int old_binary_expires(int64_t disconnect_time, int64_t now,
                              int64_t max_hold)
{
  return now - disconnect_time > max_hold;
}

static void test_marker_value_is_pinned(void **state)
{
  (void)state;
  /* On-disk format: a record written by this build carries it. */
  assert_true(BOUNCE_REC_HELD_AT_RESTART == (int64_t)-1);
  assert_true(BOUNCE_REC_HELD_AT_RESTART != 0);
}

static void test_record_field_offsets(void **state)
{
  (void)state;
  /* The fields the restore rule and the eviction pass read, as literal
   * offsets of the current (v12) layout, LP64: a move of any of them
   * changes the on-disk format (bump BOUNCER_DB_VERSION instead). */
  assert_int_equal(offsetof(struct BounceSessionRecord, bsr_disconnect_time), 200);
  assert_int_equal(offsetof(struct BounceSessionRecord, bsr_last_active), 208);
  assert_int_equal(offsetof(struct BounceSessionRecord, bsr_total_active), 224);
  assert_int_equal(offsetof(struct BounceSessionRecord, bsr_connect_count), 236);
}

static void test_restore_zero_and_negatives_are_expired(void **state)
{
  int64_t since = 12345;

  (void)state;
  /* An ACTIVE record no unclean exit brings back (or any ACTIVE record an
   * older build wrote), with or without a heartbeat. */
  assert_int_equal(restore_time(0, 0, &since), BOUNCE_RESTORE_EXPIRED);
  assert_int_equal(restore_time(0, NOW - 60, &since), BOUNCE_RESTORE_EXPIRED);
  /* A time before the epoch that is not the marker (a torn or foreign
   * record), without computing now - INT64_MIN. */
  assert_int_equal(restore_time(-2, NOW - 60, NULL), BOUNCE_RESTORE_EXPIRED);
  assert_int_equal(restore_time(INT64_MIN, NOW - 60, NULL), BOUNCE_RESTORE_EXPIRED);
  assert_true(since == 12345);   /* untouched when expired */
}

static void test_restore_marker_held_from_the_crash(void **state)
{
  struct bounce_restore_clock c = clock_at(NOW - 120);
  struct BounceSessionRecord *r;
  int64_t since = 0;

  (void)state;
  /* The previous run's last heartbeat is the crash. */
  r = rec_with(BOUNCE_REC_HELD_AT_RESTART, NOW - 3600, 0, 0);
  assert_int_equal(bounce_record_restore(r, &c, &since),
                   BOUNCE_RESTORE_HELD_AT_CRASH);
  assert_true(since == NOW - 120);
  /* The session itself was seen live later than the last heartbeat. */
  r->bsr_last_active = NOW - 30;
  assert_int_equal(bounce_record_restore(r, &c, &since),
                   BOUNCE_RESTORE_HELD_AT_CRASH);
  assert_true(since == NOW - 30);
  /* ... never after now (a clock that went back). */
  r->bsr_last_active = NOW + 500;
  assert_int_equal(bounce_record_restore(r, &c, &since),
                   BOUNCE_RESTORE_HELD_AT_CRASH);
  assert_true(since == NOW);
  /* NULL out-parameter is allowed. */
  assert_int_equal(bounce_record_restore(r, &c, NULL),
                   BOUNCE_RESTORE_HELD_AT_CRASH);
  free(r);
}

static void test_restore_marker_without_heartbeat_is_held_from_now(void **state)
{
  int64_t since = 0;

  (void)state;
  /* A record of a build that kept no heartbeat. */
  assert_int_equal(restore_time(BOUNCE_REC_HELD_AT_RESTART, 0, &since),
                   BOUNCE_RESTORE_HELD_AT_CRASH);
  assert_true(since == NOW);
}

static void test_restore_marker_outage_outlived_its_hold(void **state)
{
  struct bounce_restore_clock c;
  struct BounceSessionRecord *r;

  (void)state;
  /* No connections: the base hold, 4 h.  With decay from 50 %, the
   * decayed hold never goes below base. */
  c = clock_at(NOW - BASE);
  r = rec_with(BOUNCE_REC_HELD_AT_RESTART, 0, 0, 0);
  assert_int_equal(bounce_record_restore(r, &c, NULL), BOUNCE_RESTORE_HELD_AT_CRASH);
  c = clock_at(NOW - BASE - 1);
  assert_int_equal(bounce_record_restore(r, &c, NULL), BOUNCE_RESTORE_EXPIRED);
  free(r);
  /* Four connections: earned 8 h; decay from 4 h idle, a quarter (2 h)
   * per halving: after 6 h idle the hold is 4 h + 2 h = 6 h. */
  r = rec_with(BOUNCE_REC_HELD_AT_RESTART, 0, 4, 0);
  c = clock_at(NOW - 21600);
  assert_int_equal(bounce_record_restore(r, &c, NULL), BOUNCE_RESTORE_HELD_AT_CRASH);
  c = clock_at(NOW - 21601);
  assert_int_equal(bounce_record_restore(r, &c, NULL), BOUNCE_RESTORE_EXPIRED);
  free(r);
}

static void test_restore_marker_past_max_hold(void **state)
{
  struct bounce_restore_clock c = clock_at(NOW - 601);
  struct BounceSessionRecord *r = rec_with(BOUNCE_REC_HELD_AT_RESTART, 0, 4, 0);

  (void)state;
  c.max_hold = 600;
  assert_int_equal(bounce_record_restore(r, &c, NULL), BOUNCE_RESTORE_EXPIRED);
  c = clock_at(NOW - 600);
  c.max_hold = 600;
  assert_int_equal(bounce_record_restore(r, &c, NULL), BOUNCE_RESTORE_HELD_AT_CRASH);
  free(r);
}

static void test_restore_real_time_is_todays_check(void **state)
{
  struct bounce_restore_clock c = clock_at(NOW - 60);
  struct BounceSessionRecord *r;
  int64_t since = 0;

  (void)state;
  /* Held an hour ago: held, from then. */
  assert_int_equal(restore_time(NOW - 3600, NOW - 60, &since), BOUNCE_RESTORE_HELD);
  assert_true(since == NOW - 3600);
  /* Exactly the ceiling: still held (the check is "more than"). */
  assert_int_equal(restore_time(NOW - MAX_HOLD, NOW - 60, &since), BOUNCE_RESTORE_HELD);
  assert_true(since == NOW - MAX_HOLD);
  /* One second past it: expired. */
  assert_int_equal(restore_time(NOW - MAX_HOLD - 1, NOW - 60, &since),
                   BOUNCE_RESTORE_EXPIRED);
  /* A disconnect stamped ahead of our clock is held, as it was. */
  assert_int_equal(restore_time(NOW + 60, NOW - 60, &since), BOUNCE_RESTORE_HELD);
  assert_true(since == NOW + 60);
  /* A real time is not read against its own hold: the restore arms the
   * hold timer, which ends it after the settling period (today). */
  r = rec_with(NOW - 20000, 0, 0, 0);
  assert_int_equal(bounce_record_restore(r, &c, &since), BOUNCE_RESTORE_HELD);
  assert_true(since == NOW - 20000);
  /* Nor does the heartbeat move it. */
  c = clock_at(0);
  assert_int_equal(bounce_record_restore(r, &c, &since), BOUNCE_RESTORE_HELD);
  assert_true(since == NOW - 20000);
  free(r);
}

static void test_marker_is_expired_for_an_old_binary(void **state)
{
  (void)state;
  /* Downgrade safety: a build from before the marker evicts a marked
   * record, as it evicted the 0 it wrote itself. */
  assert_true(old_binary_expires(BOUNCE_REC_HELD_AT_RESTART, NOW, MAX_HOLD));
  assert_true(old_binary_expires(0, NOW, MAX_HOLD));
  /* And the two rules agree on every real time. */
  assert_int_equal(old_binary_expires(NOW - 3600, NOW, MAX_HOLD),
                   restore_time(NOW - 3600, NOW - 60, NULL)
                     == BOUNCE_RESTORE_EXPIRED);
  assert_int_equal(old_binary_expires(NOW - MAX_HOLD - 1, NOW, MAX_HOLD),
                   restore_time(NOW - MAX_HOLD - 1, NOW - 60, NULL)
                     == BOUNCE_RESTORE_EXPIRED);
}

/* Our own held ghost, held for its full hold. */
static struct bounce_stamp_facts held_here(void)
{
  struct bounce_stamp_facts f;

  memset(&f, 0, sizeof(f));
  f.held_here = 1;
  return f;
}

static void test_stamp_real_time_is_written_as_is(void **state)
{
  struct bounce_stamp_facts f = held_here();

  (void)state;
  /* A hold's time, our own held ghost. */
  assert_true(bounce_record_stamp(&f, NOW - 60) == NOW - 60);
}

static void test_stamp_hold_not_ours_to_bring_back(void **state)
{
  struct bounce_stamp_facts f;

  (void)state;
  /* A brief hold (hold off, held only until a device elsewhere takes
   * over): a restart would restore it as a full one, against the
   * preference. */
  f = held_here(); f.brief_hold = 1;
  assert_true(bounce_record_stamp(&f, NOW - 60) == 0);
  /* Another server's hold (a replica with a device of ours on its
   * roster): its holder's record is the one to restore. */
  f = held_here(); f.held_here = 0;
  assert_true(bounce_record_stamp(&f, NOW - 60) == 0);
  assert_true(bounce_record_stamp(NULL, NOW - 60) == 0);
  /* A live session's facts do not make a hold time ours. */
  f = restorable();
  assert_true(bounce_record_stamp(&f, NOW - 60) == 0);
}

static void test_stamp_restorable_active_session(void **state)
{
  struct bounce_stamp_facts f = restorable();

  (void)state;
  assert_true(bounce_record_stamp(&f, 0) == BOUNCE_REC_HELD_AT_RESTART);
}

static void test_stamp_each_missing_fact_writes_zero(void **state)
{
  struct bounce_stamp_facts f;

  (void)state;
  f = restorable(); f.active = 0;
  assert_true(bounce_record_stamp(&f, 0) == 0);
  /* The primary is another server's, held, or an alias: not ours to
   * bring back (its holder's record is). */
  f = restorable(); f.primary_live = 0;
  assert_true(bounce_record_stamp(&f, 0) == 0);
  f = restorable(); f.logged_in = 0;
  assert_true(bounce_record_stamp(&f, 0) == 0);
  f = restorable(); f.bouncer_on = 0;
  assert_true(bounce_record_stamp(&f, 0) == 0);
  /* Hold off: a disconnect would end it. */
  f = restorable(); f.wants_hold = 0;
  assert_true(bounce_record_stamp(&f, 0) == 0);
  /* A device on another server: that server's split promote carries the
   * session; a ghost here would be a second copy. */
  f = restorable(); f.remote_devices = 1;
  assert_true(bounce_record_stamp(&f, 0) == 0);
  f = restorable(); f.remote_devices = 3;
  assert_true(bounce_record_stamp(&f, 0) == 0);
  assert_true(bounce_record_stamp(NULL, 0) == 0);
}

static void test_shutdown_stamp_is_the_crash_rule(void **state)
{
  struct bounce_stamp_facts f;

  (void)state;
  /* A session a disconnect would hold: held from the shutdown, a real
   * time (an older build restores it too), never the marker. */
  f = restorable();
  assert_true(bounce_record_shutdown_stamp(&f, 0, NOW) == NOW);
  /* Held here for its full hold: its own time. */
  f = held_here();
  assert_true(bounce_record_shutdown_stamp(&f, NOW - 600, NOW) == NOW - 600);
  /* Everything a disconnect would not hold here ends cleanly. */
  f = restorable(); f.wants_hold = 0;
  assert_true(bounce_record_shutdown_stamp(&f, 0, NOW) == 0);
  f = restorable(); f.remote_devices = 1;
  assert_true(bounce_record_shutdown_stamp(&f, 0, NOW) == 0);
  f = restorable(); f.primary_live = 0;   /* a device of ours, primary elsewhere */
  assert_true(bounce_record_shutdown_stamp(&f, 0, NOW) == 0);
  f = restorable(); f.logged_in = 0;
  assert_true(bounce_record_shutdown_stamp(&f, 0, NOW) == 0);
  f = restorable(); f.bouncer_on = 0;
  assert_true(bounce_record_shutdown_stamp(&f, 0, NOW) == 0);
  f = held_here(); f.brief_hold = 1;
  assert_true(bounce_record_shutdown_stamp(&f, NOW - 600, NOW) == 0);
  f = held_here(); f.held_here = 0;
  assert_true(bounce_record_shutdown_stamp(&f, NOW - 600, NOW) == 0);
  assert_true(bounce_record_shutdown_stamp(NULL, 0, NOW) == 0);
  assert_true(bounce_record_shutdown_stamp(NULL, NOW - 600, NOW) == 0);
}

static void test_record_marked(void **state)
{
  struct BounceSessionRecord *r = rec_with(BOUNCE_REC_HELD_AT_RESTART, 0, 0, 0);

  (void)state;
  assert_true(bounce_record_marked(r));
  r->bsr_disconnect_time = 0;
  assert_false(bounce_record_marked(r));
  r->bsr_disconnect_time = NOW - 60;
  assert_false(bounce_record_marked(r));
  r->bsr_disconnect_time = -2;
  assert_false(bounce_record_marked(r));
  free(r);
}

static void test_stamp_then_restore_round_trip(void **state)
{
  struct bounce_stamp_facts f = restorable();
  int64_t since = 0;

  (void)state;
  /* The defect: an ACTIVE session's record came back expired.  Now it is
   * held from the crash. */
  assert_int_equal(restore_time(bounce_record_stamp(&f, 0), NOW - 90, &since),
                   BOUNCE_RESTORE_HELD_AT_CRASH);
  assert_true(since == NOW - 90);
  /* One a crash must not bring back stays expired. */
  f.wants_hold = 0;
  assert_int_equal(restore_time(bounce_record_stamp(&f, 0), NOW - 90, NULL),
                   BOUNCE_RESTORE_EXPIRED);
  f = restorable();
  f.remote_devices = 1;
  assert_int_equal(restore_time(bounce_record_stamp(&f, 0), NOW - 90, NULL),
                   BOUNCE_RESTORE_EXPIRED);
  /* A held one keeps its own clock. */
  f = held_here();
  assert_int_equal(restore_time(bounce_record_stamp(&f, NOW - 600), NOW - 90, &since),
                   BOUNCE_RESTORE_HELD);
  assert_true(since == NOW - 600);
}

static void test_hold_length_earned(void **state)
{
  struct bounce_hold_rule r = DEFAULT_RULE;

  (void)state;
  r.decay_pct = 0;
  /* Never connected: base, whatever its active time. */
  assert_true(bounce_hold_length(&r, 0, 0, 0) == BASE);
  assert_true(bounce_hold_length(&r, 0, 30 * 86400, 0) == BASE);
  /* A quarter of base per connection. */
  assert_true(bounce_hold_length(&r, 1, 0, 0) == BASE + BASE / 4);
  assert_true(bounce_hold_length(&r, 4, 0, 0) == 2 * BASE);
  /* An hour per full 24 h attached. */
  assert_true(bounce_hold_length(&r, 4, 2 * 86400, 0) == 2 * BASE + 7200);
  assert_true(bounce_hold_length(&r, 4, 2 * 86400 - 1, 0) == 2 * BASE + 3600);
  /* Capped at the ceiling. */
  assert_true(bounce_hold_length(&r, 100000, 0, 0) == MAX_HOLD);
  /* No decay without it, however long held. */
  assert_true(bounce_hold_length(&r, 4, 0, 10 * 86400) == 2 * BASE);
}

static void test_hold_length_decay(void **state)
{
  struct bounce_hold_rule r = DEFAULT_RULE;

  (void)state;
  /* Earned 8 h: decay from 4 h idle, 2 h per halving. */
  assert_true(bounce_hold_length(&r, 4, 0, 0) == 28800);
  assert_true(bounce_hold_length(&r, 4, 0, -50) == 28800);
  assert_true(bounce_hold_length(&r, 4, 0, 14400) == 28800);
  assert_true(bounce_hold_length(&r, 4, 0, 14401) == 28800);
  assert_true(bounce_hold_length(&r, 4, 0, 21600) == 21600);
  assert_true(bounce_hold_length(&r, 4, 0, 14400 + 4 * 7200) == 14400 + 900);
  /* Never below base. */
  assert_true(bounce_hold_length(&r, 4, 0, 365 * 86400) == BASE);
  assert_true(bounce_hold_length(&r, 0, 0, 7200 + 2 * 3600) == BASE);
}

static void test_breaker(void **state)
{
  (void)state;
  /* The last start ended cleanly, or outlived its window. */
  assert_int_equal(bounce_restore_breaker(BOUNCE_BOOT_NONE, 1, NOW - 60, NOW - 30, 600), 0);
  assert_int_equal(bounce_restore_breaker(BOUNCE_BOOT_SETTLED, 1, NOW - 60, NOW - 30, 600), 0);
  /* It died inside its window: a crash loop is possible. */
  assert_int_equal(bounce_restore_breaker(BOUNCE_BOOT_RUNNING, 1, NOW - 60, NOW - 30, 600), 1);
  assert_int_equal(bounce_restore_breaker(BOUNCE_BOOT_RUNNING, 1, NOW - 60, 0, 600), 1);
  /* ... before its first heartbeat (the previous run's is older). */
  assert_int_equal(bounce_restore_breaker(BOUNCE_BOOT_RUNNING, 1, NOW - 60, NOW - 7200, 600), 1);
  assert_int_equal(bounce_restore_breaker(BOUNCE_BOOT_RUNNING, 1, NOW - 700, NOW - 101, 600), 1);
  /* Its heartbeat shows it lived the window (the settle mark was lost). */
  assert_int_equal(bounce_restore_breaker(BOUNCE_BOOT_RUNNING, 1, NOW - 700, NOW - 100, 600), 0);
  /* The breaker is off. */
  assert_int_equal(bounce_restore_breaker(BOUNCE_BOOT_RUNNING, 1, NOW - 60, NOW - 30, 0), 0);
  assert_int_equal(bounce_restore_breaker(BOUNCE_BOOT_RUNNING, 1, NOW - 60, NOW - 30, -5), 0);
  /* A record naming nobody (an older build's): nothing to break, no
   * L_CRIT after every early crash (review m1). */
  assert_int_equal(bounce_restore_breaker(BOUNCE_BOOT_RUNNING, 0, NOW - 60, NOW - 30, 600), 0);
}

static void test_boot_steps(void **state)
{
  (void)state;
  /* The store is open: the markers are rewritten whatever the features
   * say (review I-A); only persistence and the bouncer on restore. */
  assert_int_equal(bounce_boot_steps(1, 1, 1),
                   BOUNCE_BOOT_STEP_REWRITE | BOUNCE_BOOT_STEP_RESTORE);
  assert_int_equal(bounce_boot_steps(1, 1, 0), BOUNCE_BOOT_STEP_REWRITE);
  assert_int_equal(bounce_boot_steps(1, 0, 1), BOUNCE_BOOT_STEP_REWRITE);
  assert_int_equal(bounce_boot_steps(1, 0, 0), BOUNCE_BOOT_STEP_REWRITE);
  /* No store: nothing to read or write. */
  assert_int_equal(bounce_boot_steps(0, 1, 1), 0);
  assert_int_equal(bounce_boot_steps(0, 0, 0), 0);
}

static void test_breaker_lists_only_crash_restores(void **state)
{
  (void)state;
  /* Restored because it was live at the crash: the breaker may skip it
   * if this start dies inside its window. */
  assert_int_equal(bounce_boot_lists(BOUNCE_RESTORE_HELD_AT_CRASH), 1);
  /* Held before the crash: restored before the crash restore existed,
   * and never skipped (ruling 2026-11-06). */
  assert_int_equal(bounce_boot_lists(BOUNCE_RESTORE_HELD), 0);
  assert_int_equal(bounce_boot_lists(BOUNCE_RESTORE_EXPIRED), 0);
}

static void test_boot_record_codec(void **state)
{
  size_t len = bounce_boot_rec_size(2);
  /* Odd-aligned on purpose: the store's value buffers have no alignment. */
  unsigned char *raw = calloc(1, len + 2);
  unsigned char *buf = raw + 1;
  enum bounce_boot_state st = BOUNCE_BOOT_NONE;
  int64_t start = 0;
  uint32_t count = 0;
  char longid[BOUNCER_SESSID_LEN + 10];

  (void)state;
  assert_non_null(raw);
  assert_true(bounce_boot_rec_size(0) < len);
  assert_true(len == bounce_boot_rec_size(0) + 2 * BOUNCER_SESSID_LEN);
  memset(longid, 'z', sizeof(longid) - 1);
  longid[sizeof(longid) - 1] = '\0';
  bounce_boot_rec_put_header(buf, BOUNCE_BOOT_RUNNING, NOW - 5, 2);
  bounce_boot_rec_put_id(buf, 0, "AZ4tXlSJcGOC5duroPhR2g");
  bounce_boot_rec_put_id(buf, 1, longid);
  assert_int_equal(bounce_boot_rec_decode(buf, len, &st, &start, &count), 0);
  assert_int_equal(st, BOUNCE_BOOT_RUNNING);
  assert_true(start == NOW - 5);
  assert_int_equal(count, 2);
  assert_string_equal(bounce_boot_rec_id(buf, 0), "AZ4tXlSJcGOC5duroPhR2g");
  assert_int_equal(strlen(bounce_boot_rec_id(buf, 1)), BOUNCER_SESSID_LEN - 1);

  /* Not ours: a short value, a long one, a bad version or state, an id
   * without its NUL. */
  assert_int_equal(bounce_boot_rec_decode(buf, 3, &st, &start, &count), -1);
  assert_int_equal(bounce_boot_rec_decode(buf, len - 1, &st, &start, &count), -1);
  assert_int_equal(bounce_boot_rec_decode(buf, len + 1, &st, &start, &count), -1);
  buf[0] ^= 0x40;
  assert_int_equal(bounce_boot_rec_decode(buf, len, &st, &start, &count), -1);
  buf[0] ^= 0x40;
  bounce_boot_rec_put_header(buf, (enum bounce_boot_state)7, NOW - 5, 2);
  assert_int_equal(bounce_boot_rec_decode(buf, len, &st, &start, &count), -1);
  bounce_boot_rec_put_header(buf, BOUNCE_BOOT_RUNNING, NOW - 5, 2);
  memset(buf + bounce_boot_rec_size(1), 'q', BOUNCER_SESSID_LEN);
  assert_int_equal(bounce_boot_rec_decode(buf, len, &st, &start, &count), -1);

  /* A settled record names none. */
  bounce_boot_rec_put_header(buf, BOUNCE_BOOT_SETTLED, NOW - 9, 0);
  assert_int_equal(bounce_boot_rec_decode(buf, bounce_boot_rec_size(0), &st,
                                          &start, &count), 0);
  assert_int_equal(st, BOUNCE_BOOT_SETTLED);
  assert_int_equal(count, 0);
  free(raw);
}

static void test_alive_record_codec(void **state)
{
  unsigned char buf[BOUNCE_ALIVE_REC_SIZE + 1];
  int64_t t = 0;

  (void)state;
  bounce_alive_rec_encode(buf + 1, NOW - 7);
  assert_int_equal(bounce_alive_rec_decode(buf + 1, BOUNCE_ALIVE_REC_SIZE, &t), 0);
  assert_true(t == NOW - 7);
  assert_int_equal(bounce_alive_rec_decode(buf + 1, BOUNCE_ALIVE_REC_SIZE - 1, &t), -1);
  assert_int_equal(bounce_alive_rec_decode(buf + 1, 8, &t), -1);
  buf[1] ^= 0x40;
  assert_int_equal(bounce_alive_rec_decode(buf + 1, BOUNCE_ALIVE_REC_SIZE, &t), -1);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_layout_sizes),
    cmocka_unit_test(test_frozen_layout_offsets),
    cmocka_unit_test(test_v8_migrates),
    cmocka_unit_test(test_v8_alias_count_is_clamped),
    cmocka_unit_test(test_v9_migrates),
    cmocka_unit_test(test_v7_leaves_sessid_to_caller),
    cmocka_unit_test(test_v10_v11_and_current),
    cmocka_unit_test(test_wrong_size_and_unknown),
    cmocka_unit_test(test_unterminated_strings_stay_bounded),
    cmocka_unit_test(test_marker_value_is_pinned),
    cmocka_unit_test(test_record_field_offsets),
    cmocka_unit_test(test_restore_zero_and_negatives_are_expired),
    cmocka_unit_test(test_restore_marker_held_from_the_crash),
    cmocka_unit_test(test_restore_marker_without_heartbeat_is_held_from_now),
    cmocka_unit_test(test_restore_marker_outage_outlived_its_hold),
    cmocka_unit_test(test_restore_marker_past_max_hold),
    cmocka_unit_test(test_restore_real_time_is_todays_check),
    cmocka_unit_test(test_marker_is_expired_for_an_old_binary),
    cmocka_unit_test(test_stamp_real_time_is_written_as_is),
    cmocka_unit_test(test_stamp_hold_not_ours_to_bring_back),
    cmocka_unit_test(test_stamp_restorable_active_session),
    cmocka_unit_test(test_stamp_each_missing_fact_writes_zero),
    cmocka_unit_test(test_shutdown_stamp_is_the_crash_rule),
    cmocka_unit_test(test_record_marked),
    cmocka_unit_test(test_stamp_then_restore_round_trip),
    cmocka_unit_test(test_hold_length_earned),
    cmocka_unit_test(test_hold_length_decay),
    cmocka_unit_test(test_breaker),
    cmocka_unit_test(test_breaker_lists_only_crash_restores),
    cmocka_unit_test(test_boot_steps),
    cmocka_unit_test(test_boot_record_codec),
    cmocka_unit_test(test_alive_record_codec),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
