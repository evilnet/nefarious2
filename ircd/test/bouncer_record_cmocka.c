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

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_layout_sizes),
    cmocka_unit_test(test_v8_migrates),
    cmocka_unit_test(test_v8_alias_count_is_clamped),
    cmocka_unit_test(test_v9_migrates),
    cmocka_unit_test(test_v7_leaves_sessid_to_caller),
    cmocka_unit_test(test_v10_v11_and_current),
    cmocka_unit_test(test_wrong_size_and_unknown),
    cmocka_unit_test(test_unterminated_strings_stay_bounded),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
