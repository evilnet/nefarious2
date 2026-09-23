/* cmocka suite for the pure bouncer deauth decision points
 * (include/bouncer_deauth.h). */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>
#include <cmocka.h>

#include "../../include/bouncer_deauth.h"

/* Every field name that appears on the BX U wire.  The receiver in
 * bounce_alias_update() is the reference list; the local-apply block in
 * bounce_emit_alias_update() had drifted two fields behind it, which is
 * the bug this table exists to prevent recurring. */
static const char *const wire_fields[] = {
  "host", "realhost", "realname", "fakehost",
  "cloakhost", "cloakip", "username", "account", "caps"
};

static void test_account_is_a_known_field(void **state)
{
  (void)state;
  /* The live-in-prod bug: the local-apply block had no "account" case, so
   * local aliases never learned an account set or clear. */
  assert_int_equal(bounce_alias_field_id("account"), BX_ALIAS_FIELD_ACCOUNT);
  assert_int_equal(bounce_alias_field_id("caps"), BX_ALIAS_FIELD_CAPS);
}

static void test_every_wire_field_maps(void **state)
{
  (void)state;
  size_t i;
  for (i = 0; i < sizeof(wire_fields) / sizeof(wire_fields[0]); i++)
    assert_int_not_equal(bounce_alias_field_id(wire_fields[i]),
                         BX_ALIAS_FIELD_UNKNOWN);
}

static void test_field_ids_are_distinct_and_complete(void **state)
{
  (void)state;
  /* Completeness guard: the wire list and the enum must stay the same
   * size, so adding an enumerator without teaching the wire (or vice
   * versa) fails here rather than silently no-op'ing at runtime. */
  size_t n = sizeof(wire_fields) / sizeof(wire_fields[0]);
  size_t i, j;
  assert_int_equal((int)n, BX_ALIAS_FIELD_COUNT - 1);  /* -1 for UNKNOWN */
  for (i = 0; i < n; i++)
    for (j = i + 1; j < n; j++)
      assert_int_not_equal(bounce_alias_field_id(wire_fields[i]),
                           bounce_alias_field_id(wire_fields[j]));
}

static void test_round_trips_to_the_wire_name(void **state)
{
  (void)state;
  size_t i;
  for (i = 0; i < sizeof(wire_fields) / sizeof(wire_fields[0]); i++) {
    enum BounceAliasField id = bounce_alias_field_id(wire_fields[i]);
    assert_string_equal(bounce_alias_field_name(id), wire_fields[i]);
  }
}

static void test_unknown_and_null_are_unknown(void **state)
{
  (void)state;
  assert_int_equal(bounce_alias_field_id(NULL), BX_ALIAS_FIELD_UNKNOWN);
  assert_int_equal(bounce_alias_field_id(""), BX_ALIAS_FIELD_UNKNOWN);
  assert_int_equal(bounce_alias_field_id("nosuchfield"), BX_ALIAS_FIELD_UNKNOWN);
  /* Field names are matched case-insensitively on the wire, as
   * bounce_alias_update() used ircd_strcmp. */
  assert_int_equal(bounce_alias_field_id("ACCOUNT"), BX_ALIAS_FIELD_ACCOUNT);
  assert_ptr_equal(bounce_alias_field_name(BX_ALIAS_FIELD_UNKNOWN), NULL);
  assert_ptr_equal(bounce_alias_field_name(BX_ALIAS_FIELD_COUNT), NULL);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_account_is_a_known_field),
    cmocka_unit_test(test_every_wire_field_maps),
    cmocka_unit_test(test_field_ids_are_distinct_and_complete),
    cmocka_unit_test(test_round_trips_to_the_wire_name),
    cmocka_unit_test(test_unknown_and_null_are_unknown),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
