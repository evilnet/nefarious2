/*
 * exit_reason_cmocka.c - which realnames are dead_link()'s old clobber.
 */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>
#include <cmocka.h>

#include "../../include/exit_reason.h"

/* What dead_link() wrote (send.c), cut to REALLEN as the realname was. */
static void test_dead_link_texts_are_clobbers(void **state)
{
  (void)state;
  assert_true(exit_reason_is_clobbered_info("Write error: Internal OpenSSL error or protocol er"));
  assert_true(exit_reason_is_clobbered_info("Write error: Success"));
  assert_true(exit_reason_is_clobbered_info("Write error: Broken pipe"));
  assert_true(exit_reason_is_clobbered_info("Max sendQ exceeded"));
  assert_true(exit_reason_is_clobbered_info("Buffer allocation error"));
}

/* A real realname is left alone, even one that mentions an error. */
static void test_real_names_are_not(void **state)
{
  (void)state;
  assert_false(exit_reason_is_clobbered_info("Richard Drake"));
  assert_false(exit_reason_is_clobbered_info("my Write error: collection"));
  assert_false(exit_reason_is_clobbered_info("Max sendQ exceeded fan club"));
  assert_false(exit_reason_is_clobbered_info("Write error"));
  assert_false(exit_reason_is_clobbered_info(""));
  assert_false(exit_reason_is_clobbered_info(NULL));
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_dead_link_texts_are_clobbers),
    cmocka_unit_test(test_real_names_are_not),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
