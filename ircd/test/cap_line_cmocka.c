/* cap_line_cmocka.c - CMocka tests for include/cap_line.h
 *
 * A CAP LS or LIST reply to a client older than CAP 302 is one line
 * (capability-negotiation, "Multiline replies to CAP LS and CAP LIST";
 * irctest cap.py testNoMultiline301Response).
 */

#include "config.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "cap_line.h"

/** LS and LIST go on several lines only to a 302 client. */
static void multiline_only_for_302(void **state)
{
  (void)state;
  assert_false(cap_reply_multiline(0, 1));
  assert_false(cap_reply_multiline(301, 1));
  assert_true(cap_reply_multiline(302, 1));
  assert_true(cap_reply_multiline(0, 0));     /* ACK: as before */
}

/** Only a 302 client's LS / LIST lines carry "* ": nobody else's line
 * keeps room for it. */
static void marker_room_only_for_302(void **state)
{
  (void)state;
  assert_int_equal(cap_line_reserve(0, 1), 0);
  assert_int_equal(cap_line_reserve(301, 1), 0);
  assert_int_equal(cap_line_reserve(302, 1), 2);
  assert_int_equal(cap_line_reserve(302, 0), 0);
}

/** A list that does not fit leaves out the vendor and draft names. */
static void narrow_list_leaves_out_vendor_caps(void **state)
{
  (void)state;
  assert_true(cap_ls_left_out("draft/chathistory", 1));
  assert_true(cap_ls_left_out("soju.im/search", 1));
  assert_false(cap_ls_left_out("multi-prefix", 1));
  assert_false(cap_ls_left_out("draft/chathistory", 0));
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(multiline_only_for_302),
    cmocka_unit_test(marker_room_only_for_302),
    cmocka_unit_test(narrow_list_leaves_out_vendor_caps),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
