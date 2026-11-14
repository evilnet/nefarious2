/*
 * iauth_held_t.c - what becomes of a client an IAuth instance was still
 * checking when the instance went away (include/iauth_held.h).
 *
 * A held client is handed to a new instance when one is running by the
 * time the server decides; otherwise it is refused when the check was
 * required (the R policy) and IAuth had not tentatively accepted it (d),
 * and released (registered without IAuth) when it was not.  Whether the
 * check was required is the policy the departed instance announced; an
 * instance that announced none (it went away before its O line) leaves
 * the client as required as it was.
 *
 * A line about a client that only a policy option asks for (H, n, u, U,
 * P, F, R) is kept untold while the instance it would go to has not
 * announced its policy, and told or forgotten once it has; lines no
 * option gates (C, N, d, W, w) are told at once.
 *
 * A failed assertion prints where and what; the program exits non-zero
 * if any did.
 */
#include <stdio.h>

#include "iauth_held.h"

static int checks;              /**< assertions evaluated */
static int failures;            /**< assertions that did not hold */

static void check(int ok, const char *file, int line, const char *what)
{
  checks++;
  if (!ok) {
    failures++;
    printf("FAILED %s:%d: %s\n", file, line, what);
  }
}

#define assert_int_equal(a, b) \
  check((long)(a) == (long)(b), __FILE__, __LINE__, #a " == " #b)

static void a_running_instance_takes_every_held_client(void)
{
  assert_int_equal(iauth_held_fate(1, 0, 0), IAUTH_HELD_HAND_OVER);
  assert_int_equal(iauth_held_fate(1, 1, 0), IAUTH_HELD_HAND_OVER);
  assert_int_equal(iauth_held_fate(1, 1, 1), IAUTH_HELD_HAND_OVER);
  assert_int_equal(iauth_held_fate(1, 0, 1), IAUTH_HELD_HAND_OVER);
}

static void without_one_a_required_check_refuses(void)
{
  assert_int_equal(iauth_held_fate(0, 1, 0), IAUTH_HELD_REFUSE);
}

static void without_one_a_tentative_accept_is_released(void)
{
  /* as at a registration timeout under R: d lets the client in */
  assert_int_equal(iauth_held_fate(0, 1, 1), IAUTH_HELD_RELEASE);
}

static void without_one_an_optional_check_is_released(void)
{
  assert_int_equal(iauth_held_fate(0, 0, 0), IAUTH_HELD_RELEASE);
  assert_int_equal(iauth_held_fate(0, 0, 1), IAUTH_HELD_RELEASE);
}

static void the_announced_policy_decides_required(void)
{
  assert_int_equal(iauth_held_required(1, 1, 0), 1);
  assert_int_equal(iauth_held_required(1, 0, 1), 0);
  assert_int_equal(iauth_held_required(1, 1, 1), 1);
  assert_int_equal(iauth_held_required(1, 0, 0), 0);
}

static void no_announced_policy_keeps_what_the_client_carried(void)
{
  /* handed to a new instance that died before its O line */
  assert_int_equal(iauth_held_required(0, 0, 1), 1);
  assert_int_equal(iauth_held_required(0, 0, 0), 0);
}

#define ASKS_ALL (IAUTH_ASKS_ADDLINFO | IAUTH_ASKS_UNDERNET | IAUTH_ASKS_SSLFP \
                  | IAUTH_ASKS_ACCOUNT)

static void lines_no_option_gates_are_told_at_once(void)
{
  static const char ungated[] = "CNdWw";
  const char *c;

  for (c = ungated; *c; c++) {
    assert_int_equal(iauth_line_verdict(*c, 0, 0), IAUTH_LINE_TELL);
    assert_int_equal(iauth_line_verdict(*c, 1, 0), IAUTH_LINE_TELL);
    assert_int_equal(iauth_line_verdict(*c, 1, ASKS_ALL), IAUTH_LINE_TELL);
  }
}

static void before_the_policy_gated_lines_are_kept(void)
{
  static const char gated[] = "HnuUPFR";
  const char *c;

  /* whatever policy bits a struct carries before its O line */
  for (c = gated; *c; c++) {
    assert_int_equal(iauth_line_verdict(*c, 0, 0), IAUTH_LINE_KEEP);
    assert_int_equal(iauth_line_verdict(*c, 0, ASKS_ALL), IAUTH_LINE_KEEP);
  }
}

static void policy_u_asks_for_nick_ident_user_and_hurry(void)
{
  assert_int_equal(iauth_line_verdict('n', 1, IAUTH_ASKS_UNDERNET), IAUTH_LINE_TELL);
  assert_int_equal(iauth_line_verdict('u', 1, IAUTH_ASKS_UNDERNET), IAUTH_LINE_TELL);
  assert_int_equal(iauth_line_verdict('U', 1, IAUTH_ASKS_UNDERNET), IAUTH_LINE_TELL);
  assert_int_equal(iauth_line_verdict('H', 1, IAUTH_ASKS_UNDERNET), IAUTH_LINE_TELL);
  assert_int_equal(iauth_line_verdict('P', 1, IAUTH_ASKS_UNDERNET), IAUTH_LINE_FORGET);
  assert_int_equal(iauth_line_verdict('F', 1, IAUTH_ASKS_UNDERNET), IAUTH_LINE_FORGET);
  assert_int_equal(iauth_line_verdict('R', 1, IAUTH_ASKS_UNDERNET), IAUTH_LINE_FORGET);
}

static void policy_a_alone_asks_for_password_and_short_user(void)
{
  assert_int_equal(iauth_line_verdict('P', 1, IAUTH_ASKS_ADDLINFO), IAUTH_LINE_TELL);
  assert_int_equal(iauth_line_verdict('U', 1, IAUTH_ASKS_ADDLINFO), IAUTH_LINE_TELL_SHORT);
  assert_int_equal(iauth_line_verdict('n', 1, IAUTH_ASKS_ADDLINFO), IAUTH_LINE_FORGET);
  assert_int_equal(iauth_line_verdict('u', 1, IAUTH_ASKS_ADDLINFO), IAUTH_LINE_FORGET);
  assert_int_equal(iauth_line_verdict('H', 1, IAUTH_ASKS_ADDLINFO), IAUTH_LINE_FORGET);
}

static void policy_a_and_u_tell_the_full_user_line(void)
{
  unsigned int au = IAUTH_ASKS_ADDLINFO | IAUTH_ASKS_UNDERNET;

  assert_int_equal(iauth_line_verdict('U', 1, au), IAUTH_LINE_TELL);
  assert_int_equal(iauth_line_verdict('P', 1, au), IAUTH_LINE_TELL);
}

static void policy_f_and_r_ask_for_fingerprint_and_account(void)
{
  assert_int_equal(iauth_line_verdict('F', 1, IAUTH_ASKS_SSLFP), IAUTH_LINE_TELL);
  assert_int_equal(iauth_line_verdict('R', 1, IAUTH_ASKS_ACCOUNT), IAUTH_LINE_TELL);
  assert_int_equal(iauth_line_verdict('F', 1, IAUTH_ASKS_ACCOUNT), IAUTH_LINE_FORGET);
  assert_int_equal(iauth_line_verdict('R', 1, IAUTH_ASKS_SSLFP), IAUTH_LINE_FORGET);
}

static void an_empty_policy_forgets_every_gated_line(void)
{
  static const char gated[] = "HnuUPFR";
  const char *c;

  for (c = gated; *c; c++)
    assert_int_equal(iauth_line_verdict(*c, 1, 0), IAUTH_LINE_FORGET);
}

int main(void)
{
  lines_no_option_gates_are_told_at_once();
  before_the_policy_gated_lines_are_kept();
  policy_u_asks_for_nick_ident_user_and_hurry();
  policy_a_alone_asks_for_password_and_short_user();
  policy_a_and_u_tell_the_full_user_line();
  policy_f_and_r_ask_for_fingerprint_and_account();
  an_empty_policy_forgets_every_gated_line();
  a_running_instance_takes_every_held_client();
  without_one_a_required_check_refuses();
  without_one_a_tentative_accept_is_released();
  without_one_an_optional_check_is_released();
  the_announced_policy_decides_required();
  no_announced_policy_keeps_what_the_client_carried();
  printf("iauth_held_t: %d checks, %d failed\n", checks, failures);
  return failures ? 1 : 0;
}
