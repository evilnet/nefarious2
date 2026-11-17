/*
 * sasl_turn_cmocka.c - whose turn a SASL exchange in flight is
 * (sasl_turn_is_clients(), sasl_turn.h), which decides whether a client
 * that completes registration mid-exchange has it aborted (906) or waits
 * for the backend's answer.
 *
 * SASL 3.1: "If the client completes registration (with CAP END, NICK,
 * USER and any other necessary messages) while the SASL authentication
 * is still in progress, the server SHOULD abort it and send a 906
 * numeric, then register the client without authentication."  An
 * exchange whose request is with the backend is not aborted: its answer
 * (a login, or a failure) comes on its own, and registration waits for
 * it as before.
 */
#include "config.h"
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>
#include <cmocka.h>
#include "sasl_turn.h"

/** Local (Keycloak) exchange: the client's turn unless a Keycloak request
 * is in flight; the services/IAuth count does not apply. */
static void local_session(void **state)
{
  (void)state;
  assert_true(sasl_turn_is_clients(1, 0, 0));    /* waiting for data */
  assert_false(sasl_turn_is_clients(1, 1, 0));   /* Keycloak asked */
  assert_true(sasl_turn_is_clients(1, 0, 3));
}

/** Services or IAuth: AUTHENTICATE PLAIN went out, then the challenge
 * "+" answered it -- the client's turn (irctest sasl.py
 * testRegistrationDuringSasl: then NICK, USER, CAP END). */
static void remote_challenge_answers_the_mechanism(void **state)
{
  unsigned char n = 0;
  (void)state;
  assert_true(sasl_turn_is_clients(0, 0, n));    /* nothing in flight */
  sasl_turn_line_out(&n);                        /* S PLAIN */
  assert_false(sasl_turn_is_clients(0, 0, n));   /* services' turn */
  assert_true(sasl_turn_challenge_in(&n));       /* C + */
  assert_true(sasl_turn_is_clients(0, 0, n));
  sasl_turn_line_out(&n);                        /* the credentials */
  assert_false(sasl_turn_is_clients(0, 0, n));
}

/** Pipelined credentials: the client sent AUTHENTICATE PLAIN and its
 * credentials before the "+" came.  That "+" answers the mechanism line;
 * the credentials are still with the backend, so it is not the client's
 * turn (an abort then would throw a good login away). */
static void remote_pipelined_credentials(void **state)
{
  unsigned char n = 0;
  (void)state;
  sasl_turn_line_out(&n);                        /* S PLAIN */
  sasl_turn_line_out(&n);                        /* C <credentials> */
  assert_false(sasl_turn_challenge_in(&n));      /* C + */
  assert_false(sasl_turn_is_clients(0, 0, n));
  assert_true(sasl_turn_challenge_in(&n));       /* a real second challenge */
  assert_true(sasl_turn_is_clients(0, 0, n));
}

/** The count saturates, and a stray challenge does not go below 0. */
static void remote_count_bounds(void **state)
{
  unsigned char n = 254;
  int i;
  (void)state;
  for (i = 0; i < 5; i++)
    sasl_turn_line_out(&n);
  assert_int_equal(n, 255);
  n = 0;
  assert_true(sasl_turn_challenge_in(&n));
  assert_int_equal(n, 0);
}

/** A line of exactly 400 bytes continues its message; any other ends it
 * ("+" after an exact multiple, the empty response, or a backend's long
 * challenge sent unsplit). */
static void line_ends_message(void **state)
{
  char line[SASL_LINE_MAX + 2];
  (void)state;
  memset(line, 'A', sizeof(line) - 1);
  line[sizeof(line) - 1] = '\0';
  assert_true(sasl_line_ends_message(line));          /* 401: unsplit */
  line[SASL_LINE_MAX] = '\0';
  assert_false(sasl_line_ends_message(line));         /* 400: more follows */
  line[SASL_LINE_MAX - 1] = '\0';
  assert_true(sasl_line_ends_message(line));          /* 399 */
  assert_true(sasl_line_ends_message("+"));
  assert_true(sasl_line_ends_message(""));
}

/** What an exchange may start with: RFC 4422's mechanism names, up to
 * ECDSA-NIST256P-CHALLENGE's 24 characters -- and not a client's base64
 * response arriving after its exchange was aborted. */
static void mechanism_names(void **state)
{
  (void)state;
  assert_true(sasl_mechanism_name_ok("PLAIN"));
  assert_true(sasl_mechanism_name_ok("EXTERNAL"));
  assert_true(sasl_mechanism_name_ok("OAUTHBEARER"));
  assert_true(sasl_mechanism_name_ok("SCRAM-SHA-256"));
  assert_true(sasl_mechanism_name_ok("SCRAM-SHA-256-PLUS"));
  assert_true(sasl_mechanism_name_ok("ECDSA-NIST256P-CHALLENGE"));
  assert_true(sasl_mechanism_name_ok("X_TEST9"));
  assert_false(sasl_mechanism_name_ok(""));
  assert_false(sasl_mechanism_name_ok(NULL));
  assert_false(sasl_mechanism_name_ok("ECDSA-NIST256P-CHALLENGEX"));  /* 25 */
  assert_false(sasl_mechanism_name_ok("plain"));       /* RFC 4422: upper case */
  assert_false(sasl_mechanism_name_ok("+"));
  assert_false(sasl_mechanism_name_ok("AGFsaWNlAHNlY3JldA=="));  /* \0alice\0secret */
  assert_false(sasl_mechanism_name_ok("AGFiAGNk"));    /* \0ab\0cd: lower case */
  assert_false(sasl_mechanism_name_ok("PL AIN"));
}

/** A lower-case mechanism is taken when the advertised list has it, in
 * the list's spelling; nothing else is, and never a part of an entry. */
static void mechanism_listed(void **state)
{
  static const char list[] = "PLAIN,EXTERNAL,SCRAM-SHA-256";
  (void)state;
  assert_ptr_equal(sasl_mechanism_listed("plain", list), list);
  assert_ptr_equal(sasl_mechanism_listed("Plain", list), list);
  assert_ptr_equal(sasl_mechanism_listed("external", list), list + 6);
  assert_ptr_equal(sasl_mechanism_listed("scram-sha-256", list), list + 15);
  assert_null(sasl_mechanism_listed("plai", list));
  assert_null(sasl_mechanism_listed("plain,external", list));
  assert_null(sasl_mechanism_listed("scram-sha-25", list));
  assert_null(sasl_mechanism_listed("scram-sha-2567", list));
  assert_null(sasl_mechanism_listed("oauthbearer", list));
  assert_null(sasl_mechanism_listed("", list));
  assert_null(sasl_mechanism_listed("", ",PLAIN"));
  assert_null(sasl_mechanism_listed("AGFiAGNk", list));
  assert_null(sasl_mechanism_listed("plain", NULL));
  assert_null(sasl_mechanism_listed("plain", ""));
  assert_null(sasl_mechanism_listed(NULL, list));
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(local_session),
    cmocka_unit_test(remote_challenge_answers_the_mechanism),
    cmocka_unit_test(remote_pipelined_credentials),
    cmocka_unit_test(remote_count_bounds),
    cmocka_unit_test(line_ends_message),
    cmocka_unit_test(mechanism_names),
    cmocka_unit_test(mechanism_listed),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
