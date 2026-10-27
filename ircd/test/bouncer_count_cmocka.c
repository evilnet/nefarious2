/* cmocka suite for the bouncer's client-counter rule (include/bouncer_count.h). */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>
#include <cmocka.h>

#include "../../include/bouncer_count.h"

static void expect_counts(const struct bounce_counts *c, int clients,
                          int local_clients, int server_clients,
                          int local_announced, int announced)
{
  assert_int_equal(c->clients, clients);
  assert_int_equal(c->local_clients, local_clients);
  assert_int_equal(c->server_clients, server_clients);
  assert_int_equal(c->local_announced, local_announced);
  assert_int_equal(c->announced, announced);
}

/* The roles, by the facts the exit reads: (local, alias, socket counted). */
static void held_by(int local, int alias, int socket, struct bounce_counts *c)
{
  memset(c, 0x55, sizeof(*c));   /* a stale value never passes for a 0 */
  bounce_count_held(local, alias, socket, c);
}
#define LIVE(c)          held_by(1, 0, 1, (c))   /* a live user of ours */
#define HELD(c)          held_by(1, 0, 0, (c))   /* a held ghost of ours */
#define ALIAS(c)         held_by(1, 1, 1, (c))   /* an alias of ours */
#define REMOTE_USER(c)   held_by(0, 0, 0, (c))   /* introduced by N */
#define REMOTE_ALIAS(c)  held_by(0, 1, 0, (c))   /* introduced by BX C */

static void held_is_what_the_exit_releases(void **s)
{
  int local, alias, socket;
  struct bounce_counts c;
  (void)s;
  /* By hand, the three exits: Count_clientdisconnects for a client of
   * ours, Count_remoteclientquits for another server's non-alias, and
   * nothing for another server's alias (exit_one_client's alias branch,
   * the BX X handler). */
  for (local = 0; local < 2; local++)
    for (alias = 0; alias < 2; alias++)
      for (socket = 0; socket < 2; socket++) {
        held_by(local, alias, socket, &c);
        if (local)
          expect_counts(&c, 1, socket, 0, !alias, !alias);
        else if (!alias)
          expect_counts(&c, 1, 0, 1, 0, 1);
        else
          expect_counts(&c, 0, 0, 0, 0, 0);
      }
}

static void each_role_holds(void **s)
{
  struct bounce_counts c;
  (void)s;
  LIVE(&c);         expect_counts(&c, 1, 1, 0, 1, 1);
  HELD(&c);         expect_counts(&c, 1, 0, 0, 1, 1);
  ALIAS(&c);        expect_counts(&c, 1, 1, 0, 0, 0);
  REMOTE_USER(&c);  expect_counts(&c, 1, 0, 1, 0, 1);
  REMOTE_ALIAS(&c); expect_counts(&c, 0, 0, 0, 0, 0);
  /* Another server's client carries no socket of ours, whatever its
   * flag says. */
  held_by(0, 0, 1, &c);
  expect_counts(&c, 1, 0, 1, 0, 1);
  held_by(0, 1, 1, &c);
  expect_counts(&c, 0, 0, 0, 0, 0);
}

static void move(void (*from)(struct bounce_counts *),
                 void (*to)(struct bounce_counts *), struct bounce_counts *d)
{
  struct bounce_counts a, b;
  from(&a);
  to(&b);
  memset(d, 0x55, sizeof(*d));
  bounce_count_delta(&a, &b, d);
}
static void f_live(struct bounce_counts *c) { LIVE(c); }
static void f_held(struct bounce_counts *c) { HELD(c); }
static void f_alias(struct bounce_counts *c) { ALIAS(c); }
static void f_ruser(struct bounce_counts *c) { REMOTE_USER(c); }
static void f_ralias(struct bounce_counts *c) { REMOTE_ALIAS(c); }
static void f_none(struct bounce_counts *c) { memset(c, 0, sizeof(*c)); }

static void each_conversion_moves(void **s)
{
  struct bounce_counts d;
  (void)s;
  /* A primary's socket drops and the session holds: the socket only. */
  move(f_live, f_held, &d);    expect_counts(&d, 0, -1, 0, 0, 0);
  /* A login revives the ghost: its socket again. */
  move(f_held, f_live, &d);    expect_counts(&d, 0, +1, 0, 0, 0);
  /* A live primary demoted to an alias (a merge), or a registering
   * client set up as one: no longer announced. */
  move(f_live, f_alias, &d);   expect_counts(&d, 0, 0, 0, -1, -1);
  /* An alias of ours promoted to primary (ours, or a peer's BX P naming
   * it): announced again. */
  move(f_alias, f_live, &d);   expect_counts(&d, 0, 0, 0, +1, +1);
  /* Another server's alias promoted there (its BX P, or our own promote
   * of a remote alias): a user that server introduced. */
  move(f_ralias, f_ruser, &d); expect_counts(&d, +1, 0, +1, 0, +1);
  /* Another server's primary converted in place into an alias (BX C):
   * counted nowhere. */
  move(f_ruser, f_ralias, &d); expect_counts(&d, -1, 0, -1, 0, -1);
  /* A held ghost of ours rebound to another server's client: still one
   * announced user, now that server's (server count of the new server). */
  move(f_held, f_ruser, &d);   expect_counts(&d, 0, 0, +1, -1, 0);
  /* A ghost restored from the database: a held ghost of ours. */
  move(f_none, f_held, &d);    expect_counts(&d, +1, 0, 0, +1, +1);
}

static void add(struct bounce_counts *acc, const struct bounce_counts *c, int sign)
{
  acc->clients += sign * c->clients;
  acc->local_clients += sign * c->local_clients;
  acc->server_clients += sign * c->server_clients;
  acc->local_announced += sign * c->local_announced;
  acc->announced += sign * c->announced;
}

static void a_life_releases_what_it_took(void **s)
{
  void (*roles[])(struct bounce_counts *) = {
    f_live, f_held, f_alias, f_ruser, f_ralias, f_none
  };
  const int n = (int)(sizeof(roles) / sizeof(roles[0]));
  struct bounce_counts a, b, d, acc;
  int i, j;
  (void)s;
  /* After any conversion the client holds exactly what its new role
   * holds: its exit, which releases by its facts then, takes back all of
   * it and nothing more. */
  for (i = 0; i < n; i++)
    for (j = 0; j < n; j++) {
      roles[i](&a);
      roles[j](&b);
      bounce_count_delta(&a, &b, &d);
      memset(&acc, 0, sizeof(acc));
      add(&acc, &a, +1);
      add(&acc, &d, +1);
      add(&acc, &b, -1);
      expect_counts(&acc, 0, 0, 0, 0, 0);
    }

  /* The merge of two primaries, on each server: the converted one ends
   * as an alias, and its exit leaves every count where it was before it
   * connected. */
  memset(&acc, 0, sizeof(acc));
  LIVE(&a); add(&acc, &a, +1);                        /* registers */
  move(f_live, f_alias, &d); add(&acc, &d, +1);       /* demoted */
  ALIAS(&b); add(&acc, &b, -1);                       /* exits */
  expect_counts(&acc, 0, 0, 0, 0, 0);
  memset(&acc, 0, sizeof(acc));
  REMOTE_USER(&a); add(&acc, &a, +1);                 /* its N */
  move(f_ruser, f_ralias, &d); add(&acc, &d, +1);     /* converted */
  REMOTE_ALIAS(&b); add(&acc, &b, -1);                /* its BX X */
  expect_counts(&acc, 0, 0, 0, 0, 0);
}

static void null_safe(void **s)
{
  struct bounce_counts c;
  (void)s;
  bounce_count_held(1, 0, 1, NULL);
  bounce_count_delta(NULL, NULL, NULL);
  memset(&c, 0x55, sizeof(c));
  bounce_count_delta(NULL, NULL, &c);
  expect_counts(&c, 0, 0, 0, 0, 0);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(held_is_what_the_exit_releases),
    cmocka_unit_test(each_role_holds),
    cmocka_unit_test(each_conversion_moves),
    cmocka_unit_test(a_life_releases_what_it_took),
    cmocka_unit_test(null_safe),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
