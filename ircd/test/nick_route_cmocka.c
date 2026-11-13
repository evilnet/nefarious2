/*
 * nick_route_cmocka.c - CMocka tests for nick_writer_route() and the
 * pure rules beside it (nick_writer_route_path(), nick_request_action()).
 *
 * The walk is linked as it is (../nick_route.o, with bouncer_wire.c): a
 * device's server sends BX W only when every server from the primary's up
 * to our own link is IRCv3-aware and announced flag N.  The trees are
 * built by hand (cli_serv()->up chains ending at &me).
 */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

#include "bouncer_wire.h"
#include "client.h"
#include "ircd_defs.h"
#include "struct.h"
#include "nick_route.h"

struct Client me;

#define F_V 1   /* 'v' */
#define F_N 2   /* 'N' */
#define NEW (F_V | F_N)

struct node {
  struct Client cli;
  struct Server serv;
};

static struct Client *mk(struct node *n, struct Client *up, int flags)
{
  memset(n, 0, sizeof(*n));
  cli_status(&n->cli) = STAT_SERVER;
  cli_serv(&n->cli) = &n->serv;
  n->serv.up = up;
  if (flags & F_V)
    SetIRCv3Aware(&n->cli);
  if (flags & F_N)
    SetNickWriter(&n->cli);
  return &n->cli;
}

static int setup(void **state)
{
  (void)state;
  memset(&me, 0, sizeof(me));
  cli_status(&me) = STAT_ME;
  return 0;
}

static void test_ends(void **state)
{
  (void)state;
  assert_false(nick_writer_route(NULL));
  assert_false(nick_writer_route(&me));   /* our own primary: no request */
}

/* Prod: F2 -- F1, both new. */
static void test_direct_new_link(void **state)
{
  struct node a;
  (void)state;
  assert_true(nick_writer_route(mk(&a, &me, NEW)));
}

/* The primary's server is an older fork server (v, no N), or legacy. */
static void test_home_without_n(void **state)
{
  struct node a;
  (void)state;
  assert_false(nick_writer_route(mk(&a, &me, F_V)));
  assert_false(nick_writer_route(mk(&a, &me, 0)));
  /* N without v: a legacy relay cannot carry it; never trusted. */
  assert_false(nick_writer_route(mk(&a, &me, F_N)));
}

/* Three new servers in a row: the middle one forwards. */
static void test_new_chain(void **state)
{
  struct node mid, far;
  struct Client *m, *f;
  (void)state;
  m = mk(&mid, &me, NEW);
  f = mk(&far, m, NEW);
  assert_true(nick_writer_route(f));
  assert_true(nick_writer_route(m));
}

/* An older fork hop or a legacy hop on the way: false for every server
 * behind it, whatever they announced. */
static void test_old_or_legacy_middle(void **state)
{
  struct node mid, far;
  struct Client *m, *f;
  (void)state;
  m = mk(&mid, &me, F_V);
  f = mk(&far, m, NEW);
  assert_false(nick_writer_route(f));
  m = mk(&mid, &me, 0);
  f = mk(&far, m, NEW);
  assert_false(nick_writer_route(f));
}

/* A non-server in the chain, a chain that never reaches us, a loop. */
static void test_broken_trees(void **state)
{
  struct node a, b;
  struct Client *x, *y;
  (void)state;
  x = mk(&a, NULL, NEW);                 /* no way to us */
  assert_false(nick_writer_route(x));
  x = mk(&a, &me, NEW);
  y = mk(&b, x, NEW);
  cli_status(x) = STAT_USER;             /* a user is no server */
  assert_false(nick_writer_route(y));
  x = mk(&a, NULL, NEW);
  y = mk(&b, x, NEW);
  a.serv.up = y;                         /* a loop: the hop cap ends it */
  assert_false(nick_writer_route(y));
}

/* ---- the pure path rule ---- */
static void test_path_rule(void **state)
{
  (void)state;
  assert_true(nick_writer_route_path(1, 1, 1));
  assert_true(nick_writer_route_path(3, 3, 1));
  assert_false(nick_writer_route_path(3, 2, 1));   /* one hop without N */
  assert_false(nick_writer_route_path(3, 3, 0));   /* never reached us */
  assert_false(nick_writer_route_path(0, 0, 1));   /* no hop at all */
}

/* ---- what a server does with a BX W ---- */

/* A well-formed request from the device's own server, over its link. */
static struct nick_request_facts req(void)
{
  struct nick_request_facts f;
  memset(&f, 0, sizeof(f));
  f.found = 1;
  f.is_alias = 1;
  f.device_dir_is_link = 1;
  f.source_is_device_server = 1;
  return f;
}

static void test_request_write_forward_drop(void **state)
{
  struct nick_request_facts f;
  (void)state;
  f = req(); f.primary_ours = 1;
  assert_int_equal(nick_request_action(&f), NICK_REQUEST_WRITE_DEVICE);
  f = req();                                   /* a middle server */
  assert_int_equal(nick_request_action(&f), NICK_REQUEST_FORWARD);
  f = req(); f.primary_dir_is_link = 1;        /* loop: crossed promote */
  assert_int_equal(nick_request_action(&f), NICK_REQUEST_DROP);
  f = req(); f.found = 0;                      /* the device left */
  assert_int_equal(nick_request_action(&f), NICK_REQUEST_DROP);
  f = req(); f.is_alias = 0;                   /* promoted on that side */
  assert_int_equal(nick_request_action(&f), NICK_REQUEST_RETURN);
}

/* Security review 1: nobody asks us to rename a client of ours. */
static void test_request_naming_ours_rejected(void **state)
{
  struct nick_request_facts f;
  (void)state;
  f = req(); f.device_ours = 1; f.is_alias = 0;      /* an ordinary user */
  assert_int_equal(nick_request_action(&f), NICK_REQUEST_REJECT);
  f = req(); f.device_ours = 1; f.is_alias = 0;      /* even a primary */
  f.session_primary_ours = 1; f.asked_here = 1;
  assert_int_equal(nick_request_action(&f), NICK_REQUEST_REJECT);
  f = req(); f.device_ours = 1; f.primary_ours = 1;  /* our own device */
  assert_int_equal(nick_request_action(&f), NICK_REQUEST_REJECT);
}

/* Security review 2: only the device's own server, over its direction. */
static void test_request_wrong_origin_rejected(void **state)
{
  struct nick_request_facts f;
  (void)state;
  f = req(); f.primary_ours = 1; f.source_is_device_server = 0;
  assert_int_equal(nick_request_action(&f), NICK_REQUEST_REJECT);
  f = req(); f.primary_ours = 1; f.device_dir_is_link = 0;
  assert_int_equal(nick_request_action(&f), NICK_REQUEST_REJECT);
  f = req(); f.source_is_device_server = 0;          /* not forwarded either */
  assert_int_equal(nick_request_action(&f), NICK_REQUEST_REJECT);
  f = req(); f.is_alias = 0; f.device_dir_is_link = 0;
  assert_int_equal(nick_request_action(&f), NICK_REQUEST_REJECT);
}

/* A returned request (R): applied only by the device's own server, for a
 * session primary of ours that itself asked for it; elsewhere it travels
 * toward the device. */
static void test_return(void **state)
{
  struct nick_request_facts f;
  (void)state;
  memset(&f, 0, sizeof(f));
  f.found = 1; f.is_return = 1; f.device_ours = 1;
  f.session_primary_ours = 1; f.asked_here = 1;
  assert_int_equal(nick_request_action(&f), NICK_REQUEST_WRITE_OWN);
  f.asked_here = 0;                  /* a return we never asked for */
  assert_int_equal(nick_request_action(&f), NICK_REQUEST_REJECT);
  f.asked_here = 1; f.session_primary_ours = 0;  /* no session primary */
  assert_int_equal(nick_request_action(&f), NICK_REQUEST_REJECT);
  f.session_primary_ours = 1; f.is_alias = 1;    /* not promoted here */
  assert_int_equal(nick_request_action(&f), NICK_REQUEST_DROP);
  memset(&f, 0, sizeof(f));          /* a middle server, toward the device */
  f.found = 1; f.is_return = 1;
  assert_int_equal(nick_request_action(&f), NICK_REQUEST_FORWARD);
  f.device_dir_is_link = 1;          /* "returned" from the device's side */
  assert_int_equal(nick_request_action(&f), NICK_REQUEST_REJECT);
  f.device_dir_is_link = 0; f.is_alias = 1;
  assert_int_equal(nick_request_action(&f), NICK_REQUEST_DROP);
  f.found = 0;
  assert_int_equal(nick_request_action(&f), NICK_REQUEST_DROP);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test_setup(test_ends, setup),
    cmocka_unit_test_setup(test_direct_new_link, setup),
    cmocka_unit_test_setup(test_home_without_n, setup),
    cmocka_unit_test_setup(test_new_chain, setup),
    cmocka_unit_test_setup(test_old_or_legacy_middle, setup),
    cmocka_unit_test_setup(test_broken_trees, setup),
    cmocka_unit_test(test_path_rule),
    cmocka_unit_test(test_request_write_forward_drop),
    cmocka_unit_test(test_request_naming_ours_rejected),
    cmocka_unit_test(test_request_wrong_origin_rejected),
    cmocka_unit_test(test_return),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
