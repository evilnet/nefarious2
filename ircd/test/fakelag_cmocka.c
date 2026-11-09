/*
 * fakelag_cmocka.c - the post-registration fake-lag credit and the
 * shared pool behind it.
 *
 * fakelag_charge() absorbs a charge into the credit before the lag clock
 * is charged.  The credit is one-shot: it only ever decreases.
 * fakelag_spend() then draws on the pool while the allowance is live;
 * fakelag_pool_take(NULL, ), fakelag_charge_client() and fakelag_grant()
 * (ircd/fakelag.c) run against the stubs below.
 */
#include "config.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdio.h>
#include <string.h>
#include <cmocka.h>

#include "fakelag.h"
#include "class.h"
#include "client.h"
#include "ircd_features.h"
#include "struct.h"

/* Stubs for what ircd/fakelag.c calls. */
time_t CurrentTime;
static int stub_grace = 20, stub_pool = 0, stub_borrow = 0, stub_factor = -1;
static int stub_borrow_time = 30, stub_account_time = 60;

int feature_int(enum Feature feat)
{
  switch (feat) {
  case FEAT_POSTREG_GRACE:  return stub_grace;
  case FEAT_FAKELAG_POOL:   return stub_pool;
  case FEAT_FAKELAG_BORROW: return stub_borrow;
  case FEAT_FAKELAG_BORROW_TIME:  return stub_borrow_time;
  case FEAT_FAKELAG_ACCOUNT_TIME: return stub_account_time;
  default:                  return 0;
  }
}

unsigned int ircrandom(void)
{
  return 0x9e3779b9u;
}

/* Two classes, "users" and "staff"; every client is in stub_class. */
static struct ConnectionClass cl_users, cl_staff;
static struct ConnectionClass *stub_class = &cl_users;

const struct ConnectionClass *get_class_list(void)
{
  return &cl_users;
}

struct ConnectionClass *get_client_class_conf(struct Client *acptr)
{
  (void)acptr;
  return stub_class;
}

static struct Client *stub_factor_asked;   /* who get_lag_factor() was asked about */

int get_lag_factor(struct Client *cptr)
{
  /* The real one asserts a local client (class.c). */
  assert_ptr_equal(cli_from(cptr), cptr);
  stub_factor_asked = cptr;
  return stub_factor;
}

static void test_no_credit_charges_in_full(void **state)
{
  int credit = 0;
  (void)state;
  assert_int_equal(fakelag_charge(&credit, 2), 2);
  assert_int_equal(credit, 0);
}

static void test_credit_absorbs_whole_charge(void **state)
{
  int credit = 20;
  (void)state;
  assert_int_equal(fakelag_charge(&credit, 2), 0);
  assert_int_equal(credit, 18);
}

static void test_credit_absorbs_part_of_a_charge(void **state)
{
  int credit = 1;
  (void)state;
  assert_int_equal(fakelag_charge(&credit, 3), 2);
  assert_int_equal(credit, 0);
}

static void test_credit_is_one_shot(void **state)
{
  int credit = 20;
  int i, charged = 0;
  (void)state;
  /* Ten 2-second commands ride on the credit, the eleventh pays. */
  for (i = 0; i < 10; i++)
    charged += fakelag_charge(&credit, 2);
  assert_int_equal(charged, 0);
  assert_int_equal(credit, 0);
  assert_int_equal(fakelag_charge(&credit, 2), 2);
  assert_int_equal(credit, 0);
}

static void test_zero_or_negative_lag_charges_nothing(void **state)
{
  int credit = 5;
  (void)state;
  assert_int_equal(fakelag_charge(&credit, 0), 0);
  assert_int_equal(fakelag_charge(&credit, -1), 0);
  assert_int_equal(credit, 5);
}

/* --- fakelag_spend(): the charge order ------------------------------ */

static int fake_pool;
static void *fake_ctx_seen;
static int fake_take(void *ctx, int want)
{
  int got = want < fake_pool ? want : fake_pool;
  fake_ctx_seen = ctx;
  fake_pool -= got;
  return got;
}

static void test_spend_without_allowance_is_charge(void **state)
{
  int c1 = 3, c2 = 3;
  (void)state;
  fake_pool = 100;
  assert_int_equal(fakelag_spend(&c1, 0, 40, fake_take, NULL, 5),
                   fakelag_charge(&c2, 5));
  assert_int_equal(c1, c2);
  assert_int_equal(fake_pool, 100);
}

/* A line that may not borrow (take is NULL) is a plain charge. */
static void test_spend_no_take_is_charge(void **state)
{
  int c1 = 3, c2 = 3;
  (void)state;
  assert_int_equal(fakelag_spend(&c1, 50, 40, NULL, NULL, 5),
                   fakelag_charge(&c2, 5));
  assert_int_equal(c1, c2);
}

static void test_spend_credit_then_pool_then_clock(void **state)
{
  int credit = 1, ctx;
  (void)state;
  fake_pool = 3;
  /* 1 from the credit, 3 from the pool, 1 to the clock. */
  assert_int_equal(fakelag_spend(&credit, 50, 40, fake_take, &ctx, 5), 1);
  assert_int_equal(credit, 0);
  assert_int_equal(fake_pool, 0);
  assert_ptr_equal(fake_ctx_seen, &ctx);
}

static void test_spend_credit_covers_pool_untouched(void **state)
{
  int credit = 10;
  (void)state;
  fake_pool = 100;
  assert_int_equal(fakelag_spend(&credit, 50, 40, fake_take, NULL, 2), 0);
  assert_int_equal(credit, 8);
  assert_int_equal(fake_pool, 100);
}

static void test_spend_capped_by_pool(void **state)
{
  int credit = 0;
  (void)state;
  fake_pool = 1;
  assert_int_equal(fakelag_spend(&credit, 50, 40, fake_take, NULL, 2), 1);
  assert_int_equal(fake_pool, 0);
}

static void test_spend_allowance_live_through_its_last_second(void **state)
{
  int credit = 0;
  (void)state;
  fake_pool = 100;
  assert_int_equal(fakelag_spend(&credit, 50, 50, fake_take, NULL, 2), 0);
  assert_int_equal(fake_pool, 98);
}

static void test_spend_lapsed_allowance_is_dropped(void **state)
{
  int credit = 0;
  (void)state;
  fake_pool = 100;
  assert_int_equal(fakelag_spend(&credit, 50, 51, fake_take, NULL, 2), 2);
  assert_int_equal(fake_pool, 100);
}

/* --- fakelag_pool_take(NULL, ): refill and settle ------------------------- */

static int pool_setup(void **state)
{
  (void)state;
  fakelag_test_reset();
  stub_grace = 20;
  stub_pool = 600;
  stub_borrow = 60;
  stub_factor = -1;
  stub_borrow_time = 30;
  stub_account_time = 60;
  memset(&cl_users, 0, sizeof(cl_users));
  memset(&cl_staff, 0, sizeof(cl_staff));
  cl_users.valid = cl_staff.valid = 1;
  cl_users.next = &cl_staff;
  stub_class = &cl_users;
  CurrentTime = 1000000;
  return 0;
}

static void test_pool_starts_empty_and_fills_in_a_minute(void **state)
{
  (void)state;
  assert_int_equal(fakelag_pool_take(NULL, 10), 0);
  CurrentTime += 30;
  assert_int_equal(fakelag_pool_take(NULL, 1000), 300);
  CurrentTime += 60;
  assert_int_equal(fakelag_pool_take(NULL, 1000), 600);
}

static void test_pool_long_gap_credits_one_cap(void **state)
{
  (void)state;
  stub_pool = 100000;               /* the largest cap: a day * cap overflows int */
  fakelag_pool_take(NULL, 0);
  CurrentTime += 86400;
  assert_int_equal(fakelag_pool_take(NULL, 1000000), 100000);
  CurrentTime += 365 * 86400;
  assert_int_equal(fakelag_pool_take(NULL, 1000000), 100000);
  fakelag_pool_take(NULL, 1000000);       /* drained */
  CurrentTime += 21475;             /* 21475 * 100000 is past INT_MAX */
  assert_int_equal(fakelag_pool_take(NULL, 1000000), 100000);
}

static void test_pool_never_exceeds_cap(void **state)
{
  (void)state;
  fakelag_pool_take(NULL, 0);
  CurrentTime += 60;
  fakelag_pool_take(NULL, 0);             /* full */
  CurrentTime += 60;
  fakelag_pool_take(NULL, 0);             /* another minute settled on a full pool */
  assert_int_equal(fakelag_pool_take(NULL, 100000), 600);
}

static void test_pool_raised_cap_credits_at_most_one_cap(void **state)
{
  (void)state;
  stub_pool = 100;
  fakelag_pool_take(NULL, 0);
  CurrentTime += 3600;
  stub_pool = 600;
  assert_int_equal(fakelag_pool_take(NULL, 100000), 600);
}

/* Off, the pool lends nothing. */
static void test_pool_off_lends_nothing(void **state)
{
  (void)state;
  fakelag_pool_take(NULL, 0);
  CurrentTime += 60;
  stub_pool = 0;
  assert_int_equal(fakelag_pool_take(NULL, 100), 0);
  stub_pool = 600;
  assert_int_equal(fakelag_pool_take(NULL, 100), 100);
}

static void test_pool_backward_step_adds_nothing(void **state)
{
  (void)state;
  fakelag_pool_take(NULL, 0);
  CurrentTime += 60;
  assert_int_equal(fakelag_pool_take(NULL, 600), 600);   /* drained */
  CurrentTime -= 3600;
  assert_int_equal(fakelag_pool_take(NULL, 10), 0);
  CurrentTime += 6;                                /* 6 s at 10/s */
  assert_int_equal(fakelag_pool_take(NULL, 1000), 60);
}

static void test_pool_carries_remainder(void **state)
{
  int i, got = 0;
  (void)state;
  stub_pool = 100;                  /* 1.67 s per second */
  fakelag_pool_take(NULL, 0);
  for (i = 0; i < 60; i++) {
    CurrentTime += 1;
    got += fakelag_pool_take(NULL, 1000);
  }
  assert_int_equal(got, 100);
}

static void test_pool_lowered_cap_clamps(void **state)
{
  (void)state;
  fakelag_pool_take(NULL, 0);
  CurrentTime += 60;
  fakelag_pool_take(NULL, 0);             /* 600 banked */
  stub_pool = 50;                   /* lowered with no time passing */
  assert_int_equal(fakelag_pool_take(NULL, 1000), 50);
}

/* --- fakelag_grant() ------------------------------------------------- */

struct grant_fixture {
  struct Client cli;
  struct Connection con;
  struct User user;
};

/** A local client, logged in to @a account unless it is NULL. */
static struct Client *mkacct(struct grant_fixture *f, const char *account)
{
  memset(f, 0, sizeof(*f));
  cli_connect(&f->cli) = &f->con;
  cli_from(&f->cli) = &f->cli;      /* a local client */
  cli_user(&f->cli) = &f->user;
  if (account) {
    SetAccount(&f->cli);
    strncpy(f->user.account, account, ACCOUNTLEN);
  }
  return &f->cli;
}

static struct Client *mkclient(struct grant_fixture *f, int account)
{
  return mkacct(f, account ? "alice" : NULL);
}

static void test_grant_pool_off_is_today(void **state)
{
  struct grant_fixture f;
  struct Client *c = mkclient(&f, 1);
  (void)state;
  stub_pool = 0;
  fakelag_grant(c);
  assert_int_equal(cli_lagcredit(c), 20);
  assert_int_equal(cli_lagborrow_until(c), 0);
}

static void test_grant_anonymous_gets_nothing(void **state)
{
  struct grant_fixture f;
  struct Client *c = mkclient(&f, 0);
  (void)state;
  fakelag_grant(c);
  assert_int_equal(cli_lagcredit(c), 0);
  assert_int_equal(cli_lagborrow_until(c), 0);
}

static void test_grant_arms_allowance(void **state)
{
  struct grant_fixture f;
  struct Client *c = mkclient(&f, 1);
  (void)state;
  fakelag_grant(c);
  assert_int_equal(cli_lagcredit(c), 20);
  assert_int_equal(cli_lagborrow_until(c), CurrentTime + 30);
  assert_ptr_equal(stub_factor_asked, c);
}

static void test_grant_lag_off_class_borrows_nothing(void **state)
{
  struct grant_fixture f;
  struct Client *c = mkclient(&f, 1);
  (void)state;
  stub_factor = 0;
  fakelag_grant(c);
  assert_int_equal(cli_lagcredit(c), 20);
  assert_int_equal(cli_lagborrow_until(c), 0);
}

static void test_grant_clears_revived_allowance(void **state)
{
  struct grant_fixture f;
  struct Client *c = mkclient(&f, 1);
  (void)state;
  fakelag_grant(c);
  cli_lagcredit(c) -= 5;             /* partly spent, then held */
  stub_grace = 0;                    /* rehashed off before the revive */
  fakelag_grant(c);
  assert_int_equal(cli_lagcredit(c), 0);
  assert_int_equal(cli_lagborrow_until(c), 0);
}

static void test_grant_borrow_off_borrows_nothing(void **state)
{
  struct grant_fixture f;
  struct Client *c = mkclient(&f, 1);
  (void)state;
  stub_borrow = 0;
  fakelag_grant(c);
  assert_int_equal(cli_lagcredit(c), 20);
  assert_int_equal(cli_lagborrow_until(c), 0);
}

/* FAKELAG_BORROW_TIME sets the window, clamped to [1, 3600]. */
static void test_grant_borrow_time(void **state)
{
  struct grant_fixture f;
  struct Client *c = mkclient(&f, 1);
  (void)state;
  stub_borrow_time = 10;
  fakelag_grant(c);
  assert_int_equal(cli_lagborrow_until(c), CurrentTime + 10);
  stub_borrow_time = 0;
  fakelag_grant(c);
  assert_int_equal(cli_lagborrow_until(c), CurrentTime + 1);
  stub_borrow_time = 1000000;
  fakelag_grant(c);
  assert_int_equal(cli_lagborrow_until(c), CurrentTime + 3600);
}

/* --- the per-account budget ------------------------------------------ */

/** Send @a n 2 s @a cmd lines from @a c; return the seconds the pool
 * lent (what neither the credit nor the clock took). */
static int lent_cmd(struct Client *c, const char *cmd, int n)
{
  int i, lent = 0;
  for (i = 0; i < n; i++) {
    int credit = cli_lagcredit(c), charged;
    charged = fakelag_charge_client(c, cmd, 2);
    cli_since(c) += charged;
    lent += 2 - (credit - cli_lagcredit(c)) - charged;
  }
  return lent;
}

static int lent_to(struct Client *c, int n)
{
  return lent_cmd(c, "JOIN", n);
}

/** A logged-in client of @a account, registered now, the pool full. */
static struct Client *reg(struct grant_fixture *f, const char *account)
{
  struct Client *c = mkacct(f, account);
  fakelag_grant(c);
  return c;
}

/** Fill the pool: a first grant starts its clock, a minute fills it. */
static void fill_pool(void)
{
  struct grant_fixture f;
  fakelag_grant(mkacct(&f, "warm"));
  CurrentTime += 60;
}

/* The drain from the live test: one account reconnecting every two
 * seconds for a minute, spending all it can each time, borrows one
 * allowance in all. */
static void test_reconnect_loop_borrows_one_allowance(void **state)
{
  struct grant_fixture f;
  int k, lent = 0;
  (void)state;
  fill_pool();
  for (k = 0; k < 30; k++, CurrentTime += 2)
    lent += lent_to(reg(&f, "mallory"), 40);
  assert_int_equal(lent, 60);
}

/* A registration that never drew keeps the budget whole for the next. */
static void test_unused_allowance_blocks_nothing(void **state)
{
  struct grant_fixture f1, f2;
  (void)state;
  fill_pool();
  reg(&f1, "alice");                 /* dropped before its burst */
  CurrentTime += 5;
  assert_int_equal(lent_to(reg(&f2, "alice"), 40), 60);
}

/* A phone that drew part of its budget, then flapped, gets the rest. */
static void test_flap_gets_the_rest(void **state)
{
  struct grant_fixture f1, f2;
  (void)state;
  fill_pool();
  assert_int_equal(lent_to(reg(&f1, "alice"), 20), 20);   /* 10 on grace */
  CurrentTime += 5;
  assert_int_equal(lent_to(reg(&f2, "alice"), 40), 40);
}

/* Two devices at once share one budget. */
static void test_two_devices_share_the_budget(void **state)
{
  struct grant_fixture f1, f2;
  struct Client *a, *b;
  (void)state;
  fill_pool();
  a = reg(&f1, "alice");
  b = reg(&f2, "alice");
  assert_int_equal(lent_to(a, 40) + lent_to(b, 40), 60);
}

static void test_budget_is_per_account(void **state)
{
  struct grant_fixture f1, f2;
  (void)state;
  fill_pool();
  assert_int_equal(lent_to(reg(&f1, "alice"), 40), 60);
  assert_int_equal(lent_to(reg(&f2, "bob"), 40), 60);
}

static void test_budget_reopens_after_a_minute(void **state)
{
  struct grant_fixture f1, f2;
  (void)state;
  fill_pool();
  assert_int_equal(lent_to(reg(&f1, "alice"), 40), 60);
  CurrentTime += 60;
  assert_int_equal(lent_to(reg(&f2, "alice"), 40), 60);
}

/* Names compare as the server compares them: case, and [ ] \ ^ as { } | ~. */
static void test_budget_folds_like_the_server(void **state)
{
  struct grant_fixture f1, f2, f3;
  (void)state;
  fill_pool();
  assert_int_equal(lent_to(reg(&f1, "Foo[bar]"), 40), 60);
  assert_int_equal(lent_to(reg(&f2, "fOO{BAR}"), 40), 0);
  assert_int_equal(lent_to(reg(&f3, "foo^bar"), 40), 60);
}

/* A clock that steps back restarts the window but keeps what was used. */
static void test_budget_clock_back_keeps_used(void **state)
{
  struct grant_fixture f1, f2;
  (void)state;
  fill_pool();
  assert_int_equal(lent_to(reg(&f1, "alice"), 40), 60);
  CurrentTime -= 30;
  assert_int_equal(lent_to(reg(&f2, "alice"), 40), 0);
}

/* A long step back holds the budget for a minute from then, not for the
 * whole step. */
static void test_budget_long_clock_back_reopens_in_a_minute(void **state)
{
  struct grant_fixture f1, f2;
  (void)state;
  fill_pool();
  assert_int_equal(lent_to(reg(&f1, "alice"), 40), 60);
  CurrentTime -= 1000;
  assert_int_equal(lent_to(reg(&f2, "alice"), 11), 0);  /* restarts it now */
  CurrentTime += 60;
  fill_pool();
  assert_int_equal(lent_to(reg(&f2, "alice"), 40), 60);
}

/* An empty pool lends nothing and so opens no window. */
static void test_empty_pool_opens_no_window(void **state)
{
  struct grant_fixture f0, f1, f2;
  (void)state;
  fakelag_grant(mkacct(&f0, "warm"));      /* pool clock starts, empty */
  assert_int_equal(lent_to(reg(&f1, "alice"), 40), 0);
  CurrentTime += 60;
  assert_int_equal(lent_to(reg(&f2, "alice"), 40), 60);
}

/* Open budgets are never pushed out: with every slot a name may use
 * taken, it borrows nothing, and the holders keep theirs. */
static void test_full_table_lends_nothing_evicts_nobody(void **state)
{
  struct grant_fixture f;
  char name[16];
  int k, lenders = 0;
  (void)state;
  stub_pool = 100000;
  fill_pool();
  for (k = 0; k < 1200; k++) {             /* more names than slots */
    snprintf(name, sizeof(name), "u%d", k);
    if (lent_to(reg(&f, name), 11) == 2)   /* one 2 s draw each */
      lenders++;
  }
  assert_true(lenders <= 1024);
  assert_true(lenders >= 900);
  /* the first name still has its open budget: a second device of it
   * gets only the remaining 58 s */
  assert_int_equal(lent_to(reg(&f, "u0"), 40), 58);
}

/* A name of the full ACCOUNTLEN is stored whole, so it meets its own
 * budget on the next registration. */
static void test_budget_full_length_name(void **state)
{
  struct grant_fixture f1, f2;
  (void)state;
  fill_pool();
  assert_int_equal(lent_to(reg(&f1, "abcdefghijklmno"), 40), 60);
  assert_int_equal(lent_to(reg(&f2, "abcdefghijklmno"), 40), 0);
}

/* Logged out after the grant: the allowance is dropped, nothing lent. */
static void test_logged_out_borrows_nothing(void **state)
{
  struct grant_fixture f;
  struct Client *c;
  (void)state;
  fill_pool();
  c = reg(&f, "alice");
  ClearAccount(c);
  f.user.account[0] = '\0';
  assert_int_equal(lent_to(c, 40), 0);
  assert_int_equal(cli_lagborrow_until(c), 0);
  assert_int_equal(fakelag_pool_take(NULL, 100000), 600);   /* pool untouched */
}

/* A lowered FAKELAG_BORROW applies to what is left this minute. */
static void test_lowered_borrow_caps_the_rest(void **state)
{
  struct grant_fixture f1, f2;
  (void)state;
  fill_pool();
  assert_int_equal(lent_to(reg(&f1, "alice"), 20), 20);
  stub_borrow = 30;
  assert_int_equal(lent_to(reg(&f2, "alice"), 40), 10);
}

/* A lone logged-in client: 80 s of credit for 2 s commands is 40 of
 * them before the clock moves at all.  The pool's clock starts at the
 * first grant, so a client a minute after the first finds it full. */
static void test_burst_with_pool(void **state)
{
  struct grant_fixture f0, f;
  struct Client *first = mkclient(&f0, 1);
  struct Client *c;
  int i, free_cmds = 0;
  (void)state;
  fakelag_grant(first);
  CurrentTime += 60;
  c = mkclient(&f, 1);
  fakelag_grant(c);
  for (i = 0; i < 50; i++)
    if (fakelag_charge_client(c, "JOIN", 2) == 0)
      free_cmds++;
  assert_int_equal(free_cmds, 40);
}

/* --- what may borrow ------------------------------------------------- */

static void test_borrowers_table(void **state)
{
  (void)state;
  assert_true(fakelag_borrows("JOIN"));
  assert_true(fakelag_borrows("CHATHISTORY"));
  assert_true(fakelag_borrows("MODE"));
  assert_true(fakelag_borrows("MARKREAD"));
  assert_false(fakelag_borrows("PRIVMSG"));
  assert_false(fakelag_borrows("NOTICE"));
  assert_false(fakelag_borrows("TAGMSG"));
  assert_false(fakelag_borrows("join"));
  assert_false(fakelag_borrows(NULL));
}

/* PRIVMSG and NOTICE spend the credit, then the clock: never the pool,
 * and they leave the budget for the catch-up that may use it. */
static void test_messages_do_not_borrow(void **state)
{
  struct grant_fixture f;
  struct Client *c;
  (void)state;
  fill_pool();
  c = reg(&f, "alice");
  assert_int_equal(lent_cmd(c, "PRIVMSG", 20), 0);
  assert_int_equal(cli_lagcredit(c), 0);            /* grace still spent */
  assert_int_equal(lent_cmd(c, "NOTICE", 5), 0);
  assert_int_equal(lent_cmd(c, "CHATHISTORY", 40), 60);
}

/* --- per-class shares ------------------------------------------------ */

/* A class's share is its own: another class emptying the unreserved
 * part leaves it whole. */
static void test_share_survives_a_drain(void **state)
{
  struct grant_fixture f;
  char name[16];
  int k, staff_lent = 0;
  (void)state;
  cl_staff.lag_share = 100;           /* 600 = 100 for staff + 500 free */
  stub_class = &cl_staff;
  fill_pool();                        /* starts both clocks */
  stub_class = &cl_users;
  for (k = 0; k < 20; k++) {          /* users empty the free part */
    snprintf(name, sizeof(name), "u%d", k);
    lent_to(reg(&f, name), 40);
  }
  assert_int_equal(fakelag_pool_take(&cl_users, 1000), 0);
  stub_class = &cl_staff;
  for (k = 0; k < 2; k++) {
    snprintf(name, sizeof(name), "s%d", k);
    staff_lent += lent_to(reg(&f, name), 40);
  }
  assert_int_equal(staff_lent, 100);
}

/* What no class reserved is all a class without a share can reach. */
static void test_unreserved_is_pool_minus_shares(void **state)
{
  (void)state;
  cl_staff.lag_share = 100;
  fakelag_pool_take(&cl_staff, 0);
  CurrentTime += 60;
  assert_int_equal(fakelag_pool_take(&cl_users, 100000), 500);
  assert_int_equal(fakelag_pool_take(&cl_staff, 100000), 100);
}

/* A class draws its share first, then the free part. */
static void test_share_then_unreserved(void **state)
{
  (void)state;
  cl_staff.lag_share = 100;
  fakelag_pool_take(&cl_staff, 0);
  CurrentTime += 60;
  assert_int_equal(fakelag_pool_take(&cl_staff, 150), 150);
  assert_int_equal(fakelag_pool_take(&cl_users, 100000), 450);
  assert_int_equal(fakelag_pool_take(&cl_staff, 100000), 0);
}

/* A removed class's share goes back to everyone. */
static void test_removed_class_frees_its_share(void **state)
{
  (void)state;
  cl_staff.lag_share = 100;
  cl_staff.valid = 0;
  fakelag_pool_take(NULL, 0);
  CurrentTime += 60;
  assert_int_equal(fakelag_pool_take(&cl_users, 100000), 600);
}

/* A removed class's clients lend from the free part only: its old share
 * is counted there now, and must not be lent a second time. */
static void test_removed_class_lends_no_share(void **state)
{
  (void)state;
  cl_staff.lag_share = 100;
  fakelag_pool_take(&cl_staff, 0);
  CurrentTime += 60;
  cl_staff.valid = 0;
  assert_int_equal(fakelag_pool_take(&cl_staff, 100000), 600);
}

/* Shares over the pool leave nothing unreserved, and each class still
 * gets its own. */
static void test_shares_over_the_pool(void **state)
{
  (void)state;
  cl_users.lag_share = 400;
  cl_staff.lag_share = 400;
  fakelag_pool_take(&cl_users, 0);
  fakelag_pool_take(&cl_staff, 0);
  CurrentTime += 60;
  assert_int_equal(fakelag_pool_take(&cl_users, 100000), 400);
  assert_int_equal(fakelag_pool_take(&cl_staff, 100000), 400);
  assert_int_equal(fakelag_pool_take(NULL, 100000), 0);
}

/* Turned off, a class's share lends nothing either. */
static void test_pool_off_silences_shares(void **state)
{
  (void)state;
  cl_staff.lag_share = 100;
  fakelag_pool_take(&cl_staff, 0);
  CurrentTime += 60;
  stub_pool = 0;
  assert_int_equal(fakelag_pool_take(&cl_staff, 100000), 0);
}

/* The account budget is one across classes. */
static void test_budget_spans_classes(void **state)
{
  struct grant_fixture f1, f2;
  (void)state;
  cl_staff.lag_share = 100;
  stub_class = &cl_staff;
  fill_pool();
  assert_int_equal(lent_to(reg(&f1, "alice"), 40), 60);
  stub_class = &cl_users;
  assert_int_equal(lent_to(reg(&f2, "alice"), 40), 0);
}

/* --- the windows ----------------------------------------------------- */

static void test_account_time_sets_the_window(void **state)
{
  struct grant_fixture f1, f2, f3;
  (void)state;
  stub_account_time = 120;
  fill_pool();
  assert_int_equal(lent_to(reg(&f1, "alice"), 40), 60);
  CurrentTime += 60;
  assert_int_equal(lent_to(reg(&f2, "alice"), 40), 0);
  CurrentTime += 60;
  assert_int_equal(lent_to(reg(&f3, "alice"), 40), 60);
}

static void test_borrow_time_ends_the_allowance(void **state)
{
  struct grant_fixture f;
  struct Client *c;
  (void)state;
  stub_borrow_time = 5;
  fill_pool();
  c = reg(&f, "alice");
  CurrentTime += 6;
  assert_int_equal(lent_to(c, 40), 0);
}

/* FAKELAG_BORROW is clamped to 600 per account. */
static void test_borrow_clamped(void **state)
{
  struct grant_fixture f;
  (void)state;
  stub_pool = 100000;
  stub_borrow = 1000000;
  fill_pool();
  assert_int_equal(lent_to(reg(&f, "alice"), 400), 600);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_no_credit_charges_in_full),
    cmocka_unit_test(test_credit_absorbs_whole_charge),
    cmocka_unit_test(test_credit_absorbs_part_of_a_charge),
    cmocka_unit_test(test_credit_is_one_shot),
    cmocka_unit_test(test_zero_or_negative_lag_charges_nothing),
    cmocka_unit_test(test_spend_without_allowance_is_charge),
    cmocka_unit_test(test_spend_no_take_is_charge),
    cmocka_unit_test(test_spend_credit_then_pool_then_clock),
    cmocka_unit_test(test_spend_credit_covers_pool_untouched),
    cmocka_unit_test(test_spend_capped_by_pool),
    cmocka_unit_test(test_spend_allowance_live_through_its_last_second),
    cmocka_unit_test(test_spend_lapsed_allowance_is_dropped),
    cmocka_unit_test_setup(test_pool_starts_empty_and_fills_in_a_minute, pool_setup),
    cmocka_unit_test_setup(test_pool_long_gap_credits_one_cap, pool_setup),
    cmocka_unit_test_setup(test_pool_never_exceeds_cap, pool_setup),
    cmocka_unit_test_setup(test_pool_raised_cap_credits_at_most_one_cap, pool_setup),
    cmocka_unit_test_setup(test_pool_off_lends_nothing, pool_setup),
    cmocka_unit_test_setup(test_pool_backward_step_adds_nothing, pool_setup),
    cmocka_unit_test_setup(test_pool_carries_remainder, pool_setup),
    cmocka_unit_test_setup(test_pool_lowered_cap_clamps, pool_setup),
    cmocka_unit_test_setup(test_grant_pool_off_is_today, pool_setup),
    cmocka_unit_test_setup(test_grant_anonymous_gets_nothing, pool_setup),
    cmocka_unit_test_setup(test_grant_arms_allowance, pool_setup),
    cmocka_unit_test_setup(test_grant_lag_off_class_borrows_nothing, pool_setup),
    cmocka_unit_test_setup(test_grant_clears_revived_allowance, pool_setup),
    cmocka_unit_test_setup(test_grant_borrow_off_borrows_nothing, pool_setup),
    cmocka_unit_test_setup(test_grant_borrow_time, pool_setup),
    cmocka_unit_test_setup(test_burst_with_pool, pool_setup),
    cmocka_unit_test_setup(test_reconnect_loop_borrows_one_allowance, pool_setup),
    cmocka_unit_test_setup(test_unused_allowance_blocks_nothing, pool_setup),
    cmocka_unit_test_setup(test_flap_gets_the_rest, pool_setup),
    cmocka_unit_test_setup(test_two_devices_share_the_budget, pool_setup),
    cmocka_unit_test_setup(test_budget_is_per_account, pool_setup),
    cmocka_unit_test_setup(test_budget_reopens_after_a_minute, pool_setup),
    cmocka_unit_test_setup(test_budget_folds_like_the_server, pool_setup),
    cmocka_unit_test_setup(test_budget_clock_back_keeps_used, pool_setup),
    cmocka_unit_test_setup(test_budget_long_clock_back_reopens_in_a_minute, pool_setup),
    cmocka_unit_test_setup(test_empty_pool_opens_no_window, pool_setup),
    cmocka_unit_test_setup(test_full_table_lends_nothing_evicts_nobody, pool_setup),
    cmocka_unit_test_setup(test_lowered_borrow_caps_the_rest, pool_setup),
    cmocka_unit_test_setup(test_budget_full_length_name, pool_setup),
    cmocka_unit_test_setup(test_logged_out_borrows_nothing, pool_setup),
    cmocka_unit_test(test_borrowers_table),
    cmocka_unit_test_setup(test_messages_do_not_borrow, pool_setup),
    cmocka_unit_test_setup(test_share_survives_a_drain, pool_setup),
    cmocka_unit_test_setup(test_unreserved_is_pool_minus_shares, pool_setup),
    cmocka_unit_test_setup(test_share_then_unreserved, pool_setup),
    cmocka_unit_test_setup(test_removed_class_frees_its_share, pool_setup),
    cmocka_unit_test_setup(test_removed_class_lends_no_share, pool_setup),
    cmocka_unit_test_setup(test_shares_over_the_pool, pool_setup),
    cmocka_unit_test_setup(test_pool_off_silences_shares, pool_setup),
    cmocka_unit_test_setup(test_budget_spans_classes, pool_setup),
    cmocka_unit_test_setup(test_account_time_sets_the_window, pool_setup),
    cmocka_unit_test_setup(test_borrow_time_ends_the_allowance, pool_setup),
    cmocka_unit_test_setup(test_borrow_clamped, pool_setup),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
