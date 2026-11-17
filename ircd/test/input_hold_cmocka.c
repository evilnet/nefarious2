/*
 * input_hold_cmocka.c - the orphan hold's pure rules (ircd/input_hold.c):
 * when a bouncer device's input is held, when the orphan sweep is asked
 * for, when the input is released (the hold ends, a sweep ran and it is
 * still an orphan, the ceiling), how much its receive queue may hold, and
 * what a QUIT line is.
 */
#include "config.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <string.h>
#include <cmocka.h>

#include "input_hold.h"

#define T0 1000000

static enum input_hold_action step(struct InputHold *h, int orphan, time_t t,
                                   unsigned int sweeps, enum input_hold_event want)
{
  enum input_hold_event ev;
  enum input_hold_action a = input_hold_step(h, orphan, t, sweeps, &ev);

  if (ev != want)
    fail_msg("at +%ld (orphan %d, sweeps %u): event %d, want %d",
             (long)(t - T0), orphan, sweeps, ev, want);
  return a;
}

/** No orphan, no hold: parse, nothing changes. */
static void not_an_orphan(void **state)
{
  struct InputHold h;

  memset(&h, 0, sizeof h);
  assert_int_equal(step(&h, 0, T0, 0, INPUT_HOLD_EV_NONE), INPUT_HOLD_PARSE);
  assert_int_equal(h.since, 0);
  assert_int_equal(h.boost, 0);
}

/** An orphan is held from the first look; a primary again: released
 * (EV_ENDED), with the allowance for INPUT_HOLD_GRACE seconds. */
static void held_then_ended(void **state)
{
  struct InputHold h;

  memset(&h, 0, sizeof h);
  assert_int_equal(step(&h, 1, T0, 3, INPUT_HOLD_EV_BEGAN), INPUT_HOLD_WAIT);
  assert_int_equal(step(&h, 1, T0 + 2, 3, INPUT_HOLD_EV_NONE), INPUT_HOLD_WAIT);
  assert_int_equal(step(&h, 1, T0 + INPUT_HOLD_MAX, 3, INPUT_HOLD_EV_NONE),
                   INPUT_HOLD_WAIT);
  assert_int_equal(step(&h, 0, T0 + 3, 3, INPUT_HOLD_EV_ENDED), INPUT_HOLD_PARSE);
  assert_int_equal(h.since, 0);
  assert_int_equal(h.boost, T0 + 3 + INPUT_HOLD_GRACE);
  /* and again: no second event, no second allowance */
  assert_int_equal(step(&h, 0, T0 + 4, 3, INPUT_HOLD_EV_NONE), INPUT_HOLD_PARSE);
  assert_int_equal(h.boost, T0 + 3 + INPUT_HOLD_GRACE);
}

/** The bound: the sweep is asked once and the input waits for a pass; a
 * pass that leaves it an orphan releases it (EV_SWEPT); it is not held
 * again while it stays one, and its later end grants no second
 * allowance. */
static void bound_asks_the_sweep(void **state)
{
  struct InputHold h;
  time_t t = T0 + INPUT_HOLD_MAX + 1;

  memset(&h, 0, sizeof h);
  step(&h, 1, T0, 7, INPUT_HOLD_EV_BEGAN);
  assert_int_equal(step(&h, 1, t, 7, INPUT_HOLD_EV_ASKED), INPUT_HOLD_ASK_SWEEP);
  assert_int_equal(h.gen, 7);
  assert_int_equal(step(&h, 1, t, 7, INPUT_HOLD_EV_NONE), INPUT_HOLD_WAIT);
  assert_int_equal(step(&h, 1, t + 1, 7, INPUT_HOLD_EV_NONE), INPUT_HOLD_WAIT);
  assert_int_equal(step(&h, 1, t + 1, 8, INPUT_HOLD_EV_SWEPT), INPUT_HOLD_PARSE);
  assert_int_equal(h.released, 1);
  assert_int_equal(h.boost, t + 1 + INPUT_HOLD_GRACE);
  assert_int_equal(step(&h, 1, t + 2, 9, INPUT_HOLD_EV_NONE), INPUT_HOLD_PARSE);
  assert_int_equal(step(&h, 0, t + 3, 9, INPUT_HOLD_EV_NONE), INPUT_HOLD_PARSE);
  assert_int_equal(h.boost, t + 1 + INPUT_HOLD_GRACE);
  assert_int_equal(h.released, 0);
  /* a new orphan episode holds again */
  assert_int_equal(step(&h, 1, t + 4, 9, INPUT_HOLD_EV_BEGAN), INPUT_HOLD_WAIT);
}

/** The sweep resolves it at the bound: the end is an ordinary end. */
static void bound_then_resolved(void **state)
{
  struct InputHold h;
  time_t t = T0 + INPUT_HOLD_MAX + 1;

  memset(&h, 0, sizeof h);
  step(&h, 1, T0, 0, INPUT_HOLD_EV_BEGAN);
  step(&h, 1, t, 0, INPUT_HOLD_EV_ASKED);
  assert_int_equal(step(&h, 0, t, 1, INPUT_HOLD_EV_ENDED), INPUT_HOLD_PARSE);
}

/** A sweep that never runs: the ceiling releases it, INPUT_HOLD_AFTER_ASK
 * after the request (INPUT_HOLD_CEILING into a hold looked at on time). */
static void ceiling(void **state)
{
  struct InputHold h;
  time_t ask = T0 + INPUT_HOLD_MAX + 1;

  memset(&h, 0, sizeof h);
  step(&h, 1, T0, 4, INPUT_HOLD_EV_BEGAN);
  step(&h, 1, ask, 4, INPUT_HOLD_EV_ASKED);
  assert_int_equal(step(&h, 1, ask + INPUT_HOLD_AFTER_ASK, 4, INPUT_HOLD_EV_NONE),
                   INPUT_HOLD_WAIT);
  assert_int_equal(step(&h, 1, ask + INPUT_HOLD_AFTER_ASK + 1, 4,
                        INPUT_HOLD_EV_CEILING), INPUT_HOLD_PARSE);
  assert_int_equal(h.released, 1);
  assert_true(ask + INPUT_HOLD_AFTER_ASK + 1 - T0 <= INPUT_HOLD_CEILING + 2);
}

/** A stall: the first look after the hold began comes long past the bound
 * and past the ceiling (the server was stopped).  The sweep is asked for
 * all the same, and the lines wait for its pass -- the I/O of a loop runs
 * before its timers, so releasing at this look would parse them before a
 * pass already due.  Then the pass resolves it (an end), or leaves an
 * orphan (released, SWEPT), or never runs (the ceiling, from the
 * request). */
static void long_stall_asks_first(void **state)
{
  static const int stalls[] = { INPUT_HOLD_CEILING + 1, INPUT_HOLD_CEILING + 5,
                                INPUT_HOLD_CEILING * 4 };
  size_t i;

  for (i = 0; i < sizeof(stalls) / sizeof(stalls[0]); i++) {
    struct InputHold h;
    time_t t = T0 + stalls[i];

    /* the pass leaves an orphan */
    memset(&h, 0, sizeof h);
    step(&h, 1, T0, 9, INPUT_HOLD_EV_BEGAN);
    assert_int_equal(step(&h, 1, t, 9, INPUT_HOLD_EV_ASKED), INPUT_HOLD_ASK_SWEEP);
    assert_int_equal(step(&h, 1, t, 9, INPUT_HOLD_EV_NONE), INPUT_HOLD_WAIT);
    assert_int_equal(step(&h, 1, t, 10, INPUT_HOLD_EV_SWEPT), INPUT_HOLD_PARSE);
    /* the pass resolves it */
    memset(&h, 0, sizeof h);
    step(&h, 1, T0, 9, INPUT_HOLD_EV_BEGAN);
    step(&h, 1, t, 9, INPUT_HOLD_EV_ASKED);
    assert_int_equal(step(&h, 0, t, 10, INPUT_HOLD_EV_ENDED), INPUT_HOLD_PARSE);
    /* no pass ever: the ceiling, from the request */
    memset(&h, 0, sizeof h);
    step(&h, 1, T0, 9, INPUT_HOLD_EV_BEGAN);
    step(&h, 1, t, 9, INPUT_HOLD_EV_ASKED);
    assert_int_equal(step(&h, 1, t + INPUT_HOLD_AFTER_ASK, 9, INPUT_HOLD_EV_NONE),
                     INPUT_HOLD_WAIT);
    assert_int_equal(step(&h, 1, t + INPUT_HOLD_AFTER_ASK + 1, 9,
                          INPUT_HOLD_EV_CEILING), INPUT_HOLD_PARSE);
  }
}

/** The queue's cap: twice while held and after the release until the
 * allowance ends, sooner once the queue is back under the usual cap; the
 * time limit holds even for a queue kept over it. */
static void cap(void **state)
{
  struct InputHold h;
  const unsigned int c = 1000;

  memset(&h, 0, sizeof h);
  assert_int_equal(input_hold_cap(&h, c, 5000, T0), c);
  step(&h, 1, T0, 0, INPUT_HOLD_EV_BEGAN);
  assert_int_equal(input_hold_cap(&h, c, 1500, T0 + 1), 2 * c);
  assert_int_equal(input_hold_cap(&h, c, 10, T0 + 1), 2 * c);   /* held: no early end */
  step(&h, 0, T0 + 2, 0, INPUT_HOLD_EV_ENDED);
  assert_int_equal(input_hold_cap(&h, c, 1500, T0 + 3), 2 * c);
  assert_int_equal(input_hold_cap(&h, c, 1500, T0 + 2 + INPUT_HOLD_GRACE - 1), 2 * c);
  /* kept over the usual cap: the allowance still ends on time */
  assert_int_equal(input_hold_cap(&h, c, 1500, T0 + 2 + INPUT_HOLD_GRACE), c);
  assert_int_equal(h.boost, 0);
  /* drained: it ends at once and does not come back */
  memset(&h, 0, sizeof h);
  step(&h, 1, T0, 0, INPUT_HOLD_EV_BEGAN);
  step(&h, 0, T0 + 1, 0, INPUT_HOLD_EV_ENDED);
  assert_int_equal(input_hold_cap(&h, c, 900, T0 + 2), c);
  assert_int_equal(input_hold_cap(&h, c, 1500, T0 + 3), c);
  /* released while still an orphan: the allowance, then the usual cap */
  memset(&h, 0, sizeof h);
  step(&h, 1, T0, 0, INPUT_HOLD_EV_BEGAN);
  step(&h, 1, T0 + INPUT_HOLD_MAX + 1, 0, INPUT_HOLD_EV_ASKED);
  step(&h, 1, T0 + INPUT_HOLD_MAX + 2, 1, INPUT_HOLD_EV_SWEPT);
  assert_int_equal(input_hold_cap(&h, c, 1500, T0 + INPUT_HOLD_MAX + 3), 2 * c);
  assert_int_equal(input_hold_cap(&h, c, 1500,
                                  T0 + INPUT_HOLD_MAX + 2 + INPUT_HOLD_GRACE), c);
}

/** input_hold_clear(): a closed socket forgets the hold and allowance. */
static void cleared(void **state)
{
  struct InputHold h;

  memset(&h, 0, sizeof h);
  step(&h, 1, T0, 0, INPUT_HOLD_EV_BEGAN);
  input_hold_clear(&h);
  assert_int_equal(step(&h, 0, T0 + 1, 0, INPUT_HOLD_EV_NONE), INPUT_HOLD_PARSE);
  assert_int_equal(h.boost, 0);
}

/** The server PING to a held client: none before INPUT_HOLD_PING, then
 * one every INPUT_HOLD_PING while held (at the bound too), none after the
 * release or for a client that is not held, and a new hold starts its own
 * clock. */
static void ping_due(void **state)
{
  struct InputHold h;
  time_t t;
  int sent = 0;

  memset(&h, 0, sizeof h);
  assert_int_equal(input_hold_ping_due(&h, T0 + 100), 0);       /* not held */
  step(&h, 1, T0, 0, INPUT_HOLD_EV_BEGAN);
  assert_int_equal(input_hold_ping_due(&h, T0), 0);
  assert_int_equal(input_hold_ping_due(&h, T0 + INPUT_HOLD_PING - 1), 0);
  assert_int_equal(input_hold_ping_due(&h, T0 + INPUT_HOLD_PING), 1);
  assert_int_equal(input_hold_ping_due(&h, T0 + INPUT_HOLD_PING), 0);   /* once */
  assert_int_equal(input_hold_ping_due(&h, T0 + 2 * INPUT_HOLD_PING - 1), 0);
  assert_int_equal(input_hold_ping_due(&h, T0 + 2 * INPUT_HOLD_PING), 1);
  /* polled every 2 s, as the process timer does, to the ceiling: never a
   * gap over INPUT_HOLD_PING + 2 */
  for (t = T0 + 2 * INPUT_HOLD_PING, sent = 0; t <= T0 + INPUT_HOLD_CEILING + 2; t += 2) {
    enum input_hold_event ev;
    enum input_hold_action a = input_hold_step(&h, 1, t, 0, &ev);

    if (a == INPUT_HOLD_PARSE)
      break;
    if (input_hold_ping_due(&h, t))
      sent++;
    assert_true(t - h.pinged <= INPUT_HOLD_PING + 2);
  }
  assert_true(sent >= 3);
  /* released at the ceiling (from the request): nothing more */
  assert_true(h.asked != 0);
  step(&h, 1, h.asked + INPUT_HOLD_AFTER_ASK + 1, 0, INPUT_HOLD_EV_CEILING);
  assert_int_equal(input_hold_ping_due(&h, T0 + INPUT_HOLD_CEILING + 20), 0);
  /* a hold that ends: nothing after; a new hold counts from its start */
  memset(&h, 0, sizeof h);
  step(&h, 1, T0, 0, INPUT_HOLD_EV_BEGAN);
  assert_int_equal(input_hold_ping_due(&h, T0 + INPUT_HOLD_PING), 1);
  step(&h, 0, T0 + INPUT_HOLD_PING + 1, 0, INPUT_HOLD_EV_ENDED);
  assert_int_equal(input_hold_ping_due(&h, T0 + 3 * INPUT_HOLD_PING), 0);
  step(&h, 1, T0 + 50, 0, INPUT_HOLD_EV_BEGAN);
  assert_int_equal(input_hold_ping_due(&h, T0 + 50 + INPUT_HOLD_PING - 1), 0);
  assert_int_equal(input_hold_ping_due(&h, T0 + 50 + INPUT_HOLD_PING), 1);
}

/** The PONGs to the hold's own PINGs are not charged fake lag: only a
 * PONG whose one parameter is exactly our name, within INPUT_HOLD_GRACE of
 * the release, and no more of them than the PINGs that hold sent. */
static void pong_free(void **state)
{
  struct InputHold h;
  const char *me = "a.test";
  time_t rel = T0 + 10;

  memset(&h, 0, sizeof h);
  assert_int_equal(input_hold_pong_free(&h, T0, ":a.test", me), 0);   /* no hold */
  step(&h, 1, T0, 0, INPUT_HOLD_EV_BEGAN);
  assert_int_equal(input_hold_ping_due(&h, T0 + INPUT_HOLD_PING), 1);
  assert_int_equal(input_hold_ping_due(&h, T0 + 2 * INPUT_HOLD_PING), 1);
  /* still held: not parsed in practice, and not free */
  assert_int_equal(input_hold_pong_free(&h, T0 + 9, ":a.test", me), 0);
  step(&h, 0, rel, 0, INPUT_HOLD_EV_ENDED);
  /* another argument, two parameters, a prefix of our name: charged */
  assert_int_equal(input_hold_pong_free(&h, rel, ":b.test", me), 0);
  assert_int_equal(input_hold_pong_free(&h, rel, "a.test :a.test", me), 0);
  assert_int_equal(input_hold_pong_free(&h, rel, ":a.tes", me), 0);
  assert_int_equal(input_hold_pong_free(&h, rel, ":a.testx", me), 0);
  assert_int_equal(input_hold_pong_free(&h, rel, NULL, me), 0);
  /* ours, with or without the colon: free, as many as were sent */
  assert_int_equal(input_hold_pong_free(&h, rel, ":a.test", me), 1);
  assert_int_equal(input_hold_pong_free(&h, rel + 1, "a.test ", me), 1);
  assert_int_equal(input_hold_pong_free(&h, rel + 1, ":a.test", me), 0);   /* one more */
  /* outside the allowance: charged */
  memset(&h, 0, sizeof h);
  step(&h, 1, T0, 0, INPUT_HOLD_EV_BEGAN);
  input_hold_ping_due(&h, T0 + INPUT_HOLD_PING);
  step(&h, 0, rel, 0, INPUT_HOLD_EV_ENDED);
  assert_int_equal(input_hold_pong_free(&h, rel + INPUT_HOLD_GRACE, ":a.test", me), 0);
  assert_int_equal(input_hold_pong_free(&h, rel + INPUT_HOLD_GRACE - 1, ":a.test", me), 1);
  /* released at the bound while an orphan: free too */
  memset(&h, 0, sizeof h);
  step(&h, 1, T0, 0, INPUT_HOLD_EV_BEGAN);
  input_hold_ping_due(&h, T0 + INPUT_HOLD_PING);
  step(&h, 1, T0 + INPUT_HOLD_MAX + 1, 0, INPUT_HOLD_EV_ASKED);
  step(&h, 1, T0 + INPUT_HOLD_MAX + 1, 1, INPUT_HOLD_EV_SWEPT);
  assert_int_equal(input_hold_pong_free(&h, T0 + INPUT_HOLD_MAX + 2, ":a.test", me), 1);
  /* a new hold starts afresh: none free before it sends a PING */
  step(&h, 0, T0 + 40, 0, INPUT_HOLD_EV_NONE);
  step(&h, 1, T0 + 50, 0, INPUT_HOLD_EV_BEGAN);
  step(&h, 0, T0 + 51, 0, INPUT_HOLD_EV_ENDED);
  assert_int_equal(input_hold_pong_free(&h, T0 + 51, ":a.test", me), 0);
}

static void is_quit(void **state)
{
  static const struct { const char *line; int quit; } rows[] = {
    { "QUIT", 1 },
    { "QUIT :bye", 1 },
    { "quit :bye", 1 },
    { "Quit", 1 },
    { "@label=x QUIT :bye", 1 },
    { "@a=b;c :nick!u@h QUIT :bye", 1 },
    { ":nick QUIT", 1 },
    { "  QUIT", 1 },
    { "QUITX", 0 },
    { "QUITX :y", 0 },
    { "QUI", 0 },
    { "", 0 },
    { "PRIVMSG #c :QUIT", 0 },
    { "PRIVMSG QUIT :x", 0 },
    { "@QUIT PRIVMSG #c :x", 0 },
    { ":QUIT PRIVMSG #c :x", 0 },
    { "@label=x", 0 },
  };
  size_t i;

  for (i = 0; i < sizeof(rows) / sizeof(rows[0]); i++)
    if (input_hold_is_quit(rows[i].line) != rows[i].quit)
      fail_msg("\"%s\": %d, want %d", rows[i].line,
               input_hold_is_quit(rows[i].line), rows[i].quit);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(not_an_orphan),
    cmocka_unit_test(held_then_ended),
    cmocka_unit_test(bound_asks_the_sweep),
    cmocka_unit_test(bound_then_resolved),
    cmocka_unit_test(ceiling),
    cmocka_unit_test(long_stall_asks_first),
    cmocka_unit_test(cap),
    cmocka_unit_test(cleared),
    cmocka_unit_test(ping_due),
    cmocka_unit_test(pong_free),
    cmocka_unit_test(is_quit),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
