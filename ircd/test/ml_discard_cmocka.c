/*
 * ml_discard_cmocka.c - what becomes of an open client multiline batch
 * that is never ended
 *
 *  - draft/multiline goes inert at a CAP change while labeled-response
 *    stays in use (cap_dependents_drop()): the batch's label, parked in
 *    con_ml_label from its BATCH + line, is answered by a labeled ACK
 *    (multiline_discard_answer()) before the batch is discarded, and the
 *    CAP line's own label is left as it was;
 *  - the client's Connection is freed with the batch open
 *    (dealloc_connection() -> multiline_free_connection()): its lines are
 *    freed with it.
 *
 * This includes the real m_batch.c, compiled with -ffunction-sections and
 * linked with --gc-sections, so the program keeps the functions under test
 * and what they call; the ircd around them is stubbed here.
 */
#include "config.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcomment"
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wunused-variable"
#include "../m_batch.c"
#pragma GCC diagnostic pop

/* ------------------------------------------------------------------ */
/* The ircd around m_batch.c                                           */
/* ------------------------------------------------------------------ */

struct Client me;
int log_inassert;

/* send.c's send_labeled_ack(): the answer is noted with the label it went
 * out under -- what the client would see is send.c's (send_label_cmocka). */
static char acked[8][64];
static int n_acked;
void send_labeled_ack(struct Client *to)
{
  assert_true(n_acked < 8);
  if (cli_label(to)[0] && !cli_label_responded(to)) {
    snprintf(acked[n_acked++], sizeof(acked[0]), "%s", cli_label(to));
    cli_label_responded(to) = 1;
  }
}

/* list.c's free_link(): the links are this test's own. */
static int links_freed;
void free_link(struct SLink *lp)
{
  links_freed++;
  free(lp);
}

void debug(int level, const char *form, ...)
{
  (void)level; (void)form;
}

void log_write(enum LogSys subsys, enum LogLevel severity, unsigned int flags,
               const char *fmt, ...)
{
  (void)subsys; (void)severity; (void)flags; (void)fmt;
}

/* ------------------------------------------------------------------ */

static struct Client cli;
static struct Connection con;

static int setup(void **state)
{
  (void)state;
  memset(&cli, 0, sizeof(cli));
  memset(&con, 0, sizeof(con));
  cli.cli_connect = &con;
  con.con_client = &cli;
  cli_status(&cli) = STAT_USER;
  n_acked = 0;
  links_freed = 0;
  return 0;
}

/** An open multiline batch of @a n lines, labeled @a label ("" none). */
static void open_batch(const char *ref, const char *label, int n)
{
  int i;

  ircd_strncpy(con_ml_batch_id(&con), ref, sizeof(con.con_ml_batch_id));
  ircd_strncpy(con_ml_target(&con), "#c", sizeof(con.con_ml_target));
  ircd_strncpy(con_ml_label(&con), label, sizeof(con.con_ml_label));
  for (i = 0; i < n; i++) {
    struct SLink *lp = calloc(1, sizeof(*lp));
    assert_non_null(lp);
    lp->value.cp = malloc(16);
    assert_non_null(lp->value.cp);
    snprintf(lp->value.cp, 16, "%cline%d", 0, i);
    lp->next = con_ml_messages(&con);
    con_ml_messages(&con) = lp;
    con_ml_msg_count(&con)++;
  }
}

/* A labeled batch: its label is ACKed, once, under its own label; the CAP
 * line's label is left as it was (still to be answered by its CAP ACK). */
static void test_discard_answer_acks_the_batch_label(void **state)
{
  (void)state;
  open_batch("r1", "m1", 2);
  ircd_strncpy(cli_label(&cli), "c1", sizeof(con.con_label));
  cli_label_responded(&cli) = 0;
  multiline_discard_answer(&cli);
  assert_int_equal(n_acked, 1);
  assert_string_equal(acked[0], "m1");
  assert_string_equal(cli_label(&cli), "c1");
  assert_int_equal(cli_label_responded(&cli), 0);
  multiline_discard_batch(&cli);
  assert_int_equal(links_freed, 2);
  assert_string_equal(con_ml_batch_id(&con), "");
  assert_null(con_ml_messages(&con));
  /* discarded: no FAIL BATCH TIMEOUT later, no dead reference kept */
  assert_string_equal(con_ml_dead_batch_id(&con), "");
}

/* An unlabeled batch, or none open: nothing is answered. */
static void test_discard_answer_nothing_to_answer(void **state)
{
  (void)state;
  multiline_discard_answer(&cli);
  open_batch("r2", "", 1);
  multiline_discard_answer(&cli);
  assert_int_equal(n_acked, 0);
  multiline_discard_batch(&cli);
  assert_int_equal(links_freed, 1);
}

/* The Connection freed with a batch open: its lines go with it. */
static void test_free_connection_frees_the_lines(void **state)
{
  (void)state;
  multiline_free_connection(&con);                 /* none open: nothing */
  assert_int_equal(links_freed, 0);
  open_batch("r3", "m3", 3);
  multiline_free_connection(&con);
  assert_int_equal(links_freed, 3);
  assert_null(con_ml_messages(&con));
  assert_int_equal(con_ml_msg_count(&con), 0);
  assert_int_equal(n_acked, 0);                    /* nothing sent */
  multiline_free_connection(NULL);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test_setup(test_discard_answer_acks_the_batch_label, setup),
    cmocka_unit_test_setup(test_discard_answer_nothing_to_answer, setup),
    cmocka_unit_test_setup(test_free_connection_frees_the_lines, setup),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
