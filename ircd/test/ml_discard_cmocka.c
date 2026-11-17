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
 *    freed with it;
 *  - a line of the batch was too long (parse_client() ->
 *    multiline_fail_batch()): FAIL BATCH MULTILINE_INVALID (no context) under the
 *    batch's label, not the cut line's, and the reference stays dead.
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

/* send.c's send_fail(): what went out, and the label it went under (the
 * tagging itself is send.c's, send_label_cmocka). */
static struct {
  int n;
  char code[64];
  char context[64];
  char label[64];
} failed;
void send_fail(struct Client *to, const char *command, const char *code,
               const char *context, const char *description)
{
  (void)command; (void)description;
  failed.n++;
  snprintf(failed.code, sizeof(failed.code), "%s", code);
  snprintf(failed.context, sizeof(failed.context), "%s",
           context ? context : "");
  snprintf(failed.label, sizeof(failed.label), "%s",
           cli_label(to)[0] && !cli_label_responded(to) ? cli_label(to) : "");
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
  memset(&failed, 0, sizeof(failed));
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

/* A labeled batch, one of its lines too long: the FAIL (no context, as
 * the multiline spec defines it) answers the batch's label -- not the cut line's own, which its 417
 * answered and which is left as it was. */
static void test_fail_batch_answers_the_batch_label(void **state)
{
  (void)state;
  open_batch("r4", "m4", 2);
  ircd_strncpy(cli_label(&cli), "c4", sizeof(con.con_label));
  cli_label_responded(&cli) = 1;               /* the 417 answered it */
  multiline_fail_batch(&cli);
  assert_int_equal(failed.n, 1);
  assert_string_equal(failed.code, "MULTILINE_INVALID");
  assert_string_equal(failed.context, "");
  assert_string_equal(failed.label, "m4");
  assert_string_equal(cli_label(&cli), "c4");
  assert_int_equal(cli_label_responded(&cli), 1);
  assert_int_equal(links_freed, 2);
  assert_string_equal(con_ml_batch_id(&con), "");
  assert_string_equal(con_ml_label(&con), "");
  assert_string_equal(con_ml_dead_batch_id(&con), "r4");  /* stays dead */
}

/* An unlabeled batch: the FAIL is unlabeled, whatever the cut line's own
 * label; none open: nothing. */
static void test_fail_batch_unlabeled(void **state)
{
  (void)state;
  multiline_fail_batch(&cli);
  assert_int_equal(failed.n, 0);
  open_batch("r5", "", 1);
  ircd_strncpy(cli_label(&cli), "c5", sizeof(con.con_label));
  cli_label_responded(&cli) = 1;
  multiline_fail_batch(&cli);
  assert_int_equal(failed.n, 1);
  assert_string_equal(failed.context, "");
  assert_string_equal(failed.label, "");
  assert_string_equal(cli_label(&cli), "c5");
  assert_int_equal(links_freed, 1);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test_setup(test_discard_answer_acks_the_batch_label, setup),
    cmocka_unit_test_setup(test_discard_answer_nothing_to_answer, setup),
    cmocka_unit_test_setup(test_free_connection_frees_the_lines, setup),
    cmocka_unit_test_setup(test_fail_batch_answers_the_batch_label, setup),
    cmocka_unit_test_setup(test_fail_batch_unlabeled, setup),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
