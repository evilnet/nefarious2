/*
 * IRC - Internet Relay Chat, ircd/test/conf_precheck_cmocka.c
 *
 * The REHASH precheck: a fresh "ircd -k" run on the configuration, before
 * the running one is discarded (conf_precheck_run()).  The binary is a
 * shell script here, which stands in for each way the check can end.
 */
#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>
#include <cmocka.h>

#include "conf_precheck.h"

static char script[64];

/* Write @a body as an executable /bin/sh script. */
static void make_script(const char *body)
{
  FILE *f;

  snprintf(script, sizeof(script), "/tmp/conf_precheck_%ld.sh", (long)getpid());
  f = fopen(script, "w");
  assert_non_null(f);
  fprintf(f, "#!/bin/sh\n%s\n", body);
  fclose(f);
  assert_int_equal(chmod(script, 0700), 0);
}

static int teardown(void **state)
{
  (void)state;
  unlink(script);
  return 0;
}

static long now_ms(void)
{
  struct timeval tv;

  gettimeofday(&tv, NULL);
  return tv.tv_sec * 1000L + tv.tv_usec / 1000;
}

/* "ircd -k" with errors exits 7 (init_conf() failed): the errors are what
 * it printed. */
static void errors_are_reported(void **state)
{
  char out[512];

  (void)state;
  make_script("echo 'Config parse error in file ircd.conf on line 3: syntax error' >&2\n"
              "exit 7");
  assert_int_equal(conf_precheck_run(script, "/tmp", "ircd.conf", 5000,
                                     out, sizeof(out)),
                   CONF_PRECHECK_ERRORS);
  assert_non_null(strstr(out, "on line 3: syntax error"));
}

static void a_clean_file_passes(void **state)
{
  char out[512];

  (void)state;
  make_script("echo 'Configuration file ircd.conf checked okay.' >&2\nexit 0");
  assert_int_equal(conf_precheck_run(script, "/tmp", "ircd.conf", 5000,
                                     out, sizeof(out)),
                   CONF_PRECHECK_OK);
}

/* The binary is run as "<exe> -k -d <dpath> -f <conf>". */
static void the_arguments(void **state)
{
  char out[512];

  (void)state;
  make_script("echo \"$#:$1:$2:$3:$4:$5\"");
  assert_int_equal(conf_precheck_run(script, "/some/dir", "x.conf", 5000,
                                     out, sizeof(out)),
                   CONF_PRECHECK_OK);
  assert_string_equal(out, "5:-k:-d:/some/dir:-f:x.conf\n");
}

/* Any other end says nothing of the file: the check is unavailable, and
 * the rehash goes ahead as it did before the check existed. */
static void other_ends_are_unavailable(void **state)
{
  char out[512];

  (void)state;
  make_script("exit 4");          /* "ircd -k" could not reach a path */
  assert_int_equal(conf_precheck_run(script, "/tmp", "c", 5000, out, sizeof(out)),
                   CONF_PRECHECK_UNAVAILABLE);
  assert_non_null(strstr(out, "it exited with status 4"));
  make_script("kill -KILL $$");   /* the OOM killer, or an operator */
  assert_int_equal(conf_precheck_run(script, "/tmp", "c", 5000, out, sizeof(out)),
                   CONF_PRECHECK_UNAVAILABLE);
  assert_non_null(strstr(out, "it died of signal 9"));
  assert_int_equal(conf_precheck_run("/nonexistent/ircd", "/tmp", "c", 5000,
                                     out, sizeof(out)),
                   CONF_PRECHECK_UNAVAILABLE);
}

/* A check that dies of a signal of its own crashed on the file: the
 * server's own parse would likely crash too.  Its output is kept, and a
 * last line says how it ended. */
static void a_crash_is_reported(void **state)
{
  char out[512], small[24];

  (void)state;
  make_script("echo 'reading ircd.conf'; kill -SEGV $$");
  assert_int_equal(conf_precheck_run(script, "/tmp", "c", 5000, out, sizeof(out)),
                   CONF_PRECHECK_CRASHED);
  assert_non_null(strstr(out, "reading ircd.conf\nit died of signal 11"));
  make_script("kill -ABRT $$");   /* an assert() */
  assert_int_equal(conf_precheck_run(script, "/tmp", "c", 5000, out, sizeof(out)),
                   CONF_PRECHECK_CRASHED);
  /* No room: the note goes over the tail of the output. */
  make_script("echo 0123456789012345678901234567890123456789; exit 4");
  assert_int_equal(conf_precheck_run(script, "/tmp", "c", 5000, small,
                                     sizeof(small)),
                   CONF_PRECHECK_UNAVAILABLE);
  assert_int_equal(strlen(small), sizeof(small) - 1);
  assert_non_null(strstr(small, "status 4"));
  /* Room for the note: it starts a line of its own over the tail. */
  make_script("echo 01234567890123456789012345678901234567890123456789; exit 4");
  assert_int_equal(conf_precheck_run(script, "/tmp", "c", 5000, out, 40),
                   CONF_PRECHECK_UNAVAILABLE);
  assert_int_equal(strlen(out), 39);
  assert_non_null(strstr(out, "\nit exited with status 4\n"));
  make_script("kill -TERM $$");   /* a stop, not a fault */
  assert_int_equal(conf_precheck_run(script, "/tmp", "c", 5000, out, sizeof(out)),
                   CONF_PRECHECK_UNAVAILABLE);
  assert_non_null(strstr(out, "it died of signal 15"));
}

/* SIGCHLD ignored (the kqueue engine): the check is still waited for,
 * and the disposition is restored. */
static void sigchld_ignored_is_still_waited_for(void **state)
{
  char out[512];
  struct sigaction ign, now;

  (void)state;
  memset(&ign, 0, sizeof(ign));
  ign.sa_handler = SIG_IGN;
  sigemptyset(&ign.sa_mask);
  assert_int_equal(sigaction(SIGCHLD, &ign, NULL), 0);
  make_script("echo 'on line 3: syntax error'; exit 7");
  assert_int_equal(conf_precheck_run(script, "/tmp", "c", 5000, out, sizeof(out)),
                   CONF_PRECHECK_ERRORS);
  assert_int_equal(sigaction(SIGCHLD, NULL, &now), 0);
  assert_true(now.sa_handler == SIG_IGN);
  ign.sa_handler = SIG_DFL;
  sigaction(SIGCHLD, &ign, NULL);
}

/* A check that does not end in time is killed and reaped. */
static void a_hung_check_is_killed(void **state)
{
  char out[512];
  long t0;
  int st;

  (void)state;
  make_script("exec sleep 30");
  t0 = now_ms();
  assert_int_equal(conf_precheck_run(script, "/tmp", "c", 300, out, sizeof(out)),
                   CONF_PRECHECK_UNAVAILABLE);
  assert_true(now_ms() - t0 < 3000);
  assert_int_equal(waitpid(-1, &st, WNOHANG), -1);   /* nothing left */
  /* Closing its output does not end the wait early either. */
  make_script("exec >&- 2>&-; exec sleep 30");
  t0 = now_ms();
  assert_int_equal(conf_precheck_run(script, "/tmp", "c", 300, out, sizeof(out)),
                   CONF_PRECHECK_UNAVAILABLE);
  assert_true(now_ms() - t0 < 3000);
  assert_int_equal(waitpid(-1, &st, WNOHANG), -1);
}

/* A process the check left behind holding its output does not hold the
 * server: the check's own status is what counts, and what it left is
 * killed with it (its process group). */
static void a_leftover_process_does_not_hold_the_wait(void **state)
{
  char out[512];
  long t0;

  (void)state;
  make_script("echo 'Config parse error in file c on line 2: x' >&2\n"
              "sleep 30 &\nexit 7");
  t0 = now_ms();
  assert_int_equal(conf_precheck_run(script, "/tmp", "c", 5000, out, sizeof(out)),
                   CONF_PRECHECK_ERRORS);
  assert_true(now_ms() - t0 < 2000);
  assert_non_null(strstr(out, "on line 2"));
}

/* More output than the buffer holds is read to the end (the check never
 * blocks on a full pipe) and cut. */
static void long_output_is_cut(void **state)
{
  char out[64];

  (void)state;
  make_script("i=0; while [ $i -lt 4000 ]; do echo 'Config parse error in file a on line 1: x' >&2; i=$((i+1)); done; exit 7");
  assert_int_equal(conf_precheck_run(script, "/tmp", "c", 10000, out, sizeof(out)),
                   CONF_PRECHECK_ERRORS);
  assert_int_equal(strlen(out), sizeof(out) - 1);
}

/* The check gets none of the server's descriptors. */
static void descriptors_are_not_inherited(void **state)
{
  char out[512], conf[16];
  int p[2];

  (void)state;
  assert_int_equal(pipe(p), 0);
  snprintf(conf, sizeof(conf), "%d", p[1]);
  make_script("if [ -e /proc/$$/fd/$5 ]; then echo open; else echo closed; fi");
  assert_int_equal(conf_precheck_run(script, "/tmp", conf, 5000, out, sizeof(out)),
                   CONF_PRECHECK_OK);
  assert_string_equal(out, "closed\n");
  close(p[0]);
  close(p[1]);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test_teardown(errors_are_reported, teardown),
    cmocka_unit_test_teardown(a_clean_file_passes, teardown),
    cmocka_unit_test_teardown(the_arguments, teardown),
    cmocka_unit_test_teardown(other_ends_are_unavailable, teardown),
    cmocka_unit_test_teardown(a_crash_is_reported, teardown),
    cmocka_unit_test_teardown(sigchld_ignored_is_still_waited_for, teardown),
    cmocka_unit_test_teardown(a_hung_check_is_killed, teardown),
    cmocka_unit_test_teardown(a_leftover_process_does_not_hold_the_wait, teardown),
    cmocka_unit_test_teardown(long_output_is_cut, teardown),
    cmocka_unit_test_teardown(descriptors_are_not_inherited, teardown),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
