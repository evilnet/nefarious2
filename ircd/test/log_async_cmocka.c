/*
 * log_async_cmocka.c - the async log writer never writes to a descriptor
 * the log has closed
 *
 * With ASYNC_LOGGING the main thread queues each line with the NUMBER of
 * its log file's descriptor, and a writer thread write()s it later.  A
 * descriptor closed while lines for it were queued, or while the writer
 * was inside its write(), sends those lines to whatever file opened next
 * and got the number: log_close() (every REHASH and log rotation) and
 * log_file_destroy() (a log file changed or dropped) closed at once, and
 * log_async_flush() returned as soon as the queue was empty -- which it
 * is while the writer is still writing the last line it took.
 *
 * And at shutdown the logs stay shut.  server_die() closes them, then
 * close_connections() closes every descriptor by number, and the rest of
 * the dying event batch still runs: a log line there reopened its file on
 * the lowest free number -- 0, 1, 2, then numbers clients still hold --
 * where Debug output (fd 2) and a stale client teardown would follow it.
 * log_shutdown() closes the logs for good; only log_resume() (a failed
 * restart's execv) opens them again.
 *
 * This links the real ircd_log.o and ircd_log_async.o, with the writer
 * thread's write() wrapped (-Wl,--wrap=write): a gate holds a write until
 * the test opens it, so a case can close a descriptor with a write in
 * flight, deterministically.
 */
#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <cmocka.h>

#ifdef HAVE_PTHREAD

#include "client.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_log_async.h"

/* ------------------------------------------------------------------ */
/* The ircd around the log                                             */
/* ------------------------------------------------------------------ */

time_t CurrentTime;
time_t TSoffset;

void debug(int level, const char *form, ...)
{
  (void)level; (void)form;
}

/** ASYNC_LOGGING's value; the cases that turn it off set it back. */
static int async_logging = 1;

int feature_bool(enum Feature feat)
{
  return feat == FEAT_ASYNC_LOGGING && async_logging;
}

int feature_int(enum Feature feat) { (void)feat; return 0; }

void sendto_opmask_butone(struct Client *one, unsigned int mask,
                          const char *pattern, ...)
{
  (void)one; (void)mask; (void)pattern;
}

int send_reply(struct Client *to, int reply, ...)
{
  (void)to; (void)reply;
  return 0;
}

/* ------------------------------------------------------------------ */
/* The writer's write(), behind a gate                                  */
/* ------------------------------------------------------------------ */

static pthread_mutex_t gate_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t gate_cv = PTHREAD_COND_INITIALIZER;
static int gate_closed;          /* writes wait while set */
static int at_gate;              /* writes waiting at the gate */
static int completed;            /* writes done */

ssize_t __real_write(int fd, const void *buf, size_t len);

ssize_t __wrap_write(int fd, const void *buf, size_t len)
{
  ssize_t rc;

  pthread_mutex_lock(&gate_mu);
  at_gate++;
  pthread_cond_broadcast(&gate_cv);
  while (gate_closed)
    pthread_cond_wait(&gate_cv, &gate_mu);
  at_gate--;
  pthread_mutex_unlock(&gate_mu);

  rc = __real_write(fd, buf, len);

  pthread_mutex_lock(&gate_mu);
  completed++;
  pthread_cond_broadcast(&gate_cv);
  pthread_mutex_unlock(&gate_mu);
  return rc;
}

static void gate_close(void)
{
  pthread_mutex_lock(&gate_mu);
  gate_closed = 1;
  pthread_mutex_unlock(&gate_mu);
}

static void gate_open(void)
{
  pthread_mutex_lock(&gate_mu);
  gate_closed = 0;
  pthread_cond_broadcast(&gate_cv);
  pthread_mutex_unlock(&gate_mu);
}

/** Wait until the writer is inside its write(), held at the gate. */
static void wait_at_gate(void)
{
  struct timespec until;

  clock_gettime(CLOCK_REALTIME, &until);
  until.tv_sec += 5;
  pthread_mutex_lock(&gate_mu);
  while (!at_gate)
    if (pthread_cond_timedwait(&gate_cv, &gate_mu, &until) != 0)
      break;
  pthread_mutex_unlock(&gate_mu);
  assert_int_equal(at_gate, 1);
}

static int writes_completed(void)
{
  int n;

  pthread_mutex_lock(&gate_mu);
  n = completed;
  pthread_mutex_unlock(&gate_mu);
  return n;
}

/** Wait (up to 5 s) until n writes have completed. */
static void wait_completed(int n)
{
  struct timespec until;

  clock_gettime(CLOCK_REALTIME, &until);
  until.tv_sec += 5;
  pthread_mutex_lock(&gate_mu);
  while (completed < n)
    if (pthread_cond_timedwait(&gate_cv, &gate_mu, &until) != 0)
      break;
  pthread_mutex_unlock(&gate_mu);
  assert_int_equal(writes_completed(), n);
}

/** Opens the gate a little later, from another thread: the main thread
 * is meanwhile inside the call under test. */
static void *open_gate_later(void *arg)
{
  struct timespec delay = { 0, 150 * 1000 * 1000 };

  (void)arg;
  nanosleep(&delay, NULL);
  gate_open();
  return NULL;
}

static pthread_t opener;

static void open_gate_soon(void)
{
  assert_int_equal(pthread_create(&opener, NULL, open_gate_later, NULL), 0);
}

static void opener_join(void)
{
  pthread_join(opener, NULL);
}

/* ------------------------------------------------------------------ */
/* Files                                                               */
/* ------------------------------------------------------------------ */

static char log_path[64];

static void temp_path(char *buf, size_t size, const char *what)
{
  snprintf(buf, size, "/tmp/log_async_%s_%ld", what, (long)getpid());
  unlink(buf);
}

static off_t path_size(const char *path)
{
  struct stat st;

  if (stat(path, &st) != 0)
    return -1;
  return st.st_size;
}

static off_t fd_size(int fd)
{
  struct stat st;

  assert_int_equal(fstat(fd, &st), 0);
  return st.st_size;
}

static int case_setup(void **state)
{
  (void)state;
  completed = 0;
  at_gate = 0;
  gate_closed = 0;
  async_logging = 1;
  temp_path(log_path, sizeof(log_path), "file");
  if (log_async_init(8) < 0)
    return -1;
  log_async_start();            /* startup is over */
  return 0;
}

/** A case that starts the writer itself. */
static int case_setup_stopped(void **state)
{
  (void)state;
  completed = 0;
  at_gate = 0;
  gate_closed = 0;
  async_logging = 1;
  temp_path(log_path, sizeof(log_path), "file");
  return log_async_available() ? -1 : 0;
}

static int case_teardown(void **state)
{
  (void)state;
  gate_open();
  log_async_stop();             /* back to before startup */
  log_resume();                 /* a case that failed while shut */
  log_close();                  /* and the syslog socket log_resume()
                                 * opened: each case starts with the same
                                 * free descriptor numbers */
  log_set_file("SYSTEM", NULL);
  unlink(log_path);
  return 0;
}

/** The descriptor number the log has open for log_path. */
static int log_fd(void)
{
  char link[64], target[256];
  ssize_t n;
  int fd;

  for (fd = 3; fd < 64; fd++) {
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    n = readlink(link, target, sizeof(target) - 1);
    if (n > 0) {
      target[n] = '\0';
      if (!strcmp(target, log_path))
        return fd;
    }
  }
  return -1;
}

/** One line queued for the SYSTEM log and taken by the writer, which is
 * now inside its write(), held at the gate.  Returns the log's fd. */
static int line_in_flight(void)
{
  int fd;

  assert_int_equal(log_set_file("SYSTEM", log_path), 0);
  gate_close();
  log_write(LS_SYSTEM, L_CRIT, LOG_NOSYSLOG | LOG_NOSNOTICE,
            "a line in flight");
  fd = log_fd();
  assert_true(fd >= 0);
  wait_at_gate();
  return fd;
}

/* ------------------------------------------------------------------ */
/* Tests                                                               */
/* ------------------------------------------------------------------ */

/** log_async_flush() returns only when every queued line is written,
 * including the one the writer took and is still writing. */
static void flush_waits_for_the_write_in_flight(void **state)
{
  (void)state;
  line_in_flight();
  open_gate_soon();

  log_async_flush();

  assert_int_equal(writes_completed(), 1);
  opener_join();
}

/** log_close() (REHASH, log rotation): the line in flight goes to the log
 * file, never to the file that gets the number after the close. */
static void log_close_drains_before_it_closes(void **state)
{
  char other_path[64];
  int fd, other;

  (void)state;
  fd = line_in_flight();
  open_gate_soon();

  log_close();
  temp_path(other_path, sizeof(other_path), "other");
  other = open(other_path, O_RDWR | O_CREAT | O_TRUNC, 0600);
  assert_int_equal(other, fd);       /* the number is free: the next open */

  opener_join();
  wait_completed(1);
  assert_int_equal(fd_size(other), 0);
  assert_true(path_size(log_path) > 0);
  close(other);
  unlink(other_path);
}

/** log_file_destroy() (a log file changed or dropped): the same. */
static void log_file_destroy_drains_before_it_closes(void **state)
{
  char other_path[64];
  int fd, other;

  (void)state;
  fd = line_in_flight();
  open_gate_soon();

  log_set_file("SYSTEM", NULL);      /* the last reference: destroyed */
  temp_path(other_path, sizeof(other_path), "other");
  other = open(other_path, O_RDWR | O_CREAT | O_TRUNC, 0600);
  assert_int_equal(other, fd);

  opener_join();
  wait_completed(1);
  assert_int_equal(fd_size(other), 0);
  assert_true(path_size(log_path) > 0);
  close(other);
  unlink(other_path);
}

/** log_async_shutdown() writes everything queued before the writer
 * exits (a pin: it always did). */
static void shutdown_writes_the_queue(void **state)
{
  int i;

  (void)state;
  assert_int_equal(log_set_file("SYSTEM", log_path), 0);
  for (i = 0; i < 5; i++)
    log_write(LS_SYSTEM, L_CRIT, LOG_NOSYSLOG | LOG_NOSNOTICE, "line %d", i);

  log_async_shutdown();

  assert_int_equal(writes_completed(), 5);
}

/** After log_shutdown() nothing reopens a log -- not a log line, not a
 * REHASH's log_reopen(); log_resume() does. */
static void no_log_reopens_after_shutdown(void **state)
{
  off_t size;

  (void)state;
  assert_int_equal(log_set_file("SYSTEM", log_path), 0);
  log_write(LS_SYSTEM, L_CRIT, LOG_NOSYSLOG | LOG_NOSNOTICE, "before");
  log_async_flush();
  size = path_size(log_path);
  assert_true(size > 0);

  log_shutdown();
  assert_int_equal(log_fd(), -1);

  log_write(LS_SYSTEM, L_CRIT, LOG_NOSYSLOG | LOG_NOSNOTICE, "while shut");
  log_async_flush();
  assert_int_equal(log_fd(), -1);
  log_reopen();
  log_write(LS_SYSTEM, L_CRIT, LOG_NOSYSLOG | LOG_NOSNOTICE, "after reopen");
  log_async_flush();
  assert_int_equal(log_fd(), -1);
  assert_int_equal(path_size(log_path), size);

  log_resume();
  log_write(LS_SYSTEM, L_CRIT, LOG_NOSYSLOG | LOG_NOSNOTICE, "resumed");
  log_async_flush();
  assert_true(log_fd() >= 0);
  assert_true(path_size(log_path) > size);
}

/** Before log_async_start() (startup: ircd.conf is still being read, or
 * this is a configuration check), the feature turned on starts nothing;
 * log_async_start() starts the writer. */
static void writer_waits_for_startup(void **state)
{
  (void)state;
  log_feature_async_logging();
  assert_false(log_async_available());

  log_async_start();
  assert_true(log_async_available());
}

/** After startup, a REHASH that turns ASYNC_LOGGING on starts the
 * writer, and log lines go through it.  Starts up and stops the writer
 * first, so it holds whichever case runs before it. */
static void turning_it_on_starts_the_writer(void **state)
{
  (void)state;
  assert_int_equal(log_set_file("SYSTEM", log_path), 0);
  log_async_start();
  log_async_shutdown();
  assert_false(log_async_available());

  log_feature_async_logging();
  assert_true(log_async_available());

  gate_close();
  log_write(LS_SYSTEM, L_CRIT, LOG_NOSYSLOG | LOG_NOSNOTICE, "queued");
  wait_at_gate();               /* the writer, not this thread */
  gate_open();
  wait_completed(1);
}

/** Turning ASYNC_LOGGING off writes what the writer still holds before
 * the next line goes out synchronously: the queue never lands after
 * newer lines. */
static void turning_it_off_writes_the_queue_first(void **state)
{
  off_t size;
  int i;

  (void)state;
  assert_int_equal(log_set_file("SYSTEM", log_path), 0);
  gate_close();
  for (i = 0; i < 3; i++)
    log_write(LS_SYSTEM, L_CRIT, LOG_NOSYSLOG | LOG_NOSNOTICE, "line %d", i);
  wait_at_gate();
  assert_int_equal(writes_completed(), 0);

  async_logging = 0;
  open_gate_soon();
  log_feature_async_logging();
  assert_int_equal(writes_completed(), 3);
  opener_join();

  /* A synchronous line is written here and now, by writev(). */
  size = path_size(log_path);
  log_write(LS_SYSTEM, L_CRIT, LOG_NOSYSLOG | LOG_NOSNOTICE, "synchronous");
  assert_true(path_size(log_path) > size);
  assert_int_equal(writes_completed(), 3);
}

/** How many times @a needle occurs in the file at @a path. */
static int occurrences(const char *path, const char *needle)
{
  char buf[8192], *p;
  ssize_t n;
  int fd, count = 0;

  fd = open(path, O_RDONLY);
  assert_true(fd >= 0);
  n = read(fd, buf, sizeof(buf) - 1);
  close(fd);
  assert_true(n >= 0);
  buf[n] = '\0';
  for (p = buf; (p = strstr(p, needle)); p += strlen(needle))
    count++;
  return count;
}

/** With the queue full, log_async_write() writes the line itself (it
 * returns 1); log_vwrite() must not write it a second time. */
static void a_line_the_full_queue_writes_is_written_once(void **state)
{
  int i;

  (void)state;
  assert_int_equal(log_set_file("SYSTEM", log_path), 0);
  gate_close();
  log_write(LS_SYSTEM, L_CRIT, LOG_NOSYSLOG | LOG_NOSNOTICE, "first");
  wait_at_gate();               /* the writer holds it; the ring is empty */
  for (i = 0; i < 7; i++)       /* a ring of 8 holds 7 */
    log_write(LS_SYSTEM, L_CRIT, LOG_NOSYSLOG | LOG_NOSNOTICE, "fill %d", i);

  open_gate_soon();             /* the fallback's own write() waits too */
  log_write(LS_SYSTEM, L_CRIT, LOG_NOSYSLOG | LOG_NOSNOTICE, "overflow");
  opener_join();
  log_async_flush();

  assert_int_equal(occurrences(log_path, "overflow"), 1);
  assert_int_equal(occurrences(log_path, "fill"), 7);
}

/** A line longer than a queue entry is cut short, but still ends its
 * line: the next one starts on a line of its own. */
static void a_cut_line_still_ends_its_line(void **state)
{
  char big[LOG_ASYNC_MAX_ENTRY + 100], buf[3 * LOG_ASYNC_MAX_ENTRY];
  ssize_t n;
  int fd;

  (void)state;
  assert_int_equal(log_set_file("SYSTEM", log_path), 0);
  memset(big, 'x', sizeof(big) - 1);
  big[sizeof(big) - 1] = '\0';
  log_write(LS_SYSTEM, L_CRIT, LOG_NOSYSLOG | LOG_NOSNOTICE, "%s", big);
  log_write(LS_SYSTEM, L_CRIT, LOG_NOSYSLOG | LOG_NOSNOTICE, "after");
  log_async_flush();

  fd = open(log_path, O_RDONLY);
  assert_true(fd >= 0);
  n = read(fd, buf, sizeof(buf) - 1);
  close(fd);
  assert_true(n > 0);
  buf[n] = '\0';
  assert_int_equal(buf[n - 1], '\n');
  assert_non_null(strstr(buf, "x\n["));   /* "after" has its own line */
}

/** The same, when the queue is full and the caller writes the line
 * itself: the cut line still ends its line. */
static void a_cut_line_the_full_queue_writes_still_ends_its_line(void **state)
{
  char big[LOG_ASYNC_MAX_ENTRY + 100], buf[8 * LOG_ASYNC_MAX_ENTRY];
  ssize_t n;
  int fd, i;
  unsigned long dropped, dropped_after;

  (void)state;
  assert_int_equal(log_set_file("SYSTEM", log_path), 0);
  gate_close();
  log_write(LS_SYSTEM, L_CRIT, LOG_NOSYSLOG | LOG_NOSNOTICE, "first");
  wait_at_gate();
  for (i = 0; i < 7; i++)               /* fill the ring */
    log_write(LS_SYSTEM, L_CRIT, LOG_NOSYSLOG | LOG_NOSNOTICE, "fill %d", i);
  memset(big, 'x', sizeof(big) - 1);
  big[sizeof(big) - 1] = '\0';
  log_async_stats(NULL, NULL, &dropped);
  open_gate_soon();                     /* long after the 1 ms wait */
  log_write(LS_SYSTEM, L_CRIT, LOG_NOSYSLOG | LOG_NOSNOTICE, "%s", big);
  log_async_stats(NULL, NULL, &dropped_after);
  assert_int_equal(dropped_after, dropped + 1);   /* the caller wrote it */
  opener_join();
  log_write(LS_SYSTEM, L_CRIT, LOG_NOSYSLOG | LOG_NOSNOTICE, "after");
  log_async_flush();

  fd = open(log_path, O_RDONLY);
  assert_true(fd >= 0);
  n = read(fd, buf, sizeof(buf) - 1);
  close(fd);
  assert_true(n > 0);
  buf[n] = '\0';
  assert_non_null(strstr(buf, "xxxx\n"));
  assert_null(strstr(buf, "x["));       /* nothing runs on from it */
}

/** After the writers stop (DIE), nothing starts the writer again. */
static void nothing_restarts_the_writer_after_stop(void **state)
{
  (void)state;
  log_async_stop();
  assert_false(log_async_available());
  log_feature_async_logging();
  assert_false(log_async_available());
}

/* syslog() is wrapped (-Wl,--wrap=syslog, and --wrap=__syslog_chk for a
 * fortified build): the text it was given. */
static pthread_mutex_t syslog_mu = PTHREAD_MUTEX_INITIALIZER;
static char syslogged[512];
static int syslog_calls;

void __wrap_syslog(int priority, const char *format, ...)
{
  va_list args;

  (void)priority;
  pthread_mutex_lock(&syslog_mu);
  va_start(args, format);
  vsnprintf(syslogged, sizeof(syslogged), format, args);
  va_end(args);
  syslog_calls++;
  pthread_mutex_unlock(&syslog_mu);
}

/* A fortified build calls __syslog_chk() instead. */
void __wrap___syslog_chk(int priority, int flag, const char *format, ...)
{
  va_list args;

  (void)priority; (void)flag;
  pthread_mutex_lock(&syslog_mu);
  va_start(args, format);
  vsnprintf(syslogged, sizeof(syslogged), format, args);
  va_end(args);
  syslog_calls++;
  pthread_mutex_unlock(&syslog_mu);
}

/** A queued line goes to syslog as syslog wants it: without the log
 * file's timestamp (syslog stamps its own) and without the newline. */
static void syslog_gets_the_line_without_the_file_stamp(void **state)
{
  (void)state;
  assert_int_equal(log_set_file("SYSTEM", log_path), 0);
  assert_int_equal(log_set_facility("SYSTEM", "LOCAL0"), 0);
  syslog_calls = 0;
  log_write(LS_SYSTEM, L_CRIT, LOG_NOSNOTICE, "to syslog");
  log_async_flush();
  log_set_facility("SYSTEM", NULL);

  assert_int_equal(syslog_calls, 1);
  assert_string_equal(syslogged, "SYSTEM [CRIT]: to syslog");
}

/* pthread_cond_timedwait() is wrapped (-Wl,--wrap=pthread_cond_timedwait):
 * while spurious_waits is set, a wait on the thread that set it returns 0
 * at once with nothing changed, as POSIX allows any wait to. */
static int spurious_waits;
static pthread_t spurious_thread;

int __real_pthread_cond_timedwait(pthread_cond_t *cond, pthread_mutex_t *mu,
                                  const struct timespec *until);

int __wrap_pthread_cond_timedwait(pthread_cond_t *cond, pthread_mutex_t *mu,
                                  const struct timespec *until)
{
  if (spurious_waits > 0 && pthread_equal(pthread_self(), spurious_thread)) {
    spurious_waits--;
    return 0;
  }
  return __real_pthread_cond_timedwait(cond, mu, until);
}

/** A full ring: a wakeup that leaves it full is not room.  The line goes
 * the direct way, and every queued line is still written. */
static void full_ring_spurious_wakeup_is_not_room(void **state)
{
  int i;

  (void)state;
  assert_int_equal(log_set_file("SYSTEM", log_path), 0);
  gate_close();
  log_write(LS_SYSTEM, L_CRIT, LOG_NOSYSLOG | LOG_NOSNOTICE, "first");
  wait_at_gate();               /* the writer holds it; the ring is empty */
  for (i = 0; i < 7; i++)       /* a ring of 8 holds 7 */
    log_write(LS_SYSTEM, L_CRIT, LOG_NOSYSLOG | LOG_NOSNOTICE, "fill %d", i);

  spurious_thread = pthread_self();
  spurious_waits = 1;
  /* No descriptor and no syslog: the fallback writes nothing (and does
   * not wait at the gate), and only its return value tells. */
  assert_int_equal(log_async_write(-1, 0, "overflow\n", -1, 0), 1);
  assert_int_equal(spurious_waits, 0);

  gate_open();
  log_async_flush();
  assert_int_equal(occurrences(log_path, "fill"), 7);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test_setup_teardown(a_cut_line_still_ends_its_line,
                                    case_setup, case_teardown),
    cmocka_unit_test_setup_teardown(syslog_gets_the_line_without_the_file_stamp,
                                    case_setup, case_teardown),
    cmocka_unit_test_setup_teardown(full_ring_spurious_wakeup_is_not_room,
                                    case_setup, case_teardown),
    cmocka_unit_test_setup_teardown(
        a_cut_line_the_full_queue_writes_still_ends_its_line,
        case_setup, case_teardown),
    cmocka_unit_test_setup_teardown(nothing_restarts_the_writer_after_stop,
                                    case_setup, case_teardown),
    cmocka_unit_test_setup_teardown(a_line_the_full_queue_writes_is_written_once,
                                    case_setup, case_teardown),
    cmocka_unit_test_setup_teardown(writer_waits_for_startup,
                                    case_setup_stopped, case_teardown),
    cmocka_unit_test_setup_teardown(turning_it_on_starts_the_writer,
                                    case_setup_stopped, case_teardown),
    cmocka_unit_test_setup_teardown(turning_it_off_writes_the_queue_first,
                                    case_setup, case_teardown),
    cmocka_unit_test_setup_teardown(flush_waits_for_the_write_in_flight,
                                    case_setup, case_teardown),
    cmocka_unit_test_setup_teardown(log_close_drains_before_it_closes,
                                    case_setup, case_teardown),
    cmocka_unit_test_setup_teardown(log_file_destroy_drains_before_it_closes,
                                    case_setup, case_teardown),
    cmocka_unit_test_setup_teardown(shutdown_writes_the_queue,
                                    case_setup, case_teardown),
    cmocka_unit_test_setup_teardown(no_log_reopens_after_shutdown,
                                    case_setup, case_teardown),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}

#else /* !HAVE_PTHREAD */

int main(void)
{
  puts("log_async_cmocka: built without pthreads, no async log to test");
  return 0;
}

#endif /* HAVE_PTHREAD */
