/*
 * IRC - Internet Relay Chat, ircd/conf_precheck.c
 *
 * The REHASH precheck (include/conf_precheck.h).  Standalone: no ircd
 * header, so a CMocka suite links it alone.
 */
#include "config.h"

#include "conf_precheck.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#ifdef __linux__
#include <sys/syscall.h>
#endif
#include <time.h>
#include <unistd.h>

/** Exit status of "ircd -k" when the configuration has errors
 * (init_conf() failed: main() returns 7). */
#define CHKCONF_ERRORS 7

static long elapsed_ms(const struct timespec *t0)
{
  struct timespec t;

  clock_gettime(CLOCK_MONOTONIC, &t);
  return (t.tv_sec - t0->tv_sec) * 1000L + (t.tv_nsec - t0->tv_nsec) / 1000000L;
}

/* In the child, between fork() and exec: async-signal-safe calls only.
 * Every signal is blocked on entry (conf_precheck_run()). */
/* Close every descriptor from 3 up, in the child.  One close() per
 * number up to the hard limit costs the server a blocked loop in
 * proportion to it (300 ms and more at 524288); closefrom() or Linux's
 * close_range() is one call.  The BSDs and Solaris are named here as
 * well as tested for: a configure that was not regenerated does not
 * define HAVE_CLOSEFROM. */
static void close_from_3(void)
{
#if defined(HAVE_CLOSEFROM) || defined(__FreeBSD__) || defined(__OpenBSD__) \
    || defined(__NetBSD__) || defined(__DragonFly__) || defined(__sun)
  closefrom(3);
#else
  int fd, max;

#if defined(__linux__) && defined(SYS_close_range)
  if (syscall(SYS_close_range, 3U, ~0U, 0U) == 0)
    return;
#endif
  max = (int)sysconf(_SC_OPEN_MAX);
  if (max < 0 || max > 1048576)
    max = 1048576;
  for (fd = 3; fd < max; fd++)
    close(fd);
#endif
}

static void run_check(const char *exe, const char *dpath, const char *conf,
                      int wfd)
{
  static const struct rlimit no_core = { 0, 0 };
  struct sigaction dfl;
  char *argv[7];
  sigset_t none;
  int fd, sig;

  /* The server's handlers write to its signal pipe: none of them may run
   * here.  Then a process group of its own, so a timeout kills whatever
   * the check leaves behind, and a group signal for the server does not
   * reach the check. */
  memset(&dfl, 0, sizeof(dfl));
  dfl.sa_handler = SIG_DFL;
  for (sig = 1; sig < NSIG; sig++)
    sigaction(sig, &dfl, NULL);
  setpgid(0, 0);
  sigemptyset(&none);
  sigprocmask(SIG_SETMASK, &none, NULL);
  if ((fd = open("/dev/null", O_RDONLY)) < 0
      || dup2(fd, 0) < 0 || dup2(wfd, 1) < 0 || dup2(wfd, 2) < 0)
    _exit(127);
  /* Every descriptor of the server's goes: its sockets, its store, its
   * poll set.  Few are marked close-on-exec. */
  close_from_3();
  /* A check that crashes leaves no core file: the server's limit
   * (set_core_limit()) is inherited, and a file that crashes the parser
   * would leave one at every try. */
  setrlimit(RLIMIT_CORE, &no_core);
  argv[0] = (char *)exe;
  argv[1] = (char *)"-k";
  argv[2] = (char *)"-d";
  argv[3] = (char *)dpath;
  argv[4] = (char *)"-f";
  argv[5] = (char *)conf;
  argv[6] = NULL;
  execv(exe, argv);
  _exit(127);
}

/* End @a out (@a used bytes so far) with a line saying how the check
 * ended, over the tail of its output if there is no room. */
static void note_end(char *out, size_t outlen, size_t used, const char *note)
{
  size_t n = strlen(note);

  if (n >= outlen)
    n = outlen - 1;
  if (used + n > outlen - 1)    /* over the tail, the newline kept */
    used = n + 1 <= outlen - 1 ? outlen - 2 - n : outlen - 1 - n;
  if (used > 0 && out[used - 1] != '\n' && used + n + 1 <= outlen - 1)
    out[used++] = '\n';
  memcpy(out + used, note, n);
  out[used + n] = '\0';
}

static enum conf_precheck_result
precheck_run(const char *exe, const char *dpath, const char *conf,
             int timeout_ms, char *out, size_t outlen);

enum conf_precheck_result
conf_precheck_run(const char *exe, const char *dpath, const char *conf,
                  int timeout_ms, char *out, size_t outlen)
{
  struct sigaction chld, dfl;
  enum conf_precheck_result res;
  int restore = 0;

  /* SIGCHLD ignored (the kqueue engine does so) has the kernel reap the
   * check, and waitpid() could never tell how it ended: default for the
   * check's lifetime.  A handler is left alone: it only queues an event,
   * and the event loop's waitpid(-1) cannot run before this returns. */
  if (sigaction(SIGCHLD, NULL, &chld) == 0
      && (chld.sa_handler == SIG_IGN || (chld.sa_flags & SA_NOCLDWAIT))) {
    memset(&dfl, 0, sizeof(dfl));
    dfl.sa_handler = SIG_DFL;
    sigemptyset(&dfl.sa_mask);
    restore = sigaction(SIGCHLD, &dfl, NULL) == 0;
  }
  res = precheck_run(exe, dpath, conf, timeout_ms, out, outlen);
  if (restore)
    sigaction(SIGCHLD, &chld, NULL);
  return res;
}

/* Has @a pid exited?  It is left a zombie (WNOWAIT), so its pid, and the
 * process group named after it, cannot be reused until it is reaped:
 * the group kill below never reaches another process. */
static int exited(pid_t pid, int *gone)
{
  siginfo_t si;

  memset(&si, 0, sizeof(si));
  if (waitid(P_PID, (id_t)pid, &si, WEXITED | WNOHANG | WNOWAIT) < 0) {
    if (errno != EINTR)
      *gone = 1;                /* not ours to wait for, or to kill */
    return 0;
  }
  return si.si_pid == pid;
}

static enum conf_precheck_result
precheck_run(const char *exe, const char *dpath, const char *conf,
             int timeout_ms, char *out, size_t outlen)
{
  struct timespec t0, exited_at;
  size_t used = 0;
  char note[160];
  int p[2], status = 0, done = 0, eof = 0, gone = 0, i;
  sigset_t all, old;
  pid_t pid;

  out[0] = '\0';
  if (pipe(p) < 0) {
    snprintf(note, sizeof(note), "it could not be started: pipe(): %s\n",
             strerror(errno));
    note_end(out, outlen, 0, note);
    return CONF_PRECHECK_FAILED;
  }
  /* No signal handler of the server's may run in the child before it
   * resets them. */
  sigfillset(&all);
  sigprocmask(SIG_BLOCK, &all, &old);
  pid = fork();
  if (pid == 0)
    run_check(exe, dpath, conf, p[1]);
  i = errno;
  /* Here as well as in the child: the group must exist before a timeout
   * can kill it, whichever of the two runs first. */
  if (pid > 0)
    setpgid(pid, pid);
  sigprocmask(SIG_SETMASK, &old, NULL);
  if (pid < 0) {
    close(p[0]);
    close(p[1]);
    snprintf(note, sizeof(note), "it could not be started: fork(): %s\n",
             strerror(i));
    note_end(out, outlen, 0, note);
    return CONF_PRECHECK_FAILED;
  }
  close(p[1]);
  fcntl(p[0], F_SETFL, fcntl(p[0], F_GETFL) | O_NONBLOCK);

  /* Read its output to the end while it runs (a full pipe would stall
   * it), and reap it; both within the time allowed. */
  clock_gettime(CLOCK_MONOTONIC, &t0);
  while (!done || !eof) {
    long left = timeout_ms - elapsed_ms(&t0);
    char buf[1024];
    ssize_t n;

    if (left <= 0)
      break;
    if (!eof) {
      struct pollfd pfd = { p[0], POLLIN, 0 };

      if (poll(&pfd, 1, left < 50 ? (int)left : 50) < 0
          && errno != EINTR)
        break;
      while ((n = read(p[0], buf, sizeof(buf))) > 0) {
        size_t take = (size_t)n;

        if (take > outlen - 1 - used)
          take = outlen - 1 - used;
        memcpy(out + used, buf, take);
        used += take;
      }
      if (n == 0)
        eof = 1;
      else if (errno != EAGAIN && errno != EINTR)
        eof = 1;
    } else {
      struct timespec ten = { 0, 10000000 };

      nanosleep(&ten, NULL);
    }
    if (!done) {
      if (exited(pid, &gone)) {
        done = 1;
        clock_gettime(CLOCK_MONOTONIC, &exited_at);
      } else if (gone)
        break;
    }
    /* Exited with the pipe still open: something it started holds it.
     * What the check said is in once it has exited. */
    if (done && !eof && elapsed_ms(&exited_at) >= 200)
      break;
  }
  out[used] = '\0';
  close(p[0]);
  if (gone) {
    note_end(out, outlen, used, "it was reaped elsewhere\n");
    return CONF_PRECHECK_FAILED;
  }
  /* Anything it left behind, and the check itself if it is still
   * running: its pid is not reaped yet, so the group is still its. */
  kill(-pid, SIGKILL);
  kill(pid, SIGKILL);

  if (!done) {
    /* Reaped within a second, or left: a check stuck in uninterruptible
     * sleep must not hold the server.  The event loop's SIGCHLD handling
     * reaps it once it goes. */
    for (i = 0; i < 100; i++) {
      struct timespec ten = { 0, 10000000 };
      pid_t r = waitpid(pid, &status, WNOHANG);

      if (r == pid || (r < 0 && errno != EINTR))
        break;
      nanosleep(&ten, NULL);
    }
    snprintf(note, sizeof(note), "it did not finish in %d ms\n", timeout_ms);
    note_end(out, outlen, used, note);
    return CONF_PRECHECK_FAILED;
  }
  while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
    ;                           /* a zombie: at once */
  if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
    return CONF_PRECHECK_OK;
  if (WIFEXITED(status) && WEXITSTATUS(status) == CHKCONF_ERRORS)
    return CONF_PRECHECK_ERRORS;
  if (WIFSIGNALED(status))
    snprintf(note, sizeof(note), "it died of signal %d (%s)\n",
             WTERMSIG(status), strsignal(WTERMSIG(status)));
  else if (WIFEXITED(status) && WEXITSTATUS(status) == 127)
    snprintf(note, sizeof(note), "it could not be run (%s: exit status "
             "127)\n", exe);
  else
    snprintf(note, sizeof(note), "it exited with status %d\n",
             WIFEXITED(status) ? WEXITSTATUS(status) : -1);
  note_end(out, outlen, used, note);
  return CONF_PRECHECK_FAILED;
}
