/*
 * IRC - Internet Relay Chat, include/conf_precheck.h
 *
 * The REHASH precheck: before rehash() discards anything of the running
 * configuration, a fresh "ircd -k" reads the new one.  A configuration
 * with errors abandons the rehash and changes nothing.
 */
#ifndef INCLUDED_conf_precheck_h
#define INCLUDED_conf_precheck_h

#include <stddef.h>

/** How long a REHASH waits for the check (milliseconds). */
#define CONF_PRECHECK_TIMEOUT_MS 10000

/** What the check found.  Only OK lets the rehash go ahead. */
enum conf_precheck_result {
  CONF_PRECHECK_OK,     /**< it read the configuration cleanly */
  CONF_PRECHECK_ERRORS, /**< it found errors (exit status 7) */
  CONF_PRECHECK_FAILED  /**< it did not finish cleanly: it could not be
                         *   started, crashed, was killed, timed out or
                         *   exited any other way */
};

/** Run "<exe> -k -d <dpath> -f <conf>" in a process of its own and wait
 * for it, at most @a timeout_ms (then it is killed).  The check gets
 * no descriptor of the server's but its output: a pipe for stdout and
 * stderr, read to the end while it runs, and /dev/null for stdin.  The
 * check is a new image (exec), never a fork of the running server: one
 * shares the server's sockets, poll set, TLS and store state, and a
 * parse there reaches all of them.
 * @param[in] exe        The ircd binary (what is executed).
 * @param[in] dpath      Its working directory (-d).
 * @param[in] conf       The configuration file (-f).
 * @param[in] timeout_ms How long to wait.
 * @param[out] out       What it printed, NUL-terminated, cut to fit.
 *                       When it failed, a last line says how it
 *                       ended.
 * @param[in] outlen     The size of @a out (at least 1).
 * @return What it found. */
extern enum conf_precheck_result
conf_precheck_run(const char *exe, const char *dpath, const char *conf,
                  int timeout_ms, char *out, size_t outlen);

/** Remember the file the server was started as.  Call it with argv[0]
 * before the first chdir(): a path relative to where the server was
 * started is resolved here.  A name with no directory in it (found
 * through PATH) is not looked up, and counts as unknown.
 * @param[in] argv0 argv[0] of main(), or NULL to forget it. */
extern void conf_precheck_started(const char *argv0);

/** Choose the binary a configuration check runs.
 *
 * The server's own image, @a self, is the right one: it stays what the
 * server runs after an upgrade replaces the file on disk.  It is used
 * when it is the file the server was started as, or the file at
 * @a spath.  When it is neither, @a self is not the ircd (under valgrind
 * it is valgrind's tool), and the check runs the file the server was
 * started as; when that is unknown, gone or not executable, @a spath.
 * @param[in] self  The running image ("/proc/self/exe").
 * @param[in] spath Where the ircd is installed (SPATH).
 * @return @a self, @a spath, or the started file's path (valid until
 *   the next conf_precheck_started()). */
extern const char *conf_precheck_binary(const char *self, const char *spath);

#endif /* INCLUDED_conf_precheck_h */
