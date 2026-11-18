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

#endif /* INCLUDED_conf_precheck_h */
