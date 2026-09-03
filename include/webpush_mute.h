/*
 * webpush_mute.h - pure decision logic for the draft/webpush mute list.
 *
 * The account metadata key `draft/webpush/mute` holds semicolon-separated
 * entries `target:until` (unix seconds); `*` is a global snooze.  Both
 * functions here are pure (no ircd dependencies) and unit-tested in
 * ircd/test/webpush_mute_cmocka.c.
 */
#ifndef INCLUDED_webpush_mute_h
#define INCLUDED_webpush_mute_h

#include <time.h>

/** Name compare used to match entries against a target: return nonzero
 * when the two names are the same.  The ircd passes its casemapping
 * compare (channel names and nicks are case-insensitive); the pure
 * default is an exact byte compare. */
typedef int (*webpush_mute_eq)(const char *a, size_t alen,
                               const char *b, size_t blen);

/** 1 when `target` is muted by `value` at `now` (global `*` entry or a
 * target match, while the entry's `until` is 0 or negative = indefinite,
 * or in the future). */
int webpush_mute_check(const char *value, const char *target, time_t now);
int webpush_mute_check_cmp(const char *value, const char *target, time_t now,
                           webpush_mute_eq eq);

/** Prune expired entries (and, when `drop_target` is non-NULL, that
 * target's entries) from `value` into `out`.  Returns 1 when the value
 * changed, 0 when not, -1 when `out` cannot hold the result (nothing
 * should be persisted from `out` then). */
int webpush_mute_prune(const char *value, const char *drop_target, time_t now,
                       char *out, size_t outlen);
int webpush_mute_prune_cmp(const char *value, const char *drop_target, time_t now,
                           char *out, size_t outlen, webpush_mute_eq eq);

#endif /* INCLUDED_webpush_mute_h */
