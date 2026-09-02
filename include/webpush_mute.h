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

/** 1 when `target` is muted by `value` at `now` (global `*` entry or a
 * target match, while the entry's `until` is 0=indefinite or in the
 * future). */
int webpush_mute_check(const char *value, const char *target, time_t now);

/** Prune expired entries (and, when `drop_target` is non-NULL, that
 * target's entries) from `value` into `out`.  Returns 1 when the value
 * changed. */
int webpush_mute_prune(const char *value, const char *drop_target, time_t now,
                       char *out, size_t outlen);

#endif /* INCLUDED_webpush_mute_h */
