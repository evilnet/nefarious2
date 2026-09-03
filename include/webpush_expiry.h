/*
 * webpush_expiry.h - pure decision logic for stale webpush subscriptions.
 *
 * Subscription records persist as "endpoint|p256dh|auth|armed", where
 * `armed` is the unix second of the last WEBPUSH REGISTER.  Clients re-arm
 * on every login, so a record not re-armed within the expiry window
 * (FEAT_WEBPUSH_EXPIRE, default 180 days) belongs to a device that has
 * not run the client since before the window began and is presumed gone.
 *
 * Both functions are pure (no ircd dependencies) and unit-tested in
 * ircd/test/webpush_expiry_cmocka.c.
 */
#ifndef INCLUDED_webpush_expiry_h
#define INCLUDED_webpush_expiry_h

#include <time.h>

/** Extract the arming timestamp (unix seconds) from a stored subscription
 * record ("endpoint|p256dh|auth|armed").  Returns 0 for old-format records
 * without a timestamp — they are never swept; the client stamps them on
 * its next REGISTER — and for malformed timestamp fields. */
long long webpush_armed_at(const char *stored);

/** 1 when a record armed at `armed` was not re-armed within `max_age`
 * seconds by `now` and should be removed.  Timestamp-less records
 * (armed <= 0) and disabled windows (max_age <= 0) never expire. */
int webpush_expired(long long armed, time_t now, long long max_age);

#endif /* INCLUDED_webpush_expiry_h */
