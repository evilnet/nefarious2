/*
 * webpush_expiry.c - pure decision logic for stale webpush subscriptions.
 *
 * See webpush_expiry.h for the record format and the re-arming contract.
 *
 * Kept free of ircd dependencies so ircd/test can link it directly.
 */
#include <stdlib.h>
#include <string.h>

#include "../include/webpush_expiry.h"

long long webpush_armed_at(const char *stored)
{
  const char *p1, *p2, *p3;
  char buf[24];
  size_t len;
  char *endp;
  unsigned long long val;

  if (!stored)
    return 0;

  p1 = strchr(stored, '|');
  if (!p1)
    return 0;
  p2 = strchr(p1 + 1, '|');
  if (!p2)
    return 0;
  p3 = strchr(p2 + 1, '|');
  if (!p3)
    return 0;  /* old-format record: no arming timestamp */

  len = strlen(p3 + 1);
  if (len == 0 || len >= sizeof(buf))
    return 0;

  memcpy(buf, p3 + 1, len);
  buf[len] = '\0';

  if (buf[0] == '-')
    return 0;  /* negative timestamps are malformed, not ancient */

  val = strtoull(buf, &endp, 10);
  if (endp == buf)
    return 0;

  return (long long)val;
}

int webpush_expired(long long armed, time_t now, long long max_age)
{
  if (armed <= 0 || max_age <= 0)
    return 0;

  return armed + max_age <= (long long)now;
}
