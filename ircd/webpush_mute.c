/*
 * webpush_mute.c - pure decision logic for the draft/webpush mute list.
 *
 * The account metadata key `draft/webpush/mute` holds semicolon-separated
 * entries `target:until` (unix seconds), where target is `*` (global
 * snooze), a channel, or a DM peer nick.  `until` bounds the entry's
 * lifetime; expired entries are simply ignored (and pruned by writers).
 *
 * Kept free of ircd dependencies so ircd/test can link it directly.
 */
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "webpush_mute.h"

/** One mute-list entry parsed out of the value string. */
struct mute_entry
{
  const char *entry;      /* start of the entry text within the value */
  size_t entry_len;       /* length of the entry text (no ';') */
  const char *target;     /* start of the target ("*" = global snooze) */
  size_t target_len;
  long long until;        /* the until token as a number */
  int neg;                /* the token carried an explicit '-' sign */
  int ok;                 /* 1 when well-formed with a numeric until */
};

/** Parse the entry at *pp (entries are ';'-separated `target:until`) and
 * advance *pp past it.  Empty or malformed entries come back with ok = 0
 * but still advance the scan, so a caller can simply loop
 * `for (p = value; *p;) next_mute_entry(&p, &e)`. */
static void next_mute_entry(const char **pp, struct mute_entry *e)
{
  const char *p = *pp;
  const char *entry_end = strchr(p, ';');
  const char *colon;
  const char *until_start;
  size_t entry_len;
  size_t until_len;
  char until_buf[24];
  char *endp;
  unsigned long long val;

  memset(e, 0, sizeof(*e));

  entry_len = entry_end ? (size_t)(entry_end - p) : strlen(p);
  e->entry = p;
  e->entry_len = entry_len;
  *pp = entry_end ? entry_end + 1 : p + entry_len;

  if (entry_len == 0)
    return;

  colon = memchr(p, ':', entry_len);
  if (!colon || colon == p)
    return;

  until_start = colon + 1;
  until_len = (size_t)((entry_end ? entry_end : p + entry_len) - until_start);
  if (until_len == 0 || until_len >= sizeof(until_buf))
    return;

  memcpy(until_buf, until_start, until_len);
  until_buf[until_len] = '\0';

  val = strtoull(until_buf, &endp, 10);
  if (endp == until_buf)
    return;

  e->ok = 1;
  e->neg = (until_buf[0] == '-');
  e->until = (long long)val;
  e->target = p;
  e->target_len = (size_t)(colon - p);
}

static int mute_eq_bytes(const char *a, size_t alen, const char *b, size_t blen)
{
  return alen == blen && memcmp(a, b, alen) == 0;
}

int webpush_mute_check_cmp(const char *value, const char *target, time_t now,
                           webpush_mute_eq eq)
{
  struct mute_entry e;
  const char *p;
  size_t target_len;

  if (!value || !*value || !target)
    return 0;
  if (!eq)
    eq = mute_eq_bytes;

  target_len = strlen(target);

  for (p = value; *p;)
  {
    next_mute_entry(&p, &e);

    if (!e.ok)
      continue;

    if ((e.target_len == 1 && e.target[0] == '*') ||
        eq(e.target, e.target_len, target, target_len))
    {
      /* 0 or negative = indefinite (same reading as the prune) */
      if (e.neg || e.until == 0 || e.until > (long long)now)
        return 1;
    }
  }

  return 0;
}

int webpush_mute_check(const char *value, const char *target, time_t now)
{
  return webpush_mute_check_cmp(value, target, now, mute_eq_bytes);
}

/** Remove expired (and, when `drop_target` is given, that target's) entries.
 * Writes the pruned list into `out` (NUL-terminated) and returns 1 when the
 * value changed. */
int webpush_mute_prune_cmp(const char *value, const char *drop_target, time_t now,
                           char *out, size_t outlen, webpush_mute_eq eq)
{
  struct mute_entry e;
  const char *p;
  size_t pos = 0;
  int changed = 0;

  if (!out || outlen == 0)
    return -1;
  if (!eq)
    eq = mute_eq_bytes;

  out[0] = '\0';

  if (!value || !*value)
    return 0;

  for (p = value; *p;)
  {
    int keep;

    next_mute_entry(&p, &e);

    if (!e.ok)
      continue;

    /* An explicit '-' or 0 until = indefinite: keep. */
    keep = (e.neg || e.until == 0 || e.until > (long long)now);

    if (drop_target && eq(e.target, e.target_len, drop_target, strlen(drop_target)))
      keep = 0;

    if (!keep)
    {
      changed = 1;
      continue;
    }

    /* The result must fit whole: a truncated list silently drops mutes. */
    if (pos + (pos > 0) + e.entry_len + 1 > outlen)
    {
      out[0] = '\0';
      return -1;
    }
    if (pos > 0)
      out[pos++] = ';';
    memcpy(out + pos, e.entry, e.entry_len);
    pos += e.entry_len;
    out[pos] = '\0';
  }

  return changed;
}

int webpush_mute_prune(const char *value, const char *drop_target, time_t now,
                       char *out, size_t outlen)
{
  return webpush_mute_prune_cmp(value, drop_target, now, out, outlen, mute_eq_bytes);
}
