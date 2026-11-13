/*
 * IRC - Internet Relay Chat, ircd/metadata_lww.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * See include/metadata_lww.h.  Keep this file free of ircd headers: it
 * is compiled standalone for the cmocka suite.  No allocation; no
 * <stdio.h>/<stdlib.h> -- every integer is parsed and formatted by hand
 * so the only headers pulled in are <string.h> (for the handful of
 * byte-level helpers below) plus the <stdint.h>/<stddef.h> the header
 * already brings in.
 */
#include "metadata_lww.h"

#include <string.h>

/* ------------------------------------------------------------------ */
/* Small internal helpers                                              */
/* ------------------------------------------------------------------ */

/** Parse exactly @a len decimal digit bytes at @a s into @a out,
 * rejecting a zero-length field, a non-digit byte anywhere, or a value
 * that would exceed @a max. @a len is capped at 20 internally (enough
 * for any uint64_t) purely to bound the loop.
 *
 * The overflow check happens BEFORE each multiply-add
 * (`v > (max - d) / 10`), not after (`v > max`): when @a max is itself
 * UINT64_MAX (as the ms field below uses), a post-hoc `v > max` check
 * can never fire no matter how far @a v has wrapped, since nothing is
 * ever greater than the type's own maximum. Checking first means every
 * field -- including one with the full 64-bit range -- correctly
 * rejects a value that would overflow rather than silently wrapping.
 */
static int md_parse_uint_field(const char *s, size_t len, uint64_t max,
                                uint64_t *out)
{
  uint64_t v = 0;
  size_t i;

  if (len == 0 || len > 20)
    return -1;

  for (i = 0; i < len; i++) {
    unsigned char c = (unsigned char)s[i];
    uint64_t d;

    if (c < '0' || c > '9')
      return -1;
    d = (uint64_t)(c - '0');
    if (v > (max - d) / 10)
      return -1;
    v = v * 10 + d;
  }

  *out = v;
  return 0;
}

/** Format @a v as decimal digits into @a buf, with no NUL terminator.
 * @a buf must have room for at least 20 bytes.
 * @return the number of digits written (always >= 1).
 */
static size_t md_format_uint(char *buf, uint64_t v)
{
  char tmp[20];
  size_t n = 0, i;

  if (v == 0) {
    buf[0] = '0';
    return 1;
  }

  while (v > 0) {
    tmp[n++] = (char)('0' + (int)(v % 10));
    v /= 10;
  }
  for (i = 0; i < n; i++)
    buf[i] = tmp[n - 1 - i];

  return n;
}

/** Bounded, always-NUL-terminated copy, truncating if necessary -- this
 * file may not include ircd_string.h for ircd_strncpy. NULL @a src is
 * treated as empty. */
static void md_bounded_copy(char *dest, size_t destsize, const char *src)
{
  size_t i;

  if (!src)
    src = "";
  for (i = 0; i + 1 < destsize && src[i]; i++)
    dest[i] = src[i];
  dest[i] = '\0';
}

/* ------------------------------------------------------------------ */
/* Stamps                                                               */
/* ------------------------------------------------------------------ */

int md_stamp_parse(const char *text, struct md_stamp *out)
{
  const char *dot1, *dot2;
  uint64_t ms, logical, node;

  if (!text || !out)
    return -1;
  /* A text that does not fit MD_STAMP_BUFSIZE (only a 20-digit ms with
   * long 16-bit fields gets there) could not be formatted back, kept as
   * a chunk identity or clock-encoded: refuse it here, once. */
  if (strlen(text) >= MD_STAMP_BUFSIZE)
    return -1;

  dot1 = strchr(text, '.');
  if (!dot1)
    return -1;
  dot2 = strchr(dot1 + 1, '.');
  if (!dot2)
    return -1;
  if (strchr(dot2 + 1, '.'))
    return -1; /* more than two dots */

  if (0 != md_parse_uint_field(text, (size_t)(dot1 - text),
                                (uint64_t)~(uint64_t)0, &ms))
    return -1;
  if (0 != md_parse_uint_field(dot1 + 1, (size_t)(dot2 - dot1 - 1),
                                65535, &logical))
    return -1;
  if (0 != md_parse_uint_field(dot2 + 1, strlen(dot2 + 1), 65535, &node))
    return -1;

  out->ms = ms;
  out->logical = (uint16_t)logical;
  out->node = (uint16_t)node;
  return 0;
}

int md_stamp_format(char *buf, size_t len, const struct md_stamp *s)
{
  char tmp[48];
  size_t pos = 0;

  if (!buf || !s || len == 0)
    return -1;

  pos += md_format_uint(tmp + pos, s->ms);
  tmp[pos++] = '.';
  pos += md_format_uint(tmp + pos, (uint64_t)s->logical);
  tmp[pos++] = '.';
  pos += md_format_uint(tmp + pos, (uint64_t)s->node);

  if (pos + 1 > len)
    return -1;

  memcpy(buf, tmp, pos);
  buf[pos] = '\0';
  return (int)pos;
}

int md_stamp_cmp(const struct md_stamp *a, const struct md_stamp *b)
{
  if (a->ms != b->ms)
    return a->ms < b->ms ? -1 : 1;
  if (a->logical != b->logical)
    return a->logical < b->logical ? -1 : 1;
  if (a->node != b->node)
    return a->node < b->node ? -1 : 1;
  return 0;
}

int md_stamp_ahead(const struct md_stamp *s, uint64_t now_ms,
                    uint64_t max_forward_ms)
{
  uint64_t diff;

  if (!s || s->ms <= now_ms)
    return 0;

  diff = s->ms - now_ms;
  return diff > max_forward_ms ? 1 : 0;
}

/* ------------------------------------------------------------------ */
/* LWW rule                                                             */
/* ------------------------------------------------------------------ */

int md_version_same_content(const struct md_version *a,
                            const struct md_version *b)
{
  if (!a || !b)
    return 0;
  if (a->tombstone || b->tombstone)
    return a->tombstone && b->tombstone;
  return a->vis == b->vis && a->vlen == b->vlen
         && (a->vlen == 0 || memcmp(a->value, b->value, a->vlen) == 0);
}

int md_lww_take(const struct md_version *local,
                 const struct md_version *incoming)
{
  int cmp;

  if (!local)
    return 1;
  if (!incoming)
    return 0;

  cmp = md_stamp_cmp(&incoming->st, &local->st);
  if (cmp > 0)
    return 1;
  if (cmp < 0)
    return 0;

  /* Equal stamps. */
  if (local->tombstone && incoming->tombstone)
    return 0; /* two tombstones: keep what's there */
  if (local->tombstone != incoming->tombstone)
    return incoming->tombstone ? 0 : 1; /* the live row always wins */

  /* Both live: the larger value wins (memcmp over the shorter length,
   * then the longer value wins a common-prefix tie). */
  {
    size_t minlen = local->vlen < incoming->vlen ? local->vlen : incoming->vlen;
    int c = minlen ? memcmp(incoming->value, local->value, minlen) : 0;

    if (c != 0)
      return c > 0 ? 1 : 0;
    if (incoming->vlen != local->vlen)
      return incoming->vlen > local->vlen ? 1 : 0;
    return 0; /* identical */
  }
}

/* ------------------------------------------------------------------ */
/* Clock wire token "L<stamp>"/"D<stamp>"                               */
/* ------------------------------------------------------------------ */

int md_clock_encode(char *buf, size_t len, const struct md_stamp *s,
                     int tombstone)
{
  char tmp[MD_STAMP_BUFSIZE + 1];
  int n;

  if (!buf || !s || len == 0)
    return -1;

  tmp[0] = tombstone ? 'D' : 'L';
  n = md_stamp_format(tmp + 1, sizeof(tmp) - 1, s);
  if (n < 0)
    return -1;
  n += 1;

  if ((size_t)n + 1 > len)
    return -1;

  memcpy(buf, tmp, (size_t)n);
  buf[n] = '\0';
  return n;
}

int md_clock_decode(const char *buf, size_t len, struct md_stamp *s,
                     int *tombstone)
{
  char tmp[MD_STAMP_BUFSIZE + 1];
  int t;

  if (!buf || !s || !tombstone || len < 2 || len > sizeof(tmp) - 1)
    return -1;

  if (buf[0] == 'L')
    t = 0;
  else if (buf[0] == 'D')
    t = 1;
  else
    return -1;

  memcpy(tmp, buf + 1, len - 1);
  tmp[len - 1] = '\0';

  if (0 != md_stamp_parse(tmp, s))
    return -1;

  *tombstone = t;
  return 0;
}

/* ------------------------------------------------------------------ */
/* Key validation                                                      */
/* ------------------------------------------------------------------ */

#define MD_PERSISTENCE_PREFIX "draft/persistence/"
#define MD_PERSISTENCE_PREFIX_LEN (sizeof(MD_PERSISTENCE_PREFIX) - 1)

/** Case-insensitive compare of @a key's first @a plen bytes against
 * @a prefix (which has no NUL inside those @a plen bytes). Caller must
 * already know @a key is at least @a plen bytes long. */
static int md_prefix_eq_ci(const char *key, const char *prefix, size_t plen)
{
  size_t i;

  for (i = 0; i < plen; i++) {
    unsigned char a = (unsigned char)key[i];
    unsigned char b = (unsigned char)prefix[i];

    if (a >= 'A' && a <= 'Z')
      a = (unsigned char)(a - 'A' + 'a');
    if (b >= 'A' && b <= 'Z')
      b = (unsigned char)(b - 'A' + 'a');
    if (a != b)
      return 0;
  }
  return 1;
}

int md_wire_key_valid(const char *key)
{
  size_t len, i;

  if (!key)
    return 0;

  len = strlen(key);
  if (len == 0)
    return 0;

  if (len >= MD_PERSISTENCE_PREFIX_LEN &&
      md_prefix_eq_ci(key, MD_PERSISTENCE_PREFIX, MD_PERSISTENCE_PREFIX_LEN)) {
    /* draft/persistence/... key: 1-127 bytes total, 0x21-0x7e, no
     * leading ':'. The no-leading-':' rule is satisfied by
     * construction here, not by an explicit check: reaching this
     * branch already required key[0] to case-insensitively match the
     * prefix's 'd'/'D', so key[0] can never be ':'. (A key that
     * somehow began with ':' would never have matched
     * md_prefix_eq_ci() above and would instead fall through to the
     * ordinary-key rule below, where ':' is not in the allowed
     * character set either.) */
    if (len > 127)
      return 0;
    for (i = 0; i < len; i++) {
      unsigned char c = (unsigned char)key[i];

      if (c < 0x21 || c > 0x7e)
        return 0;
    }
    return 1;
  }

  /* Ordinary key, per m_metadata.c's is_valid_key(): 1-63 bytes,
   * [A-Za-z0-9_./-], no leading digit. */
  if (len > 63)
    return 0;
  if (key[0] >= '0' && key[0] <= '9')
    return 0;
  for (i = 0; i < len; i++) {
    char c = key[i];
    int ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
             (c >= '0' && c <= '9') || c == '_' || c == '.' ||
             c == '/' || c == '-';

    if (!ok)
      return 0;
  }
  return 1;
}

/* ------------------------------------------------------------------ */
/* Target classification                                               */
/* ------------------------------------------------------------------ */

enum md_target_kind md_target_classify(const char *parv1)
{
  size_t len;

  if (!parv1)
    return MD_T_INVALID;

  len = strlen(parv1);
  if (len == 0)
    return MD_T_INVALID;

  if (parv1[0] == '#' || parv1[0] == '&')
    return MD_T_CHANNEL;

  if (parv1[0] == '*')
    return len == 1 ? MD_T_INVALID : MD_T_ACCOUNT;
  if (parv1[0] == '=')
    return len == 1 ? MD_T_INVALID : MD_T_ACCOUNT_STAMPED;
  if (parv1[0] == '!')
    return len == 1 ? MD_T_INVALID : MD_T_SESSION;
  if (parv1[0] == '?')
    return len == 1 ? MD_T_PULL : MD_T_INVALID;
  if (parv1[0] == '.')
    return len == 1 ? MD_T_PULL_END : MD_T_INVALID;

  return MD_T_NICK;
}

/* ------------------------------------------------------------------ */
/* Flags token                                                         */
/* ------------------------------------------------------------------ */

int md_flags_parse(const char *tok, int *vis, int *tombstone, int *more)
{
  size_t len;

  if (!tok || !vis || !tombstone || !more)
    return -1;

  len = strlen(tok);
  if (len < 1 || len > 2)
    return -1;
  if (len == 2 && tok[1] != '+')
    return -1;

  switch (tok[0]) {
  case '*':
    *vis = 0;
    *tombstone = 0;
    *more = (len == 2) ? 1 : 0;
    return 0;

  case 'P':
    *vis = 1;
    *tombstone = 0;
    *more = (len == 2) ? 1 : 0;
    return 0;

  case 'D':
    if (len == 2) /* "D+": a tombstone carries no value to chunk */
      return -1;
    *vis = 0;
    *tombstone = 1;
    *more = 0;
    return 0;

  default:
    return -1;
  }
}

/* ------------------------------------------------------------------ */
/* Chunk reassembly                                                     */
/* ------------------------------------------------------------------ */

/** Whether @a s (NULL taken as "") fits a buffer of @a size bytes with
 * its NUL. */
static int md_fits(const char *s, size_t size)
{
  return strlen(s ? s : "") < size;
}

/** Whether (@a account, @a stamp, @a key) names the same row as the
 * identity fields @a a / @a s / @a k (vis is not part of a row's
 * identity: see md_chunk_feed). */
static int md_row_eq(const char *a, const char *s, const char *k,
                     const char *account, const char *stamp, const char *key)
{
  return 0 == strcmp(a, account ? account : "") &&
         0 == strcmp(s, stamp ? stamp : "") &&
         0 == strcmp(k, key ? key : "");
}

/** The poison slot naming row (@a account, @a stamp, @a key), or NULL. */
static struct md_chunk_poison *md_chunk_poison_find(struct md_chunk *c,
                                                    const char *account,
                                                    const char *stamp,
                                                    const char *key)
{
  int i;

  for (i = 0; i < MD_CHUNK_POISON_SLOTS; i++)
    if (c->poison[i].used &&
        md_row_eq(c->poison[i].account, c->poison[i].stamp, c->poison[i].key,
                  account, stamp, key))
      return &c->poison[i];
  return NULL;
}

/** Discard the rest of row (@a account, @a stamp, @a key): its later
 * pieces, up to and including its more=0 one, are swallowed.  Each row
 * takes its own slot (a free one, else the slots in turn), so poisoning
 * one row never forgets another's while a slot is free (N3(a)). */
static void md_chunk_poison(struct md_chunk *c, const char *account,
                            const char *stamp, const char *key)
{
  struct md_chunk_poison *p = md_chunk_poison_find(c, account, stamp, key);
  int i;

  if (!p) {
    for (i = 0; i < MD_CHUNK_POISON_SLOTS; i++)
      if (!c->poison[i].used) {
        p = &c->poison[i];
        break;
      }
  }
  if (!p) {
    if (c->poison_next < 0 || c->poison_next >= MD_CHUNK_POISON_SLOTS)
      c->poison_next = 0;
    p = &c->poison[c->poison_next];
    c->poison_next = (c->poison_next + 1) % MD_CHUNK_POISON_SLOTS;
  }
  md_bounded_copy(p->account, sizeof(p->account), account);
  md_bounded_copy(p->stamp, sizeof(p->stamp), stamp);
  md_bounded_copy(p->key, sizeof(p->key), key);
  p->used = 1;
}

/** Forget the pending value, if any. */
static void md_chunk_reset(struct md_chunk *c)
{
  c->active = 0;
  c->len = 0;
  c->value[0] = '\0';
}

int md_chunk_feed(struct md_chunk *c, const char *account, const char *stamp,
                   const char *key, int vis, int more, const char *piece)
{
  size_t plen;

  if (!c || !piece)
    return MD_CHUNK_ERROR;

  c->dropped = 0;

  /* Never truncate an identity field: a cut name could match another
   * row's (final review M2).  Refused before anything changes. */
  if (!md_fits(account, sizeof(c->account)) ||
      !md_fits(stamp, sizeof(c->stamp)) ||
      !md_fits(key, sizeof(c->key)))
    return MD_CHUNK_ERROR;

  /* The rest of a row already given up on (final review M1): swallow
   * it, so no tail of it is ever handed back as the whole value. */
  {
    struct md_chunk_poison *p = md_chunk_poison_find(c, account, stamp, key);

    if (p) {
      if (!more)
        p->used = 0;
      return MD_CHUNK_ERROR;
    }
  }

  if (c->active) {
    if (md_row_eq(c->account, c->stamp, c->key, account, stamp, key)) {
      if (c->vis != vis) {
        /* The same row arriving inconsistent: none of it is trusted. */
        md_chunk_reset(c);
        if (more)
          md_chunk_poison(c, account, stamp, key);
        return MD_CHUNK_ERROR;
      }
    } else {
      /* Another row's line interrupted this one: drop what we have and
       * the rest of it, then start the new row fresh. */
      md_chunk_poison(c, c->account, c->stamp, c->key);
      md_chunk_reset(c);
      c->dropped = 1;
    }
  }

  if (!c->active) {
    c->len = 0;
    md_bounded_copy(c->account, sizeof(c->account), account);
    md_bounded_copy(c->stamp, sizeof(c->stamp), stamp);
    md_bounded_copy(c->key, sizeof(c->key), key);
    c->vis = vis;
    c->active = 1;
  }

  plen = strlen(piece);
  if (c->len + plen >= sizeof(c->value)) {
    md_chunk_reset(c);
    if (more)
      md_chunk_poison(c, account, stamp, key);
    return MD_CHUNK_ERROR;
  }

  memcpy(c->value + c->len, piece, plen);
  c->len += plen;
  c->value[c->len] = '\0';

  if (more)
    return MD_CHUNK_PENDING;

  c->active = 0;
  return MD_CHUNK_DONE;
}

void md_chunk_abandon(struct md_chunk *c, const char *account,
                      const char *stamp, const char *key, int more)
{
  if (!c)
    return;
  if (!md_fits(account, sizeof(c->account)) ||
      !md_fits(stamp, sizeof(c->stamp)) ||
      !md_fits(key, sizeof(c->key)))
    return;
  if (c->active && md_row_eq(c->account, c->stamp, c->key, account, stamp, key))
    md_chunk_reset(c);
  /* Only when pieces follow: a refused last (or only) piece leaves
   * nothing to discard, and a poison would swallow the row's next
   * delivery instead (N3(b)). */
  if (more)
    md_chunk_poison(c, account, stamp, key);
}

/* ------------------------------------------------------------------ */
/* PULL parameter parsing                                              */
/* ------------------------------------------------------------------ */

int md_pull_parse(int parc, char *parv[], unsigned long *seq, char *scope,
                   char *accounts[], int max)
{
  const char *seqtext;
  size_t seqlen;
  uint64_t useq;
  char *p, *start;
  int count = 0;

  if (!parv || parc < 5 || !seq || !scope || !accounts)
    return -1;

  /* parv[2]: decimal sequence number, the whole field. Reuses the same
   * overflow-guarded field parser the stamp fields use, rather than a
   * second hand-rolled (and unguarded) accumulation loop. */
  seqtext = parv[2];
  if (!seqtext)
    return -1;
  seqlen = strlen(seqtext);
  if (0 != md_parse_uint_field(seqtext, seqlen, (uint64_t)~(uint64_t)0,
                                &useq))
    return -1;

  /* parv[3]: scope, exactly "A" or "R". Check for an empty token
   * (parv[3][0] == '\0') BEFORE ever indexing [1] -- a 1-byte buffer
   * holding just the NUL is a realistic malformed/partial PULL
   * request, and indexing [1] first (as the old form of this check
   * did, via short-circuit ordering that read [1] before confirming
   * [0] wasn't already the terminator) is a one-byte out-of-bounds
   * read on exactly that input. */
  if (!parv[3] || parv[3][0] == '\0')
    return -1;
  if ((parv[3][0] != 'A' && parv[3][0] != 'R') || parv[3][1] != '\0')
    return -1;

  /* parv[4]: 1-16 non-empty names of <= 15 bytes, comma-separated,
   * split in place. */
  if (!parv[4])
    return -1;

  start = parv[4];
  for (p = start;; p++) {
    if (*p == ',' || *p == '\0') {
      size_t namelen = (size_t)(p - start);
      int end = (*p == '\0');

      if (namelen == 0 || namelen > 15)
        return -1;
      if (count >= 16 || count >= max)
        return -1;

      *p = '\0';
      accounts[count++] = start;

      if (end)
        break;
      start = p + 1;
    }
  }

  *seq = (unsigned long)useq;
  *scope = parv[3][0];
  return count;
}

/* ------------------------------------------------------------------ */
/* Bounded top-N-by-stamp selection (fix round 1)                      */
/* ------------------------------------------------------------------ */

int md_topn_place(const struct md_stamp *kept, int count, int cap,
                  const struct md_stamp *incoming)
{
  int i;

  if (!kept || !incoming || cap <= 0 || count < 0 || count > cap)
    return -1;

  if (count < cap) {
    /* Room to spare: find incoming's place among the ascending kept
     * stamps (linear scan from the newest end -- cap is small, at
     * most a couple hundred, so this is not performance-sensitive). */
    i = count;
    while (i > 0 && md_stamp_cmp(&kept[i - 1], incoming) > 0)
      i--;
    return i;
  }

  /* Full: discard unless incoming is strictly newer than the current
   * minimum (kept[0]) -- a tie is not an improvement, so it is
   * discarded too, same as every other non-improving candidate. */
  if (md_stamp_cmp(incoming, &kept[0]) <= 0)
    return -1;

  i = 0;
  while (i + 1 < cap && md_stamp_cmp(&kept[i + 1], incoming) < 0)
    i++;
  return i;
}

int md_topn_insert(struct md_stamp *kept, int *slot, int *count,
                   int cap, const struct md_stamp *incoming)
{
  int idx, ps, i;

  if (!kept || !slot || !count || !incoming || cap <= 0
      || *count < 0 || *count > cap)
    return -1;

  idx = md_topn_place(kept, *count, cap, incoming);
  if (idx < 0)
    return -1;

  if (*count < cap) {
    /* The slots in use are 0..count-1: the next one is free. */
    ps = *count;
    for (i = *count; i > idx; i--) {
      kept[i] = kept[i - 1];
      slot[i] = slot[i - 1];
    }
    (*count)++;
  } else {
    /* The oldest row goes; its pool slot takes the new one. */
    ps = slot[0];
    for (i = 0; i < idx; i++) {
      kept[i] = kept[i + 1];
      slot[i] = slot[i + 1];
    }
  }
  kept[idx] = *incoming;
  slot[idx] = ps;
  return ps;
}

/* ------------------------------------------------------------------ */
/* Replicated keys (push-2 final fix wave, M-2)                        */
/* ------------------------------------------------------------------ */

#define MD_KEY_LAST_PRESENT "last_present"

int md_key_replicable(const char *key)
{
  if (!md_wire_key_valid(key))
    return 0;
  if (strlen(key) == sizeof(MD_KEY_LAST_PRESENT) - 1
      && md_prefix_eq_ci(key, MD_KEY_LAST_PRESENT,
                         sizeof(MD_KEY_LAST_PRESENT) - 1))
    return 0;
  return 1;
}
