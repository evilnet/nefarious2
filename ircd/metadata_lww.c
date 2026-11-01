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
 * for any uint64_t) purely to bound the loop; the @a max check does the
 * real rejection work field-by-field as each digit is folded in. */
static int md_parse_uint_field(const char *s, size_t len, uint64_t max,
                                uint64_t *out)
{
  uint64_t v = 0;
  size_t i;

  if (len == 0 || len > 20)
    return -1;

  for (i = 0; i < len; i++) {
    unsigned char c = (unsigned char)s[i];

    if (c < '0' || c > '9')
      return -1;
    v = v * 10 + (uint64_t)(c - '0');
    if (v > max)
      return -1;
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
     * leading ':'. */
    if (len > 127)
      return 0;
    if (key[0] == ':')
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

/** Whether @a c's pending accumulation (if any) was filed under the
 * same (account, stamp, key, vis) as this feed call. */
static int md_chunk_identity_matches(const struct md_chunk *c,
                                      const char *account, const char *stamp,
                                      const char *key, int vis)
{
  return c->vis == vis &&
         0 == strcmp(c->account, account ? account : "") &&
         0 == strcmp(c->stamp, stamp ? stamp : "") &&
         0 == strcmp(c->key, key ? key : "");
}

int md_chunk_feed(struct md_chunk *c, const char *account, const char *stamp,
                   const char *key, int vis, int more, const char *piece)
{
  size_t plen;

  if (!c || !piece)
    return MD_CHUNK_ERROR;

  c->dropped = 0;

  if (c->active && !md_chunk_identity_matches(c, account, stamp, key, vis)) {
    c->active = 0;
    c->len = 0;
    c->dropped = 1;
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
    c->active = 0;
    c->len = 0;
    c->value[0] = '\0';
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

/* ------------------------------------------------------------------ */
/* PULL parameter parsing                                              */
/* ------------------------------------------------------------------ */

int md_pull_parse(int parc, char *parv[], unsigned long *seq, char *scope,
                   char *accounts[], int max)
{
  const char *seqtext;
  size_t seqlen, i;
  unsigned long s;
  char *p, *start;
  int count = 0;

  if (!parv || parc < 5 || !seq || !scope || !accounts)
    return -1;

  /* parv[2]: decimal sequence number, the whole field. */
  seqtext = parv[2];
  if (!seqtext)
    return -1;
  seqlen = strlen(seqtext);
  if (seqlen == 0 || seqlen > 20)
    return -1;

  s = 0;
  for (i = 0; i < seqlen; i++) {
    if (seqtext[i] < '0' || seqtext[i] > '9')
      return -1;
    s = s * 10 + (unsigned long)(seqtext[i] - '0');
  }

  /* parv[3]: scope, exactly "A" or "R". */
  if (!parv[3] || parv[3][1] != '\0' ||
      (parv[3][0] != 'A' && parv[3][0] != 'R'))
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

  *seq = s;
  *scope = parv[3][0];
  return count;
}
