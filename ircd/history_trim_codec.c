/* ircd/history_trim_codec.c
 * Chathistory trimming -- the pure codec: message/by_time/by_owner key
 * encoding, the by_time record, the owner-key classifier and the
 * stored row-size formula.  See include/history_trim_codec.h.
 *
 * Deliberately pure: libc, res.h (struct irc_in_addr and its macros)
 * and db_casefold.h (name folding) only -- no other IRCd headers, no
 * database, plain malloc/free (none of these builders need it).  This
 * is what lets the CMocka suite gate every byte layout without a
 * running ircd.
 */
#include "history_trim_codec.h"
#include "db_casefold.h"
#include "res.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/** Record wire-format version byte (htc_rec_pack/htc_rec_parse). */
#define HTC_REC_VERSION 1

uint64_t htc_parse_ms(const char *ts)
{
  char *end = NULL;
  unsigned long long sec;
  unsigned long ms = 0;

  if (!ts || !*ts)
    return 0;
  sec = strtoull(ts, &end, 10);
  if (end == ts)
    return 0;
  if (end && *end == '.') {
    /* Up to three fractional digits; anything beyond is ignored. */
    int digits = 0;
    const char *p = end + 1;
    while (*p >= '0' && *p <= '9' && digits < 3) {
      ms = ms * 10 + (unsigned long)(*p - '0');
      p++;
      digits++;
    }
    while (digits < 3) {
      ms *= 10;
      digits++;
    }
  }
  return sec * 1000ULL + ms;
}

int htc_owner_key(char *buf, size_t size, const char *account,
                   const struct irc_in_addr *ip, const char *server)
{
  size_t len;

  if (!buf)
    return -1;

  if (account && account[0] && strcmp(account, "*") != 0) {
    len = strlen(account);
    if (2 + len + 1 > size)
      return -1;
    buf[0] = 'a';
    buf[1] = ':';
    db_casefold_bytes(buf + 2, account, len);
    buf[2 + len] = '\0';
    return (int)(2 + len);
  }

  if (ip && irc_in_addr_valid(ip) && !irc_in_addr_unspec(ip)) {
    int n;

    if (irc_in_addr_is_ipv4(ip)) {
      unsigned int v4 = ((unsigned int)ntohs(ip->in6_16[6]) << 16)
                       | (unsigned int)ntohs(ip->in6_16[7]);
      n = snprintf(buf, size, "i:%08x", v4);
    } else {
      n = snprintf(buf, size, "i:%04x%04x%04x%04x",
                   ntohs(ip->in6_16[0]), ntohs(ip->in6_16[1]),
                   ntohs(ip->in6_16[2]), ntohs(ip->in6_16[3]));
    }
    if (n < 0 || (size_t)n >= size)
      return -1;
    return n;
  }

  if (server && server[0]) {
    len = strlen(server);
    if (2 + len + 1 > size)
      return -1;
    buf[0] = 's';
    buf[1] = ':';
    db_casefold_bytes(buf + 2, server, len);
    buf[2 + len] = '\0';
    return (int)(2 + len);
  }

  len = strlen(HTC_OWNER_NONE);
  if (len + 1 > size)
    return -1;
  memcpy(buf, HTC_OWNER_NONE, len);
  buf[len] = '\0';
  return (int)len;
}

/* THE implementation of history.c's build_key: fold(target) \0 ts \0
 * msgid.  Mirrors its bound checks exactly (>= where a separator
 * still follows, > for the final unseparated field) so this is
 * byte-identical for every input, including at the overflow edge. */
int htc_key_cmp_bound(const void *key, size_t klen,
                      const void *bound, size_t blen)
{
  return memcmp(key, bound, klen < blen ? klen : blen);
}

int htc_msg_key(char *buf, size_t size, const char *target,
                 const char *ts, const char *msgid)
{
  size_t pos = 0;
  size_t len;

  if (!buf || !target)
    return -1;

  len = strlen(target);
  if (pos + len + 1 >= size)
    return -1;
  db_casefold_bytes(buf + pos, target, len);
  pos += len;
  buf[pos++] = '\0';

  if (ts) {
    len = strlen(ts);
    if (pos + len + 1 >= size)
      return -1;
    memcpy(buf + pos, ts, len);
    pos += len;
    buf[pos++] = '\0';

    if (msgid) {
      len = strlen(msgid);
      if (pos + len >= size)
        return -1;
      memcpy(buf + pos, msgid, len);
      pos += len;
    }
  }

  return (int)pos;
}

/* Mirrors history.c's parse_key, generalized to caller-supplied output
 * sizes instead of the fixed CHANNELLEN/HISTORY_TIMESTAMP_LEN/
 * HISTORY_MSGID_LEN constants. */
int htc_msg_key_parse(const void *key, size_t klen,
                       char *target, size_t tsz,
                       char *ts, size_t tssz,
                       char *msgid, size_t msz)
{
  const char *p, *end;
  const char *sep1, *sep2;

  if (!key)
    return -1;

  p = (const char *)key;
  end = p + klen;

  sep1 = memchr(p, '\0', (size_t)(end - p));
  if (!sep1)
    return -1;

  if (target) {
    size_t len = (size_t)(sep1 - p);
    if (len >= tsz)
      return -1;
    memcpy(target, p, len);
    target[len] = '\0';
  }
  p = sep1 + 1;

  sep2 = memchr(p, '\0', (size_t)(end - p));
  if (sep2) {
    if (ts) {
      size_t len = (size_t)(sep2 - p);
      if (len >= tssz)
        return -1;
      memcpy(ts, p, len);
      ts[len] = '\0';
    }
    p = sep2 + 1;

    if (msgid) {
      size_t len = (size_t)(end - p);
      if (len >= msz)
        return -1;
      memcpy(msgid, p, len);
      msgid[len] = '\0';
    }
  } else {
    if (ts) {
      size_t len = (size_t)(end - p);
      if (len >= tssz)
        return -1;
      memcpy(ts, p, len);
      ts[len] = '\0';
    }
    if (msgid)
      msgid[0] = '\0';
  }

  return 0;
}

/* Byte-identical to history.c's build_msgid_index_key: msgid \0
 * fold(target), no trailing separator. */
int htc_msgid_key(char *buf, size_t size, const char *msgid,
                   const char *target)
{
  size_t ml, tl;

  if (!buf || !msgid || !target)
    return -1;

  ml = strlen(msgid);
  tl = strlen(target);
  if (ml + 1 + tl > size)
    return -1;
  memcpy(buf, msgid, ml);
  buf[ml] = '\0';
  db_casefold_bytes(buf + ml + 1, target, tl);
  return (int)(ml + 1 + tl);
}

/* Byte-identical to history.c's build_reply_index_key: fold(target)
 * \0 parent \0 ts \0 msgid, no trailing separator. */
int htc_reply_child_key(char *buf, size_t size, const char *target,
                         const char *parent, const char *ts,
                         const char *msgid)
{
  size_t pos = 0;
  size_t tl, pl, tsl, ml;

  if (!buf || !target || !parent || !ts || !msgid)
    return -1;

  tl  = strlen(target);
  pl  = strlen(parent);
  tsl = strlen(ts);
  ml  = strlen(msgid);

  if (pos + tl + 1 > size)
    return -1;
  db_casefold_bytes(buf + pos, target, tl);
  pos += tl;
  buf[pos++] = '\0';

  if (pos + pl + 1 > size)
    return -1;
  memcpy(buf + pos, parent, pl);
  pos += pl;
  buf[pos++] = '\0';

  if (pos + tsl + 1 > size)
    return -1;
  memcpy(buf + pos, ts, tsl);
  pos += tsl;
  buf[pos++] = '\0';

  if (pos + ml > size)
    return -1;
  memcpy(buf + pos, msgid, ml);
  pos += ml;

  return (int)pos;
}

/* fold(target) \0 parent \0: the first two parts of
 * htc_reply_child_key, separators included. */
int htc_reply_prefix(char *buf, size_t size, const char *target,
                      const char *parent)
{
  size_t pos = 0;
  size_t tl, pl;

  if (!buf || !target || !parent)
    return -1;

  tl = strlen(target);
  pl = strlen(parent);

  if (pos + tl + 1 > size)
    return -1;
  db_casefold_bytes(buf + pos, target, tl);
  pos += tl;
  buf[pos++] = '\0';

  if (pos + pl + 1 > size)
    return -1;
  memcpy(buf + pos, parent, pl);
  pos += pl;
  buf[pos++] = '\0';

  return (int)pos;
}

void htc_be64(unsigned char out[8], uint64_t ms)
{
  int i;
  for (i = 7; i >= 0; i--) {
    out[i] = (unsigned char)(ms & 0xffU);
    ms >>= 8;
  }
}

/* by_time key: be64(ms) ‖ fold(target) ‖ \0 ‖ msgid (no trailing
 * separator; msgid NULL/"" stops after the \0). */
int htc_bt_key(char *buf, size_t size, uint64_t ms, const char *target,
                const char *msgid)
{
  size_t pos;
  size_t len;

  if (!buf || !target || size < 8)
    return -1;

  htc_be64((unsigned char *)buf, ms);
  pos = 8;

  len = strlen(target);
  if (pos + len + 1 > size)
    return -1;
  db_casefold_bytes(buf + pos, target, len);
  pos += len;
  buf[pos++] = '\0';

  if (msgid) {
    len = strlen(msgid);
    if (pos + len > size)
      return -1;
    memcpy(buf + pos, msgid, len);
    pos += len;
  }

  return (int)pos;
}

int htc_bt_key_parse(const void *key, size_t klen, uint64_t *ms,
                      char *target, size_t tsz, char *msgid, size_t msz)
{
  const unsigned char *k = (const unsigned char *)key;
  const char *tstart, *sep, *end;
  size_t tlen, mlen;
  uint64_t v = 0;
  int i;

  if (!k || klen < 8)
    return -1;

  for (i = 0; i < 8; i++)
    v = (v << 8) | k[i];
  if (ms)
    *ms = v;

  tstart = (const char *)k + 8;
  end = (const char *)k + klen;
  sep = memchr(tstart, '\0', (size_t)(end - tstart));
  if (!sep)
    return -1;

  tlen = (size_t)(sep - tstart);
  if (target) {
    if (tlen >= tsz)
      return -1;
    memcpy(target, tstart, tlen);
    target[tlen] = '\0';
  }

  mlen = (size_t)(end - (sep + 1));
  if (msgid) {
    if (mlen >= msz)
      return -1;
    memcpy(msgid, sep + 1, mlen);
    msgid[mlen] = '\0';
  }

  return 0;
}

int htc_bo_key(char *buf, size_t size, const char *owner,
                const void *bt_key, size_t bt_klen)
{
  size_t olen;

  if (!buf || !owner || !bt_key)
    return -1;

  olen = strlen(owner);
  if (olen + 1 + bt_klen > size)
    return -1;

  memcpy(buf, owner, olen);
  buf[olen] = '\0';
  memcpy(buf + olen + 1, bt_key, bt_klen);
  return (int)(olen + 1 + bt_klen);
}

int htc_bo_prefix(char *buf, size_t size, const char *owner)
{
  size_t olen;

  if (!buf || !owner)
    return -1;

  olen = strlen(owner);
  if (olen + 1 > size)
    return -1;

  memcpy(buf, owner, olen);
  buf[olen] = '\0';
  return (int)(olen + 1);
}

int htc_bo_split(const void *key, size_t klen, char *owner, size_t osz,
                  const void **bt_key, size_t *bt_klen)
{
  const char *k = (const char *)key;
  const char *sep;
  size_t olen;

  if (!k)
    return -1;

  sep = memchr(k, '\0', klen);
  if (!sep)
    return -1;

  olen = (size_t)(sep - k);
  if (owner) {
    if (olen >= osz)
      return -1;
    memcpy(owner, k, olen);
    owner[olen] = '\0';
  }

  if (bt_key)
    *bt_key = sep + 1;
  if (bt_klen)
    *bt_klen = (size_t)(k + klen - (sep + 1));

  return 0;
}

int htc_rec_pack(char *buf, size_t size, const struct htc_rec *r)
{
  size_t pos;
  size_t len;

  if (!buf || !r || size < 6)
    return -1;

  buf[0] = (char)(unsigned char)HTC_REC_VERSION;
  buf[1] = (char)r->flags;
  htc_size_pack((unsigned char *)buf + 2, r->bytes);
  pos = 6;

  len = strlen(r->ts);
  if (pos + len + 1 > size)
    return -1;
  memcpy(buf + pos, r->ts, len);
  pos += len;
  buf[pos++] = '\0';

  len = strlen(r->owner);
  if (pos + len + 1 > size)
    return -1;
  memcpy(buf + pos, r->owner, len);
  pos += len;
  buf[pos++] = '\0';

  len = strlen(r->reply_parent);
  if (pos + len + 1 > size)
    return -1;
  memcpy(buf + pos, r->reply_parent, len);
  pos += len;
  buf[pos++] = '\0';

  len = strlen(r->redact_parent);
  if (pos + len > size)
    return -1;
  memcpy(buf + pos, r->redact_parent, len);
  pos += len;

  return (int)pos;
}

int htc_rec_parse(const void *v, size_t vlen, struct htc_rec *out)
{
  const unsigned char *p = (const unsigned char *)v;
  const char *body, *end;
  const char *sep1, *sep2, *sep3;
  size_t len;

  if (!p || !out || vlen < 6)
    return -1;
  if (p[0] != HTC_REC_VERSION)
    return -1;

  out->flags = p[1];
  if (htc_size_parse(p + 2, 4, &out->bytes) != 0)
    return -1;

  body = (const char *)v + 6;
  end = (const char *)v + vlen;

  sep1 = memchr(body, '\0', (size_t)(end - body));
  if (!sep1)
    return -1;
  len = (size_t)(sep1 - body);
  if (len >= sizeof(out->ts))
    return -1;
  memcpy(out->ts, body, len);
  out->ts[len] = '\0';

  sep2 = memchr(sep1 + 1, '\0', (size_t)(end - (sep1 + 1)));
  if (!sep2)
    return -1;
  len = (size_t)(sep2 - (sep1 + 1));
  if (len >= sizeof(out->owner))
    return -1;
  memcpy(out->owner, sep1 + 1, len);
  out->owner[len] = '\0';

  sep3 = memchr(sep2 + 1, '\0', (size_t)(end - (sep2 + 1)));
  if (!sep3)
    return -1;
  len = (size_t)(sep3 - (sep2 + 1));
  if (len >= sizeof(out->reply_parent))
    return -1;
  memcpy(out->reply_parent, sep2 + 1, len);
  out->reply_parent[len] = '\0';

  len = (size_t)(end - (sep3 + 1));
  if (len >= sizeof(out->redact_parent))
    return -1;
  memcpy(out->redact_parent, sep3 + 1, len);
  out->redact_parent[len] = '\0';

  return 0;
}

void htc_size_pack(unsigned char out[4], uint32_t bytes)
{
  out[0] = (unsigned char)((bytes >> 24) & 0xffU);
  out[1] = (unsigned char)((bytes >> 16) & 0xffU);
  out[2] = (unsigned char)((bytes >> 8) & 0xffU);
  out[3] = (unsigned char)(bytes & 0xffU);
}

int htc_size_parse(const void *v, size_t vlen, uint32_t *bytes)
{
  const unsigned char *p = (const unsigned char *)v;

  if (!p || vlen != 4)
    return -1;
  if (bytes)
    *bytes = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
            | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
  return 0;
}

/* Overflow-safe add: saturates at UINT64_MAX instead of wrapping. */
static uint64_t htc_sat_add_u64(uint64_t a, uint64_t b)
{
  uint64_t r = a + b;
  return (r < a) ? UINT64_MAX : r;
}

uint32_t htc_row_bytes(size_t msg_klen, size_t msg_vlen, size_t ml_vlen,
                        size_t bt_klen, size_t owner_len)
{
  uint64_t bt2 = htc_sat_add_u64((uint64_t)bt_klen, (uint64_t)bt_klen);
  uint64_t sum = (uint64_t)msg_klen;

  sum = htc_sat_add_u64(sum, (uint64_t)msg_vlen);
  sum = htc_sat_add_u64(sum, (uint64_t)ml_vlen);
  sum = htc_sat_add_u64(sum, bt2);
  sum = htc_sat_add_u64(sum, (uint64_t)owner_len);
  sum = htc_sat_add_u64(sum, 1);
  sum = htc_sat_add_u64(sum, (uint64_t)HTC_ROW_FIXED);

  return (sum > (uint64_t)UINT32_MAX) ? UINT32_MAX : (uint32_t)sum;
}

/* ---------------------------------------------------------------------
 * Owner accounting table.
 *
 * A chained hash on the owner string. Growth doubles the bucket array
 * and rehashes every entry in place whenever an insert would push the
 * load factor past 1 (count == nbuckets); collisions within a bucket
 * are resolved by a linear scan of its chain (owner strings are short
 * and this table is never the hot path -- the trim engine touches it
 * once per stored/deleted row and once per planner pass).
 * ------------------------------------------------------------------- */

#define HTC_ACCT_INITIAL_BUCKETS 16

struct htc_acct_entry {
  struct htc_acct_entry *next;
  uint64_t                bytes;
  char                    owner[HTC_OWNER_MAX];
};

struct htc_acct {
  struct htc_acct_entry **buckets;
  size_t                   nbuckets;
  size_t                   count;
  uint64_t                 total;
};

/* FNV-1a over the owner string -- fast, good-enough distribution for
 * the short "a:"/"i:"/"s:"/"-" keys htc_owner_key produces. */
static uint64_t htc_hash_owner(const char *s)
{
  uint64_t h = 14695981039346656037ULL;
  while (*s) {
    h ^= (uint64_t)(unsigned char)*s++;
    h *= 1099511628211ULL;
  }
  return h;
}

/* Bounded owner copy: truncates rather than overruns a HTC_OWNER_MAX
 * destination. Owner strings here are always built by htc_owner_key,
 * which already bounds them to HTC_OWNER_MAX -- this is a second line
 * of defense, not expected to ever actually truncate. */
static void htc_owner_copy(char *dst, const char *src)
{
  size_t n = strlen(src);
  if (n >= HTC_OWNER_MAX)
    n = HTC_OWNER_MAX - 1;
  memcpy(dst, src, n);
  dst[n] = '\0';
}

struct htc_acct *htc_acct_new(void)
{
  struct htc_acct *a = (struct htc_acct *)malloc(sizeof(*a));
  if (!a)
    return NULL;

  a->nbuckets = HTC_ACCT_INITIAL_BUCKETS;
  a->buckets = (struct htc_acct_entry **)calloc(a->nbuckets, sizeof(*a->buckets));
  if (!a->buckets) {
    free(a);
    return NULL;
  }
  a->count = 0;
  a->total = 0;
  return a;
}

void htc_acct_clear(struct htc_acct *a)
{
  size_t i;

  if (!a)
    return;

  for (i = 0; i < a->nbuckets; i++) {
    struct htc_acct_entry *e = a->buckets[i];
    while (e) {
      struct htc_acct_entry *next = e->next;
      free(e);
      e = next;
    }
    a->buckets[i] = NULL;
  }
  a->count = 0;
  a->total = 0;
}

void htc_acct_free(struct htc_acct *a)
{
  if (!a)
    return;
  htc_acct_clear(a);
  free(a->buckets);
  free(a);
}

/* Doubles the bucket array and rehashes every entry in place. A failed
 * allocation leaves the table exactly as it was -- over its target
 * load factor, but still correct -- so there is nothing to undo. */
static void htc_acct_grow(struct htc_acct *a)
{
  size_t newn = a->nbuckets * 2;
  struct htc_acct_entry **newb =
    (struct htc_acct_entry **)calloc(newn, sizeof(*newb));
  size_t i;

  if (!newb)
    return;

  for (i = 0; i < a->nbuckets; i++) {
    struct htc_acct_entry *e = a->buckets[i];
    while (e) {
      struct htc_acct_entry *next = e->next;
      size_t idx = (size_t)(htc_hash_owner(e->owner) % newn);
      e->next = newb[idx];
      newb[idx] = e;
      e = next;
    }
  }

  free(a->buckets);
  a->buckets = newb;
  a->nbuckets = newn;
}

void htc_acct_add(struct htc_acct *a, const char *owner, int64_t delta)
{
  size_t idx;
  struct htc_acct_entry *e, *prev;
  uint64_t old_bytes, new_bytes;

  if (!a || !owner)
    return;

  idx = (size_t)(htc_hash_owner(owner) % a->nbuckets);
  prev = NULL;
  for (e = a->buckets[idx]; e; e = e->next) {
    if (strcmp(e->owner, owner) == 0)
      break;
    prev = e;
  }

  if (!e) {
    /* No existing entry: a non-positive delta has nothing to clamp --
     * stay absent rather than materialize a 0-byte owner. */
    if (delta <= 0)
      return;

    if (a->count >= a->nbuckets) {
      htc_acct_grow(a);
      idx = (size_t)(htc_hash_owner(owner) % a->nbuckets);
    }

    e = (struct htc_acct_entry *)malloc(sizeof(*e));
    if (!e)
      return;
    htc_owner_copy(e->owner, owner);
    e->bytes = (uint64_t)delta;
    e->next = a->buckets[idx];
    a->buckets[idx] = e;
    a->count++;
    a->total += e->bytes;
    return;
  }

  old_bytes = e->bytes;
  if (delta >= 0) {
    new_bytes = old_bytes + (uint64_t)delta;
  } else {
    uint64_t dec = (uint64_t)(-delta);
    new_bytes = (dec >= old_bytes) ? 0 : old_bytes - dec;
  }

  a->total = a->total - old_bytes + new_bytes;

  if (new_bytes == 0) {
    if (prev)
      prev->next = e->next;
    else
      a->buckets[idx] = e->next;
    free(e);
    a->count--;
  } else {
    e->bytes = new_bytes;
  }
}

uint64_t htc_acct_owner(const struct htc_acct *a, const char *owner)
{
  size_t idx;
  const struct htc_acct_entry *e;

  if (!a || !owner)
    return 0;

  idx = (size_t)(htc_hash_owner(owner) % a->nbuckets);
  for (e = a->buckets[idx]; e; e = e->next) {
    if (strcmp(e->owner, owner) == 0)
      return e->bytes;
  }
  return 0;
}

uint64_t htc_acct_total(const struct htc_acct *a)
{
  return a ? a->total : 0;
}

size_t htc_acct_count(const struct htc_acct *a)
{
  return a ? a->count : 0;
}

/* Largest first, ties broken by owner ascending -- the comparator for
 * both htc_acct_top and the planner's over-share candidate list, which
 * reuses the same struct htc_owner_total/ordering. */
static int htc_owner_total_cmp(const void *pa, const void *pb)
{
  const struct htc_owner_total *oa = (const struct htc_owner_total *)pa;
  const struct htc_owner_total *ob = (const struct htc_owner_total *)pb;

  if (oa->bytes != ob->bytes)
    return (oa->bytes > ob->bytes) ? -1 : 1;
  return strcmp(oa->owner, ob->owner);
}

size_t htc_acct_top(const struct htc_acct *a, struct htc_owner_total *out,
                     size_t n)
{
  struct htc_owner_total *all;
  size_t i, b, copy;

  if (!a || !out || n == 0 || a->count == 0)
    return 0;

  all = (struct htc_owner_total *)malloc(sizeof(*all) * a->count);
  if (!all)
    return 0;

  i = 0;
  for (b = 0; b < a->nbuckets; b++) {
    const struct htc_acct_entry *e;
    for (e = a->buckets[b]; e; e = e->next) {
      htc_owner_copy(all[i].owner, e->owner);
      all[i].bytes = e->bytes;
      i++;
    }
  }

  qsort(all, i, sizeof(*all), htc_owner_total_cmp);

  copy = (n < i) ? n : i;
  memcpy(out, all, copy * sizeof(*out));
  free(all);
  return copy;
}

/* ---------------------------------------------------------------------
 * The fair-eviction planner. The order below IS the decision (Task 3
 * brief, as amended by the fix-round-1 controller ruling on FINDING 1
 * below) -- implemented exactly, not re-derived:
 *
 *   sanitize: high outside 1..100 -> 85; low outside 1..100 -> 75;
 *             then low>=high -> low = (high>10 ? high-10 : 0).
 *             (Fix round 1, FINDING 1: the brief's original rule --
 *             low>=high -> low = high-10, with no floor -- lets low go
 *             negative whenever high is sanitized-valid but <=10
 *             [e.g. an oper sets HIGH_WATERMARK to 1..9; feature_set's
 *             FEAT_INT path does strtoul with no min/max,
 *             ircd_features.c:1601-1617]. target = cap*(uint64_t)low/100
 *             then wraps to ~2^64 instead of landing near 0, silently
 *             defeating the cap. The ruling floors low at 0. After
 *             sanitizing, every threshold/target lies in [0, cap].)
 *   target = cap*low/100 (always set); total = htc_acct_total;
 *            cap==0 -> inactive
 *   active = draining ? total>target : total > cap*high/100;
 *            inactive -> nsteps 0, oldest 0
 *   if quota_on && 1<=share_pct<=99 (outside 1..99 keeps the share
 *   step off, same as quota_on false):
 *     share = cap*share_pct/100 (via htc_owner_share -- Amendment A)
 *     over = owners != "-" with bytes > share, sorted by bytes desc,
 *            owner asc
 *     steps = first HTC_PLAN_MAX_STEPS of over, trim = bytes - share;
 *     truncated = (|over| > HTC_PLAN_MAX_STEPS)
 *     (Fix round 1, FINDING 2: if the over-share candidate scratch
 *     array can't be allocated, truncated is also forced to 1 here --
 *     see the anti-goal note at the allocation site below.)
 *   oldest = (nsteps==0 && !truncated && total>target) ? total-target : 0
 * ------------------------------------------------------------------- */

int htc_share_active(const struct htc_plan_params *p)
{
  return p && p->quota_on && p->share_pct >= 1 && p->share_pct <= 99;
}

uint64_t htc_owner_share(const struct htc_plan_params *p, const char *owner)
{
  (void)owner; /* No per-owner override exists yet -- this is the one
                * hook a future exemption/override would change
                * (Task 3 brief, Amendment A). Every owner gets the
                * plan's flat share today. */
  if (!p)
    return 0;
  return ((uint64_t)p->cap * (uint64_t)(unsigned)p->share_pct) / 100ULL;
}

void htc_plan_sanitize(int *high_pct, int *low_pct)
{
  int high = *high_pct, low = *low_pct;

  if (high < 1 || high > 100)
    high = 85;
  /* The ruling's prose says "low outside 0..100 -> 75", but the
   * mandated kept case (high 0, low 0 -> target 750) only works if
   * low==0 takes this reset too (high alone sanitizes to 85, and
   * 0>=85 is false, so an unreset low==0 would leave target at 0, not
   * 750) -- i.e. the boundary is low<=0, matching the brief's original
   * "low<=0 -> 75" with an added upper bound. */
  if (low <= 0 || low > 100)
    low = 75;
  if (low >= high)
    low = (high > 10) ? high - 10 : 0;
  *high_pct = high;
  *low_pct = low;
}

void htc_plan_eviction(const struct htc_acct *a,
                        const struct htc_plan_params *p,
                        struct htc_plan *out)
{
  int high, low;
  uint64_t cap, target, total;

  if (!out)
    return;
  memset(out, 0, sizeof(*out));

  if (!a || !p)
    return;

  high = p->high_pct;
  low  = p->low_pct;
  htc_plan_sanitize(&high, &low);

  cap = p->cap;
  target = cap * (uint64_t)low / 100;
  out->target = target;

  total = htc_acct_total(a);

  if (cap == 0) {
    out->active = 0;
    return;
  }

  out->active = p->draining ? (total > target)
                             : (total > (cap * (uint64_t)high / 100));

  if (!out->active)
    return;

  if (htc_share_active(p)) {
    struct htc_owner_total *cand = NULL;
    size_t ncand = 0;

    out->share = htc_owner_share(p, HTC_OWNER_NONE);

    if (a->count > 0) {
      cand = (struct htc_owner_total *)malloc(sizeof(*cand) * a->count);
      if (!cand) {
        /* Anti-goal (fix round 1, FINDING 2): without this scratch
         * array we cannot tell which owners are over share, so we
         * must NOT fall through to the oldest-overall fallback below
         * -- that would evict compliant owners' rows while any
         * over-share owner's rows are left untouched (the same
         * anti-goal test_plan_truncated_blocks_oldest pins for a
         * list that's merely too long). Mark the plan truncated
         * (forcing oldest to 0 below) and leave nsteps at 0: the plan
         * does nothing this slice rather than evict the wrong rows,
         * and the next slice gets another chance. */
        out->truncated = 1;
      }
    }

    if (cand) {
      size_t b, i;

      for (b = 0; b < a->nbuckets; b++) {
        const struct htc_acct_entry *e;
        for (e = a->buckets[b]; e; e = e->next) {
          uint64_t share_i;

          if (strcmp(e->owner, HTC_OWNER_NONE) == 0)
            continue;

          share_i = htc_owner_share(p, e->owner);
          if (e->bytes > share_i) {
            htc_owner_copy(cand[ncand].owner, e->owner);
            cand[ncand].bytes = e->bytes - share_i;
            ncand++;
          }
        }
      }

      qsort(cand, ncand, sizeof(*cand), htc_owner_total_cmp);

      out->truncated = (ncand > (size_t)HTC_PLAN_MAX_STEPS) ? 1 : 0;
      out->nsteps = (ncand < (size_t)HTC_PLAN_MAX_STEPS)
                  ? ncand : (size_t)HTC_PLAN_MAX_STEPS;

      for (i = 0; i < out->nsteps; i++) {
        htc_owner_copy(out->steps[i].owner, cand[i].owner);
        out->steps[i].trim = cand[i].bytes;
      }

      free(cand);
    }
  }

  out->oldest = (out->nsteps == 0 && !out->truncated && total > target)
              ? (total - target) : 0;
}

/* ---------------------------------------------------------------------
 * Effective coverage days.
 * ------------------------------------------------------------------- */

int htc_effective_days(int configured_days, uint64_t floor_ms, uint64_t now_ms)
{
  uint64_t d;

  if (floor_ms == 0)
    return configured_days;

  d = (floor_ms >= now_ms) ? 0 : (now_ms - floor_ms) / 86400000ULL;

  if (configured_days > 0 && d >= (uint64_t)configured_days)
    return configured_days;

  if (d < 1)
    return 1;

  return (int)d;
}
