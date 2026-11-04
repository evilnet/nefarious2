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
