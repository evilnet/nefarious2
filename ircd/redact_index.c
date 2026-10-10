/* redact_index.c -- pure encoders for the redaction catch-up index (see .h). */
#include "redact_index.h"
#include <string.h>
#include <stdlib.h>

static int copy_field(char *dst, size_t dsz, const char *src, size_t n)
{
  if (n >= dsz)
    return -1;
  memcpy(dst, src, n);
  dst[n] = '\0';
  return 0;
}

int rdx_key_build(unsigned char *buf, size_t size, uint64_t time_ms, const char *redact_msgid)
{
  size_t ml = redact_msgid ? strlen(redact_msgid) : 0;
  int i;
  if (!buf || ml == 0 || ml >= RDX_MSGID_MAX || 8 + ml > size)
    return -1;
  for (i = 7; i >= 0; i--) {
    buf[i] = (unsigned char)(time_ms & 0xff);
    time_ms >>= 8;
  }
  memcpy(buf + 8, redact_msgid, ml);
  return (int)(8 + ml);
}

int rdx_key_parse(const void *key, size_t klen, uint64_t *time_ms, char *msgid, size_t msz)
{
  const unsigned char *k = (const unsigned char *)key;
  uint64_t t = 0;
  int i;
  if (!k || klen <= 8 || klen - 8 >= msz)
    return -1;
  for (i = 0; i < 8; i++)
    t = (t << 8) | k[i];
  if (time_ms) *time_ms = t;
  if (msgid) copy_field(msgid, msz, (const char *)k + 8, klen - 8);
  return 0;
}

int rdx_val_pack(char *buf, size_t size, const struct rdx_val *v)
{
  size_t tl = strlen(v->target), pl = strlen(v->parent_msgid), sl = strlen(v->sender),
         al = strlen(v->account), rl = strlen(v->reason);
  size_t need = tl + 1 + pl + 1 + sl + 1 + al + 1 + rl;
  char *p = buf;
  if (!buf || !tl || !pl || need > size)
    return -1;
  memcpy(p, v->target, tl); p += tl; *p++ = '\0';
  memcpy(p, v->parent_msgid, pl); p += pl; *p++ = '\0';
  memcpy(p, v->sender, sl); p += sl; *p++ = '\0';
  memcpy(p, v->account, al); p += al; *p++ = '\0';
  memcpy(p, v->reason, rl); p += rl;
  return (int)need;
}

int rdx_val_parse(const void *val, size_t vlen, struct rdx_val *out)
{
  const char *p = (const char *)val, *end = p + vlen, *q;
  char *dst[4] = { out->target, out->parent_msgid, out->sender, out->account };
  size_t dsz[4] = { sizeof out->target, sizeof out->parent_msgid, sizeof out->sender, sizeof out->account };
  int i;
  if (!p || !out)
    return -1;
  memset(out, 0, sizeof *out);
  for (i = 0; i < 4; i++) {
    q = memchr(p, '\0', (size_t)(end - p));
    if (!q)
      return -1;
    if (copy_field(dst[i], dsz[i], p, (size_t)(q - p)) < 0)
      return -1;
    p = q + 1;
  }
  if (copy_field(out->reason, sizeof out->reason, p, (size_t)(end - p)) < 0)
    return -1;
  if (!out->target[0] || !out->parent_msgid[0])
    return -1;
  return 0;
}

int rdx_reply_parse(int parc, char **parv, struct rdx_reply *out)
{
  const char *reason;
  if (!out || parc < 9 || !parv[1] || parv[1][0] != 'D' || parv[1][1])
    return -1;
  memset(out, 0, sizeof *out);
  if (copy_field(out->reqid, sizeof out->reqid, parv[2], strlen(parv[2])) < 0) return -1;
  out->time_ms = (uint64_t)strtoull(parv[3], NULL, 10);
  if (!out->time_ms) return -1;
  if (copy_field(out->redact_msgid, sizeof out->redact_msgid, parv[4], strlen(parv[4])) < 0) return -1;
  if (copy_field(out->v.target, sizeof out->v.target, parv[5], strlen(parv[5])) < 0) return -1;
  if (copy_field(out->v.parent_msgid, sizeof out->v.parent_msgid, parv[6], strlen(parv[6])) < 0) return -1;
  if (copy_field(out->v.sender, sizeof out->v.sender, parv[7], strlen(parv[7])) < 0) return -1;
  if (strcmp(parv[8], "*") != 0 &&
      copy_field(out->v.account, sizeof out->v.account, parv[8], strlen(parv[8])) < 0) return -1;
  reason = (parc > 9 && parv[9]) ? parv[9] : "";
  if (copy_field(out->v.reason, sizeof out->v.reason, reason, strlen(reason)) < 0) return -1;
  if (!out->reqid[0] || !out->redact_msgid[0] || !out->v.target[0] || !out->v.parent_msgid[0])
    return -1;
  return 0;
}
