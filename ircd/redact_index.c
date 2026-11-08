/* redact_index.c -- pure encoders for the redaction catch-up index, the
 * REDACT authorization rule, and the rules for applying a redaction and
 * moving the catch-up watermark (see .h).  Links against ../ircd_string.o only
 * (ircd_strcmp); history.h is read for its message-type values alone. */
#include "config.h"
#include "redact_index.h"
#include "history.h"
#include "ircd_string.h"
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

unsigned int ch_e_flags(const char *param)
{
  unsigned int flags = 0;
  if (!param)
    return 0;
  for (; *param; param++) {
    if (*param == 'T')
      flags |= CH_E_TRUNCATED;
    else if (*param == 'U')
      flags |= CH_E_UNANSWERED;
  }
  return flags;
}

enum rdx_row rdx_row_decide(int parent_lookup_rc, int already_redacted)
{
  if (parent_lookup_rc < 0)
    return RDX_ROW_RETRY;
  if (parent_lookup_rc > 0)
    return RDX_ROW_SKIP_ORPHAN;
  if (already_redacted < 0)
    return RDX_ROW_RETRY;
  return already_redacted ? RDX_ROW_SKIP_APPLIED : RDX_ROW_APPLY;
}

static enum rdx_wm rdx_wm_set(enum rdx_wm d, uint64_t ms, uint64_t *wm_out)
{
  if (wm_out)
    *wm_out = ms;
  return d;
}

enum rdx_wm rdx_watermark_decide(int cut, int truncated, int round, int max_rounds,
                                 uint64_t last_ms, uint64_t start_ms, uint64_t *wm_out)
{
  if (cut)
    return RDX_WM_KEEP;
  if (truncated) {
    /* More exists past what was fetched: never past the newest row seen. */
    if (!last_ms)
      return RDX_WM_KEEP;
    return rdx_wm_set(round < max_rounds ? RDX_WM_SET_CONTINUE : RDX_WM_SET,
                      last_ms, wm_out);
  }
  return rdx_wm_set(RDX_WM_SET, start_ms, wm_out);
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

/* "" for NULL, so a caller that has no account or mask may pass either. */
static const char *rda_str(const char *s)
{
  return s ? s : "";
}

/* Within a window: 0 = none; else the row is at most @a window seconds old. */
static int rda_within(const struct redact_auth_in *in, long window)
{
  return window <= 0 || (in->now - in->msg_time) <= window;
}

static enum redact_auth rda_expired(long window, long *window_out)
{
  if (window_out)
    *window_out = window;
  return REDACT_AUTH_EXPIRED;
}

enum redact_auth redact_authorize(const struct redact_auth_in *in, long *window_out)
{
  const char *macct, *racct;

  if (!in)
    return REDACT_AUTH_FORBIDDEN;
  macct = rda_str(in->msg_account);
  racct = rda_str(in->req_account);

  /* 1. spec: the msgid MUST name a PRIVMSG, NOTICE or TAGMSG (a stored
   * multiline is a PRIVMSG batch); a JOIN, MODE or REDACT row is not
   * redactable (audit 2026-09-06 #59). */
  if (in->msg_type != HISTORY_PRIVMSG && in->msg_type != HISTORY_NOTICE
      && in->msg_type != HISTORY_TAGMSG && in->msg_type != HISTORY_MULTILINE)
    return REDACT_AUTH_NOT_MESSAGE;

  /* 2. Opers: their own window (0 = unlimited), any sender. */
  if (in->is_oper)
    return rda_within(in, in->oper_window) ? REDACT_AUTH_OK
                                           : rda_expired(in->oper_window, window_out);

  /* 3. The authenticated owner: account match, no window. */
  if (macct[0] && racct[0] && ircd_strcmp(macct, racct) == 0)
    return REDACT_AUTH_OK;

  /* 4. The unauthenticated sender-mask fallback: both the row and the
   * requester unauthenticated, and nick!user@host equal.  Never for a row
   * whose '|'-shifted header was repaired on read (ce441a04): its account
   * is empty because none could be trusted, not because the sender was
   * unauthenticated, so the mask proves nothing.  A federated row always
   * counts as repaired: its sender came over the wire. */
  if (!macct[0] && !racct[0] && !in->header_repaired
      && ircd_strcmp(rda_str(in->req_mask), rda_str(in->msg_sender)) == 0)
    return REDACT_AUTH_OK;

  /* 5. Everyone else, chanops included: the regular window, then the
   * chanop-others grant. */
  if (!rda_within(in, in->window))
    return rda_expired(in->window, window_out);
  if (in->is_chanop && in->chanop_others)
    return REDACT_AUTH_OK;
  return REDACT_AUTH_FORBIDDEN;
}
