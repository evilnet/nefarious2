/*
 * webpush_line.c - the push payload as one IRC line (draft/webpush)
 *
 * See webpush_line.h.  Kept free of ircd dependencies so ircd/test links
 * it directly.
 */
#include "webpush_line.h"

#include <stdio.h>
#include <string.h>

/* An append-only buffer that remembers when it ran out of room. */
struct wl_buf {
  char *out;
  size_t cap;      /* bytes available, including the NUL */
  size_t pos;
  int overflow;
};

static void wl_init(struct wl_buf *b, char *out, size_t cap)
{
  b->out = out;
  b->cap = cap;
  b->pos = 0;
  b->overflow = 0;
  if (cap > 0)
    out[0] = '\0';
}

static void wl_put(struct wl_buf *b, const char *s)
{
  size_t n = strlen(s);

  if (b->overflow)
    return;
  if (b->pos + n + 1 > b->cap) {
    b->overflow = 1;
    return;
  }
  memcpy(b->out + b->pos, s, n);
  b->pos += n;
  b->out[b->pos] = '\0';
}

/* A tag value, escaped per the IRCv3 message-tags spec. */
static void wl_put_tagvalue(struct wl_buf *b, const char *s)
{
  char one[2];

  one[1] = '\0';
  for (; *s; ++s) {
    switch (*s) {
    case ';':  wl_put(b, "\\:"); break;
    case ' ':  wl_put(b, "\\s"); break;
    case '\\': wl_put(b, "\\\\"); break;
    case '\r': wl_put(b, "\\r"); break;
    case '\n': wl_put(b, "\\n"); break;
    default:
      one[0] = *s;
      wl_put(b, one);
      break;
    }
  }
}

/* "@name=value" for the first tag, ";name=value" after; value NULL = flag. */
static void wl_tag(struct wl_buf *b, int *ntags, const char *name, const char *value)
{
  wl_put(b, *ntags == 0 ? "@" : ";");
  wl_put(b, name);
  if (value) {
    wl_put(b, "=");
    wl_put_tagvalue(b, value);
  }
  (*ntags)++;
}

/* 1 when s contains a CR or LF: a payload must be exactly one IRC message,
 * and command/target/text/server ride the line unescaped (unlike tag
 * values), so a CR or LF in any of them would inject a second line. */
static int wl_has_crlf(const char *s)
{
  return strchr(s, '\r') != NULL || strchr(s, '\n') != NULL;
}

static int wl_finish(struct wl_buf *b)
{
  if (b->overflow) {
    if (b->cap > 0)
      b->out[0] = '\0';
    return -1;
  }
  return (int)b->pos;
}

size_t webpush_tag_escape(char *out, size_t outlen, const char *in)
{
  struct wl_buf b;

  if (!out || outlen == 0 || !in)
    return (size_t)-1;
  wl_init(&b, out, outlen);
  wl_put_tagvalue(&b, in);
  if (b.overflow) {
    out[0] = '\0';
    return (size_t)-1;
  }
  return b.pos;
}

int webpush_line_message(char *out, size_t outlen,
                         const struct webpush_line_src *src,
                         const char *command, const char *target,
                         const char *text, const char *msgid,
                         const char *timestamp,
                         const struct webpush_line_ml *ml)
{
  struct wl_buf b;
  int ntags = 0;
  char idx[48];

  if (!out || outlen == 0)
    return -1;
  out[0] = '\0';
  if (!src || !src->nick || !src->user || !src->host || !command || !target || !text)
    return -1;
  if (wl_has_crlf(command) || wl_has_crlf(target) || wl_has_crlf(text))
    return -1;
  if (ml && (!ml->batch || !ml->batch[0] || ml->index < 1 || ml->sent < 1
             || ml->total < 1 || ml->index > ml->sent || ml->sent > ml->total))
    return -1;

  wl_init(&b, out, outlen);

  if (ml)
    wl_tag(&b, &ntags, "batch", ml->batch);
  if (msgid && msgid[0])
    wl_tag(&b, &ntags, "msgid", msgid);
  if (timestamp && timestamp[0])
    wl_tag(&b, &ntags, "time", timestamp);
  if (src->account && src->account[0])
    wl_tag(&b, &ntags, "account", src->account);
  if (ml) {
    snprintf(idx, sizeof(idx), "%d/%d/%d", ml->index, ml->sent, ml->total);
    wl_tag(&b, &ntags, "evilnet.github.io/line", idx);
    if (ml->concat)
      wl_tag(&b, &ntags, "draft/multiline-concat", NULL);
  }
  if (ntags > 0)
    wl_put(&b, " ");

  wl_put(&b, ":");
  wl_put(&b, src->nick);
  wl_put(&b, "!");
  wl_put(&b, src->user);
  wl_put(&b, "@");
  wl_put(&b, src->host);
  wl_put(&b, " ");
  wl_put(&b, command);
  wl_put(&b, " ");
  wl_put(&b, target);
  wl_put(&b, " :");
  wl_put(&b, text);

  return wl_finish(&b);
}

int webpush_line_markread(char *out, size_t outlen, const char *server,
                          const char *target, const char *timestamp)
{
  struct wl_buf b;

  if (!out || outlen == 0)
    return -1;
  out[0] = '\0';
  if (!server || !server[0] || !target || !target[0])
    return -1;
  if (wl_has_crlf(server) || wl_has_crlf(target))
    return -1;

  wl_init(&b, out, outlen);
  wl_put(&b, ":");
  wl_put(&b, server);
  wl_put(&b, " MARKREAD ");
  wl_put(&b, target);
  wl_put(&b, " ");
  if (!timestamp || !timestamp[0] || 0 == strcmp(timestamp, "*")) {
    /* The draft's form for "no marker" is the bare "*" (no "timestamp="
     * prefix); send_markread (ircd/m_markread.c) instead sends clients
     * "timestamp=*". The client tolerates both; this is a deliberate
     * divergence from send_markread, not an oversight. */
    wl_put(&b, "*");
  } else {
    wl_put(&b, "timestamp=");
    wl_put(&b, timestamp);
  }
  return wl_finish(&b);
}
