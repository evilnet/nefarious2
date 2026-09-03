/*
 * webpush_keyring.c - the VAPID key ring (pure decision logic).
 *
 * See webpush_keyring.h for the model and the current-key rule.  Kept free
 * of ircd dependencies so ircd/test links it directly.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "webpush_keyring.h"

/* ---------------------------------------------------------------------------
 * base64url (RFC 4648 §5, unpadded)
 * ------------------------------------------------------------------------- */

static const char b64url_alphabet[] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

int webpush_b64url_encode(const unsigned char *in, size_t in_len,
                          char *out, size_t out_size)
{
  size_t i, o = 0;
  size_t need = ((in_len + 2) / 3) * 4;   /* padded length, upper bound */

  if (!in || !out || out_size == 0 || need + 1 > out_size)
    return -1;

  for (i = 0; i + 2 < in_len; i += 3) {
    unsigned int v = ((unsigned int)in[i] << 16) | ((unsigned int)in[i + 1] << 8) | in[i + 2];
    out[o++] = b64url_alphabet[(v >> 18) & 63];
    out[o++] = b64url_alphabet[(v >> 12) & 63];
    out[o++] = b64url_alphabet[(v >> 6) & 63];
    out[o++] = b64url_alphabet[v & 63];
  }
  if (i < in_len) {
    unsigned int v = (unsigned int)in[i] << 16;
    if (i + 1 < in_len)
      v |= (unsigned int)in[i + 1] << 8;
    out[o++] = b64url_alphabet[(v >> 18) & 63];
    out[o++] = b64url_alphabet[(v >> 12) & 63];
    if (i + 1 < in_len)
      out[o++] = b64url_alphabet[(v >> 6) & 63];
  }
  out[o] = '\0';
  return (int)o;
}

static int b64url_value(char c)
{
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '-') return 62;
  if (c == '_') return 63;
  return -1;
}

int webpush_b64url_decode(const char *in, size_t in_len,
                          unsigned char *out, size_t out_size,
                          size_t *out_len)
{
  size_t i, o = 0;
  unsigned int acc = 0;
  int bits = 0;

  if (!in || !out || !out_len)
    return -1;

  /* Tolerate trailing '=' padding from other encoders. */
  while (in_len > 0 && in[in_len - 1] == '=')
    in_len--;
  if (in_len % 4 == 1)
    return -1;   /* no valid unpadded length leaves a single char */

  for (i = 0; i < in_len; i++) {
    int v = b64url_value(in[i]);
    if (v < 0)
      return -1;
    acc = (acc << 6) | (unsigned int)v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      if (o >= out_size)
        return -1;
      out[o++] = (unsigned char)((acc >> bits) & 0xff);
    }
  }
  *out_len = o;
  return 0;
}

/* ---------------------------------------------------------------------------
 * Ring
 * ------------------------------------------------------------------------- */

void webpush_keyring_init(struct webpush_keyring *ring)
{
  if (ring)
    memset(ring, 0, sizeof(*ring));
}

struct webpush_key *webpush_keyring_find(struct webpush_keyring *ring,
                                         const char *id)
{
  int i;

  if (!ring || !id || !id[0])
    return NULL;
  for (i = 0; i < ring->count; i++)
    if (0 == strcmp(ring->keys[i].id, id))
      return &ring->keys[i];
  return NULL;
}

int webpush_keyring_add(struct webpush_keyring *ring,
                        const struct webpush_key *key)
{
  if (!ring || !key || !key->id[0])
    return -1;
  if (webpush_keyring_find(ring, key->id))
    return 0;
  if (ring->count >= WEBPUSH_KEYRING_MAX)
    return -1;
  ring->keys[ring->count] = *key;
  ring->keys[ring->count].id[WEBPUSH_KEY_ID_LEN] = '\0';
  ring->keys[ring->count].origin[WEBPUSH_KEY_ORIGIN_LEN] = '\0';
  ring->count++;
  return 1;
}

int webpush_keyring_remove(struct webpush_keyring *ring, const char *id)
{
  struct webpush_key *k = webpush_keyring_find(ring, id);
  int idx;

  if (!k)
    return 0;
  idx = (int)(k - ring->keys);
  /* Order carries no meaning; move the last entry into the hole and
   * scrub the vacated slot (it held a private key). */
  if (idx != ring->count - 1)
    ring->keys[idx] = ring->keys[ring->count - 1];
  memset(&ring->keys[ring->count - 1], 0, sizeof(ring->keys[0]));
  ring->count--;
  return 1;
}

int webpush_key_compare(const struct webpush_key *a,
                        const struct webpush_key *b)
{
  if (a->generation != b->generation)
    return a->generation > b->generation ? -1 : 1;   /* highest generation first */
  if (a->created != b->created)
    return a->created < b->created ? -1 : 1;         /* then oldest first */
  return strcmp(a->id, b->id);                       /* then id bytes */
}

const struct webpush_key *webpush_keyring_current(const struct webpush_keyring *ring)
{
  const struct webpush_key *best = NULL;
  int i;

  if (!ring)
    return NULL;
  for (i = 0; i < ring->count; i++)
    if (!best || webpush_key_compare(&ring->keys[i], best) < 0)
      best = &ring->keys[i];
  return best;
}

unsigned int webpush_keyring_next_generation(const struct webpush_keyring *ring)
{
  unsigned int max = 0;
  int i, any = 0;

  if (!ring)
    return 0;
  for (i = 0; i < ring->count; i++) {
    if (!any || ring->keys[i].generation > max)
      max = ring->keys[i].generation;
    any = 1;
  }
  return any ? max + 1 : 0;
}

int webpush_key_prunable(const struct webpush_keyring *ring,
                         const struct webpush_key *key,
                         long long now, long long expire, long long grace)
{
  const struct webpush_key *cur = webpush_keyring_current(ring);

  if (!key || !cur)
    return 0;
  if (cur == key || 0 == strcmp(cur->id, key->id))
    return 0;
  if (key->refs <= 0 && key->created + (grace > 0 ? grace : 0) <= now)
    return 1;
  if (expire > 0 && key->created > 0 && key->created + expire <= now)
    return 1;
  return 0;
}

/* ---------------------------------------------------------------------------
 * Records
 * ------------------------------------------------------------------------- */

int webpush_key_format(const struct webpush_key *key, char *out, size_t outsz)
{
  char priv_b64[64];
  int n;

  if (!key || !out || outsz == 0)
    return -1;
  if (webpush_b64url_encode(key->priv, sizeof(key->priv), priv_b64,
                            sizeof(priv_b64)) < 0)
    return -1;
  n = snprintf(out, outsz, "%u|%lld|%s|%d|%s", key->generation, key->created,
               key->origin[0] ? key->origin : "?", key->manual ? 1 : 0,
               priv_b64);
  if (n < 0 || (size_t)n >= outsz) {
    if (outsz)
      out[0] = '\0';
    return -1;
  }
  return 0;
}

int webpush_key_parse(const char *id, const char *text, struct webpush_key *out)
{
  const char *f[5];
  size_t flen[5];
  const char *p;
  char num[32];
  char *endp;
  size_t plen;
  int i;

  if (!id || !id[0] || strlen(id) > WEBPUSH_KEY_ID_LEN || !text || !out)
    return -1;

  /* Split exactly five '|'-separated fields; the last is the private key. */
  p = text;
  for (i = 0; i < 5; i++) {
    const char *sep = (i < 4) ? strchr(p, '|') : NULL;
    f[i] = p;
    flen[i] = sep ? (size_t)(sep - p) : strlen(p);
    if (i < 4 && !sep)
      return -1;
    p = sep ? sep + 1 : p + flen[i];
  }
  if (flen[0] == 0 || flen[1] == 0 || flen[2] == 0 || flen[3] == 0 || flen[4] == 0)
    return -1;
  if (flen[0] >= sizeof(num) || flen[1] >= sizeof(num) || flen[3] >= sizeof(num))
    return -1;
  if (flen[2] > WEBPUSH_KEY_ORIGIN_LEN)
    return -1;

  memset(out, 0, sizeof(*out));
  strncpy(out->id, id, WEBPUSH_KEY_ID_LEN);

  memcpy(num, f[0], flen[0]); num[flen[0]] = '\0';
  out->generation = (unsigned int)strtoul(num, &endp, 10);
  if (*endp || num[0] == '-')
    return -1;

  memcpy(num, f[1], flen[1]); num[flen[1]] = '\0';
  out->created = strtoll(num, &endp, 10);
  if (*endp)
    return -1;

  memcpy(out->origin, f[2], flen[2]);
  out->origin[flen[2]] = '\0';

  memcpy(num, f[3], flen[3]); num[flen[3]] = '\0';
  out->manual = (int)strtol(num, &endp, 10);
  if (*endp)
    return -1;
  out->manual = out->manual ? 1 : 0;

  if (webpush_b64url_decode(f[4], flen[4], out->priv, sizeof(out->priv), &plen) != 0
      || plen != WEBPUSH_KEY_PRIV_LEN) {
    memset(out, 0, sizeof(*out));
    return -1;
  }
  return 0;
}

int webpush_record_key_id(const char *stored, char *out, size_t outsz)
{
  const char *p = stored;
  size_t len;
  int i;

  if (!stored || !out || outsz == 0)
    return 1;
  /* Skip endpoint, p256dh, auth, armed. */
  for (i = 0; i < 4; i++) {
    p = strchr(p, '|');
    if (!p)
      return 1;
    p++;
  }
  len = strcspn(p, "|");
  if (len == 0)
    return 1;
  if (len >= outsz)
    return -1;
  memcpy(out, p, len);
  out[len] = '\0';
  return 0;
}
