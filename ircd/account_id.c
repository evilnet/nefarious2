/*
 * IRC - Internet Relay Chat, ircd/account_id.c
 *
 * account_id.c - the compact form of a Keycloak user id.
 *
 * Keycloak identifies a user by a UUID.  On the P10 wire and in services'
 * database it travels as the 16 bytes in unpadded base64url: 22 characters
 * instead of 36, fitting the burst NICK line alongside the account name.
 */
#include "config.h"
#include "account_id.h"
#include "webpush_keyring.h"

#include <ctype.h>
#include <string.h>

static int hexval(int c)
{
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

int account_id_from_uuid(const char *uuid, char out[ACCOUNT_ID_LEN + 1])
{
  unsigned char raw[16];
  /* The encoder wants room for the padded upper bound (24 + NUL) even
   * though 16 bytes come out as 22 unpadded characters; encode here and
   * hand back exactly ACCOUNT_ID_LEN. */
  char buf[((sizeof(raw) + 2) / 3) * 4 + 1];
  int digits = 0, hi = -1;
  const char *p;

  if (!uuid)
    return 0;
  for (p = uuid; *p; p++) {
    int v;
    if (*p == '-')
      continue;                    /* the canonical 8-4-4-4-12 hyphens */
    if ((v = hexval((unsigned char)*p)) < 0 || digits == 32)
      return 0;
    if (hi < 0)
      hi = v;
    else {
      raw[digits / 2] = (unsigned char)((hi << 4) | v);
      hi = -1;
    }
    digits++;
  }
  if (digits != 32)
    return 0;
  if (webpush_b64url_encode(raw, sizeof(raw), buf, sizeof(buf)) != ACCOUNT_ID_LEN)
    return 0;
  memcpy(out, buf, ACCOUNT_ID_LEN + 1);
  return 1;
}

int account_id_valid(const char *id)
{
  int i;

  if (!id)
    return 0;
  for (i = 0; id[i]; i++) {
    int c = (unsigned char)id[i];
    if (!(isalnum(c) || c == '-' || c == '_'))
      return 0;
  }
  return i == ACCOUNT_ID_LEN;
}
