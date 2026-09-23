/*
 * IRC - Internet Relay Chat, ircd/bouncer_deauth.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * See include/bouncer_deauth.h.  Keep this file free of ircd headers:
 * it is compiled standalone for the cmocka suite.
 */
#include "bouncer_deauth.h"

#include <string.h>
#include <ctype.h>

/* Indexed by enum BounceAliasField; NULL at UNKNOWN so the enum value
 * doubles as the table index. */
static const char *const field_names[BX_ALIAS_FIELD_COUNT] = {
  NULL,           /* BX_ALIAS_FIELD_UNKNOWN   */
  "host",         /* BX_ALIAS_FIELD_HOST      */
  "realhost",     /* BX_ALIAS_FIELD_REALHOST  */
  "realname",     /* BX_ALIAS_FIELD_REALNAME  */
  "fakehost",     /* BX_ALIAS_FIELD_FAKEHOST  */
  "cloakhost",    /* BX_ALIAS_FIELD_CLOAKHOST */
  "cloakip",      /* BX_ALIAS_FIELD_CLOAKIP   */
  "username",     /* BX_ALIAS_FIELD_USERNAME  */
  "account",      /* BX_ALIAS_FIELD_ACCOUNT   */
  "caps"          /* BX_ALIAS_FIELD_CAPS      */
};

/* Local case-insensitive compare: ircd_strcmp lives behind an ircd
 * header, and this file may not include one.  BX U field names are
 * ASCII literals, so plain tolower() is sufficient and avoids pulling
 * in the IRC casemap (which differs only for []\~{}| — none of which
 * appear in a field name). */
static int field_casecmp(const char *a, const char *b)
{
  while (*a && *b) {
    int ca = tolower((unsigned char)*a);
    int cb = tolower((unsigned char)*b);
    if (ca != cb)
      return ca - cb;
    a++; b++;
  }
  return (unsigned char)*a - (unsigned char)*b;
}

enum BounceAliasField bounce_alias_field_id(const char *field)
{
  int i;

  if (!field || !field[0])
    return BX_ALIAS_FIELD_UNKNOWN;

  for (i = BX_ALIAS_FIELD_UNKNOWN + 1; i < BX_ALIAS_FIELD_COUNT; i++) {
    if (0 == field_casecmp(field, field_names[i]))
      return (enum BounceAliasField)i;
  }
  return BX_ALIAS_FIELD_UNKNOWN;
}

const char *bounce_alias_field_name(enum BounceAliasField id)
{
  if (id <= BX_ALIAS_FIELD_UNKNOWN || id >= BX_ALIAS_FIELD_COUNT)
    return NULL;
  return field_names[id];
}

enum BounceDeauthAction
bounce_deauth_classify(const struct BounceDeauthSubject *s, int do_kill)
{
  if (!s)
    return BOUNCE_DEAUTH_SKIP;

  /* Only registered users carrying the account in question. */
  if (!s->is_user || !s->is_account || !s->account_matches)
    return BOUNCE_DEAUTH_SKIP;

  /* Never act on a client we do not own the socket for. */
  if (!s->is_local)
    return BOUNCE_DEAUTH_SKIP;

  /* A held ghost has no live socket; the session is the thing to remove,
   * and neither a clear nor a socket kill accomplishes that. */
  if (s->is_hold)
    return BOUNCE_DEAUTH_DESTROY_SESSION;

  if (do_kill)
    return BOUNCE_DEAUTH_KILL_SOCKET;

  /* Aliases take the account clear through the primary's field
   * propagation, not directly. */
  if (s->is_alias)
    return BOUNCE_DEAUTH_SKIP;

  return BOUNCE_DEAUTH_CLEAR_ACCOUNT;
}
