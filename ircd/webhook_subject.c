/*
 * IRC - Internet Relay Chat, ircd/webhook_subject.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * See include/webhook_subject.h.  Keep this file free of ircd headers: it
 * is compiled standalone for the cmocka suite.
 */
#include "webhook_subject.h"

#include <jansson.h>
#include <string.h>

/** What follows "users/<uuid>" in the path: "" for the user itself,
 * "/reset-password", "/credentials/<id>", ...; NULL when the path does not
 * name a well-formed user (then user_id is NULL too). */
static const char *user_subpath(const struct kc_webhook_event *ev)
{
  size_t lu;
  if (!ev->resource_path || !ev->user_id)
    return NULL;
  if (0 != strncmp(ev->resource_path, "users/", 6))
    return NULL;
  lu = strlen(ev->user_id);
  if (0 != strncmp(ev->resource_path + 6, ev->user_id, lu))
    return NULL;
  return ev->resource_path + 6 + lu;
}

/* A name that can travel on the P10 wire as one token and match a cache
 * entry: no byte at or below space, no colon, no DEL, and at most
 * WH_USERNAME_MAX bytes (this module cannot include the ircd's ACCOUNTLEN;
 * 32 is above every account length the fork carries and below any token
 * limit).  Anything else is not a name. */
#define WH_USERNAME_MAX 32
static int username_usable(const char *u)
{
  size_t i;
  if (!u || !u[0])
    return 0;
  for (i = 0; u[i]; i++) {
    unsigned char c = (unsigned char)u[i];
    if (i >= WH_USERNAME_MAX || c <= ' ' || c == ':' || c == 0x7f)
      return 0;
  }
  return 1;
}

int webhook_subject_resolve(const struct kc_webhook_event *ev,
                            struct WebhookSubject *out)
{
  if (!out)
    return 0;
  memset(out, 0, sizeof(*out));
  if (!ev || ev->resource_type != KC_WH_RESOURCE_USER)
    return 0;

  /* The uuid in resourcePath is the one handle Keycloak always gives; a
   * malformed one leaves kc_id empty (account_id_from_uuid writes nothing). */
  if (ev->user_id)
    (void)account_id_from_uuid(ev->user_id, out->kc_id);
  out->username = username_usable(ev->username) ? ev->username : NULL;

  /* Keycloak records every operation under a user's resource as USER:
   * unlinking a federated identity is USER/DELETE on
   * users/<uuid>/federated-identity/<provider>, a consent revocation is
   * USER/DELETE on users/<uuid>/consents/<client>.  Only the bare path is
   * the user; a synthetic event with no path at all names its subject by
   * name and counts as the user too. */
  {
    const char *sub = user_subpath(ev);
    int user_only = (!ev->resource_path) || (sub && sub[0] == '\0');
    int credential = sub && 0 == strncmp(sub, "/credentials/", 13);

    switch (ev->operation_type) {
    case KC_WH_OP_DELETE:
      if (credential)
        out->kind = WH_SUBJECT_CREDENTIAL_REMOVED;
      else if (user_only)
        out->kind = WH_SUBJECT_DELETE;
      break;
    case KC_WH_OP_UPDATE:
      /* Keycloak's update carries the fields it changed: an absent
       * "enabled" was not touched (PUT semantics), so only an explicit
       * false is a disable. */
      if (user_only && ev->representation) {
        json_t *en = json_object_get(ev->representation, "enabled");
        if (en && json_is_false(en))
          out->kind = WH_SUBJECT_DISABLE;
        else if (en && json_is_true(en))
          out->kind = WH_SUBJECT_ENABLE;
      }
      break;
    case KC_WH_OP_ACTION:
      if (credential)
        out->kind = WH_SUBJECT_CREDENTIAL_REMOVED;
      else if (sub && 0 == strcmp(sub, "/reset-password"))
        out->kind = WH_SUBJECT_PASSWORD_RESET;
      else if (sub && 0 == strcmp(sub, "/logout"))
        out->kind = WH_SUBJECT_LOGOUT;
      break;
    default:
      break;
    }
  }

  /* A subject nobody can name is nothing to act on. */
  if (out->kind != WH_SUBJECT_NONE && !out->kc_id[0] && !out->username)
    out->kind = WH_SUBJECT_NONE;

  return out->kind != WH_SUBJECT_NONE;
}

const char *webhook_subject_kind_name(enum WebhookSubjectKind kind)
{
  switch (kind) {
  case WH_SUBJECT_DELETE:         return "delete";
  case WH_SUBJECT_DISABLE:        return "disable";
  case WH_SUBJECT_ENABLE:         return "enable";
  case WH_SUBJECT_PASSWORD_RESET: return "reset-password";
  case WH_SUBJECT_CREDENTIAL_REMOVED: return "credential-removed";
  case WH_SUBJECT_LOGOUT:         return "logout";
  case WH_SUBJECT_NONE:
  default:                        return "none";
  }
}

char webhook_relay_kind_for(enum WebhookSubjectKind kind)
{
  switch (kind) {
  case WH_SUBJECT_DELETE:             return WH_RELAY_DELETE;
  case WH_SUBJECT_DISABLE:            return WH_RELAY_DISABLE;
  case WH_SUBJECT_ENABLE:             return WH_RELAY_ENABLE;
  case WH_SUBJECT_PASSWORD_RESET:     return WH_RELAY_RESET;
  case WH_SUBJECT_CREDENTIAL_REMOVED: return WH_RELAY_CREDENTIAL;
  case WH_SUBJECT_LOGOUT:
  case WH_SUBJECT_NONE:
  default:                            return 0;
  }
}

enum WebhookSubjectKind webhook_subject_kind_for_relay(char kind)
{
  switch (kind) {
  case WH_RELAY_DELETE:     return WH_SUBJECT_DELETE;
  case WH_RELAY_DISABLE:    return WH_SUBJECT_DISABLE;
  case WH_RELAY_ENABLE:     return WH_SUBJECT_ENABLE;
  case WH_RELAY_RESET:      return WH_SUBJECT_PASSWORD_RESET;
  case WH_RELAY_CREDENTIAL: return WH_SUBJECT_CREDENTIAL_REMOVED;
  case WH_RELAY_PURGE:
  default:                  return WH_SUBJECT_NONE;
  }
}
