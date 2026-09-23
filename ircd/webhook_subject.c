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

static int path_ends_with(const char *path, const char *suffix)
{
  size_t lp, ls;
  if (!path || !suffix)
    return 0;
  lp = strlen(path);
  ls = strlen(suffix);
  return lp >= ls && 0 == strcmp(path + lp - ls, suffix);
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
  out->username = ev->username;

  switch (ev->operation_type) {
  case KC_WH_OP_DELETE:
    out->kind = WH_SUBJECT_DELETE;
    break;
  case KC_WH_OP_UPDATE:
    /* Keycloak's update carries the fields it changed: an absent
     * "enabled" was not touched (PUT semantics), so only an explicit
     * false is a disable. */
    if (ev->representation) {
      json_t *en = json_object_get(ev->representation, "enabled");
      if (en && json_is_false(en))
        out->kind = WH_SUBJECT_DISABLE;
      else if (en && json_is_true(en))
        out->kind = WH_SUBJECT_ENABLE;
    }
    break;
  case KC_WH_OP_ACTION:
    if (path_ends_with(ev->resource_path, "/reset-password"))
      out->kind = WH_SUBJECT_PASSWORD_RESET;
    else if (path_ends_with(ev->resource_path, "/logout"))
      out->kind = WH_SUBJECT_LOGOUT;
    break;
  default:
    break;
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
  case WH_SUBJECT_LOGOUT:         return "logout";
  case WH_SUBJECT_NONE:
  default:                        return "none";
  }
}
