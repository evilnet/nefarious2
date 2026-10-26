/*
 * IRC - Internet Relay Chat, ircd/bouncer_wire.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * See include/bouncer_wire.h.  Keep this file free of ircd headers:
 * it is compiled standalone for the cmocka suite.
 */
#include "bouncer_wire.h"

int bounce_legacy_link_knows(int link_aware, int link_gated,
                             int face_behind_link)
{
  /* An aware link follows the session itself; a gated one has been sent
   * nothing yet; the face's own direction introduced it to us. */
  if (link_aware || link_gated || face_behind_link)
    return 0;
  return 1;
}

enum bounce_demote_bar bounce_demote_check(enum bounce_demote_stage stage,
                                           const struct bounce_demote_facts *f)
{
  if (!f)
    return BOUNCE_DEMOTE_NO_NEW_HOME;
  /* Different Keycloak users are never merged, whatever else holds. */
  if (f->kc_id_conflict)
    return BOUNCE_DEMOTE_KC_CONFLICT;
  if (!f->new_home_known)
    return BOUNCE_DEMOTE_NO_NEW_HOME;
  /* A legacy home has no sessions and never hears BX C. */
  if (!f->new_home_aware)
    return BOUNCE_DEMOTE_LEGACY_HOME;
  if (!f->face_account_user)
    return BOUNCE_DEMOTE_NOT_ACCOUNT_USER;
  /* Before the demote the face is a live primary; after it, the alias
   * the demote made. */
  if (stage == BOUNCE_DEMOTE_FINISH ? !f->face_alias : f->face_alias)
    return BOUNCE_DEMOTE_FACE_ALIAS;
  if (f->face_held)
    return BOUNCE_DEMOTE_FACE_HELD;
  /* Its own exit holds the session; an alias exit would end it. */
  if (f->face_dying)
    return BOUNCE_DEMOTE_FACE_DYING;
  if (!f->session_found)
    return BOUNCE_DEMOTE_NO_SESSION;
  if (f->session_slot != (stage == BOUNCE_DEMOTE_FINISH ? BOUNCE_SLOT_EMPTY
                                                       : BOUNCE_SLOT_FACE))
    return BOUNCE_DEMOTE_SESSION_SLOT;
  /* The finish's account rules, asked at both steps. */
  if (!f->new_account)
    return BOUNCE_DEMOTE_NEW_ACCOUNT;
  if (!f->session_account)
    return BOUNCE_DEMOTE_SESSION_ACCOUNT;
  return BOUNCE_DEMOTE_OK;
}

const char *bounce_demote_bar_name(enum bounce_demote_bar bar)
{
  switch (bar) {
  case BOUNCE_DEMOTE_OK:               return "ok";
  case BOUNCE_DEMOTE_NO_NEW_HOME:      return "no new primary";
  case BOUNCE_DEMOTE_LEGACY_HOME:      return "legacy home";
  case BOUNCE_DEMOTE_NOT_ACCOUNT_USER: return "not a logged-in user";
  case BOUNCE_DEMOTE_FACE_ALIAS:       return "alias state";
  case BOUNCE_DEMOTE_FACE_HELD:        return "held ghost";
  case BOUNCE_DEMOTE_FACE_DYING:       return "exiting";
  case BOUNCE_DEMOTE_NO_SESSION:       return "no session";
  case BOUNCE_DEMOTE_SESSION_SLOT:     return "not the session's primary";
  case BOUNCE_DEMOTE_NEW_ACCOUNT:      return "new primary's account differs";
  case BOUNCE_DEMOTE_SESSION_ACCOUNT:  return "session's account differs";
  case BOUNCE_DEMOTE_KC_CONFLICT:      return "Keycloak ids differ";
  }
  return "?";
}

enum bounce_merge_choice bounce_merge_choose(int we_lose,
                                             enum bounce_demote_bar bar)
{
  /* Both sides read the same two ids: neither merges. */
  if (bar == BOUNCE_DEMOTE_KC_CONFLICT)
    return BOUNCE_MERGE_CLASSIC;
  if (!we_lose)
    return BOUNCE_MERGE_REFUSE;
  return bar == BOUNCE_DEMOTE_OK ? BOUNCE_MERGE_SWAP : BOUNCE_MERGE_CLASSIC;
}
