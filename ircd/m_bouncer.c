/*
 * IRC - Internet Relay Chat, ircd/m_bouncer.c
 * Copyright (C) 2025 Nefarious Development
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
/** @file
 * @brief BOUNCER command handler - client-facing bouncer management.
 *
 * User subcommands:
 *   BOUNCER SET HOLD [on|off]   - Set hold preference
 *   BOUNCER INFO                - Show session state and preferences
 *   BOUNCER LISTCLIENTS         - List all connections for the session
 *
 * Oper-only subcommands (for admin/testing):
 *   BOUNCER TOKEN          - Request a new session token
 *   BOUNCER RESUME <token> - Resume a session by token
 *   BOUNCER LISTSESSIONS   - List sessions for current account
 *   BOUNCER DISCONNECT <id>- Disconnect/destroy a session
 *   BOUNCER SETNAME <id> <name> - Name a session
 */
#include "config.h"

#include "bouncer_session.h"
#include "capab.h"
#include "channel.h"
#include "class.h"
#include "client.h"
#include "hash.h"
#include "history.h"
#include "ircd.h"
#include "metadata.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "replay.h"
#include "send.h"
#include "s_debug.h"

#include <assert.h>
#include <string.h>

/* ---------------------------------------------------------------- */
/* Subcommand: TOKEN                                                 */
/* ---------------------------------------------------------------- */

/** Handle BOUNCER TOKEN - create a new session and return token. */
static int bouncer_token(struct Client *sptr)
{
  struct BouncerSession *session;
  int ret;

  if (!IsAccount(sptr)) {
    send_fail(sptr, "BOUNCER", "ACCOUNT_REQUIRED", NULL,
              "You must be logged in to use bouncer features");
    return 0;
  }

  ret = bounce_create(sptr, &session);
  if (ret < 0) {
    send_fail(sptr, "BOUNCER", "SESSION_LIMIT", NULL,
              "Session limit reached");
    return 0;
  }

  /* Broadcast creation to all servers */
  bounce_broadcast(session, 'C', NULL);

  /* Send token to client */
  sendrawto_one(sptr, ":%s %d %s %s :%s",
                cli_name(&me), RPL_BOUNCETOKEN, cli_name(sptr),
                session->hs_sessid, session->hs_token);

  send_note(sptr, "BOUNCER", "SESSION_CREATED", session->hs_sessid,
            "Session created");

  return 0;
}

/* ---------------------------------------------------------------- */
/* Subcommand: RESUME                                                */
/* ---------------------------------------------------------------- */



/** Handle BOUNCER RESUME <token> - resume an existing session. */
static int bouncer_resume(struct Client *sptr, const char *token)
{
  struct BouncerSession *session;
  time_t since_time;
  int ret;

  if (!token || !*token) {
    send_fail(sptr, "BOUNCER", "NEED_PARAM", "RESUME",
              "Missing required parameter");
    return 0;
  }

  session = bounce_find_by_token(token);
  if (!session) {
    send_fail(sptr, "BOUNCER", "INVALID_TOKEN", NULL,
              "Invalid or expired session token");
    return 0;
  }

  /* Verify account ownership */
  if (!IsAccount(sptr) ||
      0 != ircd_strcmp(cli_account(sptr), session->hs_account)) {
    send_fail(sptr, "BOUNCER", "INVALID_TOKEN", NULL,
              "Invalid or expired session token");
    return 0;
  }

  /* Compute replay "since" time from the ghost's idle time — messages
   * arriving after the user's last activity may not have been read.
   * Fall back to disconnect time if idle time is unavailable. */
  {
    time_t idle = 0;
    if (session->hs_client && cli_user(session->hs_client))
      idle = cli_user(session->hs_client)->last;
    since_time = (idle > 0) ? idle : session->hs_disconnect_time;
  }

  /* Attach client to session */
  ret = bounce_attach(session, sptr);
  if (ret < 0) {
    send_fail(sptr, "BOUNCER", "INVALID_TOKEN", NULL,
              "Session is already in use");
    return 0;
  }

  /* Broadcast attach to all servers */
  bounce_broadcast(session, 'A', cli_yxx(sptr));

  send_note(sptr, "BOUNCER", "SESSION_RESUMED", session->hs_sessid,
            "Session resumed");

  /* Async auto-replay for clients without draft/chathistory. */
  if (!CapOwnHas(sptr, CAP_DRAFT_CHATHISTORY)) {
    replay_start_bouncer(sptr, since_time, 0);
  }

  return 0;
}

/* ---------------------------------------------------------------- */
/* Subcommand: LISTSESSIONS                                          */
/* ---------------------------------------------------------------- */

/** Handle BOUNCER LISTSESSIONS - list sessions for current account. */
static int bouncer_listsessions(struct Client *sptr)
{
  struct AccountSessions *as;
  struct BouncerSession *s;

  if (!IsAccount(sptr)) {
    send_fail(sptr, "BOUNCER", "ACCOUNT_REQUIRED", NULL,
              "You must be logged in to use bouncer features");
    return 0;
  }

  as = bounce_find_by_account(cli_account(sptr));
  if (!as || as->as_count == 0) {
    sendrawto_one(sptr, ":%s %d %s :No active sessions",
                  cli_name(&me), RPL_BOUNCERSETTINGS, cli_name(sptr));
    return 0;
  }

  for (s = as->as_sessions; s; s = s->hs_anext) {
    const char *state_str;
    char info[256];

    state_str = (s->hs_state == BOUNCE_ACTIVE) ? "active" : "holding";

    if (s->hs_state == BOUNCE_HOLDING && s->hs_disconnect_time) {
      time_t hold_time = bounce_compute_hold_time_ext(s);
      time_t remaining = hold_time -
                         (CurrentTime - s->hs_disconnect_time);
      if (remaining < 0)
        remaining = 0;
      ircd_snprintf(0, info, sizeof(info), "%s %s %s %ldm connects:%u",
                    s->hs_sessid,
                    s->hs_name[0] ? s->hs_name : "*",
                    state_str,
                    (long)(remaining / 60),
                    s->hs_connect_count);
    } else {
      ircd_snprintf(0, info, sizeof(info), "%s %s %s connects:%u",
                    s->hs_sessid,
                    s->hs_name[0] ? s->hs_name : "*",
                    state_str,
                    s->hs_connect_count);
    }

    sendrawto_one(sptr, ":%s %d %s %s",
                  cli_name(&me), RPL_BOUNCERSESSION, cli_name(sptr),
                  info);
  }

  return 0;
}

/* ---------------------------------------------------------------- */
/* Subcommand: DISCONNECT                                            */
/* ---------------------------------------------------------------- */

/** Handle BOUNCER DISCONNECT <session-id> - destroy a session. */
static int bouncer_disconnect(struct Client *sptr, const char *sessid)
{
  struct AccountSessions *as;
  struct BouncerSession *s;

  if (!sessid || !*sessid) {
    send_fail(sptr, "BOUNCER", "NEED_PARAM", "DISCONNECT",
              "Missing required parameter");
    return 0;
  }

  if (!IsAccount(sptr)) {
    send_fail(sptr, "BOUNCER", "ACCOUNT_REQUIRED", NULL,
              "You must be logged in to use bouncer features");
    return 0;
  }

  /* Find session by ID in account's list */
  as = bounce_find_by_account(cli_account(sptr));
  if (!as)
    goto notfound;

  for (s = as->as_sessions; s; s = s->hs_anext) {
    if (0 == strcmp(s->hs_sessid, sessid)) {
      bounce_broadcast(s, 'X', NULL);
      bounce_destroy(s);
      send_note(sptr, "BOUNCER", "SESSION_DISCONNECTED", sessid,
                "Session disconnected");
      return 0;
    }
  }

notfound:
  send_fail(sptr, "BOUNCER", "NO_SUCH_SESSION", sessid,
            "No such session");
  return 0;
}

/* ---------------------------------------------------------------- */
/* Subcommand: SETNAME                                               */
/* ---------------------------------------------------------------- */

/** Handle BOUNCER SETNAME <session-id> <name>. */
static int bouncer_setname(struct Client *sptr, const char *sessid,
                           const char *name)
{
  struct AccountSessions *as;
  struct BouncerSession *s;
  char update[64];

  if (!sessid || !*sessid || !name || !*name) {
    send_fail(sptr, "BOUNCER", "NEED_PARAM", "SETNAME",
              "Missing required parameter");
    return 0;
  }

  if (!IsAccount(sptr)) {
    send_fail(sptr, "BOUNCER", "ACCOUNT_REQUIRED", NULL,
              "You must be logged in to use bouncer features");
    return 0;
  }

  as = bounce_find_by_account(cli_account(sptr));
  if (!as)
    goto notfound;

  for (s = as->as_sessions; s; s = s->hs_anext) {
    if (0 == strcmp(s->hs_sessid, sessid)) {
      bounce_setname(s, name);

      ircd_snprintf(0, update, sizeof(update), "name=%s", name);
      bounce_broadcast(s, 'U', update);

      send_note(sptr, "BOUNCER", "SESSION_RENAMED", sessid,
                "Session renamed");
      return 0;
    }
  }

notfound:
  send_fail(sptr, "BOUNCER", "NO_SUCH_SESSION", sessid,
            "No such session");
  return 0;
}

/* ---------------------------------------------------------------- */
/* Subcommand: SET                                                   */
/* ---------------------------------------------------------------- */

/** Handle BOUNCER SET HOLD [on|off]. */
static int bouncer_set(struct Client *sptr, int parc, char *parv[])
{
  /* parv[0] = "BOUNCER", parv[1] = "SET", parv[2] = "HOLD", parv[3] = on/off */
  /* or parv[2] = "SESSION", parv[3] = <id>, parv[4] = "HOLD", parv[5] = on/off */

  if (!IsAccount(sptr)) {
    send_fail(sptr, "BOUNCER", "ACCOUNT_REQUIRED", NULL,
              "You must be logged in to use bouncer features");
    return 0;
  }

  if (parc < 4) {
    send_fail(sptr, "BOUNCER", "NEED_PARAM", "SET",
              "Missing required parameter");
    return 0;
  }

  if (0 == ircd_strcmp(parv[2], "HOLD")) {
    /* Account-wide hold preference - stored in metadata */
    if (0 == ircd_strcmp(parv[3], "on")) {
      metadata_set_client(sptr, "bouncer/hold", "1", METADATA_VIS_PRIVATE);

      /* Auto-create session if this client doesn't own one — turning hold on
       * should be sufficient to get bouncer behavior without needing TOKEN.
       * Use bounce_get_session(sptr) instead of bounce_has_sessions() so that
       * stale sessions (whose primaries haven't been cleaned up yet) don't
       * prevent this client from getting its own session. */
      if (!bounce_get_session(sptr)) {
        struct BouncerSession *session = NULL;
        if (bounce_create(sptr, &session) == 0 && session) {
          bounce_broadcast(session, 'C', NULL);

          send_note(sptr, "BOUNCER", "SESSION_CREATED", session->hs_sessid,
                    "Hold mode enabled, session created");
        } else {
          send_note(sptr, "BOUNCER", "SETTINGS_UPDATED", NULL,
                    "Hold mode enabled (session limit reached)");
        }
      } else {
        send_note(sptr, "BOUNCER", "SETTINGS_UPDATED", NULL,
                  "Hold mode enabled");
      }
    } else if (0 == ircd_strcmp(parv[3], "off")) {
      metadata_set_client(sptr, "bouncer/hold", "0", METADATA_VIS_PRIVATE);

      /* Fix #24: Active teardown — user no longer wants bouncer behavior.
       * Destroy the session (disconnects all aliases) so the primary
       * continues as a normal non-bounced IRC client. */
      {
        struct BouncerSession *session = bounce_get_session(sptr);
        if (session) {
          /* Detach primary before destroy so exit_one_client doesn't
           * try to clean up a destroyed session later. */
          session->hs_client = NULL;
          bounce_broadcast(session, 'X', NULL);
          bounce_destroy(session);
        }
      }

      send_note(sptr, "BOUNCER", "SETTINGS_UPDATED", NULL,
                "Hold mode disabled");
    } else {
      send_fail(sptr, "BOUNCER", "NEED_PARAM", "SET",
                "Value must be 'on' or 'off'");
    }
    return 0;
  }

  if (0 == ircd_strcmp(parv[2], "SESSION")) {
    /* Per-session override */
    struct AccountSessions *as;
    struct BouncerSession *s;

    if (parc < 6) {
      send_fail(sptr, "BOUNCER", "NEED_PARAM", "SET",
                "Usage: BOUNCER SET SESSION <id> HOLD on|off");
      return 0;
    }

    as = bounce_find_by_account(cli_account(sptr));
    if (!as)
      goto notfound;

    for (s = as->as_sessions; s; s = s->hs_anext) {
      if (0 == strcmp(s->hs_sessid, parv[3])) {
        if (0 == ircd_strcmp(parv[5], "on"))
          s->hs_hold_override = 1;
        else if (0 == ircd_strcmp(parv[5], "off"))
          s->hs_hold_override = 0;
        else {
          send_fail(sptr, "BOUNCER", "NEED_PARAM", "SET",
                    "Value must be 'on' or 'off'");
          return 0;
        }
        send_note(sptr, "BOUNCER", "SETTINGS_UPDATED", parv[3],
                  "Session preference updated");
        return 0;
      }
    }

notfound:
    send_fail(sptr, "BOUNCER", "NO_SUCH_SESSION", parv[3],
              "No such session");
    return 0;
  }

  send_fail(sptr, "BOUNCER", "NEED_PARAM", "SET",
            "Unknown setting");
  return 0;
}

/* ---------------------------------------------------------------- */
/* Subcommand: SETTINGS                                              */
/* ---------------------------------------------------------------- */

/** Handle BOUNCER SETTINGS - show current preferences. */
static int bouncer_settings(struct Client *sptr)
{
  int hold;
  int count;
  const char *hold_src = "default";

  if (!IsAccount(sptr)) {
    send_fail(sptr, "BOUNCER", "ACCOUNT_REQUIRED", NULL,
              "You must be logged in to use bouncer features");
    return 0;
  }

  /* Check hold preference — read from persistent (mdbx) store */
  if (IsBncHoldPref(sptr)) {
    hold = 1;
    hold_src = "mode";
  } else {
    char hold_val[64];
    if (metadata_account_get(cli_account(sptr), "bouncer/hold", hold_val) == 0) {
      hold = (hold_val[0] == '1') ? 1 : 0;
      hold_src = "account";
    } else {
      /* Bouncer class defaults to hold; normal class follows feature flag */
      struct ConnectionClass *cls = get_client_class_conf(sptr);
      if (cls && FlagHas(&cls->restrictflags, CRFLAG_BOUNCER)) {
        hold = 1;
        hold_src = "class";
      } else {
        hold = feature_bool(FEAT_BOUNCER_DEFAULT_HOLD);
      }
    }
  }

  count = bounce_count(cli_account(sptr));

  sendrawto_one(sptr, ":%s %d %s :hold=%s(%s) sessions=%d max=%d hold_time=%d",
                cli_name(&me), RPL_BOUNCERSETTINGS, cli_name(sptr),
                hold ? "on" : "off", hold_src,
                count,
                feature_int(FEAT_BOUNCER_MAX_SESSIONS),
                feature_int(FEAT_BOUNCER_SESSION_HOLD));

  return 0;
}

/* ---------------------------------------------------------------- */
/* Subcommand: INFO                                                  */
/* ---------------------------------------------------------------- */

/** Handle BOUNCER LISTCLIENTS - list all connections for the session.
 * Shows primary + alias connections with client IDs, away state,
 * connect time, and IP address.
 *
 * Reply format uses NOTE:
 *   :server NOTE BOUNCER CLIENT id=N type=primary|alias state=present|away since=TIMESTAMP ip=ADDR
 *   :server NOTE BOUNCER LISTCLIENTS_END :End of client list
 */
static int bouncer_listclients(struct Client *sptr)
{
  struct BouncerSession *session;
  const char *state_str;
  char info[512];
  int i;
  int count;

  if (!IsAccount(sptr)) {
    send_fail(sptr, "BOUNCER", "ACCOUNT_REQUIRED", "LISTCLIENTS",
              "You must be logged in to use bouncer features");
    return 0;
  }

  session = bounce_get_session(sptr);
  if (!session) {
    send_fail(sptr, "BOUNCER", "NO_SESSION", "LISTCLIENTS",
              "No active bouncer session");
    return 0;
  }

  count = 0;

  /* Primary connection */
  if (session->hs_client && session->hs_state == BOUNCE_ACTIVE) {
    int away_state = 0;
    if (cli_user(session->hs_client)->away) {
      away_state = 1;
    }
    state_str = away_state ? "away" : "present";
    ircd_snprintf(0, info, sizeof(info),
                  "type=primary state=%s since=%lu ip=%s",
                  state_str,
                  (unsigned long)cli_firsttime(session->hs_client),
                  cli_sock_ip(session->hs_client));
    send_note(sptr, "BOUNCER", "CLIENT", session->hs_sessid, info);
    count++;
  }

  /* Alias connections */
  for (i = 0; i < session->hs_alias_count; i++) {
    struct Client *alias = findNUser(session->hs_aliases[i].ba_numeric);
    if (!alias)
      continue;
    state_str = (cli_user(alias) && cli_user(alias)->away) ? "away" : "present";
    ircd_snprintf(0, info, sizeof(info),
                  "id=%d type=alias state=%s since=%lu ip=%s server=%s",
                  i + 1,
                  state_str,
                  (unsigned long)cli_firsttime(alias),
                  cli_sock_ip(alias),
                  session->hs_aliases[i].ba_server);
    send_note(sptr, "BOUNCER", "CLIENT", session->hs_sessid, info);
    count++;
  }

  {
    char end_msg[128];
    ircd_snprintf(0, end_msg, sizeof(end_msg),
                  "End of client list (%d connections)",
                  count);
    send_note(sptr, "BOUNCER", "LISTCLIENTS_END", session->hs_sessid, end_msg);
  }

  return 0;
}

/* ---------------------------------------------------------------- */

/** Handle BOUNCER INFO - show session state and preferences.
 * Combines session status and hold preferences in a single view.
 * This is the primary user-facing read-only command.
 */
static int bouncer_info(struct Client *sptr)
{
  struct AccountSessions *as;
  struct BouncerSession *s;
  int hold;
  const char *hold_src = "default";

  if (!IsAccount(sptr)) {
    send_fail(sptr, "BOUNCER", "ACCOUNT_REQUIRED", NULL,
              "You must be logged in to use bouncer features");
    return 0;
  }

  /* Determine hold preference — read from persistent (mdbx) store,
   * not cli_metadata which may not be populated after a restart. */
  if (IsBncHoldPref(sptr)) {
    hold = 1;
    hold_src = "account";
  } else {
    char hold_val[64];
    if (metadata_account_get(cli_account(sptr), "bouncer/hold", hold_val) == 0) {
      hold = (hold_val[0] == '1') ? 1 : 0;
      hold_src = "account";
    } else {
      /* Bouncer class defaults to hold; normal class follows feature flag */
      struct ConnectionClass *cls = get_client_class_conf(sptr);
      if (cls && FlagHas(&cls->restrictflags, CRFLAG_BOUNCER)) {
        hold = 1;
        hold_src = "class";
      } else {
        hold = feature_bool(FEAT_BOUNCER_DEFAULT_HOLD);
      }
    }
  }

  as = bounce_find_by_account(cli_account(sptr));

  /* Session state */
  if (as && as->as_count > 0) {
    s = as->as_sessions;
    if (s) {
      const char *state_str = (s->hs_state == BOUNCE_ACTIVE)
                              ? "active" : "holding";
      char info[512];

      if (s->hs_state == BOUNCE_HOLDING && s->hs_disconnect_time) {
        time_t hold_time = bounce_compute_hold_time_ext(s);
        time_t remaining = hold_time -
                           (CurrentTime - s->hs_disconnect_time);
        if (remaining < 0)
          remaining = 0;
        ircd_snprintf(0, info, sizeof(info),
                      "state=%s hold=%s(%s) connects=%u "
                      "hold_time=%ldm session=%s",
                      state_str,
                      hold ? "on" : "off", hold_src,
                      s->hs_connect_count,
                      (long)(remaining / 60),
                      s->hs_sessid);
      } else {
        time_t hold_time = bounce_compute_hold_time_ext(s);
        ircd_snprintf(0, info, sizeof(info),
                      "state=%s hold=%s(%s) connects=%u "
                      "hold_time=%lds live=%d session=%s",
                      state_str,
                      hold ? "on" : "off", hold_src,
                      s->hs_connect_count,
                      (long)hold_time,
                      bounce_connection_count(s),
                      s->hs_sessid);
      }

      sendrawto_one(sptr, ":%s %d %s :%s",
                    cli_name(&me), RPL_BOUNCERSETTINGS, cli_name(sptr),
                    info);
    }
  } else {
    /* No session */
    char info[256];
    ircd_snprintf(0, info, sizeof(info),
                  "state=none hold=%s(%s)",
                  hold ? "on" : "off", hold_src);
    sendrawto_one(sptr, ":%s %d %s :%s",
                  cli_name(&me), RPL_BOUNCERSETTINGS, cli_name(sptr),
                  info);
  }

  return 0;
}

/* ---------------------------------------------------------------- */
/* Subcommand: HISTORY                                               */
/* ---------------------------------------------------------------- */

/** Handle BOUNCER HISTORY - show connection history for the session.
 * Available to the session owner and opers.
 *
 * Reply format uses NOTE:
 *   :server NOTE BOUNCER CONN_HISTORY sessid :ip=ADDR host=HOST connects=N last_connect=TS last_disconnect=TS
 *   :server NOTE BOUNCER HISTORY_END sessid :End of connection history
 */
static int bouncer_history(struct Client *sptr, int parc, char *parv[])
{
  struct BouncerSession *session = NULL;
  int i;
  char info[512];

  if (!IsAccount(sptr)) {
    send_fail(sptr, "BOUNCER", "ACCOUNT_REQUIRED", "HISTORY",
              "You must be logged in to use bouncer features");
    return 0;
  }

  /* Opers can specify a nick as parv[2] to view another user's history */
  if (parc >= 3 && (IsOper(sptr) || IsAnOper(sptr))) {
    struct Client *target = FindUser(parv[2]);
    if (!target) {
      send_fail(sptr, "BOUNCER", "NO_SUCH_NICK", parv[2],
                "No such nick");
      return 0;
    }
    session = bounce_get_session(target);
    if (!session && IsAccount(target)) {
      struct AccountSessions *as = bounce_find_by_account(cli_account(target));
      if (as && as->as_sessions)
        session = as->as_sessions;
    }
    if (!session) {
      send_fail(sptr, "BOUNCER", "NO_SESSION", parv[2],
                "No bouncer session for that user");
      return 0;
    }
  } else {
    /* Find own session */
    session = bounce_get_session(sptr);
    if (!session) {
      /* Check if we have a HOLDING session for this account */
      struct AccountSessions *as = bounce_find_by_account(cli_account(sptr));
      if (as && as->as_sessions)
        session = as->as_sessions;
    }
    if (!session) {
      send_fail(sptr, "BOUNCER", "NO_SESSION", "HISTORY",
                "No active bouncer session");
      return 0;
    }
  }

  for (i = 0; i < session->hs_histcount; i++) {
    struct BounceConnHistory *h = &session->hs_history[i];
    if (h->bch_last_disconnect) {
      ircd_snprintf(0, info, sizeof(info),
                    "ip=%s host=%s connects=%u last_connect=%lu last_disconnect=%lu",
                    h->bch_ip, h->bch_host, h->bch_count,
                    (unsigned long)h->bch_last_connect,
                    (unsigned long)h->bch_last_disconnect);
    } else {
      ircd_snprintf(0, info, sizeof(info),
                    "ip=%s host=%s connects=%u last_connect=%lu status=connected",
                    h->bch_ip, h->bch_host, h->bch_count,
                    (unsigned long)h->bch_last_connect);
    }
    send_note(sptr, "BOUNCER", "CONN_HISTORY", session->hs_sessid, info);
  }

  if (session->hs_histcount == 0) {
    send_note(sptr, "BOUNCER", "HISTORY_END", session->hs_sessid,
              "No connection history");
  } else {
    ircd_snprintf(0, info, sizeof(info),
                  "End of connection history (%d hosts)",
                  session->hs_histcount);
    send_note(sptr, "BOUNCER", "HISTORY_END", session->hs_sessid, info);
  }

  return 0;
}

/* ---------------------------------------------------------------- */
/* Main command handler                                              */
/* ---------------------------------------------------------------- */

/** Handle BOUNCER command from a local client.
 *
 * User commands: SET, INFO, LISTCLIENTS, HISTORY
 * Oper-only: TOKEN, RESUME, LISTSESSIONS, DISCONNECT, SETNAME, SETTINGS
 *
 * @param[in] cptr Connected client.
 * @param[in] sptr Source client.
 * @param[in] parc Number of parameters.
 * @param[in] parv Parameters.
 * @return 0 on success.
 */
int m_bouncer(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  const char *subcmd;

  if (!bounce_enabled_for(sptr)) {
    send_fail(sptr, "BOUNCER", "DISABLED", NULL,
              "Bouncer feature is not enabled");
    return 0;
  }

  if (parc < 2) {
    send_fail(sptr, "BOUNCER", "NEED_PARAM", NULL,
              "Usage: BOUNCER <subcommand> [args]");
    return 0;
  }

  subcmd = parv[1];

  /* --- User-facing commands --- */

  if (0 == ircd_strcmp(subcmd, "SET"))
    return bouncer_set(sptr, parc, parv);

  if (0 == ircd_strcmp(subcmd, "INFO"))
    return bouncer_info(sptr);

  if (0 == ircd_strcmp(subcmd, "LISTCLIENTS"))
    return bouncer_listclients(sptr);

  if (0 == ircd_strcmp(subcmd, "HISTORY"))
    return bouncer_history(sptr, parc, parv);

  /* --- Oper-only commands (admin/testing) --- */

  if (0 == ircd_strcmp(subcmd, "TOKEN")) {
    if (!IsOper(sptr) && !IsAnOper(sptr)) {
      send_fail(sptr, "BOUNCER", "NOPRIVS", "TOKEN",
                "Insufficient privileges");
      return 0;
    }
    return bouncer_token(sptr);
  }

  if (0 == ircd_strcmp(subcmd, "RESUME")) {
    if (!IsOper(sptr) && !IsAnOper(sptr)) {
      send_fail(sptr, "BOUNCER", "NOPRIVS", "RESUME",
                "Insufficient privileges");
      return 0;
    }
    if (parc < 3) {
      send_fail(sptr, "BOUNCER", "NEED_PARAM", "RESUME",
                "Missing token");
      return 0;
    }
    return bouncer_resume(sptr, parv[2]);
  }

  if (0 == ircd_strcmp(subcmd, "LISTSESSIONS")) {
    if (!IsOper(sptr) && !IsAnOper(sptr)) {
      send_fail(sptr, "BOUNCER", "NOPRIVS", "LISTSESSIONS",
                "Insufficient privileges");
      return 0;
    }
    return bouncer_listsessions(sptr);
  }

  if (0 == ircd_strcmp(subcmd, "DISCONNECT")) {
    if (!IsOper(sptr) && !IsAnOper(sptr)) {
      send_fail(sptr, "BOUNCER", "NOPRIVS", "DISCONNECT",
                "Insufficient privileges");
      return 0;
    }
    return bouncer_disconnect(sptr, (parc >= 3) ? parv[2] : NULL);
  }

  if (0 == ircd_strcmp(subcmd, "SETNAME")) {
    if (!IsOper(sptr) && !IsAnOper(sptr)) {
      send_fail(sptr, "BOUNCER", "NOPRIVS", "SETNAME",
                "Insufficient privileges");
      return 0;
    }
    return bouncer_setname(sptr,
                           (parc >= 3) ? parv[2] : NULL,
                           (parc >= 4) ? parv[3] : NULL);
  }

  if (0 == ircd_strcmp(subcmd, "SETTINGS")) {
    if (!IsOper(sptr) && !IsAnOper(sptr)) {
      send_fail(sptr, "BOUNCER", "NOPRIVS", "SETTINGS",
                "Insufficient privileges");
      return 0;
    }
    return bouncer_settings(sptr);
  }

  send_fail(sptr, "BOUNCER", "NEED_PARAM", NULL,
            "Unknown subcommand");
  return 0;
}

/* ---------------------------------------------------------------- */
/* S2S handler for BS token                                          */
/* ---------------------------------------------------------------- */

/** Handle BS (Bouncer Session) P10 token from server.
 * Delegates to bounce_handle_bs() in bouncer_session.c.
 */
int ms_bouncer_session(struct Client *cptr, struct Client *sptr,
                       int parc, char *parv[])
{
  return bounce_handle_bs(cptr, sptr, parc, parv);
}

/* ---------------------------------------------------------------- */
/* S2S handler for BT token                                          */
/* ---------------------------------------------------------------- */

/** Handle BT (Bouncer Transfer) P10 token from server.
 * Delegates to bounce_handle_bt() in bouncer_session.c.
 */
int ms_bouncer_transfer(struct Client *cptr, struct Client *sptr,
                        int parc, char *parv[])
{
  return bounce_handle_bt(cptr, sptr, parc, parv);
}
