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
 * Subcommands:
 *   BOUNCER TOKEN          - Request a new session token
 *   BOUNCER RESUME <token> - Resume a session by token
 *   BOUNCER LISTSESSIONS   - List sessions for current account
 *   BOUNCER DISCONNECT <id>- Disconnect/destroy a session
 *   BOUNCER SETNAME <id> <name> - Name a session
 *   BOUNCER SET HOLD [on|off]   - Set hold preference
 *   BOUNCER SETTINGS       - Show current settings
 */
#include "config.h"

#include "bouncer_session.h"
#include "capab.h"
#include "channel.h"
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

/** Check if a PM target (nick1:nick2 format) involves the given client.
 * @param[in] target PM target in nick1:nick2 format.
 * @param[in] cptr Client to check.
 * @return 1 if client's nick matches one of the nicks, 0 otherwise.
 */
static int is_pm_target_for_client(const char *target, struct Client *cptr)
{
  const char *colon = strchr(target, ':');
  const char *mynick = cli_name(cptr);
  size_t mynick_len, nick1_len;

  if (!colon)
    return 0;

  mynick_len = strlen(mynick);
  nick1_len = colon - target;

  /* Check if first nick matches */
  if (nick1_len == mynick_len && ircd_strncmp(target, mynick, nick1_len) == 0)
    return 1;

  /* Check if second nick matches */
  if (ircd_strcmp(colon + 1, mynick) == 0)
    return 1;

  return 0;
}

/** Auto-replay chathistory to legacy clients after resume.
 * For clients that don't support draft/chathistory, this function
 * automatically replays missed messages since disconnection.
 */
void bouncer_auto_replay(struct Client *sptr, struct BouncerSession *session)
{
  struct Membership *member;
  struct HistoryTarget *targets = NULL;
  struct HistoryTarget *tgt;
  int limit;
  int total_replayed = 0;
  int chan_count = 0;
  int pm_count = 0;
  char timestamp[HISTORY_TIMESTAMP_LEN];
  char now_timestamp[HISTORY_TIMESTAMP_LEN];

  /* Check if auto-replay is enabled */
  if (!feature_bool(FEAT_BOUNCER_AUTO_REPLAY))
    return;

  /* Need a valid disconnect time to know what to replay */
  if (session->hs_disconnect_time == 0)
    return;

  /* Convert disconnect_time to timestamp string (seconds.000 format) */
  ircd_snprintf(0, timestamp, sizeof(timestamp), "%lu.000",
                (unsigned long)session->hs_disconnect_time);

  /* Current timestamp for PM target query range */
  ircd_snprintf(0, now_timestamp, sizeof(now_timestamp), "%lu.000",
                (unsigned long)CurrentTime);

  limit = feature_int(FEAT_BOUNCER_AUTO_REPLAY_LIMIT);
  if (limit <= 0)
    limit = 100;

  /* Replay history for each channel the user is in */
  for (member = cli_user(sptr)->channel; member; member = member->next_channel) {
    const char *channame = member->channel->chname;
    int count;

    count = chathistory_auto_replay(sptr, channame, timestamp, limit);
    if (count > 0) {
      total_replayed += count;
      chan_count++;
    }
  }

  /* Replay PMs if PM history is enabled */
  if (feature_bool(FEAT_CHATHISTORY_PRIVATE) && IsAccount(sptr)) {
    int target_count;

    /* Query all targets with activity since disconnect */
    target_count = history_query_targets(timestamp, now_timestamp, 50, &targets);

    if (target_count > 0 && targets) {
      for (tgt = targets; tgt; tgt = tgt->next) {
        /* Check if this is a PM target that involves us */
        if (strchr(tgt->target, ':') && is_pm_target_for_client(tgt->target, sptr)) {
          int count = chathistory_auto_replay(sptr, tgt->target, timestamp, limit);
          if (count > 0) {
            total_replayed += count;
            pm_count++;
          }
        }
      }
      history_free_targets(targets);
    }
  }

  /* Send summary to client */
  if (total_replayed > 0) {
    if (pm_count > 0 && chan_count > 0) {
      sendcmdto_one(&me, CMD_NOTICE, sptr,
                    "%C :Session resumed. Replayed %d message(s) from %d channel(s) and %d PM(s).",
                    sptr, total_replayed, chan_count, pm_count);
    } else if (pm_count > 0) {
      sendcmdto_one(&me, CMD_NOTICE, sptr,
                    "%C :Session resumed. Replayed %d message(s) from %d PM(s).",
                    sptr, total_replayed, pm_count);
    } else {
      sendcmdto_one(&me, CMD_NOTICE, sptr,
                    "%C :Session resumed. Replayed %d message(s) from %d channel(s).",
                    sptr, total_replayed, chan_count);
    }
  } else {
    /* No messages to replay - just confirm resume */
    int total_chans = 0;
    for (member = cli_user(sptr)->channel; member; member = member->next_channel)
      total_chans++;
    if (total_chans > 0) {
      sendcmdto_one(&me, CMD_NOTICE, sptr,
                    "%C :Session resumed. You are in %d channel(s). No missed messages.",
                    sptr, total_chans);
    }
  }
}

/** Handle BOUNCER RESUME <token> - resume an existing session. */
static int bouncer_resume(struct Client *sptr, const char *token)
{
  struct BouncerSession *session;
  time_t disconnect_time;
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

  /* Save disconnect time for potential auto-replay */
  disconnect_time = session->hs_disconnect_time;

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

  /* For clients without draft/chathistory, send a hint about how to get
   * missed messages. Full auto-replay could be added later.
   */
  if (!CapActive(sptr, CAP_DRAFT_CHATHISTORY)) {
    bouncer_auto_replay(sptr, session);
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
      ircd_snprintf(0, info, sizeof(info), "%s %s %s %ldm resumes:%u",
                    s->hs_sessid,
                    s->hs_name[0] ? s->hs_name : "*",
                    state_str,
                    (long)(remaining / 60),
                    s->hs_attach_count);
    } else {
      ircd_snprintf(0, info, sizeof(info), "%s %s %s resumes:%u",
                    s->hs_sessid,
                    s->hs_name[0] ? s->hs_name : "*",
                    state_str,
                    s->hs_attach_count);
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
      metadata_set_client(sptr, "$bouncer/hold", "1", METADATA_VIS_PRIVATE);
      send_note(sptr, "BOUNCER", "SETTINGS_UPDATED", NULL,
                "Hold mode enabled");
    } else if (0 == ircd_strcmp(parv[3], "off")) {
      metadata_set_client(sptr, "$bouncer/hold", "0", METADATA_VIS_PRIVATE);
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
  struct MetadataEntry *md;
  const char *hold_src = "default";

  if (!IsAccount(sptr)) {
    send_fail(sptr, "BOUNCER", "ACCOUNT_REQUIRED", NULL,
              "You must be logged in to use bouncer features");
    return 0;
  }

  /* Check hold preference: user mode/metadata > default */
  if (IsBncHoldPref(sptr)) {
    hold = 1;
    hold_src = "mode";
  } else {
    md = metadata_get_client(sptr, "$bouncer/hold");
    if (md && md->value) {
      hold = 0;  /* Explicitly disabled */
      hold_src = "mode";
    } else {
      hold = feature_bool(FEAT_BOUNCER_DEFAULT_HOLD);
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
/* Main command handler                                              */
/* ---------------------------------------------------------------- */

/** Handle BOUNCER command from a local client.
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

  if (!bounce_enabled()) {
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

  if (0 == ircd_strcmp(subcmd, "TOKEN"))
    return bouncer_token(sptr);

  if (0 == ircd_strcmp(subcmd, "RESUME")) {
    if (parc < 3) {
      send_fail(sptr, "BOUNCER", "NEED_PARAM", "RESUME",
                "Missing token");
      return 0;
    }
    return bouncer_resume(sptr, parv[2]);
  }

  if (0 == ircd_strcmp(subcmd, "LISTSESSIONS"))
    return bouncer_listsessions(sptr);

  if (0 == ircd_strcmp(subcmd, "DISCONNECT")) {
    return bouncer_disconnect(sptr, (parc >= 3) ? parv[2] : NULL);
  }

  if (0 == ircd_strcmp(subcmd, "SETNAME")) {
    return bouncer_setname(sptr,
                           (parc >= 3) ? parv[2] : NULL,
                           (parc >= 4) ? parv[3] : NULL);
  }

  if (0 == ircd_strcmp(subcmd, "SET"))
    return bouncer_set(sptr, parc, parv);

  if (0 == ircd_strcmp(subcmd, "SETTINGS"))
    return bouncer_settings(sptr);

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
