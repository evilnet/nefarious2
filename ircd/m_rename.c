/*
 * IRC - Internet Relay Chat, ircd/m_rename.c
 * Copyright (C) 2024 Nefarious Development Team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
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
 * @brief Handler for RENAME command (IRCv3 draft/channel-rename).
 *
 * Specification: https://ircv3.net/specs/extensions/channel-rename
 *
 * RENAME <oldchannel> <newchannel> [:<reason>]
 *
 * Renames a channel while preserving all state (members, modes, bans, etc).
 */
#include "config.h"

#include "capab.h"
#include "channel.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_user.h"
#include "send.h"

#include <string.h>
#include <stdlib.h>

/** Send RENAME to clients with the capability, fallback PART/JOIN to others.
 * @param[in] sptr Client that initiated the rename.
 * @param[in] chptr Channel being renamed (already has new name).
 * @param[in] oldname The old channel name.
 * @param[in] reason Reason for rename (may be empty string).
 */
static void send_rename_to_members(struct Client *sptr, struct Channel *chptr,
                                   const char *oldname, const char *reason)
{
  struct Membership *member;
  struct Client *acptr;

  for (member = chptr->members; member; member = member->next_member) {
    acptr = member->user;

    if (!MyUser(acptr))
      continue;

    if (CapActive(acptr, CAP_DRAFT_CHANRENAME)) {
      /* Client supports draft/channel-rename - send RENAME */
      sendcmdto_one(sptr, CMD_RENAME, acptr, "%s %s :%s",
                    oldname, chptr->chname, reason ? reason : "");
    } else {
      /* Client doesn't support it - send PART/JOIN fallback */
      /* Send PART from old channel */
      sendcmdto_one(acptr, CMD_PART, acptr, "%s :Channel renamed to %s%s%s",
                    oldname, chptr->chname,
                    (reason && *reason) ? ": " : "",
                    (reason && *reason) ? reason : "");

      /* Send JOIN to new channel */
      sendcmdto_one(acptr, CMD_JOIN, acptr, "%s", chptr->chname);

      /* Send topic if set */
      if (chptr->topic[0]) {
        send_reply(acptr, RPL_TOPIC, chptr->chname, chptr->topic);
        send_reply(acptr, RPL_TOPICWHOTIME, chptr->chname, chptr->topic_nick,
                   chptr->topic_time);
      }

      /* Send NAMES list with End Of Names */
      do_names(acptr, chptr, NAMES_ALL|NAMES_EON);
    }
  }
}

/** m_rename - Handle RENAME command from local client.
 *
 * parv[0] = sender prefix
 * parv[1] = old channel name
 * parv[2] = new channel name
 * parv[3] = reason (optional, trailing)
 *
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int m_rename(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct Channel *chptr;
  struct Membership *member;
  const char *oldname;
  const char *newname;
  const char *reason;
  char oldname_buf[CHANNELLEN + 1];
  int rc;

  /* Must have draft/channel-rename capability */
  if (!CapActive(sptr, CAP_DRAFT_CHANRENAME)) {
    return send_reply(sptr, ERR_UNKNOWNCOMMAND, "RENAME");
  }

  /* Need at least old and new channel names */
  if (parc < 3 || EmptyString(parv[1]) || EmptyString(parv[2])) {
    return send_reply(sptr, ERR_NEEDMOREPARAMS, "RENAME");
  }

  oldname = parv[1];
  newname = parv[2];
  reason = (parc > 3 && !EmptyString(parv[3])) ? parv[3] : "";

  /* Check if old channel exists */
  chptr = FindChannel(oldname);
  if (!chptr) {
    return send_reply(sptr, ERR_NOSUCHCHANNEL, oldname);
  }

  /* Check if user is on the channel */
  member = find_channel_member(sptr, chptr);
  if (!member) {
    return send_reply(sptr, ERR_NOTONCHANNEL, oldname);
  }

  /* Check if user is a channel operator */
  if (!IsChanOp(member)) {
    return send_reply(sptr, ERR_CHANOPRIVSNEEDED, oldname);
  }

  /* Validate new channel name */
  if (!IsChannelName(newname)) {
    send_fail(sptr, "RENAME", "CANNOT_RENAME", oldname,
              "Invalid channel name");
    return 0;
  }

  /* Check if new channel name already exists */
  if (FindChannel(newname)) {
    send_fail(sptr, "RENAME", "CHANNEL_NAME_IN_USE", oldname,
              "Channel name already in use");
    return 0;
  }

  /* Store old name before rename */
  ircd_strncpy(oldname_buf, chptr->chname, CHANNELLEN);
  oldname_buf[CHANNELLEN] = '\0';

  /* Perform the rename */
  rc = rename_channel(chptr, newname);
  if (rc == -1) {
    send_fail(sptr, "RENAME", "CANNOT_RENAME", oldname,
              "New channel name is too long");
    return 0;
  } else if (rc == -2) {
    send_fail(sptr, "RENAME", "CHANNEL_NAME_IN_USE", oldname,
              "Channel name already in use");
    return 0;
  }

  /* Send to local channel members */
  send_rename_to_members(sptr, chptr, oldname_buf, reason);

  /* Propagate to other servers */
  sendcmdto_serv_butone(sptr, CMD_RENAME, cptr, "%s %s :%s",
                        oldname_buf, chptr->chname, reason);

  return 0;
}

/** ms_rename - Handle RENAME command from a server.
 *
 * parv[0] = sender prefix (numeric)
 * parv[1] = old channel name
 * parv[2] = new channel name
 * parv[3] = reason (optional, trailing)
 *
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int ms_rename(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct Channel *chptr;
  const char *oldname;
  const char *newname;
  const char *reason;
  char oldname_buf[CHANNELLEN + 1];
  int rc;

  /* Need at least old and new channel names */
  if (parc < 3 || EmptyString(parv[1]) || EmptyString(parv[2])) {
    return 0; /* Silently ignore malformed S2S messages */
  }

  oldname = parv[1];
  newname = parv[2];
  reason = (parc > 3 && !EmptyString(parv[3])) ? parv[3] : "";

  /* Find the channel */
  chptr = FindChannel(oldname);
  if (!chptr) {
    return 0; /* Channel doesn't exist on this server */
  }

  /* Store old name before rename */
  ircd_strncpy(oldname_buf, chptr->chname, CHANNELLEN);
  oldname_buf[CHANNELLEN] = '\0';

  /* Perform the rename */
  rc = rename_channel(chptr, newname);
  if (rc != 0) {
    /* Rename failed - log and continue */
    log_write(LS_DEBUG, L_ERROR, 0,
              "RENAME failed from %#C: %s -> %s (rc=%d)",
              sptr, oldname, newname, rc);
    return 0;
  }

  /* Send to local channel members */
  send_rename_to_members(sptr, chptr, oldname_buf, reason);

  /* Propagate to other servers */
  sendcmdto_serv_butone(sptr, CMD_RENAME, cptr, "%s %s :%s",
                        oldname_buf, chptr->chname, reason);

  return 0;
}
