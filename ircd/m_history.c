/*
 * IRC - Internet Relay Chat, ircd/m_history.c
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

/**
 * @file
 * @brief Handler for HISTORY command - convenience wrapper for history settings.
 *
 * HISTORY SET/GET allows clients without METADATA capability to configure
 * channel history access control settings. Internally stores as channel metadata.
 *
 * Commands:
 *   HISTORY SET #channel ACCESS <none|kick-gap|membership>
 *   HISTORY SET #channel LIMIT <number>  (IRCops only)
 *   HISTORY SET #channel QUOTA <0-100>
 *   HISTORY GET #channel ACCESS
 *   HISTORY GET #channel LIMIT
 *   HISTORY GET #channel QUOTA
 */
#include "config.h"

#include "channel.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "metadata.h"
#include "msg.h"
#include "numeric.h"
#include "send.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <stdlib.h>
#include <string.h>

/** Check if user has permission to modify channel history settings.
 * @param[in] sptr Client to check.
 * @param[in] chptr Channel to check.
 * @param[in] setting Setting being modified (for ircop-only checks).
 * @return 0 if allowed, -1 if not.
 */
static int check_history_permission(struct Client *sptr, struct Channel *chptr,
                                     const char *setting)
{
  struct Membership *member;

  /* LIMIT is IRCop-only */
  if (setting && ircd_strcmp(setting, "LIMIT") == 0) {
    if (!IsOper(sptr) && !IsAnOper(sptr)) {
      send_reply(sptr, ERR_NOPRIVILEGES);
      return -1;
    }
    return 0;
  }

  /* IRCops can always modify */
  if (IsOper(sptr) || IsAnOper(sptr))
    return 0;

  /* Check if user is channel op */
  member = find_member_link(chptr, sptr);
  if (!member) {
    send_reply(sptr, ERR_NOTONCHANNEL, chptr->chname);
    return -1;
  }

  if (!IsChanOp(member)) {
    send_reply(sptr, ERR_CHANOPRIVSNEEDED, chptr->chname);
    return -1;
  }

  return 0;
}

/** Handle HISTORY SET subcommand.
 * @param[in] sptr Client sending the command.
 * @param[in] chptr Target channel.
 * @param[in] setting Setting name (ACCESS, LIMIT, QUOTA).
 * @param[in] value New value.
 * @return 0 on success.
 */
static int history_set(struct Client *sptr, struct Channel *chptr,
                        const char *setting, const char *value)
{
  char metadata_key[64];
  char metadata_value[64];
  int num_value;

  if (!setting || !*setting || !value || !*value) {
    send_reply(sptr, ERR_NEEDMOREPARAMS, "HISTORY SET");
    return 0;
  }

  if (check_history_permission(sptr, chptr, setting) != 0)
    return 0;

  if (ircd_strcmp(setting, "ACCESS") == 0) {
    /* Validate access mode */
    if (ircd_strcmp(value, "none") != 0 &&
        ircd_strcmp(value, "kick-gap") != 0 &&
        ircd_strcmp(value, "membership") != 0) {
      sendcmdto_one(&me, CMD_NOTICE, sptr,
                    "%C :HISTORY: Invalid ACCESS value. Use: none, kick-gap, or membership",
                    sptr);
      return 0;
    }

    ircd_strncpy(metadata_key, "history.access", sizeof(metadata_key) - 1);
    ircd_strncpy(metadata_value, value, sizeof(metadata_value) - 1);
  }
  else if (ircd_strcmp(setting, "LIMIT") == 0) {
    /* Validate limit (IRCops only - already checked in check_history_permission) */
    num_value = atoi(value);
    if (num_value <= 0 || num_value > 1000000) {
      sendcmdto_one(&me, CMD_NOTICE, sptr,
                    "%C :HISTORY: Invalid LIMIT value. Must be 1-1000000",
                    sptr);
      return 0;
    }

    ircd_strncpy(metadata_key, "history.limit", sizeof(metadata_key) - 1);
    ircd_snprintf(0, metadata_value, sizeof(metadata_value), "%d", num_value);
  }
  else if (ircd_strcmp(setting, "QUOTA") == 0) {
    /* Validate quota percentage */
    num_value = atoi(value);
    if (num_value < 0 || num_value > 100) {
      sendcmdto_one(&me, CMD_NOTICE, sptr,
                    "%C :HISTORY: Invalid QUOTA value. Must be 0-100",
                    sptr);
      return 0;
    }

    ircd_strncpy(metadata_key, "history.quota", sizeof(metadata_key) - 1);
    ircd_snprintf(0, metadata_value, sizeof(metadata_value), "%d", num_value);
  }
  else {
    sendcmdto_one(&me, CMD_NOTICE, sptr,
                  "%C :HISTORY: Unknown setting. Use: ACCESS, LIMIT, or QUOTA",
                  sptr);
    return 0;
  }

  /* Set the metadata */
  if (metadata_set_channel(chptr, metadata_key, metadata_value, 0) == 0) {
    sendcmdto_one(&me, CMD_NOTICE, sptr,
                  "%C :HISTORY: %s %s set to %s",
                  sptr, chptr->chname, setting, metadata_value);

    /* Broadcast to other servers */
    sendcmdto_serv_butone(&me, CMD_METADATA, NULL, "%s %s :%s",
                          chptr->chname, metadata_key, metadata_value);
  } else {
    sendcmdto_one(&me, CMD_NOTICE, sptr,
                  "%C :HISTORY: Failed to set %s",
                  sptr, setting);
  }

  return 0;
}

/** Handle HISTORY GET subcommand.
 * @param[in] sptr Client sending the command.
 * @param[in] chptr Target channel.
 * @param[in] setting Setting name (ACCESS, LIMIT, QUOTA).
 * @return 0 on success.
 */
static int history_get(struct Client *sptr, struct Channel *chptr,
                        const char *setting)
{
  struct MetadataEntry *entry;
  char metadata_key[64];
  const char *value;
  const char *default_value = NULL;

  if (!setting || !*setting) {
    send_reply(sptr, ERR_NEEDMOREPARAMS, "HISTORY GET");
    return 0;
  }

  if (ircd_strcmp(setting, "ACCESS") == 0) {
    ircd_strncpy(metadata_key, "history.access", sizeof(metadata_key) - 1);
    /* Default based on feature flag */
    switch (feature_int(FEAT_CHATHISTORY_DEFAULT_ACCESS)) {
      case 0:  default_value = "none"; break;
      case 2:  default_value = "membership"; break;
      default: default_value = "kick-gap"; break;
    }
  }
  else if (ircd_strcmp(setting, "LIMIT") == 0) {
    ircd_strncpy(metadata_key, "history.limit", sizeof(metadata_key) - 1);
    default_value = "(server default)";
  }
  else if (ircd_strcmp(setting, "QUOTA") == 0) {
    ircd_strncpy(metadata_key, "history.quota", sizeof(metadata_key) - 1);
    default_value = "(server default)";
  }
  else {
    sendcmdto_one(&me, CMD_NOTICE, sptr,
                  "%C :HISTORY: Unknown setting. Use: ACCESS, LIMIT, or QUOTA",
                  sptr);
    return 0;
  }

  /* Get the metadata */
  entry = metadata_get_channel(chptr, metadata_key);
  if (entry && entry->value)
    value = entry->value;
  else
    value = default_value;

  sendcmdto_one(&me, CMD_NOTICE, sptr,
                "%C :HISTORY: %s %s = %s",
                sptr, chptr->chname, setting, value);

  return 0;
}

/** Handle HISTORY command from a local client.
 * @param[in] cptr Connection that sent the command.
 * @param[in] sptr Client that sent the command.
 * @param[in] parc Number of parameters.
 * @param[in] parv Parameters.
 * @return 0 on success.
 *
 * Usage:
 *   HISTORY SET #channel <setting> <value>
 *   HISTORY GET #channel <setting>
 */
int m_history(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  const char *subcmd;
  const char *target;
  struct Channel *chptr;

  assert(cptr == sptr);

  if (parc < 3) {
    sendcmdto_one(&me, CMD_NOTICE, sptr,
                  "%C :Usage: HISTORY SET|GET #channel <setting> [value]",
                  sptr);
    return 0;
  }

  subcmd = parv[1];
  target = parv[2];

  /* Must be a channel */
  if (!IsChannelName(target)) {
    sendcmdto_one(&me, CMD_NOTICE, sptr,
                  "%C :HISTORY: Target must be a channel",
                  sptr);
    return 0;
  }

  chptr = FindChannel(target);
  if (!chptr) {
    send_reply(sptr, ERR_NOSUCHCHANNEL, target);
    return 0;
  }

  if (ircd_strcmp(subcmd, "SET") == 0) {
    if (parc < 5) {
      sendcmdto_one(&me, CMD_NOTICE, sptr,
                    "%C :Usage: HISTORY SET #channel <ACCESS|LIMIT|QUOTA> <value>",
                    sptr);
      return 0;
    }
    return history_set(sptr, chptr, parv[3], parv[4]);
  }
  else if (ircd_strcmp(subcmd, "GET") == 0) {
    if (parc < 4) {
      sendcmdto_one(&me, CMD_NOTICE, sptr,
                    "%C :Usage: HISTORY GET #channel <ACCESS|LIMIT|QUOTA>",
                    sptr);
      return 0;
    }
    return history_get(sptr, chptr, parv[3]);
  }
  else {
    sendcmdto_one(&me, CMD_NOTICE, sptr,
                  "%C :HISTORY: Unknown subcommand. Use: SET or GET",
                  sptr);
    return 0;
  }
}
