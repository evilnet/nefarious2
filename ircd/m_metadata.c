/*
 * IRC - Internet Relay Chat, ircd/m_metadata.c
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
 * @brief Handler for METADATA command (IRCv3 draft/metadata-2).
 *
 * Specification: https://ircv3.net/specs/extensions/metadata
 *
 * Subcommands:
 *   GET <target> <key> [<key>...]
 *   SET <target> <key> [<value>]
 *   LIST <target>
 *   CLEAR <target>
 *   SUB <key> [<key>...]
 *   UNSUB <key> [<key>...]
 *   SUBS
 *   SYNC [<target>]
 */
#include "config.h"

#include "capab.h"
#include "channel.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "metadata.h"
#include "msg.h"
#include "numeric.h"
#include "s_bsd.h"
#include "s_user.h"
#include "send.h"

#include <string.h>
#include <stdlib.h>
#include <ctype.h>

/* Forward declarations */
static int metadata_cmd_get(struct Client *sptr, int parc, char *parv[]);
static int metadata_cmd_set(struct Client *sptr, int parc, char *parv[]);
static int metadata_cmd_list(struct Client *sptr, int parc, char *parv[]);
static int metadata_cmd_clear(struct Client *sptr, int parc, char *parv[]);
static int metadata_cmd_sub(struct Client *sptr, int parc, char *parv[]);
static int metadata_cmd_unsub(struct Client *sptr, int parc, char *parv[]);
static int metadata_cmd_subs(struct Client *sptr, int parc, char *parv[]);
static int metadata_cmd_sync(struct Client *sptr, int parc, char *parv[]);
static void notify_subscribers(const char *target, const char *key, const char *value);

/** Check if key is valid per spec (letters, digits, hyphens, underscores, dots, colons, forward slashes)
 * and doesn't start with a digit.
 */
static int is_valid_key(const char *key)
{
  const char *p;

  if (!key || !*key)
    return 0;

  /* Cannot start with a digit */
  if (isdigit((unsigned char)key[0]))
    return 0;

  /* Check all characters */
  for (p = key; *p; p++) {
    if (!isalnum((unsigned char)*p) && *p != '-' && *p != '_' && *p != '.' && *p != ':' && *p != '/')
      return 0;
  }

  /* Check length */
  if (strlen(key) > METADATA_KEY_LEN)
    return 0;

  return 1;
}

/** Check if client can see metadata on target.
 * @param[in] sptr Client requesting.
 * @param[in] target Target client or channel name.
 * @param[out] is_channel Set to 1 if target is channel.
 * @param[out] target_client Set to target client if user target.
 * @param[out] target_channel Set to target channel if channel target.
 * @return 1 if can view, 0 if not.
 */
static int can_see_target(struct Client *sptr, const char *target, int *is_channel,
                          struct Client **target_client, struct Channel **target_channel)
{
  *is_channel = 0;
  *target_client = NULL;
  *target_channel = NULL;

  if (IsChannelName(target)) {
    *is_channel = 1;
    *target_channel = FindChannel(target);
    if (!*target_channel)
      return 0;
    /* Anyone can view channel metadata if channel is visible to them */
    if (!ShowChannel(sptr, *target_channel) && !IsOper(sptr))
      return 0;
    return 1;
  } else if (*target == '*') {
    /* Self reference */
    *target_client = sptr;
    return 1;
  } else {
    *target_client = FindUser(target);
    if (!*target_client)
      return 0;
    /* Can always see metadata of visible users */
    return 1;
  }
}

/** Check if client can modify metadata on target.
 * @param[in] sptr Client modifying.
 * @param[in] target Target (client or channel).
 * @param[in] is_channel 1 if channel target.
 * @param[in] target_client Target client if user.
 * @param[in] target_channel Target channel if channel.
 * @return 1 if can modify, 0 if not.
 */
static int can_modify_target(struct Client *sptr, const char *target, int is_channel,
                             struct Client *target_client, struct Channel *target_channel)
{
  if (is_channel) {
    struct Membership *member;
    if (!target_channel)
      return 0;
    /* Must be chanop or halfop to modify channel metadata */
    member = find_member_link(target_channel, sptr);
    if (!member)
      return 0;
    if (!IsChanOp(member) && !IsHalfOp(member) && !IsOper(sptr))
      return 0;
    return 1;
  } else {
    /* Can only modify own metadata */
    if (target_client != sptr && !IsOper(sptr))
      return 0;
    return 1;
  }
}

/** Notify all clients subscribed to a metadata key about a change.
 * @param[in] target Target name (nick or channel).
 * @param[in] key Metadata key that changed.
 * @param[in] value New value (NULL if deleted).
 */
static void notify_subscribers(const char *target, const char *key, const char *value)
{
  struct Client *acptr;
  int fd;

  /* Iterate over all local clients */
  for (fd = HighestFd; fd >= 0; --fd) {
    if (!(acptr = LocalClientArray[fd]))
      continue;
    if (!IsUser(acptr))
      continue;
    if (!CapActive(acptr, CAP_DRAFT_METADATA2))
      continue;

    /* Check if subscribed to this key */
    if (!metadata_sub_check(acptr, key))
      continue;

    /* Send notification: METADATA <target> <key> [*] :<value> */
    if (value && *value) {
      sendrawto_one(acptr, ":%s METADATA %s %s * :%s",
                    cli_name(&me), target, key, value);
    } else {
      sendrawto_one(acptr, ":%s METADATA %s %s * :",
                    cli_name(&me), target, key);
    }
  }
}

/** Check if a client can see a specific metadata entry.
 * @param[in] viewer Client requesting to view.
 * @param[in] owner Client that owns the metadata (NULL for channels).
 * @param[in] entry Metadata entry to check.
 * @return 1 if visible, 0 if not.
 */
static int can_view_metadata(struct Client *viewer, struct Client *owner,
                             struct MetadataEntry *entry)
{
  if (!entry)
    return 0;

  /* Public metadata is visible to all */
  if (entry->visibility == METADATA_VIS_PUBLIC)
    return 1;

  /* Private metadata visible to owner */
  if (owner && owner == viewer)
    return 1;

  /* Opers can see all metadata */
  if (IsOper(viewer))
    return 1;

  return 0;
}

/** Get visibility string for metadata entry.
 * @param[in] entry Metadata entry.
 * @return "*" for public, "private" for private.
 */
static const char *get_visibility_str(struct MetadataEntry *entry)
{
  if (entry && entry->visibility == METADATA_VIS_PRIVATE)
    return "private";
  return "*";
}

/** Send a KEYVALUE reply.
 * Format: :<server> 761 <client> <target> <key> <visibility> :<value>
 */
static void send_keyvalue(struct Client *to, const char *target, const char *key,
                          const char *value, const char *visibility)
{
  if (value && *value)
    send_reply(to, RPL_KEYVALUE, target, key, visibility ? visibility : "*", value);
  else
    send_reply(to, RPL_KEYNOTSET, target, key);
}

/** Handle GET subcommand.
 * METADATA GET <target> <key> [<key>...]
 */
static int metadata_cmd_get(struct Client *sptr, int parc, char *parv[])
{
  const char *target;
  int is_channel = 0;
  struct Client *target_client = NULL;
  struct Channel *target_channel = NULL;
  int i;

  if (parc < 4) {
    send_fail(sptr, "METADATA", "INVALID_PARAMS", NULL,
              "GET requires target and at least one key");
    return 0;
  }

  target = parv[2];

  if (!can_see_target(sptr, target, &is_channel, &target_client, &target_channel)) {
    send_fail(sptr, "METADATA", "TARGET_INVALID", target,
              "Invalid target");
    return 0;
  }

  /* Process each key */
  for (i = 3; i < parc; i++) {
    const char *key = parv[i];
    struct MetadataEntry *entry = NULL;

    if (!is_valid_key(key)) {
      send_fail(sptr, "METADATA", "KEY_INVALID", key,
                "Invalid key name");
      continue;
    }

    if (is_channel) {
      entry = metadata_get_channel(target_channel, key);
    } else {
      entry = metadata_get_client(target_client, key);
    }

    if (entry) {
      /* Check visibility */
      if (can_view_metadata(sptr, is_channel ? NULL : target_client, entry)) {
        send_keyvalue(sptr, target, key, entry->value, get_visibility_str(entry));
      } else {
        /* Private metadata not visible - show as not set */
        send_reply(sptr, RPL_KEYNOTSET, target, key);
      }
    } else {
      send_reply(sptr, RPL_KEYNOTSET, target, key);
    }
  }

  return 0;
}

/** Handle SET subcommand.
 * METADATA SET <target> <key> [<value>]
 * If no value, deletes the key.
 */
static int metadata_cmd_set(struct Client *sptr, int parc, char *parv[])
{
  const char *target;
  const char *key;
  const char *value = NULL;
  int is_channel = 0;
  struct Client *target_client = NULL;
  struct Channel *target_channel = NULL;
  int max_keys, max_value_bytes;
  int current_count;
  int rc;

  if (parc < 4) {
    send_fail(sptr, "METADATA", "INVALID_PARAMS", NULL,
              "SET requires target and key");
    return 0;
  }

  target = parv[2];
  key = parv[3];
  if (parc >= 5)
    value = parv[4];

  if (!is_valid_key(key)) {
    send_fail(sptr, "METADATA", "KEY_INVALID", key,
              "Invalid key name");
    return 0;
  }

  if (!can_see_target(sptr, target, &is_channel, &target_client, &target_channel)) {
    send_fail(sptr, "METADATA", "TARGET_INVALID", target,
              "Invalid target");
    return 0;
  }

  if (!can_modify_target(sptr, target, is_channel, target_client, target_channel)) {
    send_fail(sptr, "METADATA", "KEY_NO_PERMISSION", key,
              "You don't have permission to set metadata on this target");
    return 0;
  }

  /* Check limits */
  max_keys = feature_int(FEAT_METADATA_MAX_KEYS);
  max_value_bytes = feature_int(FEAT_METADATA_MAX_VALUE_BYTES);

  if (value && strlen(value) > max_value_bytes) {
    send_fail(sptr, "METADATA", "VALUE_TOO_LONG", key,
              "Value exceeds maximum length");
    return 0;
  }

  /* Check key count limit if setting new key */
  if (value) {
    if (is_channel) {
      current_count = metadata_count_channel(target_channel);
      if (!metadata_get_channel(target_channel, key) && current_count >= max_keys) {
        send_fail(sptr, "METADATA", "LIMIT_REACHED", key,
                  "Maximum number of metadata keys reached");
        return 0;
      }
    } else {
      current_count = metadata_count_client(target_client);
      if (!metadata_get_client(target_client, key) && current_count >= max_keys) {
        send_fail(sptr, "METADATA", "LIMIT_REACHED", key,
                  "Maximum number of metadata keys reached");
        return 0;
      }
    }
  }

  /* Perform the set/delete */
  if (is_channel) {
    rc = metadata_set_channel(target_channel, key, value);
  } else {
    rc = metadata_set_client(target_client, key, value);
  }

  if (rc < 0) {
    send_fail(sptr, "METADATA", "INTERNAL_ERROR", key,
              "Failed to set metadata");
    return 0;
  }

  /* Send confirmation with visibility (new metadata is public by default) */
  send_keyvalue(sptr, target, key, value, "*");

  /* Notify local subscribers */
  notify_subscribers(target, key, value);

  /* Propagate to other servers */
  if (value) {
    sendcmdto_serv_butone(sptr, CMD_METADATA, NULL, "%s %s :%s",
                          target, key, value);
  } else {
    sendcmdto_serv_butone(sptr, CMD_METADATA, NULL, "%s %s",
                          target, key);
  }

  return 0;
}

/** Handle LIST subcommand.
 * METADATA LIST <target>
 */
static int metadata_cmd_list(struct Client *sptr, int parc, char *parv[])
{
  const char *target;
  int is_channel = 0;
  struct Client *target_client = NULL;
  struct Channel *target_channel = NULL;
  struct MetadataEntry *entry;

  if (parc < 3) {
    send_fail(sptr, "METADATA", "INVALID_PARAMS", NULL,
              "LIST requires a target");
    return 0;
  }

  target = parv[2];

  if (!can_see_target(sptr, target, &is_channel, &target_client, &target_channel)) {
    send_fail(sptr, "METADATA", "TARGET_INVALID", target,
              "Invalid target");
    return 0;
  }

  /* List all keys for target */
  if (is_channel) {
    entry = metadata_list_channel(target_channel);
  } else {
    entry = metadata_list_client(target_client);
  }

  while (entry) {
    /* Check visibility using helper function */
    if (can_view_metadata(sptr, is_channel ? NULL : target_client, entry)) {
      send_keyvalue(sptr, target, entry->key, entry->value, get_visibility_str(entry));
    }
    entry = entry->next;
  }

  /* Send end of list (there's no specific numeric for this, use KEYVALUE with empty list) */
  return 0;
}

/** Handle CLEAR subcommand.
 * METADATA CLEAR <target>
 */
static int metadata_cmd_clear(struct Client *sptr, int parc, char *parv[])
{
  const char *target;
  int is_channel = 0;
  struct Client *target_client = NULL;
  struct Channel *target_channel = NULL;

  if (parc < 3) {
    send_fail(sptr, "METADATA", "INVALID_PARAMS", NULL,
              "CLEAR requires a target");
    return 0;
  }

  target = parv[2];

  if (!can_see_target(sptr, target, &is_channel, &target_client, &target_channel)) {
    send_fail(sptr, "METADATA", "TARGET_INVALID", target,
              "Invalid target");
    return 0;
  }

  if (!can_modify_target(sptr, target, is_channel, target_client, target_channel)) {
    send_fail(sptr, "METADATA", "KEY_NO_PERMISSION", "*",
              "You don't have permission to clear metadata on this target");
    return 0;
  }

  if (is_channel) {
    metadata_clear_channel(target_channel);
  } else {
    metadata_clear_client(target_client);
  }

  /* Confirmation - send empty keyvalue? */
  return 0;
}

/** Handle SUB subcommand.
 * METADATA SUB <key> [<key>...]
 */
static int metadata_cmd_sub(struct Client *sptr, int parc, char *parv[])
{
  int i;
  int max_subs;

  if (parc < 3) {
    send_fail(sptr, "METADATA", "INVALID_PARAMS", NULL,
              "SUB requires at least one key");
    return 0;
  }

  max_subs = feature_int(FEAT_METADATA_MAX_SUBS);

  for (i = 2; i < parc; i++) {
    const char *key = parv[i];

    if (!is_valid_key(key)) {
      send_fail(sptr, "METADATA", "KEY_INVALID", key,
                "Invalid key name");
      continue;
    }

    /* Check if already at limit */
    if (metadata_sub_count(sptr) >= max_subs) {
      send_fail(sptr, "METADATA", "LIMIT_REACHED", key,
                "Maximum number of subscriptions reached");
      break;
    }

    if (metadata_sub_add(sptr, key) == 0) {
      send_reply(sptr, RPL_METADATASUBOK, key);
    }
  }

  return 0;
}

/** Handle UNSUB subcommand.
 * METADATA UNSUB <key> [<key>...]
 */
static int metadata_cmd_unsub(struct Client *sptr, int parc, char *parv[])
{
  int i;

  if (parc < 3) {
    send_fail(sptr, "METADATA", "INVALID_PARAMS", NULL,
              "UNSUB requires at least one key");
    return 0;
  }

  for (i = 2; i < parc; i++) {
    const char *key = parv[i];

    if (!is_valid_key(key)) {
      send_fail(sptr, "METADATA", "KEY_INVALID", key,
                "Invalid key name");
      continue;
    }

    if (metadata_sub_del(sptr, key) == 0) {
      send_reply(sptr, RPL_METADATAUNSUBOK, key);
    }
  }

  return 0;
}

/** Handle SUBS subcommand.
 * METADATA SUBS
 * Lists all current subscriptions.
 */
static int metadata_cmd_subs(struct Client *sptr, int parc, char *parv[])
{
  struct MetadataSub *sub;

  sub = metadata_sub_list(sptr);
  while (sub) {
    send_reply(sptr, RPL_METADATASUBS, sub->key);
    sub = sub->next;
  }

  return 0;
}

/** Send subscribed metadata for a target to client within a batch.
 * @param[in] sptr Client requesting sync.
 * @param[in] target Target name (nick or channel).
 * @param[in] target_client Client if user target.
 * @param[in] target_channel Channel if channel target.
 * @param[in] is_channel 1 if channel, 0 if user.
 * @return Number of metadata items sent.
 */
static int sync_target_metadata(struct Client *sptr, const char *target,
                                struct Client *target_client,
                                struct Channel *target_channel,
                                int is_channel)
{
  struct MetadataEntry *entry;
  struct MetadataSub *sub;
  int count = 0;

  /* Get metadata list for target */
  if (is_channel) {
    entry = metadata_list_channel(target_channel);
  } else {
    entry = metadata_list_client(target_client);
  }

  /* Send each metadata item if client is subscribed to that key */
  while (entry) {
    /* Check if client is subscribed to this key */
    if (metadata_sub_check(sptr, entry->key)) {
      /* Send metadata notification */
      if (entry->value && *entry->value) {
        sendrawto_one(sptr, "@batch=%s :%s METADATA %s %s * :%s",
                      cli_batch_id(sptr), cli_name(&me), target,
                      entry->key, entry->value);
      } else {
        sendrawto_one(sptr, "@batch=%s :%s METADATA %s %s * :",
                      cli_batch_id(sptr), cli_name(&me), target,
                      entry->key);
      }
      count++;
    }
    entry = entry->next;
  }

  return count;
}

/** Handle SYNC subcommand.
 * METADATA SYNC <target>
 * Requests all subscribed metadata for target.
 * For channels, includes metadata for all users in the channel.
 */
static int metadata_cmd_sync(struct Client *sptr, int parc, char *parv[])
{
  const char *target;
  int is_channel = 0;
  struct Client *target_client = NULL;
  struct Channel *target_channel = NULL;
  struct Membership *member;
  int count = 0;

  if (parc < 3) {
    send_fail(sptr, "METADATA", "INVALID_PARAMS", NULL,
              "SYNC requires a target");
    return 0;
  }

  target = parv[2];

  if (!can_see_target(sptr, target, &is_channel, &target_client, &target_channel)) {
    send_fail(sptr, "METADATA", "TARGET_INVALID", target,
              "Invalid target");
    return 0;
  }

  /* Check if client has any subscriptions */
  if (metadata_sub_count(sptr) == 0) {
    /* No subscriptions - nothing to sync */
    return 0;
  }

  /* Start metadata batch */
  send_batch_start(sptr, "metadata");

  /* If no active batch (client doesn't support batch), send later */
  if (!cli_batch_id(sptr)[0]) {
    send_reply(sptr, RPL_METADATASYNCLATER, target);
    return 0;
  }

  if (is_channel) {
    /* Sync channel metadata */
    count += sync_target_metadata(sptr, target, NULL, target_channel, 1);

    /* Sync metadata for all users in the channel */
    for (member = target_channel->members; member; member = member->next_member) {
      struct Client *member_client = member->user;
      if (member_client && IsUser(member_client)) {
        count += sync_target_metadata(sptr, cli_name(member_client),
                                       member_client, NULL, 0);
      }
    }
  } else {
    /* Sync user metadata */
    count += sync_target_metadata(sptr, target, target_client, NULL, 0);
  }

  /* End metadata batch */
  send_batch_end(sptr);

  return 0;
}

/** Check and update rate limiting for metadata commands.
 * Uses a token bucket style limiter: allows burst up to limit per second,
 * then rejects until the next second.
 * @param[in] sptr Client sending the command.
 * @return 1 if rate limited (reject), 0 if ok to proceed.
 */
static int check_metadata_rate_limit(struct Client *sptr)
{
  int rate_limit = feature_int(FEAT_METADATA_RATE_LIMIT);

  /* Rate limit of 0 disables limiting */
  if (rate_limit <= 0)
    return 0;

  /* Opers bypass rate limiting */
  if (IsOper(sptr))
    return 0;

  /* Reset counter if we're in a new second */
  if (cli_metadata_lastcmd(sptr) != CurrentTime) {
    cli_metadata_lastcmd(sptr) = CurrentTime;
    cli_metadata_cmdcnt(sptr) = 1;
    return 0;
  }

  /* Increment and check */
  cli_metadata_cmdcnt(sptr)++;
  if (cli_metadata_cmdcnt(sptr) > rate_limit) {
    return 1;  /* Rate limited */
  }

  return 0;
}

/** m_metadata - Handle METADATA command from local client.
 *
 * parv[0] = sender prefix
 * parv[1] = subcommand (GET, SET, LIST, CLEAR, SUB, UNSUB, SUBS, SYNC)
 * parv[2...] = subcommand arguments
 *
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int m_metadata(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  const char *subcmd;

  /* Must have draft/metadata-2 capability */
  if (!CapActive(sptr, CAP_DRAFT_METADATA2)) {
    return send_reply(sptr, ERR_UNKNOWNCOMMAND, "METADATA");
  }

  /* Check rate limiting */
  if (check_metadata_rate_limit(sptr)) {
    send_fail(sptr, "METADATA", "RATE_LIMITED", NULL,
              "Too many metadata commands, slow down");
    return 0;
  }

  if (parc < 2 || EmptyString(parv[1])) {
    send_fail(sptr, "METADATA", "INVALID_PARAMS", NULL,
              "Missing subcommand");
    return 0;
  }

  subcmd = parv[1];

  if (ircd_strcmp(subcmd, "GET") == 0) {
    return metadata_cmd_get(sptr, parc, parv);
  } else if (ircd_strcmp(subcmd, "SET") == 0) {
    return metadata_cmd_set(sptr, parc, parv);
  } else if (ircd_strcmp(subcmd, "LIST") == 0) {
    return metadata_cmd_list(sptr, parc, parv);
  } else if (ircd_strcmp(subcmd, "CLEAR") == 0) {
    return metadata_cmd_clear(sptr, parc, parv);
  } else if (ircd_strcmp(subcmd, "SUB") == 0) {
    return metadata_cmd_sub(sptr, parc, parv);
  } else if (ircd_strcmp(subcmd, "UNSUB") == 0) {
    return metadata_cmd_unsub(sptr, parc, parv);
  } else if (ircd_strcmp(subcmd, "SUBS") == 0) {
    return metadata_cmd_subs(sptr, parc, parv);
  } else if (ircd_strcmp(subcmd, "SYNC") == 0) {
    return metadata_cmd_sync(sptr, parc, parv);
  } else {
    send_fail(sptr, "METADATA", "INVALID_PARAMS", subcmd,
              "Unknown subcommand");
    return 0;
  }
}

/** ms_metadata - Handle METADATA command from server.
 *
 * Used for propagating metadata changes across the network.
 *
 * parv[0] = sender prefix
 * parv[1] = target
 * parv[2] = key
 * parv[3] = value (optional, absence means delete)
 *
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int ms_metadata(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  const char *target;
  const char *key;
  const char *value = NULL;
  int is_channel = 0;
  struct Client *target_client = NULL;
  struct Channel *target_channel = NULL;

  if (parc < 3)
    return 0;

  target = parv[1];
  key = parv[2];
  if (parc >= 4)
    value = parv[3];

  if (!is_valid_key(key))
    return 0;

  /* Find target */
  if (IsChannelName(target)) {
    is_channel = 1;
    target_channel = FindChannel(target);
    if (!target_channel)
      return 0;
  } else {
    target_client = FindUser(target);
    if (!target_client)
      return 0;
  }

  /* Apply the change */
  if (is_channel) {
    metadata_set_channel(target_channel, key, value);
  } else {
    metadata_set_client(target_client, key, value);
  }

  /* Notify local subscribers */
  notify_subscribers(target, key, value);

  /* Propagate to other servers */
  if (value) {
    sendcmdto_serv_butone(sptr, CMD_METADATA, cptr, "%s %s :%s",
                          target, key, value);
  } else {
    sendcmdto_serv_butone(sptr, CMD_METADATA, cptr, "%s %s",
                          target, key);
  }

  return 0;
}
