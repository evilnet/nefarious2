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
#include "ircd_compress.h"

#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <openssl/evp.h>

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

/** Decode base64 data for compression passthrough.
 * @param[in] input Base64 encoded string.
 * @param[out] output Buffer for decoded data.
 * @param[in] output_size Size of output buffer.
 * @param[out] decoded_len Actual decoded length.
 * @return 1 on success, 0 on error.
 */
static int base64_decode(const char *input, unsigned char *output,
                         size_t output_size, size_t *decoded_len)
{
  int inlen = strlen(input);
  int outlen;

  /* EVP_DecodeBlock requires output buffer of at least 3/4 of input */
  if ((size_t)inlen * 3 / 4 > output_size)
    return 0;

  outlen = EVP_DecodeBlock(output, (const unsigned char *)input, inlen);
  if (outlen < 0)
    return 0;

  /* EVP_DecodeBlock doesn't account for padding, adjust for = characters */
  if (inlen > 0 && input[inlen - 1] == '=') {
    outlen--;
    if (inlen > 1 && input[inlen - 2] == '=')
      outlen--;
  }

  *decoded_len = outlen;
  return 1;
}

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
 *
 * Flow:
 * 1. If target is online user/channel, get from memory
 * 2. If target is offline, check LMDB cache
 * 3. If not in LMDB, send MDQ to X3 (response will be async)
 */
static int metadata_cmd_get(struct Client *sptr, int parc, char *parv[])
{
  const char *target;
  int is_channel = 0;
  struct Client *target_client = NULL;
  struct Channel *target_channel = NULL;
  int i;
  int target_found;

  if (parc < 4) {
    send_fail(sptr, "METADATA", "INVALID_PARAMS", NULL,
              "GET requires target and at least one key");
    return 0;
  }

  target = parv[2];

  /* Check if target exists online */
  target_found = can_see_target(sptr, target, &is_channel, &target_client, &target_channel);

  /* Process each key */
  for (i = 3; i < parc; i++) {
    const char *key = parv[i];
    struct MetadataEntry *entry = NULL;
    int found = 0;

    if (!is_valid_key(key)) {
      send_fail(sptr, "METADATA", "KEY_INVALID", key,
                "Invalid key name");
      continue;
    }

    if (target_found) {
      /* Target is online - get from memory */
      if (is_channel) {
        entry = metadata_get_channel(target_channel, key);
      } else {
        entry = metadata_get_client(target_client, key);
      }

      if (entry) {
        /* Check visibility */
        if (can_view_metadata(sptr, is_channel ? NULL : target_client, entry)) {
          send_keyvalue(sptr, target, key, entry->value, get_visibility_str(entry));
          found = 1;
        }
      }
    }

    if (!found && !is_channel && !IsChannelName(target)) {
      /* Target is not online and not a channel - try LMDB cache for account */
      char value_buf[METADATA_VALUE_LEN + 1];

      if (metadata_lmdb_is_available()) {
        if (metadata_account_get(target, key, value_buf) == 0) {
          /* Found in LMDB cache */
          const char *vis_str = "*";
          const char *val = value_buf;

          /* Parse visibility prefix */
          if (val[0] == 'P' && val[1] == ':') {
            vis_str = "private";
            val = val + 2;
          }

          if (*val) {
            send_keyvalue(sptr, target, key, val, vis_str);
            found = 1;
          }
        }
      }

      if (!found) {
        /* Not in cache - send MDQ to X3 if available.
         * Response will come back via ms_metadata and be forwarded
         * to the client via metadata_handle_response.
         */
        if (metadata_send_query(sptr, target, key) == 0) {
          /* Query sent - response will be async, don't send NOT_SET yet */
          continue;
        }
      }
    }

    if (!found) {
      send_reply(sptr, RPL_KEYNOTSET, target, key);
    }
  }

  return 0;
}

/** Parse visibility string.
 * @param[in] vis Visibility string ("*" or "private").
 * @return METADATA_VIS_PUBLIC or METADATA_VIS_PRIVATE.
 */
static int parse_visibility(const char *vis)
{
  if (vis && ircd_strcmp(vis, "private") == 0)
    return METADATA_VIS_PRIVATE;
  return METADATA_VIS_PUBLIC;
}

/** Handle SET subcommand.
 * METADATA SET <target> <key> [<visibility>] [<value>]
 * If no value, deletes the key.
 * Visibility is "*" for public (default) or "private" for private.
 */
static int metadata_cmd_set(struct Client *sptr, int parc, char *parv[])
{
  const char *target;
  const char *key;
  const char *value = NULL;
  int visibility = METADATA_VIS_PUBLIC;
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

  /* Parse optional visibility and value.
   * Format options:
   * SET target key                    -> delete
   * SET target key :value             -> set public (value starts with :)
   * SET target key * :value           -> set public
   * SET target key private :value     -> set private
   */
  if (parc >= 5) {
    /* Check if parv[4] is visibility or value */
    if (parv[4][0] == '*' && parv[4][1] == '\0') {
      /* Explicit public visibility */
      visibility = METADATA_VIS_PUBLIC;
      if (parc >= 6)
        value = parv[5];
    } else if (ircd_strcmp(parv[4], "private") == 0) {
      /* Private visibility */
      visibility = METADATA_VIS_PRIVATE;
      if (parc >= 6)
        value = parv[5];
    } else {
      /* No explicit visibility, parv[4] is the value */
      value = parv[4];
    }
  }

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
    rc = metadata_set_channel(target_channel, key, value, visibility);
  } else {
    rc = metadata_set_client(target_client, key, value, visibility);
  }

  if (rc < 0) {
    send_fail(sptr, "METADATA", "INTERNAL_ERROR", key,
              "Failed to set metadata");
    return 0;
  }

  /* Send confirmation with visibility */
  send_keyvalue(sptr, target, key, value,
                visibility == METADATA_VIS_PRIVATE ? "private" : "*");

  /* Notify local subscribers (only for public metadata) */
  if (visibility == METADATA_VIS_PUBLIC) {
    notify_subscribers(target, key, value);
  }

  /* Propagate to other servers with visibility */
  if (value) {
    sendcmdto_serv_butone(sptr, CMD_METADATA, NULL, "%s %s %s :%s",
                          target, key,
                          visibility == METADATA_VIS_PRIVATE ? "P" : "*",
                          value);
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

/** ms_metadataquery - Handle METADATAQUERY (MDQ) command from server.
 *
 * Used for on-demand metadata sync - allows services (X3) to query
 * metadata for offline users or channels from the IRCd's LMDB cache.
 *
 * Format: [SOURCE] MDQ [TARGET] [KEY|*]
 *
 * parv[0] = sender prefix
 * parv[1] = target (account name or channel)
 * parv[2] = key to query, or "*" for all keys
 *
 * Response: Standard MD tokens sent back to the source server.
 *
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int ms_metadataquery(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  const char *target;
  const char *key;
  int is_channel = 0;
  int is_from_services = 0;
  struct MetadataEntry *entry = NULL;
  struct MetadataEntry *list = NULL;
  struct MetadataEntry *next;
  char value_buf[METADATA_VALUE_LEN + 1];

  /* Check if this is from services */
  if (IsServer(sptr) && IsService(sptr)) {
    is_from_services = 1;
    metadata_x3_heartbeat();
  } else if (!IsServer(sptr) && cli_user(sptr) &&
             cli_user(sptr)->server && IsService(cli_user(sptr)->server)) {
    is_from_services = 1;
    metadata_x3_heartbeat();
  }

  if (parc < 3) {
    /* Need at least target and key */
    return 0;
  }

  target = parv[1];
  key = parv[2];

  if (!target || !key)
    return 0;

  /* Log MDQ request for debugging */
  log_write(LS_DEBUG, L_DEBUG, 0, "MDQ: %s queries %s key=%s (from_services=%d)",
            cli_name(sptr), target, key, is_from_services);

  /* If MDQ is from another IRCd (not services), we have two options:
   * 1. If X3 is available, forward to X3 (authoritative source)
   * 2. If X3 is unavailable, try to answer from local LMDB cache
   *
   * This handles multi-hop topologies: Client -> ServerA -> ServerB -> X3
   */
  if (!is_from_services) {
    struct Client *services = NULL;
    struct Client *acptr;

    /* Find services server to forward to */
    for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr)) {
      if (IsServer(acptr) && IsService(acptr)) {
        services = acptr;
        break;
      }
    }

    if (services && metadata_x3_is_available()) {
      /* X3 is available - forward to authoritative source */
      sendcmdto_one(sptr, CMD_METADATAQUERY, services, "%s %s", target, key);
      log_write(LS_DEBUG, L_DEBUG, 0, "MDQ: Forwarding to %s", cli_name(services));
      return 0;
    }

    /* X3 unavailable - try to answer from local LMDB cache.
     * Fall through to the cache lookup code below, but send response
     * back to the requesting server (cptr) instead of sptr.
     */
    log_write(LS_DEBUG, L_DEBUG, 0, "MDQ: X3 unavailable, checking local cache");
    /* Fall through to process locally */
  }

  /* Determine if channel or account */
  is_channel = IsChannelName(target);

  if (is_channel) {
    /* Channel metadata query - look up from channel structure first,
     * then fall back to LMDB for unloaded/offline channels */
    struct Channel *chptr = FindChannel(target);

    if (chptr) {
      /* Channel exists in memory */
      if (key[0] == '*' && key[1] == '\0') {
        /* Return all metadata for channel */
        entry = metadata_list_channel(chptr);
        while (entry) {
          const char *vis_str = (entry->visibility == METADATA_VIS_PRIVATE) ? "P" : "*";
          if (entry->value && *entry->value) {
            sendcmdto_one(&me, CMD_METADATA, cptr, "%s %s %s :%s",
                          target, entry->key, vis_str, entry->value);
          }
          entry = entry->next;
        }
      } else {
        /* Single key query */
        entry = metadata_get_channel(chptr, key);
        if (entry && entry->value && *entry->value) {
          const char *vis_str = (entry->visibility == METADATA_VIS_PRIVATE) ? "P" : "*";
          sendcmdto_one(&me, CMD_METADATA, cptr, "%s %s %s :%s",
                        target, key, vis_str, entry->value);
        }
      }
    }
    /* For channels not in memory, we could query LMDB but currently
     * channel metadata in LMDB is keyed by channel name directly */
  } else {
    /* Account metadata query - query LMDB cache */
    if (!metadata_lmdb_is_available()) {
      /* LMDB not available, can't respond */
      return 0;
    }

    if (key[0] == '*' && key[1] == '\0') {
      /* Return all metadata for account from LMDB */
      list = metadata_account_list(target);
      entry = list;
      while (entry) {
        /* Parse visibility from stored value if prefixed with P: */
        const char *vis_str = "*";
        const char *val = entry->value;
        if (val && val[0] == 'P' && val[1] == ':') {
          vis_str = "P";
          val = val + 2;
        }
        if (val && *val) {
          sendcmdto_one(&me, CMD_METADATA, cptr, "%s %s %s :%s",
                        target, entry->key, vis_str, val);
        }
        entry = entry->next;
      }
      /* Free the list returned by metadata_account_list */
      entry = list;
      while (entry) {
        next = entry->next;
        metadata_free_entry(entry);
        entry = next;
      }
    } else {
      /* Single key query */
      if (metadata_account_get(target, key, value_buf) == 0) {
        /* Parse visibility from stored value */
        const char *vis_str = "*";
        const char *val = value_buf;
        if (val[0] == 'P' && val[1] == ':') {
          vis_str = "P";
          val = val + 2;
        }
        if (*val) {
          sendcmdto_one(&me, CMD_METADATA, cptr, "%s %s %s :%s",
                        target, key, vis_str, val);
        }
      }
    }
  }

  return 0;
}

/** ms_metadata - Handle METADATA command from server.
 *
 * Used for propagating metadata changes across the network.
 *
 * parv[0] = sender prefix
 * parv[1] = target
 * parv[2] = key
 * parv[3] = visibility ("*" or "P") (optional for backwards compat)
 * parv[4] = "Z" if compressed passthrough, or value
 * parv[5] = base64 value (if Z flag present)
 *
 * For compression passthrough:
 *   Format: target key visibility Z :base64_compressed_data
 *
 * For backwards compatibility, if parv[3] is present but not a visibility
 * token, treat it as the value.
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
  int visibility = METADATA_VIS_PUBLIC;
  int is_channel = 0;
  int is_compressed = 0;
  struct Client *target_client = NULL;
  struct Channel *target_channel = NULL;
  int is_from_services = 0;

  /* Buffers for compressed data handling */
  unsigned char raw_data[METADATA_VALUE_LEN + 64];
  size_t raw_len = 0;

  /* Check if this is from a services server (potential MDQ response) */
  if (IsServer(sptr) && IsService(sptr)) {
    is_from_services = 1;
    metadata_x3_heartbeat();
  } else if (!IsServer(sptr) && cli_user(sptr) &&
             cli_user(sptr)->server && IsService(cli_user(sptr)->server)) {
    is_from_services = 1;
    metadata_x3_heartbeat();
  }

  if (parc < 3)
    return 0;

  target = parv[1];
  key = parv[2];

  /* Parse visibility, Z flag, and value.
   * Compressed format: target key visibility Z :base64_data
   * Normal format: target key [visibility] [:value]
   * Old format: target key [:value]
   */
  if (parc >= 4) {
    /* Check if parv[3] is a visibility token */
    if ((parv[3][0] == '*' && parv[3][1] == '\0') ||
        (parv[3][0] == 'P' && parv[3][1] == '\0')) {
      visibility = (parv[3][0] == 'P') ? METADATA_VIS_PRIVATE : METADATA_VIS_PUBLIC;

      /* Check for Z flag (compression passthrough) */
      if (parc >= 5 && parv[4][0] == 'Z' && parv[4][1] == '\0') {
        is_compressed = 1;
        if (parc >= 6)
          value = parv[5]; /* Base64-encoded compressed data */
      } else if (parc >= 5) {
        value = parv[4];
      }
    } else {
      /* Old format or no visibility - parv[3] is value */
      value = parv[3];
    }
  }

  if (!is_valid_key(key))
    return 0;

  /* Handle compressed data - decode base64 now */
  if (is_compressed && value) {
    if (!base64_decode(value, raw_data, sizeof(raw_data), &raw_len)) {
      log_write(LS_SYSTEM, L_WARNING, 0,
                "ms_metadata: Failed to decode compressed data for %s/%s",
                target, key);
      is_compressed = 0; /* Fall back to treating as plain value */
    }
  }

  /* Find target */
  if (IsChannelName(target)) {
    is_channel = 1;
    target_channel = FindChannel(target);
    if (!target_channel)
      return 0;
  } else {
    target_client = FindUser(target);
    /* For MDQ responses from services, target might be offline account */
    if (!target_client && !is_from_services)
      return 0;
  }

  /* Apply the change with visibility (always decompress for in-memory storage) */
  if (!is_compressed) {
    if (is_channel) {
      metadata_set_channel(target_channel, key, value, visibility);
    } else if (target_client) {
      metadata_set_client(target_client, key, value, visibility);
    }
  } else if (raw_len > 0) {
    /* For compressed data, decompress and store in memory for online users */
#ifdef USE_ZSTD
    char decompressed[METADATA_VALUE_LEN];
    size_t decompressed_len;
    if (decompress_data(raw_data, raw_len,
                        (unsigned char *)decompressed, sizeof(decompressed) - 1,
                        &decompressed_len) >= 0) {
      decompressed[decompressed_len] = '\0';
      if (is_channel) {
        metadata_set_channel(target_channel, key, decompressed, visibility);
      } else if (target_client) {
        metadata_set_client(target_client, key, decompressed, visibility);
      }
    }
#endif
  }

  /* If from services and target is offline, cache in LMDB */
  if (is_from_services && !target_client && !is_channel && value) {
    if (metadata_lmdb_is_available()) {
      if (is_compressed && raw_len > 0) {
        /* Store raw compressed data directly - no recompression needed! */
        /* Prepend visibility if private */
        if (visibility == METADATA_VIS_PRIVATE) {
          unsigned char prefixed[METADATA_VALUE_LEN + 64];
          prefixed[0] = 'P';
          prefixed[1] = ':';
          memcpy(prefixed + 2, raw_data, raw_len);
          metadata_account_set_raw(target, key, prefixed, raw_len + 2);
        } else {
          metadata_account_set_raw(target, key, raw_data, raw_len);
        }
        log_write(LS_SYSTEM, L_DEBUG, 0,
                  "ms_metadata: Stored compressed passthrough for %s/%s (%zu bytes)",
                  target, key, raw_len);
      } else {
        /* Store with visibility prefix (will compress automatically) */
        char stored_value[METADATA_VALUE_LEN + 3];
        if (visibility == METADATA_VIS_PRIVATE) {
          ircd_snprintf(0, stored_value, sizeof(stored_value), "P:%s", value);
        } else {
          ircd_strncpy(stored_value, value, METADATA_VALUE_LEN);
        }
        metadata_account_set(target, key, stored_value);
      }
    }

    /* Forward to any clients waiting for this MDQ response */
    /* For compressed data, we need to decompress for the client */
    if (is_compressed && raw_len > 0) {
      /* Decompress for the response */
#ifdef USE_ZSTD
      char decompressed[METADATA_VALUE_LEN];
      size_t decompressed_len;
      if (decompress_data(raw_data, raw_len,
                          (unsigned char *)decompressed, sizeof(decompressed) - 1,
                          &decompressed_len) >= 0) {
        decompressed[decompressed_len] = '\0';
        metadata_handle_response(target, key, decompressed, visibility);
      }
#endif
    } else {
      metadata_handle_response(target, key, value, visibility);
    }
  }

  /* Notify local subscribers (only for public metadata) */
  if (visibility == METADATA_VIS_PUBLIC) {
    if (is_compressed && raw_len > 0) {
#ifdef USE_ZSTD
      /* Decompress for subscribers */
      char decompressed[METADATA_VALUE_LEN];
      size_t decompressed_len;
      if (decompress_data(raw_data, raw_len,
                          (unsigned char *)decompressed, sizeof(decompressed) - 1,
                          &decompressed_len) >= 0) {
        decompressed[decompressed_len] = '\0';
        notify_subscribers(target, key, decompressed);
      }
#endif
    } else {
      notify_subscribers(target, key, value);
    }
  }

  /* Propagate to other servers - forward compressed if received compressed */
  if (value) {
    if (is_compressed) {
      /* Forward compressed with Z flag */
      sendcmdto_serv_butone(sptr, CMD_METADATA, cptr, "%s %s %s Z :%s",
                            target, key,
                            visibility == METADATA_VIS_PRIVATE ? "P" : "*",
                            value);
    } else {
      sendcmdto_serv_butone(sptr, CMD_METADATA, cptr, "%s %s %s :%s",
                            target, key,
                            visibility == METADATA_VIS_PRIVATE ? "P" : "*",
                            value);
    }
  } else {
    sendcmdto_serv_butone(sptr, CMD_METADATA, cptr, "%s %s",
                          target, key);
  }

  return 0;
}
