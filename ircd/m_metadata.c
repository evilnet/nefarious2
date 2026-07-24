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

/** Check if key is valid per IRCv3 spec (letters, digits, hyphens, underscores, dots, forward slashes)
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

  /* Check all characters — spec allows a-z 0-9 _ . / - */
  for (p = key; *p; p++) {
    if (!isalnum((unsigned char)*p) && *p != '-' && *p != '_' && *p != '.' && *p != '/')
      return 0;
  }

  /* key buffers are char[METADATA_KEY_LEN]; the last byte is the NUL */
  if (strlen(key) >= METADATA_KEY_LEN)
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
/** Check if two clients share at least one common channel. */
static int shares_channel(struct Client *a, struct Client *b)
{
  struct Membership *chan;
  for (chan = cli_user(a)->channel; chan; chan = chan->next_channel) {
    if (find_member_link(chan->channel, b))
      return 1;
  }
  return 0;
}

static void notify_subscribers(const char *target, const char *key, const char *value)
{
  struct Client *acptr;
  struct Client *target_cli = NULL;
  struct Channel *target_chptr = NULL;
  int fd;

  /* Resolve target for visibility checks */
  if (IsChannelPrefix(*target))
    target_chptr = FindChannel(target);
  else
    target_cli = FindUser(target);

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

    /* Visibility: for user metadata, only notify if they share a channel
     * or are the target themselves. For channel metadata, only if member. */
    if (target_cli) {
      if (acptr != target_cli && !shares_channel(acptr, target_cli))
        continue;
    } else if (target_chptr) {
      if (!find_member_link(target_chptr, acptr))
        continue;
    }

    /* Send notification: METADATA <target> <key> <visibility> [:<value>] */
    if (value && *value) {
      sendrawto_one(acptr, ":%s METADATA %s %s * :%s",
                    cli_name(&me), target, key, value);
    } else {
      /* Unset: no value parameter */
      sendrawto_one(acptr, ":%s METADATA %s %s *",
                    cli_name(&me), target, key);
    }
  }
}

/** Send metadata subscription notifications to a client joining a channel.
 * For each channel member's metadata keys that the joiner is subscribed to,
 * send a METADATA notification. Also send for channel metadata.
 * @param[in] joiner Client that just joined.
 * @param[in] chptr Channel being joined.
 */
void metadata_send_join_notifications(struct Client *joiner, struct Channel *chptr)
{
  struct Membership *member;
  struct MetadataEntry *entry;

  if (!MyUser(joiner) || !CapActive(joiner, CAP_DRAFT_METADATA2))
    return;

  /* Send subscribed user metadata for each existing channel member */
  for (member = chptr->members; member; member = member->next_member) {
    struct Client *target = member->user;
    if (target == joiner)
      continue;

    entry = metadata_list_client(target);
    while (entry) {
      if (entry->visibility != METADATA_VIS_PRIVATE
          && metadata_sub_check(joiner, entry->key)) {
        if (entry->value && *entry->value)
          sendrawto_one(joiner, ":%s METADATA %s %s * :%s",
                        cli_name(&me), cli_name(target), entry->key, entry->value);
        else
          sendrawto_one(joiner, ":%s METADATA %s %s * :",
                        cli_name(&me), cli_name(target), entry->key);
      }
      entry = entry->next;
    }
  }

  /* Send subscribed channel metadata */
  entry = metadata_list_channel(chptr);
  while (entry) {
    if (entry->visibility != METADATA_VIS_PRIVATE
        && metadata_sub_check(joiner, entry->key)) {
      if (entry->value && *entry->value)
        sendrawto_one(joiner, ":%s METADATA %s %s * :%s",
                      cli_name(&me), chptr->chname, entry->key, entry->value);
      else
        sendrawto_one(joiner, ":%s METADATA %s %s * :",
                      cli_name(&me), chptr->chname, entry->key);
    }
    entry = entry->next;
  }
}

/** Check if a client can see a specific metadata entry.
 * @param[in] viewer Client requesting to view.
 * @param[in] owner Client that owns the metadata (NULL for channels).
 * @param[in] entry Metadata entry to check.
 * @return 1 if visible, 0 if not.
 */
int can_view_metadata(struct Client *viewer, struct Client *owner,
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
const char *get_visibility_str(struct MetadataEntry *entry)
{
  if (entry && entry->visibility == METADATA_VIS_PRIVATE)
    return "private";
  return "*";
}

/** Send a KEYVALUE reply.
 * Format: :<server> 761 <client> <target> <key> <visibility> :<value>
 * Per draft/metadata-2 spec, "*" target is expanded to the client's nick.
 */
static void send_keyvalue(struct Client *to, const char *target, const char *key,
                          const char *value, const char *visibility)
{
  /* Expand "*" to the client's own nick (only if registered and nick is set) */
  const char *display_target = (target && *target == '*' && !target[1]
                                && IsUser(to) && cli_name(to)[0])
                                ? cli_name(to) : target;
  if (value && *value)
    send_reply(to, RPL_KEYVALUE, display_target, key, visibility ? visibility : "*", value);
  else
    send_reply(to, RPL_KEYNOTSET, display_target, key);
}

/** Handle GET subcommand.
 * METADATA GET <target> <key> [<key>...]
 *
 * Flow:
 * 1. If target is online user/channel, get from memory
 * 2. If not found in memory, check the local metadata store
 * 3. If still not found, reply RPL_KEYNOTSET (766)
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

  target = parv[1];

  /* Check if target exists online */
  target_found = can_see_target(sptr, target, &is_channel, &target_client, &target_channel);

  /* Validate target existence before processing keys.
   * Per IRCv3 metadata spec, non-existent targets get TARGET_INVALID. */
  if (!target_found) {
    if (is_channel) {
      /* Channels must exist in memory to be valid metadata targets */
      send_fail(sptr, "METADATA", "INVALID_TARGET", target,
                "No such channel");
      return 0;
    }
    /* For offline users, check if account has any metadata in LMDB */
    if (metadata_lmdb_is_available()) {
      struct MetadataEntry *entries = metadata_account_list(target);
      if (entries) {
        /* Account has LMDB data — valid offline target, proceed */
        struct MetadataEntry *e = entries;
        while (e) {
          struct MetadataEntry *n = e->next;
          metadata_free_entry(e);
          e = n;
        }
      } else {
        send_fail(sptr, "METADATA", "INVALID_TARGET", target,
                  "No such target");
        return 0;
      }
    } else {
      send_fail(sptr, "METADATA", "INVALID_TARGET", target,
                "No such target");
      return 0;
    }
  }

  /* Wrap responses in a metadata batch */
  send_batch_start(sptr, "metadata");

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

    /* For registered users/channels, if not in memory, check LMDB cache */
    if (!found && !is_channel) {
      /* Get account name for cache lookup */
      const char *account = NULL;
      char value_buf[METADATA_VALUE_LEN + 1];

      if (target_client && IsAccount(target_client)) {
        /* Online registered user - use their account name for cache lookup */
        account = cli_account(target_client);
      } else if (!target_found && !IsChannelName(target)) {
        /* Offline user - target is the account name */
        account = target;
      }

      if (account && metadata_lmdb_is_available()) {
        int vis = METADATA_VIS_PUBLIC;
        /* A2 forward-pull: fetch the decoded visibility via the out-param
         * instead of locally parsing "P:" — metadata_account_get() now
         * returns the value already stripped, so the old local parse would
         * never match.  Task 2 restructures this promotion further. */
        if (metadata_account_get_vis(account, key, value_buf, sizeof(value_buf), &vis) == 0) {
          /* Found in LMDB cache */
          const char *vis_str = (vis == METADATA_VIS_PRIVATE) ? "private" : "*";
          const char *val = value_buf;

          /* Check visibility for private metadata from LMDB */
          if (vis_str[0] == 'p') {
            /* Private metadata - check if viewer is owner or oper */
            int can_view = 0;
            if (IsOper(sptr))
              can_view = 1;
            else if (IsAccount(sptr) && ircd_strcmp(cli_account(sptr), account) == 0)
              can_view = 1;
            if (!can_view)
              continue;  /* Skip to next key, don't reveal private data */
          }

          if (*val) {
            send_keyvalue(sptr, target, key, val, vis_str);
            found = 1;

            /* For online users, also load into memory for faster subsequent access */
            if (target_client) {
              metadata_set_client(target_client, key, val,
                                  (vis_str[0] == 'p') ? METADATA_VIS_PRIVATE : METADATA_VIS_PUBLIC);
            }
          }
        }
      }

      /* Nefarious is authoritative - no X3 query, just report not set */
    }

    /* For channels, check LMDB cache for registered channel metadata */
    if (!found && is_channel) {
      char value_buf[METADATA_VALUE_LEN + 1];

      /* First check LMDB cache (works for both existing and non-existent channels) */
      if (metadata_lmdb_is_available()) {
        int vis = METADATA_VIS_PUBLIC;
        /* A2 forward-pull: see the matching comment in the user GET fallback
         * above — decoded visibility comes from the out-param now. */
        if (metadata_account_get_vis(target, key, value_buf, sizeof(value_buf), &vis) == 0) {
          /* Found in LMDB cache - load into channel memory */
          const char *vis_str = (vis == METADATA_VIS_PRIVATE) ? "private" : "*";
          const char *val = value_buf;

          /* Check visibility for private channel metadata from LMDB */
          if (vis_str[0] == 'p') {
            /* Private channel metadata - visible to chanops and opers only */
            int can_view = 0;
            if (IsOper(sptr))
              can_view = 1;
            else if (target_channel) {
              struct Membership *member = find_member_link(target_channel, sptr);
              if (member && IsChanOp(member))
                can_view = 1;
            }
            if (!can_view)
              continue;  /* Skip, don't reveal private channel data */
          }

          if (*val) {
            send_keyvalue(sptr, target, key, val, vis_str);
            found = 1;

            /* Load into channel's in-memory metadata (if channel exists) */
            if (target_channel) {
              metadata_set_channel(target_channel, key, val,
                                   (vis_str[0] == 'p') ? METADATA_VIS_PRIVATE : METADATA_VIS_PUBLIC);
            }
          }
        }
      }

      /* Nefarious is authoritative - no X3 query */
    }

    if (!found) {
      /* Expand "*" to client's nick for RPL_KEYNOTSET */
      const char *display = (target[0] == '*' && !target[1]
                             && IsUser(sptr) && cli_name(sptr)[0])
                             ? cli_name(sptr) : target;
      send_reply(sptr, RPL_KEYNOTSET, display, key);
    }
  }

  send_batch_end(sptr);

  return 0;
}

/* Result codes for metadata_check_limits(). */
enum {
  METADATA_LIMIT_OK    = 0,
  METADATA_LIMIT_UTF8  = -1,   /* value is not valid UTF-8 */
  METADATA_LIMIT_VALUE = -2,   /* value longer than FEAT_METADATA_MAX_VALUE_BYTES */
  METADATA_LIMIT_KEYS  = -3    /* new key would exceed FEAT_METADATA_MAX_KEYS */
};

/* Validate a metadata write against the configured limits.  Returns
 * METADATA_LIMIT_OK if allowed, else the code of the failed check.
 * Deletes (value == NULL) are always allowed.  Server-managed keys
 * (draft/persistence/...) are exempt: they are server-written state
 * with their own lifecycle, are already excluded from
 * metadata_count_client()'s budget, and gating them here would let a
 * user's vanity-key count block bouncer/persistence S2S sync.
 * Negative feature values are clamped to 0 (fail closed) rather than
 * sign-converting into "unlimited" in the size_t comparison. */
static int metadata_check_limits(struct Client *target_client,
                                 struct Channel *target_channel,
                                 int is_channel,
                                 const char *key, const char *value)
{
  int max_keys = feature_int(FEAT_METADATA_MAX_KEYS);
  int max_value_bytes = feature_int(FEAT_METADATA_MAX_VALUE_BYTES);

  if (!value)
    return METADATA_LIMIT_OK;
  if (metadata_key_is_server_managed(key))
    return METADATA_LIMIT_OK;
  if (max_keys < 0)
    max_keys = 0;
  if (max_value_bytes < 0)
    max_value_bytes = 0;

  if (!string_is_valid_utf8(value))
    return METADATA_LIMIT_UTF8;
  if (strlen(value) > (size_t)max_value_bytes)
    return METADATA_LIMIT_VALUE;

  if (is_channel) {
    if (target_channel && !metadata_get_channel(target_channel, key)
        && metadata_count_channel(target_channel) >= max_keys)
      return METADATA_LIMIT_KEYS;
  } else if (target_client) {
    if (!metadata_get_client(target_client, key)
        && metadata_count_client(target_client) >= max_keys)
      return METADATA_LIMIT_KEYS;
  }
  return METADATA_LIMIT_OK;
}

/** Handle SET subcommand.
 * METADATA SET <target> <key> [<visibility>] [<value>]
 * If no value, deletes the key.
 * Visibility is "*" for public (default) or "private" for private.
 *
 * Target may be:
 *   <nick>          - online user (own or any if oper)
 *   *               - self
 *   *<accountname>  - account in LMDB (oper only, works offline)
 *   #channel        - channel
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
  int rc;

  if (parc < 4) {
    send_fail(sptr, "METADATA", "INVALID_PARAMS", NULL,
              "SET requires target and key");
    return 0;
  }

  target = parv[1];
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

  /* Account target: *accountname — oper-only, writes directly to LMDB.
   * Works for offline accounts (e.g., clearing bouncer metadata during cleanup).
   * Bare "*" is self-reference and falls through to normal path. */
  if (target[0] == '*' && target[1] != '\0') {
    const char *account_name = target + 1;

    if (!IsOper(sptr)) {
      send_fail_ctx(sptr, "METADATA", "KEY_NO_PERMISSION",
                    "Account targets require oper privileges",
                    "%s %s", target, key);
      return 0;
    }

    if (!metadata_lmdb_is_available()) {
      send_fail(sptr, "METADATA", "INTERNAL_ERROR", key,
                "Metadata storage not available");
      return 0;
    }

    /* If the account has online connections, update via metadata_set_client
     * which handles both in-memory and LMDB persistence.  Otherwise write
     * directly to LMDB for the offline case. */
    {
      struct Client *acptr;
      struct Client *first_online = NULL;
      int fd, found_online = 0;

      for (fd = HighestFd; fd >= 0; --fd) {
        if (!(acptr = LocalClientArray[fd]))
          continue;
        if (!IsAccount(acptr))
          continue;
        if (ircd_strcmp(cli_account(acptr), account_name) == 0) {
          first_online = acptr;
          break;
        }
      }

      /* Enforce the same limits every other write path obeys.  For an
       * online account, check against the live client; for an offline
       * account, check value constraints plus the persisted-row count. */
      if (value) {
        int limit_rc;
        if (first_online) {
          limit_rc = metadata_check_limits(first_online, NULL, 0, key, value);
        } else {
          limit_rc = metadata_check_limits(NULL, NULL, 0, key, value);  /* UTF-8 + length only */
          if (limit_rc == METADATA_LIMIT_OK
              && !metadata_key_is_server_managed(key)) {
            char scratch[METADATA_VALUE_LEN];
            int max_keys = feature_int(FEAT_METADATA_MAX_KEYS);
            if (max_keys < 0)
              max_keys = 0;
            /* Updates to an existing key are always allowed at cap. */
            if (metadata_account_get(account_name, key, scratch) != 0
                && metadata_account_count_keys(account_name) >= max_keys)
              limit_rc = METADATA_LIMIT_KEYS;
          }
        }
        switch (limit_rc) {
        case METADATA_LIMIT_UTF8:
          send_fail(sptr, "METADATA", "VALUE_INVALID", NULL, "value is not valid UTF-8");
          return 0;
        case METADATA_LIMIT_VALUE:
          send_fail(sptr, "METADATA", "VALUE_INVALID", NULL, "value is too long");
          return 0;
        case METADATA_LIMIT_KEYS:
          send_fail(sptr, "METADATA", "LIMIT_REACHED", key, "Maximum number of metadata keys reached");
          return 0;
        }
      }

      for (fd = HighestFd; fd >= 0; --fd) {
        if (!(acptr = LocalClientArray[fd]))
          continue;
        if (!IsAccount(acptr))
          continue;
        if (ircd_strcmp(cli_account(acptr), account_name) == 0) {
          metadata_set_client(acptr, key, value, visibility);
          found_online = 1;
        }
      }

      if (!found_online) {
        int rc = metadata_account_set(account_name, key, value, visibility);
        if (rc < 0) {
          send_fail(sptr, "METADATA", "INTERNAL_ERROR", key,
                    "Failed to set account metadata");
          return 0;
        }
      }
    }

    send_keyvalue(sptr, target, key, value,
                  visibility == METADATA_VIS_PRIVATE ? "private" : "*");
    return 0;
  }

  /* Refuse direct SET on server-managed keys (draft/persistence/...).
   * These keys are written exclusively by server-side logic — e.g.
   * the bouncer session/persistence-preference machinery.
   * The "*account" oper branch above is left intact so cleanup tooling
   * can still wipe stale entries on offline accounts. */
  if (metadata_key_is_server_managed(key)) {
    send_fail_ctx(sptr, "METADATA", "KEY_NO_PERMISSION",
                  "Key is server-managed and cannot be set directly",
                  "%s %s", target, key);
    return 0;
  }

  if (!can_see_target(sptr, target, &is_channel, &target_client, &target_channel)) {
    send_fail(sptr, "METADATA", "INVALID_TARGET", target,
              "Invalid target");
    return 0;
  }

  if (!can_modify_target(sptr, target, is_channel, target_client, target_channel)) {
    const char *err_target = (target[0] == '*' && !target[1])
                              ? cli_name(sptr) : target;
    send_fail_ctx(sptr, "METADATA", "KEY_NO_PERMISSION",
                  "You don't have permission to set metadata on this target",
                  "%s %s", err_target, key);
    return 0;
  }

  /* Check limits */
  switch (metadata_check_limits(target_client, target_channel, is_channel, key, value)) {
  case METADATA_LIMIT_UTF8:
    send_fail(sptr, "METADATA", "VALUE_INVALID", NULL, "value is not valid UTF-8");
    return 0;
  case METADATA_LIMIT_VALUE:
    send_fail(sptr, "METADATA", "VALUE_INVALID", NULL, "value is too long");
    return 0;
  case METADATA_LIMIT_KEYS:
    send_fail(sptr, "METADATA", "LIMIT_REACHED", key, "Maximum number of metadata keys reached");
    return 0;
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

  /* Expand "*" to client's nick.  Used for both local subscriber
   * notifications and the S2S broadcast — `*` is meaningful only in
   * the client→server direction (means "the sender's self") and has
   * no defined meaning in server→server traffic.  If we forwarded the
   * literal `*` peers would FindUser("*") → NULL and silently drop
   * the metadata, producing the bug where cross-server self-metadata
   * was unreachable. */
  const char *wire_target = (target[0] == '*' && !target[1]
                             && !is_channel && target_client)
                             ? cli_name(target_client) : target;

  /* Notify local subscribers (only for public metadata) */
  if (visibility == METADATA_VIS_PUBLIC) {
    notify_subscribers(wire_target, key, value);
  }

  /* Propagate to other servers with visibility */
  if (value) {
    sendcmdto_serv_butone_v3(sptr, CMD_METADATA, NULL, "%s %s %s :%s",
                          wire_target, key,
                          visibility == METADATA_VIS_PRIVATE ? "P" : "*",
                          value);
  } else {
    sendcmdto_serv_butone_v3(sptr, CMD_METADATA, NULL, "%s %s",
                          wire_target, key);
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

  target = parv[1];

  if (!can_see_target(sptr, target, &is_channel, &target_client, &target_channel)) {
    send_fail(sptr, "METADATA", "INVALID_TARGET", target,
              "Invalid target");
    return 0;
  }

  /* Wrap responses in a metadata batch */
  send_batch_start(sptr, "metadata");

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

  send_batch_end(sptr);
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

  target = parv[1];

  if (!can_see_target(sptr, target, &is_channel, &target_client, &target_channel)) {
    send_fail(sptr, "METADATA", "INVALID_TARGET", target,
              "Invalid target");
    return 0;
  }

  if (!can_modify_target(sptr, target, is_channel, target_client, target_channel)) {
    const char *err_target = (target[0] == '*' && !target[1])
                              ? cli_name(sptr) : target;
    send_fail_ctx(sptr, "METADATA", "KEY_NO_PERMISSION",
                  "You don't have permission to clear metadata on this target",
                  "%s *", err_target);
    return 0;
  }

  /* Broadcast a per-key unset for every key we are about to clear, BEFORE
   * clearing (the clear frees the list we enumerate). CLEAR previously
   * emitted NOTHING to other servers: the SET path broadcasts and populates
   * the target's in-memory metadata on EVERY server, but no layer ever
   * invalidated those remote copies, so remote nodes kept serving deleted
   * values until the user quit (clocktest M8 finding, 2026-07-24). The
   * value-less "MD <target> <key>" form is the existing unset wire format;
   * ms_metadata applies it under the doc-mirror suspend guard and relays it
   * onward. For USER targets metadata_set_client(NULL) clears both memory
   * and the store row (so the restored GET store-promotion has nothing to
   * re-animate). For CHANNEL targets metadata_set_channel(NULL) clears only
   * memory — channel rows are not doc-converged and metadata_clear_channel
   * never deletes the store either, a pre-existing channel-metadata store
   * leak (tracked separately); this at least propagates the memory clear.
   * Enumeration source is the in-memory list, so a key that is in the store
   * but was never hydrated into this origin's memory is not broadcast — a
   * narrow residual (offline SET + a no-load_account attach); the common
   * in-session SET/CLEAR path is fully covered. Bounded by the key budget. */
  {
    const char *wire_target = (target[0] == '*' && !target[1]
                               && !is_channel && target_client)
                               ? cli_name(target_client) : target;
    struct MetadataEntry *entry = is_channel
                                    ? metadata_list_channel(target_channel)
                                    : metadata_list_client(target_client);
    for (; entry; entry = entry->next)
      sendcmdto_serv_butone_v3(sptr, CMD_METADATA, NULL, "%s %s",
                               wire_target, entry->key);
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

  if (parc < 4) {
    send_fail(sptr, "METADATA", "INVALID_PARAMS", NULL,
              "SUB requires at least one key");
    return 0;
  }

  max_subs = feature_int(FEAT_METADATA_MAX_SUBS);

  for (i = 3; i < parc; i++) {
    const char *key = parv[i];

    if (!is_valid_key(key)) {
      send_fail(sptr, "METADATA", "KEY_INVALID", key,
                "Invalid key name");
      continue;
    }

    /* Check if already at limit */
    if (metadata_sub_count(sptr) >= max_subs) {
      send_fail(sptr, "METADATA", "TOO_MANY_SUBS", key,
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

  if (parc < 4) {
    send_fail(sptr, "METADATA", "INVALID_PARAMS", NULL,
              "UNSUB requires at least one key");
    return 0;
  }

  for (i = 3; i < parc; i++) {
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

  send_batch_start(sptr, "metadata-subs");

  sub = metadata_sub_list(sptr);
  while (sub) {
    send_reply(sptr, RPL_METADATASUBS, sub->key);
    sub = sub->next;
  }

  send_batch_end(sptr);

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

  target = parv[1];

  if (!can_see_target(sptr, target, &is_channel, &target_client, &target_channel)) {
    send_fail(sptr, "METADATA", "INVALID_TARGET", target,
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

  /* draft/metadata-2 format: METADATA <target> <subcommand> [args...]
   * parv[1] = target, parv[2] = subcommand */
  if (parc < 3 || EmptyString(parv[2])) {
    send_fail(sptr, "METADATA", "INVALID_PARAMS", NULL,
              "Usage: METADATA <target> <subcommand>");
    return 0;
  }

  subcmd = parv[2];

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
    send_fail(sptr, "METADATA", "SUBCOMMAND_INVALID", subcmd,
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
 * parv[3] = visibility ("*" or "P") (optional for backwards compat)
 * parv[4] = value (optional)
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
  struct Client *target_client = NULL;
  struct Channel *target_channel = NULL;

  if (parc < 3)
    return 0;

  target = parv[1];
  key = parv[2];

  /* Parse visibility and value.
   * Normal format: target key [visibility] [:value]
   * Old format: target key [:value]
   */
  if (parc >= 4) {
    /* Check if parv[3] is a visibility token */
    if ((parv[3][0] == '*' && parv[3][1] == '\0') ||
        (parv[3][0] == 'P' && parv[3][1] == '\0')) {
      visibility = (parv[3][0] == 'P') ? METADATA_VIS_PRIVATE : METADATA_VIS_PUBLIC;

      if (parc >= 5)
        value = parv[4];
    } else {
      /* Old format or no visibility - parv[3] is value */
      value = parv[3];
    }
  }

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

  /* Enforce the same limits every other write path obeys.  On violation
   * nothing happens: no apply, no cache, no notify, no relay.  This
   * stops the flood at the first hop; caps are uniform across the
   * network so a compliant origin never triggers this. */
  if (value
      && metadata_check_limits(target_client, target_channel, is_channel,
                               key, value) != METADATA_LIMIT_OK) {
    log_write(LS_SYSTEM, L_WARNING, 0,
              "ms_metadata: limit exceeded for %s/%s from %s — dropped, not relayed",
              target, key, cli_name(sptr));
    return 0;
  }

  /* Apply the change with visibility */
  if (is_channel) {
    metadata_set_channel(target_channel, key, value, visibility);
  } else if (target_client) {
    metadata_set_client(target_client, key, value, visibility);
  }

  /* Cache S2S metadata to LMDB (Nefarious is authoritative) */
  if (value) {
    const char *cache_key = NULL;

    /* User targets: nothing to do here.  metadata_set_client() above
     * already persisted the row PERMANENTLY for authed users
     * (metadata_account_set_permanent).  This block used to re-write
     * the same account\0key row via metadata_account_set() — a
     * TTL-stamped write that silently downgraded permanent user
     * metadata to a 4h cache entry, which the purge sweep then
     * deleted.  Channels keep the cache write below: it is their only
     * persistence path. */
    if (target_channel) {
      /* Channel - cache under channel name */
      cache_key = target;
    }

    if (cache_key && metadata_lmdb_is_available()) {
      /* TTL-class row: metadata_account_set_ts prefixes only when private
       * (bare = public), preserving this cache's on-disk shape exactly —
       * the P:/ *: encode lives wholly in set_ts now, not here. */
      metadata_account_set(cache_key, key, value, visibility);
      log_write(LS_DEBUG, L_DEBUG, 0,
                "ms_metadata: Cached metadata %s/%s in LMDB", cache_key, key);
    }
  }

  /* Notify local subscribers (only for public metadata) */
  if (visibility == METADATA_VIS_PUBLIC) {
    notify_subscribers(target, key, value);
  }

  /* Propagate to other servers */
  if (value) {
    sendcmdto_serv_butone_v3(sptr, CMD_METADATA, cptr, "%s %s %s :%s",
                          target, key,
                          visibility == METADATA_VIS_PRIVATE ? "P" : "*",
                          value);
  } else {
    sendcmdto_serv_butone_v3(sptr, CMD_METADATA, cptr, "%s %s",
                          target, key);
  }

  return 0;
}
