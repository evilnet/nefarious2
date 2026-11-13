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
#include "crdt_hlc.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "list.h"
#include "metadata.h"
#include "metadata_lww.h"
#include "metadata_sync.h"
#include "msg.h"
#include "numeric.h"
#include "s_bsd.h"
#include "s_user.h"
#include "send.h"

#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <limits.h>

/* Forward declarations */
static int metadata_cmd_get(struct Client *sptr, int parc, char *parv[]);
static int metadata_cmd_set(struct Client *sptr, int parc, char *parv[]);
static int metadata_cmd_list(struct Client *sptr, int parc, char *parv[]);
static int metadata_cmd_clear(struct Client *sptr, int parc, char *parv[]);
static int metadata_cmd_sub(struct Client *sptr, int parc, char *parv[]);
static int metadata_cmd_unsub(struct Client *sptr, int parc, char *parv[]);
static int metadata_cmd_subs(struct Client *sptr, int parc, char *parv[]);
static int metadata_cmd_sync(struct Client *sptr, int parc, char *parv[]);

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

/** Whether @a sptr may apply/relay a write that identifies its target by
 * Client (nick form, session form): true when @a target_client is
 * actually BEHIND @a sptr (its own user, or @a sptr is this server
 * relaying for its own locally-connected user), or the write is
 * @a target_client applying to itself, or @a sptr is an acting oper (who
 * may legitimately act on behalf of any user).  Otherwise a server could
 * claim to set metadata on a user it does not own.  Shared by every
 * ms_metadata branch that addresses a specific Client by identity, so
 * the rule reads identically everywhere it applies (originally the
 * nick-form-only guard in ms_metadata; Task 4 reuses it for the session
 * form instead of writing a second version).
 *
 * A bouncer device (alias) of @a target_client also qualifies: an alias
 * carries its primary's nick, another server's alias is not in the nick
 * hash, so a nick-addressed write from a device resolves to its primary
 * here, and send.c keeps the device's own numeric toward the primary's
 * server (its alias->primary rewrite skips that direction).  The test is
 * the alias pointer, which only BX C sets (never the nick), so a nick
 * collision cannot pass it; and the parser has already checked that
 * @a sptr is behind the link the line came in on (its fake-direction
 * check), exactly as it has for @a target_client == @a sptr, so a server
 * cannot speak for a device it does not host.
 */
static int md_sender_owns_client(struct Client *sptr, struct Client *target_client)
{
  return (cli_user(target_client) && cli_user(target_client)->server == sptr)
         || target_client == sptr
         || (IsUser(sptr) && IsBouncerAlias(sptr)
             && cli_alias_primary(sptr) == target_client)
         || (IsUser(sptr) && IsOper(sptr));
}

/** Notify all clients subscribed to a metadata key about a change.
 * PUBLIC: subscribed viewers sharing a channel with / being the target user
 * (or any member, for a channel target).  PRIVATE: only the target's own
 * subscribed sessions (same account, covering bouncer aliases — see
 * metadata.h for the full contract).
 * @param[in] target Target name (nick or channel).
 * @param[in] key Metadata key that changed.
 * @param[in] value New value (NULL if deleted).
 * @param[in] visibility METADATA_VIS_PUBLIC or METADATA_VIS_PRIVATE.
 */
void metadata_notify_subscribers(const char *target, const char *key,
                                 const char *value, int visibility)
{
  metadata_notify_subscribers_butone(target, key, value, visibility, NULL);
}

void metadata_notify_subscribers_butone(const char *target, const char *key,
                                        const char *value, int visibility,
                                        struct Client *butone)
{
  struct Client *acptr;
  struct Client *target_cli = NULL;
  struct Channel *target_chptr = NULL;
  const char *target_account = NULL;
  int fd;

  /* Resolve target for visibility checks */
  if (IsChannelPrefix(*target))
    target_chptr = FindChannel(target);
  else
    target_cli = FindUser(target);

  if (visibility == METADATA_VIS_PRIVATE) {
    /* Private: deliver ONLY to the target's own (subscribed) sessions — no
     * channel-share fan-out.  A channel target has no session "owner"
     * (matches can_view_metadata(): a channel's private entries pass
     * owner==NULL, visible only to opers) so there is nothing to notify. */
    if (!target_cli)
      return;
    /* Match by account only for a NON-EMPTY account.  WEBIRC TRUSTACCOUNT
     * (m_webirc.c) sets IsAccount() from a caller-supplied account string
     * that CAN be empty (no non-empty guard there, unlike the bouncer alias
     * path) — without the [0] check two empty-account clients would
     * ircd_strcmp("","")==0 and an unrelated client would pass the owner
     * filter and receive the private value.  An empty-account target falls
     * through to the pointer-identity branch below (exact Client* only),
     * which is correct — nobody but that literal client is "the owner". */
    if (IsAccount(target_cli) && cli_account(target_cli)[0])
      target_account = cli_account(target_cli);
  }

  /* Iterate over all local clients */
  for (fd = HighestFd; fd >= 0; --fd) {
    if (!(acptr = LocalClientArray[fd]))
      continue;
    if (acptr == butone || !IsUser(acptr))
      continue;
    if (!MetadataAware(acptr))
      continue;

    /* Check if subscribed to this key */
    if (!metadata_sub_check(acptr, key))
      continue;

    if (visibility == METADATA_VIS_PRIVATE) {
      /* Self-sessions only.  Account-anchored targets match by cli_account
       * so every bouncer alias / other concurrent login under the SAME
       * account is reached — aliases are removed from the nick hash, so a
       * plain acptr==target_cli check would see only the primary and
       * undercount.  target_account is guaranteed non-empty here (set above
       * only when cli_account[0]), so a recipient that is IsAccount but has
       * an EMPTY account fails ircd_strcmp(nonempty,"")!=0 and is correctly
       * skipped — the WEBIRC empty-account cross-delivery hole is closed on
       * both the target and recipient sides.  Empty-account / unauthenticated
       * targets have no multi-session concept: exact identity is the whole
       * story (the else-if pointer check). */
      if (target_account) {
        if (!IsAccount(acptr) || ircd_strcmp(cli_account(acptr), target_account) != 0)
          continue;
      } else if (acptr != target_cli) {
        continue;
      }
    } else if (target_cli) {
      /* Visibility: for user metadata, only notify if they share a channel
       * or are the target themselves. */
      if (acptr != target_cli && !shares_channel(acptr, target_cli))
        continue;
    } else if (target_chptr) {
      /* For channel metadata, only if member. */
      if (!find_member_link(target_chptr, acptr))
        continue;
    }

    /* Send notification: METADATA <target> <key> <visibility> [:<value>].
     * The spec's Visibility: "an asterisk (*) for keys visible to
     * everyone, or an implementation-defined value which describes the
     * key's visibility status" -- "private" here, as RPL_KEYVALUE and the
     * registration burst say it (get_visibility_str()). */
    if (value && *value) {
      sendrawto_one(acptr, ":%s METADATA %s %s %s :%s",
                    cli_name(&me), target, key,
                    visibility == METADATA_VIS_PRIVATE ? "private" : "*",
                    value);
    } else {
      /* Unset: no value parameter */
      sendrawto_one(acptr, ":%s METADATA %s %s %s",
                    cli_name(&me), target, key,
                    visibility == METADATA_VIS_PRIVATE ? "private" : "*");
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

  if (!MyUser(joiner) || !MetadataAware(joiner))
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
 * A key that EXISTS but is private-denied to this viewer ALSO answers 766
 * (era-2 deliberate: denied is indistinguishable from absent, so key
 * existence never leaks — see the can_view branches below).
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
        /* Fetch the decoded visibility via the out-param instead of locally
         * parsing "P:" — metadata_account_get_vis() returns the value
         * already stripped, so a local parse would never match. */
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
            if (!can_view) {
              /* Existence-leak fix (spec "Known deferrals" #3): reply
               * exactly as the absent case does (display-expansion
               * pattern below, matching :578) instead of silently
               * skipping, so a denied private key is indistinguishable
               * from a key that doesn't exist at all.  VALUE is still
               * never sent here — this only closes the exists-vs-absent
               * side channel (the A2 VALUE-hiding guarantee is untouched). */
              send_reply(sptr, RPL_KEYNOTSET,
                         (target[0] == '*' && !target[1]
                          && IsUser(sptr) && cli_name(sptr)[0])
                         ? cli_name(sptr) : target,
                         key);
              continue;  /* Skip to next key, don't reveal private data */
            }
          }

          if (*val) {
            send_keyvalue(sptr, target, key, val, vis_str);
            found = 1;

            /* For online users, also cache into memory for faster subsequent
             * access — memory-only: this is a read, it must not re-persist
             * to the store or re-mint a doc op (metadata_memory_put, not
             * metadata_set_client). */
            if (target_client) {
              metadata_memory_put(target_client, key, val, vis);
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
        /* Rows are keyed by the channel's canonical spelling (every
         * writer passes chptr->chname) and the key builder never folds
         * case, so look up by the resolved channel, not the client's
         * spelling (case-fold audit 2026-09-02). */
        const char *chan_key = target_channel ? target_channel->chname : target;
        /* Decoded visibility comes from the out-param — see the matching
         * comment in the user GET fallback above. */
        if (metadata_account_get_vis(chan_key, key, value_buf, sizeof(value_buf), &vis) == 0) {
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
            if (!can_view) {
              /* Existence-leak fix, same as the user-branch fix above:
               * reply 766 instead of silently skipping so denied == absent. */
              send_reply(sptr, RPL_KEYNOTSET,
                         (target[0] == '*' && !target[1]
                          && IsUser(sptr) && cli_name(sptr)[0])
                         ? cli_name(sptr) : target,
                         key);
              continue;  /* Skip, don't reveal private channel data */
            }
          }

          if (*val) {
            send_keyvalue(sptr, target, key, val, vis_str);
            found = 1;

            /* Load into channel's in-memory metadata (if channel exists) —
             * cache-fill only.  metadata_set_channel is now the +R persist
             * chokepoint (B1): calling it here would re-persist and
             * doc-mint a value this read merely fetched from the TTL
             * cache.  metadata_channel_memory_put is the memory-only
             * counterpart — reads never write (Global Constraints) —
             * mirroring metadata_memory_put's use in the user GET-fallback
             * above; vis comes from the decoded out-param above, not a
             * local "P:" parse. */
            if (target_channel) {
              metadata_channel_memory_put(target_channel, key, val, vis);
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

/** Check metadata_check_limits() (UTF-8 + length) plus @a account_name's
 * persisted key count against FEAT_METADATA_MAX_KEYS, for a write that
 * has no live local Client to check the key budget against directly --
 * the offline-account oper write (this file's "*account" SET branch)
 * and the inbound W4 stamped-account row (ms_metadata_stamped) both
 * need this.  Updates to an existing key are always allowed at cap,
 * same as the live-Client path metadata_check_limits() already
 * implements via metadata_count_client(). */
static int metadata_check_account_limits(const char *account_name,
                                         const char *key, const char *value)
{
  int limit_rc = metadata_check_limits(NULL, NULL, 0, key, value);

  if (limit_rc == METADATA_LIMIT_OK && !metadata_key_is_server_managed(key)) {
    char scratch[METADATA_VALUE_LEN];
    int max_keys = feature_int(FEAT_METADATA_MAX_KEYS);

    if (max_keys < 0)
      max_keys = 0;
    if (metadata_account_get(account_name, key, scratch) != 0
        && metadata_account_count_keys(account_name) >= max_keys)
      limit_rc = METADATA_LIMIT_KEYS;
  }
  return limit_rc;
}

/** Render a metadata_check_limits()/metadata_check_account_limits()
 * failure code as the oper-facing reason mdsync_limit_notice() logs and
 * notices (W4 plan 1.8's three wire-table strings, the last two with
 * the live limit substituted in). */
static const char *metadata_limit_why(int limit_rc)
{
  static char buf[64];

  switch (limit_rc) {
  case METADATA_LIMIT_UTF8:
    return "value is not UTF-8";
  case METADATA_LIMIT_VALUE:
    ircd_snprintf(0, buf, sizeof(buf), "value over METADATA_MAX_VALUE_BYTES %d",
                  feature_int(FEAT_METADATA_MAX_VALUE_BYTES));
    return buf;
  case METADATA_LIMIT_KEYS:
    ircd_snprintf(0, buf, sizeof(buf), "key count at METADATA_MAX_KEYS %d",
                  feature_int(FEAT_METADATA_MAX_KEYS));
    return buf;
  default:
    return "over this server's METADATA limits";
  }
}

/** Does a value fit every line that will carry it to a client?  A value
 * is shown, now and on every later GET, LIST, SYNC or subscription, as
 *   ":" <server> " 761 " <viewer> " " <target> " " <key> " " <vis> " :" <value>
 * (RPL_KEYVALUE; the METADATA notification ":" <server> " METADATA "
 * <target> " " <key> " * :" <value> is shorter), and everything after
 * the tags must fit 510 bytes -- or the msgq backstop cuts the value, a
 * structured one included, for whoever reads it.  The server, the
 * viewer and a user target's nick are not known when the value is set
 * (another server answers its own clients from its copy; anyone may
 * GET it; the nick can change), so they are taken at their longest:
 * HOSTLEN, NICKLEN and NICKLEN.  A channel's name and the key are
 * known.  So FEAT_METADATA_MAX_VALUE_BYTES' 300 holds for a user's key
 * of up to 63 bytes set public, and a private one or a channel with a
 * long name gets less: 300 is true by construction only where it fits.
 * @return 1 if the value fits, 0 if it is to be refused (VALUE_INVALID). */
static int metadata_value_fits_line(int is_channel, const char *target,
                                    const char *key, const char *value,
                                    int visibility)
{
  size_t tlen = strlen(target);
  size_t vis = (visibility == METADATA_VIS_PRIVATE) ? strlen("private") : 1;
  size_t line;

  if (!value)
    return 1;  /* a delete carries no value */
  if (!is_channel && tlen < NICKLEN)
    tlen = NICKLEN;
  line = ircd_keyvalue_line_len(HOSTLEN, NICKLEN, tlen, strlen(key), vis,
                                strlen(value));
  return line <= BUFSIZE - 2;
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

    /* W4: one stamped account write (metadata_account_write): the row
     * (or tombstone) and its clock row in one batch, applied to EVERY
     * client of the account (local and remote), and sent to every fork
     * peer as the stamped "MD =account" row, which they merge by the
     * stamp.  This closes the era-2 §A4 NODE-LOCAL limitation, whose live
     * consequence was a peer retaining a stale draft/persistence/hold
     * row after pool cleanup ran through an oper on one server only
     * (Gap B, bouncer-promotion scope).  Task 8 moved this from the
     * unstamped "*account" form (which each receiver stamped itself) to
     * "=account": a fork peer must run W4 push 1 to take it -- an older
     * one drops it (RECEIVER-FIRST). */
    {
      struct Client *acptr;
      struct Client *first_online = NULL;
      int fd;

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
        int limit_rc = first_online
          ? metadata_check_limits(first_online, NULL, 0, key, value)
          : metadata_check_account_limits(account_name, key, value);

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
        if (!metadata_value_fits_line(0, target, key, value, visibility)) {
          send_fail(sptr, "METADATA", "VALUE_INVALID", NULL, "value is too long");
          return 0;
        }
      }

      if (metadata_account_write(sptr, account_name, key, value, visibility) < 0) {
        send_fail(sptr, "METADATA", "INTERNAL_ERROR", key,
                  "Failed to set account metadata");
        return 0;
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
  if (!metadata_value_fits_line(is_channel,
                                is_channel ? target_channel->chname : target,
                                key, value, visibility)) {
    send_fail(sptr, "METADATA", "VALUE_INVALID", NULL, "value is too long");
    return 0;
  }

  /* A user's key: one write addressed by its account, else its session
   * (metadata_client_write: memory, store, subscribers and every fork
   * peer -- for an account, every client of it, here and there).  W4
   * Task 8: never by nick unless no session id crosses (tags off). */
  if (!is_channel) {
    rc = metadata_client_write(sptr, target_client, key, value, visibility);
    if (rc == -2) {
      /* Before registration: more sets or deletes noted than the account
       * could hold keys for (metadata_prereg_record()). */
      send_fail(sptr, "METADATA", "LIMIT_REACHED", key,
                "Maximum number of metadata keys reached");
      return 0;
    }
    if (rc < 0) {
      send_fail(sptr, "METADATA", "INTERNAL_ERROR", key,
                "Failed to set metadata");
      return 0;
    }
    send_keyvalue(sptr, target, key, value,
                  visibility == METADATA_VIS_PRIVATE ? "private" : "*");
    return 0;
  }

  /* Perform the set/delete */
  rc = metadata_set_channel(target_channel, key, value, visibility);

  if (rc < 0) {
    send_fail(sptr, "METADATA", "INTERNAL_ERROR", key,
              "Failed to set metadata");
    return 0;
  }

  /* Send confirmation with visibility */
  send_keyvalue(sptr, target, key, value,
                visibility == METADATA_VIS_PRIVATE ? "private" : "*");

  /* Channel target from here on (a user's key returned above).  Notify
   * local subscribers.  Vis-aware (Task 5, §A6): public reaches
   * subscribed members; private reaches nobody (a channel has no
   * session owner) -- see metadata_notify_subscribers. */
  metadata_notify_subscribers(target, key, value, visibility);

  /* Propagate to other servers with visibility */
  if (value) {
    sendcmdto_serv_butone_v3(sptr, CMD_METADATA, NULL, "%s %s %s :%s",
                          target, key,
                          visibility == METADATA_VIS_PRIVATE ? "P" : "*",
                          value);
  } else {
    sendcmdto_serv_butone_v3(sptr, CMD_METADATA, NULL, "%s %s",
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

/** One key a user CLEAR deletes (its name and visibility, copied out of
 * the list or the store walk before the deletes change either). */
struct md_clear_key {
  struct md_clear_key *next;
  int vis;
  char key[1];   /* allocated to fit */
};

static void md_clear_key_push(struct md_clear_key **head, const char *key, int vis)
{
  size_t len = strlen(key);
  struct md_clear_key *k = (struct md_clear_key *)MyMalloc(sizeof(*k) + len);

  if (!k)
    return;
  memcpy(k->key, key, len + 1);
  k->vis = vis;
  k->next = *head;
  *head = k;
}

static void md_clear_key_free(struct md_clear_key *head)
{
  while (head) {
    struct md_clear_key *next = head->next;
    MyFree(head);
    head = next;
  }
}

/** metadata_account_clear_keys() callback for a user CLEAR's store
 * residue: delete the row, stamped, everywhere (metadata_account_write). */
struct md_clear_residue { struct Client *sptr; const char *account; };

static void md_clear_residue_one(void *arg, const char *key, int vis)
{
  struct md_clear_residue *r = arg;

  metadata_account_write(r->sptr, r->account, key, NULL, vis);
}

/** METADATA CLEAR on a user: delete each of its keys the way SET deletes
 * one (metadata_client_write: by account, else by session id), so every
 * server and -- for an account -- every client of it loses the key, and
 * subscribers are told.  draft/persistence/ keys are not the user's to
 * clear (SET refuses them too): the hold and replay preferences and the
 * profiles stay, here and on every other server (user-accepted fix,
 * 2026-11-01; this used to wipe them through metadata_clear_client's
 * whole-account store wipe).  For an account, the store's rows that no
 * client here holds in memory (an offline SET, a key this client never
 * loaded) are deleted too, as stamped tombstones every peer merges.
 * The requester gets a `metadata` batch with one RPL_KEYNOTSET per key
 * it held in memory (#605), before the deletes.
 */
static void metadata_clear_user(struct Client *sptr, const char *display_target,
                                struct Client *target_client)
{
  struct md_clear_key *keys = NULL, *k;
  struct MetadataEntry *entry;

  /* Copied out first: every delete below edits this list.  For an
   * account, not an internal key: last_present sits in the list
   * (metadata_load_account loads every live row) but is this server's
   * own observation, and a delete of it would go out as a tombstone
   * every peer merges (push-2 final fix wave, M-2 / Task 8 M1). */
  for (entry = metadata_list_client(target_client); entry; entry = entry->next)
    if (!metadata_key_is_server_managed(entry->key)
        && (!cli_user(target_client)->account[0]
            || md_key_replicable(entry->key)))
      md_clear_key_push(&keys, entry->key, entry->visibility);

  send_batch_start(sptr, "metadata");
  for (k = keys; k; k = k->next)
    send_reply(sptr, RPL_KEYNOTSET, display_target, k->key);
  send_batch_end(sptr);

  /* Before registration (owner, 2026-11-13: a CLEAR before registration
   * clears it all, as the spec says CLEAR does).  The answer above names
   * the keys the client has in memory -- all it may be told of: the keys
   * it set, and for a client that already carries an account, what LIST
   * would show it now; never the account's other keys, for which it may
   * not be authenticated yet.  They leave its memory; the CLEAR itself is
   * noted, stamped now (metadata_prereg_record_clear()), and voids every
   * earlier note.  When registration ends logged in and metadata-aware,
   * it deletes every live user key of the account, as a CLEAR right after
   * login would, before the notes made after it apply; without a login,
   * the client's own keys were all it meant. */
  if (MyConnect(target_client) && !IsRegistered(target_client)) {
    struct md_stamp st = metadata_stamp_now();

    for (k = keys; k; k = k->next)
      metadata_client_memory_set(target_client, k->key, NULL, k->vis);
    md_clear_key_free(keys);
    if (metadata_prereg_record_clear(target_client, &st) < 0)
      send_fail(sptr, "METADATA", "INTERNAL_ERROR", display_target,
                "Failed to clear metadata");
    return;
  }

  /* The account's CLEAR floor, stamped before the deletes below (owner,
   * 2026-11-13): a value written before this CLEAR that reaches this server
   * later -- a pull answer, a burst, a relay from a server the deletes did
   * not reach -- is taken as a tombstone at it (ms_metadata_stamped()). */
  if (cli_user(target_client)->account[0] && metadata_lmdb_is_available()) {
    struct md_stamp tc = metadata_stamp_now();

    metadata_account_floor_raise(cli_user(target_client)->account, &tc);
  }

  for (k = keys; k; k = k->next)
    metadata_client_write(sptr, target_client, k->key, NULL, k->vis);
  md_clear_key_free(keys);

  /* The account's other rows: every live user key in the store that no
   * client here held in memory (metadata_account_clear_keys(), the set a
   * before-connect CLEAR deletes at the merge too). */
  if (cli_user(target_client)->account[0] && metadata_lmdb_is_available()) {
    struct md_clear_residue r;

    r.sptr = sptr;
    r.account = cli_user(target_client)->account;
    metadata_account_clear_keys(r.account, md_clear_residue_one, &r);
  }
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

  if (!is_channel) {
    /* "*" is the client's nick once it has one; before registration it
     * stays "*" (an empty parameter would break every line it is in). */
    metadata_clear_user(sptr, (target[0] == '*' && !target[1]
                               && cli_name(target_client)[0])
                              ? cli_name(target_client) : target,
                        target_client);
    return 0;
  }

  /* Channel target from here on (a user's CLEAR returned above).
   * Broadcast a per-key unset for every key we are about to clear, BEFORE
   * clearing (the clear frees the list we enumerate). CLEAR previously
   * emitted NOTHING to other servers: the SET path broadcasts and populates
   * the target's in-memory metadata on EVERY server, but no layer ever
   * invalidated those remote copies, so remote nodes kept serving deleted
   * values until the user quit (clocktest M8 finding, 2026-07-24). The
   * value-less "MD <target> <key>" form is the existing unset wire format;
   * ms_metadata applies it under the doc-mirror suspend guard and relays it
   * onward. (A USER target's CLEAR is metadata_clear_user's, above.)
   * For CHANNEL targets, metadata_set_channel(NULL) on each
   * RELAY deletes that relay's own +R store row too (the +R persist leg,
   * mint self-skipped under the suspend guard) — only the ORIGIN was left
   * out: metadata_clear_channel() below is memory-only and is never routed
   * through metadata_set_channel(), so the origin's own store rows leaked
   * and no doc tombstone was ever minted. The doc still held the SETs, so
   * reconcile_metadata_set_cb (doc-present + store-missing) re-healed the
   * "cleared" values back into every store within ~30s — mesh-wide
   * resurrection for any +R channel CLEAR. Closed below (Metadata P2 final
   * review finding).
   * Enumeration source is the in-memory list. Bounded by the key budget. */
  {
    struct MetadataEntry *entry = metadata_list_channel(target_channel);
    for (; entry; entry = entry->next)
      sendcmdto_serv_butone_v3(sptr, CMD_METADATA, NULL, "%s %s",
                               target, entry->key);
  }

  /* #605: the requester gets a `metadata` batch with one RPL_KEYNOTSET
   * per cleared key (this used to send NOTHING -- the dangling
   * "send empty keyvalue?" question below).  Enumerate BEFORE the wipe,
   * same source as the S2S loop above. */
  {
    struct MetadataEntry *entry = metadata_list_channel(target_channel);
    send_batch_start(sptr, "metadata");
    for (; entry; entry = entry->next)
      send_reply(sptr, RPL_KEYNOTSET, target, entry->key);
    send_batch_end(sptr);
  }

  {
    metadata_clear_channel(target_channel);

    /* Close the resurrection gap the comment above describes: wipe the
     * ORIGIN's own leaked "#chan\0*" store rows (metadata_account_clear —
     * the same call channel.c's -R hook, mode_channel_registered_hook(),
     * uses for the exact same wipe; on crdt-mesh it also mints the per-key
     * doc tombstones there).
     *
     * This is scoped to THIS call site rather than folded into
     * metadata_clear_channel() itself, deliberately: that function has a
     * SECOND caller — metadata_free_channel() (metadata.c), reached from
     * destruct_channel() on ordinary empty-channel GC (sub1_from_channel(),
     * every node, whenever the channel's local membership independently
     * drains to 0 — not a CLEAR, and not origin-gated). channel.c's own
     * mode_channel_registered_hook() header already documents that exact
     * call site as one that "MUST stay unhooked" from a store wipe: a +R
     * channel going momentarily empty must not destroy its persisted
     * metadata. Folding this into metadata_clear_channel() would have
     * silently re-created that hazard (every node wiping a registered
     * channel's permanent store the moment it emptied out) instead of
     * fixing the narrower CLEAR-only bug.
     *
     * Minting only here is single-writer-correct: metadata_cmd_clear runs
     * exclusively on the node that received the client's CLEAR — CLEAR has
     * no wire form of its own (it degrades to the per-key MD unsets
     * broadcast above, which every relay applies to its own store under
     * its own suspend bracket, per the comment above) — so exactly one
     * node ever mints these tombstones and every other node just
     * LWW-converges to them. */
    if ((target_channel->mode.mode & MODE_REGISTERED) &&
        metadata_lmdb_is_available())
      metadata_account_clear(target_channel->chname);
  }

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

  /* The reply is a metadata batch (its METADATA lines carry @batch=),
   * decided on the client's batch capability, never on whatever
   * cli_batch_id holds (an id left by an earlier unclosed batch would tag
   * the lines and never be closed).  m_metadata() admits only a client
   * that is metadata-aware, batch included (MetadataAware()), so this
   * holds unless the batch feature is turned off. */
  if (!feature_bool(FEAT_CAP_batch) || !CapActive(sptr, CAP_BATCH)) {
    send_reply(sptr, RPL_METADATASYNCLATER, target);
    return 0;
  }

  /* Start metadata batch */
  send_batch_start(sptr, "metadata");

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

  /* A metadata-aware client (the cap and batch, MetadataAware()), or one
   * still registering with the metadata capability: negotiation is not
   * over, and batch is judged when it ends (MetadataAware()'s note).  Such
   * a client may SET, SUB and UNSUB -- their replies (761, 770, 771) are
   * not batches; GET, LIST, CLEAR, SUBS and SYNC answer with a batch,
   * which does not exist before batch is negotiated, so they get what a
   * client without the capability gets (421), as does everything once
   * registered without batch. */
  if (!MetadataAware(sptr)
      && (IsRegistered(sptr) || !MetadataCapActive(sptr) || parc < 3
          || EmptyString(parv[2])
          || (ircd_strcmp(parv[2], "SET") && ircd_strcmp(parv[2], "SUB")
              && ircd_strcmp(parv[2], "UNSUB")))) {
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

  /* labeled-response: one labeled answer, whatever the subcommand sends
   * -- a typed metadata batch alone keeps the label on its BATCH + line;
   * a batch and a FAIL (GET with an invalid key), or several lines (SUB,
   * UNSUB with several keys), are one labeled batch; nothing is ACKed.
   * The count is made as the lines go out (labeled_batch_defer()). */
  labeled_batch_defer(sptr);

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
/** MD !sessid: an unauthenticated local client's ephemeral key, addressed
 * by session id since there is no account to address it by (W4 wire
 * table). A session id can legitimately or transiently name more than
 * one client (bouncer primary + aliases, kept-apart sessions, a
 * hard-mode double restore -- see client_find_by_session_id); apply
 * only when it currently names EXACTLY ONE IsUser client with no
 * account. An authenticated match is never written from a session
 * target -- that is what the account (`=`/`*`) forms are for.
 * @param[in] cptr The direct link this line arrived on (relay "butone").
 * @param[in] sptr Attributed origin of the write (relay "src").
 * @param[in] target parv[1], already known to classify as "!sessid".
 */
static int ms_metadata_session(struct Client *cptr, struct Client *sptr,
                               int parc, char *parv[], const char *target)
{
  const char *sessid = target + 1;
  const char *key;
  const char *value = NULL;
  int visibility = METADATA_VIS_PUBLIC;
  /* Realistic fan-out for one session id is small (a bouncer primary
   * plus its aliases, a kept-apart pair, at most a handful more -- see
   * list.c's client_find_by_session_id comment); this scan cap is
   * generous against that, independent of that function's own
   * (likewise generous) internal scratch cap. */
  enum { MD_SESSION_SCAN_MAX = 32 };
  struct Client *matches[MD_SESSION_SCAN_MAX];
  struct Client *only = NULL;
  size_t total, filled, i, qualified;

  if (parc < 3)
    return 0;

  key = parv[2];

  /* Same visibility/value parse as the nick/channel form below. */
  if (parc >= 4) {
    if ((parv[3][0] == '*' && parv[3][1] == '\0') ||
        (parv[3][0] == 'P' && parv[3][1] == '\0')) {
      visibility = (parv[3][0] == 'P') ? METADATA_VIS_PRIVATE : METADATA_VIS_PUBLIC;
      if (parc >= 5)
        value = parv[4];
    } else {
      value = parv[3];
    }
  }

  if (!is_valid_key(key))
    return 0;

  total = client_find_by_session_id(sessid, matches, MD_SESSION_SCAN_MAX);
  filled = (total < (size_t)MD_SESSION_SCAN_MAX) ? total : (size_t)MD_SESSION_SCAN_MAX;
  qualified = 0;
  for (i = 0; i < filled; i++) {
    if (IsAccount(matches[i]))
      continue;
    qualified++;
    only = matches[i];
  }
  /* total > filled means more raw IsUser matches exist than this scan
   * inspected -- already >= 2 matches, so this can never be "exactly
   * one" no matter how the unscanned remainder would have filtered. */
  if (total > (size_t)MD_SESSION_SCAN_MAX || qualified != 1) {
    log_write(LS_SYSTEM, L_DEBUG, 0,
              "ms_metadata: session target !%s/%s from %C matched %zu "
              "client(s), %zu unauthenticated - dropped, not relayed",
              sessid, key, sptr, total, qualified);
    return 0;
  }

  /* Session-target origin guard (md_sender_owns_client, same rule the
   * nick form uses): without this, any linked server could set an
   * unauthenticated local user's metadata just by naming its session
   * id -- there is no account to anchor the write, so identity-by-Client
   * is the whole guard.  L_WARNING, not L_DEBUG (fix round 2): this is
   * the same class of event -- a spoofed-ownership write -- as the
   * nick-form guard a few blocks below, which logs at L_WARNING; a
   * downgrade here would make the exact attack this guard exists to
   * stop invisible at production log levels while its nick-form twin
   * stays visible. */
  if (!md_sender_owns_client(sptr, only)) {
    log_write(LS_SYSTEM, L_WARNING, 0,
              "ms_metadata: session target !%s/%s from %C is not %s's "
              "server - dropped, not relayed",
              sessid, key, sptr, cli_name(only));
    return 0;
  }

  /* Enforce the same limits every other write path obeys.  Task 5 (W4
   * plan 1.8): on a violation, skip apply/notify and tell opers once
   * per link (mdsync_limit_notice), but still relay unchanged -- the
   * same rule every MD form now follows.  Only the origin guard above
   * still drops without relaying; an over-limit check never does. */
  {
    int limit_rc = METADATA_LIMIT_OK;

    if (value)
      limit_rc = metadata_check_limits(only, NULL, 0, key, value);

    if (limit_rc != METADATA_LIMIT_OK) {
      mdsync_limit_notice(cptr, target, key, metadata_limit_why(limit_rc));
    } else {
      /* metadata_set_client is memory-only here: `only` carries no
       * account, so its own IsAccount guard never takes the
       * LMDB-persist branch. */
      metadata_set_client(only, key, value, visibility);
      metadata_notify_subscribers(cli_name(only), key, value, visibility);
    }
  }

  /* Relay the line verbatim -- still "!sessid", never rewritten to a
   * nick -- to every other IRCv3-aware server, whether or not this
   * server applied it locally. */
  if (value)
    sendcmdto_serv_butone_v3(sptr, CMD_METADATA, cptr, "%s %s %s :%s",
                             target, key,
                             visibility == METADATA_VIS_PRIVATE ? "P" : "*",
                             value);
  else
    sendcmdto_serv_butone_v3(sptr, CMD_METADATA, cptr, "%s %s",
                             target, key);

  return 0;
}

/** MD ?: a hop-local pull request, never relayed. Accepted only from a
 * direct server link -- the wire table's other new forms could in
 * theory arrive relayed by an intermediate (still-)IRCv3-aware hop that
 * merely forwards what it does not understand, but a pull reply is
 * meaningful only to the asking link itself, so this guards against a
 * confused or hostile indirect sender forging the request.
 * @param[in] cptr The link asking (must equal @a sptr).
 */
static int ms_metadata_pull(struct Client *cptr, struct Client *sptr,
                            int parc, char *parv[])
{
  unsigned long seq;
  char scope;
  char *accounts[16];
  int n;

  if (!MyConnect(cptr) || sptr != cptr || !IsServer(sptr))
    return 0;

  /* The 16-accounts-per-request cap (the wire table's "MD ? ... <acct>
   * [,<acct>...]", <=16) is also a plan-mandated bound to log on a hit.
   * md_pull_parse folds "more than 16 names" into the same generic -1 as
   * every other malformed field (bad seq, bad scope, a too-long name),
   * so it alone can't tell us which one happened; count commas here --
   * cheaply, without re-validating anything md_pull_parse already owns
   * -- so only this specific, named cap gets its own L_WARNING instead
   * of every malformed pull doing so. */
  if (parc >= 5 && parv[4]) {
    const char *p = parv[4];
    int names = 1;

    for (; *p; p++) {
      if (*p == ',')
        names++;
    }
    if (names > 16) {
      log_write(LS_SYSTEM, L_WARNING, 0,
                "ms_metadata: pull request from %C names %d accounts, "
                "over the 16-account cap - dropped",
                sptr, names);
      return 0;
    }
  }

  n = md_pull_parse(parc, parv, &seq, &scope, accounts,
                    (int)(sizeof(accounts) / sizeof(accounts[0])));
  if (n < 0)
    return 0;

  mdsync_answer_pull(cptr, seq, scope, accounts, n);
  return 0;
}

/** MD .: the hop-local end marker closing a pull reply
 * (mdsync_answer_pull's own closing line), consumed by Task 10's EOB
 * queue to release its next batch.  Accepted only from a direct server
 * link, same rule and reasoning as "MD ?" (ms_metadata_pull): a reply
 * this close is meaningful only to the link whose request it closes,
 * never to some indirect hop merely forwarding it on.
 *
 * The sequence number is parsed here, by hand, rather than through
 * md_pull_parse (which expects the very different "? seq scope
 * accounts" layout): a malformed or out-of-range field is dropped at
 * L_DEBUG, not L_WARNING -- mdsync_on_pull_end treats a seq that
 * simply does not match this link's one outstanding request exactly
 * the same way, so a bad field here is no more a sign of real trouble
 * than that case is.
 * @param[in] cptr The link whose reply this closes (must equal @a sptr).
 */
static int ms_metadata_pull_end(struct Client *cptr, struct Client *sptr,
                                int parc, char *parv[])
{
  const char *p;
  unsigned long seq = 0;

  if (!MyConnect(cptr) || sptr != cptr || !IsServer(sptr))
    return 0;

  if (parc < 3 || !parv[2] || !parv[2][0]) {
    log_write(LS_SYSTEM, L_DEBUG, 0,
              "ms_metadata: pull-end from %C with no sequence number - "
              "ignored", sptr);
    return 0;
  }

  for (p = parv[2]; *p; p++) {
    unsigned long d;

    if (*p < '0' || *p > '9') {
      log_write(LS_SYSTEM, L_DEBUG, 0,
                "ms_metadata: pull-end from %C has a malformed sequence "
                "number '%s' - ignored", sptr, parv[2]);
      return 0;
    }
    d = (unsigned long)(*p - '0');
    if (seq > (ULONG_MAX - d) / 10) {
      log_write(LS_SYSTEM, L_DEBUG, 0,
                "ms_metadata: pull-end from %C has an out-of-range "
                "sequence number '%s' - ignored", sptr, parv[2]);
      return 0;
    }
    seq = seq * 10 + d;
  }

  mdsync_on_pull_end(cptr, seq);
  return 0;
}

/** MD =account: the W4 stamped account-metadata row (classify,
 * md_wire_key_valid, md_stamp_parse, the forward-clock-skew refusal,
 * chunk reassembly on the LINK's state, the limits rule every other
 * MD form obeys, then metadata_account_merge).  On take: apply memory
 * to every client of the account, then relay onward (unless this is
 * the last of several chunk pieces still pending).
 * @param[in] cptr The direct link this line arrived on (chunk identity
 *            and relay "butone" are both scoped to it).
 * @param[in] sptr Attributed origin of the row (relay "src").
 * @param[in] target parv[1], already known to classify as "=account".
 */
static int ms_metadata_stamped(struct Client *cptr, struct Client *sptr,
                               int parc, char *parv[], const char *target)
{
  const char *account_name = target + 1;
  const char *stamp_text;
  const char *wire_key;
  const char *flags_tok;
  const char *piece;
  struct md_stamp st;
  int vis = METADATA_VIS_PUBLIC;
  int tombstone = 0;
  int more = 0;
  struct md_chunk *chunk;
  int chunk_rc;
  struct md_version in;
  int merge_rc;

  /* Without a key nothing names a row: there is no chunk state to
   * touch.  A line that names one but has no flags token is refused
   * below, after the identity checks, through md_chunk_abandon (W4
   * push-1 fix-wave N3(c)): returning here left a refused head's tail to
   * be merged as the whole value. */
  if (parc < 4)
    return 0;

  stamp_text = parv[2];
  wire_key = parv[3];
  flags_tok = (parc >= 5) ? parv[4] : NULL;
  piece = (parc >= 6) ? parv[5] : "";

  /* Every refusal before md_chunk_feed must be the same for every piece
   * of one row, or a refused head would leave the rest to be merged as
   * the whole value (final review M1).  The account name, stamp text and
   * key are identical on every piece of a row (they are its identity),
   * so these checks are; the flags token is not (`*+` vs `*`), so its
   * refusal discards the rest of the row (md_chunk_abandon below); and
   * the clock-skew refusal, which reads a moving clock, waits until the
   * row is whole. */

  /* An account name never exceeds ACCOUNTLEN: refuse a longer one rather
   * than let the chunk identity (or a store row) carry a cut name that
   * is not an account (final review M2). */
  if (!account_name[0] || strlen(account_name) > ACCOUNTLEN)
    return 0;

  if (!md_wire_key_valid(wire_key))
    return 0;

  /* md_stamp_parse also refuses a stamp text too long for
   * MD_STAMP_BUFSIZE (M2). */
  if (md_stamp_parse(stamp_text, &st) < 0)
    return 0;

  chunk = mdsync_link_chunk(cptr);
  if (!chunk)
    return 0;

  if (!flags_tok || md_flags_parse(flags_tok, &vis, &tombstone, &more) < 0) {
    /* Whether pieces of the row follow this refused one.  Only a
     * one-character token that is not `+` says plainly that none do (a
     * flag with no continuation mark): then this was the row's last
     * piece, nothing follows to discard, and a poison would swallow the
     * row's next delivery instead (N3(b)).  Anything else may be a head
     * whose tail follows, and is treated as one so the tail is never
     * merged as the whole value: no flags token at all (N3(c)), an empty
     * one, or a longer one -- which may carry the `+`, or be the value
     * sitting where a missing flags token belongs ("=a s k :head"). */
    int follows = !flags_tok || !flags_tok[0] || flags_tok[1]
                  || flags_tok[0] == '+';

    md_chunk_abandon(chunk, account_name, stamp_text, wire_key, follows);
    return 0;
  }

  chunk_rc = md_chunk_feed(chunk, account_name, stamp_text, wire_key, vis, more, piece);
  if (chunk_rc != MD_CHUNK_DONE)
    return 0;   /* PENDING (wait for more pieces) or ERROR: nothing to merge */

  /* Checked once, on the whole row, against one reading of the clock. */
  if (md_stamp_ahead(&st, hlc_wall_clock_ms(), hlc_max_forward_ms())) {
    log_write(LS_SYSTEM, L_WARNING, 0,
              "ms_metadata: stamped row for %s/%s from %C reads too far "
              "ahead of our clock — dropped, not relayed",
              account_name, wire_key, sptr);
    return 0;
  }

  in.st = st;
  in.tombstone = tombstone;
  in.vis = vis;
  in.value = tombstone ? NULL : chunk->value;
  in.vlen = tombstone ? 0 : chunk->len;

  /* The account's CLEAR floor (owner, 2026-11-13): a live row of a key a
   * CLEAR deletes, older than the account's latest CLEAR, was written
   * before it -- a value a server held that the CLEAR's deletes did not
   * reach (a split, a pull answer or burst arriving after the CLEAR).  It
   * is taken as a tombstone at the floor's stamp instead, and that
   * tombstone goes to every link, the sender included; the live row is
   * not relayed.  A tombstone is never converted, a row written after
   * the CLEAR stands.  Nobody here is told unless this server held the
   * key live (metadata_account_merge() 1). */
  {
    struct md_stamp floor;

    if (metadata_floor_converts(account_name, wire_key, &in, &floor)) {
      struct md_version t, old;
      char oldbuf[METADATA_VALUE_LEN];
      int old_rc = metadata_account_get_version(account_name, wire_key, &old,
                                                oldbuf, sizeof(oldbuf));
      int nvis;

      t.st = floor;
      t.tombstone = 1;
      t.vis = vis;
      t.value = NULL;
      t.vlen = 0;
      /* Announced as the row it replaces was visible (md_notify_vis()). */
      nvis = md_notify_vis(old_rc == 0 ? &old : NULL, &t, vis);
      merge_rc = metadata_account_merge(account_name, wire_key, &t);
      if (merge_rc == 1 || merge_rc == 2) {
        metadata_account_apply_memory_ex(account_name, wire_key, NULL, nvis,
                                         NULL, NULL, merge_rc == 1);
        metadata_emit_versioned(&me, NULL, NULL, account_name, wire_key, &t);
      } else if (merge_rc == 0) {
        /* This server already holds the key under a stamp no older than
         * the floor (the CLEAR's own delete, or a later write): that row
         * beats the sender's, so the sender gets it. */
        struct md_version cur;
        char valbuf[METADATA_VALUE_LEN];

        if (metadata_account_get_version(account_name, wire_key, &cur, valbuf,
                                         sizeof(valbuf)) == 0)
          metadata_emit_versioned(&me, cptr, NULL, account_name, wire_key, &cur);
      }
      return 0;
    }
  }

  /* Apply this server's full limits (value bytes + key count, via
   * metadata_check_account_limits -- Task 5, W4 plan 1.8, extends what
   * used to be a UTF-8/length-only first-hop flood stop here).  On a
   * violation, skip merge/apply/store and tell opers once per link
   * (mdsync_limit_notice), but still relay the incoming version onward
   * through metadata_emit_versioned unchanged -- an over-limit check
   * must never suppress the relay. */
  if (!tombstone) {
    int limit_rc = metadata_check_account_limits(account_name, wire_key, chunk->value);

    if (limit_rc != METADATA_LIMIT_OK) {
      mdsync_limit_notice(cptr, target, wire_key, metadata_limit_why(limit_rc));
      metadata_emit_versioned(sptr, NULL, cptr, account_name, wire_key, &in);
      return 0;
    }
  }

  /* A tombstone carries no visibility ("D": md_flags_parse() leaves it
   * public): its delete is announced as the row it replaces was visible --
   * a private key's only to the account's own sessions (md_notify_vis()). */
  if (tombstone) {
    struct md_version old;
    char oldbuf[METADATA_VALUE_LEN];

    if (metadata_account_get_version(account_name, wire_key, &old, oldbuf,
                                     sizeof(oldbuf)) == 0)
      vis = md_notify_vis(&old, &in, vis);
  }

  merge_rc = metadata_account_merge(account_name, wire_key, &in);
  if (merge_rc != 1 && merge_rc != 2)
    return 0;   /* kept the local version (0), or a store error (-1): no relay */

  /* Taken.  A row that changes nothing a subscriber has seen (2: the same
   * value and visibility, tombstone over tombstone -- a SET of an
   * unchanged value elsewhere, a pull answer or burst row that only moves
   * the stamp -- or a tombstone where there was no row: nobody here ever
   * saw a value to lose) is stored and relayed, memory and mode flags
   * applied as always, but no METADATA line goes to a subscriber or a
   * connection of the account (owner, 2026-11-13: fork peers skip the
   * announcement).  A mode-synced key's flag is not part of that: a
   * tombstone over no row turns a default mode off, and that change is
   * applied and echoed as a MODE (metadata_account_apply_memory_ex ->
   * umode_sync_apply_butone, whatever tell says). */
  metadata_account_apply_memory_ex(account_name, wire_key,
                                   tombstone ? NULL : chunk->value, vis,
                                   NULL, NULL, merge_rc == 1);
  metadata_emit_versioned(sptr, NULL, cptr, account_name, wire_key, &in);
  return 0;
}

int ms_metadata(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  const char *target;
  const char *key;
  const char *value = NULL;
  int visibility = METADATA_VIS_PUBLIC;
  int is_channel = 0;
  struct Client *target_client = NULL;
  struct Channel *target_channel = NULL;
  enum md_target_kind kind;

  if (parc < 2)
    return 0;

  target = parv[1];
  kind = md_target_classify(target);

  /* "=account": an entirely different parv layout (stamp, key, flags,
   * piece) from every other MD form below -- handled start to finish
   * before any of the legacy target/key/value parsing runs. */
  if (kind == MD_T_ACCOUNT_STAMPED)
    return ms_metadata_stamped(cptr, sptr, parc, parv, target);

  if (kind == MD_T_SESSION)
    return ms_metadata_session(cptr, sptr, parc, parv, target);

  if (kind == MD_T_PULL)
    return ms_metadata_pull(cptr, sptr, parc, parv);

  if (kind == MD_T_PULL_END)
    return ms_metadata_pull_end(cptr, sptr, parc, parv);

  /* An unclassifiable target (bare sigil, empty, trailing garbage
   * after "?"/".") is simply dropped. */
  if (kind == MD_T_INVALID)
    return 0;

  if (parc < 3)
    return 0;

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

  /* Account-target form ("*account"): an oper's account write relayed from
   * mo_metadata's account branch (or a fork peer's own relay of one).
   * There is no FindUser-resolvable target.  W4: stamp the write and
   * apply it to every client of the account (local and remote, via
   * metadata_account_apply_memory) instead of only this server's
   * online ones, then relay the form onward unchanged.  Bare "*"
   * never appears S2S (mo_metadata expands it to a nick before emit), so
   * target[1] != '\0' is unambiguous. */
  if (target[0] == '*' && target[1] != '\0') {
    const char *account_name = target + 1;
    struct md_stamp st;
    int rc;
    int limit_rc = METADATA_LIMIT_OK;

    /* Same first-hop flood stop as the nick form below: UTF-8 + length
     * only (no client context; the origin already enforced key counts).
     * Task 5 (W4 plan 1.8): on a violation, skip apply/store and tell
     * opers once per link (mdsync_limit_notice), but still relay
     * unchanged below -- an over-limit check must never suppress the
     * relay. */
    if (value)
      limit_rc = metadata_check_limits(NULL, NULL, 0, key, value);

    if (limit_rc != METADATA_LIMIT_OK) {
      mdsync_limit_notice(cptr, target, key, metadata_limit_why(limit_rc));
    } else {
      /* Apply to memory regardless of storage availability (mirrors
       * metadata_set_client's own local-client resilience); the store
       * write itself is a no-op (metadata_write_versioned's own guard)
       * when storage isn't available. */
      if (metadata_lmdb_is_available()) {
        st = metadata_stamp_now();
        rc = metadata_account_put_versioned(account_name, key, value, visibility, &st);
        (void)rc;
      }
      metadata_account_apply_memory(account_name, key, value, visibility);
    }

    if (value)
      sendcmdto_serv_butone_v3(sptr, CMD_METADATA, cptr, "%s %s %s :%s",
                               target, key,
                               visibility == METADATA_VIS_PRIVATE ? "P" : "*",
                               value);
    else
      sendcmdto_serv_butone_v3(sptr, CMD_METADATA, cptr, "%s %s",
                               target, key);
    return 0;
  }

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

    /* Nick-target origin guard (md_sender_owns_client): a server may only
     * apply/relay a write to a nick-addressed target that is actually
     * BEHIND it (its own user, or this server relaying for its own
     * locally-connected user), or the write is the target applying to
     * itself, or the acting principal is an oper (who may legitimately
     * act on behalf of any user).  Otherwise a server could claim to set
     * metadata on a user it does not own -- drop and do not relay. */
    if (!md_sender_owns_client(sptr, target_client)) {
      log_write(LS_SYSTEM, L_WARNING, 0,
                "ms_metadata: %s/%s from %C is not %s's server - dropped",
                target, key, sptr, cli_name(target_client));
      return 0;
    }
  }

  /* Enforce the same limits every other write path obeys.  Task 5 (W4
   * plan 1.8): on a violation, skip apply/cache/notify and tell opers
   * once per link (mdsync_limit_notice), but still relay unchanged --
   * caps are a feature, not a protocol invariant, so a compliant
   * origin can legitimately trip a stricter downstream server's limits;
   * dropping the relay there would silently diverge that server's view
   * from the rest of the mesh instead of just not applying locally. */
  {
    int limit_rc = METADATA_LIMIT_OK;

    if (value)
      limit_rc = metadata_check_limits(target_client, target_channel, is_channel,
                                       key, value);

    if (limit_rc != METADATA_LIMIT_OK) {
      mdsync_limit_notice(cptr, target, key, metadata_limit_why(limit_rc));
    } else {
      /* Apply the change with visibility */
      if (is_channel) {
        metadata_set_channel(target_channel, key, value, visibility);
      } else if (target_client) {
        metadata_set_client(target_client, key, value, visibility);
      }

      /* B5: no separate LMDB cache step here.  metadata_set_client()
       * above already persists PERMANENTLY for authed users
       * (metadata_account_set_permanent); for a +R channel
       * metadata_set_channel() does the same (B1, gated on
       * MODE_REGISTERED).  An unregistered channel is memory+relay
       * only by design (spec §C3) -- this block used to TTL-cache its
       * rows under the plain channel name via metadata_account_set(),
       * the era-1 "remote TTL channel cache" B5 retires: nothing ever
       * reloaded those rows (metadata_channel_load only hydrates on
       * +R), so they were pure store debris that the read-only GET
       * channel fallback below could still resurrect into memory. The
       * store now keeps no row at all for an unregistered channel. */

      /* Notify local subscribers (vis-aware -- see
       * metadata_notify_subscribers). */
      metadata_notify_subscribers(target, key, value, visibility);
    }
  }

  /* Propagate to other servers regardless of whether this server
   * applied the change locally (see the comment above). */
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
