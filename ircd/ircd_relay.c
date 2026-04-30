/*
 * IRC - Internet Relay Chat, ircd/ircd_relay.c
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
 *
 * See file AUTHORS in IRC package for additional names of
 * the programmers.
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
 * @brief Helper functions to relay various types of messages.
 * @version $Id: ircd_relay.c 1913 2009-07-04 22:46:00Z entrope $
 *
 * There are four basic types of messages, each with four subtypes.
 *
 * The basic types are: channel, directed, masked, and private.
 * Channel messages are (perhaps obviously) sent directly to a
 * channel.  Directed messages are sent to "NICK[%host]@server", but
 * only allowed if the server is a services server (to avoid
 * information leaks for normal clients).  Masked messages are sent to
 * either *@*host.mask or *.server.mask.  Private messages are sent to
 * NICK.
 *
 * The subtypes for each type are: client message, client notice,
 * server message, and server notice.  Client subtypes are sent by a
 * local user, and server subtypes are given to us by a server.
 * Notice subtypes correspond to the NOTICE command, and message
 * subtypes correspond to the PRIVMSG command.
 *
 * As a special note, directed messages do not have server subtypes,
 * since there is no difference in handling them based on origin.
 */
#include "config.h"

#include "ircd_relay.h"
#include "capab.h"
#include "channel.h"
#include "client.h"
#include "hash.h"
#include "history.h"
#include "ircd.h"
#include "ircd_chattr.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "match.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_debug.h"
#include "s_misc.h"
#include "s_user.h"
#include "send.h"
#include "metadata.h"
#include "handlers.h"
#include "bouncer_session.h"
#include "forwarded_label.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

/*
 * This file contains message relaying functions for client and server
 * private messages and notices
 * TODO: This file contains a lot of cut and paste code, and needs
 * to be cleaned up a bit. The idea is to factor out the common checks
 * but not introduce any IsOper/IsUser/MyUser/IsServer etc. stuff.
 */

/**
 * Check and optionally sanitize text for UTF-8 validity (UTF8ONLY enforcement).
 *
 * When UTF8ONLY is enabled:
 * - In strict mode: sends FAIL INVALID_UTF8 and returns 0 (reject message)
 * - In warn mode: sanitizes text, sends WARN INVALID_UTF8, returns 1 (proceed)
 *
 * When UTF8ONLY is disabled, always returns 1.
 *
 * @param[in] sptr Client sending the message.
 * @param[in,out] text Message text (may be modified in warn mode).
 * @param[in] command Command name for standard reply (e.g., "PRIVMSG").
 * @return 1 if message should proceed (possibly modified), 0 if rejected.
 */
static int check_utf8_text(struct Client *sptr, char *text, const char *command)
{
  if (!feature_bool(FEAT_UTF8ONLY))
    return 1;

  if (string_is_valid_utf8(text))
    return 1;

  /* Invalid UTF-8 detected */
  if (feature_bool(FEAT_UTF8ONLY_STRICT)) {
    /* Strict mode: reject the message */
    send_fail(sptr, command, "INVALID_UTF8", NULL,
              "Message contains invalid UTF-8 and was rejected");
    return 0;
  }

  /* Warn mode: sanitize and proceed */
  string_sanitize_utf8(text);
  send_warn(sptr, command, "INVALID_UTF8", NULL,
            "Message contained invalid UTF-8 and was sanitized");
  return 1;
}

#ifdef USE_MDBX
/** Store a channel message in the history database.
 * Stores the message with the provided msgid and timestamp.
 * @param[in] sptr Client that sent the message.
 * @param[in] chptr Target channel.
 * @param[in] text Message content.
 * @param[in] type Message type (HISTORY_PRIVMSG or HISTORY_NOTICE).
 * @param[in] msgid Message ID (same one sent to clients via echo-message).
 * @param[in] timestamp ISO 8601 timestamp.
 */
static void store_channel_history(struct Client *sptr, struct Channel *chptr,
                                   const char *text, enum HistoryMessageType type,
                                   const char *msgid, const char *timestamp,
                                   const char *client_tags)
{
  char sender[HISTORY_SENDER_LEN];
  const char *account;
  int has_local_interest;

  if (!history_is_available())
    return;

  /* Check if chathistory storage is enabled */
  if (!feature_bool(FEAT_CHATHISTORY_STORE)) {
    /* If write forwarding is enabled, forward to a storage server.
     * Encode client tags into the content using \x06 sentinel so they
     * survive the CH W wire format transparently. */
    if (feature_bool(FEAT_CHATHISTORY_WRITE_FORWARD)) {
      if (client_tags && client_tags[0]) {
        char tagged_content[HISTORY_CONTENT_LEN + 512];
        ircd_snprintf(0, tagged_content, sizeof(tagged_content),
                      "\x06%s\x06%s", client_tags, text ? text : "");
        forward_history_write(chptr, sptr, msgid, timestamp, type,
                              tagged_content);
      } else {
        forward_history_write(chptr, sptr, msgid, timestamp, type, text);
      }
    }
    return;
  }

  /* Determine if we have local interest in this channel:
   * - Local sender: always interested (our user sent it)
   * - Remote sender: only if we have local users in channel
   * This prevents hub servers from storing messages they're just relaying.
   */
  if (MyConnect(sptr)) {
    has_local_interest = 1;
  } else {
    struct Membership *member;
    has_local_interest = 0;
    for (member = chptr->members; member; member = member->next_member) {
      if (MyConnect(member->user) || IsMemberAlias(member)) {
        has_local_interest = 1;
        break;
      }
    }
  }

  if (!has_local_interest) {
    /* No local interest - don't store.
     * STORE servers without users in a channel don't receive messages via P10
     * relay anyway (P10 only sends to servers with channel members). They rely
     * on CH W forwarding from non-STORE servers, which handles registered
     * channel storage in process_write_forward().
     */
    return;
  }

  /* Build sender string: nick!user@host */
  if (cli_user(sptr))
    ircd_snprintf(0, sender, sizeof(sender), "%s!%s@%s",
                  cli_name(sptr),
                  cli_user(sptr)->username,
                  cli_user(sptr)->host);
  else
    ircd_strncpy(sender, cli_name(sptr), sizeof(sender) - 1);

  /* Get account name if logged in */
  account = (cli_user(sptr) && cli_user(sptr)->account[0])
            ? cli_user(sptr)->account : NULL;

  /* Check if channel has +P (no storage) mode */
  if (chptr->mode.exmode & EXMODE_NOSTORAGE)
    return;

  /* Always store when CHATHISTORY_STORE is enabled.
   * Messages must be stored for REDACT to look up msgids, even for
   * unauthenticated channels. The +P (NOSTORAGE) mode above handles
   * channels that explicitly opt out of storage. */

  /* Check if sender has +Y (no storage) user mode — store gap marker */
  if (IsNoStorage(sptr)) {
    history_store_message(msgid, timestamp, chptr->chname, sender,
                          account, HISTORY_GAP, "", NULL);
    return;
  }

  /* Check if this is a new channel for Layer 1 advertisement */
  int is_new_channel = (history_has_channel(chptr->chname) == 0);

  /* Store in database */
  if (history_store_message(msgid, timestamp, chptr->chname, sender,
                            account, type, text, client_tags) == 0) {
    /* Layer 1: Broadcast CH A + if this is the first message in the channel */
    if (is_new_channel) {
      broadcast_channel_advertisement(chptr->chname);
    }
  }
}

/** Check if client has opted out of PM history storage.
 * @param[in] cptr Client to check.
 * @return 1 if opted out, 0 otherwise.
 */
static int has_pm_optout(struct Client *cptr)
{
  struct MetadataEntry *entry;

  if (!cptr || !IsUser(cptr))
    return 0;

  entry = metadata_get_client(cptr, "chathistory.pm");
  if (!entry)
    return 0;

  /* "0" or empty = opt-out */
  return (!entry->value || !entry->value[0] || entry->value[0] == '0');
}

/** Check if PM should be stored between two clients.
 * Both must be authenticated. Either can opt out via metadata or +y mode.
 * @param[in] sender Message sender.
 * @param[in] recipient Message recipient.
 * @return 1 if should store, 0 otherwise.
 */
static int should_store_pm(struct Client *sender, struct Client *recipient)
{
  /* Both must have accounts */
  if (!IsAccount(sender) || !IsAccount(recipient))
    return 0;

  /* Check opt-out */
  if (has_pm_optout(sender) || has_pm_optout(recipient))
    return 0;

  return 1;
}

/** Store a private (DM) message in the history database.
 * Uses a consistent target format: sorted pair of nicks as "nick1:nick2".
 * @param[in] sptr Client that sent the message.
 * @param[in] acptr Target client.
 * @param[in] text Message content.
 * @param[in] type Message type (HISTORY_PRIVMSG or HISTORY_NOTICE).
 * @param[in] msgid Message ID (same one sent to clients via echo-message).
 * @param[in] timestamp ISO 8601 timestamp.
 */
static void store_private_history(struct Client *sptr, struct Client *acptr,
                                   const char *text, enum HistoryMessageType type,
                                   const char *msgid, const char *timestamp,
                                   const char *client_tags)
{
  char sender[HISTORY_SENDER_LEN];
  char target[NICKLEN * 2 + 2];  /* nick1:nick2 */
  const char *account;
  const char *nick1, *nick2;

  if (!history_is_available())
    return;

  /* Check if chathistory storage is enabled */
  if (!feature_bool(FEAT_CHATHISTORY_STORE))
    return;

  /* Check if private message history is enabled (separate feature) */
  if (!feature_bool(FEAT_CHATHISTORY_PRIVATE))
    return;

  /* Policy check: both must have accounts (no gap marker — not opt-out) */
  if (!IsAccount(sptr) || !IsAccount(acptr))
    return;

  /* Build sender string: nick!user@host (needed for gap markers below) */
  if (cli_user(sptr))
    ircd_snprintf(0, sender, sizeof(sender), "%s!%s@%s",
                  cli_name(sptr),
                  cli_user(sptr)->username,
                  cli_user(sptr)->host);
  else
    ircd_strncpy(sender, cli_name(sptr), sizeof(sender) - 1);

  /* Build target as sorted pair for consistent lookups
   * Format: lowerNick:higherNick (case-insensitive comparison)
   */
  if (ircd_strcmp(cli_name(sptr), cli_name(acptr)) < 0) {
    nick1 = cli_name(sptr);
    nick2 = cli_name(acptr);
  } else {
    nick1 = cli_name(acptr);
    nick2 = cli_name(sptr);
  }
  ircd_snprintf(0, target, sizeof(target), "%s:%s", nick1, nick2);

  /* Get account name if logged in */
  account = (cli_user(sptr) && cli_user(sptr)->account[0])
            ? cli_user(sptr)->account : NULL;

  /* Check opt-out — store gap marker if either party opted out */
  if (has_pm_optout(sptr) || has_pm_optout(acptr)) {
    history_store_message(msgid, timestamp, target, sender,
                          account, HISTORY_GAP, "", NULL);
    return;
  }

  /* Check +Y no-storage — store gap marker */
  if (IsNoStorage(sptr)) {
    history_store_message(msgid, timestamp, target, sender,
                          account, HISTORY_GAP, "", NULL);
    return;
  }

  /* Store in database */
  history_store_message(msgid, timestamp, target, sender,
                        account, type, text, client_tags);
}
#endif /* USE_MDBX */

/** Relay a local user's message to a channel.
 * Generates an error if the client cannot send to the channel.
 * @param[in] sptr Client that originated the message.
 * @param[in] name Name of target channel.
 * @param[in] text %Message to relay.
 * @param[in] targets Number of targets for the initial PRIVMSG.
 */
void relay_channel_message(struct Client* sptr, const char* name, const char* text, int targets)
{
  struct Channel* chptr;
  const char* mytext = text;
  const char* ch;
  char utf8buf[BUFSIZE];
  assert(0 != sptr);
  assert(0 != name);
  assert(0 != text);

  /* UTF8ONLY enforcement */
  if (feature_bool(FEAT_UTF8ONLY) && !string_is_valid_utf8(text)) {
    if (feature_bool(FEAT_UTF8ONLY_STRICT)) {
      send_fail(sptr, "PRIVMSG", "INVALID_UTF8", NULL,
                "Message contains invalid UTF-8 and was rejected");
      return;
    }
    /* Warn mode: copy, sanitize, and use sanitized version */
    ircd_strncpy(utf8buf, text, sizeof(utf8buf) - 1);
    utf8buf[sizeof(utf8buf) - 1] = '\0';
    string_sanitize_utf8(utf8buf);
    send_warn(sptr, "PRIVMSG", "INVALID_UTF8", NULL,
              "Message contained invalid UTF-8 and was sanitized");
    mytext = utf8buf;
    if (EmptyString(mytext)) {
      send_reply(sptr, ERR_NOTEXTTOSEND);
      return;
    }
  }

  if (0 == (chptr = FindChannel(name))) {
    send_reply(sptr, ERR_NOSUCHCHANNEL, name);
    return;
  }
  /*
   * This first: Almost never a server/service
   */
  if (!client_can_send_to_channel(sptr, chptr, 0)) {
    send_reply(sptr, ERR_CANNOTSENDTOCHAN, chptr->chname);
    return;
  }
  if ((chptr->mode.mode & MODE_NOPRIVMSGS) &&
      check_target_limit(sptr, chptr, chptr->chname, 0))
    return;

  if ((chptr->mode.exmode & EXMODE_NOCTCPS) && (*text == '\x01') &&
      ircd_strncmp(text+1, "ACTION", 6)) {
    send_reply(sptr, ERR_CANNOTSENDTOCHAN, chptr->chname);
    return;
  }

  if (((chptr->mode.exmode & EXMODE_NOMULTITARG) ||
       feature_bool(FEAT_NOMULTITARGETS)) && (targets > 1)) {
    send_reply(sptr, ERR_CANNOTSENDTOCHAN, chptr->chname);
    return;
  }

  if (chptr->mode.exmode & EXMODE_NOCOLOR)
    for (ch=text;*ch;ch++)
      if (*ch==COLOR_COLOR || *ch==27 || *ch==COLOR_REVERSE) {
        send_reply(sptr, ERR_CANNOTSENDTOCHAN, chptr->chname);
        return;
      }

  if (chptr->mode.exmode & EXMODE_STRIPCOLOR) {
    mytext = StripColor(text);
    if (EmptyString(mytext)) {
      send_reply(sptr, ERR_NOTEXTTOSEND);
      return;
    }
  }

  RevealDelayedJoinIfNeeded(sptr, chptr);

  /* Generate msgid before channel broadcast so all recipients get the same one */
  {
    char msgid[64] = "";
    char timestamp[32] = "";
    int need_echo = feature_bool(FEAT_CAP_echo_message) && CapOwnHas(sptr, CAP_ECHOMSG);

#ifdef USE_MDBX
    if (feature_bool(FEAT_MSGID)) {
      struct timeval tv;
      gettimeofday(&tv, NULL);
      ircd_snprintf(0, timestamp, sizeof(timestamp), "%lu.%03lu",
                    (unsigned long)tv.tv_sec,
                    (unsigned long)(tv.tv_usec / 1000));
      generate_msgid(msgid, sizeof(msgid));

      /* Set S2S msgid override so the S2S relay carries the same msgid
       * that we store locally — prevents federation dedup failures. */
      sendcmdto_set_s2s_tags(
        (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000, msgid);
    }
#endif

    /* Set msgid override so channel broadcast includes it in client tags */
    if (msgid[0])
      sendcmdto_set_client_msgid(msgid);

    /* Alias source rewriting: use primary's numeric for S2S delivery.
     * When primary is remote, use split S2S delivery: primary numeric for
     * most servers, alias numeric for the primary's server direction
     * (to avoid fake direction — the primary's server handles rewriting). */
    {
      struct Client *from = sptr;
      const char *client_tags = cli_client_tags(sptr);

      if (IsBouncerAlias(sptr) && cli_user(sptr)->alias_primary) {
        if (!MyUser(cli_user(sptr)->alias_primary))
          sendcmdto_set_alias_source(sptr);
        from = cli_user(sptr)->alias_primary;
      }

      if (client_tags && *client_tags) {
        sendcmdto_channel_butone_with_client_tags(from, CMD_PRIVATE, chptr, cli_from(sptr),
                           SKIP_DEAF | SKIP_BURST, text[0], client_tags,
                           "%H :%s", chptr, mytext);
      } else {
        sendcmdto_channel_butone(from, CMD_PRIVATE, chptr, cli_from(sptr),
                                 SKIP_DEAF | SKIP_BURST, text[0], "%H :%s", chptr, mytext);
      }
    }

    /* Clear the msgid override after broadcast */
    sendcmdto_set_client_msgid(NULL);

    /* Echo message back to sender if they have echo-message cap */
    if (need_echo) {
      const char *echo_ctags = cli_client_tags(sptr);
      if (echo_ctags && *echo_ctags && CapOwnHas(sptr, CAP_MSGTAGS)) {
        /* Include client tags in echo */
        if (msgid[0])
          sendcmdto_set_client_msgid(msgid);
        sendcmdto_one_client_tags(sptr, MSG_PRIVATE, sptr, echo_ctags,
                                  "%H :%s", chptr, mytext);
        sendcmdto_set_client_msgid(NULL);
      } else {
#ifdef USE_MDBX
        sendcmdto_one_tags_ext(sptr, CMD_PRIVATE, sptr, msgid,
                               "%H :%s", chptr, mytext);
#else
        sendcmdto_one_tags(sptr, CMD_PRIVATE, sptr, "%H :%s", chptr, mytext);
#endif
      }
    }

#ifdef USE_MDBX
    /* Store message in history database for draft/chathistory.
     * Include client-only tags (+reply, +draft/react) if present. */
    if (msgid[0]) {
      const char *store_ctags = cli_client_tags(sptr);
      store_channel_history(sptr, chptr, mytext, HISTORY_PRIVMSG, msgid, timestamp,
                            (store_ctags && *store_ctags) ? store_ctags : NULL);
    }
#endif
  }
}

/** Relay a local user's notice to a channel.
 * Silently exits if the client cannot send to the channel.
 * @param[in] sptr Client that originated the message.
 * @param[in] name Name of target channel.
 * @param[in] text %Message to relay.
 * @param[in] targets Number of targets for the initial NOTICE
 */
void relay_channel_notice(struct Client* sptr, const char* name, const char* text, int targets)
{
  struct Channel* chptr;
  const char* mytext = text;
  const char* ch;
  char utf8buf[BUFSIZE];
  assert(0 != sptr);
  assert(0 != name);
  assert(0 != text);

  /* UTF8ONLY enforcement */
  if (feature_bool(FEAT_UTF8ONLY) && !string_is_valid_utf8(text)) {
    if (feature_bool(FEAT_UTF8ONLY_STRICT)) {
      send_fail(sptr, "NOTICE", "INVALID_UTF8", NULL,
                "Message contains invalid UTF-8 and was rejected");
      return;
    }
    /* Warn mode: copy, sanitize, and use sanitized version */
    ircd_strncpy(utf8buf, text, sizeof(utf8buf) - 1);
    utf8buf[sizeof(utf8buf) - 1] = '\0';
    string_sanitize_utf8(utf8buf);
    send_warn(sptr, "NOTICE", "INVALID_UTF8", NULL,
              "Message contained invalid UTF-8 and was sanitized");
    mytext = utf8buf;
    if (EmptyString(mytext))
      return;
  }

  if (0 == (chptr = FindChannel(name)))
    return;
  /*
   * This first: Almost never a server/service
   */
  if (!client_can_send_to_channel(sptr, chptr, 0))
    return;

  if ((chptr->mode.mode & MODE_NOPRIVMSGS) &&
      check_target_limit(sptr, chptr, chptr->chname, 0))
    return;

  if (chptr->mode.exmode & EXMODE_NONOTICES)
    return;

  if ((chptr->mode.exmode & EXMODE_NOCTCPS) && (*text == '\x01'))
    return;

  if (((chptr->mode.exmode & EXMODE_NOMULTITARG) ||
       feature_bool(FEAT_NOMULTITARGETS)) && (targets > 1))
    return;

  if (chptr->mode.exmode & EXMODE_NOCOLOR)
    for (ch=text;*ch;ch++)
      if (*ch==COLOR_COLOR || *ch==27 || *ch==COLOR_REVERSE)
        return;

  if (chptr->mode.exmode & EXMODE_STRIPCOLOR) {
    mytext = StripColor(text);
    if (EmptyString(mytext))
      return;
  }

  RevealDelayedJoinIfNeeded(sptr, chptr);

  /* Generate msgid before channel broadcast (mirrors relay_channel_message).
   * Setting S2S msgid override ensures the same msgid is used for both
   * local storage and S2S relay — prevents federation dedup failures. */
  {
    char msgid[64] = "";
    char timestamp[32] = "";
    int need_echo = feature_bool(FEAT_CAP_echo_message) && CapOwnHas(sptr, CAP_ECHOMSG);

#ifdef USE_MDBX
    if (feature_bool(FEAT_MSGID)) {
      struct timeval tv;
      gettimeofday(&tv, NULL);
      ircd_snprintf(0, timestamp, sizeof(timestamp), "%lu.%03lu",
                    (unsigned long)tv.tv_sec,
                    (unsigned long)(tv.tv_usec / 1000));
      generate_msgid(msgid, sizeof(msgid));

      sendcmdto_set_s2s_tags(
        (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000, msgid);
    }
#endif

    /* Set msgid override so channel broadcast includes it in client tags */
    if (msgid[0])
      sendcmdto_set_client_msgid(msgid);

    /* Alias source rewriting (see relay_channel_message) */
    {
      struct Client *from = sptr;
      const char *client_tags = cli_client_tags(sptr);

      if (IsBouncerAlias(sptr) && cli_user(sptr)->alias_primary) {
        if (!MyUser(cli_user(sptr)->alias_primary))
          sendcmdto_set_alias_source(sptr);
        from = cli_user(sptr)->alias_primary;
      }

      if (client_tags && *client_tags) {
        sendcmdto_channel_butone_with_client_tags(from, CMD_NOTICE, chptr, cli_from(sptr),
                           SKIP_DEAF | SKIP_BURST, '\0', client_tags,
                           "%H :%s", chptr, mytext);
      } else {
        sendcmdto_channel_butone(from, CMD_NOTICE, chptr, cli_from(sptr),
                                 SKIP_DEAF | SKIP_BURST, '\0', "%H :%s", chptr, mytext);
      }
    }

    /* Clear the msgid override after broadcast */
    sendcmdto_set_client_msgid(NULL);

    /* Echo notice back to sender if they have echo-message cap */
    if (need_echo) {
      const char *echo_ctags = cli_client_tags(sptr);
      if (echo_ctags && *echo_ctags && CapOwnHas(sptr, CAP_MSGTAGS)) {
        if (msgid[0])
          sendcmdto_set_client_msgid(msgid);
        sendcmdto_one_client_tags(sptr, MSG_NOTICE, sptr, echo_ctags,
                                  "%H :%s", chptr, mytext);
        sendcmdto_set_client_msgid(NULL);
      } else {
#ifdef USE_MDBX
        sendcmdto_one_tags_ext(sptr, CMD_NOTICE, sptr, msgid,
                               "%H :%s", chptr, mytext);
#else
        sendcmdto_one_tags(sptr, CMD_NOTICE, sptr, "%H :%s", chptr, mytext);
#endif
      }
    }

#ifdef USE_MDBX
    /* Store notice in history database for draft/chathistory.
     * Include client-only tags (+reply, +draft/react) if present. */
    if (msgid[0]) {
      const char *store_ctags = cli_client_tags(sptr);
      store_channel_history(sptr, chptr, mytext, HISTORY_NOTICE, msgid, timestamp,
                            (store_ctags && *store_ctags) ? store_ctags : NULL);
    }
#endif
  }
}

/** Relay a message to a channel.
 * Generates an error if the client cannot send to the channel,
 * or if the channel is a local channel
 * @param[in] sptr Client that originated the message.
 * @param[in] name Name of target channel.
 * @param[in] text %Message to relay.
 */
void server_relay_channel_message(struct Client* sptr, const char* name, const char* text)
{
  struct Channel* chptr;
  struct Client *one;
  const char *client_tags;

  assert(0 != sptr);
  assert(0 != name);
  assert(0 != text);

  if (IsLocalChannel(name) || 0 == (chptr = FindChannel(name))) {
    send_reply(sptr, ERR_NOSUCHCHANNEL, name);
    return;
  }

  /* Save alias's server link and client tags before potential rewrite.
   * For S2S-relayed messages, client tags arrive in the compact-tag
   * ,C<client_tags> segment, populated by parse_server() into
   * cli_s2s_client_tags(server_link). cli_client_tags(remote_user) is
   * always empty since remote users don't go through parse_client(),
   * so prefer the S2S-incoming form. */
  one = cli_from(sptr);
  {
    const char *s2s_tags = cli_s2s_client_tags(one);
    client_tags = (s2s_tags && *s2s_tags) ? s2s_tags : cli_client_tags(sptr);
  }

  /* Unified msgid: if no incoming S2S msgid, generate one now so
   * format_s2s_tags() (relay) and storage both use the same value.
   * Handles messages from legacy servers without P10_MESSAGE_TAGS. */
  if (feature_bool(FEAT_P10_MESSAGE_TAGS) && one && !cli_s2s_msgid(one)[0])
    generate_msgid(cli_s2s_msgid(one), S2S_MSGID_BUFSIZE);

  /* Alias source rewriting: use primary's P10 numeric for S2S.
   * The alias numeric (from BX C) is only known to BX-aware servers.
   * The primary numeric (from N token) is universally known.
   * Keep 'one' = alias's server link for echo suppression. */
  if (IsBouncerAlias(sptr) && cli_user(sptr)->alias_primary) {
    sendcmdto_set_s2s_cptr(one);  /* Preserve alias's S2S tags */
    if (!MyUser(cli_user(sptr)->alias_primary))
      sendcmdto_set_alias_source(sptr);
    sptr = cli_user(sptr)->alias_primary;
  }

  /*
   * This first: Almost never a server/service
   * Servers may have channel services, need to check for it here
   */
  if (client_can_send_to_channel(sptr, chptr, 1) || IsChannelService(sptr)) {
    /* Set client msgid override so local clients get msgid tag.
     * Use S2S msgid if available, otherwise generate one. */
    char relay_msgid[64] = "";
    if (feature_bool(FEAT_MSGID)) {
      const char *s2s_mid = (feature_bool(FEAT_P10_MESSAGE_TAGS) && one
                             && cli_s2s_msgid(one)[0]) ? cli_s2s_msgid(one) : NULL;
      if (s2s_mid)
        ircd_strncpy(relay_msgid, s2s_mid, sizeof(relay_msgid));
      else
        generate_msgid(relay_msgid, sizeof(relay_msgid));
      sendcmdto_set_client_msgid(relay_msgid);
    }

    if (client_tags && *client_tags) {
      sendcmdto_channel_butone_with_client_tags(sptr, CMD_PRIVATE, chptr, one,
                         SKIP_DEAF | SKIP_BURST, text[0], client_tags,
                         "%H :%s", chptr, text);
    } else {
      sendcmdto_channel_butone(sptr, CMD_PRIVATE, chptr, one,
                               SKIP_DEAF | SKIP_BURST, text[0], "%H :%s", chptr, text);
    }

    sendcmdto_set_client_msgid(NULL);

#ifdef USE_MDBX
    /* Store server-relayed message in history database.
     * Uses the same msgid that was broadcast to clients above. */
    if (relay_msgid[0]) {
      char timestamp[32];
      struct timeval tv;

      gettimeofday(&tv, NULL);
      ircd_snprintf(0, timestamp, sizeof(timestamp), "%lu.%03lu",
                    (unsigned long)tv.tv_sec,
                    (unsigned long)(tv.tv_usec / 1000));
      store_channel_history(sptr, chptr, text, HISTORY_PRIVMSG, relay_msgid, timestamp, NULL);
    }
#endif
  }
  else
    send_reply(sptr, ERR_CANNOTSENDTOCHAN, chptr->chname);
}

/** Relay a notice to a channel.
 * Generates an error if the client cannot send to the channel,
 * or if the channel is a local channel
 * @param[in] sptr Client that originated the message.
 * @param[in] name Name of target channel.
 * @param[in] text %Message to relay.
 */
void server_relay_channel_notice(struct Client* sptr, const char* name, const char* text)
{
  struct Channel* chptr;
  struct Client *one;
  const char *client_tags;

  assert(0 != sptr);
  assert(0 != name);
  assert(0 != text);

  if (IsLocalChannel(name) || 0 == (chptr = FindChannel(name)))
    return;

  /* Save alias's server link and client tags before potential rewrite.
   * For S2S-relayed messages, prefer cli_s2s_client_tags(server_link)
   * — see server_relay_channel_message. */
  one = cli_from(sptr);
  {
    const char *s2s_tags = cli_s2s_client_tags(one);
    client_tags = (s2s_tags && *s2s_tags) ? s2s_tags : cli_client_tags(sptr);
  }

  /* Unified msgid (see server_relay_channel_message) */
  if (feature_bool(FEAT_P10_MESSAGE_TAGS) && one && !cli_s2s_msgid(one)[0])
    generate_msgid(cli_s2s_msgid(one), S2S_MSGID_BUFSIZE);

  /* Alias source rewriting (see server_relay_channel_message) */
  if (IsBouncerAlias(sptr) && cli_user(sptr)->alias_primary) {
    sendcmdto_set_s2s_cptr(one);  /* Preserve alias's S2S tags */
    if (!MyUser(cli_user(sptr)->alias_primary))
      sendcmdto_set_alias_source(sptr);
    sptr = cli_user(sptr)->alias_primary;
  }

  /*
   * This first: Almost never a server/service
   * Servers may have channel services, need to check for it here
   */
  if ((client_can_send_to_channel(sptr, chptr, 1) &&
       !(chptr->mode.exmode & EXMODE_NONOTICES)) || IsChannelService(sptr)) {
    /* Set client msgid override so local clients get msgid tag. */
    char relay_msgid[64] = "";
    if (feature_bool(FEAT_MSGID)) {
      const char *s2s_mid = (feature_bool(FEAT_P10_MESSAGE_TAGS) && one
                             && cli_s2s_msgid(one)[0]) ? cli_s2s_msgid(one) : NULL;
      if (s2s_mid)
        ircd_strncpy(relay_msgid, s2s_mid, sizeof(relay_msgid));
      else
        generate_msgid(relay_msgid, sizeof(relay_msgid));
      sendcmdto_set_client_msgid(relay_msgid);
    }

    if (client_tags && *client_tags) {
      sendcmdto_channel_butone_with_client_tags(sptr, CMD_NOTICE, chptr, one,
                         SKIP_DEAF | SKIP_BURST, '\0', client_tags,
                         "%H :%s", chptr, text);
    } else {
      sendcmdto_channel_butone(sptr, CMD_NOTICE, chptr, one,
                               SKIP_DEAF | SKIP_BURST, '\0', "%H :%s", chptr, text);
    }

    sendcmdto_set_client_msgid(NULL);

#ifdef USE_MDBX
    /* Store server-relayed notice in history database.
     * Uses the same msgid that was broadcast to clients above. */
    if (relay_msgid[0]) {
      char timestamp[32];
      struct timeval tv;

      gettimeofday(&tv, NULL);
      ircd_snprintf(0, timestamp, sizeof(timestamp), "%lu.%03lu",
                    (unsigned long)tv.tv_sec,
                    (unsigned long)(tv.tv_usec / 1000));
      store_channel_history(sptr, chptr, text, HISTORY_NOTICE, relay_msgid, timestamp, NULL);
    }
#endif
  }
}

/** Relay a directed message.
 * Generates an error if the named server does not exist, if it is not
 * a services server, or if \a name names a local user and a hostmask
 * is specified but does not match.
 * @param[in] sptr Client that originated the message.
 * @param[in] name Target nickname, with optional "%hostname" suffix.
 * @param[in] server Name of target server.
 * @param[in] text %Message to relay.
 */
void relay_directed_message(struct Client* sptr, char* name, char* server, const char* text)
{
  struct Client* acptr;
  char*          host;

  assert(0 != sptr);
  assert(0 != name);
  assert(0 != text);
  assert(0 != server);

  if ((acptr = FindServer(server + 1)) == NULL || !IsService(acptr))
  {
    send_reply(sptr, ERR_NOSUCHNICK, name);
    return;
  }
  /*
   * NICK[%host]@server addressed? See if <server> is me first
   */
  if (!IsMe(acptr))
  {
    sendcmdto_one(sptr, CMD_PRIVATE, acptr, "%s :%s", name, text);
    return;
  }
  /*
   * Look for an user whose NICK is equal to <name> and then
   * check if it's hostname matches <host> and if it's a local
   * user.
   */
  *server = '\0';
  if ((host = strchr(name, '%')))
    *host++ = '\0';

  /* As reported by Vampire-, it's possible to brute force finding users
   * by sending a message to each server and see which one succeeded.
   * This means we have to remove error reporting.  Sigh.  Better than
   * removing the ability to send directed messages to client servers 
   * Thanks for the suggestion Vampire=.  -- Isomer 2001-08-28
   * Argh, /ping nick@server, disallow messages to non +k clients :/  I hate
   * this. -- Isomer 2001-09-16
   */
  if (!(acptr = FindUser(name)) || !MyUser(acptr) ||
      (!EmptyString(host) && 0 != match(host, cli_user(acptr)->host)) ||
      !IsChannelService(acptr))
  {
    /*
     * By this stage we might as well not bother because they will
     * know that this server is currently linked because of the
     * increased lag.
     */
    send_reply(sptr, ERR_NOSUCHNICK, name);
    return;
  }

  *server = '@';
  if (host)
    *--host = '%';

  /*
   * +R check, if target is +R and we're not +r (or opered) then
   * deny the message.
   */
  if (IsAccountOnly(acptr) && !IsAccount(sptr) && !IsOper(sptr) && (acptr != sptr)) {
    send_reply(sptr, ERR_ACCOUNTONLY, cli_name(acptr), "PRIVMSG", cli_name(acptr));
    return;
  }

  /*
   * +D check, if target is +D and we're not opered then deny
   * the message.
   */
  if (IsPrivDeaf(acptr) && !IsOper(sptr) && (acptr != sptr)) {
    send_reply(sptr, ERR_PRIVDEAF, cli_name(acptr), "PRIVMSG", cli_name(acptr));
    return;
  }

  if ((IsRestrictPrivMsg(sptr) || IsCommonChansOnly(acptr)) && !IsAnOper(sptr) &&
      !common_chan_count(acptr, sptr, 1) && (sptr != acptr)) {
    send_reply(sptr, ERR_COMMONCHANSONLY, cli_name(acptr), "PRIVMSG");
    return;
  }

  if (!(is_silenced(sptr, acptr, 0)))
    sendcmdto_one(sptr, CMD_PRIVATE, acptr, "%s :%s", name, text);
}

/** Relay a directed notice.
 * Generates an error if the named server does not exist, if it is not
 * a services server, or if \a name names a local user and a hostmask
 * is specified but does not match.
 * @param[in] sptr Client that originated the message.
 * @param[in] name Target nickname, with optional "%hostname" suffix.
 * @param[in] server Name of target server.
 * @param[in] text %Message to relay.
 */
void relay_directed_notice(struct Client* sptr, char* name, char* server, const char* text)
{
  struct Client* acptr;
  char*          host;

  assert(0 != sptr);
  assert(0 != name);
  assert(0 != text);
  assert(0 != server);

  if (0 == (acptr = FindServer(server + 1)))
    return;
  /*
   * NICK[%host]@server addressed? See if <server> is me first
   */
  if (!IsMe(acptr)) {
    sendcmdto_one(sptr, CMD_NOTICE, acptr, "%s :%s", name, text);
    return;
  }
  /*
   * Look for an user whose NICK is equal to <name> and then
   * check if it's hostname matches <host> and if it's a local
   * user.
   */
  *server = '\0';
  if ((host = strchr(name, '%')))
    *host++ = '\0';

  if (!(acptr = FindUser(name)) || !MyUser(acptr) ||
      (!EmptyString(host) && 0 != match(host, cli_user(acptr)->host)))
    return;

  *server = '@';
  if (host)
    *--host = '%';

  /*
   * +R check, if target is +R and we're not +r (or opered) then
   * deny the message.
   */
  if (IsAccountOnly(acptr) && !IsAccount(sptr) && !IsOper(sptr) && (acptr != sptr)) {
    send_reply(sptr, ERR_ACCOUNTONLY, cli_name(acptr), "NOTICE", cli_name(acptr));
    return;
  }

  /*
   * +D check, if target is +D and we're not opered then deny
   * the message.
   */
  if (IsPrivDeaf(acptr) && !IsOper(sptr) && (acptr != sptr)) {
    send_reply(sptr, ERR_PRIVDEAF, cli_name(acptr), "NOTICE", cli_name(acptr));
    return;
  }

  if ((IsRestrictPrivMsg(sptr) || IsCommonChansOnly(acptr)) && !IsAnOper(sptr) &&
      !common_chan_count(acptr, sptr, 1) && (sptr != acptr)) {
    send_reply(sptr, ERR_COMMONCHANSONLY, cli_name(acptr), "NOTICE");
    return;
  }

  if (!(is_silenced(sptr, acptr, 0)))
    sendcmdto_one(sptr, CMD_NOTICE, acptr, "%s :%s", name, text);
}

/** Relay a private message from a local user.
 * Returns an error if the user does not exist or sending to him would
 * exceed the source's free targets.  Sends an AWAY status message if
 * the target is marked as away.
 * @param[in] sptr Client that originated the message.
 * @param[in] name Nickname of target user.
 * @param[in] text %Message to relay.
 */
void relay_private_message(struct Client* sptr, const char* name, const char* text)
{
  struct Client* acptr;
  const char* mytext = text;
  char utf8buf[BUFSIZE];
  char pm_msgid[64];
  char pm_timestamp[32];

  assert(0 != sptr);
  assert(0 != name);
  assert(0 != text);

  /* UTF8ONLY enforcement */
  if (feature_bool(FEAT_UTF8ONLY) && !string_is_valid_utf8(text)) {
    if (feature_bool(FEAT_UTF8ONLY_STRICT)) {
      send_fail(sptr, "PRIVMSG", "INVALID_UTF8", NULL,
                "Message contains invalid UTF-8 and was rejected");
      return;
    }
    /* Warn mode: copy, sanitize, and use sanitized version */
    ircd_strncpy(utf8buf, text, sizeof(utf8buf) - 1);
    utf8buf[sizeof(utf8buf) - 1] = '\0';
    string_sanitize_utf8(utf8buf);
    send_warn(sptr, "PRIVMSG", "INVALID_UTF8", NULL,
              "Message contained invalid UTF-8 and was sanitized");
    mytext = utf8buf;
    if (EmptyString(mytext)) {
      send_reply(sptr, ERR_NOTEXTTOSEND);
      return;
    }
  }

  if (0 == (acptr = FindUser(name))) {
    send_reply(sptr, ERR_NOSUCHNICK, name);
    return;
  }
  if ((!IsChannelService(acptr) &&
       check_target_limit(sptr, acptr, cli_name(acptr), 0)) ||
      is_silenced(sptr, acptr, 0))
    return;

  /*
   * +R check, if target is +R and we're not +r (or opered) then
   * deny the message.
   */
  if (IsAccountOnly(acptr) && !IsAccount(sptr) && !IsOper(sptr) && (acptr != sptr)) {
    send_reply(sptr, ERR_ACCOUNTONLY, cli_name(acptr), "PRIVMSG", cli_name(acptr));
    return;
  }

  /*
   * +D check, if target is +D and we're not opered then deny
   * the message.
   */
  if (IsPrivDeaf(acptr) && !IsOper(sptr) && (acptr != sptr)) {
    send_reply(sptr, ERR_PRIVDEAF, cli_name(acptr), "PRIVMSG", cli_name(acptr));
    return;
  }

  if ((IsRestrictPrivMsg(sptr) || IsCommonChansOnly(acptr)) && !IsAnOper(sptr) &&
      !common_chan_count(acptr, sptr, 1) && (sptr != acptr)) {
    send_reply(sptr, ERR_COMMONCHANSONLY, cli_name(acptr), "PRIVMSG");
    return;
  }

  /*
   * send away message if user away
   */
  if (cli_user(acptr) && cli_user(acptr)->away)
    send_reply(sptr, RPL_AWAY, cli_name(acptr), cli_user(acptr)->away);
  /*
   * deliver the message
   */
  if (MyUser(acptr))
    add_target(acptr, sptr);

  /* Generate shared msgid + timestamp for alias forwarding, echo, and history */
  pm_msgid[0] = '\0';
  pm_timestamp[0] = '\0';
  if (feature_bool(FEAT_MSGID)) {
    struct timeval tv;
    generate_msgid(pm_msgid, sizeof(pm_msgid));
    gettimeofday(&tv, NULL);
    ircd_snprintf(0, pm_timestamp, sizeof(pm_timestamp), "%lu.%03lu",
                  (unsigned long)tv.tv_sec,
                  (unsigned long)(tv.tv_usec / 1000));
  }

  /* Alias source rewriting for S2S legacy compat.
   * If target is on the primary's server direction, keep alias numeric
   * (avoids fake direction — server_relay handles rewriting there). */
  {
    const char *client_tags = cli_client_tags(sptr);
    struct Client *from = sptr;

    if (IsBouncerAlias(sptr) && cli_user(sptr)->alias_primary) {
      from = cli_user(sptr)->alias_primary;
      /* Keep alias numeric for primary's server direction to avoid fake direction */
      if (!MyUser(from) && !MyConnect(acptr)
          && cli_from(from) == cli_from(acptr))
        from = sptr;
    }

    if (client_tags && *client_tags && MyConnect(acptr) && CapActive(acptr, CAP_MSGTAGS)) {
      /* Set msgid override so format_message_tags_with_client includes it */
      if (pm_msgid[0])
        sendcmdto_set_client_msgid(pm_msgid);
      sendcmdto_one_client_tags(from, MSG_PRIVATE, acptr, client_tags,
                                "%C :%s", acptr, mytext);
      sendcmdto_set_client_msgid(NULL);
    } else {
      if (from != sptr)  /* Alias was rewritten — preserve S2S tags */
        sendcmdto_set_s2s_cptr(cli_from(sptr));
      /* Use tag-aware send so recipient gets server-time/msgid per caps.
       * For S2S delivery to IRCV3AWARE peers, sendcmdto_one_tags_with_client
       * also adds the @A...,C<client_tags> compact-tag prefix so the
       * remote server can forward client-only tags to its local recipient
       * (per p10-compact-client-tags plan). */
      sendcmdto_one_tags_with_client(from, CMD_PRIVATE, acptr,
                                     pm_msgid, client_tags,
                                     "%C :%s", acptr, mytext);
    }
  }

  /* Forward PM to all aliases of the target bouncer primary */
  bounce_forward_pm_to_aliases(sptr, acptr, CMD_PRIVATE, mytext, pm_msgid);

  /* Echo outgoing PM to other members of the sender's bouncer session */
  bounce_echo_pm_to_session(sptr, acptr, CMD_PRIVATE, mytext, pm_msgid);

  /* Echo private message back to sender if they have echo-message cap */
#ifdef USE_MDBX
  {
    int need_echo = feature_bool(FEAT_CAP_echo_message) && CapOwnHas(sptr, CAP_ECHOMSG);

    if (need_echo) {
      const char *echo_client_tags = cli_client_tags(sptr);
      if (echo_client_tags && *echo_client_tags && CapActive(sptr, CAP_MSGTAGS)) {
        /* Include client-only tags in echo per IRCv3 echo-message spec */
        char echo_tagbuf[4608];
        int tpos = 0;
        echo_tagbuf[0] = '@';
        tpos = 1;
        /* Client tags first */
        tpos += snprintf(echo_tagbuf + tpos, sizeof(echo_tagbuf) - tpos, "%s", echo_client_tags);
        /* Then server tags: label, msgid, time */
        if (cli_label(sptr)[0] && CapActive(sptr, CAP_LABELEDRESP) && !cli_label_responded(sptr)) {
          tpos += snprintf(echo_tagbuf + tpos, sizeof(echo_tagbuf) - tpos, ";label=%s", cli_label(sptr));
          cli_label_responded(sptr) = 1;
        }
        if (pm_msgid[0])
          tpos += snprintf(echo_tagbuf + tpos, sizeof(echo_tagbuf) - tpos, ";msgid=%s", pm_msgid);
        if (feature_bool(FEAT_CAP_server_time) && CapActive(sptr, CAP_SERVERTIME)) {
          struct timeval tv; struct tm tm;
          gettimeofday(&tv, NULL); gmtime_r(&tv.tv_sec, &tm);
          tpos += snprintf(echo_tagbuf + tpos, sizeof(echo_tagbuf) - tpos,
                           ";time=%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ",
                           tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                           tm.tm_hour, tm.tm_min, tm.tm_sec, tv.tv_usec / 1000);
        }
        echo_tagbuf[tpos] = '\0';
        sendrawto_one(sptr, "%s :%s!%s@%s PRIVMSG %C :%s",
                      echo_tagbuf, cli_name(sptr), cli_user(sptr)->username,
                      cli_user(sptr)->host, acptr, mytext);
      } else {
        sendcmdto_one_tags_ext(sptr, CMD_PRIVATE, sptr, pm_msgid,
                               "%C :%s", acptr, mytext);
      }
    }

    /* Store private message in history database (if enabled) */
    if (pm_msgid[0])
      store_private_history(sptr, acptr, mytext, HISTORY_PRIVMSG, pm_msgid, pm_timestamp,
                            cli_client_tags(sptr));
  }
#else
  {
    int need_echo = feature_bool(FEAT_CAP_echo_message) && CapOwnHas(sptr, CAP_ECHOMSG);
    if (need_echo) {
      const char *echo_client_tags = cli_client_tags(sptr);
      if (echo_client_tags && *echo_client_tags && CapActive(sptr, CAP_MSGTAGS)) {
        char echo_tagbuf[4608];
        int tpos = 0;
        echo_tagbuf[0] = '@';
        tpos = 1;
        tpos += snprintf(echo_tagbuf + tpos, sizeof(echo_tagbuf) - tpos, "%s", echo_client_tags);
        if (cli_label(sptr)[0] && CapActive(sptr, CAP_LABELEDRESP) && !cli_label_responded(sptr)) {
          tpos += snprintf(echo_tagbuf + tpos, sizeof(echo_tagbuf) - tpos, ";label=%s", cli_label(sptr));
          cli_label_responded(sptr) = 1;
        }
        if (pm_msgid[0])
          tpos += snprintf(echo_tagbuf + tpos, sizeof(echo_tagbuf) - tpos, ";msgid=%s", pm_msgid);
        if (feature_bool(FEAT_CAP_server_time) && CapActive(sptr, CAP_SERVERTIME)) {
          struct timeval tv; struct tm tm;
          gettimeofday(&tv, NULL); gmtime_r(&tv.tv_sec, &tm);
          tpos += snprintf(echo_tagbuf + tpos, sizeof(echo_tagbuf) - tpos,
                           ";time=%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ",
                           tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                           tm.tm_hour, tm.tm_min, tm.tm_sec, tv.tv_usec / 1000);
        }
        echo_tagbuf[tpos] = '\0';
        sendrawto_one(sptr, "%s :%s!%s@%s PRIVMSG %C :%s",
                      echo_tagbuf, cli_name(sptr), cli_user(sptr)->username,
                      cli_user(sptr)->host, acptr, mytext);
      } else {
        sendcmdto_one_tags_ext(sptr, CMD_PRIVATE, sptr, pm_msgid,
                               "%C :%s", acptr, mytext);
      }
    }
  }
#endif
}

/** Relay a private notice from a local user.
 * Returns an error if the user does not exist or sending to him would
 * exceed the source's free targets.  Sends an AWAY status message if
 * the target is marked as away.
 * @param[in] sptr Client that originated the message.
 * @param[in] name Nickname of target user.
 * @param[in] text %Message to relay.
 */
void relay_private_notice(struct Client* sptr, const char* name, const char* text)
{
  struct Client* acptr;
  const char* mytext = text;
  char utf8buf[BUFSIZE];
  char pm_msgid[64];
  char pm_timestamp[32];

  assert(0 != sptr);
  assert(0 != name);
  assert(0 != text);

  /* UTF8ONLY enforcement */
  if (feature_bool(FEAT_UTF8ONLY) && !string_is_valid_utf8(text)) {
    if (feature_bool(FEAT_UTF8ONLY_STRICT)) {
      send_fail(sptr, "NOTICE", "INVALID_UTF8", NULL,
                "Message contains invalid UTF-8 and was rejected");
      return;
    }
    /* Warn mode: copy, sanitize, and use sanitized version */
    ircd_strncpy(utf8buf, text, sizeof(utf8buf) - 1);
    utf8buf[sizeof(utf8buf) - 1] = '\0';
    string_sanitize_utf8(utf8buf);
    send_warn(sptr, "NOTICE", "INVALID_UTF8", NULL,
              "Message contained invalid UTF-8 and was sanitized");
    mytext = utf8buf;
    if (EmptyString(mytext))
      return;
  }

  if (0 == (acptr = FindUser(name)))
    return;
  if ((!IsChannelService(acptr) && 
       check_target_limit(sptr, acptr, cli_name(acptr), 0)) ||
      is_silenced(sptr, acptr, 0))
    return;

  /*
   * +R check, if target is +R and we're not +r (or opered) then
   * deny the message.
   */
  if (IsAccountOnly(acptr) && !IsAccount(sptr) && !IsOper(sptr) && (acptr != sptr)) {
    send_reply(sptr, ERR_ACCOUNTONLY, cli_name(acptr), "NOTICE", cli_name(acptr));
    return;
  }

  /*
   * +D check, if target is +D and we're not opered then deny
   * the message.
   */
  if (IsPrivDeaf(acptr) && !IsOper(sptr) && (acptr != sptr)) {
    send_reply(sptr, ERR_PRIVDEAF, cli_name(acptr), "NOTICE", cli_name(acptr));
    return;
  }

  if ((IsRestrictPrivMsg(sptr) || IsCommonChansOnly(acptr)) && !IsAnOper(sptr) &&
      !common_chan_count(acptr, sptr, 1) && (sptr != acptr)) {
    send_reply(sptr, ERR_COMMONCHANSONLY, cli_name(acptr), "NOTICE");
    return;
  }

  /*
   * deliver the message
   */
  if (MyUser(acptr))
    add_target(acptr, sptr);

  /* Generate shared msgid + timestamp for alias forwarding, echo, and history */
  pm_msgid[0] = '\0';
  pm_timestamp[0] = '\0';
  if (feature_bool(FEAT_MSGID)) {
    struct timeval tv;
    generate_msgid(pm_msgid, sizeof(pm_msgid));
    gettimeofday(&tv, NULL);
    ircd_snprintf(0, pm_timestamp, sizeof(pm_timestamp), "%lu.%03lu",
                  (unsigned long)tv.tv_sec,
                  (unsigned long)(tv.tv_usec / 1000));
  }

  /* Alias source rewriting (see relay_private_message) */
  {
    const char *client_tags = cli_client_tags(sptr);
    struct Client *from = sptr;

    if (IsBouncerAlias(sptr) && cli_user(sptr)->alias_primary) {
      from = cli_user(sptr)->alias_primary;
      if (!MyUser(from) && !MyConnect(acptr)
          && cli_from(from) == cli_from(acptr))
        from = sptr;
    }

    if (client_tags && *client_tags && MyConnect(acptr) && CapActive(acptr, CAP_MSGTAGS)) {
      if (pm_msgid[0])
        sendcmdto_set_client_msgid(pm_msgid);
      sendcmdto_one_client_tags(from, MSG_NOTICE, acptr, client_tags,
                                "%C :%s", acptr, mytext);
      sendcmdto_set_client_msgid(NULL);
    } else {
      if (from != sptr)
        sendcmdto_set_s2s_cptr(cli_from(sptr));
      /* Tag-aware send; for S2S to IRCV3AWARE peers also includes
       * @A...,C<client_tags> compact-tag prefix. */
      sendcmdto_one_tags_with_client(from, CMD_NOTICE, acptr,
                                     pm_msgid, client_tags,
                                     "%C :%s", acptr, mytext);
    }
  }

  /* Forward notice to all aliases of the target bouncer primary */
  bounce_forward_pm_to_aliases(sptr, acptr, CMD_NOTICE, mytext, pm_msgid);

  /* Echo outgoing notice to other members of the sender's bouncer session */
  bounce_echo_pm_to_session(sptr, acptr, CMD_NOTICE, mytext, pm_msgid);

  /* Echo private notice back to sender if they have echo-message cap */
#ifdef USE_MDBX
  {
    int need_echo = feature_bool(FEAT_CAP_echo_message) && CapOwnHas(sptr, CAP_ECHOMSG);

    if (need_echo) {
      sendcmdto_one_tags_ext(sptr, CMD_NOTICE, sptr, pm_msgid,
                             "%C :%s", acptr, mytext);
    }

    /* Store private notice in history database (if enabled) */
    if (pm_msgid[0])
      store_private_history(sptr, acptr, mytext, HISTORY_NOTICE, pm_msgid, pm_timestamp,
                            cli_client_tags(sptr));
  }
#else
  {
    int need_echo = feature_bool(FEAT_CAP_echo_message) && CapOwnHas(sptr, CAP_ECHOMSG);
    if (need_echo) {
      sendcmdto_one_tags_ext(sptr, CMD_NOTICE, sptr, pm_msgid,
                             "%C :%s", acptr, mytext);
    }
  }
#endif
}

/** Relay a private message that arrived from a server.
 * Returns an error if the user does not exist.
 * @param[in] sptr Client that originated the message.
 * @param[in] name Nickname of target user.
 * @param[in] text %Message to relay.
 */
void server_relay_private_message(struct Client* sptr, const char* name, const char* text)
{
  struct Client* acptr;
  struct Client* from;
  const char *client_tags;
  char pm_msgid[64];
  char pm_timestamp[32];

  assert(0 != sptr);
  assert(0 != name);
  assert(0 != text);

  /* Save alias context before potential rewrite.
   * For S2S-relayed messages, prefer cli_s2s_client_tags(server_link)
   * — see server_relay_channel_message. */
  {
    struct Client *one = cli_from(sptr);
    const char *s2s_tags = cli_s2s_client_tags(one);
    client_tags = (s2s_tags && *s2s_tags) ? s2s_tags : cli_client_tags(sptr);
  }
  from = sptr;

  /* Alias source rewriting: use primary's numeric for S2S.
   * The recipient's server may not understand BX C alias numerics. */
  if (IsBouncerAlias(sptr) && cli_user(sptr)->alias_primary)
    from = cli_user(sptr)->alias_primary;

  /*
   * nickname addressed?
   */
  if (0 == (acptr = findNUser(name)) || !IsUser(acptr)) {
    send_reply(sptr, SND_EXPLICIT | ERR_NOSUCHNICK, "* :Target left %s. "
	       "Failed to deliver: [%.20s]", feature_str(FEAT_NETWORK),
               text);
    return;
  }
  if (is_silenced(from, acptr, 0))
    return;

  if (MyUser(acptr))
    add_target(acptr, from);

  /* Unified msgid: pre-populate before pm_msgid generation and relay */
  if (feature_bool(FEAT_P10_MESSAGE_TAGS) && cli_from(sptr)
      && !cli_s2s_msgid(cli_from(sptr))[0])
    generate_msgid(cli_s2s_msgid(cli_from(sptr)), S2S_MSGID_BUFSIZE);

  /* Generate shared msgid + timestamp for alias forwarding and history.
   * Prefer S2S msgid for federation dedup — sptr is never reassigned
   * in PM relay, so cli_from(sptr) still has the incoming S2S tags. */
  pm_msgid[0] = '\0';
  pm_timestamp[0] = '\0';
  if (feature_bool(FEAT_MSGID)) {
    const char *s2s_mid = NULL;
    struct timeval tv;

    if (feature_bool(FEAT_P10_MESSAGE_TAGS) && cli_from(sptr)
        && cli_s2s_msgid(cli_from(sptr))[0])
      s2s_mid = cli_s2s_msgid(cli_from(sptr));

    if (s2s_mid)
      ircd_strncpy(pm_msgid, s2s_mid, sizeof(pm_msgid));
    else
      generate_msgid(pm_msgid, sizeof(pm_msgid));

    gettimeofday(&tv, NULL);
    ircd_snprintf(0, pm_timestamp, sizeof(pm_timestamp), "%lu.%03lu",
                  (unsigned long)tv.tv_sec,
                  (unsigned long)(tv.tv_usec / 1000));
  }

  /* Per-target direction guard for split S2S delivery:
   * If target is behind the primary's server direction, keep alias numeric
   * to avoid fake direction — that server handles rewriting locally. */
  {
    struct Client *send_from = from;
    if (send_from != sptr && !MyUser(send_from) && !MyConnect(acptr)
        && cli_from(send_from) == cli_from(acptr))
      send_from = sptr;

    /* Set client msgid so local client gets @msgid= tag */
    if (pm_msgid[0])
      sendcmdto_set_client_msgid(pm_msgid);

    if (client_tags && *client_tags && MyConnect(acptr) && CapActive(acptr, CAP_MSGTAGS)) {
      sendcmdto_one_client_tags(send_from, MSG_PRIVATE, acptr, client_tags,
                                "%C :%s", acptr, text);
    } else {
      if (send_from != sptr)  /* Alias was rewritten — preserve S2S tags */
        sendcmdto_set_s2s_cptr(cli_from(sptr));
      sendcmdto_one_tags_ext(send_from, CMD_PRIVATE, acptr, pm_msgid,
                             "%C :%s", acptr, text);
    }

    sendcmdto_set_client_msgid(NULL);
  }

  /* Forward PM to all aliases of the target bouncer primary */
  bounce_forward_pm_to_aliases(from, acptr, CMD_PRIVATE, text, pm_msgid);

#ifdef USE_MDBX
  /* Store server-relayed private message in history database (if enabled) */
  if (pm_msgid[0])
    store_private_history(from, acptr, text, HISTORY_PRIVMSG, pm_msgid, pm_timestamp,
                          client_tags);
#endif
}


/** Relay a private notice that arrived from a server.
 * Returns an error if the user does not exist.
 * @param[in] sptr Client that originated the message.
 * @param[in] name Nickname of target user.
 * @param[in] text %Message to relay.
 */
void server_relay_private_notice(struct Client* sptr, const char* name, const char* text)
{
  struct Client* acptr;
  struct Client* from;
  const char *client_tags;
  char pm_msgid[64];
  char pm_timestamp[32];

  assert(0 != sptr);
  assert(0 != name);
  assert(0 != text);

  /* Save alias context before potential rewrite.
   * For S2S-relayed messages, prefer cli_s2s_client_tags(server_link)
   * — see server_relay_channel_message. */
  {
    struct Client *one = cli_from(sptr);
    const char *s2s_tags = cli_s2s_client_tags(one);
    client_tags = (s2s_tags && *s2s_tags) ? s2s_tags : cli_client_tags(sptr);
  }
  from = sptr;

  /* Alias source rewriting (see server_relay_private_message) */
  if (IsBouncerAlias(sptr) && cli_user(sptr)->alias_primary)
    from = cli_user(sptr)->alias_primary;

  /*
   * nickname addressed?
   */
  if (0 == (acptr = findNUser(name)) || !IsUser(acptr))
    return;

  if (is_silenced(from, acptr, 0))
    return;

  if (MyUser(acptr))
    add_target(acptr, from);

  /* Unified msgid: pre-populate before pm_msgid generation and relay */
  if (feature_bool(FEAT_P10_MESSAGE_TAGS) && cli_from(sptr)
      && !cli_s2s_msgid(cli_from(sptr))[0])
    generate_msgid(cli_s2s_msgid(cli_from(sptr)), S2S_MSGID_BUFSIZE);

  /* Generate shared msgid + timestamp (prefer S2S msgid for federation dedup) */
  pm_msgid[0] = '\0';
  pm_timestamp[0] = '\0';
  if (feature_bool(FEAT_MSGID)) {
    const char *s2s_mid = NULL;
    struct timeval tv;

    if (feature_bool(FEAT_P10_MESSAGE_TAGS) && cli_from(sptr)
        && cli_s2s_msgid(cli_from(sptr))[0])
      s2s_mid = cli_s2s_msgid(cli_from(sptr));

    if (s2s_mid)
      ircd_strncpy(pm_msgid, s2s_mid, sizeof(pm_msgid));
    else
      generate_msgid(pm_msgid, sizeof(pm_msgid));

    gettimeofday(&tv, NULL);
    ircd_snprintf(0, pm_timestamp, sizeof(pm_timestamp), "%lu.%03lu",
                  (unsigned long)tv.tv_sec,
                  (unsigned long)(tv.tv_usec / 1000));
  }

  /* Per-target direction guard (see server_relay_private_message) */
  {
    struct Client *send_from = from;
    int delivered = 0;

    if (send_from != sptr && !MyUser(send_from) && !MyConnect(acptr)
        && cli_from(send_from) == cli_from(acptr))
      send_from = sptr;

    /* Set client msgid so local client gets @msgid= tag */
    if (pm_msgid[0])
      sendcmdto_set_client_msgid(pm_msgid);

    /* Check for forwarded label batch in DRAINING state */
    if (MyConnect(acptr) && feature_bool(FEAT_CAP_labeled_response)) {
      const char *incoming_msgid = (cli_from(sptr) && cli_s2s_msgid(cli_from(sptr))[0])
                                    ? cli_s2s_msgid(cli_from(sptr)) : "";
      struct ForwardedLabel *fl = fwd_label_find_draining(acptr, incoming_msgid);
      if (fl) {
        sendcmdto_set_fwd_batch(fl->fl_batch_id);
        sendcmdto_one_tags_ext(send_from, CMD_NOTICE, acptr, pm_msgid,
                               "%C :%s", acptr, text);
        /* Stay DRAINING -- more trailing messages may follow */
        delivered = 1;
      }
    }

    if (!delivered) {
      if (client_tags && *client_tags && MyConnect(acptr) && CapActive(acptr, CAP_MSGTAGS)) {
        sendcmdto_one_client_tags(send_from, MSG_NOTICE, acptr, client_tags,
                                  "%C :%s", acptr, text);
      } else {
        if (send_from != sptr)
          sendcmdto_set_s2s_cptr(cli_from(sptr));
        sendcmdto_one_tags_ext(send_from, CMD_NOTICE, acptr, pm_msgid,
                               "%C :%s", acptr, text);
      }
    }

    sendcmdto_set_client_msgid(NULL);
  }

  /* Forward notice to all aliases of the target bouncer primary */
  bounce_forward_pm_to_aliases(from, acptr, CMD_NOTICE, text, pm_msgid);

#ifdef USE_MDBX
  /* Store server-relayed private notice in history database (if enabled) */
  if (pm_msgid[0])
    store_private_history(from, acptr, text, HISTORY_NOTICE, pm_msgid, pm_timestamp,
                          client_tags);
#endif
}

/** Relay a masked message from a local user.
 * Sends an error response if there is no top-level domain label in \a
 * mask, or if that TLD contains a wildcard.
 * @param[in] sptr Client that originated the message.
 * @param[in] mask Target mask for the message.
 * @param[in] text %Message to relay.
 */
void relay_masked_message(struct Client* sptr, const char* mask, const char* text)
{
  const char* s;
  int   host_mask = 0;

  assert(0 != sptr);
  assert(0 != mask);
  assert(0 != text);
  /*
   * look for the last '.' in mask and scan forward
   */
  if (0 == (s = strrchr(mask, '.'))) {
    send_reply(sptr, ERR_NOTOPLEVEL, mask);
    return;
  }
  while (*++s) {
    if (*s == '.' || *s == '*' || *s == '?')
       break;
  }
  if (*s == '*' || *s == '?') {
    send_reply(sptr, ERR_WILDTOPLEVEL, mask);
    return;
  }
  s = mask;
  if ('@' == *++s) {
    host_mask = 1;
    ++s;
  }

  sendcmdto_match_butone(sptr, CMD_PRIVATE, s,
			 IsServer(cli_from(sptr)) ? cli_from(sptr) : 0,
			 host_mask ? MATCH_HOST : MATCH_SERVER,
			 "%s :%s", mask, text);
}

/** Relay a masked notice from a local user.
 * Sends an error response if there is no top-level domain label in \a
 * mask, or if that TLD contains a wildcard.
 * @param[in] sptr Client that originated the message.
 * @param[in] mask Target mask for the message.
 * @param[in] text %Message to relay.
 */
void relay_masked_notice(struct Client* sptr, const char* mask, const char* text)
{
  const char* s;
  int   host_mask = 0;

  assert(0 != sptr);
  assert(0 != mask);
  assert(0 != text);
  /*
   * look for the last '.' in mask and scan forward
   */
  if (0 == (s = strrchr(mask, '.'))) {
    send_reply(sptr, ERR_NOTOPLEVEL, mask);
    return;
  }
  while (*++s) {
    if (*s == '.' || *s == '*' || *s == '?')
       break;
  }
  if (*s == '*' || *s == '?') {
    send_reply(sptr, ERR_WILDTOPLEVEL, mask);
    return;
  }
  s = mask;
  if ('@' == *++s) {
    host_mask = 1;
    ++s;
  }

  sendcmdto_match_butone(sptr, CMD_NOTICE, s,
			 IsServer(cli_from(sptr)) ? cli_from(sptr) : 0,
			 host_mask ? MATCH_HOST : MATCH_SERVER,
			 "%s :%s", mask, text);
}

/** Relay a masked message that arrived from a server.
 * @param[in] sptr Client that originated the message.
 * @param[in] mask Target mask for the message.
 * @param[in] text %Message to relay.
 */
void server_relay_masked_message(struct Client* sptr, const char* mask, const char* text)
{
  const char* s = mask;
  int         host_mask = 0;
  assert(0 != sptr);
  assert(0 != mask);
  assert(0 != text);

  if ('@' == *++s) {
    host_mask = 1;
    ++s;
  }
  sendcmdto_match_butone(sptr, CMD_PRIVATE, s,
			 IsServer(cli_from(sptr)) ? cli_from(sptr) : 0,
			 host_mask ? MATCH_HOST : MATCH_SERVER,
			 "%s :%s", mask, text);
}

/** Relay a masked notice that arrived from a server.
 * @param[in] sptr Client that originated the message.
 * @param[in] mask Target mask for the message.
 * @param[in] text %Message to relay.
 */
void server_relay_masked_notice(struct Client* sptr, const char* mask, const char* text)
{
  const char* s = mask;
  int         host_mask = 0;
  assert(0 != sptr);
  assert(0 != mask);
  assert(0 != text);

  if ('@' == *++s) {
    host_mask = 1;
    ++s;
  }
  sendcmdto_match_butone(sptr, CMD_NOTICE, s,
			 IsServer(cli_from(sptr)) ? cli_from(sptr) : 0,
			 host_mask ? MATCH_HOST : MATCH_SERVER,
			 "%s :%s", mask, text);
}

