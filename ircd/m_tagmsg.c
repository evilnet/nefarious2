/*
 * IRC - Internet Relay Chat, ircd/m_tagmsg.c
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

/*
 * m_functions execute protocol messages on this server:
 *
 *    cptr    is always NON-NULL, pointing to a *LOCAL* client
 *            structure (with an open socket connected!). This
 *            identifies the physical socket where the message
 *            originated (or which caused the m_function to be
 *            executed--some m_functions may call others...).
 *
 *    sptr    is the source of the message, defined by the
 *            prefix part of the message if present. If not
 *            or prefix not found, then sptr==cptr.
 *
 *            (!IsServer(cptr)) => (cptr == sptr), because
 *            prefixes are taken *only* from servers...
 *
 *            (IsServer(cptr))
 *                    (sptr == cptr) => the message didn't
 *                    have the prefix.
 *
 *                    (sptr != cptr && IsServer(sptr) means
 *                    the prefix specified servername. (?)
 *
 *                    (sptr != cptr && !IsServer(sptr) means
 *                    that message originated from a remote
 *                    user (not local).
 *
 *            combining
 *
 *            (!IsServer(sptr)) means that, sptr can safely
 *            taken as defining the target structure of the
 *            message in this server.
 *
 *    *Always* true (if 'parse' and others are working correct):
 *
 *    1)      sptr->from == cptr  (note: cptr->from == cptr)
 *
 *    2)      MyConnect(sptr) <=> sptr == cptr (e.g. sptr
 *            *cannot* be a local connection, unless it's
 *            actually cptr!). [MyConnect(x) should probably
 *            be defined as (x == x->from) --msa ]
 *
 *    parc    number of variable parameter strings (if zero,
 *            parv is allowed to be NULL)
 *
 *    parv    a NULL terminated list of parameter pointers,
 *
 *                    parv[0], sender (prefix string), if not present
 *                            this points to an empty string.
 *                    parv[1]...parv[parc-1]
 *                            pointers to additional parameters
 *                    parv[parc] == NULL, *always*
 *
 *            note:   it is guaranteed that parv[0]..parv[parc-1] are all
 *                    non-NULL pointers.
 */
#include "config.h"

#include "capab.h"
#include "channel.h"
#include "client.h"
#include "hash.h"
#include "history.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "send.h"
#include "handlers.h"
#include "s_user.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <string.h>
#include <sys/time.h>

/** Check if client_tags contains only ephemeral tags (+typing).
 * Returns 1 if ALL tags are ephemeral (should skip storage), 0 otherwise.
 * A TAGMSG with both +typing and +draft/react should still be stored.
 */
static int has_only_ephemeral_tags(const char *tags)
{
  const char *p = tags;

  if (!tags || !*tags)
    return 1;

  while (p && *p) {
    const char *sep = strchr(p, ';');
    size_t taglen = sep ? (size_t)(sep - p) : strlen(p);

    /* Check if this tag is +typing or +typing=* */
    if (taglen < 7 || strncmp(p, "+typing", 7) != 0 ||
        (taglen > 7 && p[7] != '=')) {
      return 0;  /* Found a non-ephemeral tag */
    }
    p = sep ? sep + 1 : NULL;
  }
  return 1;
}

/**
 * Store a TAGMSG in channel history for event-playback.
 * TAGMSG content is stored as the client-only tags.
 */
static void store_tagmsg_history(struct Client *sptr, struct Channel *chptr,
                                  const char *client_tags,
                                  const char *broadcast_msgid)
{
  struct timeval tv;
  char timestamp[32];
  char fallback_msgid[64];
  const char *msgid;
  char sender[HISTORY_SENDER_LEN];
  const char *account;

  if (!history_is_available())
    return;

  /* Only store if event-playback is enabled */
  if (!feature_bool(FEAT_CAP_draft_event_playback))
    return;

  /* Filter ephemeral tags — typing indicators are not meaningful in history.
   * Only skip if ALL tags are ephemeral; a TAGMSG with both +typing and
   * +draft/react should still be stored for the reaction. */
  if (has_only_ephemeral_tags(client_tags))
    return;

  /* Check if channel has +P (no storage) mode */
  if (chptr->mode.exmode & EXMODE_NOSTORAGE)
    return;

  /* Check if sender has +Y (no storage) user mode */
  if (IsNoStorage(sptr))
    return;

  /* Use broadcast msgid so clients can deduplicate */
  if (broadcast_msgid && broadcast_msgid[0])
    msgid = broadcast_msgid;
  else
    msgid = generate_msgid(fallback_msgid, sizeof(fallback_msgid));

  /* Generate Unix timestamp for storage */
  gettimeofday(&tv, NULL);
  ircd_snprintf(0, timestamp, sizeof(timestamp), "%lu.%03lu",
                (unsigned long)tv.tv_sec,
                (unsigned long)(tv.tv_usec / 1000));

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

  /* Store locally or forward to STORE server */
  if (feature_bool(FEAT_CHATHISTORY_STORE)) {
    history_store_message(msgid, timestamp, chptr->chname, NULL, sender,
                          account, HISTORY_TAGMSG, "", client_tags);
  } else if (feature_bool(FEAT_CHATHISTORY_WRITE_FORWARD)) {
    /* Encode client tags with \x06 sentinel for transparent forwarding */
    char tagged_content[512 + 4];
    ircd_snprintf(0, tagged_content, sizeof(tagged_content),
                  "\x06%s\x06", client_tags);
    forward_history_write(chptr, sptr, msgid, timestamp, HISTORY_TAGMSG,
                          tagged_content);
  }
}

/*
 * m_tagmsg - local client message handler
 *
 * parv[0] = sender prefix
 * parv[1] = target (channel or user)
 *
 * TAGMSG sends a message with only tags (no content).
 * Used for client-only tags like +typing.
 * IRCv3 specification: https://ircv3.net/specs/extensions/message-tags
 *
 * Client-only tags (prefixed with +) are extracted by parse.c
 * and stored in cli_client_tags(). This handler relays them to recipients.
 */
int m_tagmsg(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Channel* chptr;
  struct Client* acptr;
  char* target;
  const char* client_tags;

  assert(0 != cptr);
  assert(cptr == sptr);

  if (parc < 2 || EmptyString(parv[1])) {
    if (CapActive(sptr, CAP_STANDARDREPLIES))
      send_fail(sptr, "TAGMSG", "NEED_MORE_PARAMS", NULL, "Missing target");
    return send_reply(sptr, ERR_NEEDMOREPARAMS, "TAGMSG");
  }

  /* Get the client-only tags extracted from the message */
  client_tags = cli_client_tags(sptr);

  /* TAGMSG without client-only tags is meaningless */
  if (!client_tags || !*client_tags)
    return 0;

  target = parv[1];

  /* Check if target is a channel */
  if (IsChannelName(target)) {
    chptr = FindChannel(target);
    if (!chptr) {
      if (CapActive(sptr, CAP_STANDARDREPLIES))
        send_fail(sptr, "TAGMSG", "INVALID_TARGET", target, "No such channel");
      return send_reply(sptr, ERR_NOSUCHCHANNEL, target);
    }

    /* Check if user can send to channel */
    if (!client_can_send_to_channel(sptr, chptr, 0)) {
      if (CapActive(sptr, CAP_STANDARDREPLIES))
        send_fail(sptr, "TAGMSG", "CANNOT_SEND", chptr->chname, "Cannot send to channel");
      return send_reply(sptr, ERR_CANNOTSENDTOCHAN, chptr->chname);
    }

    /* Generate msgid for this TAGMSG (used in relay and history) */
    {
      char tagmsg_msgid[64];
      generate_msgid(tagmsg_msgid, sizeof(tagmsg_msgid));

      /* Set msgid override so channel/client tag sends include it */
      sendcmdto_set_client_msgid(tagmsg_msgid);

      /* Relay TAGMSG with client-only tags to local channel members */
      sendcmdto_channel_client_tags(sptr, MSG_TAGMSG, chptr, sptr,
                                    SKIP_DEAF | SKIP_BURST, client_tags,
                                    "%H", chptr);

      /* Echo TAGMSG back to sender if they have echo-message */
      {
        int need_echo = feature_bool(FEAT_CAP_echo_message) && CapOwnHas(sptr, CAP_ECHOMSG);
        if (need_echo) {
          sendcmdto_one_client_tags(sptr, MSG_TAGMSG, sptr, client_tags,
                                    "%H", chptr);
        }
      }

      sendcmdto_set_client_msgid(NULL);

      /* Store for chathistory event-playback — same msgid as broadcast */
      store_tagmsg_history(sptr, chptr, client_tags, tagmsg_msgid);

      /* Propagate to other servers (S2S with tags in P10 message).
       * Use the same msgid we generated for local delivery. */
      if (!IsLocalChannel(chptr->chname)) {
        sendcmdto_set_s2s_tags(0, tagmsg_msgid);
        sendcmdto_want_s2s_tags(1);
        sendcmdto_serv_butone_v3(sptr, CMD_TAGMSG, cptr, "@%s %s",
                              client_tags, chptr->chname);
      }
    }
  }
  else {
    /* Target is a user */
    acptr = FindUser(target);
    if (!acptr) {
      if (CapActive(sptr, CAP_STANDARDREPLIES))
        send_fail(sptr, "TAGMSG", "INVALID_TARGET", target, "No such nick");
      return send_reply(sptr, ERR_NOSUCHNICK, target);
    }

    {
      char dm_msgid[64];
      generate_msgid(dm_msgid, sizeof(dm_msgid));
      sendcmdto_set_client_msgid(dm_msgid);

      if (MyConnect(acptr)) {
        /* Local user - deliver with client-only tags if they support message-tags */
        if (CapActive(acptr, CAP_MSGTAGS)) {
          sendcmdto_one_client_tags(sptr, MSG_TAGMSG, acptr, client_tags,
                                    "%C", acptr);
        }
        /* Note: If client doesn't support message-tags, TAGMSG is silently dropped
         * per the IRCv3 spec - there's no message body to send as fallback */

        /* Echo TAGMSG back to sender if they have echo-message */
        {
          int need_echo = feature_bool(FEAT_CAP_echo_message) && CapOwnHas(sptr, CAP_ECHOMSG);
          if (need_echo) {
            sendcmdto_one_client_tags(sptr, MSG_TAGMSG, sptr, client_tags,
                                      "%C", acptr);
          }
        }
      }
      else {
        /* Remote user - forward to their server with tags */
        sendcmdto_set_s2s_tags(0, dm_msgid);
        sendcmdto_one(sptr, CMD_TAGMSG, acptr, "@%s %C",
                      client_tags, acptr);

        /* Echo TAGMSG back to sender if they have echo-message */
        {
          int need_echo = feature_bool(FEAT_CAP_echo_message) && CapOwnHas(sptr, CAP_ECHOMSG);
          if (need_echo) {
            sendcmdto_one_client_tags(sptr, MSG_TAGMSG, sptr, client_tags,
                                      "%C", acptr);
          }
        }
      }

      sendcmdto_set_client_msgid(NULL);
    }
  }

  return 0;
}

/*
 * ms_tagmsg - server message handler
 *
 * parv[0] = sender prefix
 * parv[1] = @client-tags or target
 * parv[2] = target (if parv[1] is tags)
 *
 * Handle TAGMSG from other servers (P10: TM token).
 * Format: NUMERIC TM @+typing=active #channel
 *         or: NUMERIC TM #channel (legacy, no tags - ignored)
 */
int ms_tagmsg(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Channel* chptr;
  struct Client* acptr;
  char* target;
  char* client_tags = NULL;

  assert(0 != cptr);
  assert(0 != sptr);

  /* Servers can't send TAGMSG */
  if (IsServer(sptr))
    return protocol_violation(sptr, "Server trying to send TAGMSG");

  if (parc < 2 || EmptyString(parv[1]))
    return 0;

  /* Two ways tags arrive on incoming S2S TAGMSG:
   *
   * 1. parv[1] @<tags> — pre-CAPAB ad-hoc convention. Still used by
   *    fork peers running older code that hasn't adopted the
   *    compact-tag ,C<client_tags> segment yet. parv[2] is the target.
   *
   * 2. cli_s2s_client_tags(cptr) — set by parse_server() from the
   *    compact-tag ,C segment of the incoming line. parv[1] is the
   *    target directly.
   *
   * Try the parv[1] form first for backward compat with peers still
   * emitting the ad-hoc form, then fall back to the compact-tag form.
   */
  if (parv[1][0] == '@') {
    client_tags = parv[1] + 1;  /* Skip the @ prefix */
    if (parc < 3 || EmptyString(parv[2]))
      return 0;
    target = parv[2];
  }
  else if (cli_s2s_client_tags(cptr)[0]) {
    client_tags = cli_s2s_client_tags(cptr);
    target = parv[1];
  }
  else {
    /* No tags via either form - meaningless TAGMSG, drop */
    return 0;
  }

  /* TAGMSG without client-only tags is meaningless */
  if (!client_tags || !*client_tags)
    return 0;

  /* Check if target is a channel */
  if (IsChannelName(target)) {
    chptr = FindChannel(target);
    if (!chptr)
      return 0;

    /* Set msgid from S2S tags for local client delivery */
    if (cli_s2s_msgid(cptr)[0])
      sendcmdto_set_client_msgid(cli_s2s_msgid(cptr));

    /* Relay to local channel members with message-tags capability */
    sendcmdto_channel_client_tags(sptr, MSG_TAGMSG, chptr, cptr,
                                  SKIP_DEAF | SKIP_BURST, client_tags,
                                  "%H", chptr);

    sendcmdto_set_client_msgid(NULL);

    /* Propagate to other servers */
    sendcmdto_serv_butone_v3(sptr, CMD_TAGMSG, cptr, "@%s %s",
                          client_tags, target);

    /* Store in history (or write-forward to STORE server).
     * Use S2S msgid if available so clients can deduplicate. */
    store_tagmsg_history(sptr, chptr, client_tags,
                         cli_s2s_msgid(cptr)[0] ? cli_s2s_msgid(cptr) : NULL);
  }
  else {
    /* Target is a user */
    acptr = findNUser(target);
    if (!acptr)
      acptr = FindUser(target);
    if (!acptr)
      return 0;

    /* Set msgid from S2S tags for local client delivery */
    if (cli_s2s_msgid(cptr)[0])
      sendcmdto_set_client_msgid(cli_s2s_msgid(cptr));

    if (MyConnect(acptr)) {
      /* Local user - deliver with client-only tags if they support message-tags */
      if (CapActive(acptr, CAP_MSGTAGS)) {
        sendcmdto_one_client_tags(sptr, MSG_TAGMSG, acptr, client_tags,
                                  "%C", acptr);
      }
      /* Note: If client doesn't support message-tags, TAGMSG is silently dropped */
    }
    else {
      /* Remote user - forward to their server with tags */
      sendcmdto_one(sptr, CMD_TAGMSG, acptr, "@%s %C",
                    client_tags, acptr);
    }

    sendcmdto_set_client_msgid(NULL);
  }

  return 0;
}
