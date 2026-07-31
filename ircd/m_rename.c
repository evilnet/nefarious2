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
#include "ircd_events.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "ircd_alloc.h"
#include "list.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_user.h"
#include "send.h"
#include "bouncer_session.h"

#include <string.h>
#include <stdlib.h>

/* ========== Pending Rename Infrastructure ========== */

/** Maximum pending rename requests */
#define RENAME_MAX_PENDING 100

/** Timeout for services response (seconds) */
#define RENAME_TIMEOUT 10

/** Pending channel rename request */
struct PendingRename {
  struct Client *client;           /**< Client waiting for response */
  struct Channel *channel;         /**< Channel being renamed */
  char oldname[CHANNELLEN + 1];    /**< Original channel name */
  char newname[CHANNELLEN + 1];    /**< Requested new name */
  char reason[TOPICLEN + 1];       /**< Rename reason */
  unsigned int cookie;             /**< Unique identifier for matching response */
  struct Timer timeout;            /**< Timeout timer */
  struct PendingRename *next;      /**< Linked list */
};

/** Global pending rename list */
static struct PendingRename *pending_renames = NULL;
static int pending_rename_count = 0;
static unsigned int rename_cookie_counter = 1;

/* Forward declarations */
static void pending_rename_timeout_cb(struct Event *ev);
static void send_rename_to_members(struct Client *sptr, struct Channel *chptr,
                                   const char *oldname, const char *reason);

/** Find the services server.
 * @return Pointer to services server, or NULL if not connected.
 */
static struct Client *find_services_server(void)
{
  struct Client *acptr;

  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr)) {
    if (IsServer(acptr) && IsService(acptr))
      return acptr;
  }

  return NULL;
}

/** RENAME is only sound when every server can apply RN.  Legacy servers
 * neither relay nor apply unknown tokens (design doc section 2), so refuse
 * while any non-v3-aware, non-service server is linked.  Services are
 * exempt: they get the targeted forward in rename_forward_legacy_services()
 * below.
 * @return First blocking legacy server found, or NULL if none.
 */
static struct Client *rename_legacy_blocker(void)
{
  struct Client *acptr;

  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr))
    if (IsServer(acptr) && !IsIRCv3Aware(acptr) && !IsService(acptr))
      return acptr;

  return NULL;
}

/** Forward a RENAME to directly-connected legacy (non-IRCv3-aware) service
 * links.  sendcmdto_serv_butone_v3() intentionally skips every
 * non-IRCv3-aware peer, but a legacy services package still needs to learn
 * about the renamed channel to keep its own channel/registration state in
 * sync, even though it can't speak the RN P10 token as an S2S relay hop.
 * @param[in] sptr Client to use as the message source.
 * @param[in] skip Downlink to skip (the direction the message came from),
 *                 or NULL if the rename originated locally.
 * @param[in] oldname Old channel name.
 * @param[in] newname New channel name.
 * @param[in] reason Rename reason (may be empty string).
 */
static void rename_forward_legacy_services(struct Client *sptr, struct Client *skip,
                                           const char *oldname, const char *newname,
                                           const char *reason)
{
  struct DLink *dlp;

  for (dlp = cli_serv(&me)->down; dlp; dlp = dlp->next) {
    if (dlp->value.cptr == skip)
      continue;
    if (!IsIRCv3Aware(dlp->value.cptr) && IsService(dlp->value.cptr))
      sendcmdto_one(sptr, CMD_RENAME, dlp->value.cptr, "%s %s :%s",
                    oldname, newname, reason);
  }
}

/** Add a pending rename request.
 * @param[in] client Client requesting the rename.
 * @param[in] channel Channel to be renamed.
 * @param[in] newname New channel name.
 * @param[in] reason Rename reason.
 * @return Pointer to new pending request, or NULL on error.
 */
static struct PendingRename *pending_rename_add(struct Client *client,
                                                 struct Channel *channel,
                                                 const char *newname,
                                                 const char *reason)
{
  struct PendingRename *pr;

  if (pending_rename_count >= RENAME_MAX_PENDING)
    return NULL;

  pr = (struct PendingRename *)MyMalloc(sizeof(struct PendingRename));
  if (!pr)
    return NULL;

  memset(pr, 0, sizeof(*pr));
  pr->client = client;
  pr->channel = channel;
  ircd_strncpy(pr->oldname, channel->chname, CHANNELLEN + 1);
  ircd_strncpy(pr->newname, newname, CHANNELLEN + 1);
  if (reason && *reason) {
    ircd_strncpy(pr->reason, reason, TOPICLEN + 1);
  }
  pr->cookie = rename_cookie_counter++;

  /* Add to list */
  pr->next = pending_renames;
  pending_renames = pr;
  pending_rename_count++;

  /* Start timeout timer */
  timer_add(timer_init(&pr->timeout), pending_rename_timeout_cb, (void *)pr,
            TT_RELATIVE, RENAME_TIMEOUT);

  log_write(LS_DEBUG, L_DEBUG, 0,
            "pending_rename_add: cookie=%u channel=%s newname=%s client=%C",
            pr->cookie, pr->oldname, pr->newname, client);

  return pr;
}

/** Find a pending rename by cookie.
 * @param[in] cookie Cookie to search for.
 * @return Pointer to pending request, or NULL if not found.
 */
struct PendingRename *pending_rename_find(unsigned int cookie)
{
  struct PendingRename *pr;

  for (pr = pending_renames; pr; pr = pr->next) {
    if (pr->cookie == cookie)
      return pr;
  }

  return NULL;
}

/** Remove a pending rename request from the list.
 * @param[in] pr Pending request to remove.
 */
static void pending_rename_remove(struct PendingRename *pr)
{
  struct PendingRename **pp;

  if (!pr)
    return;

  /* Cancel timeout timer */
  if (t_active(&pr->timeout))
    timer_del(&pr->timeout);

  /* Unlink from list */
  for (pp = &pending_renames; *pp; pp = &(*pp)->next) {
    if (*pp == pr) {
      *pp = pr->next;
      pending_rename_count--;
      break;
    }
  }

  log_write(LS_DEBUG, L_DEBUG, 0,
            "pending_rename_remove: cookie=%u", pr->cookie);

  MyFree(pr);
}

/** Complete a pending rename (called when services approves).
 * @param[in] pr Pending request to complete.
 */
void pending_rename_complete(struct PendingRename *pr)
{
  int rc;

  if (!pr || !pr->client || !pr->channel)
    return;

  log_write(LS_DEBUG, L_DEBUG, 0,
            "pending_rename_complete: cookie=%u oldname=%s newname=%s",
            pr->cookie, pr->oldname, pr->newname);

  /* Re-verify the channel still exists and name matches */
  if (0 != ircd_strcmp(pr->channel->chname, pr->oldname)) {
    log_write(LS_DEBUG, L_WARNING, 0,
              "pending_rename_complete: channel name changed while waiting");
    pending_rename_remove(pr);
    return;
  }

  /* Perform the rename (updates pr->channel if reallocated) */
  rc = rename_channel(&pr->channel, pr->newname);
  if (rc != 0) {
    send_fail(pr->client, "RENAME", "CANNOT_RENAME", pr->oldname,
              "Rename failed");
    pending_rename_remove(pr);
    return;
  }

  /* Send to local channel members */
  send_rename_to_members(pr->client, pr->channel, pr->oldname, pr->reason);

  /* Propagate to other servers */
  sendcmdto_serv_butone_v3(pr->client, CMD_RENAME, cli_from(pr->client),
                        "%s %s :%s", pr->oldname, pr->channel->chname,
                        pr->reason);

  /* Legacy services links don't get RN via the v3-only broadcast above;
   * synth it directly so they can keep their channel state in sync. */
  rename_forward_legacy_services(pr->client, NULL, pr->oldname,
                                 pr->channel->chname, pr->reason);

  pending_rename_remove(pr);
}

/** Deny a pending rename (called when services denies).
 * @param[in] pr Pending request to deny.
 * @param[in] reason Reason for denial.
 */
void pending_rename_deny(struct PendingRename *pr, const char *reason)
{
  if (!pr || !pr->client)
    return;

  log_write(LS_DEBUG, L_DEBUG, 0,
            "pending_rename_deny: cookie=%u reason=%s",
            pr->cookie, reason ? reason : "Permission denied");

  send_fail(pr->client, "RENAME", "CANNOT_RENAME", pr->oldname,
            reason ? reason : "Permission denied");

  pending_rename_remove(pr);
}

/** Timeout callback for pending rename.
 * @param[in] ev Timer event.
 */
static void pending_rename_timeout_cb(struct Event *ev)
{
  struct PendingRename *pr;

  assert(0 != ev_timer(ev));
  assert(0 != t_data(ev_timer(ev)));

  if (ev_type(ev) == ET_EXPIRE) {
    pr = (struct PendingRename *)t_data(ev_timer(ev));

    log_write(LS_DEBUG, L_DEBUG, 0,
              "pending_rename_timeout: cookie=%u channel=%s",
              pr->cookie, pr->oldname);

    send_fail(pr->client, "RENAME", "CANNOT_RENAME", pr->oldname,
              "Services response timeout");

    /* Timer already fired, mark inactive before remove */
    timer_del(&pr->timeout);
    pending_rename_remove(pr);
  }
}

/** Cleanup pending renames for a disconnecting client.
 * @param[in] cptr Client that is disconnecting.
 */
void pending_rename_client_exit(struct Client *cptr)
{
  struct PendingRename *pr, *next;
  struct PendingRename **pp;

  pp = &pending_renames;
  while (*pp) {
    pr = *pp;
    if (pr->client == cptr) {
      /* Cancel timeout and remove */
      if (t_active(&pr->timeout))
        timer_del(&pr->timeout);
      *pp = pr->next;
      pending_rename_count--;
      log_write(LS_DEBUG, L_DEBUG, 0,
                "pending_rename_client_exit: removed cookie=%u for %C",
                pr->cookie, cptr);
      MyFree(pr);
    } else {
      pp = &(*pp)->next;
    }
  }
}

/* ========== End Pending Rename Infrastructure ========== */

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

    {
      if (CapOwnHas(acptr, CAP_DRAFT_CHANRENAME)) {
        /* Non-bouncer with cap — send RENAME */
        sendcmdto_one(sptr, CMD_RENAME, acptr, "%s %s :%s",
                      oldname, chptr->chname, reason ? reason : "");
      } else {
        /* Non-bouncer without cap — PART/JOIN fallback */
        sendcmdto_one(acptr, CMD_PART, acptr, "%s :Channel renamed to %s%s%s",
                      oldname, chptr->chname,
                      (reason && *reason) ? ": " : "",
                      (reason && *reason) ? reason : "");
        sendcmdto_one(acptr, CMD_JOIN, acptr, "%s", chptr->chname);
        if (chptr->topic[0]) {
          send_reply(acptr, RPL_TOPIC, chptr->chname, chptr->topic);
          send_reply(acptr, RPL_TOPICWHOTIME, chptr->chname, chptr->topic_nick,
                     chptr->topic_time);
        }
        do_names(acptr, chptr, NAMES_ALL|NAMES_EON);
      }
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

  /* RENAME is only sound when every linked server can apply RN.  Refuse
   * up front while a legacy (non-v3-aware, non-service) server is on the
   * network, rather than only in the registered-channel branch below —
   * an unregistered-channel rename that a legacy peer can neither relay
   * nor apply diverges it from the rest of the network just as surely. */
  {
    struct Client *blocker = rename_legacy_blocker();
    if (blocker) {
      send_fail(sptr, "RENAME", "CANNOT_RENAME", oldname,
                "A linked server does not support channel rename");
      return 0;
    }
  }

  /* Registered channels (+R): authority is the channel's founder/access list,
   * which lives in services, not here.  We must ask services.
   *
   * We used to ask services with
   *   AC <user_numeric> R <cookie> <channel> RENAME <newname>
   * and wait for an AC A/D reply.  That query is HARMFUL against the services
   * package that actually ships: its AC handler treats subcommand 'R' as an
   * account-stamp notification and reads our <cookie> as the stamp, then sets
   * FLAGS_STAMPED on the querying user unconditionally.  Because a stamped
   * user is skipped by later StampUser() calls, one RENAME attempt silently
   * discards that user's *legitimate* account stamp for the rest of their
   * session — a real side effect from a command the user only sees time out.
   * The 'R' subcommand letter was simply already taken; this is a protocol
   * collision on our side, not services mishandling a well-formed query.
   *
   * A disambiguating services build now exists: it requires argc >= 7 and
   * checks for the literal "RENAME" keyword before falling through to the
   * account-stamp path, so the two no longer collide.  FEAT_RENAME_SERVICES
   * records which deployments are running that build and may safely be
   * asked — it defaults OFF, so every deployment still running the old
   * services package keeps today's honest local refusal instead of
   * re-triggering the stamp-clobbering bug.
   *
   * DO NOT delete as dead code: find_services_server() and
   * pending_rename_add() above are used by the emit below, and
   * pending_rename_find/complete/deny are still called from m_account.c's
   * AC A/D reply path, with pending_rename_client_exit called from s_misc.c.
   */
  if (chptr->mode.mode & MODE_REGISTERED) {
    struct Client *services;
    struct PendingRename *pr;

    if (!feature_bool(FEAT_RENAME_SERVICES)) {
      send_fail(sptr, "RENAME", "CANNOT_RENAME", oldname,
                "Renaming a registered channel requires services support, "
                "which is unavailable");
      return 0;
    }

    if (!(services = find_services_server())) {
      send_fail(sptr, "RENAME", "TEMPORARILY_UNAVAILABLE", oldname,
                "Registration service is not available");
      return 0;
    }

    if (!(pr = pending_rename_add(sptr, chptr, newname, reason))) {
      send_fail(sptr, "RENAME", "TEMPORARILY_UNAVAILABLE", oldname,
                "Too many renames in progress");
      return 0;
    }

    sendcmdto_one(&me, CMD_ACCOUNT, services, "%C R %u %s RENAME %s",
                 sptr, pr->cookie, chptr->chname, newname);
    return 0;
  }

  /* Unregistered channel - proceed with rename immediately */

  /* Store old name before rename */
  ircd_strncpy(oldname_buf, chptr->chname, CHANNELLEN + 1);

  /* Perform the rename (updates chptr if reallocated) */
  rc = rename_channel(&chptr, newname);
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
  sendcmdto_serv_butone_v3(sptr, CMD_RENAME, cptr, "%s %s :%s",
                        oldname_buf, chptr->chname, reason);

  /* Legacy services links don't get RN via the v3-only broadcast above;
   * synth it directly so they can keep their channel state in sync. */
  rename_forward_legacy_services(sptr, NULL, oldname_buf, chptr->chname, reason);

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
  ircd_strncpy(oldname_buf, chptr->chname, CHANNELLEN + 1);

  /* Perform the rename (updates chptr if reallocated) */
  rc = rename_channel(&chptr, newname);
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
  sendcmdto_serv_butone_v3(sptr, CMD_RENAME, cptr, "%s %s :%s",
                        oldname_buf, chptr->chname, reason);

  /* Legacy services links don't get RN via the v3-only broadcast above;
   * synth it directly so they can keep their channel state in sync.
   * Skip the link this RENAME arrived on. */
  rename_forward_legacy_services(sptr, cptr, oldname_buf, chptr->chname, reason);

  return 0;
}
