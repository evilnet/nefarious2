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

/** Pending channel rename request.
 *
 * Deliberately holds NO struct Channel * across the AC round-trip: the
 * channel can be freed/reallocated (rename_channel() MyFree()s the old
 * node when the new name is longer than the old one — channel.c ~2123)
 * or destroyed outright (last member parts mid-flight) while this request
 * is waiting on services, up to RENAME_TIMEOUT seconds away.  Only the
 * name survives that wait; every consumer re-resolves via
 * FindChannel(oldname) at the point it actually needs the channel. */
struct PendingRename {
  struct Client *client;           /**< Client waiting for response */
  char oldname[CHANNELLEN + 1];    /**< Original channel name */
  char newname[CHANNELLEN + 1];    /**< Requested new name */
  char reason[TOPICLEN + 1];       /**< Rename reason */
  unsigned int cookie;             /**< Unique identifier for matching response */
  struct Timer timeout;            /**< Timeout timer */
  int timer_active;                /**< Whether the timer still owns this
                                         struct's lifetime -- see the
                                         free-once note on
                                         pending_rename_timeout_cb() */
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
static void send_rename_to_member(struct Client *sptr, struct Client *acptr,
                                  struct Channel *chptr, const char *oldname,
                                  const char *reason);

/* Relocation mode (evilnet/channel-relocate) -- implementation lives in the
 * "Relocation" section below; declared here because the pending-rename
 * completion path above it dispatches into relocation mode too. */
struct RelocateTombstone;
static int rename_is_consent(void);
static int relocate_execute(struct Client *sptr, struct Channel *chptr,
                            const char *oldname, const char *newname,
                            const char *reason);
static struct RelocateTombstone *relocate_tombstone_find(const char *name);

/** Wire marker distinguishing a relocation-mode RN from a classic one,
 * as the parameter immediately before the trailing reason:
 *
 *     classic:     RN <old> <new> :<reason>
 *     relocation:  RN <old> <new> C :<reason>
 *
 * NORMATIVE for every emitter (including X3): the trailing reason
 * parameter MUST be present -- emit ":" with an empty reason rather than
 * dropping it.  ms_rename() only honours the marker in the five-parameter
 * shape, because a four-parameter "RN <old> <new> :C" is a classic rename
 * whose reason happens to be the letter C and must not be mistaken for a
 * relocation.  Honouring a marker in the shorter shape would turn that
 * message into a partition on some servers and a force-move on others --
 * i.e. permanent membership divergence -- which is strictly worse than
 * losing the marker on a malformed emission. */
#define RELOCATE_MARKER "C"
/** RELOCATE_MARKER as a "%s %s %s:%s" splice.  EVERY emitter -- the v3
 * sendcmdto_serv_butone_v3() broadcasts as much as rename_forward_rcapable()
 * -- must use THIS, not bare RELOCATE_MARKER: the trailing space is what
 * separates the marker from the reason's leading colon.  Without it the
 * wire renders "RN #old #new C:reason", a four-parameter classic rename
 * whose reason is "C:reason", and every downstream server force-moves a
 * membership this server left behind. */
#define RELOCATE_MARKER_SP RELOCATE_MARKER " "

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

/** Channel-oplevel gate for rename authorization.  When a channel has
 * oplevels active (MODE_APASS / +A can only be set with FEAT_OPLEVELS),
 * ownership is founder-based: only the founder at oplevel 0 may rename it,
 * not an arbitrary chanop opped by the founder.  Without oplevels there is
 * no founder notion and any chanop may rename (traditional behaviour).
 * @return non-zero if \a member is permitted to rename \a chptr.
 */
static int rename_oplevel_ok(struct Channel *chptr, struct Membership *member)
{
  /* Apass presence is the mode.apass string being non-empty, not a
   * mode.mode bit (the codebase tests it this way everywhere, e.g.
   * channel.c:390/1055/1327).  Founder == oplevel 0 / channel manager
   * (m_join.c:280 assigns the manager 0 and other ops 1 on apass chans);
   * accept either so post-burst oplevel drift can't lock the founder out. */
  return !chptr->mode.apass[0]
         || (member && (OpLevel(member) == 0 || IsChannelManager(member)));
}

/** RENAME is only sound when every server can apply RN.  Legacy servers
 * neither relay nor apply unknown tokens (design doc section 2), so refuse
 * while any non-v3-aware, non-rename-capable server is linked.  A server
 * that advertises 'r' (FLAG_RENAME_CAPABLE, e.g. X3) is not a blocker even
 * though it isn't IRCv3-aware: it gets the targeted forward in
 * rename_forward_rcapable() below instead of the v3 broadcast.  Plain
 * legacy servers with neither flag legitimately block — there is no path
 * to tell them about the rename at all.
 * @return First blocking legacy server found, or NULL if none.
 */
static struct Client *rename_legacy_blocker(void)
{
  struct Client *acptr;

  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr))
    if (IsServer(acptr) && !IsIRCv3Aware(acptr) && !IsRenameCapable(acptr))
      return acptr;

  return NULL;
}

/** Forward a RENAME to directly-connected rename-capable-but-non-v3-aware
 * links (peers advertising 'r' / FLAG_RENAME_CAPABLE, e.g. X3).
 * sendcmdto_serv_butone_v3() intentionally skips every non-IRCv3-aware
 * peer, but an r-capable peer still needs to learn about the renamed
 * channel to keep its own channel/registration state in sync, even though
 * it can't speak the RN P10 token as a v3 S2S relay hop.
 * @param[in] sptr Client to use as the message source.
 * @param[in] skip Downlink to skip (the direction the message came from),
 *                 or NULL if the rename originated locally.
 * @param[in] oldname Old channel name.
 * @param[in] newname New channel name.
 * @param[in] marker Extra parameter to splice in before the trailing
 *                   reason, ALREADY trailing-space terminated -- "" for a
 *                   classic rename (the emission is then byte-identical to
 *                   the historical "%s %s :%s" shape) or "C " for a
 *                   relocation-mode rename.
 * @param[in] reason Rename reason (may be empty string).
 */
static void rename_forward_rcapable(struct Client *sptr, struct Client *skip,
                                     const char *oldname, const char *newname,
                                     const char *marker, const char *reason)
{
  struct DLink *dlp;

  for (dlp = cli_serv(&me)->down; dlp; dlp = dlp->next) {
    struct Client *from = sptr;

    if (dlp->value.cptr == skip)
      continue;
    if (!(!IsIRCv3Aware(dlp->value.cptr) && IsRenameCapable(dlp->value.cptr)))
      continue;

    /* Alias source rewrite — a rename-capable non-v3 peer (e.g. X3) was
     * never told about the alias via BX C, so it's an unknown source to
     * it; emit from the primary instead.  sendcmdto_serv_butone_v3() (the
     * v3 broadcast one line up in every caller) already does this
     * rewrite internally, but
     * sendcmdto_one() does not, so it has to happen here.  Mirrors the
     * rewrite in ircd_relay.c (~999-1004): keep the alias numeric only
     * when the primary's own wire direction IS this destination, since
     * sending toward the primary's own uplink as the primary would be a
     * fake direction.  sptr can be a server in principle (defensive only
     * — RENAME's source is always a user in practice), so gate on
     * IsUser() before the client-only alias macros. */
    if (IsUser(sptr) && IsBouncerAlias(sptr) && cli_alias_primary(sptr)) {
      from = cli_alias_primary(sptr);
      if (!MyUser(from) && cli_from(from) == dlp->value.cptr)
        from = sptr;
    }

    sendcmdto_one(from, CMD_RENAME, dlp->value.cptr, "%s %s %s:%s",
                  oldname, newname, marker, reason);
  }
}

/** Add a pending rename request.
 * @param[in] client Client requesting the rename.
 * @param[in] channel Channel to be renamed; only its current name is
 *                     snapshotted here — the pointer itself is not kept
 *                     (see the PendingRename struct comment).
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
  pr->timer_active = 1;

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

/** Find a pending rename by the channel's original name, case-insensitive.
 * Used at request time to refuse a second concurrent RENAME on a channel
 * that already has one in flight — without this, two pendings for the
 * same channel can both complete, and the first completion's
 * rename_channel() can free the node the second one is about to touch.
 * @param[in] name Channel name to search for.
 * @return Pointer to pending request, or NULL if not found.
 */
static struct PendingRename *pending_rename_find_by_name(const char *name)
{
  struct PendingRename *pr;

  for (pr = pending_renames; pr; pr = pr->next) {
    if (0 == ircd_strcmp(pr->oldname, name))
      return pr;
  }

  return NULL;
}

/** Unlink a pending rename from the global list.  Does NOT touch the
 * timer and does NOT free pr -- see the free-once note on
 * pending_rename_timeout_cb() for why the actual MyFree() is deferred to
 * that function's ET_DESTROY case.
 * @param[in] pr Pending request to unlink.
 */
static void pending_rename_unlink(struct PendingRename *pr)
{
  struct PendingRename **pp;

  for (pp = &pending_renames; *pp; pp = &(*pp)->next) {
    if (*pp == pr) {
      *pp = pr->next;
      pending_rename_count--;
      break;
    }
  }
}

/** Remove a pending rename request: unlink it and cancel its timer.
 *
 * pr's struct Timer is embedded in pr itself, so pr cannot be freed until
 * the timer generator is actually torn down.  timer_del() on a timer
 * that is NOT mid-dispatch synchronously fires ET_DESTROY right here
 * (see ircd_events.c timer_del()/event_generate()), and
 * pending_rename_timeout_cb()'s ET_DESTROY case does the MyFree() -- so
 * by the time this call returns, pr is already gone.  This function is
 * only ever called from contexts that are NOT inside the timer callback
 * (pending_rename_complete(), pending_rename_deny()), so timer_active is
 * always true here; the check is defensive.
 * @param[in] pr Pending request to remove.
 */
static void pending_rename_remove(struct PendingRename *pr)
{
  if (!pr)
    return;

  log_write(LS_DEBUG, L_DEBUG, 0,
            "pending_rename_remove: cookie=%u", pr->cookie);

  pending_rename_unlink(pr);

  if (pr->timer_active) {
    pr->timer_active = 0;
    timer_del(&pr->timeout); /* -> ET_DESTROY -> MyFree(pr), synchronously */
  }
}

/** Complete a pending rename (called when services approves).
 * @param[in] pr Pending request to complete.
 */
void pending_rename_complete(struct PendingRename *pr)
{
  struct Channel *chptr;
  int rc;

  if (!pr || !pr->client)
    return;

  log_write(LS_DEBUG, L_DEBUG, 0,
            "pending_rename_complete: cookie=%u oldname=%s newname=%s",
            pr->cookie, pr->oldname, pr->newname);

  /* Re-check for a legacy blocker: a non-v3-aware, non-service server can
   * link during the up-to-RENAME_TIMEOUT-second AC round-trip, after
   * m_rename's request-time check already passed.  Nothing has been
   * applied anywhere on the network yet at this point (the rename below
   * is the first mutation), so deny rather than complete — that's the
   * conservative move that keeps every server consistent. */
  if (rename_legacy_blocker()) {
    pending_rename_deny(pr, "A linked server does not support channel rename");
    return;
  }

  /* Re-resolve the channel by name instead of trusting a cached pointer:
   * across the round-trip the channel may have been destroyed (last
   * member parted mid-flight) or, absent the request-time dedup, freed
   * and reallocated by a same-channel completion that ran first
   * (rename_channel() MyFree()s the old node when the new name is
   * longer).  A miss here — channel gone, or since renamed out from
   * under this name by some other path — is treated as a deny, not a
   * silent drop, so the requester gets a FAIL instead of nothing. */
  if (!(chptr = FindChannel(pr->oldname))) {
    log_write(LS_DEBUG, L_WARNING, 0,
              "pending_rename_complete: channel %s no longer exists",
              pr->oldname);
    pending_rename_deny(pr, "Channel no longer exists");
    return;
  }

  /* A name match alone isn't enough: with FEAT_ZANNELS off, an empty
   * registered channel destructs synchronously when its last member
   * parts, and a DIFFERENT user can recreate that exact name before this
   * completion runs — FindChannel() above would then resolve to that
   * unrelated fresh channel (mode 0, no +R, pr->client not even a
   * member).  Re-validate the same authorization m_rename required at
   * request time — requester still a chanop member, channel still
   * MODE_REGISTERED — before letting the approved rename land on it. */
  {
    struct Membership *member = find_channel_member(pr->client, chptr);
    if (!member || !IsChanOp(member) || !rename_oplevel_ok(chptr, member)
        || !(chptr->mode.mode & MODE_REGISTERED)) {
      log_write(LS_DEBUG, L_WARNING, 0,
                "pending_rename_complete: channel %s changed identity while "
                "awaiting services", pr->oldname);
      pending_rename_deny(pr, "Channel changed while awaiting services");
      return;
    }
  }

  /* The channel can also have BECOME a tombstone during the round-trip
   * (some other channel relocated onto this name).  Same refusal as the
   * request-time check in m_rename(). */
  if (rename_is_consent() && relocate_tombstone_find(pr->oldname)) {
    pending_rename_deny(pr, "Channel is a relocation tombstone");
    return;
  }

  /* Relocation mode: partition instead of force-moving, and mark the RN.
   * chptr keeps its old name here, so the propagated new name comes from
   * pr->newname rather than chptr->chname. */
  if (rename_is_consent()) {
    if (relocate_execute(pr->client, chptr, pr->oldname, pr->newname,
                         pr->reason) != 0) {
      send_fail(pr->client, "RENAME", "CANNOT_RENAME", pr->oldname,
                "Rename failed");
      pending_rename_remove(pr);
      return;
    }

    sendcmdto_serv_butone_v3(pr->client, CMD_RENAME, cli_from(pr->client),
                             "%s %s %s:%s", pr->oldname, pr->newname,
                             RELOCATE_MARKER_SP, pr->reason);
    rename_forward_rcapable(pr->client, NULL, pr->oldname, pr->newname,
                            RELOCATE_MARKER_SP, pr->reason);

    pending_rename_remove(pr);
    return;
  }

  /* Perform the rename (updates chptr if reallocated) */
  rc = rename_channel(&chptr, pr->newname);
  if (rc != 0) {
    send_fail(pr->client, "RENAME", "CANNOT_RENAME", pr->oldname,
              "Rename failed");
    pending_rename_remove(pr);
    return;
  }

  /* Send to local channel members */
  send_rename_to_members(pr->client, chptr, pr->oldname, pr->reason);

  /* Propagate to other servers */
  sendcmdto_serv_butone_v3(pr->client, CMD_RENAME, cli_from(pr->client),
                        "%s %s :%s", pr->oldname, chptr->chname,
                        pr->reason);

  /* Rename-capable non-v3 links (X3) don't get RN via the v3-only
   * broadcast above; synth it directly so they can keep their channel
   * state in sync. */
  rename_forward_rcapable(pr->client, NULL, pr->oldname,
                          chptr->chname, "", pr->reason);

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
 *
 * pr's struct Timer is embedded in pr (see the PendingRename struct
 * comment), so pr must NOT be freed from the ET_EXPIRE branch below:
 * timer_run() (ircd_events.c) sets GEN_MARKED on the timer generator
 * before calling this callback and keeps touching that generator after
 * we return (clearing GEN_MARKED, then generating ET_DESTROY) -- freeing
 * pr here would make all of that a use-after-free.  timer_del() called
 * from within an ET_EXPIRE dispatch hits its own "timer is being used"
 * guard and does nothing, so it can't be used to neutralize this either.
 *
 * Instead: ET_EXPIRE does the user-facing work and unlinks pr from the
 * list (so it can't be found or double-completed), but leaves the
 * actual free to the ET_DESTROY case, which fires either automatically
 * right after ET_EXPIRE returns (the timeout path) or synchronously
 * from pending_rename_remove()'s timer_del() call (the complete/deny/
 * client-exit paths).  MyFree(pr) happens in exactly one place -- the
 * ET_DESTROY case below -- so there is exactly one free per pending
 * rename no matter which of the five teardown paths (complete-success,
 * complete-failure, deny, timeout, client-exit) retires it.
 * @param[in] ev Timer event.
 */
static void pending_rename_timeout_cb(struct Event *ev)
{
  struct PendingRename *pr;

  assert(0 != ev_timer(ev));
  assert(0 != t_data(ev_timer(ev)));

  pr = (struct PendingRename *)t_data(ev_timer(ev));

  switch (ev_type(ev)) {
  case ET_EXPIRE:
    log_write(LS_DEBUG, L_DEBUG, 0,
              "pending_rename_timeout: cookie=%u channel=%s",
              pr->cookie, pr->oldname);

    send_fail(pr->client, "RENAME", "CANNOT_RENAME", pr->oldname,
              "Services response timeout");

    /* Do NOT call timer_del() (a no-op while mid-dispatch, see above)
     * and do NOT MyFree(pr) here -- just make pr unreachable until
     * ET_DESTROY frees it below. */
    pending_rename_unlink(pr);
    pr->timer_active = 0;
    break;

  case ET_DESTROY:
    /* The only place pr is freed -- see the function comment above. */
    MyFree(pr);
    break;

  default:
    break;
  }
}

/** Cleanup pending renames for a disconnecting client.
 * @param[in] cptr Client that is disconnecting.
 */
void pending_rename_client_exit(struct Client *cptr)
{
  struct PendingRename *pr, *next;

  /* Cache pr->next before unlinking/triggering the free below -- pr may
   * already be gone (freed via the synchronous ET_DESTROY that
   * timer_del() triggers) by the time a naive iteration would otherwise
   * need to read pr->next. */
  for (pr = pending_renames; pr; pr = next) {
    next = pr->next;

    if (pr->client == cptr) {
      log_write(LS_DEBUG, L_DEBUG, 0,
                "pending_rename_client_exit: removed cookie=%u for %C",
                pr->cookie, cptr);

      pending_rename_unlink(pr);

      if (pr->timer_active) {
        pr->timer_active = 0;
        timer_del(&pr->timeout); /* -> ET_DESTROY -> MyFree(pr) */
      }
    }
  }
}

/* ========== End Pending Rename Infrastructure ========== */

/** Deliver the rename notification for ONE local member: a RENAME message
 * when that connection negotiated draft/channel-rename, the legacy
 * PART/JOIN(+TOPIC/NAMES) pair otherwise.
 *
 * Split out of send_rename_to_members() so relocation mode can drive it
 * per-member: under FEAT_RENAME_CONSENT only the movers (issuer and +F
 * users) may be told "your membership now points at the new name", and
 * they are no longer walkable as "every member of chptr" -- see
 * relocate_execute().  The emissions below are unchanged from the
 * historical inline body.
 *
 * @param[in] sptr Client that initiated the rename (message source).
 * @param[in] acptr Local member to notify.  Caller guarantees MyUser().
 * @param[in] chptr Channel the member is now on (i.e. carries the NEW name).
 * @param[in] oldname The old channel name.
 * @param[in] reason Reason for rename (may be empty string or NULL).
 */
static void send_rename_to_member(struct Client *sptr, struct Client *acptr,
                                  struct Channel *chptr, const char *oldname,
                                  const char *reason)
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

    send_rename_to_member(sptr, acptr, chptr, oldname, reason);
  }
}

/* ========== Relocation (evilnet/channel-relocate) ========== */

/** Is this server running relocation mode?
 *
 * Relocation mode replaces the rename's unconditional member move with
 * consent: only the issuer and users carrying umode +F are moved, everyone
 * else stays behind in a tombstoned old channel and is invited to follow.
 * See docs/specs/channel-relocate.md.
 *
 * This gates the ORIGIN decision only.  A server that receives an RN
 * already carrying the C marker applies relocation semantics regardless of
 * its own setting -- the alternative is for one server to force-move a
 * member that its neighbours left behind, which is unrecoverable membership
 * divergence.  (The spec forbids mixing the two modes on one network; this
 * is the belt-and-braces for a misconfigured link.)
 * @return non-zero when relocation mode is active.
 */
static int rename_is_consent(void)
{
  return feature_bool(FEAT_RENAME_CONSENT);
}

/** Per-member status snapshot for grace-period rejoins.  Task 4 defines it;
 * the tombstone only carries the list head so its layout is fixed now. */
struct RelocateSnap;

/** A tombstoned old channel, alive for FEAT_RELOCATE_GRACE seconds after a
 * relocation-mode rename.
 *
 * Like struct PendingRename above, this deliberately does NOT trust its
 * struct Channel * across time: the tombstone carries EXMODE_PERSIST so the
 * ordinary empty-channel destruct can't free it, but services DESTRUCT
 * (m_destruct.c) still can.  @a oldname is the authority and @a oldchan is
 * a cache -- resolve through relocate_tombstone_channel(), never by reading
 * the field directly. */
struct RelocateTombstone {
  struct RelocateTombstone *next;   /**< Linked list */
  struct Channel *oldchan;          /**< CACHE ONLY -- see struct comment */
  char oldname[CHANNELLEN + 1];     /**< The tombstone's own (stable) name */
  char newname[CHANNELLEN + 1];     /**< Redirect target, chain-flattened */
  time_t expires;                   /**< When the grace period elapses */
  struct Timer timer;               /**< Embedded -- freed only on ET_DESTROY,
                                         mirroring the PendingRename timer
                                         discipline documented above */
  int timer_active;                 /**< Whether the timer still owns this
                                         struct's lifetime */
  struct RelocateSnap *snaps;       /**< Task 4: member status snapshots */
};

/** Global tombstone list. */
static struct RelocateTombstone *relocate_tombstones = NULL;

static void relocate_tombstone_expire_cb(struct Event *ev);

/** Find a live tombstone by its (old) channel name, case-insensitively.
 * @param[in] name Channel name to look up.
 * @return Tombstone, or NULL if @a name is not a tombstone.
 */
static struct RelocateTombstone *relocate_tombstone_find(const char *name)
{
  struct RelocateTombstone *ts;

  if (EmptyString(name))
    return NULL;

  for (ts = relocate_tombstones; ts; ts = ts->next)
    if (0 == ircd_strcmp(ts->oldname, name))
      return ts;

  return NULL;
}

/** Resolve a tombstone's channel, refreshing the cached pointer.
 *
 * A name lookup alone is NOT an identity check.  A tombstone can die early
 * (services DESTRUCT, a manual MODE -z followed by the last member
 * parting) and an unrelated user can then create a brand-new channel of
 * the same name well inside the grace period -- FindChannel() would hand
 * that fresh channel back and a chain-flattening retarget would stamp
 * +L onto somebody's live channel.  So the result is only accepted when it
 * still carries the marks this engine put on it: the internal persist bit,
 * the redirect bit, and a redirect string still pointing where this
 * tombstone points.  Anything else is a different channel wearing the same
 * name.
 * @param[in] ts Tombstone to resolve.
 * @return The tombstone channel, or NULL if it is gone or has been
 *         replaced by an unrelated channel of the same name.
 */
static struct Channel *relocate_tombstone_channel(struct RelocateTombstone *ts)
{
  struct Channel *chptr;

  if (!ts)
    return NULL;

  ts->oldchan = NULL;

  if (!(chptr = FindChannel(ts->oldname)))
    return NULL;

  if (!(chptr->mode.exmode & EXMODE_PERSIST)
      || !(chptr->mode.mode & MODE_REDIRECT)
      || 0 != ircd_strcmp(chptr->mode.redir, ts->newname))
    return NULL;

  ts->oldchan = chptr;
  return chptr;
}

/** Unlink a tombstone from the global list.  Does NOT touch the timer and
 * does NOT free @a ts -- the free happens exactly once, in the ET_DESTROY
 * case of relocate_tombstone_expire_cb().
 * @param[in] ts Tombstone to unlink.
 */
static void relocate_tombstone_unlink(struct RelocateTombstone *ts)
{
  struct RelocateTombstone **pp;

  for (pp = &relocate_tombstones; *pp; pp = &(*pp)->next) {
    if (*pp == ts) {
      *pp = ts->next;
      break;
    }
  }
}

/** Retire a tombstone from OUTSIDE the timer dispatch: unlink it and cancel
 * its grace timer.
 *
 * Mirrors pending_rename_remove() exactly.  ts's struct Timer is embedded in
 * ts, and timer_del() on a timer that is not mid-dispatch synchronously
 * fires ET_DESTROY (ircd_events.c timer_del() -> event_generate()), whose
 * case in relocate_tombstone_expire_cb() does the MyFree() -- so ts is
 * already GONE by the time this returns and must not be touched afterwards.
 *
 * Never call this from inside relocate_tombstone_expire_cb(): timer_del()
 * returns early on a GEN_MARKED (in-dispatch) timer, so the free would not
 * happen here and the caller would be left believing it had cancelled.
 * @param[in] ts Tombstone to retire.
 */
static void relocate_tombstone_remove(struct RelocateTombstone *ts)
{
  if (!ts)
    return;

  relocate_tombstone_unlink(ts);

  if (ts->timer_active) {
    ts->timer_active = 0;
    timer_del(&ts->timer); /* -> ET_DESTROY -> MyFree(ts), synchronously */
  }
}

/** Strip the marks relocate_execute() put on a tombstone channel.
 *
 * All three go together and none is optional:
 *  - EXMODE_PERSIST is the only thing keeping sub1_from_channel() from
 *    collecting the channel once it is empty (channel.c:370).  Left set,
 *    the dissolved tombstone never destructs.
 *  - MODE_REDIRECT / mode.redir keep forwarding JOINs of this name to a
 *    channel it no longer has any relationship with (m_join.c:160).
 * relocate_tombstone_channel()'s identity check keys on all three as well,
 * so leaving any one of them set would also keep a dissolved channel
 * validating as somebody's live tombstone.
 * @param[in] chptr Channel to strip.
 */
static void relocate_tombstone_clear_marks(struct Channel *chptr)
{
  chptr->mode.mode &= ~MODE_REDIRECT;
  chptr->mode.redir[0] = '\0';
  chptr->mode.exmode &= ~EXMODE_PERSIST;
}

/** Grace-period expiry sweep: PART every remaining member of a tombstone and
 * dissolve the channel (spec, "The tombstone": at grace expiry the server
 * removes each remaining member with a server-generated PART).
 *
 * NOTHING here goes to servers.  Every server on the network processed the
 * same RN C marker and registered its own tombstone with its own timer, so
 * every server runs this same sweep over its own copy of the membership;
 * broadcasting the removals would double them.  The removals are therefore
 * local bookkeeping plus local-client emission only, exactly like
 * relocate_execute()'s partition.  The cost is that the sweeps are not
 * simultaneous: the timers were armed when each server processed the RN, so
 * they fire within the link latency of each other (seconds).  For those few
 * seconds a member already swept on server A is still listed in the
 * tombstone on server B.  That is accepted -- the channel is empty and
 * dissolving on both, and the alternative (a network-wide PART burst per
 * member, from every server) is far worse.
 *
 * @param[in] ts Tombstone whose grace period has elapsed.  Already unlinked
 *               from the global list by the caller.
 */
static void relocate_tombstone_sweep(struct RelocateTombstone *ts)
{
  struct Channel *chptr;
  struct Membership *member;
  unsigned int nswept = 0;

  /* The record can outlive its channel's identity: services DESTRUCT, an
   * operator MODE -z, or a chanop stripping +L all break the tombstone
   * without going through relocate_tombstone_channel_gone(), and an
   * unrelated channel can then be created on the same name well inside the
   * grace period.  relocate_tombstone_channel() rejects all of those.  The
   * caller has ALREADY unlinked ts and disowned the timer, so returning
   * here cancels the record cleanly rather than leaving an unresolvable
   * record with a fired timer behind it. */
  if (!(chptr = relocate_tombstone_channel(ts))) {
    log_write(LS_DEBUG, L_DEBUG, 0,
              "relocate_tombstone_sweep: %s -> %s no longer resolves to a "
              "tombstone; record cancelled", ts->oldname, ts->newname);
    return;
  }

  /* Head-walk with chptr->members re-read every iteration, rather than a
   * next_member cursor: remove_user_from_channel() calls
   * bounce_sync_alias_part(), which unlinks the member's alias shadows from
   * this same list, so even a next_member captured before the call can be
   * freed by it (the hazard relocate_execute() solves with a snapshot
   * array -- here the list is being emptied outright, so re-reading the
   * head is simpler and needs no allocation).  Progress is guaranteed
   * because find_member_link() -- unlike find_channel_member()
   * (channel.c:496) -- returns zombie memberships too, so the selected
   * member is always actually removed. */
  while ((member = chptr->members)) {
    struct Client *user;
    unsigned int flags;

    /* Alias shadows follow their primary out via bounce_sync_alias_part();
     * parting one directly would drop a bouncer connection out of a channel
     * its primary is still in. */
    while (member && IsMemberAlias(member))
      member = member->next_member;
    if (!member)
      break; /* only orphaned alias shadows left -- see the tail below */

    user = member->user;
    flags = member->status;

    /* Same suppression gate joinbuf_flush() applies before announcing a
     * PART to a channel (channel.c:5394) and the same one
     * relocate_execute()'s stayer loop applies: a member the channel never
     * saw JOIN must not be announced leaving.  Without it the sweep reveals
     * a +D (delayed-join) member to everyone else as a parting shot --
     * exactly the involuntary exposure this extension exists to close.
     * They are still REMOVED, and if they are local they still get their
     * own PART, addressed to them alone: joinbuf_flush()'s self-only else
     * branch, mirrored.
     *
     * For everyone else the channel walk IS the self-echo -- it does not
     * exclude the source (one == NULL) and does not skip alias members
     * (send.c:2377), so a local member and each of their local bouncer
     * connections all see the PART under the shared nick. */
    if (!(flags & (CHFL_ZOMBIE | CHFL_DELAYED)))
      sendcmdto_channel_butserv_butone(user, CMD_PART, chptr, NULL, 0,
                                       "%H :Channel has moved to %s",
                                       chptr, ts->newname);
    else if (MyUser(user))
      sendcmdto_one(user, CMD_PART, user, "%H :Channel has moved to %s",
                    chptr, ts->newname);

    remove_user_from_channel(user, chptr);
    nswept++;
  }

  /* Order is load-bearing in both directions.  The removals above had to
   * run with EXMODE_PERSIST still set, or the last one would have
   * destructed chptr and every line from here on would be a use-after-free.
   * But that also means each removal's sub1_from_channel() took the persist
   * early return (channel.c:370) and so never scheduled the ordinary
   * empty-channel collection -- and nothing re-enters that path by itself.
   * So the dissolve clears the marks and then runs it once, by hand. */
  relocate_tombstone_clear_marks(chptr);

  ts->oldchan = NULL; /* about to be freed or zannel'd; never read again */

  if (!chptr->members) {
    /* The normal empty-channel path, entered exactly as an ordinary last
     * PART would enter it: apass is already cleared (relocate_execute()
     * strips it), so sub1_from_channel() resets the modes and then either
     * destruct_channel()s immediately (!FEAT_OPLEVELS, or !FEAT_ZANNELS) or
     * schedules the destruct event (FEAT_ZANNELS).  Either way chptr may be
     * freed by this call -- do not touch it afterwards. */
    sub1_from_channel(chptr);
  }
  /* else: alias shadows whose primaries are already gone are still holding
   * chptr->aliases > 0, so sub1_from_channel() would refuse anyway.  Assert
   * nothing: the marks are cleared, so the channel is now an ordinary empty
   * channel and the ordinary path collects it when the last shadow goes. */

  log_write(LS_DEBUG, L_DEBUG, 0,
            "relocate_tombstone_sweep: %s -> %s dissolved (%u member%s swept)",
            ts->oldname, ts->newname, nswept, (nswept == 1) ? "" : "s");
}

/** A struct Channel is about to be freed: retire any tombstone record that
 * refers to it.
 *
 * EXMODE_PERSIST defends a tombstone against the ordinary empty-channel
 * collection, but not against services DESTRUCT (m_destruct.c:202) or an
 * operator MODE -z followed by the last member parting -- either can free
 * the channel with most of the grace period still on the clock.  Left
 * alone, the record would keep a live timer and a dangling cached pointer
 * pointing at a name any user can re-create inside the grace period.
 * relocate_tombstone_channel()'s identity check already stops that becoming
 * a wrong-channel sweep, but the record and its timer are still garbage,
 * and an unresolvable record that fires is a strictly worse failure than
 * one that was cancelled at the moment it became unresolvable.  So retire
 * them here, at the one place a channel actually dies.
 * @param[in] chptr Channel being destroyed.
 */
void relocate_tombstone_channel_gone(struct Channel *chptr)
{
  struct RelocateTombstone *ts, *next;

  if (!chptr)
    return;

  /* Cache ->next before the removal: relocate_tombstone_remove() frees ts
   * synchronously, the same reason pending_rename_client_exit() caches it. */
  for (ts = relocate_tombstones; ts; ts = next) {
    next = ts->next;

    /* Match on the NAME only, never on ts->oldchan.  Channel names are
     * unique in the hash, so while the tombstone channel is alive a name
     * match here is exact.  The cached pointer, by contrast, can dangle --
     * rename_channel() MyFree()s the old node without coming through here
     * (channel.c:2131) -- and a later channel allocated at that same
     * address would then falsely match and retire a healthy record.  A
     * record left holding a dangling cache is harmless: nothing ever
     * dereferences it (relocate_tombstone_channel() re-resolves by name and
     * NULLs the cache), and the sweep cancels it as unresolvable. */
    if (0 != ircd_strcmp(ts->oldname, chptr->chname))
      continue;

    log_write(LS_DEBUG, L_DEBUG, 0,
              "relocate_tombstone_channel_gone: %s -> %s retired early "
              "(channel destroyed with %Tu seconds of grace left)",
              ts->oldname, ts->newname,
              (ts->expires > CurrentTime) ? (ts->expires - CurrentTime) : 0);

    relocate_tombstone_remove(ts); /* ts is freed by this call */
  }
}

/** Timer callback for a tombstone's grace period.
 *
 * ts's struct Timer is embedded in ts, so the same free-once discipline as
 * pending_rename_timeout_cb() applies verbatim: timer_run() keeps touching
 * the generator after ET_EXPIRE returns, so ET_EXPIRE may only make ts
 * unreachable (unlink + clear timer_active) and ET_DESTROY -- which fires
 * automatically right after ET_EXPIRE, or synchronously from a
 * relocate_tombstone_remove() timer_del() -- is the single place ts is
 * freed.
 * @param[in] ev Timer event.
 */
static void relocate_tombstone_expire_cb(struct Event *ev)
{
  struct RelocateTombstone *ts;

  assert(0 != ev_timer(ev));
  assert(0 != t_data(ev_timer(ev)));

  ts = (struct RelocateTombstone *)t_data(ev_timer(ev));

  switch (ev_type(ev)) {
  case ET_EXPIRE:
    /* Unlink and disown the timer BEFORE the sweep, not after.  The sweep
     * ends in destruct_channel(), which calls
     * relocate_tombstone_channel_gone(), which walks this very list -- with
     * ts still on it that hook would match our own record and call
     * relocate_tombstone_remove() on a timer that is mid-dispatch, where
     * timer_del() returns early (GEN_MARKED) without the ET_DESTROY that is
     * supposed to free it.  Unlinking first makes the record unfindable;
     * ts itself stays valid because only ET_DESTROY, below, frees it.
     *
     * Do NOT call timer_del() here for the same reason. */
    relocate_tombstone_unlink(ts);
    ts->timer_active = 0;

    relocate_tombstone_sweep(ts);
    break;

  case ET_DESTROY:
    /* The only place ts is freed -- see the function comment above. */
    MyFree(ts);
    break;

  default:
    break;
  }
}

/** Register a tombstone for @a chptr and arm its grace timer.
 * @param[in] chptr Channel being tombstoned (keeps its own name).
 * @param[in] newname Redirect target.
 * @return The new tombstone, or NULL on allocation failure.
 */
static struct RelocateTombstone *
relocate_tombstone_add(struct Channel *chptr, const char *newname)
{
  struct RelocateTombstone *ts;

  /* Re-tombstoning a channel that is already one: the origin server
   * refuses it (see m_rename()), so this only happens on a diverged link
   * whose RN C we are obliged to follow.  Repoint the existing record
   * rather than stacking a second one -- two records for one name means
   * two grace timers, and the second ET_EXPIRE would sweep a channel the
   * first one already dissolved.  The original grace clock is kept: the
   * channel has been dying since the first relocation. */
  if ((ts = relocate_tombstone_find(chptr->chname))) {
    ircd_strncpy(ts->newname, newname, sizeof(ts->newname));
    ts->oldchan = chptr;
    return ts;
  }

  ts = (struct RelocateTombstone *)MyMalloc(sizeof(struct RelocateTombstone));
  if (!ts)
    return NULL;

  memset(ts, 0, sizeof(*ts));
  ts->oldchan = chptr;
  ircd_strncpy(ts->oldname, chptr->chname, sizeof(ts->oldname));
  ircd_strncpy(ts->newname, newname, sizeof(ts->newname));
  ts->expires = CurrentTime + feature_int(FEAT_RELOCATE_GRACE);

  ts->next = relocate_tombstones;
  relocate_tombstones = ts;

  timer_add(timer_init(&ts->timer), relocate_tombstone_expire_cb, (void *)ts,
            TT_ABSOLUTE, ts->expires);
  ts->timer_active = 1;

  log_write(LS_DEBUG, L_DEBUG, 0,
            "relocate_tombstone_add: %s -> %s expires=%Tu",
            ts->oldname, ts->newname, ts->expires);

  return ts;
}

/** Announce a tombstone's (possibly updated) redirect to its remaining
 * LOCAL members.
 *
 * Deliberately channel-only, never MODEBUF_DEST_SERVER: every server runs
 * relocate_execute() off the same RN C marker and announces to its own
 * local members, so a server leg here would be a duplicate MODE racing the
 * RN itself.  Source is &me (modebuf_flush_int() maps that to &his under
 * FEAT_HIS_MODEWHO, matching the spec's server-sourced presentation).
 * @param[in] chptr Tombstone channel; its mode.redir is already set.
 */
static void relocate_announce_redirect(struct Channel *chptr)
{
  struct ModeBuf mbuf;

  modebuf_init(&mbuf, &me, NULL, chptr, MODEBUF_DEST_CHANNEL);
  modebuf_mode_string(&mbuf, MODE_ADD | MODE_REDIRECT, chptr->mode.redir, 0);
  modebuf_flush(&mbuf);
}

/** Chain-flattening: a rename of a channel that is itself some tombstone's
 * redirect target repoints that tombstone at the newest name, so a join of
 * the oldest name never needs multi-hop resolution (spec, "Multiple
 * renames").
 * @param[in] oldtarget Name that just stopped being a valid target.
 * @param[in] newtarget Name it became.
 */
static void relocate_tombstone_retarget(const char *oldtarget,
                                        const char *newtarget)
{
  struct RelocateTombstone *ts;

  for (ts = relocate_tombstones; ts; ts = ts->next) {
    struct Channel *chptr;

    if (0 != ircd_strcmp(ts->newname, oldtarget))
      continue;

    /* Resolve BEFORE repointing the record: relocate_tombstone_channel()
     * authenticates the channel by comparing its live redirect against
     * ts->newname, which is still the PRIOR target at this instant. */
    chptr = relocate_tombstone_channel(ts);

    if (!chptr)
      continue;

    /* Repoint only AFTER the record has been validated.  A record whose
     * channel no longer resolves is dead; rewriting its target would make
     * its remaining lifetime claim a redirect that nothing on this server
     * implements, and would leave relocate_tombstone_channel() comparing
     * against a target the record never actually pointed at. */
    ircd_strncpy(ts->newname, newtarget, sizeof(ts->newname));

    ircd_strncpy(chptr->mode.redir, ts->newname, sizeof(chptr->mode.redir));
    chptr->mode.mode |= MODE_REDIRECT;
    relocate_announce_redirect(chptr);

    log_write(LS_DEBUG, L_DEBUG, 0,
              "relocate_tombstone_retarget: %s now redirects to %s",
              ts->oldname, ts->newname);
  }
}

/** Deep-copy a ban list onto the tail of @a dst.
 *
 * The tombstone keeps its own bans (it stays a real, joinable-by-redirect
 * channel for the whole grace period), so the lists are COPIED rather than
 * spliced across.  make_ban() re-derives everything set_ban_mask() can see
 * from the mask itself (BAN_EXTENDED/BAN_IPMASK, address, addrbits,
 * nu_len, extban); only the setter, timestamp and the exception marker have
 * to be carried over by hand.  Transient parse-time bits (BAN_ADD/BAN_DEL/
 * BAN_OVERLAPPED/BAN_BURSTED) are intentionally NOT copied.
 * @param[in,out] dst Head pointer of the destination list (must be empty).
 * @param[in] src Source list.
 */
static void relocate_copy_bans(struct Ban **dst, struct Ban *src)
{
  struct Ban *b;
  struct Ban **tail = dst;

  for (b = src; b; b = b->next) {
    struct Ban *nb = make_ban(b->banstr);

    if (!nb)
      return;

    nb->when = b->when;
    nb->flags |= (b->flags & BAN_EXCEPTION);
    ircd_strncpy(nb->who, b->who, sizeof(nb->who));
    nb->next = NULL;

    *tail = nb;
    tail = &nb->next;
  }
}

/** Tell a mover's LOCAL bouncer-alias connections that their view of the
 * old channel is over.
 *
 * A classic rename notified alias connections for free: send_rename_to_
 * members() walks chptr->members, which includes the CHFL_ALIAS shadow
 * memberships, and a local alias is MyUser().  Relocation cannot reuse
 * that walk, and the alias plumbing is asymmetric -- add_user_to_channel(
 * newchan, primary) -> bounce_sync_alias_join() DOES emit a JOIN echo
 * (plus TOPIC/NAMES) to each local alias connection, but
 * remove_user_from_channel(primary, chptr) -> bounce_sync_alias_part()
 * removes the alias membership SILENTLY.  Left alone, connection 2 of a
 * bouncer user is told it joined the new channel and never told it left
 * the old one, so it believes it is in both forever.
 *
 * Of the two coherent repairs, this one -- part the alias's view of the
 * old channel and let bounce_sync_alias_join()'s existing JOIN echo stand
 * -- is chosen over replaying send_rename_to_member() for each alias.
 * Replaying it would emit a SECOND JOIN #new (and a second NAMES burst)
 * on top of the sync echo for a no-cap alias, and for a cap-holding alias
 * it would emit a RENAME asserting a membership move the connection has
 * already been told about as a JOIN -- both leave the connection
 * describing itself as in the new channel twice.  The cost is that an
 * alias connection holding draft/channel-rename gets the legacy PART/JOIN
 * presentation rather than a RENAME; that is a presentation downgrade on
 * a secondary connection, not a state divergence.
 *
 * MUST be called BEFORE add_user_to_channel(newchan, primary): that call
 * is what emits the JOIN echo, and PART-after-JOIN would render out of
 * order.  Read-only with respect to the membership list.
 * @param[in] primary The moving (non-alias) client.
 * @param[in] chptr The old channel, still holding the alias memberships.
 * @param[in] oldname The old channel name.
 * @param[in] newname The new channel name.
 * @param[in] reason Rename reason (may be empty string).
 */
static void relocate_part_local_aliases(struct Client *primary,
                                        struct Channel *chptr,
                                        const char *oldname,
                                        const char *newname,
                                        const char *reason)
{
  struct Membership *member;

  for (member = chptr->members; member; member = member->next_member) {
    struct Client *alias = member->user;

    if (!IsMemberAlias(member) || !MyConnect(alias))
      continue;
    if (cli_alias_primary(alias) != primary)
      continue;

    /* Same wording as send_rename_to_member()'s legacy fallback PART, so
     * the pair an alias connection sees is indistinguishable from the one
     * a cap-less primary sees. */
    sendcmdto_one(alias, CMD_PART, alias, "%s :Channel renamed to %s%s%s",
                  oldname, newname,
                  (reason && *reason) ? ": " : "",
                  (reason && *reason) ? reason : "");
  }
}

/** One member scheduled to move, snapshotted before any membership
 * mutation happens (see relocate_execute()'s two-pass note). */
struct RelocateMover {
  struct Client *user;    /**< The moving client */
  unsigned int status;    /**< Status bits to carry to the new channel */
  int oplevel;            /**< Oplevel to carry to the new channel */
};

/** Execute a relocation-mode rename on THIS server.
 *
 * Creates @a newname, transfers channel state to it, moves only the
 * consenting members (the issuer and umode +F users), notifies the local
 * members of both classes, and turns @a chptr into a redirecting tombstone.
 * Every server on the network runs this same function off the RN C marker
 * with the same globally-known @a sptr, so the partition is identical
 * everywhere; consequently nothing here emits network-wide per member.  In
 * particular the movers are moved with add_user_to_channel() /
 * remove_user_from_channel() rather than the joinbuf machinery precisely
 * because joinbuf broadcasts, and the RN C marker already implies the move
 * network-wide (same contract as a classic rename).
 *
 * @a chptr is NOT freed and NOT renamed -- it survives as the tombstone.
 *
 * @param[in] sptr Issuer of the rename.  May be a server when services
 *                 drove the rename: no membership can match a server, so
 *                 the issuer class is then simply empty and only +F members
 *                 move.  That is intentional -- a services-driven rename has
 *                 no user whose action counts as consent.
 * @param[in] chptr Channel being relocated (keeps its name).
 * @param[in] oldname @a chptr's name, snapshotted by the caller.
 * @param[in] newname Name to relocate to.
 * @param[in] reason Reason (may be empty string).
 * @return 0 on success, -1 on bad/oversized name or allocation failure,
 *         -2 if @a newname is already in use.
 */
static int relocate_execute(struct Client *sptr, struct Channel *chptr,
                            const char *oldname, const char *newname,
                            const char *reason)
{
  struct Channel *newchan;
  struct Membership *member;
  struct RelocateMover *movers;
  char newname_buf[CHANNELLEN + 1];
  char reasonpart[TOPICLEN + 4];
  int nmembers = 0;
  int nmovers = 0;
  int i;

  if (!sptr || !chptr || EmptyString(newname))
    return -1;
  if (strlen(newname) > CHANNELLEN)
    return -1;
  if (FindChannel(newname))
    return -2;

  /* Issuer normalisation.  A bouncer alias connection is not the channel
   * member -- the PRIMARY holds the real Membership and the alias holds a
   * CHFL_ALIAS shadow that pass 1 skips.  Without this rewrite an alias
   * issuing RENAME would match no membership at all and the issuer, whose
   * own action is the consent, would be left behind in the tombstone.
   * Same rewrite rename_forward_rcapable() and m_rename()'s AC emit
   * already perform for the same reason. */
  if (IsUser(sptr) && IsBouncerAlias(sptr) && cli_alias_primary(sptr))
    sptr = cli_alias_primary(sptr);

  if (!reason)
    reason = "";

  ircd_strncpy(newname_buf, newname, sizeof(newname_buf));

  if (*reason)
    ircd_snprintf(0, reasonpart, sizeof(reasonpart), " (%s)", reason);
  else
    reasonpart[0] = '\0';

  /* Upper-bound the mover array by the membership list length (which can
   * exceed chptr->users: aliases and zombies are on the list too).  Do it
   * before any mutation so an allocation failure leaves the channel
   * untouched. */
  for (member = chptr->members; member; member = member->next_member)
    nmembers++;

  movers = (struct RelocateMover *)
           MyMalloc(sizeof(struct RelocateMover) * (nmembers + 1));
  if (!movers)
    return -1;

  newchan = get_channel(sptr, newname_buf, CGT_CREATE);
  if (!newchan) {
    MyFree(movers);
    return -1;
  }

  /* ---- 1. Channel STATE transfer ----
   * A classic rename carries state along implicitly: rename_channel()
   * keeps (or memcpy()s) the whole struct Channel and only swaps the name.
   * Relocation needs two live channels, so the same set of fields is
   * copied explicitly here.  struct Mode covers mode/exmode/limit/key/
   * upass/apass/redir in one assignment -- which is also how registration
   * (MODE_REGISTERED) and oplevel ownership (apass/upass) follow the
   * community to the new name.  Memberships are deliberately excluded:
   * they are the whole point of this function's second half.
   *
   * NOT transferred: chptr->metadata (draft/metadata-2).  Channel metadata
   * is persisted keyed by channel name; splitting it is a Task-4-or-later
   * decision and moving the in-memory pointer here would leave the live
   * tombstone with none.  Recorded rather than silently skipped. */
  newchan->mode = chptr->mode;
  newchan->creationtime = chptr->creationtime;
  newchan->topic_time = chptr->topic_time;
  ircd_strncpy(newchan->topic, chptr->topic, sizeof(newchan->topic));
  ircd_strncpy(newchan->topic_nick, chptr->topic_nick,
               sizeof(newchan->topic_nick));
  relocate_copy_bans(&newchan->banlist, chptr->banlist);
  relocate_copy_bans(&newchan->exceptlist, chptr->exceptlist);

  /* Pending invites MOVE rather than fork: an invite is a one-shot grant
   * to enter the community, and the community is now at the new name.
   * The per-client back-pointers have to be re-aimed exactly as
   * rename_channel() re-aims them (channel.c ~2103) -- cli_user()->invited
   * holds struct Channel *, so leaving them pointing at the tombstone
   * would strand del_invite() on the wrong list. */
  {
    struct SLink *link;

    newchan->invites = chptr->invites;
    chptr->invites = NULL;

    for (link = newchan->invites; link; link = link->next) {
      struct Client *icptr = link->value.cptr;
      struct SLink *inv;

      for (inv = cli_user(icptr)->invited; inv; inv = inv->next) {
        if (inv->value.chptr == chptr) {
          inv->value.chptr = newchan;
          break;
        }
      }
    }
  }

  /* ---- 1b. Registration and channel credentials TRANSFER ----
   * They are moved, not forked.  The struct Mode assignment above already
   * gave newchan the MODE_REGISTERED bit and the apass/upass, so all that
   * is left is to strip them from the tombstone: a tombstone that stays
   * +R claims a registration that now belongs to the new name (services
   * re-point it themselves), and a tombstone that keeps the apass would
   * hand a dissolving channel's founder credentials to whoever is left in
   * it.  Nothing extra goes on the wire -- every server runs this same
   * engine off the marker, so the bit clears everywhere in lockstep. */
  chptr->mode.mode &= ~MODE_REGISTERED;
  chptr->mode.apass[0] = '\0';
  chptr->mode.upass[0] = '\0';

  /* The limit goes too, and this one is load-bearing rather than tidy.
   * m_join.c's forwarding branch only redirects when the channel is at its
   * limit -- `if (chptr->users >= chptr->mode.limit)` (m_join.c:161) inside
   * the `if (*chptr->mode.redir)` test at m_join.c:160.  With no limit set
   * that comparison is trivially true (mode.limit is unsigned) and every
   * join of the tombstone forwards, which is the unconditional behaviour
   * the spec describes.  Carry the old channel's +l across, though, and it
   * is FALSE for as long as the tombstone is under-full -- so joins of the
   * old name would silently land IN the dying channel instead of being
   * forwarded to the new one, for the whole grace period.  The limit
   * belongs to the live community, which is at the new name;
   * newchan->mode already carries it.  Cleared silently for the same
   * reason as the registration bits above: every server runs this engine
   * off the same marker, so it clears everywhere in lockstep. */
  chptr->mode.mode &= ~MODE_LIMIT;
  chptr->mode.limit = 0;

  /* ---- 2. Tombstone the old channel, BEFORE moving anyone out ----
   * EXMODE_PERSIST is what stops sub1_from_channel() from destructing
   * chptr when the last mover leaves (a channel where every member is the
   * issuer or +F is the ordinary case, not a corner case) -- without it
   * the rest of this function would be operating on freed memory.  It is
   * set on the struct directly and never put on the wire: relocation must
   * not depend on services agreeing to persist the channel.
   *
   * The redirect is set here too, but ANNOUNCED after the partition, so
   * the members who are leaving anyway don't get a MODE for a channel they
   * are about to part. */
  chptr->mode.exmode |= EXMODE_PERSIST;
  chptr->mode.mode |= MODE_REDIRECT;
  ircd_strncpy(chptr->mode.redir, newname_buf, sizeof(chptr->mode.redir));

  /* ---- 3. Classify, and notify the members who stay ----
   * Pass one only reads the membership list and sends messages, so the
   * list is stable across it.  It must NOT be fused with the move pass:
   * remove_user_from_channel() calls bounce_sync_alias_part(), which
   * unlinks the moving user's alias memberships from this same list --
   * so even a next_member captured before the call can be freed by it.
   * Snapshotting the movers first makes that structurally impossible. */
  for (member = chptr->members; member; member = member->next_member) {
    struct Client *user = member->user;

    /* Alias memberships are shadows of their primary's; they follow it
     * automatically via bounce_sync_alias_join()/_part() in pass two.
     * Zombies are kicked-but-present artifacts and follow nothing. */
    if (IsMemberAlias(member) || IsZombie(member))
      continue;

    /* Movers: the issuer (issuing the rename IS consent) and anyone who
     * pre-consented with umode +F. */
    if (user == sptr || IsRelocateFollow(user)) {
      movers[nmovers].user = user;
      /* CHFL_DELAYED rides along with the status bits: a classic rename
       * keeps the whole Membership struct, so a +D-hidden member stays
       * hidden across it.  Dropping the bit here would reveal, as a side
       * effect of a relocation, a member who had chosen not to be seen --
       * the exact class of involuntary exposure this extension exists to
       * prevent.  MODE_DELJOINS/MODE_WASDELJOINS come across with
       * newchan->mode, so the new channel is in the matching state. */
      movers[nmovers].status = member->status & (CHFL_CHANOP | CHFL_HALFOP
                                                 | CHFL_VOICE | CHFL_DELAYED);
      movers[nmovers].oplevel = OpLevel(member);
      nmovers++;
      continue;
    }

    /* Non-movers keep their membership in the tombstone.  They must NOT
     * get a RENAME: that message asserts "your membership now points at
     * the new name" and would desynchronise a client that honours it.
     * Notification is local-only -- remote members are told by their own
     * server, which ran this same code off the propagated marker. */
    if (!MyUser(user))
      continue;

    if (CapActive(user, CAP_EVILNET_RELOCATE))
      sendcmdto_one(sptr, CMD_RELOCATE, user, "%s %s :%s",
                    oldname, newname_buf, reason);
    else
      /* Exactly the spec's fallback shape.  reasonpart carries the
       * " (<reason>)" parenthetical, or is empty when there is no reason
       * -- an empty "()" would read as a rendering bug and inventing a
       * placeholder reason would put words in the issuer's mouth. */
      sendcmdto_one(&his, CMD_NOTICE, user,
                    "%H :%s has moved to %s%s. Join %s to follow; this "
                    "channel closes in %d minutes.",
                    chptr, oldname, newname_buf, reasonpart, newname_buf,
                    feature_int(FEAT_RELOCATE_GRACE) / 60);
  }

  /* ---- 4. Move the movers ----
   * Two passes, and the split matters: the PART/JOIN fallback in
   * send_rename_to_member() ends in do_names() on the new channel, so
   * every mover has to already be on it before ANY of them is notified.
   * Interleaving move-and-notify would hand each mover a NAMES list
   * containing only the movers processed before them. */
  for (i = 0; i < nmovers; i++) {
    /* Before the add: add_user_to_channel() is what emits the alias JOIN
     * echo, so the alias's PART of the old name has to precede it. */
    relocate_part_local_aliases(movers[i].user, chptr, oldname, newname_buf,
                                reason);

    add_user_to_channel(newchan, movers[i].user, movers[i].status,
                        movers[i].oplevel);
    remove_user_from_channel(movers[i].user, chptr);
  }

  /* The members staying behind have to SEE the movers go, or the
   * tombstone's NAMES list keeps names that are not in it any more.
   * Local-only: this is not the network PART that add/remove deliberately
   * avoid emitting -- every server runs this same loop for its own local
   * stayers.
   *
   * It runs as its OWN loop, after every mover has been unlinked, so that
   * no mover can receive it.  Fused into the loop above, mover i's PART
   * would still reach movers i+1..n -- who are being told by their own
   * RENAME/PART+JOIN that they are on the new channel, and would be
   * getting old-channel PART traffic at the same time. */
  for (i = 0; i < nmovers; i++) {
    /* Same gate joinbuf_flush() applies before announcing a PART to a
     * channel (channel.c ~5386): a member the channel never saw JOIN must
     * not be announced leaving.  Without it a +D (delayed-join) mover is
     * revealed to the stayers by their own departure -- undoing the whole
     * point of carrying CHFL_DELAYED through the status mask above, and
     * re-opening the involuntary-exposure class this extension exists to
     * close.  The mover still learns they moved: that is the
     * RENAME/PART+JOIN in the next loop, addressed to them alone (the same
     * split joinbuf_flush() makes with its self-only else branch).
     * CHFL_ZOMBIE is in the test to mirror joinbuf_flush()'s condition
     * exactly; pass 1 already excludes zombies from the mover set, so it
     * is belt-and-braces against a future classifier change. */
    if (movers[i].status & (CHFL_ZOMBIE | CHFL_DELAYED))
      continue;

    sendcmdto_channel_butserv_butone(movers[i].user, CMD_PART, chptr, NULL, 0,
                                     "%H :Moved to %s", chptr, newname_buf);
  }

  for (i = 0; i < nmovers; i++) {
    /* Local movers only: a mover on another server is notified by that
     * server, which ran this same function off the propagated marker. */
    if (MyUser(movers[i].user))
      send_rename_to_member(sptr, movers[i].user, newchan, oldname, reason);
  }

  MyFree(movers);

  /* ---- 5. Announce the redirect and arm the grace timer ---- */
  relocate_announce_redirect(chptr);
  relocate_tombstone_add(chptr, newname_buf);

  /* A tombstone that pointed at oldname must now point at newname_buf --
   * our own fresh tombstone points at newname_buf already, so it can never
   * match here. */
  relocate_tombstone_retarget(oldname, newname_buf);

  log_write(LS_DEBUG, L_DEBUG, 0,
            "relocate_execute: %s -> %s by %#C (%d moved, %d stayed)",
            oldname, newname_buf, sptr, nmovers, nmembers - nmovers);

  return 0;
}

/* ========== End Relocation ========== */

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

  /* Per the draft/channel-rename spec the capability governs only how a
   * client is *notified* of a rename (the RENAME message vs the PART/JOIN
   * legacy fallback, handled per-member in send_rename_to_members) — it is
   * NOT required to *issue* the command.  A client without the cap may
   * rename and simply receives the fallback for itself; do not reject with
   * ERR_UNKNOWNCOMMAND. */

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

  /* A live tombstone is a channel on its way out, not a community: its
   * name is reserved for the grace period and its remaining members were
   * explicitly NOT moved once already.  Renaming it would either strand
   * them again or produce a redirect chain nobody asked for (spec,
   * "Multiple renames": a tombstone channel itself cannot be renamed). */
  if (rename_is_consent() && relocate_tombstone_find(oldname)) {
    send_fail(sptr, "RENAME", "CANNOT_RENAME", oldname,
              "Channel is a relocation tombstone");
    return 0;
  }

  /* With channel oplevels active (+A), only the founder may rename. */
  if (!rename_oplevel_ok(chptr, member)) {
    send_fail(sptr, "RENAME", "CANNOT_RENAME", oldname,
              "Only the channel founder may rename this channel");
    return 0;
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

    /* Cheap request-time dedup: a second concurrent RENAME on the same
     * channel would produce two pendings racing the same completion path
     * (see the PendingRename struct comment) — refuse it up front rather
     * than relying solely on pending_rename_complete()'s re-resolve to
     * paper over it. */
    if (pending_rename_find_by_name(chptr->chname)) {
      send_fail(sptr, "RENAME", "TEMPORARILY_UNAVAILABLE", oldname,
                "A rename is already in progress for this channel");
      return 0;
    }

    if (!(pr = pending_rename_add(sptr, chptr, newname, reason))) {
      send_fail(sptr, "RENAME", "TEMPORARILY_UNAVAILABLE", oldname,
                "Too many renames in progress");
      return 0;
    }

    {
      /* Alias source rewrite for the %C target-user argument — sptr may
       * be a bouncer alias, which the rename-capable non-v3 services
       * package (X3's cmd_account does GetUserN(argv[1]) and silently
       * returns on an unresolvable numeric) was never told about via
       * BX C.  Unlike rename_forward_rcapable()'s rewrite, this is a *data*
       * argument, not the message's P10 prefix (that stays &me), so
       * there's no "fake direction" case to preserve the alias numeric
       * for — always prefer the primary when there is one.  pr->client
       * stays the alias: the AC A/D reply routes back by cookie, not by
       * this numeric. */
      struct Client *acct_user = sptr;
      if (IsUser(sptr) && IsBouncerAlias(sptr) && cli_alias_primary(sptr))
        acct_user = cli_alias_primary(sptr);

      sendcmdto_one(&me, CMD_ACCOUNT, services, "%C R %u %s RENAME %s",
                   acct_user, pr->cookie, chptr->chname, newname);
    }
    return 0;
  }

  /* Unregistered channel - proceed with rename immediately */

  /* Store old name before rename */
  ircd_strncpy(oldname_buf, chptr->chname, CHANNELLEN + 1);

  /* Relocation mode: partition instead of force-moving, and mark the RN so
   * every other server does the same.  Classic mode below is untouched. */
  if (rename_is_consent()) {
    rc = relocate_execute(sptr, chptr, oldname_buf, newname, reason);
    if (rc == -1) {
      send_fail(sptr, "RENAME", "CANNOT_RENAME", oldname,
                "New channel name is too long");
      return 0;
    } else if (rc == -2) {
      send_fail(sptr, "RENAME", "CHANNEL_NAME_IN_USE", oldname,
                "Channel name already in use");
      return 0;
    }

    sendcmdto_serv_butone_v3(sptr, CMD_RENAME, cptr, "%s %s %s:%s",
                             oldname_buf, newname, RELOCATE_MARKER_SP, reason);
    rename_forward_rcapable(sptr, NULL, oldname_buf, newname,
                            RELOCATE_MARKER_SP, reason);
    return 0;
  }

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

  /* Rename-capable non-v3 links (X3) don't get RN via the v3-only
   * broadcast above; synth it directly so they can keep their channel
   * state in sync. */
  rename_forward_rcapable(sptr, NULL, oldname_buf, chptr->chname, "", reason);

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
  int relocate = 0;
  int rc;

  /* Need at least old and new channel names */
  if (parc < 3 || EmptyString(parv[1]) || EmptyString(parv[2])) {
    return 0; /* Silently ignore malformed S2S messages */
  }

  oldname = parv[1];
  newname = parv[2];
  reason = (parc > 3 && !EmptyString(parv[3])) ? parv[3] : "";

  /* Relocation marker: RN <old> <new> C :<reason>.  Recognised only in the
   * five-parameter shape -- see the RELOCATE_MARKER comment for why the
   * four-parameter shape must stay a classic rename with the reason "C".
   * When the marker is present relocation semantics apply on THIS server
   * regardless of the local FEAT_RENAME_CONSENT setting. */
  if (parc > 4 && !EmptyString(parv[3]) && 0 == strcmp(parv[3],
                                                       RELOCATE_MARKER)) {
    relocate = 1;
    reason = !EmptyString(parv[4]) ? parv[4] : "";
  } else if (parc == 4 && !EmptyString(parv[3]) && parv[3][0] == 'C'
             && IsIRCv3Aware(cptr)) {
    /* Tripwire for a mis-spliced marker.  A peer that emits the marker
     * without its separating space produces "RN #old #new C:<reason>",
     * which parses here as a four-parameter CLASSIC rename with the
     * reason "C:<reason>" -- so this server force-moves a membership the
     * emitting server partitioned, and the divergence is silent and
     * permanent.  A genuine classic rename whose reason merely starts
     * with 'C' is legitimate, so this only warns; it does not reinterpret
     * the message. */
    log_write(LS_SYSTEM, L_WARNING, 0,
              "RENAME from %#C: %s -> %s has a 4-parameter reason beginning "
              "with 'C' (\"%s\").  If that peer meant to send the relocation "
              "marker it omitted the separating space, and this server has "
              "just applied a CLASSIC rename to a channel it partitioned.",
              cptr, parv[1], parv[2], parv[3]);
  }

  /* Find the channel */
  chptr = FindChannel(oldname);
  if (!chptr) {
    return 0; /* Channel doesn't exist on this server */
  }

  /* Store old name before rename */
  ircd_strncpy(oldname_buf, chptr->chname, CHANNELLEN + 1);

  if (relocate) {
    rc = relocate_execute(sptr, chptr, oldname_buf, newname, reason);

    if (rc == -2) {
      /* Both names already exist HERE.  That is a pre-existing local
       * divergence, not a defect in the message, and it is exactly the
       * case where dropping the relay does the most damage: this server
       * would become a silent wall, leaving every server behind it on the
       * old name forever while everything in front of it moved.  So warn
       * loudly enough for an operator to act -- the two channels have to
       * be reconciled by hand -- and CONTINUE propagating.  Containment of
       * the divergence to this one server beats orphaning the whole
       * subtree. */
      sendto_opmask_butone(0, SNO_OLDSNO,
                           "RELOCATE %s -> %s from %C NOT applied locally: "
                           "%s already exists on this server.  The rename "
                           "has been relayed onward, so this server is now "
                           "divergent and needs manual reconciliation.",
                           oldname_buf, newname, sptr, newname);
      /* fall through to propagation */
    } else if (rc != 0) {
      /* Any other failure is deterministic from the message itself (name
       * too long, allocation failure), so every server fails it the same
       * way and there is nothing downstream to orphan.  Log and drop,
       * matching the classic failure path below. */
      log_write(LS_DEBUG, L_ERROR, 0,
                "RELOCATE failed from %#C: %s -> %s (rc=%d)",
                sptr, oldname, newname, rc);
      return 0;
    }

    /* Propagate with the marker preserved. */
    sendcmdto_serv_butone_v3(sptr, CMD_RENAME, cptr, "%s %s %s:%s",
                             oldname_buf, newname, RELOCATE_MARKER_SP, reason);
    rename_forward_rcapable(sptr, cptr, oldname_buf, newname,
                            RELOCATE_MARKER_SP, reason);
    return 0;
  }

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

  /* Rename-capable non-v3 links (X3) don't get RN via the v3-only
   * broadcast above; synth it directly so they can keep their channel
   * state in sync. Skip the link this RENAME arrived on. */
  rename_forward_rcapable(sptr, cptr, oldname_buf, chptr->chname, "", reason);

  return 0;
}
