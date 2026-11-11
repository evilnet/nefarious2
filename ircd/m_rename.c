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
#include "gline.h"
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
#include "rename_proto.h"
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
  char services[HOSTLEN + 1];      /**< Name of the services server the query
                                         was sent to: the only server whose
                                         answer is taken.  A name and not a
                                         struct Client *, for the reason the
                                         struct comment gives for the channel
                                         (pending_rename_server_exit() retires
                                         the request when that server goes,
                                         but nothing here depends on it) */
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
                            const char *reason, time_t expires);
static struct RelocateTombstone *relocate_tombstone_find(const char *name);
static void relocate_tombstone_renamed(const char *oldname,
                                       struct Channel *chptr);
static time_t relocate_local_deadline(void);
static void relocate_propagate(struct Client *sptr, struct Client *one,
                               struct Client *skip, const char *oldname,
                               const char *newname, time_t expires,
                               const char *reason);

/** Wire marker distinguishing a relocation-mode RN from a classic one:
 *
 *     classic:     RN <old> <new> :<reason>
 *     relocation:  RN <old> <new> C <expires> :<reason>
 *     before the deadline travelled:
 *                  RN <old> <new> C :<reason>
 *
 * <expires> is the moment the tombstone is dissolved, in network time
 * (TStime()); include/rename_proto.h has the field's form and the rules a
 * receiver applies to it.  The server that executes the relocation
 * computes it once, every relay passes on the deadline it armed for, and
 * so every server dissolves the tombstone at the same moment instead of
 * each counting its own RELOCATE_GRACE from its own time of receipt.
 *
 * NORMATIVE for every emitter (including X3): the trailing reason
 * parameter MUST be present -- emit ":" with an empty reason rather than
 * dropping it.  ms_rename() only honours the marker when a parameter
 * follows it, because a four-parameter "RN <old> <new> :C" is a classic
 * rename whose reason happens to be the letter C and must not be mistaken
 * for a relocation.  Honouring a marker in the shorter shape would turn
 * that message into a partition on some servers and a force-move on others
 * -- i.e. permanent membership divergence -- which is strictly worse than
 * losing the marker on a malformed emission.
 *
 * Mixed versions.  The six-parameter form is sent to every peer a
 * relocation is sent to; no SERVER flag tells an older fork server from a
 * newer one.  An older receiver tests only "more than four parameters and
 * the fourth is C" and takes the FIFTH as the reason: it executes the
 * relocation, counts its own grace, shows its local members the digits of
 * <expires> where the reason belongs, and relays the five-parameter form
 * with those digits as the reason.  X3 tests the marker the same way and
 * reads no reason at all.  Neither misapplies the message. */
#define RELOCATE_MARKER "C"

/** Room for "C <expires> ", the splice relocate_propagate() puts in front
 * of the reason's colon. */
#define RELOCATE_MARKER_BUFLEN (sizeof(RELOCATE_MARKER) + RELOCATE_EXPIRY_BUFLEN + 2)

/** Find the services server rename permission queries go to.
 *
 * The query (AC <user> R <cookie> <#chan> RENAME <new>) names no
 * destination, so the server that asks and every server that passes the
 * query on have to pick the SAME services server: the asking server
 * accepts an answer only from the one it picked (PendingRename.services).
 * Hence a rule that does not depend on anything local: of the servers
 * that announced themselves as services ('s' in their SERVER flags), the
 * one with the lowest numeric.  Every server that knows the same servers
 * gets the same answer; the order of the global client list, which this
 * used to go by, is each server's own.  With one services server -- the
 * usual network -- there is nothing to choose.
 * @return Pointer to the services server, or NULL if none is linked.
 */
static struct Client *find_services_server(void)
{
  struct Client *acptr, *best = NULL;

  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr)) {
    if (!IsServer(acptr) || !IsService(acptr))
      continue;
    if (!best || strcmp(cli_yxx(acptr), cli_yxx(best)) < 0)
      best = acptr;
  }

  return best;
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

/** Longest new name a user of THIS server may rename a channel to: the
 * cap do_join() puts on a name a user asks to create (m_join.c),
 * IRCD_MIN(CHANNELLEN, FEAT_CHANNELLEN).  A FEAT_CHANNELLEN outside
 * 0..CHANNELLEN leaves the compile-time limit, which rename_channel()
 * enforces whatever the feature says.
 */
static size_t rename_newname_maxlen(void)
{
  int cap = feature_int(FEAT_CHANNELLEN);

  if (cap < 0 || cap > CHANNELLEN)
    cap = CHANNELLEN;

  return (size_t)cap;
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
 *                   the historical "%s %s :%s" shape) or "C <expires> "
 *                   for a relocation-mode rename (relocate_propagate()
 *                   builds it).
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
 * @param[in] services The services server the query is about to be sent
 *                     to; its name is recorded, and only its answer will
 *                     be accepted.
 * @return Pointer to new pending request, or NULL on error.
 */
static struct PendingRename *pending_rename_add(struct Client *client,
                                                 struct Channel *channel,
                                                 const char *newname,
                                                 const char *reason,
                                                 struct Client *services)
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
  ircd_strncpy(pr->services, cli_name(services), sizeof(pr->services));

  /* Add to list */
  pr->next = pending_renames;
  pending_renames = pr;
  pending_rename_count++;

  /* Start timeout timer */
  timer_add(timer_init(&pr->timeout), pending_rename_timeout_cb, (void *)pr,
            TT_RELATIVE, RENAME_TIMEOUT);
  pr->timer_active = 1;

  log_write(LS_DEBUG, L_DEBUG, 0,
            "pending_rename_add: cookie=%u channel=%s newname=%s client=%C "
            "services=%s",
            pr->cookie, pr->oldname, pr->newname, client, pr->services);

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

  /* Re-run m_rename's name rules.  The names themselves cannot change
   * while the request waits, but what this server accepts can: a REHASH
   * or SET may have lowered CHANNELLEN or turned VALID_UTF8_CHANNELS_ONLY
   * on, and the approval must not carry a name past a limit that would
   * stop a JOIN of it now (services arbitrate ownership, not this
   * server's naming policy). */
  {
    enum RenameNameError bad =
      rename_check_names(pr->oldname, pr->newname, rename_newname_maxlen(),
                         feature_bool(FEAT_VALID_UTF8_CHANNELS_ONLY));

    if (bad != RENAME_NAME_OK) {
      pending_rename_deny(pr, rename_name_error_text(bad));
      return;
    }
  }

  /* Re-run the BADCHAN check from m_rename: a badchan on the target can
   * land during the services round-trip, and the approval must not
   * override it (services arbitrate ownership, not G-line policy).
   * Runs before the consent branch — a relocation onto a banned name is
   * just as much a bypass as a classic rename onto one. */
  {
    struct Gline *gline = gline_find(pr->newname, GLINE_BADCHAN | GLINE_EXACT);
    if (gline && GlineIsActive(gline) && !IsAnOper(pr->client)) {
      pending_rename_deny(pr, "Target channel name is banned");
      return;
    }
  }

  /* The channel can also have BECOME a tombstone during the round-trip
   * (a relocation of it arrived from another server).  Same refusal as
   * the request-time check in m_rename(), and like it whatever this
   * server's own RENAME_CONSENT says. */
  if (relocate_tombstone_find(pr->oldname)) {
    pending_rename_deny(pr, "Channel is a relocation tombstone");
    return;
  }

  /* Relocation mode: partition instead of force-moving, and mark the RN.
   * chptr keeps its old name here, so the propagated new name comes from
   * pr->newname rather than chptr->chname. */
  if (rename_is_consent()) {
    time_t expires = relocate_local_deadline();

    /* chptr may be gone when this returns (a deadline of "now"). */
    if (relocate_execute(pr->client, chptr, pr->oldname, pr->newname,
                         pr->reason, expires) != 0) {
      send_fail(pr->client, "RENAME", "CANNOT_RENAME", pr->oldname,
                "Rename failed");
      pending_rename_remove(pr);
      return;
    }

    relocate_propagate(pr->client, cli_from(pr->client), NULL, pr->oldname,
                       pr->newname, expires, pr->reason);

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

/** Retire the pending renames that were waiting on a services server
 * that has just left the network: it will not answer, and the requester
 * need not wait out RENAME_TIMEOUT to be told so.
 *
 * Called from exit_one_client() (s_misc.c) for every server that exits,
 * directly or behind a broken link.
 * @param[in] server The departing server.
 */
void pending_rename_server_exit(struct Client *server)
{
  struct PendingRename *pr, *next;

  /* ->next cached first: pending_rename_remove() frees pr (see
   * pending_rename_client_exit()). */
  for (pr = pending_renames; pr; pr = next) {
    next = pr->next;

    if (0 != ircd_strcmp(pr->services, cli_name(server)))
      continue;

    log_write(LS_DEBUG, L_DEBUG, 0,
              "pending_rename_server_exit: cookie=%u, services server %s "
              "left", pr->cookie, pr->services);

    send_fail(pr->client, "RENAME", "TEMPORARILY_UNAVAILABLE", pr->oldname,
              "Registration service is not available");
    pending_rename_remove(pr);
  }
}

/* ---------- Services arbitration across servers ----------
 *
 * The query and its reply ride on ACCOUNT (see include/rename_proto.h for
 * the three line shapes and the cookie).  Neither is addressed: the query
 * goes toward the services server (find_services_server(), the same one
 * on every hop), the reply goes to the server named in its cookie.  A
 * server in between is a stateless relay -- it keeps nothing about the
 * request and forwards both lines with their original source.
 *
 * Who may do what is decided in rename_proto.c: rename_query_relayable()
 * for a query passing through, rename_reply_decide() for a reply.  In
 * short: a query is passed on only when its cookie names the server it
 * comes from, so its answer can come back to nobody else; an answer is
 * taken, and carried, only from a services server; and a pending request
 * is completed or denied only by the services server its query was sent
 * to.
 *
 * Mixed versions.  A fork server from before this relay existed, sitting
 * BETWEEN the origin and services, still runs the query through the
 * account-stamp code and forwards neither line: the origin's
 * RENAME_TIMEOUT answers the user, as it always did.  One sitting at the
 * ORIGIN sends the bare-number cookie, and gets what it always got:
 * arbitration when it is services' own uplink (nothing passes through a
 * relay then), a timeout otherwise -- the first server that would have to
 * relay its query drops it.  Passing it on would be worse than useless:
 * services' bare-number answer names no server, so services' uplink would
 * try it against its OWN table, and approve an unrelated request of its
 * own that happens to carry the same small number.
 */

/** Relay a permission query that is passing through this server.
 * @param[in] cptr Link the query arrived on.
 * @param[in] sptr Its source, the origin server.
 * @param[in] parv parv[1] user numeric, parv[3] cookie, parv[4] channel,
 *                 parv[5] "RENAME", parv[6] new name (caller checked the
 *                 shape and that there are at least seven parameters).
 */
static void rename_services_query_relay(struct Client *cptr,
                                        struct Client *sptr, char *parv[])
{
  struct Client *services;
  enum RenameCookieForm form;
  char numeric[3];
  unsigned int n;

  /* The cookie must name the server the query comes from: that is the
   * server the reply will be delivered to (rename_query_relayable()). */
  form = rename_cookie_parse(parv[3], numeric, &n);
  if (!rename_query_relayable(form, form == RENAME_COOKIE_ROUTED
                                    && FindNServer(numeric) == sptr)) {
    log_write(LS_DEBUG, L_DEBUG, 0,
              "rename query from %C (cookie %s, channel %s) dropped: its "
              "cookie does not name its source server", sptr, parv[3],
              parv[4]);
    return;
  }

  /* parv[6] is the one field that can have been a trailing parameter, so
   * the only one that can be empty or hold a space.  No channel name is
   * either, and written back out such a field would change the number of
   * parameters: the next hop would no longer see a rename query, it would
   * see an account stamp for the requesting user.  Do not pass it on. */
  if (EmptyString(parv[6]) || parv[6][0] == ':' || strchr(parv[6], ' ')) {
    log_write(LS_DEBUG, L_DEBUG, 0,
              "rename query from %C (cookie %s, channel %s) dropped: "
              "malformed new name", sptr, parv[3], parv[4]);
    return;
  }

  /* Toward the services server the origin picked -- and never back down
   * the link the query came from: if that is where this server believes
   * services are, the two disagree about the network (a link is forming
   * or breaking), and returning the line would only bounce it.  Either
   * way there is nothing to do for the user from here; the origin's
   * RENAME_TIMEOUT tells them. */
  if (!(services = find_services_server()) || cli_from(services) == cptr) {
    log_write(LS_DEBUG, L_DEBUG, 0,
              "rename query from %C (cookie %s, channel %s) dropped: no "
              "services server beyond the link it came from (%C)",
              sptr, parv[3], parv[4], cptr);
    return;
  }

  log_write(LS_DEBUG, L_DEBUG, 0,
            "rename query from %C (cookie %s, channel %s) relayed toward %C",
            sptr, parv[3], parv[4], services);

  sendcmdto_one(sptr, CMD_ACCOUNT, services, "%s R %s %s %s %s",
                parv[1], parv[3], parv[4], parv[5], parv[6]);
}

/** Handle services' answer to a permission query: complete or deny the
 * request when it is ours, pass the line on when it is another server's.
 * @param[in] cptr Link the reply arrived on.
 * @param[in] sptr Its source.
 * @param[in] parc Number of parameters (at least four).
 * @param[in] parv parv[1] cookie, parv[2] "A" or "D", parv[3] "RENAME",
 *                 parv[4] the reason of a "D" (optional).
 */
static void rename_services_reply(struct Client *cptr, struct Client *sptr,
                                  int parc, char *parv[])
{
  int approved = (parv[2][0] == 'A');
  const char *reason = (parc > 4) ? parv[4] : NULL;
  struct RenameReplyFacts facts;
  struct PendingRename *pr = NULL;
  struct Client *origin = NULL;
  enum RenameReplyVerdict verdict;
  char numeric[3];
  unsigned int n = 0;

  /* Gather what rename_reply_decide() rules on.
   *
   * "Services" is a server that announced itself as one -- the 's' in its
   * SERVER line's flags (FLAG_SERVICE; set_server_flags() in m_server.c,
   * passed on by every hop that introduces the server).  That alone lets
   * a reply be relayed.  To be APPLIED it must also come from the one
   * services server this server sent the request to (pr->services). */
  memset(&facts, 0, sizeof(facts));
  facts.form = rename_cookie_parse(parv[1], numeric, &n);
  facts.source_is_services = IsServer(sptr) && IsService(sptr);
  facts.source_is_direct = (cli_from(sptr) == sptr);
  facts.source_name = cli_name(sptr);

  if (facts.form == RENAME_COOKIE_ROUTED) {
    origin = FindNServer(numeric);
    facts.cookie_is_ours = (origin && IsMe(origin));
    facts.cookie_server_known = (origin != NULL);
    facts.cookie_server_is_back = (origin && !IsMe(origin)
                                   && cli_from(origin) == cptr);
  }

  /* Our table is consulted only for a cookie that can be ours. */
  if (facts.form == RENAME_COOKIE_LEGACY || facts.cookie_is_ours) {
    pr = pending_rename_find(n);
    facts.bound_name = pr ? pr->services : NULL;
  }

  verdict = rename_reply_decide(&facts);

  switch (verdict) {
  case RENAME_REPLY_APPLY:
    if (approved)
      pending_rename_complete(pr);
    else
      pending_rename_deny(pr, reason ? reason : "Permission denied");
    return;

  case RENAME_REPLY_RELAY:
    /* In transit: same source, same cookie, same reason. */
    if (reason)
      sendcmdto_one(sptr, CMD_ACCOUNT, origin, "%s %s %s :%s",
                    parv[1], parv[2], parv[3], reason);
    else
      sendcmdto_one(sptr, CMD_ACCOUNT, origin, "%s %s %s",
                    parv[1], parv[2], parv[3]);
    return;

  case RENAME_REPLY_NOT_SERVICES:
  case RENAME_REPLY_NOT_BOUND:
    /* Somebody answering who was not asked: operators should hear of it. */
    protocol_violation(cptr, "ACCOUNT rename reply (cookie %s) from %s "
                       "ignored: %s", parv[1], cli_name(sptr),
                       rename_reply_verdict_text(verdict));
    return;

  default:
    /* Late (the request timed out or its requester left), misrouted or
     * malformed. */
    log_write(LS_DEBUG, L_DEBUG, 0,
              "rename reply (cookie %s) from %C dropped: %s",
              parv[1], sptr, rename_reply_verdict_text(verdict));
    return;
  }
}

/** Is this ACCOUNT message part of channel-rename arbitration?  If so,
 * deal with it.
 *
 * Called by ms_account() before it reads the message as anything else,
 * and before its EXTENDED_ACCOUNTS split: neither line is an account
 * message, and read as one the query is a stamp for the requesting user
 * with the cookie (or, without EXTENDED_ACCOUNTS, the letter R) as the
 * account name.
 *
 * The query is recognised exactly as services recognise it -- subtype R,
 * at least seven parameters, the fifth the literal RENAME -- so that the
 * relay and services always agree about which lines are queries.  A real
 * stamp never has that shape: its fifth parameter is a Keycloak id
 * (account_id_valid(): 22 characters).  The reply is recognised as it
 * always was, by the RENAME that follows the A or D.
 *
 * @param[in] cptr Link the message arrived on.
 * @param[in] sptr Its source; the caller has checked it is a server.
 * @param[in] parc Number of parameters (at least three).
 * @param[in] parv Parameter vector of the ACCOUNT message.
 * @return Non-zero when the message was a rename query or reply and
 *         needs no further handling, zero when it is something else.
 */
int rename_services_ac(struct Client *cptr, struct Client *sptr, int parc,
                       char *parv[])
{
  if (parv[2][0] == 'R' && !parv[2][1] && parc >= 7
      && 0 == strcmp(parv[5], "RENAME")) {
    rename_services_query_relay(cptr, sptr, parv);
    return 1;
  }

  if ((parv[2][0] == 'A' || parv[2][0] == 'D') && !parv[2][1] && parc > 3
      && 0 == ircd_strcmp(parv[3], "RENAME")) {
    rename_services_reply(cptr, sptr, parc, parv);
    return 1;
  }

  return 0;
}

/* ========== End Pending Rename Infrastructure ========== */

/** Deliver the rename notification for ONE local member: a RENAME message
 * when that connection negotiated draft/channel-rename, the legacy
 * PART/JOIN(+TOPIC/NAMES) pair otherwise -- the JOIN in the extended-join
 * form for a connection that negotiated that.
 *
 * Split out of send_rename_to_members() so relocation mode can drive it
 * per-member: under FEAT_RENAME_CONSENT only the movers (issuer and +F
 * users) may be told "your membership now points at the new name", and
 * they are no longer walkable as "every member of chptr" -- see
 * relocate_execute().
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
    /* The JOIN half is this member's own JOIN of the new name, so it has
     * the shape and the tags of one.  There is no JOIN-specific send
     * helper: the join path (joinbuf_join() in channel.c, and the bouncer
     * replays in bouncer_session.c) picks the form with CapRecipientHas()
     * -- the receiving CONNECTION's own caps, which is what makes it
     * right for a bouncer alias, whose shadow membership this walk also
     * visits -- and writes the extended-join form as "<channel> <account
     * or *> :<realname>".  sendcmdto_one_event() tags one recipient's line
     * the way the channel fan-out of a JOIN tags it (@time, @account, the
     * oper and bot tags, each on the recipient's caps), and keeps it out
     * of any batch or label the recipient has open for something else.
     * No msgid: none is armed here, and this is not a stored JOIN event. */
    if (CapRecipientHas(acptr, CAP_EXTJOIN))
      sendcmdto_one_event(acptr, CMD_JOIN, acptr, 0, "%H %s :%s", chptr,
                          IsAccount(acptr) ? cli_account(acptr) : "*",
                          cli_info(acptr));
    else
      sendcmdto_one_event(acptr, CMD_JOIN, acptr, 0, "%H", chptr);
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

/** Per-member status snapshot, captured when relocate_execute() partitions a
 * channel and consumed (unlinked + freed) when a former member follows to
 * the new channel within the grace period (spec, "Status preservation").
 *
 * Keyed by account when the member had one at snapshot time -- accounts
 * survive nick changes and reconnects, so they are the more durable key --
 * with @a nick + @a userhost as the fallback for a member who was never
 * logged in.  @a account is empty for that fallback case, and
 * relocate_snap_find() enforces two things review round 1 found this
 * struct's own comment claiming but the code not yet doing: an account
 * holder is matched ONLY by account (never falls back to nick), and a
 * nick-keyed entry is matched only by an EXACT nick+user@host pair -- a
 * bare nick match alone would let anyone who acquires a departed op's nick
 * within the grace period (a very ordinary thing to happen: nicks free up
 * the moment their owner quits or gets ghosted) walk in and claim their
 * status. */
struct RelocateSnap {
  struct RelocateSnap *next;      /**< Linked list, off RelocateTombstone.snaps */
  char account[ACCOUNTLEN + 1];   /**< Primary key when non-empty */
  char nick[NICKLEN + 1];         /**< Fallback key part 1 -- account-less only */
  char userhost[USERLEN + HOSTLEN + 2]; /**< Fallback key part 2 ("user@host"),
                                              required alongside nick -- both
                                              account-less only */
  unsigned int flags;             /**< CHFL_CHANOP|CHFL_HALFOP|CHFL_VOICE subset */
  int oplevel;                    /**< Oplevel to restore alongside flags */
};

/** Where a tombstone record's embedded timer stands.  It decides who
 * frees the record -- see "Lifetime" in the struct comment below. */
enum RelocateTimer {
  RELOCATE_TIMER_NONE = 0,  /**< never armed: the event engine holds nothing
                                 of the record */
  RELOCATE_TIMER_ARMED,     /**< queued in the event engine */
  RELOCATE_TIMER_FIRING     /**< inside its own ET_EXPIRE; the engine still
                                 holds the timer and ET_DESTROY follows */
};

/** A tombstoned old channel, alive until its deadline after a
 * relocation-mode rename.
 *
 * Like struct PendingRename above, this deliberately does NOT trust its
 * struct Channel * across time: the tombstone carries EXMODE_PERSIST so the
 * ordinary empty-channel destruct can't free it, but services DESTRUCT
 * (m_destruct.c) still can.  @a oldname is the authority and @a oldchan is
 * a cache -- resolve through relocate_tombstone_channel(), never by reading
 * the field directly.
 *
 * Lifetime.  The struct Timer is embedded, and the event engine keeps
 * using a timer after its ET_EXPIRE callback returns (and timer_del() on a
 * timer in dispatch does nothing), so a record whose timer the engine
 * holds is freed in exactly one place: the ET_DESTROY case of
 * relocate_tombstone_expire_cb().  A record whose timer was never armed is
 * freed by hand.  ONE function decides which, from @a timer_state, for
 * every end of a record outside its own expiry: relocate_tombstone_end().
 * Nothing else frees a record, and nothing may assume a record it is
 * about to end has no timer -- a record that is re-armed for a deadline
 * that has meanwhile passed (a second RN, a merged deadline, a step of the
 * network clock) HAS one. */
struct RelocateTombstone {
  struct RelocateTombstone *next;   /**< Linked list */
  struct Channel *oldchan;          /**< CACHE ONLY -- see struct comment */
  char oldname[CHANNELLEN + 1];     /**< The tombstone's own (stable) name */
  char newname[CHANNELLEN + 1];     /**< Redirect target, chain-flattened */
  time_t target_ts;                 /**< Creation timestamp of the channel the
                                         relocation made under @a newname.
                                         Name and creation timestamp together
                                         are a channel's identity, here as in
                                         BURST: the snapshots below are
                                         honoured only in that channel, not in
                                         one a stranger creates under the name
                                         after it emptied.  Every channel a
                                         relocation makes takes the old
                                         channel's timestamp, so the value
                                         survives chain flattening. */
  time_t expires;                   /**< The deadline, in NETWORK time
                                         (TStime()), as it travels in the RN:
                                         the same number on every server.  The
                                         timer is armed for it in the event
                                         loop's clock (minus TSoffset) by
                                         relocate_tombstone_settle() */
  struct Timer timer;               /**< Embedded -- see "Lifetime" above */
  enum RelocateTimer timer_state;   /**< Where the timer stands, and so who
                                         frees this struct -- "Lifetime"
                                         above */
  char family[CHANNELLEN + 1];      /**< For the tombstone of a relocation
                                         that LOST a crossing (see
                                         relocate_again()): the name of the
                                         old channel both relocations were
                                         of.  The records of one crossing --
                                         the old channel's and every loser's
                                         -- share one deadline; this is how
                                         they are found.  Empty otherwise */
  int waiting;                      /**< The record is waiting for its
                                         channel: the loser of a crossing
                                         learned from burst announcements,
                                         whose own BURST has not arrived yet
                                         (relocate_announced_cross()).  Such a
                                         record is no tombstone until
                                         relocate_tombstone_burst_done() finds
                                         the channel; relocate_tombstone_find()
                                         does not return it, and nothing is
                                         done to any channel on its behalf */
  time_t want_ts;                   /**< ... and the creation timestamp that
                                         channel will have (the old
                                         channel's): one of another timestamp
                                         under the name is a stranger's */
  struct RelocateSnap *snaps;       /**< Member status snapshots for a
                                         grace-period follow-join (spec,
                                         "Status preservation").  Freed as a
                                         list wherever ts itself is freed --
                                         relocate_tombstone_expire_cb()'s
                                         ET_DESTROY case is the only place
                                         that happens. */
};

/** Global tombstone list. */
static struct RelocateTombstone *relocate_tombstones = NULL;

static void relocate_tombstone_expire_cb(struct Event *ev);
static void relocate_tombstone_sweep(struct RelocateTombstone *ts);
static void relocate_snap_free_list(struct RelocateSnap *head);
static void relocate_withdraw_redirect(struct Channel *chptr);

/** Find a record by its (old) channel name, case-insensitively -- any
 * record, one that is still waiting for its channel included.  For the
 * code that keeps the list itself (one record per name) and for the burst
 * hooks; everything that asks "is this channel a tombstone" uses
 * relocate_tombstone_find().
 * @param[in] name Channel name to look up.
 * @return The record, or NULL.
 */
static struct RelocateTombstone *relocate_tombstone_find_any(const char *name)
{
  struct RelocateTombstone *ts;

  if (EmptyString(name))
    return NULL;

  for (ts = relocate_tombstones; ts; ts = ts->next)
    if (0 == ircd_strcmp(ts->oldname, name))
      return ts;

  return NULL;
}

/** Find a tombstone's record by its (old) channel name,
 * case-insensitively.  A record that is waiting for its channel
 * (RelocateTombstone.waiting) is not a tombstone yet and is not returned:
 * a channel that merely has the name such a record waits under can be
 * renamed, relocated and announced like any other.
 * @param[in] name Channel name to look up.
 * @return Tombstone, or NULL if @a name is not a tombstone.
 */
static struct RelocateTombstone *relocate_tombstone_find(const char *name)
{
  struct RelocateTombstone *ts = relocate_tombstone_find_any(name);

  return (ts && !ts->waiting) ? ts : NULL;
}

/** Resolve a tombstone's channel, refreshing the cached pointer.
 *
 * A name lookup alone is NOT an identity check.  A tombstone can die early
 * (services DESTRUCT, a manual MODE -z followed by the last member
 * parting) and an unrelated user can then create a brand-new channel of
 * the same name well inside the grace period -- FindChannel() would hand
 * that fresh channel back and a chain-flattening retarget would stamp
 * +L onto somebody's live channel.  So the result is only accepted when it
 * still carries a tombstone's marks: the persist bit (mode.exmode) and a
 * redirect -- mode.redir, the string -- still pointing where this
 * tombstone points.  Anything else is a different channel wearing the same
 * name.
 *
 * The redirect IS the string.  +L, like +l and +k, lives in its parameter
 * and nowhere else: mode_parse_redir() writes mode.redir, channel_modes()
 * and do_join() read it, and nothing in channel.c ever sets, clears or
 * reads MODE_REDIRECT in a channel's mode.mode.  This check used to
 * demand that bit as well, and relocate_execute() set it by hand -- so a
 * tombstone was recognised only on a server that had executed the
 * relocation itself.  One that got "+z +L <target>" from a BURST (a
 * server that linked or healed a netsplit inside the grace) never had
 * the bit: its record, built from the announcement, did not authenticate,
 * its members were told nothing, and at the deadline it was "cancelled"
 * with the log line "+L was cleared" while every other server swept
 * (bed, 2026-11-11).  The engine no longer touches that bit at all.
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

  /* A record waiting for its channel has none, whatever is under the
   * name. */
  if (ts->waiting)
    return NULL;

  if (!(chptr = FindChannel(ts->oldname)))
    return NULL;

  /* (An empty mode.redir -- no +L -- never equals a target.) */
  if (!(chptr->mode.exmode & EXMODE_PERSIST)
      || 0 != ircd_strcmp(chptr->mode.redir, ts->newname))
    return NULL;

  ts->oldchan = chptr;
  return chptr;
}

/** Unlink a tombstone from the global list, so that no lookup finds it
 * any more.  Does NOT touch the timer and does NOT free @a ts.  Harmless
 * for a record that is not on the list.
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
  ts->next = NULL;
}

/** Free an entire snapshot list.
 * @param[in] head List head (may be NULL).
 */
static void relocate_snap_free_list(struct RelocateSnap *head)
{
  struct RelocateSnap *snap, *next;

  for (snap = head; snap; snap = next) {
    next = snap->next;
    MyFree(snap);
  }
}

/** Find @a who's snapshot entry within @a ts, if any.
 *
 * Two DISJOINT match strategies, per whether @a who currently has an
 * account (review round 1, I3 -- fixed to actually match this function's
 * own struct-level doc comment, which the original code did not):
 *
 * - An account holder is matched ONLY by account, and never falls back to
 *   a nick match.  Falling back would mean an account holder could claim a
 *   bare-nick snapshot (a member who had no account at rename time) simply
 *   by reusing that nick, which is exactly the kind of unrelated-identity
 *   collision the account/nick split exists to prevent.
 * - An account-less joiner is matched by nick AND userhost together,
 *   against snapshot entries that are themselves account-less.  Nick
 *   alone is not enough: nicks free up the instant their previous owner
 *   quits, changes nick, or gets ghosted -- all ordinary events well
 *   within a multi-minute grace period -- so an exact user@host match is
 *   required too before a bare-nick snapshot is honoured.
 * @param[in] ts Tombstone whose snapshot list to search.
 * @param[in] who Joining client to match.
 * @return Pointer to the list slot holding the match (suitable for
 *         unlinking it), or NULL if there is no snapshot for @a who.
 */
static struct RelocateSnap **relocate_snap_find(struct RelocateTombstone *ts,
                                                 struct Client *who)
{
  struct RelocateSnap **pp;

  if (IsAccount(who)) {
    const char *account = cli_user(who)->account;

    for (pp = &ts->snaps; *pp; pp = &(*pp)->next) {
      if ((*pp)->account[0] && 0 == ircd_strcmp((*pp)->account, account))
        return pp;
    }

    return NULL; /* account holders never fall back to a nick match */
  }

  {
    char who_userhost[USERLEN + HOSTLEN + 2];

    ircd_snprintf(0, who_userhost, sizeof(who_userhost), "%s@%s",
                 cli_user(who)->username, cli_user(who)->host);

    for (pp = &ts->snaps; *pp; pp = &(*pp)->next) {
      if (!(*pp)->account[0]
          && 0 == ircd_strcmp((*pp)->nick, cli_name(who))
          && 0 == ircd_strcmp((*pp)->userhost, who_userhost))
        return pp;
    }
  }

  return NULL;
}

/** Look up and CONSUME a relocation status snapshot (spec, "Status
 * preservation").
 *
 * Called from do_join() once a join to an existing channel has completed.
 * @a chptr is matched against every live tombstone's CURRENT (chain-
 * flattened) redirect target -- by name AND by creation timestamp
 * (RelocateTombstone.target_ts): a snapshot is for the channel the
 * relocation made.  When that channel empties and is destroyed, a channel
 * a stranger then creates under the name has a later timestamp, and a
 * former op of the old channel who joins it is not server-opped in it.
 * The target is matched, not any one tombstone's own name --
 * relocate_tombstone_retarget() keeps every record's ->newname pointed at
 * the newest name as renames chain, so a follower who joins the FINAL name
 * of a multi-hop chain still matches the ORIGINAL tombstone's snapshot
 * without this function needing to resolve more than one hop itself.
 *
 * This function MUST scan every matching tombstone, not stop at the first,
 * because a multi-hop chain is the ORDINARY way to get more than one live
 * record targeting the same channel.  Relocate #a -> #b, then before #b's
 * grace expires relocate #b -> #c: relocate_tombstone_retarget() repoints
 * #a's record's ->newname from #b to #c, and #b's OWN fresh record also
 * targets #c -- so #a's and #b's records BOTH have ->newname == "#c" for
 * the rest of #a's grace period.  A member who stayed in #a at the first
 * relocation, followed to #b (consuming nothing there if it already had
 * status) and stayed in #b at the second has an entry in BOTH.  The loop
 * below finds #b's record first: relocate_tombstone_add() prepends, so the
 * newest hop is always closest to the list head.  That is the desired
 * outcome, not an arbitrary tie-break -- the newer snapshot reflects this
 * member's status as of the MORE RECENT relocation, which is the one that
 * actually describes what they last held before declining to move.
 *
 * A tombstone's own (old) name can never be a match target here: the spec
 * forbids renaming a tombstone, and m_rename()/ms_rename() enforce it
 * (relocate_tombstone_find(oldname) refuses the origin, and a tombstone
 * cannot itself be @a chptr in a second relocate_execute() call), so no
 * live ts->newname is ever equal to any live ts->oldname.  A NOLINK user
 * who lands directly in the tombstone via a suppressed +L redirect
 * (m_join.c:160-163) therefore can never accidentally trigger a restore
 * there -- the lookup key it would use is the tombstone's OWN name, which
 * this invariant guarantees no record's ->newname can match.
 * @param[in] chptr Channel the join just completed against.
 * @param[in] who Joining client.
 * @param[out] flags Set to the restored CHFL_CHANOP|CHFL_HALFOP|CHFL_VOICE
 *                    subset on a hit.  Left untouched on a miss.
 * @param[out] oplevel Set to the restored oplevel on a hit.  Left untouched
 *                      on a miss.
 * @return 1 if a snapshot was found (and consumed), 0 otherwise.
 */
int relocate_snap_lookup(struct Channel *chptr, struct Client *who,
                         unsigned int *flags, int *oplevel)
{
  struct RelocateTombstone *ts;

  if (!chptr || !who || !IsUser(who))
    return 0;

  for (ts = relocate_tombstones; ts; ts = ts->next) {
    struct RelocateSnap **pp, *snap;

    if (0 != ircd_strcmp(ts->newname, chptr->chname)
        || ts->target_ts != chptr->creationtime)
      continue;

    if (!(pp = relocate_snap_find(ts, who)))
      continue; /* keep scanning -- REQUIRED, not defensive: a multi-hop
                 * rename chain ordinarily leaves more than one live record
                 * targeting the same newname (see the function comment).
                 * Do not simplify this to "return 0 on the first newname
                 * match" -- that would silently drop the older hop's
                 * snapshot whenever this member wasn't also snapshotted by
                 * the newer one. */

    snap = *pp;
    if (flags)
      *flags = snap->flags;
    if (oplevel)
      *oplevel = snap->oplevel;

    *pp = snap->next;
    MyFree(snap);
    return 1;
  }

  return 0;
}

/** Strip the tombstone marks from a channel that is being dissolved.
 *
 * The redirect goes: relocate_tombstone_channel()'s identity check keys on
 * it, and left set a dissolved channel would keep validating as somebody's
 * live tombstone.
 *
 * EXMODE_PERSIST goes too, ALWAYS -- it is the only thing keeping
 * sub1_from_channel() from collecting the channel once it is empty.  It
 * used to be cleared only when this engine had set it, and a channel that
 * was +z before its relocation (a registered channel under services'
 * persist) was left behind as an empty, opless, unregistered +z channel
 * for good.  But a +z from before the relocation was the registration's,
 * and the registration moved to the new name with everything else
 * (relocate_execute() step 1b): on the tombstone it is stale whoever set
 * it.  Every server dissolves alike, so the bit goes everywhere.
 * @param[in] chptr Channel to strip (the tombstone's own channel).
 */
static void relocate_tombstone_clear_marks(struct Channel *chptr)
{
  chptr->mode.redir[0] = '\0';
  chptr->mode.exmode &= ~EXMODE_PERSIST;
}

/** Grace-period expiry sweep: PART every remaining member of a tombstone and
 * dissolve the channel (spec, "The tombstone": at grace expiry the server
 * removes each remaining member with a server-generated PART) -- unless the
 * channel is registered at that moment, in which case the tombstone is
 * cancelled and nobody is parted (see the comment in the function).
 *
 * NOTHING here goes to servers.  Every server on the network processed the
 * same RN C marker and registered its own tombstone with its own timer, so
 * every server runs this same sweep over its own copy of the membership;
 * broadcasting the removals would double them.  The removals are therefore
 * local bookkeeping plus local-client emission only, exactly like
 * relocate_execute()'s partition.  The sweeps are simultaneous to the
 * accuracy of the network clock: every server arms for the one deadline
 * the RN carried (RelocateTombstone.expires).  Only a server that was sent
 * no deadline -- behind a server from before it travelled -- counts its own
 * grace and can be a little late.
 *
 * @param[in] ts Tombstone whose grace period has elapsed.  Already unlinked
 *               from the global list by the caller.
 */
static void relocate_tombstone_sweep(struct RelocateTombstone *ts)
{
  struct Channel *chptr;
  struct Membership *member;
  unsigned int nswept = 0;

  /* A record that waited for its channel to the end never had one: there
   * is nothing to sweep and nothing to hand back, and whatever channel is
   * under the name now is not this record's. */
  if (ts->waiting)
    return;

  /* The record can outlive its channel's identity: services DESTRUCT, a
   * services MODE -z, or a chanop stripping +L all break the tombstone
   * without going through relocate_tombstone_channel_gone(), and an
   * unrelated channel can then be created on the same name well inside the
   * grace period.  relocate_tombstone_channel() rejects all of those.  The
   * caller has ALREADY unlinked ts and disowned the timer, so returning
   * here cancels the record cleanly rather than leaving an unresolvable
   * record with a fired timer behind it.
   *
   * But cancelling the record is not enough on its own, because the most
   * likely way to get here is ONE unprivileged command.  `MODE #old -L` has
   * no privilege gate beyond ordinary chanop (channel.c:5021-5023 dispatches
   * straight into mode_parse_redir()), and it clears mode.redir --
   * failing the identity check while leaving EXMODE_PERSIST set.  And EXMODE_PERSIST is exactly the bit no ordinary user can undo:
   * channel.c:5094-5097 ignores 'z' unless the source is a service or comes
   * from a service's server.  So a chanop typing -L on a tombstone would
   * strand a channel that no member count can ever collect -- a permanent
   * leak, reachable on purpose.
   *
   * So reclaim the bit -- always, as the dissolve proper does
   * (relocate_tombstone_clear_marks()): a +z this engine set was taken
   * unilaterally, on the struct and never on the wire, and is handed back
   * the same way; a +z from before the relocation belonged to a
   * registration that has moved to the new name.  The one channel left
   * alone is one that is REGISTERED now: its persist flag is services'
   * business again.
   *
   * What is NOT done here is the sweep: a channel that failed
   * authentication may be an unrelated channel wearing the old name, and
   * parting its members would be exactly the wrong-channel damage the
   * identity check exists to prevent.  Members of a de-tombstoned channel
   * simply stay where they are -- which is why the reclaim is reported to
   * operators rather than only to the debug log. */
  if (!(chptr = relocate_tombstone_channel(ts))) {
    struct Channel *stray = FindChannel(ts->oldname);

    log_write(LS_SYSTEM, L_WARNING, 0,
              "relocate: tombstone %s -> %s no longer authenticates at grace "
              "expiry (%s); record cancelled without sweeping",
              ts->oldname, ts->newname,
              !stray ? "channel is gone"
                : !(stray->mode.exmode & EXMODE_PERSIST) ? "+z was cleared"
                : !stray->mode.redir[0] ? "+L was cleared"
                : "redirect was retargeted");

    if (stray && (stray->mode.exmode & EXMODE_PERSIST)
        && !(stray->mode.mode & MODE_REGISTERED)) {
      stray->mode.exmode &= ~EXMODE_PERSIST;

      sendto_opmask_butone(0, SNO_OLDSNO,
                           "Relocation tombstone %s (-> %s) lost its redirect "
                           "before its grace period expired; the "
                           "persist flag has been reclaimed so the channel can "
                           "be collected normally.  %u member%s left in place "
                           "-- they were NOT parted, because the channel no "
                           "longer authenticates as this tombstone.",
                           ts->oldname, ts->newname, stray->users,
                           (stray->users == 1) ? "" : "s");

      /* Same reason the sweep proper needs this (see the tail of this
       * function): every removal that happened while the bit was set took
       * sub1_from_channel()'s persist early return, so an already-empty
       * channel has nothing scheduled for it.  Mirrors what MODE -z itself
       * does for an empty channel (channel.c, mode_parse 'z').  May free
       * stray. */
      if (!stray->members)
        sub1_from_channel(stray);
    }

    return;
  }

  /* The channel is this tombstone -- and it is REGISTERED: services have
   * registered the old name inside the grace.  Sweeping it would part
   * everybody, the services bot included, and destroy a registered
   * channel.  So the tombstone is cancelled instead: nobody is parted, the
   * redirect is withdrawn (a registered channel that sends every joiner
   * elsewhere is not usable), the record is dropped (the caller has
   * unlinked it), and the channel is an ordinary registered channel again.
   * +z is left alone: on a registered channel it is services' to keep or
   * clear.
   *
   * The +R is looked at HERE, at the deadline, and never when it arrives
   * (2026-11-11, a bed run).  A channel registered and relocated within
   * one second had services' MODE +R still on its way: one server applied
   * it before the RN -- its new channel inherited +R, its tombstone had
   * it stripped -- and another executed the RN first and then put +R on
   * what was by then the tombstone.  A stray +R like that and a
   * deliberate registration of the old name look the same when the MODE
   * arrives; cancelling on arrival would cancel the tombstone on the
   * second server only, for good.  At the deadline every server reads the
   * same channel at the same moment, and services have had the whole
   * grace to take a stray +R back.  Nothing goes on the wire: each server
   * does this from its own copy of the channel. */
  if (chptr->mode.mode & MODE_REGISTERED) {
    relocate_withdraw_redirect(chptr);
    ts->oldchan = NULL;

    log_write(LS_SYSTEM, L_INFO, 0,
              "relocate: tombstone %s -> %s is registered at its deadline; "
              "cancelled, %u member%s left in place",
              ts->oldname, ts->newname, chptr->users,
              (chptr->users == 1) ? "" : "s");
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

/** End a tombstone record -- the ONE way a record goes other than by its
 * own timer expiring (RelocateTombstone, "Lifetime").
 *
 * In order:
 * 1. The record is unlinked, so that nothing below can find it again.
 *    That is what makes the rest safe to re-enter: a sweep ends in
 *    destruct_channel(), which calls relocate_tombstone_channel_gone(),
 *    which looks the dying channel's record up by name -- and must not
 *    find the record that is being ended.
 * 2. With @a dissolve, the deadline's work is done here and now
 *    (relocate_tombstone_sweep(): sweep, or cancel when the channel is
 *    registered or no longer the tombstone).  The record is intact while
 *    it runs.
 * 3. The record is freed by whoever owns it:
 *    - RELOCATE_TIMER_NONE: nobody else; freed here, with its snapshots.
 *    - RELOCATE_TIMER_ARMED: the event engine holds the embedded timer.
 *      timer_del() takes it out of the queue and generates ET_DESTROY
 *      synchronously, and relocate_tombstone_expire_cb()'s ET_DESTROY
 *      case frees the record.  No ET_EXPIRE can follow, so the sweep is
 *      not repeated.
 *    - RELOCATE_TIMER_FIRING: this is the record whose ET_EXPIRE is on
 *      the stack.  Its callback has unlinked it and is doing the sweep
 *      itself, and the engine generates ET_DESTROY when the callback
 *      returns.  Nothing is done here -- not even the sweep; timer_del()
 *      would be a no-op on a timer in dispatch, and a free would leave
 *      the engine with freed memory.  (Not reachable today: an unlinked
 *      record cannot be looked up.  Kept so that it cannot become a
 *      double free.)
 *
 * @a ts must not be used after this returns, and the tombstone's channel
 * may have been freed by the sweep.
 * @param[in] ts Record to end.
 * @param[in] dissolve Non-zero to do the deadline's work first; zero to
 *                     drop the record and touch no channel.
 */
static void relocate_tombstone_end(struct RelocateTombstone *ts, int dissolve)
{
  if (!ts || ts->timer_state == RELOCATE_TIMER_FIRING)
    return;

  relocate_tombstone_unlink(ts);

  if (dissolve)
    relocate_tombstone_sweep(ts);

  if (ts->timer_state == RELOCATE_TIMER_ARMED) {
    timer_del(&ts->timer); /* -> ET_DESTROY -> MyFree(ts), synchronously */
  } else {
    relocate_snap_free_list(ts->snaps);
    ts->snaps = NULL;
    MyFree(ts);
  }
}

/** A channel has been renamed by a classic RN from the network: if it was
 * a tombstone, its record follows it.
 *
 * No server lets its own users rename a tombstone (m_rename()), but an RN
 * that does arrives all the same -- from a server without that refusal, or
 * from services -- and every server applies it, so this one has to as
 * well.  The record is keyed by the tombstone's name; left under the old
 * one it would point at nothing, expire as "channel is gone", and the
 * renamed channel would keep +z and +L for good, with members nobody
 * parts.  Re-keyed, everything the record stands for carries on under the
 * new name: the channel is still redirected, a follower is still restored
 * (snapshots are bound to the TARGET, which has not changed), and it is
 * dissolved at the same deadline.  Every server does the same from the
 * RN alone.  The alternative -- cancelling the tombstone at the rename --
 * would turn a channel whose community has left into a live one again, on
 * the word of a message that says nothing of the kind.
 *
 * The record is not freed, so its timer is not touched.
 * @param[in] oldname The name the channel had.
 * @param[in] chptr The channel under its new name (rename_channel() may
 *                  have reallocated it).
 */
static void relocate_tombstone_renamed(const char *oldname,
                                       struct Channel *chptr)
{
  struct RelocateTombstone *ts, *stale;

  if (!(ts = relocate_tombstone_find(oldname)))
    return;

  /* A record left under the new name describes a channel that is not
   * there any more (the name was free for this rename): drop it rather
   * than have two records answer to one name. */
  if ((stale = relocate_tombstone_find_any(chptr->chname)) && stale != ts)
    relocate_tombstone_end(stale, 0);

  ircd_strncpy(ts->oldname, chptr->chname, sizeof(ts->oldname));
  ts->oldchan = chptr;

  log_write(LS_SYSTEM, L_INFO, 0,
            "relocate: tombstone %s (-> %s) was renamed to %s; its record "
            "follows it", oldname, ts->newname, ts->oldname);
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

  /* Cache ->next before the removal: relocate_tombstone_end() frees ts
   * synchronously, the same reason pending_rename_client_exit() caches it.
   * The record whose own sweep is destroying this channel is not on the
   * list (relocate_tombstone_end() and the timer callback both unlink
   * first), so it is never ended a second time from here. */
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

    /* A record waiting for its channel is not this channel's. */
    if (ts->waiting)
      continue;

    log_write(LS_DEBUG, L_DEBUG, 0,
              "relocate_tombstone_channel_gone: %s -> %s retired early "
              "(channel destroyed with %Tu seconds of grace left)",
              ts->oldname, ts->newname,
              (ts->expires > TStime()) ? (ts->expires - TStime()) : 0);

    relocate_tombstone_end(ts, 0); /* ts is freed by this call */
  }
}

/** Timer callback for a tombstone's deadline.
 *
 * ts's struct Timer is embedded in ts, so the same free-once discipline as
 * pending_rename_timeout_cb() applies: timer_run() keeps touching the
 * generator after ET_EXPIRE returns, so ET_EXPIRE may only make ts
 * unreachable (unlink, RELOCATE_TIMER_FIRING) and do the deadline's work.
 * ET_DESTROY -- which fires automatically right after ET_EXPIRE, or
 * synchronously from relocate_tombstone_end()'s timer_del() -- is the
 * single place a record with a timer is freed.
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
    /* Unlink BEFORE the sweep.  The sweep ends in destruct_channel(),
     * which calls relocate_tombstone_channel_gone(), which walks the
     * record list for this very channel's name: found there, this record
     * would be handed to relocate_tombstone_end() from inside its own
     * callback.  That function refuses a FIRING record, so it would not
     * be freed twice -- but unlinked, it is simply not found.
     *
     * Do NOT call timer_del() here: it returns early on a timer in
     * dispatch (GEN_MARKED) without generating ET_DESTROY; timer_run()
     * generates it once this returns. */
    relocate_tombstone_unlink(ts);
    ts->timer_state = RELOCATE_TIMER_FIRING;

    relocate_tombstone_sweep(ts);
    break;

  case ET_DESTROY:
    /* The only place a record with a timer is freed -- see the function
     * comment.  Any snapshot entries still on the list belong to members
     * who never followed within the grace period; per spec ("Status
     * preservation") they simply lose the restore now. */
    relocate_snap_free_list(ts->snaps);
    ts->snaps = NULL;
    MyFree(ts);
    break;

  default:
    break;
  }
}

/** This server's own deadline for a relocation executed now: the one the
 * issuing server puts in the RN, and the fallback of a receiver that was
 * sent none.
 * @return Network time.
 */
static time_t relocate_local_deadline(void)
{
  return relocate_expiry_from_grace(TStime(),
                                    feature_int(FEAT_RELOCATE_GRACE));
}

/** Register a tombstone under a name.  The record is linked but its timer
 * is NOT armed: the caller fills the record in and then calls
 * relocate_tombstone_settle().
 * @param[in] oldname The tombstone's name.
 * @param[in] newname Redirect target.
 * @param[in] expires The deadline, network time.
 * @return The new tombstone, or NULL on allocation failure.
 */
static struct RelocateTombstone *
relocate_tombstone_add_named(const char *oldname, const char *newname,
                             time_t expires)
{
  struct RelocateTombstone *ts;

  /* One record per name.  A record still under this name is not this
   * channel's live tombstone -- a relocation of a live tombstone never
   * comes here (ms_rename() hands it to relocate_again()) -- so it is a
   * leftover: the record of a tombstone that was cancelled (its +L
   * removed) and is waiting out its deadline, or one that waited for a
   * channel.  It goes; its timer is dealt with by
   * relocate_tombstone_end(). */
  if ((ts = relocate_tombstone_find_any(oldname)))
    relocate_tombstone_end(ts, 0);

  ts = (struct RelocateTombstone *)MyMalloc(sizeof(struct RelocateTombstone));
  if (!ts)
    return NULL;

  memset(ts, 0, sizeof(*ts));
  ircd_strncpy(ts->oldname, oldname, sizeof(ts->oldname));
  ircd_strncpy(ts->newname, newname, sizeof(ts->newname));
  ts->expires = expires;

  ts->next = relocate_tombstones;
  relocate_tombstones = ts;

  log_write(LS_DEBUG, L_DEBUG, 0,
            "relocate_tombstone_add: %s -> %s expires=%Tu",
            ts->oldname, ts->newname, ts->expires);

  return ts;
}

/** Register a tombstone for @a chptr -- relocate_tombstone_add_named()
 * for a channel that is here.
 * @param[in] chptr Channel being tombstoned (keeps its own name).
 * @param[in] newname Redirect target.
 * @param[in] expires The deadline, network time.
 * @return The new tombstone, or NULL on allocation failure.
 */
static struct RelocateTombstone *
relocate_tombstone_add(struct Channel *chptr, const char *newname,
                       time_t expires)
{
  struct RelocateTombstone *ts =
    relocate_tombstone_add_named(chptr->chname, newname, expires);

  if (ts)
    ts->oldchan = chptr;

  return ts;
}

/** Arm (or re-arm) a tombstone's timer for its deadline -- or, when the
 * deadline is already here, do its work on the spot and end the record.
 *
 * The deadline is network time; the event loop runs on this server's own
 * clock, so the timer is set for the deadline less TSoffset -- the same
 * instant.  (A SETTIME that moves TSoffset later does not move a timer
 * that is already armed.)
 *
 * A deadline that is now or past -- a relocation with no grace, an RN
 * that arrived after its deadline, or a record re-armed after its
 * deadline went by with its timer still queued -- is dissolved here and
 * not through a timer that is already due, so that there is no redirect
 * window at all: a due timer fires only after the event loop has dealt
 * with every line it has already read, and a JOIN of the old name among
 * them would still be forwarded.  relocate_tombstone_end() frees the
 * record whichever state its timer is in.
 * @param[in] ts Tombstone, linked.
 * @return 1 when the record lives on with its timer armed; 0 when it was
 *         dissolved: @a ts is then gone and its channel may be too.
 */
static int relocate_tombstone_settle(struct RelocateTombstone *ts)
{
  if (ts->expires <= TStime()) {
    relocate_tombstone_end(ts, 1);
    return 0;
  }

  if (ts->timer_state == RELOCATE_TIMER_ARMED) {
    timer_chg(&ts->timer, TT_ABSOLUTE, ts->expires - TSoffset);
  } else if (ts->timer_state == RELOCATE_TIMER_NONE) {
    timer_add(timer_init(&ts->timer), relocate_tombstone_expire_cb,
              (void *)ts, TT_ABSOLUTE, ts->expires - TSoffset);
    ts->timer_state = RELOCATE_TIMER_ARMED;
  }

  return 1;
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

/** Take a tombstone's redirect off its channel and tell the remaining
 * LOCAL members -- the counterpart of relocate_announce_redirect(), for a
 * tombstone that is cancelled at its deadline because it is registered.
 * Channel-only for the same reason: every server does the same from its
 * own copy of the channel at the same deadline.  -L takes no parameter
 * and modebuf_mode_string() keeps no reference to the string for it, so
 * the redirect is cleared in place afterwards (as m_clearmode.c does).
 * @param[in] chptr The tombstone channel.
 */
static void relocate_withdraw_redirect(struct Channel *chptr)
{
  struct ModeBuf mbuf;

  modebuf_init(&mbuf, &me, NULL, chptr, MODEBUF_DEST_CHANNEL);
  modebuf_mode_string(&mbuf, MODE_DEL | MODE_REDIRECT, chptr->mode.redir, 0);
  modebuf_flush(&mbuf);

  chptr->mode.redir[0] = '\0';
}

/** Chain-flattening: a rename of a channel that is itself some tombstone's
 * redirect target repoints that tombstone at the newest name, so a join of
 * the oldest name never needs multi-hop resolution (spec, "Multiple
 * renames").  Also how every tombstone that pointed at the loser of a
 * crossing comes to point at the winner (relocate_again()).
 * @param[in] oldtarget Name that just stopped being a valid target.
 * @param[in] newtarget Name it became.
 * @param[in] target_ts Creation timestamp of the channel under
 *                      @a newtarget, which the repointed records'
 *                      snapshots are bound to from now on
 *                      (RelocateTombstone.target_ts).
 */
static void relocate_tombstone_retarget(const char *oldtarget,
                                        const char *newtarget,
                                        time_t target_ts)
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
    ts->target_ts = target_ts;

    ircd_strncpy(chptr->mode.redir, ts->newname, sizeof(chptr->mode.redir));
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

/** Snapshot one member's status onto the tail of a snapshot list, for a
 * grace-period follow-join restore (spec, "Status preservation").
 * Read-only with respect to the membership list.  Allocation failure is
 * not fatal: a missing snapshot costs one member the optional restore.
 * @param[in,out] tail_p Tail pointer of the list being built.
 * @param[in] member The membership (not an alias shadow, not a zombie).
 */
static void relocate_snap_take(struct RelocateSnap ***tail_p,
                               struct Membership *member)
{
  struct Client *user = member->user;
  struct RelocateSnap *snap =
    (struct RelocateSnap *)MyMalloc(sizeof(struct RelocateSnap));

  if (!snap)
    return;

  memset(snap, 0, sizeof(*snap));
  if (IsAccount(user))
    ircd_strncpy(snap->account, cli_user(user)->account,
                 sizeof(snap->account));
  ircd_strncpy(snap->nick, cli_name(user), sizeof(snap->nick));
  /* Populated regardless of IsAccount(): harmless for an account holder
   * (relocate_snap_find() never reads nick/userhost on that path), and
   * this is the only point that ever sees this member's identity. */
  ircd_snprintf(0, snap->userhost, sizeof(snap->userhost), "%s@%s",
                cli_user(user)->username, cli_user(user)->host);
  snap->flags = member->status & (CHFL_CHANOP | CHFL_HALFOP | CHFL_VOICE);
  snap->oplevel = OpLevel(member);
  snap->next = NULL;

  **tail_p = snap;
  *tail_p = &snap->next;
}

/** Snapshot every member of a channel that has just become a tombstone
 * without anybody being moved out of it (the loser of a crossing).
 * @param[in] chptr The channel.
 * @return The list (may be NULL).
 */
static struct RelocateSnap *relocate_snap_members(struct Channel *chptr)
{
  struct RelocateSnap *head = NULL, **tail = &head;
  struct Membership *member;

  for (member = chptr->members; member; member = member->next_member)
    if (!IsMemberAlias(member) && !IsZombie(member))
      relocate_snap_take(&tail, member);

  return head;
}

/** Tell one LOCAL member who stays in a tombstone that the channel has
 * moved: RELOCATE when its connection negotiated evilnet/channel-relocate,
 * the fallback NOTICE otherwise.  It must NOT get a RENAME: that message
 * asserts "your membership now points at the new name" and would
 * desynchronise a client that honours it.
 * @param[in] source Whose relocation it is (the RELOCATE's source).
 * @param[in] user Local member to tell.
 * @param[in] chptr The tombstone.
 * @param[in] oldname Its name.
 * @param[in] newname Where the channel went.
 * @param[in] reason Reason (may be an empty string).
 * @param[in] expires The tombstone's deadline, network time.
 */
static void relocate_notify_stayer(struct Client *source, struct Client *user,
                                   struct Channel *chptr, const char *oldname,
                                   const char *newname, const char *reason,
                                   time_t expires)
{
  char reasonpart[TOPICLEN + 4];

  if (CapActive(user, CAP_EVILNET_RELOCATE)) {
    sendcmdto_one(source, CMD_RELOCATE, user, "%s %s :%s",
                  oldname, newname, reason);
    return;
  }

  /* Exactly the spec's fallback shape.  reasonpart carries the
   * " (<reason>)" parenthetical, or is empty when there is no reason -- an
   * empty "()" would read as a rendering bug and inventing a placeholder
   * reason would put words in the issuer's mouth.  The minutes are what
   * is left until the deadline. */
  if (*reason)
    ircd_snprintf(0, reasonpart, sizeof(reasonpart), " (%s)", reason);
  else
    reasonpart[0] = '\0';

  sendcmdto_one(&his, CMD_NOTICE, user,
                "%H :%s has moved to %s%s. Join %s to follow; this "
                "channel closes in %d minutes.",
                chptr, oldname, newname, reasonpart, newname,
                (int)((expires > TStime() ? expires - TStime() : 0) / 60));
}

/** Take off a tombstone what would keep it from working as one, or
 * what is not a dissolving channel's to keep: the limit (with one, the
 * +L redirect fires only when the channel is full -- relocate_execute()
 * step 1b) and the channel passwords.  Silent.
 * @param[in] chptr The tombstone.
 */
static void relocate_tombstone_normalise(struct Channel *chptr)
{
  /* The limit, like the redirect, is its parameter: there is no
   * MODE_LIMIT bit in a channel's mode.mode to clear. */
  chptr->mode.limit = 0;
  chptr->mode.apass[0] = '\0';
  chptr->mode.upass[0] = '\0';
}

/** Give a channel the marks of a tombstone: persistent, redirecting to
 * @a target, and without the things that belong to the community that has
 * left -- see relocate_execute() steps 1b and 2 for each.  Silent: nothing
 * here is announced or sent; every server does the same from the same
 * message.
 * @param[in] chptr Channel that becomes a tombstone.
 * @param[in] target Where it redirects.
 * @param[in] registration_moved Non-zero when this server has moved the
 *            channel's registration (+R) to another channel and it is
 *            stripped here: a relocation executed from an RN.  Zero for
 *            a tombstone learned from a burst announcement, where +R is
 *            whatever the bursts say and decides at the deadline.
 */
static void relocate_mark_tombstone(struct Channel *chptr, const char *target,
                                    int registration_moved)
{
  if (registration_moved)
    chptr->mode.mode &= ~MODE_REGISTERED;
  relocate_tombstone_normalise(chptr);

  /* +z is a bit of mode.exmode; +L is mode.redir and nothing else (see
   * relocate_tombstone_channel()). */
  chptr->mode.exmode |= EXMODE_PERSIST;
  ircd_strncpy(chptr->mode.redir, target, sizeof(chptr->mode.redir));
}

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
 * @a chptr is NOT renamed -- it survives as the tombstone, until the
 * deadline.
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
 * @param[in] expires The tombstone's deadline, network time.  When it is
 *                    now or past the tombstone is dissolved before this
 *                    returns, and @a chptr may have been freed.
 * @return 0 on success, -1 on bad/oversized name or allocation failure,
 *         -2 if @a newname is already in use.
 */
static int relocate_execute(struct Client *sptr, struct Channel *chptr,
                            const char *oldname, const char *newname,
                            const char *reason, time_t expires)
{
  struct Channel *newchan;
  struct Membership *member;
  struct RelocateMover *movers;
  struct RelocateSnap *snaphead = NULL, **snaptail = &snaphead;
  struct RelocateTombstone *ts;
  char newname_buf[CHANNELLEN + 1];
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

  /* A record still under this channel's name is a leftover: a relocation
   * of a LIVE tombstone never comes here (relocate_again()), so this is a
   * tombstone that was cancelled -- its +L removed -- and whose record is
   * waiting out its deadline to hand +z back.  Hand it back now, by the
   * rule that record would have applied (not from a channel that is
   * registered), so that the new channel made below does not inherit a
   * tombstone's persist flag as if it were the channel's own. */
  if ((ts = relocate_tombstone_find(chptr->chname))) {
    if (!(chptr->mode.mode & MODE_REGISTERED))
      chptr->mode.exmode &= ~EXMODE_PERSIST;
    relocate_tombstone_end(ts, 0);
  }

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
   * engine off the marker, so the bit clears everywhere in lockstep.
   * (relocate_mark_tombstone() in step 2 does the stripping.)
   *
   * The limit goes too, and this one is load-bearing rather than tidy.
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
   * are about to part.
   *
   * Whether the channel was +z already does not matter: the dissolve
   * clears the bit either way (relocate_tombstone_clear_marks()). */
  relocate_mark_tombstone(chptr, newname_buf, 1);

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

    /* Snapshot every member who STAYS, for a grace-period follow-join
     * restore (spec, "Status preservation").  The mover -- the issuer --
     * gets none: it is moved with its status, so its snapshot was used the
     * moment the relocation ran, and one left behind was never consumed --
     * deopped or kicked in the new channel, the issuer got its op back
     * with a PART and a JOIN.  Every server runs this pass and leaves the
     * issuer out alike.  Read-only with respect to the membership list, so
     * it is safe in this same pass.  Allocation failure here is non-fatal
     * -- unlike the mover array above, a missing snapshot only costs one
     * member the optional grace-period restore, not the relocation
     * itself. */
    if (user != sptr)
      relocate_snap_take(&snaptail, member);

    /* Movers: the issuer only -- issuing the rename IS consent.  Every
     * other member stays in the tombstone and follows by their own JOIN
     * (see docs/specs/channel-relocate.md, design "D"); the per-member
     * snapshot captured above is what restores their status on follow. */
    if (user == sptr) {
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

    relocate_notify_stayer(sptr, user, chptr, oldname, newname_buf, reason,
                           expires);
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

  ts = relocate_tombstone_add(chptr, newname_buf, expires);

  if (ts) {
    ts->snaps = snaphead;
    ts->target_ts = newchan->creationtime;
  } else {
    /* Allocation failure inside relocate_tombstone_add() itself -- there
     * is no record to attach these to.  Same "life goes on without
     * grace tracking" contract Task 3 already accepted for this failure;
     * just don't leak the list built above. */
    relocate_snap_free_list(snaphead);
  }

  /* A tombstone that pointed at oldname must now point at newname_buf --
   * our own fresh tombstone points at newname_buf already, so it can never
   * match here. */
  relocate_tombstone_retarget(oldname, newname_buf, newchan->creationtime);

  log_write(LS_DEBUG, L_DEBUG, 0,
            "relocate_execute: %s -> %s by %#C (%d moved, %d stayed)",
            oldname, newname_buf, sptr, nmovers, nmembers - nmovers);

  /* Last: a deadline that is already here dissolves the tombstone on the
   * spot, and that can free chptr (and frees ts). */
  if (ts)
    relocate_tombstone_settle(ts);

  return 0;
}

/** Find a client's own membership of a channel: not an alias shadow, not
 * a zombie.
 */
static struct Membership *relocate_member(struct Channel *chptr,
                                          struct Client *who)
{
  struct Membership *member;

  for (member = chptr->members; member; member = member->next_member)
    if (member->user == who && !IsMemberAlias(member) && !IsZombie(member))
      return member;

  return NULL;
}

/** Make a channel "from a tombstone": the second new channel a channel
 * that was relocated twice ends up with.
 *
 * It gets the state the tombstone has AS AN ORDINARY CHANNEL -- modes,
 * key, creation timestamp, topic, ban lists -- and nothing of what makes
 * the tombstone one: no +z, no +L, no redirect.  (Before this, the second
 * relocation ran relocate_execute() on the tombstone and its plain copy
 * of struct Mode put the tombstone's +z, +L and old redirect into the
 * second channel.)  What the first relocation MOVED off the tombstone --
 * the limit, the registration, the channel passwords -- is not on it to
 * be copied; relocate_again() moves those between the two new channels
 * where that is needed.
 * @param[in] sptr The issuer (get_channel()'s client argument).
 * @param[in] tomb The tombstone.
 * @param[in] name Name of the channel to make; must not exist.
 * @return The new channel, or NULL.
 */
static struct Channel *relocate_channel_from_tombstone(struct Client *sptr,
                                                       struct Channel *tomb,
                                                       const char *name)
{
  struct Channel *newchan;
  char name_buf[CHANNELLEN + 1];

  ircd_strncpy(name_buf, name, sizeof(name_buf));
  if (!(newchan = get_channel(sptr, name_buf, CGT_CREATE)))
    return NULL;

  newchan->mode = tomb->mode;
  newchan->mode.exmode &= ~EXMODE_PERSIST;
  newchan->mode.redir[0] = '\0';

  newchan->creationtime = tomb->creationtime;
  newchan->topic_time = tomb->topic_time;
  ircd_strncpy(newchan->topic, tomb->topic, sizeof(newchan->topic));
  ircd_strncpy(newchan->topic_nick, tomb->topic_nick,
               sizeof(newchan->topic_nick));
  relocate_copy_bans(&newchan->banlist, tomb->banlist);
  relocate_copy_bans(&newchan->exceptlist, tomb->exceptlist);

  return newchan;
}

/** Move the issuer of a relocation out of a tombstone into a channel, the
 * way relocate_execute() moves its mover: with its status, silently on
 * the network (the RN implies the move on every server), its departure
 * shown to the local members who stay, and its snapshot in the
 * tombstone's record consumed -- it has been moved with its status and
 * has nothing to regain.
 * @param[in] sptr The issuer (a primary, never an alias).
 * @param[in] ts The tombstone's record.
 * @param[in] from The tombstone.
 * @param[in] to Where the issuer goes.
 * @param[in] reason Reason (may be an empty string).
 * @return 1 when the issuer was moved, 0 when it is not a member of
 *         @a from (or already one of @a to) and nothing was done.
 */
static int relocate_move_issuer(struct Client *sptr,
                                struct RelocateTombstone *ts,
                                struct Channel *from, struct Channel *to,
                                const char *reason)
{
  struct Membership *member;
  struct RelocateSnap **pp;
  unsigned int status;
  int oplevel;

  if (!IsUser(sptr) || !(member = relocate_member(from, sptr)))
    return 0;
  if (relocate_member(to, sptr))
    return 0;

  /* CHFL_DELAYED rides along, as in relocate_execute(). */
  status = member->status & (CHFL_CHANOP | CHFL_HALFOP | CHFL_VOICE
                             | CHFL_DELAYED);
  oplevel = OpLevel(member);

  if ((pp = relocate_snap_find(ts, sptr))) {
    struct RelocateSnap *snap = *pp;

    *pp = snap->next;
    MyFree(snap);
  }

  /* Before the add: add_user_to_channel() is what emits the alias JOIN
   * echo, so the alias's PART of the old name has to precede it. */
  relocate_part_local_aliases(sptr, from, from->chname, to->chname, reason);

  add_user_to_channel(to, sptr, status, oplevel);
  remove_user_from_channel(sptr, from);         /* +z: from stays */

  /* A member the channel never saw JOIN is not announced leaving. */
  if (!(status & (CHFL_ZOMBIE | CHFL_DELAYED)))
    sendcmdto_channel_butserv_butone(sptr, CMD_PART, from, NULL, 0,
                                     "%H :Moved to %s", from, to->chname);

  if (MyUser(sptr))
    send_rename_to_member(sptr, sptr, to, from->chname, reason);

  return 1;
}

/** Fill in the record of a channel that has just become a tombstone
 * WITHOUT anybody being moved out of it -- the loser of a crossing, a
 * tombstone learned from a burst announcement: snapshot its members (so
 * that they can regain their status if they follow) and tell the local
 * ones, who have not been told by any relocation executed here.
 * @param[in] ts The channel's record.
 * @param[in] chptr The tombstone.
 * @param[in] source Source of the RELOCATE a member with the capability
 *                   gets: the issuer when one is known, else &his.
 * @param[in] reason Reason (may be an empty string).
 * @param[in] announce Non-zero to announce the redirect (MODE +L) to the
 *                     local members as well; zero when they have been
 *                     shown it already (a BURST's own mode changes).
 */
static void relocate_tombstone_populate(struct RelocateTombstone *ts,
                                        struct Channel *chptr,
                                        struct Client *source,
                                        const char *reason, int announce)
{
  struct Membership *member;

  relocate_snap_free_list(ts->snaps);
  ts->snaps = relocate_snap_members(chptr);
  ts->oldchan = chptr;

  for (member = chptr->members; member; member = member->next_member) {
    if (IsMemberAlias(member) || IsZombie(member) || !MyUser(member->user))
      continue;
    relocate_notify_stayer(source, member->user, chptr, chptr->chname,
                           ts->newname, reason, ts->expires);
  }

  if (announce)
    relocate_announce_redirect(chptr);
}

/** Turn a channel into the tombstone of a relocation that lost a
 * crossing: mark it, record it, and relocate_tombstone_populate() it.
 * @param[in] source Source of the RELOCATE a local member with the
 *                   capability gets.
 * @param[in] chptr The losing channel.
 * @param[in] winner Name of the winning channel.
 * @param[in] target_ts The winner's creation timestamp.
 * @param[in] family Name of the old channel both relocations were of.
 * @param[in] reason Reason of the winning relocation.
 * @param[in] expires The crossing's deadline.
 * @param[in] registration_moved See relocate_mark_tombstone().
 */
static void relocate_tombstone_loser(struct Client *source,
                                     struct Channel *chptr, const char *winner,
                                     time_t target_ts, const char *family,
                                     const char *reason, time_t expires,
                                     int registration_moved)
{
  struct RelocateTombstone *ts;

  relocate_mark_tombstone(chptr, winner, registration_moved);

  if ((ts = relocate_tombstone_add(chptr, winner, expires))) {
    ts->target_ts = target_ts;
    ircd_strncpy(ts->family, family, sizeof(ts->family));
    relocate_tombstone_populate(ts, chptr, source, reason, 1);
  } else
    relocate_announce_redirect(chptr);
}

/** Give one deadline to the records of a crossing -- the old channel's
 * and every loser's -- and settle each: when the deadline is already
 * here, all of them are dissolved now.
 * @param[in] oldname The old channel both relocations were of.
 * @param[in] deadline The crossing's deadline.
 */
static void relocate_family_settle(const char *oldname, time_t deadline)
{
  struct RelocateTombstone *rec, *next;

  /* ->next is read first: relocate_tombstone_settle() can free the record
   * (only that one: a sweep destroys only its own channel, whose record
   * is already unlinked). */
  for (rec = relocate_tombstones; rec; rec = next) {
    next = rec->next;

    if (0 != ircd_strcmp(rec->oldname, oldname)
        && 0 != ircd_strcmp(rec->family, oldname))
      continue;

    rec->expires = deadline;
    relocate_tombstone_settle(rec);
  }
}

/** A relocation of a channel that is ALREADY a live tombstone here: the
 * same channel was relocated twice, by two servers that had not heard of
 * each other's relocation yet (within the delay of a link, or on the two
 * sides of a netsplit).  Each has executed its own; this server now has
 * to bring the two together, and so that every server ends in the same
 * state whichever of the two it heard first, everything here is decided
 * from the two messages alone:
 *
 * - Same new name twice: one relocation, executed by two issuers.  The
 *   second issuer is moved into the new channel beside the first.
 * - Two new names: the one that sorts FIRST under the casemapping wins
 *   (relocate_name_cmp()).  The old channel redirects to the winner, and
 *   so does every earlier tombstone that pointed at the loser.  The
 *   losing new channel becomes a tombstone redirecting to the winner as
 *   well, with its issuer in it -- who can follow from there with a JOIN
 *   like anybody else.
 *
 *   The server that heard the WINNER first makes the loser's channel
 *   from the tombstone, moves the loser's issuer into it and marks it.
 *   The server that heard the LOSER first makes the winner's channel
 *   from the tombstone, hands it what its own relocation had moved to
 *   the loser's channel (the limit, the registration, the channel
 *   passwords, a +z the old channel had before it all), moves the
 *   winner's issuer into it, and marks the loser's channel.  Both end
 *   with the same three channels.
 *
 * - One deadline for all of it: the latest of the deadlines involved
 *   (relocate_deadline_merge()), shared by the old channel's record and
 *   every loser's (RelocateTombstone.family), in whatever order they
 *   arrive.
 * - Snapshots: the old channel's record keeps its own (its members can
 *   regain their status in the winner; the record's target is now the
 *   winner).  A loser's record snapshots the loser's members, its issuer
 *   among them.  An issuer moved here has its snapshot consumed, as in
 *   relocate_execute().
 *
 * A chain is not this: in "#a to #b, then #b to #c" the second
 * relocation is of #b, which is nobody's tombstone but a tombstone's
 * TARGET; relocate_execute() handles it and flattens.  This function is
 * entered only for an RN whose OLD name is a live tombstone.
 *
 * Nothing is sent to servers here; the caller relays the RN as it came,
 * and every server works the same thing out.
 *
 * When the name a new channel would get is taken here by an unrelated
 * channel, that step is not applied and the operators are told, as for a
 * first relocation.
 *
 * The old channel and the losing one may be gone when this returns (a
 * deadline already here).
 * @param[in] sptr Issuer of the incoming relocation.
 * @param[in] ts The old channel's record (live).
 * @param[in] oldchan The old channel, a tombstone.
 * @param[in] incoming New name in the incoming relocation.
 * @param[in] reason Its reason (may be an empty string).
 * @param[in] expires Its deadline, network time, already checked.
 */
static void relocate_again(struct Client *sptr, struct RelocateTombstone *ts,
                           struct Channel *oldchan, const char *incoming,
                           const char *reason, time_t expires)
{
  struct RelocateTombstone *rec;
  struct Channel *wchan, *lchan;
  char oldname[CHANNELLEN + 1];
  char current_buf[CHANNELLEN + 1];
  const char *current = current_buf;    /* the record's own copy changes */
  time_t deadline;

  if (IsUser(sptr) && IsBouncerAlias(sptr) && cli_alias_primary(sptr))
    sptr = cli_alias_primary(sptr);
  if (!reason)
    reason = "";

  ircd_strncpy(oldname, ts->oldname, sizeof(oldname));
  ircd_strncpy(current_buf, ts->newname, sizeof(current_buf));

  /* The crossing's one deadline: the later of the incoming one and the
   * old channel's -- which is already the latest of every relocation of
   * this channel heard so far, because the loop at the end of this
   * function gives it to the old channel's record and every loser's each
   * time. */
  deadline = relocate_deadline_merge(ts->expires, expires);

  if (0 == ircd_strcmp(current, incoming)) {
    /* ---- The same relocation, twice ---- */
    wchan = FindChannel(current);

    if (!wchan)
      /* Emptied and collected here since; the second issuer is in it
       * everywhere else. */
      wchan = relocate_channel_from_tombstone(sptr, oldchan, current);
    else if (wchan->creationtime != ts->target_ts)
      /* A stranger's channel under the name: not the one to put the
       * issuer in. */
      wchan = NULL;

    if (wchan)
      relocate_move_issuer(sptr, ts, oldchan, wchan, reason);

  } else if (relocate_name_cmp(incoming, current) < 0) {
    /* ---- The incoming relocation wins ---- */
    if (FindChannel(incoming)) {
      sendto_opmask_butone(0, SNO_OLDSNO,
                           "RELOCATE %s -> %s from %C NOT applied locally: "
                           "%s already exists on this server.  %s was "
                           "relocated to %s here; the network takes %s.  "
                           "The relocation has been relayed onward, so this "
                           "server is now divergent and needs manual "
                           "reconciliation.",
                           oldname, incoming, sptr, incoming, oldname,
                           current, incoming);
    } else if ((wchan = relocate_channel_from_tombstone(sptr, oldchan,
                                                        incoming))) {
      int transfer = 0;

      /* The channel this server's own (losing) relocation made -- by name
       * and creation timestamp, not one a stranger has made under the
       * name since (that one is left alone).  When it has emptied and
       * been collected here it is made again, empty: the servers that
       * heard the winner first make the loser's channel in any case, and
       * a tombstone some servers hold and others do not is swept on some
       * and not on others. */
      if ((lchan = FindChannel(current))) {
        if (lchan->creationtime == ts->target_ts)
          transfer = 1;
        else
          lchan = NULL;
      } else
        lchan = relocate_channel_from_tombstone(sptr, oldchan, current);

      if (transfer) {
        /* What relocate_execute() moved from the old channel to the new
         * one belongs to the community, and the community's channel is
         * now the winner.  relocate_tombstone_loser() strips the same
         * things off the loser (relocate_mark_tombstone()). */
        wchan->mode.mode |= lchan->mode.mode & MODE_REGISTERED;
        wchan->mode.limit = lchan->mode.limit;
        wchan->mode.exmode |= lchan->mode.exmode & EXMODE_PERSIST;
        ircd_strncpy(wchan->mode.apass, lchan->mode.apass,
                     sizeof(wchan->mode.apass));
        ircd_strncpy(wchan->mode.upass, lchan->mode.upass,
                     sizeof(wchan->mode.upass));
      }

      relocate_move_issuer(sptr, ts, oldchan, wchan, reason);

      /* The old channel, and every earlier tombstone that pointed at the
       * loser, now point at the winner. */
      relocate_tombstone_retarget(current, incoming, wchan->creationtime);

      if (lchan && !relocate_tombstone_find(lchan->chname))
        relocate_tombstone_loser(sptr, lchan, incoming, wchan->creationtime,
                                 oldname, reason, deadline, 1);
    }

  } else {
    /* ---- The incoming relocation loses ---- */
    wchan = FindChannel(current);
    lchan = FindChannel(incoming);
    rec = lchan ? relocate_tombstone_find(lchan->chname) : NULL;

    if (lchan && rec && relocate_tombstone_channel(rec) == lchan
        && 0 == ircd_strcmp(rec->newname, current)) {
      /* Already the loser's tombstone (the losing relocation heard a
       * second time): only its issuer may still have to go there. */
      relocate_move_issuer(sptr, ts, oldchan, lchan, reason);
    } else if (lchan) {
      sendto_opmask_butone(0, SNO_OLDSNO,
                           "RELOCATE %s -> %s from %C NOT applied locally: "
                           "%s already exists on this server.  The network "
                           "takes %s for %s and makes %s a tombstone "
                           "redirecting there.  The relocation has been "
                           "relayed onward, so this server is now divergent "
                           "and needs manual reconciliation.",
                           oldname, incoming, sptr, incoming, current,
                           oldname, incoming);
    } else if ((lchan = relocate_channel_from_tombstone(sptr, oldchan,
                                                        incoming))) {
      relocate_move_issuer(sptr, ts, oldchan, lchan, reason);
      relocate_tombstone_loser(sptr, lchan, current,
                               wchan ? wchan->creationtime : ts->target_ts,
                               oldname, reason, deadline, 1);
    }
  }

  relocate_family_settle(oldname, deadline);
}

/** Send a relocation on: "<sptr> RN <old> <new> C <expires> :<reason>" to
 * the IRCv3-aware links and to the rename-capable non-v3 ones (X3), which
 * get the alias source rewrite rename_forward_rcapable() does.
 * @param[in] sptr The issuer (message source).
 * @param[in] one Client whose link the IRCv3-aware broadcast skips: the
 *                issuer's own connection for a relocation executed here,
 *                the link the RN arrived on for a relay.
 * @param[in] skip Rename-capable link to skip: the link the RN arrived
 *                 on, or NULL for a relocation executed here.
 * @param[in] oldname Old channel name.
 * @param[in] newname New channel name.
 * @param[in] expires The deadline this server went by, network time.
 * @param[in] reason Reason (may be an empty string; always sent).
 */
static void relocate_propagate(struct Client *sptr, struct Client *one,
                               struct Client *skip, const char *oldname,
                               const char *newname, time_t expires,
                               const char *reason)
{
  char digits[RELOCATE_EXPIRY_BUFLEN];
  char marker[RELOCATE_MARKER_BUFLEN];

  /* "C <expires> ": the trailing space is what separates the deadline
   * from the reason's colon.  Without it the line would read
   * "RN #old #new C 1731340900:reason" and the reason would be lost in
   * the deadline. */
  relocate_expiry_format(digits, sizeof(digits), expires);
  ircd_snprintf(0, marker, sizeof(marker), "%s %s ", RELOCATE_MARKER, digits);

  sendcmdto_serv_butone_v3(sptr, CMD_RENAME, one, "%s %s %s:%s",
                           oldname, newname, marker, reason);
  rename_forward_rcapable(sptr, skip, oldname, newname, marker, reason);
}

/* ---------- The tombstone in the burst ----------
 *
 * A server that links, restarts or heals a netsplit inside a tombstone's
 * grace learns of the channel from its BURST -- "+z, +L <target>" and
 * whoever is still in it -- and from that alone it cannot tell a
 * tombstone from a persistent channel with a redirect: it would keep the
 * members and +zL for good.  So the record itself follows the channel's
 * BURST:
 *
 *     <server> RT <old> <old-creation-ts> <new> <expires>
 *     AC RT #old 1731000000 #new 1731340900
 *
 * - <old>: the tombstone.  <old-creation-ts>: its channel's creation
 *   timestamp as the sender holds it -- with the name, the channel's
 *   identity, exactly as in BURST: a receiver whose channel of that name
 *   has another timestamp holds another channel, and the announcement is
 *   not about it.
 * - <new>: where it redirects (chain-flattened; the winner, for both
 *   tombstones of a crossing).
 * - <expires>: the deadline, network time, the same field as in the RN
 *   (include/rename_proto.h).
 *
 * That is all of the record a receiver needs.  The status snapshots are
 * NOT sent: a restore is the act of one server -- the one the follower
 * joins through -- and goes out as an ordinary MODE, so it is not state
 * the network has to agree on; sending it would put a per-member list of
 * who is to be opped where on every link at every netjoin, for every
 * tombstone.  A server that builds a record from an announcement
 * snapshots the members it holds in the tombstone at that moment instead
 * (after a netsplit those are its own users, with the status they had).
 * What is lost: a former member who is no longer in the tombstone when
 * the announcement arrives (it parted, or its server restarted and it
 * reconnected) and who follows through that server joins the new channel
 * without its old status.  Services access on a registered channel is
 * not affected.
 *
 * A token of its own (TOMBSTONE, RT), not a new marker on RN: every
 * existing receiver of RN -- a fork server from before this, X3 -- reads
 * an RN whose fourth parameter is not exactly "C" as a CLASSIC rename and
 * would rename the channel, and one that is "C" as a relocation to
 * execute (move the issuer, snapshot again).  An unknown token is counted
 * and dropped by parse_server() (ServerStats->is_unco) and logged as a
 * parse error by X3's parse_line(); neither acts on it, and neither
 * relays it.
 *
 * Receiving it: relocate_announced().  Bringing a tombstone held here
 * through a BURST: relocate_tombstone_burst_lost() and _burst_done().
 *
 * Sent to IRCv3-aware links and to rename-capable links that are not
 * (X3, a relay-only server): the peers an RN goes to.  Never to a plain
 * legacy server.  Relayed by every server that understands it, as it
 * came, to the same kinds of link -- as a BURST is passed on -- whether
 * or not this server could use it.
 */

/** Is @a link a server a relocation's messages go to?
 */
static int relocate_link_wants(struct Client *link)
{
  return IsIRCv3Aware(link) || IsRenameCapable(link);
}

void relocate_burst(struct Client *cptr, struct Channel *chptr)
{
  struct RelocateTombstone *ts;
  char digits[RELOCATE_EXPIRY_BUFLEN];

  if (!relocate_link_wants(cptr))
    return;

  /* Only a LIVE tombstone: a record whose channel no longer authenticates
   * (its +L was removed) is waiting to hand +z back and describes nothing
   * the other side should build. */
  if (!(ts = relocate_tombstone_find(chptr->chname))
      || relocate_tombstone_channel(ts) != chptr)
    return;

  relocate_expiry_format(digits, sizeof(digits), ts->expires);
  sendcmdto_one(&me, CMD_TOMBSTONE, cptr, "%H %Tu %s %s", chptr,
                chptr->creationtime, ts->newname, digits);
}

/** Two announcements -- or an announcement and this server's own record
 * -- name different targets for one old channel: the two sides of a
 * netjoin each relocated it.  The crossing rule (relocate_again()) with
 * what a burst can tell: no issuer is known and nobody is moved -- the
 * memberships are what the BURSTs say -- so all there is to do is agree
 * on the redirects, the marks and the deadline.
 *
 * - The old channel redirects to the winner (its marks are set again:
 *   the +L merge of the BURST that came first may have left either
 *   target on it), and so does every earlier tombstone that pointed at
 *   the loser.
 * - The loser's channel is a tombstone redirecting to the winner.  It is
 *   one of the two new channels and reaches this server by its own
 *   BURST, before this announcement or after it (channels are burst in
 *   no particular order).  When it is here -- the channel of the old
 *   one's creation timestamp, which every channel a relocation makes has
 *   -- it is marked now.  When it is not, a record WAITS for it under its
 *   name (RelocateTombstone.waiting) and relocate_tombstone_burst_done()
 *   marks it when its BURST has been taken in; a channel of another
 *   timestamp under that name is a stranger's and is never touched.  If
 *   no such channel ever comes (it had emptied on the other side) the
 *   waiting record just expires; the other side holds nothing either.
 * - Both records, and every loser's, take the later deadline.
 *
 * Both sides compute this from the same pair of announcements, so both
 * end with the same redirects and the same deadline.
 * @param[in] ts The old channel's record here (held, not waiting).
 * @param[in] chptr The old channel.
 * @param[in] announced The target the announcement names.
 * @param[in] expires The deadline it carries, already checked.
 */
static void relocate_announced_cross(struct RelocateTombstone *ts,
                                     struct Channel *chptr,
                                     const char *announced, time_t expires)
{
  struct RelocateTombstone *rec;
  struct Channel *lchan;
  char oldname[CHANNELLEN + 1];
  char winner_buf[CHANNELLEN + 1], loser_buf[CHANNELLEN + 1];
  const char *winner = winner_buf, *loser = loser_buf;
  time_t deadline = relocate_deadline_merge(ts->expires, expires);
  time_t chan_ts = chptr->creationtime;
  int changed;

  ircd_strncpy(oldname, ts->oldname, sizeof(oldname));
  if (relocate_name_cmp(announced, ts->newname) < 0) {
    ircd_strncpy(winner_buf, announced, sizeof(winner_buf));
    ircd_strncpy(loser_buf, ts->newname, sizeof(loser_buf));
  } else {
    ircd_strncpy(winner_buf, ts->newname, sizeof(winner_buf));
    ircd_strncpy(loser_buf, announced, sizeof(loser_buf));
  }

  /* The old channel. */
  changed = (0 != ircd_strcmp(chptr->mode.redir, winner));
  relocate_mark_tombstone(chptr, winner, 0);
  ircd_strncpy(ts->newname, winner, sizeof(ts->newname));
  ts->oldchan = chptr;
  if (changed)
    relocate_announce_redirect(chptr);

  /* Earlier tombstones that pointed at the loser. */
  relocate_tombstone_retarget(loser, winner, ts->target_ts);

  /* The loser. */
  rec = relocate_tombstone_find_any(loser);
  lchan = FindChannel(loser);

  if (rec && !rec->waiting) {
    /* Already a tombstone here in its own right (it was announced, or
     * relocated on): its own record stands, with its own deadline. */
    ;
  } else if (lchan && lchan->creationtime == chan_ts) {
    relocate_tombstone_loser(&his, lchan, winner, ts->target_ts, oldname, "",
                             deadline, 0);
  } else if ((rec = relocate_tombstone_add_named(loser, winner, deadline))) {
    rec->waiting = 1;
    rec->want_ts = chan_ts;
    rec->target_ts = ts->target_ts;
    ircd_strncpy(rec->family, oldname, sizeof(rec->family));
  }

  relocate_family_settle(oldname, deadline);
}

/** Act on an announced tombstone (ms_tombstone(), after the line has
 * been checked).  relocate_announce_decide() (rename_proto.c) says which
 * case this is.
 * @param[in] oldname The tombstone's name.
 * @param[in] chan_ts Its channel's creation timestamp at the sender.
 * @param[in] target Where it redirects.
 * @param[in] expires Its deadline, network time, as received.
 */
static void relocate_announced(const char *oldname, time_t chan_ts,
                               const char *target, time_t expires)
{
  struct RelocateAnnounceFacts facts;
  struct Channel *chptr = FindChannel(oldname);
  struct RelocateTombstone *ts =
    chptr ? relocate_tombstone_find(chptr->chname) : NULL;

  memset(&facts, 0, sizeof(facts));
  facts.channel_exists = (chptr != NULL);
  facts.ts_matches = (chptr && chptr->creationtime == chan_ts);
  facts.have_record = (ts != NULL);
  facts.same_target = (ts && 0 == ircd_strcmp(ts->newname, target));

  /* An absurd deadline is cut as an RN's is; one that is past dissolves
   * the tombstone as soon as its record is settled below. */
  relocate_expiry_check(&expires, TStime());

  switch (relocate_announce_decide(&facts)) {
  case RELOCATE_ANNOUNCE_NO_CHANNEL:
  case RELOCATE_ANNOUNCE_OTHER_CHANNEL:
    log_write(LS_DEBUG, L_DEBUG, 0,
              "relocate: announced tombstone %s (%Tu) -> %s not taken: %s",
              oldname, chan_ts, target,
              chptr ? "the channel here has another creation timestamp"
                    : "no such channel here");
    return;

  case RELOCATE_ANNOUNCE_BUILD:
    /* The BURST gave the channel its +z and +L; this is the record.  The
     * marks are NOT imposed: when the channel does not redirect to the
     * announced target (an op's own +L here won the merge), the sender's
     * tombstone has lost its redirect the same way, and the record
     * expires as the sender's will -- nobody parted, +z handed back. */
    if (!(ts = relocate_tombstone_add(chptr, target, expires)))
      return;
    if (relocate_tombstone_channel(ts) == chptr) {
      relocate_tombstone_normalise(chptr);
      ts->target_ts = chptr->creationtime;
      /* No MODE +L: the BURST's own mode change showed the members that. */
      relocate_tombstone_populate(ts, chptr, &his, "", 0);
    }
    relocate_tombstone_settle(ts);
    return;

  case RELOCATE_ANNOUNCE_MERGE:
    if (relocate_tombstone_channel(ts) == chptr)
      relocate_tombstone_normalise(chptr);
    ts->expires = relocate_deadline_merge(ts->expires, expires);
    relocate_tombstone_settle(ts);
    return;

  case RELOCATE_ANNOUNCE_CROSS:
    relocate_announced_cross(ts, chptr, target, expires);
    return;
  }
}

/** A channel is about to be wiped by a BURST whose creation timestamp is
 * older (ms_burst()): the channel of that name is another server's from
 * here on.  A tombstone held for the losing channel is over -- its
 * record is dropped, and its +z, which the wipe-out leaves alone (it
 * clears mode.mode, not the extended modes), goes with it.  When the
 * winning channel is itself a tombstone its BURST sets +z again and its
 * announcement, which follows, builds a new record.
 * @param[in] chptr The channel, before the BURST's modes are applied.
 */
void relocate_tombstone_burst_lost(struct Channel *chptr)
{
  struct RelocateTombstone *ts;

  if (!(ts = relocate_tombstone_find(chptr->chname)))
    return;

  log_write(LS_SYSTEM, L_INFO, 0,
            "relocate: tombstone %s -> %s lost a BURST on timestamp; "
            "cancelled", ts->oldname, ts->newname);

  chptr->mode.exmode &= ~EXMODE_PERSIST;
  relocate_tombstone_end(ts, 0);
}

/** A BURST for a channel has been taken in (ms_burst(), last thing).
 *
 * - A record was WAITING for this channel (relocate_announced_cross())
 *   and this is it -- the creation timestamp it waited for: the channel
 *   becomes the tombstone the record describes, and its local members
 *   are told.
 * - The channel is a live tombstone: the merge may have put a limit or
 *   channel passwords back on it (the other side still held it as an
 *   ordinary channel); they come off again, or the redirect would fire
 *   only when the channel is full.
 * @param[in] chptr The channel.
 */
void relocate_tombstone_burst_done(struct Channel *chptr)
{
  struct RelocateTombstone *ts;

  if (!(ts = relocate_tombstone_find_any(chptr->chname)))
    return;

  if (ts->waiting) {
    if (chptr->creationtime != ts->want_ts)
      return;                   /* a stranger's channel under the name */

    ts->waiting = 0;
    relocate_mark_tombstone(chptr, ts->newname, 0);
    relocate_tombstone_populate(ts, chptr, &his, "", 1);
    return;
  }

  if (relocate_tombstone_channel(ts) == chptr)
    relocate_tombstone_normalise(chptr);
}

/** ms_tombstone - a relocation tombstone announced by a server.
 *
 * parv[0] = sender prefix (a server)
 * parv[1] = the tombstone's (old) channel name
 * parv[2] = that channel's creation timestamp
 * parv[3] = the channel it redirects to
 * parv[4] = the deadline, network time
 *
 * See "The tombstone in the burst" above for the line and who gets it,
 * and relocate_announced() for what this server makes of it.
 *
 * @param[in] cptr Link the message arrived on.
 * @param[in] sptr Original source of the message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int ms_tombstone(struct Client *cptr, struct Client *sptr, int parc,
                 char *parv[])
{
  struct DLink *dlp;
  time_t chan_ts, expires;
  enum RenameNameError bad;

  /* Refused from the message alone -- every server refuses alike, so
   * there is nobody to keep in step and the line is not passed on: a
   * source that is not a server, too few fields, names RN would refuse
   * (a local channel, not a channel, a byte no channel name has), a
   * channel redirecting to itself, a timestamp or deadline that is not a
   * number. */
  if (!IsServer(sptr))
    return protocol_violation(cptr, "TOMBSTONE from %s, which is not a "
                              "server", cli_name(sptr));
  if (parc < 5)
    return protocol_violation(cptr, "TOMBSTONE from %s with too few "
                              "parameters", cli_name(sptr));
  if ((bad = rename_check_names(parv[1], parv[3], CHANNELLEN, 0))
      != RENAME_NAME_OK)
    return protocol_violation(cptr, "TOMBSTONE %s -> %s from %s refused: %s",
                              parv[1], parv[3], cli_name(sptr),
                              rename_name_error_text(bad));
  if (0 == ircd_strcmp(parv[1], parv[3]))
    return protocol_violation(cptr, "TOMBSTONE %s -> %s from %s refused: a "
                              "channel cannot redirect to itself",
                              parv[1], parv[3], cli_name(sptr));
  if (!relocate_expiry_parse(parv[2], &chan_ts)
      || !relocate_expiry_parse(parv[4], &expires))
    return protocol_violation(cptr, "TOMBSTONE %s -> %s from %s refused: "
                              "\"%s\" / \"%s\" are not a creation timestamp "
                              "and a deadline", parv[1], parv[3],
                              cli_name(sptr), parv[2], parv[4]);

  relocate_announced(parv[1], chan_ts, parv[3], expires);

  /* Passed on as it came, to every other link an announcement goes to. */
  sendcmdto_serv_butone_v3(sptr, CMD_TOMBSTONE, cptr, "%s %s %s %s",
                           parv[1], parv[2], parv[3], parv[4]);
  for (dlp = cli_serv(&me)->down; dlp; dlp = dlp->next) {
    if (dlp->value.cptr == cptr || IsIRCv3Aware(dlp->value.cptr)
        || !IsRenameCapable(dlp->value.cptr))
      continue;
    sendcmdto_one(sptr, CMD_TOMBSTONE, dlp->value.cptr, "%s %s %s %s",
                  parv[1], parv[2], parv[3], parv[4]);
  }

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
   * "Multiple renames": a tombstone channel itself cannot be renamed).
   *
   * Whatever this server's own RENAME_CONSENT says: a tombstone comes off
   * the wire (the RN's marker is obeyed regardless of the local setting),
   * so a server with the feature off holds tombstones too, and a classic
   * rename of one would take the channel away from under its record --
   * which is keyed by the old name -- leaving +z and +L on the renamed
   * channel for good.  ms_rename() repairs that when such a rename
   * arrives from elsewhere (relocate_tombstone_renamed()); it is not to
   * be started here. */
  if (relocate_tombstone_find(oldname)) {
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

  /* Validate the names, classic and relocation mode alike and before any
   * services query: no local (&) channel on either side, and for the new
   * name everything JOIN demands of a name a user asks for -- a channel
   * prefix, the channel character set (no comma, no space or control
   * character, no 0xA0), valid UTF-8 under VALID_UTF8_CHANNELS_ONLY, the
   * CHANNELLEN cap.  rename_check_names() (rename_proto.c) has the rules
   * and why local channels are out.  Each case has its own text; the
   * BADCHAN check below is the remaining JOIN-time rule. */
  {
    enum RenameNameError bad =
      rename_check_names(chptr->chname, newname, rename_newname_maxlen(),
                         feature_bool(FEAT_VALID_UTF8_CHANNELS_ONLY));

    if (bad != RENAME_NAME_OK) {
      send_fail(sptr, "RENAME", "CANNOT_RENAME", oldname,
                rename_name_error_text(bad));
      return 0;
    }
  }

  /* Check if new channel name already exists */
  if (FindChannel(newname)) {
    send_fail(sptr, "RENAME", "CHANNEL_NAME_IN_USE", oldname,
              "Channel name already in use");
    return 0;
  }

  /* BADCHAN-glined target: renaming onto a banned name would move the
   * whole membership into a channel none of them could have JOINed —
   * do_join() enforces this per-joiner (m_join.c, GLINE_BADCHAN branch);
   * without this check RENAME is a wholesale bypass.  Mirror do_join's
   * exact test, including the oper exemption.  Deliberately NOT enforced
   * in ms_rename: local badchans never blocked remote users' presence in
   * a channel (join-time, local policy), so a remote-origin rename is
   * accepted the same way remote joins are. */
  {
    struct Gline *gline = gline_find((char *)newname, GLINE_BADCHAN | GLINE_EXACT);
    if (gline && GlineIsActive(gline) && !IsAnOper(sptr)) {
      send_fail(sptr, "RENAME", "CANNOT_RENAME", oldname,
                "Target channel name is banned");
      return 0;
    }
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
   * pending_rename_find/complete/deny are called from the AC A/D reply
   * path (rename_services_reply() above, entered from m_account.c through
   * rename_services_ac()), with pending_rename_client_exit called from
   * s_misc.c.
   *
   * The services server need not be linked to THIS server: the query is
   * sent toward it and every server on the way relays it, as each relays
   * the reply back by the server numeric in the cookie (see "Services
   * arbitration across servers" above).  The request remembers which
   * services server it asked, and no other server's answer is taken.
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

    if (!(pr = pending_rename_add(sptr, chptr, newname, reason, services))) {
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
      char cookie[RENAME_COOKIE_BUFLEN];

      if (IsUser(sptr) && IsBouncerAlias(sptr) && cli_alias_primary(sptr))
        acct_user = cli_alias_primary(sptr);

      /* The cookie on the wire names this server (<numeric>.<n>), so the
       * reply finds its way back from wherever services are linked; the
       * table stays keyed by the number alone. */
      if (!rename_cookie_format(cookie, sizeof(cookie), cli_yxx(&me),
                                pr->cookie)) {
        /* Cannot happen with a server numeric; do not leave the requester
         * waiting for a timeout if it does. */
        pending_rename_deny(pr, "Rename failed");
        return 0;
      }

      sendcmdto_one(&me, CMD_ACCOUNT, services, "%C R %s %s RENAME %s",
                   acct_user, cookie, chptr->chname, newname);
    }
    return 0;
  }

  /* Unregistered channel - proceed with rename immediately */

  /* Store old name before rename */
  ircd_strncpy(oldname_buf, chptr->chname, CHANNELLEN + 1);

  /* Relocation mode: partition instead of force-moving, and mark the RN so
   * every other server does the same.  Classic mode below is untouched. */
  if (rename_is_consent()) {
    time_t expires = relocate_local_deadline();

    /* chptr may be gone when this returns (a deadline of "now"). */
    rc = relocate_execute(sptr, chptr, oldname_buf, newname, reason, expires);
    if (rc == -1) {
      send_fail(sptr, "RENAME", "CANNOT_RENAME", oldname,
                "New channel name is too long");
      return 0;
    } else if (rc == -2) {
      send_fail(sptr, "RENAME", "CHANNEL_NAME_IN_USE", oldname,
                "Channel name already in use");
      return 0;
    }

    relocate_propagate(sptr, cptr, NULL, oldname_buf, newname, expires,
                       reason);
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
  time_t expires = 0;
  int rc;

  /* Need at least old and new channel names */
  if (parc < 3 || EmptyString(parv[1]) || EmptyString(parv[2])) {
    return 0; /* Silently ignore malformed S2S messages */
  }

  oldname = parv[1];
  newname = parv[2];
  reason = (parc > 3 && !EmptyString(parv[3])) ? parv[3] : "";

  /* Relocation marker: RN <old> <new> C [<expires>] :<reason>.  Recognised
   * only when a parameter follows it -- see the RELOCATE_MARKER comment
   * for why the four-parameter shape must stay a classic rename with the
   * reason "C".  When the marker is present relocation semantics apply on
   * THIS server regardless of the local FEAT_RENAME_CONSENT setting.
   *
   * With six parameters the fifth is the deadline; with five, the message
   * comes from (or through) a server from before the deadline travelled,
   * and this server counts its own grace from now, as every server used
   * to.  A fifth of six that is not a deadline gets the same fallback:
   * the relocation itself has to be executed either way, or this server's
   * membership differs from everyone's. */
  if (parc > 4 && !EmptyString(parv[3]) && 0 == strcmp(parv[3],
                                                       RELOCATE_MARKER)) {
    relocate = 1;
    reason = !EmptyString(parv[parc - 1]) ? parv[parc - 1] : "";

    if (parc == 5) {
      expires = relocate_local_deadline();
    } else if (!relocate_expiry_parse(parv[4], &expires)) {
      protocol_violation(cptr, "RENAME %s -> %s from %s: \"%s\" is not a "
                         "relocation deadline; using this server's own grace",
                         parv[1], parv[2], cli_name(sptr), parv[4]);
      expires = relocate_local_deadline();
    } else if (relocate_expiry_check(&expires, TStime())
               == RELOCATE_EXPIRY_CLAMPED) {
      log_write(LS_SYSTEM, L_WARNING, 0,
                "RENAME from %#C: %s -> %s carries a deadline (%s) more than "
                "%d seconds ahead; cut to %Tu",
                cptr, parv[1], parv[2], parv[4], RELOCATE_GRACE_MAX, expires);
    }
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

  /* Names from a peer.  A peer is trusted to have run the checks m_rename
   * runs for its own users, and most of them are that server's policy and
   * not this one's to repeat: its CHANNELLEN feature, its
   * VALID_UTF8_CHANNELS_ONLY, its BADCHAN list (see m_rename) -- a remote
   * rename is accepted on those counts the way a remote JOIN is.  What is
   * refused here is what no policy can make right, because the damage is
   * to the network and not to one channel:
   *
   * - A local (&) channel on either side.  RN is applied by name on every
   *   server; "&ops" here is not the channel the sender renamed, and a
   *   global channel renamed to "&x" would become one private channel per
   *   server.  The same rule, and the same answer, as for a remote JOIN
   *   of a local channel (ms_join).
   * - A name that is not a channel name at all (old or new).
   * - A new name with a byte outside the channel character set: a comma,
   *   a space or control character, 0xA0.  The comma is the one that
   *   breaks the protocol -- JOIN, PART and CREATE carry channel LISTS, so
   *   every later "J #a,b" would be read as two channels by every server
   *   -- and the rest are bytes no fork server lets a user JOIN, so such a
   *   channel could not be joined or parted by name again.  The OLD
   *   name's bytes are not checked: renaming a badly named channel away
   *   is the repair.
   * - A new name over the compile-time CHANNELLEN, which no server can
   *   store (rename_channel() refused it before, with a debug line).
   *
   * Refused means not applied and NOT relayed, unlike a rename this server
   * merely cannot apply (below): every server judges these from the
   * message alone and refuses alike, so there is no subtree to keep in
   * step, and passing the line on would only spread it.  A server from
   * before these checks does apply such an RN; that divergence exists the
   * moment its user's RENAME was accepted, whatever is done here. */
  {
    enum RenameNameError bad =
      rename_check_names(oldname, newname, CHANNELLEN, 0);

    if (bad != RENAME_NAME_OK)
      return protocol_violation(cptr, "RENAME %s -> %s from %s refused: %s",
                                oldname, newname, cli_name(sptr),
                                rename_name_error_text(bad));
  }

  /* Find the channel */
  chptr = FindChannel(oldname);

  if (relocate) {
    /* A relocation this server cannot apply is still relayed, exactly as
     * a classic rename is (below): what stops it here is this server's
     * own state -- the old channel is not here, the new name is taken
     * here -- and says nothing about the servers behind this one.  A
     * server that dropped the line became a wall: everything behind it
     * kept the old channel, with the issuer in it, and never heard of
     * the tombstone or its deadline.  So: leave local state alone, tell
     * the operators (this server may now differ from the network, and
     * only a person can sort that out), and pass the line on to the peers
     * a relocation that was applied would have told, in the same form.
     * The link the RN arrived on is skipped as on success, so nothing
     * can loop. */
    if (!chptr) {
      sendto_opmask_butone(0, SNO_OLDSNO,
                           "RELOCATE %s -> %s from %C NOT applied locally: "
                           "%s does not exist on this server.  The "
                           "relocation has been relayed onward; unless that "
                           "channel has just emptied everywhere, this server "
                           "is now divergent and needs manual "
                           "reconciliation.",
                           oldname, newname, sptr, oldname);
      /* The names as received: there is no local channel to take a
       * spelling from. */
      relocate_propagate(sptr, cptr, cptr, oldname, newname, expires,
                         reason);
      return 0;
    }

    /* Store old name before rename */
    ircd_strncpy(oldname_buf, chptr->chname, CHANNELLEN + 1);

    /* The channel is already a live tombstone here: it has been relocated
     * twice, by two servers that had not heard of each other.  No second
     * relocation is executed on top of the first -- relocate_again()
     * decides, from the two messages alone, what both leave behind -- and
     * the RN goes on as it came, so that the servers behind decide the
     * same.  (chptr may be gone when that returns.) */
    {
      struct RelocateTombstone *ts = relocate_tombstone_find(oldname_buf);

      if (ts && relocate_tombstone_channel(ts) == chptr) {
        relocate_again(sptr, ts, chptr, newname, reason, expires);
        relocate_propagate(sptr, cptr, cptr, oldname_buf, newname, expires,
                           reason);
        return 0;
      }
    }

    /* chptr may be gone when this returns (a deadline of "now"). */
    rc = relocate_execute(sptr, chptr, oldname_buf, newname, reason, expires);

    if (rc == -2) {
      /* Both names already exist HERE: a local divergence, not a defect
       * in the message. */
      sendto_opmask_butone(0, SNO_OLDSNO,
                           "RELOCATE %s -> %s from %C NOT applied locally: "
                           "%s already exists on this server.  The rename "
                           "has been relayed onward, so this server is now "
                           "divergent and needs manual reconciliation.",
                           oldname_buf, newname, sptr, newname);
      /* fall through to propagation */
    } else if (rc != 0) {
      /* Anything else relocate_execute() can fail on here is this
       * server's as well (an allocation): the names were judged above. */
      sendto_opmask_butone(0, SNO_OLDSNO,
                           "RELOCATE %s -> %s from %C NOT applied locally "
                           "(relocate_execute: %d).  The relocation has "
                           "been relayed onward, so this server is now "
                           "divergent and needs manual reconciliation.",
                           oldname_buf, newname, sptr, rc);
      log_write(LS_DEBUG, L_ERROR, 0,
                "RELOCATE from %#C not applied, relayed: %s -> %s (rc=%d)",
                sptr, oldname_buf, newname, rc);
      /* fall through to propagation */
    }

    /* Propagate with the marker, and with the deadline this server went
     * by: the one it was sent (cut, if it was absurd), or -- for the
     * five-parameter form of an older peer -- the one it has just
     * computed, so that every server behind this one shares it. */
    relocate_propagate(sptr, cptr, cptr, oldname_buf, newname, expires,
                       reason);
    return 0;
  }

  /* Classic rename.  Apply it when this server can; when it cannot, the
   * rename is still relayed.
   *
   * The names were judged above, so what is left to stop the rename is
   * this server's own state: the channel is not here under the old name,
   * or the new name is taken here.  Neither says anything about the
   * servers behind this one.  Two servers can disagree for a moment -- a
   * user creates #new here while #old is renamed to #new elsewhere, two
   * renames of one channel cross, the channel emptied here just before
   * the RN arrived -- and a server that answered that by dropping the
   * line became a wall: everything behind it never heard of the rename at
   * all, and kept the old name for good.  So, exactly as the relocation
   * branch above does for its own collision: leave local state alone,
   * tell the operators (this server may now differ from the network, and
   * only a person can sort that out), and pass the line on to the peers a
   * successful rename would have told, in the same form.
   *
   * No loop can come of it: the line goes to every link but the one it
   * arrived on, here as on success, and the network is a tree. */
  {
    struct Channel *taken = chptr ? FindChannel(newname) : NULL;

    if (!chptr) {
      sendto_opmask_butone(0, SNO_OLDSNO,
                           "RENAME %s -> %s from %C NOT applied locally: %s "
                           "does not exist on this server.  The rename has "
                           "been relayed onward; unless that channel has "
                           "just emptied everywhere, this server is now "
                           "divergent and needs manual reconciliation.",
                           oldname, newname, sptr, oldname);
      rc = -1;
    } else if (taken == chptr) {
      /* The two names are one channel here (they differ in case only).
       * m_rename refuses that at the origin, so only a server that
       * disagrees about the channel's name can have sent it. */
      sendto_opmask_butone(0, SNO_OLDSNO,
                           "RENAME %s -> %s from %C NOT applied locally: "
                           "both names are the channel %s on this server.  "
                           "The rename has been relayed onward.",
                           oldname, newname, sptr, chptr->chname);
      rc = -1;
    } else if (taken) {
      sendto_opmask_butone(0, SNO_OLDSNO,
                           "RENAME %s -> %s from %C NOT applied locally: %s "
                           "already exists on this server.  The rename has "
                           "been relayed onward, so this server is now "
                           "divergent and needs manual reconciliation.",
                           oldname, newname, sptr, taken->chname);
      rc = -1;
    } else {
      /* Store old name before rename */
      ircd_strncpy(oldname_buf, chptr->chname, CHANNELLEN + 1);

      /* Perform the rename (updates chptr if reallocated) */
      rc = rename_channel(&chptr, newname);
      if (rc != 0)
        sendto_opmask_butone(0, SNO_OLDSNO,
                             "RENAME %s -> %s from %C NOT applied locally "
                             "(rename_channel: %d).  The rename has been "
                             "relayed onward, so this server is now "
                             "divergent and needs manual reconciliation.",
                             oldname, newname, sptr, rc);
      else
        /* The channel may have been a relocation tombstone: its record
         * follows it to the new name. */
        relocate_tombstone_renamed(oldname_buf, chptr);
    }

    if (rc != 0) {
      log_write(LS_DEBUG, L_ERROR, 0,
                "RENAME from %#C not applied, relayed: %s -> %s",
                sptr, oldname, newname);

      /* The names as received: there is no local channel to take a
       * spelling from. */
      sendcmdto_serv_butone_v3(sptr, CMD_RENAME, cptr, "%s %s :%s",
                               oldname, newname, reason);
      /* Rename-capable non-v3 links (X3), with the same alias source
       * rewrite a successful rename gets. */
      rename_forward_rcapable(sptr, cptr, oldname, newname, "", reason);
      return 0;
    }
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
