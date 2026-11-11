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
 * @brief Channel rename, as a server that carries it.
 *
 * Channel rename (an IRCv3 draft specification,
 * https://ircv3.net/specs/extensions/channel-rename) is issued on servers
 * of the ircv3.2-upgrade branch.  This server does not offer it: there is
 * no RENAME command for users or operators here, no capability and no
 * setting.  What it does is coexist with servers that do:
 *
 * - it takes the server-to-server message
 *
 *       <source> RN <old> <new> :<reason>
 *
 *   renames its own copy of the channel, tells its own members, and
 *   passes the message on (ms_rename());
 * - it takes the other form of that message, a channel relocation
 *
 *       <source> RN <old> <new> C <expires> :<reason>
 *
 *   in which only the issuer moves to the new channel and the old one
 *   stays behind until <expires> as a tombstone that redirects there:
 *   it does to its own copy of the two channels what every server does,
 *   dissolves its own copy of the tombstone at that deadline, and passes
 *   the message on ("Relocation" below);
 * - it announces the tombstones it holds after their channels' BURST,
 *   takes and passes on the announcements of others
 *
 *       <server> RT <old> <old-creation-ts> <new> <expires>
 *
 *   ("The tombstone in the burst" below);
 * - it passes all of these on to every link whose server said it takes
 *   RN: 'v' in its SERVER flags (a server of that branch) or 'r'
 *   (services, or a server that carries renames the way this one does);
 * - it carries the question such a server asks services before it
 *   renames a registered channel, and services' answer, between the two
 *   (rename_services_ac()).
 */
#include "config.h"

#include "capab.h"
#include "channel.h"
#include "client.h"
#include "destruct_event.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_events.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "list.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "rename_proto.h"
#include "s_debug.h"
#include "s_user.h"
#include "send.h"
#include "struct.h"

#include <string.h>

/** The fourth parameter of an RN that is not a rename but a channel
 * relocation (see "Relocation" below):
 *
 *     rename:      RN <old> <new> :<reason>
 *     relocation:  RN <old> <new> C <expires> :<reason>
 *     from a server from before the deadline travelled:
 *                  RN <old> <new> C :<reason>
 *
 * It counts only when at least one more parameter follows it: "RN <old>
 * <new> :C" is a rename whose reason is the letter C.  That is the test
 * every server applies, so that all read one line the same way: taken
 * for a relocation on one server and a rename on another, it would move
 * everybody here and only the issuer there.
 *
 * <expires> is the moment the tombstone is dissolved, in network time
 * (TStime()); include/rename_proto.h has the field's form and the rules
 * a receiver applies to it.
 */
#define RELOCATE_MARKER "C"

/** Pass an RN on to every link that takes it, but the one it came from.
 *
 * A link takes it when its server announced 'v' or 'r' (see the file
 * comment).  Both kinds get the same line; a link with neither flag
 * would not know the token and gets nothing.  Asking for 'r' alone
 * would stop a rename at this server whenever it sits between two
 * servers of the ircv3.2-upgrade branch, which announce 'v' only.
 *
 * @param[in] sptr Source of the message, kept as it is.
 * @param[in] cptr Link the message arrived on.
 * @param[in] oldname Channel's old name.
 * @param[in] newname Channel's new name.
 * @param[in] rest Everything after the two names, as it goes on the
 *                 wire: ":<reason>" for a rename, "C <expires> :<reason>"
 *                 for a relocation.
 */
static void rename_relay(struct Client *sptr, struct Client *cptr,
                         const char *oldname, const char *newname,
                         const char *rest)
{
  struct DLink *lp;

  for (lp = cli_serv(&me)->down; lp; lp = lp->next) {
    if (lp->value.cptr == cptr)
      continue;
    if (!TakesRename(lp->value.cptr))
      continue;
    sendcmdto_one(sptr, CMD_RENAME, lp->value.cptr, "%s %s %s",
                  oldname, newname, rest);
  }
}

/** Tell this server's members of a channel that it has a new name.
 *
 * No client of this server can have asked for rename messages (the
 * capability is not offered here), so each gets what the specification
 * gives a client without it: its own PART of the old name and its own
 * JOIN of the new one, then the topic and the member list, as after any
 * JOIN.  The JOIN has the extended-join form for a client that asked for
 * that, as every other JOIN it is sent has (joinbuf_join() in channel.c).
 * Nobody is told about anybody else: the members did not change.
 *
 * Every local member gets it, one whose join is still hidden by +D
 * included -- it knows it is on the channel.  A zombie is never a local
 * user (make_zombie() removes those at once).
 *
 * @param[in] chptr The channel, already under its new name.
 * @param[in] oldname The name it had.
 * @param[in] reason Reason given for the rename; may be empty.
 */
static void send_rename_to_members(struct Channel *chptr, const char *oldname,
                                   const char *reason)
{
  struct Membership *member;
  struct Client *acptr;

  for (member = chptr->members; member; member = member->next_member) {
    acptr = member->user;

    if (!MyUser(acptr))
      continue;

    sendcmdto_one(acptr, CMD_PART, acptr, "%s :Channel renamed to %s%s%s",
                  oldname, chptr->chname, *reason ? ": " : "", reason);

    if (CapActive(acptr, CAP_EXTJOIN))
      sendcmdto_one(acptr, CMD_JOIN, acptr, "%H %s :%s", chptr,
                    IsAccount(acptr) ? cli_account(acptr) : "*",
                    cli_info(acptr));
    else
      sendcmdto_one(acptr, CMD_JOIN, acptr, "%H", chptr);

    if (chptr->topic[0]) {
      send_reply(acptr, RPL_TOPIC, chptr->chname, chptr->topic);
      send_reply(acptr, RPL_TOPICWHOTIME, chptr->chname, chptr->topic_nick,
                 chptr->topic_time);
    }
    do_names(acptr, chptr, NAMES_ALL|NAMES_EON);
  }
}

/* ---------- Relocation ----------
 *
 * The second form of a rename on the ircv3.2-upgrade branch
 * (evilnet/channel-relocate): the channel moves to a new name, and its
 * members are asked to follow instead of being moved.
 *
 *     <user> RN <old> <new> C <expires> :<reason>
 *     ADAAA RN #old #new C 1731340900 :moving
 *
 * - The new channel is made with the old one's state: modes, key, limit,
 *   passwords, creation timestamp, topic, bans and excepts, and its
 *   pending invites.
 * - Only the issuer -- the source of the RN -- is moved to it, with the
 *   status it had.
 * - The old channel stays, with everybody else in it, as a TOMBSTONE: it
 *   is +z (it does not go away when it empties), it has +L <new> and no
 *   limit (a JOIN of it is forwarded to the new channel, m_join.c), and
 *   its registration (+R) and passwords are gone; they moved.
 * - At <expires>, network time, the tombstone is dissolved: every member
 *   still in it is parted, the marks come off, and the empty channel is
 *   collected.  Unless it is registered (+R) at that moment: then it is
 *   cancelled instead -- nobody is parted, the redirect is withdrawn, and
 *   it is an ordinary channel again.
 * - Until then a member of the tombstone who joins the new channel takes
 *   the status he holds in the tombstone with him and is parted from it
 *   ("Following: live status, then part"), and nobody else gets into the
 *   tombstone ("Who can be in a tombstone").
 *
 * None of this is sent from server to server but the RN itself.  Every
 * server does all of it to its own copy of the two channels, tells its
 * own users, arms its own timer for the one deadline the RN carries, and
 * parts its own users at it.  So a server that only carries the RN -- as
 * this one did before -- ends with the issuer in a channel no other
 * server has him in, a tombstone nobody dissolves, and none of its users
 * redirected.  That is why a server that offers none of it to its own
 * users still does all of it here.
 *
 * What this server tells its own users is what a server of that branch
 * tells a client without that branch's capabilities, in the same words:
 * a NOTICE to each member who stays, the issuer's PART, the MODE +L, and
 * at the deadline each member's own PART.
 */

/** The grace of a relocation whose RN carries no deadline, in seconds.
 *
 * The deadline is the issuing server's to set, and it travels in the RN.
 * Only a server from before it travelled sends none ("RN <old> <new> C
 * :<reason>"), and each receiver of that form counts a grace of its own
 * from the moment of receipt.  On that branch the grace is the setting
 * RELOCATE_GRACE; this is its default.  It is a constant here: a setting
 * would be an operator's knob for a feature this server does not offer,
 * read only until the last such server has been upgraded, and the
 * deadline computed from it is relayed, so every server behind this one
 * shares it whatever its value. */
#define RELOCATE_GRACE_FALLBACK 900

/** Where a tombstone record's embedded timer stands.  It decides who
 * frees the record; see "Lifetime" at struct RelocateTombstone. */
enum RelocateTimer {
  RELOCATE_TIMER_NONE = 0,  /**< never armed: the event engine holds
                                 nothing of the record */
  RELOCATE_TIMER_ARMED,     /**< queued in the event engine */
  RELOCATE_TIMER_FIRING     /**< inside its own ET_EXPIRE; the engine still
                                 holds the timer and ET_DESTROY follows */
};

/** A tombstone: the old channel of a relocation, until its deadline.
 *
 * The record names its channel -- by name and creation timestamp, a
 * channel's identity here as in BURST -- and keeps no pointer to it.  +z
 * keeps a tombstone from being collected when it empties, but services
 * can still destroy it (DESTRUCT), a rename can reallocate it, and
 * somebody can then make a new channel of the same name.  Whoever needs
 * the channel asks relocate_tombstone_channel(), which also checks that
 * it still is this tombstone.
 *
 * Lifetime.  The struct Timer is embedded, and the event engine goes on
 * using a timer after its ET_EXPIRE callback has returned (and
 * timer_del() of a timer in dispatch does nothing).  So a record whose
 * timer the engine holds is freed in exactly one place: the ET_DESTROY
 * case of relocate_tombstone_expire_cb().  A record whose timer was
 * never armed is freed by hand.  ONE function decides which, from
 * @a timer_state, for every end of a record other than its own expiry:
 * relocate_tombstone_end().  Nothing else frees a record, and nothing
 * may assume that a record it is about to end has no timer: one that is
 * settled again after its deadline has passed (a second message about
 * the tombstone, a step of the network clock) has one. */
struct RelocateTombstone {
  struct RelocateTombstone *next;   /**< next in relocate_tombstones */
  char oldname[CHANNELLEN + 1];     /**< the tombstone's own name */
  time_t chan_ts;                   /**< creation timestamp of the channel
                                         the record was made for.  +z and a
                                         +L to the same target are things
                                         the network can put on ANOTHER
                                         channel that later has the name,
                                         and the record must not answer for
                                         that one */
  char newname[CHANNELLEN + 1];     /**< where it redirects: the name the
                                         network has for the target now */
  char issued[CHANNELLEN + 1];      /**< the new name of the relocation the
                                         record was made by, AS IT WAS
                                         ISSUED.  @a newname moves on when
                                         the target is relocated or renamed;
                                         this does not, and a second
                                         relocation of the same old channel
                                         is compared with it
                                         (relocate_again()).  For a record
                                         built from a burst announcement:
                                         the target announced */
  time_t target_ts;                 /**< creation timestamp of the channel
                                         the relocation made under
                                         @a newname.  A member of this
                                         tombstone who joins THAT channel
                                         follows (relocate_follow()); one
                                         who joins a channel somebody made
                                         under the name after it emptied
                                         does not.  Every channel a
                                         relocation makes has the old
                                         channel's timestamp */
  time_t expires;                   /**< the deadline, in NETWORK time
                                         (TStime()), as the RN carries it:
                                         the same number on every server */
  struct Timer timer;               /**< embedded; see "Lifetime" */
  enum RelocateTimer timer_state;   /**< where the timer stands, and so
                                         who frees this record */
  char family[CHANNELLEN + 1];      /**< for the tombstone of a relocation
                                         that LOST a crossing
                                         (relocate_again()): the name of the
                                         old channel both relocations were
                                         of.  The records of one crossing --
                                         the old channel's and every loser's
                                         -- share one deadline; this is how
                                         they are found.  Empty otherwise */
  int detached;                     /**< the tombstone is DETACHED from its
                                         target: @a newname is what the
                                         network calls the target, but on
                                         this server that name is another
                                         channel's, so the tombstone must
                                         not point at it and has no +L here.
                                         See relocate_tombstone_point() */
  int unsettled;                    /**< a BURST's mode merge left a redirect
                                         on the tombstone that is not this
                                         record's
                                         (relocate_tombstone_burst_done()).
                                         It may be a crossing whose
                                         announcement is the next line,
                                         which settles it.  If it is not,
                                         the record is not allowed back: the
                                         next MODE that touches a mark ends
                                         it
                                         (relocate_tombstone_marks_changed()),
                                         also one that would make the
                                         channel match again, and failing
                                         that the deadline drops it */
  int waiting;                      /**< the record is waiting for its
                                         channel: the loser of a crossing
                                         learned from burst announcements,
                                         whose own BURST has not arrived yet
                                         (relocate_announced_cross()).  It
                                         is no tombstone until
                                         relocate_tombstone_burst_done()
                                         finds the channel -- the one
                                         created at @a chan_ts;
                                         relocate_tombstone_find() does not
                                         return it, and nothing is done to
                                         any channel for it */
};

/** Every tombstone this server holds. */
static struct RelocateTombstone *relocate_tombstones = NULL;

static void relocate_tombstone_expire_cb(struct Event *ev);
static void relocate_tombstone_end(struct RelocateTombstone *ts, int dissolve);
static void relocate_tombstone_detach(struct RelocateTombstone *ts,
                                      struct Channel *chptr,
                                      struct Channel *there);

/** Find a record by the name of its (old) channel -- any record, one
 * that is still waiting for its channel included.  For the code that
 * keeps the list (one record per name) and for the burst hook;
 * everything that asks "is this channel a tombstone" uses
 * relocate_tombstone_find().
 * @param[in] name Channel name.
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

/** Find a tombstone's record by the name of its (old) channel.  A record
 * that is waiting for its channel (RelocateTombstone.waiting) is not a
 * tombstone yet and is not returned.
 * @param[in] name Channel name.
 * @return The record, or NULL.
 */
static struct RelocateTombstone *relocate_tombstone_find(const char *name)
{
  struct RelocateTombstone *ts = relocate_tombstone_find_any(name);

  return (ts && !ts->waiting) ? ts : NULL;
}

/** Find the channel a record is the tombstone of.
 *
 * The name alone does not say it.  A tombstone can lose what makes it
 * one -- a chanop removes or changes +L, services take +z off -- or go
 * away altogether, and a channel somebody then makes under the name is
 * not this record's to redirect, strip or sweep.  So the channel is
 * accepted only when it IS the channel the record was made for -- the
 * name and the creation timestamp -- and still carries the marks: +z,
 * and a redirect to where this record points.  The marks alone are not
 * enough: services can make another channel of the name +z, and anybody
 * can give it a +L to the same target.  A DETACHED tombstone is the one
 * that must have no redirect at all (relocate_tombstone_point()).
 *
 * The redirect IS the name in mode.redir.  +L, like +l and +k, lives in
 * its parameter and nowhere else: mode_parse_redir() writes mode.redir,
 * channel_modes() and do_join() read it, and nothing sets or reads a
 * MODE_REDIRECT bit in a channel's mode.mode.  So nothing here does
 * either: a tombstone this server learns from a BURST ("+z +L <new>")
 * has to be recognised exactly as one it made itself from an RN.
 * @param[in] ts The record.
 * @return Its channel, or NULL when that is gone or no longer its
 *         tombstone.
 */
static struct Channel *relocate_tombstone_channel(struct RelocateTombstone *ts)
{
  struct Channel *chptr;

  /* A record that is waiting for its channel has none, whatever is under
   * the name. */
  if (!ts || ts->waiting || !(chptr = FindChannel(ts->oldname)))
    return NULL;

  /* (An empty mode.redir -- no +L -- never equals a target.) */
  if (chptr->creationtime != ts->chan_ts
      || !(chptr->mode.exmode & EXMODE_PERSIST)
      || (ts->detached ? chptr->mode.redir[0] != '\0'
                       : 0 != ircd_strcmp(chptr->mode.redir, ts->newname)))
    return NULL;

  return chptr;
}

/** Take a record off the list, so that no lookup finds it any more.  Does
 * not touch its timer and does not free it.
 * @param[in] ts The record.
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

/** Take the marks of a tombstone off a channel that is being dissolved:
 * the redirect, and +z -- always.  +z is all that keeps the empty channel
 * from being collected, and whoever set it, it does not belong on what is
 * left: this engine's own is handed back, and one from before the
 * relocation was the registration's, which moved to the new channel with
 * everything else.  Every server dissolves alike, so it goes everywhere.
 * @param[in] chptr The tombstone.
 */
static void relocate_tombstone_clear_marks(struct Channel *chptr)
{
  chptr->mode.redir[0] = '\0';
  chptr->mode.exmode &= ~EXMODE_PERSIST;
}

/** Which of a tombstone's marks is its channel missing?  For a log line
 * or a notice to operators.
 * @param[in] ts The record.
 * @param[in] chptr The channel of the record's name (may be NULL).
 * @return A constant string.
 */
static const char *relocate_missing_mark(struct RelocateTombstone *ts,
                                         struct Channel *chptr)
{
  if (!chptr)
    return "channel is gone";
  if (!(chptr->mode.exmode & EXMODE_PERSIST))
    return "+z was removed";
  if (ts->detached)
    return "a redirect was set on it while it was detached from its target";
  if (!chptr->mode.redir[0])
    return "+L was removed";
  return "+L was changed";
}

/** A tombstone has been cancelled -- one of its marks was taken off, or
 * changed -- and its channel is an ordinary channel again: do what is
 * owed to the CHANNEL.  (The record is the caller's to end.)
 *
 * Nobody is parted.  +z goes, as when a tombstone is dissolved: it is
 * the one mark no user can remove (MODE takes 'z' from services only),
 * so a chanop's -L would otherwise leave a channel that is never
 * collected.  The one channel left alone is one that is REGISTERED: its
 * +z is services'.  A redirect that is on the channel now is not
 * touched: it is whatever the MODE made it, an ordinary +L.  The
 * operators are told.
 *
 * An EMPTY channel has to be collected by hand now, because every member
 * who left while +z was set left a channel that could not be.  From
 * inside a MODE that is still being parsed the channel must not be
 * freed, so its collection is scheduled, as MODE -z does for an empty
 * channel (@a defer); at the deadline it is collected at once.
 * @param[in] ts The record (for the names).
 * @param[in] chptr The channel.
 * @param[in] defer Non-zero when called under mode_parse() or CLEARMODE.
 */
static void relocate_tombstone_cancelled(struct RelocateTombstone *ts,
                                         struct Channel *chptr, int defer)
{
  const char *why = relocate_missing_mark(ts, chptr);

  if (chptr->mode.mode & MODE_REGISTERED)
    return;

  sendto_opmask_butone(0, SNO_OLDSNO,
                       "Relocation tombstone %s (-> %s) was cancelled: %s.  "
                       "It is an ordinary channel again; its %u member%s "
                       "were NOT parted.",
                       ts->oldname, ts->newname, why, chptr->users,
                       (chptr->users == 1) ? "" : "s");

  if (!(chptr->mode.exmode & EXMODE_PERSIST))
    return;                     /* -z: whoever took it off deals with it */

  chptr->mode.exmode &= ~EXMODE_PERSIST;

  if (!chptr->members) {
    if (defer)
      schedule_destruct_event_1m(chptr);
    else
      sub1_from_channel(chptr);         /* may free chptr */
  }
}

/** A MODE (a user's, an operator's OPMODE or CLEARMODE, services', a
 * server's) has just changed a channel's redirect or its +z: if the
 * channel was a tombstone and no longer is, the tombstone is over NOW,
 * not at its deadline.
 *
 * Why at once.  A record that waited for the deadline could be made to
 * match again: a remaining op takes +L off (the channel stops being a
 * tombstone, so it admits anybody), lets people in and ops them, and
 * sets "+L <target>" again -- a live tombstone once more, with members
 * who were never in the old channel and who could each follow with
 * status.  Cancelling is final: the record is ended here, and a redirect
 * set later is an ordinary redirect on an ordinary channel.
 *
 * Every server sees the same MODE and ends its own record at the same
 * point of the same stream, so this converges as the MODE does.
 *
 * NOT called for what this file itself does to a tombstone's redirect
 * (relocate_tombstone_point()), which writes the channel directly, nor
 * for the mode merge of a BURST, which relocate_tombstone_burst_done()
 * and the announcement that follows settle.
 *
 * The channel is never freed here (the caller is in the middle of a
 * MODE).
 * @param[in] chptr The channel whose mode.redir or +z changed.
 */
void relocate_tombstone_marks_changed(struct Channel *chptr)
{
  struct RelocateTombstone *ts;

  if (!relocate_tombstones
      || !(ts = relocate_tombstone_find(chptr->chname))
      || ts->chan_ts != chptr->creationtime)
    return;

  /* Still the tombstone: the MODE set the redirect it already had, or
   * changed something else.  (An unsettled record is not given the
   * benefit: see RelocateTombstone.unsettled.) */
  if (!ts->unsettled && relocate_tombstone_channel(ts) == chptr)
    return;

  log_write(LS_SYSTEM, L_INFO, 0,
            "relocate: tombstone %s -> %s cancelled (%s)", ts->oldname,
            ts->newname,
            ts->unsettled ? "a MODE on a tombstone a BURST had left with "
                            "another redirect"
                          : relocate_missing_mark(ts, chptr));

  relocate_tombstone_cancelled(ts, chptr, 1);
  relocate_tombstone_end(ts, 0);
}

/** Announce a tombstone's redirect to its LOCAL members, as a MODE +L
 * from the server.  Nothing goes to other servers: each does the same
 * from the same RN.
 * @param[in] chptr The tombstone; its mode.redir is set.
 */
static void relocate_announce_redirect(struct Channel *chptr)
{
  struct ModeBuf mbuf;

  modebuf_init(&mbuf, &me, NULL, chptr, MODEBUF_DEST_CHANNEL);
  modebuf_mode_string(&mbuf, MODE_ADD | MODE_REDIRECT, chptr->mode.redir, 0);
  modebuf_flush(&mbuf);
}

/** Take a tombstone's redirect off its channel and tell its LOCAL
 * members (MODE -L from the server) -- for a tombstone that is cancelled
 * at its deadline because it is registered.  Nothing goes to other
 * servers, for the same reason.  -L has no parameter and the mode buffer
 * keeps no reference to the name, so the name is cleared here.
 * @param[in] chptr The tombstone.
 */
static void relocate_withdraw_redirect(struct Channel *chptr)
{
  struct ModeBuf mbuf;

  if (!chptr->mode.redir[0])
    return;                     /* a detached tombstone has none */

  modebuf_init(&mbuf, &me, NULL, chptr, MODEBUF_DEST_CHANNEL);
  modebuf_mode_string(&mbuf, MODE_DEL | MODE_REDIRECT, chptr->mode.redir, 0);
  modebuf_flush(&mbuf);

  chptr->mode.redir[0] = '\0';
}

/** The deadline's work for one tombstone: part every member still in it
 * and let the channel go -- or cancel the tombstone, when its channel is
 * registered or is no longer the tombstone.
 *
 * NOTHING here goes to servers.  Every server holds the same tombstone
 * with the same deadline and runs this over its own copy of the members;
 * a PART sent out would be applied a second time everywhere.  A user of
 * another server is taken out of this server's copy without a word, and
 * that user's own server tells him.
 *
 * @param[in] ts The record, already off the list.
 */
static void relocate_tombstone_sweep(struct RelocateTombstone *ts)
{
  struct Channel *chptr;
  struct Membership *member;
  unsigned int nswept = 0;

  /* A record that waited for its channel to the end never had one. */
  if (ts->waiting)
    return;

  /* SAFETY NET.  A record whose channel is not its tombstone any more
   * should not reach its deadline: whatever takes a mark off a tombstone
   * ends the record there and then (relocate_tombstone_marks_changed()),
   * and whatever replaces or re-stamps the channel tells the record
   * (relocate_tombstone_channel_gone(), _ts_lost(),
   * relocate_channel_restamped()).  What
   * can still arrive here is a record a BURST left unsettled
   * (RelocateTombstone.unsettled), and a change that went past every
   * hook.  The record is dropped (the caller has unlinked it) and NOBODY
   * is parted: a channel that is not the tombstone may be somebody else's
   * under the old name. */
  if (!(chptr = relocate_tombstone_channel(ts))) {
    struct Channel *stray = FindChannel(ts->oldname);

    /* First: is it the record's channel at all?  One of another creation
     * timestamp is another channel that has the name now.  Nothing of it
     * is this record's -- not its members, not its +z, not its redirect
     * -- and nothing of it is touched. */
    if (stray && stray->creationtime != ts->chan_ts) {
      log_write(LS_SYSTEM, L_WARNING, 0,
                "relocate: tombstone %s -> %s: the channel of that name is "
                "another channel at the deadline (created %Tu, the "
                "tombstone's was created %Tu); record dropped, channel not "
                "touched", ts->oldname, ts->newname, stray->creationtime,
                ts->chan_ts);
      return;
    }

    log_write(LS_SYSTEM, L_WARNING, 0,
              "relocate: tombstone %s -> %s is no longer one at its "
              "deadline (%s); record dropped, nobody parted",
              ts->oldname, ts->newname, relocate_missing_mark(ts, stray));

    if (stray)
      relocate_tombstone_cancelled(ts, stray, 0);
    return;
  }

  /* The tombstone is REGISTERED: services registered the old name inside
   * the grace.  Sweeping it would part everybody, services' own client
   * included, and destroy a registered channel.  It is cancelled instead:
   * nobody is parted, the redirect is withdrawn, the record goes (the
   * caller has unlinked it), and the channel is an ordinary registered
   * channel again.  +z stays; on a registered channel it is services'.
   *
   * +R is looked at HERE, at the deadline, and never when it arrives.  A
   * MODE +R that crosses the RN lands on the old channel on one server
   * (before the relocation: it moves to the new channel with the rest)
   * and on the tombstone on another; that and a deliberate registration
   * of the old name look the same when the MODE arrives.  At the
   * deadline every server reads its own copy at the same moment, and
   * services have had the whole grace to take a stray +R back. */
  if (chptr->mode.mode & MODE_REGISTERED) {
    relocate_withdraw_redirect(chptr);

    log_write(LS_SYSTEM, L_INFO, 0,
              "relocate: tombstone %s -> %s is registered at its deadline; "
              "cancelled, %u member%s left in place",
              ts->oldname, ts->newname, chptr->users,
              (chptr->users == 1) ? "" : "s");
    return;
  }

  /* From the head each time: removing a member can remove others
   * (remove_user_from_channel() clears out a channel left with zombies
   * only).  +z is still set, so the channel survives its last member. */
  while ((member = chptr->members)) {
    struct Client *user = member->user;

    /* A member whose JOIN the channel was never shown (+D) is not shown
     * leaving either, as in joinbuf_flush(); a local one gets his own
     * PART.  For everybody else the channel-wide PART includes the user
     * himself. */
    if (!(member->status & (CHFL_ZOMBIE | CHFL_DELAYED)))
      sendcmdto_channel_butserv_butone(user, CMD_PART, chptr, NULL, 0,
                                       "%H :Channel has moved to %s",
                                       chptr, ts->newname);
    else if (MyUser(user))
      sendcmdto_one(user, CMD_PART, user, "%H :Channel has moved to %s",
                    chptr, ts->newname);

    remove_user_from_channel(user, chptr);
    nswept++;
  }

  /* The marks had to stay on until here, or the last removal would have
   * destroyed the channel under the loop.  That also means no removal
   * scheduled the collection of the empty channel; it is done by hand,
   * the way a last PART would.  The passwords are gone since the
   * relocation, so sub1_from_channel() resets the modes and destroys the
   * channel or schedules that; chptr may be freed by it. */
  relocate_tombstone_clear_marks(chptr);
  sub1_from_channel(chptr);

  log_write(LS_DEBUG, L_DEBUG, 0,
            "relocate: tombstone %s -> %s dissolved (%u member%s parted)",
            ts->oldname, ts->newname, nswept, (nswept == 1) ? "" : "s");
}

/** End a tombstone record -- the ONE way a record goes other than by its
 * own timer expiring (struct RelocateTombstone, "Lifetime").
 *
 * In order:
 * 1. The record is unlinked, so that nothing below finds it again.  A
 *    sweep ends in destruct_channel(), which calls
 *    relocate_tombstone_channel_gone(), which looks the dying channel's
 *    record up by name -- and must not find the one being ended.
 * 2. With @a dissolve, the deadline's work is done here and now
 *    (relocate_tombstone_sweep()).  The record is whole while it runs.
 * 3. The record is freed by whoever owns it:
 *    - RELOCATE_TIMER_NONE: nobody else; freed here.
 *    - RELOCATE_TIMER_ARMED: the event engine holds the embedded timer.
 *      timer_del() takes it off the queue and generates ET_DESTROY
 *      before it returns, and relocate_tombstone_expire_cb() frees the
 *      record there.  No ET_EXPIRE can follow, so nothing is swept
 *      twice.
 *    - RELOCATE_TIMER_FIRING: the record's own ET_EXPIRE is on the
 *      stack.  Its callback has unlinked it and is sweeping, and the
 *      engine generates ET_DESTROY when the callback returns.  Nothing
 *      is done here, not even the sweep: timer_del() does nothing to a
 *      timer in dispatch, and a free would leave the engine with freed
 *      memory.  (An unlinked record cannot be looked up, so this is not
 *      reached today; it is here so that it cannot become a double
 *      free.)
 *
 * @a ts must not be used after this returns, and the tombstone's channel
 * may have been freed by the sweep.
 * @param[in] ts The record.
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
    timer_del(&ts->timer);      /* -> ET_DESTROY -> MyFree(ts), at once */
  } else {
    MyFree(ts);
  }
}

/** A channel has been renamed by an RN from the network: if it was a
 * tombstone, its record follows it.
 *
 * The servers that issue renames refuse to rename a tombstone for their
 * own users, but such an RN can arrive all the same -- from a server
 * without that refusal, from services -- and every server applies it, so
 * this one does.  The record is kept by the tombstone's name.  Left under
 * the old one it would describe nothing, and the renamed channel would
 * keep +z and +L for good, with members nobody parts.  Under the new
 * name everything the record stands for carries on: the channel still
 * redirects, a member can still follow out of it, and it is dissolved at
 * the same deadline.  Every server does the same from the RN alone.
 * Cancelling the tombstone instead would make a channel whose community
 * has left a live one again, on the word of a message that says nothing
 * of the kind.
 *
 * The record is not freed and its timer is not touched; a detached
 * record stays detached.
 * @param[in] oldname The name the channel had.
 * @param[in] chptr The channel under its new name.
 */
static void relocate_tombstone_renamed(const char *oldname,
                                       struct Channel *chptr)
{
  struct RelocateTombstone *ts, *stale;

  if (!(ts = relocate_tombstone_find(oldname)))
    return;

  /* A record under the old name that was made for another channel (its
   * creation timestamp is not this one's) does not follow this one. */
  if (ts->chan_ts != chptr->creationtime) {
    relocate_tombstone_end(ts, 0);
    return;
  }

  /* A record left under the new name describes a channel that is gone
   * (the name was free for this rename): two records must not answer to
   * one name. */
  if ((stale = relocate_tombstone_find_any(chptr->chname)) && stale != ts)
    relocate_tombstone_end(stale, 0);

  /* rename_channel() keeps the creation timestamp. */
  ircd_strncpy(ts->oldname, chptr->chname, sizeof(ts->oldname));

  log_write(LS_SYSTEM, L_INFO, 0,
            "relocate: tombstone %s (-> %s) was renamed to %s; its record "
            "follows it", oldname, ts->newname, ts->oldname);
}

/** A channel is about to be freed (destruct_channel()): a tombstone
 * record for it is over.
 *
 * +z keeps a tombstone from being collected when it empties, but not
 * from services' DESTRUCT, nor from a -z by services followed by the
 * last member leaving.  The record would be left with a timer running
 * for a name anybody can make a channel under.
 * relocate_tombstone_channel() would keep that channel from being swept,
 * but a record that describes nothing is better ended when it stops
 * describing something.
 *
 * The record whose own sweep is destroying the channel is not on the
 * list (both ways a record is swept unlink it first), so it is not ended
 * a second time from here.
 * @param[in] chptr The channel.
 */
void relocate_tombstone_channel_gone(struct Channel *chptr)
{
  struct RelocateTombstone *ts;

  if ((ts = relocate_tombstone_find(chptr->chname)))
    relocate_tombstone_end(ts, 0);
}

/* ---------- A channel's creation timestamp changes ----------
 *
 * A record is bound to its channel by name and creation timestamp
 * (RelocateTombstone.chan_ts), so every place that changes a channel's
 * creationtime has to say which of two things happened:
 *
 * - The channel was WIPED for an older timestamp: the channel of that
 *   name is another server's older one from here on, and ours -- with
 *   the tombstone it was -- is over.  ms_burst()'s wipe-out, and
 *   ms_join()'s for a JOIN that carries an older timestamp.
 *   -> relocate_tombstone_ts_lost(), BEFORE the timestamp is assigned.
 * - The timestamp was CHANGED and the channel left as it is, modes and
 *   all: mode_parse() for a server MODE with an older timestamp (always
 *   older: a correction), ms_create() for a CREATE it accepts for a
 *   channel that exists (older: a correction; later: only for an empty
 *   channel, which is being made anew), and ms_burst() when our EMPTY
 *   channel is a few seconds older than the BURST's ("use the same TS on
 *   both sides": always later, the other side's channel).
 *   -> relocate_channel_restamped(), AFTER the assignment: to an OLDER
 *      timestamp the records follow; to a later one they do not.
 *
 * get_channel(), and ms_join() for a channel it has just made, stamp a
 * NEW channel; no record exists for one.  A local JOIN of an empty
 * channel (do_join(), m_svsjoin.c) adds a second to the timestamp, but
 * never of a channel that is +z, so never of a tombstone.  A destroyed
 * channel takes its record along (relocate_tombstone_channel_gone()),
 * and a renamed one keeps its timestamp.
 *
 * A record whose channel changed timestamp WITHOUT either call would no
 * longer find it; relocate_tombstone_sweep() then drops the record at
 * the deadline without touching the channel, and logs exactly that.
 */

/** A channel is about to be wiped because a line carries an older
 * creation timestamp for its name (ms_burst(), ms_join()): the channel
 * of that name is another server's from here on.  A tombstone held for
 * the losing channel is over, at once and on every server that loses
 * alike: its record is dropped, and so are its two marks, neither of
 * which the wipe-out can be relied on to take -- +z is an extended mode,
 * which both wipe-outs leave alone, and ms_join()'s does not clear a
 * redirect either.  Left on, they would make an ordinary channel a
 * tombstone that nobody will ever dissolve.  The redirect goes only when
 * it is still the record's own.
 * @param[in] chptr The channel, before its timestamp is changed and
 *                  before the winner's modes are applied.
 */
void relocate_tombstone_ts_lost(struct Channel *chptr)
{
  struct RelocateTombstone *ts;

  if (!(ts = relocate_tombstone_find(chptr->chname)))
    return;

  /* A record made for another channel that had the name: only the record
   * goes. */
  if (ts->chan_ts == chptr->creationtime) {
    log_write(LS_SYSTEM, L_INFO, 0,
              "relocate: tombstone %s -> %s (created %Tu) lost to an older "
              "creation timestamp; cancelled", ts->oldname, ts->newname,
              ts->chan_ts);

    chptr->mode.exmode &= ~EXMODE_PERSIST;
    if (chptr->mode.redir[0]
        && 0 == ircd_strcmp(chptr->mode.redir, ts->newname))
      relocate_withdraw_redirect(chptr);
  }

  relocate_tombstone_end(ts, 0);
}

/** A channel's creation timestamp has been changed and the channel
 * itself left alone (see "A channel's creation timestamp changes"): what
 * of the records bound to it -- the record of the channel as a tombstone
 * (chan_ts), and every record that points AT it and knows its target by
 * that timestamp (target_ts)?  Only a record bound to the old value is
 * concerned.
 *
 * - To an OLDER timestamp: a correction of the same channel -- this
 *   server learned that the channel is older than it thought, from a
 *   server MODE or a CREATE that carries the earlier time.  The records
 *   follow.
 * - To a LATER timestamp: not a correction.  Only an EMPTY channel takes
 *   one (ms_create() for a channel without members, ms_burst()'s
 *   few-seconds rule), and what it means is that somebody made the name
 *   anew.  The records do NOT follow:
 *     * a tombstone whose TARGET this was has lost its target: it is
 *       detached (relocate_tombstone_detach()) -- no forward, no status,
 *       still dissolved on time;
 *     * a record whose OWN channel this was no longer describes it and
 *       is ended; the channel, which is somebody else's now, is not
 *       touched.
 *
 * (A target that was DESTROYED and made again from scratch comes through
 * no hook at all; relocate_join_verdict() finds it out when the redirect
 * is about to be used.)
 * @param[in] chptr The channel, with its new timestamp.
 * @param[in] old_ts The timestamp it had.
 */
void relocate_channel_restamped(struct Channel *chptr, time_t old_ts)
{
  struct RelocateTombstone *ts, *next;
  int older = (chptr->creationtime < old_ts);

  if (old_ts == chptr->creationtime)
    return;

  /* ->next first: a record can be ended in this loop (that one only). */
  for (ts = relocate_tombstones; ts; ts = next) {
    next = ts->next;

    /* As a target. */
    if (ts->target_ts == old_ts
        && 0 == ircd_strcmp(ts->newname, chptr->chname)) {
      if (older)
        ts->target_ts = chptr->creationtime;
      else if (!ts->waiting && !ts->detached) {
        struct Channel *tomb = relocate_tombstone_channel(ts);

        if (tomb)
          relocate_tombstone_detach(ts, tomb, chptr);
      }
    }

    /* As the tombstone's own channel. */
    if (!ts->waiting && ts->chan_ts == old_ts
        && 0 == ircd_strcmp(ts->oldname, chptr->chname)) {
      if (older)
        ts->chan_ts = chptr->creationtime;
      else {
        log_write(LS_SYSTEM, L_INFO, 0,
                  "relocate: the channel of tombstone %s -> %s was "
                  "re-stamped from %Tu to a later %Tu: another channel has "
                  "the name; record ended, channel not touched",
                  ts->oldname, ts->newname, old_ts, chptr->creationtime);
        relocate_tombstone_end(ts, 0);
      }
    }
  }
}

/** A tombstone's timer: its deadline, and its end.
 *
 * ET_EXPIRE makes the record unreachable and does the deadline's work.
 * It does not free the record and does not call timer_del(): the engine
 * still uses the timer when the callback returns, and generates
 * ET_DESTROY itself then.  ET_DESTROY -- that one, or the one
 * relocate_tombstone_end()'s timer_del() generates -- is the only place
 * a record that had a timer is freed.
 * @param[in] ev The timer's event.
 */
static void relocate_tombstone_expire_cb(struct Event *ev)
{
  struct RelocateTombstone *ts;

  assert(0 != ev_timer(ev));
  assert(0 != t_data(ev_timer(ev)));

  ts = (struct RelocateTombstone *)t_data(ev_timer(ev));

  switch (ev_type(ev)) {
  case ET_EXPIRE:
    /* Unlinked BEFORE the sweep, for the reason given at
     * relocate_tombstone_end(). */
    relocate_tombstone_unlink(ts);
    ts->timer_state = RELOCATE_TIMER_FIRING;

    relocate_tombstone_sweep(ts);
    break;

  case ET_DESTROY:
    MyFree(ts);
    break;

  default:
    break;
  }
}

/** The deadline this server goes by when the RN carries none.
 * @return Network time.
 */
static time_t relocate_fallback_deadline(void)
{
  return relocate_expiry_from_grace(TStime(), RELOCATE_GRACE_FALLBACK);
}

/** Make a record under a name.  It is linked, and its timer is NOT armed:
 * the caller fills it in and then calls relocate_tombstone_settle().
 * @param[in] oldname The tombstone's name.
 * @param[in] chan_ts Creation timestamp of the channel it is made for.
 * @param[in] newname The name the network has for its target.
 * @param[in] expires The deadline, network time.
 * @return The record.
 */
static struct RelocateTombstone *
relocate_tombstone_add_named(const char *oldname, time_t chan_ts,
                             const char *newname, time_t expires)
{
  struct RelocateTombstone *ts;

  /* One record per name.  One that is still under this name is not this
   * channel's live tombstone -- the callers deal with that case before
   * they come here -- but a leftover: the record of a tombstone that
   * lost its redirect and was waiting out its deadline, of another
   * channel that had the name, or one that waited for a channel.  It
   * goes, whatever state its timer is in. */
  if ((ts = relocate_tombstone_find_any(oldname)))
    relocate_tombstone_end(ts, 0);

  ts = (struct RelocateTombstone *)MyMalloc(sizeof(struct RelocateTombstone));
  memset(ts, 0, sizeof(*ts));
  ircd_strncpy(ts->oldname, oldname, sizeof(ts->oldname));
  ircd_strncpy(ts->newname, newname, sizeof(ts->newname));
  ts->chan_ts = chan_ts;
  ts->expires = expires;

  ts->next = relocate_tombstones;
  relocate_tombstones = ts;

  return ts;
}

/** Make the record of a tombstone that is here: bound to the channel's
 * name and creation timestamp.
 * @param[in] chptr The tombstone.
 * @param[in] newname The name the network has for its target.
 * @param[in] expires The deadline, network time.
 * @return The record.
 */
static struct RelocateTombstone *
relocate_tombstone_add(struct Channel *chptr, const char *newname,
                       time_t expires)
{
  return relocate_tombstone_add_named(chptr->chname, chptr->creationtime,
                                      newname, expires);
}

/** Arm a record's timer for its deadline, or arm it again for a deadline
 * that changed -- or, when the deadline is already here, do its work on
 * the spot and end the record.
 *
 * The deadline is network time and the event loop runs on this server's
 * own clock, so the timer is set for the deadline less TSoffset: the
 * same instant.  (A SETTIME that moves TSoffset afterwards does not move
 * a timer that is armed.)
 *
 * A deadline that is now or past -- an RN that says so, one that arrived
 * late, a record settled again after its time -- is not left to a timer
 * that is already due.  Such a timer runs only after the event loop has
 * dealt with the lines it has already read, and a JOIN of the old name
 * among them would still be forwarded.  relocate_tombstone_end() frees
 * the record whatever state its timer is in.
 * @param[in] ts The record, linked.
 * @return 1 when the record lives on with its timer armed; 0 when it was
 *         dissolved: @a ts is gone then, and its channel may be.
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

/** Detach a tombstone from its target (RelocateTombstone.detached): the
 * +L is withdrawn from the channel, with a MODE -L from the server to its
 * local members, and the operators are told, once.  See
 * relocate_tombstone_point() for what a detached tombstone is.
 * @param[in] ts The record.
 * @param[in] chptr The tombstone.
 * @param[in] there The channel that has the target's name here.
 */
static void relocate_tombstone_detach(struct RelocateTombstone *ts,
                                      struct Channel *chptr,
                                      struct Channel *there)
{
  relocate_withdraw_redirect(chptr);

  if (ts->detached)
    return;

  ts->detached = 1;
  sendto_opmask_butone(0, SNO_OLDSNO,
                       "Relocation tombstone %s: its target %s is another "
                       "channel on this server (created %Tu; the target was "
                       "created %Tu).  The tombstone has been detached from "
                       "its target: it forwards nobody and carries no "
                       "status, and is still dissolved at its deadline.",
                       ts->oldname, ts->newname, there->creationtime,
                       ts->target_ts);
}

/** Point a tombstone at a target -- or DETACH it, when the target's name
 * is not the target here.
 *
 * A tombstone's redirect may only ever name a channel that, IF it exists
 * on this server, is the channel the record means: the same name, and
 * the creation timestamp every channel of this relocation has
 * (@a target_ts).  A name that is free here is fine -- the tombstone then
 * points at a channel this server does not hold, as it does whenever its
 * target has emptied.  A name that ANOTHER channel has here is not:
 * pointed at it, the tombstone would forward every joiner into a
 * stranger's channel.  That happens when this server is out of step with
 * the network -- the network renamed the target to a name that is taken
 * here, or a BURST or an announcement names a target whose name is taken
 * here -- and when the target emptied and somebody made its name again
 * (relocate_channel_restamped(), relocate_join_verdict()).
 *
 * Then the tombstone is detached (RelocateTombstone.detached): the record
 * remembers the network's name for the target, the +L is withdrawn from
 * the channel (a MODE -L from the server to its local members), and the
 * operators are told.  A detached tombstone forwards nobody and admits
 * nobody (do_join()), nobody follows out of it with status
 * (relocate_follow()), and it still ends on time: its members are parted
 * at the deadline and +z goes, as for any tombstone.  It is attached
 * again as soon as something points it at a name that passes this test.
 * @param[in] ts The tombstone's record.
 * @param[in] chptr The tombstone.
 * @param[in] target The name the network has for the target.
 * @param[in] target_ts The target's creation timestamp.
 * @param[in] announce Non-zero to show the local members a changed
 *                     redirect (MODE +L); zero when the caller does,
 *                     after it has told them the channel moved.
 */
static void relocate_tombstone_point(struct RelocateTombstone *ts,
                                     struct Channel *chptr, const char *target,
                                     time_t target_ts, int announce)
{
  struct Channel *there = FindChannel(target);
  char target_buf[CHANNELLEN + 1];

  /* @a target may be the record's own newname. */
  ircd_strncpy(target_buf, target, sizeof(target_buf));
  ircd_strncpy(ts->newname, target_buf, sizeof(ts->newname));
  ts->target_ts = target_ts;
  ts->unsettled = 0;            /* the redirect is set from here */

  if (there && there->creationtime != target_ts) {
    relocate_tombstone_detach(ts, chptr, there);
    return;
  }

  ts->detached = 0;
  if (0 != ircd_strcmp(chptr->mode.redir, ts->newname)) {
    ircd_strncpy(chptr->mode.redir, ts->newname, sizeof(chptr->mode.redir));
    if (announce)
      relocate_announce_redirect(chptr);
  } else
    /* the same name, perhaps in another spelling */
    ircd_strncpy(chptr->mode.redir, ts->newname, sizeof(chptr->mode.redir));
}

/** A channel that tombstones redirect to has itself moved on -- it was
 * relocated again, or renamed: they redirect to where it went.  A JOIN
 * of the oldest name is then forwarded once and not along a chain ("#a
 * to #b, then #b to #c": #a redirects to #c), and never lands on a name
 * the community has left, which anybody could take.
 *
 * The target is a channel, not a name: only the tombstones bound to THE
 * channel that moved -- its name and its creation timestamp
 * (RelocateTombstone.target_ts) -- follow it.  One whose target emptied,
 * and whose target's name somebody has since taken, does not follow that
 * channel when it is renamed or relocated.  Each is repointed through
 * relocate_tombstone_point(): when the new name is another channel's on
 * this server it is detached instead.
 * @param[in] oldtarget The name that stopped being where the channel is.
 * @param[in] old_ts Creation timestamp of the channel that had that name,
 *                   or NULL when this server does not hold it (a rename
 *                   it could only pass on): every tombstone pointing at
 *                   the name is then repointed.
 * @param[in] newtarget The name it is under now.
 * @param[in] new_ts Creation timestamp of the channel under @a newtarget;
 *                   NULL to leave each record's as it is.
 */
static void relocate_tombstone_retarget(const char *oldtarget,
                                        const time_t *old_ts,
                                        const char *newtarget,
                                        const time_t *new_ts)
{
  struct RelocateTombstone *ts;
  /* Copies: either may point into a record this loop rewrites. */
  time_t was = old_ts ? *old_ts : 0;
  time_t becomes = new_ts ? *new_ts : 0;

  for (ts = relocate_tombstones; ts; ts = ts->next) {
    struct Channel *chptr;

    if (0 != ircd_strcmp(ts->newname, oldtarget))
      continue;
    if (old_ts && ts->target_ts != was)
      continue;

    /* Before the record is changed: the channel is recognised by its
     * redirect to where the record points NOW.  A record whose channel
     * is no longer its tombstone is left as it is. */
    if (!(chptr = relocate_tombstone_channel(ts)))
      continue;

    relocate_tombstone_point(ts, chptr, newtarget,
                             new_ts ? becomes : ts->target_ts, 1);
  }
}

/** A channel has been renamed by an RN -- one this server applied, or
 * one it could only pass on: every tombstone whose target it was now
 * points at its new name.
 *
 * Otherwise the tombstone's +L and its record would go on naming a
 * channel that no longer exists, and whoever made a channel of that name
 * next would be sent every user the tombstone forwards for the rest of
 * the grace.
 *
 * Every server does this from the RN alone, the one that cannot apply
 * the rename included: the network did rename the channel, and a
 * redirect left on the old name here would be the one that can be taken.
 * But a tombstone is pointed at the new name only when that name is free
 * here or is the target itself; when this server could not apply the
 * rename because ANOTHER channel has the new name, the tombstone is
 * detached (relocate_tombstone_point()).
 * @param[in] oldname The name the channel had.
 * @param[in] newname The name it has now.
 * @param[in] chptr The channel, when this server holds it (under either
 *                  name), or NULL when it does not.
 */
static void relocate_target_renamed(const char *oldname, const char *newname,
                                    struct Channel *chptr)
{
  relocate_tombstone_retarget(oldname, chptr ? &chptr->creationtime : NULL,
                              newname, chptr ? &chptr->creationtime : NULL);
}

/** Copy a ban list.  The tombstone keeps its own bans, so the new
 * channel gets copies.  make_ban() works out from the mask everything
 * that follows from it; who set the ban, when, and whether it is an
 * exception are carried over.
 * @param[in,out] dst Head of the list to fill (empty).
 * @param[in] src The list to copy.
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

/** Tell one LOCAL member who stays in a tombstone that the channel has
 * moved.  The words are those a server of the ircv3.2-upgrade branch
 * sends a client that did not ask for that branch's RELOCATE message,
 * which no client here can have.
 * @param[in] user The member.
 * @param[in] chptr The tombstone.
 * @param[in] newname Where the channel went.
 * @param[in] reason Reason given (may be empty).
 * @param[in] expires The tombstone's deadline, network time.
 */
static void relocate_notify_stayer(struct Client *user, struct Channel *chptr,
                                   const char *newname, const char *reason,
                                   time_t expires)
{
  char reasonpart[TOPICLEN + 4];

  if (*reason)
    ircd_snprintf(0, reasonpart, sizeof(reasonpart), " (%s)", reason);
  else
    reasonpart[0] = '\0';

  sendcmdto_one(&his, CMD_NOTICE, user,
                "%H :%s has moved to %s%s. Join %s to follow; this "
                "channel closes in %d minutes.",
                chptr, chptr->chname, newname, reasonpart, newname,
                (int)((expires > TStime() ? expires - TStime() : 0) / 60));
}

/** Take off a tombstone what would keep it from working as one, or what
 * is not a dissolving channel's to keep: the limit -- the redirect of
 * +L is followed only by a JOIN that finds the channel full (do_join()),
 * which without a limit is every JOIN -- and the channel passwords.
 * Nobody is told; every server does the same.
 * @param[in] chptr The tombstone.
 */
static void relocate_tombstone_normalise(struct Channel *chptr)
{
  /* The limit is its parameter, as the redirect is: there is no bit for
   * it in mode.mode. */
  chptr->mode.limit = 0;
  chptr->mode.apass[0] = '\0';
  chptr->mode.upass[0] = '\0';
}

/** Make a channel a tombstone's channel: +z, no limit and no passwords
 * (relocate_tombstone_normalise()).  The redirect is set by the caller
 * (relocate_execute() itself, relocate_tombstone_point()).  Nobody is
 * told here.
 * @param[in] chptr The channel that becomes a tombstone.
 * @param[in] registration_moved Non-zero when this server has moved the
 *            channel's registration (+R) to another channel and it comes
 *            off here: a relocation done from an RN.  Zero for a
 *            tombstone learned from a burst announcement, where +R is
 *            whatever the bursts say and counts at the deadline.
 */
static void relocate_mark_tombstone(struct Channel *chptr,
                                    int registration_moved)
{
  if (registration_moved)
    chptr->mode.mode &= ~MODE_REGISTERED;
  relocate_tombstone_normalise(chptr);

  chptr->mode.exmode |= EXMODE_PERSIST;
}

/** Relocate a channel on THIS server, as every server does from the same
 * RN: make the new channel with the old one's state, move the issuer,
 * tell the local members who stay, and turn the old channel into a
 * tombstone until @a expires.  Nothing is sent to servers.
 *
 * @param[in] sptr The issuer: the source of the RN.  Only a user who is
 *                 a member of @a chptr here is moved.  When the source is
 *                 a server (services relocated the channel), or a user
 *                 this server does not have in the channel, nobody is
 *                 moved and the new channel starts empty -- on every
 *                 server alike.
 * @param[in] chptr The channel; it keeps its name and becomes the
 *                  tombstone.  When @a expires is now or past it is
 *                  dissolved before this returns and may be freed.
 * @param[in] newname Name of the channel to make.
 * @param[in] reason Reason given (may be empty).
 * @param[in] expires The tombstone's deadline, network time.
 * @return 0 when done, -1 when @a newname cannot be a channel here, -2
 *         when a channel of that name exists here.
 */
static int relocate_execute(struct Client *sptr, struct Channel *chptr,
                            const char *newname, const char *reason,
                            time_t expires)
{
  struct Channel *newchan;
  struct Membership *member, *mover = NULL;
  struct RelocateTombstone *ts;
  struct SLink *link;
  char oldname[CHANNELLEN + 1];
  char newname_buf[CHANNELLEN + 1];

  if (strlen(newname) > CHANNELLEN)
    return -1;
  if (FindChannel(newname))
    return -2;

  ircd_strncpy(oldname, chptr->chname, sizeof(oldname));
  ircd_strncpy(newname_buf, newname, sizeof(newname_buf));

  /* A record still under this channel's name is a leftover: the caller
   * has dealt with a channel that is a live tombstone, so this is one
   * that lost its redirect and whose record was waiting out its deadline
   * to hand +z back.  Hand it back now, by that record's rule (not from
   * a registered channel), so that the new channel does not inherit a
   * tombstone's +z as the channel's own.  A record made for another
   * channel that had the name is just dropped: this channel's +z is its
   * own. */
  if ((ts = relocate_tombstone_find(oldname))) {
    if (ts->chan_ts == chptr->creationtime
        && !(chptr->mode.mode & MODE_REGISTERED))
      chptr->mode.exmode &= ~EXMODE_PERSIST;
    relocate_tombstone_end(ts, 0);
  }

  if (!(newchan = get_channel(sptr, newname_buf, CGT_CREATE)))
    return -1;

  /* 1. The channel's state goes to the new name -- what a rename keeps
   * by keeping the structure.  struct Mode is modes, key, limit and
   * passwords, so registration (+R) and ownership (the passwords) follow
   * the community; step 2 takes them off the tombstone.  The tombstone
   * keeps its own bans, so the new channel gets copies.  Pending invites
   * move: an invite is leave to join the community, which is at the new
   * name now, and each invited user's own list is repointed as
   * rename_channel() repoints it. */
  newchan->mode = chptr->mode;
  newchan->creationtime = chptr->creationtime;
  newchan->topic_time = chptr->topic_time;
  ircd_strncpy(newchan->topic, chptr->topic, sizeof(newchan->topic));
  ircd_strncpy(newchan->topic_nick, chptr->topic_nick,
               sizeof(newchan->topic_nick));
  relocate_copy_bans(&newchan->banlist, chptr->banlist);
  relocate_copy_bans(&newchan->exceptlist, chptr->exceptlist);

  newchan->invites = chptr->invites;
  chptr->invites = NULL;
  for (link = newchan->invites; link; link = link->next) {
    struct SLink *inv;

    for (inv = cli_user(link->value.cptr)->invited; inv; inv = inv->next) {
      if (inv->value.chptr == chptr) {
        inv->value.chptr = newchan;
        break;
      }
    }
  }

  /* 2. The old channel becomes the tombstone, BEFORE anybody leaves it:
   * +z is what keeps it when the issuer was its last member.  It is set
   * on the structure and never sent; every server sets it from the RN. */
  relocate_mark_tombstone(chptr, 1);
  /* newname_buf is the channel made a few lines up: the target itself. */
  ircd_strncpy(chptr->mode.redir, newname_buf, sizeof(chptr->mode.redir));

  /* 3. The members.  The issuer moves; everybody else stays where he
   * is, and is told when he is a user of this server.  A zombie is
   * neither moved nor told. */
  for (member = chptr->members; member; member = member->next_member) {
    if (IsZombie(member))
      continue;

    if (member->user == sptr)
      mover = member;
    else if (MyUser(member->user))
      relocate_notify_stayer(member->user, chptr, newname_buf, reason,
                             expires);
  }

  /* 4. Move the issuer, with the status he has; a hidden (+D) join stays
   * hidden.  Nothing is sent to servers -- the RN says it -- and the
   * issuer is never a user of this server, which has no command that
   * issues a relocation, so there is nobody to tell that he is in the
   * new channel now.  The local members who stay see him leave, unless
   * they never saw him join. */
  if (mover) {
    unsigned int status = mover->status & (CHFL_CHANOP | CHFL_HALFOP
                                           | CHFL_VOICE | CHFL_DELAYED);
    int oplevel = OpLevel(mover);

    add_user_to_channel(newchan, sptr, status, oplevel);
    remove_user_from_channel(sptr, chptr);

    if (!(status & CHFL_DELAYED))
      sendcmdto_channel_butserv_butone(sptr, CMD_PART, chptr, NULL, 0,
                                       "%H :Moved to %s", chptr, newname_buf);
  }

  /* 5. The redirect is shown to the members who stayed, the record is
   * made, and tombstones that redirected to this channel now redirect to
   * where it went. */
  relocate_announce_redirect(chptr);

  ts = relocate_tombstone_add(chptr, newname_buf, expires);
  ts->target_ts = newchan->creationtime;
  ircd_strncpy(ts->issued, newname_buf, sizeof(ts->issued));

  relocate_tombstone_retarget(oldname, &newchan->creationtime, newname_buf,
                              &newchan->creationtime);

  /* Last: a deadline that is already here dissolves the tombstone on the
   * spot, which frees ts and can free chptr. */
  relocate_tombstone_settle(ts);

  return 0;
}

/* ---------- Two relocations of one channel ---------- */

/** Make a channel "from a tombstone": the second new channel of a
 * channel that was relocated twice.
 *
 * It gets what the tombstone has AS AN ORDINARY CHANNEL -- modes, key,
 * creation timestamp, topic, bans -- and nothing of what makes the
 * tombstone one: no +z, no redirect.  What the first relocation MOVED
 * off the tombstone -- the limit, the registration, the passwords -- is
 * not on it to be copied; relocate_again() moves those between the two
 * new channels where that is needed.
 * @param[in] sptr The issuer (get_channel()'s client argument).
 * @param[in] tomb The tombstone.
 * @param[in] name Name of the channel to make; no channel has it.
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

/** Move the issuer of a relocation out of a tombstone into a channel,
 * the way relocate_execute() moves him: with his status, without a word
 * to the network (the RN says it on every server), and shown leaving to
 * the local members who stay.
 * @param[in] sptr The issuer.
 * @param[in] from The tombstone.
 * @param[in] to Where he goes.
 * @return 1 when he was moved, 0 when he is not a member of @a from (or
 *         is one of @a to already) and nothing was done.
 */
static int relocate_move_issuer(struct Client *sptr, struct Channel *from,
                                struct Channel *to)
{
  struct Membership *member;
  unsigned int status;
  int oplevel;

  if (!IsUser(sptr) || !(member = find_channel_member(sptr, from)))
    return 0;
  if (find_channel_member(sptr, to))
    return 0;

  /* A hidden (+D) join stays hidden, as in relocate_execute(). */
  status = member->status & (CHFL_CHANOP | CHFL_HALFOP | CHFL_VOICE
                             | CHFL_DELAYED);
  oplevel = OpLevel(member);

  add_user_to_channel(to, sptr, status, oplevel);
  remove_user_from_channel(sptr, from);         /* +z: from stays */

  if (!(status & CHFL_DELAYED))
    sendcmdto_channel_butserv_butone(sptr, CMD_PART, from, NULL, 0,
                                     "%H :Moved to %s", from, to->chname);

  return 1;
}

/** Tell the LOCAL members of a channel that has just become a tombstone
 * WITHOUT anybody being moved out of it -- the loser of a crossing, a
 * tombstone learned from a burst announcement: no relocation done here
 * has told them.
 * @param[in] ts The channel's record.
 * @param[in] chptr The tombstone.
 * @param[in] reason Reason (may be empty).
 * @param[in] announce Non-zero to show them the redirect (MODE +L) as
 *                     well; zero when they have been shown it already (a
 *                     BURST's own mode changes).
 */
static void relocate_tombstone_tell(struct RelocateTombstone *ts,
                                    struct Channel *chptr,
                                    const char *reason, int announce)
{
  struct Membership *member;

  for (member = chptr->members; member; member = member->next_member) {
    if (IsZombie(member) || !MyUser(member->user))
      continue;
    relocate_notify_stayer(member->user, chptr, ts->newname, reason,
                           ts->expires);
  }

  if (announce)
    relocate_announce_redirect(chptr);
}

/** Turn a channel into the tombstone of a relocation that lost a
 * crossing: mark it, record it, point it at the winner and tell its
 * local members.
 * @param[in] chptr The losing channel.
 * @param[in] winner Name of the winning channel.
 * @param[in] target_ts The winner's creation timestamp.
 * @param[in] family Name of the old channel both relocations were of.
 * @param[in] reason Reason of the winning relocation.
 * @param[in] expires The crossing's deadline.
 * @param[in] registration_moved See relocate_mark_tombstone().
 */
static void relocate_tombstone_loser(struct Channel *chptr, const char *winner,
                                     time_t target_ts, const char *family,
                                     const char *reason, time_t expires,
                                     int registration_moved)
{
  struct RelocateTombstone *ts;

  relocate_mark_tombstone(chptr, registration_moved);

  ts = relocate_tombstone_add(chptr, winner, expires);
  ircd_strncpy(ts->family, family, sizeof(ts->family));
  /* The winner by name and timestamp -- or detached, when the winner's
   * name is another channel's here. */
  chptr->mode.redir[0] = '\0';
  relocate_tombstone_point(ts, chptr, winner, target_ts, 0);
  if (!ts->detached)
    relocate_tombstone_tell(ts, chptr, reason, 1);
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

  /* ->next is read first: relocate_tombstone_settle() can free the
   * record (and only that one: a sweep destroys only its own channel,
   * whose record is off the list by then). */
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
 * sides of a netsplit).  Each has done its own; this server has to bring
 * the two together, and so that every server ends in the same state
 * whichever of the two it heard first, everything here is decided from
 * the two messages alone:
 *
 * - The same new name twice: one relocation, issued by two users.  The
 *   second issuer is moved into the new channel beside the first.
 * - Two new names: the one that sorts FIRST under the casemapping wins
 *   (relocate_name_cmp()) -- the names as the two relocations were
 *   issued, see the comparison below.  The old channel redirects to the
 *   winner, and so does every earlier tombstone that pointed at the
 *   loser.  The losing new channel becomes a tombstone redirecting to
 *   the winner as well, with its issuer in it, who can follow from there
 *   with a JOIN like anybody else.
 *
 *   The server that heard the WINNER first makes the loser's channel
 *   from the tombstone, moves the loser's issuer into it and marks it.
 *   The server that heard the LOSER first makes the winner's channel
 *   from the tombstone, hands it what its own relocation had moved to
 *   the loser's channel (the limit, the registration, the passwords, a
 *   +z the old channel had before it all), moves the winner's issuer
 *   into it, and marks the loser's channel.  Both end with the same
 *   three channels.
 * - One deadline for all of it: the latest of the deadlines involved
 *   (relocate_deadline_merge()), shared by the old channel's record and
 *   every loser's (RelocateTombstone.family), in whatever order they
 *   arrive.
 *
 * A chain is not this: in "#a to #b, then #b to #c" the second
 * relocation is of #b, which is nobody's tombstone but a tombstone's
 * TARGET; relocate_execute() does it and flattens.  This function is
 * entered only for an RN whose OLD name is a live tombstone.
 *
 * Nothing is sent to servers here; the caller passes the RN on as it
 * came, and every server works the same thing out.  When the name a new
 * channel would get is taken here by an unrelated channel, that step is
 * not done and the operators are told, as for a first relocation.
 *
 * The old channel and the losing one may be gone when this returns (a
 * deadline already here).
 * @param[in] sptr Issuer of the incoming relocation.
 * @param[in] ts The old channel's record (live).
 * @param[in] oldchan The old channel, a tombstone.
 * @param[in] incoming New name in the incoming relocation.
 * @param[in] reason Its reason (may be empty).
 * @param[in] expires Its deadline, network time, already checked.
 */
static void relocate_again(struct Client *sptr, struct RelocateTombstone *ts,
                           struct Channel *oldchan, const char *incoming,
                           const char *reason, time_t expires)
{
  struct RelocateTombstone *rec;
  struct Channel *wchan, *lchan;
  char oldname[CHANNELLEN + 1];
  char family[CHANNELLEN + 1];
  char current_buf[CHANNELLEN + 1];
  const char *current = current_buf;    /* the record's own copy changes */
  time_t deadline;
  int verdict;                          /* 0 same, <0 incoming wins, >0 loses */

  ircd_strncpy(oldname, ts->oldname, sizeof(oldname));
  ircd_strncpy(current_buf, ts->newname, sizeof(current_buf));

  /* Which relocation wins.  The incoming new name is compared with the
   * name this channel's own relocation was ISSUED with (ts->issued), not
   * with what its target is called by now: the target may have been
   * relocated on, or renamed, before this server heard of the second
   * relocation, and on a server that heard the two the other way round
   * it had not.  Both must name the same winner.
   *
   * And a channel that has itself LOST a crossing (ts->family) cannot
   * win one: a relocation of it -- issued where it was still alive --
   * loses with it, and its new channel becomes one more tombstone of the
   * winner.  (The server that heard that relocation before the crossing
   * did it as a chain and ends in the same state: when the crossing
   * arrives there, the chain's last channel is the loser's current
   * target, and that is what is made a tombstone.) */
  if (ts->family[0]) {
    verdict = 1;
    ircd_strncpy(family, ts->family, sizeof(family));
  } else {
    verdict = relocate_name_cmp(incoming, ts->issued[0] ? ts->issued
                                                        : current);
    ircd_strncpy(family, oldname, sizeof(family));
  }

  /* The crossing's one deadline: the later of the incoming one and the
   * old channel's -- which is already the latest of every relocation of
   * this channel heard so far, because relocate_family_settle() at the
   * end gives it to the old channel's record and every loser's each
   * time. */
  deadline = relocate_deadline_merge(ts->expires, expires);

  if (verdict == 0) {
    /* ---- The same relocation, twice ----
     * The second issuer goes where the first went: the channel of that
     * name when it is still there (as the target, or as a tombstone the
     * target has since been relocated on from), else the current target
     * (the channel was renamed), made again when it has emptied and gone
     * here. */
    if (!(wchan = FindChannel(incoming)) && !(wchan = FindChannel(current)))
      wchan = relocate_channel_from_tombstone(sptr, oldchan, current);
    else if (wchan->creationtime != ts->target_ts)
      /* Somebody else's channel under the name: not the one to put the
       * issuer in. */
      wchan = NULL;

    if (wchan)
      relocate_move_issuer(sptr, oldchan, wchan);

  } else if (verdict < 0) {
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

      /* The channel the losing relocation made here -- by name and
       * creation timestamp, not one somebody has made under the name
       * since (that one is left alone).  When it has emptied and gone
       * here it is made again, empty: the servers that heard the winner
       * first make the loser's channel in any case, and a tombstone some
       * servers hold and others do not is dissolved on some and not on
       * others. */
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
         * the winner now.  relocate_tombstone_loser() takes the same
         * things off the loser. */
        wchan->mode.mode |= lchan->mode.mode & MODE_REGISTERED;
        wchan->mode.limit = lchan->mode.limit;
        wchan->mode.exmode |= lchan->mode.exmode & EXMODE_PERSIST;
        ircd_strncpy(wchan->mode.apass, lchan->mode.apass,
                     sizeof(wchan->mode.apass));
        ircd_strncpy(wchan->mode.upass, lchan->mode.upass,
                     sizeof(wchan->mode.upass));
      }

      relocate_move_issuer(sptr, oldchan, wchan);
      ircd_strncpy(ts->issued, incoming, sizeof(ts->issued));

      /* The old channel, and every earlier tombstone that pointed at the
       * loser, now point at the winner. */
      relocate_tombstone_retarget(current, &ts->target_ts, incoming,
                                  &wchan->creationtime);

      if (lchan && !relocate_tombstone_find(lchan->chname))
        relocate_tombstone_loser(lchan, incoming, wchan->creationtime,
                                 family, reason, deadline, 1);
    }

  } else {
    /* ---- The incoming relocation loses ---- */
    lchan = FindChannel(incoming);
    rec = lchan ? relocate_tombstone_find(lchan->chname) : NULL;

    if (lchan && rec && relocate_tombstone_channel(rec) == lchan
        && 0 == ircd_strcmp(rec->newname, current)) {
      /* Already the loser's tombstone (the losing relocation heard a
       * second time): only its issuer may still have to go there. */
      relocate_move_issuer(sptr, oldchan, lchan);
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
      relocate_move_issuer(sptr, oldchan, lchan);
      relocate_tombstone_loser(lchan, current, ts->target_ts, family, reason,
                               deadline, 1);
    }
  }

  relocate_family_settle(family, deadline);
}

/* ---------- Who can be in a tombstone ----------
 *
 * A member who follows takes the status he holds in the tombstone when
 * he follows (below).  So an op who stayed can op or voice somebody in
 * the tombstone afterwards, and that member then arrives in the new
 * channel with it.  That is sound PROVIDED the membership of a tombstone
 * is closed: nobody gets in after the relocation.
 *
 * do_join() forwards a JOIN of a channel with a redirect only when the
 * channel is "full" (users >= limit).  A tombstone has no limit, so that
 * is always true -- until a remaining chanop sets one (MODE +l 500): a
 * stranger would then join the tombstone itself.  So for a live
 * tombstone do_join() forwards unconditionally (relocate_join_verdict()),
 * before it looks at +i, +k, bans, invites or X-tra ops: nothing a user
 * can set on the tombstone, and no INVITE, lets anybody in.  A user who does not follow
 * redirects (umode +L) is refused as before and is not joined either.  A
 * detached tombstone has nowhere to forward to and refuses the JOIN.
 *
 * A chanop removing +L ends the tombstone: the channel is then joined
 * like any channel and nothing follows out of it.  SVSJOIN puts a user
 * into a channel past every check; that is services' to answer for.  A
 * member a remote server brings (a JOIN from a server that does not hold
 * the record, the far side of a netsplit) is that server's user; this
 * server never moves him, and removes him with everybody at the
 * deadline.
 */

/** What is do_join() to do with a local JOIN of @a chptr?  Asked before
 * any admission check.
 *
 * - Not a live tombstone: the ordinary rules (RELOCATE_JOIN_ORDINARY).
 * - A live tombstone: forward to its redirect whatever its limit
 *   (RELOCATE_JOIN_FORWARD) -- after one more look at where the redirect
 *   leads.  The record knows its target by creation timestamp.  If a
 *   channel of ANOTHER timestamp has the target's name now -- the target
 *   emptied, was collected, and somebody made the name again, which no
 *   hook reports -- the target is lost: the tombstone is detached here
 *   and now, and the JOIN refused.  When no channel has the name the
 *   JOIN is forwarded and makes one: that is the joiner's own new
 *   channel, not somebody else's, and the next JOIN finds it and
 *   detaches.
 * - A detached tombstone: refuse (RELOCATE_JOIN_REFUSE); it has nowhere
 *   to forward to, and like every tombstone it admits nobody.
 * @param[in] chptr The channel being joined.
 * @return One of the RELOCATE_JOIN_ values.
 */
int relocate_join_verdict(struct Channel *chptr)
{
  struct RelocateTombstone *ts;
  struct Channel *there;

  if (!relocate_tombstones
      || !(ts = relocate_tombstone_find(chptr->chname))
      || relocate_tombstone_channel(ts) != chptr)
    return RELOCATE_JOIN_ORDINARY;

  if (!ts->detached && (there = FindChannel(ts->newname))
      && there->creationtime != ts->target_ts)
    relocate_tombstone_detach(ts, chptr, there);

  return ts->detached ? RELOCATE_JOIN_REFUSE : RELOCATE_JOIN_FORWARD;
}

/* ---------- Following: live status, then part ----------
 *
 * A member who stays in the tombstone does not lose his standing by
 * following later.  When he joins the new channel he takes with him the
 * status he holds IN THE TOMBSTONE AT THAT MOMENT, and leaves the
 * tombstone in the same breath.  Nothing is recorded when the relocation
 * runs: the membership is the standing, every server has the same one, a
 * MODE or KICK in the tombstone changes it like anywhere else, and the
 * PART that goes with the follow takes it off the network, so it is used
 * once.
 *
 * The rule, for a user of THIS server whose own JOIN of a channel has
 * just succeeded (do_join(); a JOIN of an old name that +L forwarded
 * comes the same way):
 *
 * 1. The channel joined must be the target of a live tombstone, by name
 *    and creation timestamp (RelocateTombstone.target_ts): the channel
 *    the relocation made, not one somebody made under the name after it
 *    emptied.  Targets are kept flat, so after "#a to #b to #c" every
 *    tombstone the user could come from points straight at the channel
 *    he has joined.
 * 2. The user must be a member of that tombstone right now, and not a
 *    zombie.  One who was kicked, has parted, or never was in it gets an
 *    ordinary JOIN.
 * 3. A user in SEVERAL such tombstones (he stayed in #a, followed to #b,
 *    stayed again when #b went to #c) leaves all of them and takes the
 *    union of what he holds in them.
 * 4. He is given what he holds there and does not have here already --
 *    never less than the JOIN itself gave him (a channel password that
 *    ops).
 * 5. He is parted from the tombstone(s) with a real PART, reason "Channel
 *    has moved to <new>" (the deadline's): to himself, to the members who
 *    stay, and to every server.
 *
 * On the wire, in this order, from the follower's server:
 *
 *     <user> J #new <creation-ts>                 (do_join(), just before)
 *     <server> M #new +o <user> <creation-ts>     (only if he had status)
 *     <user> L #old :Channel has moved to #new
 *
 * JOIN first: a MODE for somebody who is not in the channel is dropped by
 * the receiver.  PART last: the status is taken from the old membership,
 * and at no point is the user in neither channel.  Every receiver applies
 * three ordinary lines; nothing in them is specific to relocation, and a
 * remote user's follow needs no code here at all.
 *
 * Not done, on purpose:
 * - A JOIN of the new channel by somebody who is already in it is ignored
 *   by do_join() before any of this: nothing moves, and he is not parted
 *   from the tombstone either (a command that did nothing must not part
 *   its user from another channel).  He is parted at the deadline.
 * - A JOIN that fails (banned, +i, +k, +r, a full channel) returns from
 *   do_join() earlier still: the user stays in the tombstone.
 *
 * This is what a server of the ircv3.2-upgrade branch does for its own
 * users, less that branch's bouncer bookkeeping.  It is not something
 * this server offers: it completes a relocation another server issued,
 * for the users who happen to be here -- and the PART is what keeps every
 * other server's copy of the tombstone the same as this one's.
 */

/** A user of this server has joined @a chptr: if he is following out of
 * a tombstone, carry his status over and part him from there.  See
 * "Following: live status, then part".
 * @param[in] cptr The connection the JOIN came from.
 * @param[in] sptr The user who joined.
 * @param[in] chptr The channel he is now a member of.
 */
void relocate_follow(struct Client *cptr, struct Client *sptr,
                     struct Channel *chptr)
{
  struct RelocateTombstone *ts;
  struct Membership *here;
  struct JoinBuf part;
  char reason[CHANNELLEN + 32];
  unsigned int status = 0, grant;
  int oplevel = MAXOPLEVEL;

  /* The common case first: no tombstone anywhere. */
  if (!relocate_tombstones)
    return;
  if (!MyUser(sptr) || !(here = find_channel_member(sptr, chptr)))
    return;

  /* What does he hold in the tombstones that point here? */
  for (ts = relocate_tombstones; ts; ts = ts->next) {
    struct Channel *tomb;
    struct Membership *there;

    if (ts->detached || 0 != ircd_strcmp(ts->newname, chptr->chname)
        || ts->target_ts != chptr->creationtime)
      continue;
    if (!(tomb = relocate_tombstone_channel(ts)))
      continue;
    if (!(there = find_channel_member(sptr, tomb)))
      continue;

    status |= there->status & (CHFL_CHANOP | CHFL_HALFOP | CHFL_VOICE);
    if ((there->status & CHFL_CHANOP) && OpLevel(there) < oplevel)
      oplevel = OpLevel(there);
  }

  /* The status: what he holds there and not here.  (In no tombstone that
   * points here: nothing to give, and nothing to part below.) */
  grant = status & ~here->status;

  if (grant) {
    struct ModeBuf mbuf;

    /* A join that +D is hiding is shown first, as for any member who is
     * given a status (mode_process_clients()). */
    if (IsDelayedJoin(here) && !IsZombie(here))
      RevealDelayedJoin(here);

    here->status = (here->status & ~CHFL_DEOPPED) | grant;
    if (grant & CHFL_CHANOP)
      SetOpLevel(here, oplevel);

    modebuf_init(&mbuf, &me, cptr, chptr,
                 MODEBUF_DEST_CHANNEL | MODEBUF_DEST_SERVER);
    if (grant & CHFL_CHANOP)
      modebuf_mode_client(&mbuf, MODE_ADD | MODE_CHANOP, sptr, oplevel);
    if (grant & CHFL_HALFOP)
      modebuf_mode_client(&mbuf, MODE_ADD | MODE_HALFOP, sptr, oplevel);
    if (grant & CHFL_VOICE)
      modebuf_mode_client(&mbuf, MODE_ADD | MODE_VOICE, sptr, oplevel);
    modebuf_flush(&mbuf);
  }

  /* The PART(s), after the status has been taken: one line for all of
   * them.  A member the tombstone never saw join (+D) is not shown
   * leaving it; he is told himself (joinbuf_join()'s rule for a PART).
   * The list of records does not change under this loop: a tombstone is
   * +z, so losing a member never destroys it. */
  ircd_snprintf(0, reason, sizeof(reason), "Channel has moved to %s",
                chptr->chname);
  joinbuf_init(&part, sptr, cptr, JOINBUF_TYPE_PART, reason, 0);

  for (ts = relocate_tombstones; ts; ts = ts->next) {
    struct Channel *tomb;
    struct Membership *there;

    if (ts->detached || 0 != ircd_strcmp(ts->newname, chptr->chname)
        || ts->target_ts != chptr->creationtime)
      continue;
    if (!(tomb = relocate_tombstone_channel(ts)))
      continue;
    if (!(there = find_channel_member(sptr, tomb)))
      continue;

    joinbuf_join(&part, tomb, IsDelayedJoin(there) ? CHFL_DELAYED : 0);
  }

  joinbuf_flush(&part);
}

/** Pass a relocation on: "<source> RN <old> <new> C <expires> :<reason>"
 * to every link that takes RN, but the one it came from (rename_relay()).
 *
 * It is written out again and not repeated byte for byte, as a server of
 * the ircv3.2-upgrade branch writes it: with the deadline this server
 * went by -- the one it was sent, cut if it was absurd, or its own for a
 * message that carried none -- so that every server behind this one
 * dissolves the tombstone when this one does.  A well-formed RN goes on
 * exactly as it came.
 * @param[in] sptr Source of the RN, kept as it is.
 * @param[in] cptr Link it arrived on.
 * @param[in] oldname Old channel name.
 * @param[in] newname New channel name.
 * @param[in] expires The deadline this server went by, network time.
 * @param[in] reason Reason (may be empty; always sent).
 */
static void relocate_relay(struct Client *sptr, struct Client *cptr,
                           const char *oldname, const char *newname,
                           time_t expires, const char *reason)
{
  char digits[RELOCATE_EXPIRY_BUFLEN];
  char rest[BUFSIZE];

  relocate_expiry_format(digits, sizeof(digits), expires);
  ircd_snprintf(0, rest, sizeof(rest), "%s %s :%s", RELOCATE_MARKER, digits,
                reason);
  rename_relay(sptr, cptr, oldname, newname, rest);
}

/* ---------- The tombstone in the burst ----------
 *
 * A server that links, restarts or heals a netsplit inside a tombstone's
 * grace learns of the channel from its BURST -- "+z, +L <target>" and
 * whoever is still in it -- and from that alone it cannot tell a
 * tombstone from a persistent channel with a redirect: it would keep the
 * members and +zL for good.  So the record follows the channel's BURST:
 *
 *     <server> RT <old> <old-creation-ts> <new> <expires>
 *     AC RT #old 1731000000 #new 1731340900
 *
 * - <old>: the tombstone.  <old-creation-ts>: its channel's creation
 *   timestamp as the sender holds it -- with the name, the channel's
 *   identity, as in BURST.
 * - <new>: where it redirects (the name the network has for the target).
 * - <expires>: the deadline, network time, the same field as in the RN
 *   (include/rename_proto.h).
 *
 * The message is TOMBSTONE, token RT, between servers only.  It is sent
 * to the links an RN is sent to ('v' and 'r'), never to one with neither
 * flag, and passed on as it came to the same links by every server that
 * knows it, as a BURST is passed on, whether or not this server could
 * use it.
 *
 * Receiving it: relocate_announced().  Bringing a tombstone held here
 * through a BURST: relocate_tombstone_ts_lost() and _burst_done().
 */

/** A channel's BURST has been sent to a link (server_finish_burst()):
 * when the channel is a live tombstone, its record follows.
 * @param[in] cptr The link.
 * @param[in] chptr The channel.
 */
void relocate_burst(struct Client *cptr, struct Channel *chptr)
{
  struct RelocateTombstone *ts;
  char digits[RELOCATE_EXPIRY_BUFLEN];

  if (!relocate_tombstones || !TakesRename(cptr))
    return;

  /* Only a LIVE tombstone: a record whose channel is no longer its
   * tombstone (its +L was removed) is waiting to hand +z back and
   * describes nothing the other side should build. */
  if (!(ts = relocate_tombstone_find(chptr->chname))
      || relocate_tombstone_channel(ts) != chptr)
    return;

  relocate_expiry_format(digits, sizeof(digits), ts->expires);
  sendcmdto_one(&me, CMD_TOMBSTONE, cptr, "%H %Tu %s %s", chptr,
                chptr->creationtime, ts->newname, digits);
}

/** An announcement and this server's own record name different targets
 * for one old channel: the two sides of a netjoin each relocated it.
 * The crossing rule (relocate_again()) with what a burst can tell: no
 * issuer is known and nobody is moved -- the memberships are what the
 * BURSTs say -- so all there is to do is agree on the redirects, the
 * marks and the deadline.
 *
 * - The old channel redirects to the winner, and so does every earlier
 *   tombstone that pointed at the loser.
 * - The loser's channel is a tombstone redirecting to the winner.  It is
 *   one of the two new channels and reaches this server by its own
 *   BURST, before this announcement or after it.  When it is here -- the
 *   channel of the old one's creation timestamp, which every channel a
 *   relocation makes has -- it is marked now.  When it is not, a record
 *   WAITS for it under its name (RelocateTombstone.waiting) and
 *   relocate_tombstone_burst_done() marks it when its BURST has been
 *   taken in; a channel of another timestamp under that name is somebody
 *   else's and is never touched.  If no such channel ever comes the
 *   waiting record just expires.
 * - Both records, and every loser's, take the later deadline.
 *
 * Both sides work this out from the same pair of announcements.
 * @param[in] ts The old channel's record here (not waiting).
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

  ircd_strncpy(oldname, ts->oldname, sizeof(oldname));
  if (relocate_name_cmp(announced, ts->newname) < 0) {
    ircd_strncpy(winner_buf, announced, sizeof(winner_buf));
    ircd_strncpy(loser_buf, ts->newname, sizeof(loser_buf));
  } else {
    ircd_strncpy(winner_buf, ts->newname, sizeof(winner_buf));
    ircd_strncpy(loser_buf, announced, sizeof(loser_buf));
  }

  /* The old channel: the winner, or detached when the winner's name is
   * another channel's here. */
  relocate_mark_tombstone(chptr, 0);
  ircd_strncpy(ts->issued, winner, sizeof(ts->issued));
  relocate_tombstone_point(ts, chptr, winner, ts->target_ts, 1);

  /* Earlier tombstones that pointed at the loser. */
  relocate_tombstone_retarget(loser, &ts->target_ts, winner, &ts->target_ts);

  /* The loser. */
  rec = relocate_tombstone_find_any(loser);
  lchan = FindChannel(loser);

  if (rec && !rec->waiting) {
    /* Already a tombstone here in its own right (it was announced, or
     * relocated on): its own record stands. */
    ;
  } else if (lchan && lchan->creationtime == chan_ts) {
    relocate_tombstone_loser(lchan, winner, ts->target_ts, oldname, "",
                             deadline, 0);
  } else {
    rec = relocate_tombstone_add_named(loser, chan_ts, winner, deadline);
    rec->waiting = 1;
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

  /* A record under the name that was made for another channel is not a
   * record of this one; relocate_tombstone_add() replaces it. */
  if (ts && ts->chan_ts != chptr->creationtime)
    ts = NULL;

  memset(&facts, 0, sizeof(facts));
  facts.channel_exists = (chptr != NULL);
  facts.ts_matches = (chptr
                      && relocate_announce_ts_matches(chan_ts,
                                                      chptr->creationtime));
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
              chptr ? "the channel here is another one (its creation "
                      "timestamp is older, or more than a few seconds younger)"
                    : "no such channel here");
    return;

  case RELOCATE_ANNOUNCE_BUILD:
    /* Is the channel what the announcement describes -- +z, and the
     * announced redirect, or none (the sender's tombstone is detached
     * and its BURST had no +L)?  The BURST that precedes an announcement
     * leaves it so, also on a server that had ended its own record for
     * the channel: at an equal timestamp the modes are merged back.
     *
     * If it is not, there is no tombstone here and none is made: no
     * record that could come to match later.  One case leaves something
     * to undo: the channel carries ANOTHER redirect (an op's own +L here
     * won the BURST's merge).  The sender's tombstone has lost its
     * redirect to that merge too and is ending; the +z the merge put on
     * this channel was that tombstone's, and goes -- unless the channel
     * is registered. */
    if (!(chptr->mode.exmode & EXMODE_PERSIST)
        || (chptr->mode.redir[0]
            && 0 != ircd_strcmp(chptr->mode.redir, target))) {
      log_write(LS_SYSTEM, L_INFO, 0,
                "relocate: announced tombstone %s -> %s not taken: the "
                "channel here is not one (%s)", oldname, target,
                !(chptr->mode.exmode & EXMODE_PERSIST) ? "no +z"
                                                       : "another redirect");
      if ((chptr->mode.exmode & EXMODE_PERSIST)
          && !(chptr->mode.mode & MODE_REGISTERED)) {
        chptr->mode.exmode &= ~EXMODE_PERSIST;
        if (!chptr->members)
          schedule_destruct_event_1m(chptr);
      }
      return;
    }

    /* The BURST gave the channel its +z and +L; this is the record. */
    ts = relocate_tombstone_add(chptr, target, expires);
    ircd_strncpy(ts->issued, target, sizeof(ts->issued));

    relocate_tombstone_normalise(chptr);
    /* The new channel has the timestamp the sender's old channel has --
     * the announced one, which is not always this channel's
     * (relocate_announce_ts_matches()).  Pointing the tombstone detaches
     * it when the target's name is another channel's on this server;
     * then there is nowhere to tell the local members to go.  They were
     * never told the channel moved; no MODE +L from here for a redirect
     * the BURST's own mode change showed them. */
    relocate_tombstone_point(ts, chptr, target, chan_ts, 1);
    if (!ts->detached)
      relocate_tombstone_tell(ts, chptr, "", 0);
    relocate_tombstone_settle(ts);
    return;

  case RELOCATE_ANNOUNCE_MERGE:
    if (relocate_tombstone_channel(ts) == chptr) {
      relocate_tombstone_normalise(chptr);
      /* A detached tombstone is attached again when it can be. */
      if (ts->detached)
        relocate_tombstone_point(ts, chptr, target, ts->target_ts, 1);
    }
    ts->expires = relocate_deadline_merge(ts->expires, expires);
    relocate_tombstone_settle(ts);
    return;

  case RELOCATE_ANNOUNCE_CROSS:
    relocate_announced_cross(ts, chptr, target, expires);
    return;
  }
}

/** A BURST for a channel has been taken in (ms_burst(), last thing).
 *
 * - A record was WAITING for this channel (relocate_announced_cross())
 *   and this is it -- the creation timestamp it waited for: the channel
 *   becomes the tombstone the record describes, and its local members
 *   are told.
 * - The channel is a live tombstone: the merge may have put a limit or
 *   passwords back on it (the other side still held it as an ordinary
 *   channel); they come off again, or a JOIN of it would be forwarded
 *   only when it is full.
 * @param[in] chptr The channel.
 */
void relocate_tombstone_burst_done(struct Channel *chptr)
{
  struct RelocateTombstone *ts;

  if (!relocate_tombstones
      || !(ts = relocate_tombstone_find_any(chptr->chname)))
    return;

  if (ts->waiting) {
    if (chptr->creationtime != ts->chan_ts)
      return;                   /* somebody else's channel under the name */

    ts->waiting = 0;
    relocate_mark_tombstone(chptr, 0);
    chptr->mode.redir[0] = '\0';
    relocate_tombstone_point(ts, chptr, ts->newname, ts->target_ts, 0);
    if (!ts->detached)
      relocate_tombstone_tell(ts, chptr, "", 1);
    return;
  }

  /* A detached tombstone that the BURST gave its redirect back (the
   * sender holds it attached): attached now if the name has become free
   * or the target's, taken off again if not. */
  if (ts->detached && chptr->creationtime == ts->chan_ts
      && (chptr->mode.exmode & EXMODE_PERSIST)
      && 0 == ircd_strcmp(chptr->mode.redir, ts->newname))
    relocate_tombstone_point(ts, chptr, ts->newname, ts->target_ts, 1);

  if (relocate_tombstone_channel(ts) == chptr)
    relocate_tombstone_normalise(chptr);
  else if (ts->chan_ts == chptr->creationtime)
    /* The merge left a redirect on it that is not the record's.  If the
     * sender relocated the channel elsewhere, its announcement is the
     * next line and settles this as a crossing; until something does,
     * the record is unsettled (see the field). */
    ts->unsettled = 1;
}

/** ms_tombstone - a relocation tombstone announced by a server.
 *
 * parv[0] = sender prefix (a server)
 * parv[1] = the tombstone's (old) channel name
 * parv[2] = that channel's creation timestamp
 * parv[3] = the channel it redirects to
 * parv[4] = the deadline, network time
 *
 * See "The tombstone in the burst" for the line and who gets it, and
 * relocate_announced() for what this server makes of it.  Like RN the
 * message is in the token table only (MFLG_TOKONLY).
 *
 * @param[in] cptr Link the message arrived on.
 * @param[in] sptr Source of the message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int ms_tombstone(struct Client *cptr, struct Client *sptr, int parc,
                 char *parv[])
{
  struct DLink *lp;
  time_t chan_ts, expires;
  enum RenameNameError bad;

  /* Refused from the message alone -- every server refuses alike, so
   * there is nobody to keep in step and the line is not passed on: a
   * source that is not a server, too few fields, names RN would refuse,
   * a channel redirecting to itself, a timestamp or deadline that is not
   * a number. */
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
  for (lp = cli_serv(&me)->down; lp; lp = lp->next) {
    if (lp->value.cptr == cptr || !TakesRename(lp->value.cptr))
      continue;
    sendcmdto_one(sptr, CMD_TOMBSTONE, lp->value.cptr, "%s %s %s %s",
                  parv[1], parv[2], parv[3], parv[4]);
  }

  return 0;
}

/** ms_rename - a channel was renamed, or relocated, on another server.
 *
 * parv[0] = sender prefix
 * parv[1] = old channel name
 * parv[2] = new channel name
 * parv[3] = reason (optional, trailing)
 *
 * or, for a relocation (see RELOCATE_MARKER):
 *
 * parv[3] = "C"
 * parv[4] = the tombstone's deadline, network time (absent in the
 *           five-parameter form of an older server)
 * parv[parc - 1] = reason
 *
 * The message is reachable from a server link only: it is in the token
 * table and not in the command table (MFLG_TOKONLY in parse.c), so a
 * user's "RENAME" is an unknown command here, as it always was, and
 * "RN" from a user is not looked up as a token at all.  The source is
 * whatever the sending server gave: the user who renamed the channel as
 * a rule, possibly a server.  A rename uses it for nothing but the
 * relay; a relocation moves it to the new channel when it is a member of
 * the old one.  It is always a client this server knows, and never one
 * of its own: parse_server() drops a line whose source it cannot find or
 * that arrives from the wrong direction before any handler sees it.
 *
 * @param[in] cptr Link the message arrived on.
 * @param[in] sptr Source of the message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int ms_rename(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct Channel *chptr, *taken;
  const char *oldname;
  const char *newname;
  const char *reason;
  enum RenameNameError bad;
  char oldname_buf[CHANNELLEN + 1];
  char rest[BUFSIZE];
  int relocate = 0;
  time_t expires = 0;
  int rc;

  if (parc < 3 || EmptyString(parv[1]) || EmptyString(parv[2]))
    return 0;

  oldname = parv[1];
  newname = parv[2];
  reason = (parc > 3 && !EmptyString(parv[3])) ? parv[3] : "";

  /* A relocation: the marker, and at least one parameter after it.  With
   * six parameters the fifth is the deadline.  With five, the message
   * comes from or through a server from before the deadline travelled,
   * and this server counts a grace of its own from now, as every server
   * did then.  A fifth of six that is not a deadline gets the same
   * fallback, and a notice: the relocation itself has to be done either
   * way, or this server's members differ from everybody's.  A deadline
   * more than RELOCATE_GRACE_MAX ahead is cut to that
   * (relocate_expiry_check()); one that is past is kept, and dissolves
   * the tombstone as soon as it is made.
   *
   * The reason is the last parameter; what an RN with more than six has
   * between the deadline and the reason is not read. */
  if (parc > 4 && 0 == strcmp(parv[3], RELOCATE_MARKER)) {
    relocate = 1;
    reason = !EmptyString(parv[parc - 1]) ? parv[parc - 1] : "";

    if (parc == 5) {
      expires = relocate_fallback_deadline();
    } else if (!relocate_expiry_parse(parv[4], &expires)) {
      protocol_violation(cptr, "RENAME %s -> %s from %s: \"%s\" is not a "
                         "relocation deadline; using this server's own grace",
                         parv[1], parv[2], cli_name(sptr), parv[4]);
      expires = relocate_fallback_deadline();
    } else if (relocate_expiry_check(&expires, TStime())
               == RELOCATE_EXPIRY_CLAMPED) {
      log_write(LS_SYSTEM, L_WARNING, 0,
                "RENAME %s -> %s from %s carries a deadline (%s) more than "
                "%d seconds ahead; cut to %Tu",
                parv[1], parv[2], cli_name(cptr), parv[4], RELOCATE_GRACE_MAX,
                expires);
    }
  }

  /* Names that are refused for what they are: not applied and NOT passed
   * on.  Every server judges these from the message alone and refuses
   * alike, so there is no server behind this one to keep in step, and
   * passing the line on would only spread it.
   *
   * - A local (&) channel on either side.  RN is applied by name on every
   *   server; "&ops" here is not the channel the sender renamed, and a
   *   global channel renamed to "&x" would become one private channel per
   *   server.  The same rule as for a remote JOIN of a local channel
   *   (ms_join).
   * - A name that is not a channel name at all, old or new.
   * - A new name with a byte outside the channel character set: a comma,
   *   a space or control character, 0xA0.  The comma is the one that
   *   breaks the protocol -- JOIN, PART and CREATE carry channel LISTS,
   *   so every later "J #a,b" would be read as two channels -- and the
   *   rest are bytes m_join lets no user join, so such a channel could
   *   not be joined or parted by name again.  The OLD name's bytes are
   *   not checked: renaming a badly named channel away is the repair.
   * - A new name over the compile-time CHANNELLEN, which no server can
   *   store.
   *
   * This server's CHANNELLEN and VALID_UTF8_CHANNELS_ONLY features and
   * its BADCHAN list are not applied: they are the policy of the server
   * the user is on, as for a remote JOIN.
   *
   * A relocation carries the same two names and is held to the same
   * rules. */
  bad = rename_check_names(oldname, newname, CHANNELLEN, 0);
  if (bad != RENAME_NAME_OK)
    return protocol_violation(cptr, "RENAME %s -> %s from %s refused: %s",
                              oldname, newname, cli_name(sptr),
                              rename_name_error_text(bad));

  chptr = FindChannel(oldname);

  /* A relocation.  Done here when this server can; when it cannot -- the
   * old channel is not here, the new name is taken here -- it is still
   * passed on, for the reason given for a rename below: that is this
   * server's state and says nothing of the servers behind it, which
   * would otherwise keep the old channel, with the issuer in it, and
   * never hear of the tombstone or its deadline.  Local state is left
   * alone, the operators are told, and the line goes to the links an
   * applied relocation would have gone to, in the same form. */
  if (relocate) {
    if (!chptr) {
      sendto_opmask_butone(0, SNO_OLDSNO,
                           "RELOCATE %s -> %s from %C NOT applied locally: "
                           "%s does not exist on this server.  The "
                           "relocation has been relayed onward; unless that "
                           "channel has just emptied everywhere, this server "
                           "is now divergent and needs manual "
                           "reconciliation.",
                           oldname, newname, sptr, oldname);
      /* The names as received: there is no local spelling to prefer. */
      relocate_relay(sptr, cptr, oldname, newname, expires, reason);
      return 0;
    }

    /* The name the channel has here, in this server's spelling. */
    ircd_strncpy(oldname_buf, chptr->chname, CHANNELLEN + 1);

    /* The channel is already a live tombstone here: it has been
     * relocated twice, by two servers that had not heard of each other.
     * A second relocation is not done on top of the first;
     * relocate_again() decides from the two messages alone what both
     * leave behind, and the RN goes on as it came, so that the servers
     * behind decide the same.  (chptr may be gone when that returns.) */
    {
      struct RelocateTombstone *ts = relocate_tombstone_find(oldname_buf);

      if (ts && relocate_tombstone_channel(ts) == chptr) {
        relocate_again(sptr, ts, chptr, newname, reason, expires);
        relocate_relay(sptr, cptr, oldname_buf, newname, expires, reason);
        return 0;
      }
    }

    /* chptr may be gone when this returns (a deadline of "now"). */
    rc = relocate_execute(sptr, chptr, newname, reason, expires);

    if (rc == -2)
      sendto_opmask_butone(0, SNO_OLDSNO,
                           "RELOCATE %s -> %s from %C NOT applied locally: "
                           "%s already exists on this server.  The rename "
                           "has been relayed onward, so this server is now "
                           "divergent and needs manual reconciliation.",
                           oldname_buf, newname, sptr, newname);
    else if (rc != 0)
      sendto_opmask_butone(0, SNO_OLDSNO,
                           "RELOCATE %s -> %s from %C NOT applied locally "
                           "(relocate_execute: %d).  The relocation has "
                           "been relayed onward, so this server is now "
                           "divergent and needs manual reconciliation.",
                           oldname_buf, newname, sptr, rc);

    relocate_relay(sptr, cptr, oldname_buf, newname, expires, reason);
    return 0;
  }

  /* A rename.  Apply it when this server can; when it cannot, the rename
   * is still passed on.
   *
   * The names were judged above, so what is left to stop it is this
   * server's own state: the channel is not here under the old name, or
   * the new name is taken here.  Neither says anything about the servers
   * behind this one.  Two servers can disagree for a moment -- a user
   * creates #new here while #old is renamed to #new elsewhere, two
   * renames of one channel cross, the channel emptied here just before
   * the RN arrived -- and a server that answered by dropping the line
   * would be a wall: everything behind it would never hear of the rename
   * and keep the old name for good.  So: leave local state alone, tell
   * the operators (this server may now differ from the network, and only
   * a person can sort that out), and pass the line on as it came.
   *
   * No loop can come of it: the line goes to every link but the one it
   * arrived on, here as on success, and the network is a tree. */
  ircd_snprintf(0, rest, sizeof(rest), ":%s", reason);

  taken = chptr ? FindChannel(newname) : NULL;

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
    /* The two names are one channel here: they differ in case only.  A
     * server that issues renames refuses that, so only one that
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
    /* The name the channel has here, in this server's spelling. */
    ircd_strncpy(oldname_buf, chptr->chname, CHANNELLEN + 1);

    /* May replace the structure; chptr is updated. */
    rc = rename_channel(&chptr, newname);
    if (rc != 0)
      sendto_opmask_butone(0, SNO_OLDSNO,
                           "RENAME %s -> %s from %C NOT applied locally "
                           "(rename_channel: %d).  The rename has been "
                           "relayed onward, so this server is now "
                           "divergent and needs manual reconciliation.",
                           oldname, newname, sptr, rc);
    else {
      /* The channel may be a relocation tombstone: its record goes with
       * it to the new name.  Or a tombstone's target: the tombstone
       * follows it. */
      relocate_tombstone_renamed(oldname_buf, chptr);
      relocate_target_renamed(oldname_buf, chptr->chname, chptr);
    }
  }

  if (rc != 0) {
    Debug((DEBUG_ERROR, "RENAME from %s not applied, relayed: %s -> %s",
           cli_name(sptr), oldname, newname));

    /* Not applied HERE -- but the network renamed the channel, and its
     * tombstones' redirects with it: ours follow, or they would name a
     * channel that is gone everywhere else (relocate_target_renamed()).
     * Not for a case-only rename: both names are one name. */
    if (taken != chptr || !chptr)
      relocate_target_renamed(oldname, newname, chptr);

    /* The names as received: there is no local spelling to prefer. */
    rename_relay(sptr, cptr, oldname, newname, rest);
    return 0;
  }

  send_rename_to_members(chptr, oldname_buf, reason);
  rename_relay(sptr, cptr, oldname_buf, chptr->chname, rest);

  return 0;
}

/* ---------- Services arbitration, passing through ----------
 *
 * Before it renames a registered channel, a server of the ircv3.2-upgrade
 * branch asks services for permission, and services answer.  Both lines
 * ride on ACCOUNT (include/rename_proto.h has the three shapes and the
 * cookie):
 *
 *     <origin> AC <user> R <cookie> <#chan> RENAME <new>
 *     <services> AC <cookie> A RENAME
 *     <services> AC <cookie> D RENAME :<reason>
 *
 * Neither is addressed.  The query goes toward the services server
 * (find_services_server(), the same one on every hop); the reply goes to
 * the server named in its cookie, <origin-numeric>.<n>.  A server in
 * between keeps nothing about the request and forwards both lines with
 * their original source.
 *
 * This server is only ever in between: it has no RENAME command, so it
 * never asks, and no reply is ever meant for it.  It forwards, or drops:
 *
 * - a query only when its cookie has the routed form and names the
 *   server the query comes from (rename_query_relayable()), so that the
 *   answer can come back to nobody else;
 * - a reply only from a services server, and only toward a known server
 *   that is not back down the link the reply arrived on
 *   (rename_reply_decide()).  A reply whose cookie names this server, or
 *   a bare number that names nobody, has no request here to answer and
 *   is dropped.
 *
 * The server that asked makes the checks that need its own state: that
 * request <n> is pending, and that the answer comes from the services
 * server it was sent to.
 */

/** Find the services server rename permission queries go to.
 *
 * The query names no destination, so the server that asks and every
 * server that passes the query on have to pick the SAME services server:
 * the asking server accepts an answer only from the one it picked.
 * Hence a rule that does not depend on anything local, and that is the
 * asking server's rule: of the servers that announced themselves as
 * services ('s' in their SERVER flags), the one with the lowest numeric.
 * With one services server -- the usual network -- there is nothing to
 * choose.
 * @return The services server, or NULL if none is linked.
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
   * timeout tells them. */
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

/** Relay services' answer to a permission query toward the server that
 * asked, or drop it.
 * @param[in] cptr Link the reply arrived on.
 * @param[in] sptr Its source.
 * @param[in] parc Number of parameters (at least four).
 * @param[in] parv parv[1] cookie, parv[2] "A" or "D", parv[3] "RENAME",
 *                 parv[4] the reason of a "D" (optional).
 */
static void rename_services_reply_relay(struct Client *cptr,
                                        struct Client *sptr, int parc,
                                        char *parv[])
{
  const char *reason = (parc > 4) ? parv[4] : NULL;
  struct RenameReplyFacts facts;
  struct Client *origin = NULL;
  enum RenameReplyVerdict verdict;
  char numeric[3];
  unsigned int n = 0;

  /* Gather what rename_reply_decide() rules on.
   *
   * "Services" is a server that announced itself as one: IsService() is
   * the 's' in its SERVER line's flags (set_server_flags() in m_server.c,
   * repeated by every hop that introduces the server) and nothing more --
   * a server's own word, no configuration of this server behind it.  A
   * reply is carried on the strength of that alone.  It is the same test
   * the asking server applies, which then also requires the reply to
   * come from the one services server it sent the request to.
   *
   * bound_name stays NULL: this server sends no requests, so none is
   * pending here, and a reply that could only be this server's own (its
   * numeric in the cookie, or a bare number) comes out as "no such
   * request". */
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

  verdict = rename_reply_decide(&facts);

  switch (verdict) {
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
    /* Somebody answering who is not services: operators should hear of
     * it. */
    protocol_violation(cptr, "ACCOUNT rename reply (cookie %s) from %s "
                       "ignored: %s", parv[1], cli_name(sptr),
                       rename_reply_verdict_text(verdict));
    return;

  default:
    /* Misrouted or malformed, or addressed to this server, which never
     * asked. */
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
 * account name, and the reply's cookie is looked up as a server numeric.
 *
 * The query is recognised exactly as services recognise it -- subtype R,
 * at least seven parameters, the fifth the literal RENAME -- so that the
 * relay and services always agree about which lines are queries.  An
 * account stamp never has that shape: it has at most five parameters.
 * The reply is recognised by the RENAME that follows the A or D; a
 * login-on-connect reply has a request id there, which starts with a
 * dot.
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
    rename_services_reply_relay(cptr, sptr, parc, parv);
    return 1;
  }

  return 0;
}
