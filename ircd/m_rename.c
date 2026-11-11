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
 * - it passes it on to every link whose server said it takes it: 'v' in
 *   its SERVER flags (a server of that branch) or 'r' (services, or a
 *   server that carries renames the way this one does);
 * - it carries the question such a server asks services before it
 *   renames a registered channel, and services' answer, between the two
 *   (rename_services_ac()).
 */
#include "config.h"

#include "capab.h"
#include "channel.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
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
 * relocation, a different feature of the ircv3.2-upgrade branch (members
 * are asked to follow to the new channel instead of being moved):
 *
 *     rename:      RN <old> <new> :<reason>
 *     relocation:  RN <old> <new> C [<more>] :<reason>
 *
 * It counts only when at least one more parameter follows it: "RN <old>
 * <new> :C" is a rename whose reason is the letter C.  That is the test
 * the servers that implement relocation apply, so that every server reads
 * one line the same way.  This server does not implement relocation; see
 * ms_rename().
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
 *                 wire: ":<reason>" for a rename.
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
 * parv[4..parc - 1] = whatever a relocation carries; the last is its
 *                     reason
 *
 * The message is reachable from a server link only: it is in the token
 * table and not in the command table (MFLG_TOKONLY in parse.c), so a
 * user's "RENAME" is an unknown command here, as it always was, and
 * "RN" from a user is not looked up as a token at all.  The source is
 * whatever the sending server gave: the user who renamed the channel as
 * a rule, possibly a server.  It is not used for anything but the relay.
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
  int rc;

  if (parc < 3 || EmptyString(parv[1]) || EmptyString(parv[2]))
    return 0;

  oldname = parv[1];
  newname = parv[2];
  reason = (parc > 3 && !EmptyString(parv[3])) ? parv[3] : "";

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

  /* A relocation.  This server does not implement it, and must not take
   * it for a rename: a rename moves every member, a relocation only
   * those who agreed, and a server that moved them all would disagree
   * with every other server about who is on which channel.  So nothing
   * is changed here.  The line is still passed on, unchanged, to the
   * links that take RN -- the servers behind this one may well implement
   * it -- and the operators are told, because from here on this server's
   * view of the two channels differs from the network's.
   *
   * The parameters after the marker are not interpreted, only repeated:
   * all but the last are single words, the last may hold anything. */
  if (parc > 4 && 0 == strcmp(parv[3], RELOCATE_MARKER)) {
    size_t len = 0;
    int i;

    rest[0] = '\0';
    for (i = 3; i < parc && len < sizeof(rest) - 1; i++) {
      ircd_snprintf(0, rest + len, sizeof(rest) - len,
                    (i < parc - 1) ? "%s " : ":%s", parv[i]);
      len += strlen(rest + len);
    }

    sendto_opmask_butone(0, SNO_OLDSNO,
                         "RENAME %s -> %s from %C is a channel relocation, "
                         "which this server does not support.  Nothing was "
                         "changed here and the message has been relayed "
                         "onward, so this server now differs from the "
                         "servers that applied it.",
                         oldname, newname, sptr);
    rename_relay(sptr, cptr, oldname, newname, rest);
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

  chptr = FindChannel(oldname);
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
  }

  if (rc != 0) {
    Debug((DEBUG_ERROR, "RENAME from %s not applied, relayed: %s -> %s",
           cli_name(sptr), oldname, newname));
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
