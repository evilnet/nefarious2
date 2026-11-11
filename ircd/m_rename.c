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
 *   server that carries renames the way this one does).
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
