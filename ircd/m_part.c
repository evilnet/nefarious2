/*
 * IRC - Internet Relay Chat, ircd/m_part.c
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
 *
 * $Id: m_part.c 1344 2005-03-30 04:01:17Z entrope $
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

#include "channel.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_log.h"
#include "ircd_features.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "numeric.h"
#include "numnicks.h"
#include "send.h"
#include "bouncer_session.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <string.h>

/*
 * m_part - generic message handler
 *
 * parv[0] = sender prefix
 * parv[1] = channel
 * parv[parc - 1] = comment
 */
int m_part(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Channel *chptr;
  struct Membership *member;
  struct JoinBuf parts;
  unsigned int flags = 0;
  char *p = 0;
  char *name;
  struct Client *alias_source = NULL;

  /* Alias PART means the user is leaving — rewrite to primary so
   * joinbuf removes the primary (triggering bounce_sync_alias_part to
   * clean up all aliases), and the L token carries the primary numeric.
   * For remote primaries, jb_alias_source enables split S2S delivery:
   * alias numeric to the primary's server, primary numeric to others. */
  if (IsBouncerAlias(sptr) && cli_alias_primary(sptr)) {
    alias_source = sptr;
    sptr = cli_alias_primary(sptr);
  }

  ClrFlag(sptr, FLAG_TS8);

  /* check number of arguments */
  if (parc < 2 || parv[1][0] == '\0')
    return need_more_params(sptr, "PART");

  /* UTF8ONLY enforcement on part message */
  if (parc > 2 && !EmptyString(parv[parc - 1]) &&
      feature_bool(FEAT_UTF8ONLY) && !string_is_valid_utf8(parv[parc - 1])) {
    if (feature_bool(FEAT_UTF8ONLY_STRICT)) {
      send_fail(sptr, "PART", "INVALID_UTF8", NULL,
                "Part message contains invalid UTF-8 and was rejected");
      return 0;
    }
    /* Warn mode: sanitize the part message */
    string_sanitize_utf8(parv[parc - 1]);
    send_warn(sptr, "PART", "INVALID_UTF8", NULL,
              "Part message contained invalid UTF-8 and was sanitized");
  }

  /* init join/part buffer */
  joinbuf_init(&parts, sptr, cptr, JOINBUF_TYPE_PART,
	       (parc > 2 && !EmptyString(parv[parc - 1])) ? parv[parc - 1] : 0,
	       0);
  if (alias_source && !MyConnect(sptr))
    parts.jb_alias_source = alias_source;

  /* scan through channel list */
  for (name = ircd_strtok(&p, parv[1], ","); name;
       name = ircd_strtok(&p, 0, ",")) {

    chptr = get_channel(sptr, name, CGT_NO_CREATE); /* look up channel */

    if (!chptr) { /* complain if there isn't such a channel */
      send_reply(sptr, ERR_NOSUCHCHANNEL, name);
      continue;
    }

    if (!(member = find_member_link(chptr, sptr))) { /* complain if not on */
      send_reply(sptr, ERR_NOTONCHANNEL, chptr->chname);
      continue;
    }

    assert(!IsZombie(member)); /* Local users should never zombie */

    if (!member_can_send_to_channel(member, 0))
    {
      flags |= CHFL_BANNED;
      /* Remote clients don't want to see a comment either. */
      parts.jb_comment = 0;
    }

    /* Strip PART message if required */
    if (chptr->mode.exmode & EXMODE_NOQUITPARTS)
      parts.jb_comment = 0;

    /* Strip PART message if color blocked and has color */
    if ((chptr->mode.exmode & EXMODE_NOCOLOR) && parts.jb_comment && HasColor(parts.jb_comment))
      parts.jb_comment = 0;

    /* Strip color from PART message */
    if ((chptr->mode.exmode & EXMODE_STRIPCOLOR) && (parts.jb_comment != 0)) {
      parts.jb_comment = (char*)StripColor(parts.jb_comment);
      if (EmptyString(parts.jb_comment))
        parts.jb_comment = 0;
    }

    if (IsDelayedJoin(member))
      flags |= CHFL_DELAYED;

    joinbuf_join(&parts, chptr, flags); /* part client from channel */
  }

  return joinbuf_flush(&parts); /* flush channel parts */
}

/*
 * ms_part - server message handler
 *
 * parv[0] = sender prefix
 * parv[1] = channel
 * parv[parc - 1] = comment
 */
int ms_part(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Channel *chptr;
  struct Membership *member;
  struct JoinBuf parts;
  unsigned int flags;
  char *p = 0;
  char *name;
  struct Client *alias_source = NULL;

  /* Alias PART — rewrite to primary unconditionally.  On the primary's
   * server, this triggers normal PART + bounce_sync_alias_part cascade.
   * On other servers, the primary was already the jb_source (from the
   * split delivery's primary-numeric buffer). */
  if (IsBouncerAlias(sptr) && cli_alias_primary(sptr)) {
    alias_source = sptr;
    sptr = cli_alias_primary(sptr);
  }

  ClrFlag(sptr, FLAG_TS8);

  /* check number of arguments */
  if (parc < 2 || parv[1][0] == '\0')
    return need_more_params(sptr, "PART");

  /* init join/part buffer */
  joinbuf_init(&parts, sptr, cptr, JOINBUF_TYPE_PART,
	       (parc > 2 && !EmptyString(parv[parc - 1])) ? parv[parc - 1] : 0,
	       0);
  if (alias_source && !MyConnect(sptr))
    parts.jb_alias_source = alias_source;

  /* Parse per-channel msgids from incoming S2S multi-msgid tag.
   * Format: "msgid1+msgid2+msgid3" — positional match to channel list. */
  {
    char incoming_msgids[MAXJOINARGS][16];
    int chan_idx = 0;
    memset(incoming_msgids, 0, sizeof(incoming_msgids));
    {
      const char *multi = cli_s2s_multi_msgid(cptr);
      if (multi[0]) {
        const char *mp = multi;
        int idx = 0;
        while (mp && *mp && idx < MAXJOINARGS) {
          const char *plus = strchr(mp, '+');
          int len = plus ? (int)(plus - mp) : (int)strlen(mp);
          if (len > 0 && len < (int)sizeof(incoming_msgids[0])) {
            memcpy(incoming_msgids[idx], mp, len);
            incoming_msgids[idx][len] = '\0';
          }
          idx++;
          mp = plus ? plus + 1 : NULL;
        }
      }
    }
    if (cli_s2s_time_ms(cptr))
      parts.jb_msgid_time_ms = cli_s2s_time_ms(cptr);

  /* scan through channel list */
  for (name = ircd_strtok(&p, parv[1], ","); name;
       name = ircd_strtok(&p, 0, ","), chan_idx++) {

    flags = 0;

    chptr = get_channel(sptr, name, CGT_NO_CREATE); /* look up channel */

    if (!chptr || IsLocalChannel(name) ||
	!(member = find_member_link(chptr, sptr)))
      continue; /* ignore from remote clients */

    if (IsZombie(member)) /* figure out special flags... */
      flags |= CHFL_ZOMBIE;

    if (IsDelayedJoin(member))
      flags |= CHFL_DELAYED;

    /* Pre-populate per-channel msgid from incoming S2S tag (positional) */
    if (incoming_msgids[chan_idx][0])
      ircd_strncpy(parts.jb_msgids[parts.jb_count],
                    incoming_msgids[chan_idx],
                    sizeof(parts.jb_msgids[0]));

    /* part user from channel */
    joinbuf_join(&parts, chptr, flags);
  }

  } /* end incoming_msgids/chan_idx scope */

  return joinbuf_flush(&parts); /* flush channel parts */
}
