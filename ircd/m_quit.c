/*
 * IRC - Internet Relay Chat, ircd/m_quit.c
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
 * $Id: m_quit.c 1271 2004-12-11 05:14:07Z klmitch $
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

#include "bouncer_session.h"
#include "channel.h"
#include "client.h"
#include "ircd.h"
#include "ircd_log.h"
#include "ircd_features.h"
#include "ircd_string.h"
#include "struct.h"
#include "s_misc.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "send.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <string.h>

/** The comment a QUIT from @a sptr leaves with: what channel members see
 * and what is relayed.  A channel it cannot speak in signs it off; a
 * channel that drops quit text (+Q) or blocks colour (and the text has
 * some) leaves "Quit"; one that strips colour strips it; UTF8ONLY
 * sanitizes the text, or with UTF8ONLY_STRICT drops it; otherwise
 * "Quit: <text>", or "Quit" with none.  Read from the channels the client
 * is in now, so before anything takes them from it.
 * @param[in] sptr The quitting client.
 * @param[in,out] text Its QUIT text, or NULL (UTF8ONLY may rewrite it in
 *                place).
 * @param[out] buf Where a composed comment is written.
 * @param[in] len Size of @a buf.
 * @return The comment: @a buf or a constant string.
 */
static const char *quit_comment(struct Client *sptr, char *text,
                                char *buf, size_t len)
{
  int stripquit = 0;
  int blockcolor = 0;
  int stripcolor = 0;

  if (cli_user(sptr)) {
    struct Membership* chan;
    for (chan = cli_user(sptr)->channel; chan; chan = chan->next_channel) {
        if (chan->channel->mode.exmode & EXMODE_NOQUITPARTS)
          stripquit = 1;
        if (chan->channel->mode.exmode & EXMODE_NOCOLOR)
          blockcolor = 1;
        if (chan->channel->mode.exmode & EXMODE_STRIPCOLOR)
          stripcolor = 1;
        if (!IsZombie(chan) && !IsDelayedJoin(chan) && !member_can_send_to_channel(chan, 0))
          return "Signed off";
    }
  }

  if (BadPtr(text))
    return "Quit";

  /* UTF8ONLY enforcement on quit message */
  if (feature_bool(FEAT_UTF8ONLY) && !string_is_valid_utf8(text)) {
    if (feature_bool(FEAT_UTF8ONLY_STRICT))
      return "Quit";  /* Strict mode: the default quit message */
    string_sanitize_utf8(text);  /* Warn mode: sanitize the quit message */
  }

  if (stripquit || (blockcolor && HasColor(text)))
    return "Quit";
  if (stripcolor) {
    const char *stripped = StripColor(text);
    if (EmptyString(stripped))
      return "Quit";
    ircd_snprintf(0, buf, len, "Quit: %s", stripped);
    return buf;
  }
  ircd_snprintf(0, buf, len, "Quit: %s", text);
  return buf;
}

/*
 * m_quit - client message handler 
 *
 * parv[0]        = sender prefix
 * parv[parc - 1] = comment
 */
int m_quit(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  char buf[1024];
  const char *comment;

  assert(0 != cptr);
  assert(0 != sptr);
  assert(cptr == sptr);

  /* Bouncer alias: skip all hold logic — just clean up.
   * exit_client() sends BX X to notify other servers. */
  if (IsBouncerAlias(sptr))
    return exit_client(cptr, sptr, sptr, "Quit");

  /* The comment the exit would use, composed while the client is still in
   * its channels.  A hold keeps the same comment: a hold that ends with
   * nothing to take over (hold off, the device elsewhere already gone)
   * leaves with it, so it must say what this QUIT would have -- never the
   * raw text, which no channel rule has seen. */
  comment = quit_comment(sptr, parc > 1 ? parv[parc - 1] : NULL,
                         buf, sizeof(buf));

  /* A session primary: the bouncer decides first (bounce_promote_or_hold).
   * A live device of the session takes over -- one on this server at
   * once, one elsewhere at the next tick, whatever the hold preference --
   * else the session holds or, with hold off, ends.  Clients send QUIT
   * on their way out all the time; holding is what keeps the session and
   * its channels across that.
   *
   * After a promote here the session goes on under the device; the old
   * primary's channels are already left (bounce_promote_alias), so the
   * exit below shows no QUIT in them.  Peers see BX P + BS T, then the
   * primary's Q. */
  if (IsUser(sptr) && bounce_promote_or_hold(sptr, comment) == 0)
    return 0; /* Held (a device elsewhere takes over at the next tick, or
               * the hold runs its course) */

  /* Promoted here, or nothing to keep: the normal quit. */
  return exit_client(cptr, sptr, sptr, comment);
}


/*
 * ms_quit - server message handler
 *
 * parv[0] = sender prefix
 * parv[parc - 1] = comment
 */
int ms_quit(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  assert(0 != sptr);
  assert(parc > 0);
  if (IsServer(sptr)) {
  	protocol_violation(sptr,"Server QUIT, not SQUIT?");
  	return 0;
  }
  /*
   * ignore quit from servers
   */
  {
    int rc;
    /* A legacy peer's QUIT line carries no tags of its own, so the
     * link's stash is still whatever its last line left there, or
     * empty.  Mint once into that same stash before arming it: the
     * onward relay reads the stash while this line is current, and
     * arming below hands the identical id and time to the local
     * broadcast and rows, so all three agree. */
    if (feature_bool(FEAT_P10_MESSAGE_TAGS) && !cli_s2s_msgid(cptr)[0])
      s2s_mint_link_event(cptr);
    /* This QUIT line's own tags (the link stash holds exactly this line
     * now) -- so exit_client stamps the quitter's rows with them and not
     * with whatever the link carried last on a KILL/collision/SQUIT. */
    exit_arm_s2s_event(cli_s2s_msgid(cptr), cli_s2s_time_ms(cptr));
    rc = exit_client(cptr, sptr, sptr, parv[parc - 1]);
    exit_arm_s2s_event(NULL, 0);
    return rc;
  }
}
