/*
 * IRC - Internet Relay Chat, ircd/m_zline.c
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
 * $Id: m_zline.c 1917 2009-07-06 02:02:31Z entrope $
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

#include "client.h"
#include "zline.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "match.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_misc.h"
#include "send.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <stdlib.h>
#include <string.h>

#define PASTWATCH	157680000	/* number of seconds in 5 years */

/*
 * If the expiration value, interpreted as an absolute timestamp, is
 * more recent than 5 years in the past, we interpret it as an
 * absolute timestamp; otherwise, we assume it's relative and convert
 * it to an absolute timestamp.  Either way, the output of this macro
 * is an absolute timestamp--not guaranteed to be a *valid* timestamp,
 * but you can't have everything in a macro ;)
 */
#define abs_expire(exp)							\
  ((exp) >= TStime() - PASTWATCH ? (exp) : (exp) + TStime())

/*
 * ms_zline - server message handler
 *
 * parv[0] = Sender prefix
 * parv[1] = Target: server numeric
 * parv[2] = (+|-)<Z-line mask>
 *
 * For other parameters, see doc/readme.zline.
 */
int
ms_zline(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct Client *acptr = 0;
  struct Zline *azline = 0;
  unsigned int flags = 0;
  enum ZlineAction action = ZLINE_MODIFY;
  time_t expire = 0, lastmod = 0, lifetime = 0;
  char *mask = parv[2], *target = parv[1], *reason = "No reason", *tmp = 0;

  if (parc < 3)
    return need_more_params(sptr, "ZLINE");

  if (IsServer(sptr))
    flags |= ZLINE_FORCE;

  if (*mask == '!') {
    mask++;
    flags |= ZLINE_OPERFORCE; /* assume oper had WIDE_ZLINE */
  }

  switch (*mask) { /* handle +, -, <, and > */
  case '+': /* activate the ZG-line */
    action = ZLINE_ACTIVATE;
    mask++;
    break;

  case '-': /* deactivate the Z-line */
    action = ZLINE_DEACTIVATE;
    mask++;
    break;

  case '>': /* locally activate the Z-line */
    action = ZLINE_LOCAL_ACTIVATE;
    mask++;
    break;

  case '<': /* locally deactivate the Z-line */
    action = ZLINE_LOCAL_DEACTIVATE;
    mask++;
    break;
  }

  /* Is there no mask left? */
  if (mask[0] == '\0')
    return need_more_params(sptr, "ZLINE");

  /* Now, let's figure out if it's a local or global Z-line */
  if (action == ZLINE_LOCAL_ACTIVATE || action == ZLINE_LOCAL_DEACTIVATE ||
      (target[0] == '*' && target[1] == '\0'))
    flags |= ZLINE_GLOBAL;
  else
    flags |= ZLINE_LOCAL;

  /* now figure out if we need to resolve a server */
  if ((action == ZLINE_LOCAL_ACTIVATE || action == ZLINE_LOCAL_DEACTIVATE ||
       (flags & ZLINE_LOCAL)) && !(acptr = FindNServer(target)))
    return 0; /* no such server, jump out */

  /* If it's a local activate/deactivate and server isn't me, propagate it */
  if ((action == ZLINE_LOCAL_ACTIVATE || action == ZLINE_LOCAL_DEACTIVATE) &&
      !IsMe(acptr)) {
    Debug((DEBUG_DEBUG, "I am forwarding a local change to a global zline "
	   "to a remote server; target %s, mask %s, operforce %s, action %c",
	   target, mask, flags & ZLINE_OPERFORCE ? "YES" : "NO",
	   action == ZLINE_LOCAL_ACTIVATE ? '>' : '<'));

    sendcmdto_one(sptr, CMD_ZLINE, acptr, "%C %s%c%s", acptr,
		  flags & ZLINE_OPERFORCE ? "!" : "",
		  action == ZLINE_LOCAL_ACTIVATE ? '>' : '<', mask);

    return 0; /* all done */
  }

  /* Next, try to find the Z-line... */
  if ((flags & ZLINE_GLOBAL) || IsMe(acptr)) /* don't bother if it's not me! */
    azline = zline_find(mask, flags | ZLINE_ANY | ZLINE_EXACT);

  /* We now have all the pieces to tell us what we've got; let's put
   * it all together and convert the rest of the arguments.
   */

  /* Handle the local Z-lines first... */
  if (flags & ZLINE_LOCAL) {
    assert(acptr);

    /* normalize the action, first */
    if (action == ZLINE_LOCAL_ACTIVATE || action == ZLINE_MODIFY)
      action = ZLINE_ACTIVATE;
    else if (action == ZLINE_LOCAL_DEACTIVATE)
      action = ZLINE_DEACTIVATE;

    if (action == ZLINE_ACTIVATE) { /* get expiration and reason */
      if (parc < 5) /* check parameter count... */
	return need_more_params(sptr, "ZLINE");

      expire = atoi(parv[3]); /* get expiration... */
      expire = abs_expire(expire); /* convert to absolute... */
      reason = parv[parc - 1]; /* and reason */

      if (IsMe(acptr)) {
	if (azline) /* Z-line already exists, so let's ignore it... */
	  return 0;

	/* OK, create the local Z-line */
	Debug((DEBUG_DEBUG, "I am creating a local Z-line here; target %s, "
	       "mask %s, operforce %s, action %s, expire %Tu, reason: %s",
	       target, mask, flags & ZLINE_OPERFORCE ? "YES" : "NO",
	       action == ZLINE_ACTIVATE ? "+" : "-", expire, reason));

	return zline_add(cptr, sptr, mask, reason, expire, lastmod,
			 lifetime, flags | ZLINE_ACTIVE);
      }
    } else if (IsMe(acptr)) { /* destroying a local Z-line */
      if (!azline) /* Z-line doesn't exist, so let's complain... */
	return send_reply(sptr, ERR_NOSUCHZLINE, mask);

      /* Let's now destroy the Z-line */;
      Debug((DEBUG_DEBUG, "I am destroying a local Z-line here; target %s, "
	     "mask %s, operforce %s, action %s", target, mask,
	     flags & ZLINE_OPERFORCE ? "YES" : "NO",
	     action == ZLINE_ACTIVATE ? "+" : "-"));

      return zline_destroy(cptr, sptr, azline);
    }

    /* OK, we've converted arguments; if it's not for us, forward */
    /* UPDATE NOTE: Once all servers are updated to u2.10.12.11, the
     * format string in this sendcmdto_one() may be updated to omit
     * <lastmod> for ZLINE_ACTIVATE and to omit <expire>, <lastmod>,
     * and <reason> for ZLINE_DEACTIVATE.
     */
    assert(!IsMe(acptr));

    Debug((DEBUG_DEBUG, "I am forwarding a local Z-line to a remote server; "
	   "target %s, mask %s, operforce %s, action %c, expire %Tu, "
	   "lastmod %Tu, reason: %s", target, mask,
	   flags & ZLINE_OPERFORCE ? "YES" : "NO",
	   action == ZLINE_ACTIVATE ? '+' :  '-', expire, TStime(),
	   reason));

    sendcmdto_one(sptr, CMD_ZLINE, acptr, "%C %s%c%s %Tu %Tu :%s",
		  acptr, flags & ZLINE_OPERFORCE ? "!" : "",
		  action == ZLINE_ACTIVATE ? '+' : '-', mask,
		  expire - TStime(), TStime(), reason);

    return 0; /* all done */
  }

  /* can't modify a Z-line that doesn't exist, so remap to activate */
  if (!azline && action == ZLINE_MODIFY)
    action = ZLINE_ACTIVATE;

  /* OK, let's figure out what other parameters we may have... */
  switch (action) {
  case ZLINE_LOCAL_ACTIVATE: /* locally activating a Z-line */
  case ZLINE_LOCAL_DEACTIVATE: /* locally deactivating a Z-line */
    if (!azline) /* no Z-line to locally activate or deactivate? */
      return send_reply(sptr, ERR_NOSUCHZLINE, mask);
    lastmod = azline->zl_lastmod;
    break; /* no additional parameters to manipulate */

  case ZLINE_ACTIVATE: /* activating a Z-line */
  case ZLINE_DEACTIVATE: /* deactivating a Z-line */
    /* in either of these cases, we have at least a lastmod parameter */
    if (parc < 4)
      return need_more_params(sptr, "ZLINE");
    else if (parc == 4) /* lastmod only form... */
      lastmod = atoi(parv[3]);
    /*FALLTHROUGH*/
  case ZLINE_MODIFY: /* modifying a Z-line */
    /* convert expire and lastmod, look for lifetime and reason */
    if (parc > 4) { /* protect against fall-through from 4-param form */
      expire = atoi(parv[3]); /* convert expiration and lastmod */
      expire = abs_expire(expire);
      lastmod = atoi(parv[4]);

      flags |= ZLINE_EXPIRE; /* we have an expiration time update */

      if (parc > 6) { /* no question, have a lifetime and reason */
	lifetime = atoi(parv[5]);
	reason = parv[parc - 1];

	flags |= ZLINE_LIFETIME | ZLINE_REASON;
      } else if (parc == 6) { /* either a lifetime or a reason */
	if (!azline || /* zline creation, has to be the reason */
	    /* trial-convert as lifetime, and if it doesn't fully convert,
	     * it must be the reason */
	    (!(lifetime = strtoul(parv[5], &tmp, 10)) && !*tmp)) {
	  lifetime = 0;
	  reason = parv[5];

	  flags |= ZLINE_REASON; /* have a reason update */
	} else if (lifetime)
	  flags |= ZLINE_LIFETIME; /* have a lifetime update */
      }
    }
  }

  if (!lastmod) /* must have a lastmod parameter by now */
    return need_more_params(sptr, "ZLINE");

  Debug((DEBUG_DEBUG, "I have a global Z-line I am acting upon now; "
	 "target %s, mask %s, operforce %s, action %s, expire %Tu, "
	 "lastmod %Tu, lifetime %Tu, reason: %s; zline %s!  (fields "
	 "present: %s %s %s)", target, mask,
	 flags & ZLINE_OPERFORCE ? "YES" : "NO",
	 action == ZLINE_ACTIVATE ? "+" :
	 (action == ZLINE_DEACTIVATE ? "-" :
	  (action == ZLINE_LOCAL_ACTIVATE ? ">" :
	   (action == ZLINE_LOCAL_DEACTIVATE ? "<" : "(MODIFY)"))),
	 expire, lastmod, lifetime, reason,
	 azline ? "EXISTS" : "does not exist",
	 flags & ZLINE_EXPIRE ? "expire" : "",
	 flags & ZLINE_LIFETIME ? "lifetime" : "",
	 flags & ZLINE_REASON ? "reason" : ""));

  /* OK, at this point, we have converted all available parameters.
   * Let's actually do the action!
   */
  if (azline)
    return zline_modify(cptr, sptr, azline, action, reason, expire,
			lastmod, lifetime, flags);

  assert(action != ZLINE_LOCAL_ACTIVATE);
  assert(action != ZLINE_LOCAL_DEACTIVATE);
  assert(action != ZLINE_MODIFY);

  if (!expire) { /* Cannot *add* a Z-line we don't have, but try hard */
    Debug((DEBUG_DEBUG, "Propagating Z-line %s for Z-line we don't have",
	   action == ZLINE_ACTIVATE ? "activation" : "deactivation"));

    /* propagate the Z-line, even though we don't have it */
    sendcmdto_serv_butone(sptr, CMD_ZLINE, cptr, "* %c%s %Tu",
			  action == ZLINE_ACTIVATE ? '+' : '-',
			  mask, lastmod);

    return 0;
  }

  return zline_add(cptr, sptr, mask, reason, expire, lastmod, lifetime,
		   flags | ((action == ZLINE_ACTIVATE) ? ZLINE_ACTIVE : 0));
}

/*
 * mo_zline - oper message handler
 *
 * parv[0] = Sender prefix
 * parv[1] = [[+|-]<Z-line mask>]
 *
 * For other parameters, see doc/readme.zline.
 */
int
mo_zline(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct Client *acptr = 0;
  struct Zline *azline = 0;
  unsigned int flags = 0;
  enum ZlineAction action = ZLINE_MODIFY;
  time_t expire = 0;
  char *mask = parv[1], *target = 0, *reason = 0, *end;

  if (parc < 2)
    return zline_list(sptr, 0);

  if (*mask == '!') {
    mask++;

    if (HasPriv(sptr, PRIV_WIDE_ZLINE))
      flags |= ZLINE_OPERFORCE;
  }

  switch (*mask) { /* handle +, -, <, and > */
  case '+': /* activate the Z-line */
    action = ZLINE_ACTIVATE;
    mask++;
    break;

  case '-': /* deactivate the Z-line */
    action = ZLINE_DEACTIVATE;
    mask++;
    break;

  case '>': /* locally activate the Z-line */
    action = ZLINE_LOCAL_ACTIVATE;
    mask++;
    break;

  case '<': /* locally deactivate the Z-line */
    action = ZLINE_LOCAL_DEACTIVATE;
    mask++;
    break;
  }

  /* OK, let's figure out the parameters... */
  switch (action) {
  case ZLINE_MODIFY: /* no specific action on the Z-line... */
    if (parc == 2) /* user wants a listing of a specific Z-line */
      return zline_list(sptr, mask);
    else if (parc < 4) /* must have target and expire, minimum */
      return need_more_params(sptr, "ZLINE");

    target = parv[2]; /* get the target... */
    if (is_timestamp(parv[3])) {
      expire = strtol(parv[3], &end, 10) + TStime(); /* and the expiration */
      if (*end != '\0')
        return send_reply(sptr, SND_EXPLICIT | ERR_BADEXPIRE, "%s :Bad expire time", parv[3]);
    } else
      expire = ParseInterval(parv[3]) + TStime();

    flags |= ZLINE_EXPIRE; /* remember that we got an expire time */

    if (parc > 4) { /* also got a reason... */
      reason = parv[parc - 1];
      flags |= ZLINE_REASON;
    }

    /* target is not global, interpolate action and require reason */
    if (target[0] != '*' || target[1] != '\0') {
      if (!reason) /* have to have a reason for this */
	return need_more_params(sptr, "ZLINE");

      action = ZLINE_ACTIVATE;
    }
    break;

  case ZLINE_LOCAL_ACTIVATE: /* locally activate a Z-line */
  case ZLINE_LOCAL_DEACTIVATE: /* locally deactivate a Z-line */
    if (parc > 2) { /* if target is available, pick it */
      target = parv[2];
      if (target[0] == '*' && target[1] == '\0')
        return send_reply(sptr, ERR_NOSUCHSERVER, target);
    }
    break;

  case ZLINE_ACTIVATE: /* activating/adding a Z-line */
  case ZLINE_DEACTIVATE: /* deactivating/removing a Z-line */
    if (parc < 3)
      return need_more_params(sptr, "ZLINE");

    if (parc > 3) {
      /* get expiration and target */
      reason = parv[parc - 1];
      if (is_timestamp(parv[parc - 2])) {
        expire = strtol(parv[parc - 2], &end, 10) + TStime();
        if (*end != '\0')
          return send_reply(sptr, SND_EXPLICIT | ERR_BADEXPIRE, "%s :Bad expire time", parv[parc - 2]);
      } else
        expire = ParseInterval(parv[parc - 2]) + TStime();

      flags |= ZLINE_EXPIRE | ZLINE_REASON; /* remember that we got 'em */

      if (parc > 4) /* also have a target! */
	target = parv[2];
    } else {
      target = parv[2]; /* target has to be present, and has to be '*' */

      if (target[0] != '*' || target[1] != '\0')
	return need_more_params(sptr, "ZLINE");
    }
    break;
  }

  /* Is there no mask left? */
  if (mask[0] == '\0')
    return need_more_params(sptr, "ZLINE");

  /* Now let's figure out which is the target server */
  if (!target) /* no target, has to be me... */
    acptr = &me;
  /* if it's not '*', look up the server */
  else if ((target[0] != '*' || target[1] != '\0') &&
	   !(acptr = find_match_server(target)))
    return send_reply(sptr, ERR_NOSUCHSERVER, target);

  /* Now, is the Z-line local or global? */
  if (action == ZLINE_LOCAL_ACTIVATE || action == ZLINE_LOCAL_DEACTIVATE ||
      !acptr)
    flags |= ZLINE_GLOBAL;
  else /* it's some form of local Z-line */
    flags |= ZLINE_LOCAL;

  /* If it's a local activate/deactivate and server isn't me, propagate it */
  if ((action == ZLINE_LOCAL_ACTIVATE || action == ZLINE_LOCAL_DEACTIVATE) &&
      !IsMe(acptr)) {
    /* check for permissions... */
    if (!feature_bool(FEAT_CONFIG_OPERCMDS))
      return send_reply(sptr, ERR_DISABLED, "ZLINE");
    else if (!HasPriv(sptr, PRIV_ZLINE))
      return send_reply(sptr, ERR_NOPRIVILEGES);

    Debug((DEBUG_DEBUG, "I am forwarding a local change to a global zline "
	   "to a remote server; target %s, mask %s, operforce %s, action %c",
	   cli_name(acptr), mask, flags & ZLINE_OPERFORCE ? "YES" : "NO",
	   action == ZLINE_LOCAL_ACTIVATE ? '>' : '<'));

    sendcmdto_one(sptr, CMD_ZLINE, acptr, "%C %s%c%s", acptr,
                  flags & ZLINE_OPERFORCE ? "!" : "",
                  action == ZLINE_LOCAL_ACTIVATE ? '>' : '<', mask);

    return 0; /* all done */
  }

  /* Next, try to find the Z-line... */
  if ((flags & ZLINE_GLOBAL) || IsMe(acptr)) /* don't bother if it's not me! */
    azline = zline_find(mask, flags | ZLINE_ANY | ZLINE_EXACT);

  /* We now have all the pieces to tell us what we've got; let's put
   * it all together and convert the rest of the arguments.
   */

  /* Handle the local Z-lines first... */
  if (flags & ZLINE_LOCAL) {
    assert(acptr);

    /* normalize the action, first */
    if (action == ZLINE_LOCAL_ACTIVATE || action == ZLINE_MODIFY)
      action = ZLINE_ACTIVATE;
    else if (action == ZLINE_LOCAL_DEACTIVATE)
      action = ZLINE_DEACTIVATE;

    /* If it's not for us, forward */
    /* UPDATE NOTE: Once all servers are updated to u2.10.12.11, the
     * format string in this sendcmdto_one() may be updated to omit
     * <lastmod> for ZLINE_ACTIVATE and to omit <expire>, <lastmod>,
     * and <reason> for ZLINE_DEACTIVATE.
     */

    if (!IsMe(acptr)) {
      /* check for permissions... */
      if (!feature_bool(FEAT_CONFIG_OPERCMDS))
	return send_reply(sptr, ERR_DISABLED, "ZLINE");
      else if (!HasPriv(sptr, PRIV_ZLINE))
	return send_reply(sptr, ERR_NOPRIVILEGES);

      Debug((DEBUG_DEBUG, "I am forwarding a local Z-line to a remote "
	     "server; target %s, mask %s, operforce %s, action %c, "
	     "expire %Tu, reason %s", target, mask,
	     flags & ZLINE_OPERFORCE ? "YES" : "NO",
	     action == ZLINE_ACTIVATE ? '+' : '-', expire, reason));

      sendcmdto_one(sptr, CMD_ZLINE, acptr, "%C %s%c%s %Tu %Tu :%s",
		    acptr, flags & ZLINE_OPERFORCE ? "!" : "",
		    action == ZLINE_ACTIVATE ? '+' : '-', mask,
		    expire - TStime(), TStime(), reason);

      return 0; /* all done */
    }

    /* check local Z-line permissions... */
    if (!HasPriv(sptr, PRIV_LOCAL_ZLINE))
      return send_reply(sptr, ERR_NOPRIVILEGES);

    /* let's handle activation... */
    if (action == ZLINE_ACTIVATE) {
      if (azline) /* Z-line already exists, so let's ignore it... */
	return 0;

      /* OK, create the local Z-line */
      Debug((DEBUG_DEBUG, "I am creating a local Z-line here; target %s, "
	     "mask %s, operforce %s, action  %s, expire %Tu, reason: %s",
	     target, mask, flags & ZLINE_OPERFORCE ? "YES" : "NO",
	     action == ZLINE_ACTIVATE ? "+" : "-", expire, reason));

      return zline_add(cptr, sptr, mask, reason, expire, 0, 0,
		       flags | ZLINE_ACTIVE);
    } else { /* OK, it's a deactivation/destruction */
      if (!azline) /* Z-line doesn't exist, so let's complain... */
	return send_reply(sptr, ERR_NOSUCHZLINE, mask);

      /* Let's now destroy the Z-line */
      Debug((DEBUG_DEBUG, "I am destroying a local Z-line here; target %s, "
	     "mask %s, operforce %s, action %s", target, mask,
	     flags & ZLINE_OPERFORCE ? "YES" : "NO",
	     action == ZLINE_ACTIVATE ? "+" : "-"));

      return zline_destroy(cptr, sptr, azline);
    }
  }

  /* can't modify a Z-line that doesn't exist...
   * (and if we are creating a new one, we need a reason and expiration)
   */
  if (!azline &&
      (action == ZLINE_MODIFY || action == ZLINE_LOCAL_ACTIVATE ||
       action == ZLINE_LOCAL_DEACTIVATE || !reason || !expire))
    return send_reply(sptr, ERR_NOSUCHZLINE, mask);

  /* check for Z-line permissions... */
  if (action == ZLINE_LOCAL_ACTIVATE || action == ZLINE_LOCAL_DEACTIVATE) {
    /* only need local privileges for locally-limited status changes */
    if (!HasPriv(sptr, PRIV_LOCAL_ZLINE))
      return send_reply(sptr, ERR_NOPRIVILEGES);
  } else { /* global privileges required */
    if (!feature_bool(FEAT_CONFIG_OPERCMDS))
      return send_reply(sptr, ERR_DISABLED, "ZLINE");
    else if (!HasPriv(sptr, PRIV_ZLINE))
      return send_reply(sptr, ERR_NOPRIVILEGES);
  }

  Debug((DEBUG_DEBUG, "I have a global Z-line I am acting upon now; "
	 "target %s, mask %s, operforce %s, action %s, expire %Tu, "
	 "reason: %s; zline %s!  (fields present: %s %s)", target, 
	 mask, flags & ZLINE_OPERFORCE ? "YES" : "NO",
	 action == ZLINE_ACTIVATE ? "+" :
	 (action == ZLINE_DEACTIVATE ? "-" :
	  (action == ZLINE_LOCAL_ACTIVATE ? ">" :
	   (action == ZLINE_LOCAL_DEACTIVATE ? "<" : "(MODIFY)"))),
	 expire, reason, azline ? "EXISTS" : "does not exist",
	 flags & ZLINE_EXPIRE ? "expire" : "",
	 flags & ZLINE_REASON ? "reason" : ""));

  if (azline) /* modifying an existing Z-line */
    return zline_modify(cptr, sptr, azline, action, reason, expire,
			TStime(), 0, flags);

  assert(action != ZLINE_LOCAL_ACTIVATE);
  assert(action != ZLINE_LOCAL_DEACTIVATE);
  assert(action != ZLINE_MODIFY);

  /* create a new Z-line */
  return zline_add(cptr, sptr, mask, reason, expire, TStime(), 0,
		   flags | ((action == ZLINE_ACTIVATE) ? ZLINE_ACTIVE : 0));
}

/*
 * m_zline - user message handler
 *
 * parv[0] = Sender prefix
 * parv[1] = [<server name>]
 *
 */
int
m_zline(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  if (parc < 2)
    return send_reply(sptr, ERR_NOSUCHZLINE, "");

  return zline_list(sptr, parv[1]);
}
