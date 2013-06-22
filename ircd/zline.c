/*
 * IRC - Internet Relay Chat, ircd/zline.c
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Finland
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
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
 * @brief Implementation of Zline manipulation functions.
 * @version $Id: zline.c 1936 2010-01-07 02:55:33Z entrope $
 */
#include "config.h"

#include "zline.h"
#include "channel.h"
#include "client.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "match.h"
#include "numeric.h"
#include "res.h"
#include "s_bsd.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_misc.h"
#include "s_stats.h"
#include "send.h"
#include "struct.h"
#include "sys.h"
#include "msg.h"
#include "numnicks.h"
#include "numeric.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define CHECK_APPROVED	   0	/**< Mask is acceptable */
#define CHECK_OVERRIDABLE  1	/**< Mask is acceptable, but not by default */
#define CHECK_REJECTED	   2	/**< Mask is totally unacceptable */

#define MASK_WILD_0	0x01	/**< Wildcards in the last position */
#define MASK_WILD_1	0x02	/**< Wildcards in the next-to-last position */

#define MASK_WILD_MASK	0x03	/**< Mask out the positional wildcards */

#define MASK_WILDS	0x10	/**< Mask contains wildcards */
#define MASK_IP		0x20	/**< Mask is an IP address */
#define MASK_HALT	0x40	/**< Finished processing mask */

/** List of user Z-lines. */
struct Zline* GlobalZlineList  = 0;

/** Iterate through \a list of Z-lines.  Use this like a for loop,
 * i.e., follow it with braces and use whatever you passed as \a zl
 * as a single Z-line to be acted upon.
 *
 * @param[in] list List of Z-lines to iterate over.
 * @param[in] zl Name of a struct Zline pointer variable that will be made to point to the Z-lines in sequence.
 * @param[in] next Name of a scratch struct Zline pointer variable.
 */
/* There is some subtlety here with the boolean operators:
 * (x || 1) is used to continue in a logical-and series even when !x.
 * (x && 0) is used to continue in a logical-or series even when x.
 */
#define zliter(list, zl, next)				\
  /* Iterate through the Z-lines in the list */		\
  for ((zl) = (list); (zl); (zl) = (next))		\
    /* Figure out the next pointer in list... */	\
    if ((((next) = (zl)->zl_next) || 1) &&		\
	/* Then see if it's expired */			\
	(zl)->zl_lifetime <= TStime())                  \
      /* Record has expired, so free the Z-line */	\
      zline_free((zl));					\
    /* See if we need to expire the Z-line */		\
    else if ((((zl)->zl_expire > TStime()) ||		\
	      (((zl)->zl_flags &= ~ZLINE_ACTIVE) && 0) ||	\
	      ((zl)->zl_state = ZLOCAL_GLOBAL)) && 0)	\
      ; /* empty statement */				\
    else

/** Create a Zline structure.
 * @param[in] mask Mask.
 * @param[in] reason Reason for Z-line.
 * @param[in] expire Expiration timestamp.
 * @param[in] lastmod Last modification timestamp.
 * @param[in] flags Bitwise combination of ZLINE_* bits.
 * @return Newly allocated Z-line.
 */
static struct Zline *
make_zline(char *mask, char *reason, time_t expire, time_t lastmod,
	   time_t lifetime, unsigned int flags)
{
  struct Zline *zline;

  assert(0 != expire);

  zline = (struct Zline *)MyMalloc(sizeof(struct Zline)); /* alloc memory */
  assert(0 != zline);

  DupString(zline->zl_reason, reason); /* initialize zline... */
  zline->zl_expire = expire;
  zline->zl_lifetime = lifetime;
  zline->zl_lastmod = lastmod;
  zline->zl_flags = flags & ZLINE_MASK;
  zline->zl_state = ZLOCAL_GLOBAL; /* not locally modified */

  DupString(zline->zl_mask, mask);

  if (ipmask_parse(mask, &zline->zl_addr, &zline->zl_bits)) {
    zline->zl_flags |= ZLINE_IPMASK;
    zline->zl_addr = ipmask_clean(&zline->zl_addr, zline->zl_bits);
  }

  zline->zl_next = GlobalZlineList; /* then link it into list */
  zline->zl_prev_p = &GlobalZlineList;
  if (GlobalZlineList)
    GlobalZlineList->zl_prev_p = &zline->zl_next;
  GlobalZlineList = zline;

  return zline;
}

/** Check local clients against a new Z-line.
 * If the Z-line is inactive, return immediately.
 * Otherwise, if any users match it, disconnect them.
 * @param[in] cptr Peer connect that sent the Z-line.
 * @param[in] sptr Client that originated the Z-line.
 * @param[in] zline New Z-line to check.
 * @return Zero, unless \a sptr Z-lined himself, in which case CPTR_KILLED.
 */
static int
do_zline(struct Client *cptr, struct Client *sptr, struct Zline *zline)
{
  struct Client *acptr;
  int fd, retval = 0, tval;

  if (feature_bool(FEAT_DISABLE_ZLINES))
    return 0; /* Z-lines are disabled */

  if (!ZlineIsActive(zline)) /* no action taken on inactive zlines */
    return 0;

  for (fd = HighestFd; fd >= 0; --fd) {
    /*
     * get the users!
     */
    if ((acptr = LocalClientArray[fd])) {
      if (!cli_user(acptr))
	continue;

      if (find_except_conf(acptr, EFLAG_ZLINE))
        continue;

      /* IP zline */
      if (ZlineIsIpMask(zline)) {
        if (!irc_in_addr_type_cmp(&cli_ip(acptr), &zline->zl_addr))
          continue;
        if (!ipmask_check(&cli_ip(acptr), &zline->zl_addr, zline->zl_bits))
          continue;
      }
      else {
        if (match(zline->zl_mask, cli_sock_ip(acptr)) != 0)
          continue;
      }

      /* ok, here's one that got Z-lined */
      send_reply(acptr, SND_EXPLICIT | ERR_YOUREBANNEDCREEP, ":%s",
      	   zline->zl_reason);

      /* let the ops know about it */
      sendto_opmask_butone_global(&me, SNO_GLINE, "Z-line active for %s",
                           get_client_name(acptr, SHOW_IP));

      /* and get rid of him */
      if ((tval = exit_client_msg(cptr, acptr, &me, "Z-lined%s%s%s",
          (!feature_bool(FEAT_HIS_ZLINE_REASON) ? " (" : ""),
          (!feature_bool(FEAT_HIS_ZLINE_REASON) ? zline->zl_reason : ""),
          (!feature_bool(FEAT_HIS_ZLINE_REASON) ? ")" : ""))))
        retval = tval; /* retain killed status */
    }
  }
  return retval;
}

/**
 * Implements the mask checking applied to local Z-lines.
 * Basically, host masks must have a minimum of two non-wild domain
 * fields, and IP masks must have a minimum of 16 bits.  If the mask
 * has even one wild-card, OVERRIDABLE is returned, assuming the other
 * check doesn't fail.
 * @param[in] mask Z-line mask to check.
 * @return One of CHECK_REJECTED, CHECK_OVERRIDABLE, or CHECK_APPROVED.
 */
static int
zline_checkmask(char *mask)
{
  unsigned int flags = MASK_IP;
  unsigned int dots = 0;
  unsigned int ipmask = 0;

  for (; *mask; mask++) { /* go through given mask */
    if (*mask == '.') { /* it's a separator; advance positional wilds */
      flags = (flags & ~MASK_WILD_MASK) | ((flags << 1) & MASK_WILD_MASK);
      dots++;

      if ((flags & (MASK_IP | MASK_WILDS)) == MASK_IP)
	ipmask += 8; /* It's an IP with no wilds, count bits */
    } else if (*mask == '*' || *mask == '?')
      flags |= MASK_WILD_0 | MASK_WILDS; /* found a wildcard */
    else if (*mask == '/') { /* n.n.n.n/n notation; parse bit specifier */
      ++mask;
      ipmask = strtoul(mask, &mask, 10);

      /* sanity-check to date */
      if (*mask || (flags & (MASK_WILDS | MASK_IP)) != MASK_IP)
	return CHECK_REJECTED;
      if (!dots) {
        if (ipmask > 128)
          return CHECK_REJECTED;
        if (ipmask < 128)
          flags |= MASK_WILDS;
      } else {
        if (dots != 3 || ipmask > 32)
          return CHECK_REJECTED;
        if (ipmask < 32)
	  flags |= MASK_WILDS;
      }

      flags |= MASK_HALT; /* Halt the ipmask calculation */
      break; /* get out of the loop */
    } else if (!IsIP6Char(*mask)) {
      flags &= ~MASK_IP; /* not an IP anymore! */
      ipmask = 0;
    }
  }

  /* Sanity-check quads */
  if (dots > 3 || (!(flags & MASK_WILDS) && dots < 3)) {
    flags &= ~MASK_IP;
    ipmask = 0;
  }

  /* update bit count if necessary */
  if ((flags & (MASK_IP | MASK_WILDS | MASK_HALT)) == MASK_IP)
    ipmask += 8;

  /* Check to see that it's not too wide of a mask */
  if (flags & MASK_WILDS &&
      ((!(flags & MASK_IP) && (dots < 2 || flags & MASK_WILD_MASK)) ||
       (flags & MASK_IP && ipmask < 16)))
    return CHECK_REJECTED; /* to wide, reject */

  /* Ok, it's approved; require override if it has wildcards, though */
  return flags & MASK_WILDS ? CHECK_OVERRIDABLE : CHECK_APPROVED;
}

/** Forward a Z-line to other servers.
 * @param[in] cptr Client that sent us the Z-line.
 * @param[in] sptr Client that originated the Z-line.
 * @param[in] zline Z-line to forward.
 * @return Zero.
 */
static int
zline_propagate(struct Client *cptr, struct Client *sptr, struct Zline *zline)
{
  if (ZlineIsLocal(zline))
    return 0;

  assert(zline->zl_lastmod);

  sendcmdto_serv_butone(sptr, CMD_ZLINE, cptr, "* %c%s %Tu %Tu %Tu :%s",
			ZlineIsRemActive(zline) ? '+' : '-',
			zline->zl_mask, zline->zl_expire - TStime(),
			zline->zl_lastmod, zline->zl_lifetime, zline->zl_reason);

  return 0;
}

/** Count number of users who match \a mask.
 * @param[in] mask ip mask to check.
 * @param[in] flags Bitmask possibly containing the value ZLINE_LOCAL, to limit searches to this server.
 * @return Count of matching users.
 */
static int
count_users(char *mask, int flags)
{
  struct irc_in_addr ipmask;
  struct Client *acptr;
  int count = 0;
  int ipmask_valid;
  char ipbuf[SOCKIPLEN + 2];
  unsigned char ipmask_len;

  ipmask_valid = ipmask_parse(mask, &ipmask, &ipmask_len);
  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr)) {
    if (!IsUser(acptr))
      continue;
    if ((flags & ZLINE_LOCAL) && !MyConnect(acptr))
      continue;

    ircd_snprintf(0, ipbuf, sizeof(ipbuf), "%s", ircd_ntoa(&cli_ip(acptr)));

    if (!match(mask, ipbuf)
        || (ipmask_valid && ipmask_check(&cli_ip(acptr), &ipmask, ipmask_len)
            && irc_in_addr_type_cmp(&cli_ip(acptr), &ipmask)))
      count++;
  }

  return count;
}

/** Create a new Z-line and add it to global lists.
 * \a ipmask must be an IP mask to create an IP-based ban.
 *
 * @param[in] cptr Client that sent us the Z-line.
 * @param[in] sptr Client that originated the Z-line.
 * @param[in] ipmask Text mask for the Z-line.
 * @param[in] reason Reason for Z-line.
 * @param[in] expire Expiration time of Z-line.
 * @param[in] lastmod Last modification time of Z-line.
 * @param[in] lifetime Lifetime of Z-line.
 * @param[in] flags Bitwise combination of ZLINE_* flags.
 * @return Zero or CPTR_KILLED, depending on whether \a sptr is suicidal.
 */
int
zline_add(struct Client *cptr, struct Client *sptr, char *ipmask,
	  char *reason, time_t expire, time_t lastmod, time_t lifetime,
	  unsigned int flags)
{
  struct Zline *azline;
  char imask[HOSTLEN + 2];
  char *mask;
  int tmp;

  assert(0 != ipmask);
  assert(0 != reason);
  assert(((flags & (ZLINE_GLOBAL | ZLINE_LOCAL)) == ZLINE_GLOBAL) ||
         ((flags & (ZLINE_GLOBAL | ZLINE_LOCAL)) == ZLINE_LOCAL));

  Debug((DEBUG_DEBUG, "zline_add(\"%s\", \"%s\", \"%s\", \"%s\", %Tu, %Tu "
	 "%Tu, 0x%04x)", cli_name(cptr), cli_name(sptr), ipmask, reason,
	 expire, lastmod, lifetime, flags));

  mask = ipmask;
  if (sizeof(imask) <
      ircd_snprintf(0, imask, sizeof(imask), "%s", mask))
    return send_reply(sptr, ERR_LONGMASK);
  else if (MyUser(sptr) || (IsUser(sptr) && flags & ZLINE_LOCAL)) {
    switch (zline_checkmask(mask)) {
      case CHECK_OVERRIDABLE: /* oper overrided restriction */
        if (flags & ZLINE_OPERFORCE)
          break;
      /*FALLTHROUGH*/
      case CHECK_REJECTED:
        return send_reply(sptr, ERR_MASKTOOWIDE, imask);
        break;
    }

    if ((tmp = count_users(imask, flags)) >=
      feature_int(FEAT_ZLINEMAXUSERCOUNT) && !(flags & ZLINE_OPERFORCE))
    return send_reply(sptr, ERR_TOOMANYUSERS, tmp);
  }

  if (!check_if_ipmask(ipmask))
    return send_reply(sptr, ERR_INVALIDMASK);

  /*
   * You cannot set a negative (or zero) expire time, nor can you set an
   * expiration time for greater than ZLINE_MAX_EXPIRE.
   */
  if (!(flags & ZLINE_FORCE) &&
      (expire <= TStime() || expire > TStime() + ZLINE_MAX_EXPIRE)) {
    if (!IsServer(sptr) && MyConnect(sptr))
      send_reply(sptr, ERR_BADEXPIRE, expire);
    return 0;
  } else if (expire <= TStime()) {
    /* This expired Z-line was forced to be added, so mark it inactive. */
    flags &= ~ZLINE_ACTIVE;
  }

  if (!lifetime) /* no lifetime set, use expiration time */
    lifetime = expire;

  /* lifetime is already an absolute timestamp */

  /* Inform ops... */
  sendto_opmask_butone(0, ircd_strncmp(reason, "AUTO", 4) ? SNO_GLINE :
                       SNO_AUTO, "%s adding %s%s ZLINE for %s, expiring at "
                       "%Tu: %s",
                       (feature_bool(FEAT_HIS_SNOTICES) || IsServer(sptr)) ?
                         cli_name(sptr) :
                         cli_name((cli_user(sptr))->server),
                       (flags & ZLINE_ACTIVE) ? "" : "deactivated ",
		       (flags & ZLINE_LOCAL) ? "local" : "global",
		       mask, expire, reason);

  /* and log it */
  log_write(LS_GLINE, L_INFO, LOG_NOSNOTICE,
	    "%#C adding %s ZLINE for %s, expiring at %Tu: %s", sptr,
	    flags & ZLINE_LOCAL ? "local" : "global", mask,
	    expire, reason);

  /* make the zline */
  azline = make_zline(mask, reason, expire, lastmod, lifetime, flags);

  /* since we've disabled overlapped Z-line checking, azline should
   * never be NULL...
   */
  assert(azline);

  zline_propagate(cptr, sptr, azline);

  return do_zline(cptr, sptr, azline); /* knock off users if necessary */
}

/** Activate a currently inactive Z-line.
 * @param[in] cptr Peer that told us to activate the Z-line.
 * @param[in] sptr Client that originally thought it was a good idea.
 * @param[in] zline Z-line to activate.
 * @param[in] lastmod New value for last modification timestamp.
 * @param[in] flags 0 if the activation should be propagated, ZLINE_LOCAL if not.
 * @return Zero, unless \a sptr had a death wish (in which case CPTR_KILLED).
 */
int
zline_activate(struct Client *cptr, struct Client *sptr, struct Zline *zline,
	       time_t lastmod, unsigned int flags)
{
  unsigned int saveflags = 0;

  assert(0 != zline);

  saveflags = zline->zl_flags;

  if (flags & ZLINE_LOCAL)
    zline->zl_flags &= ~ZLINE_LDEACT;
  else {
    zline->zl_flags |= ZLINE_ACTIVE;

    if (zline->zl_lastmod) {
      if (zline->zl_lastmod >= lastmod) /* force lastmod to increase */
	zline->zl_lastmod++;
      else
	zline->zl_lastmod = lastmod;
    }
  }

  if ((saveflags & ZLINE_ACTMASK) == ZLINE_ACTIVE)
    return 0; /* was active to begin with */

  /* Inform ops and log it */
  sendto_opmask_butone(0, SNO_GLINE, "%s activating global ZLINE for %s, "
                       "expiring at %Tu: %s",
                       (feature_bool(FEAT_HIS_SNOTICES) || IsServer(sptr)) ?
                         cli_name(sptr) :
                         cli_name((cli_user(sptr))->server),
                       zline->zl_mask, zline->zl_expire, zline->zl_reason);

  log_write(LS_GLINE, L_INFO, LOG_NOSNOTICE,
	    "%#C activating global ZLINE for %s, expiring at %Tu: %s", sptr,
	    zline->zl_mask, zline->zl_expire, zline->zl_reason);

  if (!(flags & ZLINE_LOCAL)) /* don't propagate local changes */
    zline_propagate(cptr, sptr, zline);

  return do_zline(cptr, sptr, zline);
}

/** Deactivate a Z-line.
 * @param[in] cptr Peer that gave us the message.
 * @param[in] sptr Client that initiated the deactivation.
 * @param[in] zline Z-line to deactivate.
 * @param[in] lastmod New value for Z-line last modification timestamp.
 * @param[in] flags ZLINE_LOCAL to only deactivate locally, 0 to propagate.
 * @return Zero.
 */
int
zline_deactivate(struct Client *cptr, struct Client *sptr, struct Zline *zline,
		 time_t lastmod, unsigned int flags)
{
  unsigned int saveflags = 0;
  char *msg;

  assert(0 != zline);

  saveflags = zline->zl_flags;

  if (ZlineIsLocal(zline))
    msg = "removing local";
  else if (!zline->zl_lastmod && !(flags & ZLINE_LOCAL)) {
    msg = "removing global";
    zline->zl_flags &= ~ZLINE_ACTIVE; /* propagate a -<mask> */
  } else {
    msg = "deactivating global";

    if (flags & ZLINE_LOCAL)
      zline->zl_flags |= ZLINE_LDEACT;
    else {
      zline->zl_flags &= ~ZLINE_ACTIVE;

      if (zline->zl_lastmod) {
	if (zline->zl_lastmod >= lastmod)
	  zline->zl_lastmod++;
	else
	  zline->zl_lastmod = lastmod;
      }
    }

    if ((saveflags & ZLINE_ACTMASK) != ZLINE_ACTIVE)
      return 0; /* was inactive to begin with */
  }

  /* Inform ops and log it */
  sendto_opmask_butone(0, SNO_GLINE, "%s %s ZLINE for %s, expiring at %Tu: "
		       "%s",
                       (feature_bool(FEAT_HIS_SNOTICES) || IsServer(sptr)) ?
                         cli_name(sptr) :
                         cli_name((cli_user(sptr))->server), msg,
		       zline->zl_mask, zline->zl_expire, zline->zl_reason);

  log_write(LS_GLINE, L_INFO, LOG_NOSNOTICE,
	    "%#C %s ZLINE for %s, expiring at %Tu: %s", sptr, msg,
	    zline->zl_mask, zline->zl_expire, zline->zl_reason);

  if (!(flags & ZLINE_LOCAL)) /* don't propagate local changes */
    zline_propagate(cptr, sptr, zline);

  /* if it's a local zline or a Uworld zline (and not locally deactivated).. */
  if (ZlineIsLocal(zline) || (!zline->zl_lastmod && !(flags & ZLINE_LOCAL)))
    zline_free(zline); /* get rid of it */

  return 0;
}

/** Modify a global Z-line.
 * @param[in] cptr Client that sent us the Z-line modification.
 * @param[in] sptr Client that originated the Z-line modification.
 * @param[in] zline Z-line being modified.
 * @param[in] action Resultant status of the Z-line.
 * @param[in] reason Reason for Z-line.
 * @param[in] expire Expiration time of Z-line.
 * @param[in] lastmod Last modification time of Z-line.
 * @param[in] lifetime Lifetime of Z-line.
 * @param[in] flags Bitwise combination of ZLINE_* flags.
 * @return Zero or CPTR_KILLED, depending on whether \a sptr is suicidal.
 */
int
zline_modify(struct Client *cptr, struct Client *sptr, struct Zline *zline,
	     enum ZlineAction action, char *reason, time_t expire,
	     time_t lastmod, time_t lifetime, unsigned int flags)
{
  char buf[BUFSIZE], *op = "";
  int pos = 0, non_auto = 0;

  assert(zline);
  assert(!ZlineIsLocal(zline));

  Debug((DEBUG_DEBUG,  "zline_modify(\"%s\", \"%s\", \"%s\", %s, \"%s\", "
	 "%Tu, %Tu, %Tu, 0x%04x)", cli_name(cptr), cli_name(sptr),
	 zline->zl_mask,
	 action == ZLINE_ACTIVATE ? "ZLINE_ACTIVATE" :
	 (action == ZLINE_DEACTIVATE ? "ZLINE_DEACTIVATE" :
	  (action == ZLINE_LOCAL_ACTIVATE ? "ZLINE_LOCAL_ACTIVATE" :
	   (action == ZLINE_LOCAL_DEACTIVATE ? "ZLINE_LOCAL_DEACTIVATE" :
	    (action == ZLINE_MODIFY ? "ZLINE_MODIFY" : "<UNKNOWN>")))),
	 reason, expire, lastmod, lifetime, flags));

  /* First, let's check lastmod... */
  if (action != ZLINE_LOCAL_ACTIVATE && action != ZLINE_LOCAL_DEACTIVATE) {
    if (ZlineLastMod(zline) > lastmod) { /* we have a more recent version */
      if (IsBurstOrBurstAck(cptr))
	return 0; /* middle of a burst, it'll resync on its own */
      return zline_resend(cptr, zline); /* resync the server */
    } else if (ZlineLastMod(zline) == lastmod)
      return 0; /* we have that version of the Z-line... */
  }

  /* All right, we know that there's a change of some sort.  What is it? */
  /* first, check out the expiration time... */
  if ((flags & ZLINE_EXPIRE) && expire) {
    if (!(flags & ZLINE_FORCE) &&
	(expire <= TStime() || expire > TStime() + ZLINE_MAX_EXPIRE)) {
      if (!IsServer(sptr) && MyConnect(sptr)) /* bad expiration time */
	send_reply(sptr, ERR_BADEXPIRE, expire);
      return 0;
    }
  } else
    flags &= ~ZLINE_EXPIRE;

  /* Now check to see if there's any change... */
  if ((flags & ZLINE_EXPIRE) && expire == zline->zl_expire) {
    flags &= ~ZLINE_EXPIRE; /* no change to expiration time... */
    expire = 0;
  }

  /* Next, check out lifetime--this one's a bit trickier... */
  if (!(flags & ZLINE_LIFETIME) || !lifetime)
    lifetime = zline->zl_lifetime; /* use Z-line lifetime */

  lifetime = IRCD_MAX(lifetime, expire); /* set lifetime to the max */

  /* OK, let's see which is greater... */
  if (lifetime > zline->zl_lifetime)
    flags |= ZLINE_LIFETIME; /* have to update lifetime */
  else {
    flags &= ~ZLINE_LIFETIME; /* no change to lifetime */
    lifetime = 0;
  }

  /* Finally, let's see if the reason needs to be updated */
  if ((flags & ZLINE_REASON) && reason &&
      !ircd_strcmp(zline->zl_reason, reason))
    flags &= ~ZLINE_REASON; /* no changes to the reason */

  /* OK, now let's take a look at the action... */
  if ((action == ZLINE_ACTIVATE && (zline->zl_flags & ZLINE_ACTIVE)) ||
      (action == ZLINE_DEACTIVATE && !(zline->zl_flags & ZLINE_ACTIVE)) ||
      (action == ZLINE_LOCAL_ACTIVATE &&
       (zline->zl_state == ZLOCAL_ACTIVATED)) ||
      (action == ZLINE_LOCAL_DEACTIVATE &&
       (zline->zl_state == ZLOCAL_DEACTIVATED)) ||
      /* can't activate an expired Z-line */
      IRCD_MAX(zline->zl_expire, expire) <= TStime())
    action = ZLINE_MODIFY; /* no activity state modifications */

  Debug((DEBUG_DEBUG,  "About to perform changes; flags 0x%04x, action %s",
	 flags, action == ZLINE_ACTIVATE ? "ZLINE_ACTIVATE" :
	 (action == ZLINE_DEACTIVATE ? "ZLINE_DEACTIVATE" :
	  (action == ZLINE_LOCAL_ACTIVATE ? "ZLINE_LOCAL_ACTIVATE" :
	   (action == ZLINE_LOCAL_DEACTIVATE ? "ZLINE_LOCAL_DEACTIVATE" :
	    (action == ZLINE_MODIFY ? "ZLINE_MODIFY" : "<UNKNOWN>"))))));

  /* If there are no changes to perform, do no changes */
  if (!(flags & ZLINE_UPDATE) && action == ZLINE_MODIFY)
    return 0;

  /* Now we know what needs to be changed, so let's process the changes... */

  /* Start by updating lastmod, if indicated... */
  if (action != ZLINE_LOCAL_ACTIVATE && action != ZLINE_LOCAL_DEACTIVATE)
    zline->zl_lastmod = lastmod;

  /* Then move on to activity status changes... */
  switch (action) {
  case ZLINE_ACTIVATE: /* Globally activating Z-line */
    zline->zl_flags |= ZLINE_ACTIVE; /* make it active... */
    zline->zl_state = ZLOCAL_GLOBAL; /* reset local activity state */
    pos += ircd_snprintf(0, buf, sizeof(buf), " globally activating Z-line");
    op = "+"; /* operation for Z-line propagation */
    break;

  case ZLINE_DEACTIVATE: /* Globally deactivating Z-line */
    zline->zl_flags &= ~ZLINE_ACTIVE; /* make it inactive... */
    zline->zl_state = ZLOCAL_GLOBAL; /* reset local activity state */
    pos += ircd_snprintf(0, buf, sizeof(buf), " globally deactivating Z-line");
    op = "-"; /* operation for Z-line propagation */
    break;

  case ZLINE_LOCAL_ACTIVATE: /* Locally activating Z-line */
    zline->zl_state = ZLOCAL_ACTIVATED; /* make it locally active */
    pos += ircd_snprintf(0, buf, sizeof(buf), " locally activating Z-line");
    break;

  case ZLINE_LOCAL_DEACTIVATE: /* Locally deactivating Z-line */
    zline->zl_state = ZLOCAL_DEACTIVATED; /* make it locally inactive */
    pos += ircd_snprintf(0, buf, sizeof(buf), " locally deactivating Z-line");
    break;

  case ZLINE_MODIFY: /* no change to activity status */
    break;
  }

  /* Handle expiration changes... */
  if (flags & ZLINE_EXPIRE) {
    zline->zl_expire = expire; /* save new expiration time */
    if (pos < BUFSIZE)
      pos += ircd_snprintf(0, buf + pos, sizeof(buf) - pos,
			   "%s%s changing expiration time to %Tu",
			   pos ? ";" : "",
			   pos && !(flags & (ZLINE_LIFETIME | ZLINE_REASON)) ?
			   " and" : "", expire);
  }

  /* Next, handle lifetime changes... */
  if (flags & ZLINE_LIFETIME) {
    zline->zl_lifetime = lifetime; /* save new lifetime */
    if (pos < BUFSIZE)
      pos += ircd_snprintf(0, buf + pos, sizeof(buf) - pos,
			   "%s%s extending record lifetime to %Tu",
			   pos ? ";" : "", pos && !(flags & ZLINE_REASON) ?
			   " and" : "", lifetime);
  }

  /* Now, handle reason changes... */
  if (flags & ZLINE_REASON) {
    non_auto = non_auto || ircd_strncmp(zline->zl_reason, "AUTO", 4);
    MyFree(zline->zl_reason); /* release old reason */
    DupString(zline->zl_reason, reason); /* store new reason */
    if (pos < BUFSIZE)
      pos += ircd_snprintf(0, buf + pos, sizeof(buf) - pos,
			   "%s%s changing reason to \"%s\"",
			   pos ? ";" : "", pos ? " and" : "", reason);
  }

  /* All right, inform ops... */
  non_auto = non_auto || ircd_strncmp(zline->zl_reason, "AUTO", 4);
  sendto_opmask_butone(0, non_auto ? SNO_GLINE : SNO_AUTO,
		       "%s modifying global ZLINE for %s:%s",
		       (feature_bool(FEAT_HIS_SNOTICES) || IsServer(sptr)) ?
		       cli_name(sptr) : cli_name((cli_user(sptr))->server),
		       zline->zl_mask, buf);

  /* and log the change */
  log_write(LS_GLINE, L_INFO, LOG_NOSNOTICE,
	    "%#C modifying global ZLINE for %s:%s", sptr, zline->zl_mask, buf);

  /* We'll be simple for this release, but we can update this to change
   * the propagation syntax on future updates
   */
  if (action != ZLINE_LOCAL_ACTIVATE && action != ZLINE_LOCAL_DEACTIVATE)
    sendcmdto_serv_butone(sptr, CMD_ZLINE, cptr,
			  "* %s%s%s %Tu %Tu %Tu :%s",
			  flags & ZLINE_OPERFORCE ? "!" : "", op,
			  zline->zl_mask, zline->zl_expire - TStime(),
                          zline->zl_lastmod, zline->zl_lifetime, zline->zl_reason);

  /* OK, let's do the Z-line... */
  return do_zline(cptr, sptr, zline);
}

/** Destroy a local Z-line.
 * @param[in] cptr Peer that gave us the message.
 * @param[in] sptr Client that initiated the destruction.
 * @param[in] zline Z-line to destroy.
 * @return Zero.
 */
int
zline_destroy(struct Client *cptr, struct Client *sptr, struct Zline *zline)
{
  assert(zline);
  assert(ZlineIsLocal(zline));

  /* Inform ops and log it */
  sendto_opmask_butone(0, SNO_GLINE, "%s removing local ZLINE for %s",
		       (feature_bool(FEAT_HIS_SNOTICES) || IsServer(sptr)) ?
		       cli_name(sptr) : cli_name((cli_user(sptr))->server),
		       zline->zl_mask);
  log_write(LS_GLINE, L_INFO, LOG_NOSNOTICE,
	    "%#C removing local ZLINE for %s", sptr, zline->zl_mask);

  zline_free(zline); /* get rid of the Z-line */

  return 0; /* convenience return */
}

/** Find a Z-line for a particular mask, guided by certain flags.
 * Certain bits in \a flags are interpreted specially:
 * <dl>
 * <dt>ZLINE_ANY</dt><dd>Search user Z-lines.</dd>
 * <dt>ZLINE_GLOBAL</dt><dd>Only match global Z-lines.</dd>
 * <dt>ZLINE_LOCAL</dt><dd>Only match local Z-lines.</dd>
 * <dt>ZLINE_LASTMOD</dt><dd>Only match Z-lines with a last modification time.</dd>
 * <dt>ZLINE_EXACT</dt><dd>Require an exact match of Z-line mask.</dd>
 * <dt>anything else</dt><dd>Search user Z-lines.</dd>
 * </dl>
 * @param[in] ipmask Mask to search for.
 * @param[in] flags Bitwise combination of ZLINE_* flags.
 * @return First matching Z-line, or NULL if none are found.
 */
struct Zline *
zline_find(char *ipmask, unsigned int flags)
{
  struct Zline *zline = 0;
  struct Zline *szline;
  char *mask, *t_uh;

  DupString(t_uh, ipmask);
  mask = t_uh;

  zliter(GlobalZlineList, zline, szline) {
    if ((flags & (ZlineIsLocal(zline) ? ZLINE_GLOBAL : ZLINE_LOCAL)) ||
	(flags & ZLINE_LASTMOD && !zline->zl_lastmod))
      continue;
    else if (flags & ZLINE_EXACT) {
      if (((zline->zl_mask && mask && ircd_strcmp(zline->zl_mask, mask) == 0)
           || (!zline->zl_mask && !mask)))
	break;
    } else {
      if (((zline->zl_mask && mask && match(zline->zl_mask, mask) == 0)
           || (!zline->zl_mask && !mask)))
	break;
    }
  }

  MyFree(t_uh);

  return zline;
}

/** Find a matching Z-line for a user.
 * @param[in] cptr Client to compare against.
 * @param[in] flags Bitwise combination of ZLINE_GLOBAL and/or
 * ZLINE_LASTMOD to limit matches.
 * @return Matching Z-line, or NULL if none are found.
 */
struct Zline *
zline_lookup(struct Client *cptr, unsigned int flags)
{
  struct Zline *zline;
  struct Zline *szline;

  if (find_except_conf(cptr, EFLAG_ZLINE))
    return 0;

  zliter(GlobalZlineList, zline, szline) {
    if ((flags & ZLINE_GLOBAL && zline->zl_flags & ZLINE_LOCAL) ||
        (flags & ZLINE_LASTMOD && !zline->zl_lastmod))
      continue;

    if (ZlineIsIpMask(zline)) {
      if (!irc_in_addr_type_cmp(&cli_ip(cptr), &zline->zl_addr))
        continue;
      if (!ipmask_check(&cli_ip(cptr), &zline->zl_addr, zline->zl_bits))
        continue;
    }
    else {
      if (match(zline->zl_mask, cli_sock_ip(cptr)) != 0)
        continue;
    }
    if (ZlineIsActive(zline))
      return zline;
  }
  /*
   * No Zlines matched
   */
  return 0;
}

/** Delink and free a Z-line.
 * @param[in] zline Z-line to free.
 */
void
zline_free(struct Zline *zline)
{
  assert(0 != zline);

  *zline->zl_prev_p = zline->zl_next; /* squeeze this zline out */
  if (zline->zl_next)
    zline->zl_next->zl_prev_p = zline->zl_prev_p;

  if (zline->zl_mask)
    MyFree(zline->zl_mask);
  MyFree(zline->zl_reason);
  MyFree(zline);
}

/** Burst all known global Z-lines to another server.
 * @param[in] cptr Destination of burst.
 */
void
zline_burst(struct Client *cptr)
{
  struct Zline *zline;
  struct Zline *szline;

  zliter(GlobalZlineList, zline, szline) {
    if (!ZlineIsLocal(zline) && zline->zl_lastmod)
      sendcmdto_one(&me, CMD_ZLINE, cptr, "* %c%s %Tu %Tu %Tu :%s",
		    ZlineIsRemActive(zline) ? '+' : '-',
                    zline->zl_mask, zline->zl_expire - TStime(),
		    zline->zl_lastmod, zline->zl_lifetime,
		    zline->zl_reason);
  }
}

/** Send a Z-line to another server.
 * @param[in] cptr Who to inform of the Z-line.
 * @param[in] zline Z-line to send.
 * @return Zero.
 */
int
zline_resend(struct Client *cptr, struct Zline *zline)
{
  if (ZlineIsLocal(zline) || !zline->zl_lastmod)
    return 0;

  sendcmdto_one(&me, CMD_ZLINE, cptr, "* %c%s %Tu %Tu %Tu :%s",
		ZlineIsRemActive(zline) ? '+' : '-',
                zline->zl_mask, zline->zl_expire - TStime(),
		zline->zl_lastmod, zline->zl_lifetime,
		zline->zl_reason);

  return 0;
}

/** Display one or all Z-lines to a user.
 * If \a ipmask is not NULL, only send the first matching Z-line.
 * Otherwise send the whole list.
 * @param[in] sptr User asking for Z-line list.
 * @param[in] ipmask Z-line mask to search for (or NULL).
 * @return Zero.
 */
int
zline_list(struct Client *sptr, char *ipmask)
{
  struct Zline *zline;
  struct Zline *szline;

  if (ipmask) {
    if (!(zline = zline_find(ipmask, ZLINE_ANY))) /* no such zline */
      return send_reply(sptr, ERR_NOSUCHZLINE, ipmask);

    /* send zline information along */
    send_reply(sptr, RPL_ZLIST,
               zline->zl_mask, zline->zl_expire,
	       zline->zl_lastmod, zline->zl_lifetime,
	       ZlineIsLocal(zline) ? cli_name(&me) : "*",
	       zline->zl_state == ZLOCAL_ACTIVATED ? ">" :
	       (zline->zl_state == ZLOCAL_DEACTIVATED ? "<" : ""),
	       ZlineIsRemActive(zline) ? '+' : '-', zline->zl_reason);
  } else {
    zliter(GlobalZlineList, zline, szline) {
      send_reply(sptr, RPL_ZLIST,
		 zline->zl_mask, zline->zl_expire,
		 zline->zl_lastmod, zline->zl_lifetime,
		 ZlineIsLocal(zline) ? cli_name(&me) : "*",
		 zline->zl_state == ZLOCAL_ACTIVATED ? ">" :
		 (zline->zl_state == ZLOCAL_DEACTIVATED ? "<" : ""),
		 ZlineIsRemActive(zline) ? '+' : '-', zline->zl_reason);
    }
  }

  /* end of zline information */
  return send_reply(sptr, RPL_ENDOFZLIST);
}

/** Statistics callback to list Z-lines.
 * @param[in] sptr Client requesting statistics.
 * @param[in] sd Stats descriptor for request (ignored).
 * @param[in] param Extra parameter from user (ignored).
 */
void
zline_stats(struct Client *sptr, const struct StatDesc *sd,
            char *param)
{
  struct Zline *zline;
  struct Zline *szline;

  zliter(GlobalZlineList, zline, szline) {
    send_reply(sptr, RPL_STATSZLINE, 'Z',
	       zline->zl_mask, zline->zl_expire,
	       zline->zl_lastmod, zline->zl_lifetime,
	       zline->zl_state == ZLOCAL_ACTIVATED ? ">" :
	       (zline->zl_state == ZLOCAL_DEACTIVATED ? "<" : ""),
	       ZlineIsRemActive(zline) ? '+' : '-',
	       zline->zl_reason);
  }
}

/** Calculate memory used by Z-lines.
 * @param[out] zl_size Number of bytes used by Z-lines.
 * @return Number of Z-lines in use.
 */
int
zline_memory_count(size_t *zl_size)
{
  struct Zline *zline;
  unsigned int zl = 0;

  for (zline = GlobalZlineList; zline; zline = zline->zl_next) {
    zl++;
    *zl_size += sizeof(struct Zline);
    *zl_size += zline->zl_mask ? (strlen(zline->zl_mask) + 1) : 0;
    *zl_size += zline->zl_reason ? (strlen(zline->zl_reason) + 1) : 0;
  }

  return zl;
}

/** Remove a zline with a specified mask.
 * @param[in] sptr Client issuing the removal request.
 * @param[in] ipmask ZLine to be removed.
 * @param[in] reason Reason for the removal.
 */
int
zline_remove(struct Client* sptr, char *ipmask, char *reason)
{
  char imask[HOSTLEN + 2];
  struct Zline *zline, *szline;
  char *mask, *t_uh;

  DupString(t_uh, ipmask);
  mask = t_uh;

  if (sizeof(imask) <
      ircd_snprintf(0, imask, sizeof(imask), "%s", mask))
    return send_reply(sptr, ERR_LONGMASK);

  for (zline = GlobalZlineList; zline; zline = szline) {
    szline = zline->zl_next;

    if (zline->zl_expire <= CurrentTime)
      zline_free(zline);
    else if (((zline->zl_mask && mask && ircd_strcmp(zline->zl_mask,mask) == 0)
            ||(!zline->zl_mask && !mask))) {
      sendto_opmask_butone(0, SNO_GLINE, "%s force removing ZLINE for %s (%s)",
                           feature_bool(FEAT_HIS_SNOTICES) || IsServer(sptr) ?
                           cli_name(sptr) : cli_name((cli_user(sptr))->server),
                           imask, reason);

      log_write(LS_GLINE, L_INFO, LOG_NOSNOTICE,
                "%#C force removing ZLINE for %s (%s)", sptr, imask, reason);

      zline_free(zline);
    }
  }

  if (!BadPtr(t_uh))
    MyFree(t_uh);

  return 0;
}

