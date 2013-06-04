/*
 * IRC - Internet Relay Chat, ircd/shun.c
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
 * @brief Implementation of Shun manipulation functions.
 * @version $Id: shun.c 1936 2010-01-07 02:55:33Z entrope $
 */
#include "config.h"

#include "shun.h"
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

/** List of user Shuns. */
struct Shun* GlobalShunList  = 0;

/** Iterate through \a list of Shuns.  Use this like a for loop,
 * i.e., follow it with braces and use whatever you passed as \a gl
 * as a single Shun to be acted upon.
 *
 * @param[in] list List of Shuns to iterate over.
 * @param[in] gl Name of a struct Shun pointer variable that will be made to point to the Shuns in sequence.
 * @param[in] next Name of a scratch struct Shun pointer variable.
 */
/* There is some subtlety here with the boolean operators:
 * (x || 1) is used to continue in a logical-and series even when !x.
 * (x && 0) is used to continue in a logical-or series even when x.
 */
#define shiter(list, gl, next)				\
  /* Iterate through the Shuns in the list */		\
  for ((gl) = (list); (gl); (gl) = (next))		\
    /* Figure out the next pointer in list... */	\
    if ((((next) = (gl)->sh_next) || 1) &&		\
	/* Then see if it's expired */			\
	(gl)->sh_lifetime <= TStime())                  \
      /* Record has expired, so free the Shun */	\
      shun_free((gl));					\
    /* See if we need to expire the Shun */		\
    else if ((((gl)->sh_expire > TStime()) ||		\
	      (((gl)->sh_flags &= ~SHUN_ACTIVE) && 0) ||	\
	      ((gl)->sh_state = SLOCAL_GLOBAL)) && 0)	\
      ; /* empty statement */				\
    else

/** Find canonical user and host for a string.
 * If \a userhost starts with '$', assign \a userhost to *user_p and NULL to *host_p.
 * Otherwise, if \a userhost contains '@', assign the earlier part of it to *user_p and the rest to *host_p.
 * Otherwise, assign \a def_user to *user_p and \a userhost to *host_p.
 *
 * @param[in] userhost Input string from user.
 * @param[out] user_p Gets pointer to user (or channel/realname) part of hostmask.
 * @param[out] host_p Gets point to host part of hostmask (may be assigned NULL).
 * @param[in] def_user Default value for user part.
 */
static void
canon_userhost(char *userhost, char **user_p, char **host_p, char *def_user)
{
  char *tmp;

  if (*userhost == '$') {
    *user_p = userhost;
    *host_p = NULL;
    return;
  }

  if (!(tmp = strchr(userhost, '@'))) {
    *user_p = def_user;
    *host_p = userhost;
  } else {
    *user_p = userhost;
    *(tmp++) = '\0';
    *host_p = tmp;
  }
}

/** Create a Shun structure.
 * @param[in] user User part of mask.
 * @param[in] host Host part of mask (NULL if not applicable).
 * @param[in] reason Reason for Shun.
 * @param[in] expire Expiration timestamp.
 * @param[in] lastmod Last modification timestamp.
 * @param[in] flags Bitwise combination of SHUN_* bits.
 * @return Newly allocated Shun.
 */
static struct Shun *
make_shun(char *user, char *host, char *reason, time_t expire, time_t lastmod,
	   time_t lifetime, unsigned int flags)
{
  struct Shun *shun;

  assert(0 != expire);

  shun = (struct Shun *)MyMalloc(sizeof(struct Shun)); /* alloc memory */
  assert(0 != shun);

  DupString(shun->sh_reason, reason); /* initialize shun... */
  shun->sh_expire = expire;
  shun->sh_lifetime = lifetime;
  shun->sh_lastmod = lastmod;
  shun->sh_flags = flags & SHUN_MASK;
  shun->sh_state = SLOCAL_GLOBAL; /* not locally modified */

  DupString(shun->sh_user, user); /* remember them... */
  if (*user != '$')
    DupString(shun->sh_host, host);
  else
    shun->sh_host = NULL;

  if (*user != '$' && ipmask_parse(host, &shun->sh_addr, &shun->sh_bits)) {
    shun->sh_flags |= SHUN_IPMASK;
    shun->sh_addr = ipmask_clean(&shun->sh_addr, shun->sh_bits);
  }

  shun->sh_next = GlobalShunList; /* then link it into list */
  shun->sh_prev_p = &GlobalShunList;
  if (GlobalShunList)
    GlobalShunList->sh_prev_p = &shun->sh_next;
  GlobalShunList = shun;

  return shun;
}

/** Check local clients against a new Shun.
 * If the Shun is inactive, return immediately.
 * Otherwise, if any users match it, disconnect them.
 * @param[in] cptr Peer connect that sent the Shun.
 * @param[in] sptr Client that originated the Shun.
 * @param[in] shun New Shun to check.
 * @return Zero, unless \a sptr Shunned himself, in which case CPTR_KILLED.
 */
static int
do_shun(struct Client *cptr, struct Client *sptr, struct Shun *shun)
{
  struct Client *acptr;
  int fd;

  if (feature_bool(FEAT_DISABLE_SHUNS))
    return 0; /* Shuns are disabled */

  if (!ShunIsActive(shun)) /* no action taken on inactive shuns */
    return 0;

  for (fd = HighestFd; fd >= 0; --fd) {
    /*
     * get the users!
     */
    if ((acptr = LocalClientArray[fd])) {
      if (!cli_user(acptr))
	continue;

      if (find_except_conf(acptr, EFLAG_SHUN))
        continue;

      if (ShunIsRealName(shun)) { /* Realname Shun */
	Debug((DEBUG_DEBUG,"Realname Shun: %s %s",(cli_info(acptr)),
					shun->sh_user+2));
        if (match(shun->sh_user+2, cli_info(acptr)) != 0)
            continue;
        Debug((DEBUG_DEBUG,"Matched!"));
      } else if (ShunIsVersion(shun)) { /* CTCP Version Shun */
        Debug((DEBUG_DEBUG,"CTCP Version Shun: %s %s",(cli_version(acptr)),
                                        shun->sh_user+2));
        if (EmptyString(cli_version(acptr)) || (match(shun->sh_user+2, cli_version(acptr)) != 0))
            continue;
        Debug((DEBUG_DEBUG,"Matched!"));
      } else { /* Host/IP shun */
        if (cli_user(acptr)->username &&
            match(shun->sh_user, (cli_user(acptr))->username) != 0)
          continue;

        if (ShunIsIpMask(shun)) {
          if (!irc_in_addr_type_cmp(&cli_ip(acptr), &shun->sh_addr))
            continue;
          if (!ipmask_check(&cli_ip(acptr), &shun->sh_addr, shun->sh_bits))
            continue;
        }
        else {
          if (match(shun->sh_host, cli_sockhost(acptr)) != 0)
            continue;
        }
      }

      /* ok, here's one that got Shunned */
      if (!feature_bool(FEAT_HIS_SHUN_REASON))
        sendcmdto_one(&me, CMD_NOTICE, acptr, "%C :You are shunned: %s", acptr,
             shun->sh_reason);

      /* let the ops know about it */
      sendto_opmask_butone_global(&me, SNO_GLINE, "Shun active for %s",
                           get_client_name(acptr, SHOW_IP));
    }
  }
  return 0;
}

/**
 * Implements the mask checking applied to local Shuns.
 * Basically, host masks must have a minimum of two non-wild domain
 * fields, and IP masks must have a minimum of 16 bits.  If the mask
 * has even one wild-card, OVERRIDABLE is returned, assuming the other
 * check doesn't fail.
 * @param[in] mask Shun mask to check.
 * @return One of CHECK_REJECTED, CHECK_OVERRIDABLE, or CHECK_APPROVED.
 */
static int
shun_checkmask(char *mask)
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

/** Forward a Shun to other servers.
 * @param[in] cptr Client that sent us the Shun.
 * @param[in] sptr Client that originated the Shun.
 * @param[in] shun Shun to forward.
 * @return Zero.
 */
static int
shun_propagate(struct Client *cptr, struct Client *sptr, struct Shun *shun)
{
  if (ShunIsLocal(shun))
    return 0;

  assert(shun->sh_lastmod);

  sendcmdto_serv_butone(sptr, CMD_SHUN, cptr, "* %c%s%s%s %Tu %Tu %Tu :%s",
			ShunIsRemActive(shun) ? '+' : '-', shun->sh_user,
			shun->sh_host ? "@" : "",
			shun->sh_host ? shun->sh_host : "",
			shun->sh_expire - TStime(), shun->sh_lastmod,
			shun->sh_lifetime, shun->sh_reason);

  return 0;
}

/** Count number of users who match \a mask.
 * @param[in] mask user\@host or user\@ip mask to check.
 * @param[in] flags Bitmask possibly containing the value SHUN_LOCAL, to limit searches to this server.
 * @return Count of matching users.
 */
static int
count_users(char *mask, int flags)
{
  struct irc_in_addr ipmask;
  struct Client *acptr;
  int count = 0;
  int ipmask_valid;
  char namebuf[USERLEN + HOSTLEN + 2];
  char ipbuf[USERLEN + SOCKIPLEN + 2];
  unsigned char ipmask_len;

  ipmask_valid = ipmask_parse(mask, &ipmask, &ipmask_len);
  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr)) {
    if (!IsUser(acptr))
      continue;
    if ((flags & SHUN_LOCAL) && !MyConnect(acptr))
      continue;

    ircd_snprintf(0, namebuf, sizeof(namebuf), "%s@%s",
		  cli_user(acptr)->username, cli_user(acptr)->host);
    ircd_snprintf(0, ipbuf, sizeof(ipbuf), "%s@%s", cli_user(acptr)->username,
		  ircd_ntoa(&cli_ip(acptr)));

    if (!match(mask, namebuf)
        || !match(mask, ipbuf)
        || (ipmask_valid && ipmask_check(&cli_ip(acptr), &ipmask, ipmask_len)
            && irc_in_addr_type_cmp(&cli_ip(acptr), &ipmask)))
      count++;
  }

  return count;
}

/** Count number of users with a realname matching \a mask.
 * @param[in] mask Wildcard mask to match against realnames.
 * @return Count of matching users.
 */
static int
count_realnames(const char *mask)
{
  struct Client *acptr;
  int minlen;
  int count;
  char cmask[BUFSIZE];

  count = 0;
  matchcomp(cmask, &minlen, NULL, mask);
  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr)) {
    if (!IsUser(acptr))
      continue;
    if (strlen(cli_info(acptr)) < minlen)
      continue;
    if (!matchexec(cli_info(acptr), cmask, minlen))
      count++;
  }
  return count;
}

/** Count number of users with a CTCP version matching \a mask.
 * @param[in] mask Wildcard mask to match against CTCP versions.
 * @return Count of matching users.
 */
static int
count_versions(const char *mask)
{
  struct Client *acptr;
  int minlen;
  int count;
  char cmask[BUFSIZE];

  count = 0;
  matchcomp(cmask, &minlen, NULL, mask);
  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr)) {
    if (!IsUser(acptr))
      continue;
    if (EmptyString(cli_version(acptr)))
      continue;
    if (strlen(cli_version(acptr)) < minlen)
      continue;
    if (!matchexec(cli_version(acptr), cmask, minlen))
      count++;
  }
  return count;
}

/** Create a new Shun and add it to global lists.
 * \a userhost may be in one of four forms:
 * \li A string starting with $R and followed by a mask to match against their realname.
 * \li A string starting with $V and followed by a mask to match against their CTCP version.
 * \li A user\@IP mask (user\@ part optional) to create an IP-based ban.
 * \li A user\@host mask (user\@ part optional) to create a hostname ban.
 *
 * @param[in] cptr Client that sent us the Shun.
 * @param[in] sptr Client that originated the Shun.
 * @param[in] userhost Text mask for the Shun.
 * @param[in] reason Reason for Shun.
 * @param[in] expire Expiration time of Shun.
 * @param[in] lastmod Last modification time of Shun.
 * @param[in] lifetime Lifetime of Shun.
 * @param[in] flags Bitwise combination of SHUN_* flags.
 * @return Zero or CPTR_KILLED, depending on whether \a sptr is suicidal.
 */
int
shun_add(struct Client *cptr, struct Client *sptr, char *userhost,
	  char *reason, time_t expire, time_t lastmod, time_t lifetime,
	  unsigned int flags)
{
  struct Shun *ashun;
  char uhmask[USERLEN + HOSTLEN + 2];
  char *user, *host;
  int tmp;

  assert(0 != userhost);
  assert(0 != reason);
  assert(((flags & (SHUN_GLOBAL | SHUN_LOCAL)) == SHUN_GLOBAL) ||
         ((flags & (SHUN_GLOBAL | SHUN_LOCAL)) == SHUN_LOCAL));

  Debug((DEBUG_DEBUG, "shun_add(\"%s\", \"%s\", \"%s\", \"%s\", %Tu, %Tu "
	 "%Tu, 0x%04x)", cli_name(cptr), cli_name(sptr), userhost, reason,
	 expire, lastmod, lifetime, flags));

  if (*userhost == '$') {
    switch (userhost[1]) {
      case 'R': flags |= SHUN_REALNAME; break;
      case 'V': flags |= SHUN_VERSION; break;
      default:
        /* uh, what to do here? */
        /* The answer, my dear Watson, is we throw a protocol_violation()
           -- hikari */
        if (IsServer(cptr))
          return protocol_violation(sptr,"%s has been smoking the sweet leaf and sent me a whacky shun",cli_name(sptr));
        sendto_opmask_butone(NULL, SNO_GLINE, "%s has been smoking the sweet leaf and sent me a whacky shun", cli_name(sptr));
        return 0;
    }
    user = userhost;
    host = NULL;
    if (MyUser(sptr) || (IsUser(sptr) && flags & SHUN_LOCAL)) {
      if (flags & SHUN_VERSION)
        tmp = count_versions(userhost + 2);
      else
        tmp = count_realnames(userhost + 2);
      if ((tmp >= feature_int(FEAT_SHUNMAXUSERCOUNT))
	  && !(flags & SHUN_OPERFORCE))
	return send_reply(sptr, ERR_TOOMANYUSERS, tmp);
    }
  } else {
    canon_userhost(userhost, &user, &host, "*");
    if (sizeof(uhmask) <
	ircd_snprintf(0, uhmask, sizeof(uhmask), "%s@%s", user, host))
      return send_reply(sptr, ERR_LONGMASK);
    else if (MyUser(sptr) || (IsUser(sptr) && flags & SHUN_LOCAL)) {
      switch (shun_checkmask(host)) {
      case CHECK_OVERRIDABLE: /* oper overrided restriction */
	if (flags & SHUN_OPERFORCE)
	  break;
	/*FALLTHROUGH*/
      case CHECK_REJECTED:
	return send_reply(sptr, ERR_MASKTOOWIDE, uhmask);
	break;
      }

      if ((tmp = count_users(uhmask, flags)) >=
	  feature_int(FEAT_SHUNMAXUSERCOUNT) && !(flags & SHUN_OPERFORCE))
	return send_reply(sptr, ERR_TOOMANYUSERS, tmp);
    }
  }

  /*
   * You cannot set a negative (or zero) expire time, nor can you set an
   * expiration time for greater than SHUN_MAX_EXPIRE.
   */
  if (!(flags & SHUN_FORCE) &&
      (expire <= TStime() || expire > TStime() + SHUN_MAX_EXPIRE)) {
    if (!IsServer(sptr) && MyConnect(sptr))
      send_reply(sptr, ERR_BADEXPIRE, expire);
    return 0;
  } else if (expire <= TStime()) {
    /* This expired Shun was forced to be added, so mark it inactive. */
    flags &= ~SHUN_ACTIVE;
  }

  if (!lifetime) /* no lifetime set, use expiration time */
    lifetime = expire;

  /* lifetime is already an absolute timestamp */

  /* Inform ops... */
  sendto_opmask_butone(0, ircd_strncmp(reason, "AUTO", 4) ? SNO_GLINE :
                       SNO_AUTO, "%s adding %s%s SHUN for %s%s%s, expiring at "
                       "%Tu: %s",
                       (feature_bool(FEAT_HIS_SNOTICES) || IsServer(sptr)) ?
                         cli_name(sptr) :
                         cli_name((cli_user(sptr))->server),
                       (flags & SHUN_ACTIVE) ? "" : "deactivated ",
		       (flags & SHUN_LOCAL) ? "local" : "global", user,
		       (flags & (SHUN_REALNAME|SHUN_VERSION)) ? "" : "@",
		       (flags & (SHUN_REALNAME|SHUN_VERSION)) ? "" : host,
		       expire, reason);

  /* and log it */
  log_write(LS_GLINE, L_INFO, LOG_NOSNOTICE,
	    "%#C adding %s SHUN for %s%s%s, expiring at %Tu: %s", sptr,
	    flags & SHUN_LOCAL ? "local" : "global", user,
	    flags & (SHUN_REALNAME|SHUN_VERSION) ? "" : "@",
	    flags & (SHUN_REALNAME|SHUN_VERSION) ? "" : host,
	    expire, reason);

  /* make the shun */
  ashun = make_shun(user, host, reason, expire, lastmod, lifetime, flags);

  /* since we've disabled overlapped Shun checking, ashun should
   * never be NULL...
   */
  assert(ashun);

  shun_propagate(cptr, sptr, ashun);

  return do_shun(cptr, sptr, ashun); /* knock off users if necessary */
}

/** Activate a currently inactive Shun.
 * @param[in] cptr Peer that told us to activate the Shun.
 * @param[in] sptr Client that originally thought it was a good idea.
 * @param[in] shun Shun to activate.
 * @param[in] lastmod New value for last modification timestamp.
 * @param[in] flags 0 if the activation should be propagated, SHUN_LOCAL if not.
 * @return Zero, unless \a sptr had a death wish (in which case CPTR_KILLED).
 */
int
shun_activate(struct Client *cptr, struct Client *sptr, struct Shun *shun,
	       time_t lastmod, unsigned int flags)
{
  unsigned int saveflags = 0;

  assert(0 != shun);

  saveflags = shun->sh_flags;

  if (flags & SHUN_LOCAL)
    shun->sh_flags &= ~SHUN_LDEACT;
  else {
    shun->sh_flags |= SHUN_ACTIVE;

    if (shun->sh_lastmod) {
      if (shun->sh_lastmod >= lastmod) /* force lastmod to increase */
	shun->sh_lastmod++;
      else
	shun->sh_lastmod = lastmod;
    }
  }

  if ((saveflags & SHUN_ACTMASK) == SHUN_ACTIVE)
    return 0; /* was active to begin with */

  /* Inform ops and log it */
  sendto_opmask_butone(0, SNO_GLINE, "%s activating global SHUN for %s%s%s, "
                       "expiring at %Tu: %s",
                       (feature_bool(FEAT_HIS_SNOTICES) || IsServer(sptr)) ?
                         cli_name(sptr) :
                         cli_name((cli_user(sptr))->server),
                       shun->sh_user, shun->sh_host ? "@" : "",
                       shun->sh_host ? shun->sh_host : "",
                       shun->sh_expire, shun->sh_reason);

  log_write(LS_GLINE, L_INFO, LOG_NOSNOTICE,
	    "%#C activating global SHUN for %s%s%s, expiring at %Tu: %s", sptr,
	    shun->sh_user,
	    shun->sh_host ? "@" : "",
	    shun->sh_host ? shun->sh_host : "",
	    shun->sh_expire, shun->sh_reason);

  if (!(flags & SHUN_LOCAL)) /* don't propagate local changes */
    shun_propagate(cptr, sptr, shun);

  return do_shun(cptr, sptr, shun);
}

/** Deactivate a Shun.
 * @param[in] cptr Peer that gave us the message.
 * @param[in] sptr Client that initiated the deactivation.
 * @param[in] shun Shun to deactivate.
 * @param[in] lastmod New value for Shun last modification timestamp.
 * @param[in] flags SHUN_LOCAL to only deactivate locally, 0 to propagate.
 * @return Zero.
 */
int
shun_deactivate(struct Client *cptr, struct Client *sptr, struct Shun *shun,
		 time_t lastmod, unsigned int flags)
{
  unsigned int saveflags = 0;
  char *msg;

  assert(0 != shun);

  saveflags = shun->sh_flags;

  if (ShunIsLocal(shun))
    msg = "removing local";
  else if (!shun->sh_lastmod && !(flags & SHUN_LOCAL)) {
    msg = "removing global";
    shun->sh_flags &= ~SHUN_ACTIVE; /* propagate a -<mask> */
  } else {
    msg = "deactivating global";

    if (flags & SHUN_LOCAL)
      shun->sh_flags |= SHUN_LDEACT;
    else {
      shun->sh_flags &= ~SHUN_ACTIVE;

      if (shun->sh_lastmod) {
	if (shun->sh_lastmod >= lastmod)
	  shun->sh_lastmod++;
	else
	  shun->sh_lastmod = lastmod;
      }
    }

    if ((saveflags & SHUN_ACTMASK) != SHUN_ACTIVE)
      return 0; /* was inactive to begin with */
  }

  /* Inform ops and log it */
  sendto_opmask_butone(0, SNO_GLINE, "%s %s SHUN for %s%s%s, expiring at %Tu: "
		       "%s",
                       (feature_bool(FEAT_HIS_SNOTICES) || IsServer(sptr)) ?
                         cli_name(sptr) :
                         cli_name((cli_user(sptr))->server), msg,
		       shun->sh_user, shun->sh_host ? "@" : "",
                       shun->sh_host ? shun->sh_host : "",
		       shun->sh_expire, shun->sh_reason);

  log_write(LS_GLINE, L_INFO, LOG_NOSNOTICE,
	    "%#C %s SHUN for %s%s%s, expiring at %Tu: %s", sptr, msg,
	    shun->sh_user,
	    shun->sh_host ? "@" : "",
	    shun->sh_host ? shun->sh_host : "",
	    shun->sh_expire, shun->sh_reason);

  if (!(flags & SHUN_LOCAL)) /* don't propagate local changes */
    shun_propagate(cptr, sptr, shun);

  /* if it's a local shun or a Uworld shun (and not locally deactivated).. */
  if (ShunIsLocal(shun) || (!shun->sh_lastmod && !(flags & SHUN_LOCAL)))
    shun_free(shun); /* get rid of it */

  return 0;
}

/** Modify a global Shun.
 * @param[in] cptr Client that sent us the Shun modification.
 * @param[in] sptr Client that originated the Shun modification.
 * @param[in] shun Shun being modified.
 * @param[in] action Resultant status of the Shun.
 * @param[in] reason Reason for Shun.
 * @param[in] expire Expiration time of Shun.
 * @param[in] lastmod Last modification time of Shun.
 * @param[in] lifetime Lifetime of Shun.
 * @param[in] flags Bitwise combination of SHUN_* flags.
 * @return Zero or CPTR_KILLED, depending on whether \a sptr is suicidal.
 */
int
shun_modify(struct Client *cptr, struct Client *sptr, struct Shun *shun,
	     enum ShunAction action, char *reason, time_t expire,
	     time_t lastmod, time_t lifetime, unsigned int flags)
{
  char buf[BUFSIZE], *op = "";
  int pos = 0;

  assert(shun);
  assert(!ShunIsLocal(shun));

  Debug((DEBUG_DEBUG,  "shun_modify(\"%s\", \"%s\", \"%s%s%s\", %s, \"%s\", "
	 "%Tu, %Tu, %Tu, 0x%04x)", cli_name(cptr), cli_name(sptr),
	 shun->sh_user, shun->sh_host ? "@" : "",
	 shun->sh_host ? shun->sh_host : "",
	 action == SHUN_ACTIVATE ? "SHUN_ACTIVATE" :
	 (action == SHUN_DEACTIVATE ? "SHUN_DEACTIVATE" :
	  (action == SHUN_LOCAL_ACTIVATE ? "SHUN_LOCAL_ACTIVATE" :
	   (action == SHUN_LOCAL_DEACTIVATE ? "SHUN_LOCAL_DEACTIVATE" :
	    (action == SHUN_MODIFY ? "SHUN_MODIFY" : "<UNKNOWN>")))),
	 reason, expire, lastmod, lifetime, flags));

  /* First, let's check lastmod... */
  if (action != SHUN_LOCAL_ACTIVATE && action != SHUN_LOCAL_DEACTIVATE) {
    if (ShunLastMod(shun) > lastmod) { /* we have a more recent version */
      if (IsBurstOrBurstAck(cptr))
	return 0; /* middle of a burst, it'll resync on its own */
      return shun_resend(cptr, shun); /* resync the server */
    } else if (ShunLastMod(shun) == lastmod)
      return 0; /* we have that version of the Shun... */
  }

  /* All right, we know that there's a change of some sort.  What is it? */
  /* first, check out the expiration time... */
  if ((flags & SHUN_EXPIRE) && expire) {
    if (!(flags & SHUN_FORCE) &&
	(expire <= TStime() || expire > TStime() + SHUN_MAX_EXPIRE)) {
      if (!IsServer(sptr) && MyConnect(sptr)) /* bad expiration time */
	send_reply(sptr, ERR_BADEXPIRE, expire);
      return 0;
    }
  } else
    flags &= ~SHUN_EXPIRE;

  /* Now check to see if there's any change... */
  if ((flags & SHUN_EXPIRE) && expire == shun->sh_expire) {
    flags &= ~SHUN_EXPIRE; /* no change to expiration time... */
    expire = 0;
  }

  /* Next, check out lifetime--this one's a bit trickier... */
  if (!(flags & SHUN_LIFETIME) || !lifetime)
    lifetime = shun->sh_lifetime; /* use Shun lifetime */

  lifetime = IRCD_MAX(lifetime, expire); /* set lifetime to the max */

  /* OK, let's see which is greater... */
  if (lifetime > shun->sh_lifetime)
    flags |= SHUN_LIFETIME; /* have to update lifetime */
  else {
    flags &= ~SHUN_LIFETIME; /* no change to lifetime */
    lifetime = 0;
  }

  /* Finally, let's see if the reason needs to be updated */
  if ((flags & SHUN_REASON) && reason &&
      !ircd_strcmp(shun->sh_reason, reason))
    flags &= ~SHUN_REASON; /* no changes to the reason */

  /* OK, now let's take a look at the action... */
  if ((action == SHUN_ACTIVATE && (shun->sh_flags & SHUN_ACTIVE)) ||
      (action == SHUN_DEACTIVATE && !(shun->sh_flags & SHUN_ACTIVE)) ||
      (action == SHUN_LOCAL_ACTIVATE &&
       (shun->sh_state == SLOCAL_ACTIVATED)) ||
      (action == SHUN_LOCAL_DEACTIVATE &&
       (shun->sh_state == SLOCAL_DEACTIVATED)) ||
      /* can't activate an expired Shun */
      IRCD_MAX(shun->sh_expire, expire) <= TStime())
    action = SHUN_MODIFY; /* no activity state modifications */

  Debug((DEBUG_DEBUG,  "About to perform changes; flags 0x%04x, action %s",
	 flags, action == SHUN_ACTIVATE ? "SHUN_ACTIVATE" :
	 (action == SHUN_DEACTIVATE ? "SHUN_DEACTIVATE" :
	  (action == SHUN_LOCAL_ACTIVATE ? "SHUN_LOCAL_ACTIVATE" :
	   (action == SHUN_LOCAL_DEACTIVATE ? "SHUN_LOCAL_DEACTIVATE" :
	    (action == SHUN_MODIFY ? "SHUN_MODIFY" : "<UNKNOWN>"))))));

  /* If there are no changes to perform, do no changes */
  if (!(flags & SHUN_UPDATE) && action == SHUN_MODIFY)
    return 0;

  /* Now we know what needs to be changed, so let's process the changes... */

  /* Start by updating lastmod, if indicated... */
  if (action != SHUN_LOCAL_ACTIVATE && action != SHUN_LOCAL_DEACTIVATE)
    shun->sh_lastmod = lastmod;

  /* Then move on to activity status changes... */
  switch (action) {
  case SHUN_ACTIVATE: /* Globally activating Shun */
    shun->sh_flags |= SHUN_ACTIVE; /* make it active... */
    shun->sh_state = SLOCAL_GLOBAL; /* reset local activity state */
    pos += ircd_snprintf(0, buf, sizeof(buf), " globally activating Shun");
    op = "+"; /* operation for Shun propagation */
    break;

  case SHUN_DEACTIVATE: /* Globally deactivating Shun */
    shun->sh_flags &= ~SHUN_ACTIVE; /* make it inactive... */
    shun->sh_state = SLOCAL_GLOBAL; /* reset local activity state */
    pos += ircd_snprintf(0, buf, sizeof(buf), " globally deactivating Shun");
    op = "-"; /* operation for Shun propagation */
    break;

  case SHUN_LOCAL_ACTIVATE: /* Locally activating Shun */
    shun->sh_state = SLOCAL_ACTIVATED; /* make it locally active */
    pos += ircd_snprintf(0, buf, sizeof(buf), " locally activating Shun");
    break;

  case SHUN_LOCAL_DEACTIVATE: /* Locally deactivating Shun */
    shun->sh_state = SLOCAL_DEACTIVATED; /* make it locally inactive */
    pos += ircd_snprintf(0, buf, sizeof(buf), " locally deactivating Shun");
    break;

  case SHUN_MODIFY: /* no change to activity status */
    break;
  }

  /* Handle expiration changes... */
  if (flags & SHUN_EXPIRE) {
    shun->sh_expire = expire; /* save new expiration time */
    if (pos < BUFSIZE)
      pos += ircd_snprintf(0, buf + pos, sizeof(buf) - pos,
			   "%s%s changing expiration time to %Tu",
			   pos ? ";" : "",
			   pos && !(flags & (SHUN_LIFETIME | SHUN_REASON)) ?
			   " and" : "", expire);
  }

  /* Next, handle lifetime changes... */
  if (flags & SHUN_LIFETIME) {
    shun->sh_lifetime = lifetime; /* save new lifetime */
    if (pos < BUFSIZE)
      pos += ircd_snprintf(0, buf + pos, sizeof(buf) - pos,
			   "%s%s extending record lifetime to %Tu",
			   pos ? ";" : "", pos && !(flags & SHUN_REASON) ?
			   " and" : "", lifetime);
  }

  /* Now, handle reason changes... */
  if (flags & SHUN_REASON) {
    MyFree(shun->sh_reason); /* release old reason */
    DupString(shun->sh_reason, reason); /* store new reason */
    if (pos < BUFSIZE)
      pos += ircd_snprintf(0, buf + pos, sizeof(buf) - pos,
			   "%s%s changing reason to \"%s\"",
			   pos ? ";" : "", pos ? " and" : "", reason);
  }

  /* All right, inform ops... */
  sendto_opmask_butone(0, SNO_GLINE, "%s modifying global SHUN for %s%s%s:%s",
		       (feature_bool(FEAT_HIS_SNOTICES) || IsServer(sptr)) ?
		       cli_name(sptr) : cli_name((cli_user(sptr))->server),
		       shun->sh_user, shun->sh_host ? "@" : "",
		       shun->sh_host ? shun->sh_host : "", buf);

  /* and log the change */
  log_write(LS_GLINE, L_INFO, LOG_NOSNOTICE,
	    "%#C modifying global SHUN for %s%s%s:%s", sptr,
	    shun->sh_user,
	    shun->sh_host ? "@" : "", shun->sh_host ? shun->sh_host : "",
	    buf);

  /* We'll be simple for this release, but we can update this to change
   * the propagation syntax on future updates
   */
  if (action != SHUN_LOCAL_ACTIVATE && action != SHUN_LOCAL_DEACTIVATE)
    sendcmdto_serv_butone(sptr, CMD_SHUN, cptr,
			  "* %s%s%s%s%s %Tu %Tu %Tu :%s",
			  flags & SHUN_OPERFORCE ? "!" : "", op,
			  shun->sh_user, shun->sh_host ? "@" : "",
			  shun->sh_host ? shun->sh_host : "",
			  shun->sh_expire - TStime(), shun->sh_lastmod,
			  shun->sh_lifetime, shun->sh_reason);

  /* OK, let's do the Shun... */
  return do_shun(cptr, sptr, shun);
}

/** Destroy a local Shun.
 * @param[in] cptr Peer that gave us the message.
 * @param[in] sptr Client that initiated the destruction.
 * @param[in] shun Shun to destroy.
 * @return Zero.
 */
int
shun_destroy(struct Client *cptr, struct Client *sptr, struct Shun *shun)
{
  assert(shun);
  assert(ShunIsLocal(shun));

  /* Inform ops and log it */
  sendto_opmask_butone(0, SNO_GLINE, "%s removing local SHUN for %s%s%s",
		       (feature_bool(FEAT_HIS_SNOTICES) || IsServer(sptr)) ?
		       cli_name(sptr) : cli_name((cli_user(sptr))->server),
		       shun->sh_user, shun->sh_host ? "@" : "",
		       shun->sh_host ? shun->sh_host : "");
  log_write(LS_GLINE, L_INFO, LOG_NOSNOTICE,
	    "%#C removing local SHUN for %s%s%s", sptr,
	    shun->sh_user,
	    shun->sh_host ? "@" : "", shun->sh_host ? shun->sh_host : "");

  shun_free(shun); /* get rid of the Shun */

  return 0; /* convenience return */
}

/** Find a Shun for a particular mask, guided by certain flags.
 * Certain bits in \a flags are interpreted specially:
 * <dl>
 * <dt>SHUN_ANY</dt><dd>Search user Shuns.</dd>
 * <dt>SHUN_GLOBAL</dt><dd>Only match global Shuns.</dd>
 * <dt>SHUN_LOCAL</dt><dd>Only match local Shuns.</dd>
 * <dt>SHUN_LASTMOD</dt><dd>Only match Shuns with a last modification time.</dd>
 * <dt>SHUN_EXACT</dt><dd>Require an exact match of Shun mask.</dd>
 * <dt>anything else</dt><dd>Search user Shuns.</dd>
 * </dl>
 * @param[in] userhost Mask to search for.
 * @param[in] flags Bitwise combination of SHUN_* flags.
 * @return First matching Shun, or NULL if none are found.
 */
struct Shun *
shun_find(char *userhost, unsigned int flags)
{
  struct Shun *shun = 0;
  struct Shun *sshun;
  char *user, *host, *t_uh;

  DupString(t_uh, userhost);
  canon_userhost(t_uh, &user, &host, "*");

  shiter(GlobalShunList, shun, sshun) {
    if ((flags & (ShunIsLocal(shun) ? SHUN_GLOBAL : SHUN_LOCAL)) ||
	(flags & SHUN_LASTMOD && !shun->sh_lastmod))
      continue;
    else if (flags & SHUN_EXACT) {
      if (((shun->sh_host && host && ircd_strcmp(shun->sh_host, host) == 0)
           || (!shun->sh_host && !host)) &&
          (ircd_strcmp(shun->sh_user, user) == 0))
	break;
    } else {
      if (((shun->sh_host && host && match(shun->sh_host, host) == 0)
           || (!shun->sh_host && !host)) &&
	  (match(shun->sh_user, user) == 0))
	break;
    }
  }

  MyFree(t_uh);

  return shun;
}

/** Find a matching Shun for a user.
 * @param[in] cptr Client to compare against.
 * @param[in] flags Bitwise combination of SHUN_GLOBAL and/or
 * SHUN_LASTMOD to limit matches.
 * @return Matching Shun, or NULL if none are found.
 */
struct Shun *
shun_lookup(struct Client *cptr, unsigned int flags)
{
  struct Shun *shun;
  struct Shun *sshun;

  if (find_except_conf(cptr, EFLAG_SHUN))
    return 0;

  shiter(GlobalShunList, shun, sshun) {
    if ((flags & SHUN_GLOBAL && shun->sh_flags & SHUN_LOCAL) ||
        (flags & SHUN_LASTMOD && !shun->sh_lastmod))
      continue;

    if (ShunIsRealName(shun)) {
      Debug((DEBUG_DEBUG,"realname shun: '%s' '%s'",shun->sh_user,cli_info(cptr)));
      if (match(shun->sh_user+2, cli_info(cptr)) != 0)
        continue;
    }
    else if (ShunIsVersion(shun)){
      Debug((DEBUG_DEBUG,"ctcp version shun: '%s' '%s'",shun->sh_user,cli_version(cptr)));
      if (EmptyString(cli_version(cptr)) || (match(shun->sh_user+2, cli_version(cptr)) != 0))
        continue;
    }
    else {
      if (match(shun->sh_user, (cli_user(cptr))->username) != 0)
        continue;

      if (ShunIsIpMask(shun)) {
        if (!irc_in_addr_type_cmp(&cli_ip(cptr), &shun->sh_addr))
          continue;
        if (!ipmask_check(&cli_ip(cptr), &shun->sh_addr, shun->sh_bits))
          continue;
      }
      else {
        if (match(shun->sh_host, (cli_user(cptr))->realhost) != 0)
          continue;
      }
    }
    if (ShunIsActive(shun))
      return shun;
  }
  /*
   * No Shuns matched
   */
  return 0;
}

/** Delink and free a Shun.
 * @param[in] shun Shun to free.
 */
void
shun_free(struct Shun *shun)
{
  assert(0 != shun);

  *shun->sh_prev_p = shun->sh_next; /* squeeze this shun out */
  if (shun->sh_next)
    shun->sh_next->sh_prev_p = shun->sh_prev_p;

  MyFree(shun->sh_user); /* free up the memory */
  if (shun->sh_host)
    MyFree(shun->sh_host);
  MyFree(shun->sh_reason);
  MyFree(shun);
}

/** Burst all known global Shuns to another server.
 * @param[in] cptr Destination of burst.
 */
void
shun_burst(struct Client *cptr)
{
  struct Shun *shun;
  struct Shun *sshun;

  shiter(GlobalShunList, shun, sshun) {
    if (!ShunIsLocal(shun) && shun->sh_lastmod)
      sendcmdto_one(&me, CMD_SHUN, cptr, "* %c%s%s%s %Tu %Tu %Tu :%s",
		    ShunIsRemActive(shun) ? '+' : '-', shun->sh_user,
                    shun->sh_host ? "@" : "",
                    shun->sh_host ? shun->sh_host : "",
		    shun->sh_expire - TStime(), shun->sh_lastmod,
                    shun->sh_lifetime, shun->sh_reason);
  }
}

/** Send a Shun to another server.
 * @param[in] cptr Who to inform of the Shun.
 * @param[in] shun Shun to send.
 * @return Zero.
 */
int
shun_resend(struct Client *cptr, struct Shun *shun)
{
  if (ShunIsLocal(shun) || !shun->sh_lastmod)
    return 0;

  sendcmdto_one(&me, CMD_SHUN, cptr, "* %c%s%s%s %Tu %Tu %Tu :%s",
		ShunIsRemActive(shun) ? '+' : '-', shun->sh_user,
		shun->sh_host ? "@" : "",
                shun->sh_host ? shun->sh_host : "",
		shun->sh_expire - TStime(), shun->sh_lastmod,
		shun->sh_lifetime, shun->sh_reason);

  return 0;
}

/** Display one or all Shuns to a user.
 * If \a userhost is not NULL, only send the first matching Shun.
 * Otherwise send the whole list.
 * @param[in] sptr User asking for Shun list.
 * @param[in] userhost Shun mask to search for (or NULL).
 * @return Zero.
 */
int
shun_list(struct Client *sptr, char *userhost)
{
  struct Shun *shun;
  struct Shun *sshun;

  if (userhost) {
    if (!(shun = shun_find(userhost, SHUN_ANY))) /* no such shun */
      return send_reply(sptr, ERR_NOSUCHSHUN, userhost);

    /* send shun information along */
    send_reply(sptr, RPL_GLIST, shun->sh_user,
               shun->sh_host ? "@" : "",
               shun->sh_host ? shun->sh_host : "",
	       shun->sh_expire, shun->sh_lastmod,
	       shun->sh_lifetime,
	       ShunIsLocal(shun) ? cli_name(&me) : "*",
	       shun->sh_state == SLOCAL_ACTIVATED ? ">" :
	       (shun->sh_state == SLOCAL_DEACTIVATED ? "<" : ""),
	       ShunIsRemActive(shun) ? '+' : '-', shun->sh_reason);
  } else {
    shiter(GlobalShunList, shun, sshun) {
      send_reply(sptr, RPL_GLIST, shun->sh_user,
		 shun->sh_host ? "@" : "",
		 shun->sh_host ? shun->sh_host : "",
		 shun->sh_expire, shun->sh_lastmod,
		 shun->sh_lifetime,
		 ShunIsLocal(shun) ? cli_name(&me) : "*",
		 shun->sh_state == SLOCAL_ACTIVATED ? ">" :
		 (shun->sh_state == SLOCAL_DEACTIVATED ? "<" : ""),
		 ShunIsRemActive(shun) ? '+' : '-', shun->sh_reason);
    }
  }

  /* end of shun information */
  return send_reply(sptr, RPL_ENDOFSLIST);
}

/** Statistics callback to list Shuns.
 * @param[in] sptr Client requesting statistics.
 * @param[in] sd Stats descriptor for request (ignored).
 * @param[in] param Extra parameter from user (ignored).
 */
void
shun_stats(struct Client *sptr, const struct StatDesc *sd,
            char *param)
{
  struct Shun *shun;
  struct Shun *sshun;

  shiter(GlobalShunList, shun, sshun) {
    send_reply(sptr, RPL_STATSSHUN, 'G', shun->sh_user,
	       shun->sh_host ? "@" : "",
	       shun->sh_host ? shun->sh_host : "",
	       shun->sh_expire, shun->sh_lastmod,
	       shun->sh_lifetime,
	       shun->sh_state == SLOCAL_ACTIVATED ? ">" :
	       (shun->sh_state == SLOCAL_DEACTIVATED ? "<" : ""),
	       ShunIsRemActive(shun) ? '+' : '-',
	       shun->sh_reason);
  }
}

/** Calculate memory used by Shuns.
 * @param[out] sh_size Number of bytes used by Shuns.
 * @return Number of Shuns in use.
 */
int
shun_memory_count(size_t *sh_size)
{
  struct Shun *shun;
  unsigned int gl = 0;

  for (shun = GlobalShunList; shun; shun = shun->sh_next) {
    gl++;
    *sh_size += sizeof(struct Shun);
    *sh_size += shun->sh_user ? (strlen(shun->sh_user) + 1) : 0;
    *sh_size += shun->sh_host ? (strlen(shun->sh_host) + 1) : 0;
    *sh_size += shun->sh_reason ? (strlen(shun->sh_reason) + 1) : 0;
  }

  return gl;
}

/** Check for and remove any expired shuns.
 */
void expire_shuns()
{
  struct Shun *shun;
  struct Shun *sshun;

  for (shun = GlobalShunList; shun; shun = sshun) { /* all shuns */
    sshun = shun->sh_next;

    if (shun->sh_expire <= CurrentTime) /* expire any that need expiring */
      shun_free(shun);
  }
}

