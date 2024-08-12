#ifndef INCLUDED_shun_h
#define INCLUDED_shun_h
/*
 * IRC - Internet Relay Chat, include/shun.h
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
 * Copyright (C) 1996 -1997 Carlo Wood
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
 * @brief Structures and APIs for Shun manipulation.
 * @version $Id: shun.h 1913 2009-07-04 22:46:00Z entrope $
 */
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>
#define INCLUDED_sys_types_h
#endif

#ifndef INCLUDED_res_h
#include "res.h"
#endif

struct Client;
struct StatDesc;

#define SHUN_MAX_EXPIRE 604800	/**< max expire: 7 days */

/** Local state of a Shun. */
enum ShunLocalState {
  SLOCAL_GLOBAL,		/**< Shun state unmodified locally. */
  SLOCAL_ACTIVATED,		/**< Shun state locally activated. */
  SLOCAL_DEACTIVATED		/**< Shun state locally deactivated. */
};

/** Description of a Shun. */
struct Shun {
  struct Shun  *sh_next;	/**< Next Shun in linked list. */
  struct Shun **sh_prev_p;	/**< Previous pointer to this Shun. */
  char	       *sh_user;	/**< Username mask (or channel/realname mask). */
  char	       *sh_host;	/**< Host portion of mask. */
  char	       *sh_reason;	/**< Reason for Shun. */
  time_t	sh_expire;	/**< Expiration timestamp. */
  time_t	sh_lastmod;	/**< Last modification timestamp. */
  time_t	sh_lifetime;	/**< Record expiration timestamp. */
  struct irc_in_addr sh_addr;	/**< IP address (for IP-based Shuns). */
  unsigned char sh_bits;	/**< Bits in sh_addr used in the mask. */
  unsigned int	sh_flags;	/**< Shun status flags. */
  enum ShunLocalState sh_state;	/**< Shun local state. */
};

/** Action to perform on a Shun. */
enum ShunAction {
  SHUN_ACTIVATE,		/**< Shun should be activated. */
  SHUN_DEACTIVATE,		/**< Shun should be deactivated. */
  SHUN_LOCAL_ACTIVATE,		/**< Shun should be locally activated. */
  SHUN_LOCAL_DEACTIVATE,	/**< Shun should be locally deactivated. */
  SHUN_MODIFY			/**< Shun should be modified. */
};

#define SHUN_ACTIVE	0x00001 /**< Shun is active. */
#define SHUN_IPMASK	0x00002 /**< sh_addr and sh_bits fields are valid. */
#define SHUN_LOCAL	0x00008 /**< Shun only applies to this server. */
#define SHUN_ANY	0x00010 /**< Search flag: Find any Shun. */
#define SHUN_FORCE	0x00020 /**< Override normal limits on Shuns. */
#define SHUN_EXACT	0x00040 /**< Exact match only (no wildcards). */
#define SHUN_LDEACT	0x00080	/**< Locally deactivated. */
#define SHUN_GLOBAL	0x00100	/**< Find only global Shuns. */
#define SHUN_LASTMOD	0x00200	/**< Find only Shuns with non-zero lastmod. */
#define SHUN_OPERFORCE	0x00400	/**< Oper forcing Shun to be set. */
#define SHUN_REALNAME	0x00800 /**< Shun matches only the realname field. */
#define SHUN_VERSION	0x00004 /**< Shun matches only the CTCP version. */

#define SHUN_EXPIRE	0x01000	/**< Expiration time update */
#define SHUN_LIFETIME	0x02000	/**< Record lifetime update */
#define SHUN_REASON	0x04000	/**< Reason update */

/** Controllable flags that can be set on an actual Shun. */
#define SHUN_MASK	(SHUN_ACTIVE | SHUN_LOCAL | SHUN_REALNAME | SHUN_VERSION)
/** Mask for Shun activity flags. */
#define SHUN_ACTMASK	(SHUN_ACTIVE | SHUN_LDEACT)

/** Mask for Shun update flags. */
#define SHUN_UPDATE	(SHUN_EXPIRE | SHUN_LIFETIME | SHUN_REASON)

/** Test whether \a s is active. */
#define ShunIsActive(s)		((((s)->sh_flags & SHUN_ACTIVE) &&	  \
				  (s)->sh_state != SLOCAL_DEACTIVATED) || \
				 (s)->sh_state == SLOCAL_ACTIVATED)
/** Test whether \a s is remotely (globally) active. */
#define ShunIsRemActive(s)	((s)->sh_flags & SHUN_ACTIVE)
/** Test whether \a s is an IP-based Shun. */
#define ShunIsIpMask(s)		((s)->sh_flags & SHUN_IPMASK)
/** Test whether \a s is a realname-based Shun. */
#define ShunIsRealName(s)      ((s)->sh_flags & SHUN_REALNAME)
/** Test whether \a s is a CTCP version-based Shun. */
#define ShunIsVersion(s)       ((s)->sh_flags & SHUN_VERSION)
/** Test whether \a s is local to this server. */
#define ShunIsLocal(s)		((s)->sh_flags & SHUN_LOCAL)

/** Return user mask of a Shun. */
#define ShunUser(s)		((s)->sh_user)
/** Return host mask of a Shun. */
#define ShunHost(s)		((s)->sh_host)
/** Return reason/message of a Shun. */
#define ShunReason(s)		((s)->sh_reason)
/** Return last modification time of a Shun. */
#define ShunLastMod(s)		((s)->sh_lastmod)

extern int shun_add(struct Client *cptr, struct Client *sptr, char *userhost,
		     char *reason, time_t expire, time_t lastmod,
		     time_t lifetime, unsigned int flags);
extern int shun_activate(struct Client *cptr, struct Client *sptr,
			  struct Shun *shun, time_t lastmod,
			  unsigned int flags);
extern int shun_deactivate(struct Client *cptr, struct Client *sptr,
			    struct Shun *shun, time_t lastmod,
			    unsigned int flags);
extern int shun_modify(struct Client *cptr, struct Client *sptr,
			struct Shun *shun, enum ShunAction action,
			char *reason, time_t expire, time_t lastmod,
			time_t lifetime, unsigned int flags);
extern int shun_destroy(struct Client *cptr, struct Client *sptr,
			 struct Shun *shun);
extern struct Shun *shun_find(char *userhost, unsigned int flags);
extern struct Shun *shun_lookup(struct Client *cptr, unsigned int flags);
extern void shun_free(struct Shun *shun);
extern void shun_burst(struct Client *cptr);
extern int shun_resend(struct Client *cptr, struct Shun *shun);
extern int shun_list(struct Client *sptr, char *userhost);
extern void shun_stats(struct Client *sptr, const struct StatDesc *sd,
                        char *param);
extern int shun_memory_count(size_t *sh_size);
extern int shun_remove(struct Client* sptr, char *userhost, char *reason);

extern void expire_shuns(void);

#endif /* INCLUDED_shun_h */
