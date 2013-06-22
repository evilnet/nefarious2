#ifndef INCLUDED_zline_h
#define INCLUDED_zline_h
/*
 * IRC - Internet Relay Chat, include/zline.h
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
 * @brief Structures and APIs for Z-line manipulation.
 * @version $Id: zline.h 1913 2009-07-04 22:46:00Z entrope $
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

#define ZLINE_MAX_EXPIRE 604800	/**< max expire: 7 days */

/** Local state of a Z-line. */
enum ZlineLocalState {
  ZLOCAL_GLOBAL,		/**< Z-line state unmodified locally. */
  ZLOCAL_ACTIVATED,		/**< Z-line state locally activated. */
  ZLOCAL_DEACTIVATED		/**< Z-line state locally deactivated. */
};

/** Description of a Z-line. */
struct Zline {
  struct Zline *zl_next;	/**< Next Z-line in linked list. */
  struct Zline**zl_prev_p;	/**< Previous pointer to this Z-line. */
  char	       *zl_mask;	/**< Mask. */
  char         *zl_reason;      /**< Reason for Z-line. */
  time_t	zl_expire;	/**< Expiration timestamp. */
  time_t	zl_lastmod;	/**< Last modification timestamp. */
  time_t	zl_lifetime;	/**< Record expiration timestamp. */
  struct irc_in_addr zl_addr;	/**< IP address (for IP-based Z-lines). */
  unsigned char zl_bits;	/**< Bits in zl_addr used in the mask. */
  unsigned int	zl_flags;	/**< Z-line status flags. */
  enum ZlineLocalState zl_state;/**< Z-line local state. */
};

/** Action to perform on a Z-line. */
enum ZlineAction {
  ZLINE_ACTIVATE,		/**< Z-line should be activated. */
  ZLINE_DEACTIVATE,		/**< Z-line should be deactivated. */
  ZLINE_LOCAL_ACTIVATE,		/**< Z-line should be locally activated. */
  ZLINE_LOCAL_DEACTIVATE,	/**< Z-line should be locally deactivated. */
  ZLINE_MODIFY			/**< Z-line should be modified. */
};

#define ZLINE_ACTIVE	0x00001 /**< Z-line is active. */
#define ZLINE_IPMASK	0x00002 /**< zl_addr and zl_bits fields are valid. */
#define ZLINE_LOCAL	0x00008 /**< Z-line only applies to this server. */
#define ZLINE_ANY	0x00010 /**< Search flag: Find any Z-line. */
#define ZLINE_FORCE	0x00020 /**< Override normal limits on Z-lines. */
#define ZLINE_EXACT	0x00040 /**< Exact match only (no wildcards). */
#define ZLINE_LDEACT	0x00080	/**< Locally deactivated. */
#define ZLINE_GLOBAL	0x00100	/**< Find only global Z-lines. */
#define ZLINE_LASTMOD	0x00200	/**< Find only Z-lines with non-zero lastmod. */
#define ZLINE_OPERFORCE	0x00400	/**< Oper forcing Z-line to be set. */

#define ZLINE_EXPIRE	0x01000	/**< Expiration time update */
#define ZLINE_LIFETIME	0x02000	/**< Record lifetime update */
#define ZLINE_REASON	0x04000	/**< Reason update */

/** Controllable flags that can be set on an actual Z-line. */
#define ZLINE_MASK	(ZLINE_ACTIVE | ZLINE_LOCAL)
/** Mask for Z-line activity flags. */
#define ZLINE_ACTMASK	(ZLINE_ACTIVE | ZLINE_LDEACT)

/** Mask for Z-line update flags. */
#define ZLINE_UPDATE	(ZLINE_EXPIRE | ZLINE_LIFETIME | ZLINE_REASON)

/** Test whether \a z is active. */
#define ZlineIsActive(z)	((((z)->zl_flags & ZLINE_ACTIVE) &&	  \
				  (z)->zl_state != ZLOCAL_DEACTIVATED) || \
				 (z)->zl_state == ZLOCAL_ACTIVATED)
/** Test whether \a z is remotely (globally) active. */
#define ZlineIsRemActive(z)	((z)->zl_flags & ZLINE_ACTIVE)
/** Test whether \a z is an IP-based Z-line. */
#define ZlineIsIpMask(z)	((z)->zl_flags & ZLINE_IPMASK)
/** Test whether \a z is local to this server. */
#define ZlineIsLocal(z)		((z)->zl_flags & ZLINE_LOCAL)

/** Return mask of a Z-line. */
#define ZlineMask(z)		((z)->zl_mask)
/** Return reason/message of a Z-line. */
#define ZlineReason(z)		((z)->zl_reason)
/** Return last modification time of a Z-line. */
#define ZlineLastMod(z)		((z)->zl_lastmod)

extern int zline_add(struct Client *cptr, struct Client *sptr, char *ipmask,
		     char *reason, time_t expire, time_t lastmod,
		     time_t lifetime, unsigned int flags);
extern int zline_activate(struct Client *cptr, struct Client *sptr,
			  struct Zline *zline, time_t lastmod,
			  unsigned int flags);
extern int zline_deactivate(struct Client *cptr, struct Client *sptr,
			    struct Zline *zline, time_t lastmod,
			    unsigned int flags);
extern int zline_modify(struct Client *cptr, struct Client *sptr,
			struct Zline *zline, enum ZlineAction action,
			char *reason, time_t expire, time_t lastmod,
			time_t lifetime, unsigned int flags);
extern int zline_destroy(struct Client *cptr, struct Client *sptr,
			 struct Zline *zline);
extern struct Zline *zline_find(char *ipmask, unsigned int flags);
extern struct Zline *zline_lookup(struct Client *cptr, unsigned int flags);
extern void zline_free(struct Zline *zline);
extern void zline_burst(struct Client *cptr);
extern int zline_resend(struct Client *cptr, struct Zline *zline);
extern int zline_list(struct Client *sptr, char *ipmask);
extern void zline_stats(struct Client *sptr, const struct StatDesc *sd,
                        char *param);
extern int zline_memory_count(size_t *zl_size);
extern int zline_remove(struct Client* sptr, char *ipmask, char *reason);

#endif /* INCLUDED_zline_h */
