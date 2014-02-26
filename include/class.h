/*
 * IRC - Internet Relay Chat, include/class.h
 * Copyright (C) 1990 Darren Reed
 * Copyright (C) 1996 - 1997 Carlo Wood
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
 * @brief Declarations and interfaces for handling connection classes.
 * @version $Id: class.h 1511 2005-10-05 01:53:30Z entrope $
 */
#ifndef INCLUDED_class_h
#define INCLUDED_class_h
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>
#define INCLUDED_sys_types_h
#endif

#include "client.h"

struct ConfItem;
struct StatDesc;

/* Class restriction FlagSet */
enum ClassRestrictFlag {
  CRFLAG_JOIN,          /**< User cannot join channerls. */
  CRFLAG_PRIVMSG,       /**< User cannot send PRIVMSG/NOTICE to users not on common channels. */
  CRFLAG_UMODE,         /**< User cannot change his/her own user modes. */
  CRFLAG_LAST_FLAG
};

/** Declare flagset type for Class restriction flags. */
DECLARE_FLAGSET(ClassRestrictFlags, CRFLAG_LAST_FLAG);

/*
 * Structures
 */
/** Represents a connection class. */
struct ConnectionClass {
  struct ConnectionClass* next;           /**< Link to next connection class. */
  char                    *cc_name;       /**< Name of connection class. */
  char                    *default_umode; /**< Default usermode for users
                                             in this class. */
  char                    *autojoinchan;  /**< Auto join channel list. */
  char                    *autojoinnotice; /**< Auto join notice. */
  unsigned int            snomask;        /**< Default server notice mask. */
  struct Privs            privs;          /**< Privilege bits that are set on
                                             or off. */
  struct Privs            privs_dirty;    /**< Indication of which bits in
                                             ConnectionClass::privs are valid. */
  struct ClassRestrictFlags restrictflags; /**< Class restrictions applied to users. */
  unsigned int            max_sendq;      /**< Maximum client SendQ in bytes. */
  unsigned int            max_recvq;      /**< Maximum client RecvQ in bytes. */
  unsigned int            max_links;      /**< Maximum connections allowed. */
  unsigned int            max_chans;      /**< Maximum channels allowed to join. */
  unsigned int            ref_count;      /**< Number of references to class. */
  signed int              lag_min;        /**< Minimum number of seconds for fake lag. */
  signed int              lag_factor;     /**< Factor by which the message length is divided to add to fake lag. */
  unsigned short          ping_freq;      /**< Ping frequency for clients. */
  unsigned short          conn_freq;      /**< Auto-connect frequency. */
  unsigned char           valid;          /**< Valid flag (cleared after this
                                             class is removed from the config).*/
};

/*
 * Macro's
 */

/** Get class name for \a x. */
#define ConClass(x)     ((x)->cc_name)
/** Get ping frequency for \a x. */
#define PingFreq(x)     ((x)->ping_freq)
/** Get connection frequency for \a x. */
#define ConFreq(x)      ((x)->conn_freq)
/** Get maximum links allowed for \a x. */
#define MaxLinks(x)     ((x)->max_links)
/** Get maximum SendQ size for \a x. */
#define MaxSendq(x)     ((x)->max_sendq)
/** Get maximum RecvQ size for \a x. */
#define MaxRecvq(x)     ((x)->max_recvq)
/** Get maximum channel limit for \a x. */
#define MaxChans(x)    ((x)->max_chans)
/** Get number of references to \a x. */
#define Links(x)        ((x)->ref_count)
/** Get fake lag minimum for \a x. */
#define LagMin(x)       ((x)->lag_min)
/** Get fake lag factor for \a x. */
#define LagFactor(x)    ((x)->lag_factor)

/** Get class name for ConfItem \a x. */
#define ConfClass(x)    ((x)->conn_class->cc_name)
/** Get ping frequency for ConfItem \a x. */
#define ConfPingFreq(x) ((x)->conn_class->ping_freq)
/** Get connection frequency for ConfItem \a x. */
#define ConfConFreq(x)  ((x)->conn_class->conn_freq)
/** Get maximum links allowed for ConfItem \a x. */
#define ConfMaxLinks(x) ((x)->conn_class->max_links)
/** Get maximum SendQ size for ConfItem \a x. */
#define ConfSendq(x)    ((x)->conn_class->max_sendq)
/** Get maximum RecvQ size for ConfItem \a x. */
#define ConfRecvq(x)    ((x)->conn_class->max_recvq)
/** Get number of references to class in ConfItem \a x. */
#define ConfLinks(x)    ((x)->conn_class->ref_count)
/** Get default usermode for ConfItem \a x. */
#define ConfUmode(x)    ((x)->conn_class->default_umode)
/** Get default snomask for ConfItem \a x. */
#define ConfSnoMask(x)  ((x)->conn_class->snomask)
/** Get autojoin channel list for ConfItem \a x. */
#define ConfAjoinChan(x) ((x)->conn_class->autojoinchan)
/** Get autojoin channel notice for ConfItem \a x. */
#define ConfAjoinNotice(x) ((x)->conn_class->autojoinnotice)
/** Find a valid configuration class by name. */
#define find_class(name) do_find_class((name), 0)

/*
 * Proto types
 */

extern void init_class(void);

extern const struct ConnectionClass* get_class_list(void);
extern void class_mark_delete(void);
extern void class_delete_marked(void);

extern struct ConnectionClass *do_find_class(const char *name, int extras);
extern struct ConnectionClass *make_class(void);
extern void free_class(struct ConnectionClass * tmp);
extern char *get_conf_class(const struct ConfItem *aconf);
extern int get_conf_ping(const struct ConfItem *aconf);
extern char *get_client_class(struct Client *acptr);
extern struct ConnectionClass *get_client_class_conf(struct Client *acptr);
extern void add_class(char *name, unsigned int ping,
                      unsigned int confreq, unsigned int maxli,
                      unsigned int sendq, unsigned int recvq);
extern void report_classes(struct Client *sptr, const struct StatDesc *sd,
                           char *param);
extern unsigned int get_sendq(struct Client* cptr);
extern unsigned int get_recvq(struct Client *cptr);
extern int get_lag_min(struct Client *cptr);
extern int get_lag_factor(struct Client *cptr);
extern unsigned int get_client_maxchans(struct Client *acptr);

extern void class_send_meminfo(struct Client* cptr);
#endif /* INCLUDED_class_h */
