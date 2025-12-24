/*
 * IRC - Internet Relay Chat, include/client.h
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
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
 * @brief Structures and functions for handling local clients.
 * @version $Id: client.h 1907 2009-02-09 04:11:04Z entrope $
 */
#ifndef INCLUDED_client_h
#define INCLUDED_client_h
#ifndef INCLUDED_ircd_defs_h
#include "ircd_defs.h"
#endif
#ifndef INCLUDED_dbuf_h
#include "dbuf.h"
#endif
#ifndef INCLUDED_msgq_h
#include "msgq.h"
#endif
#ifndef INCLUDED_ircd_events_h
#include "ircd_events.h"
#endif
#ifndef INCLUDED_ircd_handler_h
#include "ircd_handler.h"
#endif
#ifndef INCLUDED_res_h
#include "res.h"
#endif
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>          /* time_t, size_t */
#define INCLUDED_sys_types_h
#endif
#ifdef USE_SSL
#ifndef INCLUDED_ssl_h
#include "ssl.h"
#endif
#endif /* USE_SSL */

struct ConfItem;
struct Listener;
struct ListingArgs;
struct SLink;
struct Server;
struct User;
struct Whowas;
struct hostent;
struct Privs;
struct AuthRequest;

/*
 * Structures
 *
 * Only put structures here that are being used in a very large number of
 * source files. Other structures go in the header file of there corresponding
 * source file, or in the source file itself (when only used in that file).
 */

/** Single element in a flag bitset array. */
typedef unsigned long flagpage_t;

/** Number of bits in a flagpage_t. */
#ifndef FLAGSET_NBITS
#define FLAGSET_NBITS (8 * sizeof(flagpage_t))
#endif
/** Element number for flag \a flag. */
#ifndef FLAGSET_INDEX
#define FLAGSET_INDEX(flag) ((flag) / FLAGSET_NBITS)
#endif
/** Element bit for flag \a flag. */
#ifndef FLAGSET_MASK
#define FLAGSET_MASK(flag) (1ul<<((flag) % FLAGSET_NBITS))
#endif

/** Declare a flagset structure of a particular size. */
#ifndef DECLARE_FLAGSET
#define DECLARE_FLAGSET(name,max) \
  struct name \
  { \
    unsigned long bits[((max + FLAGSET_NBITS - 1) / FLAGSET_NBITS)]; \
  }
#endif

/** Test whether a flag is set in a flagset. */
#ifndef FlagHas
#define FlagHas(set,flag) ((set)->bits[FLAGSET_INDEX(flag)] & FLAGSET_MASK(flag))
#endif
/** Set a flag in a flagset. */
#ifndef FlagSet
#define FlagSet(set,flag) ((set)->bits[FLAGSET_INDEX(flag)] |= FLAGSET_MASK(flag))
#endif
/** Clear a flag in a flagset. */
#ifndef FlagClr
#define FlagClr(set,flag) ((set)->bits[FLAGSET_INDEX(flag)] &= ~FLAGSET_MASK(flag))
#endif

/** String containing valid user modes, in no particular order. */
#define infousermodes "adgiknoqswxzBDHLNORWX"

/** Operator privileges. */
enum Priv
  {
    PRIV_CHAN_LIMIT, /**< no channel limit on oper */
    PRIV_MODE_LCHAN, /**< oper can mode local chans */
    PRIV_WALK_LCHAN, /**< oper can walk through local modes */
    PRIV_DEOP_LCHAN, /**< no deop oper on local chans */
    PRIV_SHOW_INVIS, /**< show local invisible users */
    PRIV_SHOW_ALL_INVIS, /**< show all invisible users */
    PRIV_UNLIMIT_QUERY, /**< unlimit who queries */
    PRIV_KILL, /**< oper can KILL */
    PRIV_LOCAL_KILL, /**< oper can local KILL */
    PRIV_REHASH, /**< oper can REHASH */
    PRIV_RESTART, /**< oper can RESTART */
    PRIV_DIE, /**< oper can DIE */
    PRIV_GLINE, /**< oper can GLINE */
    PRIV_LOCAL_GLINE, /**< oper can local GLINE */
    PRIV_JUPE, /**< oper can JUPE */
    PRIV_LOCAL_JUPE, /**< oper can local JUPE */
    PRIV_OPMODE, /**< oper can OP/CLEARMODE */
    PRIV_LOCAL_OPMODE, /**< oper can local OP/CLEARMODE */
    PRIV_SET,  /**< oper can SET */
    PRIV_WHOX, /**< oper can use /who x */
    PRIV_BADCHAN, /**< oper can BADCHAN */
    PRIV_LOCAL_BADCHAN, /**< oper can local BADCHAN */
    PRIV_SEE_CHAN, /**< oper can see in secret chans */
    PRIV_PROPAGATE, /**< propagate oper status */
    PRIV_DISPLAY, /**< "Is an oper" displayed */
    PRIV_SEE_OPERS, /**< display hidden opers */
    PRIV_WIDE_GLINE, /**< oper can set wider G-lines */
    PRIV_LIST_CHAN, /**< oper can list secret channels */
    PRIV_FORCE_OPMODE, /**< can hack modes on quarantined channels */
    PRIV_FORCE_LOCAL_OPMODE, /**< can hack modes on quarantined local channels */
    PRIV_APASS_OPMODE, /**< can hack modes +A/-A/+U/-U */
    PRIV_CHECK, /**< can use /CHECK */
    PRIV_WHOIS_NOTICE, /**< oper can set user mode +W */
    PRIV_HIDE_OPER, /**< oper can set user mode +H */
    PRIV_HIDE_CHANNELS, /**< oper can set user mode +n */
    PRIV_HIDE_IDLE, /**< oper can set user mode +I */
    PRIV_ADMIN, /**< oper is an admin (gets, can set and unset mode +a) */
    PRIV_XTRAOP, /**< oper can set/unset user mode +X */
    PRIV_SERVICE, /**< oper can set/unset user mode +k */
    PRIV_REMOTE, /**< oper can OPER from another server */
    PRIV_SHUN, /**< oper can SHUN */
    PRIV_LOCAL_SHUN, /**< oper can local SHUN */
    PRIV_WIDE_SHUN, /**< oper can set wider Shuns */
    PRIV_FREEFORM, /**< oper can use SETHOST with custom host names */
    PRIV_REMOTEREHASH, /**< oper can REHASH remote servers */
    PRIV_REMOVE, /**< oper can REMOVE glines, zlines and shuns */
    PRIV_LOCAL_ZLINE, /**< oper can local ZLINE */
    PRIV_ZLINE, /**< oper can ZLINE */
    PRIV_WIDE_ZLINE, /**< oper can set wider Z-lines */
    PRIV_TEMPSHUN, /**< oper can use the TEMPSHUN command */
    PRIV_LAST_PRIV /**< number of privileges */
  };

/** Client flags and modes.
 * Note that flags at least FLAG_LOCAL_UMODES but less than
 * FLAG_GLOBAL_UMODES are treated as local modes, and flags at least
 * FLAG_GLOBAL_UMODES (but less than FLAG_LAST_FLAG) are treated as
 * global modes.
 */
enum Flag
  {
    FLAG_PINGSENT,                  /**< Unreplied ping sent */
    FLAG_DEADSOCKET,                /**< Local socket is dead--Exiting soon */
    FLAG_KILLED,                    /**< Prevents "QUIT" from being sent for this */
    FLAG_BLOCKED,                   /**< socket is in a blocked condition */
    FLAG_CLOSING,                   /**< set when closing to suppress errors */
    FLAG_UPING,                     /**< has active UDP ping request */
    FLAG_HUB,                       /**< server is a hub */
    FLAG_IPV6,                      /**< server understands P10 IPv6 addrs */
    FLAG_SERVICE,                   /**< server is a service */
    FLAG_OPLEVELS,                  /**< server has oplevels support */
    FLAG_GOTID,                     /**< successful ident lookup achieved */
    FLAG_DOID,                      /**< I-lines say must use ident return */
    FLAG_NONL,                      /**< No \n in buffer */
    FLAG_TS8,                       /**< Why do you want to know? */
    FLAG_MAP,                       /**< Show server on the map */
    FLAG_JUNCTION,                  /**< Junction causing the net.burst. */
    FLAG_BURST,                     /**< Server is receiving a net.burst */
    FLAG_BURST_ACK,                 /**< Server is waiting for eob ack */
    FLAG_IPCHECK,                   /**< Added or updated IPregistry data */
    FLAG_LOCOP,                     /**< Local operator -- SRB */
    FLAG_SERVNOTICE,                /**< server notices such as kill */
    FLAG_OPER,                      /**< Operator */
    FLAG_INVISIBLE,                 /**< makes user invisible */
    FLAG_WALLOP,                    /**< send wallops to them */
    FLAG_DEAF,                      /**< Makes user deaf */
    FLAG_CHSERV,                    /**< Disallow KICK or MODE -o on the user;
                                       don't display channels in /whois */
    FLAG_DEBUG,                     /**< send global debug/anti-hack info */
    FLAG_ACCOUNT,                   /**< account name has been set */
    FLAG_HIDDENHOST,                /**< user's host is hidden */

    FLAG_WHOIS_NOTICE,              /**< user can see WHOIS notices */
    FLAG_HIDE_OPER,                 /**< user's oper status is hidden */
    FLAG_NOCHAN,                    /**< user's channels are hidden in WHOIS */
    FLAG_NOIDLE,                    /**< user's idle time is hidden in WHOIS */
    FLAG_NAMESX,                    /**< Client supports extended NAMES replies */
    FLAG_UHNAMES,                   /**< Client supports user-host NAMES replies */
    FLAG_WEBIRC,                    /**< Client is a WEBIRC client */
    FLAG_WEBIRC_USERIDENT,          /**< Client should use USER username param as ident */
    FLAG_IPSPOOFED,                 /**< Client has had his IP/host changed */
    FLAG_ACCOUNTONLY,               /**< hide privmsgs/notices if user is
                                       not authed or opered */
    FLAG_PRIVDEAF,                  /**< Client is deaf to all private messages */
    FLAG_COMMONCHANSONLY,           /**< SNIRCD_q: hide privmsgs/notices if in no
                                         common channels (with +ok exceptions) */
    FLAG_BOT,                       /**< Bot */
    FLAG_GEOIP,                     /**< User has had GeoIP data applied */
    FLAG_ADMIN,                     /**< User is an admin (user mode +a) */
    FLAG_XTRAOP,                    /**< User has user mode +X (XtraOp) */
    FLAG_NOLINK,                    /**< Client will not automatically get redirected if +L is set on a chan */

    FLAG_CLOAKIP,                   /**< User has a cloaked IP (+c) */
    FLAG_CLOAKHOST,                 /**< User has a cloaked host (+C) */
    FLAG_FAKEHOST,                  /**< User has a fake host (+f) */
    FLAG_SETHOST,                   /**< User has a set host (+h) */
    FLAG_SSL,                       /**< User is connected via SSL (+z) */
    FLAG_STARTTLS,                  /**< User is connecting with StartTLS */
    FLAG_SSLNEEDACCEPT,             /**< Client needs SSL_accept() to be called again */

    FLAG_IPCEXEMPT,                 /**< User is IPcheck exempt */
    FLAG_IPCNOTEXEMPT,              /**< User is not IPcheck exempt */

    FLAG_SASLCOMPLETE,              /**< SASL Complete */

    FLAG_MARKED,                    /**< Client is marked */

    FLAG_RESTRICT_JOIN,             /**< Client is in a client class that has the restrict_join option */
    FLAG_RESTRICT_PRIVMSG,          /**< Client is in a client class that has the restrict_privmsg option */
    FLAG_RESTRICT_UMODE,            /**< Client is in a client class that has the restrict_umode option */

	FLAG_TEMPSHUN,					/**< Client has temporarily been shunned */

    FLAG_OPERED_LOCAL,              /**< Client /OPER'ed using a local O:Line */
    FLAG_OPERED_REMOTE,             /**< Client /OPER'ed using a remote O:Line */
    FLAG_SERVER_NOOP,               /**< Server has been NOOP'ed */
    FLAG_SENT_CVERSION,             /**< Client's CTCP VERSION reply has been sent out */

    FLAG_LAST_FLAG,                 /**< number of flags */
    FLAG_LOCAL_UMODES = FLAG_LOCOP, /**< First local mode flag */
    FLAG_GLOBAL_UMODES = FLAG_OPER  /**< First global mode flag */
  };

/** Declare flagset type for operator privileges. */
DECLARE_FLAGSET(Privs, PRIV_LAST_PRIV);
/** Declare flagset type for user flags. */
DECLARE_FLAGSET(Flags, FLAG_LAST_FLAG);

#include "capab.h" /* client capabilities */

/** Represents a local connection.
 * This contains a lot of stuff irrelevant to server connections, but
 * those are so rare as to not be worth special-casing.
 */
struct Connection
{
  unsigned long       con_magic;     /**< magic number */
  struct Connection*  con_next;      /**< Next connection with queued data */
  struct Connection** con_prev_p;    /**< What points to us */
  struct Client*      con_client;    /**< Client associated with connection */
  unsigned int        con_count;     /**< Amount of data in buffer */
  int                 con_freeflag;  /**< indicates if connection can be freed */
  int                 con_error;     /**< last socket level error for client */
  int                 con_sentalong; /**< sentalong marker for connection */
  unsigned int        con_snomask;   /**< mask for server messages */
  time_t              con_nextnick;  /**< Next time a nick change is allowed */
  time_t              con_nexttarget;/**< Next time a target change is allowed */
  time_t              con_lasttime;  /**< Last time data read from socket */
  time_t              con_since;     /**< Last time we accepted a command */
  struct MsgQ         con_sendQ;     /**< Outgoing message queue */
  struct DBuf         con_recvQ;     /**< Incoming data yet to be parsed */
  unsigned int        con_sendM;     /**< Stats: protocol messages sent */
  unsigned int        con_receiveM;  /**< Stats: protocol messages received */
  uint64_t            con_sendB;     /**< Bytes sent. */
  uint64_t            con_receiveB;  /**< Bytes received. */
  struct Listener*    con_listener;  /**< Listening socket which we accepted
                                        from. */
  struct SLink*       con_confs;     /**< Associated configuration records. */
  HandlerType         con_handler;   /**< Message index into command table
                                        for parsing. */
  struct ListingArgs* con_listing;   /**< Current LIST status. */
  unsigned int        con_max_sendq; /**< cached max send queue for client */
  unsigned int        con_max_recvq; /**< cached max recv queue for client */
  unsigned int        con_ping_freq; /**< cached ping freq */
  int                 con_lag_min;   /**< cached fake lag minimum */
  int                 con_lag_factor; /**< cached fake lag factor */
  unsigned short      con_lastsq;    /**< # 2k blocks when sendqueued
                                        called last. */
  unsigned short      con_port;       /**< and the remote port# too :-) */
  unsigned char       con_targets[MAXTARGETS]; /**< Hash values of
						  current targets. */
  char con_sock_ip[SOCKIPLEN + 1];   /**< Remote IP address as a string. */
  char con_sockhost[HOSTLEN + 1];    /**< This is the host name from
                                        the socket and after which the
                                        connection was accepted. */
  char con_passwd[PASSWDLEN + 1];    /**< Password given by user. */
  char con_buffer[BUFSIZE];          /**< Incoming message buffer; or
                                        the error that caused this
                                        clients socket to close. */
  char*               con_sslerror;  /**< SSL Error. */

  struct Socket       con_socket;    /**< socket descriptor for
                                      client */
  struct Timer        con_proc;      /**< process latent messages from
                                      client */
  struct CapSet       con_capab;     /**< Client capabilities (from us) */
  struct CapSet       con_active;    /**< Active capabilities (to us) */
  unsigned short      con_capab_version; /**< CAP version (0, 301, 302) */
  struct AuthRequest* con_auth;      /**< Auth request for client */
  struct LOCInfo*     con_loc;       /**< Login-on-connect information */
  char                con_label[64]; /**< Current command label for labeled-response */
  char                con_batch_id[16]; /**< Current batch reference ID */
  unsigned int        con_batch_seq;  /**< Batch sequence number for generating IDs */
  char                con_client_tags[512]; /**< Client-only tags (+tag=value) for TAGMSG relay */
  char                con_s2s_time[32];  /**< S2S @time tag from incoming message */
  char                con_s2s_msgid[64]; /**< S2S @msgid tag from incoming message */
  char                con_s2s_batch_id[32]; /**< Active S2S batch ID from server */
  char                con_s2s_batch_type[16]; /**< Active S2S batch type (netjoin, netsplit) */
  unsigned char       con_pre_away;   /**< Pre-registration away state: 0=none, 1=away, 2=away-star */
  char                con_pre_away_msg[AWAYLEN + 1]; /**< Pre-registration away message */
};

/** Magic constant to identify valid Connection structures. */
#define CONNECTION_MAGIC 0x12f955f3

/** Represents a client anywhere on the network. */
struct Client {
  unsigned long  cli_magic;       /**< magic number */
  struct Client* cli_next;        /**< link in GlobalClientList */
  struct Client* cli_prev;        /**< link in GlobalClientList */
  struct Client* cli_hnext;       /**< link in hash table bucket or this */
  struct Connection* cli_connect; /**< Connection structure associated with us */
  struct User*   cli_user;        /**< Defined if this client is a user */
  struct Server* cli_serv;        /**< Defined if this client is a server */
  struct Whowas* cli_whowas;      /**< Pointer to ww struct to be freed on quit */
  struct Privs   cli_privs;       /**< Oper privileges */
  char           cli_yxx[4];      /**< Numeric Nick: YY if this is a
                                     server, XXX if this is a user */
  time_t         cli_firsttime;   /**< time client was created */
  time_t         cli_lastnick;    /**< TimeStamp on nick */
  int            cli_marker;      /**< /who processing marker */
  struct Flags   cli_flags;       /**< client flags */
  unsigned int   cli_hopcount;    /**< number of servers to this 0 = local */
  struct irc_in_addr cli_ip;      /**< Real IP of client */
  short          cli_status;      /**< Client type */
  char cli_name[HOSTLEN + 1];     /**< Unique name of the client, nick or host */
  char cli_username[USERLEN + 1]; /**< Username determined by ident lookup */
  char cli_info[REALLEN + 1];     /**< Free form additional client information */

  struct irc_in_addr cli_connectip;  /**< Client connection IP address. */
  char cli_connecthost[HOSTLEN + 1]; /**< Client connection host name. */

  struct SLink* cli_marks;       /**< chain of mark pointer blocks */

  /* GeoIP data */
  char cli_countrycode[3];          /**< GeoIP 2 letter country code. */
  char cli_countryname[256];        /**< GeoIP country name. */
  char cli_continentcode[3];        /**< GeoIP 2 letter continent code. */
  char cli_continentname[256];      /**< GeoIP continent name. */

  /* MARKs */
  char cli_webirc[BUFSIZE + 1];     /**< webirc description */
  char cli_version[VERSIONLEN + 1]; /**< Free form client version information */
  char cli_sslclifp[BUFSIZE + 1];   /**< SSL client certificate fingerprint if available */
  char cli_killmark[BUFSIZE + 1];   /**< Kill block mark */

  /* SASL */
  int            cli_saslagentref; /**< Number of clients that reference this client as an SASL agent */
  struct Client* cli_saslagent;     /**< SASL agent handling SASL exchange */
  char cli_saslaccount[ACCOUNTLEN + 1]; /**< SASL authenticated account name */
  time_t cli_saslacccreate;         /**< SASL authenticate account timestamp */
  unsigned int cli_saslcookie;      /**< SASL session cookie */
  struct Timer cli_sasltimeout;     /**< timeout timer for SASL */
};

/** Magic constant to identify valid Client structures. */
#define CLIENT_MAGIC 0x4ca08286

/** Verify that a client is valid. */
#define cli_verify(cli)		((cli)->cli_magic == CLIENT_MAGIC)
/** Get client's magic number. */
#define cli_magic(cli)		((cli)->cli_magic)
/** Get global next client. */
#define cli_next(cli)		((cli)->cli_next)
/** Get global previous client. */
#define cli_prev(cli)		((cli)->cli_prev)
/** Get next client in hash bucket chain. */
#define cli_hnext(cli)		((cli)->cli_hnext)
/** Get connection associated with client. */
#define cli_connect(cli)	((cli)->cli_connect)
/** Get local client that links us to \a cli. */
#define cli_from(cli)		con_client(cli_connect(cli))
/** Get User structure for client, if client is a user. */
#define cli_user(cli)		((cli)->cli_user)
/** Get Server structure for client, if client is a server. */
#define cli_serv(cli)		((cli)->cli_serv)
/** Get Whowas link for client. */
#define cli_whowas(cli)		((cli)->cli_whowas)
/** Get client numnick. */
#define cli_yxx(cli)		((cli)->cli_yxx)
/** Get time we last read data from the client socket. */
#define cli_lasttime(cli)	con_lasttime(cli_connect(cli))
/** Get time we last parsed something from the client. */
#define cli_since(cli)		con_since(cli_connect(cli))
/** Get time client was created. */
#define cli_firsttime(cli)	((cli)->cli_firsttime)
/** Get time client last changed nickname. */
#define cli_lastnick(cli)	((cli)->cli_lastnick)
/** Get WHO marker for client. */
#define cli_marker(cli)		((cli)->cli_marker)
/** Get flags flagset for client. */
#define cli_flags(cli)		((cli)->cli_flags)
/** Get hop count to client. */
#define cli_hopcount(cli)	((cli)->cli_hopcount)
/** Get client IP address. */
#define cli_ip(cli)		((cli)->cli_ip)
/** Get status bitmask for client. */
#define cli_status(cli)		((cli)->cli_status)
/** Return non-zero if the client is local. */
#define cli_local(cli)          (cli_from(cli) == cli)
/** Get oper privileges for client. */
#define cli_privs(cli)		((cli)->cli_privs)
/** Get client capabilities for client */
#define cli_capab(cli)		con_capab(cli_connect(cli))
/** Get active client capabilities for client */
#define cli_active(cli)		con_active(cli_connect(cli))
/** Get CAP version for client (0, 301, 302) */
#define cli_capab_version(cli)	con_capab_version(cli_connect(cli))
/** Get current command label for labeled-response */
#define cli_label(cli)		con_label(cli_connect(cli))
/** Get current batch reference ID */
#define cli_batch_id(cli)	con_batch_id(cli_connect(cli))
/** Get batch sequence number */
#define cli_batch_seq(cli)	con_batch_seq(cli_connect(cli))
/** Get client-only tags buffer for TAGMSG relay */
#define cli_client_tags(cli)	con_client_tags(cli_connect(cli))
/** Get S2S @time tag from incoming message */
#define cli_s2s_time(cli)	con_s2s_time(cli_connect(cli))
/** Get S2S @msgid tag from incoming message */
#define cli_s2s_msgid(cli)	con_s2s_msgid(cli_connect(cli))
/** Get S2S batch ID from server */
#define cli_s2s_batch_id(cli)	con_s2s_batch_id(cli_connect(cli))
/** Get S2S batch type from server */
#define cli_s2s_batch_type(cli)	con_s2s_batch_type(cli_connect(cli))
/** Get client name. */
#define cli_name(cli)		((cli)->cli_name)
/** Get client username (ident). */
#define cli_username(cli)	((cli)->cli_username)
/** Get client realname (information field). */
#define cli_info(cli)		((cli)->cli_info)
/** Get client account string. */
#define cli_account(cli)       (cli_user(cli) ? cli_user(cli)->account : "0")
/** Get client connection IP address. */
#define cli_connectip(cli)      ((cli)->cli_connectip)
/** Get client connection host name. */
#define cli_connecthost(cli)     ((cli)->cli_connecthost)
/** Get client WEBIRC info line. */
#define cli_webirc(cli)         ((cli)->cli_webirc)
/** Get a clients CTCP version string. */
#define cli_version(cli)        ((cli)->cli_version)
/** Get a clients SSL fingerprint string. */
#define cli_sslclifp(cli)       ((cli)->cli_sslclifp)
/** Get a clients Kill block exemption mark. */
#define cli_killmark(cli)       ((cli)->cli_killmark)
/** Get all marks set for client. */
#define cli_marks(cli)        ((cli)->cli_marks)
/** Get client GeoIP country code. */
#define cli_countrycode(cli)    ((cli)->cli_countrycode)
/** Get client GeoIP country name. */
#define cli_countryname(cli)    ((cli)->cli_countryname)
/** Get client GeoIP continent code. */
#define cli_continentcode(cli)  ((cli)->cli_continentcode)
/** Get client GeoIP continent name. */
#define cli_continentname(cli)  ((cli)->cli_continentname)
/** Get SASL agent ref count. */
#define cli_saslagentref(cli)   ((cli)->cli_saslagentref)
/** Get SASL agent name. */
#define cli_saslagent(cli)      ((cli)->cli_saslagent)
/** Get SASL authenticated account name. */
#define cli_saslaccount(cli)    ((cli)->cli_saslaccount)
/** Get SASL authenticated account timestamp. */
#define cli_saslacccreate(cli)  ((cli)->cli_saslacccreate)
/** Get SASL session cookie. */
#define cli_saslcookie(cli)     ((cli)->cli_saslcookie)
/** Get Timer for SASL timeout. */
#define cli_sasltimeout(cli)     ((cli)->cli_sasltimeout)

/** Get number of incoming bytes queued for client. */
#define cli_count(cli)		con_count(cli_connect(cli))
/** Get file descriptor for sending in client's direction. */
#define cli_fd(cli)		con_fd(cli_connect(cli))
/** Get free flags for the client's connection. */
#define cli_freeflag(cli)	con_freeflag(cli_connect(cli))
/** Get last error code for the client's connection. */
#define cli_error(cli)		con_error(cli_connect(cli))
/** Get last SSL error string. */
#define cli_sslerror(cli)       con_sslerror(cli_connect(cli))
/** Get server notice mask for the client. */
#define cli_snomask(cli)	con_snomask(cli_connect(cli))
/** Get next time a nick change is allowed for the client. */
#define cli_nextnick(cli)	con_nextnick(cli_connect(cli))
/** Get next time a target change is allowed for the client. */
#define cli_nexttarget(cli)	con_nexttarget(cli_connect(cli))
/** Get SendQ for client. */
#define cli_sendQ(cli)		con_sendQ(cli_connect(cli))
/** Get RecvQ for client. */
#define cli_recvQ(cli)		con_recvQ(cli_connect(cli))
/** Get count of messages sent to client. */
#define cli_sendM(cli)		con_sendM(cli_connect(cli))
/** Get number of messages received from client. */
#define cli_receiveM(cli)	con_receiveM(cli_connect(cli))
/** Get number of bytes (modulo 1024) sent to client. */
#define cli_sendB(cli)		con_sendB(cli_connect(cli))
/** Get number of bytes (modulo 1024) received from client. */
#define cli_receiveB(cli)	con_receiveB(cli_connect(cli))
/** Get listener that accepted the client's connection. */
#define cli_listener(cli)	con_listener(cli_connect(cli))
/** Get list of attached conf lines. */
#define cli_confs(cli)		con_confs(cli_connect(cli))
/** Get handler type for client. */
#define cli_handler(cli)	con_handler(cli_connect(cli))
/** Get LIST status for client. */
#define cli_listing(cli)	con_listing(cli_connect(cli))
/** Get cached max SendQ for client. */
#define cli_max_sendq(cli)	con_max_sendq(cli_connect(cli))
/** Get cached max RecvQ for client. */
#define cli_max_recvq(cli)      con_max_recvq(cli_connect(cli))
/** Get ping frequency for client. */
#define cli_ping_freq(cli)	con_ping_freq(cli_connect(cli))
/** Get cached fake lag minimum for client. */
#define cli_lag_min(cli)        con_lag_min(cli_connect(cli))
/** Get cached fake lag factor for client. */
#define cli_lag_factor(cli)     con_lag_factor(cli_connect(cli))
/** Get lastsq for client's connection. */
#define cli_lastsq(cli)		con_lastsq(cli_connect(cli))
/** Get port that the client is connected to */
#define cli_port(cli)           ((cli)->cli_connect->con_port)
/** Get the array of current targets for the client.  */
#define cli_targets(cli)	con_targets(cli_connect(cli))
/** Get the string form of the client's IP address. */
#define cli_sock_ip(cli)	con_sock_ip(cli_connect(cli))
/** Get the resolved hostname for the client. */
#define cli_sockhost(cli)	con_sockhost(cli_connect(cli))
/** Get the client's password. */
#define cli_passwd(cli)		con_passwd(cli_connect(cli))
/** Get the unprocessed input buffer for a client's connection.  */
#define cli_buffer(cli)		con_buffer(cli_connect(cli))
/** Get the Socket structure for sending to a client. */
#define cli_socket(cli)		con_socket(cli_connect(cli))
/** Get Timer for processing waiting messages from the client. */
#define cli_proc(cli)		con_proc(cli_connect(cli))
/** Get auth request for client. */
#define cli_auth(cli)		con_auth(cli_connect(cli))
/** Get login on connect request for client. */
#define cli_loc(cli)            ((cli)->cli_connect->con_loc)
/** Get sentalong marker for client. */
#define cli_sentalong(cli)      con_sentalong(cli_connect(cli))

/** Verify that a connection is valid. */
#define con_verify(con)		((con)->con_magic == CONNECTION_MAGIC)
/** Get connection's magic number. */
#define con_magic(con)		((con)->con_magic)
/** Get global next connection. */
#define con_next(con)		((con)->con_next)
/** Get global previous connection. */
#define con_prev_p(con)		((con)->con_prev_p)
/** Get locally connected client for connection. */
#define con_client(con)		((con)->con_client)
/** Get number of unprocessed data bytes from connection. */
#define con_count(con)		((con)->con_count)
/** Get file descriptor for connection. */
#define con_fd(con)		s_fd(&(con)->con_socket)
/** Get freeable flags for connection. */
#define con_freeflag(con)	((con)->con_freeflag)
/** Get last error code on connection. */
#define con_error(con)		((con)->con_error)
/** Get last SSL error string. */
#define con_sslerror(con)       ((con)->con_sslerror)
/** Get sentalong marker for connection. */
#define con_sentalong(con)      ((con)->con_sentalong)
/** Get server notice mask for connection. */
#define con_snomask(con)	((con)->con_snomask)
/** Get next nick change time for connection. */
#define con_nextnick(con)	((con)->con_nextnick)
/** Get next new target time for connection. */
#define con_nexttarget(con)	((con)->con_nexttarget)
/** Get last time we read from the connection. */
#define con_lasttime(con)       ((con)->con_lasttime)
/** Get last time we accepted a command from the connection. */
#define con_since(con)          ((con)->con_since)
/** Get SendQ for connection. */
#define con_sendQ(con)		((con)->con_sendQ)
/** Get RecvQ for connection. */
#define con_recvQ(con)		((con)->con_recvQ)
/** Get number of messages sent to connection. */
#define con_sendM(con)		((con)->con_sendM)
/** Get number of messages received from connection. */
#define con_receiveM(con)	((con)->con_receiveM)
/** Get number of bytes (modulo 1024) sent to connection. */
#define con_sendB(con)		((con)->con_sendB)
/** Get number of bytes (modulo 1024) received from connection. */
#define con_receiveB(con)	((con)->con_receiveB)
/** Get listener that accepted the connection. */
#define con_listener(con)	((con)->con_listener)
/** Get list of ConfItems attached to the connection. */
#define con_confs(con)		((con)->con_confs)
/** Get command handler for the connection. */
#define con_handler(con)	((con)->con_handler)
/** Get the LIST status for the connection. */
#define con_listing(con)	((con)->con_listing)
/** Get the maximum permitted SendQ size for the connection. */
#define con_max_sendq(con)	((con)->con_max_sendq)
/** Get the maximum permitted RecvQ size for the connection. */
#define con_max_recvq(con)      ((con)->con_max_recvq)
/** Get the ping frequency for the connection. */
#define con_ping_freq(con)	((con)->con_ping_freq)
/** Get the minimum fake lag for the connection. */
#define con_lag_min(con)        ((con)->con_lag_min)
/** Get the fake lag factor for the connection. */
#define con_lag_factor(con)     ((con)->con_lag_factor)
/** Get the lastsq for the connection. */
#define con_lastsq(con)		((con)->con_lastsq)
/** Get the current targets array for the connection. */
#define con_targets(con)	((con)->con_targets)
/** Get the string-formatted IP address for the connection. */
#define con_sock_ip(con)	((con)->con_sock_ip)
/** Get the resolved hostname for the connection. */
#define con_sockhost(con)	((con)->con_sockhost)
/** Get the password sent by the remote end of the connection.  */
#define con_passwd(con)		((con)->con_passwd)
/** Get the buffer of unprocessed incoming data from the connection. */
#define con_buffer(con)		((con)->con_buffer)
/** Get the Socket for the connection. */
#define con_socket(con)		((con)->con_socket)
/** Get the Timer for processing more data from the connection. */
#define con_proc(con)		((con)->con_proc)
/** Get the peer's capabilities for the connection. */
#define con_capab(con)          (&(con)->con_capab)
/** Get the active capabilities for the connection. */
#define con_active(con)         (&(con)->con_active)
/** Get the CAP version for the connection (0, 301, 302). */
#define con_capab_version(con)  ((con)->con_capab_version)
/** Get the auth request for the connection. */
#define con_auth(con)		((con)->con_auth)
/** Get the current command label for labeled-response. */
#define con_label(con)		((con)->con_label)
/** Get the current batch reference ID. */
#define con_batch_id(con)	((con)->con_batch_id)
/** Get the batch sequence number. */
#define con_batch_seq(con)	((con)->con_batch_seq)
/** Get the client-only tags buffer for TAGMSG relay. */
#define con_client_tags(con)	((con)->con_client_tags)
/** Get the S2S @time tag from incoming message. */
#define con_s2s_time(con)	((con)->con_s2s_time)
/** Get the S2S @msgid tag from incoming message. */
#define con_s2s_msgid(con)	((con)->con_s2s_msgid)
/** Get the S2S batch ID from server. */
#define con_s2s_batch_id(con)	((con)->con_s2s_batch_id)
/** Get the S2S batch type from server. */
#define con_s2s_batch_type(con)	((con)->con_s2s_batch_type)
/** Get the pre-registration away state. */
#define con_pre_away(con)	((con)->con_pre_away)
/** Get the pre-registration away message. */
#define con_pre_away_msg(con)	((con)->con_pre_away_msg)

#define STAT_CONNECTING         0x001 /**< connecting to another server */
#define STAT_HANDSHAKE          0x002 /**< pass - server sent */
#define STAT_ME                 0x004 /**< this server */
#define STAT_UNKNOWN            0x008 /**< unidentified connection */
#define STAT_UNKNOWN_USER       0x010 /**< connection on a client port */
#define STAT_UNKNOWN_SERVER     0x020 /**< connection on a server port */
#define STAT_SERVER             0x040 /**< fully registered server */
#define STAT_USER               0x080 /**< fully registered user */

/*
 * status macros.
 */
/** Return non-zero if the client is registered. */
#define IsRegistered(x)         (cli_status(x) & (STAT_SERVER | STAT_USER))
/** Return non-zero if the client is an outbound connection that is
 * still connecting. */
#define IsConnecting(x)         (cli_status(x) == STAT_CONNECTING)
/** Return non-zero if the client is an outbound connection that has
 * sent our password. */
#define IsHandshake(x)          (cli_status(x) == STAT_HANDSHAKE)
/** Return non-zero if the client is this server. */
#define IsMe(x)                 (cli_status(x) == STAT_ME)
/** Return non-zero if the client has not yet registered. */
#define IsUnknown(x)            (cli_status(x) & \
        (STAT_UNKNOWN | STAT_UNKNOWN_USER | STAT_UNKNOWN_SERVER))
/** Return non-zero if the client is an unregistered connection on a
 * server port. */
#define IsServerPort(x)         (cli_status(x) == STAT_UNKNOWN_SERVER )
/** Return non-zero if the client is an unregistered connection on a
 * user port. */
#define IsUserPort(x)           (cli_status(x) == STAT_UNKNOWN_USER )
/** Return non-zero if the client is a real client connection. */
#define IsClient(x)             (cli_status(x) & \
        (STAT_HANDSHAKE | STAT_ME | STAT_UNKNOWN |\
         STAT_UNKNOWN_USER | STAT_UNKNOWN_SERVER | STAT_SERVER | STAT_USER))
/** Return non-zero if the client ignores flood limits. */
#define IsTrusted(x)            (cli_status(x) & \
        (STAT_CONNECTING | STAT_HANDSHAKE | STAT_ME | STAT_SERVER))
/** Return non-zero if the client is a registered server. */
#define IsServer(x)             (cli_status(x) == STAT_SERVER)
/** Return non-zero if the client is a registered user. */
#define IsUser(x)               (cli_status(x) == STAT_USER)


/** Mark a client with STAT_CONNECTING. */
#define SetConnecting(x)        (cli_status(x) = STAT_CONNECTING)
/** Mark a client with STAT_HANDSHAKE. */
#define SetHandshake(x)         (cli_status(x) = STAT_HANDSHAKE)
/** Mark a client with STAT_SERVER. */
#define SetServer(x)            (cli_status(x) = STAT_SERVER)
/** Mark a client with STAT_ME. */
#define SetMe(x)                (cli_status(x) = STAT_ME)
/** Mark a client with STAT_USER. */
#define SetUser(x)              (cli_status(x) = STAT_USER)

/** Return non-zero if a client is directly connected to me. */
#define MyConnect(x)    (cli_from(x) == (x))
/** Return non-zero if a client is a locally connected user. */
#define MyUser(x)       (MyConnect(x) && IsUser(x))
/** Return non-zero if a client is a locally connected IRC operator. */
#define MyOper(x)       (MyConnect(x) && IsOper(x))
/** Return protocol version used by a server. */
#define Protocol(x)     ((cli_serv(x))->prot)

/*
 * flags macros
 */
/** Set a flag in a client's flags. */
#define SetFlag(cli, flag)  FlagSet(&cli_flags(cli), flag)
/** Clear a flag from a client's flags. */
#define ClrFlag(cli, flag)  FlagClr(&cli_flags(cli), flag)
/** Return non-zero if a flag is set in a client's flags. */
#define HasFlag(cli, flag)  FlagHas(&cli_flags(cli), flag)

/** Return non-zero if the client is an IRC operator (global or local). */
#define IsAnOper(x)             (IsOper(x) || IsLocOp(x) || IsAdmin(x))
/** Return non-zero if the client's connection is blocked. */
#define IsBlocked(x)            HasFlag(x, FLAG_BLOCKED)
/** Return non-zero if the client's connection is still being burst. */
#define IsBurst(x)              HasFlag(x, FLAG_BURST)
/** Return non-zero if we have received the peer's entire burst but
 * not their EOB ack. */
#define IsBurstAck(x)           HasFlag(x, FLAG_BURST_ACK)
/** Return non-zero if we are still bursting to the client. */
#define IsBurstOrBurstAck(x)    (HasFlag(x, FLAG_BURST) || HasFlag(x, FLAG_BURST_ACK))
/** Return non-zero if the client has set mode +k (channel service). */
#define IsChannelService(x)     HasFlag(x, FLAG_CHSERV)
/** Return non-zero if the client's socket is disconnected. */
#define IsDead(x)               HasFlag(x, FLAG_DEADSOCKET)
/** Return non-zero if the client has set mode +d (deaf). */
#define IsDeaf(x)               HasFlag(x, FLAG_DEAF)
/** Return non-zero if the client has been IP-checked for clones. */
#define IsIPChecked(x)          HasFlag(x, FLAG_IPCHECK)
/** Return non-zero if we have received an ident response for the client. */
#define IsIdented(x)            HasFlag(x, FLAG_GOTID)
/** Return non-zero if the client has set mode +i (invisible). */
#define IsInvisible(x)          HasFlag(x, FLAG_INVISIBLE)
/** Return non-zero if the client caused a net.burst. */
#define IsJunction(x)           HasFlag(x, FLAG_JUNCTION)
/** Return non-zero if the client has set mode +O (local operator) locally. */
#define IsLocOp(x)              (MyConnect(x) && HasFlag(x, FLAG_LOCOP))
/** Return non-zero if the client has set mode +o (global operator). */
#define IsOper(x)               HasFlag(x, FLAG_OPER)
/** Return non-zero if the client has an active UDP ping request. */
#define IsUPing(x)              HasFlag(x, FLAG_UPING)
/** Return non-zero if the client has no '\n' in its buffer. */
#define NoNewLine(x)            HasFlag(x, FLAG_NONL)
/** Return non-zero if the client has set mode +g (debugging). */
#define SendDebug(x)            HasFlag(x, FLAG_DEBUG)
/** Return non-zero if the client has set mode +s (server notices). */
#define SendServNotice(x)       HasFlag(x, FLAG_SERVNOTICE)
/** Return non-zero if the client has set mode +w (wallops). */
#define SendWallops(x)          HasFlag(x, FLAG_WALLOP)
/** Return non-zero if the client claims to be a hub. */
#define IsHub(x)                HasFlag(x, FLAG_HUB)
/** Return non-zero if the client understands IPv6 addresses in P10. */
#define IsIPv6(x)               HasFlag(x, FLAG_IPV6)
/** Return non-zero if the client claims to be a services server. */
#define IsService(x)            HasFlag(x, FLAG_SERVICE)
/** Return non-zero if the client has oplevels support. */
#define IsOpLevels(x)           HasFlag(x, FLAG_OPLEVELS)
/** Return non-zero if the client has an account stamp. */
#define IsAccount(x)            HasFlag(x, FLAG_ACCOUNT)
/** Return non-zero if the client has set mode +x (hidden host). */
#define IsHiddenHost(x)         HasFlag(x, FLAG_HIDDENHOST)
/** Return non-zero if the client has set mode +W (whois notices). */
#define IsWhoisNotice(x)        HasFlag(x, FLAG_WHOIS_NOTICE)
/** Return non-zero if the client has set mode +H (hide oper status). */
#define IsHideOper(x)           HasFlag(x, FLAG_HIDE_OPER)
/** Return non-zero if the client has the channel hiding mode set. */
#define IsNoChan(x)		HasFlag(x, FLAG_NOCHAN)
/** Return non-zero if the client has the hidden idle time mode set. */
#define IsNoIdle(x)		HasFlag(x, FLAG_NOIDLE)
/** Return non-zero if the client supports extended NAMES */
#define IsNamesX(x)             HasFlag(x, FLAG_NAMESX)
/** Return non-zero if the client supports user-host NAMES */
#define IsUHNames(x)            HasFlag(x, FLAG_UHNAMES)
/** Return non-zero if the client is a WEBIRC client. */
#define IsWebIRC(x)             HasFlag(x, FLAG_WEBIRC)
/** Return non-zero if the client should use USER username as ident. */
#define IsWebIRCUserIdent(x)    HasFlag(x, FLAG_WEBIRC_USERIDENT)
/** Return non-zero if the client has had its IP address or host name changed. */
#define IsIPSpoofed(x)          HasFlag(x, FLAG_IPSPOOFED)
/** Return non-zero if the client only accepts messages from clients with an account. */
#define IsAccountOnly(x)	HasFlag(x, FLAG_ACCOUNTONLY)
/** Return non-zero if the client is private deaf */
#define IsPrivDeaf(x)           HasFlag(x, FLAG_PRIVDEAF)
/** Return non-zero if the client has set mode +q (common chans only). */
#define IsCommonChansOnly(x)    HasFlag(x, FLAG_COMMONCHANSONLY)
/** Return non-zero if the client has set +B. */
#define IsBot(x)                HasFlag(x, FLAG_BOT)
/** Return non-zero if the client has got GeoIP data. */
#define IsGeoIP(x)              HasFlag(x, FLAG_GEOIP)
/** Return non-zero if the client is an admin. */
#define IsAdmin(x)              HasFlag(x, FLAG_ADMIN)
/** Return non-zero if the client has set +X. */
#define IsXtraOp(x)             HasFlag(x, FLAG_XTRAOP)
/** Return non-zero if the client has set +L. */
#define IsNoLink(x)              HasFlag(x, FLAG_NOLINK)
/** Return non-zero if the client has a cloaked IP. */
#define IsCloakIP(x)            HasFlag(x, FLAG_CLOAKIP)
/** Return non-zero if the client has a cloaked host. */
#define IsCloakHost(x)          HasFlag(x, FLAG_CLOAKHOST)
/** Return non-zero if the client has a fake host. */
#define IsFakeHost(x)           HasFlag(x, FLAG_FAKEHOST)
/** Return non-zero if the client has a set host. */
#define IsSetHost(x)            HasFlag(x, FLAG_SETHOST)
/** Return non-zero if the client is connected via SSL. */
#define IsSSL(x)                HasFlag(x, FLAG_SSL)
/** Return non-zero if the client is connecting using STARTTLS. */
#define IsStartTLS(x)           HasFlag(x, FLAG_STARTTLS)
/** Return non-zero if the client still needs SSL_accept(). */
#define IsSSLNeedAccept(x)      HasFlag(x, FLAG_SSLNEEDACCEPT)
/** Return non-zero if the client is IPcheck exempt. */
#define IsIPCheckExempt(x)      HasFlag(x, FLAG_IPCEXEMPT)
/** Return non-zero if the client is not IPcheck exempt. */
#define IsNotIPCheckExempt(x)   HasFlag(x, FLAG_IPCNOTEXEMPT)
/** Return non-zero if the client has completed SASL authentication. */
#define IsSASLComplete(x)       HasFlag(x, FLAG_SASLCOMPLETE)
/** Return non-zero if the client has been marked. */
#define IsMarked(x)             HasFlag(x, FLAG_MARKED)
/** Return non-zero if the client cannot join channels. */
#define IsRestrictJoin(x)       HasFlag(x, FLAG_RESTRICT_JOIN)
/** Return non-zero if the client cannot send private PRIVMSG or NOTICE. */
#define IsRestrictPrivMsg(x)    HasFlag(x, FLAG_RESTRICT_PRIVMSG)
/** Return non-zero if the client cannot change his/her user modes. */
#define IsRestrictUMode(x)      HasFlag(x, FLAG_RESTRICT_UMODE)
/** Return non-zero if the client is temporarily shunned. */
#define IsTempShun(x)           HasFlag(x, FLAG_TEMPSHUN)
/** Return non-zero if the client /OPER'ed using a local O:Line. */
#define IsOperedLocal(x)        HasFlag(x, FLAG_OPERED_LOCAL)
/** Return non-zero if the client /OPER'ed using a remote O:Line. */
#define IsOperedRemote(x)       HasFlag(x, FLAG_OPERED_REMOTE)
/** Return non-zero if the server is NOOP'ed. */
#define IsServerNoop(x)         HasFlag(x, FLAG_SERVER_NOOP)
/** Return non-zero if the client's CTCP VERSION reply has been sent out. */
#define IsCVersionSent(x)       HasFlag(x, FLAG_SENT_CVERSION)
/** Return non-zero if the client has an active PING request. */
#define IsPingSent(x)           HasFlag(x, FLAG_PINGSENT)

/** Return non-zero if the client has operator or server privileges. */
#define IsPrivileged(x)         (IsAnOper(x) || IsServer(x))
/** Return non-zero if the client's host is hidden. */
#define HasHiddenHost(x)        (IsHiddenHost(x) && IsAccount(x))

/** Mark a client as having an in-progress net.burst. */
#define SetBurst(x)             SetFlag(x, FLAG_BURST)
/** Mark a client as being between EOB and EOB ACK. */
#define SetBurstAck(x)          SetFlag(x, FLAG_BURST_ACK)
/** Mark a client as having mode +k (channel service). */
#define SetChannelService(x)    SetFlag(x, FLAG_CHSERV)
/** Mark a client as having mode +d (deaf). */
#define SetDeaf(x)              SetFlag(x, FLAG_DEAF)
/** Mark a client as having mode +g (debugging). */
#define SetDebug(x)             SetFlag(x, FLAG_DEBUG)
/** Mark a client as having ident looked up. */
#define SetGotId(x)             SetFlag(x, FLAG_GOTID)
/** Mark a client as being IP-checked. */
#define SetIPChecked(x)         SetFlag(x, FLAG_IPCHECK)
/** Mark a client as having mode +i (invisible). */
#define SetInvisible(x)         SetFlag(x, FLAG_INVISIBLE)
/** Mark a client as causing a net.join. */
#define SetJunction(x)          SetFlag(x, FLAG_JUNCTION)
/** Mark a client as having mode +O (local operator). */
#define SetLocOp(x)             SetFlag(x, FLAG_LOCOP)
/** Mark a client as having mode +o (global operator). */
#define SetOper(x)              SetFlag(x, FLAG_OPER)
/** Mark a client as having a pending UDP ping. */
#define SetUPing(x)             SetFlag(x, FLAG_UPING)
/** Mark a client as having mode +w (wallops). */
#define SetWallops(x)           SetFlag(x, FLAG_WALLOP)
/** Mark a client as having mode +s (server notices). */
#define SetServNotice(x)        SetFlag(x, FLAG_SERVNOTICE)
/** Mark a client as being a hub server. */
#define SetHub(x)               SetFlag(x, FLAG_HUB)
/** Mark a client as being an IPv6-grokking server. */
#define SetIPv6(x)              SetFlag(x, FLAG_IPV6)
/** Mark a client as being a services server. */
#define SetService(x)           SetFlag(x, FLAG_SERVICE)
/** Mark a client as having oplevels support. */
#define SetOpLevels(x)          SetFlag(x, FLAG_OPLEVELS)
/** Mark a client as having an account stamp. */
#define SetAccount(x)           SetFlag(x, FLAG_ACCOUNT)
/** Mark a client as having mode +x (hidden host). */
#define SetHiddenHost(x)        SetFlag(x, FLAG_HIDDENHOST)
/** Mark a client as having mode +W (whois notices). */
#define SetWhoisNotice(x)       SetFlag(x, FLAG_WHOIS_NOTICE)
/** Mark a client as having mode +H (hide oper status). */
#define SetHideOper(x)          SetFlag(x, FLAG_HIDE_OPER)
/** Mark a client as having the channel hiding mode set. */
#define SetNoChan(x)		SetFlag(x, FLAG_NOCHAN)
/** Mark a client as having the hidden idle time mode set. */
#define SetNoIdle(x)		SetFlag(x, FLAG_NOIDLE)
/** Mark a client as supporting extended NAMES. */
#define SetNamesX(x)            SetFlag(x, FLAG_NAMESX)
/** Mark a client as supporting user-host NAMES. */
#define SetUHNames(x)           SetFlag(x, FLAG_UHNAMES)
/** Mark a client as a WEBIRC client. */
#define SetWebIRC(x)            SetFlag(x, FLAG_WEBIRC)
/** Mark a client as having to use USER username as ident. */
#define SetWebIRCUserIdent(x)   SetFlag(x, FLAG_WEBIRC_USERIDENT)
/** Mark a client as having a spoofed IP or host name. */
#define SetIPSpoofed(x)         SetFlag(x, FLAG_IPSPOOFED)
/** Mark a client as only accepting messages from users with accounts. */
#define SetAccountOnly(x)	SetFlag(x, FLAG_ACCOUNTONLY)
/** Mark a client as being private deaf. */
#define SetPrivDeaf(x)          SetFlag(x, FLAG_PRIVDEAF)
/** Mark a client as having mode +q (common chans only). */
#define SetCommonChansOnly(x)   SetFlag(x, FLAG_COMMONCHANSONLY)
/** Mark a client as having mode +B (bot). */
#define SetBot(x)               SetFlag(x, FLAG_BOT)
/** Mark a client as having GeoIP data. */
#define SetGeoIP(x)             SetFlag(x, FLAG_GEOIP)
/** Mark a client as being an admin. */
#define SetAdmin(x)             SetFlag(x, FLAG_ADMIN)
/** Mark a client as having mode +X (XtraOp). */
#define SetXtraOp(x)            SetFlag(x, FLAG_XTRAOP)
/** Mark a client as having mode +L (No Redirect). */
#define SetNoLink(x)            SetFlag(x, FLAG_NOLINK)
/** Mark a client as having a cloaked IP. */
#define SetCloakIP(x)           SetFlag(x, FLAG_CLOAKIP)
/** Mark a client as having a cloaked host. */
#define SetCloakHost(x)         SetFlag(x, FLAG_CLOAKHOST)
/** Mark a client as having a fake host. */
#define SetFakeHost(x)          SetFlag(x, FLAG_FAKEHOST)
/** Mark a client as having a set host. */
#define SetSetHost(x)           SetFlag(x, FLAG_SETHOST)
/** Mark a client as having connected via SSL. */
#define SetSSL(x)               SetFlag(x, FLAG_SSL)
/** Mark a client as using STARTTLS. */
#define SetStartTLS(x)          SetFlag(x, FLAG_STARTTLS)
/** Mark a client as needing SSL_accept(). */
#define SetSSLNeedAccept(x)     SetFlag(x, FLAG_SSLNEEDACCEPT)
/** Mark a client as IPcheck exempt. */
#define SetIPCheckExempt(x)     SetFlag(x, FLAG_IPCEXEMPT)
/** Mark a client as not IPcheck exempt. */
#define SetNotIPCheckExempt(x)  SetFlag(x, FLAG_IPCNOTEXEMPT)
/** Mark a client as having completed SASL authentication. */
#define SetSASLComplete(x)      SetFlag(x, FLAG_SASLCOMPLETE)
/** Mark a client as having been marked.. */
#define SetMarked(x)            SetFlag(x, FLAG_MARKED)
/** Mark a client as not being allowed to join channels. */
#define SetRestrictJoin(x)      SetFlag(x, FLAG_RESTRICT_JOIN)
/** Mark a client as not being allowed to send private PRIVMSG and NOTICE. */
#define SetRestrictPrivMsg(x)   SetFlag(x, FLAG_RESTRICT_PRIVMSG)
/** Mark a client as not being allowed to change user modes. */
#define SetRestrictUMode(x)     SetFlag(x, FLAG_RESTRICT_UMODE)
/** Mark a client as temporarily shunned. */
#define SetTempShun(x)          SetFlag(x, FLAG_TEMPSHUN)
/** Mark a client as having /OPER'ed using a local O:Line. */
#define SetOperedLocal(x)       SetFlag(x, FLAG_OPERED_LOCAL)
/** Mark a client as having /OPER'ed using a remote O:Line. */
#define SetOperedRemote(x)      SetFlag(x, FLAG_OPERED_REMOTE)
/** Mark a server as having been NOOP'ed. */
#define SetServerNoop(x)        SetFlag(x, FLAG_SERVER_NOOP)
/** Mark a client as having had it's CTCP VERSION sent out. */
#define SetCVersionSent(x)      SetFlag(x, FLAG_SENT_CVERSION)
/** Mark a client as having a pending PING. */
#define SetPingSent(x)          SetFlag(x, FLAG_PINGSENT)

/** Return non-zero if \a sptr sees \a acptr as an operator. */
#define SeeOper(sptr,acptr) (IsAnOper(acptr) && ((HasPriv(acptr, PRIV_DISPLAY) && \
                             !IsHideOper(acptr)) || HasPriv(sptr, PRIV_SEE_OPERS)))

/** Clear the client's net.burst in-progress flag. */
#define ClearBurst(x)           ClrFlag(x, FLAG_BURST)
/** Clear the client's between EOB and EOB ACK flag. */
#define ClearBurstAck(x)        ClrFlag(x, FLAG_BURST_ACK)
/** Remove mode +k (channel service) from the client. */
#define ClearChannelService(x)  ClrFlag(x, FLAG_CHSERV)
/** Remove mode +d (deaf) from the client. */
#define ClearDeaf(x)            ClrFlag(x, FLAG_DEAF)
/** Remove mode +g (debugging) from the client. */
#define ClearDebug(x)           ClrFlag(x, FLAG_DEBUG)
/** Remove the client's IP-checked flag. */
#define ClearIPChecked(x)       ClrFlag(x, FLAG_IPCHECK)
/** Remove mode +i (invisible) from the client. */
#define ClearInvisible(x)       ClrFlag(x, FLAG_INVISIBLE)
/** Remove mode +O (local operator) from the client. */
#define ClearLocOp(x)           ClrFlag(x, FLAG_LOCOP)
/** Remove mode +o (global operator) from the client. */
#define ClearOper(x)            ClrFlag(x, FLAG_OPER)
/** Clear the client's pending UDP ping flag. */
#define ClearUPing(x)           ClrFlag(x, FLAG_UPING)
/** Remove mode +w (wallops) from the client. */
#define ClearWallops(x)         ClrFlag(x, FLAG_WALLOP)
/** Remove mode +s (server notices) from the client. */
#define ClearServNotice(x)      ClrFlag(x, FLAG_SERVNOTICE)
/** Remove mode +x (hidden host) from the client. */
#define ClearHiddenHost(x)      ClrFlag(x, FLAG_HIDDENHOST)
/** Remove mode +W (whois notices) from the client. */
#define ClearWhoisNotice(x)     ClrFlag(x, FLAG_WHOIS_NOTICE)
/** Remove mode +H (hide oper status) from the client. */
#define ClearHideOper(x)        ClrFlag(x, FLAG_HIDE_OPER)
/** Remove mode +n (hide channels in whois) from the client. */
#define ClearNoChan(x)		ClrFlag(x, FLAG_NOCHAN)
/** Remove mode +I (hide idle time in whois) from the client. */
#define ClearNoIdle(x)		ClrFlag(x, FLAG_NOIDLE)
/** Client no longer supports extended names. */
#define ClearNamesX(x)          ClrFlag(x, FLAG_NAMESX)
/** Client no longer supports user-host names. */
#define ClearUHNames(x)         ClrFlag(x, FLAG_UHNAMES)
/** Client is no long a WEBIRC client. */
#define ClearWebIRC(x)          ClrFlag(x, FLAG_WEBIRC)
/** Client no longer has to use USER username as ident. */
#define ClearWebIRCUserIdent(x) ClrFlag(x, FLAG_WEBIRC_USERIDENT)
/** Client no longer has a spoofed IP or host name. */
#define ClearIPSpoofed(x)       ClrFlag(x, FLAG_IPSPOOFED)
/** Remove mode +R (only accept pms from users with an account) from the client. */
#define ClearAccountOnly(x)	ClrFlag(x, FLAG_ACCOUNTONLY)
/** Client is no longer private deaf. */
#define ClearPrivDeaf(x)        ClrFlag(x, FLAG_PRIVDEAF)
/** Remove mode +q (common chans only) from a client */
#define ClearCommonChansOnly(x) ClrFlag(x, FLAG_COMMONCHANSONLY)
/** Remove mode +B (bot) flag from the client */
#define ClearBot(x)             ClrFlag(x, FLAG_BOT)
/** Client no longer has GeoIP data. */
#define ClearGeoIP(x)           ClrFlag(x, FLAG_GEOIP)
/** Client is no long an admin. */
#define ClearAdmin(x)           ClrFlag(x, FLAG_ADMIN)
/** Remove mode +X (XtraOp) flag from client */
#define ClearXtraOp(x)          ClrFlag(x, FLAG_XTRAOP)
/** Remove mode +L (No Redirect) flag from client */
#define ClearNoLink(x)          ClrFlag(x, FLAG_NOLINK)
/** Client no longer has a cloaked IP. */
#define ClearCloakIP(x)         ClrFlag(x, FLAG_CLOAKIP)
/** Client no longer has a cloaked host. */
#define ClearCloakHost(x)       ClrFlag(x, FLAG_CLOAKHOST)
/** Client no longer has a fake host. */
#define ClearFakeHost(x)        ClrFlag(x, FLAG_FAKEHOST)
/** Client no longer has a set host. */
#define ClearSetHost(x)         ClrFlag(x, FLAG_SETHOST)
/** Client is no longer connected via SSL (this cannot be possible). */
#define ClearSSL(x)             ClrFlag(x, FLAG_SSL)
/** Client is no longer using STARTTLS. */
#define ClearStartTLS(x)        ClrFlag(x, FLAG_STARTTLS)
/** Client no longer needs SSL_accept(). */
#define ClearSSLNeedAccept(x)   ClrFlag(x, FLAG_SSLNEEDACCEPT)
/** Clear the client's join restriction. */
#define ClearRestrictJoin(x)    ClrFlag(x, FLAG_RESTRICT_JOIN)
/** Clear the client's PRIVMSG/NOTICE restriction. */
#define ClearRestrictPrivMsg(x) ClrFlag(x, FLAG_RESTRICT_PRIVMSG)
/** Clear the client's user mode restriction. */
#define ClearRestrictUMode(x)   ClrFlag(x, FLAG_RESTRICT_UMODE)
/** Client is no longer temporarily shunned. */
#define ClearTempShun(x)        ClrFlag(x, FLAG_TEMPSHUN)
/** Client is no longer OPER'ed using a local O:Line. */
#define ClearOperedLocal(x)     ClrFlag(x, FLAG_OPERED_LOCAL)
/** Client is no longet OPER'ed using a remote O:Line. */
#define ClearOperedRemote(x)    ClrFlag(x, FLAG_OPERED_REMOTE)
/** Server is no longer NOOP'ed. */
#define ClearServerNoop(x)      ClrFlag(x, FLAG_SERVER_NOOP)
/** Clear the client's pending PING flag. */
#define ClearPingSent(x)        ClrFlag(x, FLAG_PINGSENT)
/** Clear the client's HUB flag. */
#define ClearHub(x)             ClrFlag(x, FLAG_HUB)
/** Clear the client's OPLEVELS flag. */
#define ClearOpLevels(x)        ClrFlag(x, FLAG_OPLEVELS)
/** Clear the client's account status. */
#define ClearAccount(x)         ClrFlag(x, FLAG_ACCOUNT)
/** Clear the client's SASL authentication complete flag. */
#define ClearSASLComplete(x)    ClrFlag(x, FLAG_SASLCOMPLETE)

/* free flags */
#define FREEFLAG_SOCKET	0x0001	/**< socket needs to be freed */
#define FREEFLAG_TIMER	0x0002	/**< timer needs to be freed */

/* server notice stuff */

#define SNO_ADD         1       /**< Perform "or" on server notice mask. */
#define SNO_DEL         2       /**< Perform "and ~x" on server notice mask. */
#define SNO_SET         3       /**< Set server notice mask. */
                                /* DON'T CHANGE THESE VALUES ! */
                                /* THE CLIENTS DEPEND ON IT  ! */
#define SNO_OLDSNO      0x1     /**< unsorted old messages */
#define SNO_SERVKILL    0x2     /**< server kills (nick collisions) */
#define SNO_OPERKILL    0x4     /**< oper kills */
#define SNO_HACK2       0x8     /**< desyncs */
#define SNO_HACK3       0x10    /**< temporary desyncs */
#define SNO_UNAUTH      0x20    /**< unauthorized connections */
#define SNO_TCPCOMMON   0x40    /**< common TCP or socket errors */
#define SNO_TOOMANY     0x80    /**< too many connections */
#define SNO_HACK4       0x100   /**< Uworld actions on channels */
#define SNO_GLINE       0x200   /**< glines */
#define SNO_NETWORK     0x400   /**< net join/break, etc */
#define SNO_IPMISMATCH  0x800   /**< IP mismatches */
#define SNO_THROTTLE    0x1000  /**< host throttle add/remove notices */
#define SNO_OLDREALOP   0x2000  /**< old oper-only messages */
#define SNO_CONNEXIT    0x4000  /**< client connect/exit (ugh) */
#define SNO_AUTO        0x8000  /**< AUTO G-Lines */
#define SNO_DEBUG       0x10000 /**< debugging messages (DEBUGMODE only) */
#define SNO_NICKCHG     0x20000 /**< Nick change notices */
#define SNO_AUTH        0x40000 /**< IAuth notices */
#define SNO_WEBIRC      0x80000 /**< WebIRC notices */

/** Bitmask of all valid server notice bits. */
#ifdef DEBUGMODE
# define SNO_ALL        0xfffff
#else
# define SNO_ALL        0xeffff
#endif

/** Server notice bits allowed to normal users. */
#define SNO_USER        (SNO_ALL & ~SNO_OPER)

/** Server notice bits enabled by default for normal users. */
#define SNO_DEFAULT (SNO_NETWORK|SNO_OPERKILL|SNO_GLINE)
/** Server notice bits enabled by default for IRC operators. */
#define SNO_OPERDEFAULT (SNO_DEFAULT|SNO_HACK2|SNO_THROTTLE|SNO_OLDSNO)
/** Server notice bits reserved to IRC operators. */
#define SNO_OPER (SNO_CONNEXIT|SNO_OLDREALOP|SNO_AUTH)
/** Noisy server notice bits that cause other bits to be cleared during connect. */
#define SNO_NOISY (SNO_SERVKILL|SNO_UNAUTH)

/** Test whether a privilege has been granted to a client. */
#define HasPriv(cli, priv)  FlagHas(&cli_privs(cli), priv)
/** Grant a privilege to a client. */
#define SetPriv(cli, priv)  FlagSet(&cli_privs(cli), priv)
/** Revoke a privilege from a client. */
#define ClrPriv(cli, priv)  FlagClr(&cli_privs(cli), priv)

/** Used in setting and unsetting privs. */
#define PRIV_ADD 1
/** Used in setting and unsetting privs. */
#define PRIV_DEL 0

/** Test whether a client has a capability */
#define HasCap(cli, cap)    CapHas(cli_capab(cli), (cap))
/** Test whether a client has the capability active */
#define CapActive(cli, cap) CapHas(cli_active(cli), (cap))

#define HIDE_IP 0 /**< Do not show IP address in get_client_name() */
#define SHOW_IP 1 /**< Show ident and IP address in get_client_name() */

extern const char* get_client_name(const struct Client* sptr, int showip);
extern const char* client_get_default_umode(const struct Client* sptr);
extern int client_get_hidehostcomponents(const struct Client* sptr);
extern int client_get_ping(const struct Client* local_client);
extern void client_drop_sendq(struct Connection* con);
extern void client_add_sendq(struct Connection* con,
			     struct Connection** con_p);
extern void client_set_privs(struct Client *client, struct ConfItem *oper);
extern int client_report_privs(struct Client* to, struct Client* client);
extern void client_check_privs(struct Client *client, struct Client *replyto);
extern void client_send_privs(struct Client *from, struct Client *to, struct Client *client);
extern void client_check_marks(struct Client *client, struct Client *replyto);
extern void client_sendtoserv_privs(struct Client *client);
extern char *client_print_privs(struct Client *client);

extern int client_modify_priv_by_name(struct Client *who, char *priv, int what);
extern int clear_privs(struct Client *who);

#endif /* INCLUDED_client_h */

