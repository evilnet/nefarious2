/** @file s_conf.h
 * @brief ircd configuration file API.
 * @version $Id: s_conf.h 1462 2005-08-21 13:46:08Z entrope $
 */
#ifndef INCLUDED_s_conf_h
#define INCLUDED_s_conf_h
#ifndef INCLUDED_time_h
#include <time.h>              /* struct tm */
#define INCLUDED_time_h
#endif
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>
#define INCLUDED_sys_types_h
#endif
#include "client.h"

struct Client;
struct SLink;
struct Message;

/*
 * General defines
 */

/*-----------------------------------------------------------------------------
 * Macros
 */

#define CONF_ILLEGAL            0x80000000 /**< Delete the ConfItem when no remaining clients. */
#define CONF_CLIENT             0x0002     /**< ConfItem describes a Client block */
#define CONF_SERVER             0x0004     /**< ConfItem describes a Connect block */
#define CONF_OPERATOR           0x0020     /**< ConfItem describes an Operator block */
#define CONF_UWORLD             0x8000     /**< ConfItem describes a Uworld server */

#define CONF_AUTOCONNECT        0x0001     /**< Autoconnect to a server */
#define CONF_SSL                0x0080     /**< Connect using SSL */
#define CONF_NOIDENTTILDE       0x0100     /**< Client should not get a ~ prefix if no ident */

/** Indicates ConfItem types that count associated clients. */
#define CONF_CLIENT_MASK        (CONF_CLIENT | CONF_OPERATOR | CONF_SERVER)

/** Checks whether the CONF_ILLEGAL bit is set on \a x. */
#define IsIllegal(x)    ((x)->status & CONF_ILLEGAL)

/* WEBIRC FlagSet */
enum WebIRCFlag {
  WFLAG_USERIDENT,	/**< use USER username as ident */
  WFLAG_NOIDENT,	/**< ignore ident reply */
  WFLAG_STRIPSSLFP,	/**< strip SSL client certificate fingerprint */
  WFLAG_LAST_FLAG
};

/** Declare flagset type for WEBIRC flags. */
DECLARE_FLAGSET(WebIRCFlags, WFLAG_LAST_FLAG);

/*
 * Structures
 */

/** Configuration item to limit peer or client access. */
struct ConfItem
{
  struct ConfItem *next;    /**< Next ConfItem in #GlobalConfList */
  unsigned int status;      /**< Set of CONF_* bits. */
  unsigned int clients;     /**< Number of *LOCAL* clients using this */
  unsigned int maximum;     /**< For CONF_SERVER, max hops.
                               For CONF_CLIENT, max connects per IP. */
  struct ConnectionClass *conn_class;  /**< Class of connection */
  struct irc_sockaddr origin;  /**< Local address for outbound connections */
  struct irc_sockaddr address; /**< IP and port */
  char *username;     /**< For CONF_CLIENT and CONF_OPERATOR, username mask. */
  char *host;         /**< Peer hostname */
  char *origin_name;  /**< Text form of origin address */
  char *passwd;       /**< Password field */
  char *sslfp;        /**< SSL certificate fingerprint */
  char *name;         /**< Name of peer */
  char *hub_limit;    /**< Mask that limits servers allowed behind
                         this one. */
  char *countrymask;  /**< Mask for country code. */
  char *continentmask; /**< Mask for continent code. */
  time_t hold;        /**< Earliest time to attempt an outbound
                         connect on this ConfItem. */
  int dns_pending;    /**< A dns request is pending. */
  int flags;          /**< Additional modifiers for item. */
  int addrbits;       /**< Number of bits valid in ConfItem::address. */
  unsigned int snomask; /**< Default server notice mask. */
  struct Privs privs; /**< Privileges for opers. */
  /** Used to detect if a privilege has been set by this ConfItem. */
  struct Privs privs_dirty;
};

/** Channel quarantine structure. */
struct qline
{
  struct qline *next; /**< Next qline in #GlobalQuarantineList. */
  char *chname;       /**< Quarantined channel name. */
  char *reason;       /**< Reason for quarantine. */
};

/** Local K-line structure. */
struct DenyConf {
  struct DenyConf*    next;     /**< Next DenyConf in #denyConfList. */
  char*               hostmask; /**< Mask for  IP or hostname. */
  char*               message;  /**< Message to send to denied users. */
  char*               usermask; /**< Mask for client's username. */
  char*               realmask; /**< Mask for realname. */
  char*               countrymask; /**< Mask for country code. */
  char*               continentmask; /**< Mask for continent code. */
  char*               version;  /**< Mask for CTCP version. */
  struct irc_in_addr  address;  /**< Address for IP-based denies. */
  unsigned int        flags;    /**< Interpretation flags for the above.  */
  unsigned char       bits;     /**< Number of bits for ipkills */
};

#define DENY_FLAGS_FILE     0x0001 /**< Comment is a filename */

/** Local server configuration. */
struct LocalConf {
  char*          name;        /**< Name of server. */
  char*          description; /**< Description of server. */
  unsigned int   numeric;     /**< Globally assigned server numnick. */
  char*          location1;   /**< First line of location information. */
  char*          location2;   /**< Second line of location information. */
  char*          contact;     /**< Admin contact information. */
};

enum {
  CRULE_AUTO = 1, /**< CRule applies to automatic connections. */
  CRULE_ALL  = 2, /**< CRule applies to oper-requested connections. */
  CRULE_MASK = 3
};

/** Connection rule configuration. */
struct CRuleConf {
  struct CRuleConf* next;     /**< Next CRule in cruleConfList. */
  char*             hostmask; /**< Mask of affected server names. */
  char*             rule;     /**< Text version of the rule. */
  int               type;     /**< One of CRULE_AUTO or CRULE_ALL. */
  struct CRuleNode* node;     /**< Parsed form of the rule. */
};

/** Authorization check result. */
enum AuthorizationCheckResult {
  ACR_OK,                 /**< User accepted. */
  ACR_NO_AUTHORIZATION,   /**< No matching ConfItem for the user. */
  ACR_TOO_MANY_IN_CLASS,  /**< Connection class was already full. */
  ACR_TOO_MANY_FROM_IP,   /**< User's IP already has max connections. */
  ACR_ALREADY_AUTHORIZED, /**< User already had an attached ConfItem. */
  ACR_BAD_SOCKET          /**< Client has bad file descriptor. */
};

/** Target description for service commands. */
struct nick_host {
  struct nick_host *next; /**< Next nick_host struct in struct s_map. */
  int nicklen;            /**< offset of @ part of server string */
  char nick[1];           /**< start of nick\@server string */
};

#define SMAP_FAST 1           /**< Command does not have MFLG_SLOW. */

/** Target set for a service pseudo-command. */
struct s_map {
  struct s_map *next;         /**< Next element in #GlobalServiceMapList. */
  struct Message *msg;        /**< Message element formed for this mapping. */
  char *name;                 /**< Text name of the mapping. */
  char *command;              /**< Command name to use. */
  char *prepend;              /**< Extra text to prepend to user's text. */
  unsigned int flags;         /**< Bitwise map of SMAP_* flags. */
  struct nick_host *services; /**< Linked list of possible targets. */
};

/* WebIRC configuration. */
struct WebIRCConf {
  struct WebIRCConf*  next;
  char*               hostmask;
  char*               usermask;
  struct irc_in_addr  address;
  unsigned char       bits;
  char*               passwd;
  char*               ident;
  char*               description;
  struct WebIRCFlags  flags;
};

/* SpoofHost configuration. */
struct SHostConf {
  struct SHostConf*   next;
  char*               spoofhost;
  char*               hostmask;
  char*               usermask;
  struct irc_in_addr  address;
  unsigned char       bits;
  char*               passwd;
  int                 flags;
};

#define SHFLAG_AUTOAPPLY 0x1  /* SpoofHost is automatically applied on connect. */
#define SHFLAG_NOPASS    0x2  /* SpoofHost has no password. */
#define SHFLAG_ISMASK    0x4  /* SpoofHost is a wild card host. */

/* Except configuration. */
struct ExceptConf {
  struct ExceptConf*  next;
  char*               hostmask;
  char*               usermask;
  struct irc_in_addr  address;
  unsigned char       bits;
  int                 flags;
};

#define EFLAG_SHUN	0x001	/**< Matching users are exempt from SHUN */
#define EFLAG_KLINE	0x002	/**< Matching users are exempt from Kill blocks */
#define EFLAG_GLINE	0x004	/**< Matching users are exempt from GLINE */
#define EFLAG_ZLINE     0x008   /**< Matching users are exempt from ZLINE */
#define EFLAG_IDENT	0x010	/**< Matching users are exempt from ident lookups */
#define EFLAG_RDNS	0x020	/**< Matching users are exempt from rDNS lookups */
#define EFLAG_IPCHECK   0x040   /**< Matching users are exempt from IPcheck checks */
#define EFLAG_TARGLIMIT 0x080   /**< Matching users are exempt from target limiting */
#define EFLAG_LISTDELAY 0x100   /**< Matching users are exempt from LISTDELAY */

/*
 * GLOBALS
 */
extern struct ConfItem* GlobalConfList;
extern int              GlobalConfCount;
extern struct s_map*    GlobalServiceMapList;
extern struct qline*    GlobalQuarantineList;
extern char *           GlobalForwards[256];

/*
 * Proto types
 */

extern int init_conf(void);

extern const struct LocalConf* conf_get_local(void);
extern const struct CRuleConf* conf_get_crule_list(void);
extern const struct DenyConf*  conf_get_deny_list(void);
extern const struct WebIRCConf* conf_get_webirc_list(void);
extern const struct SHostConf* conf_get_shost_list(void);
extern const struct ExceptConf* conf_get_except_list(void);

extern const char* conf_eval_crule(const char* name, int mask);

extern struct ConfItem* attach_confs_byhost(struct Client* cptr, const char* host, int statmask);
extern struct ConfItem* find_conf_byhost(struct SLink* lp, const char* host, int statmask);
extern struct ConfItem* find_conf_byname(struct SLink* lp, const char *name, int statmask);
extern struct ConfItem* conf_find_server(const char* name);

extern void det_confs_butmask(struct Client *cptr, int mask);
extern enum AuthorizationCheckResult attach_conf(struct Client *cptr, struct ConfItem *aconf);
extern struct ConfItem* find_conf_exact(const char* name, struct Client *cptr, int statmask);
extern enum AuthorizationCheckResult conf_check_client(struct Client *cptr);
extern int  conf_check_server(struct Client *cptr);
extern int rehash(struct Client *cptr, int sig);
extern int find_kill(struct Client *cptr);
extern const char *find_quarantine(const char* chname);
extern void lookup_confhost(struct ConfItem *aconf);
extern void conf_parse_userhost(struct ConfItem *aconf, char *host);
extern struct ConfItem *conf_debug_iline(const char *client);
extern void free_mapping(struct s_map *smap);
extern struct WebIRCConf* find_webirc_conf(struct Client *cptr, char *passwd, int* status);
extern struct SHostConf* find_shost_conf(struct Client *cptr, char *host, char *passwd, int *status);
extern int get_except_flags(struct Client *cptr);
extern int find_except_conf(struct Client *cptr, int flags);
extern int find_except_conf_by_ip(const struct irc_in_addr *addr, int flags);

extern void yyerror(const char *msg);

extern int verify_sslclifp(struct Client* cptr, struct ConfItem* aconf);

#endif /* INCLUDED_s_conf_h */
