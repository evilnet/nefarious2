/** @file ircd.h
 * @brief Global data for the daemon.
 * @version $Id: ircd.h 1229 2004-10-05 04:14:44Z entrope $
 */
#ifndef INCLUDED_ircd_h
#define INCLUDED_ircd_h
#ifndef INCLUDED_struct_h
#include "struct.h"           /* struct Client */
#endif
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>        /* size_t, time_t */
#endif

/** Describes status for a daemon. */
struct Daemon
{
  int          argc;        /**< Number of command-line arguments. */
  char**       argv;        /**< Array of command-line arguments. */
  pid_t        pid;         /**< %Daemon's process id. */
  uid_t        uid;         /**< %Daemon's user id. */
  uid_t        euid;        /**< %Daemon's effective user id. */
  unsigned int bootopt;     /**< Boot option flags. */
  int          pid_fd;      /**< File descriptor for process id file. */
};

/*
 * Macros
 */
#define TStime() (CurrentTime + TSoffset) /**< Current network time*/
#define OLDEST_TS 780000000	/**< Any TS older than this is bogus */
#define BadPtr(x) (!(x) || (*(x) == '\0')) /**< Is \a x a bad string? */

/* Miscellaneous defines */

#define UDP_PORT        7007  /**< Default port for server-to-server pings. */
#define MINOR_PROTOCOL  "09"    /**< Minimum protocol version supported. */
#define MAJOR_PROTOCOL  "10"    /**< Current protocol version. */
#define BASE_VERSION    "u2.10" /**< Base name of IRC daemon version. */

/*
 * Proto types
 */
extern void server_die(const char* message);
extern void server_panic(const char* message);
extern void server_restart(const char* message);

extern struct Client  me;
extern time_t         CurrentTime;
extern struct Client* GlobalClientList;
extern time_t         TSoffset;
extern int            GlobalRehashFlag;      /* 1 if SIGHUP is received */
extern int            GlobalRestartFlag;     /* 1 if SIGINT is received */
extern char*          configfile;
extern int            debuglevel;
extern char*          debugmode;
extern int	      running;
extern unsigned long  MsgIdCounter;   /**< Counter for unique message IDs */

/** SASL mechanism list received from services (dynamic, for CAP LS) */
#define SASL_MECHS_LEN 128
extern char           SaslMechanisms[SASL_MECHS_LEN];

/** Set the SASL mechanism list (called when services announces mechanisms) */
extern void set_sasl_mechanisms(const char *mechs);
/** Get the SASL mechanism list (for CAP LS value) */
extern const char* get_sasl_mechanisms(void);

/** VAPID public key received from services (for webpush ISUPPORT) */
#define VAPID_KEY_LEN 128
extern char           VapidPublicKey[VAPID_KEY_LEN];

/** Set the VAPID public key (called when services announces it) */
extern void set_vapid_pubkey(const char *key);
/** Get the VAPID public key (for ISUPPORT and CAP value) */
extern const char* get_vapid_pubkey(void);

/** Check if a client-only tag is denied by CLIENTTAGDENY config */
extern int is_client_tag_denied(const char *tag, size_t tag_len);

#endif /* INCLUDED_ircd_h */

