/** @file IPcheck.h
 * @brief Interface to count users connected from particular IP addresses.
 * @version $Id: IPcheck.h 1329 2005-03-19 23:22:09Z entrope $
 */
#ifndef INCLUDED_ipcheck_h
#define INCLUDED_ipcheck_h

#ifndef INCLUDED_sys_types_h
#include <sys/types.h>          /* time_t, size_t */
#define INCLUDED_sys_types_h
#endif

#ifndef INCLUDED_res_h
#include "res.h"              /* struct irc_in_addr */
#endif

struct Client;
struct StatDesc;

/** Why IPcheckInfo::would_refuse refuses (0: the connection is accepted). */
enum IPcheckRefusal {
  IPCHECK_REFUSE_NONE = 0,
  IPCHECK_REFUSE_WINDOW,      /**< The chain is at its limit; retry_in counts down. */
  IPCHECK_REFUSE_OVERFLOW,    /**< The live count is full until one leaves. */
  IPCHECK_REFUSE_LIMIT        /**< IPCHECK_CLONE_LIMIT refuses even a fresh chain. */
};

/** What the registry holds for one address (STATS ipcheck). */
struct IPcheckInfo {
  struct irc_in_addr key;     /**< The entry's key, in canonical form. */
  unsigned int connected;     /**< Clients counted as connected from it. */
  unsigned int attempts;      /**< Connection attempts in its current chain. */
  unsigned int since;         /**< Seconds since its last connect or last drop, modulo 65536. */
  int has_targets;            /**< Free-target state is kept for it. */
  unsigned int free_targets;  /**< That free-target count (STARTTARGETS if none). */
  int would_refuse;           /**< Whether, and why, its next local connection would be refused (enum IPcheckRefusal). */
  unsigned int retry_in;      /**< For IPCHECK_REFUSE_WINDOW, seconds until it would not be. */
};

/*
 * Prototypes
 */
extern void IPcheck_init(void);
extern int IPcheck_local_connect(const struct irc_in_addr *ip, time_t *next_target_out);
extern void IPcheck_connect_fail(const struct Client *cptr, int disconnect);
extern void IPcheck_connect_succeeded(struct Client *cptr);
extern void IPcheck_login_refund(struct Client *cptr, const char *account);
extern int IPcheck_remote_connect(struct Client *cptr, int is_burst);
extern void IPcheck_disconnect(struct Client *cptr);
extern unsigned short IPcheck_nr(struct Client* cptr);
extern int IPcheck_lookup(const struct irc_in_addr *addr, struct IPcheckInfo *info);
extern void IPcheck_report(struct Client *to, const struct StatDesc *sd, char *param);

#endif /* INCLUDED_ipcheck_h */
