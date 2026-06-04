/** @file
 * @brief Interface and declarations for client counting functions.
 * @version $Id: querycmds.h 1212 2004-10-03 17:02:23Z entrope $
 */
#ifndef INCLUDED_querycmds_h
#define INCLUDED_querycmds_h

#ifndef INCLUDED_ircd_features_h
#include "ircd_features.h"	/* feature_str() */
#endif

struct Client;

/*
 * Structs
 */

/** Counts types of clients, servers, etc.\ on the network. */
struct UserStatistics {
  /* Local connections: */
  unsigned int unknowns;  /**< Clients of types: unknown, connecting, handshake */
  unsigned int local_servers;   /**< Directly connected servers. */
  unsigned int local_clients;   /**< Directly connected clients (sockets, including bouncer aliases). */
  unsigned int local_clients_max; /**< Maximum number of Directly connected clients. */

  /* Global counts: */
  unsigned int servers;         /**< Known servers, including #me. */
  unsigned int clients;         /**< Registered users (includes our local aliases — see note). */
  unsigned int clients_max;     /**< Maximum number of Registered users. */

  /* Network-visible (N-token) counts — exclude bouncer aliases.
   * RPL_CURRENT_LOCAL / RPL_CURRENT_GLOBAL display these so the
   * advertised user count matches what peers actually see on the
   * wire.  Aliases come in via BX C (not N) and don't bump
   * announced_*; held ghosts stay counted (still N-visible). */
  unsigned int local_announced_clients;     /**< Local primaries + held ghosts (N-announced from this server). */
  unsigned int local_announced_clients_max; /**< Maximum number of local announced clients. */
  unsigned int announced_clients;           /**< Network-wide N-announced users. */
  unsigned int announced_clients_max;       /**< Maximum number of network-wide announced users. */

  /* Global user mode changes: */
  unsigned int inv_clients;     /**< Registered invisible users. */
  unsigned int opers;           /**< Registered IRC operators. */

  /* Misc: */
  unsigned int channels;        /**< Existing channels. */
};

extern struct UserStatistics UserStats;

/*
 * Macros
 */

/* Macros for remote connections: */
/** Count \a cptr as a new remote client.
 *
 * Bumps clients (socket/identity count) and announced_clients
 * (N-token count) symmetrically — Count_newremoteclient is only
 * reached via the N-token receive path (see m_nick.c:1101), and N
 * is by construction the "this is a network-visible user"
 * announcement.  Bouncer aliases arrive via BX C and do NOT go
 * through this macro. */
#define Count_newremoteclient(UserStats, cptr) \
  do { \
    ++UserStats.clients; \
    ++(cli_serv(cptr)->clients); \
    ++UserStats.announced_clients; \
    if (UserStats.clients > UserStats.clients_max) { \
      UserStats.clients_max = UserStats.clients; \
      save_tunefile(); \
    } \
    if (UserStats.announced_clients > UserStats.announced_clients_max) { \
      UserStats.announced_clients_max = UserStats.announced_clients; \
      save_tunefile(); \
    } \
  } while (0)
/** Count a new remote server. */
#define Count_newremoteserver(UserStats)  (++UserStats.servers)

/** Count a remote user quit.
 *
 * Decrements clients (sockets) unconditionally.  announced_clients
 * decrements only if cptr is NOT a bouncer alias — aliases were
 * never counted in announced_clients (they came via BX C, not N).
 * The BX-X exit path for aliases reuses this macro for the
 * non-announced sides; gating the announced decrement on
 * !IsBouncerAlias prevents underflow. */
#define Count_remoteclientquits(UserStats,cptr)                \
  do { \
    --UserStats.clients; \
    if (!IsServer(cptr)) \
      --(cli_serv(cli_user(cptr)->server)->clients); \
    if (!IsServer(cptr) && !IsBouncerAlias(cptr)) \
      --UserStats.announced_clients; \
  } while (0)

/** Count a remote server quit. */
#define Count_remoteserverquits(UserStats)      (--UserStats.servers)

/** Underflow guard helper for Count_unknown* decrement macros. */
void count_unknowns_underflow(const char *file, int line, const char *what);

/** Decrement UserStats.unknowns with underflow detection.
 * If the counter is already zero, log + skip the decrement and snotice
 * the offending caller's file:line so the source of the imbalance can be
 * traced rather than silently wrapping to UINT_MAX.
 */
#define DEC_UNKNOWNS_GUARDED(what) \
  do { \
    if (UserStats.unknowns == 0) \
      count_unknowns_underflow(__FILE__, __LINE__, (what)); \
    else \
      --UserStats.unknowns; \
  } while (0)

/* Macros for local connections: */
/** Count a new local unknown connection. */
#define Count_newunknown(UserStats)                     (++UserStats.unknowns)
/** Update counters when \a cptr goes from unknown to registered. */
#define Count_unknownbecomesclient(cptr, UserStats) \
  do { \
    DEC_UNKNOWNS_GUARDED("becomesclient"); \
    ++UserStats.local_clients; ++UserStats.clients; \
    /* Announced counters: register_user fires for primaries only.   \
     * Aliases are converted from this state by                       \
     * bounce_setup_local_alias which decrements the announced       \
     * counters after the conversion.  No IsBouncerAlias gate needed \
     * here — the flag isn't set yet at register_user time. */       \
    ++UserStats.local_announced_clients; \
    ++UserStats.announced_clients; \
    if (match(feature_str(FEAT_DOMAINNAME), cli_sockhost(cptr)) == 0) \
      ++current_load.local_count; \
    if (UserStats.local_clients > max_client_count) \
      max_client_count = UserStats.local_clients; \
    if (UserStats.local_clients > UserStats.local_clients_max) { \
      UserStats.local_clients_max = UserStats.local_clients; \
      save_tunefile(); \
    } \
    if (UserStats.clients > UserStats.clients_max) { \
      UserStats.clients_max = UserStats.local_clients_max; \
      save_tunefile(); \
    } \
    if (UserStats.local_announced_clients > UserStats.local_announced_clients_max) { \
      UserStats.local_announced_clients_max = UserStats.local_announced_clients; \
      save_tunefile(); \
    } \
    if (UserStats.announced_clients > UserStats.announced_clients_max) { \
      UserStats.announced_clients_max = UserStats.announced_clients; \
      save_tunefile(); \
    } \
    if (UserStats.local_clients + UserStats.local_servers > max_connection_count) \
    { \
      max_connection_count = UserStats.local_clients + UserStats.local_servers; \
      if (max_connection_count % 10 == 0) \
        sendto_opmask_butone(0, SNO_OLDSNO, "Maximum connections: %d (%d clients)", \
            max_connection_count, max_client_count); \
    } \
  } while(0)
/** Update counters when \a cptr goes from unknown to server. */
#define Count_unknownbecomesserver(UserStats) \
  do { DEC_UNKNOWNS_GUARDED("becomesserver"); ++UserStats.local_servers; ++UserStats.servers; } while(0)
/** Update counters when \a cptr (a local user) disconnects.
 *
 * `local_clients` and `current_load.local_count` are socket-side
 * counters — gated on `!IsNoLcDecrement(cptr)`.  The flag is set
 * when local_clients is already settled for this Client (decremented
 * at bounce_hold_client, or never bumped for boot-spawned ghosts),
 * and cleared by bounce_revive when a fresh socket attaches and
 * bumps local_clients again.  Without this gate, destroy paths
 * for held ghosts would double-decrement (once at hold, again at
 * destroy via this macro).  Cannot use cli_fd >= 0 as the gate —
 * exit_client closes the socket before reaching this macro, so
 * cli_fd is -1 by the time we get here for every destroy.
 *
 * `clients` is the registered-user count (network-wide identity
 * tally) and decrements unconditionally on every destroy — ghosts
 * ARE counted there from their creation through destroy.
 *
 * Announced counters decrement only if cptr is NOT a bouncer alias
 * — aliases got their announced bump at register_user but had it
 * removed by bounce_setup_local_alias when they were converted.
 * Held ghosts (IsBouncerHold) ARE still announced and need the
 * decrement on destroy. */
#define Count_clientdisconnects(cptr, UserStats) \
  do \
  { \
    --UserStats.clients; \
    if (!IsNoLcDecrement(cptr)) \
      --UserStats.local_clients; \
    if (!IsBouncerAlias(cptr)) { \
      --UserStats.local_announced_clients; \
      --UserStats.announced_clients; \
    } \
    if (!IsNoLcDecrement(cptr) \
        && match(feature_str(FEAT_DOMAINNAME), cli_sockhost(cptr)) == 0) \
      --current_load.local_count; \
  } while(0)
/** Update counters when a local server disconnects. */
#define Count_serverdisconnects(UserStats)              do { --UserStats.local_servers; --UserStats.servers; } while(0)
/** Update counters when an unknown client disconnects. */
#define Count_unknowndisconnects(UserStats)             DEC_UNKNOWNS_GUARDED("unknowndisconnects")

/*
 * Prototypes
 */

void load_tunefile(void);
void save_tunefile(void);

#endif /* INCLUDED_querycmds_h */
