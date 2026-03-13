/*
 * IRC - Internet Relay Chat, include/sasl_auth.h
 * Copyright (C) 2026 Afternet Development
 *
 * Local SASL authentication via Keycloak (libkc).
 * Handles SASL PLAIN (and later EXTERNAL, OAUTHBEARER, SCRAM)
 * directly in the IRCd without relaying through X3 services.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
 * any later version.
 */
#ifndef INCLUDED_sasl_auth_h
#define INCLUDED_sasl_auth_h

#ifndef INCLUDED_ircd_defs_h
#include "ircd_defs.h"
#endif
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>
#define INCLUDED_sys_types_h
#endif
#include <stdint.h>

struct Client;

/** SASL mechanism types. */
enum SASLMechanism {
  SASL_MECH_NONE = 0,
  SASL_MECH_PLAIN,
  SASL_MECH_EXTERNAL,
  SASL_MECH_OAUTHBEARER,   /**< Phase 2 */
  SASL_MECH_SCRAM_SHA256,  /**< Phase 3 */
  SASL_MECH_ECDSA,         /**< Phase 3 */
};

/** SASL session state. */
enum SASLState {
  SASL_STATE_NONE = 0,
  SASL_STATE_INIT,          /**< Mechanism selected, waiting for data */
  SASL_STATE_WAITING_DATA,  /**< Accumulating chunked data */
  SASL_STATE_WAITING_KC,    /**< Async Keycloak request in flight */
  SASL_STATE_SCRAM_SENT,    /**< SCRAM: server-first sent, waiting for client-final */
  SASL_STATE_SCRAM_VERIFY,  /**< SCRAM: server-final sent, waiting for client ack */
  SASL_STATE_COMPLETE,
  SASL_STATE_FAILED,
};

/** Maximum accumulated SASL data (base64). 400 * 10 chunks = 4000 bytes. */
#define SASL_DATA_MAX 4096

/** SASL session state, attached to a client during authentication. */
struct SASLSession {
  enum SASLMechanism mech;
  enum SASLState     state;
  char              *accumulated_data;  /**< Base64-encoded accumulated chunks */
  size_t             data_len;
  size_t             data_alloc;
  int                chunks_received;
  char               authcid[ACCOUNTLEN + 1];  /**< Authentication identity */
  char               authzid[ACCOUNTLEN + 1];  /**< Authorization identity (may differ) */

  /* Auth cache credential hash (PLAIN only) */
  uint64_t           cred_hash;          /**< SipHash of username+password */
  int                cred_hash_valid;    /**< Whether cred_hash is populated */

  /* SCRAM-SHA-256 state (Phase 3) */
  char              *scram_client_first_bare;  /**< "n=user,r=client_nonce" */
  char              *scram_server_first;       /**< "r=combined,s=salt,i=iter" */
  char              *scram_combined_nonce;      /**< Server's full nonce */
  unsigned char      scram_stored_key[32];     /**< Binary StoredKey from KC */
  unsigned char      scram_server_key[32];     /**< Binary ServerKey from KC */
  char              *scram_salt_b64;           /**< Base64 salt from KC */
  int                scram_iterations;         /**< Iteration count from KC */

  /* Account creation timestamp from Keycloak (epoch secs, 0 = unknown) */
  time_t             acc_created_at;
};

/** Heap-allocated context for async Keycloak callbacks.
 *  NEVER pass raw struct Client * to async callbacks — the client
 *  may disconnect while a request is in flight.  Instead, pass this
 *  context and re-resolve the client via LocalClientArray[fd] + cookie
 *  validation in the callback.
 */
struct sasl_cb_ctx {
  unsigned int fd;      /**< Client file descriptor */
  unsigned int cookie;  /**< SASL session cookie for FD-reuse protection */
};

/* ---- Public API ---- */

/** Start a local SASL session.
 *  @return 0 on success, -1 if Keycloak unavailable (fall through to P10).
 */
extern int sasl_start(struct Client *sptr, const char *mechanism);

/** Process AUTHENTICATE data (may be chunked).
 *  @return 0 on success.
 */
extern int sasl_continue(struct Client *sptr, const char *data);

/** Abort and clean up a local SASL session.
 *  @return 0.
 */
extern int sasl_abort_local(struct Client *sptr);

/** Free a local SASL session (disconnect cleanup). */
extern void sasl_session_free(struct Client *sptr);

/** Complete a successful SASL login.  Shared between local and P10 paths.
 *  Handles: account set, RPL_SASLSUCCESS, metadata load, account-notify,
 *  AC broadcast, hidden host, bouncer alias update, auth_sasl_done.
 */
extern void sasl_complete_login(struct Client *sptr, const char *account,
                                time_t acc_create);

/** Get the local SASL mechanism list string for CAP advertisement.
 *  @return Comma-separated mechanism string, or NULL if none.
 */
extern const char *sasl_local_mechanisms(void);

/** Check if local Keycloak SASL is available.
 *  @return 1 if available, 0 otherwise.
 */
extern int sasl_local_available(void);

/** Initialize the local SASL subsystem (called from ircd.c after kc_keycloak_init).
 *  @return 0 on success, -1 on failure.
 */
extern int sasl_local_init(void);

/** Periodic health check callback — call from a timer to probe Keycloak liveness. */
extern void sasl_health_check(void);

/* ---- Auth cache API (for webhook invalidation and stats) ---- */

/** Auth cache statistics. */
struct sasl_cache_stats {
  unsigned long neg_hits;
  unsigned long neg_misses;
  unsigned long neg_inserts;
  unsigned long neg_invalidations;
  unsigned long neg_expirations;
  unsigned long pos_hits;
  unsigned long pos_misses;
  unsigned long pos_inserts;
  unsigned long pos_invalidations;
  unsigned long pos_expirations;
};

/** Invalidate all auth cache entries for a user (called from webhook handler). */
extern void sasl_cache_invalidate_user(const char *username);

/** Get auth cache statistics. */
extern void sasl_cache_stats_get(struct sasl_cache_stats *out);

#endif /* INCLUDED_sasl_auth_h */
