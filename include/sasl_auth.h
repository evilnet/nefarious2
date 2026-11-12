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
#ifndef INCLUDED_account_id_h
#include "account_id.h"      /* ACCOUNT_ID_LEN */
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

  /* Keycloak user id of the verified identity, compact ("" = not in hand) */
  char               kc_id[ACCOUNT_ID_LEN + 1];
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
 *  @return 0 on success; -1 when there is no local exchange to continue or
 *  it is not in a state that takes client data (the line is ignored); or
 *  CPTR_KILLED when the exchange ended (or was aborted) inside this call
 *  and the registration it resumed exited or freed \a sptr; the
 *  AUTHENTICATE handler returns it to the parser.
 */
extern int sasl_continue(struct Client *sptr, const char *data);

/** Abort and clean up a local SASL session, and let registration go on.
 *  @return CPTR_KILLED when registration exited or freed \a sptr, else 0.
 */
extern int sasl_abort_local(struct Client *sptr);

/** Free a local SASL session (disconnect cleanup). */
extern void sasl_session_free(struct Client *sptr);

/** Set, as a whole, the identity a login gives a connection (account name,
 *  timestamp, Keycloak id, whether Keycloak confirmed the id); an empty
 *  account clears them all.  Before registration this is what registration
 *  applies with the SASL-complete flag.
 */
extern void sasl_identity_set(struct Client *cptr, const char *account,
                              time_t acc_create, const char *kc_id,
                              int id_live);

/** Is \a cptr logged in, for the rule that a re-authentication never
 *  changes the account: the ircd has applied an account to it -- after
 *  registration, or by registration that has passed its auth stage (a
 *  login waiting for burst convergence, a revived or attached connection).
 *  A login before that is what registration will apply, and a later login
 *  may replace it.
 */
extern int sasl_logged_in(struct Client *cptr);

/** The rule: a login of \a sptr as \a account (Keycloak id \a kc_id, NULL
 *  or invalid for none) when \a sptr is logged in (sasl_logged_in()) must
 *  be its own account -- the same name as the ircd compares account names
 *  and equal but for ASCII letter case (names only the ircd's casemapping
 *  folds together are different accounts) and, when both sides carry a
 *  Keycloak id, the same id (its bouncer session's when it is in one).
 *  Otherwise the client is told (FAIL AUTHENTICATE ALREADY_AUTHENTICATED,
 *  no context, with standard-replies -- the fork's addition -- then 904), the
 *  refusal is logged (accounts only) and the opers told, and 1 is returned:
 *  the caller ends its exchange and applies nothing.  0: not refused.
 */
extern int sasl_reauth_refused(struct Client *sptr, const char *account,
                               const char *kc_id);

/** Complete a successful SASL login.  Shared between local and P10 paths
 *  (and, through sasl_register_login(), REGISTER's success).
 *  Handles: account set, RPL_SASLSUCCESS, metadata load, account-notify,
 *  AC broadcast, hidden host, bouncer alias update, auth_sasl_done.
 *  @return CPTR_KILLED when the registration it resumes last exited or
 *  freed \a sptr (a K-line, a SASL-required class, a bouncer revive), else
 *  0.  The AUTHENTICATE handler returns it to the parser; a caller handling
 *  another connection's line ignores it.  Nothing may touch \a sptr after
 *  CPTR_KILLED.
 */
extern int sasl_complete_login(struct Client *sptr, const char *account,
                               time_t acc_create, const char *kc_id,
                               int id_live);

/** Log in a client whose REGISTER created \a account (e-mail verification
 *  off) as a SASL login would -- draft/account-registration: after REGISTER
 *  SUCCESS the client is "authenticated to the <account> as if it used
 *  SASL" -- with REGISTER SUCCESS in place of 903.  For REGISTER's Keycloak
 *  answer: the registration check is left to the event loop, and a SASL
 *  exchange in flight on the connection is left alone.  The client must
 *  hold no account.
 *  @param[in] acptr Local client that sent the REGISTER.
 *  @param[in] account The account created.
 *  @param[in] kc_id Its compact Keycloak id, from Keycloak in this
 *  registration, or NULL for none.
 */
extern void sasl_register_login(struct Client *acptr, const char *account,
                                const char *kc_id);

/** Broadcast an ACCOUNT (AC) message to other servers for a client whose
 *  account just changed.  Holds the four FEAT_EXTENDED_ACCOUNTS x ts/id
 *  variants; the login's step 7 (a SASL login's and a REGISTER's).
 *  @param[in] cptr Client whose account just changed.
 *  @param[in] type 'R' (register/first login) or 'M' (modify).
 */
extern void sasl_broadcast_account(struct Client *cptr, char type);

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

/** Restart the health retry timer with the current FEAT_SASL_HEALTH_INTERVAL.
 * No-op when the timer isn't running (Keycloak is healthy). */
extern void sasl_health_restart_timer(void);

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
/** Invalidate the positive cache by Keycloak id.  When names is given, the
 * distinct account names of the dropped entries are written to it (up to
 * max) and their count returned: a session that carries no id can still be
 * reached under a name the cache knew. */
extern int sasl_cache_invalidate_id(const char *kc_id,
                                    char names[][ACCOUNTLEN + 1], int max);

/** Get auth cache statistics. */
extern void sasl_cache_stats_get(struct sasl_cache_stats *out);

#endif /* INCLUDED_sasl_auth_h */
