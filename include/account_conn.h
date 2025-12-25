/*
 * IRC - Internet Relay Chat, include/account_conn.h
 * Copyright (C) 2024 AfterNET Development Team
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
 * @brief Account connection registry for presence aggregation.
 *
 * This module tracks all connections logged into each account to enable
 * presence aggregation across multiple devices. When a user has multiple
 * connections to the same account, their effective presence is computed
 * using "most-present-wins" logic:
 *
 * 1. If ANY connection is PRESENT -> account is PRESENT
 * 2. If ALL present connections are AWAY -> use first away message
 * 3. If ALL connections are AWAY_STAR -> account is hidden
 */
#ifndef INCLUDED_account_conn_h
#define INCLUDED_account_conn_h

#ifndef INCLUDED_ircd_defs_h
#include "ircd_defs.h"
#endif
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>
#define INCLUDED_sys_types_h
#endif

struct Client;

/** Size of account connection hash table.
 * Should be a power of 2 for efficient modulo operation.
 */
#define ACCOUNT_CONN_HASHSIZE 4096

/** Away state for a single connection. */
enum ConnAwayState {
  CONN_PRESENT = 0,    /**< Connection is not away */
  CONN_AWAY = 1,       /**< Connection is away with message */
  CONN_AWAY_STAR = 2   /**< Connection is away-star (hidden) */
};

/** Single connection in an account's connection list.
 * Linked list of all connections for a given account.
 */
struct AccountConn {
  struct AccountConn *next;      /**< Next connection for this account */
  struct AccountConn **prev_p;   /**< Pointer to previous->next for O(1) removal */
  struct Client *client;         /**< The client connection */
  enum ConnAwayState away_state; /**< This connection's away state */
  char away_msg[AWAYLEN + 1];    /**< This connection's away message */
};

/** Account entry in the account connection registry.
 * Each unique account has one entry containing all its connections.
 */
struct AccountEntry {
  struct AccountEntry *hnext;             /**< Hash chain for collision handling */
  char account[ACCOUNTLEN + 1];           /**< Account name (hash key) */
  struct AccountConn *connections;        /**< Head of connection list */
  unsigned int conn_count;                /**< Number of connections */
  enum ConnAwayState effective_state;     /**< Computed aggregated presence */
  char effective_away_msg[AWAYLEN + 1];   /**< Current effective away message */
  time_t last_present;                    /**< Last time any conn was present */
};

/** Initialize account connection registry.
 * Called once at server startup.
 */
extern void account_conn_init(void);

/** Add a client to the account connection registry.
 * Creates an account entry if this is the first connection.
 * The client must have IsAccount(cptr) true.
 * @param[in] cptr Client that just got an account
 * @return Pointer to the AccountConn structure, or NULL on error
 */
extern struct AccountConn *account_conn_add(struct Client *cptr);

/** Remove a client from the account connection registry.
 * Frees the account entry if this was the last connection.
 * Recomputes effective presence for remaining connections.
 * @param[in] cptr Client to remove
 * @return 1 if effective presence changed (broadcast needed), 0 otherwise
 */
extern int account_conn_remove(struct Client *cptr);

/** Find account entry by name.
 * @param[in] account Account name to look up
 * @return AccountEntry or NULL if not found
 */
extern struct AccountEntry *account_conn_find(const char *account);

/** Get connection count for an account.
 * @param[in] account Account name
 * @return Number of connections, 0 if account not found
 */
extern unsigned int account_conn_count(const char *account);

/** Update away state for a connection and recompute effective presence.
 * @param[in] cptr Client whose state changed
 * @param[in] state New away state for this connection
 * @param[in] message Away message (can be NULL for PRESENT)
 * @return 1 if effective presence changed (broadcast needed), 0 otherwise
 */
extern int account_conn_set_away(struct Client *cptr,
                                  enum ConnAwayState state,
                                  const char *message);

/** Get effective presence state for an account.
 * @param[in] account Account name
 * @param[out] state Receives effective state (can be NULL)
 * @param[out] message Receives effective away message (can be NULL)
 * @param[in] msg_size Size of message buffer
 * @return 0 on success, -1 if account not found
 */
extern int account_conn_get_presence(const char *account,
                                      enum ConnAwayState *state,
                                      char *message,
                                      size_t msg_size);

/** Get the last time any connection for this account was present.
 * @param[in] account Account name
 * @return Unix timestamp, or 0 if account not found or never present
 */
extern time_t account_conn_last_present(const char *account);

#endif /* INCLUDED_account_conn_h */
