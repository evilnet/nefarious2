/*
 * IRC - Internet Relay Chat, ircd/account_conn.c
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
 * @brief Account connection registry implementation.
 *
 * This module implements presence aggregation for users with multiple
 * connections logged into the same account. It uses a hash table to
 * efficiently track all connections per account and computes the
 * effective presence using "most-present-wins" logic.
 */
#include "config.h"

#include "account_conn.h"
#include "client.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_chattr.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "metadata.h"
#include "struct.h"

#include <stdlib.h>
#include <string.h>

/** Hash table for account entries. */
static struct AccountEntry *accountTable[ACCOUNT_CONN_HASHSIZE];

/** Statistics for debugging. */
static struct {
  unsigned int entries;      /**< Number of account entries */
  unsigned int connections;  /**< Total connections tracked */
} account_conn_stats;

/* Forward declarations for LMDB persistence */
static void persist_last_present(const char *account, time_t when);
static time_t load_last_present(const char *account);

/** Calculate hash value for an account name.
 * Uses a simple FNV-1a hash for case-insensitive account names.
 * @param[in] account Account name to hash
 * @return Hash value in range [0, ACCOUNT_CONN_HASHSIZE-1]
 */
static unsigned int account_hash(const char *account)
{
  unsigned int hash = 2166136261u; /* FNV offset basis */
  const char *p;

  for (p = account; *p; p++) {
    hash ^= (unsigned int)ToLower(*p);
    hash *= 16777619u; /* FNV prime */
  }

  return hash % ACCOUNT_CONN_HASHSIZE;
}

/** Find an account entry in the hash table.
 * @param[in] account Account name to find
 * @return AccountEntry or NULL if not found
 */
static struct AccountEntry *find_entry(const char *account)
{
  unsigned int hashv = account_hash(account);
  struct AccountEntry *entry;

  for (entry = accountTable[hashv]; entry; entry = entry->hnext) {
    if (ircd_strcmp(entry->account, account) == 0)
      return entry;
  }

  return NULL;
}

/** Create a new account entry and add it to the hash table.
 * @param[in] account Account name
 * @return New AccountEntry or NULL on allocation failure
 */
static struct AccountEntry *create_entry(const char *account)
{
  unsigned int hashv = account_hash(account);
  struct AccountEntry *entry;
  time_t persisted_time;

  entry = (struct AccountEntry *)MyCalloc(1, sizeof(struct AccountEntry));
  if (!entry)
    return NULL;

  ircd_strncpy(entry->account, account, ACCOUNTLEN);
  entry->effective_state = CONN_PRESENT; /* Default to present */

  /* Load persisted last_present from LMDB, or use current time */
  persisted_time = load_last_present(account);
  entry->last_present = persisted_time ? persisted_time : CurrentTime;

  /* Add to hash table */
  entry->hnext = accountTable[hashv];
  accountTable[hashv] = entry;

  account_conn_stats.entries++;

  return entry;
}

/** Remove an account entry from the hash table and free it.
 * @param[in] entry Entry to remove
 */
static void remove_entry(struct AccountEntry *entry)
{
  unsigned int hashv = account_hash(entry->account);
  struct AccountEntry *tmp = accountTable[hashv];
  struct AccountEntry **prev_p = &accountTable[hashv];

  while (tmp) {
    if (tmp == entry) {
      *prev_p = entry->hnext;
      account_conn_stats.entries--;
      MyFree(entry);
      return;
    }
    prev_p = &tmp->hnext;
    tmp = tmp->hnext;
  }
}

/** Compute effective presence for an account entry.
 * Uses "most-present-wins" logic:
 * 1. PRESENT beats everything
 * 2. AWAY beats AWAY_STAR
 * 3. AWAY_STAR only if all connections are AWAY_STAR
 *
 * @param[in] entry Account entry to aggregate
 * @return 1 if effective state changed, 0 otherwise
 */
static int compute_effective_presence(struct AccountEntry *entry)
{
  struct AccountConn *conn;
  enum ConnAwayState new_state = CONN_AWAY_STAR;
  const char *best_msg = NULL;
  int changed = 0;

  if (!entry || !entry->connections) {
    /* No connections - shouldn't happen, but handle gracefully */
    return 0;
  }

  /* Scan all connections, most-present-wins */
  for (conn = entry->connections; conn; conn = conn->next) {
    if (conn->away_state == CONN_PRESENT) {
      /* Present beats everything - we're done */
      new_state = CONN_PRESENT;
      best_msg = NULL;
      entry->last_present = CurrentTime;
      break;
    } else if (conn->away_state == CONN_AWAY) {
      /* Away with message beats away-star */
      new_state = CONN_AWAY;
      if (!best_msg && conn->away_msg[0])
        best_msg = conn->away_msg;
    }
    /* AWAY_STAR contributes nothing - it's the default if nothing better */
  }

  /* Check if effective state changed */
  if (entry->effective_state != new_state) {
    changed = 1;
    entry->effective_state = new_state;

    /* Persist last_present when becoming present */
    if (new_state == CONN_PRESENT) {
      persist_last_present(entry->account, entry->last_present);
    }
  }

  /* Update effective message */
  if (new_state == CONN_AWAY && best_msg) {
    if (ircd_strcmp(entry->effective_away_msg, best_msg) != 0) {
      changed = 1;
      ircd_strncpy(entry->effective_away_msg, best_msg, AWAYLEN);
    }
  } else if (new_state == CONN_PRESENT || new_state == CONN_AWAY_STAR) {
    if (entry->effective_away_msg[0]) {
      entry->effective_away_msg[0] = '\0';
      /* Message clearing doesn't count as a change for broadcast purposes */
    }
  }

  return changed;
}

/*
 * Public API implementations
 */

void account_conn_init(void)
{
  memset(accountTable, 0, sizeof(accountTable));
  memset(&account_conn_stats, 0, sizeof(account_conn_stats));

  log_write(LS_SYSTEM, L_DEBUG, 0,
            "account_conn: initialized with hash size %d",
            ACCOUNT_CONN_HASHSIZE);
}

struct AccountConn *account_conn_add(struct Client *cptr)
{
  struct AccountEntry *entry;
  struct AccountConn *conn;
  const char *account;

  if (!cptr || !IsAccount(cptr))
    return NULL;

  account = cli_account(cptr);
  if (!account || !account[0] || account[0] == '0')
    return NULL;

  /* Find or create account entry */
  entry = find_entry(account);
  if (!entry) {
    entry = create_entry(account);
    if (!entry)
      return NULL;
  }

  /* Check if already added (shouldn't happen) */
  for (conn = entry->connections; conn; conn = conn->next) {
    if (conn->client == cptr) {
      log_write(LS_SYSTEM, L_WARNING, 0,
                "account_conn_add: client %C already in registry for %s",
                cptr, account);
      return conn;
    }
  }

  /* Create new connection entry */
  conn = (struct AccountConn *)MyCalloc(1, sizeof(struct AccountConn));
  if (!conn)
    return NULL;

  conn->client = cptr;
  conn->away_state = CONN_PRESENT; /* Default to present */

  /* Check if client already has away state from pre-away */
  if (cli_user(cptr) && cli_user(cptr)->away) {
    conn->away_state = CONN_AWAY;
    ircd_strncpy(conn->away_msg, cli_user(cptr)->away, AWAYLEN);
  }

  /* Add to head of connection list */
  conn->next = entry->connections;
  if (entry->connections)
    entry->connections->prev_p = &conn->next;
  conn->prev_p = &entry->connections;
  entry->connections = conn;

  entry->conn_count++;
  account_conn_stats.connections++;

  /* Store back-reference in client for O(1) lookup */
  if (cli_user(cptr))
    cli_user(cptr)->account_conn = conn;

  /* Recompute effective presence */
  compute_effective_presence(entry);

  log_write(LS_SYSTEM, L_DEBUG, 0,
            "account_conn_add: added %C to account %s (count: %u)",
            cptr, account, entry->conn_count);

  return conn;
}

int account_conn_remove(struct Client *cptr)
{
  struct AccountEntry *entry;
  struct AccountConn *conn;
  const char *account;
  int changed = 0;

  if (!cptr || !IsAccount(cptr))
    return 0;

  account = cli_account(cptr);
  if (!account || !account[0] || account[0] == '0')
    return 0;

  entry = find_entry(account);
  if (!entry)
    return 0;

  /* Find this client's connection */
  for (conn = entry->connections; conn; conn = conn->next) {
    if (conn->client == cptr)
      break;
  }

  if (!conn) {
    log_write(LS_SYSTEM, L_WARNING, 0,
              "account_conn_remove: client %C not found in registry for %s",
              cptr, account);
    return 0;
  }

  /* Remove from linked list */
  if (conn->next)
    conn->next->prev_p = conn->prev_p;
  *conn->prev_p = conn->next;

  entry->conn_count--;
  account_conn_stats.connections--;

  /* Clear back-reference */
  if (cli_user(cptr))
    cli_user(cptr)->account_conn = NULL;

  MyFree(conn);

  log_write(LS_SYSTEM, L_DEBUG, 0,
            "account_conn_remove: removed %C from account %s (remaining: %u)",
            cptr, account, entry->conn_count);

  /* If last connection, remove the entry */
  if (entry->conn_count == 0) {
    remove_entry(entry);
    /* Effective state becomes undefined, but there's no one to broadcast to */
    return 0;
  }

  /* Recompute effective presence */
  changed = compute_effective_presence(entry);

  return changed;
}

struct AccountEntry *account_conn_find(const char *account)
{
  if (!account || !account[0])
    return NULL;

  return find_entry(account);
}

unsigned int account_conn_count(const char *account)
{
  struct AccountEntry *entry = find_entry(account);

  return entry ? entry->conn_count : 0;
}

int account_conn_set_away(struct Client *cptr,
                           enum ConnAwayState state,
                           const char *message)
{
  struct AccountEntry *entry;
  struct AccountConn *conn;
  const char *account;

  if (!cptr || !IsAccount(cptr))
    return 0;

  account = cli_account(cptr);
  if (!account || !account[0] || account[0] == '0')
    return 0;

  entry = find_entry(account);
  if (!entry)
    return 0;

  /* Find this client's connection */
  for (conn = entry->connections; conn; conn = conn->next) {
    if (conn->client == cptr)
      break;
  }

  if (!conn) {
    log_write(LS_SYSTEM, L_WARNING, 0,
              "account_conn_set_away: client %C not in registry for %s",
              cptr, account);
    return 0;
  }

  /* Update this connection's state */
  conn->away_state = state;
  if (message && message[0]) {
    ircd_strncpy(conn->away_msg, message, AWAYLEN);
  } else {
    conn->away_msg[0] = '\0';
  }

  /* Recompute and return whether effective changed */
  return compute_effective_presence(entry);
}

int account_conn_get_presence(const char *account,
                               enum ConnAwayState *state,
                               char *message,
                               size_t msg_size)
{
  struct AccountEntry *entry = find_entry(account);

  if (!entry)
    return -1;

  if (state)
    *state = entry->effective_state;

  if (message && msg_size > 0) {
    ircd_strncpy(message, entry->effective_away_msg, msg_size - 1);
    message[msg_size - 1] = '\0';
  }

  return 0;
}

time_t account_conn_last_present(const char *account)
{
  struct AccountEntry *entry = find_entry(account);

  if (entry)
    return entry->last_present;

  /* Try to load from LMDB if account not in memory */
  if (metadata_lmdb_is_available()) {
    char value[32];
    if (metadata_account_get(account, "$last_present", value) == 0) {
      return (time_t)strtoul(value, NULL, 10);
    }
  }

  return 0;
}

/** Persist last_present timestamp to LMDB.
 * @param[in] account Account name.
 * @param[in] when Timestamp to persist.
 */
static void persist_last_present(const char *account, time_t when)
{
  char value[32];

  if (!metadata_lmdb_is_available())
    return;

  ircd_snprintf(0, value, sizeof(value), "%lu", (unsigned long)when);
  metadata_account_set(account, "$last_present", value);
}

/** Load last_present timestamp from LMDB.
 * @param[in] account Account name.
 * @return Timestamp or 0 if not found.
 */
static time_t load_last_present(const char *account)
{
  char value[32];

  if (!metadata_lmdb_is_available())
    return 0;

  if (metadata_account_get(account, "$last_present", value) == 0) {
    return (time_t)strtoul(value, NULL, 10);
  }

  return 0;
}
