/*
 * IRC - Internet Relay Chat, ircd/m_markread.c
 * Copyright (C) 2024 Nefarious Development Team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
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
 * @brief Handler for MARKREAD command (IRCv3 draft/read-marker).
 *
 * Specification: https://ircv3.net/specs/extensions/read-marker
 *
 * Client Protocol (ISO 8601 timestamps per IRCv3 spec):
 *   MARKREAD <target> [timestamp=YYYY-MM-DDThh:mm:ss.sssZ]
 *
 * This implementation routes read markers through X3 services for
 * authoritative storage and multi-device synchronization.
 *
 * P10 Protocol (Unix timestamps for S2S):
 *   SET: [SERVER] MR S <user_numeric> <target> <unix_timestamp>
 *   GET: [SERVER] MR G <user_numeric> <target>
 *   REPLY: [X3] MR R <target_server> <user_numeric> <target> <unix_timestamp>
 *   BROADCAST: [X3] MR <account> <target> <unix_timestamp>
 *
 * Timestamps are stored internally as Unix (seconds.milliseconds) and
 * converted to ISO 8601 only for client-facing protocol.
 */
#include "config.h"

#include "capab.h"
#include "client.h"
#include "hash.h"
#include "history.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_user.h"
#include "send.h"

#include <string.h>
#include <stdlib.h>

/** Maximum timestamp length */
#define MARKREAD_TS_LEN 32

/** Parse timestamp= parameter from client argument.
 * Extracts ISO 8601 timestamp and converts to Unix timestamp for internal use.
 * @param[in] arg Argument string (e.g., "timestamp=2025-01-01T00:00:00.000Z")
 * @param[out] unix_ts Buffer for Unix timestamp (seconds.milliseconds).
 * @param[in] tslen Size of unix_ts buffer.
 * @return 1 if found and valid format, 0 otherwise.
 */
static int parse_timestamp_param(const char *arg, char *unix_ts, size_t tslen)
{
  const char *eq;
  char iso_ts[32];

  if (!arg)
    return 0;

  /* Check for "timestamp=" prefix */
  if (ircd_strncmp(arg, "timestamp=", 10) != 0)
    return 0;

  eq = arg + 10;

  /* Basic validation: must be at least YYYY-MM-DDThh:mm:ss format */
  if (strlen(eq) < 19)
    return 0;

  /* Check for 'T' separator */
  if (eq[10] != 'T')
    return 0;

  /* Copy ISO timestamp */
  ircd_strncpy(iso_ts, eq, sizeof(iso_ts) - 1);
  iso_ts[sizeof(iso_ts) - 1] = '\0';

  /* Convert to Unix timestamp for internal use */
  if (history_iso_to_unix(iso_ts, unix_ts, tslen) != 0)
    return 0;

  return 1;
}

/** Send MARKREAD response to a client.
 * Converts internal Unix timestamp to ISO 8601 for client display.
 * @param[in] to Client to send to.
 * @param[in] target Channel or nick.
 * @param[in] unix_ts Unix timestamp (or "*" if unknown).
 */
static void send_markread(struct Client *to, const char *target, const char *unix_ts)
{
  char iso_ts[32];

  /* Format: MARKREAD <target> timestamp=<ts>
   * The timestamp can be "*" if unknown.
   */
  if (!unix_ts || !*unix_ts || *unix_ts == '*') {
    sendrawto_one(to, "MARKREAD %s timestamp=*", target);
  } else if (history_unix_to_iso(unix_ts, iso_ts, sizeof(iso_ts)) == 0) {
    sendrawto_one(to, "MARKREAD %s timestamp=%s", target, iso_ts);
  } else {
    /* Conversion failed - send as-is (might already be ISO or invalid) */
    sendrawto_one(to, "MARKREAD %s timestamp=%s", target, unix_ts);
  }
}

/** Notify all local clients with matching account about a read marker update.
 * @param[in] account Account name.
 * @param[in] target Channel or nick.
 * @param[in] unix_ts Unix timestamp (will be converted to ISO for clients).
 */
static void notify_local_clients(const char *account, const char *target, const char *timestamp)
{
  struct Client *acptr;

  if (!account || !*account)
    return;

  /* Find all local clients with the same account */
  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr)) {
    if (!IsUser(acptr) || !MyUser(acptr))
      continue;
    if (!CapActive(acptr, CAP_DRAFT_READMARKER))
      continue;
    if (!cli_user(acptr) || !cli_user(acptr)->account[0])
      continue;
    if (ircd_strcmp(cli_user(acptr)->account, account) != 0)
      continue;

    send_markread(acptr, target, timestamp);
  }
}

/** Find the services server.
 * @return Services server client or NULL if not found.
 */
static struct Client *find_services_server(void)
{
  struct Client *acptr;

  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr)) {
    if (IsServer(acptr) && IsService(acptr))
      return acptr;
  }
  return NULL;
}

/** m_markread - Handle MARKREAD command from local client.
 *
 * parv[0] = sender prefix
 * parv[1] = target (channel or nick)
 * parv[2] = timestamp=YYYY-MM-DDThh:mm:ss.sssZ (optional)
 *
 * If timestamp is provided: set read marker (send to X3)
 * If no timestamp: query current read marker (from local cache or X3)
 *
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int m_markread(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  const char *target;
  const char *account;
  char timestamp[MARKREAD_TS_LEN];
  char stored_ts[MARKREAD_TS_LEN];
  struct Client *services;
  int rc;

  /* Must have draft/read-marker capability */
  if (!CapActive(sptr, CAP_DRAFT_READMARKER)) {
    return send_reply(sptr, ERR_UNKNOWNCOMMAND, "MARKREAD");
  }

  /* Must be logged in */
  if (!cli_user(sptr) || !cli_user(sptr)->account[0]) {
    send_fail(sptr, "MARKREAD", "ACCOUNT_REQUIRED", NULL,
              "You must be logged in to use MARKREAD");
    return 0;
  }

  account = cli_user(sptr)->account;

  /* Need at least target */
  if (parc < 2 || EmptyString(parv[1])) {
    send_fail(sptr, "MARKREAD", "NEED_MORE_PARAMS", NULL,
              "Missing target parameter");
    return 0;
  }

  target = parv[1];

  /* Find services for forwarding */
  services = find_services_server();

  /* Check if timestamp is provided (SET operation) */
  if (parc >= 3 && parse_timestamp_param(parv[2], timestamp, sizeof(timestamp))) {
    /* SET operation: send to X3 for storage and broadcast */

    if (services) {
      /* Forward to X3: MR S <user_numeric> <target> <timestamp>
       * X3 will store and broadcast back to all servers
       */
      sendcmdto_one(&me, CMD_MARKREAD, services, "S %C %s %s",
                    sptr, target, timestamp);
    }

    /* Also store locally in LMDB as cache (if available) */
    if (history_is_available()) {
      rc = readmarker_set(account, target, timestamp);
      if (rc == 0) {
        /* Successfully updated locally - notify local clients immediately */
        notify_local_clients(account, target, timestamp);
      } else if (rc == 1) {
        /* Timestamp was not newer - respond with current stored value */
        rc = readmarker_get(account, target, stored_ts);
        if (rc == 0) {
          send_markread(sptr, target, stored_ts);
        } else {
          send_markread(sptr, target, timestamp);
        }
      } else {
        /* Error storing - still notify client of what they sent */
        send_markread(sptr, target, timestamp);
      }
    } else if (!services) {
      /* No services and no LMDB - cannot store */
      send_fail(sptr, "MARKREAD", "TEMPORARILY_UNAVAILABLE", target,
                "Read marker storage is not available");
    } else {
      /* No LMDB but have services - notify the sending client */
      send_markread(sptr, target, timestamp);
    }
  } else {
    /* GET operation: query current timestamp from local cache */
    if (history_is_available()) {
      rc = readmarker_get(account, target, stored_ts);
      if (rc == 0) {
        send_markread(sptr, target, stored_ts);
      } else if (rc == 1) {
        /* Not found locally */
        if (services) {
          /* Query X3: MR G <user_numeric> <target> */
          sendcmdto_one(&me, CMD_MARKREAD, services, "G %C %s", sptr, target);
          /* Response will come back via ms_markread */
        } else {
          /* No services, no local data - send "*" */
          send_markread(sptr, target, "*");
        }
      } else {
        send_fail(sptr, "MARKREAD", "INTERNAL_ERROR", target,
                  "Could not retrieve read marker");
      }
    } else if (services) {
      /* No LMDB, query X3 */
      sendcmdto_one(&me, CMD_MARKREAD, services, "G %C %s", sptr, target);
    } else {
      send_fail(sptr, "MARKREAD", "TEMPORARILY_UNAVAILABLE", target,
                "Read marker storage is not available");
    }
  }

  return 0;
}

/** ms_markread - Handle MARKREAD command from server.
 *
 * P10 formats:
 *   Broadcast from X3: MR <account> <target> <timestamp>
 *   Reply to query:    MR R <target_server> <user_numeric> <target> <timestamp>
 *   Forward set:       MR S <user_numeric> <target> <timestamp>
 *   Forward get:       MR G <user_numeric> <target>
 *
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message (X3 or another server).
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int ms_markread(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  const char *subcmd;
  const char *account;
  const char *target;
  const char *timestamp;
  struct Client *acptr;
  struct Client *services;
  int is_from_services = 0;

  if (parc < 2)
    return 0;

  /* Check if this is from a services server */
  if (IsServer(sptr) && IsService(sptr)) {
    is_from_services = 1;
  } else if (!IsServer(sptr) && cli_user(sptr) &&
             cli_user(sptr)->server && IsService(cli_user(sptr)->server)) {
    is_from_services = 1;
  }

  subcmd = parv[1];

  /* Check for subcmd-style messages (S, G, R) */
  if (subcmd[0] == 'S' && subcmd[1] == '\0') {
    /* SET forward: MR S <user_numeric> <target> <timestamp> */
    if (parc < 5)
      return 0;

    /* Find the user */
    acptr = findNUser(parv[2]);
    if (!acptr || !IsUser(acptr))
      return 0;

    target = parv[3];
    timestamp = parv[4];
    account = cli_user(acptr)->account;

    if (!account || !*account)
      return 0;

    /* If not from services, forward toward X3 (multi-hop routing) */
    services = find_services_server();
    if (!is_from_services) {
      if (services) {
        /* Forward toward X3 - sendcmdto_one routes through intermediate servers */
        sendcmdto_one(sptr, CMD_MARKREAD, services, "S %s %s %s",
                      parv[2], target, timestamp);
      }
      /* Don't propagate further until X3 broadcasts */

      /* Store locally if LMDB available (as cache) */
      if (history_is_available()) {
        readmarker_set(account, target, timestamp);
      }
    }
    /* If from services, this was part of X3's processing - ignore S format from services */

    return 0;
  }

  if (subcmd[0] == 'G' && subcmd[1] == '\0') {
    /* GET forward: MR G <user_numeric> <target> */
    if (parc < 4)
      return 0;

    /* Find the user - may not exist anymore */
    acptr = findNUser(parv[2]);
    target = parv[3];

    /* If not from services, forward toward X3 (multi-hop routing) */
    services = find_services_server();
    if (!is_from_services && services) {
      /* Forward toward X3 - sendcmdto_one routes through intermediate servers */
      sendcmdto_one(sptr, CMD_MARKREAD, services, "G %s %s", parv[2], target);
    }

    return 0;
  }

  if (subcmd[0] == 'R' && subcmd[1] == '\0') {
    /* Reply: MR R <target_server> <user_numeric> <target> <timestamp> */
    if (parc < 6)
      return 0;

    /* Find the target user */
    acptr = findNUser(parv[3]);
    if (!acptr || !IsUser(acptr))
      return 0;

    target = parv[4];
    timestamp = parv[5];

    /* If user is local, send MARKREAD response */
    if (MyUser(acptr) && CapActive(acptr, CAP_DRAFT_READMARKER)) {
      send_markread(acptr, target, timestamp);
    } else {
      /* Forward toward the user's server */
      sendcmdto_one(sptr, CMD_MARKREAD, cli_from(acptr), "R %s %s %s %s",
                    parv[2], parv[3], target, timestamp);
    }

    /* Cache locally if available */
    if (history_is_available() && cli_user(acptr) && cli_user(acptr)->account[0]) {
      readmarker_set(cli_user(acptr)->account, target, timestamp);
    }

    return 0;
  }

  /* Broadcast format from X3: MR <account> <target> <timestamp> */
  if (parc < 4)
    return 0;

  account = parv[1];
  target = parv[2];
  timestamp = parv[3];

  /* Cache locally if LMDB available */
  if (history_is_available()) {
    readmarker_set(account, target, timestamp);
  }

  /* Notify local clients with this account */
  notify_local_clients(account, target, timestamp);

  /* Propagate to other servers */
  sendcmdto_serv_butone(sptr, CMD_MARKREAD, cptr, "%s %s %s",
                        account, target, timestamp);

  return 0;
}

/** Send MARKREAD for a target to a client after JOIN.
 * Called from m_join.c after sending JOIN but before RPL_ENDOFNAMES.
 * @param[in] sptr Client to send to.
 * @param[in] target Channel name.
 */
void send_markread_on_join(struct Client *sptr, const char *target)
{
  const char *account;
  char stored_ts[MARKREAD_TS_LEN];
  int rc;

  /* Only for clients with draft/read-marker capability */
  if (!CapActive(sptr, CAP_DRAFT_READMARKER))
    return;

  /* Must be logged in */
  if (!cli_user(sptr) || !cli_user(sptr)->account[0])
    return;

  /* Check if readmarker subsystem is available */
  if (!history_is_available())
    return;

  account = cli_user(sptr)->account;

  rc = readmarker_get(account, target, stored_ts);
  if (rc == 0) {
    send_markread(sptr, target, stored_ts);
  } else {
    /* No stored marker - send "*" */
    send_markread(sptr, target, "*");
  }
}
