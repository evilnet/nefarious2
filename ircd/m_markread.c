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
 * MARKREAD <target> [timestamp=YYYY-MM-DDThh:mm:ss.sssZ]
 *
 * This implementation stores read markers in LMDB per account+target.
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
#include "s_user.h"
#include "send.h"

#include <string.h>
#include <stdlib.h>

/** Maximum timestamp length (ISO 8601 with milliseconds) */
#define MARKREAD_TS_LEN 32

/** Parse timestamp= parameter from argument.
 * @param[in] arg Argument string (e.g., "timestamp=2025-01-01T00:00:00.000Z")
 * @param[out] ts Buffer for extracted timestamp.
 * @param[in] tslen Size of ts buffer.
 * @return 1 if found and valid format, 0 otherwise.
 */
static int parse_timestamp_param(const char *arg, char *ts, size_t tslen)
{
  const char *eq;

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

  /* Copy to output */
  ircd_strncpy(ts, eq, tslen - 1);
  ts[tslen - 1] = '\0';

  return 1;
}

/** Send MARKREAD response to a client.
 * @param[in] to Client to send to.
 * @param[in] target Channel or nick.
 * @param[in] timestamp ISO 8601 timestamp (or "*" if unknown).
 */
static void send_markread(struct Client *to, const char *target, const char *timestamp)
{
  /* Format: MARKREAD <target> timestamp=<ts>
   * The timestamp can be "*" if unknown.
   */
  if (timestamp && *timestamp)
    sendrawto_one(to, "MARKREAD %s timestamp=%s", target, timestamp);
  else
    sendrawto_one(to, "MARKREAD %s timestamp=*", target);
}

/** Broadcast MARKREAD to all of user's connections with draft/read-marker.
 * @param[in] sptr Source user (whose account we're updating).
 * @param[in] target Channel or nick.
 * @param[in] timestamp The new timestamp.
 */
static void broadcast_markread(struct Client *sptr, const char *target, const char *timestamp)
{
  struct Client *acptr;
  struct Client *user;
  const char *account;

  if (!cli_user(sptr) || !cli_user(sptr)->account[0])
    return;

  account = cli_user(sptr)->account;

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

/** m_markread - Handle MARKREAD command from local client.
 *
 * parv[0] = sender prefix
 * parv[1] = target (channel or nick)
 * parv[2] = timestamp=YYYY-MM-DDThh:mm:ss.sssZ (optional)
 *
 * If timestamp is provided: set read marker
 * If no timestamp: query current read marker
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

  /* Check if history/readmarker subsystem is available */
  if (!history_is_available()) {
    send_fail(sptr, "MARKREAD", "TEMPORARILY_UNAVAILABLE", target,
              "Read marker storage is not available");
    return 0;
  }

  /* Check if timestamp is provided (SET operation) */
  if (parc >= 3 && parse_timestamp_param(parv[2], timestamp, sizeof(timestamp))) {
    /* SET operation: store new timestamp */

    /* Try to set the timestamp (only updates if newer) */
    rc = readmarker_set(account, target, timestamp);
    if (rc < 0) {
      send_fail(sptr, "MARKREAD", "INTERNAL_ERROR", target,
                "Could not save read marker");
      return 0;
    }

    if (rc == 1) {
      /* Timestamp was not newer - respond with current stored value */
      rc = readmarker_get(account, target, stored_ts);
      if (rc == 0) {
        send_markread(sptr, target, stored_ts);
      } else {
        /* This shouldn't happen, but handle gracefully */
        send_markread(sptr, target, timestamp);
      }
    } else {
      /* Successfully updated - broadcast to all user's connections */
      broadcast_markread(sptr, target, timestamp);
    }
  } else {
    /* GET operation: query current timestamp */
    rc = readmarker_get(account, target, stored_ts);
    if (rc == 0) {
      send_markread(sptr, target, stored_ts);
    } else if (rc == 1) {
      /* Not found - send "*" */
      send_markread(sptr, target, "*");
    } else {
      send_fail(sptr, "MARKREAD", "INTERNAL_ERROR", target,
                "Could not retrieve read marker");
    }
  }

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
