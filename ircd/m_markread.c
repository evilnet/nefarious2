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
 * Nefarious is authoritative for read markers. Storage is in the metadata
 * LMDB environment (available on all servers), synchronized via P10 MR token.
 *
 * P10 Protocol (Unix timestamps for S2S):
 *   MR <account> <target> <unix_timestamp>
 *
 * Timestamps are stored internally as Unix (seconds.milliseconds) and
 * converted to ISO 8601 only for client-facing protocol.
 */
#include "config.h"

#include "capab.h"
#include "channel.h"
#include "client.h"
#include "hash.h"
#include "history.h"
#include "metadata.h"
#include "ircd.h"
#include "ircd_alloc.h"
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
#include "session_markread.h"

#include <string.h>
#include <stdlib.h>

/** Maximum timestamp length */
#define MARKREAD_TS_LEN 32

/* ---------------------------------------------------------------- */
/* Session-anchored (ephemeral) read-marker store                    */
/* ---------------------------------------------------------------- */
/* Ephemeral clients (no account) can still use MARKREAD; their
 * markers live in this in-memory hash keyed on (session_id, target).
 * No persistence, no S2S broadcast — the markers disappear with the
 * session.  Account-anchored markers continue through the existing
 * metadata_readmarker_* path (LMDB-persisted, S2S-broadcast via MR).
 *
 * Same shape as the chathistory_presence session store: small fixed
 * bucket array, chained collisions, FNV-1a hash.  Bounded by the
 * number of ephemeral clients currently connected times the number
 * of targets each has marked. */

#define SESSION_MR_HASH_BITS 10
#define SESSION_MR_HASH_SIZE (1u << SESSION_MR_HASH_BITS)
#define SESSION_MR_HASH_MASK (SESSION_MR_HASH_SIZE - 1u)

struct session_markread_entry {
  struct session_markread_entry *hnext;
  char session_id[S2S_SESSID_BUFSIZE];
  char target[CHANNELLEN + 1];
  char timestamp[MARKREAD_TS_LEN];
};

static struct session_markread_entry *sm_buckets[SESSION_MR_HASH_SIZE];

static unsigned int sm_hash(const char *session_id, const char *target)
{
  unsigned int h = 2166136261u;
  const char *p;
  for (p = session_id; *p; p++) {
    h ^= (unsigned char)*p;
    h *= 16777619u;
  }
  h ^= 0;
  h *= 16777619u;
  for (p = target; *p; p++) {
    unsigned char c = (unsigned char)*p;
    if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
    h ^= c;
    h *= 16777619u;
  }
  return h & SESSION_MR_HASH_MASK;
}

static struct session_markread_entry *
sm_find(const char *session_id, const char *target)
{
  unsigned int b = sm_hash(session_id, target);
  struct session_markread_entry *e;
  for (e = sm_buckets[b]; e; e = e->hnext) {
    if (0 == strcmp(e->session_id, session_id)
        && 0 == ircd_strcmp(e->target, target))
      return e;
  }
  return NULL;
}

/** Store @a timestamp for (session_id, target).  Returns 0 if the
 *  marker was newer than (or absent from) the existing value and was
 *  stored, 1 if the existing value was >= new and nothing changed.
 *  Mirrors metadata_readmarker_set's "only update if newer" semantics
 *  on the client-facing path. */
static int session_markread_set(const char *session_id, const char *target,
                                 const char *timestamp)
{
  struct session_markread_entry *e = sm_find(session_id, target);
  if (e) {
    if (strcmp(timestamp, e->timestamp) <= 0)
      return 1;
  } else {
    unsigned int b = sm_hash(session_id, target);
    e = (struct session_markread_entry *)MyCalloc(1, sizeof(*e));
    ircd_strncpy(e->session_id, session_id, sizeof(e->session_id));
    ircd_strncpy(e->target, target, sizeof(e->target));
    e->hnext = sm_buckets[b];
    sm_buckets[b] = e;
  }
  ircd_strncpy(e->timestamp, timestamp, sizeof(e->timestamp));
  return 0;
}

/** Retrieve the marker for (session_id, target).  Returns 0 on found
 *  (fills @a out_ts), 1 on not found. */
static int session_markread_get(const char *session_id, const char *target,
                                 char *out_ts)
{
  struct session_markread_entry *e = sm_find(session_id, target);
  if (!e)
    return 1;
  ircd_strncpy(out_ts, e->timestamp, MARKREAD_TS_LEN);
  return 0;
}

void readmarker_ephemeral_purge(const char *session_id)
{
  unsigned int i;
  if (!session_id || !*session_id)
    return;
  for (i = 0; i < SESSION_MR_HASH_SIZE; i++) {
    struct session_markread_entry **pp = &sm_buckets[i];
    while (*pp) {
      if (0 == strcmp((*pp)->session_id, session_id)) {
        struct session_markread_entry *doomed = *pp;
        *pp = doomed->hnext;
        MyFree(doomed);
      } else {
        pp = &(*pp)->hnext;
      }
    }
  }
}

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
    sendrawto_one(to, ":%s MARKREAD %s timestamp=*", cli_name(&me), target);
  } else if (history_unix_to_iso(unix_ts, iso_ts, sizeof(iso_ts)) == 0) {
    sendrawto_one(to, ":%s MARKREAD %s timestamp=%s", cli_name(&me), target, iso_ts);
  } else {
    /* Conversion failed - send as-is (might already be ISO or invalid) */
    sendrawto_one(to, ":%s MARKREAD %s timestamp=%s", cli_name(&me), target, unix_ts);
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

/* X3 dependency removed - Nefarious is authoritative for read markers */

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
  int is_session;   /* 0 = account-anchored (LMDB + S2S); 1 = ephemeral (in-memory) */

  /* Must have draft/read-marker capability */
  if (!CapActive(sptr, CAP_DRAFT_READMARKER)) {
    return send_reply(sptr, ERR_UNKNOWNCOMMAND, "MARKREAD");
  }

  /* Resolve the anchor: account if authed, else session_id.  Ephemeral
   * markers use an in-memory store and don't broadcast S2S; account
   * markers use the persistent metadata-LMDB path with MR broadcast.
   * is_session toggles between the two paths in the SET/GET blocks
   * below. */
  if (cli_user(sptr) && cli_user(sptr)->account[0]) {
    account = cli_user(sptr)->account;
    is_session = 0;
  } else if (cli_session_id(sptr)[0]) {
    account = cli_session_id(sptr);
    is_session = 1;
  } else {
    send_fail(sptr, "MARKREAD", "ACCOUNT_REQUIRED", NULL,
              "MARKREAD requires either an authenticated account or "
              "a session ID");
    return 0;
  }

  /* Need at least target */
  if (parc < 2 || EmptyString(parv[1])) {
    send_fail(sptr, "MARKREAD", "NEED_MORE_PARAMS", NULL,
              "Missing target parameter");
    return 0;
  }

  target = parv[1];

  /* Check if timestamp parameter is present */
  if (parc >= 3 && parv[2] && ircd_strncmp(parv[2], "timestamp=", 10) == 0) {
    /* Timestamp parameter provided - must be valid format for SET operation */
    if (!parse_timestamp_param(parv[2], timestamp, sizeof(timestamp))) {
      /* Invalid timestamp format */
      send_fail(sptr, "MARKREAD", "INVALID_PARAMS", parv[2],
                "Invalid timestamp format (expected ISO 8601)");
      return 0;
    }

    /* SET operation.  Ephemeral path: in-memory session store, no
     * persistence, no S2S broadcast (session_id is local-only).
     * Account path: LMDB + MR broadcast as before. */
    if (is_session) {
      rc = session_markread_set(account, target, timestamp);
      if (rc == 0) {
        /* Newer timestamp accepted — notify owning client only.
         * Other servers don't know about this session, so no
         * sendcmdto_serv_butone.  notify_local_clients walks every
         * local client matching the account; for session anchors the
         * "account" key is the session_id and no other Client shares
         * it, so the notify naturally hits just sptr. */
        notify_local_clients(account, target, timestamp);
      } else if (rc == 1) {
        /* Not newer — echo current stored value. */
        if (session_markread_get(account, target, stored_ts) == 0)
          send_markread(sptr, target, stored_ts);
        else
          send_markread(sptr, target, timestamp);
      }
    } else {
      if (!metadata_lmdb_is_available()) {
        send_fail(sptr, "MARKREAD", "TEMPORARILY_UNAVAILABLE", target,
                  "Read marker storage is not available");
        return 0;
      }

      rc = metadata_readmarker_set(account, target, timestamp);
      if (rc == 0) {
        /* Successfully updated - notify local clients and broadcast */
        notify_local_clients(account, target, timestamp);

        /* Broadcast to other servers: MR <account> <target> <timestamp> */
        sendcmdto_serv_butone_v3(&me, CMD_MARKREAD, cptr, "%s %s %s",
                              account, target, timestamp);
      } else if (rc == 1) {
        /* Timestamp was not newer - respond with current stored value */
        rc = metadata_readmarker_get(account, target, stored_ts);
        if (rc == 0) {
          send_markread(sptr, target, stored_ts);
        } else {
          send_markread(sptr, target, timestamp);
        }
      } else {
        /* Error storing */
        send_fail(sptr, "MARKREAD", "INTERNAL_ERROR", target,
                  "Could not store read marker");
      }
    }
  } else {
    /* GET operation.  Same anchor-dispatch as SET. */
    if (is_session) {
      rc = session_markread_get(account, target, stored_ts);
      if (rc == 0)
        send_markread(sptr, target, stored_ts);
      else
        send_markread(sptr, target, "*");
    } else {
      if (!metadata_lmdb_is_available()) {
        send_fail(sptr, "MARKREAD", "TEMPORARILY_UNAVAILABLE", target,
                  "Read marker storage is not available");
        return 0;
      }

      rc = metadata_readmarker_get(account, target, stored_ts);
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
  }

  return 0;
}

/** ms_markread - Handle MARKREAD command from server.
 *
 * P10 format: MR <account> <target> <timestamp>
 *
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int ms_markread(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  const char *account;
  const char *target;
  const char *timestamp;

  /* Format: MR <account> <target> <timestamp> */
  if (parc < 4)
    return 0;

  account = parv[1];
  target = parv[2];
  timestamp = parv[3];

  /* Store locally in metadata LMDB */
  if (metadata_lmdb_is_available()) {
    metadata_readmarker_set(account, target, timestamp);
  }

  /* Notify local clients with this account */
  notify_local_clients(account, target, timestamp);

  /* Propagate to other servers */
  sendcmdto_serv_butone_v3(sptr, CMD_MARKREAD, cptr, "%s %s %s",
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

  /* Check if readmarker storage is available (metadata LMDB) */
  if (!metadata_lmdb_is_available())
    return;

  account = cli_user(sptr)->account;

  rc = metadata_readmarker_get(account, target, stored_ts);
  if (rc == 0) {
    send_markread(sptr, target, stored_ts);
  } else {
    /* No stored marker - send "*" */
    send_markread(sptr, target, "*");
  }
}
