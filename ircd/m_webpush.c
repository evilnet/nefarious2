/*
 * IRC - Internet Relay Chat, ircd/m_webpush.c
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
 * @brief Handler for WEBPUSH command (IRCv3 draft/webpush).
 *
 * Specification: https://github.com/ircv3/ircv3-specifications/pull/471
 *
 * Subcommands:
 *   REGISTER <endpoint> <keys>
 *   UNREGISTER <endpoint>
 *
 * This implementation uses X3 services for subscription storage and push
 * delivery. The IRCd relays commands to X3 via P10 WP token.
 */
#include "config.h"

#include "capab.h"
#include "client.h"
#include "hash.h"
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

/** Maximum endpoint URL length */
#define WEBPUSH_MAX_ENDPOINT 512

/** Maximum p256dh key length (base64) */
#define WEBPUSH_MAX_P256DH 128

/** Maximum auth secret length (base64) */
#define WEBPUSH_MAX_AUTH 32

/** Send a FAIL response using standard-replies format.
 * @param[in] sptr Client to send to.
 * @param[in] code Error code.
 * @param[in] context Context (subcommand).
 * @param[in] message Human-readable message.
 */
static void send_webpush_fail(struct Client *sptr, const char *code,
                              const char *context, const char *message)
{
  sendrawto_one(sptr, "FAIL WEBPUSH %s %s :%s",
                code, context ? context : "*", message);
}

/** Check if an endpoint URL is valid (HTTPS only, no internal IPs).
 * @param[in] endpoint The endpoint URL to validate.
 * @return 1 if valid, 0 otherwise.
 */
static int is_valid_endpoint(const char *endpoint)
{
  /* Must start with https:// */
  if (strncmp(endpoint, "https://", 8) != 0)
    return 0;

  /* Check length */
  if (strlen(endpoint) > WEBPUSH_MAX_ENDPOINT)
    return 0;

  /* Block localhost and private IPs */
  if (strstr(endpoint, "://localhost") ||
      strstr(endpoint, "://127.") ||
      strstr(endpoint, "://10.") ||
      strstr(endpoint, "://192.168.") ||
      strstr(endpoint, "://172.16.") ||
      strstr(endpoint, "://172.17.") ||
      strstr(endpoint, "://172.18.") ||
      strstr(endpoint, "://172.19.") ||
      strstr(endpoint, "://172.2") ||
      strstr(endpoint, "://172.30.") ||
      strstr(endpoint, "://172.31.") ||
      strstr(endpoint, "://[::1]") ||
      strstr(endpoint, "://[fe80:") ||
      strstr(endpoint, "://[fc") ||
      strstr(endpoint, "://[fd"))
    return 0;

  return 1;
}

/** Parse keys parameter in format "p256dh=...;auth=..."
 * @param[in] keys The keys string to parse.
 * @param[out] p256dh Buffer to receive p256dh key.
 * @param[in] p256dh_size Size of p256dh buffer.
 * @param[out] auth Buffer to receive auth secret.
 * @param[in] auth_size Size of auth buffer.
 * @return 1 if parsed successfully, 0 otherwise.
 */
static int parse_keys(const char *keys, char *p256dh, size_t p256dh_size,
                      char *auth, size_t auth_size)
{
  const char *p256dh_start, *auth_start;
  const char *p256dh_end, *auth_end;

  /* Find p256dh= */
  p256dh_start = strstr(keys, "p256dh=");
  if (!p256dh_start)
    return 0;
  p256dh_start += 7; /* skip "p256dh=" */

  /* Find end of p256dh (semicolon or end of string) */
  p256dh_end = strchr(p256dh_start, ';');
  if (!p256dh_end)
    p256dh_end = keys + strlen(keys);

  /* Find auth= */
  auth_start = strstr(keys, "auth=");
  if (!auth_start)
    return 0;
  auth_start += 5; /* skip "auth=" */

  /* Find end of auth (semicolon or end of string) */
  auth_end = strchr(auth_start, ';');
  if (!auth_end)
    auth_end = keys + strlen(keys);

  /* Check lengths */
  if ((size_t)(p256dh_end - p256dh_start) >= p256dh_size ||
      (size_t)(auth_end - auth_start) >= auth_size)
    return 0;

  /* Copy values */
  ircd_strncpy(p256dh, p256dh_start, p256dh_end - p256dh_start);
  p256dh[p256dh_end - p256dh_start] = '\0';

  ircd_strncpy(auth, auth_start, auth_end - auth_start);
  auth[auth_end - auth_start] = '\0';

  /* Basic validation - should be non-empty base64 */
  if (!*p256dh || !*auth)
    return 0;

  return 1;
}

/** Handle WEBPUSH REGISTER subcommand.
 * @param[in] sptr Source client.
 * @param[in] parc Parameter count.
 * @param[in] parv Parameters.
 * @return 0 on success.
 */
static int webpush_cmd_register(struct Client *sptr, int parc, char *parv[])
{
  const char *endpoint;
  const char *keys;
  char p256dh[WEBPUSH_MAX_P256DH];
  char auth[WEBPUSH_MAX_AUTH];

  /* WEBPUSH REGISTER <endpoint> <keys> */
  if (parc < 4) {
    send_webpush_fail(sptr, "INVALID_PARAMS", "REGISTER",
                      "Usage: WEBPUSH REGISTER <endpoint> <keys>");
    return 0;
  }

  endpoint = parv[2];
  keys = parv[3];

  /* Must be authenticated */
  if (!IsAccount(sptr)) {
    send_webpush_fail(sptr, "ACCOUNT_REQUIRED", "REGISTER",
                      "You must be logged in to register for push notifications");
    return 0;
  }

  /* Validate endpoint */
  if (!is_valid_endpoint(endpoint)) {
    send_webpush_fail(sptr, "INVALID_PARAMS", "REGISTER",
                      "Invalid push endpoint (must be HTTPS, no internal IPs)");
    return 0;
  }

  /* Parse keys */
  if (!parse_keys(keys, p256dh, sizeof(p256dh), auth, sizeof(auth))) {
    send_webpush_fail(sptr, "INVALID_PARAMS", "REGISTER",
                      "Invalid keys format (expected p256dh=...;auth=...)");
    return 0;
  }

  /* Relay to services via P10 WP token
   * Format: WP R <user_numeric> <endpoint> <p256dh> <auth>
   */
  sendcmdto_serv_butone(&me, CMD_WEBPUSH, NULL, "R %C %s %s %s",
                        sptr, endpoint, p256dh, auth);

  /* Echo success to client per spec */
  sendrawto_one(sptr, "WEBPUSH REGISTER %s", endpoint);

  log_write(LS_SYSTEM, L_INFO, 0,
            "WEBPUSH: %s!%s@%s registered endpoint for account %s",
            cli_name(sptr), cli_user(sptr)->username,
            cli_user(sptr)->host, cli_user(sptr)->account);

  return 0;
}

/** Handle WEBPUSH UNREGISTER subcommand.
 * @param[in] sptr Source client.
 * @param[in] parc Parameter count.
 * @param[in] parv Parameters.
 * @return 0 on success.
 */
static int webpush_cmd_unregister(struct Client *sptr, int parc, char *parv[])
{
  const char *endpoint;

  /* WEBPUSH UNREGISTER <endpoint> */
  if (parc < 3) {
    send_webpush_fail(sptr, "INVALID_PARAMS", "UNREGISTER",
                      "Usage: WEBPUSH UNREGISTER <endpoint>");
    return 0;
  }

  endpoint = parv[2];

  /* Must be authenticated */
  if (!IsAccount(sptr)) {
    send_webpush_fail(sptr, "ACCOUNT_REQUIRED", "UNREGISTER",
                      "You must be logged in to unregister push notifications");
    return 0;
  }

  /* Relay to services via P10 WP token
   * Format: WP U <user_numeric> <endpoint>
   */
  sendcmdto_serv_butone(&me, CMD_WEBPUSH, NULL, "U %C %s",
                        sptr, endpoint);

  /* Echo success to client per spec (silently succeeds even if not registered) */
  sendrawto_one(sptr, "WEBPUSH UNREGISTER %s", endpoint);

  log_write(LS_SYSTEM, L_INFO, 0,
            "WEBPUSH: %s!%s@%s unregistered endpoint for account %s",
            cli_name(sptr), cli_user(sptr)->username,
            cli_user(sptr)->host, cli_user(sptr)->account);

  return 0;
}

/** Handle WEBPUSH command from a local client.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 * @return 0 on success.
 */
int m_webpush(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  const char *subcmd;

  /* Check if capability is enabled */
  if (!CapActive(sptr, CAP_DRAFT_WEBPUSH)) {
    send_webpush_fail(sptr, "INVALID_PARAMS", "*",
                      "You must enable the draft/webpush capability");
    return 0;
  }

  if (parc < 2) {
    send_webpush_fail(sptr, "INVALID_PARAMS", "*",
                      "Usage: WEBPUSH <REGISTER|UNREGISTER> ...");
    return 0;
  }

  subcmd = parv[1];

  if (!ircd_strcmp(subcmd, "REGISTER"))
    return webpush_cmd_register(sptr, parc, parv);
  else if (!ircd_strcmp(subcmd, "UNREGISTER"))
    return webpush_cmd_unregister(sptr, parc, parv);
  else {
    send_webpush_fail(sptr, "INVALID_PARAMS", subcmd,
                      "Unknown subcommand (expected REGISTER or UNREGISTER)");
    return 0;
  }
}

/** Handle WEBPUSH (WP) command from a server (P10).
 *
 * Incoming formats:
 *   WP V :<vapid_pubkey>                             - VAPID key broadcast
 *   WP R <user_numeric> <endpoint> <p256dh> <auth>  - Register subscription
 *   WP U <user_numeric> <endpoint>                   - Unregister subscription
 *   WP E <user_numeric> <code> :<message>           - Error from services
 *
 * This is primarily for receiving responses from X3 services.
 *
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 * @return 0 on success.
 */
int ms_webpush(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct Client *acptr;
  const char *subcmd;

  if (parc < 2)
    return 0;

  subcmd = parv[1];

  /* Handle VAPID key broadcast from services: WP V :<vapid_pubkey> */
  if (subcmd[0] == 'V') {
    const char *vapid_key;

    if (parc < 3)
      return 0;

    vapid_key = parv[2];
    set_vapid_pubkey(vapid_key);

    log_write(LS_SYSTEM, L_INFO, 0, "WEBPUSH: VAPID public key set to: %s",
              vapid_key);

    /* Propagate to other servers */
    sendcmdto_serv_butone(sptr, CMD_WEBPUSH, cptr, "V :%s", vapid_key);

    /* Update ISUPPORT with new VAPID key */
    add_isupport_s("VAPID", vapid_key);

    return 0;
  }

  if (parc < 3)
    return 0;

  /* Handle error response from services */
  if (subcmd[0] == 'E') {
    const char *code;
    const char *message;

    if (parc < 4)
      return 0;

    /* Find target client */
    acptr = findNUser(parv[2]);
    if (!acptr)
      return 0;

    code = parv[3];
    message = (parc > 4) ? parv[4] : "Unknown error";

    /* Forward error to local client */
    if (MyUser(acptr)) {
      send_webpush_fail(acptr, code, "*", message);
    }
    return 0;
  }

  /* Forward to other servers if needed */
  if (subcmd[0] == 'R' || subcmd[0] == 'U') {
    /* Propagate to other servers */
    if (subcmd[0] == 'R' && parc >= 6) {
      sendcmdto_serv_butone(sptr, CMD_WEBPUSH, cptr, "R %s %s %s %s",
                            parv[2], parv[3], parv[4], parv[5]);
    } else if (subcmd[0] == 'U' && parc >= 4) {
      sendcmdto_serv_butone(sptr, CMD_WEBPUSH, cptr, "U %s %s",
                            parv[2], parv[3]);
    }
  }

  return 0;
}
