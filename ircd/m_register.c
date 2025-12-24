/*
 * IRC - Internet Relay Chat, ircd/m_register.c
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
 * @brief Handler for REGISTER/VERIFY commands (IRCv3 draft/account-registration).
 *
 * Specification: https://ircv3.net/specs/extensions/account-registration
 *
 * REGISTER <account> {<email> | "*"} <password>
 * VERIFY <account> <code>
 *
 * This implementation relays registration requests to X3 services via P10
 * using RG (REGISTER), VF (VERIFY), and RR (REGREPLY) tokens.
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
#include "s_conf.h"
#include "s_user.h"
#include "send.h"

#include <string.h>

/** Find the services server (X3).
 * @return Pointer to services server, or NULL if not connected.
 */
static struct Client *find_services_server(void)
{
  /* Look for a server that matches our services server pattern */
  const char *services_name = feature_str(FEAT_HIS_SERVERNAME);

  /* For now, find any server that's a service (has +s) */
  /* TODO: Make this configurable via a new FEAT_SERVICES_SERVER */
  struct Client *acptr;

  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr)) {
    if (IsServer(acptr) && IsService(acptr))
      return acptr;
  }

  return NULL;
}

/** Send registration request to X3 via RG token (new protocol).
 * @param[in] sptr Client requesting registration.
 * @param[in] account Account name to register.
 * @param[in] email Email address (or "*").
 * @param[in] password Password.
 * @param[in] services Services server to send to.
 * @return 0 on success.
 */
static int send_register_rg(struct Client *sptr, const char *account,
                             const char *email, const char *password,
                             struct Client *services)
{
  /* Format: RG <user_numeric> <account> <email> :<password>
   * Password is sent as last param to allow spaces (though shouldn't have any)
   */
  sendcmdto_one(sptr, CMD_REGISTER, services, "%C %s %s :%s",
                sptr, account, email, password);
  return 0;
}

/** Send verify request to X3 via VF token.
 * @param[in] sptr Client requesting verification.
 * @param[in] account Account name.
 * @param[in] code Verification code.
 * @param[in] services Services server to send to.
 * @return 0 on success.
 */
static int send_verify_vf(struct Client *sptr, const char *account,
                           const char *code, struct Client *services)
{
  sendcmdto_one(sptr, CMD_VERIFY, services, "%C %s %s",
                sptr, account, code);
  return 0;
}

/** m_register - Handle REGISTER command from local client.
 *
 * parv[0] = sender prefix
 * parv[1] = account name (or "*" for current nick)
 * parv[2] = email address (or "*" for none)
 * parv[3] = password
 *
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 * @return 0 on success.
 */
int m_register(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  const char *account;
  const char *email;
  const char *password;
  struct Client *services;

  /* Check if feature is enabled */
  if (!feature_bool(FEAT_CAP_draft_account_registration)) {
    return send_reply(sptr, ERR_DISABLED, "REGISTER");
  }

  /* Need account, email, and password */
  if (parc < 4) {
    send_fail(sptr, "REGISTER", "NEED_MORE_PARAMS", NULL,
              "Not enough parameters");
    return 0;
  }

  account = parv[1];
  email = parv[2];
  password = parv[3];

  /* Check if already authenticated */
  if (IsAccount(sptr)) {
    send_fail(sptr, "REGISTER", "ALREADY_AUTHENTICATED", account,
              "You are already authenticated");
    return 0;
  }

  /* Validate account name */
  if (account[0] == '*' && account[1] == '\0') {
    /* Use current nickname */
    account = cli_name(sptr);
  }

  /* Basic account name validation */
  if (strlen(account) > ACCOUNTLEN) {
    send_fail(sptr, "REGISTER", "BAD_ACCOUNT_NAME", account,
              "Account name too long");
    return 0;
  }

  /* Basic password length check */
  if (strlen(password) < 5) {
    send_fail(sptr, "REGISTER", "WEAK_PASSWORD", account,
              "Password too short (minimum 5 characters)");
    return 0;
  }

  if (strlen(password) > 300) {
    send_fail(sptr, "REGISTER", "WEAK_PASSWORD", account,
              "Password too long (maximum 300 characters)");
    return 0;
  }

  /* Find services server */
  services = find_services_server();
  if (!services) {
    send_fail(sptr, "REGISTER", "TEMPORARILY_UNAVAILABLE", account,
              "Registration service is not available");
    return 0;
  }

  /* Send to services using RG (REGISTER) P10 token */
  send_register_rg(sptr, account, email, password, services);

  return 0;
}

/** m_verify - Handle VERIFY command from local client.
 *
 * parv[0] = sender prefix
 * parv[1] = account name
 * parv[2] = verification code
 *
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 * @return 0 on success.
 */
int m_verify(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  const char *account;
  const char *code;
  struct Client *services;

  /* Check if feature is enabled */
  if (!feature_bool(FEAT_CAP_draft_account_registration)) {
    return send_reply(sptr, ERR_DISABLED, "VERIFY");
  }

  /* Need account and code */
  if (parc < 3) {
    send_fail(sptr, "VERIFY", "NEED_MORE_PARAMS", NULL,
              "Not enough parameters");
    return 0;
  }

  account = parv[1];
  code = parv[2];

  /* Check if already authenticated */
  if (IsAccount(sptr)) {
    send_fail(sptr, "VERIFY", "ALREADY_AUTHENTICATED", account,
              "You are already authenticated");
    return 0;
  }

  /* Find services server */
  services = find_services_server();
  if (!services) {
    send_fail(sptr, "VERIFY", "TEMPORARILY_UNAVAILABLE", account,
              "Verification service is not available");
    return 0;
  }

  /* Send to services using VF (VERIFY) P10 token */
  send_verify_vf(sptr, account, code, services);

  return 0;
}

/** ms_regreply - Handle REGREPLY from services (S2S).
 *
 * parv[0] = sender prefix (services server)
 * parv[1] = target user numeric
 * parv[2] = status: S=success, F=fail, V=verification needed
 * parv[3] = account name
 * parv[4] = message
 *
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 * @return 0 on success.
 */
int ms_regreply(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct Client *acptr;
  const char *status;
  const char *account;
  const char *message;

  if (parc < 5)
    return 0;

  /* Find the target user */
  acptr = findNUser(parv[1]);
  if (!acptr)
    return 0;

  /* If not our user, forward */
  if (!MyConnect(acptr)) {
    sendcmdto_one(sptr, CMD_REGREPLY, acptr, "%C %s %s :%s",
                  acptr, parv[2], parv[3], parv[4]);
    return 0;
  }

  status = parv[2];
  account = parv[3];
  message = parv[4];

  switch (status[0]) {
  case 'S': /* Success */
    /* Log the user in */
    if (!IsAccount(acptr)) {
      ircd_strncpy(cli_user(acptr)->account, account,
                   sizeof(cli_user(acptr)->account) - 1);
      SetAccount(acptr);
      /* Notify the user and other clients */
      sendrawto_one(acptr, "REGISTER SUCCESS %s :%s", account, message);
      /* Send ACCOUNT to clients with account-notify */
      sendcmdto_common_channels_capab_butone(acptr, CMD_ACCOUNT, acptr,
                                              CAP_ACCNOTIFY, CAP_NONE,
                                              "%s", account);
    }
    break;

  case 'V': /* Verification required */
    sendrawto_one(acptr, "REGISTER VERIFICATION_REQUIRED %s :%s",
                  account, message);
    break;

  case 'F': /* Failure */
    /* Parse the error code from message if present, otherwise generic */
    if (strstr(message, "exists") || strstr(message, "ACCOUNT_EXISTS")) {
      send_fail(acptr, "REGISTER", "ACCOUNT_EXISTS", account, message);
    } else if (strstr(message, "email") || strstr(message, "INVALID_EMAIL")) {
      send_fail(acptr, "REGISTER", "INVALID_EMAIL", account, message);
    } else if (strstr(message, "weak") || strstr(message, "WEAK_PASSWORD")) {
      send_fail(acptr, "REGISTER", "WEAK_PASSWORD", account, message);
    } else if (strstr(message, "invalid") || strstr(message, "BAD_ACCOUNT_NAME")) {
      send_fail(acptr, "REGISTER", "BAD_ACCOUNT_NAME", account, message);
    } else {
      send_fail(acptr, "REGISTER", "TEMPORARILY_UNAVAILABLE", account, message);
    }
    break;

  default:
    log_write(LS_SYSTEM, L_WARNING, 0,
              "Unknown REGREPLY status '%s' from %#C for %#C",
              status, sptr, acptr);
    break;
  }

  return 0;
}
