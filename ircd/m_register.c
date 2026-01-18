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
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_auth.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_user.h"
#include "send.h"

#include <stdlib.h>
#include <string.h>

extern struct Client* LocalClientArray[];

/** Find the services server (X3).
 * Uses FEAT_REGISTER_SERVER to determine which server to use:
 * - "*" (default): Find any server with +s (service) flag
 * - Specific name: Use find_match_server to find a matching server
 * @return Pointer to services server, or NULL if not connected.
 */
static struct Client *find_services_server(void)
{
  const char *server_name = feature_str(FEAT_REGISTER_SERVER);
  struct Client *acptr;

  Debug((DEBUG_DEBUG, "find_services_server: REGISTER_SERVER=%s", server_name));

  /* If a specific server is configured, try to find it */
  if (strcmp(server_name, "*") != 0) {
    acptr = find_match_server((char *)server_name);
    if (acptr) {
      Debug((DEBUG_DEBUG, "find_services_server: Found configured server %s",
             cli_name(acptr)));
      return acptr;
    }
    Debug((DEBUG_DEBUG, "find_services_server: Configured server %s not found",
           server_name));
    return NULL;
  }

  /* Default: find any server that's a service (has +s) */
  Debug((DEBUG_DEBUG, "find_services_server: Searching for any service server"));

  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr)) {
    if (IsServer(acptr)) {
      Debug((DEBUG_DEBUG, "find_services_server: Found server %s, IsService=%d",
             cli_name(acptr), IsService(acptr) ? 1 : 0));
      if (IsService(acptr))
        return acptr;
    }
  }

  Debug((DEBUG_DEBUG, "find_services_server: No service server found"));
  return NULL;
}

/** Send registration request to X3 via RG token (new protocol).
 * @param[in] cptr Client connection (for fd).
 * @param[in] sptr Client requesting registration.
 * @param[in] account Account name to register.
 * @param[in] email Email address (or "*").
 * @param[in] password Password.
 * @param[in] services Services server to send to.
 * @return 0 on success.
 */
static int send_register_rg(struct Client *cptr, struct Client *sptr,
                             const char *account, const char *email,
                             const char *password, struct Client *services)
{
  /* Format: <server> RG <target> <server>!<fd>.<cookie> <account> <email> :<password>
   * Similar to SASL, we use server!fd.cookie to identify pre-registration clients.
   * The cookie is the SASL cookie assigned to this connection.
   */
  sendcmdto_one(&me, CMD_REGISTER, services, "%C %C!%u.%u %s %s :%s",
                services, &me, cli_fd(cptr), cli_saslcookie(cptr),
                account, email, password);
  return 0;
}

/** Send verify request to X3 via VF token.
 * @param[in] cptr Client connection (for fd).
 * @param[in] sptr Client requesting verification.
 * @param[in] account Account name.
 * @param[in] code Verification code.
 * @param[in] services Services server to send to.
 * @return 0 on success.
 */
static int send_verify_vf(struct Client *cptr, struct Client *sptr,
                           const char *account, const char *code,
                           struct Client *services)
{
  /* Format similar to RG: server!fd.cookie to identify client */
  sendcmdto_one(&me, CMD_VERIFY, services, "%C %C!%u.%u %s %s",
                services, &me, cli_fd(cptr), cli_saslcookie(cptr),
                account, code);
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

  Debug((DEBUG_DEBUG, "m_register called: parc=%d from %s", parc, cli_name(sptr)));

  /* Check if feature is enabled */
  if (!feature_bool(FEAT_CAP_draft_account_registration)) {
    Debug((DEBUG_DEBUG, "m_register: feature disabled"));
    send_fail(sptr, "REGISTER", "DISABLED", NULL,
              "Account registration is not enabled on this server");
    return 0;
  }
  Debug((DEBUG_DEBUG, "m_register: feature enabled, checking params"));

  /* Need account, email, and password */
  if (parc < 4) {
    send_fail(sptr, "REGISTER", "NEED_MORE_PARAMS", NULL,
              "Not enough parameters");
    return 0;
  }

  account = parv[1];
  email = parv[2];
  password = parv[3];
  Debug((DEBUG_DEBUG, "m_register: account=%s email=%s", account, email));

  /* Check if already authenticated */
  if (IsAccount(sptr)) {
    Debug((DEBUG_DEBUG, "m_register: already authenticated"));
    send_fail(sptr, "REGISTER", "ALREADY_AUTHENTICATED", account,
              "You are already authenticated");
    return 0;
  }

  Debug((DEBUG_DEBUG, "m_register: checking IsAccount"));

  /* Validate account name */
  if (account[0] == '*' && account[1] == '\0') {
    /* Use current nickname */
    account = cli_name(sptr);
  }
  Debug((DEBUG_DEBUG, "m_register: account len=%zu ACCOUNTLEN=%d", strlen(account), ACCOUNTLEN));

  /* Basic account name validation */
  if (strlen(account) > ACCOUNTLEN) {
    Debug((DEBUG_DEBUG, "m_register: account name too long"));
    send_fail(sptr, "REGISTER", "BAD_ACCOUNT_NAME", account,
              "Account name too long");
    return 0;
  }

  Debug((DEBUG_DEBUG, "m_register: password len=%zu", strlen(password)));
  /* Basic password length check */
  if (strlen(password) < 5) {
    Debug((DEBUG_DEBUG, "m_register: password too short"));
    send_fail(sptr, "REGISTER", "WEAK_PASSWORD", account,
              "Password too short (minimum 5 characters)");
    return 0;
  }

  if (strlen(password) > 300) {
    Debug((DEBUG_DEBUG, "m_register: password too long"));
    send_fail(sptr, "REGISTER", "WEAK_PASSWORD", account,
              "Password too long (maximum 300 characters)");
    return 0;
  }

  /* Find services server */
  Debug((DEBUG_DEBUG, "m_register: looking for services server"));
  services = find_services_server();
  if (!services) {
    Debug((DEBUG_DEBUG, "m_register: no services server found"));
    send_fail(sptr, "REGISTER", "TEMPORARILY_UNAVAILABLE", account,
              "Registration service is not available");
    return 0;
  }
  Debug((DEBUG_DEBUG, "m_register: found services %s, sending RG", cli_name(services)));

  /* Send to services using RG (REGISTER) P10 token */
  send_register_rg(cptr, sptr, account, email, password, services);
  Debug((DEBUG_DEBUG, "m_register: sent RG to services"));

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
    send_fail(sptr, "VERIFY", "DISABLED", NULL,
              "Account registration is not enabled on this server");
    return 0;
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
  send_verify_vf(cptr, sptr, account, code, services);

  return 0;
}

/** Find a pre-registration client by server!fd.cookie token.
 * @param[in] token The token in format "server!fd.cookie"
 * @return Client pointer or NULL if not found.
 */
static struct Client *find_prereg_client(const char *token)
{
  char buf[64];
  char *fdstr, *cookiestr;
  int fd;
  unsigned int cookie;
  struct Client *acptr;

  /* Copy token so we can modify it */
  ircd_strncpy(buf, token, sizeof(buf) - 1);
  buf[sizeof(buf) - 1] = '\0';

  /* Find the ! separator (server!fd.cookie) */
  fdstr = strchr(buf, '!');
  if (!fdstr)
    return NULL;
  fdstr++; /* Skip past the ! */

  /* Find the . separator (fd.cookie) */
  cookiestr = strchr(fdstr, '.');
  if (!cookiestr)
    return NULL;
  *cookiestr++ = '\0';

  fd = atoi(fdstr);
  cookie = (unsigned int)atoi(cookiestr);

  Debug((DEBUG_DEBUG, "find_prereg_client: token=%s fd=%d cookie=%u", token, fd, cookie));

  /* Find client by fd and verify cookie */
  acptr = LocalClientArray[fd];
  if (!acptr) {
    Debug((DEBUG_DEBUG, "find_prereg_client: no client at fd %d", fd));
    return NULL;
  }

  if (cli_saslcookie(acptr) != cookie) {
    Debug((DEBUG_DEBUG, "find_prereg_client: cookie mismatch (%u != %u)",
           cli_saslcookie(acptr), cookie));
    return NULL;
  }

  Debug((DEBUG_DEBUG, "find_prereg_client: found client %s", cli_name(acptr)));
  return acptr;
}

/** ms_regreply - Handle REGREPLY from services (S2S).
 *
 * parv[0] = sender prefix (services server)
 * parv[1] = target client ID (either "server!fd.cookie" for pre-reg or user numeric)
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

  Debug((DEBUG_DEBUG, "ms_regreply: target=%s status=%s account=%s msg=%s",
         parv[1], parv[2], parv[3], parv[4]));

  /* Try to find the target client - could be either:
   * 1. Pre-registration client: "server!fd.cookie" format
   * 2. Registered user: user numeric
   */
  if (strchr(parv[1], '!')) {
    /* Pre-registration client format: server!fd.cookie */
    acptr = find_prereg_client(parv[1]);
  } else {
    /* Registered user numeric */
    acptr = findNUser(parv[1]);
  }

  if (!acptr) {
    Debug((DEBUG_DEBUG, "ms_regreply: target not found: %s", parv[1]));
    return 0;
  }

  /* If not our user, forward (only for registered users) */
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
    Debug((DEBUG_DEBUG, "ms_regreply: SUCCESS for %s, IsRegistered=%d",
           cli_name(acptr), IsRegistered(acptr) ? 1 : 0));

    if (IsRegistered(acptr)) {
      /* Fully registered user - set account directly */
      if (!IsAccount(acptr) && cli_user(acptr)) {
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
    } else {
      /* Pre-registration client - store in saslaccount for later.
       * When registration completes (NICK/USER done), auth_complete_sasl()
       * will copy saslaccount to cli_user(acptr)->account and SetAccount().
       */
      ircd_strncpy(cli_saslaccount(acptr), account, ACCOUNTLEN);
      SetSASLComplete(acptr);  /* Mark SASL as complete so auth_complete_sasl applies account */
      if (cli_auth(acptr))
        auth_set_account(cli_auth(acptr), account);
      /* Send success message to client */
      sendrawto_one(acptr, "REGISTER SUCCESS %s :%s", account, message);
      Debug((DEBUG_DEBUG, "ms_regreply: pre-reg client, set saslaccount=%s, SetSASLComplete", account));
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
    Debug((DEBUG_DEBUG, "Unknown REGREPLY status '%s' from %s for %s",
           status, cli_name(sptr), cli_name(acptr)));
    break;
  }

  return 0;
}
