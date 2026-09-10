/*
 * IRC - Internet Relay Chat, ircd/m_token.c
 * Copyright (C) 2026 Evilnet Development
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
 * @brief IRCv3 draft/authtoken TOKEN command and the P10 TK token.
 *
 * Client side:
 *   TOKEN SERVICELIST
 *   TOKEN GENERATE <service> [<scope>]
 *   TOKEN VALIDATE <service> :<token>      (also before registration)
 *
 * Server side (IRCv3-aware peers only):
 *   TK G <token> <service> <yxx> <expires> <scope|*>   token minted
 *   TK U <token>                                        token consumed
 */
#include "config.h"

#include "authtoken.h"
#include "capab.h"
#include "channel.h"
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
#include "s_user.h"
#include "send.h"
#include "struct.h"

#include <stdlib.h>
#include <string.h>

static int fail_unknown(struct Client *sptr, const char *sub)
{
  char desc[128];
  ircd_snprintf(0, desc, sizeof(desc), "No such subcommand TOKEN %s", sub);
  send_fail(sptr, "TOKEN", "UNKNOWN_COMMAND", sub, desc);
  return 0;
}

static int do_generate(struct Client *sptr, int parc, char *parv[])
{
  const char *service = parc > 2 ? parv[2] : NULL;
  const char *scope = parc > 3 && !EmptyString(parv[3]) ? parv[3] : NULL;
  const char *token;
  char desc[256];
  int svc;

  if (EmptyString(service))
    return send_reply(sptr, ERR_NEEDMOREPARAMS, "TOKEN GENERATE");

  svc = authtoken_find_service(service);
  if (svc < 0) {
    ircd_snprintf(0, desc, sizeof(desc), "No external service named %s is defined", service);
    send_fail(sptr, "TOKEN", "UNKNOWN_SERVICE", service, desc);
    return 0;
  }
  if (!IsAccount(sptr)) {
    ircd_snprintf(0, desc, sizeof(desc),
                  "You must be logged into an account to generate a token for the %s service",
                  service);
    send_fail(sptr, "TOKEN", "ACCOUNT_REQUIRED", NULL, desc);
    return 0;
  }

  if (scope) {
    if (strlen(scope) > AUTHTOKEN_SCOPELEN) {
      send_fail(sptr, "TOKEN", "INVALID_SCOPE", scope, "The provided scope is invalid");
      return 0;
    }
    if (IsChannelName(scope)) {
      struct Channel *chptr = FindChannel(scope);
      if (!chptr || !find_channel_member(sptr, chptr)) {
        ircd_snprintf(0, desc, sizeof(desc),
                      "You do not have permission to generate a %s token for %s",
                      service, scope);
        send_fail(sptr, "TOKEN", "NO_PERMISSIONS", scope, desc);
        return 0;
      }
      scope = chptr->chname;                    /* canonical spelling */
    } else {
      struct Client *acptr = FindUser(scope);
      if (!acptr) {
        send_fail(sptr, "TOKEN", "INVALID_SCOPE", scope, "The provided scope is invalid");
        return 0;
      }
      scope = cli_name(acptr);
    }
  }

  token = authtoken_generate(sptr, svc, scope);
  if (!token) {
    send_fail(sptr, "TOKEN", "INTERNAL_ERROR", NULL,
              "The requested action could not be completed due to an internal error");
    return 0;
  }
  sendcmdto_one(&me, CMD_TOKEN, sptr, "GENERATE %s :%s", service, token);
  return 0;
}

static int do_validate(struct Client *sptr, int parc, char *parv[])
{
  const char *service = parc > 2 ? parv[2] : NULL;
  const char *token = parc > 3 ? parv[3] : NULL;
  char desc[256];
  int svc;

  if (EmptyString(service) || EmptyString(token))
    return send_reply(sptr, ERR_NEEDMOREPARAMS, "TOKEN VALIDATE");

  svc = authtoken_find_service(service);
  if (svc < 0 || !authtoken_may_validate(sptr, svc)) {
    /* An unknown service reads the same as an unauthorised one so a
     * probe cannot enumerate service keys without credentials. */
    ircd_snprintf(0, desc, sizeof(desc),
                  "You do not have permission to validate %s tokens", service);
    send_fail(sptr, "TOKEN", "NO_PERMISSIONS", service, desc);
    return 0;
  }
  if (authtoken_consume(sptr, svc, token) < 0)
    send_fail(sptr, "TOKEN", "INVALID_TOKEN", NULL, "The provided token could not be validated");
  return 0;
}

/** TOKEN from a registered local user. */
int m_token(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  const char *sub = parc > 1 ? parv[1] : NULL;

  if (EmptyString(sub))
    return send_reply(sptr, ERR_NEEDMOREPARAMS, "TOKEN");

  if (!ircd_strcmp(sub, "SERVICELIST")) {
    authtoken_send_servicelist(sptr);
    return 0;
  }
  if (!ircd_strcmp(sub, "GENERATE"))
    return do_generate(sptr, parc, parv);
  if (!ircd_strcmp(sub, "VALIDATE"))
    return do_validate(sptr, parc, parv);
  return fail_unknown(sptr, sub);
}

/** TOKEN before registration: VALIDATE (spec MUST) and SERVICELIST
 * (spec MAY); GENERATE needs an account, so it is a registered-only
 * command. */
int mr_token(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  const char *sub = parc > 1 ? parv[1] : NULL;

  if (EmptyString(sub))
    return send_reply(sptr, ERR_NEEDMOREPARAMS, "TOKEN");
  if (!ircd_strcmp(sub, "VALIDATE"))
    return do_validate(sptr, parc, parv);
  if (!ircd_strcmp(sub, "SERVICELIST")) {
    authtoken_send_servicelist(sptr);
    return 0;
  }
  if (!ircd_strcmp(sub, "GENERATE"))
    return send_reply(sptr, ERR_NOTREGISTERED);
  return fail_unknown(sptr, sub);
}

/** TK from a peer server. */
int ms_token(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  if (parc < 3)
    return 0;

  switch (parv[1][0]) {
  case 'G':
    /* TK G <token> <service> <yxx> <expires> <scope|*> */
    if (parc < 7)
      return 0;
    authtoken_learn(parv[2], parv[3], parv[4], (time_t)strtoll(parv[5], NULL, 10), parv[6]);
    sendcmdto_serv_butone_v3(sptr, CMD_TOKEN, cptr, "G %s %s %s %s %s",
                             parv[2], parv[3], parv[4], parv[5], parv[6]);
    return 0;
  case 'U':
    authtoken_forget(parv[2]);
    sendcmdto_serv_butone_v3(sptr, CMD_TOKEN, cptr, "U %s", parv[2]);
    return 0;
  default:
    return 0;
  }
}
