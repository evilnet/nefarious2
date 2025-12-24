/*
 * IRC - Internet Relay Chat, ircd/m_isupport.c
 * Copyright (C) 2024 AfterNET IRC Network
 *
 * See file AUTHORS in IRC package for additional names of
 * the programmers.
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
 * @brief Handlers for ISUPPORT command (IRCv3 draft/extended-isupport).
 *
 * This implements the draft/extended-isupport extension which allows
 * clients to request ISUPPORT (005) tokens before completing registration.
 *
 * @see https://ircv3.net/specs/extensions/extended-isupport
 */

#include "config.h"

#include "capab.h"
#include "client.h"
#include "ircd_reply.h"
#include "numeric.h"
#include "s_user.h"

/** Handle an ISUPPORT command from a local client.
 *
 * Returns RPL_ISUPPORT (005) messages to the client. Requires the
 * draft/extended-isupport capability to be negotiated.
 *
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int m_isupport(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  /* Check if capability negotiated */
  if (!HasCap(sptr, CAP_DRAFT_EXTISUPPORT))
    return send_reply(sptr, ERR_UNKNOWNCOMMAND, "ISUPPORT");

  /* Send ISUPPORT - reuses existing infrastructure from s_user.c */
  send_supported(sptr);

  return 0;
}
