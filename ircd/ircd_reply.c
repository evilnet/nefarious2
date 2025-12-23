/*
 * IRC - Internet Relay Chat, ircd/m_proto.c
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
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
 * @brief Implementation of functions to send common replies to users.
 * @version $Id: ircd_reply.c 1762 2007-02-04 04:18:31Z entrope $
 */
#include "config.h"

#include "ircd_reply.h"
#include "capab.h"
#include "client.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_snprintf.h"
#include "msg.h"
#include "msgq.h"
#include "numeric.h"
#include "s_conf.h"
#include "s_debug.h"
#include "send.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <string.h>
#include <sys/time.h>

/** Report a protocol violation warning to anyone listening.  This can
 * be easily used to clean up the last couple of parts of the code.
 * @param[in] cptr Client that violated the protocol.
 * @param[in] pattern Description of how the protocol was violated.
 * @return Zero.
 */
int protocol_violation(struct Client* cptr, const char* pattern, ...)
{
  struct VarData vd;
  char message[BUFSIZE];

  assert(pattern);
  assert(cptr);

  vd.vd_format = pattern;
  va_start(vd.vd_args, pattern);
  ircd_snprintf(NULL, message, sizeof(message),
                "Protocol Violation from %s: %v", cli_name(cptr), &vd);
  va_end(vd.vd_args);

  sendwallto_group_butone(&me, WALL_DESYNCH, NULL, "%s", message);
  return 0;
}

/** Inform a client that they need to provide more parameters.
 * @param[in] cptr Taciturn client.
 * @param[in] cmd Command name.
 * @return Zero.
 */
int need_more_params(struct Client* cptr, const char* cmd)
{
  send_reply(cptr, ERR_NEEDMOREPARAMS, cmd);
  return 0;
}

/** Send a generic reply to a user.
 * @param[in] to Client that wants a reply.
 * @param[in] reply Numeric of message to send.
 * @return Zero.
 */
int send_reply(struct Client *to, int reply, ...)
{
  struct VarData vd;
  struct MsgBuf *mb;
  const struct Numeric *num;
  char tagbuf[256];
  int use_tags = 0;

  assert(0 != to);
  assert(0 != reply);

  num = get_error_numeric(reply & ~SND_EXPLICIT); /* get reply... */

  va_start(vd.vd_args, reply);

  if (reply & SND_EXPLICIT) /* get right pattern */
    vd.vd_format = (const char *) va_arg(vd.vd_args, char *);
  else
    vd.vd_format = num->format;

  assert(0 != vd.vd_format);

  /* Check if we need message tags for this client */
  if (MyConnect(to)) {
    int pos = 0;
    int need_label = feature_bool(FEAT_CAP_labeled_response) &&
                     CapActive(to, CAP_LABELEDRESP) && cli_label(to)[0];
    int need_time = feature_bool(FEAT_CAP_server_time) &&
                    CapActive(to, CAP_SERVERTIME);

    if (need_label || need_time) {
      tagbuf[0] = '@';
      pos = 1;

      if (need_label) {
        pos += snprintf(tagbuf + pos, sizeof(tagbuf) - pos, "label=%s", cli_label(to));
      }

      if (need_time) {
        struct timeval tv;
        struct tm tm;
        if (pos > 1 && pos < (int)sizeof(tagbuf) - 1)
          tagbuf[pos++] = ';';
        gettimeofday(&tv, NULL);
        gmtime_r(&tv.tv_sec, &tm);
        pos += snprintf(tagbuf + pos, sizeof(tagbuf) - pos,
                        "time=%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ",
                        tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                        tm.tm_hour, tm.tm_min, tm.tm_sec,
                        tv.tv_usec / 1000);
      }

      if (pos < (int)sizeof(tagbuf) - 1) {
        tagbuf[pos++] = ' ';
        tagbuf[pos] = '\0';
      }
      use_tags = 1;
    }
  }

  /* build buffer with or without tags */
  if (use_tags)
    mb = msgq_make(cli_from(to), "%s%:#C %s %C %v", tagbuf, &me, num->str, to, &vd);
  else
    mb = msgq_make(cli_from(to), "%:#C %s %C %v", &me, num->str, to, &vd);

  va_end(vd.vd_args);

  /* send it to the user */
  send_buffer(to, mb, 0);

  msgq_clean(mb);

  return 0; /* convenience return */
}



