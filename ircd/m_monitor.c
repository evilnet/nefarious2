/*
 * IRC - Internet Relay Chat, ircd/m_monitor.c
 * Copyright (C) 2024 Afternet Development Team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
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
 *
 * IRCv3 MONITOR command implementation
 * Specification: https://ircv3.net/specs/extensions/monitor
 *
 * Shares internal watch list infrastructure with WATCH command.
 *
 * NOTE: Online/offline notifications when users connect/disconnect are
 * currently sent using WATCH numerics (600-607) via check_status_watch().
 * MONITOR clients can use MONITOR S to poll for status in MONITOR format
 * (730-734). A future enhancement could track whether clients used WATCH
 * vs MONITOR and send appropriate numeric formats.
 */

#include "config.h"

#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "list.h"
#include "numeric.h"
#include "s_user.h"
#include "send.h"
#include "watch.h"

#include <stdlib.h>
#include <string.h>

/*
 * Helper to send batched MONONLINE/MONOFFLINE responses
 * Accumulates nicks until buffer would overflow, then sends
 */
static void
monitor_send_status(struct Client *sptr, char *online_buf, char *offline_buf)
{
  if (*online_buf)
    send_reply(sptr, RPL_MONONLINE, online_buf);
  if (*offline_buf)
    send_reply(sptr, RPL_MONOFFLINE, offline_buf);
}

/*
 * Check if a nick is valid for MONITOR (no wildcards, servers, or invalid chars)
 */
static int
monitor_valid_nick(const char *nick)
{
  if (!nick || !*nick)
    return 0;
  if (strchr(nick, '*') || strchr(nick, '?'))
    return 0;
  if (strchr(nick, '.') || strchr(nick, '@'))
    return 0;
  return 1;
}

/*
 * m_monitor - IRCv3 MONITOR command handler
 *
 *   parv[0] = sender prefix
 *   parv[1] = subcommand (+/-/C/L/S)
 *   parv[2] = targets (for +/-) - comma-separated nick list
 *
 * Subcommands:
 *   + nick,nick,...  - Add nicks to monitor list
 *   - nick,nick,...  - Remove nicks from monitor list
 *   C                - Clear entire monitor list
 *   L                - List all monitored nicks
 *   S                - Status of all monitored nicks (online/offline)
 */
int m_monitor(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  char *s, *p = NULL;
  char online_buf[512];
  char offline_buf[512];
  int online_len = 0;
  int offline_len = 0;
  char subcmd;

  if (parc < 2 || !parv[1] || !*parv[1])
    return need_more_params(sptr, "MONITOR");

  subcmd = parv[1][0];

  /*
   * MONITOR + nick,nick,...
   * Add nicks to monitor list
   */
  if (subcmd == '+')
  {
    if (parc < 3 || !parv[2] || !*parv[2])
      return need_more_params(sptr, "MONITOR");

    online_buf[0] = '\0';
    offline_buf[0] = '\0';
    online_len = 0;
    offline_len = 0;

    /* Parse comma-separated nick list */
    for (s = ircd_strtok(&p, parv[2], ","); s; s = ircd_strtok(&p, NULL, ","))
    {
      struct Client *acptr;
      char entry[NICKLEN + USERLEN + HOSTLEN + 4]; /* nick!user@host + null */

      /* Skip whitespace */
      while (*s == ' ')
        s++;

      if (!monitor_valid_nick(s))
        continue;

      /* Truncate long nicks */
      if (strlen(s) > NICKLEN)
        ((char *)s)[NICKLEN] = '\0';

      /* Check monitor list limit */
      if (cli_user(sptr)->watches >= feature_int(FEAT_MAXWATCHS))
      {
        /* Flush any pending responses first */
        monitor_send_status(sptr, online_buf, offline_buf);
        online_buf[0] = '\0';
        offline_buf[0] = '\0';
        online_len = 0;
        offline_len = 0;

        /* Send list full error */
        send_reply(sptr, ERR_MONLISTFULL, feature_int(FEAT_MAXWATCHS), s);
        return 0;
      }

      /* Add to watch list (shared infrastructure) */
      add_nick_watch(sptr, s);

      /* Check if nick is online */
      if ((acptr = FindUser(s)))
      {
        /* Format: nick!user@host */
        ircd_snprintf(0, entry, sizeof(entry), "%s!%s@%s",
                      cli_name(acptr),
                      cli_user(acptr)->username,
                      IsAnOper(sptr) ? cli_user(acptr)->realhost : cli_user(acptr)->host);

        /* Check if entry fits in buffer */
        if (online_len + strlen(entry) + 2 > sizeof(online_buf))
        {
          /* Flush buffer */
          send_reply(sptr, RPL_MONONLINE, online_buf);
          online_buf[0] = '\0';
          online_len = 0;
        }

        /* Append to buffer */
        if (online_len > 0)
        {
          strcat(online_buf, ",");
          online_len++;
        }
        strcat(online_buf, entry);
        online_len += strlen(entry);
      }
      else
      {
        /* Nick is offline - just the nick, no hostmask */
        if (offline_len + strlen(s) + 2 > sizeof(offline_buf))
        {
          /* Flush buffer */
          send_reply(sptr, RPL_MONOFFLINE, offline_buf);
          offline_buf[0] = '\0';
          offline_len = 0;
        }

        if (offline_len > 0)
        {
          strcat(offline_buf, ",");
          offline_len++;
        }
        strcat(offline_buf, s);
        offline_len += strlen(s);
      }
    }

    /* Send any remaining buffered responses */
    monitor_send_status(sptr, online_buf, offline_buf);
    return 0;
  }

  /*
   * MONITOR - nick,nick,...
   * Remove nicks from monitor list
   */
  if (subcmd == '-')
  {
    if (parc < 3 || !parv[2] || !*parv[2])
      return need_more_params(sptr, "MONITOR");

    /* Parse comma-separated nick list */
    for (s = ircd_strtok(&p, parv[2], ","); s; s = ircd_strtok(&p, NULL, ","))
    {
      /* Skip whitespace */
      while (*s == ' ')
        s++;

      if (!monitor_valid_nick(s))
        continue;

      /* Truncate long nicks */
      if (strlen(s) > NICKLEN)
        ((char *)s)[NICKLEN] = '\0';

      /* Remove from watch list */
      del_nick_watch(sptr, s);
    }

    /* MONITOR - doesn't send a response per the spec */
    return 0;
  }

  /*
   * MONITOR C
   * Clear entire monitor list
   */
  if (subcmd == 'C' || subcmd == 'c')
  {
    del_list_watch(sptr);
    return 0;
  }

  /*
   * MONITOR L
   * List all monitored nicks
   */
  if (subcmd == 'L' || subcmd == 'l')
  {
    struct SLink *lp = cli_user(sptr)->watch;
    char list_buf[512];
    int list_len = 0;

    list_buf[0] = '\0';

    while (lp)
    {
      const char *nick = lp->value.wptr->wt_nick;

      /* Check if nick fits in buffer */
      if (list_len + strlen(nick) + 2 > sizeof(list_buf))
      {
        /* Flush buffer */
        send_reply(sptr, RPL_MONLIST, list_buf);
        list_buf[0] = '\0';
        list_len = 0;
      }

      /* Append to buffer */
      if (list_len > 0)
      {
        strcat(list_buf, ",");
        list_len++;
      }
      strcat(list_buf, nick);
      list_len += strlen(nick);

      lp = lp->next;
    }

    /* Send any remaining */
    if (list_len > 0)
      send_reply(sptr, RPL_MONLIST, list_buf);

    send_reply(sptr, RPL_ENDOFMONLIST);
    return 0;
  }

  /*
   * MONITOR S
   * Status of all monitored nicks (report online/offline)
   */
  if (subcmd == 'S' || subcmd == 's')
  {
    struct SLink *lp = cli_user(sptr)->watch;

    online_buf[0] = '\0';
    offline_buf[0] = '\0';
    online_len = 0;
    offline_len = 0;

    while (lp)
    {
      struct Client *acptr;
      const char *nick = lp->value.wptr->wt_nick;

      if ((acptr = FindUser(nick)))
      {
        char entry[NICKLEN + USERLEN + HOSTLEN + 4];

        /* Format: nick!user@host */
        ircd_snprintf(0, entry, sizeof(entry), "%s!%s@%s",
                      cli_name(acptr),
                      cli_user(acptr)->username,
                      IsAnOper(sptr) ? cli_user(acptr)->realhost : cli_user(acptr)->host);

        /* Check if entry fits in buffer */
        if (online_len + strlen(entry) + 2 > sizeof(online_buf))
        {
          send_reply(sptr, RPL_MONONLINE, online_buf);
          online_buf[0] = '\0';
          online_len = 0;
        }

        if (online_len > 0)
        {
          strcat(online_buf, ",");
          online_len++;
        }
        strcat(online_buf, entry);
        online_len += strlen(entry);
      }
      else
      {
        /* Nick is offline */
        if (offline_len + strlen(nick) + 2 > sizeof(offline_buf))
        {
          send_reply(sptr, RPL_MONOFFLINE, offline_buf);
          offline_buf[0] = '\0';
          offline_len = 0;
        }

        if (offline_len > 0)
        {
          strcat(offline_buf, ",");
          offline_len++;
        }
        strcat(offline_buf, nick);
        offline_len += strlen(nick);
      }

      lp = lp->next;
    }

    /* Send any remaining buffered responses */
    monitor_send_status(sptr, online_buf, offline_buf);
    send_reply(sptr, RPL_ENDOFMONLIST);
    return 0;
  }

  /* Unknown subcommand - silently ignore per spec */
  return 0;
}
