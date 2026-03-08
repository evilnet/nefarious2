/*
 * IRC - Internet Relay Chat, ircd/m_bouncer_transfer.c
 * Copyright (C) 2026 AfterNET Development
 *
 * Minimal BX (Bouncer Transfer) handler for legacy/upstream Nefarious.
 *
 * Handles BX P (promote/transfer) and forwards ALL BX subcommands to
 * peer servers without processing.  This allows legacy servers to
 * participate in a mixed network where IRCv3 servers use BX C/X/P/N/U
 * for multi-server bouncer aliases.
 *
 * BX P has two modes:
 *   - If both old and new numerics are known: transfer memberships
 *     (swap path, used when BX C created the alias Client).
 *   - If the new numeric is unknown (no BX C support): swap old
 *     client's P10 numeric to the new one in-place.  The client
 *     keeps its nick, channels, and all state — only the internal
 *     routing numeric changes, so messages from the promoted alias
 *     are properly attributed.
 *
 * See evilnet/nefarious2 IRCv3 branch for the full alias implementation.
 */
#include "config.h"

#include "client.h"
#include "channel.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_log.h"
#include "ircd_string.h"
#include "msg.h"
#include "numnicks.h"
#include "s_misc.h"
#include "send.h"
#include "struct.h"

#include <assert.h>
#include <string.h>

/** Handle a BX (Bouncer Transfer) message from a server.
 *
 * All subcommands are forwarded to peer servers.  Only "P" (promote /
 * transfer) is processed locally — it swaps channel memberships from
 * one user numeric to another, renames the target, and silently removes
 * the source.
 *
 * Wire format for BX P:
 *   <server> BX P <old_numeric> <new_numeric> <sessid> <nick>
 *   parv[0] = sender prefix
 *   parv[1] = subcommand ("P", "C", "X", "N", "U", ...)
 *   parv[2..] = subcommand-specific parameters
 *
 * @param[in] cptr Local server that sent the message.
 * @param[in] sptr Original source of the message.
 * @param[in] parc Parameter count.
 * @param[in] parv Parameter vector.
 */
int ms_bouncer_transfer(struct Client *cptr, struct Client *sptr,
                        int parc, char *parv[])
{
  assert(0 != cptr);
  assert(0 != sptr);

  if (parc < 2)
    return 0;

  /* Process BX P: membership swap */
  if (parv[1][0] == 'P' && parv[1][1] == '\0') {
    struct Client *old_client;
    struct Client *new_client;
    struct Membership *memb;
    struct Membership *next;
    const char *nick;

    /* BX P <old_numeric> <new_numeric> <sessid> <nick> */
    if (parc < 6)
      return 0;

    old_client = findNUser(parv[2]);
    new_client = findNUser(parv[3]);
    /* parv[4] = sessid (not used by legacy) */
    nick = parv[5];

    if (!old_client || !IsUser(old_client))
      goto relay;

    if (new_client && IsUser(new_client)) {
      /* Both clients exist: transfer channel memberships from old to new. */
      for (memb = cli_user(old_client)->channel; memb; memb = next) {
        struct Channel *chptr = memb->channel;
        unsigned int status = memb->status;
        unsigned short oplevel = memb->oplevel;

        next = memb->next_channel;

        if (find_member_link(chptr, new_client))
          continue;

        add_user_to_channel(chptr, new_client, status, oplevel);
      }

      remove_user_from_all_channels(old_client);

      if (ircd_strcmp(cli_name(new_client), nick) != 0) {
        char safe_nick[NICKLEN + 1];
        ircd_strncpy(safe_nick, nick, NICKLEN + 1);
        hChangeClient(new_client, safe_nick);
        ircd_strncpy(cli_name(new_client), safe_nick, NICKLEN + 1);
      }

      SetFlag(old_client, FLAG_KILLED);
      exit_client(cptr, old_client, &me, "Bouncer transfer");
    } else {
      /* new_client not found: this server doesn't have the alias
       * (no BX C support).  Swap old_client's P10 numeric to the
       * new one so messages from the promoted alias route correctly.
       * old_client keeps its nick, channels, and all state — only
       * the internal numeric changes. */
      struct Client *new_server = FindNServer(parv[3]);
      if (!new_server || !IsServer(new_server))
        goto relay;

      /* Same numeric = no-op (SQUIT independent promotion) */
      if (0 == ircd_strcmp(parv[2], parv[3]))
        goto relay;

      /* Remove from old server's client array */
      RemoveYXXClient(cli_user(old_client)->server, cli_yxx(old_client));

      /* Move to new server */
      --(cli_serv(cli_user(old_client)->server)->clients);
      cli_user(old_client)->server = new_server;
      ++(cli_serv(new_server)->clients);

      /* Assign new numeric (sets cli_yxx + adds to new server's client_list) */
      SetRemoteNumNick(old_client, parv[3]);

      /* Rename if nick changed */
      if (ircd_strcmp(cli_name(old_client), nick) != 0) {
        char safe_nick[NICKLEN + 1];
        ircd_strncpy(safe_nick, nick, NICKLEN + 1);
        hChangeClient(old_client, safe_nick);
        ircd_strncpy(cli_name(old_client), safe_nick, NICKLEN + 1);
      }
    }
  }

relay:
  /* Forward all BX subcommands to peer servers.
   * Reconstruct the full parameter list for relay. */
  {
    char buf[512];
    int i, len = 0;
    for (i = 1; i < parc && len < (int)sizeof(buf) - 1; i++) {
      if (i > 1)
        buf[len++] = ' ';
      /* Last param gets : prefix if it contains spaces */
      if (i == parc - 1 && strchr(parv[i], ' ')) {
        len += ircd_snprintf(0, buf + len, sizeof(buf) - len, ":%s", parv[i]);
      } else {
        len += ircd_snprintf(0, buf + len, sizeof(buf) - len, "%s", parv[i]);
      }
    }
    if (len >= (int)sizeof(buf))
      len = (int)sizeof(buf) - 1;
    buf[len] = '\0';
    sendcmdto_serv_butone(sptr, CMD_BOUNCER_TRANSFER, cptr, "%s", buf);
  }

  return 0;
}
