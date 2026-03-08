/*
 * IRC - Internet Relay Chat, ircd/m_bouncer_transfer.c
 * Copyright (C) 2026 AfterNET Development
 *
 * Minimal BX (Bouncer Transfer) handler for legacy/upstream Nefarious.
 *
 * Handles BX P (membership swap between two user numerics) and
 * forwards ALL BX subcommands to peer servers without processing.
 * This allows legacy servers to participate in a mixed network where
 * IRCv3 servers use BX C/X/P/N/U for multi-server bouncer aliases.
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
    if (!new_client || !IsUser(new_client))
      goto relay;

    /* Transfer channel memberships from old to new.
     * For each channel old is on, add new with same flags, then remove old. */
    for (memb = cli_user(old_client)->channel; memb; memb = next) {
      struct Channel *chptr = memb->channel;
      unsigned int status = memb->status;
      unsigned short oplevel = memb->oplevel;

      /* Save next before we modify the chain */
      next = memb->next_channel;

      /* Skip if new is already on this channel */
      if (find_member_link(chptr, new_client))
        continue;

      add_user_to_channel(chptr, new_client, status, oplevel);
    }

    /* Remove old from all channels */
    remove_user_from_all_channels(old_client);

    /* Rename new_client to the target nick */
    if (ircd_strcmp(cli_name(new_client), nick) != 0) {
      char safe_nick[NICKLEN + 1];
      ircd_strncpy(safe_nick, nick, NICKLEN + 1);
      hChangeClient(new_client, safe_nick);
      ircd_strncpy(cli_name(new_client), safe_nick, NICKLEN + 1);
    }

    /* Silently exit old_client (FLAG_KILLED suppresses QUIT) */
    SetFlag(old_client, FLAG_KILLED);
    exit_client(cptr, old_client, &me, "Bouncer transfer");
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
