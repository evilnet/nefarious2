/*
 * IRC - Internet Relay Chat, ircd/s_numeric.c
 * Copyright (C) 1990 Jarkko Oikarinen
 *
 * Numerous fixes by Markku Savela
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
 * @brief Send a numeric message to a client.
 * @version $Id: s_numeric.c 1519 2005-10-10 12:18:11Z entrope $
 */
#include "config.h"

#include "s_numeric.h"
#include "bouncer_session.h"
#include "channel.h"
#include "client.h"
#include "forwarded_label.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_snprintf.h"
#include "numnicks.h"
#include "send.h"
#include "struct.h"


/*
 * do_numeric()
 * Rewritten by Nemesi, Jan 1999, to support numeric nicks in parv[1]
 *
 * Called when we get a numeric message from a remote _server_ and we are
 * supposed to forward it somewhere. Note that we always ignore numerics sent
 * to 'me' and simply drop the message if we can't handle with this properly:
 * the savvy approach is NEVER generate an error in response to an... error :)
 */

/** Forwards a numeric message from a remote server.
 * @param numeric Value of numeric message.
 * @param nnn If non-zero, treat parv[1] as a numnick; else as a client name.
 * @param cptr Client that originated the numeric.
 * @param sptr Peer that sent us the numeric.
 * @param parc Count of valid arguments in \a parv.
 * @param parv Argument list.
 * @return Zero (always).
 */
int do_numeric(int numeric, int nnn, struct Client *cptr, struct Client *sptr,
    int parc, char *parv[])
{
  struct Client *acptr = 0;
  struct Channel *achptr = 0;
  char num[4];

  /* Avoid trash, we need it to come from a server and have a target  */
  if ((parc < 2) || !IsServer(sptr))
    return 0;

  /* Who should receive this message ? Will we do something with it ?
     Note that we use findUser functions, so the target can't be neither
     a server, nor a channel (?) nor a list of targets (?) .. u2.10
     should never generate numeric replies to non-users anyway
     Ahem... it can be a channel actually, csc bots use it :\ --Nem */

  if (IsChannelName(parv[1]))
    achptr = FindChannel(parv[1]);
  else
    acptr = (nnn) ? (findNUser(parv[1])) : (FindUser(parv[1]));

  if (((!acptr) || (cli_from(acptr) == cptr)) && !achptr)
    return 0;

  /* Remap low number numerics, not that I understand WHY.. --Nemesi  */
  /* numerics below 100 talk about the current 'connection', you're not
   * connected to a remote server so it doesn't make sense to send them
   * remotely - but the information they contain may be useful, so we
   * remap them up.  Weird, but true.  -- Isomer */
  if (numeric < 100)
    numeric += 100;

  ircd_snprintf(0, num, sizeof(num), "%03d", numeric);

  /* Since 2.10.10.pl14 we rewrite numerics from remote servers to appear to
   * come from the local server
   */
  if (acptr) {
    struct Client *from = (feature_bool(FEAT_HIS_REWRITE) && !IsOper(acptr)) ? &me : sptr;

    if (MyConnect(acptr)) {
      const char *incoming_msgid = cli_s2s_msgid(cptr);

      /* Check for forwarded label batch wrapping */
      struct ForwardedLabel *fl = fwd_label_find(acptr, incoming_msgid);
      if (fl) {
        if (fl->fl_state == FWD_LABEL_PENDING)
          fwd_label_open_batch(acptr, fl);

        /* DRAINING → ACTIVE: more messages arrived with same msgid */
        if (fl->fl_state == FWD_LABEL_DRAINING)
          fl->fl_state = FWD_LABEL_ACTIVE;

        sendcmdto_set_fwd_batch(fl->fl_batch_id);
        sendcmdto_one_tags(from, num, num, acptr, "%C %s", acptr, parv[2]);

        if (fwd_label_is_terminal(fl, numeric)) {
          if ((numeric == 401 || numeric == 402)
              && numeric != fl->fl_terminal && numeric != fl->fl_terminal2) {
            /* Generic error mid-sequence (e.g. multi-target WHOIS a,b
             * emits 401 between lists): hold the batch open briefly for
             * the rest, swept by the expiry timer. */
            fl->fl_state = FWD_LABEL_DRAINING;
            fl->fl_created = CurrentTime;
          } else {
            /* The command's own terminal numeric IS the end of the
             * response -- close NOW, mirroring the synchronous
             * labeled_batch_end on the local path.  Leaving the batch
             * in DRAINING made closure contingent on the client's next
             * command: a client silently awaiting its reply buffered
             * the whole batched response until its next PONG (~90s)
             * and saw only ACK in the meantime. */
            fwd_label_close_batch(acptr, fl);
          }
        }
        return 0;
      }

      /* Numeric with different/no msgid: close any DRAINING batches */
      fwd_label_close_draining(acptr);
    } else {
      /* Remote client: relay numeric, preserving compact tag for correlation */
      if (cli_s2s_msgid(cptr)[0] && cli_s2s_time_ms(cptr))
        sendcmdto_set_s2s_tags(cli_s2s_time_ms(cptr), cli_s2s_msgid(cptr));
    }

    sendcmdto_one(from, num, num, acptr, "%C %s", acptr, parv[2]);

    /* Bouncer: a numeric that arrived over S2S addressed to a local
     * primary is a reply to something the SESSION did -- and after the
     * alias->primary egress rewrite (hunt_server_cmd, ircd_relay) the
     * device that actually asked may be one of the aliases.  Mirror it
     * to every local alias so replies never land only on another
     * device.  Plain path only: label-batched numerics belong to the
     * primary connection's batch and would be discarded by an alias
     * that never opened it. */
    if (MyConnect(acptr) && !IsBouncerAlias(acptr)) {
      struct BouncerSession *bs = bounce_get_session(acptr);
      if (bs && bs->hs_alias_count > 0) {
        int ai;
        for (ai = 0; ai < bs->hs_alias_count; ai++) {
          struct Client *alias = findNUser(bs->hs_aliases[ai].ba_numeric);
          if (alias && alias != acptr && MyConnect(alias)
              && IsBouncerAlias(alias) && cli_user(alias)
              && cli_user(alias)->alias_primary == acptr)
            sendcmdto_one(from, num, num, alias, "%C %s", acptr, parv[2]);
        }
      }
    }
  } else
    sendcmdto_channel_butone(feature_bool(FEAT_HIS_REWRITE) ? &me : sptr,
                             num, num, achptr, cptr, SKIP_DEAF | SKIP_BURST,
                             '\0', "%H %s", achptr, parv[2]);
  return 0;
}
