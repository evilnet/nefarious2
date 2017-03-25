/*
 * IRC - Internet Relay Chat, ircd/m_check.c
 * Copyright (C) 1990 Jarkko Oikarinen and
 * University of Oulu, Computing Center
 *
 * See file AUTHORS in IRC package for additional names of
 * the programmers.
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
 */

#include "channel.h"
#include "class.h"
#include "client.h"
#include "destruct_event.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_defs.h"
#include "ircd_features.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "ircd_snprintf.h"
#include "list.h"
#include "listener.h"
#include "match.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "querycmds.h"
#include "send.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_misc.h"
#include "s_user.h"

#include <arpa/inet.h>
#include <string.h>

#define CHECK_CHECKCHAN 0x01 /* -c */
#define CHECK_SHOWUSERS 0x02 /* ! -u */
#define CHECK_OPSONLY   0x04 /* -o */
#define CHECK_SHOWIPS   0x08 /* -i */
#define CHECK_CIDRMASK  0x10 /* automatically detected when performing a hostmask /CHECK */

#define HEADERLINE "--------------------------------------------------------------------"
#define COLOR_OFF  '\017'

void checkChannel(struct Client *sptr, struct Channel *chptr);
void checkUsers(struct Client *sptr, struct Channel *chptr, int flags);
void checkClient(struct Client *sptr, struct Client *acptr);
void checkServer(struct Client *sptr, struct Client *acptr);
signed int checkHostmask(struct Client *sptr, char *hoststr, int flags);

/*
 * - ASUKA ---------------------------------------------------------------------
 * This is the implimentation of the CHECK function for Asuka.
 * Some of this code is from previous QuakeNet ircds, but most of it is mine..
 * The old code was written by Durzel (durzel@quakenet.org).
 * 
 * qoreQ (qoreQ@quakenet.org) - 08/14/2002
 * -----------------------------------------------------------------------------
 */

/*
 * Syntax: CHECK <channel|nick|server|hostmask> [-flags]
 * 
 * Where valid flags are:
 * -c: Show channels when checking a hostmask.
 * -i: Show IPs instead of hostnames when displaying results.
 * -o: Only show channel operators when checking a channel.
 * -u: Hide users when checking a channel.
 * 
 * <hostmask> can be of the form host, user@host, nick!user@host, 
 * with host being host.domain.cc, 127.0.0.1 or 127.0.0.0/24.
 * Wildcards are supported.
 */
int mo_check(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
   struct Channel *chptr;
   struct Client *acptr;
   int flags = CHECK_SHOWUSERS, i;


   if (!HasPriv(sptr, PRIV_CHECK))
     return send_reply(sptr, ERR_DISABLED, "CHECK");

   if (parc < 2) {
      send_reply(sptr, ERR_NEEDMOREPARAMS, "CHECK");
      return 0;
   }

   if ( parc>=4 || (parc==3 && parv[2][0] != '-')) {
    /* remote query */
    if (hunt_server_cmd(sptr, CMD_CHECK, cptr, 0, parc==4 ? "%C %s %s" : "%C %s", 1, parc, parv) != HUNTED_ISME)
       return 0;
     parv++; parc--;
   }

   /* This checks to see if any flags have been supplied */
   if ((parc >= 3) && (parv[2][0] == '-')) {
    for (i = 0; parv[2][i]; i++) {
        switch (parv[2][i]) {
       case 'c':
         flags |= CHECK_CHECKCHAN;
         break;
        
       case 'o':
         flags |= CHECK_OPSONLY; /* fall through */
       case 'u':
         flags &= ~(CHECK_SHOWUSERS);
         break;
        
       case 'i':
         flags |= CHECK_SHOWIPS;
         break;
        
       default:
         /* might want to raise some sort of error here? */
         break;
       }
     }
   }

   if (IsChannelName(parv[1]))  /* channel */
   {
      if ((chptr = FindChannel(parv[1])))
      {
         checkChannel(sptr, chptr);
         checkUsers(sptr, chptr, flags);
      }
      else
      {
         send_reply(sptr, ERR_SEARCHNOMATCH, "CHECK", parv[1]);
      }
   }
   else if ((acptr = FindClient(parv[1])) && !(FindServer(parv[1])))  /* client and not a server */
   {
      if (!IsRegistered(acptr))
   	{
         send_reply(sptr, ERR_SEARCHNOMATCH, "CHECK", parv[1]);
         return 0;
      }

    checkClient(sptr, acptr);
   }
   else if ((acptr = FindServer(parv[1]))) { /* server */
     checkServer(sptr, acptr);
   }
   else if (checkHostmask(sptr, parv[1], flags) > 0) /* hostmask */
     return 1;
   else /* no match */
     send_reply(sptr, ERR_SEARCHNOMATCH, "CHECK", parv[1]);

 
  return 1;
}

static int checkClones(struct Channel *chptr, char *nick, char *host) {
  int clones = 0;
  struct Membership *lp;
  struct Client *acptr;

  for (lp = chptr->members; lp; lp = lp->next_member) {
    acptr = lp->user;
    if (!strcmp(acptr->cli_user->realhost, host) && strcmp(acptr->cli_name, nick)) {
      /* this is a clone */
      clones++;
    }
  }

  return ((clones) ? clones + 1 : 0);
}

void checkUsers(struct Client *sptr, struct Channel *chptr, int flags) {
  struct Membership *lp;
  struct Ban *slp;
  struct Client *acptr;

   char outbuf[BUFSIZE], ustat[64], oplvl[4];
   int cntr = 0, opcntr = 0, hopcntr = 0, vcntr = 0, clones = 0, bans = 0, c = 0, authed = 0, delayed = 0;

   if (flags & CHECK_SHOWUSERS) {
     if (feature_bool(FEAT_HALFOPS))
       send_reply(sptr, RPL_DATASTR, "Users (@ = op, % = halfop, + = voice, < = delayed)");
     else
       send_reply(sptr, RPL_DATASTR, "Users (@ = op, + = voice, < = delayed)");
   }

   for (lp = chptr->members; lp; lp = lp->next_member)
   {
      int opped = 0;

      acptr = lp->user;

      if ((c = checkClones(chptr, acptr->cli_name, acptr->cli_user->realhost)) != 0)
      {
         ircd_snprintf(0, ustat, sizeof(ustat), "%2d ", c);
         clones++;
      }
      else
      {
         strcpy(ustat, "   ");
      }

      if (chptr && IsZombie(lp))
         strcat(ustat, "!");
      else
         strcat(ustat, " ");

      if (chptr && IsDelayedJoin(lp))
      {
         strcat(ustat, "<");
         delayed++;
      }

      else if (chptr && IsChanOp(lp))
      {
         strcat(ustat, "@");
         opcntr++;
         opped = 1;
      }

      else if (chptr && IsHalfOp(lp))
      {
         strcat(ustat, "%");
         hopcntr++;
      }

      else if (chptr && HasVoice(lp))
      {
         strcat(ustat, "+");
         vcntr++;
      }
      else
         strcat(ustat, " ");

      if (feature_bool(FEAT_OPLEVELS) && opped)
         ircd_snprintf(0, oplvl, sizeof(oplvl), "%3d", OpLevel(lp));
      else
         ircd_snprintf(0, oplvl, sizeof(oplvl), "   ");

      if ((c = IsAccount(acptr)) != 0) ++authed;

      if ((flags & CHECK_SHOWUSERS) || ((flags & CHECK_OPSONLY) && opped)) {
        ircd_snprintf(0, outbuf, sizeof(outbuf), "%s%c", acptr->cli_info, COLOR_OFF);
        send_reply(sptr, RPL_CHANUSER, oplvl, ustat, acptr->cli_name, acptr->cli_user->username,
            (flags & CHECK_SHOWIPS) ? ircd_ntoa(&cli_ip(acptr)) : acptr->cli_user->realhost, outbuf, 
            (c ? acptr->cli_user->account : ""));
      }

      cntr++;
   }

   send_reply(sptr, RPL_DATASTR, " ");

   if (feature_bool(FEAT_HALFOPS))
     ircd_snprintf(0, outbuf, sizeof(outbuf),
        "Total users:: %d (%d ops, %d halfops, %d voiced, %d clones, %d authed, %d delayed)",
        cntr, opcntr, hopcntr, vcntr, clones, authed, delayed);
   else
     ircd_snprintf(0, outbuf, sizeof(outbuf),
        "Total users:: %d (%d ops, %d voiced, %d clones, %d authed, %d delayed)",
        cntr, opcntr, vcntr, clones, authed, delayed);

   send_reply(sptr, RPL_DATASTR, outbuf);

   send_reply(sptr, RPL_DATASTR, " ");

   /* Do not display bans if ! flags & CHECK_SHOWUSERS */
   if (!(flags & CHECK_SHOWUSERS)) {
     send_reply(sptr, RPL_ENDOFCHECK, " ");
     return;
   }

   /* Bans */
   send_reply(sptr, RPL_DATASTR, "Bans on channel::");

   for (slp = chptr->banlist; slp; slp = slp->next)
   {
      ircd_snprintf(0, outbuf, sizeof(outbuf),  "[%d] - %s - Set by %s, on %s", 
         ++bans, slp->banstr, slp->who, myctime(slp->when));
      send_reply(sptr, RPL_DATASTR, outbuf);
   }

   if (bans == 0)
     send_reply(sptr, RPL_DATASTR, "<none>");

   /* Ban Exceptions */
   if (feature_bool(FEAT_EXCEPTS)) {
     send_reply(sptr, RPL_DATASTR, " ");

     send_reply(sptr, RPL_DATASTR, "Excepts on channel::");
     bans = 0;

     for (slp = chptr->exceptlist; slp; slp = slp->next)
     {
        ircd_snprintf(0, outbuf, sizeof(outbuf),  "[%d] - %s - Set by %s, on %s",
                      ++bans, slp->banstr, slp->who, myctime(slp->when));
        send_reply(sptr, RPL_DATASTR, outbuf);
     }

     if (bans == 0)
       send_reply(sptr, RPL_DATASTR, "<none>");
   }

   send_reply(sptr, RPL_ENDOFCHECK, " ");
}

void checkChannel(struct Client *sptr, struct Channel *chptr)
{
   char outbuf[TOPICLEN + MODEBUFLEN + 64], modebuf[MODEBUFLEN], parabuf[MODEBUFLEN];

   /* Header */
   send_reply(sptr, RPL_DATASTR, " ");
   send_reply(sptr, RPL_CHKHEAD, "channel", chptr->chname);
   send_reply(sptr, RPL_DATASTR, " ");

   /* Creation Time */
   ircd_snprintf(sptr, outbuf, sizeof(outbuf), "   Creation time:: %s", myctime(chptr->creationtime));
   send_reply(sptr, RPL_DATASTR, outbuf);

   /* Destruction time (if it channel has one) */
   if (chptr->destruct_event && (chptr->users < 1)) {
     ircd_snprintf(sptr, outbuf, sizeof(outbuf), "Destruction time:: %s", myctime(chptr->destruct_event->expires));
     send_reply(sptr, RPL_DATASTR, outbuf);
   }

   /* Topic */
   if (strlen(chptr->topic) <= 0)
      send_reply(sptr, RPL_DATASTR, "           Topic:: <none>");
   else {
      ircd_snprintf(sptr, outbuf, sizeof(outbuf), "           Topic:: %s", chptr->topic);
      send_reply(sptr, RPL_DATASTR, outbuf);

      /* ..set by */
      ircd_snprintf(sptr, outbuf, sizeof(outbuf), "          Set by:: %s", chptr->topic_nick);
      send_reply(sptr, RPL_DATASTR, outbuf);
   }

   /* Channel Modes */

   strcpy(outbuf, " Channel mode(s):: ");

   modebuf[0] = '\0';
   parabuf[0] = '\0';

   channel_modes(sptr, modebuf, parabuf, sizeof(modebuf), chptr, NULL);

   if(modebuf[1] == '\0')
      strcat(outbuf, "<none>");
   else if(*parabuf) {
      strcat(outbuf, modebuf);
      strcat(outbuf, " ");
      strcat(outbuf, parabuf);
   } else
      strcat(outbuf, modebuf);

   send_reply(sptr, RPL_DATASTR, outbuf);

   /* Don't send 'END OF CHECK' message, it's sent in checkUsers, which is called after this. */
}

void checkClient(struct Client *sptr, struct Client *acptr)
{
   struct Channel *chptr;
   struct Membership *lp;
   char outbuf[BUFSIZE];
   time_t nowr;
   int eflags = 0;
   char ebuf[BUFSIZE] = "";

   /* Header */
   send_reply(sptr, RPL_DATASTR, " ");
   send_reply(sptr, RPL_CHKHEAD, "user", acptr->cli_name);
   send_reply(sptr, RPL_DATASTR, " ");

   ircd_snprintf(0, outbuf, sizeof(outbuf), "           Nick:: %s (%s%s)", acptr->cli_name, NumNick(acptr));
   send_reply(sptr, RPL_DATASTR, outbuf);

   if (MyUser(acptr))
   {
      ircd_snprintf(0, outbuf, sizeof(outbuf),  "      Signed on:: %s", myctime(acptr->cli_firsttime));
      send_reply(sptr, RPL_DATASTR, outbuf);
   }

   ircd_snprintf(0, outbuf, sizeof(outbuf), "      Timestamp:: %s (%d)", myctime(acptr->cli_lastnick), acptr->cli_lastnick);
   send_reply(sptr, RPL_DATASTR, outbuf);


   if (IsHiddenHost(acptr))
   {
     ircd_snprintf(0, outbuf, sizeof(outbuf), "  User/Hostmask:: %s@%s", acptr->cli_user->username, acptr->cli_user->host);
     send_reply(sptr, RPL_DATASTR, outbuf);
   }

   ircd_snprintf(0, outbuf, sizeof(outbuf), " Real User/Host:: %s@%s (%s)", acptr->cli_user->username,
                 acptr->cli_user->realhost, ircd_ntoa(&cli_ip(acptr)));
   send_reply(sptr, RPL_DATASTR, outbuf);

   if (IsIPSpoofed(acptr))
   {
     ircd_snprintf(0, outbuf, sizeof(outbuf), "Connect host/ip:: %s (%s)", cli_connecthost(acptr), ircd_ntoa(&cli_connectip(acptr)));
     send_reply(sptr, RPL_DATASTR, outbuf);
   }

   ircd_snprintf(0, outbuf, sizeof(outbuf), "      Real Name:: %s%c", cli_info(acptr), COLOR_OFF);
   send_reply(sptr, RPL_DATASTR, outbuf);

   if (feature_bool(FEAT_GEOIP_ENABLE) && IsGeoIP(acptr))
   {
     ircd_snprintf(0, outbuf, sizeof(outbuf), "        Country:: %s (%s)", cli_countryname(acptr), cli_countrycode(acptr));
     send_reply(sptr, RPL_DATASTR, outbuf);

     ircd_snprintf(0, outbuf, sizeof(outbuf), "      Continent:: %s (%s)", cli_continentname(acptr), cli_continentcode(acptr));
     send_reply(sptr, RPL_DATASTR, outbuf);
   }

   if (IsService(cli_user(acptr)->server)) {
     if (acptr)
       send_reply(sptr, RPL_DATASTR, "         Status:: Network Service");
     else if (IsAnOper(acptr))
       send_reply(sptr, RPL_DATASTR, "         Status:: IRC Operator (service)");
     else 
       send_reply(sptr, RPL_DATASTR, "         Status:: Client (service)");
   } else if (IsAdmin(acptr)) {
     send_reply(sptr, RPL_DATASTR, "         Status:: IRC Administrator");
   } else if (IsAnOper(acptr)) {
     send_reply(sptr, RPL_DATASTR, "         Status:: IRC Operator");
   } else {
     send_reply(sptr, RPL_DATASTR, "         Status:: Client");
   }

   if (MyUser(acptr)) {
     ircd_snprintf(0, outbuf, sizeof(outbuf), "          Class:: %s", get_client_class(acptr));
     send_reply(sptr, RPL_DATASTR, outbuf);
   }

   client_check_privs(acptr, sptr);

   if (MyUser(acptr))
     client_check_caps(acptr, sptr);

   if (IsMarked(acptr))
     client_check_marks(acptr, sptr);

   ircd_snprintf(0, outbuf, sizeof(outbuf), "   Connected to:: %s", cli_name(acptr->cli_user->server));
   send_reply(sptr, RPL_DATASTR, outbuf);

   if (cli_version(acptr)) {
     if (strlen(cli_version(acptr)) > 0) {
       ircd_snprintf(0, outbuf, sizeof(outbuf), "   CTCP Version:: %s", cli_version(acptr));
       send_reply(sptr, RPL_DATASTR, outbuf);
     }
   }

   if (cli_user(acptr) && !EmptyString(cli_user(acptr)->swhois)) {
     ircd_snprintf(0, outbuf, sizeof(outbuf), "         SWHOIS:: %s", cli_user(acptr)->swhois);
     send_reply(sptr, RPL_DATASTR, outbuf);
   }

   if (cli_webirc(acptr)) {
     if (strlen(cli_webirc(acptr)) > 0) {
       ircd_snprintf(0, outbuf, sizeof(outbuf), "         WebIRC:: %s", cli_webirc(acptr));
       send_reply(sptr, RPL_DATASTR, outbuf);
     }
   }

   if (cli_killmark(acptr)) {
     if (strlen(cli_killmark(acptr)) > 0) {
       ircd_snprintf(0, outbuf, sizeof(outbuf), "           Kill:: %s", cli_killmark(acptr));
       send_reply(sptr, RPL_DATASTR, outbuf);
     }
   }

   if (cli_sslclifp(acptr) && (strlen(cli_sslclifp(acptr)) > 0)) {
     ircd_snprintf(0, outbuf, sizeof(outbuf), "SSL Fingerprint:: %s", cli_sslclifp(acptr));
     send_reply(sptr, RPL_DATASTR, outbuf);
   }

#ifdef USE_SSL
   if (MyConnect(acptr) && IsSSL(acptr)) {
    ircd_snprintf(0, outbuf, sizeof(outbuf), "    SSL Ciphers:: %s", ssl_get_cipher(cli_socket(acptr).ssl));
    send_reply(sptr, RPL_DATASTR, outbuf);
   }
#endif /* USE_SSL */

   if ((eflags = get_except_flags(acptr)) != 0) {
     if (eflags & EFLAG_SHUN) { if (ebuf[0]) { strcat(ebuf, ", "); } strcat(ebuf, "Shuns"); }
     if (eflags & EFLAG_KLINE) { if (ebuf[0]) { strcat(ebuf, ", "); } strcat(ebuf, "K:Lines"); }
     if (eflags & EFLAG_GLINE) { if (ebuf[0]) { strcat(ebuf, ", "); } strcat(ebuf, "G:Lines"); }
     if (eflags & EFLAG_ZLINE) { if (ebuf[0]) { strcat(ebuf, ", "); } strcat(ebuf, "Z:Lines"); }
     if (eflags & EFLAG_IDENT) { if (ebuf[0]) { strcat(ebuf, ", "); } strcat(ebuf, "Ident Lookups"); }
     if (eflags & EFLAG_RDNS) { if (ebuf[0]) { strcat(ebuf, ", "); } strcat(ebuf, "rDNS Lookups"); }
     if (eflags & EFLAG_IPCHECK) { if (ebuf[0]) { strcat(ebuf, ", "); } strcat(ebuf, "IPCheck"); }
     if (eflags & EFLAG_TARGLIMIT) { if (ebuf[0]) { strcat(ebuf, ", "); } strcat(ebuf, "Target Limiting"); }

     ircd_snprintf(0, outbuf, sizeof(outbuf), "     Exemptions:: %s", ebuf);
     send_reply(sptr, RPL_DATASTR, outbuf);
   }

   /* +s (SERV_NOTICE) is not relayed to us from remote servers,
    * so we cannot tell if a remote client has that mode set.
    * And hacking it onto the end of the output of umode_str is EVIL BAD AND WRONG
    * (and breaks if the user is +r) so we won't do that either.
    */

   if (strlen(umode_str(acptr)) < 1)
      strcpy(outbuf, "       Umode(s):: <none>");
   else
      ircd_snprintf(0, outbuf, sizeof(outbuf), "       Umode(s):: +%s", umode_str(acptr));

   send_reply(sptr, RPL_DATASTR, outbuf);

   if (acptr->cli_user->joined == 0)
      send_reply(sptr, RPL_DATASTR, "     Channel(s):: <none>");
   else if (acptr->cli_user->joined > 50) 
   {

      /* NB. As a sanity check, we DO NOT show the individual channels the
       *     client is on if it is on > 50 channels.  This is to prevent the ircd
       *     barfing ala Uworld when someone does /quote check Q :).. (I shouldn't imagine
       *     an Oper would want to see every single channel 'x' client is on anyway if
       *     they are on *that* many).
       */

      ircd_snprintf(0, outbuf, sizeof(outbuf), "     Channel(s):: - (total: %u)", acptr->cli_user->joined);
      send_reply(sptr, RPL_DATASTR, outbuf);
   }
   else
   {
      char chntext[BUFSIZE];
      int len = strlen("     Channel(s):: ");
      int mlen = strlen(me.cli_name) + len + strlen(sptr->cli_name);
      *chntext = '\0';

      strcpy(chntext, "     Channel(s):: ");
      for (lp = acptr->cli_user->channel; lp; lp = lp->next_channel) {
         chptr = lp->channel;
         if (len + strlen(chptr->chname) + mlen > BUFSIZE - 7) {
            send_reply(sptr, RPL_DATASTR, chntext);
            *chntext = '\0';
            strcpy(chntext, "     Channel(s):: ");
            len = strlen(chntext);
         }
         if (IsDeaf(acptr))
            *(chntext + len++) = '-';
         if (IsDelayedJoin(lp))
            *(chntext + len++) = '<';
         if (IsChanOp(lp))
            *(chntext + len++) = '@';
         if (HasVoice(lp))
            *(chntext + len++) = '+';
         if (IsOper(sptr) && !ShowChannel(sptr,chptr))
            *(chntext + len++) = '*';
         if (IsZombie(lp))
            *(chntext + len++) = '!';
         if (len)
            *(chntext + len) = '\0';

         strcpy(chntext + len, chptr->chname);
         len += strlen(chptr->chname);
         strcat(chntext + len, " ");
         len++;
      }

      if (chntext[0] != '\0')
        send_reply(sptr, RPL_DATASTR, chntext);
   }

   /* If client processing command ISN'T target (or a registered
    * Network Service), show idle time since the last time we
    * parsed something.
    */
   if (MyUser(acptr) && !(IsService(acptr) == -1) && !(strCasediff(acptr->cli_name, sptr->cli_name) == 0)) {
      nowr = CurrentTime - acptr->cli_user->last;
      ircd_snprintf(0, outbuf, sizeof(outbuf), "       Idle for:: %d days, %02ld:%02ld:%02ld",
         nowr / 86400, (nowr / 3600) % 24, (nowr / 60) % 60, nowr % 60);
      send_reply(sptr, RPL_DATASTR, outbuf);
   }

   /* Away message (if applicable) */
   if (acptr->cli_user->away) {
      ircd_snprintf(0, outbuf, sizeof(outbuf), "   Away message:: %s", acptr->cli_user->away);
      send_reply(sptr, RPL_DATASTR, outbuf);
   }

   /* If local user.. */

   if (MyUser(acptr)) {
      send_reply(sptr, RPL_DATASTR, " ");
      ircd_snprintf(0, outbuf, sizeof(outbuf), "          Ports:: %d -> %d (client -> server)",
         cli_port(acptr), cli_listener(acptr)->addr.port);
      send_reply(sptr, RPL_DATASTR, outbuf);
      if (feature_bool(FEAT_CHECK_EXTENDED)) {
        /* Note: sendq = receiveq for a client (it makes sense really) */
        ircd_snprintf(0, outbuf, sizeof(outbuf), "      Data sent:: %lu.%0.3u Kb (%u protocol messages)",
            (unsigned long)cli_receiveB(acptr) / 1024, (unsigned long)cli_receiveB(acptr) % 1024, cli_receiveM(acptr));
        send_reply(sptr, RPL_DATASTR, outbuf);
        ircd_snprintf(0, outbuf, sizeof(outbuf), "  Data received:: %lu.%0.3lu Kb (%u protocol messages)",
            (unsigned long)cli_sendB(acptr) / 1024, (unsigned long)cli_sendB(acptr) % 1024, cli_sendM(acptr));
        send_reply(sptr, RPL_DATASTR, outbuf);
        ircd_snprintf(0, outbuf, sizeof(outbuf), "  receiveQ size:: %d bytes (max. %d bytes)",
           DBufLength(&(cli_recvQ(acptr))), get_recvq(acptr));
        send_reply(sptr, RPL_DATASTR, outbuf);
        ircd_snprintf(0, outbuf, sizeof(outbuf), "     sendQ size:: %d bytes (max. %d bytes)",
           DBufLength(&(cli_sendQ(acptr))), get_sendq(acptr));                                
        send_reply(sptr, RPL_DATASTR, outbuf);                
      }
   }
   
   /* Send 'END OF CHECK' message */
   send_reply(sptr, RPL_ENDOFCHECK, " ");
}

void checkServer(struct Client *sptr, struct Client *acptr)
{
   char outbuf[BUFSIZE];

   /* Header */
   send_reply(sptr, RPL_DATASTR, " ");
   send_reply(sptr, RPL_CHKHEAD, "server", acptr->cli_name);
   send_reply(sptr, RPL_DATASTR, " ");

   ircd_snprintf(0, outbuf, sizeof(outbuf),  "   Connected at:: %s (%Tu)", myctime(acptr->cli_serv->timestamp), acptr->cli_serv->timestamp);
   send_reply(sptr, RPL_DATASTR, outbuf);

   ircd_snprintf(0, outbuf, sizeof(outbuf), "    Server name:: %s", acptr->cli_name);
   send_reply(sptr, RPL_DATASTR,  outbuf);

   if (cli_sslclifp(acptr) && (strlen(cli_sslclifp(acptr)) > 0)) {
     ircd_snprintf(0, outbuf, sizeof(outbuf), "SSL Fingerprint:: %s", cli_sslclifp(acptr));
     send_reply(sptr, RPL_DATASTR, outbuf);
   }

#ifdef USE_SSL
   if (MyConnect(acptr) && IsSSL(acptr)) {
    ircd_snprintf(0, outbuf, sizeof(outbuf), "    SSL Ciphers:: %s", ssl_get_cipher(cli_socket(acptr).ssl));
    send_reply(sptr, RPL_DATASTR, outbuf);
   }
#endif /* USE_SSL */

   ircd_snprintf(0, outbuf, sizeof(outbuf), "        Numeric:: %s --> %d", NumServ(acptr), base64toint(acptr->cli_yxx));
   send_reply(sptr, RPL_DATASTR, outbuf);

   ircd_snprintf(0, outbuf, sizeof(outbuf), "          Users:: %d / %d", (acptr == &me) ? UserStats.local_clients : cli_serv(acptr)->clients,
                 base64toint(cli_serv(acptr)->nn_capacity));
   send_reply(sptr, RPL_DATASTR, outbuf);

   if (IsBurst(acptr))
     send_reply(sptr, RPL_DATASTR, "         Status:: Bursting");
   else if (IsBurstAck(acptr))
     send_reply(sptr, RPL_DATASTR, "         Status:: Awaiting EOB Ack");
   else if (IsService(acptr))
     send_reply(sptr, RPL_DATASTR, "         Status:: Network Service");
   else if (IsHub(acptr))
     send_reply(sptr, RPL_DATASTR, "         Status:: Network Hub");

   ircd_snprintf(0, outbuf, sizeof(outbuf), "          Class:: %s", get_client_class(acptr));
   send_reply(sptr, RPL_DATASTR, outbuf);

   if (feature_bool(FEAT_CHECK_EXTENDED)) {
     int dlinkc = 0;
     struct DLink* slink = NULL;
    
     send_reply(sptr, RPL_DATASTR, " ");
     send_reply(sptr, RPL_DATASTR, "Downlinks::");
     for (slink = cli_serv(acptr)->down; slink; slink = slink->next) {
       ircd_snprintf(0, outbuf, sizeof(outbuf), "[%d] - %s%s", ++dlinkc, 
             IsBurst(slink->value.cptr) ? "*" : IsBurstAck(slink->value.cptr) ? "!" : IsService(slink->value.cptr) ? "=" : IsHub(slink->value.cptr) ? "+" : " ", 
             cli_name(slink->value.cptr));
       send_reply(sptr, RPL_DATASTR, outbuf);
     }

     if (!dlinkc)
       send_reply(sptr, RPL_DATASTR, "<none>");
   }

   /* Send 'END OF CHECK' message */
   send_reply(sptr, RPL_ENDOFCHECK, " ");
}

signed int checkHostmask(struct Client *sptr, char *hoststr, int flags) {
  struct Client *acptr;
  struct Channel *chptr;
  struct Membership *lp;
  int count = 0, found = 0;
  unsigned char cidr_check_bits = 0;
  char outbuf[BUFSIZE];
  char targhost[NICKLEN + USERLEN + HOSTLEN + 3], curhost[NICKLEN + USERLEN + HOSTLEN + 3];
  char nickm[NICKLEN + 1], userm[USERLEN + 1], hostm[HOSTLEN + 1];
  char *p = NULL;
  struct irc_in_addr cidr_check;

  strcpy(nickm,"*");
  strcpy(userm,"*");
  strcpy(hostm,"*");

  if (!strchr(hoststr, '!') && !strchr(hoststr, '@'))
    ircd_strncpy(hostm,hoststr,HOSTLEN);
  else {
    if ((p = strchr(hoststr, '@'))) {
      *p++ = '\0';
      if (*p) ircd_strncpy(hostm,p, HOSTLEN);
    }

    /* Get the nick!user mask */
    if ((p = strchr(hoststr, '!'))) {
      *p++ = '\0';
      if (*p) ircd_strncpy(userm,p,USERLEN);
      if (*hoststr) ircd_strncpy(nickm,hoststr,NICKLEN);
    }
    else if (*hoststr) {
      /* Durz: We should only do the following *IF* the hoststr has not already been
       * copied into hostm (ie. neither ! or @ specified).. otherwise, when we do
       * /quote check *.barrysworld.com - we end up with targhost as: *!*.barryswo@*.barrysworld.com
       */
      ircd_strncpy(userm,hoststr,USERLEN);
    }
  }

  if (ipmask_parse(hostm, &cidr_check, &cidr_check_bits) != 0) {
    flags |= CHECK_CIDRMASK;
    cidr_check = ipmask_clean(&cidr_check, cidr_check_bits);
  }

  /* Copy formatted string into "targhost" buffer */
  ircd_snprintf(0, targhost, sizeof(targhost),  "%s!%s@%s", nickm, userm, hostm);

  targhost[sizeof(targhost) - 1] = '\0';

  /* Note: we have to exclude the last client struct as it is not a real client
   * structure, and therefore any attempt to access elements in it would cause
   * a segfault.
   */

  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr)) {
    /* Dont process if acptr is a unregistered client, a server or a ping */
    if (!IsRegistered(acptr) || IsServer(acptr))
      continue;

    if (IsMe(acptr))   /* Always the last acptr record */
      break;

    if(count > feature_int(FEAT_MAX_CHECK_OUTPUT)) { /* sanity stuff */
      ircd_snprintf(0, outbuf, sizeof(outbuf), "More than %d results, truncating...", count);
      send_reply(sptr, RPL_DATASTR, outbuf);
      send_reply(sptr, RPL_ENDOFCHECK, " ");
      break;
    }

    /* Copy host info into buffer */
    curhost[0] = '\0';
    ircd_snprintf(0, curhost, sizeof(curhost), "%s!%s@%s", acptr->cli_name, acptr->cli_user->username, acptr->cli_user->realhost);

    if (flags & CHECK_CIDRMASK) {
      if (ipmask_check(&cli_ip(acptr), &cidr_check, cidr_check_bits) && !match(nickm, acptr->cli_name) 
            && (!match(userm, acptr->cli_user->username) || !match(userm, acptr->cli_user->username)))
        found = 1;
    }
    else {
      if(match((const char*)targhost,(const char*)curhost) == 0)
        found = 1;
      else {
        curhost[0] = '\0';
        ircd_snprintf(0, curhost, sizeof(curhost), "%s!%s@%s", acptr->cli_name, acptr->cli_user->username, acptr->cli_user->host);

        if(match((const char*)targhost,(const char*)curhost) == 0)
          found = 1;
      }
    }

    if (found == 1) {
      found = 0;  /* reset that so it doesn't get crazy go nuts */

      /* Show header if we've found at least 1 record */
      if (count == 0) {
        /* Output header */ 
        send_reply(sptr, RPL_DATASTR, " ");
        send_reply(sptr, RPL_CHKHEAD, "host", targhost);

        send_reply(sptr, RPL_DATASTR, " ");
        ircd_snprintf(0, outbuf, sizeof(outbuf),  "%s   %-*s%-*s%s", "No.", (NICKLEN + 2 ), "Nick",
                (USERLEN + 2), "User", "Host");
        send_reply(sptr, RPL_DATASTR, outbuf);
      }

      ircd_snprintf(0, outbuf, sizeof(outbuf), "%-4d  %-*s%-*s%s", (count+1), (NICKLEN + 2),
            acptr->cli_name, (USERLEN + 2), acptr->cli_user->username, 
            (flags & CHECK_SHOWIPS) ? ircd_ntoa(&cli_ip(acptr)) : acptr->cli_user->realhost);
      send_reply(sptr, RPL_DATASTR, outbuf);

      /* Show channel output (if applicable) - the 50 channel limit sanity check
       * is specifically to prevent coredumping when someone lamely tries to /check
       * Q or some other channel service...
       */
      if (flags & CHECK_CHECKCHAN) {
        if (acptr->cli_user->joined > 0 && acptr->cli_user->joined <= 50) {
          char chntext[BUFSIZE];
          int len = strlen("      on channels: ");
          int mlen = strlen(me.cli_name) + len + strlen(sptr->cli_name);
          *chntext = '\0';

          strcpy(chntext, "      on channels: ");
          for (lp = acptr->cli_user->channel; lp; lp = lp->next_channel) {
            chptr = lp->channel;
            if (len + strlen(chptr->chname) + mlen > BUFSIZE - 5) {
              send_reply(sptr, RPL_DATASTR, chntext);
              *chntext = '\0';
              strcpy(chntext, "      on channels: ");
              len = strlen(chntext);
            }
            if (IsDeaf(acptr))
              *(chntext + len++) = '-';
            if (is_chan_op(acptr, chptr))
              *(chntext + len++) = '@';
            if (is_half_op(acptr, chptr))
              *(chntext + len++) = '%';
            if (IsOper(sptr) && !ShowChannel(sptr,chptr))
              *(chntext + len++) = '*';
            else if (has_voice(acptr, chptr))
              *(chntext + len++) = '+';
            else if (IsZombie(lp))
              *(chntext + len++) = '!';
            if (len)
              *(chntext + len) = '\0';

            strcpy(chntext + len, chptr->chname);
            len += strlen(chptr->chname);
            strcat(chntext + len, " ");
            len++;
          }
          if (chntext[0] != '\0')
            send_reply(sptr, RPL_DATASTR, chntext);

          send_reply(sptr, RPL_DATASTR, " ");
        }
      }
      count++;
    }
  }

  if (count > 0) {
    send_reply(sptr, RPL_DATASTR, " ");

    ircd_snprintf(0, outbuf, sizeof(outbuf), "Matching records found:: %d", count);
    send_reply(sptr, RPL_DATASTR, outbuf);

    send_reply(sptr, RPL_ENDOFCHECK, " ");
  }

  return count;
}

