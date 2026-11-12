/*
 * IRC - Internet Relay Chat, ircd/m_burst.c
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
 *
 * $Id: m_burst.c 1941 2010-01-14 02:35:51Z entrope $
 */

/*
 * m_functions execute protocol messages on this server:
 *
 *    cptr    is always NON-NULL, pointing to a *LOCAL* client
 *            structure (with an open socket connected!). This
 *            identifies the physical socket where the message
 *            originated (or which caused the m_function to be
 *            executed--some m_functions may call others...).
 *
 *    sptr    is the source of the message, defined by the
 *            prefix part of the message if present. If not
 *            or prefix not found, then sptr==cptr.
 *
 *            (!IsServer(cptr)) => (cptr == sptr), because
 *            prefixes are taken *only* from servers...
 *
 *            (IsServer(cptr))
 *                    (sptr == cptr) => the message didn't
 *                    have the prefix.
 *
 *                    (sptr != cptr && IsServer(sptr) means
 *                    the prefix specified servername. (?)
 *
 *                    (sptr != cptr && !IsServer(sptr) means
 *                    that message originated from a remote
 *                    user (not local).
 *
 *            combining
 *
 *            (!IsServer(sptr)) means that, sptr can safely
 *            taken as defining the target structure of the
 *            message in this server.
 *
 *    *Always* true (if 'parse' and others are working correct):
 *
 *    1)      sptr->from == cptr  (note: cptr->from == cptr)
 *
 *    2)      MyConnect(sptr) <=> sptr == cptr (e.g. sptr
 *            *cannot* be a local connection, unless it's
 *            actually cptr!). [MyConnect(x) should probably
 *            be defined as (x == x->from) --msa ]
 *
 *    parc    number of variable parameter strings (if zero,
 *            parv is allowed to be NULL)
 *
 *    parv    a NULL terminated list of parameter pointers,
 *
 *                    parv[0], sender (prefix string), if not present
 *                            this points to an empty string.
 *                    parv[1]...parv[parc-1]
 *                            pointers to additional parameters
 *                    parv[parc] == NULL, *always*
 *
 *            note:   it is guaranteed that parv[0]..parv[parc-1] are all
 *                    non-NULL pointers.
 */
#include "config.h"

#include "channel.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "list.h"
#include "match.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_conf.h"
#include "s_misc.h"
#include "send.h"
#include "struct.h"
#include "sys.h"
#include "ircd_snprintf.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static int
netride_modes(int parc, char **parv, const char *curr_key)
{
  char *modes = parv[0];
  int result = 0;

  assert(modes && modes[0] == '+');
  while (*modes) {
    switch (*modes++) {
    case '-':
      return -1;
    case 'i':
      result |= MODE_INVITEONLY;
      break;
    case 'k':
      if (--parc > 0 && strcmp(curr_key, *++parv))
        result |= MODE_KEY;
      break;
    case 'l':
      if (--parc > 0)
        ++parv;
      break;
    case 'r':
      result |= MODE_REGONLY;
      break;
    }
  }
  return result;
}

static int
netride_exmodes(int parc, char **parv, const char *curr_key)
{
  char *modes = parv[0];
  int result = 0;

  assert(modes && modes[0] == '+');
  while (*modes) {
    switch (*modes++) {
    case '-':
      return -1;
    case 'a':
      result |= EXMODE_ADMINONLY;
      break;
    case 'O':
      result |= EXMODE_OPERONLY;
      break;
    case 'Z':
      result |= EXMODE_SSLONLY;
    }
  }
  return result;
}

/** The BURST lines ms_burst() relays for the one it received, in two
 * forms: with op-levels for the peers that have them, and with "o" for
 * the others.  What is relayed can be longer than what came in -- a short
 * ban mask is expanded ("a" becomes "a!*@*"), a member's mode field can
 * grow -- so it goes on as many lines as it needs, split as
 * send_channel_modes() splits a channel's own BURST: each line starts
 * "<source> B <channel> <timestamp>", the modes go on the first one, and
 * members and bans continue on the next.  Each buffer holds at most one
 * line, so no input overruns it. */
struct BurstRelay {
  struct Client *sptr;          /**< Source of the BURST. */
  struct Client *cptr;          /**< The link it came from: not sent back. */
  struct Channel *chptr;        /**< The channel. */
  int room;                     /**< Bytes a line has after its prefix. */
  int excepts;                  /**< Ban exceptions are relayed (EXCEPTS). */
  int modes_pending;            /**< The modes are not on a line yet. */
  int lines;                    /**< Lines sent so far. */
  int nickpos, nickposo, banpos, expos;
  char modestr[BUFSIZE], modestro[BUFSIZE];  /**< " +modes params" or "" */
  char nickstr[BUFSIZE], nickstro[BUFSIZE];  /**< " nick[:mode],..." or "" */
  char banstr[BUFSIZE];         /**< " :%ban ban" (and the separator
                                 *   before the exceptions) or "" */
  char exstr[BUFSIZE];          /**< "~ except except" or "" */
};

/** Start the relay of a BURST of @a chptr from @a sptr, received on
 * @a cptr.  Called once the channel has its final timestamp. */
static void burst_relay_init(struct BurstRelay *rl, struct Client *sptr,
                             struct Client *cptr, struct Channel *chptr)
{
  char ts[24];
  int prefix;

  rl->sptr = sptr;
  rl->cptr = cptr;
  rl->chptr = chptr;
  rl->excepts = feature_bool(FEAT_EXCEPTS);
  rl->modes_pending = rl->lines = 0;
  rl->nickpos = rl->nickposo = rl->banpos = rl->expos = 0;
  rl->modestr[0] = rl->modestro[0] = '\0';
  ircd_snprintf(0, ts, sizeof(ts), "%Tu", chptr->creationtime);
  /* "<source> B <channel> <ts>", the source a numnick of at most
   * NUMNICKLEN characters; a line is at most BUFSIZE - 2 before CR LF. */
  prefix = NUMNICKLEN + 3 + strlen(chptr->chname) + 1 + strlen(ts);
  rl->room = IRCD_MAX(BUFSIZE - 2 - prefix, 0);
}

/** Whether the line being built has nothing on it. */
static int burst_relay_empty(const struct BurstRelay *rl)
{
  return !rl->modes_pending && !rl->nickpos && !rl->nickposo
    && !rl->banpos && !rl->expos;
}

/** Bytes the line being built takes, in its longer form. */
static int burst_relay_used(const struct BurstRelay *rl)
{
  int used = 0;

  if (rl->modes_pending)
    used += IRCD_MAX(strlen(rl->modestr), strlen(rl->modestro));
  used += IRCD_MAX(rl->nickpos, rl->nickposo) + rl->banpos;
  if (rl->excepts)
    used += rl->expos;
  return used;
}

/** Send the line built so far, in both forms, and start an empty one. */
static void burst_relay_send(struct BurstRelay *rl)
{
  const char *modes = rl->modes_pending ? rl->modestr : "";
  const char *modeso = rl->modes_pending ? rl->modestro : "";

  rl->nickstr[rl->nickpos] = '\0';
  rl->nickstro[rl->nickposo] = '\0';
  rl->banstr[rl->banpos] = '\0';
  rl->exstr[rl->expos] = '\0';

  /* Send oplevels to servers with oplevels support. */
  sendcmdto_flag_serv_butone(rl->sptr, CMD_BURST, rl->cptr, FLAG_OPLEVELS,
                             FLAG_LAST_FLAG, "%H %Tu%s%s%s%s", rl->chptr,
                             rl->chptr->creationtime, modes, rl->nickstr,
                             rl->banstr, rl->excepts ? rl->exstr : "");
  /* Send mode o to servers without oplevels support. */
  sendcmdto_flag_serv_butone(rl->sptr, CMD_BURST, rl->cptr, FLAG_LAST_FLAG,
                             FLAG_OPLEVELS, "%H %Tu%s%s%s%s", rl->chptr,
                             rl->chptr->creationtime, modeso, rl->nickstro,
                             rl->banstr, rl->excepts ? rl->exstr : "");

  rl->modes_pending = 0;
  rl->nickpos = rl->nickposo = rl->banpos = rl->expos = 0;
  rl->lines++;
}

/** Make room for @a len more bytes on the line being built: when they do
 * not fit, send the line and start a new one.
 * @return Non-zero when a new line was started. */
static int burst_relay_need(struct BurstRelay *rl, int len)
{
  if (burst_relay_empty(rl) || burst_relay_used(rl) + len <= rl->room)
    return 0;
  burst_relay_send(rl);
  return 1;
}

/** Take the modes the BURST has set so far (@a mbuf) for the relay.
 * They go on the next line sent; normally that is the first, as the mode
 * parameters come before the members and bans. */
static void burst_relay_modes(struct BurstRelay *rl, struct ModeBuf *mbuf)
{
  char modes[BUFSIZE], modeso[BUFSIZE];

  modebuf_extract(mbuf, modes + 1, 1);
  modebuf_extract(mbuf, modeso + 1, 0);
  modes[0] = modes[1] ? ' ' : '\0';
  modeso[0] = modeso[1] ? ' ' : '\0';
  if (!strcmp(modes, rl->modestr) && !strcmp(modeso, rl->modestro))
    return;
  ircd_strncpy(rl->modestr, modes, sizeof(rl->modestr));
  ircd_strncpy(rl->modestro, modeso, sizeof(rl->modestro));
  rl->modes_pending = (modes[0] != '\0');
}

/** Relay a ban (@a except: a ban exception) the BURST added. */
static void burst_relay_ban(struct BurstRelay *rl, const char *ban, int except)
{
  int len = strlen(ban);

  if (except && !rl->excepts)
    return;             /* not relayed without EXCEPTS */

  /* " :%" opens the list, a space separates; an exception puts its
   * separator in banstr and itself in exstr, after the "~ " that ends the
   * bans. */
  burst_relay_need(rl, (rl->banpos ? 1 : 3)
                   + (except ? (rl->expos ? 1 : 2) : 0) + len);
  if (rl->banpos + 3 + len >= (int)sizeof(rl->banstr)
      || rl->expos + 2 + len >= (int)sizeof(rl->exstr))
    return;             /* longer than a line: cannot happen */

  if (!rl->banpos) {
    memcpy(rl->banstr, " :%", 3);
    rl->banpos = 3;
  } else
    rl->banstr[rl->banpos++] = ' ';

  if (except) {
    if (!rl->expos) {
      memcpy(rl->exstr, "~ ", 2);
      rl->expos = 2;
    } else
      rl->exstr[rl->expos++] = ' ';
    memcpy(rl->exstr + rl->expos, ban, len);
    rl->expos += len;
  } else {
    memcpy(rl->banstr + rl->banpos, ban, len);
    rl->banpos += len;
  }
}

/** Relay a member the BURST named: @a ent in the op-level form, @a ento
 * in the "o" form, each with its separator, both from
 * burst_member_entry().  The caller has made room with
 * burst_relay_need(). */
static void burst_relay_member(struct BurstRelay *rl, const char *ent,
                               const char *ento)
{
  int len = strlen(ent), leno = strlen(ento);

  if (rl->nickpos + len >= (int)sizeof(rl->nickstr)
      || rl->nickposo + leno >= (int)sizeof(rl->nickstro))
    return;             /* longer than a line: cannot happen */
  memcpy(rl->nickstr + rl->nickpos, ent, len);
  rl->nickpos += len;
  memcpy(rl->nickstro + rl->nickposo, ento, leno);
  rl->nickposo += leno;
}

/** Size of a member's relay entry: a separator, the numnick, and a mode
 * field (':', 'v', 'h', and an op-level of up to ten digits). */
#define BURST_ENTRY_LEN (1 + NUMNICKLEN + 3 + 10 + 1)

/** A member's entry in the relayed member list, in both forms: the
 * separator (@a first: ' ', else ','), @a nick, and a ":<mode>" field
 * when its mode (@a mode, @a oplevel) is not the one the previous entry
 * left (@a last_mode, @a last_oplevel), which are updated.  @a nick is a
 * numnick findNUser() resolved, so at most NUMNICKLEN characters. */
static void burst_member_entry(char *ent, char *ento, int first,
                               const char *nick, int mode, int oplevel,
                               int *last_mode, int *last_oplevel)
{
  char num[16];
  int pos = 0, poso = 0;

  ent[pos++] = ento[poso++] = first ? ' ' : ',';
  for (; *nick && pos < 1 + NUMNICKLEN; nick++)
    ent[pos++] = ento[poso++] = *nick;

  if (mode != *last_mode) { /* if mode changed... */
    *last_mode = mode;
    *last_oplevel = oplevel;

    ent[pos++] = ento[poso++] = ':'; /* add a specifier */
    if (mode & CHFL_VOICE)
      ent[pos++] = ento[poso++] = 'v';
    if (mode & CHFL_HALFOP)
      ent[pos++] = ento[poso++] = 'h';
    if (mode & CHFL_CHANOP) {
      if (oplevel != MAXOPLEVEL) {
        ircd_snprintf(0, num, sizeof(num), "%u", oplevel);
        memcpy(ent + pos, num, strlen(num));
        pos += strlen(num);
      } else
        ent[pos++] = 'o';
      ento[poso++] = 'o';
    }
  } else if (mode & CHFL_CHANOP && oplevel != *last_oplevel) {
    /* if just op level changed... */
    ent[pos++] = ento[poso++] = ':'; /* add a specifier */
    ircd_snprintf(0, num, sizeof(num), "%u", oplevel - *last_oplevel);
    memcpy(ent + pos, num, strlen(num));
    pos += strlen(num);
    ento[poso++] = 'o';
    *last_oplevel = oplevel;
  }
  ent[pos] = ento[poso] = '\0';
}

/*
 * ms_burst - server message handler
 *
 * --  by Run carlo@runaway.xs4all.nl  december 1995 till march 1997
 *
 * parv[0] = sender prefix
 * parv[1] = channel name
 * parv[2] = channel timestamp
 * The meaning of the following parv[]'s depend on their first character:
 * If parv[n] starts with a '+':
 * Net burst, additive modes
 *   parv[n] = <mode>
 *   parv[n+1] = <param> (optional)
 *   parv[n+2] = <param> (optional)
 * If parv[n] starts with a '%', then n will be parc-1:
 *   parv[n] = %<ban> <ban> <ban> ...
 * If parv[n] starts with another character:
 *   parv[n] = <nick>[:<mode>],<nick>[:<mode>],...
 *   where <mode> defines the mode and op-level
 *   for nick and all following nicks until the
 *   next <mode> field.
 *   Digits in the <mode> field have of two meanings:
 *   1) if it is the first field in this BURST message
 *      that contains digits, and/or when a 'v' is
 *      present in the <mode>:
 *      The absolute value of the op-level.
 *   2) if there are only digits in this field and
 *      it is not the first field with digits:
 *      An op-level increment relative to the previous
 *      op-level.
 *   First all modeless nicks must be emmitted,
 *   then all combinations of modes without ops
 *   (currently that is only 'v') followed by the same
 *   series but then with ops (currently 'o','ov').
 *
 * Example:
 * "A8 B #test 87654321 +ntkAl key secret 123 A8AAG,A8AAC:v,A8AAA:0,A8AAF:2,A8AAD,A8AAB:v1,A8AAE:1 :%ban1 ban2"
 *
 * <mode> list example:
 *
 * "xxx,sss:v,ttt,aaa:123,bbb,ccc:2,ddd,kkk:v2,lll:2,mmm"
 *
 * means
 *
 *  xxx		// first modeless nicks
 *  sss +v	// then opless nicks
 *  ttt +v	// no ":<mode>": everything stays the same
 *  aaa -123	// first field with digit: absolute value
 *  bbb -123
 *  ccc -125	// only digits, not first field: increment
 *  ddd -125
 *  kkk -2 +v	// field with a 'v': absolute value
 *  lll -4 +v	// only digits: increment
 *  mmm -4 +v
 *
 * Anti net.ride code.
 *
 * When the channel already exist, and its TS is larger than
 * the TS in the BURST message, then we cancel all existing modes.
 * If its is smaller then the received BURST message is ignored.
 * If it's equal, then the received modes are just added.
 *
 * BURST is also accepted outside a netburst now because it
 * is sent upstream as reaction to a DESTRUCT message.  For
 * these BURST messages it is possible that the listed channel
 * members are already joined.
 */
int ms_burst(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct ModeBuf modebuf, *mbuf = 0;
  struct Channel *chptr;
  time_t timestamp;
  struct Membership *member, *nmember;
  struct Ban *lp, **lp_p;
  unsigned int parse_flags = (MODE_PARSE_FORCE | MODE_PARSE_BURST);
  int param, banned = 0, excepted = 0;
  struct BurstRelay relay;

  if (parc < 3)
    return protocol_violation(sptr,"Too few parameters for BURST");

  if (!(chptr = get_channel(sptr, parv[1], CGT_CREATE)))
    return 0; /* can't create the channel? */

  timestamp = atoi(parv[2]);

  if (chptr->creationtime)	/* 0 for new (empty) channels,
                                   i.e. when this server just restarted. */
  {
    if (parc == 3)		/* Zannel BURST? */
    {
      /* An empty channel without +A set, will cause a BURST message
	 with exactly 3 parameters (because all modes have been reset).
	 If the timestamp on such channels is only a few seconds older
	 from our own, then we ignore this burst: we do not deop our
	 own side.
	 Likewise, we expect the other (empty) side to copy our timestamp
	 from our own BURST message, even though it is slightly larger.

	 The reason for this is to allow people to join an empty
	 non-A channel (a zannel) during a net.split, and not be
	 deopped when the net reconnects (with another zannel). When
	 someone joins a split zannel, their side increments the TS by one.
	 If they cycle a few times then we still don't have a reason to
	 deop them. Theoretically I see no reason not to accept ANY timestamp,
	 but to be sure, we only accept timestamps that are just a few
	 seconds off (one second for each time they cycled the channel). */

      /* Don't even deop users who cycled four times during the net.break. */
      if (timestamp < chptr->creationtime &&
          chptr->creationtime <= timestamp + 4 &&
	  chptr->users != 0)	/* Only do this when WE have users, so that
	  			   if we do this the BURST that we sent has
				   parc > 3 and the other side will use the
				   test below: */
	timestamp = chptr->creationtime; /* Do not deop our side. */
    }
    else if (chptr->creationtime < timestamp &&
             timestamp <= chptr->creationtime + 4 &&
	     chptr->users == 0)
    {
      /* If one side of the net.junction does the above
         timestamp = chptr->creationtime, then the other
	 side must do this: */
      chptr->creationtime = timestamp;	/* Use the same TS on both sides. */
    }
    /* In more complex cases, we might still end up with a
       creationtime desync of a few seconds, but that should
       be synced automatically rather quickly (every JOIN
       caries a timestamp and will sync it; modes by users do
       not carry timestamps and are accepted regardless).
       Only when nobody joins the channel on the side with
       the oldest timestamp before a new net.break occurs
       precisely inbetween the desync, an unexpected bounce
       might happen on reconnect. */
  }

  if (!chptr->creationtime || chptr->creationtime > timestamp) {
    /*
     * Kick local members if channel is +i or +k and our TS was larger
     * than the burst TS (anti net.ride). The modes hack is here because
     * we have to do this before mode_parse, as chptr may go away.
     */
    for (param = 3; param < parc; param++)
    {
      int check_modes, check_exmodes;
      if (parv[param][0] != '+')
        continue;
      check_modes = netride_modes(parc - param, parv + param, chptr->mode.key);
      check_exmodes = netride_exmodes(parc - param, parv + param, chptr->mode.key);
      if ((check_modes < 0) || (check_exmodes < 0))
      {
        if (chptr->users == 0)
          sub1_from_channel(chptr);
        return protocol_violation(sptr, "Invalid mode string in BURST");
      }
      else if (check_modes || check_exmodes)
      {
        /* Clear any outstanding rogue invites */
        mode_invite_clear(chptr);
        for (member = chptr->members; member; member = nmember)
        {
          nmember = member->next_member;
          if (!MyUser(member->user) || IsZombie(member))
            continue;
          /* Kick as netrider if key mismatch *or* remote channel is
           * +i (unless user is an oper) *or* remote channel is +r
           * (unless user has an account).
           */
          if (!(check_modes & MODE_KEY)
              && (!(check_modes & MODE_INVITEONLY) || IsAnOper(member->user))
              && (!(check_modes & MODE_REGONLY) || IsAccount(member->user))
              && (!(check_exmodes & EXMODE_ADMINONLY) || IsAdmin(member->user))
              && (!(check_exmodes & EXMODE_OPERONLY) || IsAnOper(member->user))
              && (!(check_exmodes & EXMODE_SSLONLY) || IsSSL(member->user)))
            continue;
          sendcmdto_serv_butone(&me, CMD_KICK, NULL, "%H %C :Net Rider", chptr, member->user);
          sendcmdto_channel_butserv_butone(&his, CMD_KICK, chptr, NULL, 0, "%H %C :Net Rider", chptr, member->user);
          make_zombie(member, member->user, &me, &me, chptr);
        }
      }
      break;
    }

    /* If the channel had only locals, it went away by now. */
    if (!(chptr = get_channel(sptr, parv[1], CGT_CREATE)))
      return 0; /* can't create the channel? */
  }

  /* turn off burst joined flag */
  for (member = chptr->members; member; member = member->next_member)
    member->status &= ~(CHFL_BURST_JOINED|CHFL_BURST_ALREADY_OPPED|CHFL_BURST_ALREADY_VOICED);

  if (!chptr->creationtime) /* mark channel as created during BURST */
    chptr->mode.mode |= MODE_BURSTADDED;

  /* new channel or an older one */
  if (!chptr->creationtime || chptr->creationtime > timestamp) {
    chptr->creationtime = timestamp;

    modebuf_init(mbuf = &modebuf, &me, cptr, chptr,
		 MODEBUF_DEST_CHANNEL | MODEBUF_DEST_NOKEY);
    modebuf_mode(mbuf, MODE_DEL | chptr->mode.mode); /* wipeout modes */
    chptr->mode.mode &= MODE_BURSTADDED | MODE_WASDELJOINS;

    /* wipeout any limit and keys that are set */
    parse_flags |= (MODE_PARSE_SET | MODE_PARSE_WIPEOUT);

    /* mark bans for wipeout */
    for (lp = chptr->banlist; lp; lp = lp->next)
      lp->flags |= BAN_BURST_WIPEOUT;

    /* mark ban exceptions for wipeout */
    for (lp = chptr->exceptlist; lp; lp = lp->next)
      lp->flags |= BAN_BURST_WIPEOUT;

    /* clear topic set by netrider (if set) */
    if (*chptr->topic) {
      *chptr->topic = '\0';
      *chptr->topic_nick = '\0';
      chptr->topic_time = 0;
      sendcmdto_channel_butserv_butone(&his, CMD_TOPIC, chptr, NULL, 0,
                                       "%H :%s", chptr, chptr->topic);
    }
  } else if (chptr->creationtime == timestamp) {
    modebuf_init(mbuf = &modebuf, &me, cptr, chptr,
		 MODEBUF_DEST_CHANNEL | MODEBUF_DEST_NOKEY);

    parse_flags |= MODE_PARSE_SET; /* set new modes */
  }

  burst_relay_init(&relay, sptr, cptr, chptr);

  param = 3; /* parse parameters */
  while (param < parc) {
    switch (*parv[param]) {
    case '+': /* parameter introduces a mode string */
      param += mode_parse(mbuf, cptr, sptr, chptr, parc - param,
			  parv + param, parse_flags, NULL);
      if (parse_flags & MODE_PARSE_SET)
        burst_relay_modes(&relay, mbuf);
      break;

    case '%': /* parameter contains bans */
      if (parse_flags & MODE_PARSE_SET) {
	char *banlist = parv[param] + 1, *p = 0, *ban;
	struct Ban *newban;
        int excepts = 0;

	for (ban = ircd_strtok(&p, banlist, " "); ban;
	     ban = ircd_strtok(&p, 0, " ")) {
          if ((*ban == '~') && (ban[1] == '\0')) {
            excepts = 1;
            continue;
          }

          ban = collapse(pretty_extmask(ban));

          if (!ban)
            continue;

	    /*
	     * Yeah, we should probably do this elsewhere, and make it better
	     * and more general; this will hold until we get there, though.
	     * I dislike the current add_banid API... -Kev
	     *
	     * I wish there were a better algo. for this than the n^2 one
	     * shown below *sigh*
	     */
	  for (lp = (excepts ? chptr->exceptlist : chptr->banlist); lp; lp = lp->next) {
	    if (!ircd_strcmp(lp->banstr, ban)) {
	      ban = 0; /* don't add ban */
	      lp->flags &= ~BAN_BURST_WIPEOUT; /* not wiping out */
	      break; /* new ban already existed; don't even repropagate */
	    } else if (!(lp->flags & BAN_BURST_WIPEOUT) &&
		       !mmatch(lp->banstr, ban)) {
	      ban = 0; /* don't add ban unless wiping out bans */
	      break; /* new ban is encompassed by an existing one; drop */
	    } else if (!mmatch(ban, lp->banstr))
	      lp->flags |= BAN_OVERLAPPED; /* remove overlapping ban */

	    if (!lp->next)
	      break;
	  }

	  if (ban) { /* add the new ban to the end of the list */
	    /* Relay it: a ban that does not fit the line goes on the next. */
	    burst_relay_ban(&relay, ban, excepts);
	    banned = 1;
	    if (excepts)
	      excepted = 1;

	    newban = make_ban(ban); /* create new ban */
            strcpy(newban->who, "*");
	    newban->when = TStime();
	    newban->flags |= BAN_BURSTED;
	    newban->next = 0;
	    if (lp)
	      lp->next = newban; /* link it in */
	    else
              if (excepts)
                chptr->exceptlist = newban;
              else
                chptr->banlist = newban;
	  }
	}
      } 
      param++; /* look at next param */
      break;

    default: /* parameter contains clients */
      {
	struct Client *acptr;
	char *nicklist = parv[param], *p = 0, *nick, *ptr;
	int current_mode, last_mode, base_mode;
	int oplevel = -1;	/* Mark first field with digits: means the same as 'o' (but with level). */
	int last_oplevel = 0;
	struct Membership* member;

        base_mode = CHFL_DEOPPED | CHFL_BURST_JOINED;
        if (chptr->mode.mode & MODE_DELJOINS)
            base_mode |= CHFL_DELAYED;
        current_mode = last_mode = base_mode;

	for (nick = ircd_strtok(&p, nicklist, ","); nick;
	     nick = ircd_strtok(&p, 0, ",")) {

	  if ((ptr = strchr(nick, ':'))) { /* new flags; deal */
	    *ptr++ = '\0';

	    if (parse_flags & MODE_PARSE_SET) {
	      int current_mode_needs_reset;
	      for (current_mode_needs_reset = 1; *ptr; ptr++) {
		if (*ptr == 'o') { /* has oper status */
		  /*
		   * An 'o' is pre-oplevel protocol, so this is only for
		   * backwards compatibility.  Give them an op-level of
		   * MAXOPLEVEL so everyone can deop them.
		   */
		  oplevel = MAXOPLEVEL;
		  if (current_mode_needs_reset) {
		    current_mode = base_mode;
		    current_mode_needs_reset = 0;
		  }
		  current_mode = (current_mode & ~(CHFL_DEOPPED | CHFL_DELAYED)) | CHFL_CHANOP;
                  /*
                   * Older servers may send XXYYY:ov, in which case we
                   * do not want to use the code for 'v' below.
                   */
                  if (ptr[1] == 'h') {
                    current_mode |= CHFL_HALFOP;
                    ptr++;
                  }
                  if (ptr[1] == 'v') {
                    current_mode |= CHFL_VOICE;
                    ptr++;
                  }
		}
                else if (*ptr == 'h') { /* has halfop status */
                  if (current_mode_needs_reset) {
                    current_mode = base_mode;
                    current_mode_needs_reset = 0;
                  }
                  current_mode = (current_mode & ~CHFL_DELAYED) | CHFL_HALFOP;
                  oplevel = -1; /* subsequent digits are an absolute op-level value. */

                  if (ptr[1] == 'v') {
                    current_mode |= CHFL_VOICE;
                    ptr++;
                  }
                }
		else if (*ptr == 'v') { /* has voice status */
		  if (current_mode_needs_reset) {
                    current_mode = base_mode;
		    current_mode_needs_reset = 0;
		  }
		  current_mode = (current_mode & ~CHFL_DELAYED) | CHFL_VOICE;
		  oplevel = -1;	/* subsequent digits are an absolute op-level value. */
                }
		else if (IsDigit(*ptr)) {
		  int level_increment = 0;
		  if (oplevel == -1) { /* op-level is absolute value? */
		    if (current_mode_needs_reset) {
		      current_mode = base_mode;
		      current_mode_needs_reset = 0;
		    }
		    oplevel = 0;
		  }
		  current_mode = (current_mode & ~(CHFL_DEOPPED | CHFL_DELAYED)) | CHFL_CHANOP;
		  do {
		    level_increment = 10 * level_increment + *ptr++ - '0';
		  } while (IsDigit(*ptr));
		  --ptr;
		  oplevel += level_increment;
                  if (oplevel > MAXOPLEVEL) {
                    protocol_violation(sptr, "Invalid cumulative oplevel %u during burst", oplevel);
                    oplevel = MAXOPLEVEL;
                    break;
                  }
		}
		else { /* I don't recognize that flag */
		  protocol_violation(sptr, "Invalid flag '%c' in nick part of burst", *ptr);
		  break; /* so stop processing */
		}
	      }
	    }
	  }

	  if (!(acptr = findNUser(nick)) || cli_from(acptr) != cptr)
	    continue; /* ignore this client */

	  /* Relay the member.  One that does not fit the line goes on the
	   * next, and states its mode there: a receiver reads each line's
	   * mode fields from scratch. */
	  {
	    char ent[BURST_ENTRY_LEN], ento[BURST_ENTRY_LEN];
	    int entry_mode = last_mode, entry_oplevel = last_oplevel;

	    burst_member_entry(ent, ento, !relay.nickpos, nick, current_mode,
	                       oplevel, &entry_mode, &entry_oplevel);
	    if (burst_relay_need(&relay, IRCD_MAX(strlen(ent), strlen(ento)))) {
	      entry_mode = base_mode;
	      entry_oplevel = 0;
	      burst_member_entry(ent, ento, 1, nick, current_mode, oplevel,
	                         &entry_mode, &entry_oplevel);
	    }
	    burst_relay_member(&relay, ent, ento);
	    last_mode = entry_mode;
	    last_oplevel = entry_oplevel;
	  }

	  if (!(member = find_member_link(chptr, acptr)))
	  {
	    add_user_to_channel(chptr, acptr, current_mode, oplevel);
            if (!(current_mode & CHFL_DELAYED)) {
              sendcmdto_channel_capab_butserv_butone(acptr, CMD_JOIN, chptr, NULL, 0,
                                                     CAP_NONE, CAP_EXTJOIN, "%H", chptr);
              sendcmdto_channel_capab_butserv_butone(acptr, CMD_JOIN, chptr, NULL, 0,
                                                     CAP_EXTJOIN, CAP_NONE, "%H %s :%s",
                                                     chptr, IsAccount(acptr) ? cli_account(acptr) : "*",
                                                     cli_info(acptr));
              if (cli_user(acptr)->away)
                sendcmdto_channel_capab_butserv_butone(acptr, CMD_AWAY, chptr, NULL, 0,
                                                       CAP_AWAYNOTIFY, CAP_NONE, ":%s",
                                                       cli_user(acptr)->away);
            }
	  }
	  else
	  {
	    /* The member was already joined (either by CREATE or JOIN).
	       Remember the current mode. */
	    if (member->status & CHFL_CHANOP)
	      member->status |= CHFL_BURST_ALREADY_OPPED;
            if (member->status & CHFL_HALFOP)
              member->status |= CHFL_BURST_ALREADY_HALFOPPED;
	    if (member->status & CHFL_VOICE)
	      member->status |= CHFL_BURST_ALREADY_VOICED;
	    /* Synchronize with the burst. */
	    member->status |= CHFL_BURST_JOINED | (current_mode & (CHFL_CHANOP|CHFL_HALFOP|CHFL_VOICE));
	    SetOpLevel(member, oplevel);
	  }
	}
      }
      param++;
      break;
    } /* switch (*parv[param]) */
  } /* while (param < parc) */

  /* Send the relay's last line (its only one, unless it was split; an
   * empty BURST is relayed as one). */
  if (parse_flags & MODE_PARSE_SET)
    burst_relay_modes(&relay, mbuf);
  if (!burst_relay_empty(&relay) || !relay.lines)
    burst_relay_send(&relay);

  if (parse_flags & MODE_PARSE_WIPEOUT || banned)
    mode_ban_invalidate(chptr);
  if (parse_flags & MODE_PARSE_WIPEOUT || excepted)
    mode_except_invalidate(chptr);

  if (parse_flags & MODE_PARSE_SET) { /* any modes changed? */
    /* first deal with channel members */
    for (member = chptr->members; member; member = member->next_member) {
      if (member->status & CHFL_BURST_JOINED) { /* joined during burst */
	if ((member->status & CHFL_CHANOP) && !(member->status & CHFL_BURST_ALREADY_OPPED))
	  modebuf_mode_client(mbuf, MODE_ADD | CHFL_CHANOP, member->user, OpLevel(member));
        if ((member->status & CHFL_HALFOP) && !(member->status & CHFL_BURST_ALREADY_HALFOPPED))
          modebuf_mode_client(mbuf, MODE_ADD | CHFL_HALFOP, member->user, OpLevel(member));
	if ((member->status & CHFL_VOICE) && !(member->status & CHFL_BURST_ALREADY_VOICED))
	  modebuf_mode_client(mbuf, MODE_ADD | CHFL_VOICE, member->user, OpLevel(member));
      } else if (parse_flags & MODE_PARSE_WIPEOUT) { /* wipeout old ops */
	if (member->status & CHFL_CHANOP)
	  modebuf_mode_client(mbuf, MODE_DEL | CHFL_CHANOP, member->user, OpLevel(member));
        if (member->status & CHFL_HALFOP)
          modebuf_mode_client(mbuf, MODE_DEL | CHFL_HALFOP, member->user, OpLevel(member));
	if (member->status & CHFL_VOICE)
	  modebuf_mode_client(mbuf, MODE_DEL | CHFL_VOICE, member->user, OpLevel(member));
	member->status = (member->status
                          & ~(CHFL_CHANNEL_MANAGER | CHFL_CHANOP | CHFL_HALFOP | CHFL_VOICE))
			 | CHFL_DEOPPED;
      }
    }

    /* Now deal with channel bans */
    lp_p = &chptr->banlist;
    while (*lp_p) {
      lp = *lp_p;

      /* remove ban from channel */
      if (lp->flags & (BAN_OVERLAPPED | BAN_BURST_WIPEOUT)) {
        char *bandup;
        DupString(bandup, lp->banstr);
	modebuf_mode_string(mbuf, MODE_DEL | MODE_BAN,
			    bandup, 1);
	*lp_p = lp->next; /* clip out of list */
        free_ban(lp);
	continue;
      } else if (lp->flags & BAN_BURSTED) /* add ban to channel */
	modebuf_mode_string(mbuf, MODE_ADD | MODE_BAN,
			    lp->banstr, 0); /* don't free banstr */

      lp->flags &= BAN_IPMASK | BAN_EXTENDED; /* reset the flag */
      lp_p = &(*lp_p)->next;
    }

    /* Now deal with channel ban exceptions */
    lp_p = &chptr->exceptlist;
    while (*lp_p) {
      lp = *lp_p;

      /* remove ban exceptionfrom channel */
      if (lp->flags & (BAN_OVERLAPPED | BAN_BURST_WIPEOUT)) {
        char *bandup;
        DupString(bandup, lp->banstr);
        modebuf_mode_string(mbuf, MODE_DEL | MODE_EXCEPT,
                            bandup, 1);
        *lp_p = lp->next; /* clip out of list */
        free_ban(lp);
        continue;
      } else if (lp->flags & BAN_BURSTED) /* add ban to channel */
        modebuf_mode_string(mbuf, MODE_ADD | MODE_EXCEPT,
                            lp->banstr, 0); /* don't free banstr */

      lp->flags &= BAN_IPMASK | BAN_EXTENDED; /* reset the flag */
      lp_p = &(*lp_p)->next;
    }
  }

  return mbuf ? modebuf_flush(mbuf) : 0;
}
