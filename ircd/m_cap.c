/*
 * IRC - Internet Relay Chat, ircd/m_cap.c
 * Copyright (C) 2004 Kevin L. Mitchell <klmitch@mit.edu>
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
 * @brief Capability negotiation commands
 * @version $Id: m_cap.c 1620 2006-02-16 03:49:55Z entrope $
 */

#include "config.h"

#include "bouncer_session.h"
#include "capab.h"
#include "client.h"
#include "ircd.h"
#include "ircd_chattr.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "metadata.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "querycmds.h"
#include "send.h"
#include "s_auth.h"
#include "s_user.h"

#include <stdlib.h>
#include <string.h>

/** Get effective SASL mechanisms (dynamic or default fallback).
 * @return Mechanism string, or NULL if none available.
 */
static const char *
get_effective_sasl_mechanisms(void)
{
  const char *mechs = get_sasl_mechanisms();
  if (mechs)
    return mechs;

  /* Fall back to configured default mechanisms (for legacy X3) */
  const char *default_mechs = feature_str(FEAT_SASL_DEFAULT_MECHANISMS);
  if (default_mechs && *default_mechs)
    return default_mechs;

  return NULL;
}

/** Check if the SASL server is available.
 * @return 1 if SASL server is connected and mechanisms available, 0 otherwise.
 */
static int
sasl_server_available(void)
{
  const char *sasl_server = feature_str(FEAT_SASL_SERVER);

  /* IAUTH can provide SASL independently of P10 services (supports fallback
   * when services disconnects). But we still require mechanisms - if IAUTH
   * announces SASL capability without providing mechanisms, don't advertise.
   * Note: IAUTH runs locally and supports dynamic mechanisms, so we check
   * IAUTH's own mechanism list directly - SASL_DEFAULT_MECHANISMS is only
   * for legacy X3 that can't advertise mechanisms dynamically. */
  if (auth_iauth_handles_sasl()) {
    return (auth_iauth_sasl_mechs() != NULL);
  }

  /* No mechanisms = no SASL, regardless of server connectivity */
  if (!get_effective_sasl_mechanisms())
    return 0;

  /* If set to "*", SASL is broadcast to all servers - check if any exist */
  if (!strcmp(sasl_server, "*"))
    return (UserStats.servers > 0);

  /* Otherwise, check if the specific SASL server is connected */
  return (find_match_server((char *)sasl_server) != NULL);
}

/**
 * Send CAP NEW or CAP DEL notification to all clients with cap-notify.
 * Per IRCv3 spec, servers MUST send CAP NEW when a capability becomes
 * available and CAP DEL when it becomes unavailable.
 * @param[in] capname Name of the capability (e.g., "sasl").
 * @param[in] available 1 if capability is now available, 0 if removed.
 * @param[in] value Optional value for CAP NEW (e.g., mechanism list). NULL for no value.
 */
void send_cap_notify(const char *capname, int available, const char *value)
{
  struct Client *cptr;

  /* Iterate all local clients with cap-notify enabled */
  for (cptr = GlobalClientList; cptr; cptr = cli_next(cptr)) {
    if (!MyConnect(cptr) || IsServer(cptr) || !IsUser(cptr))
      continue;
    if (!CapActive(cptr, CAP_CAPNOTIFY))
      continue;

    if (available) {
      /* CAP NEW with optional value */
      if (value && *value)
        sendrawto_one(cptr, "CAP %s NEW :%s=%s",
                      cli_name(cptr), capname, value);
      else
        sendrawto_one(cptr, "CAP %s NEW :%s", cli_name(cptr), capname);
    } else {
      /* CAP DEL */
      sendrawto_one(cptr, "CAP %s DEL :%s", cli_name(cptr), capname);
    }
  }
}

typedef int (*bqcmp)(const void *, const void *);

static struct capabilities {
  enum Capab cap;
  char *capstr;
  unsigned long flags;
  char *name;
  int namelen;
  int feat;
  char *value;           /**< CAP 302 value (e.g., "PLAIN,EXTERNAL" for sasl) */
} capab_list[] = {
#define _CAP(cap, flags, name, feat) \
    { CAP_ ## cap, #cap, (flags), (name), sizeof(name) - 1, feat, 0 }
#define _CAP_V(cap, flags, name, feat, val) \
    { CAP_ ## cap, #cap, (flags), (name), sizeof(name) - 1, feat, val }
  _CAP(NONE, CAPFL_HIDDEN|CAPFL_PROHIBIT, "none", 0),
  _CAP(NAMESX, 0, "multi-prefix", FEAT_CAP_multi_prefix),
  _CAP(UHNAMES, 0, "userhost-in-names", FEAT_CAP_userhost_in_names),
  _CAP(EXTJOIN, 0, "extended-join", FEAT_CAP_extended_join),
  _CAP(AWAYNOTIFY, 0, "away-notify", FEAT_CAP_away_notify),
  _CAP(ACCNOTIFY, 0, "account-notify", FEAT_CAP_account_notify),
  _CAP(SASL, 0, "sasl", FEAT_CAP_sasl),
  _CAP(CAPNOTIFY, 0, "cap-notify", FEAT_CAP_cap_notify),
  _CAP(SERVERTIME, 0, "server-time", FEAT_CAP_server_time),
  _CAP(ECHOMSG, 0, "echo-message", FEAT_CAP_echo_message),
  _CAP(ACCOUNTTAG, 0, "account-tag", FEAT_CAP_account_tag),
  _CAP(CHGHOST, 0, "chghost", FEAT_CAP_chghost),
  _CAP(INVITENOTIFY, 0, "invite-notify", FEAT_CAP_invite_notify),
  _CAP(LABELEDRESP, 0, "labeled-response", FEAT_CAP_labeled_response),
  _CAP(BATCH, 0, "batch", FEAT_CAP_batch),
  _CAP(SETNAME, 0, "setname", FEAT_CAP_setname),
  _CAP(STANDARDREPLIES, 0, "standard-replies", FEAT_CAP_standard_replies),
  _CAP(MSGTAGS, 0, "message-tags", FEAT_CAP_message_tags),
  _CAP(DRAFT_NOIMPLICITNAMES, 0, "draft/no-implicit-names", FEAT_CAP_draft_no_implicit_names),
  _CAP(DRAFT_EXTISUPPORT, 0, "draft/extended-isupport", FEAT_CAP_draft_extended_isupport),
  _CAP(DRAFT_PREAWAY, 0, "draft/pre-away", FEAT_CAP_draft_pre_away),
  _CAP(DRAFT_MULTILINE, 0, "draft/multiline", FEAT_CAP_draft_multiline),
  _CAP(DRAFT_CHATHISTORY, 0, "draft/chathistory", FEAT_CAP_draft_chathistory),
  _CAP(DRAFT_EVENTPLAYBACK, 0, "draft/event-playback", FEAT_CAP_draft_event_playback),
  _CAP(DRAFT_REDACT, 0, "draft/message-redaction", FEAT_CAP_draft_message_redaction),
  _CAP_V(DRAFT_ACCOUNTREG, 0, "draft/account-registration", FEAT_CAP_draft_account_registration, "before-connect,custom-account-name"),
  _CAP(DRAFT_READMARKER, 0, "draft/read-marker", FEAT_CAP_draft_read_marker),
  _CAP(DRAFT_CHANRENAME, 0, "draft/channel-rename", FEAT_CAP_draft_channel_rename),
  _CAP_V(DRAFT_METADATA2, 0, "draft/metadata-2", FEAT_CAP_draft_metadata_2, "max-subs=50,max-keys=20,max-value-bytes=300"),
  _CAP(DRAFT_WEBPUSH, 0, "draft/webpush", FEAT_CAP_draft_webpush),
  _CAP(DRAFT_BOUNCER, 0, "draft/bouncer", FEAT_CAP_draft_bouncer),
#ifdef USE_SSL
  _CAP(TLS, 0, "tls", FEAT_CAP_tls),
  _CAP(STS, CAPFL_PROHIBIT, "sts", FEAT_CAP_sts),
#endif
/*  CAPLIST */
#undef _CAP
#undef _CAP_V
};

#define CAPAB_LIST_LEN (sizeof(capab_list) / sizeof(struct capabilities))

static int
capab_sort(const struct capabilities *cap1, const struct capabilities *cap2)
{
  return ircd_strcmp(cap1->name, cap2->name);
}

static int
capab_search(const char *key, const struct capabilities *cap)
{
  const char *rb = cap->name;
  while (ToLower(*key) == ToLower(*rb)) /* walk equivalent part of strings */
    if (!*key++) /* hit the end, all right... */
      return 0;
    else /* OK, let's move on... */
      rb++;

  /* If the character they differ on happens to be a space, and it happens
   * to be the same length as the capability name, then we've found a
   * match; otherwise, return the difference of the two.
   */
  return (IsSpace(*key) && !*rb) ? 0 : (ToLower(*key) - ToLower(*rb));
}

static struct capabilities *
find_cap(const char **caplist_p, int *neg_p)
{
  static int inited = 0;
  const char *caplist = *caplist_p;
  struct capabilities *cap = 0;

  *neg_p = 0; /* clear negative flag... */

  if (!inited) { /* First, let's sort the array... */
    qsort(capab_list, CAPAB_LIST_LEN, sizeof(struct capabilities),
          (bqcmp)capab_sort);
    inited++; /* remember that we've done this step... */
  }

  /* Next, find first non-whitespace character... */
  while (*caplist && IsSpace(*caplist))
    caplist++;

  /* We are now at the beginning of an element of the list; is it negative? */
  if (*caplist == '-') {
    caplist++; /* yes; step past the flag... */
    *neg_p = 1; /* remember that it is negative... */
  }

  /* OK, now see if we can look up the capability... */
  if (*caplist) {
    if (!(cap = (struct capabilities *)bsearch(caplist, capab_list,
                 CAPAB_LIST_LEN,
                 sizeof(struct capabilities),
                 (bqcmp)capab_search))) {
      /* Couldn't find the capability; advance to first whitespace character */
      while (*caplist && !IsSpace(*caplist))
        caplist++;
    } else
      caplist += cap->namelen; /* advance to end of capability name */
  }

  assert(caplist != *caplist_p || !*caplist); /* we *must* advance */

  /* skip past any trailing whitespace... */
  while (*caplist && IsSpace(*caplist))
    caplist++;

  /* move ahead in capability list string--or zero pointer if we hit end */
  *caplist_p = *caplist ? caplist : 0;

  return cap; /* and return the capability (if any) */
}

/** Look up a capability by name from the capability list.
 * Initializes the sorted capability table on first call.
 * @param[in,out] caplist_p Pointer into capability name list string.
 *                          Advanced past the found cap (or past unknown caps).
 * @param[out] neg_p Set to 1 if prefixed with '-', 0 otherwise.
 * @param[out] cap_out Set to the capability enum value if found.
 * @param[out] flags_out Set to the capability flags if found.
 * @return 1 if a capability was found, 0 if not (end of list or unknown cap).
 */
int cap_lookup(const char **caplist_p, int *neg_p, int *cap_out, unsigned long *flags_out)
{
  struct capabilities *cap = find_cap(caplist_p, neg_p);
  if (cap) {
    *cap_out = cap->cap;
    *flags_out = cap->flags;
    return 1;
  }
  return 0;
}

/** Send a CAP \a subcmd list of capability changes to \a sptr.
 * If more than one line is necessary, each line before the last has
 * an added "*" parameter before that line's capability list (CAP 302).
 * @param[in] sptr Client receiving capability list.
 * @param[in] set Capabilities to show as set (with ack and sticky modifiers).
 * @param[in] rem Capabalities to show as removed (with no other modifier).
 * @param[in] subcmd Name of capability subcommand.
 */
static int
send_caplist(struct Client *sptr, const struct CapSet *set,
             const struct CapSet *rem, const char *subcmd)
{
  char capbuf[BUFSIZE] = "", pfx[16], valbuf[128];
  struct MsgBuf *mb;
  int i, loc, len, flags, pfx_len, val_len;
  int cap_version = cli_capab_version(sptr);
  int is_ls = (ircd_strcmp(subcmd, "LS") == 0);

  /* set up the buffer for the final LS message... */
  mb = msgq_make(sptr, "%:#C " MSG_CAP " %s %s :", &me,
                 BadPtr(cli_name(sptr)) ? "*" : cli_name(sptr), subcmd);

  for (i = 0, loc = 0; i < CAPAB_LIST_LEN; i++) {
    flags = capab_list[i].flags;
    /* This is a little bit subtle, but just involves applying de
     * Morgan's laws to the obvious check: We must display the
     * capability if (and only if) it is set in \a rem or \a set, or
     * if both are null and the capability is hidden.
     */
    if (!(rem && CapHas(rem, capab_list[i].cap))
        && !(set && CapHas(set, capab_list[i].cap))
        && (rem || set || (flags & CAPFL_HIDDEN)
            || (capab_list[i].feat && (!feature_bool(capab_list[i].feat)))))
      continue;

    /* Don't advertise SASL if the SASL server is not available */
    if (capab_list[i].cap == CAP_SASL && is_ls && !sasl_server_available())
      continue;

#ifdef USE_SSL
    /* STS requires CAP 302+ for values to be meaningful */
    if (capab_list[i].cap == CAP_STS && is_ls && cap_version < 302)
      continue;
#endif

    /* Build the prefix (space separator and any modifiers needed). */
    pfx_len = 0;
    if (loc)
      pfx[pfx_len++] = ' ';
    if (rem && CapHas(rem, capab_list[i].cap))
        pfx[pfx_len++] = '-';
    else {
      if (flags & CAPFL_PROTO)
        pfx[pfx_len++] = '~';
      if (flags & CAPFL_STICKY)
        pfx[pfx_len++] = '=';
    }
    pfx[pfx_len] = '\0';

    /* Build value string for CAP 302+ */
    valbuf[0] = '\0';
    val_len = 0;
    if (is_ls && cap_version >= 302) {
      /* For SASL, use effective mechanism list (dynamic or default fallback) */
      if (capab_list[i].cap == CAP_SASL) {
        const char *mechs = get_effective_sasl_mechanisms();
        if (mechs)
          val_len = ircd_snprintf(0, valbuf, sizeof(valbuf), "=%s", mechs);
      } else if (capab_list[i].cap == CAP_DRAFT_MULTILINE) {
        /* Build dynamic multiline value from features */
        val_len = ircd_snprintf(0, valbuf, sizeof(valbuf), "=max-bytes=%d,max-lines=%d",
                                feature_int(FEAT_MULTILINE_MAX_BYTES),
                                feature_int(FEAT_MULTILINE_MAX_LINES));
      } else if (capab_list[i].cap == CAP_DRAFT_WEBPUSH) {
        /* Show VAPID key if available from services */
        const char *vapid = get_vapid_pubkey();
        if (vapid)
          val_len = ircd_snprintf(0, valbuf, sizeof(valbuf), "=vapid=%s", vapid);
      } else if (capab_list[i].cap == CAP_DRAFT_CHATHISTORY) {
        /* Build chathistory value with limit, retention, and optional pm flag */
        int retention_days = feature_int(FEAT_CHATHISTORY_RETENTION);
        if (feature_bool(FEAT_CHATHISTORY_PRIVATE)) {
          val_len = ircd_snprintf(0, valbuf, sizeof(valbuf), "=limit=%d,retention=%dd,pm",
                                  feature_int(FEAT_CHATHISTORY_MAX), retention_days);
        } else {
          val_len = ircd_snprintf(0, valbuf, sizeof(valbuf), "=limit=%d,retention=%dd",
                                  feature_int(FEAT_CHATHISTORY_MAX), retention_days);
        }
#ifdef USE_SSL
      } else if (capab_list[i].cap == CAP_STS) {
        /* STS value depends on whether connection is secure or not */
        if (IsSSL(sptr)) {
          /* Secure connection: advertise duration (and optional preload) */
          int duration = feature_int(FEAT_STS_DURATION);
          if (feature_bool(FEAT_STS_PRELOAD)) {
            val_len = ircd_snprintf(0, valbuf, sizeof(valbuf), "=duration=%d,preload", duration);
          } else {
            val_len = ircd_snprintf(0, valbuf, sizeof(valbuf), "=duration=%d", duration);
          }
        } else {
          /* Insecure connection: advertise secure port to upgrade to */
          int port = feature_int(FEAT_STS_PORT);
          val_len = ircd_snprintf(0, valbuf, sizeof(valbuf), "=port=%d", port);
        }
#endif
      } else if (capab_list[i].value) {
        val_len = ircd_snprintf(0, valbuf, sizeof(valbuf), "=%s", capab_list[i].value);
      }
    }

    len = capab_list[i].namelen + pfx_len + val_len; /* how much we'd add... */
    if (msgq_bufleft(mb) < loc + len + 2) { /* would add too much; must flush */
      /* For CAP 302+, use * continuation marker */
      if (cap_version >= 302) {
        sendcmdto_one(&me, CMD_CAP, sptr, "%s %s * :%s",
                      BadPtr(cli_name(sptr)) ? "*" : cli_name(sptr), subcmd, capbuf);
      } else {
        sendcmdto_one(&me, CMD_CAP, sptr, "%s %s :%s",
                      BadPtr(cli_name(sptr)) ? "*" : cli_name(sptr), subcmd, capbuf);
      }
      capbuf[(loc = 0)] = '\0'; /* re-terminate the buffer... */
    }

    loc += ircd_snprintf(0, capbuf + loc, sizeof(capbuf) - loc, "%s%s%s",
                         pfx, capab_list[i].name, valbuf);
  }

  msgq_append(0, mb, "%s", capbuf); /* append capabilities to the final cmd */
  send_buffer(sptr, mb, 0); /* send them out... */
  msgq_clean(mb); /* and release the buffer */

  return 0; /* convenience return */
}

static int
cap_ls(struct Client *sptr, const char *caplist)
{
  if (IsUnknown(sptr) && cli_auth(sptr)) /* registration hasn't completed; suspend it... */
    auth_cap_start(cli_auth(sptr));

  /* Parse CAP version from CAP LS 302 */
  if (caplist && *caplist) {
    int version = atoi(caplist);
    if (version > 0)
      cli_capab_version(sptr) = version;
  }

  return send_caplist(sptr, 0, 0, "LS"); /* send list of capabilities */
}

static int
cap_req(struct Client *sptr, const char *caplist)
{
  const char *cl = caplist;
  struct capabilities *cap;
  struct CapSet set, rem;
  struct CapSet cs = *cli_capab(sptr); /* capability set */
  struct CapSet as = *cli_active(sptr); /* active set */
  int neg;

  if (IsUnknown(sptr) && cli_auth(sptr)) /* registration hasn't completed; suspend it... */
    auth_cap_start(cli_auth(sptr));

  memset(&set, 0, sizeof(set));
  memset(&rem, 0, sizeof(rem));
  while (cl) { /* walk through the capabilities list... */
    if (!(cap = find_cap(&cl, &neg)) /* look up capability... */
        || (!neg && (cap->flags & CAPFL_PROHIBIT)) /* is it prohibited? */
        || (neg && (cap->flags & CAPFL_STICKY))) { /* is it sticky? */
      sendcmdto_one(&me, CMD_CAP, sptr, "%s NAK :%s",
                    BadPtr(cli_name(sptr)) ? "*" : cli_name(sptr), caplist);
      return 0; /* can't complete requested op... */
    }

    if (neg) { /* set or clear the capability... */
      CapSet(&rem, cap->cap);
      CapClr(&set, cap->cap);
      CapClr(&cs, cap->cap);
      if (!(cap->flags & CAPFL_PROTO))
        CapClr(&as, cap->cap);
    } else {
      CapClr(&rem, cap->cap);
      CapSet(&set, cap->cap);
      CapSet(&cs, cap->cap);
      if (!(cap->flags & CAPFL_PROTO))
        CapSet(&as, cap->cap);
    }
  }

  /* Notify client of accepted changes and copy over results. */
  send_caplist(sptr, &set, &rem, "ACK");
  *cli_capab(sptr) = cs;
  *cli_active_own(sptr) = as;
  bounce_recompute_session_caps(sptr);

  return 0;
}

static int
cap_ack(struct Client *sptr, const char *caplist)
{
  const char *cl = caplist;
  struct capabilities *cap;
  int neg;

  /* Coming from the client, this generally indicates that the client
   * is using a new backwards-incompatible protocol feature.  As such,
   * it does not require further response from the server.
   */
  while (cl) { /* walk through the capabilities list... */
    if (!(cap = find_cap(&cl, &neg)) || /* look up capability... */
        (neg ? HasCap(sptr, cap->cap) : !HasCap(sptr, cap->cap))) /* uh... */
      continue;

    if (neg) { /* set or clear the active capability... */
      if (cap->flags & CAPFL_STICKY)
        continue; /* but don't clear sticky capabilities */
      CapClr(cli_active_own(sptr), cap->cap);

      /* Clean up metadata subscriptions when metadata-2 is disabled */
      if (cap->cap == CAP_DRAFT_METADATA2) {
        metadata_sub_free(sptr);
      }
    } else {
      if (cap->flags & CAPFL_PROHIBIT)
        continue; /* and don't set prohibited ones */
      CapSet(cli_active_own(sptr), cap->cap);
    }
  }

  bounce_recompute_session_caps(sptr);
  return 0;
}

static int
cap_clear(struct Client *sptr, const char *caplist)
{
  struct CapSet cleared;
  struct capabilities *cap;
  unsigned int ii;

  /* XXX: If we ever add a capab list sorted by capab value, it would
   * be good cache-wise to use it here. */
  memset(&cleared, 0, sizeof(cleared));
  for (ii = 0; ii < CAPAB_LIST_LEN; ++ii) {
    cap = &capab_list[ii];
    /* Only clear active non-sticky capabilities. */
    if (!HasCap(sptr, cap->cap) || (cap->flags & CAPFL_STICKY))
      continue;
    CapSet(&cleared, cap->cap);
    CapClr(cli_capab(sptr), cap->cap);
    if (!(cap->flags & CAPFL_PROTO))
      CapClr(cli_active_own(sptr), cap->cap);

    /* Clean up metadata subscriptions when metadata-2 is cleared */
    if (cap->cap == CAP_DRAFT_METADATA2) {
      metadata_sub_free(sptr);
    }
  }
  send_caplist(sptr, 0, &cleared, "ACK");
  bounce_recompute_session_caps(sptr);

  return 0;
}

static int
cap_end(struct Client *sptr, const char *caplist)
{
  if (!IsUnknown(sptr) || !cli_auth(sptr)) /* registration has completed... */
    return 0; /* so just ignore the message... */

  return auth_cap_done(cli_auth(sptr));
}

static int
cap_list(struct Client *sptr, const char *caplist)
{
  /* Send the list of the client's capabilities */
  return send_caplist(sptr, cli_capab(sptr), 0, "LIST");
}

static struct subcmd {
  char *cmd;
  int (*proc)(struct Client *sptr, const char *caplist);
} cmdlist[] = {
  { "ACK",   cap_ack   },
  { "CLEAR", cap_clear },
  { "END",   cap_end   },
  { "LIST",  cap_list  },
  { "LS",    cap_ls    },
  { "NAK",   0         },
  { "REQ",   cap_req   }
};

static int
subcmd_search(const char *cmd, const struct subcmd *elem)
{
  return ircd_strcmp(cmd, elem->cmd);
}

/** Handle a capability request or response from a client.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 * @see \ref m_functions
 */
int
m_cap(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  char *subcmd, *caplist = 0;
  struct subcmd *cmd;

  if (parc < 2) /* a subcommand is required */
    return 0;
  subcmd = parv[1];
  if (parc > 2) /* a capability list was provided */
    caplist = parv[2];

  /* find the subcommand handler */
  if (!(cmd = (struct subcmd *)bsearch(subcmd, cmdlist,
      sizeof(cmdlist) / sizeof(struct subcmd),
      sizeof(struct subcmd),
      (bqcmp)subcmd_search)))
    return send_reply(sptr, ERR_UNKNOWNCAPCMD, subcmd);

  /* then execute it... */
  return cmd->proc ? (cmd->proc)(sptr, caplist) : 0;
}

void client_check_caps(struct Client *client, struct Client *replyto)
{
  char outbuf[BUFSIZE];
  int i = 0;
  static char capbufp[BUFSIZE] = "";

  memset(&capbufp, 0, BUFSIZE);

  for (i = 0; i < CAPAB_LIST_LEN; i++) {
    if (CapActive(client, capab_list[i].cap)) {
      if (strlen(capbufp) + capab_list[i].namelen + 4 > 70) {
        ircd_snprintf(0, outbuf, sizeof(outbuf), "   Capabilities:: %s", capbufp);
        send_reply(replyto, RPL_DATASTR, outbuf);
        memset(&capbufp, 0, BUFSIZE);
      }

      strcat(capbufp, capab_list[i].name);
      strcat(capbufp, " ");
    }
  }

  if (strlen(capbufp) > 0) {
    ircd_snprintf(0, outbuf, sizeof(outbuf), "   Capabilities:: %s", capbufp);
    send_reply(replyto, RPL_DATASTR, outbuf);
  }
}
