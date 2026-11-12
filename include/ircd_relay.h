#ifndef INCLUDED_IRCD_RELAY_H
#define INCLUDED_IRCD_RELAY_H
/*
 * IRC - Internet Relay Chat, include/ircd_relay.h
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
 * @brief Interface to functions for relaying messages.
 * @version $Id: ircd_relay.h 1231 2004-10-05 04:21:37Z entrope $
 */

#include <stddef.h>            /* size_t — this header is the first include
                                  in some translation units (e.g. ircd_relay.c),
                                  so it cannot rely on a later header for this. */

struct Client;
struct Channel;

extern void relay_channel_message(struct Client* sptr, const char* name, const char* text, int targets);
extern void relay_channel_notice(struct Client* sptr, const char* name, const char* text, int targets);
extern void relay_directed_message(struct Client* sptr, char* name, char* server, const char* text);
extern void relay_directed_notice(struct Client* sptr, char* name, char* server, const char* text);
extern void relay_masked_message(struct Client* sptr, const char* mask, const char* text);
extern void relay_masked_notice(struct Client* sptr, const char* mask, const char* text);
extern void relay_private_message(struct Client* sptr, const char* name, const char* text);
extern void relay_private_notice(struct Client* sptr, const char* name, const char* text);

extern void server_relay_channel_message(struct Client* sptr, const char* name, const char* text);
extern void server_relay_channel_notice(struct Client* sptr, const char* name, const char* text);
extern void server_relay_masked_message(struct Client* sptr, const char* mask, const char* text);
extern void server_relay_masked_notice(struct Client* sptr, const char* mask, const char* text);
extern void server_relay_private_message(struct Client* sptr, const char* name, const char* text);
extern void server_relay_private_notice(struct Client* sptr, const char* name, const char* text);

/* The send checks of a local user's PRIVMSG / NOTICE, one place for the
 * single-line relay and a multiline batch (m_batch.c) alike, so the two
 * cannot drift apart: each answers the sender as its command answers. */
#define RELAY_UTF8_OK        0   /**< valid UTF-8, or UTF8ONLY off */
#define RELAY_UTF8_SANITISED 1   /**< invalid, sanitised copy made (warn mode) */
#define RELAY_UTF8_REFUSED   2   /**< invalid, refused (UTF8ONLY_STRICT) */
extern int relay_utf8_check(const char *text, char *buf, size_t bufsize);
extern void relay_utf8_answer(struct Client *sptr, const char *cmd, int result);
extern int relay_channel_refused(struct Client *sptr, struct Channel *chptr,
                                 int is_notice);
extern const char *relay_channel_text(struct Client *sptr, struct Channel *chptr,
                                      const char *text, const char *mytext,
                                      int targets, int is_notice);
extern int relay_private_refused(struct Client *sptr, struct Client *acptr,
                                 int is_notice);
extern void relay_private_accepted(struct Client *sptr, struct Client *acptr,
                                   int is_notice);
extern int server_relay_channel_allowed(struct Client *sptr, struct Channel *chptr,
                                        int is_notice);

/* A local user's message is cut once, at its origin, to what the line
 * its recipients get (":nick!user@host <cmd> <target> :<text>", 510
 * bytes after the tags) can carry -- before it is delivered, echoed,
 * relayed, stored or pushed. */
extern size_t relay_text_budget(struct Client *sptr, const char *cmd,
                                size_t target_len, size_t lead_len);
extern const char *relay_cut_text(struct Client *sptr, const char *cmd,
                                  size_t target_len, size_t lead_len,
                                  const char *text, char *buf, size_t bufsize);
extern const char *relay_cut_to(const char *text, size_t room, char *buf,
                                size_t bufsize);
extern size_t relay_dm_text_budget(struct Client *sptr, const char *cmd,
                                   struct Client *acptr, size_t msgid_len,
                                   size_t ctags_len, int multiline);

/* DM chathistory identity keying (F-CH1): account when authenticated,
 * else the per-connection session id.  NEVER the nick. */
extern void history_pm_identity(struct Client *cli, char *buf, size_t buflen);
#include "history.h"  /* enum HistoryMessageType for the prototype below */

extern int  has_pm_optout(struct Client *cptr);
extern void store_private_history(struct Client *sptr, struct Client *acptr,
                                  const char *text, enum HistoryMessageType type,
                                  const char *msgid, const char *timestamp,
                                  const char *client_tags);
extern int  history_pm_identity_matches(struct Client *cli,
                                        const char *half, size_t half_len);

#endif /* INCLUDED_IRCD_RELAY_H */
