/*
 * IRC - Internet Relay Chat, include/chathistory.h
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
/** @file
 * @brief Storage-server advertisements, write forwarding, and the
 * history delivery helpers replay.c shares, all defined in
 * m_chathistory.c.  Its command handlers stay in handlers.h, and its
 * federation and replay entry points in history.h and replay.h.
 * m_chathistory.c includes all of them, so every prototype is checked
 * against its definition.
 */
#ifndef INCLUDED_chathistory_h
#define INCLUDED_chathistory_h

#include "history.h"   /* enum HistoryMessageType, struct HistoryMessage */

#include <stddef.h>    /* size_t */
#include <time.h>      /* time_t */

struct Channel;
struct Client;
struct StatDesc;

/* Storage-server advertisements and retention. */
extern int has_chathistory_advertisement(struct Client *server);
extern int server_retention_days(struct Client *server);
extern int chathistory_retention_advertised(void);
extern void chathistory_update_retention_isupport(int announce);
extern void chathistory_coverage_changed(void);
extern int server_retention_covers(struct Client *server, time_t when);
extern void clear_server_ad(struct Client *server);
extern void chathistory_report_ads(struct Client *to, const struct StatDesc *sd,
                                   char *param);
extern void chathistory_reflood_ads(struct Client *newpeer);
extern void chathistory_server_eob(struct Client *server);
extern int send_channel_advertisements(struct Client *cptr);
extern void broadcast_channel_advertisement(const char *channel);
extern void chathistory_init_callbacks(void);

/* Forwarding a channel message to the nearest storage server. */
extern void forward_history_write(struct Channel *chptr, struct Client *sptr,
                                  const char *msgid, const char *timestamp,
                                  enum HistoryMessageType type,
                                  const char *content);

/* History delivery, shared with replay.c. */
extern const char *msg_type_cmd[];
extern void send_history_message(struct Client *sptr, struct HistoryMessage *msg,
                                 const char *target, const char *outer_batchid,
                                 const char *time_str, const char *cmd);
extern void generate_batch_id(char *buf, size_t buflen, struct Client *sptr);
extern void send_gap_marker(struct Client *sptr, const char *target,
                            const char *batchid, const char *time_str,
                            const char *msgid, const char *sender, int count);

#endif /* INCLUDED_chathistory_h */
