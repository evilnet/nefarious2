/*
 * IRC - Internet Relay Chat, include/history_record.h
 * Copyright (C) 2024 Nefarious Development Team
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
 * @brief Chathistory record codec (ircd/history_record.c).
 *
 * Stored value: type|sender|account|[\x05ot\x05][\x06tags\x06][\x07inc\x07]content
 * with sender and account escaped so a '|' in either cannot shift the
 * fields (history_unescape_header reads them back).
 * history_deserialize_record and the CH W forward encode/split are
 * declared in history.h with the rest of the history API.  Pure: no
 * database, client or channel dependencies, so ircd/test links it.
 */
#ifndef INCLUDED_history_record_h
#define INCLUDED_history_record_h

#include "history.h"

extern int history_serialize_record(char *buf, int bufsize,
                                    enum HistoryMessageType type,
                                    const char *sender, const char *account,
                                    const char *content, const char *client_tags,
                                    const char *original_target, time_t incarnation);
extern char *history_escape_field(char *dst, size_t dstsize, const char *src);
extern void history_unescape_field(char *s);
extern int history_unescape_header(char *dst, size_t dstsize,
                                   const char *src, size_t len);

#endif /* INCLUDED_history_record_h */
