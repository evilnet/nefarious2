/*
 * IRC - Internet Relay Chat, include/chathistory_ref.h
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 */
/** @file
 * @brief CHATHISTORY references on the S2S wire (chathistory_ref.c).
 */
#ifndef INCLUDED_chathistory_ref_h
#define INCLUDED_chathistory_ref_h

#include "history.h"   /* enum HistoryRefType */

#include <stddef.h>    /* size_t */

/** Is @a ts a timestamp: unix "sec[.ms]" or ISO 8601? */
extern int chathistory_valid_timestamp(const char *ts);

/** A client reference ("timestamp=", "msgid=", "*") in its S2S form, in
 * @a buf; NULL if it is neither. */
extern char *chathistory_ref_to_s2s(const char *ref, char *buf, size_t buflen);

/** Read an S2S reference: its type in @a ref_type, its value in
 * @a value.  0 on success, -1 on an empty one. */
extern int chathistory_parse_s2s_ref(const char *ref, enum HistoryRefType *ref_type,
                               const char **value);

#endif /* INCLUDED_chathistory_ref_h */
