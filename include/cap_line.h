/*
 * IRC - Internet Relay Chat, include/cap_line.h
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
 * any later version.
 */
/** @file
 * @brief How a CAP LS / LIST reply is laid out in lines (pure; used by
 * m_cap.c send_caplist(), tested by cap_line_cmocka).
 *
 * capability-negotiation: "If the client supports CAP version 302, the
 * server MAY send multiple lines in response to CAP LS and CAP LIST",
 * each but the last marked with a "*" parameter.  A client of an older
 * version gets one line.
 */
#ifndef INCLUDED_cap_line_h
#define INCLUDED_cap_line_h

#include <string.h>

/** Whether a reply of \a subcmd may take several lines for a client of
 * CAP version \a version: LS and LIST only, and only from 302 on.  (ACK
 * and the other replies are split as before, with no marker.) */
static inline int cap_reply_multiline(int version, int is_ls_or_list)
{
  return !is_ls_or_list || version >= 302;
}

/** The bytes a line keeps free beyond its capabilities: the "* "
 * continuation marker, which only a 302 client's LS or LIST lines take. */
static inline int cap_line_reserve(int version, int is_ls_or_list)
{
  return (is_ls_or_list && version >= 302) ? 2 : 0;
}

/** Whether CAP LS leaves out capability \a name for a client that must
 * get one line and whose full list does not fit on it (\a narrow): the
 * vendor and draft capabilities (a name with a '/') go first.  Clients
 * older than 302 predate them; the ratified capabilities are kept. */
static inline int cap_ls_left_out(const char *name, int narrow)
{
  return narrow && strchr(name, '/') != NULL;
}

#endif /* INCLUDED_cap_line_h */
