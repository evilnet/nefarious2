/*
 * IRC - Internet Relay Chat, include/markread_wire.h
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
 * any later version.
 */
/** @file
 * @brief The MARKREAD parameter forms of draft/read-marker (pure; used by
 * m_markread.c, tested by markread_wire_cmocka).
 *
 * The spec's timestamp parameter "MUST be a literal `*`, or have the
 * format `timestamp=YYYY-MM-DDThh:mm:ss.sssZ`".  A client's set command
 * "MUST NOT be a literal `*`", and a server sends the literal `*` when
 * "there is no known last message read timestamp".
 */
#ifndef INCLUDED_markread_wire_h
#define INCLUDED_markread_wire_h

#include <string.h>
#include <strings.h>

/** What a client's MARKREAD asks for, from its parameters. */
enum MarkreadArg {
  MARKREAD_ARG_GET,      /**< no timestamp: the client get command */
  MARKREAD_ARG_SET,      /**< "timestamp=...": the client set command
                          *   (the timestamp itself is checked after) */
  MARKREAD_ARG_INVALID   /**< anything else, the literal `*` included:
                          *   FAIL MARKREAD INVALID_PARAMS */
};

/** Classify a client MARKREAD from \a parc and its second parameter
 * \a arg (parv[2]).  An empty second parameter counts as none. */
static inline enum MarkreadArg markread_arg_kind(int parc, const char *arg)
{
  if (parc < 3 || !arg || !*arg)
    return MARKREAD_ARG_GET;
  if (strncasecmp(arg, "timestamp=", 10) == 0)
    return MARKREAD_ARG_SET;
  return MARKREAD_ARG_INVALID;
}

/** Whether the server's MARKREAD carries no known timestamp, and so is
 * sent as the literal `*`: \a ts (Unix seconds.millis) is NULL, empty
 * or "*". */
static inline int markread_ts_unknown(const char *ts)
{
  return !ts || !*ts || *ts == '*';
}

/** The context parameter of FAIL MARKREAD INVALID_PARAMS for the client's
 * parameter \a arg: \a arg itself when it can stand as a middle
 * parameter, else "*".  One with a space, or that is empty or starts with
 * ':', would split into two parameters or swallow the description. */
static inline const char *markread_fail_context(const char *arg)
{
  if (!arg || !*arg || *arg == ':' || strchr(arg, ' '))
    return "*";
  return arg;
}

#endif /* INCLUDED_markread_wire_h */
