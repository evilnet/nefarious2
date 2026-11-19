/*
 * IRC - Internet Relay Chat, include/sasl_turn.h
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
 * any later version.
 */
/** @file
 * @brief Whose turn a SASL exchange in flight is (pure; used by
 * m_authenticate.c and m_sasl.c, tested by sasl_turn_cmocka).  It decides
 * which side a SASL timeout is charged to (SASLX_CLIENTTURN,
 * SASL_MAX_FAILURES); registering mid-exchange never ends an exchange, on
 * either side's turn (a client may pipeline CAP END behind AUTHENTICATE
 * and answer the challenge when it comes).
 *
 * A services or IAuth exchange is the client's turn when every line the
 * ircd passed on to the backend (the mechanism, then each response) has
 * been answered by a challenge: the count of unanswered lines is 0.  A
 * client may send its response before the challenge it answers (it
 * pipelines AUTHENTICATE PLAIN and its credentials), and the challenge
 * that then comes answers the mechanism line, not the credentials.
 * A message is counted once, however many lines carry it: SASL splits
 * one of 400 bytes or more into 400-byte lines, ended by a shorter one
 * ("+" after an exact multiple), and the backend answers the whole.
 *
 * Also the shape of the line that starts an exchange: a mechanism name
 * (sasl_mechanism_name_ok()), or an advertised one in another case
 * (sasl_mechanism_listed()).
 */
#ifndef INCLUDED_sasl_turn_h
#define INCLUDED_sasl_turn_h

#include <string.h>

/** The longest line of a SASL message ("AUTHENTICATE" in either
 * direction); a line this long continues on the next one. */
#define SASL_LINE_MAX 400

/** Whether a line of SASL data (a response, or a challenge) ends its
 * message: any line but one of exactly SASL_LINE_MAX bytes, which is
 * followed by the rest of the message, or by "+".  A longer line (a
 * backend that does not split its challenge; the client's are refused
 * with 905 before this) ends its message too. */
static inline int sasl_line_ends_message(const char *data)
{
  const char *p = data;

  while (*p && p - data <= SASL_LINE_MAX)
    p++;
  return p - data != SASL_LINE_MAX;
}

/** A message of the client's went out to services or IAuth (its
 * mechanism, or the last line of a response: sasl_line_ends_message()):
 * one more to be answered (saturating). */
static inline void sasl_turn_line_out(unsigned char *unanswered)
{
  if (*unanswered < 255)
    (*unanswered)++;
}

/** A challenge came from services or IAuth (its last line:
 * sasl_line_ends_message()): it answers the oldest message still
 * unanswered.  Returns non-zero when none is left, i.e. the
 * exchange is now the client's turn. */
static inline int sasl_turn_challenge_in(unsigned char *unanswered)
{
  if (*unanswered)
    (*unanswered)--;
  return *unanswered == 0;
}

/** The longest mechanism name an exchange may start with.  RFC 4422
 * section 3.1 allows 20 characters, but ECDSA-NIST256P-CHALLENGE, which
 * this ircd offers (as atheme does), has 24. */
#define SASL_MECHANISM_NAME_MAX 24

/** Whether \a name can be a SASL mechanism name, the parameter of the
 * AUTHENTICATE that starts an exchange: RFC 4422 section 3.1's
 * characters (upper-case letters, digits, '-' and '_'), 1 to
 * #SASL_MECHANISM_NAME_MAX of them.  A line that is not one is not passed
 * to any tier: it is most likely a client's response that arrived after
 * its exchange ended -- base64 credentials (lower case, '+', '/', '=')
 * pipelined behind an exchange that has already ended -- and taken
 * as a mechanism it would go to IAuth or services as one, in clear. */
static inline int sasl_mechanism_name_ok(const char *name)
{
  unsigned int len = 0;

  if (!name)
    return 0;
  for (; name[len]; len++) {
    char c = name[len];

    if (len >= SASL_MECHANISM_NAME_MAX)
      return 0;
    if (!((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
          || c == '-' || c == '_'))
      return 0;
  }
  return len > 0;
}

/** The entry of \a mechs, a comma-separated list of mechanism names (what
 * the sasl capability advertises), that \a name spells in lower or mixed
 * case: "plain" finds "PLAIN".  For a client that sends its mechanism in lower
 * case, which sasl_mechanism_name_ok() refuses; the caller passes the
 * list's spelling on, so that whatever the client sent, only a name out
 * of the server's own list reaches a backend.
 * @return The entry (ended by ',' or the end of the list), or NULL. */
static inline const char *sasl_mechanism_listed(const char *name,
                                                const char *mechs)
{
  while (name && *name && mechs && *mechs) {
    const char *n = name;
    const char *m = mechs;

    for (; *m && *m != ','; m++, n++)
      if (*n != *m && !(*n >= 'a' && *n <= 'z' && *n - 'a' + 'A' == *m))
        break;
    if ((!*m || *m == ',') && !*n && m != mechs)
      return mechs;
    mechs += strcspn(mechs, ",");
    mechs += *mechs == ',';
  }
  return NULL;
}

#endif /* INCLUDED_sasl_turn_h */
