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
 * m_authenticate.c, m_sasl.c and s_auth.c, tested by sasl_turn_cmocka).
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
 */
#ifndef INCLUDED_sasl_turn_h
#define INCLUDED_sasl_turn_h

/** Whether an exchange in flight waits for the client, not for its
 * backend.
 * - A local (Keycloak) exchange (\a local): the client's turn unless a
 *   Keycloak request is in flight (\a waiting_kc, SASL_STATE_WAITING_KC).
 * - A services or IAuth exchange: the client's turn when no line it sent
 *   is still unanswered (\a unanswered, con_sasl_unanswered()).
 */
static inline int sasl_turn_is_clients(int local, int waiting_kc,
                                       unsigned int unanswered)
{
  if (local)
    return !waiting_kc;
  return unanswered == 0;
}

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

#endif /* INCLUDED_sasl_turn_h */
