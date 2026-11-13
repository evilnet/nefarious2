/*
 * IRC - Internet Relay Chat, ircd/input_hold.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
 * any later version.
 */
/** @file
 * @brief The orphan hold's pure rules (see include/input_hold.h).
 */
#include "config.h"

#include "input_hold.h"

#include <string.h>

/** Decide what the read path does with the queued lines of a connection,
 * and keep its hold's state.
 *
 * - Not an orphan: parse.  A hold that was on ends (EV_ENDED) and leaves
 *   the doubled allowance for INPUT_HOLD_GRACE seconds, once per hold: a
 *   hold already released while an orphan gets no second one.
 * - An orphan: held from the first time it is asked (EV_BEGAN).  Past
 *   INPUT_HOLD_MAX the orphan sweep is asked to run now (ASK_SWEEP, once,
 *   with the sweep count then); still held until a sweep has run since,
 *   and only then, if it is still an orphan, released (EV_SWEPT).  Past
 *   INPUT_HOLD_CEILING it is released whatever happened (EV_CEILING).  A
 *   released orphan is not held again until it stops being one.
 *
 * @param[in,out] h The connection's hold.
 * @param[in] orphan Non-zero while the connection is a holdable orphan (a
 *            registered local alias with no primary, not leaving).
 * @param[in] now The time.
 * @param[in] sweeps The orphan sweep count (bounce_orphan_sweep_count()).
 * @param[out] ev What changed.
 * @return What to do with the lines. */
enum input_hold_action input_hold_step(struct InputHold *h, int orphan,
                                       time_t now, unsigned int sweeps,
                                       enum input_hold_event *ev)
{
  *ev = INPUT_HOLD_EV_NONE;
  if (!orphan) {
    if (h->since && !h->released) {
      *ev = INPUT_HOLD_EV_ENDED;
      h->boost = now + INPUT_HOLD_GRACE;
    }
    h->since = 0;
    h->asked = 0;
    h->gen = 0;
    h->released = 0;
    h->pinged = 0;
    return INPUT_HOLD_PARSE;
  }
  if (h->released)
    return INPUT_HOLD_PARSE;
  if (!h->since) {
    h->since = now;
    h->pinged = 0;
    *ev = INPUT_HOLD_EV_BEGAN;
    return INPUT_HOLD_WAIT;
  }
  if (now - h->since > INPUT_HOLD_CEILING) {
    *ev = INPUT_HOLD_EV_CEILING;
  } else if (h->asked && sweeps != h->gen) {
    *ev = INPUT_HOLD_EV_SWEPT;
  } else if (h->asked) {
    return INPUT_HOLD_WAIT;
  } else if (now - h->since > INPUT_HOLD_MAX) {
    h->asked = now;
    h->gen = sweeps;
    *ev = INPUT_HOLD_EV_ASKED;
    return INPUT_HOLD_ASK_SWEEP;
  } else
    return INPUT_HOLD_WAIT;
  /* released while still an orphan */
  h->released = 1;
  h->pinged = 0;
  h->boost = now + INPUT_HOLD_GRACE;
  return INPUT_HOLD_PARSE;
}

/** Is a server PING due to the held client now?  While a hold lasts
 * (begun, not released), one every INPUT_HOLD_PING seconds, the first that
 * long after the hold began: it gives a client whose keepalive needs
 * inbound traffic something to hear while its own lines (its PING among
 * them) wait.  Its PONG waits in the queue like any line and is parsed in
 * order at the release.  Nothing for a connection that is not held.
 * @param[in,out] h The connection's hold (the send is recorded).
 * @param[in] now The time.
 * @return Non-zero when the caller is to send the PING now. */
int input_hold_ping_due(struct InputHold *h, time_t now)
{
  time_t last;

  if (!h->since || h->released)
    return 0;
  last = h->pinged ? h->pinged : h->since;
  if (now - last < INPUT_HOLD_PING)
    return 0;
  h->pinged = now;
  return 1;
}

/** Forget a connection's hold and allowance (its socket closed: a held
 * ghost keeps its Connection, and a revive must not find them).
 * @param[out] h The hold. */
void input_hold_clear(struct InputHold *h)
{
  memset(h, 0, sizeof(*h));
}

/** How much a user connection's receive queue may hold before it is an
 * excess flood: @a cap (its class's recvq plus one message of the largest
 * size), and twice that while it is held and, after the hold's release,
 * until its allowance ends (INPUT_HOLD_GRACE seconds, or sooner once the
 * queue is back under @a cap).
 * @param[in,out] h The connection's hold (an ended allowance is cleared).
 * @param[in] cap The usual cap.
 * @param[in] queued The bytes queued now.
 * @param[in] now The time.
 * @return The cap in bytes. */
unsigned int input_hold_cap(struct InputHold *h, unsigned int cap,
                            unsigned int queued, time_t now)
{
  if (h->boost && (now >= h->boost || queued <= cap))
    h->boost = 0;
  if ((h->since && !h->released) || h->boost)
    return 2 * cap;
  return cap;
}

/** Is @a line a QUIT: its command, after any tags (@...) and any source
 * prefix (:...), is QUIT in any case, alone or followed by a space?
 * @param[in] line One line, NUL-terminated, without its line end.
 * @return Non-zero for a QUIT. */
int input_hold_is_quit(const char *line)
{
  const char *p = line;
  static const char quit[] = "QUIT";
  int i;

  if (*p == '@')
    while (*p && *p != ' ')
      p++;
  while (*p == ' ')
    p++;
  if (*p == ':') {
    while (*p && *p != ' ')
      p++;
    while (*p == ' ')
      p++;
  }
  for (i = 0; i < 4; i++) {
    char c = p[i];

    if (c >= 'a' && c <= 'z')
      c -= 'a' - 'A';
    if (c != quit[i])
      return 0;
  }
  return p[4] == '\0' || p[4] == ' ';
}
