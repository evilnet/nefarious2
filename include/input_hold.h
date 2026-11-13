/** @file input_hold.h
 * @brief The orphan hold's pure rules: when a bouncer device's input is
 * held, how much its receive queue may hold, and what a QUIT line is.
 *
 * A device of ours whose primary is momentarily gone (an orphan) has its
 * input held, not parsed (s_bsd.c read_packet()); these rules decide, from
 * the facts the caller reads, and keep the hold's state.  Pure: no ircd
 * state is read or written here (cmocka: input_hold_cmocka).
 */
#ifndef INCLUDED_input_hold_h
#define INCLUDED_input_hold_h

#ifndef INCLUDED_sys_types_h
#include <sys/types.h>
#define INCLUDED_sys_types_h
#endif
#include <time.h>

/** How long a connection's input is held before the orphan sweep is asked
 * to run at once (seconds): the sweep's own longest wait
 * (BOUNCE_ORPHAN_WAIT_MAX 10) plus its grace (2) and a margin for
 * one-second timers. */
#define INPUT_HOLD_MAX      15
/** The absolute ceiling: past it the input is released whatever the sweep
 * did (a sweep that never runs cannot hold a client's input for good). */
#define INPUT_HOLD_CEILING  25
/** How long at most the doubled receive allowance outlives the release of
 * a hold (less once the queue is back under the usual cap). */
#define INPUT_HOLD_GRACE    15
/** While a hold lasts, the held client is sent a server PING every this
 * many seconds (the first this long after the hold began), so a client
 * that drops a socket with no inbound traffic for 10 s (Seance's
 * keepalive) hears something: the hold is noticed at reads and at the
 * 2-second process timer, so the gap between two lines it receives is at
 * most this plus about two seconds, and its own PING, held, began or
 * joined the hold no earlier than the hold's start. */
#define INPUT_HOLD_PING     4

/** A connection's hold, kept on its Connection (zero: none). */
struct InputHold {
  time_t       since;     /**< when the hold began; 0: not held */
  time_t       asked;     /**< when the sweep was asked to run (the bound); 0: not yet */
  unsigned int gen;       /**< the sweep count when it was asked */
  int          released;  /**< released while still an orphan: not held again until it stops being one */
  time_t       boost;     /**< the doubled allowance lasts until then; 0: none */
  time_t       pinged;    /**< when the hold last sent the client a PING; 0: not yet */
};

/** What the read path does with a connection's queued lines. */
enum input_hold_action {
  INPUT_HOLD_PARSE,       /**< parse them */
  INPUT_HOLD_WAIT,        /**< hold them */
  INPUT_HOLD_ASK_SWEEP    /**< hold them, and ask the orphan sweep to run now */
};

/** What changed, for the caller's log. */
enum input_hold_event {
  INPUT_HOLD_EV_NONE,
  INPUT_HOLD_EV_BEGAN,    /**< the hold began */
  INPUT_HOLD_EV_ENDED,    /**< it ended: the device is no orphan any more */
  INPUT_HOLD_EV_ASKED,    /**< the bound: the sweep is asked to run */
  INPUT_HOLD_EV_SWEPT,    /**< a sweep ran and it is still an orphan: released */
  INPUT_HOLD_EV_CEILING   /**< the ceiling released it (no sweep ran) */
};

extern enum input_hold_action input_hold_step(struct InputHold *h, int orphan,
                                              time_t now, unsigned int sweeps,
                                              enum input_hold_event *ev);
extern int input_hold_ping_due(struct InputHold *h, time_t now);
extern void input_hold_clear(struct InputHold *h);
extern unsigned int input_hold_cap(struct InputHold *h, unsigned int cap,
                                   unsigned int queued, time_t now);
extern int input_hold_is_quit(const char *line);

#endif /* INCLUDED_input_hold_h */
