/*
 * IRC - Internet Relay Chat, include/bouncer_count.h
 *
 * Which of the core client counters a registered user holds, and how a
 * bouncer conversion moves them.  No ircd dependencies, so the cmocka
 * suite (ircd/test/bouncer_count_cmocka.c) compiles it standalone; the
 * callers in bouncer_session.c read the client's state and apply the
 * result to UserStats.
 *
 * A user holds a fixed set of counts for as long as it exists, and its
 * exit releases exactly that set, read from three facts:
 *  - a client of ours (MyConnect): Count_clientdisconnects releases one
 *    registered user, one live socket unless FLAG_NO_LC_DECREMENT says
 *    its socket already went (a held ghost), and one locally announced
 *    user unless it is an alias;
 *  - another server's client that is not an alias (introduced by N):
 *    Count_remoteclientquits releases one registered user, one in its
 *    server's count, and one announced user;
 *  - another server's alias (introduced by BX C): nothing.
 * A bouncer conversion changes those facts in place -- a live primary
 * becomes an alias, an alias a primary, another server's primary an
 * alias, a held ghost of ours another server's client -- and the counts
 * must follow, or the exit releases what the client never held, or keeps
 * what it no longer holds.
 */
#ifndef INCLUDED_bouncer_count_h
#define INCLUDED_bouncer_count_h

/** The core client counters, as one user holds them (each 0 or 1), or as
 * a conversion changes them (each -1, 0 or +1). */
struct bounce_counts {
  int clients;          /**< UserStats.clients: a registered user */
  int local_clients;    /**< UserStats.local_clients: a live local socket */
  int server_clients;   /**< its server's count (cli_serv()->clients): a
                         *   user another server introduced by N */
  int local_announced;  /**< UserStats.local_announced_clients: a user of
                         *   ours the network knows by N */
  int announced;        /**< UserStats.announced_clients: a user the
                         *   network knows by N */
};

/** What a registered user holds, from the facts its exit reads.
 *
 * @param[in]  local          The client is ours (MyConnect).
 * @param[in]  alias          It is a bouncer alias.
 * @param[in]  socket_counted Its socket is counted (FLAG_NO_LC_DECREMENT
 *                            is not set); read for a client of ours only.
 * @param[out] out            The counts it holds.
 */
extern void bounce_count_held(int local, int alias, int socket_counted,
                              struct bounce_counts *out);

/** The change in each counter when a user that held @a from comes to hold
 * @a to.  The server count's change is meaningful only when the user's
 * server stays the same; a user that moves to another server leaves its
 * old server's count by @a from and joins the new one's by @a to.
 *
 * @param[in]  from What the user held before the conversion.
 * @param[in]  to   What it holds after.
 * @param[out] out  to - from, per counter.
 */
extern void bounce_count_delta(const struct bounce_counts *from,
                               const struct bounce_counts *to,
                               struct bounce_counts *out);

#endif /* INCLUDED_bouncer_count_h */
