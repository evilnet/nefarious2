/*
 * IRC - Internet Relay Chat, include/nick_request.h
 *
 * What a server does when a nick CHANGE it is handed over a link (not an
 * introduction) meets another client already holding the nick.
 */
#ifndef INCLUDED_nick_request_h
#define INCLUDED_nick_request_h

/** The outcome of a nick change meeting the nick's holder. */
enum nick_meet {
  NICK_MEET_CLASSIC,   /**< the classic collision rules (a KILL)           */
  NICK_MEET_OVERRIDE,  /**< our unregistered holder gives way (stock)      */
  NICK_MEET_REFUSE     /**< refused: the user keeps its nick, nobody killed */
};

/** Decide a nick change that meets another holder of the nick.
 * @param[in] user_ours The user being renamed is ours.  A change over a
 * link names another server's user, so ours means a bouncer device on
 * another server asked for its session user's rename (ms_nick() rewrote
 * the device's request to our primary).  We are the one authority for
 * that user's nick: the request is refused as a ban or NICKDELAY would
 * refuse it, and the device's server is answered.  The classic rules
 * would KILL our own user (whole session, #6) -- and assert first.
 * @param[in] holder_unreg_ours The holder is our unregistered connection:
 * it gives way to any rename, ours included, as for a local NICK.
 * @return The outcome; never NICK_MEET_CLASSIC for a user of ours.
 */
static inline enum nick_meet nick_change_meets(int user_ours,
                                               int holder_unreg_ours)
{
  if (holder_unreg_ours)
    return NICK_MEET_OVERRIDE;
  if (user_ours)
    return NICK_MEET_REFUSE;
  return NICK_MEET_CLASSIC;
}

#endif /* INCLUDED_nick_request_h */
