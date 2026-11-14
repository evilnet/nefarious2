/*
 * IRC - Internet Relay Chat, include/iauth_held.h
 *
 * What becomes of a client an IAuth instance was still checking when the
 * instance went away (it exited, was restarted by "REHASH a", replaced
 * because its program changed, or removed).  Such a client is held: it
 * does not register while the server decides.  If an instance is running
 * by then -- one started in the same step, or a program restarted at once
 * after a good run -- the client is handed to it: introduced again with
 * everything the departed instance had been told, and pending until the
 * new instance answers or the registration timeout ends the wait.  With
 * no instance to hand it to, a client whose check was required (the R
 * policy) is refused, unless IAuth had tentatively accepted it (d), as at
 * a registration timeout; any other is released and registers without
 * IAuth, as a client does that connects while no instance runs.
 */
#ifndef INCLUDED_iauth_held_h
#define INCLUDED_iauth_held_h

/** What happens to a held client. */
enum IAuthHeldFate {
  IAUTH_HELD_HAND_OVER,   /**< introduced to the running instance */
  IAUTH_HELD_REFUSE,      /**< disconnected: the check was required */
  IAUTH_HELD_RELEASE      /**< registers without IAuth */
};

/** Decide the fate of a held client.
 * @param[in] running Non-zero when an IAuth instance is running now.
 * @param[in] required Non-zero when the client's check was required.
 * @param[in] soft_done Non-zero when IAuth had tentatively accepted it.
 * @return What to do with the client.
 */
static inline enum IAuthHeldFate iauth_held_fate(int running, int required,
                                                 int soft_done)
{
  if (running)
    return IAUTH_HELD_HAND_OVER;
  if (required && !soft_done)
    return IAUTH_HELD_REFUSE;
  return IAUTH_HELD_RELEASE;
}

/** Whether the check of a client held from an instance was required.
 * @param[in] announced Non-zero when the instance announced a policy (O).
 * @param[in] policy_r Non-zero when that policy included R.
 * @param[in] was_required What the client carried from an earlier
 *   instance (zero for a client never held before).
 * @return Non-zero when the check was required.
 */
static inline int iauth_held_required(int announced, int policy_r,
                                      int was_required)
{
  return announced ? !!policy_r : !!was_required;
}

/* What an instance is told about a client before it has announced its
 * policy (its O line): a line told only under a policy option is kept,
 * not told and not dropped, and is told when the O line arrives if the
 * policy asks for it, or forgotten if it does not.  A client handed to an
 * instance is told the same way: at once what no policy option gates and
 * what an announced policy asks for, the rest at the O line. */

/** Policy options that gate lines about a client (the \a policy argument
 * of iauth_line_verdict()). */
#define IAUTH_ASKS_ADDLINFO  0x01  /**< A: P, and U in its short form */
#define IAUTH_ASKS_UNDERNET  0x02  /**< U: n, u, U in its full form, H */
#define IAUTH_ASKS_SSLFP     0x04  /**< F: F (certificate fingerprint) */
#define IAUTH_ASKS_ACCOUNT   0x08  /**< r: R (account) */

/** What becomes of a line about a client. */
enum IAuthLineVerdict {
  IAUTH_LINE_TELL,        /**< told */
  IAUTH_LINE_TELL_SHORT,  /**< told in the short form "U <username>" */
  IAUTH_LINE_KEEP,        /**< kept untold until the policy is known */
  IAUTH_LINE_FORGET       /**< not told, and forgotten */
};

/** Decide what becomes of a line about a client, for the instance it
 * would be told to.
 * @param[in] cmd The line's command letter.
 * @param[in] announced Non-zero when the instance has sent its O line.
 * @param[in] policy IAUTH_ASKS_* bits of the policy it announced.
 * @return What to do with the line.
 */
static inline enum IAuthLineVerdict iauth_line_verdict(char cmd,
                                                       int announced,
                                                       unsigned int policy)
{
  unsigned int asks;

  switch (cmd) {
  case 'H': case 'n': case 'u': asks = IAUTH_ASKS_UNDERNET; break;
  case 'U': asks = IAUTH_ASKS_UNDERNET | IAUTH_ASKS_ADDLINFO; break;
  case 'P': asks = IAUTH_ASKS_ADDLINFO; break;
  case 'F': asks = IAUTH_ASKS_SSLFP; break;
  case 'R': asks = IAUTH_ASKS_ACCOUNT; break;
  default: return IAUTH_LINE_TELL;       /* no policy option gates it */
  }
  if (!announced)
    return IAUTH_LINE_KEEP;
  if (!(policy & asks))
    return IAUTH_LINE_FORGET;
  if (cmd == 'U' && !(policy & IAUTH_ASKS_UNDERNET))
    return IAUTH_LINE_TELL_SHORT;
  return IAUTH_LINE_TELL;
}

#endif /* INCLUDED_iauth_held_h */
