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

/** Whether the R policy of a departing instance was in force: announced
 * (R) and not bypassed by its circuit breaker, which, open, lets a client
 * whose wait ends without an answer in, as at a registration timeout.
 * @param[in] policy_r Non-zero when the instance's policy includes R.
 * @param[in] circuit_open Non-zero when its circuit breaker is open.
 * @return Non-zero when R was in force.
 */
static inline int iauth_held_policy_r(int policy_r, int circuit_open)
{
  return policy_r && !circuit_open;
}

/** Whether the check of a client held from an instance was required.
 * @param[in] announced Non-zero when the instance announced a policy (O).
 * @param[in] policy_r Non-zero when R was in force for it
 *   (iauth_held_policy_r()).
 * @param[in] was_required What the client carried from an earlier
 *   instance (zero for a client never held before).
 * @return Non-zero when the check was required.
 */
static inline int iauth_held_required(int announced, int policy_r,
                                      int was_required)
{
  return announced ? !!policy_r : !!was_required;
}

#endif /* INCLUDED_iauth_held_h */
