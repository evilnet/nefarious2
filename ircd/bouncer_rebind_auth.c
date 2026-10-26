/*
 * Rebind authorization decision. Pure: no ircd dependencies, so the
 * CMocka suite links it without the server.
 */
#include "bouncer_rebind_auth.h"

#include <string.h>

enum BounceRebindAuth
bounce_rebind_auth(int origin_match, int sessid_match, int acc_ts_match)
{
  /* The session id alone: per redesign A.2/C.2 it is the canonical
   * session identity.  origin_match and acc_ts_match are accepted and
   * ignored -- both retired, see the header.  The parameters stay so
   * callers and old log lines keep their shape. */
  (void)origin_match;
  (void)acc_ts_match;

  if (sessid_match)
    return BRA_SESSID;
  return BRA_NONE;
}

const char *
bounce_rebind_auth_name(enum BounceRebindAuth auth)
{
  switch (auth) {
  case BRA_ORIGIN: return "origin";
  case BRA_SESSID: return "sessid";
  case BRA_ACC_TS: return "account-TS";
  case BRA_NONE:   break;
  }
  return "none";
}

int
bounce_rebind_kc_conflict(const char *ghost_id, const char *incoming_id)
{
  if (!ghost_id || !*ghost_id || !incoming_id || !*incoming_id)
    return 0;
  return strcmp(ghost_id, incoming_id) != 0;
}

int
bounce_side_kc_conflict(const char *session_id, const char *client_id,
                        const char *incoming_id)
{
  /* The session's id speaks for it (a session is bound to one Keycloak
   * user); a client in no session, or in one that knows no id yet,
   * speaks for itself. */
  if (session_id && *session_id)
    return bounce_rebind_kc_conflict(session_id, incoming_id);
  return bounce_rebind_kc_conflict(client_id, incoming_id);
}

enum BounceKcJoin
bounce_kc_join(const char *session_id, const char *login_id, int session_unused)
{
  if (!bounce_rebind_kc_conflict(session_id, login_id))
    return BKJ_JOIN;
  return session_unused ? BKJ_END_STALE : BKJ_REFUSE;
}
