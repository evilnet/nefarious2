/*
 * Rebind authorization decision. Pure: no ircd dependencies, so the
 * CMocka suite links it without the server.
 */
#include "bouncer_rebind_auth.h"

enum BounceRebindAuth
bounce_rebind_auth(int origin_match, int sessid_match, int acc_ts_match)
{
  /* Sessid first: per redesign A.2/C.2 it is the canonical session
   * identity and hs_origin is historical-only metadata, so where both
   * hold the sessid is what actually established trust. */
  /* acc_ts_match is accepted and ignored: retired 2026-09, see the header.
   * The parameter stays so callers and old log lines keep their shape. */
  (void)acc_ts_match;

  if (sessid_match)
    return BRA_SESSID;
  if (origin_match)
    return BRA_ORIGIN;
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
