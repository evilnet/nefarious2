/*
 * webpush_attention.c - is anyone attending this account? (pure decision logic)
 *
 * See webpush_attention.h.  Kept free of ircd dependencies so ircd/test
 * links it directly.
 */
#include "webpush_attention.h"

int webpush_conn_attending(const struct webpush_conn_state *c,
                           long long now, long long idle)
{
  if (!c || c->held || c->away)
    return 0;
  if (idle <= 0)
    return 1;                       /* idle rule off: connected + present attends */
  if (c->last_msg <= 0)
    return 0;                       /* never spoke: idle */
  return c->last_msg + idle > now;  /* spoke inside the window */
}

int webpush_unattended(const struct webpush_conn_state *c, int n,
                       long long now, long long idle)
{
  int i;
  for (i = 0; i < n; i++)
    if (webpush_conn_attending(&c[i], now, idle))
      return 0;
  return 1;
}
