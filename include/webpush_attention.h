/*
 * webpush_attention.h - is anyone attending this account? (pure decision logic)
 *
 * A push is worth sending only when nobody is looking.  A connection is
 * ATTENDING when it is connected, not away, and has sent a message within
 * the idle window.  The account is UNATTENDED when no connection attends:
 * every connection is held (no socket), away, or idle past the window.
 *
 * Remote connections (aliases on other servers) carry replicated activity
 * (BX U la=, see bouncer_session.h); it is coarse (one update per quiet
 * period), so it is used the same way as a local idle clock.
 *
 * Pure: no ircd dependencies; unit-tested in
 * ircd/test/webpush_attention_cmocka.c.
 */
#ifndef INCLUDED_webpush_attention_h
#define INCLUDED_webpush_attention_h

struct webpush_conn_state {
  int held;              /**< no socket (bouncer HOLDING) */
  int away;              /**< the connection's own AWAY state */
  long long last_msg;    /**< unix time of its last message; 0 = unknown */
};

/** 1 when no connection in c[0..n) attends at `now` with idle window
 * `idle` seconds (idle <= 0 disables the idle rule: only held/away
 * connections count as not attending).  n == 0 is unattended.  A
 * connection with last_msg == 0 and the idle rule on is treated as idle
 * (never spoke). */
int webpush_unattended(const struct webpush_conn_state *c, int n,
                       long long now, long long idle);

/** 1 when this single connection attends (helper for callers that
 * want the reason). */
int webpush_conn_attending(const struct webpush_conn_state *c,
                           long long now, long long idle);

#endif /* INCLUDED_webpush_attention_h */
