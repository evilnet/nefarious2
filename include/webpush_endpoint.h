/*
 * webpush_endpoint.h - which push endpoints the server may deliver to.
 *
 * A logged-in client registers a push endpoint URL (WEBPUSH REGISTER) and
 * the server later connects to it.  It must not be made to connect to the
 * server's own or its network's internal addresses.  Two checks: the URL
 * when it is registered (webpush_endpoint_url_ok()), and every address a
 * delivery is about to connect to, whatever name led there
 * (webpush_endpoint_address_ok(), from the HTTP client's socket hook).
 * Both are pure (no ircd dependencies) and unit-tested in
 * ircd/test/webpush_endpoint_cmocka.c.
 */
#ifndef INCLUDED_webpush_endpoint_h
#define INCLUDED_webpush_endpoint_h

#include <stddef.h>
#include <sys/socket.h>

/** 1 when \a url may be registered as a push endpoint, else 0. */
int webpush_endpoint_url_ok(const char *url);

/** 1 when a delivery may connect to \a addr (\a len bytes: a sockaddr_in
 * or sockaddr_in6), else 0. */
int webpush_endpoint_address_ok(const struct sockaddr *addr, size_t len);

#endif /* INCLUDED_webpush_endpoint_h */
