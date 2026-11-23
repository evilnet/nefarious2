/*
 * webpush_endpoint.c - which push endpoints the server may deliver to.
 * See include/webpush_endpoint.h.
 */
#include "config.h"

#include "webpush_endpoint.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <string.h>

/** 1 when the IPv4 address \a a (host byte order) is public: not
 * "this network" (0/8), private (10/8, 172.16/12, 192.168/16), loopback
 * (127/8), shared (CGNAT, 100.64/10), link-local (169.254/16), IETF
 * protocol assignments (192.0.0/24), documentation (192.0.2/24,
 * 198.51.100/24, 203.0.113/24), the old 6to4 relay (192.88.99/24),
 * benchmarking (198.18/15), multicast (224/4), reserved or broadcast
 * (240/4). */
static int v4_public(uint32_t a)
{
  if ((a >> 24) == 0 || (a >> 24) == 10 || (a >> 24) == 127)
    return 0;
  if ((a & 0xFFC00000u) == 0x64400000u          /* 100.64/10 */
      || (a & 0xFFFF0000u) == 0xA9FE0000u       /* 169.254/16 */
      || (a & 0xFFF00000u) == 0xAC100000u       /* 172.16/12 */
      || (a & 0xFFFF0000u) == 0xC0A80000u       /* 192.168/16 */
      || (a & 0xFFFFFF00u) == 0xC0000000u       /* 192.0.0/24 */
      || (a & 0xFFFFFF00u) == 0xC0000200u       /* 192.0.2/24 */
      || (a & 0xFFFFFF00u) == 0xC0586300u       /* 192.88.99/24 */
      || (a & 0xFFFE0000u) == 0xC6120000u       /* 198.18/15 */
      || (a & 0xFFFFFF00u) == 0xC6336400u       /* 198.51.100/24 */
      || (a & 0xFFFFFF00u) == 0xCB007100u)      /* 203.0.113/24 */
    return 0;
  if ((a >> 28) >= 0xE)                         /* 224/4, 240/4 */
    return 0;
  return 1;
}

static uint32_t v4_at(const unsigned char *p)
{
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/** 1 when the IPv6 address \a b is public.  An IPv4-mapped address
 * (::ffff:0:0/96, a dual-stack socket's IPv4 connection) or one under the
 * well-known NAT64 prefix (64:ff9b::/96, how an IPv6-only network reaches
 * IPv4 hosts) is judged by the IPv4 address in it.  Anything else must be
 * global unicast (2000::/3: this refuses ::/8 with the unspecified,
 * loopback, IPv4-compatible and IPv4-translated forms, 64:ff9b:1::/48,
 * 100::/64, 5f00::/16, unique local fc00::/7, link and site local
 * fe80::/9, multicast ff00::/8), and not one of its special-purpose
 * blocks: 2001::/23 (IETF protocol assignments: Teredo, benchmarking,
 * ORCHID), 2001:db8::/32 and 3fff::/20 (documentation), 2002::/16 (6to4,
 * an IPv4 address inside). */
static int v6_public(const unsigned char *b)
{
  static const unsigned char mapped[12] =
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
  static const unsigned char nat64[12] =
    { 0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0 };

  if (!memcmp(b, mapped, 12) || !memcmp(b, nat64, 12))
    return v4_public(v4_at(b + 12));
  if ((b[0] & 0xe0) != 0x20)                              /* 2000::/3 */
    return 0;
  if (b[0] == 0x20 && b[1] == 0x01
      && (b[2] <= 0x01                                    /* 2001::/23 */
          || (b[2] == 0x0d && b[3] == 0xb8)))             /* 2001:db8::/32 */
    return 0;
  if (b[0] == 0x20 && b[1] == 0x02)                       /* 2002::/16 */
    return 0;
  if (b[0] == 0x3f && b[1] == 0xff && (b[2] & 0xf0) == 0) /* 3fff::/20 */
    return 0;
  return 1;
}

int webpush_endpoint_address_ok(const struct sockaddr *addr, size_t len)
{
  if (!addr || len < sizeof(addr->sa_family))
    return 0;
  if (addr->sa_family == AF_INET && len >= sizeof(struct sockaddr_in)) {
    struct sockaddr_in sin;

    memcpy(&sin, addr, sizeof(sin));
    return v4_public(ntohl(sin.sin_addr.s_addr));
  }
  if (addr->sa_family == AF_INET6 && len >= sizeof(struct sockaddr_in6)) {
    struct sockaddr_in6 sin6;

    memcpy(&sin6, addr, sizeof(sin6));
    return v6_public(sin6.sin6_addr.s6_addr);
  }
  return 0;
}

/** 1 when \a host (lower or upper case) is "localhost" or a name under
 * it (RFC 6761: they all mean this machine). */
static int is_localhost(const char *host)
{
  size_t n = strlen(host);
  const char *tail;
  size_t i;

  if (n < 9)
    return 0;
  tail = host + n - 9;
  for (i = 0; i < 9; i++)
    if ((tail[i] | 0x20) != "localhost"[i])
      return 0;
  return n == 9 || tail[-1] == '.';
}

/** The URL: "https://", then an authority with no user part and nothing
 * but plain printable characters (no '%' escapes, no '\'), a host and an
 * optional port (1-65535).  A host that is an IP address -- bracketed
 * IPv6, or IPv4 in any form the resolver takes (dotted, shortened,
 * decimal, octal, hex) -- must be public; a name must not be localhost.
 * Where a name leads is judged when a delivery connects
 * (webpush_endpoint_address_ok()). */
int webpush_endpoint_url_ok(const char *url)
{
  const char *auth, *end, *rest, *p;
  char host[256];
  size_t hlen;

  if (!url || strncmp(url, "https://", 8) != 0)
    return 0;
  auth = url + 8;
  end = auth + strcspn(auth, "/?#");
  if (end == auth)
    return 0;
  for (p = auth; p < end; p++) {
    unsigned char c = (unsigned char)*p;
    if (c <= 0x20 || c >= 0x7f || c == '@' || c == '\\' || c == '%')
      return 0;
  }

  if (*auth == '[') {
    const char *close = memchr(auth, ']', (size_t)(end - auth));
    struct in6_addr in6;

    if (!close)
      return 0;
    hlen = (size_t)(close - auth - 1);
    if (hlen == 0 || hlen >= sizeof(host))
      return 0;
    memcpy(host, auth + 1, hlen);
    host[hlen] = '\0';
    if (inet_pton(AF_INET6, host, &in6) != 1 || !v6_public(in6.s6_addr))
      return 0;
    rest = close + 1;
  } else {
    const char *colon = memchr(auth, ':', (size_t)(end - auth));
    struct in_addr in;

    rest = colon ? colon : end;
    hlen = (size_t)(rest - auth);
    if (hlen == 0 || hlen >= sizeof(host))
      return 0;
    memcpy(host, auth, hlen);
    host[hlen] = '\0';
    if (hlen > 1 && host[hlen - 1] == '.')    /* the root: same host */
      host[--hlen] = '\0';
    if (inet_aton(host, &in)) {
      if (!v4_public(ntohl(in.s_addr)))
        return 0;
    } else if (is_localhost(host))
      return 0;
  }

  if (rest < end) {
    unsigned long port = 0;

    if (*rest++ != ':' || rest == end || end - rest > 5)
      return 0;
    for (p = rest; p < end; p++) {
      if (*p < '0' || *p > '9')
        return 0;
      port = port * 10 + (unsigned long)(*p - '0');
    }
    if (port == 0 || port > 65535)
      return 0;
  }
  return 1;
}
