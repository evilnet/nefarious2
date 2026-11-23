/*
 * webpush_endpoint_cmocka.c - which push endpoints the server may deliver
 * to (ircd/webpush_endpoint.c).
 *
 * The registered URL: https only, no user part, and a host that is not
 * an internal address in any spelling the resolver accepts (dotted,
 * shortened, decimal, hex, octal IPv4; IPv6 with an IPv4 inside) nor a
 * localhost name.  The address a delivery connects to: not loopback,
 * private, link-local, shared (CGNAT), multicast, unspecified, reserved,
 * documentation, benchmarking or another special-purpose block; IPv6 only
 * global unicast outside its special blocks (6to4, Teredo, ...), the
 * mapped and well-known NAT64 forms judged by the IPv4 inside.  The real
 * push services' endpoints, and public addresses, keep working.
 */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#include "webpush_endpoint.h"

struct url_case {
  const char *url;
  int ok;
};

static void check_urls(const struct url_case *cases, size_t n)
{
  size_t i;
  int wrong = 0;

  for (i = 0; i < n; i++) {
    int got = webpush_endpoint_url_ok(cases[i].url);
    if (got != cases[i].ok) {
      print_message("  %s: got %d, want %d\n", cases[i].url, got, cases[i].ok);
      wrong++;
    }
  }
  assert_int_equal(wrong, 0);
}

/* The real push services' endpoints (and other public hosts) register. */
static void test_push_services_accepted(void **state)
{
  static const struct url_case cases[] = {
    { "https://fcm.googleapis.com/fcm/send/dQw4w9WgXcQ:APA91bHPRgkF3JUikC4ENAHEeMrd41Zxv3hVZjC9KtT8OvPVGJ-hQMRKRrZuJAEcl7B338qju59zJMjw2DELjzEvxwYv7hH5Ynpc1ODQ0aT4U4OFEeco8ohsN5PjL1iC2dNtk2BAokeMCg2ZXKqpc8FXKmhX94kIxQ", 1 },
    { "https://updates.push.services.mozilla.com/wpush/v2/gAAAAABmZ3xQx1N0Y2Fh", 1 },
    { "https://web.push.apple.com/QGuQyavXutnMH9z2vXoFzYdl2hYFJn1W", 1 },
    { "https://wns2-par02p.notify.windows.com/w/?token=BQYAAAB%2fQx1Y%2bZ", 1 },
    { "https://push.example.com/endpoint", 1 },
    { "https://push.example.com:8443/endpoint", 1 },     /* a port is not refused */
    { "https://push.example.com", 1 },
    { "https://8.8.8.8/push", 1 },                       /* a public address */
    { "https://172.200.1.1/push", 1 },                   /* public, not 172.16/12 */
    { "https://172.32.0.1/push", 1 },
    { "https://100.128.0.1/push", 1 },                   /* past 100.64/10 */
    { "https://[2001:4860:4860::8888]/push", 1 },
    { "https://[2001:200::1]/push", 1 },                 /* past 2001::/23 */
    { "https://198.20.0.1/push", 1 },                    /* past 198.18/15 */
    { "https://localhost.example.com/push", 1 },         /* a name, not localhost */
  };
  (void)state;
  check_urls(cases, sizeof(cases) / sizeof(cases[0]));
}

/* What was refused before stays refused. */
static void test_plain_internal_urls_refused(void **state)
{
  static const struct url_case cases[] = {
    { "http://push.example.com/endpoint", 0 },
    { "ftp://push.example.com/endpoint", 0 },
    { "push.example.com/endpoint", 0 },
    { "https://localhost/push", 0 },
    { "https://127.0.0.1/push", 0 },
    { "https://10.1.2.3/push", 0 },
    { "https://172.16.0.1/push", 0 },
    { "https://172.31.255.255/push", 0 },
    { "https://192.168.1.1/push", 0 },
    { "https://[::1]/push", 0 },
    { "https://[fe80::1]/push", 0 },
    { "https://[fc00::1]/push", 0 },
    { "https://[fd12:3456::1]/push", 0 },
  };
  (void)state;
  check_urls(cases, sizeof(cases) / sizeof(cases[0]));
}

/* Each way around the old text blocklist is refused. */
static void test_blocklist_bypasses_refused(void **state)
{
  static const struct url_case cases[] = {
    /* a user part before the host */
    { "https://x@127.0.0.1/push", 0 },
    { "https://user:pw@push.example.com/push", 0 },
    /* case and spelling of localhost */
    { "https://LOCALHOST/push", 0 },
    { "https://LocalHost:8443/push", 0 },
    { "https://localhost./push", 0 },
    { "https://api.localhost/push", 0 },
    /* unspecified */
    { "https://0.0.0.0/push", 0 },
    { "https://0/push", 0 },
    { "https://[::]/push", 0 },
    /* link-local, cloud metadata */
    { "https://169.254.169.254/latest", 0 },
    /* shared address space (CGNAT) */
    { "https://100.64.0.1/push", 0 },
    { "https://100.127.255.254/push", 0 },
    /* other IPv4 spellings of loopback and private addresses */
    { "https://2130706433/push", 0 },                    /* decimal */
    { "https://0x7f000001/push", 0 },                    /* hex */
    { "https://0x7f.0.0.1/push", 0 },
    { "https://0177.0.0.1/push", 0 },                    /* octal */
    { "https://127.1/push", 0 },                         /* shortened */
    { "https://127.0.0.1./push", 0 },                    /* trailing dot */
    { "https://167772161/push", 0 },                     /* 10.0.0.1 */
    { "https://0xc0.0xa8.1.1/push", 0 },                 /* 192.168.1.1 */
    /* IPv6 with an internal IPv4 inside */
    { "https://[::ffff:127.0.0.1]/push", 0 },
    { "https://[::ffff:7f00:1]/push", 0 },
    { "https://[::ffff:10.0.0.1]/push", 0 },
    { "https://[64:ff9b::a9fe:a9fe]/push", 0 },          /* NAT64 169.254.169.254 */
    { "https://[::127.0.0.1]/push", 0 },                 /* IPv4-compatible */
    /* any port on an internal address */
    { "https://127.0.0.1:8443/push", 0 },
    { "https://[::1]:9200/push", 0 },
    /* multicast, broadcast, reserved */
    { "https://224.0.0.1/push", 0 },
    { "https://255.255.255.255/push", 0 },
    { "https://240.0.0.1/push", 0 },
    { "https://[ff02::1]/push", 0 },
    /* special-purpose IPv4 blocks */
    { "https://192.0.0.8/push", 0 },
    { "https://192.0.2.1/push", 0 },
    { "https://198.18.0.1/push", 0 },
    { "https://198.51.100.7/push", 0 },
    { "https://203.0.113.9/push", 0 },
    /* IPv6 that embeds or reaches an IPv4 or non-global address */
    { "https://[64:ff9b:1::a00:1]/push", 0 },            /* local-use NAT64 */
    { "https://[2002:7f00:1::1]/push", 0 },              /* 6to4 */
    { "https://[2001:0:4136:e378:8000:63bf:3fff:fdd2]/push", 0 },  /* Teredo */
    { "https://[100::1]/push", 0 },                      /* discard */
    { "https://[2001:db8::1]/push", 0 },                 /* documentation */
    { "https://[::ffff:0:7f00:1]/push", 0 },             /* IPv4-translated */
    /* a malformed authority */
    { "https:///push", 0 },
    { "https://[::1/push", 0 },
    { "https://[zz::1]/push", 0 },
    { "https://push.example.com:/push", 0 },
    { "https://push.example.com:99999/push", 0 },
    { "https://push.example.com:44x3/push", 0 },
    { "https://push.example.com\\@127.0.0.1/push", 0 },
    { "https://push.exa mple.com/push", 0 },
    { "https://%31%32%37.0.0.1/push", 0 },
  };
  (void)state;
  check_urls(cases, sizeof(cases) / sizeof(cases[0]));
}

static int v4_ok(const char *a)
{
  struct sockaddr_in sin;

  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_port = htons(443);
  assert_int_equal(inet_pton(AF_INET, a, &sin.sin_addr), 1);
  return webpush_endpoint_address_ok((const struct sockaddr *)&sin, sizeof(sin));
}

static int v6_ok(const char *a)
{
  struct sockaddr_in6 sin6;

  memset(&sin6, 0, sizeof(sin6));
  sin6.sin6_family = AF_INET6;
  sin6.sin6_port = htons(443);
  assert_int_equal(inet_pton(AF_INET6, a, &sin6.sin6_addr), 1);
  return webpush_endpoint_address_ok((const struct sockaddr *)&sin6, sizeof(sin6));
}

struct addr_case {
  const char *addr;
  int ok;
};

/* The address a delivery is about to connect to, whatever name resolved
 * to it: public ones only. */
static void test_connect_addresses(void **state)
{
  static const struct addr_case v4[] = {
    { "8.8.8.8", 1 }, { "142.250.74.10", 1 }, { "17.188.128.1", 1 },
    { "172.15.255.255", 1 }, { "172.32.0.0", 1 }, { "100.63.255.255", 1 },
    { "100.128.0.0", 1 }, { "169.253.0.1", 1 }, { "223.255.255.255", 1 },
    { "192.0.1.255", 1 }, { "192.0.3.0", 1 }, { "198.17.255.255", 1 },
    { "198.20.0.0", 1 }, { "198.51.99.255", 1 }, { "203.0.114.0", 1 },
    { "192.0.0.0", 0 }, { "192.0.0.255", 0 }, { "192.0.2.1", 0 },
    { "192.88.99.1", 0 }, { "198.18.0.0", 0 }, { "198.19.255.255", 0 },
    { "198.51.100.1", 0 }, { "203.0.113.255", 0 },
    { "0.0.0.0", 0 }, { "0.1.2.3", 0 }, { "127.0.0.1", 0 }, { "127.255.0.9", 0 },
    { "10.0.0.1", 0 }, { "172.16.0.1", 0 }, { "172.31.255.255", 0 },
    { "192.168.0.1", 0 }, { "169.254.169.254", 0 }, { "100.64.0.1", 0 },
    { "100.127.255.255", 0 }, { "224.0.0.251", 0 }, { "239.255.255.250", 0 },
    { "240.0.0.1", 0 }, { "255.255.255.255", 0 },
  };
  static const struct addr_case v6[] = {
    { "2001:4860:4860::8888", 1 }, { "2a00:1450:4001:82a::200a", 1 },
    { "::ffff:8.8.8.8", 1 }, { "64:ff9b::808:808", 1 },
    { "2001:200::1", 1 }, { "2600::1", 1 }, { "3ffe::1", 1 },
    { "64:ff9b:1::808:808", 0 }, { "64:ff9b:1:ffff::1", 0 },
    { "2002:808:808::1", 0 }, { "2002:7f00:1::1", 0 },
    { "2001::1", 0 }, { "2001:0:4136:e378:8000:63bf:3fff:fdd2", 0 },
    { "2001:2::1", 0 }, { "2001:10::1", 0 }, { "2001:1ff::1", 0 },
    { "2001:db8::1", 0 }, { "2001:db8:ffff::1", 0 },
    { "100::1", 0 }, { "100::ffff:ffff:ffff:ffff", 0 },
    { "3fff::1", 0 }, { "5f00::1", 0 }, { "::ffff:0:7f00:1", 0 },
    { "::ffff:0:808:808", 0 }, { "1000::1", 0 }, { "4000::1", 0 },
    { "::", 0 }, { "::1", 0 }, { "::127.0.0.1", 0 }, { "::ffff:127.0.0.1", 0 },
    { "::ffff:10.1.2.3", 0 }, { "::ffff:169.254.169.254", 0 },
    { "64:ff9b::7f00:1", 0 }, { "64:ff9b::a9fe:a9fe", 0 },
    { "fe80::1", 0 }, { "febf::1", 0 }, { "fec0::1", 0 }, { "fc00::1", 0 },
    { "fdff::1", 0 }, { "ff02::1", 0 }, { "ff0e::1", 0 },
  };
  size_t i;
  int wrong = 0;

  (void)state;
  for (i = 0; i < sizeof(v4) / sizeof(v4[0]); i++)
    if (v4_ok(v4[i].addr) != v4[i].ok) {
      print_message("  %s: want %d\n", v4[i].addr, v4[i].ok);
      wrong++;
    }
  for (i = 0; i < sizeof(v6) / sizeof(v6[0]); i++)
    if (v6_ok(v6[i].addr) != v6[i].ok) {
      print_message("  %s: want %d\n", v6[i].addr, v6[i].ok);
      wrong++;
    }
  assert_int_equal(wrong, 0);
}

/* Another family, or a length too short for the family, is refused. */
static void test_connect_other_families_refused(void **state)
{
  struct sockaddr_in sin;
  struct sockaddr sa;

  (void)state;
  memset(&sa, 0, sizeof(sa));
  sa.sa_family = AF_UNIX;
  assert_int_equal(webpush_endpoint_address_ok(&sa, sizeof(sa)), 0);
  assert_int_equal(webpush_endpoint_address_ok(NULL, 0), 0);

  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  inet_pton(AF_INET, "8.8.8.8", &sin.sin_addr);
  assert_int_equal(webpush_endpoint_address_ok((struct sockaddr *)&sin, 2), 0);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_push_services_accepted),
    cmocka_unit_test(test_plain_internal_urls_refused),
    cmocka_unit_test(test_blocklist_bypasses_refused),
    cmocka_unit_test(test_connect_addresses),
    cmocka_unit_test(test_connect_other_families_refused),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
