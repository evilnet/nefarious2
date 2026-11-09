/*
 * ircd_string_cmocka.c - CMocka unit tests for IRC string utilities
 *
 * Tests various string manipulation functions used throughout the IRC daemon.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <cmocka.h>

#include "ircd_defs.h"
#include "ircd_string.h"
#include "ircd_chattr.h"


/* ========== ircd_strncpy ========== */

static void test_ircd_strncpy_normal(void **state)
{
    (void)state;
    char dest[32];

    /* Normal copy */
    ircd_strncpy(dest, "hello", sizeof(dest));
    assert_string_equal(dest, "hello");

    /* Copy with exact size */
    ircd_strncpy(dest, "world", 6);
    assert_string_equal(dest, "world");
}

static void test_ircd_strncpy_truncation(void **state)
{
    (void)state;
    char dest[8];

    /* Source longer than dest - should truncate.  ircd_strncpy is strlcpy-like:
     * the size arg is the FULL buffer size and it writes at most size-1 chars
     * + NUL, so an 8-byte dest yields a 7-char result. */
    ircd_strncpy(dest, "hello world", sizeof(dest));
    assert_int_equal(strlen(dest), 7);
}

static void test_ircd_strncpy_empty(void **state)
{
    (void)state;
    char dest[32];

    /* Empty string copy */
    ircd_strncpy(dest, "", sizeof(dest));
    assert_string_equal(dest, "");
    assert_int_equal(strlen(dest), 0);
}


/* ========== ircd_strcmp (case-insensitive IRC comparison) ========== */

static void test_ircd_strcmp_equal(void **state)
{
    (void)state;

    /* Same case */
    assert_int_equal(0, ircd_strcmp("hello", "hello"));
    assert_int_equal(0, ircd_strcmp("HELLO", "HELLO"));
    assert_int_equal(0, ircd_strcmp("", ""));

    /* Different case - should still be equal for IRC */
    assert_int_equal(0, ircd_strcmp("hello", "HELLO"));
    assert_int_equal(0, ircd_strcmp("HeLLo", "hElLO"));
    assert_int_equal(0, ircd_strcmp("Nick123", "NICK123"));
}

static void test_ircd_strcmp_not_equal(void **state)
{
    (void)state;

    assert_int_not_equal(0, ircd_strcmp("hello", "world"));
    assert_int_not_equal(0, ircd_strcmp("abc", "abcd"));
    assert_int_not_equal(0, ircd_strcmp("abcd", "abc"));
    assert_int_not_equal(0, ircd_strcmp("", "x"));
}

static void test_ircd_strcmp_irc_special_chars(void **state)
{
    (void)state;

    /* IRC treats {}|^ as lowercase of []\~ */
    /* These should be considered equal */
    assert_int_equal(0, ircd_strcmp("[", "{"));
    assert_int_equal(0, ircd_strcmp("]", "}"));
    assert_int_equal(0, ircd_strcmp("\\", "|"));
    assert_int_equal(0, ircd_strcmp("~", "^"));

    /* Mixed with regular chars */
    assert_int_equal(0, ircd_strcmp("nick[away]", "nick{away}"));
}


/* ========== ircd_strncmp ========== */

static void test_ircd_strncmp_basic(void **state)
{
    (void)state;

    /* Compare first n characters */
    assert_int_equal(0, ircd_strncmp("hello", "hello world", 5));
    assert_int_equal(0, ircd_strncmp("HELLO", "hello", 5));
    assert_int_equal(0, ircd_strncmp("abcdef", "abcxyz", 3));

    assert_int_not_equal(0, ircd_strncmp("abcdef", "abcxyz", 4));
}


/* ========== unique_name_vector ========== */

static void test_unique_name_vector_basic(void **state)
{
    (void)state;
    char *vector[20];
    char *names;
    int count;

    /* Basic comma-separated list */
    names = strdup("a,b,c");
    count = unique_name_vector(names, ',', vector, 20);
    assert_int_equal(count, 3);
    assert_string_equal(vector[0], "a");
    assert_string_equal(vector[1], "b");
    assert_string_equal(vector[2], "c");
    free(names);
}

static void test_unique_name_vector_duplicates(void **state)
{
    (void)state;
    char *vector[20];
    char *names;
    int count;

    /* Duplicates should be removed (case-insensitive) */
    names = strdup("a,b,a,c,B,C");
    count = unique_name_vector(names, ',', vector, 20);
    assert_int_equal(count, 3);  /* Only a, b, c should remain */
    free(names);
}

static void test_unique_name_vector_empty_elements(void **state)
{
    (void)state;
    char *vector[20];
    char *names;
    int count;

    /* Empty elements should be skipped */
    names = strdup(",,,a,,b,,");
    count = unique_name_vector(names, ',', vector, 20);
    assert_int_equal(count, 2);
    free(names);
}

static void test_unique_name_vector_single(void **state)
{
    (void)state;
    char *vector[20];
    char *names;
    int count;

    /* Single element */
    names = strdup("foo");
    count = unique_name_vector(names, ',', vector, 20);
    assert_int_equal(count, 1);
    assert_string_equal(vector[0], "foo");
    free(names);
}

static void test_unique_name_vector_empty(void **state)
{
    (void)state;
    char *vector[20];
    char *names;
    int count;

    /* Empty string */
    names = strdup("");
    count = unique_name_vector(names, ',', vector, 20);
    assert_int_equal(count, 0);
    free(names);
}

static void test_unique_name_vector_limit(void **state)
{
    (void)state;
    char *vector[5];
    char *names;
    int count;

    /* More elements than vector can hold */
    names = strdup("a,b,c,d,e,f,g,h");
    count = unique_name_vector(names, ',', vector, 5);
    assert_true(count <= 5);  /* Should not exceed limit */
    free(names);
}


/* ========== token_vector ========== */

static void test_token_vector_basic(void **state)
{
    (void)state;
    char *vector[20];
    char *names;
    int count;

    /* Unlike unique_name_vector, keeps duplicates and empty elements */
    names = strdup("a,b,c");
    count = token_vector(names, ',', vector, 20);
    assert_int_equal(count, 3);
    free(names);
}


/* ========== EmptyString macro ========== */

static void test_EmptyString_macro(void **state)
{
    (void)state;
    const char *null_str = NULL;
    const char *empty_str = "";
    const char *x_str = "x";
    const char *hello_str = "hello";

    /* Use variables to avoid macro expansion issues with assert_true */
    assert_int_not_equal(0, EmptyString(null_str));
    assert_int_not_equal(0, EmptyString(empty_str));
    assert_int_equal(0, EmptyString(x_str));
    assert_int_equal(0, EmptyString(hello_str));
}


/* ========== string_has_wildcards ========== */

static void test_string_has_wildcards(void **state)
{
    (void)state;

    /* Strings with wildcards */
    assert_true(string_has_wildcards("*"));
    assert_true(string_has_wildcards("hello*"));
    assert_true(string_has_wildcards("?"));
    assert_true(string_has_wildcards("a?b"));
    assert_true(string_has_wildcards("*?*"));

    /* Strings without wildcards */
    assert_false(string_has_wildcards("hello"));
    assert_false(string_has_wildcards(""));
    assert_false(string_has_wildcards("test123"));
}


/* ========== ParseInterval ========== */

static void test_ParseInterval_seconds(void **state)
{
    (void)state;

    /* Plain numbers are seconds */
    assert_int_equal(60, ParseInterval("60"));
    assert_int_equal(3600, ParseInterval("3600"));
    assert_int_equal(0, ParseInterval("0"));
}

static void test_ParseInterval_with_units(void **state)
{
    (void)state;

    /* Minutes */
    assert_int_equal(60, ParseInterval("1m"));
    assert_int_equal(300, ParseInterval("5m"));

    /* Hours */
    assert_int_equal(3600, ParseInterval("1h"));
    assert_int_equal(7200, ParseInterval("2h"));

    /* Days */
    assert_int_equal(86400, ParseInterval("1d"));
    assert_int_equal(172800, ParseInterval("2d"));

    /* Weeks */
    assert_int_equal(604800, ParseInterval("1w"));
}

static void test_ParseInterval_combined(void **state)
{
    (void)state;

    /* Combined intervals */
    assert_int_equal(3661, ParseInterval("1h1m1"));  /* 1 hour + 1 min + 1 sec */
    assert_int_equal(90061, ParseInterval("1d1h1m1")); /* 1 day + 1 hour + 1 min + 1 sec */
}


/* ========== is_timestamp ========== */

/* Test is_timestamp - checks if string contains only digits (and dots).
 * Note: ircu implementation returns true for empty string because the loop
 * "while (IsDigit(*str)) ++str" immediately hits NUL, then "*str == '\0'"
 * returns true. This is vacuous truth - callers should check for empty first
 * if that matters. This is historical ircu behavior preserved in nefarious. */
static void test_is_timestamp(void **state)
{
    (void)state;

    /* Valid timestamps (all digits) */
    assert_true(is_timestamp("1234567890"));
    assert_true(is_timestamp("0"));
    assert_true(is_timestamp("999999999"));

    /* Empty string: ircu returns true (vacuously valid - no invalid chars) */
    assert_true(is_timestamp(""));

    /* Invalid timestamps */
    assert_false(is_timestamp("abc"));
    assert_false(is_timestamp("123abc"));
    assert_false(is_timestamp("-123"));
}


/* ========== valid_username ========== */

/* Test valid_username - checks if all chars are valid user ID chars.
 * Note: ircu implementation returns true for empty string because the loop
 * "for (c = name; *c; c++)" never executes, so it returns 1. This is vacuous
 * truth - callers should check for empty first if that matters.
 * Compare to valid_hostname() which explicitly rejects empty strings.
 * This is historical ircu behavior preserved in nefarious. */
static void test_valid_username(void **state)
{
    (void)state;

    /* Valid usernames */
    assert_true(valid_username("user"));
    assert_true(valid_username("user123"));
    assert_true(valid_username("a"));

    /* Empty string: ircu returns true (vacuously valid - no invalid chars) */
    assert_true(valid_username(""));

    /* Invalid usernames */
    assert_false(valid_username("user name"));  /* No spaces */
}


/* ========== valid_hostname ========== */

static void test_valid_hostname(void **state)
{
    (void)state;

    /* Valid hostnames */
    assert_true(valid_hostname("example.com"));
    assert_true(valid_hostname("irc.example.org"));
    assert_true(valid_hostname("host-name.domain.tld"));
    assert_true(valid_hostname("localhost"));

    /* Invalid hostnames */
    assert_false(valid_hostname(""));
    assert_false(valid_hostname("host name.com"));  /* No spaces */
}



/* PR #109 + follow-up: Spoofhost block validation.  The user part takes
 * IsUserChar (alphanumerics, Latin-1 letters and .-_^'`~ -- so the
 * no-ident '~' prefix is fine); it is bounded by USERLEN and the host part
 * by HOSTLEN because both are strlcpy'd into sethost[HOSTLEN + USERLEN + 2]
 * downstream; an IPv6 literal is not a host. */
static void test_valid_spoofhost(void **state)
{
    char longuser[USERLEN + 2 + 16];
    char longhost[HOSTLEN + 2 + 16];
    (void)state;

    assert_true(valid_spoofhost("example.com", 0));
    assert_true(valid_spoofhost("user@example.com", 0));
    assert_true(valid_spoofhost("~user@example.com", 0));
    assert_true(valid_spoofhost("*", 1));
    assert_true(valid_spoofhost("us?r@*.example.com", 1));

    assert_false(valid_spoofhost("", 0));
    assert_false(valid_spoofhost("@example.com", 0));
    assert_false(valid_spoofhost("user@", 0));
    assert_false(valid_spoofhost(":evil@example.com", 0));
    assert_false(valid_spoofhost("us er@example.com", 0));
    assert_true(valid_spoofhost("u.s-e_r@example.com", 0));
    assert_false(valid_spoofhost(".example.com", 0));
    assert_false(valid_spoofhost("example.com.", 0));
    assert_false(valid_spoofhost("2001:db8::1", 0));          /* IPv6 literal */
    assert_false(valid_spoofhost("*", 0));                    /* wildcard needs ismask */

    memset(longuser, 'a', sizeof(longuser) - 1);
    longuser[sizeof(longuser) - 1] = '\0';
    {
        char buf[128];
        snprintf(buf, sizeof(buf), "%.*s@example.com", USERLEN + 1, longuser);
        assert_false(valid_spoofhost(buf, 0));
        snprintf(buf, sizeof(buf), "%.*s@example.com", USERLEN, longuser);
        assert_true(valid_spoofhost(buf, 0));
    }
    memset(longhost, 'h', sizeof(longhost) - 1);
    longhost[sizeof(longhost) - 1] = '\0';
    {
        char buf[160];
        snprintf(buf, sizeof(buf), "%.*s", HOSTLEN + 1, longhost);
        assert_false(valid_spoofhost(buf, 0));
        snprintf(buf, sizeof(buf), "%.*s", HOSTLEN, longhost);
        assert_true(valid_spoofhost(buf, 0));
    }
}

/* ========== Character classification string functions ========== */
/* NOTE: strIsDigit/strIsAlpha/strIsAlnum tests removed because strChattr()
 * is conditionally compiled with FORCEINLINE and difficult to link in tests.
 * The underlying character classification is tested in ircd_chattr_cmocka.c */


/* ========== str_appendf ========== */

static void test_str_appendf_basic(void **state)
{
    (void)state;
    char buf[16];
    size_t pos = 0;
    buf[0] = '\0';
    assert_int_equal(str_appendf(buf, sizeof(buf), &pos, "%s", "ab"), 2);
    assert_int_equal(str_appendf(buf, sizeof(buf), &pos, "%d", 34), 2);
    assert_string_equal(buf, "ab34");
    assert_int_equal((int)pos, 4);
}

static void test_str_appendf_clamps_at_buffer_end(void **state)
{
    (void)state;
    char buf[8];              /* 7 usable + NUL */
    size_t pos = 0;
    buf[0] = '\0';
    /* would-be 11 chars, but only 7 fit; pos must clamp to 7, not 11 */
    str_appendf(buf, sizeof(buf), &pos, "%s", "hello world");
    assert_true(pos <= sizeof(buf) - 1);
    assert_int_equal(buf[sizeof(buf) - 1], '\0');
    /* a further append must be a safe no-op, never writing past the buffer */
    assert_int_equal(str_appendf(buf, sizeof(buf), &pos, "%s", "XYZ"), 0);
    assert_true(pos <= sizeof(buf) - 1);
}

static void test_str_appendf_noop_when_pos_at_end(void **state)
{
    (void)state;
    char buf[4] = "abc";
    size_t pos = 3;
    assert_int_equal(str_appendf(buf, sizeof(buf), &pos, "z"), 0);
    assert_string_equal(buf, "abc");
    assert_int_equal((int)pos, 3);
}

static void test_str_appendf_guard_pos_at_or_past_buflen(void **state)
{
    (void)state;
    char buf[8] = "abcdefg";        /* full: 7 chars + NUL */
    size_t pos = sizeof(buf);       /* pos == buflen: initial guard must no-op */
    assert_int_equal(str_appendf(buf, sizeof(buf), &pos, "X"), 0);
    assert_int_equal((int)pos, (int)sizeof(buf));
    assert_string_equal(buf, "abcdefg");

    pos = sizeof(buf) + 5;          /* pos > buflen: still a safe no-op */
    assert_int_equal(str_appendf(buf, sizeof(buf), &pos, "X"), 0);
    assert_string_equal(buf, "abcdefg");
}


/* ========== csv_contains_token ========== */

static void test_csv_contains_token_empty_denies(void **state)
{
    (void)state;
    assert_int_equal(csv_contains_token(NULL, "svc"), 0);
    assert_int_equal(csv_contains_token("", "svc"), 0);
}

static void test_csv_contains_token_match_and_case(void **state)
{
    (void)state;
    assert_int_equal(csv_contains_token("bnc,svc,relay", "svc"), 1);
    assert_int_equal(csv_contains_token("bnc,svc,relay", "SVC"), 1); /* ci */
    assert_int_equal(csv_contains_token("bnc svc relay", "relay"), 1); /* space-sep */
    assert_int_equal(csv_contains_token("bnc,svc", "mallory"), 0);
    assert_int_equal(csv_contains_token("bnc,svc", "sv"), 0);       /* no prefix match */
}


/* ========== ircd_clienttagdeny_match ========== */
/* The IRCv3 message-tags spec writes CLIENTTAGDENY entries WITHOUT
 * the client-only `+` prefix (e.g. "*,-draft/react"); the fork's
 * matcher (pre-fix: is_client_tag_denied() in ircd.c) required a
 * literal leading '+' on positive entries.  These pin the normalised
 * behaviour: spec form and `+`-form entries are equivalent, both as
 * positive denials and as negations. */

#define CTD_MATCH(list, tag) \
  ircd_clienttagdeny_match((list), (tag), strlen(tag))

static void test_ctd_spec_form_denies(void **state)
{
    (void)state;
    assert_int_equal(CTD_MATCH("draft/language", "+draft/language"), 1);
    assert_int_equal(CTD_MATCH("draft/language", "+draft/react"), 0);
}

static void test_ctd_plus_form_denies_same(void **state)
{
    (void)state;
    assert_int_equal(CTD_MATCH("+draft/language", "+draft/language"), 1);
    assert_int_equal(CTD_MATCH("+draft/language", "+draft/react"), 0);
}

static void test_ctd_star_denies_all(void **state)
{
    (void)state;
    assert_int_equal(CTD_MATCH("*", "+draft/language"), 1);
    assert_int_equal(CTD_MATCH("*", "+anything/at-all"), 1);
}

static void test_ctd_star_with_negation_exempts_one(void **state)
{
    (void)state;
    assert_int_equal(CTD_MATCH("*,-draft/react", "+draft/react"), 0);
    assert_int_equal(CTD_MATCH("*,-draft/react", "+draft/language"), 1);
}

static void test_ctd_negated_plus_form_equivalent(void **state)
{
    (void)state;
    assert_int_equal(CTD_MATCH("-+draft/react", "+draft/react"), 0);
    assert_int_equal(CTD_MATCH("-draft/react", "+draft/react"), 0);
    /* Without a deny-all, a bare negation entry denies nothing else. */
    assert_int_equal(CTD_MATCH("-+draft/react", "+draft/language"), 0);
}

static void test_ctd_prefix_wildcard_positive(void **state)
{
    (void)state;
    assert_int_equal(CTD_MATCH("draft/*", "+draft/x"), 1);
    assert_int_equal(CTD_MATCH("draft/*", "+drafty"), 0);
    /* Bare prefix with nothing past the slash does not match -- the
     * same "longer than the prefix" rule as negation (unified; see
     * the hotfix report for the pre-fix positive/negative asymmetry). */
    assert_int_equal(CTD_MATCH("draft/*", "+draft/"), 0);
}

static void test_ctd_prefix_wildcard_negated_exempts_subtree(void **state)
{
    (void)state;
    assert_int_equal(CTD_MATCH("*,-draft/*", "+draft/language"), 0);
    assert_int_equal(CTD_MATCH("*,-draft/*", "+draft/react"), 0);
    assert_int_equal(CTD_MATCH("*,-draft/*", "+other/tag"), 1);
}

static void test_ctd_exemption_wins_over_denial(void **state)
{
    (void)state;
    assert_int_equal(CTD_MATCH("draft/language,-draft/language", "+draft/language"), 0);
    assert_int_equal(CTD_MATCH("+draft/language,-draft/language", "+draft/language"), 0);
}

static void test_ctd_spaces_and_empty_entries_ignored(void **state)
{
    (void)state;
    assert_int_equal(CTD_MATCH(" draft/language ,, -draft/react ", "+draft/language"), 1);
    assert_int_equal(CTD_MATCH(" draft/language ,, -draft/react ", "+draft/react"), 0);
}

static void test_ctd_tag_without_plus_never_denied(void **state)
{
    (void)state;
    assert_int_equal(ircd_clienttagdeny_match("*", "draft/language", strlen("draft/language")), 0);
    assert_int_equal(ircd_clienttagdeny_match("*", "", 0), 0);
}

static void test_ctd_empty_or_null_list_denies_nothing(void **state)
{
    (void)state;
    assert_int_equal(CTD_MATCH("", "+draft/language"), 0);
    assert_int_equal(ircd_clienttagdeny_match(NULL, "+draft/language", strlen("+draft/language")), 0);
}

static void test_ctd_value_bearing_tag_matches_by_name(void **state)
{
    (void)state;
    /* A client-only tag almost always carries a value
     * (draft/reply=<msgid>, draft/react=<emoji>); CLIENTTAGDENY
     * filters by tag KEY, not value -- the spec's own worked example
     * (-draft/react,-draft/reply in FEATURE_FLAGS_CONFIG.md) would be
     * silently inert otherwise, since those tags are never sent bare. */
    assert_int_equal(CTD_MATCH("draft/language", "+draft/language=x"), 1);
    assert_int_equal(CTD_MATCH("*,-draft/react", "+draft/react=\xf0\x9f\x91\x8d"), 0);
    assert_int_equal(CTD_MATCH("draft/*", "+draft/reply=12345"), 1);
    /* A longer NAME must not be mistaken for the entry plus a value:
     * "draft/x" must not match "+draft/xy" (no '=' boundary). */
    assert_int_equal(CTD_MATCH("draft/x", "+draft/xy"), 0);
}

static void test_ctd_old_matcher_missed_spec_form(void **state)
{
    /* Semantic RED pin: reproduces the OLD is_client_tag_denied()
     * positive-match rule (pre-fix, ircd.c ~:401-413) inline, showing
     * the spec-form entry it failed to deny.  Kept after the fix
     * lands so a regression that reintroduces the +-only requirement
     * trips THIS test too, not just a missing symbol. */
    const char *tag = "+draft/language";
    size_t tag_len = strlen(tag);
    const char *deny_list = "draft/language";
    const char *p, *pattern_start;
    size_t pattern_len;
    int explicitly_denied = 0;
    (void)state;

    p = deny_list;
    while (*p) {
      while (*p == ' ' || *p == ',')
        p++;
      if (!*p)
        break;
      pattern_start = p;
      while (*p && *p != ',')
        p++;
      pattern_len = p - pattern_start;
      /* OLD rule: a positive entry only matched with a literal '+'. */
      if (pattern_start[0] == '+' &&
          tag_len == pattern_len &&
          ircd_strncmp(tag, pattern_start, pattern_len) == 0)
        explicitly_denied = 1;
    }
    assert_int_equal(explicitly_denied, 0);    /* old matcher: missed it (the bug) */
    assert_int_equal(CTD_MATCH(deny_list, tag), 1); /* new matcher: denies it (fixed) */
}


/* ========== ircd_reserved_vendor_tag ========== */
/* Pre-fix, is_reserved_vendor_tag() (ircd.c) reserved the WHOLE
 * `+evilnet.github.io/` namespace from client tags.  User decision
 * 2026-11-09: Seance (an evilnet project) may use the rest of that
 * namespace for ordinary client-only tags (e.g.
 * `+evilnet.github.io/machine-translated`) -- only the specific
 * NAMES the server itself writes (sid, ssid, rsid, chathistory-gap)
 * stay reserved there.  `+afternet.org/` stays reserved whole
 * (legacy). */

#define RVT(tag) ircd_reserved_vendor_tag((tag), strlen(tag))

static void test_rvt_reserved_names_bare(void **state)
{
    (void)state;
    assert_int_equal(RVT("+evilnet.github.io/sid"), 1);
    assert_int_equal(RVT("+evilnet.github.io/ssid"), 1);
    assert_int_equal(RVT("+evilnet.github.io/rsid"), 1);
    assert_int_equal(RVT("+evilnet.github.io/chathistory-gap"), 1);
}

static void test_rvt_reserved_names_with_value(void **state)
{
    (void)state;
    assert_int_equal(RVT("+evilnet.github.io/sid=abc123"), 1);
    assert_int_equal(RVT("+evilnet.github.io/ssid=abc123"), 1);
    assert_int_equal(RVT("+evilnet.github.io/rsid=abc123"), 1);
    assert_int_equal(RVT("+evilnet.github.io/chathistory-gap=1"), 1);
}

static void test_rvt_afternet_namespace_reserved_whole(void **state)
{
    (void)state;
    assert_int_equal(RVT("+afternet.org/sid=abc"), 1);
    assert_int_equal(RVT("+afternet.org/anything"), 1);
    assert_int_equal(RVT("+afternet.org/machine-translated"), 1);
    assert_int_equal(RVT("+AfterNet.ORG/sid=abc"), 1); /* case-insensitive domain */
}

static void test_rvt_other_evilnet_names_pass_through(void **state)
{
    (void)state;
    /* The whole point of this hotfix: Seance's own tag must NOT be
     * reserved just for living under the evilnet.github.io host. */
    assert_int_equal(RVT("+evilnet.github.io/machine-translated"), 0);
    assert_int_equal(RVT("+evilnet.github.io/machine-translated=1"), 0);
}

static void test_rvt_name_boundary_not_a_byte_prefix(void **state)
{
    (void)state;
    /* "sid" must not match "sidecar" -- the pre-fix bug this hotfix
     * also fixes in m_chathistory.c's strip_internal_tags(), which
     * used the same kind of unanchored byte-prefix memcmp. */
    assert_int_equal(RVT("+evilnet.github.io/sidecar"), 0);
    assert_int_equal(RVT("+evilnet.github.io/sidecar=x"), 0);
}

static void test_rvt_evilnet_empty_name_not_reserved(void **state)
{
    (void)state;
    assert_int_equal(RVT("+evilnet.github.io/"), 0);
    assert_int_equal(RVT("+evilnet.github.io/="), 0);
}

static void test_rvt_unrelated_tag_not_reserved(void **state)
{
    (void)state;
    assert_int_equal(RVT("+draft/react"), 0);
    assert_int_equal(RVT("+draft/react=x"), 0);
    assert_int_equal(ircd_reserved_vendor_tag(NULL, 0), 0);
    assert_int_equal(RVT(""), 0);
}

static void test_rvt_lookalike_shorter_than_prefix(void **state)
{
    (void)state;
    assert_int_equal(RVT("+afternet.org"), 0);
    assert_int_equal(RVT("+evilnet.github.io"), 0);
}


/* --- ircd_json_escape --- */

static void test_json_escape_passthrough(void **state)
{
  char buf[64];
  (void)state;
  assert_string_equal(ircd_json_escape(buf, sizeof(buf), "plain text"),
                      "plain text");
  assert_string_equal(ircd_json_escape(buf, sizeof(buf), NULL), "");
}

static void test_json_escape_specials(void **state)
{
  char buf[64];
  (void)state;
  assert_string_equal(ircd_json_escape(buf, sizeof(buf), "a\"b\\c"),
                      "a\\\"b\\\\c");
  assert_string_equal(ircd_json_escape(buf, sizeof(buf), "x\ny"),
                      "x\\u000ay");
}

static void test_json_escape_truncates_cleanly(void **state)
{
  char buf[4];
  (void)state;
  /* 2-byte escape does not fit in the 1 remaining slot: clean stop. */
  assert_string_equal(ircd_json_escape(buf, sizeof(buf), "ab\"cd"), "ab");
}

/* --- ircd_text_mentions --- */

static void test_mentions_basic_and_case(void **state)
{
  (void)state;
  assert_int_equal(1, ircd_text_mentions("hey rubin look", "rubin"));
  assert_int_equal(1, ircd_text_mentions("hey RUBIN look", "rubin"));
  assert_int_equal(1, ircd_text_mentions("rubin: ping", "Rubin"));
}

static void test_mentions_boundaries(void **state)
{
  (void)state;
  assert_int_equal(1, ircd_text_mentions("rubin", "rubin"));      /* whole text */
  assert_int_equal(1, ircd_text_mentions("(rubin)", "rubin"));    /* punct sides */
  assert_int_equal(1, ircd_text_mentions("cc rubin", "rubin"));   /* end of text */
}

static void test_mentions_substring_rejected(void **state)
{
  (void)state;
  assert_int_equal(0, ircd_text_mentions("rubinstein plays", "rubin"));
  assert_int_equal(0, ircd_text_mentions("subrubin here", "rubin"));
  assert_int_equal(0, ircd_text_mentions("rubin2 spoke", "rubin"));
}

static void test_mentions_null_safe(void **state)
{
  (void)state;
  assert_int_equal(0, ircd_text_mentions(NULL, "x"));
  assert_int_equal(0, ircd_text_mentions("text", NULL));
  assert_int_equal(0, ircd_text_mentions("text", ""));
}

/* --- ircd_utf8_clamp --- */

static void test_utf8_clamp_fits_untouched(void **state)
{
  char buf[32] = "hello";
  (void)state;
  assert_int_equal(0, ircd_utf8_clamp(buf, 10));
  assert_string_equal(buf, "hello");
  assert_int_equal(0, ircd_utf8_clamp(buf, 5)); /* exact fit */
  assert_string_equal(buf, "hello");
}

static void test_utf8_clamp_ascii_cut(void **state)
{
  char buf[32] = "hello world";
  (void)state;
  assert_int_equal(1, ircd_utf8_clamp(buf, 5));
  assert_string_equal(buf, "hello");
}

static void test_utf8_clamp_multibyte_boundary(void **state)
{
  /* "aX" where X = 2-byte U+00E9 (0xC3 0xA9).  Cutting at 2 lands on
   * the continuation byte -> whole sequence dropped. */
  char buf[8] = "a\303\251";
  (void)state;
  assert_int_equal(1, ircd_utf8_clamp(buf, 2));
  assert_string_equal(buf, "a");
}

static void test_utf8_clamp_keeps_complete_sequence(void **state)
{
  /* Cutting exactly after the full 2-byte sequence keeps it. */
  char buf[8] = "a\303\251b";
  (void)state;
  assert_int_equal(1, ircd_utf8_clamp(buf, 3));
  assert_string_equal(buf, "a\303\251");
}

static void test_utf8_clamp_null_safe(void **state)
{
  (void)state;
  assert_int_equal(0, ircd_utf8_clamp(NULL, 5));
}

/* --- ircd_line_body_clamp --- */

static void test_line_body_clamp_tagged(void **state)
{
  /* "@Axx " (5-byte tag region) + 600 x 'a', clamped to a 510-byte body. */
  char line[700];
  (void)state;
  memcpy(line, "@Axx ", 5);
  memset(line + 5, 'a', 600);
  assert_int_equal(5 + 510, ircd_line_body_clamp(line, 605, 510));
}

static void test_line_body_clamp_untagged(void **state)
{
  /* No tag region: the whole line is the body. */
  char line[600];
  (void)state;
  memset(line, 'a', 600);
  assert_int_equal(510, ircd_line_body_clamp(line, 600, 510));
}

static void test_line_body_clamp_fits(void **state)
{
  /* "@A " (3-byte tag region) + a 510-byte body: already at the cap. */
  char line[513];
  (void)state;
  memcpy(line, "@A ", 3);
  memset(line + 3, 'a', 510);
  assert_int_equal(513, ircd_line_body_clamp(line, 513, 510));
}

static void test_line_body_clamp_utf8(void **state)
{
  /* "@A " + 300 x (2-byte) 'e-acute': clamped to a 509-byte body backs
   * off one byte to land on a lead byte, keeping 508 body bytes. */
  char line[603];
  int i;
  (void)state;
  memcpy(line, "@A ", 3);
  for (i = 0; i < 300; i++) {
    line[3 + 2 * i] = '\303';
    line[3 + 2 * i + 1] = '\251';
  }
  assert_int_equal(3 + 508, ircd_line_body_clamp(line, 603, 509));
}

static void test_line_body_clamp_tag_no_space(void **state)
{
  /* A tag region with no trailing space has no body to measure. */
  char line[701];
  (void)state;
  line[0] = '@';
  memset(line + 1, 'a', 700);
  assert_int_equal(701, ircd_line_body_clamp(line, 701, 510));
}

static void test_line_body_clamp_tagged_512_cap(void **state)
{
  /* Ruling P1: a tagged line's body cap is 512, not 510. */
  char line[700];
  (void)state;
  memcpy(line, "@Axx ", 5);
  memset(line + 5, 'a', 600);
  assert_int_equal(5 + 512, ircd_line_body_clamp(line, 605, 512));
}

static void test_line_body_clamp_latin1_run(void **state)
{
  /* Not UTF-8: a Latin-1 / cp1252 run of 0x80-0xBF bytes ("\260" is the
   * Latin-1 degree sign).  No lead byte within three bytes of the cut,
   * so the back-off must not walk into the run: the cut stays at 510. */
  char line[603];
  (void)state;
  memcpy(line, "@A ", 3);
  memset(line + 3, '\260', 600);
  assert_int_equal(3 + 510, ircd_line_body_clamp(line, 603, 510));
}

static void test_line_body_clamp_utf8_4byte(void **state)
{
  /* 150 x U+1F600 (F0 9F 98 80): a 511-byte cap lands on the third
   * continuation byte of the 128th character, so the back-off takes all
   * three bytes back to its lead byte and keeps 127 whole characters. */
  char line[600];
  int i;
  (void)state;
  for (i = 0; i < 150; i++)
    memcpy(line + 4 * i, "\360\237\230\200", 4);
  assert_int_equal(508, ircd_line_body_clamp(line, 600, 511));
}

static void test_line_body_clamp_stray_continuation(void **state)
{
  /* 'a' x 508, a complete U+00E9 (C3 A9), then a stray A9: the cut at 510
   * lands on the stray byte, whose lead's sequence is already complete
   * before the cut -- nothing is split, so the cut stays at 510. */
  char line[514];
  (void)state;
  memset(line, 'a', 508);
  memcpy(line + 508, "\303\251\251bbb", 6);
  assert_int_equal(510, ircd_line_body_clamp(line, 514, 510));
}

/* --- string_is_valid_utf8 / string_sanitize_utf8 --- */

/* A line as an IRC client actually sends it: CTCP delimiters and the mIRC
 * formatting codes are bare C0 control bytes, and every one of them is a
 * well-formed single-byte UTF-8 sequence. */
#define CTCP_ACTION_LINE "\001ACTION waves\001"
#define FORMATTED_LINE   "\002bold\002 \037under\037 \003" "04red\003 \035it\035 \017"

static void test_utf8_valid_plain_ascii(void **state)
{
  (void)state;
  assert_int_equal(1, string_is_valid_utf8(""));
  assert_int_equal(1, string_is_valid_utf8("hello world"));
  assert_int_equal(1, string_is_valid_utf8("tab\there\r\n"));
}

static void test_utf8_valid_control_characters(void **state)
{
  (void)state;
  /* CTCP delimiter and the mIRC formatting codes. */
  assert_int_equal(1, string_is_valid_utf8(CTCP_ACTION_LINE));
  assert_int_equal(1, string_is_valid_utf8(FORMATTED_LINE));
  /* Every byte 0x01-0x7F on its own. */
  {
    char one[2] = {0, 0};
    int c;
    for (c = 0x01; c <= 0x7F; c++) {
      one[0] = (char)c;
      assert_int_equal(1, string_is_valid_utf8(one));
    }
  }
}

static void test_utf8_valid_multibyte(void **state)
{
  (void)state;
  assert_int_equal(1, string_is_valid_utf8("caf\303\251"));          /* U+00E9 */
  assert_int_equal(1, string_is_valid_utf8("\342\202\254"));         /* U+20AC */
  assert_int_equal(1, string_is_valid_utf8("\360\237\222\251"));     /* U+1F4A9 */
  assert_int_equal(1, string_is_valid_utf8("\355\237\277"));         /* U+D7FF */
}

static void test_utf8_invalid_sequences(void **state)
{
  (void)state;
  assert_int_equal(0, string_is_valid_utf8("\200"));                 /* lone continuation */
  assert_int_equal(0, string_is_valid_utf8("\300\200"));             /* overlong NUL */
  assert_int_equal(0, string_is_valid_utf8("\301\277"));             /* overlong */
  assert_int_equal(0, string_is_valid_utf8("\340\200\200"));         /* overlong 3-byte */
  assert_int_equal(0, string_is_valid_utf8("\360\200\200\200"));     /* overlong 4-byte */
  assert_int_equal(0, string_is_valid_utf8("\355\240\200"));         /* U+D800 surrogate */
  assert_int_equal(0, string_is_valid_utf8("\342\202"));             /* truncated 3-byte */
  assert_int_equal(0, string_is_valid_utf8("\364\220\200\200"));     /* > U+10FFFF */
  assert_int_equal(0, string_is_valid_utf8("\365\200\200\200"));     /* 0xF5 lead */
  assert_int_equal(0, string_is_valid_utf8("\376\377"));             /* never valid */
  assert_int_equal(0, string_is_valid_utf8("ok then \377 no"));      /* mid-string */
}

static void test_utf8_sanitize_leaves_control_codes_alone(void **state)
{
  char buf[BUFSIZE];
  (void)state;

  strcpy(buf, FORMATTED_LINE);
  assert_int_equal(-1, string_sanitize_utf8(buf));   /* -1 == nothing modified */
  assert_string_equal(buf, FORMATTED_LINE);

  strcpy(buf, CTCP_ACTION_LINE);
  assert_int_equal(-1, string_sanitize_utf8(buf));
  assert_string_equal(buf, CTCP_ACTION_LINE);
}

static void test_utf8_sanitize_replaces_invalid_bytes(void **state)
{
  char buf[BUFSIZE];
  (void)state;

  /* One bad byte becomes the 3-byte U+FFFD, so the string grows by two. */
  strcpy(buf, "bad\377end");
  assert_int_equal((int)strlen("bad") + 3 + (int)strlen("end"),
                   string_sanitize_utf8(buf));
  assert_string_equal(buf, "bad\357\277\275end");

  /* Valid multibyte text survives untouched alongside a bad byte:
   * "caf" (3) + U+00E9 (2) + U+FFFD for the 0x80 (3) + "!" (1) = 9. */
  strcpy(buf, "caf\303\251\200!");
  assert_int_equal(9, string_sanitize_utf8(buf));
  assert_string_equal(buf, "caf\303\251\357\277\275!");
}

static void test_utf8_sanitize_keeps_formatted_line_intact(void **state)
{
  /* The WebSocket text-frame path (s_bsd.c) validates and then sanitizes:
   * a formatted line must come out of both steps byte-for-byte unchanged. */
  char buf[BUFSIZE];
  (void)state;

  strcpy(buf, "\002Rubin\002: Pong!");
  assert_int_equal(1, string_is_valid_utf8(buf));
  assert_int_equal(-1, string_sanitize_utf8(buf));
  assert_string_equal(buf, "\002Rubin\002: Pong!");
}


static void test_utf8_sanitize_returns_minus_one_past_its_window(void **state)
{
  /* string_sanitize_utf8() only scans until its output buffer is nearly
   * full (BUFSIZE), while string_is_valid_utf8() scans the whole string.
   * A long line whose only bad byte sits past that window is therefore
   * "invalid" but sanitizes to -1 == "nothing modified".  s_bsd.c used to
   * assign that straight into the WebSocket frame length, i.e. memcpy() of
   * SIZE_MAX bytes; pin the contract here so it stays visible. */
  char buf[BUFSIZE * 4];
  size_t i;
  (void)state;

  for (i = 0; i < BUFSIZE + 100; i++)
    buf[i] = 'x';
  buf[i++] = (char)0xFF;      /* the one malformed byte, past the window */
  buf[i] = '\0';

  assert_int_equal(0, string_is_valid_utf8(buf));
  assert_int_equal(-1, string_sanitize_utf8(buf));
  assert_int_equal(BUFSIZE + 101, (int)strlen(buf));  /* left untouched */
}

static void test_utf8_sanitize_truncates_at_a_sequence_boundary(void **state)
{
  /* A bad byte inside the window is replaced, and the result is clamped to
   * the working buffer without splitting a multibyte sequence. */
  char buf[BUFSIZE * 4];
  size_t i;
  int n;
  (void)state;

  buf[0] = (char)0x80;        /* lone continuation, inside the window */
  for (i = 1; i < BUFSIZE * 2; i++)
    buf[i] = 'z';
  buf[i] = '\0';

  n = string_sanitize_utf8(buf);
  assert_true(n > 0);
  assert_true(n < BUFSIZE);
  assert_int_equal(n, (int)strlen(buf));
  assert_int_equal(1, string_is_valid_utf8(buf));
}

/* string_is_valid_utf8_len() checks exactly 'len' bytes, a U+0000 among
 * them: a WebSocket TEXT payload or a Close reason is counted bytes, not
 * a C string.  Checked as a C string, everything after the NUL went
 * unseen (RFC 6455 §8.1 asks about the whole message). */
static void test_utf8_valid_len_runs_past_nul(void **state)
{
  (void)state;
  assert_int_equal(1, string_is_valid_utf8_len("ok\0fine", 7));
  assert_int_equal(1, string_is_valid_utf8_len("\0", 1));
  assert_int_equal(1, string_is_valid_utf8_len("caf\303\251\0\342\202\254", 10));
  assert_int_equal(0, string_is_valid_utf8_len("ok\0\377", 4));         /* bad byte past the NUL */
  assert_int_equal(0, string_is_valid_utf8_len("ok\0\303", 4));         /* truncated past the NUL */
  assert_int_equal(0, string_is_valid_utf8_len("\0\0\355\240\200", 5)); /* surrogate past NULs */
  assert_int_equal(0, string_is_valid_utf8_len("\0\360\200\200\200", 5)); /* overlong 4-byte past a NUL */
}

/* ...and no byte past 'len': a sequence the length cuts is invalid even
 * when the bytes after it would complete it. */
static void test_utf8_valid_len_stops_at_len(void **state)
{
  (void)state;
  assert_int_equal(1, string_is_valid_utf8_len("", 0));
  assert_int_equal(1, string_is_valid_utf8_len("\377", 0));               /* nothing to check */
  assert_int_equal(1, string_is_valid_utf8_len("ab\377", 2));
  assert_int_equal(0, string_is_valid_utf8_len("\342\202\254", 2));      /* U+20AC cut short */
  assert_int_equal(0, string_is_valid_utf8_len("\360\237\222\251", 3)); /* U+1F4A9 cut short */
  assert_int_equal(0, string_is_valid_utf8_len("x\303\251", 2));          /* U+00E9 cut short */
  assert_int_equal(1, string_is_valid_utf8_len("\360\237\222\251", 4));

  /* On the heap with no byte to spare, a read past the end is valgrind's */
  {
    static const unsigned char cut[] = { 'o', 'k', 0x00, 0xF0, 0x9F, 0x92 };
    unsigned char *heap = malloc(sizeof(cut));
    size_t n;

    assert_non_null(heap);
    memcpy(heap, cut, sizeof(cut));
    for (n = 0; n <= sizeof(cut); n++)
      assert_int_equal(n <= 3, string_is_valid_utf8_len((char *)heap, n));
    free(heap);
  }
}



/* ---- msgid intrinsic time decode (2026-09 repack) ---- */

static const char *msgid_test_alphabet =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789[]";

static void msgid_encode7(char *out, unsigned long long ms)
{
  int i;
  for (i = 6; i >= 0; i--) {
    out[i] = msgid_test_alphabet[ms & 63];
    ms >>= 6;
  }
  out[7] = '\0';
}

static void test_msgid_decode_roundtrip(void **state)
{
  char id[16];
  char t7[8];
  unsigned long long samples[] = {
    1577836800000ULL,          /* 2020-01-01 floor */
    1788112345678ULL,          /* ~now */
    4102444799999ULL,          /* just under the 2100 ceiling */
  };
  size_t i;
  (void)state;

  for (i = 0; i < sizeof(samples)/sizeof(samples[0]); i++) {
    msgid_encode7(t7, samples[i]);
    snprintf(id, sizeof(id), "Bj" "AAB" "%s" "Ac", t7);
    assert_int_equal((unsigned long long)msgid_decode_time_ms(id), samples[i]);
  }
}

static void test_msgid_decode_rejects(void **state)
{
  (void)state;
  /* Legacy layout: counter high padding decodes to ~0 -> rejected. */
  assert_int_equal(msgid_decode_time_ms("BjAABAAAAAAAAB"), 0);
  /* Garbage char in the time field. */
  assert_int_equal(msgid_decode_time_ms("BjAAB!!!!!!!Ac"), 0);
  /* Too short. */
  assert_int_equal(msgid_decode_time_ms("BjAAB"), 0);
  assert_int_equal(msgid_decode_time_ms(NULL), 0);
  /* Below the 2020 floor (counter-era values). */
  {
    char id[16], t7[8];
    msgid_encode7(t7, 123456ULL);
    snprintf(id, sizeof(id), "BjAAB%sAc", t7);
    assert_int_equal(msgid_decode_time_ms(id), 0);
  }
}

int main(void)
{
    const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_msgid_decode_roundtrip),
    cmocka_unit_test(test_msgid_decode_rejects),
        /* ircd_strncpy */
        cmocka_unit_test(test_ircd_strncpy_normal),
        cmocka_unit_test(test_ircd_strncpy_truncation),
        cmocka_unit_test(test_ircd_strncpy_empty),

        /* ircd_strcmp */
        cmocka_unit_test(test_ircd_strcmp_equal),
        cmocka_unit_test(test_ircd_strcmp_not_equal),
        cmocka_unit_test(test_ircd_strcmp_irc_special_chars),

        /* ircd_strncmp */
        cmocka_unit_test(test_ircd_strncmp_basic),

        /* unique_name_vector */
        cmocka_unit_test(test_unique_name_vector_basic),
        cmocka_unit_test(test_unique_name_vector_duplicates),
        cmocka_unit_test(test_unique_name_vector_empty_elements),
        cmocka_unit_test(test_unique_name_vector_single),
        cmocka_unit_test(test_unique_name_vector_empty),
        cmocka_unit_test(test_unique_name_vector_limit),

        /* token_vector */
        cmocka_unit_test(test_token_vector_basic),

        /* EmptyString */
        cmocka_unit_test(test_EmptyString_macro),

        /* Wildcard detection */
        cmocka_unit_test(test_string_has_wildcards),

        /* Interval parsing */
        cmocka_unit_test(test_ParseInterval_seconds),
        cmocka_unit_test(test_ParseInterval_with_units),
        cmocka_unit_test(test_ParseInterval_combined),

        /* Timestamp validation */
        cmocka_unit_test(test_is_timestamp),

        /* Username/hostname validation */
        cmocka_unit_test(test_valid_username),
        cmocka_unit_test(test_valid_hostname),
        cmocka_unit_test(test_valid_spoofhost),

        /* str_appendf */
        cmocka_unit_test(test_str_appendf_basic),
        cmocka_unit_test(test_str_appendf_clamps_at_buffer_end),
        cmocka_unit_test(test_str_appendf_noop_when_pos_at_end),
        cmocka_unit_test(test_str_appendf_guard_pos_at_or_past_buflen),

        /* csv_contains_token */
        cmocka_unit_test(test_csv_contains_token_empty_denies),
        cmocka_unit_test(test_csv_contains_token_match_and_case),

        /* ircd_clienttagdeny_match */
        cmocka_unit_test(test_ctd_spec_form_denies),
        cmocka_unit_test(test_ctd_plus_form_denies_same),
        cmocka_unit_test(test_ctd_star_denies_all),
        cmocka_unit_test(test_ctd_star_with_negation_exempts_one),
        cmocka_unit_test(test_ctd_negated_plus_form_equivalent),
        cmocka_unit_test(test_ctd_prefix_wildcard_positive),
        cmocka_unit_test(test_ctd_prefix_wildcard_negated_exempts_subtree),
        cmocka_unit_test(test_ctd_exemption_wins_over_denial),
        cmocka_unit_test(test_ctd_spaces_and_empty_entries_ignored),
        cmocka_unit_test(test_ctd_tag_without_plus_never_denied),
        cmocka_unit_test(test_ctd_empty_or_null_list_denies_nothing),
        cmocka_unit_test(test_ctd_value_bearing_tag_matches_by_name),
        cmocka_unit_test(test_ctd_old_matcher_missed_spec_form),

        /* ircd_reserved_vendor_tag */
        cmocka_unit_test(test_rvt_reserved_names_bare),
        cmocka_unit_test(test_rvt_reserved_names_with_value),
        cmocka_unit_test(test_rvt_afternet_namespace_reserved_whole),
        cmocka_unit_test(test_rvt_other_evilnet_names_pass_through),
        cmocka_unit_test(test_rvt_name_boundary_not_a_byte_prefix),
        cmocka_unit_test(test_rvt_evilnet_empty_name_not_reserved),
        cmocka_unit_test(test_rvt_unrelated_tag_not_reserved),
        cmocka_unit_test(test_rvt_lookalike_shorter_than_prefix),

        /* ircd_utf8_clamp */
        cmocka_unit_test(test_utf8_clamp_fits_untouched),
        cmocka_unit_test(test_utf8_clamp_ascii_cut),
        cmocka_unit_test(test_utf8_clamp_multibyte_boundary),
        cmocka_unit_test(test_utf8_clamp_keeps_complete_sequence),
        cmocka_unit_test(test_utf8_clamp_null_safe),

        /* ircd_line_body_clamp */
        cmocka_unit_test(test_line_body_clamp_tagged),
        cmocka_unit_test(test_line_body_clamp_untagged),
        cmocka_unit_test(test_line_body_clamp_fits),
        cmocka_unit_test(test_line_body_clamp_utf8),
        cmocka_unit_test(test_line_body_clamp_tag_no_space),
        cmocka_unit_test(test_line_body_clamp_tagged_512_cap),
        cmocka_unit_test(test_line_body_clamp_latin1_run),
        cmocka_unit_test(test_line_body_clamp_utf8_4byte),
        cmocka_unit_test(test_line_body_clamp_stray_continuation),

        /* ircd_text_mentions */
        cmocka_unit_test(test_mentions_basic_and_case),
        cmocka_unit_test(test_mentions_boundaries),
        cmocka_unit_test(test_mentions_substring_rejected),
        cmocka_unit_test(test_mentions_null_safe),

        /* ircd_json_escape */
        cmocka_unit_test(test_json_escape_passthrough),
        cmocka_unit_test(test_json_escape_specials),
        cmocka_unit_test(test_json_escape_truncates_cleanly),

        /* string_is_valid_utf8 / string_sanitize_utf8 */
        cmocka_unit_test(test_utf8_valid_plain_ascii),
        cmocka_unit_test(test_utf8_valid_control_characters),
        cmocka_unit_test(test_utf8_valid_multibyte),
        cmocka_unit_test(test_utf8_invalid_sequences),
        cmocka_unit_test(test_utf8_sanitize_leaves_control_codes_alone),
        cmocka_unit_test(test_utf8_sanitize_replaces_invalid_bytes),
        cmocka_unit_test(test_utf8_sanitize_keeps_formatted_line_intact),
        cmocka_unit_test(test_utf8_sanitize_returns_minus_one_past_its_window),
        cmocka_unit_test(test_utf8_sanitize_truncates_at_a_sequence_boundary),
        cmocka_unit_test(test_utf8_valid_len_runs_past_nul),
        cmocka_unit_test(test_utf8_valid_len_stops_at_len),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
