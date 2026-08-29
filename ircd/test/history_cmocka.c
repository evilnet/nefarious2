/* history_cmocka.c - CMocka unit tests for history serialization functions
 *
 * Tests the pure functions from history.c without requiring LMDB:
 * - build_key() - Key construction
 * - parse_key() - Key parsing
 * - serialize_message() - Message serialization
 * - deserialize_message() - Message deserialization
 * - parse_reference() - Reference string parsing (from m_chathistory.c)
 */

#include "config.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <cmocka.h>

/* Include necessary headers */
#include "ircd_defs.h"
#include "ircd_chattr.h"

/* Define constants from history.c */
#define KEY_SEP '\0'
/* HISTORY_VALUE_BUFSIZE now defined in history.h */

#define HISTORY_MSGID_LEN 64
#define HISTORY_TIMESTAMP_LEN 32
#define HISTORY_SENDER_LEN (NICKLEN + USERLEN + HOSTLEN + 3)
#define HISTORY_CONTENT_LEN 4096

/* Message types from history.h */
enum HistoryMessageType {
    HISTORY_PRIVMSG = 0,
    HISTORY_NOTICE  = 1,
    HISTORY_JOIN    = 2,
    HISTORY_PART    = 3,
    HISTORY_QUIT    = 4,
    HISTORY_KICK    = 5,
    HISTORY_MODE    = 6,
    HISTORY_TOPIC   = 7,
    HISTORY_TAGMSG  = 8,
    HISTORY_GAP     = 9,
    HISTORY_NICK    = 10,
    HISTORY_REDACT  = 11,
    HISTORY_MULTILINE = 12
};

/* Reference types from history.h */
enum HistoryRefType {
    HISTORY_REF_TIMESTAMP = 0,
    HISTORY_REF_MSGID     = 1,
    HISTORY_REF_NONE      = 2
};

/* HistoryMessage structure from history.h */
struct HistoryMessage {
    char msgid[HISTORY_MSGID_LEN];
    char timestamp[HISTORY_TIMESTAMP_LEN];
    char target[CHANNELLEN + 1];
    char sender[HISTORY_SENDER_LEN];
    char account[ACCOUNTLEN + 1];
    enum HistoryMessageType type;
    char content[HISTORY_CONTENT_LEN];
    struct HistoryMessage *next;
};

/* Stub for ircd_snprintf - use regular snprintf */
#define ircd_snprintf(client, buf, size, fmt, ...) snprintf(buf, size, fmt, ##__VA_ARGS__)

/* ========== Inlined functions from history.c ========== */

static int build_key(char *key, int keysize, const char *target,
                     const char *timestamp, const char *msgid)
{
    int pos = 0;
    int len;

    /* Copy target */
    len = strlen(target);
    if (pos + len + 1 >= keysize) return -1;
    memcpy(key + pos, target, len);
    pos += len;
    key[pos++] = KEY_SEP;

    /* Copy timestamp if provided */
    if (timestamp) {
        len = strlen(timestamp);
        if (pos + len + 1 >= keysize) return -1;
        memcpy(key + pos, timestamp, len);
        pos += len;
        key[pos++] = KEY_SEP;

        /* Copy msgid if provided */
        if (msgid) {
            len = strlen(msgid);
            if (pos + len >= keysize) return -1;
            memcpy(key + pos, msgid, len);
            pos += len;
        }
    }

    return pos;
}

static int parse_key(const char *key, int keylen,
                     char *target, char *timestamp, char *msgid)
{
    const char *p, *end;
    const char *sep1, *sep2;

    p = key;
    end = key + keylen;

    /* Find first separator (end of target) */
    sep1 = memchr(p, KEY_SEP, end - p);
    if (!sep1) return -1;

    if (target) {
        if ((size_t)(sep1 - p) > CHANNELLEN) return -1;
        memcpy(target, p, sep1 - p);
        target[sep1 - p] = '\0';
    }
    p = sep1 + 1;

    /* Find second separator (end of timestamp) */
    sep2 = memchr(p, KEY_SEP, end - p);
    if (sep2) {
        if (timestamp) {
            if ((size_t)(sep2 - p) >= HISTORY_TIMESTAMP_LEN) return -1;
            memcpy(timestamp, p, sep2 - p);
            timestamp[sep2 - p] = '\0';
        }
        p = sep2 + 1;

        if (msgid) {
            if ((size_t)(end - p) >= HISTORY_MSGID_LEN) return -1;
            memcpy(msgid, p, end - p);
            msgid[end - p] = '\0';
        }
    } else {
        /* No msgid in key */
        if (timestamp) {
            if ((size_t)(end - p) >= HISTORY_TIMESTAMP_LEN) return -1;
            memcpy(timestamp, p, end - p);
            timestamp[end - p] = '\0';
        }
        if (msgid)
            msgid[0] = '\0';
    }

    return 0;
}

static int serialize_message(char *buf, int bufsize,
                             enum HistoryMessageType type,
                             const char *sender, const char *account,
                             const char *content)
{
    return ircd_snprintf(0, buf, bufsize, "%d|%s|%s|%s",
                         (int)type,
                         sender ? sender : "",
                         account ? account : "",
                         content ? content : "");
}

static int deserialize_message(const char *data, int datalen,
                               struct HistoryMessage *msg)
{
    const char *p, *end;
    char *field;
    int type;

    p = data;
    end = data + datalen;

    /* Parse type */
    field = strchr(p, '|');
    if (!field || field >= end) return -1;
    type = atoi(p);
    if (type < 0 || type > HISTORY_MULTILINE) return -1;
    msg->type = (enum HistoryMessageType)type;
    p = field + 1;

    /* Parse sender */
    field = strchr(p, '|');
    if (!field || field >= end) return -1;
    if ((size_t)(field - p) >= sizeof(msg->sender)) return -1;
    memcpy(msg->sender, p, field - p);
    msg->sender[field - p] = '\0';
    p = field + 1;

    /* Parse account */
    field = strchr(p, '|');
    if (!field || field >= end) return -1;
    if ((size_t)(field - p) >= sizeof(msg->account)) return -1;
    memcpy(msg->account, p, field - p);
    msg->account[field - p] = '\0';
    p = field + 1;

    /* Parse content - rest of string */
    if ((size_t)(end - p) >= sizeof(msg->content)) return -1;
    memcpy(msg->content, p, end - p);
    msg->content[end - p] = '\0';

    return 0;
}

/* parse_reference from m_chathistory.c */
static int parse_reference(const char *ref, enum HistoryRefType *ref_type, const char **value)
{
    if (!ref || !*ref)
        return -1;

    if (*ref == '*') {
        *ref_type = HISTORY_REF_NONE;
        *value = ref;
        return 0;
    }

    if (strncmp(ref, "timestamp=", 10) == 0) {
        *ref_type = HISTORY_REF_TIMESTAMP;
        *value = ref + 10;
        return 0;
    }

    if (strncmp(ref, "msgid=", 6) == 0) {
        *ref_type = HISTORY_REF_MSGID;
        *value = ref + 6;
        return 0;
    }

    return -1;
}

/* ========== build_key Tests ========== */

static void test_build_key_target_only(void **state)
{
    (void)state;
    char key[256];
    int len;

    len = build_key(key, sizeof(key), "#channel", NULL, NULL);
    assert_int_equal(len, 9); /* "#channel" + KEY_SEP */
    assert_memory_equal(key, "#channel\0", 9);
}

static void test_build_key_with_timestamp(void **state)
{
    (void)state;
    char key[256];
    int len;

    len = build_key(key, sizeof(key), "#channel", "2024-01-15T12:30:00Z", NULL);
    assert_int_equal(len, 30); /* "#channel" + SEP + "2024-01-15T12:30:00Z" + SEP */
    assert_memory_equal(key, "#channel\0" "2024-01-15T12:30:00Z\0", 30);
}

static void test_build_key_with_msgid(void **state)
{
    (void)state;
    char key[256];
    int len;

    len = build_key(key, sizeof(key), "#channel", "2024-01-15T12:30:00Z", "abc123");
    assert_int_equal(len, 36);
    assert_memory_equal(key, "#channel\0" "2024-01-15T12:30:00Z\0" "abc123", 36);
}

static void test_build_key_buffer_too_small(void **state)
{
    (void)state;
    char key[10];
    int len;

    len = build_key(key, sizeof(key), "#verylongchannelname", NULL, NULL);
    assert_int_equal(len, -1);
}

static void test_build_key_dm_target(void **state)
{
    (void)state;
    char key[256];
    int len;

    /* DM targets use "$nick1,nick2" format */
    len = build_key(key, sizeof(key), "$alice,bob", "2024-01-15T12:30:00Z", NULL);
    assert_true(len > 0);
    assert_memory_equal(key, "$alice,bob\0", 11);
}

/* ========== parse_key Tests ========== */

static void test_parse_key_target_timestamp_msgid(void **state)
{
    (void)state;
    char key[256];
    char target[64], timestamp[64], msgid[64];
    int len, rc;

    len = build_key(key, sizeof(key), "#test", "2024-01-15T12:30:00Z", "msg123");
    assert_true(len > 0);

    rc = parse_key(key, len, target, timestamp, msgid);
    assert_int_equal(rc, 0);
    assert_string_equal(target, "#test");
    assert_string_equal(timestamp, "2024-01-15T12:30:00Z");
    assert_string_equal(msgid, "msg123");
}

static void test_parse_key_target_timestamp_only(void **state)
{
    (void)state;
    char key[256];
    char target[64], timestamp[64], msgid[64];
    int len, rc;

    len = build_key(key, sizeof(key), "#test", "2024-01-15T12:30:00Z", NULL);
    assert_true(len > 0);

    rc = parse_key(key, len, target, timestamp, msgid);
    assert_int_equal(rc, 0);
    assert_string_equal(target, "#test");
    assert_string_equal(timestamp, "2024-01-15T12:30:00Z");
    assert_string_equal(msgid, "");
}

static void test_parse_key_null_outputs(void **state)
{
    (void)state;
    char key[256];
    int len, rc;

    len = build_key(key, sizeof(key), "#test", "2024-01-15T12:30:00Z", "msg123");
    assert_true(len > 0);

    /* All NULL outputs should still succeed */
    rc = parse_key(key, len, NULL, NULL, NULL);
    assert_int_equal(rc, 0);
}

static void test_parse_key_no_separator(void **state)
{
    (void)state;
    char target[64];
    int rc;

    /* Key with no separator should fail */
    rc = parse_key("noseparator", 11, target, NULL, NULL);
    assert_int_equal(rc, -1);
}

static void test_parse_key_roundtrip(void **state)
{
    (void)state;
    char key[256];
    char target[64], timestamp[64], msgid[64];
    int len, rc;

    /* Test various targets */
    const char *targets[] = {"#channel", "#foo-bar", "$nick1,nick2", "&local"};

    for (int i = 0; i < 4; i++) {
        len = build_key(key, sizeof(key), targets[i], "2024-12-25T00:00:00Z", "id456");
        assert_true(len > 0);

        rc = parse_key(key, len, target, timestamp, msgid);
        assert_int_equal(rc, 0);
        assert_string_equal(target, targets[i]);
        assert_string_equal(timestamp, "2024-12-25T00:00:00Z");
        assert_string_equal(msgid, "id456");
    }
}

/* ========== #103 sentinel-escape helpers (copied verbatim from
 * ircd/history.c -- pure logic, no deps, gated here) ========== */
#define HIST_ESC 0x04
static int history_field_needs_escape(unsigned char c)
{
  return c == HIST_ESC || c == 0x05 || c == 0x06;
}
static char *history_escape_field(char *dst, size_t dstsize, const char *src)
{
  size_t o = 0;
  const unsigned char *p;
  if (dstsize == 0)
    return dst;
  for (p = (const unsigned char *)(src ? src : ""); *p; ++p) {
    if (history_field_needs_escape(*p)) {
      if (o + 2 >= dstsize) break;
      dst[o++] = HIST_ESC;
      dst[o++] = (char)(*p ^ 0x40);
    } else {
      if (o + 1 >= dstsize) break;
      dst[o++] = (char)*p;
    }
  }
  dst[o] = '\0';
  return dst;
}
static void history_unescape_field(char *str)
{
  char *r = str, *w = str;
  while (*r) {
    if (*r == HIST_ESC && r[1]) { *w++ = (char)((unsigned char)r[1] ^ 0x40); r += 2; }
    else { *w++ = *r++; }
  }
  *w = '\0';
}
static char *history_forward_encode(char *dst, size_t dstsize,
                                    const char *client_tags, const char *text)
{
  size_t used = 0;
  if (dstsize == 0)
    return dst;
  dst[0] = '\0';
  if (client_tags && client_tags[0]) {
    if (dstsize < 3)
      return dst;
    dst[used++] = '\x06';
    history_escape_field(dst + used, dstsize - used - 1, client_tags);
    used += strlen(dst + used);
    dst[used++] = '\x06';
    dst[used] = '\0';
  }
  history_escape_field(dst + used, dstsize - used, text ? text : "");
  return dst;
}
static char *history_forward_split(char *content, char **tags_out)
{
  char *text = content;
  *tags_out = NULL;
  if (content[0] == '\x06') {
    char *close = strchr(content + 1, '\x06');
    if (close) {
      *close = '\0';
      *tags_out = content + 1;
      history_unescape_field(*tags_out);
      text = close + 1;
    }
  }
  history_unescape_field(text);
  return text;
}

static void test_sentinel_escape_roundtrip(void **state)
{
  char esc[128];
  (void)state;
  /* Plain text is untouched. */
  history_escape_field(esc, sizeof(esc), "hello world");
  assert_string_equal(esc, "hello world");
  history_unescape_field(esc);
  assert_string_equal(esc, "hello world");
  /* Formatting/CTCP bytes (0x02, 0x03, 0x01) are NOT escaped -- only
   * the record sentinels are -- so mIRC codes survive verbatim. */
  history_escape_field(esc, sizeof(esc), "\002bold\003 \001ACTION\001");
  assert_string_equal(esc, "\002bold\003 \001ACTION\001");
}

static void test_sentinel_escape_neutralizes_injection(void **state)
{
  char esc[128];
  (void)state;
  /* The reproduced attack: body starting with a forged \x06 tag span. */
  history_escape_field(esc, sizeof(esc), "\x06+evil/injected=owned\x06text");
  /* No raw sentinel remains, so the deserializer's leading-\x06 check
   * can never lift it into client_tags. */
  assert_null(strchr(esc, '\x06'));
  assert_null(strchr(esc, '\x05'));
  assert_true(esc[0] == HIST_ESC);
  /* Round-trip restores the exact body as literal content. */
  history_unescape_field(esc);
  assert_string_equal(esc, "\x06+evil/injected=owned\x06text");
}

static void test_sentinel_escape_of_escape_byte(void **state)
{
  char esc[64];
  (void)state;
  /* A literal 0x04 in the body must itself be escaped, else unescape
   * would misread the following byte.  "a\x04b" -> "a" ESC (0x04^0x40='D')
   * "b" = "a\x04Db"; the escaped form differs from the input, and the
   * round-trip restores it exactly. */
  history_escape_field(esc, sizeof(esc), "a\004b");
  assert_string_equal(esc, "a\004Db");
  history_unescape_field(esc);
  assert_string_equal(esc, "a\004b");
}

/* Mirror of ml_content_resolve's multiline-identification predicate
 * (ircd/ml_content.c): TYPE-keyed, with an EXACT-3-byte legacy fallback.
 * Copied here as pure logic to lock the #103-residue semantics: client
 * message bytes must never forge a multiline resolve. */
static int ml_is_multiline_ref(int type, const char *content)
{
  if (type == HISTORY_MULTILINE)
    return 1;
  if (type == HISTORY_PRIVMSG &&
      content[0] == '\x1E' && content[1] == 'm' &&
      content[2] == 'l' && content[3] == '\0')
    return 1;  /* legacy pre-type-12 placeholder */
  return 0;
}

/* Mirror of ircd.c is_reserved_vendor_tag -- pure prefix test; the real
 * one uses ircd_strncmp (case-insensitive IRC casemap), available here
 * because the suite links ../ircd_string.o. */
extern int ircd_strncmp(const char *a, const char *b, size_t n);
static int is_reserved_vendor_tag(const char *tag, size_t tag_len)
{
  static const char *prefixes[] = { "+evilnet.github.io/", "+afternet.org/" };
  size_t i;
  if (!tag)
    return 0;
  for (i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); i++) {
    size_t plen = strlen(prefixes[i]);
    if (tag_len >= plen && 0 == ircd_strncmp(tag, prefixes[i], plen))
      return 1;
  }
  return 0;
}

static void test_reserved_vendor_tag(void **state)
{
  (void)state;
  /* The org vendor namespace is reserved (case-insensitive vendor). */
  assert_true(is_reserved_vendor_tag("+evilnet.github.io/sid=abc",
                                     strlen("+evilnet.github.io/sid=abc")));
  assert_true(is_reserved_vendor_tag("+EvilNet.GitHub.IO/sid=abc",
                                     strlen("+EvilNet.GitHub.IO/sid=abc")));
  assert_true(is_reserved_vendor_tag("+evilnet.github.io/anything",
                                     strlen("+evilnet.github.io/anything")));
  /* The legacy namespace stays reserved (pre-2026-08-29 records carry
   * the sid marker there and the auth check still honors it). */
  assert_true(is_reserved_vendor_tag("+afternet.org/sid=abc",
                                     strlen("+afternet.org/sid=abc")));
  assert_true(is_reserved_vendor_tag("+AfterNet.ORG/sid=abc",
                                     strlen("+AfterNet.ORG/sid=abc")));
  /* Other client tags pass through untouched. */
  assert_false(is_reserved_vendor_tag("+reply=abc", strlen("+reply=abc")));
  assert_false(is_reserved_vendor_tag("+draft/react=x", strlen("+draft/react=x")));
  assert_false(is_reserved_vendor_tag("+example.com/afternet.org",
                                      strlen("+example.com/afternet.org")));
  /* A lookalike shorter than the prefix cannot match. */
  assert_false(is_reserved_vendor_tag("+afternet.org", strlen("+afternet.org")));
  assert_false(is_reserved_vendor_tag("+evilnet.github.io",
                                      strlen("+evilnet.github.io")));
  assert_false(is_reserved_vendor_tag(NULL, 0));
}

static void test_multiline_ref_is_type_keyed(void **state)
{
  (void)state;
  /* Genuine placeholder: type-12, resolves regardless of content. */
  assert_true(ml_is_multiline_ref(HISTORY_MULTILINE, "\x1Eml"));
  assert_true(ml_is_multiline_ref(HISTORY_MULTILINE, "anything"));
  /* Legacy placeholder: PRIVMSG whose entire body is the 3-byte sentinel. */
  assert_true(ml_is_multiline_ref(HISTORY_PRIVMSG, "\x1Eml"));
  /* #103 residue closed: a client PRIVMSG that merely STARTS with the
   * sentinel (or embeds \x1F) is NOT multiline -- renders as literal. */
  assert_false(ml_is_multiline_ref(HISTORY_PRIVMSG, "\x1Emlctrl-injected"));
  assert_false(ml_is_multiline_ref(HISTORY_PRIVMSG, "line1\x1Fline2"));
  assert_false(ml_is_multiline_ref(HISTORY_PRIVMSG, "\x1E"));
  assert_false(ml_is_multiline_ref(HISTORY_NOTICE, "\x1Eml"));
}

static void test_forward_encode_split_roundtrip(void **state)
{
  char wire[512];
  char *tags = (char *)1;
  char *text;
  (void)state;
  /* Benign tags+text: escape is identity, wire format unchanged from
   * the pre-escape encoding, split recovers both halves exactly. */
  history_forward_encode(wire, sizeof(wire), "+draft/react=x;+reply=abc", "hello");
  assert_string_equal(wire, "\006+draft/react=x;+reply=abc\006hello");
  text = history_forward_split(wire, &tags);
  assert_non_null(tags);
  assert_string_equal(tags, "+draft/react=x;+reply=abc");
  assert_string_equal(text, "hello");
  /* Tags-only (TAGMSG) form. */
  history_forward_encode(wire, sizeof(wire), "+typing=active", "");
  text = history_forward_split(wire, &tags);
  assert_non_null(tags);
  assert_string_equal(tags, "+typing=active");
  assert_string_equal(text, "");
  /* No tags: no bracket. */
  history_forward_encode(wire, sizeof(wire), NULL, "plain");
  assert_string_equal(wire, "plain");
  text = history_forward_split(wire, &tags);
  assert_null(tags);
  assert_string_equal(text, "plain");
}

static void test_forward_encode_blocks_injection(void **state)
{
  char wire[512];
  char *tags = (char *)1;
  char *text;
  (void)state;
  /* The federation-side #103 variant: no real tags, client text opens
   * with a forged \x06 span.  Pre-escape this went raw onto the wire
   * and the storage server lifted it as tags; now the composer escapes
   * it, so split finds no bracket and the text survives as literals. */
  history_forward_encode(wire, sizeof(wire), NULL,
                         "\006+evil/injected=owned\006hi");
  assert_true(wire[0] != '\006');
  text = history_forward_split(wire, &tags);
  assert_null(tags);
  assert_string_equal(text, "\006+evil/injected=owned\006hi");
  /* Sentinel bytes inside genuinely-tagged text round-trip too. */
  history_forward_encode(wire, sizeof(wire), "+reply=abc",
                         "body\005with\006bytes\004too");
  text = history_forward_split(wire, &tags);
  assert_non_null(tags);
  assert_string_equal(tags, "+reply=abc");
  assert_string_equal(text, "body\005with\006bytes\004too");
}

/* ========== serialize_message Tests ========== */

static void test_serialize_privmsg(void **state)
{
    (void)state;
    char buf[512];
    int len;

    len = serialize_message(buf, sizeof(buf), HISTORY_PRIVMSG,
                            "nick!user@host", "account", "Hello world");
    assert_true(len > 0);
    assert_string_equal(buf, "0|nick!user@host|account|Hello world");
}

static void test_serialize_notice(void **state)
{
    (void)state;
    char buf[512];
    int len;

    len = serialize_message(buf, sizeof(buf), HISTORY_NOTICE,
                            "nick!user@host", "account", "Notice message");
    assert_true(len > 0);
    assert_string_equal(buf, "1|nick!user@host|account|Notice message");
}

static void test_serialize_join(void **state)
{
    (void)state;
    char buf[512];
    int len;

    len = serialize_message(buf, sizeof(buf), HISTORY_JOIN,
                            "nick!user@host", "account", NULL);
    assert_true(len > 0);
    assert_string_equal(buf, "2|nick!user@host|account|");
}

static void test_serialize_null_account(void **state)
{
    (void)state;
    char buf[512];
    int len;

    len = serialize_message(buf, sizeof(buf), HISTORY_PRIVMSG,
                            "nick!user@host", NULL, "Message");
    assert_true(len > 0);
    assert_string_equal(buf, "0|nick!user@host||Message");
}

static void test_serialize_empty_content(void **state)
{
    (void)state;
    char buf[512];
    int len;

    len = serialize_message(buf, sizeof(buf), HISTORY_TAGMSG,
                            "nick!user@host", "account", "");
    assert_true(len > 0);
    assert_string_equal(buf, "8|nick!user@host|account|");
}

/* ========== deserialize_message Tests ========== */

static void test_deserialize_privmsg(void **state)
{
    (void)state;
    struct HistoryMessage msg;
    const char *data = "0|nick!user@host|account|Hello world";
    int rc;

    memset(&msg, 0, sizeof(msg));
    rc = deserialize_message(data, strlen(data), &msg);
    assert_int_equal(rc, 0);
    assert_int_equal(msg.type, HISTORY_PRIVMSG);
    assert_string_equal(msg.sender, "nick!user@host");
    assert_string_equal(msg.account, "account");
    assert_string_equal(msg.content, "Hello world");
}

static void test_deserialize_join(void **state)
{
    (void)state;
    struct HistoryMessage msg;
    const char *data = "2|nick!user@host|myaccount|";
    int rc;

    memset(&msg, 0, sizeof(msg));
    rc = deserialize_message(data, strlen(data), &msg);
    assert_int_equal(rc, 0);
    assert_int_equal(msg.type, HISTORY_JOIN);
    assert_string_equal(msg.sender, "nick!user@host");
    assert_string_equal(msg.account, "myaccount");
    assert_string_equal(msg.content, "");
}

static void test_deserialize_empty_account(void **state)
{
    (void)state;
    struct HistoryMessage msg;
    const char *data = "0|nick!user@host||Some message";
    int rc;

    memset(&msg, 0, sizeof(msg));
    rc = deserialize_message(data, strlen(data), &msg);
    assert_int_equal(rc, 0);
    assert_string_equal(msg.account, "");
    assert_string_equal(msg.content, "Some message");
}

static void test_deserialize_invalid_type(void **state)
{
    (void)state;
    struct HistoryMessage msg;
    const char *data = "99|nick!user@host|account|msg";
    int rc;

    rc = deserialize_message(data, strlen(data), &msg);
    assert_int_equal(rc, -1);
}

static void test_deserialize_missing_field(void **state)
{
    (void)state;
    struct HistoryMessage msg;
    const char *data = "0|nick!user@host";  /* Missing account and content */
    int rc;

    rc = deserialize_message(data, strlen(data), &msg);
    assert_int_equal(rc, -1);
}

static void test_serialize_deserialize_roundtrip(void **state)
{
    (void)state;
    char buf[512];
    struct HistoryMessage msg;
    int len, rc;

    len = serialize_message(buf, sizeof(buf), HISTORY_PRIVMSG,
                            "test!user@example.com", "testaccount",
                            "This is a test message");
    assert_true(len > 0);

    memset(&msg, 0, sizeof(msg));
    rc = deserialize_message(buf, len, &msg);
    assert_int_equal(rc, 0);
    assert_int_equal(msg.type, HISTORY_PRIVMSG);
    assert_string_equal(msg.sender, "test!user@example.com");
    assert_string_equal(msg.account, "testaccount");
    assert_string_equal(msg.content, "This is a test message");
}

static void test_deserialize_all_message_types(void **state)
{
    (void)state;
    struct HistoryMessage msg;
    char buf[512];
    int len, rc;

    const char *type_names[] = {
        "PRIVMSG", "NOTICE", "JOIN", "PART", "QUIT",
        "KICK", "MODE", "TOPIC", "TAGMSG", "GAP",
        "NICK", "REDACT", "MULTILINE"
    };

    for (int i = 0; i <= HISTORY_MULTILINE; i++) {
        len = serialize_message(buf, sizeof(buf), (enum HistoryMessageType)i,
                                "nick!user@host", "acc", type_names[i]);
        assert_true(len > 0);

        memset(&msg, 0, sizeof(msg));
        rc = deserialize_message(buf, len, &msg);
        assert_int_equal(rc, 0);
        assert_int_equal(msg.type, i);
        assert_string_equal(msg.content, type_names[i]);
    }
}

/* ========== parse_reference Tests ========== */

static void test_parse_reference_timestamp(void **state)
{
    (void)state;
    enum HistoryRefType ref_type;
    const char *value;
    int rc;

    rc = parse_reference("timestamp=2024-01-15T12:30:00Z", &ref_type, &value);
    assert_int_equal(rc, 0);
    assert_int_equal(ref_type, HISTORY_REF_TIMESTAMP);
    assert_string_equal(value, "2024-01-15T12:30:00Z");
}

static void test_parse_reference_msgid(void **state)
{
    (void)state;
    enum HistoryRefType ref_type;
    const char *value;
    int rc;

    rc = parse_reference("msgid=abc123def456", &ref_type, &value);
    assert_int_equal(rc, 0);
    assert_int_equal(ref_type, HISTORY_REF_MSGID);
    assert_string_equal(value, "abc123def456");
}

static void test_parse_reference_star(void **state)
{
    (void)state;
    enum HistoryRefType ref_type;
    const char *value;
    int rc;

    rc = parse_reference("*", &ref_type, &value);
    assert_int_equal(rc, 0);
    assert_int_equal(ref_type, HISTORY_REF_NONE);
    assert_string_equal(value, "*");
}

static void test_parse_reference_null(void **state)
{
    (void)state;
    enum HistoryRefType ref_type;
    const char *value;
    int rc;

    rc = parse_reference(NULL, &ref_type, &value);
    assert_int_equal(rc, -1);

    rc = parse_reference("", &ref_type, &value);
    assert_int_equal(rc, -1);
}

static void test_parse_reference_invalid(void **state)
{
    (void)state;
    enum HistoryRefType ref_type;
    const char *value;
    int rc;

    rc = parse_reference("invalid=something", &ref_type, &value);
    assert_int_equal(rc, -1);

    rc = parse_reference("justtext", &ref_type, &value);
    assert_int_equal(rc, -1);
}

static void test_parse_reference_case_sensitive(void **state)
{
    (void)state;
    enum HistoryRefType ref_type;
    const char *value;
    int rc;

    /* Reference parsing is case-sensitive per IRC spec */
    rc = parse_reference("TIMESTAMP=2024-01-15T12:30:00Z", &ref_type, &value);
    assert_int_equal(rc, -1);

    rc = parse_reference("MSGID=abc123", &ref_type, &value);
    assert_int_equal(rc, -1);
}

/* ========== Main ========== */

int main(void)
{
    const struct CMUnitTest tests[] = {
        /* build_key tests */
        cmocka_unit_test(test_build_key_target_only),
        cmocka_unit_test(test_build_key_with_timestamp),
        cmocka_unit_test(test_build_key_with_msgid),
        cmocka_unit_test(test_build_key_buffer_too_small),
        cmocka_unit_test(test_build_key_dm_target),

        /* parse_key tests */
        cmocka_unit_test(test_parse_key_target_timestamp_msgid),
        cmocka_unit_test(test_parse_key_target_timestamp_only),
        cmocka_unit_test(test_parse_key_null_outputs),
        cmocka_unit_test(test_parse_key_no_separator),
        cmocka_unit_test(test_parse_key_roundtrip),

        /* serialize_message tests */
        cmocka_unit_test(test_serialize_privmsg),
        cmocka_unit_test(test_serialize_notice),
        cmocka_unit_test(test_serialize_join),
        cmocka_unit_test(test_serialize_null_account),
        cmocka_unit_test(test_serialize_empty_content),

        /* deserialize_message tests */
        cmocka_unit_test(test_deserialize_privmsg),
        cmocka_unit_test(test_deserialize_join),
        cmocka_unit_test(test_deserialize_empty_account),
        cmocka_unit_test(test_deserialize_invalid_type),
        cmocka_unit_test(test_deserialize_missing_field),
        cmocka_unit_test(test_serialize_deserialize_roundtrip),
        cmocka_unit_test(test_sentinel_escape_roundtrip),
        cmocka_unit_test(test_sentinel_escape_neutralizes_injection),
        cmocka_unit_test(test_sentinel_escape_of_escape_byte),
        cmocka_unit_test(test_forward_encode_split_roundtrip),
        cmocka_unit_test(test_forward_encode_blocks_injection),
        cmocka_unit_test(test_multiline_ref_is_type_keyed),
        cmocka_unit_test(test_reserved_vendor_tag),
        cmocka_unit_test(test_deserialize_all_message_types),

        /* parse_reference tests */
        cmocka_unit_test(test_parse_reference_timestamp),
        cmocka_unit_test(test_parse_reference_msgid),
        cmocka_unit_test(test_parse_reference_star),
        cmocka_unit_test(test_parse_reference_null),
        cmocka_unit_test(test_parse_reference_invalid),
        cmocka_unit_test(test_parse_reference_case_sensitive),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
