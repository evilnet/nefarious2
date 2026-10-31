/* history_cmocka.c - CMocka unit tests for history serialization functions
 *
 * Links the real record codec (history_record.c) -- serialize,
 * deserialize, sentinel escaping, CH W forward encode/split -- and tests
 * copies of the other pure helpers, without a database:
 * - build_key() - Key construction
 * - parse_key() - Key parsing
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
#include "history_stamp.h"

/* The real record codec: ../history_record.o */
#include "history.h"
#include "history_record.h"

/* Define constants from history.c */
#define KEY_SEP '\0'
/* The parse_key copy's own timestamp bound: its tests use ISO timestamps,
 * longer than history.h's HISTORY_TIMESTAMP_LEN (unix seconds.millis). */
#define KEY_TIMESTAMP_LEN 32

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
            if ((size_t)(sep2 - p) >= KEY_TIMESTAMP_LEN) return -1;
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
            if ((size_t)(end - p) >= KEY_TIMESTAMP_LEN) return -1;
            memcpy(timestamp, p, end - p);
            timestamp[end - p] = '\0';
        }
        if (msgid)
            msgid[0] = '\0';
    }

    return 0;
}

/* serialize/deserialize run the real codec (../history_record.o); these
 * wrappers keep the older tests' call shape. */
static int serialize_message(char *buf, int bufsize,
                             enum HistoryMessageType type,
                             const char *sender, const char *account,
                             const char *content)
{
    return history_serialize_record(buf, bufsize, type, sender, account,
                                    content, NULL, NULL, 0);
}

static int deserialize_message(const char *data, int datalen,
                               struct HistoryMessage *msg)
{
    return history_deserialize_record(data, (size_t)datalen, msg);
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

/* ========== redaction catch-up index (redact_index.c, design B) ========== */
#include "redact_index.h"

static void test_rdx_key_roundtrip_and_order(void **state)
{
  unsigned char a[RDX_KEY_MAX], b[RDX_KEY_MAX];
  uint64_t t; char m[RDX_MSGID_MAX];
  int la, lb;
  (void)state;
  la = rdx_key_build(a, sizeof a, 1789962797402ULL, "AIAAAaDCGMFaNc");
  lb = rdx_key_build(b, sizeof b, 1789962797403ULL, "AAAAAaDCGMFaNa");
  assert_true(la > 8 && lb > 8);
  /* later time sorts after, whatever the msgid bytes */
  assert_true(memcmp(a, b, 8) < 0);
  assert_int_equal(0, rdx_key_parse(a, (size_t)la, &t, m, sizeof m));
  assert_true(t == 1789962797402ULL);
  assert_string_equal(m, "AIAAAaDCGMFaNc");
  assert_int_equal(-1, rdx_key_build(a, sizeof a, 1, ""));
  assert_int_equal(-1, rdx_key_parse(a, 8, &t, m, sizeof m));
}

static void test_rdx_val_roundtrip(void **state)
{
  struct rdx_val v, o;
  char buf[RDX_VAL_MAX];
  int l;
  (void)state;
  memset(&v, 0, sizeof v);
  strcpy(v.target, "#chan"); strcpy(v.parent_msgid, "ADAAAaDCF3KvTd");
  strcpy(v.sender, "bob!b@h.example"); strcpy(v.account, "bob"); strcpy(v.reason, "gate reason");
  l = rdx_val_pack(buf, sizeof buf, &v);
  assert_true(l > 0);
  assert_int_equal(0, rdx_val_parse(buf, (size_t)l, &o));
  assert_string_equal(o.target, "#chan"); assert_string_equal(o.parent_msgid, "ADAAAaDCF3KvTd");
  assert_string_equal(o.sender, "bob!b@h.example"); assert_string_equal(o.account, "bob");
  assert_string_equal(o.reason, "gate reason");
  /* empty account + empty reason survive */
  v.account[0] = '\0'; v.reason[0] = '\0';
  l = rdx_val_pack(buf, sizeof buf, &v);
  assert_true(l > 0);
  assert_int_equal(0, rdx_val_parse(buf, (size_t)l, &o));
  assert_string_equal(o.account, ""); assert_string_equal(o.reason, "");
  /* a value without the four separators is malformed */
  assert_int_equal(-1, rdx_val_parse("#chan", 5, &o));
}

static void test_rdx_reply_parse(void **state)
{
  char *pv[10] = { "CH", "D", "AD7", "1789962797402", "AIAAAaDCGMFaNc", "#chan",
                   "AIAAAaDCGKw4Nb", "bob!b@h", "*", "gate reason" };
  struct rdx_reply r;
  (void)state;
  assert_int_equal(0, rdx_reply_parse(10, pv, &r));
  assert_string_equal(r.reqid, "AD7");
  assert_true(r.time_ms == 1789962797402ULL);
  assert_string_equal(r.redact_msgid, "AIAAAaDCGMFaNc");
  assert_string_equal(r.v.target, "#chan");
  assert_string_equal(r.v.parent_msgid, "AIAAAaDCGKw4Nb");
  assert_string_equal(r.v.account, "");          /* "*" = none */
  assert_string_equal(r.v.reason, "gate reason");
  assert_int_equal(0, rdx_reply_parse(9, pv, &r));   /* no reason param */
  assert_string_equal(r.v.reason, "");
  assert_int_equal(-1, rdx_reply_parse(8, pv, &r));  /* short */
  pv[3] = "0";
  assert_int_equal(-1, rdx_reply_parse(10, pv, &r)); /* no time */
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

/* ========== #103 sentinel-escape helpers (../history_record.o) ========== */
#define HIST_ESC 0x04

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

/* ========== '|' in the header fields (parsers fuzz F14) ========== */

/* Store a full record through the real codec and read it back. */
static void record_roundtrip(const char *sender, const char *account,
                             const char *content, struct HistoryMessage *msg)
{
  char buf[HISTORY_VALUE_BUFSIZE];
  int len;

  len = history_serialize_record(buf, sizeof(buf), HISTORY_PRIVMSG, sender,
                                 account, content, NULL, NULL, 0);
  assert_true(len > 0 && len < (int)sizeof(buf));
  memset(msg, 0, sizeof(*msg));
  assert_int_equal(0, history_deserialize_record(buf, (size_t)len, msg));
}

static void test_record_pipe_nick_roundtrip(void **state)
{
  struct HistoryMessage msg;
  (void)state;
  /* '|' is a nick character ({|}~ are lowercase letters in ircd_chattr). */
  record_roundtrip("foo|away!user@host.example", "foo", "back soon", &msg);
  assert_string_equal(msg.sender, "foo|away!user@host.example");
  assert_string_equal(msg.account, "foo");
  assert_string_equal(msg.content, "back soon");
}

static void test_record_pipe_nick_account_spoof(void **state)
{
  struct HistoryMessage msg;
  (void)state;
  /* The F14 reproducer: nick "a|admin|b" logged in as "realacct".  The
   * record must not replay as sender "a" with account=admin. */
  record_roundtrip("a|admin|b!user@host", "realacct", "spoof?", &msg);
  assert_string_equal(msg.sender, "a|admin|b!user@host");
  assert_string_equal(msg.account, "realacct");
  assert_string_equal(msg.content, "spoof?");
}

static void test_record_pipe_in_account(void **state)
{
  struct HistoryMessage msg;
  (void)state;
  record_roundtrip("nick!user@host", "a|b", "text", &msg);
  assert_string_equal(msg.sender, "nick!user@host");
  assert_string_equal(msg.account, "a|b");
  assert_string_equal(msg.content, "text");
}

static void test_record_longest_pipe_sender(void **state)
{
  char sender[HISTORY_SENDER_LEN];
  char *p = sender;
  struct HistoryMessage msg;
  (void)state;
  /* A NICKLEN nick of all '|' plus the longest user and host: the
   * longest legal sender, which escapes to more than HISTORY_SENDER_LEN
   * bytes on disk and must still decode. */
  memset(p, '|', NICKLEN); p += NICKLEN;
  *p++ = '!';
  memset(p, 'u', USERLEN); p += USERLEN;
  *p++ = '@';
  memset(p, 'h', HOSTLEN); p += HOSTLEN;
  *p = '\0';
  assert_int_equal(strlen(sender), HISTORY_SENDER_LEN - 1);
  record_roundtrip(sender, "acct", "x", &msg);
  assert_string_equal(msg.sender, sender);
  assert_string_equal(msg.account, "acct");
  assert_string_equal(msg.content, "x");
}

static void test_record_ordinary_bytes_unchanged(void **state)
{
  char buf[HISTORY_VALUE_BUFSIZE];
  int len;
  (void)state;
  /* A sender without '|' serializes exactly as before, and '|' in the
   * content (the last field) stays raw. */
  len = history_serialize_record(buf, sizeof(buf), HISTORY_PRIVMSG,
                                 "nick!user@host", "acct", "a|b|c",
                                 NULL, NULL, 0);
  assert_int_equal(len, (int)strlen("0|nick!user@host|acct|a|b|c"));
  assert_string_equal(buf, "0|nick!user@host|acct|a|b|c");
}

static void test_unescape_header_span(void **state)
{
  static const char stored[] = "2|a\004<b!u@h|acct|";
  char out[16];
  (void)state;
  /* The JOIN-row scan decodes the raw sender span between the first two
   * '|' with this; the escaped '|' comes back. */
  assert_int_equal(7, history_unescape_header(out, sizeof(out), stored + 2, 8));
  assert_string_equal(out, "a|b!u@h");
  /* Legacy span, no escapes: copied unchanged. */
  assert_int_equal(5, history_unescape_header(out, sizeof(out), "n!u@h", 5));
  assert_string_equal(out, "n!u@h");
  /* Too long for dst after unescaping: refused, not truncated. */
  assert_int_equal(-1, history_unescape_header(out, 5, "n!u@h", 5));
  assert_int_equal(4, history_unescape_header(out, 5, "a\004<b!", 5));
  assert_string_equal(out, "a|b!");
}

static void test_record_legacy_decode(void **state)
{
  static const char plain[] = "0|nick!user@host|acct|hello|world";
  static const char pipe_nick[] = "1|a|admin|b!user@host|realacct|spoof?";
  struct HistoryMessage msg;
  (void)state;
  /* Records written before '|' was escaped decode as they always did. */
  memset(&msg, 0, sizeof(msg));
  assert_int_equal(0, history_deserialize_record(plain, strlen(plain), &msg));
  assert_int_equal(msg.type, HISTORY_PRIVMSG);
  assert_string_equal(msg.sender, "nick!user@host");
  assert_string_equal(msg.account, "acct");
  assert_string_equal(msg.content, "hello|world");
  /* A legacy row from a '|' nick was split wrongly when it was written;
   * nothing in it marks where the nick ended, so it reads back exactly
   * as it did before. */
  memset(&msg, 0, sizeof(msg));
  assert_int_equal(0, history_deserialize_record(pipe_nick, strlen(pipe_nick), &msg));
  assert_int_equal(msg.type, HISTORY_NOTICE);
  assert_string_equal(msg.sender, "a");
  assert_string_equal(msg.account, "admin");
  assert_string_equal(msg.content, "b!user@host|realacct|spoof?");
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

/* TARGETS index max() rule (history_stamp_newer): a row stored late with
 * an older stamp must not move a target's latest time backwards. */
static void test_stamp_newer_orders_by_time(void **state)
{
  (void)state;
  assert_true(history_stamp_newer("1792600200.500", 14, "1792600200.499", 14));
  assert_false(history_stamp_newer("1792600200.499", 14, "1792600200.500", 14));
  assert_false(history_stamp_newer("1792600200.500", 14, "1792600200.500", 14));
}

static void test_stamp_newer_late_older_row_loses(void **state)
{
  (void)state;
  /* the newest message is held; a multiline batch stamped a second earlier
   * arrives afterwards over S2S */
  assert_false(history_stamp_newer("1792600199.900", 14, "1792600200.100", 14));
}

static void test_stamp_newer_longer_seconds_wins(void **state)
{
  (void)state;
  assert_true(history_stamp_newer("10000000000.000", 15, "9999999999.999", 14) ||
              history_stamp_newer("10000000000.000", 15, "1000000000.000", 14));
  assert_true(history_stamp_newer("1792600200.5001", 15, "1792600200.500", 14));
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        /* build_key tests */
        cmocka_unit_test(test_rdx_key_roundtrip_and_order),
    cmocka_unit_test(test_rdx_val_roundtrip),
    cmocka_unit_test(test_rdx_reply_parse),
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
        cmocka_unit_test(test_record_pipe_nick_roundtrip),
        cmocka_unit_test(test_record_pipe_nick_account_spoof),
        cmocka_unit_test(test_record_pipe_in_account),
        cmocka_unit_test(test_record_longest_pipe_sender),
        cmocka_unit_test(test_record_ordinary_bytes_unchanged),
        cmocka_unit_test(test_unescape_header_span),
        cmocka_unit_test(test_record_legacy_decode),
        cmocka_unit_test(test_forward_encode_split_roundtrip),
        cmocka_unit_test(test_forward_encode_blocks_injection),
        cmocka_unit_test(test_stamp_newer_orders_by_time),
        cmocka_unit_test(test_stamp_newer_late_older_row_loses),
        cmocka_unit_test(test_stamp_newer_longer_seconds_wins),
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
