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
#define HISTORY_VALUE_BUFSIZE 1024

#define HISTORY_MSGID_LEN 64
#define HISTORY_TIMESTAMP_LEN 32
#define HISTORY_SENDER_LEN (NICKLEN + USERLEN + HOSTLEN + 3)
#define HISTORY_CONTENT_LEN 512

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
    HISTORY_TAGMSG  = 8
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
    if (type < 0 || type > HISTORY_TAGMSG) return -1;
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
        "KICK", "MODE", "TOPIC", "TAGMSG"
    };

    for (int i = 0; i <= HISTORY_TAGMSG; i++) {
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
