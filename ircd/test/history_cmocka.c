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

static void test_ch_e_flags(void **state)
{
  (void)state;
  assert_int_equal(0, ch_e_flags(NULL));
  assert_int_equal(0, ch_e_flags(""));
  assert_int_equal(CH_E_TRUNCATED, ch_e_flags("T"));
  assert_int_equal(CH_E_UNANSWERED, ch_e_flags("U"));
  assert_int_equal(CH_E_TRUNCATED | CH_E_UNANSWERED, ch_e_flags("TU"));
  assert_int_equal(CH_E_TRUNCATED | CH_E_UNANSWERED, ch_e_flags("UT"));
  assert_int_equal(0, ch_e_flags("x"));
}

/* CH A S <days> [<features>]: the letters a store advertises (W5 Task 14). */
static void test_ch_ad_features(void **state)
{
  (void)state;
  assert_int_equal(0, ch_ad_features(NULL));
  assert_int_equal(0, ch_ad_features(""));
  assert_int_equal(CH_AD_CHILDREN, ch_ad_features("K"));
  assert_int_equal(CH_AD_CHILDREN, ch_ad_features("xK"));
  assert_int_equal(0, ch_ad_features("x"));
}

/* The letters a CH A S relay and re-flood pass on (fix round 1): every
 * letter the store sent, known or not, so a later feature survives a hop
 * that does not know it -- [A-Za-z] only, at most CH_AD_LETTERS_MAX. */
static void test_ch_ad_letters(void **state)
{
  char out[CH_AD_LETTERS_MAX + 1];

  (void)state;
  assert_int_equal(2, ch_ad_letters("KZ", out, sizeof out));
  assert_string_equal(out, "KZ");
  assert_int_equal(CH_AD_CHILDREN, ch_ad_features(out));
  assert_int_equal(1, ch_ad_letters("Z", out, sizeof out));
  assert_string_equal(out, "Z");
  assert_int_equal(0, ch_ad_features(out));
  assert_int_equal(2, ch_ad_letters("K!z9:", out, sizeof out));
  assert_string_equal(out, "Kz");
  assert_int_equal(CH_AD_LETTERS_MAX, ch_ad_letters("ABCDEFGHIJKL", out, sizeof out));
  assert_string_equal(out, "ABCDEFGH");
  assert_int_equal(0, ch_ad_letters(NULL, out, sizeof out));
  assert_string_equal(out, "");
  assert_int_equal(0, ch_ad_letters("", out, sizeof out));
  assert_string_equal(out, "");
  assert_int_equal(1, ch_ad_letters("KZ", out, 2));
  assert_string_equal(out, "K");
}

/* W5 Task 15 fix round 1 (S2): the reply index's one-byte entry value.  A
 * REDACT link reads "R", any other child "C"; an older build's entry is
 * empty and the lookup must read the child row, as it must for any value
 * but "R" and "C". */
static void test_ri_link_kind(void **state)
{
  char v;

  (void)state;
  v = ri_link_value(1);
  assert_int_equal(v, RI_LINK_REDACT);
  assert_int_equal(ri_link_kind(&v, 1), RI_LINK_IS_REDACT);
  v = ri_link_value(0);
  assert_int_equal(v, RI_LINK_CHILD);
  assert_int_equal(ri_link_kind(&v, 1), RI_LINK_NOT_REDACT);
  assert_int_equal(ri_link_kind("", 0), RI_LINK_LEGACY);
  assert_int_equal(ri_link_kind(NULL, 0), RI_LINK_LEGACY);
  /* Only "C" is a known non-REDACT (fix round 2): any other value is read
   * as an older build's -- the row is fetched (fail closed). */
  assert_int_equal(ri_link_kind("X", 1), RI_LINK_LEGACY);
  assert_int_equal(ri_link_kind("Rx", 2), RI_LINK_LEGACY);
  assert_int_equal(ri_link_kind("Cx", 2), RI_LINK_LEGACY);
}

/* ========== applying a redaction: rdx_row_decide / rdx_watermark_decide ========== */

static void test_rdx_row_decide(void **state)
{
  (void)state;
  assert_int_equal(RDX_ROW_APPLY, rdx_row_decide(0, 0));
  assert_int_equal(RDX_ROW_SKIP_APPLIED, rdx_row_decide(0, 1));
  assert_int_equal(RDX_ROW_SKIP_ORPHAN, rdx_row_decide(1, 0));
  assert_int_equal(RDX_ROW_RETRY, rdx_row_decide(-1, 0));
  /* the redacted check could not read: never guess either way */
  assert_int_equal(RDX_ROW_RETRY, rdx_row_decide(0, -1));
  assert_int_equal(RDX_ROW_RETRY, rdx_row_decide(1, -1));
  /* a tombstone already annotates the missing message: no second one */
  assert_int_equal(RDX_ROW_SKIP_APPLIED, rdx_row_decide(1, 1));
  assert_int_equal(RDX_ROW_RETRY, rdx_row_decide(-1, 1));
}

static void test_rdx_wm_cut_keeps(void **state)
{
  uint64_t wm = 7;
  (void)state;
  assert_int_equal(RDX_WM_KEEP, rdx_watermark_decide(1, 0, 1, 8, 500, 900, &wm));
  assert_int_equal(RDX_WM_KEEP, rdx_watermark_decide(1, 1, 1, 8, 500, 900, &wm));
  assert_int_equal(RDX_WM_KEEP, rdx_watermark_decide(1, 1, 8, 8, 500, 900, &wm));
  assert_int_equal(7, wm);   /* untouched on KEEP */
}

static void test_rdx_wm_truncated_continues(void **state)
{
  uint64_t wm = 7;
  (void)state;
  assert_int_equal(RDX_WM_SET_CONTINUE, rdx_watermark_decide(0, 1, 1, 8, 500, 900, &wm));
  assert_int_equal(500, wm);
  wm = 7;
  assert_int_equal(RDX_WM_SET_CONTINUE, rdx_watermark_decide(0, 1, 7, 8, 500, 900, &wm));
  assert_int_equal(500, wm);
}

/* Review Focus 3: still truncated after the last round, the watermark stops
 * at the newest row fetched (it used to jump to the round's start, past the
 * rows it never fetched). */
static void test_rdx_wm_round_cap_keeps_last(void **state)
{
  uint64_t wm = 7;
  (void)state;
  assert_int_equal(RDX_WM_SET, rdx_watermark_decide(0, 1, 8, 8, 500, 900, &wm));
  assert_int_equal(500, wm);
  assert_int_equal(RDX_WM_SET, rdx_watermark_decide(0, 1, 8, 8, 500, 900, NULL));   /* NULL-safe */
}

static void test_rdx_wm_complete_sets_start(void **state)
{
  uint64_t wm = 7;
  (void)state;
  assert_int_equal(RDX_WM_SET, rdx_watermark_decide(0, 0, 1, 8, 500, 900, &wm));
  assert_int_equal(900, wm);
  wm = 7;   /* a complete round with no rows: nothing was missed before it */
  assert_int_equal(RDX_WM_SET, rdx_watermark_decide(0, 0, 1, 8, 0, 900, &wm));
  assert_int_equal(900, wm);
  wm = 7;   /* the last round of a continuation */
  assert_int_equal(RDX_WM_SET, rdx_watermark_decide(0, 0, 8, 8, 500, 900, &wm));
  assert_int_equal(900, wm);
}

/* W5 Push F, I-3: a catch-up round that leaves the store's REDACTs not all
 * fetched, while the store stays linked, is retried without waiting for the
 * next relink.  A failure (KEEP: a cut, an unread row, truncated with no
 * row; or a round that could not start) backs off; the last round's SET
 * with more left progressed and retries at the first interval; a continue
 * starts its next round itself; a complete round needs nothing. */
static void test_rdx_retry_decide(void **state)
{
  (void)state;
  assert_int_equal(RDX_RETRY_BACKOFF, rdx_retry_decide(RDX_WM_KEEP, 0));
  assert_int_equal(RDX_RETRY_BACKOFF, rdx_retry_decide(RDX_WM_KEEP, 1));
  assert_int_equal(RDX_RETRY_SOON, rdx_retry_decide(RDX_WM_SET, 1));
  assert_int_equal(RDX_RETRY_NONE, rdx_retry_decide(RDX_WM_SET, 0));
  assert_int_equal(RDX_RETRY_NONE, rdx_retry_decide(RDX_WM_SET_CONTINUE, 1));
}

/* The backoff: 30 s, doubling, capped at 10 min. */
static void test_rdx_retry_next_delay(void **state)
{
  (void)state;
  assert_int_equal(30, rdx_retry_next_delay(0));
  assert_int_equal(30, rdx_retry_next_delay(-5));
  assert_int_equal(60, rdx_retry_next_delay(30));
  assert_int_equal(120, rdx_retry_next_delay(60));
  assert_int_equal(480, rdx_retry_next_delay(240));
  assert_int_equal(600, rdx_retry_next_delay(480));
  assert_int_equal(600, rdx_retry_next_delay(600));
  assert_int_equal(600, rdx_retry_next_delay(1 << 30));
}

static void test_rdx_wm_truncated_no_rows_keeps(void **state)
{
  uint64_t wm = 7;
  (void)state;
  assert_int_equal(RDX_WM_KEEP, rdx_watermark_decide(0, 1, 1, 8, 0, 900, &wm));
  assert_int_equal(RDX_WM_KEEP, rdx_watermark_decide(0, 1, 8, 8, 0, 900, &wm));
  assert_int_equal(7, wm);
}

/* ========== redact_authorize (redact_index.c): the one REDACT rule ========== */

/* A plain member's request for a PRIVMSG row sent at t=1000; each case
 * overrides what it tests.  "" = none, as the struct documents. */
static struct redact_auth_in rda_base(long age)
{
  struct redact_auth_in in;
  memset(&in, 0, sizeof in);
  in.msg_type = HISTORY_PRIVMSG;
  in.msg_time = 1000;
  in.now = 1000 + age;
  in.msg_account = "";
  in.msg_sender = "s!u@h";
  in.req_account = "";
  in.req_mask = "r!u@h";
  in.window = 60;
  in.oper_window = 0;
  return in;
}

static void test_redact_auth_owner_no_window(void **state)
{
  struct redact_auth_in in = rda_base(3600);
  long w = -1;
  (void)state;
  in.msg_account = "w5a";
  in.req_account = "W5A";   /* accounts compare case-insensitively */
  assert_int_equal(REDACT_AUTH_OK, redact_authorize(&in, &w));
}

static void test_redact_auth_oper_window(void **state)
{
  struct redact_auth_in in = rda_base(601);
  long w = -1;
  (void)state;
  in.is_oper = 1;
  in.oper_window = 600;
  assert_int_equal(REDACT_AUTH_EXPIRED, redact_authorize(&in, &w));
  assert_int_equal(600, w);
  in.now = 1000 + 600;      /* at the edge: still within */
  assert_int_equal(REDACT_AUTH_OK, redact_authorize(&in, &w));
  in.oper_window = 0;       /* 0 = no oper window */
  in.now = 1000 + 1000000;
  assert_int_equal(REDACT_AUTH_OK, redact_authorize(&in, &w));
}

static void test_redact_auth_chanop_others(void **state)
{
  struct redact_auth_in in = rda_base(10);
  long w = -1;
  (void)state;
  in.is_chanop = 1;
  in.chanop_others = 1;
  assert_int_equal(REDACT_AUTH_OK, redact_authorize(&in, &w));
  in.chanop_others = 0;
  assert_int_equal(REDACT_AUTH_FORBIDDEN, redact_authorize(&in, &w));
}

static void test_redact_auth_not_message(void **state)
{
  struct redact_auth_in in = rda_base(10);
  long w = -1;
  (void)state;
  in.msg_type = HISTORY_JOIN;
  in.is_oper = 1;           /* not even an oper redacts a JOIN */
  assert_int_equal(REDACT_AUTH_NOT_MESSAGE, redact_authorize(&in, &w));
  in.msg_type = HISTORY_REDACT;
  assert_int_equal(REDACT_AUTH_NOT_MESSAGE, redact_authorize(&in, &w));
  in.msg_type = HISTORY_NOTICE;
  assert_int_equal(REDACT_AUTH_OK, redact_authorize(&in, &w));
  in.msg_type = HISTORY_TAGMSG;
  assert_int_equal(REDACT_AUTH_OK, redact_authorize(&in, &w));
  in.msg_type = HISTORY_MULTILINE;
  assert_int_equal(REDACT_AUTH_OK, redact_authorize(&in, &w));
}

static void test_redact_auth_unauth_mask(void **state)
{
  struct redact_auth_in in = rda_base(10);
  long w = -1;
  (void)state;
  in.msg_sender = "N!u@h";
  in.req_mask = "n!u@h";
  assert_int_equal(REDACT_AUTH_OK, redact_authorize(&in, &w));
  in.req_mask = "m!u@h";
  in.window = 0;
  assert_int_equal(REDACT_AUTH_FORBIDDEN, redact_authorize(&in, &w));
}

static void test_redact_auth_header_repaired(void **state)
{
  struct redact_auth_in in = rda_base(10);
  long w = -1;
  (void)state;
  in.msg_sender = "n!u@h";
  in.req_mask = "n!u@h";
  in.header_repaired = 1;   /* the mask proves nothing for a repaired row */
  assert_int_equal(REDACT_AUTH_FORBIDDEN, redact_authorize(&in, &w));
  in.now = 1000 + 61;
  assert_int_equal(REDACT_AUTH_EXPIRED, redact_authorize(&in, &w));
  assert_int_equal(60, w);
}

static void test_redact_auth_window_expired_other(void **state)
{
  struct redact_auth_in in = rda_base(61);
  long w = -1;
  (void)state;
  assert_int_equal(REDACT_AUTH_EXPIRED, redact_authorize(&in, &w));
  assert_int_equal(60, w);
  in.is_chanop = 1;         /* the window binds a chanop too */
  in.chanop_others = 1;
  w = -1;
  assert_int_equal(REDACT_AUTH_EXPIRED, redact_authorize(&in, &w));
  assert_int_equal(60, w);
  assert_int_equal(REDACT_AUTH_EXPIRED, redact_authorize(&in, NULL));   /* NULL-safe */
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
  struct HistoryMessage msg;
  (void)state;
  /* Records written before '|' was escaped decode as they always did. */
  memset(&msg, 0, sizeof(msg));
  assert_int_equal(0, history_deserialize_record(plain, strlen(plain), &msg));
  assert_int_equal(msg.type, HISTORY_PRIVMSG);
  assert_string_equal(msg.sender, "nick!user@host");
  assert_string_equal(msg.account, "acct");
  assert_string_equal(msg.content, "hello|world");
}

/* ========== Legacy rows a '|' nick shifted (read-side repair) ========== */

/* Decode a raw stored value (a row as an older binary wrote it). */
static void legacy_decode(const char *row, struct HistoryMessage *msg)
{
  memset(msg, 0, sizeof(*msg));
  assert_int_equal(0, history_deserialize_record(row, strlen(row), msg));
}

static void test_legacy_pipe_nick_no_account(void **state)
{
  struct HistoryMessage msg;
  (void)state;
  /* The F14 reproducer as an older binary stored it: nick a|admin|b, not
   * logged in.  The naive split read sender "a", account=admin. */
  legacy_decode("1|a|admin|b!u@host||spoof?", &msg);
  assert_int_equal(msg.type, HISTORY_NOTICE);
  assert_string_equal(msg.sender, "a|admin|b!u@host");
  assert_string_equal(msg.account, "");
  assert_string_equal(msg.content, "spoof?");
  /* Content is never split: its own '|' (and a mask-like run) stay. */
  legacy_decode("0|a|admin|b!u@host||x|y!z@w|v", &msg);
  assert_string_equal(msg.sender, "a|admin|b!u@host");
  assert_string_equal(msg.account, "");
  assert_string_equal(msg.content, "x|y!z@w|v");
}

static void test_legacy_pipe_nick_real_account(void **state)
{
  struct HistoryMessage msg;
  (void)state;
  /* Logged in as realacct: sender and content are repaired, but a
   * shifted row never yields an account (review ruling: the re-split
   * cannot rule out a '|' in the host, so its account slot could be a
   * host fragment).  Missing, never spoofed. */
  legacy_decode("1|a|admin|b!user@host|realacct|spoof?", &msg);
  assert_int_equal(msg.type, HISTORY_NOTICE);
  assert_string_equal(msg.sender, "a|admin|b!user@host");
  assert_string_equal(msg.account, "");
  assert_string_equal(msg.content, "spoof?");
}

static void test_legacy_pipe_nick_and_pipe_host_no_account(void **state)
{
  struct HistoryMessage msg;
  (void)state;
  /* A '|' in the host too (IsHostChar takes {|}~: a resolved, WEBIRC,
   * SETHOST or services-assigned host).  Nick a|b, host x|admin, no
   * login: the re-split closes the host at its first '|', and the slot
   * after it holds "admin".  No account is ever produced from it. */
  legacy_decode("0|a|b!u@x|admin||hi", &msg);
  assert_string_equal(msg.account, "");
  assert_string_equal(msg.sender, "a|b!u@x");
  assert_string_equal(msg.content, "|hi");
  /* Same with a real account behind it. */
  legacy_decode("0|a|b!u@x|admin|realacct|hi", &msg);
  assert_string_equal(msg.account, "");
  assert_string_equal(msg.sender, "a|b!u@x");
  assert_string_equal(msg.content, "realacct|hi");
}

static void test_legacy_ordinary_pipe_nick(void **state)
{
  struct HistoryMessage msg;
  (void)state;
  /* An ordinary nick like foo|away: every row it ever wrote. */
  legacy_decode("0|foo|away!u@h|acct|back | soon", &msg);
  assert_int_equal(msg.type, HISTORY_PRIVMSG);
  assert_string_equal(msg.sender, "foo|away!u@h");
  assert_string_equal(msg.account, "");
  assert_string_equal(msg.content, "back | soon");
  /* A JOIN row (empty content), as the JOIN-row scan reads it. */
  legacy_decode("2|foo|away!~u@2001:db8::1|acct|", &msg);
  assert_int_equal(msg.type, HISTORY_JOIN);
  assert_string_equal(msg.sender, "foo|away!~u@2001:db8::1");
  assert_string_equal(msg.account, "");
  assert_string_equal(msg.content, "");
}

static void test_legacy_pipe_nick_leading_and_runs(void **state)
{
  struct HistoryMessage msg;
  (void)state;
  /* A nick that starts with '|': the naive sender was empty. */
  legacy_decode("0||lead!u@h||hi", &msg);
  assert_string_equal(msg.sender, "|lead!u@h");
  assert_string_equal(msg.account, "");
  assert_string_equal(msg.content, "hi");
  /* A nick of '|' only, logged in (the account is not returned). */
  legacy_decode("0|||||!u@h|acct|x", &msg);
  assert_string_equal(msg.sender, "||||!u@h");
  assert_string_equal(msg.account, "");
  assert_string_equal(msg.content, "x");
}

static void test_legacy_pipe_username_resplit(void **state)
{
  struct HistoryMessage msg;
  (void)state;
  /* A '|' in the USERNAME shifts the fields too (IsUserChar takes {|}~):
   * the naive sender is "nick!x", the account "admin".  No user
   * character is '@', so the first '@' after the '!' closes the user. */
  legacy_decode("0|nick!x|admin|y@host||hi", &msg);
  assert_string_equal(msg.sender, "nick!x|admin|y@host");
  assert_string_equal(msg.account, "");
  assert_string_equal(msg.content, "hi");
  /* Logged in: still no account from a shifted row. */
  legacy_decode("0|nick!~x|ad|y@host|acct|hi|there", &msg);
  assert_string_equal(msg.sender, "nick!~x|ad|y@host");
  assert_string_equal(msg.account, "");
  assert_string_equal(msg.content, "hi|there");
  /* The common real shape: a client that sends its nick as USER, so the
   * nick and the username both carry the '|' (the bed's test clients do
   * this: p|admin|271dc!p|admin|27@...). */
  legacy_decode("0|p|admin|x!p|admin|x@767A62.F9398.IP||spoof?", &msg);
  assert_string_equal(msg.sender, "p|admin|x!p|admin|x@767A62.F9398.IP");
  assert_string_equal(msg.account, "");
  assert_string_equal(msg.content, "spoof?");
  /* A username that starts with '|'. */
  legacy_decode("0|nick!|u@h||hi", &msg);
  assert_string_equal(msg.sender, "nick!|u@h");
  assert_string_equal(msg.account, "");
  assert_string_equal(msg.content, "hi");
}

static void test_legacy_pipe_nick_sections(void **state)
{
  struct HistoryMessage msg;
  (void)state;
  /* The shift also hid the content's sentinel sections (PM original
   * target, client tags, incarnation) behind the header bytes; after
   * the repair they open the content field again. */
  legacy_decode("0|a|b!u@h|acct|\005x|y\005\006+reply=abc\006\007123\007text|more", &msg);
  assert_string_equal(msg.sender, "a|b!u@h");
  assert_string_equal(msg.account, "");
  assert_string_equal(msg.original_target, "x|y");
  assert_string_equal(msg.client_tags, "+reply=abc");
  assert_int_equal(msg.incarnation, 123);
  assert_string_equal(msg.content, "text|more");
}

static void test_legacy_legit_senders_unchanged(void **state)
{
  struct HistoryMessage msg;
  (void)state;
  /* Every sender form the store paths write, as before the escape:
   * nick!user@host (users, services, CH W forwards), a server name (a
   * server's MODE/KICK/TOPIC/notice, CH W from a server).  None was
   * split wrongly, so none may change -- whatever its content holds. */
  legacy_decode("0|nick!user@host||a|b!c@d|e|f", &msg);
  assert_string_equal(msg.sender, "nick!user@host");
  assert_string_equal(msg.account, "");
  assert_string_equal(msg.content, "a|b!c@d|e|f");
  legacy_decode("0|ChanServ!X3@X3.AfterNET.Services||Welcome", &msg);
  assert_string_equal(msg.sender, "ChanServ!X3@X3.AfterNET.Services");
  assert_string_equal(msg.account, "");
  assert_string_equal(msg.content, "Welcome");
  legacy_decode("0|n!~u@2001:db8::1|acct|x|y", &msg);
  assert_string_equal(msg.sender, "n!~u@2001:db8::1");
  assert_string_equal(msg.account, "acct");
  assert_string_equal(msg.content, "x|y");
  legacy_decode("6|hub.fractalrealities.net||+o x|y", &msg);
  assert_int_equal(msg.type, HISTORY_MODE);
  assert_string_equal(msg.sender, "hub.fractalrealities.net");
  assert_string_equal(msg.account, "");
  assert_string_equal(msg.content, "+o x|y");
  /* A server's KICK or TOPIC can carry a mask-shaped text. */
  legacy_decode("7|hub.fractalrealities.net||a|b!c@d|e|f", &msg);
  assert_string_equal(msg.sender, "hub.fractalrealities.net");
  assert_string_equal(msg.account, "");
  assert_string_equal(msg.content, "a|b!c@d|e|f");
  /* No store path writes "*" or an empty sender; such a row reads as
   * before when it has no account (one it has is dropped: such a
   * sender is not a legitimate form, see the next test). */
  legacy_decode("0|*||text", &msg);
  assert_string_equal(msg.sender, "*");
  assert_string_equal(msg.account, "");
  assert_string_equal(msg.content, "text");
  legacy_decode("0|||text", &msg);
  assert_string_equal(msg.sender, "");
  assert_string_equal(msg.account, "");
  assert_string_equal(msg.content, "text");
}

static void test_legacy_ambiguous_shift_drops_account(void **state)
{
  struct HistoryMessage msg;
  (void)state;
  /* Mis-split, but the re-split is not a safe nick!user@host: the
   * naive split stands, without its account (a fragment of the sender,
   * never the real one), and nothing else changes.  A '|' username
   * longer than USERLEN, or with a byte no username holds: */
  legacy_decode("0|nick!x|admin|yyyy@host||hi", &msg);
  assert_string_equal(msg.sender, "nick!x");
  assert_string_equal(msg.account, "");
  assert_string_equal(msg.content, "yyyy@host||hi");
  legacy_decode("0|nick!x|ad+min@host||hi", &msg);
  assert_string_equal(msg.sender, "nick!x");
  assert_string_equal(msg.account, "");
  assert_string_equal(msg.content, "|hi");
  /* No '!' anywhere: nothing marks where the sender ended. */
  legacy_decode("0|a|admin|text", &msg);
  assert_string_equal(msg.sender, "a");
  assert_string_equal(msg.account, "");
  assert_string_equal(msg.content, "text");
  /* The would-be nick is not a nick (a space; a leading digit). */
  legacy_decode("0|a|b c!u@h|acct|x", &msg);
  assert_string_equal(msg.sender, "a");
  assert_string_equal(msg.account, "");
  assert_string_equal(msg.content, "acct|x");
  legacy_decode("0|1a|b!u@h|acct|x", &msg);
  assert_string_equal(msg.sender, "1a");
  assert_string_equal(msg.account, "");
  assert_string_equal(msg.content, "acct|x");
  /* Too long to be a nick. */
  legacy_decode("0|aaaaaaaaaaaaaaaaaaaa|bbbbbbbbbbbbbbbbbbbb!u@h|acct|x", &msg);
  assert_string_equal(msg.sender, "aaaaaaaaaaaaaaaaaaaa");
  assert_string_equal(msg.account, "");
  assert_string_equal(msg.content, "acct|x");
  /* No account field after the would-be sender. */
  legacy_decode("0|a|b!u@h|acct", &msg);
  assert_string_equal(msg.sender, "a");
  assert_string_equal(msg.account, "");
  assert_string_equal(msg.content, "acct");
  /* The account field is never read on the re-split path, whatever it
   * holds: here one longer than any account, and the row still
   * re-splits, without an account. */
  legacy_decode("0|a|b!u@h|aaaaaaaaaaaaaaaaaaaa|x", &msg);
  assert_string_equal(msg.sender, "a|b!u@h");
  assert_string_equal(msg.account, "");
  assert_string_equal(msg.content, "x");
}

static void test_escaped_rows_never_resplit(void **state)
{
  struct HistoryMessage msg;
  char buf[HISTORY_VALUE_BUFSIZE];
  int len;
  (void)state;
  /* A row written with the escape keeps exactly what was stored, even
   * when its content looks like the rest of a shifted header. */
  len = history_serialize_record(buf, sizeof(buf), HISTORY_PRIVMSG,
                                 "a|b!u@h", "", "c!d@e|f|g", NULL, NULL, 0);
  assert_true(len > 0);
  memset(&msg, 0, sizeof(msg));
  assert_int_equal(0, history_deserialize_record(buf, (size_t)len, &msg));
  assert_string_equal(msg.sender, "a|b!u@h");
  assert_string_equal(msg.account, "");
  assert_string_equal(msg.content, "c!d@e|f|g");
  /* Escaped '|' in the account only. */
  len = history_serialize_record(buf, sizeof(buf), HISTORY_PRIVMSG,
                                 "n!u@h", "a|b", "x!y@z|w|v", NULL, NULL, 0);
  memset(&msg, 0, sizeof(msg));
  assert_int_equal(0, history_deserialize_record(buf, (size_t)len, &msg));
  assert_string_equal(msg.sender, "n!u@h");
  assert_string_equal(msg.account, "a|b");
  assert_string_equal(msg.content, "x!y@z|w|v");
  /* A stored sender holding an escape is never treated as legacy, even
   * a bare one: written by the escaping code, it is exact. */
  legacy_decode("0|a\004<b|acct|c!d@e|f|g", &msg);
  assert_string_equal(msg.sender, "a|b");
  assert_string_equal(msg.account, "acct");
  assert_string_equal(msg.content, "c!d@e|f|g");
}

static void test_split_header_resplits_legacy_join(void **state)
{
  static const char row[] = "2|foo|away!u@h|acct|";
  char sender[HISTORY_SENDER_LEN];
  char account[ACCOUNTLEN + 1];
  int shifted = -1;
  (void)state;
  /* The JOIN-row scan reads the header through history_split_header,
   * so a legacy foo|away JOIN is found under its whole nick. */
  memset(account, 'x', sizeof(account));
  assert_int_equal((int)strlen("foo|away!u@h|acct|"),
                   history_split_header(row + 2, strlen(row) - 2,
                                        sender, sizeof(sender),
                                        account, sizeof(account), &shifted));
  assert_string_equal(sender, "foo|away!u@h");
  assert_string_equal(account, "");
  assert_int_equal(shifted, 1);
  /* A NULL out-parameter is allowed (the JOIN-row scan passes one). */
  assert_int_equal((int)strlen("foo|away!u@h|acct|"),
                   history_split_header(row + 2, strlen(row) - 2,
                                        sender, sizeof(sender),
                                        account, sizeof(account), NULL));
  /* A legitimate header clears it. */
  shifted = -1;
  assert_int_equal((int)strlen("n!u@h|acct|"),
                   history_split_header("n!u@h|acct|x", strlen("n!u@h|acct|x"),
                                        sender, sizeof(sender),
                                        account, sizeof(account), &shifted));
  assert_int_equal(shifted, 0);
  assert_string_equal(account, "acct");
}

/* Decode a raw stored value and return its header_repaired flag. */
static int repaired_flag(const char *row)
{
  struct HistoryMessage msg;
  memset(&msg, 0x5a, sizeof(msg));   /* the decode must set it either way */
  assert_int_equal(0, history_deserialize_record(row, strlen(row), &msg));
  return msg.header_repaired;
}

static void test_header_repaired_flag(void **state)
{
  char buf[HISTORY_VALUE_BUFSIZE];
  struct HistoryMessage msg;
  int len;
  (void)state;
  /* Set for every row found shifted: re-split (nick '|', username '|',
   * both, a '|' host behind it) ... */
  assert_int_equal(1, repaired_flag("1|a|admin|b!u@host||spoof?"));
  assert_int_equal(1, repaired_flag("1|a|admin|b!user@host|realacct|spoof?"));
  assert_int_equal(1, repaired_flag("0|nick!x|admin|y@host||hi"));
  assert_int_equal(1, repaired_flag("0|p|admin|x!p|admin|x@767A62.F9398.IP||spoof?"));
  assert_int_equal(1, repaired_flag("0|a|b!u@x|admin||hi"));
  assert_int_equal(1, repaired_flag("0||lead!u@h||hi"));
  /* ... and kept as read without its account (re-split refused). */
  assert_int_equal(1, repaired_flag("0|nick!x|admin|yyyy@host||hi"));
  assert_int_equal(1, repaired_flag("0|a|admin|text"));
  assert_int_equal(1, repaired_flag("0|a|b c!u@h|acct|x"));
  /* Clear for every legitimate legacy form ... */
  assert_int_equal(0, repaired_flag("0|nick!user@host|acct|hello|world"));
  assert_int_equal(0, repaired_flag("0|nick!user@host||a|b!c@d|e|f"));
  assert_int_equal(0, repaired_flag("0|ChanServ!X3@X3.AfterNET.Services||Welcome"));
  assert_int_equal(0, repaired_flag("0|n!~u@2001:db8::1|acct|x|y"));
  assert_int_equal(0, repaired_flag("6|hub.fractalrealities.net||+o x|y"));
  assert_int_equal(0, repaired_flag("7|hub.fractalrealities.net||a|b!c@d|e|f"));
  /* ... and for escaped rows, '|' sender or '|' account. */
  len = history_serialize_record(buf, sizeof(buf), HISTORY_PRIVMSG,
                                 "a|admin|b!u@h", "realacct", "c!d@e|f|g",
                                 NULL, NULL, 0);
  memset(&msg, 0x5a, sizeof(msg));
  assert_int_equal(0, history_deserialize_record(buf, (size_t)len, &msg));
  assert_int_equal(0, msg.header_repaired);
  assert_string_equal(msg.account, "realacct");
  len = history_serialize_record(buf, sizeof(buf), HISTORY_PRIVMSG,
                                 "n!u@h", "a|b", "x", NULL, NULL, 0);
  memset(&msg, 0x5a, sizeof(msg));
  assert_int_equal(0, history_deserialize_record(buf, (size_t)len, &msg));
  assert_int_equal(0, msg.header_repaired);
  assert_int_equal(0, repaired_flag("0|a\004<b|acct|c!d@e|f|g"));
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

/* is_reserved_vendor_tag (ircd.c) is a thin wrapper over the real,
 * pure ircd_reserved_vendor_tag() (ircd_string.c) -- call that one
 * directly rather than keeping a second, driftable mirror; the suite
 * already links ../ircd_string.o.  Hotfix 6, part 2 (2026-11-09):
 * only specific NAMES are reserved under +evilnet.github.io/ now
 * (Seance, an evilnet project, uses the rest of that namespace for
 * ordinary client-only tags); +afternet.org/ stays reserved whole. */
extern int ircd_reserved_vendor_tag(const char *tag, size_t tag_len);

static void test_reserved_vendor_tag(void **state)
{
  (void)state;
  /* The specific server-written names are reserved (case-insensitive
   * domain). */
  assert_true(ircd_reserved_vendor_tag("+evilnet.github.io/sid=abc",
                                     strlen("+evilnet.github.io/sid=abc")));
  assert_true(ircd_reserved_vendor_tag("+EvilNet.GitHub.IO/sid=abc",
                                     strlen("+EvilNet.GitHub.IO/sid=abc")));
  assert_true(ircd_reserved_vendor_tag("+evilnet.github.io/ssid=abc",
                                     strlen("+evilnet.github.io/ssid=abc")));
  assert_true(ircd_reserved_vendor_tag("+evilnet.github.io/rsid=abc",
                                     strlen("+evilnet.github.io/rsid=abc")));
  assert_true(ircd_reserved_vendor_tag("+evilnet.github.io/chathistory-gap",
                                     strlen("+evilnet.github.io/chathistory-gap")));
  /* Anything else under the namespace is NOT reserved anymore --
   * Seance's own tags live there now. */
  assert_false(ircd_reserved_vendor_tag("+evilnet.github.io/anything",
                                     strlen("+evilnet.github.io/anything")));
  assert_false(ircd_reserved_vendor_tag("+evilnet.github.io/machine-translated",
                                     strlen("+evilnet.github.io/machine-translated")));
  /* "sid" must not match "sidecar" (name-boundary, not a byte-prefix). */
  assert_false(ircd_reserved_vendor_tag("+evilnet.github.io/sidecar",
                                     strlen("+evilnet.github.io/sidecar")));
  /* The legacy namespace stays reserved WHOLE (pre-2026-08-29 records
   * carry the sid marker there and the auth check still honors it). */
  assert_true(ircd_reserved_vendor_tag("+afternet.org/sid=abc",
                                     strlen("+afternet.org/sid=abc")));
  assert_true(ircd_reserved_vendor_tag("+AfterNet.ORG/sid=abc",
                                     strlen("+AfterNet.ORG/sid=abc")));
  assert_true(ircd_reserved_vendor_tag("+afternet.org/anything",
                                     strlen("+afternet.org/anything")));
  /* Other client tags pass through untouched. */
  assert_false(ircd_reserved_vendor_tag("+reply=abc", strlen("+reply=abc")));
  assert_false(ircd_reserved_vendor_tag("+draft/react=x", strlen("+draft/react=x")));
  assert_false(ircd_reserved_vendor_tag("+example.com/afternet.org",
                                      strlen("+example.com/afternet.org")));
  /* A lookalike shorter than the prefix cannot match. */
  assert_false(ircd_reserved_vendor_tag("+afternet.org", strlen("+afternet.org")));
  assert_false(ircd_reserved_vendor_tag("+evilnet.github.io",
                                      strlen("+evilnet.github.io")));
  assert_false(ircd_reserved_vendor_tag(NULL, 0));
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
    cmocka_unit_test(test_ch_e_flags),
    cmocka_unit_test(test_ch_ad_features),
    cmocka_unit_test(test_ch_ad_letters),
    cmocka_unit_test(test_ri_link_kind),
    cmocka_unit_test(test_rdx_row_decide),
    cmocka_unit_test(test_rdx_wm_cut_keeps),
    cmocka_unit_test(test_rdx_wm_truncated_continues),
    cmocka_unit_test(test_rdx_wm_round_cap_keeps_last),
    cmocka_unit_test(test_rdx_wm_complete_sets_start),
    cmocka_unit_test(test_rdx_wm_truncated_no_rows_keeps),
    cmocka_unit_test(test_rdx_retry_decide),
    cmocka_unit_test(test_rdx_retry_next_delay),
    cmocka_unit_test(test_redact_auth_owner_no_window),
    cmocka_unit_test(test_redact_auth_oper_window),
    cmocka_unit_test(test_redact_auth_chanop_others),
    cmocka_unit_test(test_redact_auth_not_message),
    cmocka_unit_test(test_redact_auth_unauth_mask),
    cmocka_unit_test(test_redact_auth_header_repaired),
    cmocka_unit_test(test_redact_auth_window_expired_other),
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
        cmocka_unit_test(test_legacy_pipe_nick_no_account),
        cmocka_unit_test(test_legacy_pipe_nick_real_account),
        cmocka_unit_test(test_legacy_pipe_nick_and_pipe_host_no_account),
        cmocka_unit_test(test_legacy_ordinary_pipe_nick),
        cmocka_unit_test(test_legacy_pipe_nick_leading_and_runs),
        cmocka_unit_test(test_legacy_pipe_username_resplit),
        cmocka_unit_test(test_legacy_pipe_nick_sections),
        cmocka_unit_test(test_legacy_legit_senders_unchanged),
        cmocka_unit_test(test_legacy_ambiguous_shift_drops_account),
        cmocka_unit_test(test_escaped_rows_never_resplit),
        cmocka_unit_test(test_split_header_resplits_legacy_join),
        cmocka_unit_test(test_header_repaired_flag),
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
