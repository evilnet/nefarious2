/*
 * kc_keycloak_cmocka.c - unit tests for the vendored libkc Keycloak client
 * (kc_keycloak.c).
 *
 * The HTTP layer is a fake: kc_http_request() below records every request
 * (URL, method, body, timeout) and keeps its callback, and a test answers
 * request N with fake_answer() when it chooses, so a token-gated operation
 * can be walked step by step (client-credentials token first, then the
 * admin request itself).  kc.c is not linked: kc_get_log_ops() and
 * kc_get_event_ops() are stubbed to NULL, which makes logging a no-op and
 * the clock time(NULL).
 */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <jansson.h>

#include <kc/kc.h>
#include <kc/kc_http.h>
#include <kc/kc_keycloak.h>

const struct kc_log_ops *kc_get_log_ops(void) { return NULL; }
const struct kc_event_ops *kc_get_event_ops(void) { return NULL; }

/* ---- The fake HTTP layer ---- */

#define FAKE_REQ_MAX 8

struct fake_req {
    char url[512];
    char method[8];
    char body[2048];
    char bearer[64];              /* the admin token sent; "" for none */
    long timeout_ms;
};

static struct fake_req fake_reqs[FAKE_REQ_MAX];
static int fake_req_count;
static kc_http_callback fake_cbs[FAKE_REQ_MAX];
static void *fake_cb_data[FAKE_REQ_MAX];

/* Called with the new request's index once it is recorded, before
 * kc_http_request() returns: the real one runs every transfer that has
 * finished before it returns (kc_http.c: check_multi_info()), so a test
 * can answer another request from here, nested inside this one. */
static void (*fake_on_request)(int idx);

int kc_http_request(const struct kc_http_request *req,
                    kc_http_callback cb, void *data)
{
    struct fake_req *r;
    const char *method = req->method ? req->method : "GET";
    int idx;

    assert_true(fake_req_count < FAKE_REQ_MAX);
    r = &fake_reqs[fake_req_count];

    /* A field too long for its buffer fails the test rather than being
     * compared truncated. */
    assert_true(strlen(req->url) < sizeof(r->url));
    assert_true(strlen(method) < sizeof(r->method));
    assert_true(req->body_len < sizeof(r->body));
    assert_true(!req->bearer_token || strlen(req->bearer_token) < sizeof(r->bearer));

    strcpy(r->url, req->url);
    strcpy(r->method, method);
    if (req->body)
        memcpy(r->body, req->body, req->body_len);
    r->body[req->body_len] = '\0';
    strcpy(r->bearer, req->bearer_token ? req->bearer_token : "");
    r->timeout_ms = req->timeout_ms;

    idx = fake_req_count;
    fake_cbs[idx] = cb;
    fake_cb_data[idx] = data;
    fake_req_count++;
    if (fake_on_request)
        fake_on_request(idx);
    return 0;
}

/*
 * Answer request idx: json is parsed from json_text when it parses (else
 * NULL), status 0 is a transport failure (error set).  Each request is
 * answered at most once.
 */
static void fake_answer(int idx, long status, const char *json_text)
{
    struct kc_http_response resp;
    kc_http_callback cb;
    char *body;

    assert_true(idx >= 0 && idx < fake_req_count);
    cb = fake_cbs[idx];
    assert_non_null(cb);
    fake_cbs[idx] = NULL;

    body = strdup(json_text ? json_text : "");
    assert_non_null(body);

    memset(&resp, 0, sizeof(resp));
    resp.status_code = status;
    resp.body = body;
    resp.body_len = strlen(body);
    resp.json = json_text ? json_loads(json_text, 0, NULL) : NULL;
    if (status == 0)
        resp.error = "fake: transport failure";

    cb(&resp, fake_cb_data[idx]);

    if (resp.json)
        json_decref(resp.json);
    free(body);
}

/* Answer a client-credentials token request. */
static void fake_answer_token(int idx)
{
    fake_answer(idx, 200, "{\"access_token\":\"t\",\"expires_in\":300}");
}

static void fake_reset(void)
{
    memset(fake_reqs, 0, sizeof(fake_reqs));
    memset(fake_cbs, 0, sizeof(fake_cbs));
    memset(fake_cb_data, 0, sizeof(fake_cb_data));
    fake_req_count = 0;
    fake_on_request = NULL;
}

/* ---- Callbacks ---- */

/* The password grant's answer: the result, a copy of the reason ("" for
 * NULL; the pointer is only valid during the call; cut to the buffer, the
 * whole length kept apart), whether it was NULL, and how many answers
 * came. */
static int last_result;
static char last_reason[256];
static size_t last_reason_len;
static int last_reason_null;
static int grant_calls;

static void grant_cb(int result, const struct kc_access_token *token,
                     const char *reason, void *data)
{
    (void)data;
    grant_calls++;
    last_result = result;
    last_reason_null = (reason == NULL);
    last_reason_len = reason ? strlen(reason) : 0;
    snprintf(last_reason, sizeof(last_reason), "%s", reason ? reason : "");
    if (result == KC_SUCCESS)
        assert_non_null(token);
    else
        assert_null(token);
}

/* An introspection's answer: the result only. */
static void introspect_cb(int result, const struct kc_token_info *info, void *data)
{
    (void)info; (void)data;
    last_result = result;
}

static void user_cb(int result, const struct kc_user *user, void *data)
{
    (void)result; (void)user; (void)data;
}

/* A group lookup's answer: the result, a copy of the group's id ("" when
 * there is no group; the group is only valid during the call), and how
 * many answers came. */
static char last_group_id[64];
static int group_calls;

static void group_cb(int result, const struct kc_group *group, void *data)
{
    (void)data;
    group_calls++;
    last_result = result;
    if (result == KC_SUCCESS) {
        assert_non_null(group);
        assert_non_null(group->id);
        assert_true(strlen(group->id) < sizeof(last_group_id));
        strcpy(last_group_id, group->id);
    } else {
        assert_null(group);
        strcpy(last_group_id, "");
    }
}

/* A user representation's answer: the result, a copy of its "username"
 * ("" when there is no representation or no such string; the JSON is
 * borrowed, valid during the call), and how many answers came. */
static char last_repr_username[64];
static int repr_calls;

static void repr_cb(int result, json_t *repr, void *data)
{
    (void)data;
    repr_calls++;
    last_result = result;
    strcpy(last_repr_username, "");
    if (result == KC_SUCCESS) {
        json_t *name;
        assert_non_null(repr);
        assert_true(json_is_object(repr));
        name = json_object_get(repr, "username");
        if (json_is_string(name)) {
            assert_true(strlen(json_string_value(name)) < sizeof(last_repr_username));
            strcpy(last_repr_username, json_string_value(name));
        }
    } else {
        assert_null(repr);
    }
}

/* ---- Setup / teardown ---- */

static int setup(void **state)
{
    (void)state;
    fake_reset();
    last_result = 999;
    strcpy(last_reason, "(no answer)");
    last_reason_len = 0;
    last_reason_null = 0;
    grant_calls = 0;
    strcpy(last_group_id, "(no answer)");
    group_calls = 0;
    strcpy(last_repr_username, "(no answer)");
    repr_calls = 0;
    return 0;
}

/* init with a valid config, nothing sent yet. */
static void start(void)
{
    struct kc_config cfg = { "http://kc", "r", "cid", "sec", 0 };
    assert_int_equal(kc_keycloak_init(&cfg), 0);
    assert_int_equal(fake_req_count, 0);
}

/* A request a test never answers keeps its operation's context: nothing
 * frees it (kc_keycloak_shutdown() does not cancel requests in flight), so
 * a leak checker reports those contexts. */
static int teardown(void **state)
{
    (void)state;
    kc_keycloak_shutdown();
    fake_reset();
    return 0;
}

/* ---- The request timeout setting ---- */

static void test_timeout_defaults_to_10s(void **state)
{
    struct kc_config cfg = { "http://kc", "r", "cid", "sec", 0 };
    (void)state;
    assert_int_equal(kc_keycloak_init(&cfg), 0);
    assert_int_equal(kc_user_verify_password("u", "p", grant_cb, NULL), 0);
    assert_int_equal(fake_reqs[0].timeout_ms, 10000);
}

static void test_timeout_negative_is_default(void **state)
{
    struct kc_config cfg = { "http://kc", "r", "cid", "sec", -5 };
    (void)state;
    assert_int_equal(kc_keycloak_init(&cfg), 0);
    assert_int_equal(kc_user_verify_password("u", "p", grant_cb, NULL), 0);
    assert_int_equal(fake_reqs[0].timeout_ms, 10000);
}

static void test_timeout_setting_reaches_every_request(void **state)
{
    struct kc_config cfg = { "http://kc", "r", "cid", "sec", 2500 };
    (void)state;
    assert_int_equal(kc_keycloak_init(&cfg), 0);
    assert_int_equal(kc_user_verify_password("u", "p", grant_cb, NULL), 0);
    assert_int_equal(fake_reqs[0].timeout_ms, 2500);      /* password grant */
    assert_int_equal(kc_user_get("u", user_cb, NULL), 0);
    assert_int_equal(fake_reqs[1].timeout_ms, 2500);      /* client-credentials token */
    fake_answer_token(1);
    assert_int_equal(fake_reqs[2].timeout_ms, 2500);      /* the admin request itself */
}

/* ---- The password grant's outcomes ---- */

/* init, then a password grant for u/p: request 0. */
static void start_grant(void)
{
    struct kc_config cfg = { "http://kc", "r", "cid", "sec", 0 };
    assert_int_equal(kc_keycloak_init(&cfg), 0);
    assert_int_equal(kc_user_verify_password("u", "p", grant_cb, NULL), 0);
    assert_int_equal(fake_req_count, 1);
    assert_int_equal(grant_calls, 0);
}

static void test_grant_disabled_carries_reason(void **state)
{
    (void)state;
    start_grant();
    fake_answer(0, 400, "{\"error\":\"invalid_grant\",\"error_description\":\"Account disabled\"}");
    assert_int_equal(grant_calls, 1);
    assert_int_equal(last_result, KC_DISABLED);
    assert_string_equal(last_reason, "Account disabled");
}

static void test_grant_wrong_password_carries_reason(void **state)
{
    (void)state;
    start_grant();
    fake_answer(0, 401, "{\"error\":\"invalid_grant\",\"error_description\":\"Invalid user credentials\"}");
    assert_int_equal(grant_calls, 1);
    assert_int_equal(last_result, KC_FORBIDDEN);
    assert_string_equal(last_reason, "Invalid user credentials");
}

static void test_grant_not_set_up_carries_reason(void **state)
{
    (void)state;
    start_grant();
    fake_answer(0, 400, "{\"error\":\"invalid_grant\",\"error_description\":\"Account is not fully set up\"}");
    assert_int_equal(grant_calls, 1);
    assert_int_equal(last_result, KC_UNVERIFIED);
    assert_string_equal(last_reason, "Account is not fully set up");
}

static void test_grant_success_has_no_reason(void **state)
{
    (void)state;
    start_grant();
    fake_answer(0, 200, "{\"access_token\":\"t\",\"expires_in\":300}");
    assert_int_equal(grant_calls, 1);
    assert_int_equal(last_result, KC_SUCCESS);
    assert_string_equal(last_reason, "");
}

static void test_grant_client_refused(void **state)
{
    (void)state;
    start_grant();
    fake_answer(0, 401, "{\"error\":\"invalid_client\",\"error_description\":\"Invalid client or Invalid client credentials\"}");
    assert_int_equal(grant_calls, 1);
    assert_int_equal(last_result, KC_CLIENT_REFUSED);
    assert_string_equal(last_reason, "Invalid client or Invalid client credentials");
}

static void test_grant_no_description_has_no_reason(void **state)
{
    (void)state;
    start_grant();
    fake_answer(0, 400, "{\"error\":\"invalid_grant\",\"error_description\":42}");
    assert_int_equal(grant_calls, 1);
    assert_int_equal(last_result, KC_FORBIDDEN);
    assert_string_equal(last_reason, "");
}

static void test_grant_html_400_is_transport_error(void **state)
{
    (void)state;
    start_grant();
    fake_answer(0, 400, "<html>");
    assert_int_equal(grant_calls, 1);
    assert_int_equal(last_result, KC_ERROR);
    assert_string_equal(last_reason, "");
}

static void test_grant_502_is_transport_error(void **state)
{
    (void)state;
    start_grant();
    fake_answer(0, 502, "<html>");
    assert_int_equal(grant_calls, 1);
    assert_int_equal(last_result, KC_ERROR);
    assert_string_equal(last_reason, "");
}

static void test_grant_no_answer_is_transport_error(void **state)
{
    (void)state;
    start_grant();
    fake_answer(0, 0, NULL);
    assert_int_equal(grant_calls, 1);
    assert_int_equal(last_result, KC_ERROR);
    assert_string_equal(last_reason, "");
}

static void test_grant_200_without_token_is_invalid(void **state)
{
    (void)state;
    start_grant();
    fake_answer(0, 200, "{\"token_type\":\"Bearer\",\"expires_in\":300}");
    assert_int_equal(grant_calls, 1);
    assert_int_equal(last_result, KC_INVALID_RESPONSE);   /* grant_cb: token NULL */
    assert_true(last_reason_null);
}

static void test_grant_error_without_description_has_null_reason(void **state)
{
    (void)state;
    start_grant();
    fake_answer(0, 400, "{\"error\":\"invalid_grant\"}");
    assert_int_equal(grant_calls, 1);
    assert_int_equal(last_result, KC_FORBIDDEN);
    assert_true(last_reason_null);
}

/* A description far longer than anything Keycloak sends is classified and
 * passed up whole, never cut or overrun (the caller bounds what it shows). */
static void test_grant_very_long_description(void **state)
{
    enum { DESC_LEN = 5000 };
    char *json = malloc(DESC_LEN + 64);
    size_t i, n;

    (void)state;
    assert_non_null(json);
    n = (size_t)sprintf(json, "{\"error\":\"invalid_grant\",\"error_description\":\"");
    for (i = 0; i < DESC_LEN; i++)
        json[n++] = (char)('a' + i % 26);
    strcpy(json + n, "\"}");

    start_grant();
    fake_answer(0, 400, json);
    free(json);
    assert_int_equal(grant_calls, 1);
    assert_int_equal(last_result, KC_FORBIDDEN);
    assert_false(last_reason_null);
    assert_int_equal(last_reason_len, DESC_LEN);
    assert_int_equal(strlen(last_reason), sizeof(last_reason) - 1);
    assert_int_equal(strncmp(last_reason, "abcdefghijklmnopqrstuvwxyzabc", 29), 0);
}

/* ---- A group looked up by its path ---- */

static void test_group_by_path_found(void **state)
{
    (void)state;
    start();
    assert_int_equal(kc_group_get_by_path("/staff/opers", group_cb, NULL), 0);
    assert_int_equal(fake_req_count, 1);                  /* the client-credentials token */
    fake_answer_token(0);
    assert_int_equal(fake_req_count, 2);
    assert_string_equal(fake_reqs[1].method, "GET");
    assert_non_null(strstr(fake_reqs[1].url, "/admin/realms/r/group-by-path/staff/opers"));
    assert_int_equal(group_calls, 0);
    fake_answer(1, 200, "{\"id\":\"g-1\",\"name\":\"opers\",\"path\":\"/staff/opers\"}");
    assert_int_equal(group_calls, 1);
    assert_int_equal(last_result, KC_SUCCESS);
    assert_string_equal(last_group_id, "g-1");
}

static void test_group_by_path_missing(void **state)
{
    (void)state;
    start();
    assert_int_equal(kc_group_get_by_path("/staff/opers", group_cb, NULL), 0);
    fake_answer_token(0);
    fake_answer(1, 404, "{\"error\":\"Group path does not exist\"}");
    assert_int_equal(group_calls, 1);
    assert_int_equal(last_result, KC_NOT_FOUND);
    assert_string_equal(last_group_id, "");
}

static void test_group_by_path_not_an_object_is_error(void **state)
{
    (void)state;
    start();
    assert_int_equal(kc_group_get_by_path("/staff/opers", group_cb, NULL), 0);
    fake_answer_token(0);
    fake_answer(1, 200, "[]");
    assert_int_equal(group_calls, 1);
    assert_int_equal(last_result, KC_ERROR);
}

/* A 200 object without a string "id" is no group: the caller would use the
 * id at once. */
static void test_group_by_path_without_id_is_invalid(void **state)
{
    (void)state;
    start();
    assert_int_equal(kc_group_get_by_path("/staff/opers", group_cb, NULL), 0);
    fake_answer_token(0);
    fake_answer(1, 200, "{\"name\":\"opers\",\"path\":\"/staff/opers\"}");
    assert_int_equal(group_calls, 1);
    assert_int_equal(last_result, KC_INVALID_RESPONSE);  /* group_cb: group NULL */

    assert_int_equal(kc_group_get_by_path("/staff/opers", group_cb, NULL), 0);
    assert_int_equal(fake_req_count, 3);                 /* the cached token */
    fake_answer(2, 200, "{\"id\":42,\"name\":\"opers\"}");
    assert_int_equal(group_calls, 2);
    assert_int_equal(last_result, KC_INVALID_RESPONSE);
}

static void test_group_by_path_needs_leading_slash(void **state)
{
    (void)state;
    start();
    assert_int_equal(kc_group_get_by_path("opers", group_cb, NULL), -1);
    assert_int_equal(group_calls, 0);
    assert_int_equal(fake_req_count, 0);
}

static void test_group_by_path_token_failure(void **state)
{
    (void)state;
    start();
    assert_int_equal(kc_group_get_by_path("/staff/opers", group_cb, NULL), 0);
    fake_answer(0, 401, "{}");
    assert_int_equal(group_calls, 1);
    assert_int_equal(last_result, KC_TOKEN_ERROR);
    assert_int_equal(fake_req_count, 1);                  /* the lookup itself never went out */
}

/* ---- A user's full representation ---- */

static void test_user_repr_found(void **state)
{
    (void)state;
    start();
    assert_int_equal(kc_user_get_repr("u-1", repr_cb, NULL), 0);
    fake_answer_token(0);
    assert_int_equal(fake_req_count, 2);
    assert_string_equal(fake_reqs[1].method, "GET");
    {
        const char *tail = "/admin/realms/r/users/u-1";
        size_t ul = strlen(fake_reqs[1].url), tl = strlen(tail);
        assert_true(ul >= tl);
        assert_string_equal(fake_reqs[1].url + ul - tl, tail);
    }
    assert_int_equal(repr_calls, 0);
    fake_answer(1, 200, "{\"id\":\"u-1\",\"username\":\"alice\",\"attributes\":{\"x\":[\"1\"]}}");
    assert_int_equal(repr_calls, 1);
    assert_int_equal(last_result, KC_SUCCESS);
    assert_string_equal(last_repr_username, "alice");
}

static void test_user_repr_missing(void **state)
{
    (void)state;
    start();
    assert_int_equal(kc_user_get_repr("u-1", repr_cb, NULL), 0);
    fake_answer_token(0);
    fake_answer(1, 404, "{\"error\":\"User not found\"}");
    assert_int_equal(repr_calls, 1);
    assert_int_equal(last_result, KC_NOT_FOUND);
}

static void test_user_repr_token_failure(void **state)
{
    (void)state;
    start();
    assert_int_equal(kc_user_get_repr("u-1", repr_cb, NULL), 0);
    fake_answer(0, 401, "{}");
    assert_int_equal(repr_calls, 1);
    assert_int_equal(last_result, KC_TOKEN_ERROR);
    assert_int_equal(fake_req_count, 1);
}

static void test_user_repr_other_status_is_error(void **state)
{
    (void)state;
    start();
    assert_int_equal(kc_user_get_repr("u-1", repr_cb, NULL), 0);
    fake_answer_token(0);
    fake_answer(1, 500, "{}");
    assert_int_equal(repr_calls, 1);
    assert_int_equal(last_result, KC_ERROR);
}

/* ---- A token refresh that outlives its configuration ---- */

/* init A; an admin op waits on token request 0; shutdown answers it (the
 * request itself stays in flight); init B; an admin op waits on token
 * request 1. */
static void stale_refresh_setup(void)
{
    struct kc_config a = { "http://kc-a", "ra", "cid-a", "sec-a", 0 };
    struct kc_config b = { "http://kc-b", "rb", "cid-b", "sec-b", 0 };

    assert_int_equal(kc_keycloak_init(&a), 0);
    assert_int_equal(kc_group_get_by_path("/staff", group_cb, NULL), 0);
    assert_int_equal(fake_req_count, 1);
    kc_keycloak_shutdown();
    assert_int_equal(group_calls, 1);                 /* answered inside shutdown */
    assert_int_equal(last_result, KC_TOKEN_ERROR);

    assert_int_equal(kc_keycloak_init(&b), 0);
    assert_int_equal(kc_user_get_repr("u-1", repr_cb, NULL), 0);
    assert_int_equal(fake_req_count, 2);
    assert_non_null(strstr(fake_reqs[1].url, "http://kc-b/realms/rb/"));
    assert_int_equal(repr_calls, 0);
}

/* B's waiters and B's refresh are untouched by A's late answer: the op
 * still waits, a second op queues behind B's refresh instead of starting
 * another one, and B's token is what the admin requests carry. */
static void stale_refresh_then_b_answers(void)
{
    assert_int_equal(repr_calls, 0);
    assert_null(kc_token_cached());
    assert_int_equal(kc_user_get_repr("u-2", repr_cb, NULL), 0);
    assert_int_equal(fake_req_count, 2);              /* B's refresh is still the one */

    fake_answer(1, 200, "{\"access_token\":\"new\",\"expires_in\":300}");
    assert_int_equal(fake_req_count, 4);              /* both ops' admin requests */
    assert_string_equal(fake_reqs[2].bearer, "new");
    assert_string_equal(fake_reqs[3].bearer, "new");
    assert_non_null(strstr(fake_reqs[2].url, "http://kc-b/admin/realms/rb/"));
    assert_non_null(strstr(fake_reqs[3].url, "http://kc-b/admin/realms/rb/"));
    assert_int_equal(repr_calls, 0);
}

static void test_stale_refresh_success_is_ignored(void **state)
{
    (void)state;
    stale_refresh_setup();
    fake_answer(0, 200, "{\"access_token\":\"old\",\"expires_in\":300}");
    assert_int_equal(fake_req_count, 2);              /* nothing went out on A's token */
    stale_refresh_then_b_answers();
}

static void test_stale_refresh_failure_is_ignored(void **state)
{
    (void)state;
    stale_refresh_setup();
    fake_answer(0, 401, "{\"error\":\"unauthorized_client\"}");
    assert_int_equal(fake_req_count, 2);
    stale_refresh_then_b_answers();                   /* B's op did not fail */
}

static void test_stale_refresh_after_shutdown_without_init(void **state)
{
    (void)state;
    start();
    assert_int_equal(kc_group_get_by_path("/staff", group_cb, NULL), 0);
    kc_keycloak_shutdown();
    assert_int_equal(group_calls, 1);
    assert_int_equal(last_result, KC_TOKEN_ERROR);
    fake_answer_token(0);
    assert_null(kc_token_cached());                   /* nothing installed */
    assert_int_equal(fake_req_count, 1);
    assert_int_equal(group_calls, 1);
}

/* While the first waiter's admin request is submitted (request 1), an op
 * starts: the token just installed expires inside the refresh margin, so
 * the op queues and a refresh goes out (request 2), and that refresh
 * finishes before the submit returns (its op's admin request: 3). */
static void nested_refresh_hook(int idx)
{
    if (idx != 1)
        return;
    assert_int_equal(kc_user_get_repr("u-3", repr_cb, NULL), 0);
    assert_int_equal(fake_req_count, 3);
    fake_answer(2, 200, "{\"access_token\":\"new\",\"expires_in\":300}");
}

/* That nested refresh replaces (and frees) the token the outer waiter loop
 * was handing out: the waiters after it get the current token. */
static void test_nested_refresh_hands_out_the_current_token(void **state)
{
    (void)state;
    start();
    assert_int_equal(kc_user_get_repr("u-1", repr_cb, NULL), 0);
    assert_int_equal(kc_user_get_repr("u-2", repr_cb, NULL), 0);
    assert_int_equal(fake_req_count, 1);
    fake_on_request = nested_refresh_hook;
    fake_answer(0, 200, "{\"access_token\":\"short\",\"expires_in\":30}");
    fake_on_request = NULL;
    assert_int_equal(fake_req_count, 5);
    assert_string_equal(fake_reqs[1].bearer, "short");   /* the first waiter */
    assert_string_equal(fake_reqs[2].bearer, "");        /* the nested refresh */
    assert_string_equal(fake_reqs[3].bearer, "new");     /* the nested op */
    assert_string_equal(fake_reqs[4].bearer, "new");     /* the second waiter */
    assert_non_null(kc_token_cached());
    assert_string_equal(kc_token_cached()->access_token, "new");
    assert_int_equal(repr_calls, 0);
}

/* ---- The client's own credentials in form bodies ---- */

static void test_client_credentials_are_form_encoded(void **state)
{
    struct kc_config cfg = { "http://kc", "r", "my cid", "a&b%c+d e", 0 };
    const char *creds = "client_id=my%20cid&client_secret=a%26b%25c%2Bd%20e";
    char want[512];

    (void)state;
    assert_int_equal(kc_keycloak_init(&cfg), 0);

    assert_int_equal(kc_user_get_repr("u-1", repr_cb, NULL), 0);
    snprintf(want, sizeof(want), "grant_type=client_credentials&%s", creds);
    assert_string_equal(fake_reqs[0].body, want);

    assert_int_equal(kc_user_verify_password("u", "p", grant_cb, NULL), 0);
    snprintf(want, sizeof(want),
             "grant_type=password&scope=openid&%s&username=u&password=p", creds);
    assert_string_equal(fake_reqs[1].body, want);

    assert_int_equal(kc_token_introspect("tok", introspect_cb, NULL), 0);
    snprintf(want, sizeof(want), "token=tok&%s", creds);
    assert_string_equal(fake_reqs[2].body, want);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_timeout_defaults_to_10s, setup, teardown),
        cmocka_unit_test_setup_teardown(test_timeout_negative_is_default, setup, teardown),
        cmocka_unit_test_setup_teardown(test_timeout_setting_reaches_every_request, setup, teardown),
        cmocka_unit_test_setup_teardown(test_grant_disabled_carries_reason, setup, teardown),
        cmocka_unit_test_setup_teardown(test_grant_wrong_password_carries_reason, setup, teardown),
        cmocka_unit_test_setup_teardown(test_grant_not_set_up_carries_reason, setup, teardown),
        cmocka_unit_test_setup_teardown(test_grant_success_has_no_reason, setup, teardown),
        cmocka_unit_test_setup_teardown(test_grant_client_refused, setup, teardown),
        cmocka_unit_test_setup_teardown(test_grant_no_description_has_no_reason, setup, teardown),
        cmocka_unit_test_setup_teardown(test_grant_html_400_is_transport_error, setup, teardown),
        cmocka_unit_test_setup_teardown(test_grant_502_is_transport_error, setup, teardown),
        cmocka_unit_test_setup_teardown(test_grant_no_answer_is_transport_error, setup, teardown),
        cmocka_unit_test_setup_teardown(test_grant_200_without_token_is_invalid, setup, teardown),
        cmocka_unit_test_setup_teardown(test_grant_error_without_description_has_null_reason, setup, teardown),
        cmocka_unit_test_setup_teardown(test_grant_very_long_description, setup, teardown),
        cmocka_unit_test_setup_teardown(test_group_by_path_found, setup, teardown),
        cmocka_unit_test_setup_teardown(test_group_by_path_missing, setup, teardown),
        cmocka_unit_test_setup_teardown(test_group_by_path_not_an_object_is_error, setup, teardown),
        cmocka_unit_test_setup_teardown(test_group_by_path_without_id_is_invalid, setup, teardown),
        cmocka_unit_test_setup_teardown(test_group_by_path_needs_leading_slash, setup, teardown),
        cmocka_unit_test_setup_teardown(test_group_by_path_token_failure, setup, teardown),
        cmocka_unit_test_setup_teardown(test_user_repr_found, setup, teardown),
        cmocka_unit_test_setup_teardown(test_user_repr_missing, setup, teardown),
        cmocka_unit_test_setup_teardown(test_user_repr_token_failure, setup, teardown),
        cmocka_unit_test_setup_teardown(test_user_repr_other_status_is_error, setup, teardown),
        cmocka_unit_test_setup_teardown(test_stale_refresh_success_is_ignored, setup, teardown),
        cmocka_unit_test_setup_teardown(test_stale_refresh_failure_is_ignored, setup, teardown),
        cmocka_unit_test_setup_teardown(test_stale_refresh_after_shutdown_without_init, setup, teardown),
        cmocka_unit_test_setup_teardown(test_nested_refresh_hands_out_the_current_token, setup, teardown),
        cmocka_unit_test_setup_teardown(test_client_credentials_are_form_encoded, setup, teardown),
    };

    return cmocka_run_group_tests_name("kc_keycloak", tests, NULL, NULL);
}
