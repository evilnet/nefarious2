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
    long timeout_ms;
};

static struct fake_req fake_reqs[FAKE_REQ_MAX];
static int fake_req_count;
static kc_http_callback fake_cbs[FAKE_REQ_MAX];
static void *fake_cb_data[FAKE_REQ_MAX];

int kc_http_request(const struct kc_http_request *req,
                    kc_http_callback cb, void *data)
{
    struct fake_req *r;
    const char *method = req->method ? req->method : "GET";

    assert_true(fake_req_count < FAKE_REQ_MAX);
    r = &fake_reqs[fake_req_count];

    /* A field too long for its buffer fails the test rather than being
     * compared truncated. */
    assert_true(strlen(req->url) < sizeof(r->url));
    assert_true(strlen(method) < sizeof(r->method));
    assert_true(req->body_len < sizeof(r->body));

    strcpy(r->url, req->url);
    strcpy(r->method, method);
    if (req->body)
        memcpy(r->body, req->body, req->body_len);
    r->body[req->body_len] = '\0';
    r->timeout_ms = req->timeout_ms;

    fake_cbs[fake_req_count] = cb;
    fake_cb_data[fake_req_count] = data;
    fake_req_count++;
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
}

/* ---- Callbacks ---- */

/* The password grant's answer: the result, a copy of the reason ("" for
 * NULL; the pointer is only valid during the call), and how many answers
 * came. */
static int last_result;
static char last_reason[256];
static int grant_calls;

static void grant_cb(int result, const struct kc_access_token *token,
                     const char *reason, void *data)
{
    (void)data;
    grant_calls++;
    last_result = result;
    assert_true(!reason || strlen(reason) < sizeof(last_reason));
    strcpy(last_reason, reason ? reason : "");
    if (result == KC_SUCCESS)
        assert_non_null(token);
    else
        assert_null(token);
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
        cmocka_unit_test_setup_teardown(test_group_by_path_found, setup, teardown),
        cmocka_unit_test_setup_teardown(test_group_by_path_missing, setup, teardown),
        cmocka_unit_test_setup_teardown(test_group_by_path_not_an_object_is_error, setup, teardown),
        cmocka_unit_test_setup_teardown(test_group_by_path_needs_leading_slash, setup, teardown),
        cmocka_unit_test_setup_teardown(test_group_by_path_token_failure, setup, teardown),
        cmocka_unit_test_setup_teardown(test_user_repr_found, setup, teardown),
        cmocka_unit_test_setup_teardown(test_user_repr_missing, setup, teardown),
        cmocka_unit_test_setup_teardown(test_user_repr_token_failure, setup, teardown),
        cmocka_unit_test_setup_teardown(test_user_repr_other_status_is_error, setup, teardown),
    };

    return cmocka_run_group_tests_name("kc_keycloak", tests, NULL, NULL);
}
