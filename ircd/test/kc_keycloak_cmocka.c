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

static void grant_cb(int result, const struct kc_access_token *token, void *data)
{
    (void)result; (void)token; (void)data;
}

static void user_cb(int result, const struct kc_user *user, void *data)
{
    (void)result; (void)user; (void)data;
}

/* ---- Setup / teardown ---- */

static int setup(void **state)
{
    (void)state;
    fake_reset();
    return 0;
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

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_timeout_defaults_to_10s, setup, teardown),
        cmocka_unit_test_setup_teardown(test_timeout_negative_is_default, setup, teardown),
        cmocka_unit_test_setup_teardown(test_timeout_setting_reaches_every_request, setup, teardown),
    };

    return cmocka_run_group_tests_name("kc_keycloak", tests, NULL, NULL);
}
