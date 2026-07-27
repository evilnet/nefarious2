/*
 * kc_cache_cmocka.c - unit tests for the vendored libkc caches.
 * kc_cache.c uses the kc_log_* macros; stub kc_get_log_ops as in
 * kc_url_cmocka.c.  jansson is required for the representation cache.
 */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <string.h>
#include <jansson.h>

#include <kc/kc_log.h>
#include <kc/kc_cache.h>

const struct kc_log_ops *kc_get_log_ops(void);
const struct kc_log_ops *kc_get_log_ops(void) { return NULL; }

static int setup(void **state) { (void)state; kc_cache_init(); return 0; }
static int teardown(void **state) { (void)state; kc_cache_cleanup(); return 0; }

static void test_userid_put_get(void **state) {
    (void)state;
    kc_userid_cache_put("alice", "uuid-alice");
    const char *got = kc_userid_cache_get("alice");
    assert_non_null(got);
    assert_string_equal(got, "uuid-alice");
}

static void test_userid_miss_returns_null(void **state) {
    (void)state;
    assert_null(kc_userid_cache_get("nobody"));
}

/* Nick comparison in IRC is case-insensitive; kc_cache.c includes
 * <strings.h> for strcasecmp, so a case-varied lookup must hit. */
static void test_userid_lookup_is_case_insensitive(void **state) {
    (void)state;
    kc_userid_cache_put("Alice", "uuid-alice");
    const char *got = kc_userid_cache_get("alice");
    assert_non_null(got);
    assert_string_equal(got, "uuid-alice");
}

static void test_userid_put_overwrites(void **state) {
    (void)state;
    kc_userid_cache_put("bob", "uuid-old");
    kc_userid_cache_put("bob", "uuid-new");
    assert_string_equal(kc_userid_cache_get("bob"), "uuid-new");
}

static void test_userid_remove(void **state) {
    (void)state;
    kc_userid_cache_put("carol", "uuid-carol");
    kc_userid_cache_remove("carol");
    assert_null(kc_userid_cache_get("carol"));
}

static void test_stats_count_hits_and_misses(void **state) {
    (void)state;
    struct kc_cache_stats before, after;
    kc_cache_stats_get(&before);

    kc_userid_cache_put("dave", "uuid-dave");
    (void)kc_userid_cache_get("dave");      /* hit */
    (void)kc_userid_cache_get("nobody2");   /* miss */

    kc_cache_stats_get(&after);
    assert_int_equal(after.user_cache_hits,   before.user_cache_hits + 1);
    assert_int_equal(after.user_cache_misses, before.user_cache_misses + 1);
}

/* The repr cache must deep-copy: mutating the caller's object afterwards
 * must not change what the cache holds. */
static void test_repr_cache_deep_copies(void **state) {
    (void)state;
    json_t *repr = json_pack("{s:s}", "username", "erin");
    kc_user_repr_cache_put("uuid-erin", repr);
    json_object_set_new(repr, "username", json_string("mallory"));

    json_t *cached = kc_user_repr_cache_get("uuid-erin");
    assert_non_null(cached);
    assert_string_equal(json_string_value(json_object_get(cached, "username")),
                        "erin");
    json_decref(repr);
}

/* Credentials must never be retained in the cache. */
static void test_repr_cache_strips_credentials(void **state) {
    (void)state;
    json_t *repr = json_pack("{s:s, s:[{s:s}]}",
                             "username", "frank",
                             "credentials", "value", "hunter2");
    kc_user_repr_cache_put("uuid-frank", repr);
    json_decref(repr);

    json_t *cached = kc_user_repr_cache_get("uuid-frank");
    assert_non_null(cached);
    assert_null(json_object_get(cached, "credentials"));
}

static void test_repr_cache_remove(void **state) {
    (void)state;
    json_t *repr = json_pack("{s:s}", "username", "grace");
    kc_user_repr_cache_put("uuid-grace", repr);
    json_decref(repr);
    kc_user_repr_cache_remove("uuid-grace");
    assert_null(kc_user_repr_cache_get("uuid-grace"));
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_userid_put_get, setup, teardown),
        cmocka_unit_test_setup_teardown(test_userid_miss_returns_null, setup, teardown),
        cmocka_unit_test_setup_teardown(test_userid_lookup_is_case_insensitive, setup, teardown),
        cmocka_unit_test_setup_teardown(test_userid_put_overwrites, setup, teardown),
        cmocka_unit_test_setup_teardown(test_userid_remove, setup, teardown),
        cmocka_unit_test_setup_teardown(test_stats_count_hits_and_misses, setup, teardown),
        cmocka_unit_test_setup_teardown(test_repr_cache_deep_copies, setup, teardown),
        cmocka_unit_test_setup_teardown(test_repr_cache_strips_credentials, setup, teardown),
        cmocka_unit_test_setup_teardown(test_repr_cache_remove, setup, teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
