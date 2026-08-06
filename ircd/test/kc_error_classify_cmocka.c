#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <jansson.h>
#include "kc/kc_keycloak.h"
#include "kc/kc_error_classify.h"

static void check(const char *body, int expect) {
    json_t *j = body ? json_loads(body, 0, NULL) : NULL;
    assert_int_equal(kc_classify_grant_error(j), expect);
    if (j) json_decref(j);
}

static void test_classify(void **state) {
    check("{\"error\":\"invalid_grant\",\"error_description\":\"Account is not fully set up\"}", KC_UNVERIFIED);
    check("{\"error\":\"invalid_grant\",\"error_description\":\"Invalid user credentials\"}", KC_FORBIDDEN);
    check("{\"error\":\"invalid_grant\"}", KC_FORBIDDEN);      /* no description */
    check("{\"error_description\":\"ACCOUNT IS NOT FULLY SET UP\"}", KC_UNVERIFIED); /* case-insensitive */
    check(NULL, KC_FORBIDDEN);
    check("[1,2]", KC_FORBIDDEN);                              /* non-object */
}

int main(void) {
    const struct CMUnitTest tests[] = { cmocka_unit_test(test_classify) };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
