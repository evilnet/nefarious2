#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <jansson.h>
#include "kc/kc_keycloak.h"
#include "kc/kc_error_classify.h"

static void check(long status, const char *body, int expect) {
    json_t *j = json_loads(body, 0, NULL);
    assert_non_null(j);
    assert_int_equal(kc_classify_grant_error(status, j), expect);
    json_decref(j);
}

/* A body that is not JSON at all (an HTML error page, an empty body):
 * the HTTP layer hands the classifier no json. */
static void check_null_json(long status, int expect) {
    assert_int_equal(kc_classify_grant_error(status, NULL), expect);
}

/* A password grant's refusal, as Keycloak's token endpoint answers it:
 * {"error": ..., "error_description": ...}.  The bodies are the ones
 * Keycloak 26 sends (wrong password, disabled account, pending required
 * action, a wrong client secret were observed on the test bed). */
static void test_classify(void **state) {
    (void)state;
    check(401, "{\"error\":\"invalid_grant\",\"error_description\":\"Invalid user credentials\"}", KC_FORBIDDEN);
    check(400, "{\"error\":\"invalid_grant\",\"error_description\":\"Account disabled\"}", KC_DISABLED);
    check(400, "{\"error\":\"invalid_grant\",\"error_description\":\"Account is not fully set up\"}", KC_UNVERIFIED);
    check(401, "{\"error\":\"invalid_client\",\"error_description\":\"Invalid client or Invalid client credentials\"}", KC_CLIENT_REFUSED);
    check(400, "{\"error\":\"unauthorized_client\",\"error_description\":\"Client not allowed for direct access grants\"}", KC_CLIENT_REFUSED);
    check(401, "{\"error\":\"unauthorized_client\",\"error_description\":\"Invalid client or Invalid client credentials\"}", KC_CLIENT_REFUSED);  /* wrong client secret, Keycloak 26.4 */
    check(400, "{\"error\":\"invalid_grant\"}", KC_FORBIDDEN);            /* no description */
    check(400, "{\"error\":\"invalid_grant\",\"error_description\":42}", KC_FORBIDDEN);
    check(401, "{\"message\":\"nope\"}", KC_ERROR);                      /* not a Keycloak error object */
    check_null_json(400, KC_ERROR);                                      /* HTML or empty body */

    /* the descriptions are matched case-insensitively */
    check(400, "{\"error\":\"invalid_grant\",\"error_description\":\"ACCOUNT IS NOT FULLY SET UP\"}", KC_UNVERIFIED);
    check(400, "{\"error\":\"invalid_grant\",\"error_description\":\"Account DISABLED\"}", KC_DISABLED);
    /* a description with no "error" is not a Keycloak error object */
    check(400, "{\"error_description\":\"ACCOUNT IS NOT FULLY SET UP\"}", KC_ERROR);
    check(400, "[1,2]", KC_ERROR);                                     /* non-object */
    /* an error object under a status that is no refusal of the credentials */
    check(503, "{\"error\":\"temporarily_unavailable\"}", KC_ERROR);
}

static void create(long status, const char *body, int expect) {
    json_t *j = body ? json_loads(body, 0, NULL) : NULL;
    if (body)
        assert_non_null(j);
    assert_int_equal(kc_classify_create_error(status, j), expect);
    if (j) json_decref(j);
}

/* A user create's refusal, in the shapes Keycloak 2x's admin API answers:
 * user-profile validation names the attribute in "field" (alone, or
 * several under "errors"); the duplicate check answers 409 with
 * "errorMessage"; a credential or password-policy refusal answers
 * "errorMessage" or "error"/"error_description" with no field. */
static void test_classify_create(void **state) {
    (void)state;
    /* 409: which one exists */
    create(409, "{\"errorMessage\":\"User exists with same username\"}", KC_CONFLICT);
    create(409, "{\"errorMessage\":\"User exists with same email\"}", KC_CONFLICT_EMAIL);
    create(409, "{\"errorMessage\":\"User exists with same username or email\"}", KC_CONFLICT);
    create(409, "{\"field\":\"email\",\"errorMessage\":\"emailExistsMessage\"}", KC_CONFLICT_EMAIL);
    create(409, "{\"field\":\"username\",\"errorMessage\":\"usernameExistsMessage\"}", KC_CONFLICT);
    create(409, NULL, KC_CONFLICT);
    create(409, "{}", KC_CONFLICT);

    /* 400 with a field: the field decides */
    create(400, "{\"field\":\"username\",\"errorMessage\":\"error-username-invalid-character\","
                "\"params\":[\"username\",\"victim{\"]}", KC_BAD_USERNAME);
    create(400, "{\"field\":\"username\",\"errorMessage\":\"error-invalid-length\","
                "\"params\":[\"username\",3,255]}", KC_BAD_USERNAME);
    create(400, "{\"field\":\"email\",\"errorMessage\":\"invalidEmailMessage\","
                "\"params\":[\"email\"]}", KC_BAD_EMAIL);
    create(400, "{\"field\":\"email\",\"errorMessage\":\"error-invalid-email\"}", KC_BAD_EMAIL);
    /* ... a field that is not ours names nothing, whatever its message says */
    create(400, "{\"field\":\"firstName\",\"errorMessage\":\"error-username-like\"}", KC_REJECTED);
    create(400, "{\"field\":\"firstName\",\"errorMessage\":\"error-invalid-length\"}", KC_REJECTED);

    /* 400 with no field: the message, the password first */
    create(400, "{\"errorMessage\":\"Password policy not met\"}", KC_BAD_PASSWORD);
    create(400, "{\"error\":\"invalidPasswordNotUsernameMessage\","
                "\"error_description\":\"Invalid password: must not be equal to the username.\"}",
           KC_BAD_PASSWORD);
    create(400, "{\"error\":\"invalidPasswordNotEmailMessage\","
                "\"error_description\":\"Invalid password: must not be equal to the email.\"}",
           KC_BAD_PASSWORD);
    create(400, "{\"error\":\"invalidPasswordMinLengthMessage\","
                "\"error_description\":\"Invalid password: minimum length 8.\"}", KC_BAD_PASSWORD);
    create(400, "{\"errorMessage\":\"Invalid credential\"}", KC_BAD_PASSWORD);
    create(400, "{\"errorMessage\":\"invalidEmailMessage\"}", KC_BAD_EMAIL);
    create(400, "{\"errorMessage\":\"invalidUsernameMessage\"}", KC_BAD_USERNAME);

    /* several errors: the account name, then the email, then the password */
    create(400, "{\"errors\":[{\"field\":\"email\",\"errorMessage\":\"invalidEmailMessage\"},"
                "{\"field\":\"username\",\"errorMessage\":\"error-username-invalid-character\"}]}",
           KC_BAD_USERNAME);
    create(400, "{\"errors\":[{\"errorMessage\":\"Password policy not met\"},"
                "{\"field\":\"email\",\"errorMessage\":\"error-invalid-email\"}]}", KC_BAD_EMAIL);
    create(400, "{\"errors\":[{\"field\":\"email\",\"errorMessage\":\"error-invalid-email\"}]}",
           KC_BAD_EMAIL);

    /* nothing it can name */
    create(400, "{\"errorMessage\":\"Cannot parse the JSON\"}", KC_REJECTED);
    create(400, NULL, KC_REJECTED);
    create(400, "[1]", KC_REJECTED);

    /* not a refusal of what was sent */
    create(500, "{\"field\":\"username\"}", KC_ERROR);
    create(503, NULL, KC_ERROR);
    create(401, NULL, KC_ERROR);
    create(403, "{\"error\":\"unknown_error\"}", KC_ERROR);
}

int main(void) {
    const struct CMUnitTest tests[] = { cmocka_unit_test(test_classify),
                                        cmocka_unit_test(test_classify_create) };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
