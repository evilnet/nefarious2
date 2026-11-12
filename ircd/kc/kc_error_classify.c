/* kc_error_classify.c -- classify a ROPC grant-error body. Pure, boundary
 * clean (see kc_error_classify.h). */
#include <kc/kc_keycloak.h>
#include <kc/kc_error_classify.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>

static int contains_ci(const char *haystack, const char *needle) {
    size_t nl = strlen(needle);
    for (; *haystack; haystack++)
        if (!strncasecmp(haystack, needle, nl))
            return 1;
    return 0;
}

int kc_classify_grant_error(json_t *json)
{
    json_t *desc;
    const char *s;
    if (!json || !json_is_object(json))
        return KC_FORBIDDEN;
    desc = json_object_get(json, "error_description");
    if (!desc || !json_is_string(desc))
        return KC_FORBIDDEN;
    s = json_string_value(desc);
    if (s && contains_ci(s, "not fully set up"))
        return KC_UNVERIFIED;
    return KC_FORBIDDEN;
}

/* What one error object of a create's refusal names: 3 username, 2 email,
 * 1 password or credential, 0 nothing it can name.
 *
 * Keycloak's own structure first: user-profile validation names the
 * attribute in "field" ({"field":"username","errorMessage":
 * "error-username-invalid-character","params":[...]}), and when there is
 * a field, it alone decides (an unknown one -- firstName -- names nothing
 * of ours).  Without a field the message key is read ("errorMessage", or
 * "error" / "error_description" from a credential or password-policy
 * refusal: {"errorMessage":"Password policy not met"}, {"error":
 * "invalidPasswordNotUsernameMessage","error_description":"Invalid
 * password: must not be equal to the username."}), password first: a
 * password-policy message that mentions the username is about the
 * password. */
static int create_error_names(json_t *err)
{
    static const char *const msgs[] = { "errorMessage", "error",
                                        "error_description" };
    json_t *f;
    int password = 0, email = 0, username = 0;
    size_t i;

    if (!json_is_object(err))
        return 0;
    f = json_object_get(err, "field");
    if (json_is_string(f)) {
        const char *field = json_string_value(f);
        if (!strcasecmp(field, "username"))
            return 3;
        if (!strcasecmp(field, "email"))
            return 2;
        if (contains_ci(field, "password") || contains_ci(field, "credential"))
            return 1;
        return 0;
    }
    for (i = 0; i < sizeof(msgs) / sizeof(msgs[0]); i++) {
        json_t *m = json_object_get(err, msgs[i]);
        const char *s;
        if (!json_is_string(m) || !(s = json_string_value(m)))
            continue;
        password |= contains_ci(s, "password") || contains_ci(s, "credential");
        email |= contains_ci(s, "email");
        username |= contains_ci(s, "username");
    }
    return password ? 1 : email ? 2 : username ? 3 : 0;
}

int kc_classify_create_error(long status, json_t *json)
{
    int named = 0;

    if (status == 409) {
        /* Which attribute exists: the field when the answer names one,
         * else the message ("User exists with same username" / "... same
         * email"; an older "... same username or email" is the username). */
        json_t *f = json_is_object(json) ? json_object_get(json, "field") : NULL;
        json_t *m = json_is_object(json) ? json_object_get(json, "errorMessage") : NULL;
        const char *s = json_is_string(m) ? json_string_value(m) : NULL;
        if (json_is_string(f))
            return strcasecmp(json_string_value(f), "email") ? KC_CONFLICT
                                                            : KC_CONFLICT_EMAIL;
        if (s && contains_ci(s, "email") && !contains_ci(s, "username"))
            return KC_CONFLICT_EMAIL;
        return KC_CONFLICT;
    }
    if (status != 400)
        return KC_ERROR;

    /* Several errors (an "errors" list): the account name first, then the
     * email, then the password -- the order the client would fix them. */
    if (json_is_object(json)) {
        json_t *errs = json_object_get(json, "errors");
        named = create_error_names(json);
        if (json_is_array(errs)) {
            size_t i;
            for (i = 0; i < json_array_size(errs); i++) {
                int n = create_error_names(json_array_get(errs, i));
                if (n > named)
                    named = n;
            }
        }
    }
    switch (named) {
    case 3: return KC_BAD_USERNAME;
    case 2: return KC_BAD_EMAIL;
    case 1: return KC_BAD_PASSWORD;
    default: return KC_REJECTED;
    }
}
