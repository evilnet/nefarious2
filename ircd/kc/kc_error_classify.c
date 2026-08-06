/* kc_error_classify.c -- classify a ROPC grant-error body. Pure, boundary
 * clean (see kc_error_classify.h). */
#include <kc/kc_keycloak.h>
#include <kc/kc_error_classify.h>
#include <string.h>
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
