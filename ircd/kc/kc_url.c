/*
 * kc_url.c - Keycloak endpoint URL builders for libkc
 *
 * Ported from X3's keycloak.c endpoint builders (lines 194-367).
 * Uses snprintf(NULL,0) + malloc + snprintf pattern for exact allocation.
 *
 * Changes from X3:
 *   - realm.base_uri → realm.base_url (libkc naming)
 *   - log_module() → kc_log_debug() / kc_log_error()
 *   - kc_build_*_endpoint() → kc_url_*()
 *   - Added: kc_url_token(), kc_url_introspect(), kc_url_jwks(),
 *     kc_url_user_groups(), kc_url_user_reset_password() (from libkc's kc_keycloak.c)
 */

#include <kc/kc.h>
#include <kc/kc_url.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>  /* for curl_easy_escape / curl_free in group_by_path */

/*
 * =============================================================================
 * OIDC Protocol Endpoints
 * =============================================================================
 */

char *
kc_url_token(struct kc_realm r)
{
    static const char tmpl[] = "%s/realms/%s/protocol/openid-connect/token";
    if (!r.base_url || !r.realm) return NULL;

    int len = snprintf(NULL, 0, tmpl, r.base_url, r.realm) + 1;
    char *uri = malloc(len);
    if (uri) snprintf(uri, len, tmpl, r.base_url, r.realm);
    return uri;
}

char *
kc_url_introspect(struct kc_realm r)
{
    /* Keycloak serves introspection under the token endpoint; the bare
     * .../openid-connect/introspect answers 405 with a JSON body. */
    static const char tmpl[] = "%s/realms/%s/protocol/openid-connect/token/introspect";
    if (!r.base_url || !r.realm) return NULL;

    int len = snprintf(NULL, 0, tmpl, r.base_url, r.realm) + 1;
    char *uri = malloc(len);
    if (uri) snprintf(uri, len, tmpl, r.base_url, r.realm);
    return uri;
}

char *
kc_url_jwks(struct kc_realm r)
{
    static const char tmpl[] = "%s/realms/%s/protocol/openid-connect/certs";
    if (!r.base_url || !r.realm) return NULL;

    int len = snprintf(NULL, 0, tmpl, r.base_url, r.realm) + 1;
    char *uri = malloc(len);
    if (uri) snprintf(uri, len, tmpl, r.base_url, r.realm);
    return uri;
}

/*
 * =============================================================================
 * Admin REST API: Users
 * =============================================================================
 */

char *
kc_url_users(struct kc_realm r)
{
    static const char tmpl[] = "%s/admin/realms/%s/users";
    if (!r.base_url || !r.realm) return NULL;

    int len = snprintf(NULL, 0, tmpl, r.base_url, r.realm) + 1;
    char *uri = malloc(len);
    if (uri) snprintf(uri, len, tmpl, r.base_url, r.realm);
    return uri;
}

char *
kc_url_user(struct kc_realm r, const char *user_id)
{
    static const char tmpl[] = "%s/admin/realms/%s/users/%s";
    if (!r.base_url || !r.realm || !user_id) return NULL;

    int len = snprintf(NULL, 0, tmpl, r.base_url, r.realm, user_id) + 1;
    char *uri = malloc(len);
    if (uri) snprintf(uri, len, tmpl, r.base_url, r.realm, user_id);
    return uri;
}

char *
kc_url_user_by_username(struct kc_realm r, const char *escaped_username, int exact)
{
    static const char tmpl[] = "%s/admin/realms/%s/users/?username=%s%s";
    static const char exact_suffix[] = "&exact=true";
    if (!r.base_url || !r.realm || !escaped_username) return NULL;

    const char *suffix = exact ? exact_suffix : "";
    int len = snprintf(NULL, 0, tmpl, r.base_url, r.realm, escaped_username, suffix) + 1;
    char *uri = malloc(len);
    if (uri) snprintf(uri, len, tmpl, r.base_url, r.realm, escaped_username, suffix);
    return uri;
}

char *
kc_url_user_groups(struct kc_realm r, const char *user_id)
{
    static const char tmpl[] = "%s/admin/realms/%s/users/%s/groups";
    if (!r.base_url || !r.realm || !user_id) return NULL;

    int len = snprintf(NULL, 0, tmpl, r.base_url, r.realm, user_id) + 1;
    char *uri = malloc(len);
    if (uri) snprintf(uri, len, tmpl, r.base_url, r.realm, user_id);
    return uri;
}

char *
kc_url_user_group(struct kc_realm r, const char *user_id, const char *group_id)
{
    static const char tmpl[] = "%s/admin/realms/%s/users/%s/groups/%s";
    if (!r.base_url || !r.realm || !user_id || !group_id) return NULL;

    int len = snprintf(NULL, 0, tmpl, r.base_url, r.realm, user_id, group_id) + 1;
    char *uri = malloc(len);
    if (uri) snprintf(uri, len, tmpl, r.base_url, r.realm, user_id, group_id);
    return uri;
}

char *
kc_url_user_reset_password(struct kc_realm r, const char *user_id)
{
    static const char tmpl[] = "%s/admin/realms/%s/users/%s/reset-password";
    if (!r.base_url || !r.realm || !user_id) return NULL;

    int len = snprintf(NULL, 0, tmpl, r.base_url, r.realm, user_id) + 1;
    char *uri = malloc(len);
    if (uri) snprintf(uri, len, tmpl, r.base_url, r.realm, user_id);
    return uri;
}

char *
kc_url_user_send_verify_email(struct kc_realm r, const char *user_id)
{
    static const char tmpl[] = "%s/admin/realms/%s/users/%s/send-verify-email";
    if (!r.base_url || !r.realm || !user_id) return NULL;

    int len = snprintf(NULL, 0, tmpl, r.base_url, r.realm, user_id) + 1;
    char *uri = malloc(len);
    if (uri) snprintf(uri, len, tmpl, r.base_url, r.realm, user_id);
    return uri;
}

/*
 * =============================================================================
 * Admin REST API: Groups
 * =============================================================================
 */

char *
kc_url_groups(struct kc_realm r)
{
    static const char tmpl[] = "%s/admin/realms/%s/groups";
    if (!r.base_url || !r.realm) return NULL;

    int len = snprintf(NULL, 0, tmpl, r.base_url, r.realm) + 1;
    char *uri = malloc(len);
    if (uri) snprintf(uri, len, tmpl, r.base_url, r.realm);
    return uri;
}

char *
kc_url_group(struct kc_realm r, const char *group_id)
{
    static const char tmpl[] = "%s/admin/realms/%s/groups/%s";
    if (!r.base_url || !r.realm || !group_id) return NULL;

    int len = snprintf(NULL, 0, tmpl, r.base_url, r.realm, group_id) + 1;
    char *uri = malloc(len);
    if (uri) snprintf(uri, len, tmpl, r.base_url, r.realm, group_id);
    return uri;
}

char *
kc_url_group_members(struct kc_realm r, const char *group_id)
{
    static const char tmpl[] = "%s/admin/realms/%s/groups/%s/members?max=1000";
    if (!r.base_url || !r.realm || !group_id) return NULL;

    int len = snprintf(NULL, 0, tmpl, r.base_url, r.realm, group_id) + 1;
    char *uri = malloc(len);
    if (uri) snprintf(uri, len, tmpl, r.base_url, r.realm, group_id);
    return uri;
}

char *
kc_url_group_children(struct kc_realm r, const char *parent_id)
{
    static const char tmpl[] = "%s/admin/realms/%s/groups/%s/children";
    if (!r.base_url || !r.realm || !parent_id) return NULL;

    int len = snprintf(NULL, 0, tmpl, r.base_url, r.realm, parent_id) + 1;
    char *uri = malloc(len);
    if (uri) snprintf(uri, len, tmpl, r.base_url, r.realm, parent_id);
    return uri;
}

char *
kc_url_group_by_path(struct kc_realm r, const char *path)
{
    static const char tmpl[] = "%s/admin/realms/%s/group-by-path%s";
    if (!r.base_url || !r.realm || !path) return NULL;

    /* URL-encode the path — especially important for # which is a URL fragment delimiter */
    char *encoded_path = curl_easy_escape(NULL, path, 0);
    if (!encoded_path) {
        kc_log_error("kc_url_group_by_path: curl_easy_escape returned NULL for '%s'", path);
        return NULL;
    }

    kc_log_debug("kc_url_group_by_path: BEFORE %%2F fix: raw='%s'", encoded_path);

    /* curl_easy_escape encodes / as %2F, but we need literal slashes in the path */
    char *p = encoded_path;
    char *w = encoded_path;
    while (*p) {
        if (p[0] == '%' && p[1] == '2' && (p[2] == 'F' || p[2] == 'f')) {
            *w++ = '/';
            p += 3;
        } else {
            *w++ = *p++;
        }
    }
    *w = '\0';

    kc_log_debug("kc_url_group_by_path: AFTER %%2F fix: encoded='%s'", encoded_path);

    int len = snprintf(NULL, 0, tmpl, r.base_url, r.realm, encoded_path) + 1;
    char *uri = malloc(len);
    if (uri) snprintf(uri, len, tmpl, r.base_url, r.realm, encoded_path);

    kc_log_debug("kc_url_group_by_path: FINAL uri='%s'", uri ? uri : "(null)");

    curl_free(encoded_path);
    return uri;
}

char *
kc_url_group_search(struct kc_realm r, const char *escaped_name)
{
    static const char tmpl[] = "%s/admin/realms/%s/groups?search=%s&exact=true";
    if (!r.base_url || !r.realm || !escaped_name) return NULL;

    int len = snprintf(NULL, 0, tmpl, r.base_url, r.realm, escaped_name) + 1;
    char *uri = malloc(len);
    if (uri) snprintf(uri, len, tmpl, r.base_url, r.realm, escaped_name);
    return uri;
}

/*
 * =============================================================================
 * Admin REST API: Search
 * =============================================================================
 */

char *
kc_url_fingerprint_search(struct kc_realm r, const char *escaped_fingerprint)
{
    static const char tmpl[] = "%s/admin/realms/%s/users?q=x509_fingerprints:%s";
    if (!r.base_url || !r.realm || !escaped_fingerprint) return NULL;

    int len = snprintf(NULL, 0, tmpl, r.base_url, r.realm, escaped_fingerprint) + 1;
    char *uri = malloc(len);
    if (uri) snprintf(uri, len, tmpl, r.base_url, r.realm, escaped_fingerprint);
    return uri;
}

/*
 * =============================================================================
 * Location header: the user a create answer names
 * =============================================================================
 */

int
kc_url_is_uuid(const char *s, size_t len)
{
    size_t i;

    if (!s || len != 36)
        return 0;
    for (i = 0; i < 36; i++) {
        char c = s[i];
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (c != '-')
                return 0;
        } else if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
                     || (c >= 'A' && c <= 'F')))
            return 0;
    }
    return 1;
}

/* Case-insensitive equality of n bytes (ASCII). */
static int
same_ci(const char *a, const char *b, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) {
        char x = a[i], y = b[i];
        if (x >= 'A' && x <= 'Z') x = (char)(x - 'A' + 'a');
        if (y >= 'A' && y <= 'Z') y = (char)(y - 'A' + 'a');
        if (x != y)
            return 0;
    }
    return 1;
}

int
kc_url_location_user_id(const char *location, const char *users_url,
                        char *out, size_t out_size)
{
    const char *path, *rest, *scheme;
    size_t ulen, origin_len, llen;

    if (out && out_size)
        out[0] = '\0';
    if (!location || !users_url || !out || out_size < 37)
        return 0;

    /* users_url = <scheme>://<host[:port]><path>, its path never ending
     * in '/' (kc_url_users()); one trailing '/' is tolerated. */
    ulen = strlen(users_url);
    if (ulen && users_url[ulen - 1] == '/')
        ulen--;
    scheme = strstr(users_url, "://");
    if (!scheme || (size_t)(scheme - users_url) >= ulen)
        return 0;
    path = strchr(scheme + 3, '/');
    if (!path || (size_t)(path - users_url) >= ulen)
        return 0;
    origin_len = (size_t)(path - users_url);

    /* The same origin (scheme and host compared without case) and path,
     * or the path alone (an absolute-path reference). */
    llen = strlen(location);
    if (location[0] == '/') {
        size_t plen = ulen - origin_len;
        if (llen < plen || memcmp(location, path, plen) != 0)
            return 0;
        rest = location + plen;
    } else {
        if (llen < ulen || !same_ci(location, users_url, origin_len)
            || memcmp(location + origin_len, path, ulen - origin_len) != 0)
            return 0;
        rest = location + ulen;
    }

    /* Then "/<uuid>" and nothing after it. */
    if (rest[0] != '/' || strlen(rest + 1) != 36 || !kc_url_is_uuid(rest + 1, 36))
        return 0;
    memcpy(out, rest + 1, 36);
    out[36] = '\0';
    return 1;
}

void
kc_location_capture_line(struct kc_location_capture *c, const char *line,
                         size_t len)
{
    static const char name[] = "location:";
    size_t i, start, end;
    char *value;

    if (!c || !line)
        return;

    /* A status line starts a response's header block: an interim one (100
     * Continue) or a redirect's is forgotten with what it said. */
    if (len >= 5 && memcmp(line, "HTTP/", 5) == 0) {
        kc_location_capture_free(c);
        c->in_block = 1;
        return;
    }
    /* The empty line ends the block; anything after it and before another
     * status line is a trailer, which never names the resource. */
    if (len == 0 || (len <= 2 && (line[0] == '\r' || line[0] == '\n'))) {
        c->in_block = 0;
        return;
    }
    if (!c->in_block || len < sizeof(name) - 1)
        return;
    for (i = 0; i < sizeof(name) - 1; i++) {
        char ch = line[i];
        if (ch >= 'A' && ch <= 'Z')
            ch = (char)(ch - 'A' + 'a');
        if (ch != name[i])
            return;
    }

    /* More than one Location in a block names nothing for certain. */
    if (++c->seen > 1) {
        free(c->value);
        c->value = NULL;
        return;
    }

    start = sizeof(name) - 1;
    end = len;
    while (start < end && (line[start] == ' ' || line[start] == '\t'))
        start++;
    while (end > start && (line[end - 1] == '\r' || line[end - 1] == '\n'
                           || line[end - 1] == ' ' || line[end - 1] == '\t'))
        end--;
    if (end == start || end - start > 4096)
        return;                 /* empty, or no URL: none */
    value = malloc(end - start + 1);
    if (!value)
        return;
    memcpy(value, line + start, end - start);
    value[end - start] = '\0';
    c->value = value;
}

void
kc_location_capture_free(struct kc_location_capture *c)
{
    if (!c)
        return;
    free(c->value);
    c->value = NULL;
    c->seen = 0;
}

void
kc_url_log_safe(const char *in, char *out, size_t out_size)
{
    size_t n = 0, cap;

    if (!out || !out_size)
        return;
    if (!in)
        in = "(none)";
    cap = out_size - 1;
    while (*in && n < cap) {
        unsigned char ch = (unsigned char)*in++;
        out[n++] = (ch >= 0x20 && ch < 0x7f) ? (char)ch : '?';
    }
    if (*in && cap >= 3)        /* cut: say so */
        out[cap - 3] = out[cap - 2] = out[cap - 1] = '.';
    out[n] = '\0';
}
