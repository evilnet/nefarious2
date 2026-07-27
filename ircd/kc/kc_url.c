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
    static const char tmpl[] = "%s/realms/%s/protocol/openid-connect/introspect";
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
