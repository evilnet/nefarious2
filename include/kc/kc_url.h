/*
 * kc_url.h - Keycloak endpoint URL builders for libkc
 *
 * All functions return allocated strings. Caller must free().
 * Returns NULL on invalid input (NULL realm, missing required params).
 *
 * Ported from X3's keycloak.c endpoint builders + libkc's static builders.
 */

#ifndef KC_URL_H
#define KC_URL_H

#include <stddef.h>

#include <kc/kc_realm.h>

/* OIDC protocol endpoints (no admin auth required) */
char *kc_url_token(struct kc_realm r);
char *kc_url_introspect(struct kc_realm r);
char *kc_url_jwks(struct kc_realm r);

/* Admin REST API: Users */
char *kc_url_users(struct kc_realm r);
char *kc_url_user(struct kc_realm r, const char *user_id);
char *kc_url_user_by_username(struct kc_realm r, const char *escaped_username, int exact);
char *kc_url_user_groups(struct kc_realm r, const char *user_id);
char *kc_url_user_group(struct kc_realm r, const char *user_id, const char *group_id);
char *kc_url_user_reset_password(struct kc_realm r, const char *user_id);
char *kc_url_user_send_verify_email(struct kc_realm r, const char *user_id);

/* Admin REST API: Groups */
char *kc_url_groups(struct kc_realm r);
char *kc_url_group(struct kc_realm r, const char *group_id);
char *kc_url_group_members(struct kc_realm r, const char *group_id);
char *kc_url_group_children(struct kc_realm r, const char *parent_id);
char *kc_url_group_by_path(struct kc_realm r, const char *path);
char *kc_url_group_search(struct kc_realm r, const char *escaped_name);

/* Admin REST API: Search */
char *kc_url_fingerprint_search(struct kc_realm r, const char *escaped_fingerprint);

/* The user a create's 201 answer names in its Location header, accepted
 * only as exactly "<users_url>/<uuid>": users_url is the URL the create was
 * sent to (kc_url_users()), its scheme and host compared without case and
 * its path exactly; the same path alone (an absolute-path reference) is
 * accepted too.  The id must be a UUID in its 8-4-4-4-12 hex form, and
 * nothing may follow it (no query, fragment, slash, escape, dot segment,
 * control byte), so it is safe in a URL path and in a log line.  Writes
 * the 36 characters into out (at least 37 bytes) and returns 1; else 0
 * with out empty. */
int kc_url_location_user_id(const char *location, const char *users_url,
                            char *out, size_t out_size);

/* Is s[0..len) a UUID in its 8-4-4-4-12 hex form? */
int kc_url_is_uuid(const char *s, size_t len);

/* The Location header of a response's final header block, read from the
 * header lines as libcurl hands them over (status line, headers, the empty
 * line; trailers after it).  A new status line starts over; a block with
 * two Location headers, or an empty one, names none; trailers are ignored.
 * Zero-initialise; value is NULL or the header's value, trimmed. */
struct kc_location_capture {
    char *value;
    int in_block;     /* inside a header block (after its status line) */
    int seen;         /* Location headers seen in this block */
};
void kc_location_capture_line(struct kc_location_capture *c,
                              const char *line, size_t len);
void kc_location_capture_free(struct kc_location_capture *c);

/* A value from the wire made fit for a log line: printable ASCII kept,
 * any other byte written as '?', cut short with "..." to out_size - 1;
 * NULL reads "(none)". */
void kc_url_log_safe(const char *in, char *out, size_t out_size);

#endif /* KC_URL_H */
