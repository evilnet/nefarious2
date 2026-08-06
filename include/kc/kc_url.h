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

#endif /* KC_URL_H */
