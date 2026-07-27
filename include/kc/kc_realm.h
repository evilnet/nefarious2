/*
 * kc_realm.h - Keycloak realm configuration
 *
 * Lightweight struct identifying a Keycloak realm.
 * Used by URL builders (kc_url.h), JWT validation (kc_jwt.h),
 * and sync HTTP helpers (kc_http_sync.h).
 */

#ifndef KC_REALM_H
#define KC_REALM_H

struct kc_realm {
    const char *base_url;   /* e.g., "http://keycloak:8080" */
    const char *realm;      /* e.g., "master" */
};

#endif /* KC_REALM_H */
