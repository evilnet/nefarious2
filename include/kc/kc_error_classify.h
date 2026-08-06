/* kc_error_classify.h -- classify a resource-owner-password-credentials
 * (ROPC) grant error body.
 *
 * Keycloak's token endpoint returns HTTP 400/401 with a JSON body
 * {"error": "...", "error_description": "..."} for both "bad credentials"
 * and "account not fully set up" (pending a required action such as
 * VERIFY_EMAIL). Both cases are otherwise indistinguishable from the HTTP
 * status alone, so callers that need to tell a genuinely rejected login
 * apart from "the account exists but registration didn't finish" must
 * inspect error_description. This is the substring Task 0's live probe
 * confirmed verbatim: {"error":"invalid_grant","error_description":
 * "Account is not fully set up"}.
 *
 * MUST stay ircd-header-free (kc boundary; see check-kc-boundary in
 * ircd/Makefile.in).
 */
#ifndef KC_ERROR_CLASSIFY_H
#define KC_ERROR_CLASSIFY_H

#include <jansson.h>

/* Classify a 400/401 password-grant error body. Returns KC_UNVERIFIED when
 * error_description matches Keycloak's "Account is not fully set up"
 * (substring "not fully set up", case-insensitive), else KC_FORBIDDEN.
 * NULL json => KC_FORBIDDEN. */
int kc_classify_grant_error(json_t *json);

#endif /* KC_ERROR_CLASSIFY_H */
