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

/* Classify a user create's refusal (the admin API's POST .../users) by its
 * HTTP status and JSON body.  409 (a user exists): KC_CONFLICT_EMAIL when
 * the field is "email", or with no field the message names the email and
 * not the username; else KC_CONFLICT.  400 (Keycloak refused the
 * representation): each error object -- the body, and each in an "errors"
 * list -- is read by its "field" when it has one (user-profile validation:
 * "username", "email", a password/credential field; any other field names
 * nothing), else by its message ("errorMessage", "error",
 * "error_description"), where the password wins over the email and the
 * email over the username (a password-policy message may mention the
 * username).  Across several errors the username wins, then the email,
 * then the password: KC_BAD_USERNAME / KC_BAD_EMAIL / KC_BAD_PASSWORD,
 * else KC_REJECTED.  Any other status: KC_ERROR (5xx, 401/403: not the
 * client's to fix). */
int kc_classify_create_error(long status, json_t *json);

#endif /* KC_ERROR_CLASSIFY_H */
