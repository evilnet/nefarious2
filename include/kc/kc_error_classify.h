/* kc_error_classify.h -- classify Keycloak's refusals: a
 * resource-owner-password-credentials (ROPC) grant's, and a user create's.
 *
 * Keycloak's token endpoint answers a refused password grant with HTTP
 * 400/401 and a JSON body {"error": "...", "error_description": "..."},
 * whatever the reason, so the status alone cannot tell the reasons apart.
 * kc_classify_grant_error() reads the body into one of five outcomes:
 *   - KC_FORBIDDEN       the user's credentials are wrong
 *   - KC_DISABLED        the account is disabled
 *   - KC_UNVERIFIED      the account is not fully set up (a pending
 *                        required action such as VERIFY_EMAIL; Task 0's
 *                        live probe saw {"error":"invalid_grant",
 *                        "error_description":"Account is not fully set up"})
 *   - KC_CLIENT_REFUSED  Keycloak refused the caller's own client (its
 *                        secret, or the grant not enabled for it)
 *   - KC_ERROR           no Keycloak error object at all (a proxy's page,
 *                        an empty body), or not a 400/401: nothing about
 *                        the credentials
 * The rules, in order, are on the function below.
 *
 * MUST stay ircd-header-free (kc boundary; see check-kc-boundary in
 * ircd/Makefile.in).
 */
#ifndef KC_ERROR_CLASSIFY_H
#define KC_ERROR_CLASSIFY_H

#include <jansson.h>

/* Classify a password grant's refusal by its HTTP status and JSON body
 * (NULL when the body is not JSON).  First match wins:
 *   - not a JSON object, or no string "error"      -> KC_ERROR
 *     (not a Keycloak error object: a proxy's page, an empty body)
 *   - "error" is invalid_client / unauthorized_client -> KC_CLIENT_REFUSED
 *     (Keycloak refused the caller's own client)
 *   - error_description contains "disabled"        -> KC_DISABLED
 *   - error_description contains "not fully set up" -> KC_UNVERIFIED
 *   - anything else with status 400 or 401         -> KC_FORBIDDEN
 *   - anything else                                -> KC_ERROR
 * Descriptions are matched case-insensitively; a description that is not
 * a string is ignored. */
int kc_classify_grant_error(long status, json_t *json);

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
