/*
 * IRC - Internet Relay Chat, include/account_id.h
 *
 * The compact form of a Keycloak user id.
 *
 * Keycloak identifies a user by a UUID.  On the P10 wire and in services'
 * database it travels as the 16 bytes in unpadded base64url: 22 characters
 * instead of 36, fitting the burst NICK line alongside the account name.
 */
#ifndef INCLUDED_account_id_h
#define INCLUDED_account_id_h

/** Length of the compact id: 16 bytes as unpadded base64url. */
#define ACCOUNT_ID_LEN 22

/** Encode a UUID (canonical 8-4-4-4-12 form, or the 32 hex digits
 * without hyphens, either case) into its compact form.
 * @param uuid  The UUID text.
 * @param out   Receives ACCOUNT_ID_LEN characters plus a terminating NUL.
 * @return 1 on success, 0 when uuid is malformed (out is left untouched).
 */
int account_id_from_uuid(const char *uuid, char out[ACCOUNT_ID_LEN + 1]);

/** Is id a well-formed compact id: exactly ACCOUNT_ID_LEN characters,
 * all from the base64url alphabet (letters, digits, '-', '_')?
 * @return 1 when it is, 0 otherwise (including NULL).
 */
int account_id_valid(const char *id);

#endif /* INCLUDED_account_id_h */
