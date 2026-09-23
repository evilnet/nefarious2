/*
 * IRC - Internet Relay Chat, include/bouncer_deauth.h
 *
 * The two pure decision points of account deauthorization:
 *   1. BX U field identity — which alias field a wire name refers to.
 *      One enum both apply blocks switch on, so they cannot drift again
 *      (they had, by two fields, for the whole life of the BX U path).
 *   2. Per-client deauth action — what to do with one client when an
 *      account is deauthed or killed, from wire-visible flags alone.
 *
 * Pure (no ircd dependencies) so both are unit tested; see
 * ircd/bouncer_deauth.c for the standalone-compilation contract.
 */
#ifndef INCLUDED_bouncer_deauth_h
#define INCLUDED_bouncer_deauth_h

/** A field carried by the BX U (bouncer alias update) token. */
enum BounceAliasField {
  BX_ALIAS_FIELD_UNKNOWN = 0,
  BX_ALIAS_FIELD_HOST,
  BX_ALIAS_FIELD_REALHOST,
  BX_ALIAS_FIELD_REALNAME,
  BX_ALIAS_FIELD_FAKEHOST,
  BX_ALIAS_FIELD_CLOAKHOST,
  BX_ALIAS_FIELD_CLOAKIP,
  BX_ALIAS_FIELD_USERNAME,
  BX_ALIAS_FIELD_ACCOUNT,
  BX_ALIAS_FIELD_CAPS,
  BX_ALIAS_FIELD_COUNT           /**< enumerator count, not a field */
};

/** Map a BX U wire field name to its identity.
 * Matched case-insensitively, as the original ircd_strcmp dispatch was.
 * @param[in] field  Wire field name (may be NULL).
 * @return The field identity, or BX_ALIAS_FIELD_UNKNOWN.
 */
extern enum BounceAliasField bounce_alias_field_id(const char *field);

/** The canonical wire name for a field identity.
 * @param[in] id  A field identity.
 * @return The wire name, or NULL for UNKNOWN/COUNT/out of range.
 */
extern const char *bounce_alias_field_name(enum BounceAliasField id);

#endif /* INCLUDED_bouncer_deauth_h */
