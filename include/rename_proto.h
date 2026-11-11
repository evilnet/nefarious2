/*
 * IRC - Internet Relay Chat, include/rename_proto.h
 *
 * The parts of channel RENAME that depend on nothing but their arguments:
 * the cookie a services permission query travels under.  Kept apart from
 * m_rename.c so they can be unit-tested (ircd/test/rename_proto_cmocka.c).
 */
#ifndef INCLUDED_rename_proto_h
#define INCLUDED_rename_proto_h

#include <stddef.h>

/*
 * The services permission query for a registered channel
 *
 *     <origin> AC <user> R <cookie> <#chan> RENAME <newname>
 *
 * is answered by services with
 *
 *     <services> AC <cookie> A RENAME
 *     <services> AC <cookie> D RENAME :<reason>
 *
 * Services treat the cookie as an opaque string and echo it verbatim, and
 * the reply carries nothing else that says where it belongs.  So the
 * cookie itself names the server that is waiting:
 *
 *     <origin-server-numeric> "." <n>          e.g.  Bj.17
 *
 * - the origin's P10 server numeric, one or two characters of the numeric
 *   alphabet (A-Z a-z 0-9 [ ]), exactly as "%C" prints a server;
 * - a dot, which is not in that alphabet;
 * - the origin's pending-request number in decimal, as "%u" prints it.
 *
 * A server that is not the origin forwards the reply toward that numeric;
 * the origin strips it and looks <n> up in its own table.
 *
 * Before this form the cookie was the bare number ("17").  A server that
 * still sends it gets it back unchanged, so the parser tells the two apart
 * rather than refusing the old one.
 */

/** Room for the longest cookie: two numeric characters, the dot, ten
 * decimal digits (UINT_MAX is 4294967295) and the terminating NUL. */
#define RENAME_COOKIE_BUFLEN 14

/** What rename_cookie_parse() found. */
enum RenameCookieForm {
  RENAME_COOKIE_INVALID = 0,  /**< neither form: ignore the message */
  RENAME_COOKIE_LEGACY,       /**< "<n>": no origin, only a local lookup is possible */
  RENAME_COOKIE_ROUTED        /**< "<numeric>.<n>": belongs to the server named */
};

/** Write the cookie for pending request @a n of the server whose P10
 * numeric is @a numeric.
 * @param[out] buf Receives the cookie, NUL-terminated.
 * @param[in] buflen Size of @a buf; RENAME_COOKIE_BUFLEN always suffices.
 * @param[in] numeric The origin's server numeric (one or two characters).
 * @param[in] n The origin's pending-request number.
 * @return The cookie's length, or 0 when @a numeric is not a server
 *         numeric or @a buf is too small (buf then holds an empty string
 *         if it has any room at all).
 */
extern int rename_cookie_format(char *buf, size_t buflen, const char *numeric,
                                unsigned int n);

/** Take a cookie apart.
 *
 * Strict in both forms: only what rename_cookie_format() (or the "%u" of
 * the old form) can have written is accepted -- no sign, no leading zero,
 * no trailing bytes, nothing that does not fit an unsigned int.  A cookie
 * that fails is not "probably 0": it belongs to nobody.
 *
 * @param[in] text The cookie as received (may be NULL).
 * @param[out] numeric Receives the origin's server numeric for
 *             RENAME_COOKIE_ROUTED, an empty string otherwise.
 * @param[out] n Receives the request number for both valid forms; left
 *             untouched for RENAME_COOKIE_INVALID.
 * @return The form found.
 */
extern enum RenameCookieForm rename_cookie_parse(const char *text,
                                                 char numeric[3],
                                                 unsigned int *n);

#endif /* INCLUDED_rename_proto_h */
