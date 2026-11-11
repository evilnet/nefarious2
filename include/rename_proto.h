/*
 * IRC - Internet Relay Chat, include/rename_proto.h
 *
 * The parts of channel RENAME that depend on nothing but their arguments:
 * the cookie a services permission query travels under, the rules a pair
 * of channel names has to pass before a rename is attempted, and (last)
 * the rules of relocation mode that every server has to apply alike.
 * Kept apart from m_rename.c so they can be unit-tested
 * (ircd/test/rename_proto_cmocka.c).
 */
#ifndef INCLUDED_rename_proto_h
#define INCLUDED_rename_proto_h

#include <stddef.h>
#include <time.h>

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
 * Before this form the cookie was the bare number ("17"), which only
 * worked when the asking server was services' own uplink.  The parser
 * tells the two apart; what each may still do is decided below
 * (rename_query_relayable(), rename_reply_decide()).
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

/*
 * Who may move or answer a request.
 *
 * Both decisions are made from facts the caller looks up, so that the
 * rules themselves can be read, and tested, in one place.
 */

/** May a server that is not its origin pass a permission query on?
 *
 * Only when the cookie is the routed form AND the server it names is the
 * server the query came from (its source).  Then the reply can only come
 * back to the server that asked.  A bare-number cookie names nobody: its
 * reply would be looked up in the table of whichever server received it,
 * and passing the query on to services is what would produce that reply.
 * A cookie naming some other server would send the reply to a server that
 * never asked.  Either is dropped at the first hop.
 *
 * @param[in] form What rename_cookie_parse() made of the cookie.
 * @param[in] cookie_names_source Non-zero when the cookie's numeric is
 *            the numeric of the query's source server.
 * @return Non-zero when the query may be forwarded.
 */
extern int rename_query_relayable(enum RenameCookieForm form,
                                  int cookie_names_source);

/** What a server knows about a reply (AC <cookie> A|D RENAME) it has just
 * received.  Fill in every field; the comments say which matter when. */
struct RenameReplyFacts {
  enum RenameCookieForm form;   /**< rename_cookie_parse() of the cookie */
  int source_is_services;       /**< the source is a server that announced
                                     itself as a services server */
  int source_is_direct;         /**< the source is linked to this server
                                     itself (nothing in between) */
  const char *source_name;      /**< the source server's name */
  int cookie_is_ours;           /**< ROUTED: the numeric is this server's */
  int cookie_server_known;      /**< ROUTED, not ours: a server has that
                                     numeric */
  int cookie_server_is_back;    /**< ROUTED, not ours: that server is
                                     reached through the link the reply
                                     arrived on */
  const char *bound_name;       /**< ours or LEGACY: name of the services
                                     server this server sent request <n>
                                     to, NULL when it has no request <n>
                                     pending */
};

/** What to do with a reply. */
enum RenameReplyVerdict {
  RENAME_REPLY_APPLY = 0,       /**< complete or deny our pending request */
  RENAME_REPLY_RELAY,           /**< forward toward the server in the cookie */
  RENAME_REPLY_NOT_SERVICES,    /**< dropped: the source is not services */
  RENAME_REPLY_BAD_COOKIE,      /**< dropped: the cookie is neither form */
  RENAME_REPLY_UNKNOWN_SERVER,  /**< dropped: nobody has the cookie's numeric */
  RENAME_REPLY_BACKWARD,        /**< dropped: its server is back down the
                                     link it came from */
  RENAME_REPLY_NO_REQUEST,      /**< dropped: no such request pending here */
  RENAME_REPLY_NOT_BOUND,       /**< dropped: the request was sent to a
                                     different services server */
  RENAME_REPLY_BARE_INDIRECT    /**< dropped: a bare-number cookie from a
                                     server not linked here */
};

/** Decide what to do with a reply.
 *
 * - Nothing is done for a source that is not a services server, whatever
 *   the cookie says: not applied, and not relayed either, so that a relay
 *   never carries a forged answer to an origin.
 * - A routed cookie naming ANOTHER server is relayed toward it (unless
 *   that server is unknown, or back where the reply came from).  The
 *   relay holds no request, so there is nothing more it can check; the
 *   origin does.
 * - A routed cookie naming THIS server, or a bare number, is ours to
 *   apply only when request <n> is pending here AND the reply's source is
 *   the very services server that request was sent to.  A services server
 *   answering a request it was not sent, a second services server, or a
 *   reply meant for another server's request with the same number: none
 *   of them passes.
 * - A bare number is never relayed (it names nobody), and is applied only
 *   under the rule above and only from a services server linked to this
 *   server itself -- the one arrangement in which the form was ever
 *   produced: the asking server being services' own uplink.
 *
 * @param[in] facts What the caller found out; see the struct.
 * @return The verdict; anything but APPLY and RELAY means drop.
 */
extern enum RenameReplyVerdict
rename_reply_decide(const struct RenameReplyFacts *facts);

/** Why a reply was dropped, for a log line.
 * @param[in] verdict A value rename_reply_decide() returned.
 * @return A static string; never NULL.
 */
extern const char *rename_reply_verdict_text(enum RenameReplyVerdict verdict);

/*
 * Name rules.
 */

/** Why a pair of names cannot be renamed, RENAME_NAME_OK when it can. */
enum RenameNameError {
  RENAME_NAME_OK = 0,
  RENAME_NAME_OLD_NOT_CHANNEL,  /**< old name is empty or has no channel prefix */
  RENAME_NAME_OLD_LOCAL,        /**< old name is a local (&) channel */
  RENAME_NAME_NEW_NOT_CHANNEL,  /**< new name is empty or has no channel prefix */
  RENAME_NAME_NEW_LOCAL,        /**< new name is a local (&) channel */
  RENAME_NAME_NEW_BAD_CHARS,    /**< new name has a byte JOIN refuses: a comma,
                                     a space or control character, 0xA0 */
  RENAME_NAME_NEW_BAD_UTF8,     /**< new name is neither ASCII nor valid UTF-8
                                     (only when asked to check) */
  RENAME_NAME_NEW_TOO_LONG,     /**< new name is longer than the cap given */
  RENAME_NAME_PREFIX_MISMATCH   /**< old and new are different channel types */
};

/** Check a rename's two names.
 *
 * The new name gets the checks JOIN applies to a name a user asks for
 * (m_join.c: IsChannelName, strIsIrcCh, the VALID_UTF8_CHANNELS_ONLY
 * check, the length cap in do_join).  Local (&) channels are refused on
 * either side: a local channel exists on one server only, but RN is
 * applied by every server by NAME, so renaming one would rename every
 * other server's unrelated channel of the same name, and renaming a
 * global channel to a local name would leave each server with a private
 * copy of what used to be one channel.
 *
 * The old name's characters are deliberately NOT checked: the channel
 * exists, and renaming a badly named channel is how it gets a good name.
 *
 * The checks run in the order of the enum, so the first failing one is
 * reported.  With today's two prefixes (# and &) a prefix mismatch always
 * has a local channel on one side and is reported as that;
 * RENAME_NAME_PREFIX_MISMATCH is there for the day a third prefix exists.
 *
 * @param[in] oldname The channel's current name (may be NULL).
 * @param[in] newname The requested name (may be NULL).
 * @param[in] maxlen Longest new name accepted, in bytes.
 * @param[in] utf8_only Non-zero to refuse a new name that is neither
 *            plain ASCII nor valid UTF-8.
 * @return RENAME_NAME_OK or the first rule broken.
 */
extern enum RenameNameError rename_check_names(const char *oldname,
                                               const char *newname,
                                               size_t maxlen, int utf8_only);

/** Text for a client (the description of a FAIL RENAME CANNOT_RENAME).
 * @param[in] err A value rename_check_names() returned.
 * @return A static string; never NULL.
 */
extern const char *rename_name_error_text(enum RenameNameError err);

/*
 * Relocation mode (evilnet/channel-relocate): the deadline.
 *
 * A relocated channel's old name stays behind as a tombstone until a
 * deadline, and every server has to dissolve it at the same moment.  So
 * the deadline is an absolute time, computed once by the server that
 * executes the relocation and carried by the message:
 *
 *     <user> RN <old> <new> C <expires> :<reason>
 *     ABAAC RN #old #new C 1731340900 :moving
 *
 * <expires> is network time -- TStime(), the clock channel creation
 * timestamps are in -- in seconds, as "%Tu" prints it: decimal digits, no
 * sign, no leading zero.  A server from before the deadline travelled
 * sends
 *
 *     <user> RN <old> <new> C :<reason>
 *
 * and a receiver of that form counts its own RELOCATE_GRACE from the
 * moment of receipt, as every server used to.
 */

/** Longest grace, in seconds, and so the furthest a deadline may lie
 * ahead: seven days.
 *
 * It is a constant of the protocol and not a feature, because every
 * server must cut an over-long deadline to the same length.  A tombstone
 * holds a name (+z, +L) that nobody can use; RELOCATE_GRACE is minutes
 * (default 900 s) and a network that wants a long notice may want a day
 * or two.  A week is beyond any of that and still bounds what one
 * corrupt or hostile <expires> (0x7fffffff, say) can do: without a bound
 * it would pin the name for decades, on every server. */
#define RELOCATE_GRACE_MAX 604800

/** Room for the longest <expires>: the nineteen digits of the largest
 * 64-bit time_t, one to spare, and the terminating NUL. */
#define RELOCATE_EXPIRY_BUFLEN 21

/** The deadline of a relocation executed at @a now with a grace of
 * @a grace seconds (the issuing server's RELOCATE_GRACE; also the
 * fallback of a receiver that was sent no deadline).
 * @param[in] now Network time.
 * @param[in] grace Seconds; below 0 counts as 0 (dissolve at once),
 *            above RELOCATE_GRACE_MAX as RELOCATE_GRACE_MAX, so that no
 *            server announces a deadline another would cut.
 * @return The deadline, network time.
 */
extern time_t relocate_expiry_from_grace(time_t now, int grace);

/** Write a deadline as it goes on the wire.
 * @param[out] buf Receives the digits, NUL-terminated.
 * @param[in] buflen Size of @a buf; RELOCATE_EXPIRY_BUFLEN always suffices.
 * @param[in] expires The deadline; a negative time is written as 0.
 * @return The length written, or 0 when @a buf is too small (it then
 *         holds an empty string if it has any room at all).
 */
extern int relocate_expiry_format(char *buf, size_t buflen, time_t expires);

/** Read a deadline off the wire.
 *
 * Strict: only what relocate_expiry_format() can have written -- digits,
 * no sign, no leading zero, no trailing byte, nothing that does not fit a
 * time_t.  Anything else is not a deadline, and the caller falls back to
 * its own grace rather than guess.
 * @param[in] text The parameter as received (may be NULL).
 * @param[out] expires Receives the deadline; untouched on failure.
 * @return 1 when @a text is a deadline, 0 otherwise.
 */
extern int relocate_expiry_parse(const char *text, time_t *expires);

/** What a receiver makes of a deadline. */
enum RelocateExpiryKind {
  RELOCATE_EXPIRY_LIVE = 0,   /**< ahead, within RELOCATE_GRACE_MAX: arm for it */
  RELOCATE_EXPIRY_PAST,       /**< now or earlier: dissolve at once */
  RELOCATE_EXPIRY_CLAMPED     /**< further ahead than RELOCATE_GRACE_MAX:
                                   cut to now + RELOCATE_GRACE_MAX */
};

/** Judge a deadline against this server's clock.
 *
 * - Now or already past: the tombstone is dissolved at once.  The
 *   deadline is left as it is, so a relay passes the same past time on
 *   and every server behind it dissolves at once too.
 * - More than RELOCATE_GRACE_MAX ahead: cut to now + RELOCATE_GRACE_MAX
 *   (see the constant for why there is a bound and why it is fixed).
 *   The cut value is what this server arms for AND what it relays, so
 *   the servers behind it get a sane deadline and the same one; servers
 *   that receive the absurd value by different routes cut at their own
 *   moment of receipt and can differ by the delay between them.
 * - Otherwise it is taken as it is.
 *
 * @param[in,out] expires The deadline; cut when the result is
 *                RELOCATE_EXPIRY_CLAMPED, otherwise unchanged.
 * @param[in] now Network time.
 * @return What was found.
 */
extern enum RelocateExpiryKind relocate_expiry_check(time_t *expires,
                                                     time_t now);

#endif /* INCLUDED_rename_proto_h */
