/*
 * IRC - Internet Relay Chat, ircd/rename_proto.c
 *
 * rename_proto.c - the parts of channel RENAME that depend on nothing but
 * their arguments.  See include/rename_proto.h for the wire forms and the
 * name rules.  The cookie codec uses nothing of the ircd; the rest uses
 * only the character tables and string checks in ircd_string.c.
 */
#include "config.h"
#include "rename_proto.h"

#include "channel.h"            /* IsChannelName, IsLocalChannel */
#include "ircd_chattr.h"        /* ToLower */
#include "ircd_string.h"        /* strIsIrcCh, the UTF-8 check */

#include <limits.h>
#include <string.h>

/** Is @a c a character of a P10 numeric (numnicks.c convert2y[])?
 * Spelled out rather than isalnum(): that follows the locale, and a
 * Latin-1 one takes bytes above 0x7f as letters. */
static int is_numeric_char(int c)
{
  return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
      || (c >= '0' && c <= '9') || c == '[' || c == ']';
}

/** Length of the server numeric at the start of @a s -- one or two numeric
 * characters -- when it is followed by @a end; 0 otherwise. */
static size_t server_numeric_len(const char *s, char end)
{
  size_t len = 0;

  while (len < 2 && is_numeric_char((unsigned char)s[len]))
    len++;

  return (len > 0 && s[len] == end) ? len : 0;
}

/** Read the decimal number that is ALL of @a s, as "%u" prints one.
 * @return 1 and the value in @a out, or 0 when @a s is anything else
 *         (empty, a sign, a leading zero, a non-digit, too large). */
static int parse_request_number(const char *s, unsigned int *out)
{
  unsigned int value = 0;
  const char *p;

  if (!*s)
    return 0;
  if (s[0] == '0' && s[1])
    return 0;                   /* "%u" never writes a leading zero */

  for (p = s; *p; p++) {
    unsigned int digit;

    if (*p < '0' || *p > '9')
      return 0;
    digit = (unsigned int)(*p - '0');
    /* Refuse before the multiply can wrap, so no length check is needed
     * and a 600-digit number fails at its eleventh digit. */
    if (value > (UINT_MAX - digit) / 10)
      return 0;
    value = value * 10 + digit;
  }

  *out = value;
  return 1;
}

int rename_cookie_format(char *buf, size_t buflen, const char *numeric,
                         unsigned int n)
{
  char digits[11];              /* ten digits and the NUL */
  size_t numlen, ndigits = 0, i;
  char *p;

  if (!buf || !buflen)
    return 0;
  buf[0] = '\0';

  if (!numeric || !(numlen = server_numeric_len(numeric, '\0')))
    return 0;

  /* Decimal by hand (least significant digit first): this file stays free
   * of the ircd's printf family and of stdio. */
  do {
    digits[ndigits++] = (char)('0' + n % 10);
    n /= 10;
  } while (n);

  if (numlen + 1 + ndigits + 1 > buflen)
    return 0;

  p = buf;
  memcpy(p, numeric, numlen);
  p += numlen;
  *p++ = '.';
  for (i = ndigits; i > 0; i--)
    *p++ = digits[i - 1];
  *p = '\0';

  return (int)(p - buf);
}

enum RenameCookieForm rename_cookie_parse(const char *text, char numeric[3],
                                          unsigned int *n)
{
  const char *dot;
  size_t numlen;
  unsigned int value;

  numeric[0] = '\0';

  if (!text || !*text)
    return RENAME_COOKIE_INVALID;

  if (!(dot = strchr(text, '.'))) {
    /* The form before the origin was part of the cookie. */
    if (!parse_request_number(text, &value))
      return RENAME_COOKIE_INVALID;
    *n = value;
    return RENAME_COOKIE_LEGACY;
  }

  /* <numeric> "." <n>.  A second dot is not a digit, so the number parse
   * refuses it. */
  if (!(numlen = server_numeric_len(text, '.')))
    return RENAME_COOKIE_INVALID;
  if (!parse_request_number(dot + 1, &value))
    return RENAME_COOKIE_INVALID;

  memcpy(numeric, text, numlen);
  numeric[numlen] = '\0';
  *n = value;
  return RENAME_COOKIE_ROUTED;
}

int rename_query_relayable(enum RenameCookieForm form, int cookie_names_source)
{
  return form == RENAME_COOKIE_ROUTED && cookie_names_source;
}

enum RenameReplyVerdict
rename_reply_decide(const struct RenameReplyFacts *facts)
{
  /* Only services decide, and only services' word is carried. */
  if (!facts->source_is_services)
    return RENAME_REPLY_NOT_SERVICES;

  if (facts->form != RENAME_COOKIE_ROUTED && facts->form != RENAME_COOKIE_LEGACY)
    return RENAME_REPLY_BAD_COOKIE;

  /* Another server's: in transit.  Whether a request with the same number
   * happens to be pending here is deliberately not looked at. */
  if (facts->form == RENAME_COOKIE_ROUTED && !facts->cookie_is_ours) {
    if (!facts->cookie_server_known)
      return RENAME_REPLY_UNKNOWN_SERVER;
    if (facts->cookie_server_is_back)
      return RENAME_REPLY_BACKWARD;
    return RENAME_REPLY_RELAY;
  }

  /* Ours, or a bare number (which is nobody's, so can only be tried
   * here): the request must exist, and the answer must come from the
   * services server it was sent to. */
  if (!facts->bound_name)
    return RENAME_REPLY_NO_REQUEST;
  if (!facts->source_name
      || 0 != ircd_strcmp(facts->bound_name, facts->source_name))
    return RENAME_REPLY_NOT_BOUND;
  if (facts->form == RENAME_COOKIE_LEGACY && !facts->source_is_direct)
    return RENAME_REPLY_BARE_INDIRECT;

  return RENAME_REPLY_APPLY;
}

const char *rename_reply_verdict_text(enum RenameReplyVerdict verdict)
{
  switch (verdict) {
  case RENAME_REPLY_APPLY:
    return "applied";
  case RENAME_REPLY_RELAY:
    return "relayed";
  case RENAME_REPLY_NOT_SERVICES:
    return "its source is not a services server";
  case RENAME_REPLY_BAD_COOKIE:
    return "malformed cookie";
  case RENAME_REPLY_UNKNOWN_SERVER:
    return "no server has the numeric in its cookie";
  case RENAME_REPLY_BACKWARD:
    return "the server in its cookie is back down the link it arrived on";
  case RENAME_REPLY_NO_REQUEST:
    return "no such request is pending here";
  case RENAME_REPLY_NOT_BOUND:
    return "the request was sent to a different services server";
  case RENAME_REPLY_BARE_INDIRECT:
    return "a bare-number cookie from a server that is not linked here";
  }

  return "unknown verdict";
}

enum RenameNameError rename_check_names(const char *oldname,
                                        const char *newname,
                                        size_t maxlen, int utf8_only)
{
  if (!oldname || !IsChannelName(oldname))
    return RENAME_NAME_OLD_NOT_CHANNEL;
  if (IsLocalChannel(oldname))
    return RENAME_NAME_OLD_LOCAL;

  if (!newname || !IsChannelName(newname))
    return RENAME_NAME_NEW_NOT_CHANNEL;
  if (IsLocalChannel(newname))
    return RENAME_NAME_NEW_LOCAL;

  /* m_join.c, for each name a user asks to join: NTL_IRCCH is every byte
   * from 0x21 up except the comma and 0xA0. */
  if (!strIsIrcCh(newname))
    return RENAME_NAME_NEW_BAD_CHARS;
  if (utf8_only && !string_character_structure_is_sane(newname))
    return RENAME_NAME_NEW_BAD_UTF8;
  if (strlen(newname) > maxlen)
    return RENAME_NAME_NEW_TOO_LONG;

  if (oldname[0] != newname[0])
    return RENAME_NAME_PREFIX_MISMATCH;

  return RENAME_NAME_OK;
}

const char *rename_name_error_text(enum RenameNameError err)
{
  switch (err) {
  case RENAME_NAME_OK:
    return "Channel names are acceptable";
  case RENAME_NAME_OLD_NOT_CHANNEL:
    return "Not a channel";
  case RENAME_NAME_OLD_LOCAL:
    return "Local channels cannot be renamed";
  case RENAME_NAME_NEW_NOT_CHANNEL:
    return "Invalid channel name";
  case RENAME_NAME_NEW_LOCAL:
    return "A channel cannot be renamed to a local channel name";
  case RENAME_NAME_NEW_BAD_CHARS:
    return "New channel name contains a character that is not allowed "
           "in channel names";
  case RENAME_NAME_NEW_BAD_UTF8:
    return "New channel name is not valid UTF-8";
  case RENAME_NAME_NEW_TOO_LONG:
    return "New channel name is too long";
  case RENAME_NAME_PREFIX_MISMATCH:
    return "Old and new channel names must be the same type of channel";
  }

  return "Invalid channel name";
}

/*
 * Relocation: the deadline.
 */

time_t relocate_expiry_from_grace(time_t now, int grace)
{
  if (grace < 0)
    grace = 0;
  if (grace > RELOCATE_GRACE_MAX)
    grace = RELOCATE_GRACE_MAX;

  return now + grace;
}

int relocate_expiry_format(char *buf, size_t buflen, time_t expires)
{
  char digits[RELOCATE_EXPIRY_BUFLEN];
  unsigned long long value;
  size_t ndigits = 0, i;

  if (!buf || !buflen)
    return 0;
  buf[0] = '\0';

  value = (expires < 0) ? 0 : (unsigned long long)expires;

  /* Decimal by hand, as the cookie: no stdio in this file. */
  do {
    digits[ndigits++] = (char)('0' + value % 10);
    value /= 10;
  } while (value);

  if (ndigits + 1 > buflen)
    return 0;

  for (i = 0; i < ndigits; i++)
    buf[i] = digits[ndigits - 1 - i];
  buf[ndigits] = '\0';

  return (int)ndigits;
}

int relocate_expiry_parse(const char *text, time_t *expires)
{
  /* The largest value a time_t holds, whatever its width. */
  const unsigned long long limit =
    (((unsigned long long)1 << (sizeof(time_t) * CHAR_BIT - 2)) - 1) * 2 + 1;
  unsigned long long value = 0;
  const char *p;

  if (!text || !*text)
    return 0;
  if (text[0] == '0' && text[1])
    return 0;                   /* "%Tu" never writes a leading zero */

  for (p = text; *p; p++) {
    unsigned long long digit;

    if (*p < '0' || *p > '9')
      return 0;
    digit = (unsigned long long)(*p - '0');
    /* Refuse before the multiply can pass the limit: no length check is
     * needed and a 600-digit number fails at its twentieth digit. */
    if (value > (limit - digit) / 10)
      return 0;
    value = value * 10 + digit;
  }

  *expires = (time_t)value;
  return 1;
}

enum RelocateExpiryKind relocate_expiry_check(time_t *expires, time_t now)
{
  if (*expires <= now)
    return RELOCATE_EXPIRY_PAST;

  /* Compared as a difference: now + RELOCATE_GRACE_MAX cannot overflow
   * for any real clock, *expires - now cannot for an *expires above now. */
  if (*expires - now > RELOCATE_GRACE_MAX) {
    *expires = now + RELOCATE_GRACE_MAX;
    return RELOCATE_EXPIRY_CLAMPED;
  }

  return RELOCATE_EXPIRY_LIVE;
}

/*
 * Relocation: rules that must give two servers the same answer.
 */

time_t relocate_deadline_merge(time_t a, time_t b)
{
  return (a > b) ? a : b;
}

int relocate_name_cmp(const char *a, const char *b)
{
  for (;; a++, b++) {
    /* ToLower() takes a plain char (it indexes its table from CHAR_MIN);
     * the result is compared as a signed byte whatever plain char is. */
    int ca = (signed char)ToLower(*a);
    int cb = (signed char)ToLower(*b);

    if (ca != cb)
      return (ca < cb) ? -1 : 1;
    if (!*a)
      return 0;
  }
}

const char *relocate_winner(const char *a, const char *b)
{
  return (relocate_name_cmp(a, b) <= 0) ? a : b;
}

int relocate_announce_ts_matches(time_t announced, time_t mine)
{
  return mine >= announced && mine - announced <= RELOCATE_TS_FUZZ;
}

enum RelocateAnnounceVerdict
relocate_announce_decide(const struct RelocateAnnounceFacts *facts)
{
  if (!facts->channel_exists)
    return RELOCATE_ANNOUNCE_NO_CHANNEL;
  if (!facts->ts_matches)
    return RELOCATE_ANNOUNCE_OTHER_CHANNEL;
  if (!facts->have_record)
    return RELOCATE_ANNOUNCE_BUILD;

  return facts->same_target ? RELOCATE_ANNOUNCE_MERGE
                            : RELOCATE_ANNOUNCE_CROSS;
}
