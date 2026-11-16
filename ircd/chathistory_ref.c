/*
 * IRC - Internet Relay Chat, ircd/chathistory_ref.c
 *
 * chathistory_ref.c - CHATHISTORY references on the S2S wire: how a
 * client's "timestamp=" / "msgid=" reference is sent in a CH Q query and
 * how a responder reads one.  Depends on nothing but its arguments and
 * the character tables, so the CMocka suite links it alone.
 */
#include "config.h"
#include "chathistory_ref.h"

#include "ircd_chattr.h"        /* IsDigit */
#include "ircd_string.h"        /* ircd_strncpy */

#include <string.h>

/** Validate a timestamp value.
 * Valid formats:
 *   - Unix timestamp: digits with optional decimal (e.g., "1234567890.123")
 *   - ISO 8601: "YYYY-MM-DDTHH:MM:SS.sssZ" or similar
 * @param[in] ts Timestamp string to validate.
 * @return 1 if valid, 0 if invalid.
 */
int chathistory_valid_timestamp(const char *ts)
{
  const char *p;

  if (!ts || !*ts)
    return 0;

  /* Check for Unix timestamp format: digits with optional decimal point */
  if (IsDigit(*ts)) {
    int has_decimal = 0;
    for (p = ts; *p; p++) {
      if (*p == '.') {
        if (has_decimal)
          return 0;  /* Multiple decimals */
        has_decimal = 1;
      } else if (*p == 'T' || *p == '-' || *p == ':' || *p == 'Z') {
        /* This looks like ISO 8601 format - validate below */
        break;
      } else if (!IsDigit(*p)) {
        return 0;  /* Invalid character */
      }
    }
    if (!*p)
      return 1;  /* Valid Unix timestamp */
  }

  /* Check for ISO 8601 format: YYYY-MM-DDTHH:MM:SS[.sss]Z
   * Relaxed validation - just check basic structure */
  if (strlen(ts) >= 19) {  /* Minimum: YYYY-MM-DDTHH:MM:SS */
    /* Check YYYY-MM-DD pattern at start */
    if (IsDigit(ts[0]) && IsDigit(ts[1]) && IsDigit(ts[2]) && IsDigit(ts[3]) &&
        ts[4] == '-' &&
        IsDigit(ts[5]) && IsDigit(ts[6]) &&
        ts[7] == '-' &&
        IsDigit(ts[8]) && IsDigit(ts[9]) &&
        ts[10] == 'T') {
      return 1;  /* Valid ISO 8601 */
    }
  }

  return 0;  /* Invalid format */
}

/** Convert a client reference to its S2S form.
 * Input:  "timestamp=<ts>" or "msgid=<id>" or "*"
 * Output: "<ts>" or "msgid=<id>" or "*"
 * A timestamp goes bare; a msgid keeps its "msgid=" marker.  A bare msgid
 * is not safe: a msgid begins with its server's numnick, and numerics
 * 3328-3967 have a digit there (0-9 are numnick values 52-61), so a
 * responder could read it as a timestamp.  chathistory_parse_s2s_ref() has
 * read the marker since 400a39f, so older responders take it too.
 * @param[in] ref Client reference string.
 * @param[out] buf Buffer for S2S format.
 * @param[in] buflen Buffer size.
 * @return Pointer to buf, or NULL on error.
 */
char *chathistory_ref_to_s2s(const char *ref, char *buf, size_t buflen)
{
  if (!ref || !buf || buflen < 2)
    return NULL;

  if (*ref == '*') {
    buf[0] = '*';
    buf[1] = '\0';
    return buf;
  }

  if (strncmp(ref, "timestamp=", 10) == 0) {
    ircd_strncpy(buf, ref + 10, buflen - 1);
    buf[buflen - 1] = '\0';
    return buf;
  }

  if (strncmp(ref, "msgid=", 6) == 0 && ref[6]) {
    ircd_strncpy(buf, ref, buflen - 1);
    buf[buflen - 1] = '\0';
    return buf;
  }

  return NULL;
}

/** Parse S2S reference format.
 * Input:  "timestamp=<ts>" or "<ts>" (timestamp), "msgid=<id>" or
 *         "<id>" (msgid), or "*" (none).
 * A bare reference is a timestamp only when it has a timestamp's shape
 * (chathistory_valid_timestamp(): unix "sec[.ms]" or ISO 8601).  Older
 * senders put msgids on the wire bare, and a msgid minted by a server
 * whose numnick starts with a digit starts with a digit too, so the
 * first character does not tell them apart.  A 14-character msgid of
 * digits alone would still read as a timestamp; its other characters
 * are base64 with letters and brackets, so that is about one in 10^9.
 * @param[in] ref S2S reference string.
 * @param[out] ref_type Type of reference.
 * @param[out] value Pointer to value.
 * @return 0 on success, -1 on error.
 */
int chathistory_parse_s2s_ref(const char *ref, enum HistoryRefType *ref_type, const char **value)
{
  if (!ref || !*ref)
    return -1;

  if (*ref == '*') {
    *ref_type = HISTORY_REF_NONE;
    *value = ref;
    return 0;
  }

  /* Handle IRC client format prefixes (X3 sends these).  A marker with
   * nothing after it names nothing: refused, as the client's own
   * reference parser refuses it. */
  if (strncmp(ref, "timestamp=", 10) == 0) {
    if (!ref[10])
      return -1;
    *ref_type = HISTORY_REF_TIMESTAMP;
    *value = ref + 10;
    return 0;
  }

  if (strncmp(ref, "msgid=", 6) == 0) {
    if (!ref[6])
      return -1;
    *ref_type = HISTORY_REF_MSGID;
    *value = ref + 6;
    return 0;
  }

  if (chathistory_valid_timestamp(ref)) {
    *ref_type = HISTORY_REF_TIMESTAMP;
    *value = ref;
    return 0;
  }

  /* Anything else is a msgid */
  *ref_type = HISTORY_REF_MSGID;
  *value = ref;
  return 0;
}
