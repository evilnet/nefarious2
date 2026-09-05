/*
 * webpush_line.h - the push payload as one IRC line (draft/webpush)
 *
 * The draft says "Each push notification MUST contain exactly one IRC
 * message as the payload, without the final CRLF" and that servers may
 * drop tags but never msgid.  This module builds those lines:
 *
 *   @msgid=..;time=..;account=.. :nick!user@host PRIVMSG target :text
 *   @batch=<base msgid>;msgid=..;time=..;account=..;evilnet.github.io/line=i/sent/total[;draft/multiline-concat] :nick!user@host PRIVMSG target :line
 *   :server MARKREAD target timestamp=<ts>
 *
 * Tags appear in that order and only when they have a value.  Pure: no
 * ircd dependencies; unit-tested in ircd/test/webpush_line_cmocka.c.
 * Contract: docs/projects/push-payload-multiline.md §3 (Seance repo).
 */
#ifndef INCLUDED_webpush_line_h
#define INCLUDED_webpush_line_h

#include <stddef.h>

/** The sender as the line names it.  account may be NULL or "" (not logged in). */
struct webpush_line_src {
  const char *nick;
  const char *user;
  const char *host;
  const char *account;
};

/** One line of a draft/multiline batch (NULL for a single message). */
struct webpush_line_ml {
  const char *batch;   /**< batch reference: the batch's base msgid */
  int index;           /**< 1-based line index in the original message */
  int sent;            /**< lines pushed for this batch (<= total) */
  int total;           /**< lines the message had */
  int concat;          /**< non-zero when the line carried draft/multiline-concat */
};

/** Escape a message-tag value: ';' -> "\:", ' ' -> "\s", '\' -> "\\",
 * CR -> "\r", LF -> "\n".  Returns the escaped length (excluding NUL), or
 * (size_t)-1 when it does not fit outlen.  Exposed as the unit-test seam
 * for the escaping; production code reaches it only through
 * webpush_line_message. */
size_t webpush_tag_escape(char *out, size_t outlen, const char *in);

/** Build "@tags :nick!user@host COMMAND target :text" (no CRLF) into out.
 * msgid/timestamp may be NULL or "" (tag omitted).  Returns the line
 * length, or -1 when an argument is missing, ml is malformed, or the line
 * does not fit (out is then ""). */
int webpush_line_message(char *out, size_t outlen,
                         const struct webpush_line_src *src,
                         const char *command, const char *target,
                         const char *text, const char *msgid,
                         const char *timestamp,
                         const struct webpush_line_ml *ml);

/** Build ":server MARKREAD target timestamp=<ts>" (no CRLF); a NULL, ""
 * or "*" timestamp gives ":server MARKREAD target *".  Returns the line
 * length, or -1 when an argument is missing or it does not fit. */
int webpush_line_markread(char *out, size_t outlen, const char *server,
                          const char *target, const char *timestamp);

#endif /* INCLUDED_webpush_line_h */
