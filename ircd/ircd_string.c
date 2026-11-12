/*
 * IRC - Internet Relay Chat, ircd/ircd_string.c
 * Copyright (C) 1999 Thomas Helvey
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
/** @file
 * @brief Implementation of string operations.
 * @version $Id: ircd_string.c 1872 2008-03-20 23:58:27Z entrope $
 */
#include "config.h"

#include "ircd_string.h"
#include "ircd_defs.h"
#include "ircd_chattr.h"
#include "ircd_log.h"
#include "res.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>

/*
 * include the character attribute tables here
 */
#include "chattr.tab.c"

/** Check whether \a str contains wildcard characters.
 * @param[in] str String that might contain wildcards.
 * @return Non-zero if \a str contains naked (non-escaped) wildcards,
 * zero if there are none or if they are all escaped.
 */
int string_has_wildcards(const char* str)
{
  assert(0 != str);
  for ( ; *str; ++str) {
    if ('\\' == *str) {
      if ('\0' == *++str)
        break;
    }
    else if ('*' == *str || '?' == *str)
      return 1;
  }
  return 0;
}

/**
 * Check if a given string is a valid UTF-8 encoded string.
 *
 * This answers the encoding question only.  C0 control characters are valid
 * UTF-8 and are accepted: IRC carries CTCP delimiters (0x01) and the mIRC
 * formatting codes (bold 0x02, colour 0x03, reset 0x0F, reverse 0x16,
 * monospace 0x11, italic 0x1D, strikethrough 0x1E, underline 0x1F) as bare
 * control bytes, and rejecting them here would strip them from every message.
 * A caller that wants printable-only text must check for that separately.
 *
 * The string ends at its NUL.  For counted bytes that may hold a U+0000
 * (a WebSocket payload), use string_is_valid_utf8_len().
 *
 * @param str The string to check.
 * @return 1 if the string is valid UTF-8, 0 otherwise.
 */
int string_is_valid_utf8(const char * str)
{
    assert(str != NULL);

    return string_is_valid_utf8_len(str, strlen(str));
}

/**
 * Check if \a len bytes are valid UTF-8, as string_is_valid_utf8() checks
 * a string.  A NUL byte is U+0000, a valid one-byte sequence, and ends
 * nothing: every byte up to \a len is checked, and none after it is read,
 * so a sequence that \a len cuts short is invalid.
 *
 * @param str The bytes to check.
 * @param len How many.
 * @return 1 if they are valid UTF-8, 0 otherwise.
 */
int string_is_valid_utf8_len(const char * str, size_t len)
{
    const unsigned char * bytes = (const unsigned char *)str;
    const unsigned char * end;

    assert(str != NULL || len == 0);
    end = bytes + len;

    while (bytes < end)
    {
        size_t left = (size_t)(end - bytes);

        if( (// ASCII: every byte 0x00-0x7F is a well-formed single-byte
             // sequence, C0 control characters (and U+0000) included.
                bytes[0] <= 0x7F
            )
        ) {
            bytes += 1;
            continue;
        }

        if( left >= 2 &&
            (// non-overlong 2-byte
                (0xC2 <= bytes[0] && bytes[0] <= 0xDF) &&
                (0x80 <= bytes[1] && bytes[1] <= 0xBF)
            )
        ) {
            bytes += 2;
            continue;
        }

        if( left >= 3 && (
            (// excluding overlongs
                bytes[0] == 0xE0 &&
                (0xA0 <= bytes[1] && bytes[1] <= 0xBF) &&
                (0x80 <= bytes[2] && bytes[2] <= 0xBF)
            ) ||
            (// straight 3-byte
                ((0xE1 <= bytes[0] && bytes[0] <= 0xEC) ||
                    bytes[0] == 0xEE ||
                    bytes[0] == 0xEF) &&
                (0x80 <= bytes[1] && bytes[1] <= 0xBF) &&
                (0x80 <= bytes[2] && bytes[2] <= 0xBF)
            ) ||
            (// excluding surrogates
                bytes[0] == 0xED &&
                (0x80 <= bytes[1] && bytes[1] <= 0x9F) &&
                (0x80 <= bytes[2] && bytes[2] <= 0xBF)
            ))
        ) {
            bytes += 3;
            continue;
        }

        if( left >= 4 && (
            (// planes 1-3
                bytes[0] == 0xF0 &&
                (0x90 <= bytes[1] && bytes[1] <= 0xBF) &&
                (0x80 <= bytes[2] && bytes[2] <= 0xBF) &&
                (0x80 <= bytes[3] && bytes[3] <= 0xBF)
            ) ||
            (// planes 4-15
                (0xF1 <= bytes[0] && bytes[0] <= 0xF3) &&
                (0x80 <= bytes[1] && bytes[1] <= 0xBF) &&
                (0x80 <= bytes[2] && bytes[2] <= 0xBF) &&
                (0x80 <= bytes[3] && bytes[3] <= 0xBF)
            ) ||
            (// plane 16
                bytes[0] == 0xF4 &&
                (0x80 <= bytes[1] && bytes[1] <= 0x8F) &&
                (0x80 <= bytes[2] && bytes[2] <= 0xBF) &&
                (0x80 <= bytes[3] && bytes[3] <= 0xBF)
            ))
        ) {
            bytes += 4;
            continue;
        }

        return 0;
    }

    return 1;
}

/**
 * Sanitize a string by replacing invalid UTF-8 sequences with U+FFFD.
 *
 * This function walks through the string and replaces any invalid UTF-8
 * byte sequences with the Unicode replacement character U+FFFD (encoded
 * as 0xEF 0xBF 0xBD in UTF-8).
 *
 * Since U+FFFD is 3 bytes and invalid sequences can be 1 byte, the output
 * may be longer than input. The function uses a local buffer and copies
 * back, truncating at a valid UTF-8 boundary if the result is too long.
 *
 * The string is modified in place. Caller should ensure str has at least
 * BUFSIZE bytes available.
 *
 * Note that "no modification was needed" is also what callers get when the
 * invalid bytes lie beyond the working buffer: the scan stops at BUFSIZE
 * while string_is_valid_utf8() scans the whole string, so a long line whose
 * only bad byte is near the end validates as invalid yet sanitizes to -1.
 * Callers must therefore treat -1 as "leave the string and its length
 * alone", never as a length.
 *
 * @param str The string to sanitize (will be modified).
 * @return Length of sanitized string, or -1 if no modification was needed.
 */
int string_sanitize_utf8(char *str)
{
    unsigned char *in;
    unsigned char out[BUFSIZE];
    unsigned char *outp;
    size_t outlen;
    int modified = 0;
    int seq_len;

    if (!str)
        return -1;

    in = (unsigned char *)str;
    outp = out;
    outlen = 0;

    while (*in && outlen < sizeof(out) - 4)  /* Leave room for U+FFFD + NUL */
    {
        seq_len = 0;

        /* ASCII: any byte 0x01-0x7F, C0 control characters included */
        if (in[0] <= 0x7F)
        {
            seq_len = 1;
        }
        /* Non-overlong 2-byte */
        else if ((0xC2 <= in[0] && in[0] <= 0xDF) &&
                 (0x80 <= in[1] && in[1] <= 0xBF))
        {
            seq_len = 2;
        }
        /* 3-byte sequences */
        else if ((in[0] == 0xE0 &&
                  (0xA0 <= in[1] && in[1] <= 0xBF) &&
                  (0x80 <= in[2] && in[2] <= 0xBF)) ||
                 (((0xE1 <= in[0] && in[0] <= 0xEC) ||
                   in[0] == 0xEE || in[0] == 0xEF) &&
                  (0x80 <= in[1] && in[1] <= 0xBF) &&
                  (0x80 <= in[2] && in[2] <= 0xBF)) ||
                 (in[0] == 0xED &&
                  (0x80 <= in[1] && in[1] <= 0x9F) &&
                  (0x80 <= in[2] && in[2] <= 0xBF)))
        {
            seq_len = 3;
        }
        /* 4-byte sequences */
        else if ((in[0] == 0xF0 &&
                  (0x90 <= in[1] && in[1] <= 0xBF) &&
                  (0x80 <= in[2] && in[2] <= 0xBF) &&
                  (0x80 <= in[3] && in[3] <= 0xBF)) ||
                 ((0xF1 <= in[0] && in[0] <= 0xF3) &&
                  (0x80 <= in[1] && in[1] <= 0xBF) &&
                  (0x80 <= in[2] && in[2] <= 0xBF) &&
                  (0x80 <= in[3] && in[3] <= 0xBF)) ||
                 (in[0] == 0xF4 &&
                  (0x80 <= in[1] && in[1] <= 0x8F) &&
                  (0x80 <= in[2] && in[2] <= 0xBF) &&
                  (0x80 <= in[3] && in[3] <= 0xBF)))
        {
            seq_len = 4;
        }

        if (seq_len > 0)
        {
            /* Valid sequence - copy it */
            memcpy(outp, in, seq_len);
            outp += seq_len;
            outlen += seq_len;
            in += seq_len;
        }
        else
        {
            /* Invalid byte - replace with U+FFFD (0xEF 0xBF 0xBD) */
            if (outlen + 3 < sizeof(out) - 1)
            {
                *outp++ = 0xEF;
                *outp++ = 0xBF;
                *outp++ = 0xBD;
                outlen += 3;
            }
            in += 1;  /* Skip the invalid byte */
            modified = 1;
        }
    }

    *outp = '\0';

    if (!modified)
        return -1;

    /* Copy sanitized string back */
    memcpy(str, out, outlen + 1);
    return (int)outlen;
}

/** Check whether \a str contains non-ASCII characters.
 * @param[in] str String that might contain such characters.
 * @return Non-zero if \a str contains characters with code points > 127,
 * zero if there are none.
 */
int string_contains_non_ascii(const char* str)
{
    assert(str != NULL);

    for ( ; *str; ++str) {
        if ((unsigned char)*str > 127) {
            return 1;
        }
    }

    return 0;
}

/** Check whether \a str contains either only ASCII characters or properly
 * encoded UTF-8 characters.
 * @param[in] str String that might contain such characters.
 * @return Non-zero if \a str contains non-printable characters,
 * zero if there are none.
 */
int string_character_structure_is_sane(const char* str)
{
	assert(str!= NULL);

    if (string_is_valid_utf8(str) || !string_contains_non_ascii(str)) {
		return 1;
	}

	return 0;
}

/** Split a string on certain delimiters.
 * This is a reentrant version of normal strtok().  The first call for
 * a particular input string must use a non-NULL \a str; *save will be
 * initialized based on that.  Later calls must use a NULL \a str;
 * *save will be updated.
 * @param[in,out] save Pointer to a position indicator.
 * @param[in] str Pointer to the input string, or NULL to continue.
 * @param[in] fs String that lists token delimiters.
 * @return Next token in input string, or NULL if no tokens remain.
 */
char* ircd_strtok(char **save, char *str, char *fs)
{
  char *pos = *save;            /* keep last position across calls */
  char *tmp;

  if (str)
    pos = str;                  /* new string scan */

  while (pos && *pos && strchr(fs, *pos) != NULL)
    pos++;                      /* skip leading separators */

  if (!pos || !*pos)
    return (pos = *save = NULL);        /* string contains only sep's */

  tmp = pos;                    /* now, keep position of the token */

  while (*pos && strchr(fs, *pos) == NULL)
    pos++;                      /* skip content of the token */

  if (*pos)
    *pos++ = '\0';              /* remove first sep after the token */
  else
    pos = NULL;                 /* end of string */

  *save = pos;
  return (tmp);
}

/** Rewrite a comma-delimited list of items to remove duplicates.
 * @param[in,out] buffer Comma-delimited list.
 * @return The input buffer \a buffer.
 */
char* canonize(char* buffer)
{
  static char cbuf[BUFSIZE];
  char*       s;
  char*       t;
  char*       cp = cbuf;
  int         l = 0;
  char*       p = NULL;
  char*       p2;

  *cp = '\0';

  for (s = ircd_strtok(&p, buffer, ","); s; s = ircd_strtok(&p, NULL, ","))
  {
    if (l)
    {
      p2 = NULL;
      for (t = ircd_strtok(&p2, cbuf, ","); t; t = ircd_strtok(&p2, NULL, ","))
        if (0 == ircd_strcmp(s, t))
          break;
        else if (p2)
          p2[-1] = ',';
    }
    else
      t = NULL;
    if (!t)
    {
      if (l)
        *(cp - 1) = ',';
      else
        l = 1;
      strcpy(cp, s);
      if (p)
        cp += (p - s);
    }
    else if (p2)
      p2[-1] = ',';
  }
  return cbuf;
}

/** Copy one string to another with guaranteed null-termination.
 * Operates like BSD strlcpy - always null-terminates if size > 0.
 * @param[out] s1 Output buffer.
 * @param[in] s2 Source buffer.
 * @param[in] n Full size of destination buffer (not size-1).
 * @return The original input buffer \a s1.
 *
 * Note: Unlike the original implementation, this takes the FULL buffer
 * size and always null-terminates safely. Callers that previously passed
 * (size-1) should now pass (size) or use sizeof(buffer).
 */
char* ircd_strncpy(char* s1, const char* s2, size_t n)
{
  char* dst = s1;

  assert(0 != s1);
  assert(0 != s2);

  if (n != 0) {
    while (--n != 0) {
      if ((*dst++ = *s2++) == '\0')
        return s1;
    }
    *dst = '\0';
  }
  return s1;
}

/** Append a formatted string at buf[*pos], clamping to buflen.
 * Advances *pos by the number of bytes ACTUALLY written (never the
 * would-be length that vsnprintf returns), and is a safe no-op once
 * the buffer is full.  buf stays NUL-terminated within buflen.
 * Use this instead of the unguarded `x += ircd_snprintf(0, buf+x,
 * buflen-x, ...)` idiom, which overflows once x reaches buflen.
 *
 * Uses libc vsnprintf (not ircd_vsnprintf) so ircd_string stays
 * dependency-light -- it is linked standalone into helper tools like
 * umkpasswd and table_gen that do not link ircd_snprintf.o.  The call
 * sites format only plain %s/%d, so no ircd_snprintf %C-style conversions
 * are needed; C99 vsnprintf's would-be-length return makes the clamp exact.
 */
int str_appendf(char* buf, size_t buflen, size_t* pos, const char* fmt, ...)
{
  va_list args;
  int would;
  size_t remaining, wrote;

  if (!buf || !pos || *pos >= buflen)
    return 0;                       /* full or invalid: no-op */

  remaining = buflen - *pos;        /* >= 1 */
  va_start(args, fmt);
  would = vsnprintf(buf + *pos, remaining, fmt, args);
  va_end(args);

  if (would <= 0)
    return 0;
  /* vsnprintf writes at most remaining-1 chars + NUL and returns the C99
   * would-be length; the bytes actually written are min(would, remaining-1). */
  wrote = ((size_t)would < remaining) ? (size_t)would : (remaining - 1);
  *pos += wrote;
  return (int)wrote;
}

#ifndef FORCEINLINE
NTL_HDR_strChattr { NTL_SRC_strChattr }
NTL_HDR_strCasediff { NTL_SRC_strCasediff }
#endif /* !FORCEINLINE */

/*
 * Other functions visible externally
 */

/** Case insensitive string comparison.
 * @param[in] a First string to compare.
 * @param[in] b Second string to compare.
 * @return Less than, equal to, or greater than zero if \a a is lexicographically less than, equal to, or greater than \a b.
 */
int ircd_strcmp(const char *a, const char *b)
{
  const char* ra = a;
  const char* rb = b;
  while (ToLower(*ra) == ToLower(*rb)) {
    if (!*ra++)
      return 0;
    else
      ++rb;
  }
  return (ToLower(*ra) - ToLower(*rb));
}

/** Case insensitive comparison of the starts of two strings.
 * @param[in] a First string to compare.
 * @param[in] b Second string to compare.
 * @param[in] n Maximum number of characters to compare.
 * @return Less than, equal to, or greater than zero if \a a is
 * lexicographically less than, equal to, or greater than \a b.
 */
int ircd_strncmp(const char *a, const char *b, size_t n)
{
  const char* ra = a;
  const char* rb = b;
  int left = n;
  if (!left--)
    return 0;
  while (ToLower(*ra) == ToLower(*rb)) {
    if (!*ra++ || !left--)
      return 0;
    else
      ++rb;
  }
  return (ToLower(*ra) - ToLower(*rb));
}

/** Is @a token a member of the comma/space/tab-separated @a csv list
 * (case-insensitive, exact token match, no prefix match)?  Empty/NULL csv
 * or token denies.  Pure helper; the SASL layer passes feature_str(...) in. */
/** Truncate \a s in place to at most \a maxbytes bytes (excluding the
 * NUL), never splitting a UTF-8 sequence: if the cut lands mid-sequence
 * the whole partial sequence is dropped.
 * @param[in,out] s        String to clamp (may be NULL).
 * @param[in]     maxbytes Maximum byte length to keep.
 * @return 1 if truncation occurred, 0 if the string already fit.
 */
int ircd_utf8_clamp(char* s, size_t maxbytes)
{
  size_t len;

  if (!s)
    return 0;
  len = strlen(s);
  if (len <= maxbytes)
    return 0;
  /* Back off over UTF-8 continuation bytes so the byte at the cut
   * index is a lead byte (or ASCII); cutting there drops any partial
   * sequence while keeping every complete one. */
  while (maxbytes > 0 && ((unsigned char)s[maxbytes] & 0xC0) == 0x80)
    --maxbytes;
  s[maxbytes] = '\0';
  return 1;
}

/** Compute how many of the \a len bytes at \a text to keep so that at
 * most \a max are kept, never splitting a UTF-8 sequence.  Pure
 * function: it only measures, it does not write to \a text.
 *
 * When \a len is already within \a max, \a len is returned unchanged;
 * otherwise, when the cut would split a UTF-8 sequence, it is moved
 * back to that sequence's lead byte so the sequence is dropped whole.
 * The back-off is at most three bytes (a sequence is at most four) and
 * needs a lead byte whose sequence the cut really splits; text that is
 * not UTF-8 (a Latin-1 / cp1252 run of 0x80-0xBF bytes) keeps the
 * byte-exact cut instead of losing more.  This is the one UTF-8 cut:
 * ircd_line_body_clamp() (every line msgq builds) and the relay's cut
 * of a message at its origin both use it, so they agree on where a
 * text ends.
 *
 * @param[in] text  Bytes to measure (need not be NUL-terminated); may
 *                  be NULL.
 * @param[in] len   Number of bytes at \a text.
 * @param[in] max   Maximum number of bytes to keep.
 * @return The number of bytes (<= \a len, <= \a max when \a len > \a max)
 *         to keep.
 */
size_t ircd_utf8_cut_len(const char* text, size_t len, size_t max)
{
  size_t cut;

  if (!text || len <= max)
    return len;

  cut = max;
  /* The byte at the cut index is the first one dropped.  If it is a
   * continuation byte (10xxxxxx), walk back over at most three of them
   * to the lead byte (11xxxxxx) of the sequence they belong to, and cut
   * there when that sequence runs past the cut.  Anything else -- a
   * fourth continuation byte, ASCII before the run, or a lead whose
   * sequence already ended -- means the bytes are not UTF-8 here, and
   * the byte-exact cut stands. */
  {
    size_t back = cut;
    int steps = 0;
    unsigned char lead;
    size_t seqlen;

    while (steps < 3 && back > 0
           && ((unsigned char)text[back] & 0xC0) == 0x80) {
      --back;
      ++steps;
    }
    lead = (unsigned char)text[back];
    if (steps > 0 && (lead & 0xC0) == 0xC0) {
      seqlen = (lead >= 0xF0) ? 4 : (lead >= 0xE0) ? 3 : 2;
      if (back + seqlen > cut)
        cut = back;
    }
  }
  return cut;
}

/** Compute the length to keep \a line at or under \a body_max body
 * bytes, never splitting a UTF-8 sequence.  Pure function: it only
 * measures, it does not write to \a line.
 *
 * If \a line starts with '@' (a tag region -- the client form's or the
 * S2S compact one), the body is everything after the first space; a
 * tagged line with no space has no body to measure, so the whole line
 * is kept.  Otherwise the body is the whole line.  The body is cut by
 * ircd_utf8_cut_len().
 *
 * @param[in] line     Line to measure (tag region + body, or just a
 *                      body); may be NULL.
 * @param[in] len       Length of \a line in bytes.
 * @param[in] body_max  Maximum number of body bytes to keep.
 * @return The length (<= \a len) that keeps the body at or under
 *         \a body_max bytes.
 */
size_t ircd_line_body_clamp(const char* line, size_t len, size_t body_max)
{
  size_t head = 0;

  if (!line || len == 0)
    return len;

  if (line[0] == '@') {
    const char* sp = memchr(line, ' ', len);
    if (!sp)
      return len; /* no space after the tag region: nothing to measure */
    head = (size_t)(sp - line) + 1;
  }

  return head + ircd_utf8_cut_len(line + head, len - head, body_max);
}

/** Bytes a relayed line leaves for its trailing text.  The line a
 * client receives for a relayed message is
 *   ":" <source> " " <command> " " <target> " :" <text>
 * and everything after the tag region must fit \a body_max bytes (510:
 * RFC 1459's 512 less CRLF, which message-tags keeps for the part after
 * the tags).  Pure arithmetic, so a caller can bound a text by the form
 * its recipients will see before the text is stored or sent anywhere.
 *
 * @param[in] source_len  Length of the source as shown, "nick!user@host".
 * @param[in] cmd_len     Length of the command word ("PRIVMSG").
 * @param[in] target_len  Length of the target as shown, with any
 *                        statusmsg prefix ("@#chan").
 * @param[in] body_max    The line budget after the tags (BUFSIZE - 2).
 * @return The text bytes that fit, or 0 when the line without any text
 *         already fills (or overruns) \a body_max.
 */
size_t ircd_relay_text_room(size_t source_len, size_t cmd_len,
                            size_t target_len, size_t body_max)
{
  /* ':' source ' ' cmd ' ' target ' ' ':' */
  size_t head = 1 + source_len + 1 + cmd_len + 1 + target_len + 2;

  return head < body_max ? body_max - head : 0;
}

/** Length of a source as clients are shown it, "nick!user@host".
 * \a realhost is the real host when the user is not hidden (multiline
 * delivery shows it then, m_batch.c get_displayed_host()) and NULL when
 * the user is hidden, whose real host length nobody is shown; the longer
 * of the two hosts is counted.  Pure, for relay_source_len(). */
size_t ircd_relay_face_len(const char *nick, const char *user,
                           const char *host, const char *realhost)
{
  size_t hlen = host ? strlen(host) : 0;

  if (realhost && strlen(realhost) > hlen)
    hlen = strlen(realhost);
  return (nick ? strlen(nick) : 0) + 1 + (user ? strlen(user) : 0) + 1 + hlen;
}

/** Bytes a bouncer session echo frame leaves for a DM's text within
 * \a body_max (510: S2S lines are cut there, ircd_line_body_clamp()).  A
 * DM from a session with other devices reaches a device on another fork
 * server inside a BX frame (bounce_echo_pm_to_session, m_batch.c
 * emit_bxm_to_remote_member), whose head is longer than the client line's
 * for a short source:
 *   BX E:       "YY BX E AAAAA BBBBB T <nick> <msgid> :"           25+N+M
 *   BX M first: "YY BX M +<id> AAAAA BBBBB T <nick> <msgid> [@<ctags>] :"
 *                                                  27+I+N+M (+2+C)
 * (YY the 2-character server numeric, AAAAA/BBBBB 5-character user
 * numerics, T the one-letter P/O token, I the BX M batch id, at most
 * BX_M_ID_MAX).  Later BX M lines ("M c<id> AAAAA :") are shorter than
 * the first.  \a multiline takes the larger of the BX M first line and
 * BX E (multiline DMs use both, BX E toward legacy bouncer servers).
 * @return The text bytes that fit, or 0. */
size_t ircd_bx_echo_text_room(size_t nick_len, size_t msgid_len,
                              size_t ctags_len, int multiline,
                              size_t body_max)
{
  size_t head = 25 + nick_len + msgid_len;

  if (multiline) {
    size_t mhead = 27 + BX_M_ID_MAX + nick_len + msgid_len
                 + (ctags_len ? 2 + ctags_len : 0);
    if (mhead > head)
      head = mhead;
  }
  return head < body_max ? body_max - head : 0;
}

/** Where to split a multiline line of \a len bytes for a part of at most
 * \a room bytes: ircd_utf8_cut_len(), then moved back so it does not
 * split a mIRC colour code ("\003" with up to two digits, a comma and up
 * to two more) -- the part after it would show the digits as text.  Never
 * 0 for a line that needs a split, so a splitter always progresses (a cut
 * that would leave nothing falls back to the byte-exact \a room).
 * @return The bytes of the first part (\a len when it fits or \a room is 0). */
size_t ircd_split_len(const char *text, size_t len, size_t room)
{
  size_t keep, p;

  if (!text || room == 0 || len <= room)
    return len;
  keep = ircd_utf8_cut_len(text, len, room);
  /* A colour code is at most 6 bytes ("\003NN,NN"): look back 5 bytes. */
  for (p = keep; p > 0 && keep - p < 6; ) {
    --p;
    if (text[p] == '\003') {
      size_t q = p + 1, d = 0;
      while (q < len && d < 2 && text[q] >= '0' && text[q] <= '9') { ++q; ++d; }
      if (d > 0 && q + 1 < len && text[q] == ',' && text[q + 1] >= '0'
          && text[q + 1] <= '9') {
        ++q; d = 0;
        while (q < len && d < 2 && text[q] >= '0' && text[q] <= '9') { ++q; ++d; }
      }
      if (q > keep && p > 0)
        keep = p;  /* the code runs past the cut: it goes to the next part */
      break;
    }
  }
  return keep ? keep : room;
}

/** Length of the RPL_KEYVALUE (761) line that carries a metadata value
 * to a client, after the tags:
 *   ":" <server> " 761 " <viewer> " " <target> " " <key> " " <vis> " :" <value>
 * (the METADATA subscription notification ":" <server> " METADATA "
 * <target> " " <key> " * :" <value> is never longer).  Pure; the caller
 * passes the longest server name, viewer and target it cannot know. */
size_t ircd_keyvalue_line_len(size_t server_len, size_t viewer_len,
                              size_t target_len, size_t key_len,
                              size_t vis_len, size_t value_len)
{
  return 1 + server_len + 5 + viewer_len + 1 + target_len + 1 + key_len
       + 1 + vis_len + 2 + value_len;
}

/** Case-insensitive word-boundary search for \a nick in \a text, using
 * the IRC nickname character class as the boundary definition: a match
 * counts only when the characters on both sides of it are not nickname
 * characters (start/end of string included).  Comparison uses the
 * server casemapping (ircd_strncmp).
 * @param[in] text Message text to scan (may be NULL).
 * @param[in] nick Nickname to look for (may be NULL/empty).
 * @return 1 when mentioned, 0 otherwise.
 */
int ircd_text_mentions(const char* text, const char* nick)
{
  size_t nlen;
  const char* p;

  if (!text || !nick || !*nick)
    return 0;
  nlen = strlen(nick);
  for (p = text; *p; ++p) {
    if ((p == text || !IsNickChar(p[-1]))
        && 0 == ircd_strncmp(p, nick, nlen)
        && !IsNickChar(p[nlen]))
      return 1;
  }
  return 0;
}

/** Escape \a src as a JSON string body (no surrounding quotes) into
 * \a dst: backslash, double-quote, and control characters below 0x20
 * are escaped; everything else (UTF-8 bytes included) passes through
 * verbatim.  Output is always NUL-terminated; content that would
 * overflow is truncated at an escape-sequence boundary.
 * @param[out] dst    Destination buffer.
 * @param[in]  dstlen Destination size in bytes (>= 1).
 * @param[in]  src    Source string (may be NULL == empty).
 * @return dst.
 */
char* ircd_json_escape(char* dst, size_t dstlen, const char* src)
{
  size_t o = 0;
  const unsigned char* p;

  if (!dst || dstlen == 0)
    return dst;
  for (p = (const unsigned char*)(src ? src : ""); *p; ++p) {
    if (*p == '"' || *p == '\\') {
      if (o + 2 >= dstlen)
        break;
      dst[o++] = '\\';
      dst[o++] = (char)*p;
    }
    else if (*p < 0x20) {
      if (o + 6 >= dstlen)
        break;
      dst[o++] = '\\';
      dst[o++] = 'u';
      dst[o++] = '0';
      dst[o++] = '0';
      dst[o++] = "0123456789abcdef"[*p >> 4];
      dst[o++] = "0123456789abcdef"[*p & 0xf];
    }
    else {
      if (o + 1 >= dstlen)
        break;
      dst[o++] = (char)*p;
    }
  }
  dst[o] = '\0';
  return dst;
}

int csv_contains_token(const char* csv, const char* token)
{
  const char *p;
  size_t nlen;
  if (!csv || !*csv || !token || !*token)
    return 0;
  nlen = strlen(token);
  for (p = csv; *p; ) {
    const char *start;
    size_t tlen;
    while (*p == ',' || *p == ' ' || *p == '\t')
      p++;
    start = p;
    while (*p && *p != ',' && *p != ' ' && *p != '\t')
      p++;
    tlen = (size_t)(p - start);
    if (tlen == nlen && 0 == ircd_strncmp(start, token, nlen))
      return 1;
  }
  return 0;
}

/* ------------------------------------------------------------------
 * CLIENTTAGDENY matcher (message-tags spec normalisation)
 *
 * The IRCv3 message-tags spec writes CLIENTTAGDENY entries WITHOUT
 * the client-only '+' prefix (e.g. "*,-draft/react,-draft/reply"),
 * but this fork's config has historically carried entries with it
 * ("+draft/language").  Both forms name the same tag; this matcher
 * normalises an entry's single optional leading '+' (after any
 * leading '-') away before comparing, so a deny list can mix spec
 * form and fork form freely.  It is pure and dependency-light (no
 * feature_str() lookup here -- the caller passes the deny list in),
 * matching the msgid_decode_time_ms() helpers above.
 * ------------------------------------------------------------------ */

/** Match a client-only tag against an operator CLIENTTAGDENY list.
 *
 * Semantics (preserved from the pre-fix is_client_tag_denied(),
 * except where noted):
 *   - a tag not starting with '+' is never denied;
 *   - a bare "*" entry denies every client-only tag;
 *   - "name/" + "*" (or "+name/" + "*") is a prefix wildcard -- it
 *     denies/exempts any "+name/<something>" tag, but NOT the bare
 *     "+name/" itself with nothing past the slash.  The pre-fix
 *     matcher applied that "longer than the prefix" rule only to
 *     negated wildcards; positive wildcards now follow the same
 *     rule for consistency (see the hotfix 6 report for the
 *     pre-fix asymmetry);
 *   - an exact entry matches the tag's NAME, ignoring any
 *     "=value" the tag carries on the wire -- CLIENTTAGDENY
 *     filters by tag key per spec, and tags like draft/reply or
 *     draft/react are essentially never sent bare;
 *   - a negated wildcard/exact entry ("-name", "-+name",
 *     "-name/" + "*", "-+name/" + "*") exempts a matching tag, and
 *     an exemption always wins over a denial of the same tag;
 *   - spaces around an entry are ignored; empty entries (from
 *     doubled commas, etc.) are skipped;
 *   - a bare "+*" is treated the same as "*" (deny-all), matching
 *     what ircd_clienttagdeny_isupport() normalises it to;
 *   - comparisons are case-INsensitive per ircd_strncmp (ASCII fold).
 *
 * @param[in] deny_list The FEAT_CLIENTTAGDENY value (comma-separated
 *                      entries); NULL or empty denies nothing.
 * @param[in] tag The client-only tag as seen on the wire, including
 *                its leading '+' (name, optionally "=value").
 * @param[in] tag_len Length of \a tag.
 * @return 1 if the tag is denied, 0 otherwise. */
int ircd_clienttagdeny_match(const char *deny_list, const char *tag, size_t tag_len)
{
  const char *p, *entry_start;
  size_t entry_len;
  int deny_all = 0;
  int exempted = 0;
  int denied = 0;

  if (!tag || tag_len == 0 || tag[0] != '+')
    return 0;
  if (!deny_list || !*deny_list)
    return 0;

  /* First pass: a bare "*" entry means deny-all (whitelist mode). */
  p = deny_list;
  while (*p) {
    while (*p == ' ' || *p == ',')
      p++;
    if (!*p)
      break;
    entry_start = p;
    while (*p && *p != ',')
      p++;
    entry_len = p - entry_start;
    while (entry_len > 0 && entry_start[entry_len - 1] == ' ')
      entry_len--;
    if ((entry_len == 1 && entry_start[0] == '*') ||
        (entry_len == 2 && entry_start[0] == '+' && entry_start[1] == '*'))
      deny_all = 1;   /* "*" and "+*" both mean deny-all (005 normalises
                       * "+*" to "*"; the matcher must agree). */
  }

  /* Second pass: negated and positive entries, '+' normalised away. */
  p = deny_list;
  while (*p) {
    const char *name;
    size_t name_len;
    int negate = 0;

    while (*p == ' ' || *p == ',')
      p++;
    if (!*p)
      break;
    entry_start = p;
    while (*p && *p != ',')
      p++;
    entry_len = p - entry_start;
    while (entry_len > 0 && entry_start[entry_len - 1] == ' ')
      entry_len--;
    if (entry_len == 0)
      continue;
    if ((entry_len == 1 && entry_start[0] == '*') ||
        (entry_len == 2 && entry_start[0] == '+' && entry_start[1] == '*'))
      continue;   /* handled in the first pass */

    name = entry_start;
    name_len = entry_len;
    if (name_len > 0 && name[0] == '-') {
      negate = 1;
      name++;
      name_len--;
      if (name_len == 0)
        continue;
    }
    /* Spec form ("draft/x") and fork form ("+draft/x") name the
     * same tag -- one leading '+' on the (possibly negated) entry
     * is optional and dropped before comparing. */
    if (name_len > 0 && name[0] == '+') {
      name++;
      name_len--;
      if (name_len == 0)
        continue;
    }

    if (name_len >= 2 && name[name_len - 1] == '*' && name[name_len - 2] == '/') {
      /* "prefix/" + "*" wildcard: requires at least one char past
       * the slash on the tag side (same rule for both polarities). */
      size_t prefix_len = name_len - 1;  /* includes '/', excludes '*' */
      if (tag_len - 1 > prefix_len &&
          ircd_strncmp(tag + 1, name, prefix_len) == 0) {
        if (negate)
          exempted = 1;
        else
          denied = 1;
      }
    }
    else if (tag_len - 1 >= name_len &&
             ircd_strncmp(tag + 1, name, name_len) == 0 &&
             (tag_len - 1 == name_len || tag[1 + name_len] == '=')) {
      /* Exact name match, tolerating a trailing "=value" on the
       * wire tag (see the doc comment: CLIENTTAGDENY filters by
       * tag key, not value). */
      if (negate)
        exempted = 1;
      else
        denied = 1;
    }
  }

  if (exempted)
    return 0;
  if (denied)
    return 1;
  if (deny_all)
    return 1;
  return 0;
}

/** Sanitize a CLIENTTAGDENY feature value into its 005 ISUPPORT form.
 *
 * Every caller that puts CLIENTTAGDENY on the wire -- the feature's own
 * change notify (ircd_features.c set_isupport_clienttagdeny()) AND
 * init_isupport()'s unconditional rebuild at boot and on every REHASH
 * (s_user.c) -- must go through this ONE function, or whichever ran
 * last wins: init_isupport() used to re-add the raw feature string
 * verbatim after a REHASH, skipping the "+" normalisation below on
 * whatever value was current at that point (a REHASH resetting a
 * SET-only value back to its config/default, via feature_mark(), is
 * normal and by design -- that part was never the bug).
 *
 * - Each entry is trimmed of leading/trailing spaces; an empty entry
 *   (from doubled commas, or an entry that was only spaces) is skipped.
 * - One optional leading '+' (after any leading '-') is stripped, same
 *   as ircd_clienttagdeny_match() -- spec form and fork form advertise
 *   identically.  "+*" normalises to the bare "*" deny-all.
 * - IRCv3 #600 ("Servers MUST NOT advertise the same tag twice in the
 *   list, negated or otherwise"): exact duplicates are dropped; when a
 *   tag appears both plain and negated, only the negated form
 *   survives (matching ircd_clienttagdeny_match(), where negation
 *   wins) -- regardless of which form came first, and regardless of
 *   whether the surviving entry ends up as the last, comma-less token
 *   in \a out (the lookup walks a comma-WRAPPED copy of \a out so
 *   every entry, including the tail, is anchored on both sides; the
 *   pre-fix code searched for "name," directly in \a out, which a
 *   comma-less tail entry never has, so a plain-before-negated pair
 *   where the plain entry landed last was never fixed up).
 *
 * @param[in] in The FEAT_CLIENTTAGDENY value; NULL/empty clears \a out.
 * @param[out] out The sanitised, comma-separated 005 value.
 * @param[in] outsz Size of \a out; \a out is always NUL-terminated.
 * @return \a out. */
const char *ircd_clienttagdeny_isupport(const char *in, char *out, size_t outsz)
{
  const char *p, *entry_start;
  size_t entry_len;

  if (outsz > 0)
    out[0] = '\0';
  if (!in || !*in || outsz == 0)
    return out;

  /* The scratch buffers below (norm/haystack/probe_*) are sized off
   * BUFSIZE, matching both real callers (set_isupport_clienttagdeny(),
   * init_isupport(), each with a BUFSIZE-sized `out`).  Clamp the
   * working size so a hypothetical caller with a LARGER buffer can't
   * grow `out`'s accumulated content past what `haystack` can hold --
   * otherwise the dedup search below would run against a silently
   * truncated copy of `out`, missing or misplacing a match. */
  if (outsz > BUFSIZE)
    outsz = BUFSIZE;

  p = in;
  while (*p) {
    const char *name;
    size_t name_len;
    int negate;
    char norm[BUFSIZE];
    char haystack[BUFSIZE + 2];
    char probe_neg[BUFSIZE + 2];
    char probe_plain[BUFSIZE + 2];
    char *hit;
    size_t cur;

    /* Trim: leading spaces/commas between entries, then trailing
     * spaces on this one. */
    while (*p == ' ' || *p == ',')
      p++;
    if (!*p)
      break;
    entry_start = p;
    while (*p && *p != ',')
      p++;
    entry_len = p - entry_start;
    while (entry_len > 0 && entry_start[entry_len - 1] == ' ')
      entry_len--;
    if (entry_len == 0)
      continue;

    /* Normalise: strip one leading '-' (negation), then one leading
     * '+' (spec/fork equivalence; "+*" -> "*" deny-all falls out of
     * this for free, since "*" alone is left untouched below). */
    name = entry_start;
    name_len = entry_len;
    negate = (name_len > 0 && name[0] == '-');
    if (negate) {
      name++;
      name_len--;
    }
    if (name_len > 0 && name[0] == '+') {
      name++;
      name_len--;
    }
    if (name_len == 0)
      continue;
    /* A negated bare "*" ("-*", "-+*") does not mean "exempt the
     * literal tag named *" -- no real tag is ever named that -- so
     * letting it fall into the ordinary dedup path below would
     * negate-and-rewrite an EARLIER bare "*" deny-all entry into
     * "-*", which a spec client reads as "nothing is denied" while
     * the matcher (ircd_clienttagdeny_match(), where the same
     * negated-"*" entry is equally inert) still denies everything.
     * Drop it outright; it never changes what the 005 or the
     * matcher do. */
    if (negate && name_len == 1 && name[0] == '*')
      continue;
    if (name_len > sizeof(norm) - 2)
      name_len = sizeof(norm) - 2;   /* defensive clamp; BUFSIZE-sized
                                      * config values never reach this */

    if (negate) {
      norm[0] = '-';
      memcpy(norm + 1, name, name_len);
      norm[name_len + 1] = '\0';
    } else {
      memcpy(norm, name, name_len);
      norm[name_len] = '\0';
    }

    /* #600 dedup against what's in `out` so far. */
    snprintf(haystack, sizeof(haystack), ",%s,", out);
    snprintf(probe_neg, sizeof(probe_neg), ",-%.*s,", (int)name_len, name);
    snprintf(probe_plain, sizeof(probe_plain), ",%.*s,", (int)name_len, name);

    if (strstr(haystack, probe_neg))
      continue;   /* negated form already present */

    hit = strstr(haystack, probe_plain);
    if (hit) {
      if (negate) {
        /* Plain form already present; negation wins.  `haystack` is
         * `out` shifted right by the one leading sentinel comma, so
         * `hit - haystack` is `name`'s offset into `out` too -- this
         * works even when the plain entry is the last, comma-less
         * token in `out`, which a direct search of `out` itself
         * (for "name,") would miss. */
        char *in_out = out + (hit - haystack);
        if (strlen(out) + 2 < outsz) {
          memmove(in_out + 1, in_out, strlen(in_out) + 1);
          *in_out = '-';
        } else {
          /* No room left to insert the leading '-'.  Leaving the
           * plain form in place would be actively wrong -- it would
           * go on advertising this tag as allowed (or denied) with
           * the opposite of the polarity the operator just asked
           * for -- so delete the entry outright instead: absent is
           * honest, wrong-polarity is not. */
          size_t at = (size_t)(in_out - out);
          size_t total = strlen(out);
          size_t after = at + name_len;
          if (after < total && out[after] == ',')
            after++;                      /* swallow the trailing comma */
          else if (at > 0 && out[at - 1] == ',')
            at--;                         /* tail entry: swallow the leading comma instead */
          memmove(out + at, out + after, total - after + 1);  /* +1 for NUL */
        }
      }
      continue;   /* plain form (or now-negated/now-deleted form) already present */
    }

    cur = strlen(out);
    if (cur + strlen(norm) + 2 >= outsz)
      continue;   /* THIS entry doesn't fit -- skip only it; a later
                   * negation of a tag already in `out` still needs
                   * its turn (it only inserts one '-' into existing
                   * content, so it fits even when a whole new entry
                   * would not). A bare `break` here used to abandon
                   * every entry after the first one that overflowed,
                   * so a negation placed later in a long list was
                   * silently never applied. */
    if (cur)
      out[cur++] = ',';
    memcpy(out + cur, norm, strlen(norm) + 1);
  }
  return out;
}

/* ------------------------------------------------------------------
 * Reserved vendor tag namespace (server-authored, client-unforgeable)
 *
 * `+afternet.org/` is reserved WHOLE: the network's own domain (cf.
 * the afternet.org/account WEBIRC option), independent of any single
 * use -- and pre-2026-08-29 PM-history records carry their sid
 * marker under it, so the reservation can never be narrowed without
 * re-poisoning that legacy residue.
 *
 * `+evilnet.github.io/` is this fork's own vendor namespace, but
 * Seance -- itself an evilnet project -- legitimately wants ordinary
 * client-only tags under it too (e.g.
 * `+evilnet.github.io/machine-translated`; user decision 2026-11-09).
 * So only the NAMES the server itself writes and trusts are reserved
 * there -- not the whole namespace:
 *   sid              -- the PM-history auth marker.  SECURITY-relevant:
 *                        forging it would grant access to another
 *                        session's PM history (ircd_relay.c store;
 *                        history.c / history_pm_target_has_sessid
 *                        checks it).
 *   ssid, rsid       -- internal PM naming tags (ircd_relay.c store;
 *                        replay.c pm_tag_value() reads them).
 *   chathistory-gap  -- the server's own gap-marker line
 *                        (m_chathistory.c send_gap_marker()).
 * Everything else under `+evilnet.github.io/` is an ordinary
 * client-only tag -- still subject to CLIENTTAGDENY above, just not
 * reserved outright.
 *
 * Add a future server-written tag name HERE ONLY: is_reserved_vendor_tag()
 * (ircd.c, the parse.c capture-time gate) and m_chathistory.c's
 * strip_internal_tags() (hiding these from chathistory playback) both
 * call this one function.
 * ------------------------------------------------------------------ */
static const char rvt_evilnet_prefix[] = "+evilnet.github.io/";
static const char rvt_afternet_prefix[] = "+afternet.org/";
static const char *rvt_evilnet_reserved_names[] = { "sid", "ssid", "rsid", "chathistory-gap" };

/** Does the NAME at \a name (length \a name_len, optionally followed
 * by "=value" within the original tag) equal \a want exactly -- never
 * a byte-prefix ("sid" must not match "sidecar")? */
static int rvt_name_is(const char *name, size_t name_len, const char *want)
{
  size_t wlen = strlen(want);
  if (name_len < wlen)
    return 0;
  if (0 != ircd_strncmp(name, want, wlen))
    return 0;
  return name_len == wlen || name[wlen] == '=';
}

/** Is \a tag (length \a tag_len, including its leading '+') in a
 * vendor namespace the server reserves for its own use?  See the
 * block comment above for exactly which names qualify.
 * @param[in] tag The tag name to check (including + prefix).
 * @param[in] tag_len Length of the tag (name, optionally "=value").
 * @return 1 if the tag is reserved to the server, 0 otherwise. */
int ircd_reserved_vendor_tag(const char *tag, size_t tag_len)
{
  size_t plen;

  if (!tag)
    return 0;

  plen = strlen(rvt_afternet_prefix);
  if (tag_len >= plen && 0 == ircd_strncmp(tag, rvt_afternet_prefix, plen))
    return 1;   /* whole namespace reserved (legacy) */

  plen = strlen(rvt_evilnet_prefix);
  if (tag_len >= plen && 0 == ircd_strncmp(tag, rvt_evilnet_prefix, plen)) {
    const char *name = tag + plen;
    size_t name_len = tag_len - plen;
    size_t i;
    for (i = 0; i < sizeof(rvt_evilnet_reserved_names) / sizeof(rvt_evilnet_reserved_names[0]); i++)
      if (rvt_name_is(name, name_len, rvt_evilnet_reserved_names[i]))
        return 1;
  }
  return 0;
}

/** Copy \a in to \a out, dropping any ';'-separated client-only tag
 * for which ircd_reserved_vendor_tag() is true.  One pure filter
 * shared by m_chathistory.c's strip_internal_tags() (hiding these
 * from chathistory playback) and ircd_relay.c's
 * store_private_history() (defence in depth: scrub anything already
 * in an incoming client_tags -- e.g. relayed from another server's
 * S2S ',C' -- before layering this server's own sid/ssid/rsid on top,
 * in case a buggy or hostile fork peer forged one; this is in
 * addition to, never a substitute for, the capture-time gate in
 * parse.c, which already keeps a tag matching a reserved name out of
 * a LOCAL client's client_tags to begin with).
 * @param[in] in The tag list to filter; NULL is treated as empty.
 * @param[out] out The filtered, ';'-separated tag list.
 * @param[in] outsz Size of \a out; \a out is always NUL-terminated.
 * @return \a out (empty when nothing else was there). */
const char *ircd_strip_reserved_vendor_tags(const char *in, char *out, size_t outsz)
{
  size_t pos = 0;

  if (outsz > 0)
    out[0] = '\0';
  if (!in || outsz == 0)
    return out;

  while (*in) {
    const char *end = strchr(in, ';');
    size_t len = end ? (size_t)(end - in) : strlen(in);
    if (!ircd_reserved_vendor_tag(in, len) && len > 0 && pos + len + 2 <= outsz) {
      if (pos)
        out[pos++] = ';';
      memcpy(out + pos, in, len);
      pos += len;
      out[pos] = '\0';
    }
    in = end ? end + 1 : in + len;
  }
  return out;
}

/** Fill a vector of distinct names from a delimited input list.
 * Empty tokens (when \a token occurs at the start or end of \a list,
 * or when \a token occurs adjacent to itself) are ignored.  When
 * \a size tokens have been written to \a vector, the rest of the
 * string is ignored.
 * Unlike token_vector(), if a token repeats an earlier token, it is
 * skipped.
 * @param[in,out] names Input buffer.
 * @param[in] token Delimiter used to split \a list.
 * @param[out] vector Output vector.
 * @param[in] size Maximum number of elements to put in \a vector.
 * @return Number of elements written to \a vector.
 */
int unique_name_vector(char* names, char token, char** vector, int size)
{
  int   i;
  int   count = 0;
  char* start = names;
  char* end;

  assert(0 != names);
  assert(0 != vector);
  assert(0 < size);

  /*
   * ignore spurious tokens
   */
  while (token == *start)
    ++start;

  for (end = strchr(start, token); end; end = strchr(start, token)) {
    *end++ = '\0';
    /*
     * ignore spurious tokens
     */
    while (token == *end)
      ++end;
    for (i = 0; i < count; ++i) {
      if (0 == ircd_strcmp(vector[i], start))
        break;
    }
    if (i == count) {
      vector[count++] = start;
      if (count == size)
        return count;
    }
    start = end;
  }
  if (*start) {
    for (i = 0; i < count; ++i)
      if (0 == ircd_strcmp(vector[i], start))
        return count;
    vector[count++] = start;
  }
  return count;
}

/** Fill a vector of tokens from a delimited input list.
 * Empty tokens (when \a token occurs at the start or end of \a list,
 * or when \a token occurs adjacent to itself) are ignored.  When
 * \a size tokens have been written to \a vector, the rest of the
 * string is ignored.
 * @param[in,out] names Input buffer.
 * @param[in] token Delimiter used to split \a list.
 * @param[out] vector Output vector.
 * @param[in] size Maximum number of elements to put in \a vector.
 * @return Number of elements written to \a vector.
 */
int token_vector(char* names, char token, char** vector, int size)
{
  int   count = 0;
  char* start = names;
  char* end;

  assert(0 != names);
  assert(0 != vector);
  assert(1 < size);

  vector[count++] = start;
  for (end = strchr(start, token); end; end = strchr(start, token)) {
    *end++ = '\0';
    start = end;
    if (*start) {
      vector[count++] = start;
      if (count < size)
        continue;
    }
    break;
  }
  return count;
}

/** Copy all or part of the hostname in a string to another string.
 * If \a userhost contains an '\@', the remaining portion is used;
 * otherwise, the whole \a userhost is used.
 * @param[out] buf Output buffer (must be at least len+1 bytes).
 * @param[in] userhost user\@hostname or hostname string.
 * @param[in] len Maximum content length (not including null terminator).
 * @return The output buffer \a buf.
 */
char* host_from_uh(char* buf, const char* userhost, size_t len)
{
  const char* s;

  assert(0 != buf);
  assert(0 != userhost);

  if ((s = strchr(userhost, '@')))
    ++s;
  else
    s = userhost;
  ircd_strncpy(buf, s, len + 1);
  return buf;
}

/*
 * this new faster inet_ntoa was ripped from:
 * From: Thomas Helvey <tomh@inxpress.net>
 */
/** Array of text strings for dotted quads. */
static const char* IpQuadTab[] =
{
    "0",   "1",   "2",   "3",   "4",   "5",   "6",   "7",   "8",   "9",
   "10",  "11",  "12",  "13",  "14",  "15",  "16",  "17",  "18",  "19",
   "20",  "21",  "22",  "23",  "24",  "25",  "26",  "27",  "28",  "29",
   "30",  "31",  "32",  "33",  "34",  "35",  "36",  "37",  "38",  "39",
   "40",  "41",  "42",  "43",  "44",  "45",  "46",  "47",  "48",  "49",
   "50",  "51",  "52",  "53",  "54",  "55",  "56",  "57",  "58",  "59",
   "60",  "61",  "62",  "63",  "64",  "65",  "66",  "67",  "68",  "69",
   "70",  "71",  "72",  "73",  "74",  "75",  "76",  "77",  "78",  "79",
   "80",  "81",  "82",  "83",  "84",  "85",  "86",  "87",  "88",  "89",
   "90",  "91",  "92",  "93",  "94",  "95",  "96",  "97",  "98",  "99",
  "100", "101", "102", "103", "104", "105", "106", "107", "108", "109",
  "110", "111", "112", "113", "114", "115", "116", "117", "118", "119",
  "120", "121", "122", "123", "124", "125", "126", "127", "128", "129",
  "130", "131", "132", "133", "134", "135", "136", "137", "138", "139",
  "140", "141", "142", "143", "144", "145", "146", "147", "148", "149",
  "150", "151", "152", "153", "154", "155", "156", "157", "158", "159",
  "160", "161", "162", "163", "164", "165", "166", "167", "168", "169",
  "170", "171", "172", "173", "174", "175", "176", "177", "178", "179",
  "180", "181", "182", "183", "184", "185", "186", "187", "188", "189",
  "190", "191", "192", "193", "194", "195", "196", "197", "198", "199",
  "200", "201", "202", "203", "204", "205", "206", "207", "208", "209",
  "210", "211", "212", "213", "214", "215", "216", "217", "218", "219",
  "220", "221", "222", "223", "224", "225", "226", "227", "228", "229",
  "230", "231", "232", "233", "234", "235", "236", "237", "238", "239",
  "240", "241", "242", "243", "244", "245", "246", "247", "248", "249",
  "250", "251", "252", "253", "254", "255"
};

/** Convert an IP address to printable ASCII form.
 * This is generally deprecated in favor of ircd_ntoa_r().
 * @param[in] in Address to convert.
 * @return Pointer to a static buffer containing the readable form.
 */
const char* ircd_ntoa(const struct irc_in_addr* in)
{
  static char buf[SOCKIPLEN];
  return ircd_ntoa_r(buf, in);
}

/** Convert an IP address to printable ASCII form.
 * @param[out] buf Output buffer to write to.
 * @param[in] in Address to format.
 * @return Pointer to the output buffer \a buf.
 */
const char* ircd_ntoa_r(char* buf, const struct irc_in_addr* in)
{
    assert(buf != NULL);
    assert(in != NULL);

    if (irc_in_addr_is_ipv4(in)) {
      unsigned int pos, len;
      unsigned char *pch;

      pch = (unsigned char*)&in->in6_16[6];
      len = strlen(IpQuadTab[*pch]);
      memcpy(buf, IpQuadTab[*pch++], len);
      pos = len;
      buf[pos++] = '.';
      len = strlen(IpQuadTab[*pch]);
      memcpy(buf+pos, IpQuadTab[*pch++], len);
      pos += len;
      buf[pos++] = '.';
      len = strlen(IpQuadTab[*pch]);
      memcpy(buf+pos, IpQuadTab[*pch++], len);
      pos += len;
      buf[pos++] = '.';
      len = strlen(IpQuadTab[*pch]);
      memcpy(buf+pos, IpQuadTab[*pch++], len);
      buf[pos + len] = '\0';
      return buf;
    } else {
      static const char hexdigits[] = "0123456789abcdef";
      unsigned int pos, part, max_start, max_zeros, curr_zeros, ii;

      /* Find longest run of zeros. */
      for (max_start = ii = 1, max_zeros = curr_zeros = 0; ii < 8; ++ii) {
        if (!in->in6_16[ii])
          curr_zeros++;
        else {
          if (curr_zeros > max_zeros) {
            max_start = ii - curr_zeros;
            max_zeros = curr_zeros;
          }
          curr_zeros = 0;
        }
      }
      if (curr_zeros > max_zeros) {
        max_start = ii - curr_zeros;
        max_zeros = curr_zeros;
      }

      /* Print out address. */
/** Append \a CH to the output buffer. */
#define APPEND(CH) do { buf[pos++] = (CH); } while (0)
      for (pos = ii = 0; (ii < 8); ++ii) {
        if ((max_zeros > 0) && (ii == max_start)) {
          APPEND(':');
          ii += max_zeros - 1;
          continue;
        }
        part = ntohs(in->in6_16[ii]);
        if (part >= 0x1000)
          APPEND(hexdigits[part >> 12]);
        if (part >= 0x100)
          APPEND(hexdigits[(part >> 8) & 15]);
        if (part >= 0x10)
          APPEND(hexdigits[(part >> 4) & 15]);
        APPEND(hexdigits[part & 15]);
        if (ii < 7)
          APPEND(':');
      }
#undef APPEND

      /* Nul terminate and return number of characters used. */
      buf[pos++] = '\0';
      return buf;
    }
}

/** Attempt to parse an IPv4 address into a network-endian form.
 * @param[in] input Input string.
 * @param[out] output Network-endian representation of the address.
 * @param[out] pbits Number of bits found in pbits.
 * @return Number of characters used from \a input, or 0 if the parse failed.
 */
static unsigned int
ircd_aton_ip4(const char *input, unsigned int *output, unsigned char *pbits)
{
  unsigned int dots = 0, pos = 0, part = 0, ip = 0, bits;

  /* Intentionally no support for bizarre IPv4 formats (plain
   * integers, octal or hex components) -- only vanilla dotted
   * decimal quads.
   */
  if (input[0] == '.')
    return 0;
  bits = 32;
  while (1) switch (input[pos]) {
  case '\0':
    if (dots < 3)
      return 0;
  out:
    ip |= part << (24 - 8 * dots);
    *output = htonl(ip);
    if (pbits)
      *pbits = bits;
    return pos;
  case '.':
    if (++dots > 3)
      return 0;
    if (input[++pos] == '.')
      return 0;
    ip |= part << (32 - 8 * dots);
    part = 0;
    if (input[pos] == '*') {
      while (input[++pos] == '*' || input[pos] == '.') ;
      if (input[pos] != '\0')
        return 0;
      if (pbits)
        *pbits = dots * 8;
      *output = htonl(ip);
      return pos;
    }
    break;
  case '/':
    if (!pbits || !IsDigit(input[pos + 1]))
      return 0;
    for (bits = 0; IsDigit(input[++pos]); )
      bits = bits * 10 + input[pos] - '0';
    if (bits > 32)
      return 0;
    goto out;
  case '0': case '1': case '2': case '3': case '4':
  case '5': case '6': case '7': case '8': case '9':
    part = part * 10 + input[pos++] - '0';
    if (part > 255)
      return 0;
    break;
  default:
    return 0;
  }
}

/** Parse a numeric IPv4 or IPv6 address into an irc_in_addr.
 * @param[in] input Input buffer.
 * @param[out] ip Receives parsed IP address.
 * @param[out] pbits If non-NULL, receives number of bits specified in address mask.
 * @return Number of characters used from \a input, or 0 if the
 * address was unparseable or malformed.
 */
int
ipmask_parse(const char *input, struct irc_in_addr *ip, unsigned char *pbits)
{
  char *colon;
  char *dot;

  assert(ip);
  assert(input);
  memset(ip, 0, sizeof(*ip));
  colon = strchr(input, ':');
  dot = strchr(input, '.');

  if (colon && (!dot || (dot > colon))) {
    unsigned int part = 0, pos = 0, ii = 0, colon = 8;
    const char *part_start = NULL;

    /* Parse IPv6, possibly like ::127.0.0.1.
     * This is pretty straightforward; the only trick is borrowed
     * from Paul Vixie (BIND): when it sees a "::" continue as if
     * it were a single ":", but note where it happened, and fill
     * with zeros afterward.
     */
    if (input[pos] == ':') {
      if ((input[pos+1] != ':') || (input[pos+2] == ':'))
        return 0;
      colon = 0;
      pos += 2;
      part_start = input + pos;
    }
    while (ii < 8) switch (input[pos]) {
      unsigned char chval;
    case '0': case '1': case '2': case '3': case '4':
    case '5': case '6': case '7': case '8': case '9':
      chval = input[pos] - '0';
    use_chval:
      part = (part << 4) | chval;
      if (part > 0xffff)
        return 0;
      pos++;
      break;
    case 'A': case 'B': case 'C': case 'D': case 'E': case 'F':
      chval = input[pos] - 'A' + 10;
      goto use_chval;
    case 'a': case 'b': case 'c': case 'd': case 'e': case 'f':
      chval = input[pos] - 'a' + 10;
      goto use_chval;
    case ':':
      part_start = input + ++pos;
      if (input[pos] == '.')
        return 0;
      ip->in6_16[ii++] = htons(part);
      part = 0;
      if (input[pos] == ':') {
        if (colon < 8)
          return 0;
        if (ii == 8)
            return 0;
        colon = ii;
        pos++;
      }
      break;
    case '.': {
      uint32_t ip4;
      unsigned int len;
      len = ircd_aton_ip4(part_start, &ip4, pbits);
      if (!len || (ii > 6))
        return 0;
      ip->in6_16[ii++] = htons(ntohl(ip4) >> 16);
      ip->in6_16[ii++] = htons(ntohl(ip4) & 65535);
      if (pbits)
        *pbits += 96;
      pos = part_start + len - input;
      goto finish;
    }
    case '/':
      if (!pbits || !IsDigit(input[pos + 1]))
        return 0;
      ip->in6_16[ii++] = htons(part);
      for (part = 0; IsDigit(input[++pos]); )
        part = part * 10 + input[pos] - '0';
      if (part > 128)
        return 0;
      *pbits = part;
      goto finish;
    case '*':
      while (input[++pos] == '*' || input[pos] == ':') ;
      if (input[pos] != '\0' || colon < 8)
        return 0;
      if (part && ii < 8)
          ip->in6_16[ii++] = htons(part);
      if (pbits)
        *pbits = ii * 16;
      return pos;
    case '\0':
      ip->in6_16[ii++] = htons(part);
      if (colon == 8 && ii < 8)
        return 0;
      if (pbits)
        *pbits = 128;
      goto finish;
    default:
      return 0;
    }
    if (input[pos] != '\0')
      return 0;
  finish:
    if (colon < 8) {
      unsigned int jj;
      /* Shift stuff after "::" up and fill middle with zeros. */
      for (jj = 0; jj < ii - colon; jj++)
        ip->in6_16[7 - jj] = ip->in6_16[ii - jj - 1];
      for (jj = 0; jj < 8 - ii; jj++)
        ip->in6_16[colon + jj] = 0;
    }
    return pos;
  } else if (dot || strchr(input, '/')) {
    unsigned int addr;
    int len = ircd_aton_ip4(input, &addr, pbits);
    if (len) {
      ip->in6_16[5] = htons(65535);
      ip->in6_16[6] = htons(ntohl(addr) >> 16);
      ip->in6_16[7] = htons(ntohl(addr) & 65535);
      if (pbits)
        *pbits += 96;
    }
    return len;
  } else if (input[0] == '*') {
    unsigned int pos = 0;
    while (input[++pos] == '*') ;
    if (input[pos] != '\0')
      return 0;
    if (pbits)
      *pbits = 0;
    return pos;
  } else return 0; /* parse failed */
}

char* itoa(int n) {
  int i=0,j;
  static char s[17];
  static char u[17];

  do{
    s[i++]=(char)( n%10+48 );
    n-=n%10;
  }
  while((n/=10)>0);
  for (j=0;j<i;j++)
  u[i-1-j]=s[j];

  u[j]='\0';
  return (char *)&u;
}

static long
TypeLength(char type)
{
    switch (type) {
    case 'y': return 365*24*60*60;
    case 'M': return 31*24*60*60;
    case 'w': return 7*24*60*60;
    case 'd': return 24*60*60;
    case 'h': return 60*60;
    case 'm': return 60;
    case 's': return 1;
    default: return 0;
    }
}


unsigned long
ParseInterval(const char *interval)
{
    unsigned long seconds = 0;
    int partial = 0;
    char c;

    /* process the string, resetting the count if we find a unit character */
    while ((c = *interval++)) {
        if (IsDigit((int)c)) {
            partial = partial*10 + c - '0';
        } else {
            seconds += TypeLength(c) * partial;
            partial = 0;
        }
    }
    /* assume the last chunk is seconds (the normal case) */
    return seconds + partial;
}

int is_timestamp(char *str)
{

  while ( IsDigit(*str) || *str == '.' )
    ++str;

  return *str == '\0';
}

const char* StripColor(const char* text)
{
  static char stripped[BUFSIZE];
  const char *src;
  char *dest;

  dest = stripped;
  for (src = text; (*src); src++) {
    switch (*src) {
      case COLOR_BOLD:
      case COLOR_REVERSE:
      case COLOR_UNDERLINE:
      case COLOR_ITALIC:
      case COLOR_NORMAL:
        break;
      case COLOR_COLOR:
        if (!IsDigit(src[1])) break;
        src++;
        if (IsDigit(src[1])) src++;
        if (src[1]==',' && IsDigit(src[2])) src+=2;
        else break;
        if (IsDigit(src[1])) src++;
        break;
      default:
        *dest++ = *src;
    }
  }

  *dest = '\0';
  return (const char*) stripped;
}

int HasColor(const char* text)
{
  const char *tmp;
  for (tmp = text; (*tmp); tmp++) {
    if (*tmp & 224) continue;
    switch (*tmp) {
      case COLOR_BOLD:
      case COLOR_REVERSE:
      case COLOR_UNDERLINE:
      case COLOR_ITALIC:
      case COLOR_NORMAL:
      case COLOR_COLOR:
        return 1;
      default:;
    }
  }
  return 0;
}

int check_if_ipmask(const char *mask)
{
  int has_digit = 0;
  const char *p;

  if (*mask == '.' || *mask == '/')
    return 0;
  for (p = mask; *p; ++p)
    if (*p != '*' && *p != '?' && *p != '/')
    {
      if (!IsIP6Char(*p))
        return 0;
      has_digit = -1;
    }

  return has_digit;
}

/* Check if a username is valid */
int valid_username(const char* name) {
  const char *c = NULL;

  for (c = name; *c; c++) {
    if (!IsUserChar(*c))
      return 0;
  }

  return 1;
}

/* Check if a hostname is valid */
int valid_hostname(const char* name) {
  const char *c = NULL;

  /* Empty strings are not valid hosts */
  if (EmptyString(name))
    return 0;
  /* Don't allow leading period */
  if (*name == '.')
    return 0;
  /* Don't allow trailing period */
  if (name[strlen(name)-1] == '.')
    return 0;

  for (c = name; *c; c++) {
    if (!IsHostChar(*c))
      return 0;
  }

  return 1;
}

/* ------------------------------------------------------------------
 * msgid intrinsic time decode
 *
 * generate_msgid() (send.c) lays a msgid out as
 *   <node_2><logical_3><time_ms_7><counter_2>   (14 chars)
 * with time_ms_7 = milliseconds since epoch in the ircd base64
 * alphabet.  Decoding it lets every msgid resolve to WHEN it was
 * minted even after the message aged out of history storage (or was
 * never stored).  Pre-repack msgids carried a monotonic counter in
 * those positions whose value decodes to ~zero -- far outside the
 * accepted epoch range -- so legacy ids are rejected cleanly and the
 * caller falls back to index/failure paths.
 *
 * The alphabet below MUST match numnicks.c convert2y; it is duplicated
 * here because this file stays dependency-light (umkpasswd/table_gen
 * link it standalone).  A build-time drift would break the round-trip
 * cmocka test in ircd_string_cmocka.c.
 * ------------------------------------------------------------------ */
static const char msgid_b64_alphabet[65] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789[]";

/** Length of every msgid generate_msgid() mints: node 2 + logical 3 +
 * time 7 + counter 2.  The layout before the 2026-09 repack (node 2 +
 * logical 3 + counter 9) had the same length; the one before that
 * ("<yxx>-<startup>-<counter>") carried no time at all. */
#define MSGID_HLC_LEN 14

/** Value of one msgid character, or -1 when it is not in the alphabet
 * (strchr() would match the terminating NUL, so test it first). */
static int msgid_b64_value(char c)
{
  const char *pos;
  if (c == '\0')
    return -1;
  pos = strchr(msgid_b64_alphabet, c);
  return pos ? (int)(pos - msgid_b64_alphabet) : -1;
}

/** Decode the intrinsic mint-time from a msgid.
 * @param[in] msgid The message id.
 * @return Milliseconds since epoch, or 0 if the id is not a
 *         time-carrying msgid (legacy format, malformed, or the
 *         decoded value falls outside 2020..2100). */
int msgid_decode_hlc(const char *msgid, uint64_t *ms_out, uint16_t *logical_out)
{
  uint64_t ms, logical = 0;
  int i;

  ms = msgid_decode_time_ms(msgid);
  if (!ms)
    return 0;
  /* <node_2><logical_3><time_7><counter_2>: the logical counter sits in
   * chars 2..4 (see generate_msgid); msgid_decode_time_ms checked them. */
  for (i = 2; i < 5; i++)
    logical = (logical << 6) | (uint64_t)msgid_b64_value(msgid[i]);
  if (ms_out)
    *ms_out = ms;
  if (logical_out)
    *logical_out = (uint16_t)(logical & 0xFFFF);
  return 1;
}

/** Only a string with exactly the form generate_msgid() mints decodes:
 * MSGID_HLC_LEN characters, every one of them in the alphabet, a logical
 * counter that fits the HLC's 16 bits, and a time inside 2020..2100.
 * Anything else -- a shorter or longer id (an id with junk appended used
 * to decode, as did "zzzz-unknown", 12 characters), a character outside
 * the alphabet anywhere, the pre-repack layout (its counter padding
 * decodes to ~0) -- is not a time and decodes to 0 (#214). */
uint64_t msgid_decode_time_ms(const char *msgid)
{
  uint64_t ms = 0, logical = 0;
  int i, v;

  if (!msgid)
    return 0;
  for (i = 0; i < MSGID_HLC_LEN; i++)
    if (msgid_b64_value(msgid[i]) < 0)
      return 0;   /* too short, or a character no msgid carries */
  if (msgid[MSGID_HLC_LEN] != '\0')
    return 0;     /* too long */

  for (i = 2; i < 5; i++)
    logical = (logical << 6) | (uint64_t)msgid_b64_value(msgid[i]);
  if (logical > 0xFFFF)
    return 0;     /* struct HLC's logical is 16 bits */

  for (i = 5; i < 12; i++) {
    v = msgid_b64_value(msgid[i]);
    ms = (ms << 6) | (uint64_t)v;
  }

  /* Sanity: accept 2020-01-01 .. 2100-01-01 only.  Legacy msgids
   * decode to near-zero here (counter high padding). */
  if (ms < 1577836800000ULL || ms > 4102444800000ULL)
    return 0;
  return ms;
}

/** msgid_decode_time_ms() for an id a client hands back as a CHATHISTORY
 * selector: also 0 when the id says it was minted more than @a max_ahead_ms
 * after @a now_ms.  The caller passes as @a now_ms the later of the wall
 * clock and its own HLC's physical time, and as @a max_ahead_ms the HLC's
 * forward slack (FEAT_HLC_MAX_FORWARD_MS).  That slack only stops this
 * server ADOPTING a peer's reading further ahead (hlc_receive_bounded); a
 * server mints at its own clock (hlc_local_event), and after its clock
 * steps back its HLC stays pinned ahead of the wall clock -- hence the
 * HLC's time, not the wall clock, as "now".  An id further ahead than
 * that was minted by a server whose clock is off by more than the network
 * tolerates; as a reference to a message the target does not hold it is
 * refused rather than read as a time.  Ids the server reads back itself
 * (stored rows, ATTACH cursors) are decoded without this bound.
 * @a max_ahead_ms 0 means unbounded (the feature's own meaning). */
uint64_t msgid_decode_ref_time_ms(const char *msgid, uint64_t now_ms,
                                  uint64_t max_ahead_ms)
{
  uint64_t ms = msgid_decode_time_ms(msgid);

  if (ms && max_ahead_ms && ms > now_ms && ms - now_ms > max_ahead_ms)
    return 0;
  return ms;
}


/* Check if a spoof host is valid.  A spoof host is a host name, optionally
 * prefixed with a user name and '@'.  Wildcards are only allowed if mask is
 * non-zero (Spoofhost blocks using ismask).  Anything else is rejected so
 * that the spoof host cannot be mistaken for something other than a single
 * parameter when it is sent to other servers, most notably a spoof host
 * beginning with a ':'.
 */
int valid_spoofhost(const char* host, int mask) {
  const char *c = NULL;
  const char *at = NULL;

  /* Empty strings are not valid spoof hosts */
  if (EmptyString(host))
    return 0;

  if ((at = strchr(host, '@')) != NULL) {
    /* Don't allow an empty user name */
    if (at == host)
      return 0;
    /* The user part is copied into cli_user()->sethost[HOSTLEN+USERLEN+2]
     * downstream with strlcpy semantics; bound it here rather than let
     * it truncate silently (PR #109 follow-up). */
    if ((size_t)(at - host) > USERLEN)
      return 0;
    for (c = host; c < at; c++) {
      if (!IsUserChar(*c) && !(mask && ((*c == '*') || (*c == '?'))))
        return 0;
    }
    c = at + 1;
  } else
    c = host;

  /* Empty strings are not valid hosts */
  if (EmptyString(c))
    return 0;
  if (strlen(c) > HOSTLEN)
    return 0;
  /* Don't allow leading period */
  if (*c == '.')
    return 0;
  /* Don't allow trailing period */
  if (c[strlen(c)-1] == '.')
    return 0;

  for ( ; *c; c++) {
    if (!IsHostChar(*c) && !(mask && ((*c == '*') || (*c == '?'))))
      return 0;
  }

  return 1;
}
