/*
 * IRC - Internet Relay Chat, ircd/history_record.c
 * Copyright (C) 2024 Nefarious Development Team
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
 * @brief Chathistory record codec: the stored value format and its
 * sentinel escaping, plus the CH W forward payload that shares it.
 *
 * Split out of history.c so ircd/test links the real codec instead of
 * a copy.  No database, client or channel dependencies.
 */
#include "config.h"

#include "history.h"
#include "history_record.h"
#include "ircd_alloc.h"
#include "ircd_compress.h"
#include "ircd_snprintf.h"

#include <stdlib.h>
#include <string.h>
#ifdef USE_ZSTD
#include <zstd.h>
#endif

/** Serialize a message to a buffer.
 * Format: type|sender|account|content (sender and account escaped by
 * history_escape_header, so a '|' in either cannot shift the fields)
 * @param[out] buf Output buffer.
 * @param[in] bufsize Size of output buffer.
 * @param[in] type Message type.
 * @param[in] sender Sender mask.
 * @param[in] account Account name (may be NULL).
 * @param[in] content Message content (may be NULL).
 * @return Length of serialized data.
 */
/* In-band record sentinels (\x05 original_target, \x06 client_tags) are
 * structural in the serialized value.  A client can put those bytes in
 * its own message body, and the deserializer would lift the span into
 * client_tags/original_target -- tag/target injection into chathistory
 * replay (evilnet/nefarious2#103, reproduced on a stock build).  Nothing
 * upstream guarantees the bytes are absent (check_utf8_text is a no-op
 * unless FEAT_UTF8ONLY).  So escape them in every VALUE field on write
 * and reverse on read; the structural brackets serialize_message adds
 * stay raw.  Escape introducer \x04 (EOT); escaped byte = \x04,(b^0x40)
 * -- 0x04->0x44 'D', 0x05->0x45 'E', 0x06->0x46 'F', none of which are
 * themselves sentinels.  Legacy records (no \x04 escapes) unescape to
 * themselves, so the format stays backward compatible; already-poisoned
 * legacy records can't be retroactively cleaned, but no NEW injection
 * lands.  NB: the multiline markers \x1E/\x1F are deliberately NOT in
 * this escape set: record-layer escaping is a transparent round-trip, so
 * it cannot distinguish server-written markers from client bytes -- both
 * would unescape identically.  Their fix is semantic instead: multiline
 * placeholders carry HISTORY_MULTILINE (out-of-band record type, also on
 * the CH R/Z/B fed wire), ml_content_resolve keys on that type, and the
 * \x1F replay split is gated on it -- client-injected \x1E/\x1F bytes
 * render as literals. */
#define HIST_ESC 0x04
static int history_field_needs_escape(unsigned char c)
{
  return c == HIST_ESC || c == 0x05 || c == 0x06 || c == 0x07;
}

/* The header fields (sender, account) are '|'-delimited, and '|' is a
 * legal nick character (table_gen.c makes {|}~ lowercase letters).
 * Unescaped, nick "a|admin|b" shifted the fields: replay read sender "a"
 * and account=admin, with the real header glued onto the text (parsers
 * fuzz F14).  So the header fields escape '|' too, through the same \x04
 * scheme ('|' ^ 0x40 = '<').  No format marker is needed: nick, user,
 * host and account names carry no control bytes, so a legacy header
 * field holds no \x04 and unescapes to itself.  Value fields leave '|'
 * raw: content is the last field, and the CH W forward payload stays
 * byte-identical across mixed-version links. */
static int history_header_needs_escape(unsigned char c)
{
  return c == '|' || history_field_needs_escape(c);
}

/** Escape the bytes of \a src that \a needs_escape selects.  Writes at
 * most \a dstsize-1 bytes + NUL; returns dst.  A field that would
 * overflow the escaped buffer is truncated at a whole escape-sequence
 * boundary (never a dangling \x04). */
static char *history_escape_bytes(char *dst, size_t dstsize, const char *src,
                                  int (*needs_escape)(unsigned char))
{
  size_t o = 0;
  const unsigned char *p;

  if (dstsize == 0)
    return dst;
  for (p = (const unsigned char *)(src ? src : ""); *p; ++p) {
    if (needs_escape(*p)) {
      if (o + 2 >= dstsize)
        break;
      dst[o++] = HIST_ESC;
      dst[o++] = (char)(*p ^ 0x40);
    } else {
      if (o + 1 >= dstsize)
        break;
      dst[o++] = (char)*p;
    }
  }
  dst[o] = '\0';
  return dst;
}

/** Escape VALUE-field bytes that would otherwise read as structural
 * sentinels.  Writes at most \a dstsize-1 bytes + NUL; returns dst. */
char *history_escape_field(char *dst, size_t dstsize, const char *src)
{
  return history_escape_bytes(dst, dstsize, src, history_field_needs_escape);
}

/** Escape a header field (sender, account): the value-field set plus
 * the '|' delimiter.  Writes at most \a dstsize-1 bytes + NUL. */
static char *history_escape_header(char *dst, size_t dstsize, const char *src)
{
  return history_escape_bytes(dst, dstsize, src, history_header_needs_escape);
}

/** Copy the stored header field \a src[0..len) into \a dst, unescaping
 * it.  Legacy fields (no \x04) copy through unchanged.
 * @return Unescaped length, or -1 if it does not fit in \a dstsize. */
int history_unescape_header(char *dst, size_t dstsize,
                            const char *src, size_t len)
{
  size_t i = 0, o = 0;

  if (dstsize == 0)
    return -1;
  while (i < len) {
    if (o + 1 >= dstsize)
      return -1;
    if (src[i] == HIST_ESC && i + 1 < len) {
      dst[o++] = (char)((unsigned char)src[i + 1] ^ 0x40);
      i += 2;
    } else {
      dst[o++] = src[i++];
    }
  }
  dst[o] = '\0';
  return (int)o;
}

/** Reverse history_escape_field in place. */
void history_unescape_field(char *s)
{
  char *r = s, *w = s;

  while (*r) {
    if (*r == HIST_ESC && r[1]) {
      *w++ = (char)((unsigned char)r[1] ^ 0x40);
      r += 2;
    } else {
      *w++ = *r++;
    }
  }
  *w = '\0';
}

/** Compose the CH W federation-forward payload: client tags ride in-band
 * as [\x06<tags>\x06]<text>, with BOTH halves sentinel-escaped first so
 * a raw \x06 in the wire payload can only ever be the composer's own
 * bracket.  (#103 follow-up: the pre-escape encoding relied on
 * deserialize_message lifting raw sentinels back out of stored content,
 * which the #103 escape closed -- and it was itself an injection vector:
 * client text with a leading \x06, forwarded raw in the no-tags branch,
 * was lifted as tags on the storage server.)  Benign payloads contain no
 * 0x04-0x06 bytes, so the escape is an identity map for them and the
 * wire format is unchanged across mixed-version links.
 * @param[out] dst Output buffer.
 * @param[in] dstsize Size of dst.
 * @param[in] client_tags Client-only tag list (NULL/empty = no bracket).
 * @param[in] text Message text (may be NULL).
 * @return dst. */
char *history_forward_encode(char *dst, size_t dstsize,
                             const char *client_tags, const char *text)
{
  size_t used = 0;

  if (dstsize == 0)
    return dst;
  dst[0] = '\0';
  if (client_tags && client_tags[0]) {
    if (dstsize < 3)
      return dst;
    dst[used++] = '\x06';
    history_escape_field(dst + used, dstsize - used - 1, client_tags);
    used += strlen(dst + used);
    dst[used++] = '\x06';
    dst[used] = '\0';
  }
  history_escape_field(dst + used, dstsize - used, text ? text : "");
  return dst;
}


/** Reverse history_forward_encode in place on a received CH W payload.
 * If a leading raw \x06 bracket is present, terminates the tag span,
 * unescapes it, and points *tags_out at it; unescapes the remaining
 * text either way.  On a current sender a raw bracket can only be
 * composer-written (client bytes are escaped); on a pre-escape sender
 * this matches the old deserializer lift, no worse.
 * @param[in,out] content Received payload (modified in place).
 * @param[out] tags_out Set to the tag span within \a content, or NULL.
 * @return Pointer to the text portion within \a content. */
char *history_forward_split(char *content, char **tags_out)
{
  char *text = content;

  *tags_out = NULL;
  if (content[0] == '\x06') {
    char *close = strchr(content + 1, '\x06');
    if (close) {
      *close = '\0';
      *tags_out = content + 1;
      history_unescape_field(*tags_out);
      text = close + 1;
    }
  }
  history_unescape_field(text);
  return text;
}

int history_serialize_record(char *buf, int bufsize,
                             enum HistoryMessageType type,
                             const char *sender, const char *account,
                             const char *content, const char *client_tags,
                             const char *original_target, time_t incarnation)
{
  /* The content field can carry up to two stacked sentinel sections,
   * always in this order at the very start of the field:
   *
   *   [\x05<original_target>\x05][\x06<client_tags>\x06]<actual_content>
   *
   * Sentinels are bytes \x05 (ENQ) and \x06 (ACK), neither of which
   * occur in normal IRC payloads or in channel/nick names.  Old data
   * predates these sentinels and deserializes with the corresponding
   * fields empty, so the format is fully backward compatible.
   *
   * original_target is only persisted for PM-pair-keyed messages where
   * the storage key (`nick1:nick2`) does not identify the actual
   * recipient.  Channel messages omit it.
   */
  const char *ot_open = "";
  const char *ot_close = "";
  const char *ct_open = "";
  const char *ct_close = "";
  /* Third sentinel section: [\x07<creationtime>\x07], the channel
   * incarnation (2026-09-08).  Digits only, never escaped. */
  char inc_sec[32];
  /* Escaped copies (worst case 2x + NUL): sentinel bytes inside the
   * value fields are neutralized so they can't forge structure. */
  char ot_esc[(CHANNELLEN + 1) * 2 + 1];
  char ct_esc[512 * 2 + 1];
  char content_esc[HISTORY_CONTENT_LEN * 2 + 1];
  char sender_esc[HISTORY_SENDER_LEN * 2 + 1];
  char account_esc[(ACCOUNTLEN + 1) * 2 + 1];

  history_escape_header(sender_esc, sizeof(sender_esc), sender);
  history_escape_header(account_esc, sizeof(account_esc), account);
  history_escape_field(content_esc, sizeof(content_esc), content ? content : "");
  if (original_target && original_target[0]) {
    ot_open = "\x05";
    ot_close = "\x05";
    history_escape_field(ot_esc, sizeof(ot_esc), original_target);
  } else {
    ot_esc[0] = '\0';
  }
  if (client_tags && client_tags[0]) {
    ct_open = "\x06";
    ct_close = "\x06";
    history_escape_field(ct_esc, sizeof(ct_esc), client_tags);
  } else {
    ct_esc[0] = '\0';
  }

  if (incarnation > 0)
    ircd_snprintf(0, inc_sec, sizeof(inc_sec), "\x07%lu\x07", (unsigned long)incarnation);
  else
    inc_sec[0] = '\0';

  return ircd_snprintf(0, buf, bufsize, "%d|%s|%s|%s%s%s%s%s%s%s%s",
                       (int)type,
                       sender_esc,
                       account_esc,
                       ot_open, ot_esc, ot_close,
                       ct_open, ct_esc, ct_close,
                       inc_sec,
                       content_esc);
}

/** Deserialize a message from a buffer.
 * @param[in] data Serialized data (possibly compressed).
 * @param[in] datalen Length of data.
 * @param[out] msg Message structure to fill.
 * @return 0 on success, -1 on error.
 */
static int deserialize_message(const char *data, int datalen,
                               struct HistoryMessage *msg)
{
  const char *p, *end;
  char *field;
  int type;
  int ret = -1;
#ifdef USE_ZSTD
  char decomp_stack[HISTORY_VALUE_BUFSIZE];
  char *decompressed = NULL;
  int decomp_dynamic = 0;
  size_t decompressed_len;

  /* Check if data is compressed and decompress if needed */
  if (is_compressed((const unsigned char *)data, datalen)) {
    /* Determine decompressed size for buffer allocation */
    unsigned long long frame_size = ZSTD_getFrameContentSize(
        (const unsigned char *)data + 1, datalen - 1);
    size_t out_size;

    if (frame_size != ZSTD_CONTENTSIZE_ERROR
        && frame_size != ZSTD_CONTENTSIZE_UNKNOWN
        && frame_size > sizeof(decomp_stack)) {
      if (frame_size > COMPRESS_MAX_UNCOMPRESSED)
        goto deser_cleanup;
      decompressed = (char *)MyMalloc(frame_size + 1);
      decomp_dynamic = 1;
      out_size = frame_size + 1;
    } else {
      decompressed = decomp_stack;
      out_size = sizeof(decomp_stack);
    }

    if (decompress_data((const unsigned char *)data, datalen,
                        (unsigned char *)decompressed, out_size,
                        &decompressed_len) < 0) {
      goto deser_cleanup;
    }
    data = decompressed;
    datalen = decompressed_len;
  }
#endif

  p = data;
  end = data + datalen;

  /* Parse type */
  field = memchr(p, '|', end - p);
  if (!field || field >= end) goto deser_cleanup;
  type = atoi(p);
  if (type < 0 || type > HISTORY_MULTILINE) goto deser_cleanup;
  msg->type = (enum HistoryMessageType)type;
  p = field + 1;

  /* Parse sender (escaped: the stored field may be longer than the
   * sender it decodes to, so the bound applies after unescaping) */
  field = memchr(p, '|', end - p);
  if (!field || field >= end) goto deser_cleanup;
  if (history_unescape_header(msg->sender, sizeof(msg->sender),
                              p, field - p) < 0)
    goto deser_cleanup;
  p = field + 1;

  /* Parse account (escaped likewise) */
  field = memchr(p, '|', end - p);
  if (!field || field >= end) goto deser_cleanup;
  if (history_unescape_header(msg->account, sizeof(msg->account),
                              p, field - p) < 0)
    goto deser_cleanup;
  p = field + 1;

  /* Parse content (rest of string), extracting optional sentinel-bracketed
   * fields that may appear in this order at the very start of the field:
   *   [\x05original_target\x05][\x06client_tags\x06]content
   * Both are optional and absent in legacy entries (which deserialize with
   * the corresponding msg fields empty).
   */
  {
    size_t content_len = end - p;
    msg->original_target[0] = '\0';
    msg->client_tags[0] = '\0';

    /* Optional original_target sentinel (\x05<value>\x05) */
    if (content_len > 2 && p[0] == '\x05') {
      const char *ot_end = memchr(p + 1, '\x05', content_len - 1);
      if (ot_end) {
        size_t ot_len = ot_end - (p + 1);
        if (ot_len >= sizeof(msg->original_target))
          ot_len = sizeof(msg->original_target) - 1;
        memcpy(msg->original_target, p + 1, ot_len);
        msg->original_target[ot_len] = '\0';
        history_unescape_field(msg->original_target);
        p = ot_end + 1;
        content_len = end - p;
      }
    }

    /* Optional client_tags sentinel (\x06<value>\x06) */
    if (content_len > 2 && p[0] == '\x06') {
      const char *tag_end = memchr(p + 1, '\x06', content_len - 1);
      if (tag_end) {
        size_t tags_len = tag_end - (p + 1);
        if (tags_len >= sizeof(msg->client_tags))
          tags_len = sizeof(msg->client_tags) - 1;
        memcpy(msg->client_tags, p + 1, tags_len);
        msg->client_tags[tags_len] = '\0';
        history_unescape_field(msg->client_tags);
        p = tag_end + 1;
        content_len = end - p;
      }
    }

    /* Optional incarnation sentinel (\x07<creationtime>\x07) */
    msg->incarnation = 0;
    if (content_len > 2 && p[0] == '\x07') {
      const char *inc_end = memchr(p + 1, '\x07', content_len - 1);
      if (inc_end) {
        msg->incarnation = (time_t)strtoul(p + 1, NULL, 10);
        p = inc_end + 1;
        content_len = end - p;
      }
    }

    if (content_len >= sizeof(msg->content))
      content_len = sizeof(msg->content) - 1;
    memcpy(msg->content, p, content_len);
    msg->content[content_len] = '\0';
    history_unescape_field(msg->content);
  }

  ret = 0;

deser_cleanup:
#ifdef USE_ZSTD
  if (decomp_dynamic && decompressed)
    MyFree(decompressed);
#endif
  return ret;
}

/** Parse a stored history record value (as read from the DB, possibly
 * zstd-compressed) into \a msg.  Public wrapper for consumers that
 * receive raw record values off the wire -- notably the CH Z federation
 * passthrough, whose payload is the sender's stored record.  Caller
 * zeroes \a msg first.
 * @param[in] data Record value bytes.
 * @param[in] datalen Length of data.
 * @param[out] msg Parsed message.
 * @return 0 on success, -1 on error. */
int history_deserialize_record(const void *data, size_t datalen,
                               struct HistoryMessage *msg)
{
  return deserialize_message((const char *)data, (int)datalen, msg);
}
