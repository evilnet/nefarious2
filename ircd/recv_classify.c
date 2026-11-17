/*
 * recv_classify.c - per-class recv-path byte classifier
 *
 * Walks each inbound byte and routes it as either tag-region or
 * message-region based on wire shape (presence of `@` prefix, position
 * of the first SPACE).  Maintains per-connection counters reset on line
 * terminators.  Caller (read_packet in s_bsd.c) uses the return value
 * to decide whether to kill the connection for per-class overrun.
 *
 * Design: .claude/para/projects/per-class-recvq-buffers.md
 */

#include "config.h"

#include "recv_classify.h"

#include "client.h"
#include "ircd_defs.h"

#include <string.h>

int
recv_classify(struct Client *cptr, const char *buf, unsigned int len)
{
  struct Connection *con = cli_connect(cptr);
  unsigned int tag_cap;
  unsigned int msg_cap;
  unsigned int i;
  int overrun = RECV_CLASSIFY_OK;

  if (IsServer(cptr) || IsHandshake(cptr)) {
    tag_cap = 8191;
  } else {
    tag_cap = 4095;
  }
  /* Body region is BUFSIZE (512) in both directions:
   *  - Server: legacy P10 body limit, never relaxed.
   *  - Client: IRCv3 message-tags spec is explicit that the tag region
   *    grows but "the standard 510 byte tag-less message limit"
   *    (= BUFSIZE - 2 with CRLF) is unchanged.  Nefarious's own
   *    outbound P10 chunks at BUFSIZE per line (m_burst.c, m_names.c),
   *    so anything inbound that exceeds it is either misbehaving or
   *    using a non-multiline channel for content that should use
   *    multiline.
   * FULL_MSG_SIZE = IRCV3_TAG_MAX + BUFSIZE is the *total* line cap
   * (tags + body), not a body cap — easy to mistake when reading
   * code, hence this note. */
  msg_cap = BUFSIZE;

  for (i = 0; i < len; i++) {
    unsigned char c = (unsigned char)buf[i];

    if (c == '\n' || c == '\r') {
      /* Line terminator (CR or LF).  Either resets — the parser layer
       * (dbuf_getmsg) treats either as a line ender. */
      con_recv_state(con) = RECV_TAGS;
      con_recv_tag_bytes(con) = 0;
      con_recv_msg_bytes(con) = 0;
      continue;
    }

    if (con_recv_state(con) == RECV_TAGS) {
      if (con_recv_tag_bytes(con) == 0) {
        /* First non-terminator byte on the line decides region. */
        if (c == '@') {
          con_recv_tag_bytes(con) = 1;  /* count the @ itself */
          continue;
        }
        /* No tag region — fall through to MSG accounting below. */
        con_recv_state(con) = RECV_MSG;
      } else if (c == ' ') {
        /* End of tag region; separator itself is counted in neither. */
        con_recv_state(con) = RECV_MSG;
        continue;
      } else {
        con_recv_tag_bytes(con)++;
        if (con_recv_tag_bytes(con) > tag_cap && overrun == RECV_CLASSIFY_OK)
          overrun = RECV_CLASSIFY_TAG_OVERRUN;
        continue;
      }
    }

    /* RECV_MSG accumulation (either by initial state or just-switched). */
    con_recv_msg_bytes(con)++;
    if (con_recv_msg_bytes(con) > msg_cap && overrun == RECV_CLASSIFY_OK)
      overrun = RECV_CLASSIFY_MSG_OVERRUN;
  }

  return overrun;
}

/** Client tag-region cap: '@' plus the 4094 bytes message-tags allows. */
#define RECV_CLIENT_TAG_CAP 4095
/** A client line this long (tags and body together) has stopped being an
 * overlong message and become a flood: recv_clip() reports it. */
#define RECV_CLIP_FATAL 65536

/** Cut a client's overlong lines down as they arrive, in place.
 *
 * message-tags says a line whose tags are over the limit gets
 * ERR_INPUTTOOLONG (417), and the client stays; a body over the 512-byte
 * line is answered the same way.  recv_classify() can only report such a
 * line, after which the client was dropped.  This keeps each region's
 * bytes up to one past its cap and drops the rest, so the recvQ never
 * holds more than a capped line, and the line still says it was too long:
 * recv_line_overlong() sees the extra byte when the line is parsed, and
 * the parser answers 417 instead of running it.
 *
 * State lives on the Connection, as for recv_classify(), so a line split
 * over several reads is cut the same as one read whole.
 *
 * @param cptr Client (not a server or handshake) the bytes came from.
 * @param buf Newly-read bytes; overwritten with the bytes kept.
 * @param len In: bytes in @a buf.  Out: bytes kept.
 * @return RECV_CLASSIFY_OK, or RECV_CLASSIFY_MSG_OVERRUN once one line has
 *         run past RECV_CLIP_FATAL bytes (the caller drops the client).
 */
int
recv_clip(struct Client *cptr, char *buf, unsigned int *len)
{
  struct Connection *con = cli_connect(cptr);
  unsigned int i, out = 0;
  int ret = RECV_CLASSIFY_OK;

  for (i = 0; i < *len; i++) {
    char c = buf[i];
    int keep = 1;

    if (c == '\n' || c == '\r') {
      con_recv_state(con) = RECV_TAGS;
      con_recv_tag_bytes(con) = 0;
      con_recv_msg_bytes(con) = 0;
    } else if (con_recv_state(con) == RECV_TAGS
               && con_recv_tag_bytes(con) == 0 && c == '@') {
      con_recv_tag_bytes(con) = 1;
    } else if (con_recv_state(con) == RECV_TAGS
               && con_recv_tag_bytes(con) != 0) {
      if (c == ' ')
        con_recv_state(con) = RECV_MSG;         /* the separator: kept */
      else if (con_recv_tag_bytes(con) + con_recv_msg_bytes(con)
               < RECV_CLIP_FATAL)
        keep = ++con_recv_tag_bytes(con) <= RECV_CLIENT_TAG_CAP + 1;
      else
        keep = 0;
    } else {
      con_recv_state(con) = RECV_MSG;
      if (con_recv_tag_bytes(con) + con_recv_msg_bytes(con)
          < RECV_CLIP_FATAL)
        keep = ++con_recv_msg_bytes(con) <= BUFSIZE + 1;
      else
        keep = 0;
    }
    if (con_recv_tag_bytes(con) + con_recv_msg_bytes(con) >= RECV_CLIP_FATAL)
      ret = RECV_CLASSIFY_MSG_OVERRUN;
    if (keep)
      buf[out++] = c;
  }
  *len = out;
  return ret;
}

/** Whether a client's line, as recv_clip() kept it, was too long: its tag
 * region (the '@' included) is over RECV_CLIENT_TAG_CAP, or its body (all
 * after the space that ends the tags, or the whole line without tags) over
 * BUFSIZE.  The line has no CR or LF.
 * @param cptr Client the line came from (unused; kept for symmetry).
 * @param line Line bytes.
 * @param len Bytes in @a line.
 * @return Non-zero for a line to answer with ERR_INPUTTOOLONG.
 */
int
recv_line_overlong(struct Client *cptr, const char *line, unsigned int len)
{
  const char *body = line;
  const char *end = line + len;

  (void)cptr;
  if (len && *line == '@') {
    const char *sp = memchr(line, ' ', len);

    if (!sp)
      return len > RECV_CLIENT_TAG_CAP;
    if ((unsigned int)(sp - line) > RECV_CLIENT_TAG_CAP)
      return 1;
    body = sp + 1;
  }
  return (unsigned int)(end - body) > BUFSIZE;
}

/** Forget the line in progress on @a con: its recvQ was dropped or moved,
 * and the counts were for those bytes. */
void
recv_classify_reset(struct Connection *con)
{
  con_recv_state(con) = RECV_TAGS;
  con_recv_tag_bytes(con) = 0;
  con_recv_msg_bytes(con) = 0;
}
