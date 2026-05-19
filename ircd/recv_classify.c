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
