/*
 * recv_classify.h - per-class recv-path byte classifier
 *
 * Walks the inbound byte stream and tracks per-line byte counts for the
 * @-tag region and the message region.  Used by read_packet (s_bsd.c)
 * to enforce per-class flood caps at byte-append time rather than via
 * CAP-conditional arithmetic on the total recvQ depth.
 *
 * Design: .claude/para/projects/per-class-recvq-buffers.md
 */

#ifndef INCLUDED_recv_classify_h
#define INCLUDED_recv_classify_h

struct Client;

/* recv_classify() outcome codes.  Non-zero values indicate an over-cap
 * condition for the named class; the caller decides whether to kill
 * (Commit 2) or just log (Commit 1 shadow mode).  The first overrun
 * observed in a given byte buffer wins — once set, subsequent overruns
 * in the same call do not change the return value. */
#define RECV_CLASSIFY_OK            0
#define RECV_CLASSIFY_TAG_OVERRUN   1  /* tag region exceeded per-direction cap */
#define RECV_CLASSIFY_MSG_OVERRUN   2  /* msg region exceeded per-direction cap */

/* Classify @a len bytes from @a buf as either tag-region or message-region
 * bytes and update the per-connection counters on @a cptr.  Counters and
 * state reset on \r or \n (either terminator).  State is resumable across
 * calls so TCP segment boundaries mid-line do not lose context.
 *
 * Caps are direction-dependent:
 *   - Client (default):   tag <= 4095, msg <= FULL_MSG_SIZE.
 *   - Server / handshake: tag <= 8191, msg <= 512 (legacy P10 body).
 *
 * @param cptr  Client whose Connection holds the classifier state.
 * @param buf   Newly-read bytes.
 * @param len   Number of bytes in @a buf.
 * @return RECV_CLASSIFY_OK if no per-class cap was exceeded; one of
 *         RECV_CLASSIFY_*_OVERRUN otherwise.
 */
extern int recv_classify(struct Client *cptr, const char *buf, unsigned int len);

#endif /* INCLUDED_recv_classify_h */
