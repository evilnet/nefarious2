/*
 * IRC - Internet Relay Chat, include/m_batch.h
 *
 * Public API for multiline batch helpers exposed across translation
 * units.  Most of m_batch.c is private; this header surfaces only the
 * pieces other modules need to call.
 */
#ifndef INCLUDED_m_batch_h
#define INCLUDED_m_batch_h

struct Client;
struct Channel;
struct SLink;

/** Send a truncated-preview + paste-URL fallback for a multiline batch
 * to a single recipient.  See send_multiline_fallback's docblock in
 * ircd/m_batch.c for full parameter semantics.  Used by both m_batch.c
 * itself and the BX M (multiline alias echo) receive handler in
 * bouncer_session.c when a remote alias lacks draft/multiline cap.
 */
extern void send_multiline_fallback(struct Client *sptr, struct Client *to,
                                     struct Client *acptr, const char *msgid,
                                     struct SLink *messages, int total_lines,
                                     int is_channel, struct Channel *chptr,
                                     const char *paste_url_str,
                                     const char *client_tags, int is_notice);

/** Free any S2S multiline batches buffered against \a link.
 * Called from exit_one_client when a directly-connected server exits,
 * so partially-accumulated batches whose terminating ML "-" token will
 * never arrive don't leak their slots in the per-link batch array.
 */
extern void s2s_multiline_cleanup_link(struct Client *link);

#endif /* INCLUDED_m_batch_h */
