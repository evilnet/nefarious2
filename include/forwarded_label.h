/** @file forwarded_label.h
 * @brief Labeled-response support for commands forwarded via hunt_server_cmd.
 *
 * When a client sends a labeled command that gets forwarded to a remote
 * server, the label must be preserved and the response numerics batch-wrapped.
 * This module manages a per-connection FIFO of ForwardedLabel entries that
 * track pending forwarded labels, correlate responses via compact tag msgids,
 * and manage batch lifecycle (PENDING → ACTIVE → DRAINING → EMPTY).
 */
#ifndef INCLUDED_forwarded_label_h
#define INCLUDED_forwarded_label_h

#include <stdint.h>

struct Client;
struct ForwardedLabel;

/** Track a command hunt_server_cmd() forwards for a local client using
 * labeled-response, just before it goes out: its family and subject
 * (fwd_match.h), the server it goes to and the link it goes out on, and
 * -- for a labeled command -- its label, which the reply is to carry (no
 * ACK at the end of the line; a label already answered by the handler's
 * own labeled batch has that batch taken over).  An unlabeled command is
 * tracked too (fl_plain), so that its replies are never taken for a
 * labeled one's.  Every tracked command gets a compact msgid for the
 * caller to arm: a fork server's reply echoes it and is matched exactly.
 *
 * A command of a family we do not know is not tracked.  One that cannot
 * be (no free slot, a subject too long) is not either, and then no
 * command of its family is labeled until its replies can no longer come.
 *
 * @param[in] from     Local client sending the command.
 * @param[in] cmd      Command name (e.g., "WHOIS", "STATS").
 * @param[in] dest     Server the command is forwarded to.
 * @param[in] parc     Its parameter count (hunt_server_cmd()'s).
 * @param[in] parv     Its parameters.
 * @param[out] msgid   Receives the msgid (for the S2S compact tag).
 * @param[out] time_out Receives the HLC physical_ms for compact tag time.
 * @return 1 if the command is tracked (arm \a msgid), else 0.
 */
int fwd_label_forward(struct Client *from, const char *cmd, struct Client *dest,
                      int parc, char *parv[], char *msgid, uint64_t *time_out);

/** Find the tracked forwarded command a reply WITHOUT a msgid answers:
 * by its family and subject, over the link it came in on
 * (fwd_match.h, fwd_pick()).  When the candidates cannot be told apart
 * none of them is labeled from then on (their labels are answered: an
 * ACK, or the end of the batch) and the oldest is returned unlabeled
 * (fl_plain) for counting.  Entries past their deadline are given up.
 *
 * @param[in] acptr   Local client the reply is addressed to.
 * @param[in] numeric The reply's numeric.
 * @param[in] params  Its parameters after the target.
 * @param[in] link    The link it came in on.
 * @param[in] source  The server it names as its source.
 * @param[out] owner  The connection whose command it answers.
 * @param[out] fit    How it fits (enum FwdFit).
 * @return The entry, or NULL: the reply goes out as it would without
 *   labeled-response.
 */
struct ForwardedLabel *fwd_label_match(struct Client *acptr, int numeric,
                                       const char *params, struct Client *link,
                                       struct Client *source,
                                       struct Client **owner, int *fit);

/** Account for a reply fwd_label_match() matched: an end frees the entry
 * (ending its batch if one is open); NAMES' 366 ends it at its last
 * channel.
 * @return 1 if the entry was freed. */
int fwd_label_reply_ends(struct Client *owner, struct ForwardedLabel *fl, int fit);

/** Find a ForwardedLabel entry matching the given msgid.
 * If msgid is non-empty, searches by exact match (compact tag correlation).
 * If msgid is empty, returns the first non-empty entry (FIFO fallback for
 * legacy servers that strip compact tags).
 * Entries past timeout are cleaned up (batch closed if active).
 *
 * @param[in] acptr   Local client to search.
 * @param[in] msgid   Msgid from incoming compact tag, or empty string for FIFO.
 * @return Matching ForwardedLabel, or NULL.
 */
struct ForwardedLabel *fwd_label_find(struct Client *acptr, const char *msgid);

/** As fwd_label_find(), for a reply addressed to \a acptr: among the
 * entries of \a acptr and -- for a bouncer session's primary -- of its
 * devices on this server, whose commands went out under the primary's
 * numeric.
 * @param[in] acptr   Local client the reply is addressed to.
 * @param[in] msgid   Msgid from the incoming compact tag.
 * @param[out] owner  The connection whose command it answers.
 * @return Matching ForwardedLabel, or NULL.
 */
struct ForwardedLabel *fwd_label_find_for(struct Client *acptr, const char *msgid,
                                          struct Client **owner);

/** Whether \a msgid is one this server minted -- on an S2S line, the
 * compact msgid of a command we forwarded, echoed by the server that
 * answers it.  It names the command, not the reply line that carries it.
 *
 * @param[in] msgid  Msgid from an incoming compact tag.
 * @return Non-zero if it is ours.
 */
int fwd_label_is_echo(const char *msgid);

/** Open a labeled-response batch for a forwarded label entry.
 * Sends BATCH +<batch_id> labeled-response with @label=<label> to the client.
 * Sets fl_state to FWD_LABEL_ACTIVE.
 *
 * @param[in] acptr   Local client.
 * @param[in,out] fl  ForwardedLabel entry to open batch for.
 */
void fwd_label_open_batch(struct Client *acptr, struct ForwardedLabel *fl);

/** Close a forwarded label batch.
 * Sends BATCH -<batch_id> to the client and clears the entry.
 *
 * @param[in] acptr   Local client.
 * @param[in,out] fl  ForwardedLabel entry to close.
 */
void fwd_label_close_batch(struct Client *acptr, struct ForwardedLabel *fl);

/** Check if a numeric is a terminal for the given forwarded label.
 * Checks fl_terminal, fl_terminal2, and generic error numerics (401, 402).
 *
 * @param[in] fl       ForwardedLabel entry.
 * @param[in] numeric  Numeric to check.
 * @return Non-zero if terminal.
 */
int fwd_label_is_terminal(struct ForwardedLabel *fl, int numeric);

/** Close all DRAINING batches for a client.
 * Called before processing a new client command and when a numeric
 * with a different msgid arrives.
 *
 * @param[in] acptr   Local client.
 */
void fwd_label_close_draining(struct Client *acptr);

/** Timer-driven expiry sweep across all local clients. */
void fwd_label_expire_all(void);

/** Zero all forwarded label entries on client disconnect.
 * Does not send BATCH close (dead socket). Called from exit_client.
 *
 * @param[in] cptr    Disconnecting client.
 */
void fwd_label_cleanup(struct Client *cptr);

/** labeled-response is going inert on @a cptr (a CAP change): end every
 * forwarded-label batch it was sent the start of (when @a send_end: it
 * held batch until now), and forget every entry. */
void fwd_label_drop_all(struct Client *cptr, int send_end);

#endif /* INCLUDED_forwarded_label_h */
