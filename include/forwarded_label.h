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

/** Save a client's label for a forwarded command.
 * Looks up the command in the terminal numeric table, finds an empty slot
 * in the client's ForwardedLabel FIFO, generates a batch ID and msgid,
 * and saves all state. Sets cli_label_responded to suppress ACK.
 *
 * @param[in] from    Local client whose label is being saved.
 * @param[in] cmd     Command name (e.g., "WHOIS", "STATS").
 * @param[out] msgid  Buffer to receive the generated HLC msgid (for S2S compact tag).
 * @param[out] time_out Receives the HLC physical_ms for compact tag time.
 * @return 1 if label was saved, 0 if not (unknown command, no empty slot, etc.).
 */
int fwd_label_save(struct Client *from, const char *cmd,
                   char *msgid, uint64_t *time_out);

/** Record how the replies to a command hunt_server_cmd forwards will be
 * matched to it, just before it is forwarded.
 *
 * Over a route that carries S2S tags to and from \a dest, a labeled
 * command is saved by fwd_label_save() and matched by its msgid; an
 * unlabeled one carries a msgid too, with nothing saved, so that no
 * reply over a tagged route comes back without one.  Over a route with
 * a legacy server on it no msgid comes back: the command -- labeled or
 * not, for a client with labeled-response -- is recorded with its link,
 * destination and send order, and its replies are matched by the link
 * and the order (fwd_label_find_order).  A command that cannot be
 * recorded there marks the client so that no label is created on such
 * a route until its replies have had time to arrive.
 *
 * @param[in] from     Local client sending the command.
 * @param[in] cmd      Command name (e.g., "WHOIS").
 * @param[in] dest     Server the command is forwarded to.
 * @param[out] msgid   As fwd_label_save().
 * @param[out] time_out As fwd_label_save().
 * @return 1 if the caller must arm the S2S tags with \a msgid and
 *         \a time_out (a tagged route), else 0.
 */
int fwd_label_forward(struct Client *from, const char *cmd,
                      struct Client *dest, char *msgid, uint64_t *time_out);

/** Find a ForwardedLabel entry matching the given msgid exactly
 * (compact tag correlation).  An empty msgid matches nothing: a reply
 * without one comes over an order route (fwd_label_find_order).
 * Entries past timeout are cleaned up (batch closed if active).
 *
 * @param[in] acptr   Local client to search.
 * @param[in] msgid   Msgid from incoming compact tag.
 * @return Matching ForwardedLabel, or NULL.
 */
struct ForwardedLabel *fwd_label_find(struct Client *acptr, const char *msgid);

/** Find the order-route entry a reply without a msgid belongs to: the
 * oldest one recorded for the link the reply came over.  Every forwarded
 * command of a labeled-response client over a tagged route carries a
 * msgid, so its reply does too; on an order route the unlabeled ones are
 * recorded as well, and one destination per link is tracked at a time
 * -- the server asked answers in the order it was asked, so the oldest
 * entry is the one being answered.
 * Entries past timeout are cleaned up (batch closed if active).
 *
 * @param[in] acptr   Local client the reply is for.
 * @param[in] source  Server the reply names as its source.
 * @return Matching ForwardedLabel, or NULL.
 */
struct ForwardedLabel *fwd_label_find_order(struct Client *acptr,
                                            struct Client *source);

/** Whether \a numeric ends the reply an order-route entry tracks: its
 * terminal, or an error the command's reply does not go on past.
 *
 * @param[in] fl       Order-route entry.
 * @param[in] numeric  Numeric received.
 * @return Non-zero if the reply is complete.
 */
int fwd_label_order_done(struct ForwardedLabel *fl, int numeric);

/** Whether \a msgid is one this server minted -- on an S2S line, the
 * compact msgid of a command we forwarded, echoed by the server that
 * answers it (fwd_label_forward tags every one over a tagged route).
 * It names the command, not the reply line that carries it.
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

/** Find a DRAINING entry matching the given msgid.
 * Only matches entries in FWD_LABEL_DRAINING state.
 *
 * @param[in] acptr   Local client.
 * @param[in] msgid   Msgid from incoming compact tag, or empty string.
 * @return Matching ForwardedLabel in DRAINING state, or NULL.
 */
struct ForwardedLabel *fwd_label_find_draining(struct Client *acptr,
                                                const char *msgid);

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

#endif /* INCLUDED_forwarded_label_h */
