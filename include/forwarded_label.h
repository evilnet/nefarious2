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

/** Zero all forwarded label entries on client disconnect.
 * Does not send BATCH close (dead socket). Called from exit_client.
 *
 * @param[in] cptr    Disconnecting client.
 */
void fwd_label_cleanup(struct Client *cptr);

#endif /* INCLUDED_forwarded_label_h */
