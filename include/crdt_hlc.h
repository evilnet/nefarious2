/*
 * crdt_hlc.h - Hybrid Logical Clock for causal message ordering
 *
 * Provides HLC timestamps that combine wall clock time with a logical
 * counter, enabling causal ordering even with clock skew between servers.
 *
 * Used in msgid generation (v1 format) and S2S tag processing.
 */

#ifndef INCLUDED_crdt_hlc_h
#define INCLUDED_crdt_hlc_h

#include <stdint.h>

/** @brief Hybrid Logical Clock state. */
struct HLC {
    uint64_t physical_ms;   /**< Wall clock milliseconds (epoch) */
    uint16_t logical;       /**< Counter for same-ms events */
    uint16_t node_id;       /**< Server numeric (tiebreaker) */
};

/*
 * Core API — operate on caller-provided HLC state
 */

/** @brief Get current wall clock time in milliseconds. */
uint64_t hlc_wall_clock_ms(void);

/** @brief Advance HLC for a local event.
 *  If wall clock advanced, resets logical to 0.
 *  Otherwise increments logical.
 *  Updates *local in-place and returns the new value.
 */
struct HLC hlc_local_event(struct HLC *local);

/** @brief Advance HLC on receiving a remote timestamp.
 *  Takes max of (now, local, remote) for physical_ms,
 *  sets logical based on which was the max.
 *  Updates *local in-place and returns the new value.
 */
struct HLC hlc_receive(struct HLC *local, const struct HLC *remote);

/** @brief Advance HLC on receiving a remote timestamp, with a bound on
 *  how far ahead of our wall clock the remote is allowed to read.
 *
 *  If @a max_forward_ms is nonzero and the remote's physical_ms reads
 *  more than @a max_forward_ms ahead of @a now_ms, the remote reading
 *  is refused: *rejected is set to 1 and *local is advanced exactly as
 *  a local event at @a now_ms (today's hlc_local_event rule, but using
 *  the caller-supplied "now" instead of re-reading the wall clock).
 *  The remote's own stamp is left untouched by this refusal — the
 *  event keeps its origin time; only the receiving clock declines to
 *  move toward it.
 *
 *  Otherwise *rejected is set to 0 and today's receive algorithm runs
 *  using @a now_ms in place of a fresh wall-clock read.
 *
 *  @a rejected may be NULL when the caller does not need the outcome.
 */
struct HLC hlc_receive_bounded(struct HLC *local, const struct HLC *remote,
                                uint64_t now_ms, uint64_t max_forward_ms,
                                int *rejected);

/** @brief Compare two HLC timestamps.
 *  Returns <0, 0, >0 (lexicographic on physical_ms, logical, node_id).
 */
int hlc_compare(const struct HLC *a, const struct HLC *b);

/*
 * Global HLC state — convenience wrappers for the server-wide clock
 */

/** @brief Initialize the global HLC with server's node_id and current time. */
void hlc_init(uint16_t node_id);

/** @brief Read the current global HLC state (read-only). */
const struct HLC *hlc_global(void);

/** @brief Advance the global HLC for a local event. */
struct HLC hlc_global_event(void);

/** @brief Update the global HLC from a received remote timestamp, refusing
 *  it when the remote reads more than @a max_forward_ms ahead of our wall
 *  clock (0 = unbounded, matching hlc_receive's unbounded behaviour).
 *  Returns 1 when refused (the global clock was NOT advanced toward the
 *  remote; it still took a local-event step), 0 when adopted normally.
 *  On refusal, *ahead_ms is set to how far ahead the remote read; it may
 *  be NULL when the caller does not need that value.
 */
int hlc_global_receive(const struct HLC *remote, uint64_t max_forward_ms,
                        uint64_t *ahead_ms);

#endif /* INCLUDED_crdt_hlc_h */
