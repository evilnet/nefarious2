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

/** @brief Update the global HLC from a received remote timestamp. */
void hlc_global_receive(const struct HLC *remote);

#endif /* INCLUDED_crdt_hlc_h */
