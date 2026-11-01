/*
 * IRC - Internet Relay Chat, include/metadata_sync.h
 *
 * Per-link state and wire emission for the W4 stamped account-metadata
 * sync protocol (MD =account / !sessid / ? / .).  See the W4 plan
 * (.claude/para/projects/2026-10-24-s2s-w4-account-state.md) for the
 * full wire reference.
 */
#ifndef INCLUDED_metadata_sync_h
#define INCLUDED_metadata_sync_h

#ifndef INCLUDED_metadata_lww_h
#include "metadata_lww.h"
#endif

struct Client;

/** Per-link state for the stamped account-metadata sync protocol,
 * hung off cli_serv(link)->mdsync.  This task (W4 Task 3) only needs
 * the chunk-reassembly state for a `+`-continued "=account" row.
 * Task 10 adds this link's pull-queue fields (outstanding sequence
 * number, queued accounts awaiting a reply, etc.) to this SAME struct
 * -- keep it a real struct, not an opaque buffer, so that addition is
 * a field, not a redesign.
 */
struct MdSyncLink {
  struct md_chunk chunk;  /**< reassembly state for a `+`-continued row */
};

/** Return this link's chunk-reassembly state, lazily allocating
 * cli_serv(link)->mdsync on first use.
 * @param[in] link The directly-connected server whose line is being fed.
 * @return The link's struct md_chunk, or NULL if @a link has no Server
 *         block (cli_serv(link) is NULL) or allocation failed.
 */
extern struct md_chunk *mdsync_link_chunk(struct Client *link);

/** Free a link's struct MdSyncLink (and anything it holds), called as
 * the server's Client is torn down.  Safe to call on a server with no
 * struct MdSyncLink allocated (no-op).
 * @param[in] server The server Client being freed.
 */
extern void mdsync_link_free(struct Client *server);

/** Emit a stamped account-metadata row (MD =account form).  Splits a
 * live value into <=300-byte `+`-continued pieces; a tombstone is a
 * single line with flags token "D" and no value.
 * @param[in] src Client to attribute the emission to (the P10 prefix).
 * @param[in] one If non-NULL, send only to this one link/client.
 * @param[in] butone If @a one is NULL, send to every IRCv3-aware server
 *            except this one (NULL sends to all of them).
 * @param[in] account Account name.
 * @param[in] key Metadata key.
 * @param[in] v Version to emit (stamp, tombstone/vis/value).
 */
extern void metadata_emit_versioned(struct Client *src, struct Client *one,
                                    struct Client *butone,
                                    const char *account, const char *key,
                                    const struct md_version *v);

/** Answer a hop-local "MD ?" pull request from @a link: for each of the
 * @a n account names in @a accounts, send every stored version (live row
 * or tombstone, up to 128) via metadata_emit_versioned(&me, link, NULL,
 * ...); when @a scope is 'A', also send up to 256 of that account's
 * newest-by-timestamp read markers as "MR account target ts" (the
 * channel's canonical spelling when the target names a live channel).
 * Finishes with "MD . seq" regardless of scope or whether anything else
 * was sent. A no-op when @a link is not IRCv3-aware.
 * @param[in] link The server that asked (every line goes only to it).
 * @param[in] seq The request's sequence number, echoed back in "MD .".
 * @param[in] scope 'A' (rows + markers) or 'R' (rows only).
 * @param[in] accounts Account names to answer for.
 * @param[in] n Number of entries in @a accounts.
 */
extern void mdsync_answer_pull(struct Client *link, unsigned long seq,
                               char scope, char *accounts[], int n);

#endif /* INCLUDED_metadata_sync_h */
