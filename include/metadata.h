/*
 * IRC - Internet Relay Chat, include/metadata.h
 * Copyright (C) 2024 Nefarious Development Team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
/** @file
 * @brief Metadata storage declarations (IRCv3 draft/metadata-2).
 *
 * Implements IRCv3 draft/metadata-2 extension for user/channel key-value storage.
 *
 * Specification: https://ircv3.net/specs/extensions/metadata
 * Capability: draft/metadata-2
 */
#ifndef INCLUDED_metadata_h
#define INCLUDED_metadata_h

#ifndef INCLUDED_metadata_lww_h
#include "metadata_lww.h"

#endif

/* The metadata capability half of "metadata-aware": draft/metadata-2
 * today.  The owner (2026-11-12): draft/metadata-3 will not replace it,
 * "it's just another layer; we'll ultimately have to handle both" -- a
 * second capability is OR'd in here (and in MetadataCapIn()), every site
 * asks MetadataAware() / MetadataCapActive(), and version-specific
 * differences stay at the edges.  The caller includes client.h and
 * capab.h. */
#define MetadataCapActive(cli)  CapActive((cli), CAP_DRAFT_METADATA2)
/* A CapSet (a CAP REQ's removals, say) names the metadata capability. */
#define MetadataCapIn(set)      CapHas((set), CAP_DRAFT_METADATA2)
/* A capability is the metadata capability, or batch: the two that make a
 * client metadata-aware. */
#define MetadataAwareCap(cap)   ((cap) == CAP_DRAFT_METADATA2 || (cap) == CAP_BATCH)

/** @a cli is a metadata-aware client: the metadata capability AND batch
 * both active on its connection.  "This specification depends on the
 * batch capability which MUST be negotiated to use draft/metadata-2"; the
 * owner's reading (2026-11-12): negotiating draft/metadata-2 is a no-op
 * until batch is negotiated too -- the proposed draft/metadata-3
 * (ircv3-specifications PR #613) words the same rule: "A metadata-aware
 * client is a client who has negotiated both the draft/metadata-3
 * capability and the batch capability."  The cap is ACKed alone (the order
 * of negotiation is never enforced).  After registration a client that is
 * not metadata-aware is treated exactly as one without the cap, until
 * batch is there, and again whenever either is dropped (which clears its
 * subscriptions: m_cap.c).  During registration negotiation is still in
 * progress, and batch is judged when it ends (owner, 2026-11-12, "the
 * order of capability negotiation is not significant and MUST NOT be
 * enforced"): a client with the metadata capability may SET, SUB and
 * UNSUB before batch arrives (their replies are not batches), and
 * metadata_burst_self_to_client() decides once, at registration
 * (metadata_registration_check()).  Per connection: a bouncer device's
 * own caps. */
#define MetadataAware(cli) (MetadataCapActive(cli) && CapActive((cli), CAP_BATCH))

struct Client;
struct Channel;

/** Maximum length of a metadata key name */
#define METADATA_KEY_LEN 64

/** Maximum length of a metadata value */
#define METADATA_VALUE_LEN 1024

/** Visibility levels for metadata */
#define METADATA_VIS_PUBLIC  0  /* Anyone can see */
#define METADATA_VIS_PRIVATE 1  /* Only owner can see */
#define METADATA_VIS_ERROR   2  /* Error response (no such target) */

/** Metadata entry structure */
struct MetadataEntry {
  char key[METADATA_KEY_LEN];           /**< Key name */
  char *value;                          /**< Value (dynamically allocated) */
  int visibility;                       /**< Visibility level */
  struct MetadataEntry *next;           /**< Next entry in list */
};

/** One METADATA write a client of ours made to itself before registration
 * (before-connect): the last write per key, in the order of those last
 * writes (cli_metadata_prereg).  Kept beside its in-memory list (which a
 * login during registration replaces with the account's rows) until
 * registration ends, when a metadata-aware client logged in by then has
 * them merged into its account (metadata_prereg.h's rule). */
struct MetadataPrereg {
  char key[METADATA_KEY_LEN];           /**< Key name */
  char *value;                          /**< Value, or NULL: a delete */
  int visibility;                       /**< Visibility level of a set */
  struct md_stamp st;                   /**< When its SET was accepted */
  struct MetadataPrereg *next;          /**< Next write */
};

/** Metadata subscription for a client */
struct MetadataSub {
  char key[METADATA_KEY_LEN];           /**< Key being subscribed to */
  struct MetadataSub *next;             /**< Next subscription in list */
};

/** Shutdown the metadata subsystem */
extern void metadata_shutdown(void);

/** Initialize LMDB for metadata persistence.
 * @param[in] dbpath Path to the database directory.
 * @return 0 on success, -1 on error.
 */
extern int metadata_lmdb_init(const char *dbpath);

/** Shutdown LMDB metadata storage. */
extern void metadata_lmdb_shutdown(void);

/** Check if LMDB metadata storage is available.
 * @return 1 if available, 0 if not.
 */
extern int metadata_lmdb_is_available(void);

/** Get account metadata from LMDB, decoding the visibility prefix and
 * stripping it from the returned value.
 * @param[in] account Account name.
 * @param[in] key Metadata key.
 * @param[out] value Buffer for the STRIPPED value.
 * @param[in] value_len Size of the value buffer.
 * @param[out] visibility Decoded visibility (METADATA_VIS_PUBLIC/PRIVATE),
 *             or NULL if the caller doesn't need it.
 * @return 0 on success, 1 if not found or expired, -1 on error.
 */
extern int metadata_account_get_vis(const char *account, const char *key,
                                    char *value, size_t value_len, int *visibility);

/** Get account metadata from LMDB. Equivalent to
 * metadata_account_get_vis(account, key, value, METADATA_VALUE_LEN, NULL) —
 * the visibility prefix is decoded and stripped; the caller only sees the
 * raw value.
 * @param[in] account Account name.
 * @param[in] key Metadata key.
 * @param[out] value Buffer for value (at least METADATA_VALUE_LEN).
 * @return 0 on success, 1 if not found, -1 on error.
 */
extern int metadata_account_get(const char *account, const char *key, char *value);

/** Set account metadata in LMDB.
 * Store-row encoding (see metadata_account_set_ts in metadata.c): non-exempt
 * permanent rows (metadata_account_set_permanent) always carry a P:/ *:
 * prefix; non-exempt TTL rows (metadata_account_set) carry the prefix only
 * when @a visibility is METADATA_VIS_PRIVATE (bare = public); server-managed
 * keys (metadata_key_is_server_managed) are always stored bare regardless of
 * @a visibility.
 * @param[in] account Account name.
 * @param[in] key Metadata key.
 * @param[in] value Value to set (NULL to delete; @a visibility is ignored).
 * @param[in] visibility METADATA_VIS_PUBLIC or METADATA_VIS_PRIVATE.
 * @return 0 on success, -1 on error.
 */
extern int metadata_account_set(const char *account, const char *key, const char *value, int visibility);
extern int metadata_account_set_permanent(const char *account, const char *key, const char *value, int visibility);

/** List all metadata for an account from LMDB. Each entry's value is the
 * STRIPPED form and entry->visibility carries the decoded/rule visibility
 * (see metadata_account_get_vis).
 * @param[in] account Account name.
 * @return Head of metadata list (caller must free).
 */
extern struct MetadataEntry *metadata_account_list(const char *account);

/*
 * Read Marker API (IRCv3 draft/read-marker)
 *
 * Read markers are stored in the metadata LMDB environment (available on
 * all servers, not just storing servers). Uses a dedicated "readmarkers" DBI.
 */

/** Get the read marker timestamp for an account and target.
 * @param[in] account Account name.
 * @param[in] target Channel name or nick.
 * @param[out] timestamp Buffer for timestamp (at least 32 bytes).
 * @return 0 on success, 1 if not found, -1 on error.
 */
extern int metadata_readmarker_get(const char *account, const char *target, char *timestamp);

/** Set the read marker timestamp for an account and target.
 * Only updates if the new timestamp is greater than the stored one.
 * @param[in] account Account name.
 * @param[in] target Channel name or nick.
 * @param[in] timestamp Unix timestamp (seconds.milliseconds as string).
 * @return 0 on success (updated), 1 if not updated (older timestamp), -1 on error.
 */
extern int metadata_readmarker_set(const char *account, const char *target, const char *timestamp);

/** Visit every read marker stored for an account: its target name and
 * timestamp string, in key (target-name) order -- it does not sort or
 * bound by timestamp itself; a caller wanting the newest N decides that.
 * @param[in] account Account name.
 * @param[in] cb Called once per marker; a nonzero return stops the walk.
 * @param[in] arg Opaque pointer passed through to @a cb.
 * @return the number of markers visited, or -1 on error.
 */
extern int metadata_readmarker_foreach(const char *account,
                       int (*cb)(const char *target, const char *ts, void *arg),
                       void *arg);

/** Clear all metadata for an account in LMDB.
 * @param[in] account Account name.
 * @return 0 on success, -1 on error.
 */
extern int metadata_account_clear(const char *account);

/** Purge expired metadata entries from LMDB.
 * Called periodically to enforce METADATA_CACHE_TTL.
 * @return Number of entries purged, or -1 on error.
 */
extern int metadata_account_purge_expired(void);

/** Load metadata from LMDB for a logged-in user.
 * Called when a user logs into an account.
 * @param[in] cptr Client that just logged in.
 * @param[in] account Account name.
 */
extern void metadata_load_account(struct Client *cptr, const char *account);

/** Get metadata for a client.
 * @param[in] cptr Client to get metadata from.
 * @param[in] key Key name.
 * @return Metadata entry or NULL if not found.
 */
extern struct MetadataEntry *metadata_get_client(struct Client *cptr, const char *key);

/** Set metadata for a client.
 * @param[in] cptr Client to set metadata on.
 * @param[in] key Key name.
 * @param[in] value Value to set (NULL to delete).
 * @param[in] visibility Visibility level (METADATA_VIS_PUBLIC or METADATA_VIS_PRIVATE).
 * @return 0 on success, -1 on error.
 */
extern int metadata_set_client(struct Client *cptr, const char *key, const char *value, int visibility);

/** Insert or update a client's in-memory metadata entry only — no store
 * write, no doc mirror.  The read-path counterpart to metadata_set_client:
 * use this to cache a value a read already fetched from the store (GET
 * fallback promotion, lazy fill) so the read never re-enters the write
 * chokepoint.
 * @param[in] cptr Client whose in-memory cache gets the entry.
 * @param[in] key Key name.
 * @param[in] value Value to cache (non-NULL).
 * @param[in] visibility Visibility level, decoded from the store row.
 * @return The new-or-updated entry, or NULL on bad args / allocation failure.
 */
extern struct MetadataEntry *metadata_memory_put(struct Client *cptr, const char *key,
                                                  const char *value, int visibility);

/** Insert or update a channel's in-memory metadata entry only — no store
 * write, no doc mirror.  The channel counterpart to metadata_memory_put:
 * use this to cache a value a read already fetched from the store (GET
 * fallback promotion) so the read never re-enters metadata_set_channel,
 * which is now the +R persist chokepoint (B1).
 * @param[in] chptr Channel whose in-memory cache gets the entry.
 * @param[in] key Key name.
 * @param[in] value Value to cache (non-NULL).
 * @param[in] visibility Visibility level, decoded from the store row.
 * @return The new-or-updated entry, or NULL on bad args / allocation failure.
 */
extern struct MetadataEntry *metadata_channel_memory_put(struct Channel *chptr, const char *key,
                                                          const char *value, int visibility);

/** Remove a channel's in-memory metadata entry only — no store write, no
 * doc mirror.  The channel counterpart to metadata_memory_del.
 * @param[in] chptr Channel whose in-memory cache loses the entry.
 * @param[in] key Key name to remove.
 * @return 1 if an entry was removed, 0 if none matched / bad args.
 */
extern int metadata_channel_memory_del(struct Channel *chptr, const char *key);
/** List all metadata for a client.
 * @param[in] cptr Client to list metadata for.
 * @return Head of metadata list (read-only).
 */
extern struct MetadataEntry *metadata_list_client(struct Client *cptr);

/** Emit the draft/metadata-2 self-metadata BATCH to @a to.
 *
 * The registration check is folded in (metadata_registration_check()):
 * a client that is not metadata-aware when it runs gets nothing, and loses
 * what it set before registration.  Used by
 * register_user (normal path) and the bouncer-revive / alias-setup
 * fast paths so each emit point doesn't have to repeat the BATCH
 * open / METADATA loop / batch end sequence.
 *
 * @param[in] to Client receiving the burst (must be local).
 * @param[in] on_network Non-zero when @a to is already known to the
 *   network (a revived session, a device attached to one); zero on the
 *   path that introduces it by N after the burst.
 */
extern void metadata_burst_self_to_client(struct Client *to, int on_network);

/** The registration check (owner, 2026-11-12): whether batch was
 * negotiated is judged once, when registration ends -- the point the
 * registration burst goes out, on each path (register_user(), the bouncer
 * revive, a device attach; metadata_burst_self_to_client() runs it).
 * A metadata-aware client keeps what it set before registration -- and
 * when it is logged in by then, those writes are merged into its account
 * (owner, 2026-11-13: metadata_prereg.h's rule, metadata_prereg_merge()).
 * One that is not never became metadata-aware: its own keys (a client
 * with no account: everything it set before registration), its
 * before-connect writes and its subscriptions are dropped, and it is
 * inert from then on.
 * @param[in] cptr A local client completing registration.
 * @param[in] on_network As for metadata_burst_self_to_client().
 * @return Non-zero if it is metadata-aware.
 */
extern int metadata_registration_check(struct Client *cptr, int on_network);

/** Note a before-connect write of @a cptr (a client of ours still
 * registering) to itself: the last write per key is kept, with @a st, the
 * time its SET was accepted, until registration ends
 * (cli_metadata_prereg).  Deletes are capped at METADATA_MAX_KEYS -- an
 * account never holds more user keys than that, so no more of them can
 * matter.
 * @return 0, -1 on allocation failure, -2 when a delete is over the cap
 *   (the SET is to be refused: LIMIT_REACHED). */
extern int metadata_prereg_record(struct Client *cptr, const char *key,
                                  const char *value, int visibility,
                                  const struct md_stamp *st);

/** Drop @a cptr's before-connect writes. */
extern void metadata_prereg_free(struct Client *cptr);

/** Hand @a from's before-connect writes to @a to (a bouncer revive: the
 * connection that registered becomes the held session's client), dropping
 * any @a to had. */
extern void metadata_prereg_move(struct Client *to, struct Client *from);

/** Announce to the network the keys a client of ours set before
 * registration and kept (a metadata-aware client with no account): run by
 * register_user() after the client's N, since a peer drops a line for a
 * client it does not know.  The keys were kept in memory only until then
 * (metadata_client_write()).
 * @param[in] cptr A local client that has just been introduced.
 */
extern void metadata_announce_registered(struct Client *cptr);

/** Clear all metadata for a client.
 * @param[in] cptr Client to clear.
 */
extern void metadata_clear_client(struct Client *cptr);

/** Get metadata for a channel.
 * @param[in] chptr Channel to get metadata from.
 * @param[in] key Key name.
 * @return Metadata entry or NULL if not found.
 */
extern struct MetadataEntry *metadata_get_channel(struct Channel *chptr, const char *key);

/** Set metadata for a channel. THE persist chokepoint for +R (registered)
 * channel metadata (B1): memory half always runs (metadata_channel_memory_put/
 * _del); for a MODE_REGISTERED channel the change is also persisted via
 * metadata_account_set_permanent(chptr->chname, ...) through the single
 * store chokepoint, metadata_account_set_ts (on crdt-mesh the CRDT doc
 * mirror also rides that chokepoint).
 * Not +R: memory only. See metadata.c for the full contract.
 * @param[in] chptr Channel to set metadata on.
 * @param[in] key Key name.
 * @param[in] value Value to set (NULL to delete).
 * @param[in] visibility Visibility level (METADATA_VIS_PUBLIC or METADATA_VIS_PRIVATE).
 * @return 0 on success, -1 on error.
 */
extern int metadata_set_channel(struct Channel *chptr, const char *key, const char *value, int visibility);

/** Hydrate a channel's in-memory metadata (chptr->metadata) from the
 * persistent store — the LOAD half of the B3 ±R transition hook.  Inserts
 * every stored "#chan\0key" row not already present in memory via
 * metadata_channel_memory_put (memory-only, NO notify — hydration, not a
 * change event); rows already in memory are left untouched.  Frees the
 * transient list it fetches.  At burst/restart memory is empty, so this
 * materializes the full persisted set (the restart-hydration path).
 * @param[in] chptr Channel to hydrate.
 */
extern void metadata_channel_load(struct Channel *chptr);

/** List all metadata for a channel.
 * @param[in] chptr Channel to list metadata for.
 * @return Head of metadata list (read-only).
 */
extern struct MetadataEntry *metadata_list_channel(struct Channel *chptr);

/** Clear all metadata for a channel.
 * @param[in] chptr Channel to clear.
 */
extern void metadata_clear_channel(struct Channel *chptr);

/** Count metadata entries for a client.
 * Server-managed entries (draft/persistence/...) are excluded from
 * the count so they do not consume the user-facing key budget.
 * @param[in] cptr Client to count.
 * @return Number of user-managed metadata entries.
 */
extern int metadata_count_client(struct Client *cptr);

/** Count metadata entries for a channel.
 * Server-managed entries are excluded from the count.
 * @param[in] chptr Channel to count.
 * @return Number of user-managed metadata entries.
 */
extern int metadata_count_channel(struct Channel *chptr);

/** Count persisted metadata keys for an account, excluding
 * server-managed keys.  Used to enforce FEAT_METADATA_MAX_KEYS against
 * LMDB-persisted rows for offline accounts (the oper "*account" SET
 * path), where there is no in-memory MetadataEntry list to walk.
 * Bounded: stops counting at FEAT_METADATA_MAX_KEYS + 1 so a
 * pathological account cannot make the scan unbounded.
 * @param[in] account Account name.
 * @return Number of keys (possibly capped at max_keys + 1), or 0 on
 *         storage unavailable/error.
 */
extern int metadata_account_count_keys(const char *account);

/** Test whether a metadata key is server-managed.
 * Server-managed keys live under the reserved prefix (draft/persistence/...).
 * They are written exclusively by server-side logic, never
 * by direct METADATA SET from a client, and do not count against the
 * per-target key-count limit.
 * @param[in] key Metadata key name.
 * @return Non-zero if the key is server-managed.
 */
extern int metadata_key_is_server_managed(const char *key);

/** Check if a viewer can see a metadata entry.
 * @param[in] viewer Client viewing the metadata.
 * @param[in] owner Client owning the metadata (NULL for channel metadata).
 * @param[in] entry Metadata entry to check.
 * @return Non-zero if visible.
 */
extern int can_view_metadata(struct Client *viewer, struct Client *owner,
                             struct MetadataEntry *entry);

/** Get visibility string for metadata entry.
 * @param[in] entry Metadata entry.
 * @return "*" for public, "private" for private.
 */
extern const char *get_visibility_str(struct MetadataEntry *entry);

/** Free a metadata entry.
 * @param[in] entry Entry to free.
 */
extern void metadata_free_entry(struct MetadataEntry *entry);

/** Free all metadata for a client (called on disconnect).
 * @param[in] cptr Client being freed.
 */
extern void metadata_free_client(struct Client *cptr);

/** Free all metadata for a channel (called on channel destruction).
 * @param[in] chptr Channel being freed.
 */
extern void metadata_free_channel(struct Channel *chptr);

/* Subscription functions */

/** Add a subscription for a client.
 * @param[in] cptr Client subscribing.
 * @param[in] key Key to subscribe to.
 * @return 0 on success, -1 if limit reached.
 */
extern int metadata_sub_add(struct Client *cptr, const char *key);

/** Remove a subscription for a client.
 * @param[in] cptr Client unsubscribing.
 * @param[in] key Key to unsubscribe from.
 * @return 0 on success, -1 if not subscribed.
 */
extern int metadata_sub_del(struct Client *cptr, const char *key);

/** Check if a client is subscribed to a key.
 * @param[in] cptr Client to check.
 * @param[in] key Key to check.
 * @return 1 if subscribed, 0 if not.
 */
extern int metadata_sub_check(struct Client *cptr, const char *key);

/** List subscriptions for a client.
 * @param[in] cptr Client to list.
 * @return Head of subscription list.
 */
extern struct MetadataSub *metadata_sub_list(struct Client *cptr);

/** Count subscriptions for a client.
 * @param[in] cptr Client to count.
 * @return Number of subscriptions.
 */
extern int metadata_sub_count(struct Client *cptr);

/** Free all subscriptions for a client.
 * @param[in] cptr Client being freed.
 */
extern void metadata_sub_free(struct Client *cptr);

/** Send metadata subscription notifications when a client joins a channel.
 * @param[in] joiner Client that just joined.
 * @param[in] chptr Channel being joined.
 */
extern void metadata_send_join_notifications(struct Client *joiner, struct Channel *chptr);

/** Notify local draft/metadata-2 subscribers of a metadata change on @a target.
 * Walks LocalClientArray and sends `:me METADATA <target> <key> * [:value]` to
 * each qualifying local client that has CAP_DRAFT_METADATA2 and is subscribed
 * to @a key.  Recipient scoping depends on @a visibility:
 *   - METADATA_VIS_PUBLIC: current behavior — the target user/channel itself,
 *     or any local client sharing a channel with the target user (channel
 *     targets: any member).
 *   - METADATA_VIS_PRIVATE: ONLY the target's own subscribed sessions — for
 *     an account-anchored target this means every LOCAL session authed to the
 *     SAME account (bouncer aliases + any other concurrent login), not just
 *     the specific nick @a target resolves to (aliases are removed from the
 *     nick hash — see the bouncer-architecture skill).  An unauthenticated
 *     target reduces to exact client identity (no multi-session concept).
 *     Channel targets have no session "owner" (matches can_view_metadata():
 *     a channel's private entries have owner==NULL) so nothing is sent.
 * LOCAL delivery only — no S2S emission.  value==NULL/empty is an unset
 * notification (wire form unchanged regardless of visibility — a value-less
 * unset carries no value, so scoping is the only thing visibility affects).
 * @param[in] target Nick or channel name the change applies to.
 * @param[in] key Metadata key that changed.
 * @param[in] value New value, or NULL/empty for an unset.
 * @param[in] visibility METADATA_VIS_PUBLIC or METADATA_VIS_PRIVATE.
 */
extern void metadata_notify_subscribers(const char *target, const char *key,
                                        const char *value, int visibility);

/** metadata_notify_subscribers(), telling everyone but @a butone (NULL:
 * everyone) -- a client whose registration burst carries the change.
 */
extern void metadata_notify_subscribers_butone(const char *target, const char *key,
                                               const char *value, int visibility,
                                               struct Client *butone);

/** Change one key of @a cptr's in-memory metadata and its mode-sync flag
 * (metadata_mode_sync[]) only: no store row, no notification, nothing
 * sent.  For a server that learns a user's mode-synced key from another
 * fork server's M line: that user's own server is the one writer of the
 * account's row (set_user_mode), and the stamped row it sends is what
 * this server stores.
 * @param[in] cptr Client whose memory changes.
 * @param[in] key Key name.
 * @param[in] value Value to set, or NULL to delete.
 * @param[in] visibility METADATA_VIS_PUBLIC or METADATA_VIS_PRIVATE.
 */
/** Give one of our connections the account's stored modes (push-2 final
 * fix wave, I-1): for each mode-synced key (metadata_mode_sync[]:
 * umode.*, chathistory.*, draft/persistence/hold) the account has a row
 * for, the flag follows the row -- a live row by its value, a tombstone
 * as off; a key with no row leaves the flag as it is.  The +p rule
 * (PRIV_HIDE_CHANNELS / DERESTRICT_HIDECHANS) applies.  Not for a device
 * (bouncer alias) or a remote copy.
 * @param[in] cptr Our connection, a user with an account.
 * @param[in] live 0 at registration, before the N (flags and list set
 *            silently: the N carries them); 1 for a login after
 *            registration (each change through umode_sync_apply: echo,
 *            counts, M line, session mirror).
 */
extern void metadata_mode_sync_restore(struct Client *cptr, int live);

extern void metadata_client_memory_set(struct Client *cptr, const char *key,
                                       const char *value, int visibility);

/* ========== W4: stamped account store (cross-fork-server sync) ========== */

/** Mint a fresh HLC stamp for a local account-store write.
 * Thin wrapper over hlc_global_event() (crdt_hlc.h) in the struct
 * md_stamp shape the metadata_lww.h codec and store use.
 */
extern struct md_stamp metadata_stamp_now(void);

/** Write (or tombstone) one stamped account-metadata row: the value row
 * and its clock row (metadata_clock column family) in one write batch.
 * metadata_account_set_ts (the backing of metadata_account_set /
 * metadata_account_set_permanent) is stamp-now plus this writer, so
 * every existing writer is stamped and every delete leaves a tombstone.
 * @param[in] account Account name.
 * @param[in] key Metadata key.
 * @param[in] value Value to set, or NULL to tombstone (delete the value
 *             row; the clock row is still written, with tombstone=1).
 * @param[in] vis METADATA_VIS_PUBLIC or METADATA_VIS_PRIVATE (meaningless
 *             for a tombstone, but still recorded).
 * @param[in] st Stamp to record in the clock row.
 * @return 0 on success, -1 on error.
 */
extern int metadata_account_put_versioned(const char *account, const char *key,
                                          const char *value, int vis,
                                          const struct md_stamp *st);

/** Read one account-metadata row's current version: the clock row plus
 * (for a live row) the decoded value.  A live row with no clock entry
 * (written before this feature existed) reads with stamp 0.0.0.
 * @param[in] account Account name.
 * @param[in] key Metadata key.
 * @param[out] out Version info (stamp/tombstone/vis/value/vlen); on a
 *             live row, @a out->value points into @a valbuf.
 * @param[out] valbuf Buffer the live value is decoded into.
 * @param[in] vlen Size of @a valbuf.
 * @return 0 (found — live row or tombstone), 1 (absent), -1 (error).
 */
extern int metadata_account_get_version(const char *account, const char *key,
                                        struct md_version *out,
                                        char *valbuf, size_t vlen);

/** Merge an incoming stamped version against the stored one by the pure
 * LWW rule (metadata_lww.h's md_lww_take).  On take: folds the incoming
 * stamp into this server's global HLC (hlc_global_receive, so our clock
 * never reads behind a peer's) and persists the incoming row under its
 * OWN stamp (metadata_account_put_versioned) — never a freshly minted
 * one, so every peer that merges the same row agrees on its stamp.
 * @param[in] account Account name.
 * @param[in] key Metadata key.
 * @param[in] in Incoming version to merge.
 * @return 1 (taken), 0 (kept the local version), -1 (error).
 */
extern int metadata_account_merge(const char *account, const char *key,
                                  const struct md_version *in);

/** Visit every live row and every tombstone stored for @a account.
 * Unlike metadata_account_list, a key of any length is visited — a
 * 64+ byte draft/persistence/... key is never skipped or truncated.
 * @param[in] account Account name.
 * @param[in] cb Called once per row; a nonzero return stops the walk.
 * @param[in] arg Opaque pointer passed through to @a cb.
 * @return the number of rows visited, or -1 on error.
 */
extern int metadata_account_foreach_version(const char *account,
                       int (*cb)(const char *key, const struct md_version *v, void *arg),
                       void *arg);

/** Apply an account-store change to every IsUser client logged into
 * @a account, local or remote: updates the in-memory MetadataEntry list
 * (metadata_apply_client_memory's per-client half) and the mode-sync
 * flag table (metadata_mode_sync[]) for each.  A mode-synced key touches
 * only this server's own connections: each non-device connection whose
 * mode differs is changed as a self MODE (umode_sync_apply: echo, counts,
 * M line, session mirror); remote copies change by their servers' M
 * lines.  No store write.  Keys of METADATA_KEY_LEN or longer are skipped (they
 * cannot fit the in-memory key buffer).  Notifies local
 * draft/metadata-2 subscribers once for a PRIVATE key (any one session
 * of the account resolves every session, per metadata_notify_subscribers'
 * own account-wide PRIVATE scoping), or once per distinct non-alias nick
 * for a PUBLIC one.
 * @param[in] account Account name.
 * @param[in] key Metadata key.
 * @param[in] value New value, or NULL for an unset.
 * @param[in] vis METADATA_VIS_PUBLIC or METADATA_VIS_PRIVATE.
 */
extern void metadata_account_apply_memory(const char *account, const char *key,
                                          const char *value, int vis);

/** metadata_account_apply_memory() for a client's before-connect write
 * merged into its account at registration (metadata_prereg_merge()):
 * @a quiet, when not NULL, is that client on the path that introduces it
 * by N after the burst -- nobody knows it yet, so its own list entry and
 * mode flag are set silently (the N carries the flag), as at
 * metadata_mode_sync_restore(..., 0); @a butone, when not NULL, is told
 * nothing: its registration burst carries the key, and a mode-synced key
 * changes its flag (as the account's connection, or as a device through
 * its primary's session mirror) without a MODE line -- its sign-on mode
 * line says it (umode_sync_apply_butone()).
 */
extern void metadata_account_apply_memory_ex(const char *account, const char *key,
                                             const char *value, int vis,
                                             struct Client *quiet,
                                             struct Client *butone);

/* X3 dependency removed - Nefarious is now authoritative for metadata */

/* MDQ removed entirely (protocol + responder) - Nefarious answers GET
 * from local LMDB only */

struct StatDesc;

/** Report METADATA statistics for /STATS.
 * @param[in] to Client requesting stats.
 * @param[in] sd Stats descriptor.
 * @param[in] param Extra parameter (unused).
 */
extern void metadata_report_stats(struct Client *to, const struct StatDesc *sd, char *param);

/** Report defrag results for the metadata database.
 * @param[in] to Client to send results to.
 */
extern void metadata_report_defrag(struct Client *to);

/** Force sync/flush the metadata database to disk.
 * @return 0 on success, -1 on error.
 */
extern int metadata_sync(void);

/** Report detailed GC info for the metadata database.
 * @param[in] to Client to send results to.
 */
extern void metadata_report_gc(struct Client *to);

/** Report detailed MDBX environment info for the metadata database.
 * @param[in] to Client to send results to.
 */
extern void metadata_report_store_info(struct Client *to);

/* ========== Bouncer Persistence Accessors ========== */

struct db_env;
struct db_cf;

/** Get the storage environment handle (for bouncer session persistence).
 * @return db_env pointer, or NULL if storage not initialized.
 */
extern struct db_env *metadata_get_env(void);

/** Get the bouncer_sessions CF handle.
 * @return db_cf pointer for the bouncer_sessions column family.
 */
extern struct db_cf *metadata_get_bouncer_cf(void);

#endif /* INCLUDED_metadata_h */
