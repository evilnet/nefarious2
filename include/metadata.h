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

struct Client;
struct Channel;

/** Maximum length of a metadata key name */
#define METADATA_KEY_LEN 64

/** Maximum length of a metadata value */
#define METADATA_VALUE_LEN 1024

/** Maximum number of metadata entries per target */
#define METADATA_MAX_KEYS 20

/** Maximum number of subscriptions per client */
#define METADATA_MAX_SUBS 50

/** Visibility levels for metadata */
#define METADATA_VIS_PUBLIC  0  /* Anyone can see */
#define METADATA_VIS_PRIVATE 1  /* Only owner can see */

/** Metadata entry structure */
struct MetadataEntry {
  char key[METADATA_KEY_LEN];           /**< Key name */
  char *value;                          /**< Value (dynamically allocated) */
  int visibility;                       /**< Visibility level */
  struct MetadataEntry *next;           /**< Next entry in list */
};

/** Metadata subscription for a client */
struct MetadataSub {
  char key[METADATA_KEY_LEN];           /**< Key being subscribed to */
  struct MetadataSub *next;             /**< Next subscription in list */
};

/** Initialize the metadata subsystem */
extern void metadata_init(void);

/** Shutdown the metadata subsystem */
extern void metadata_shutdown(void);

/** Validate a metadata key name.
 * @param[in] key Key name to validate.
 * @return 1 if valid, 0 if invalid.
 */
extern int metadata_valid_key(const char *key);

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
 * @return 0 on success, -1 on error.
 */
extern int metadata_set_client(struct Client *cptr, const char *key, const char *value);

/** List all metadata for a client.
 * @param[in] cptr Client to list metadata for.
 * @return Head of metadata list (read-only).
 */
extern struct MetadataEntry *metadata_list_client(struct Client *cptr);

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

/** Set metadata for a channel.
 * @param[in] chptr Channel to set metadata on.
 * @param[in] key Key name.
 * @param[in] value Value to set (NULL to delete).
 * @return 0 on success, -1 on error.
 */
extern int metadata_set_channel(struct Channel *chptr, const char *key, const char *value);

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
 * @param[in] cptr Client to count.
 * @return Number of metadata entries.
 */
extern int metadata_count_client(struct Client *cptr);

/** Count metadata entries for a channel.
 * @param[in] chptr Channel to count.
 * @return Number of metadata entries.
 */
extern int metadata_count_channel(struct Channel *chptr);

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

#endif /* INCLUDED_metadata_h */
