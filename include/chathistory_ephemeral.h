#ifndef INCLUDED_chathistory_ephemeral_h
#define INCLUDED_chathistory_ephemeral_h
/*
 * IRC - Internet Relay Chat, include/chathistory_ephemeral.h
 * Copyright (C) 2026 Nefarious Development Team
 *
 * In-memory PM ring for ephemeral↔ephemeral conversations.  When neither
 * party of a PM has an account, the LMDB-backed store is skipped (no
 * durable anchor) and the message is instead appended to a per-Client
 * ring on both ends.  Queried by CHATHISTORY for ephemeral senders;
 * freed on exit_client via ephemeral_purge_session.
 *
 * Authed↔authed and authed↔ephemeral PMs continue to use the LMDB path
 * (with Phase 5a's sessid-tag participant check) and are unaffected.
 */

#ifndef INCLUDED_history_h
#include "history.h"      /* enum HistoryMessageType, struct HistoryMessage */
#endif

struct Client;

/** Single ring entry — same fields as we'd populate in a HistoryMessage
 * at query time.  Capped at HISTORY_CONTENT_LEN to match the LMDB
 * record cap; multiline isn't supported here (an ephemeral session
 * doesn't have multiline persistence backing it). */
struct EphemeralPmEntry {
  struct EphemeralPmEntry *next;       /**< Singly-linked, oldest-first */
  char  msgid[HISTORY_MSGID_LEN];
  char  timestamp[HISTORY_TIMESTAMP_LEN];
  char  target[NICKLEN * 2 + 2];       /**< Canonical "nick1:nick2" key */
  char  original_target[CHANNELLEN + 1]; /**< Receiver nick at send time */
  char  sender[HISTORY_SENDER_LEN];    /**< nick!user@host */
  enum HistoryMessageType type;
  char  content[HISTORY_CONTENT_LEN];
  char  client_tags[512];
  size_t bytes;                        /**< Approx memory footprint */
};

/** Per-Client ring.  Allocated lazily on first insert. */
struct EphemeralPmRing {
  struct EphemeralPmEntry *head;       /**< Oldest entry */
  struct EphemeralPmEntry *tail;       /**< Newest entry */
  size_t total_bytes;                  /**< Sum of all entries' .bytes */
  unsigned int count;                  /**< Entry count (debug/stats) */
};

/** Record a PM that traveled between two ephemeral parties.  Inserts
 * on BOTH @a sender and @a recipient's rings (each side carries its
 * own copy so a disconnect only loses one side's view).  Called from
 * store_private_history when neither party is authed. */
extern void chathistory_ephemeral_store_pair(struct Client *sender,
                                              struct Client *recipient,
                                              const char *text,
                                              enum HistoryMessageType type,
                                              const char *msgid,
                                              const char *timestamp,
                                              const char *client_tags);

/** Walk @a cli's ring and append every entry whose target matches @a
 * canonical_target to *@a result_head.  Honors @a limit; returns the
 * number of entries appended.  Caller still owns the resulting list
 * and must free via history_free_messages.
 *
 * The ring is oldest-first; this walks it in storage order and the
 * caller can reverse if they want newest-first display.  For LATEST
 * the standard chathistory replay path orders by timestamp anyway, so
 * a simple append is sufficient. */
extern int chathistory_ephemeral_query(struct Client *cli,
                                        const char *canonical_target,
                                        int limit,
                                        struct HistoryMessage **result_head);

/** Returns non-zero iff @a cli's ring has any entry whose target
 * matches @a canonical_target.  Used by check_history_access to gate
 * PM-history queries for ephemeral senders when LMDB has no record. */
extern int chathistory_ephemeral_has_target(struct Client *cli,
                                             const char *canonical_target);

/** Free @a cli's ring and detach it from the Client.  Idempotent. */
extern void chathistory_ephemeral_purge(struct Client *cli);

#endif /* INCLUDED_chathistory_ephemeral_h */
