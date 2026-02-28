/*
 * IRC - Internet Relay Chat, include/ml_content.h
 * Copyright (C) 2026 Nefarious Development Team
 *
 * Unified multiline content store.
 *
 * Provides MDBX-backed persistent storage for multiline message content,
 * replacing the separate ml_storage (in-memory) and paste_store (MDBX)
 * systems. Lives within history's MDBX environment for atomic writes
 * and shared retention cleanup.
 *
 * Two named databases:
 *   ml_content       - msgid -> sender\0target\0content (compressed)
 *   ml_paste_secrets - paste_id -> msgid (HTTP access control index)
 */

#ifndef INCLUDED_ml_content_h
#define INCLUDED_ml_content_h

#include <stddef.h>

struct Client;
struct HistoryMessage;

#ifdef USE_MDBX
#include <mdbx.h>

/** Initialize ml_content databases within an existing MDBX environment.
 * Opens (or creates) the ml_content and ml_paste_secrets named databases.
 * @param[in] env  The MDBX environment (history's env).
 * @param[in] txn  An open write transaction for DBI creation.
 * @return 0 on success, -1 on error.
 */
extern int ml_content_init(MDBX_env *env, MDBX_txn *txn);

/** Shutdown ml_content databases.
 * Closes DBI handles. Called before mdbx_env_close().
 * @param[in] env  The MDBX environment.
 */
extern void ml_content_shutdown(MDBX_env *env);

/** Store multiline content and optional paste secret.
 * Called within an open write transaction for atomic history+content writes.
 * @param[in] txn          Open write transaction.
 * @param[in] msgid        Base message ID.
 * @param[in] sender       Sender nick!user@host mask.
 * @param[in] target       Target channel or nick.
 * @param[in] content      Multiline content (\x1F-separated lines).
 * @param[in] content_len  Length of content.
 * @param[in] paste_secret Paste secret string (NULL if paste not enabled).
 * @return 0 on success, -1 on error.
 */
extern int ml_content_store(MDBX_txn *txn, const char *msgid,
                            const char *sender, const char *target,
                            const char *content, size_t content_len,
                            const char *paste_secret);

/** Retrieve multiline content by msgid.
 * Opens a read transaction internally.
 * @param[in]  msgid           Message ID to look up.
 * @param[out] content_len_out Receives content length (may be NULL).
 * @param[out] sender_out      Receives pointer to sender within returned buffer (may be NULL).
 * @param[out] target_out      Receives pointer to target within returned buffer (may be NULL).
 * @return Allocated buffer containing the full value (caller must MyFree), or NULL on miss/error.
 *         sender_out/target_out point into the returned buffer; content starts after target\0.
 */
extern char *ml_content_get(const char *msgid, size_t *content_len_out,
                            const char **sender_out, const char **target_out);

/** Resolve multiline content for a history message (in-transaction).
 * If msg->content starts with the \x1Eml sentinel, looks up the full content
 * from ml_content and sets msg->dyn_content. No-op for normal messages.
 * @param[in] txn  Open read or write transaction.
 * @param[in] msg  HistoryMessage with msgid and content fields populated.
 * @return 0 on success (or if not a multiline ref), -1 on error.
 */
extern int ml_content_resolve(MDBX_txn *txn, struct HistoryMessage *msg);

/** Delete a content entry within an open write transaction.
 * Called during history eviction/purge. Harmless no-op if no entry exists.
 * @param[in] txn    Open write transaction.
 * @param[in] msgid  Message ID to delete.
 * @return 0 on success or not found, -1 on error.
 */
extern int ml_content_delete(MDBX_txn *txn, const char *msgid);

/** Look up msgid from paste_id (for HTTP paste serving).
 * Opens a read transaction internally.
 * @param[in] paste_id  Paste ID (msgid-secret format).
 * @return Static buffer containing msgid, or NULL on miss.
 */
extern const char *ml_content_paste_lookup(const char *paste_id);

/** Check if ml_content is available.
 * @return 1 if initialized, 0 if not.
 */
extern int ml_content_available(void);

#else /* !USE_MDBX — stubs */

#define ml_content_available() 0

#endif /* USE_MDBX */

/** Multiline reference sentinel: \x1E + "ml" */
#define ML_CONTENT_SENTINEL "\x1E" "ml"
#define ML_CONTENT_SENTINEL_LEN 3

#endif /* INCLUDED_ml_content_h */
