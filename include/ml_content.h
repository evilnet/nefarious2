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

#ifdef USE_ROCKSDB

struct db_env;
struct db_writebatch;
struct db_snapshot;

/** Initialize ml_content column families within history's storage env.
 * Opens (or creates) the ml_content and ml_paste_secrets CFs.
 * @param[in] env  The storage environment (history's db_env*).
 * @return 0 on success, -1 on error.
 */
extern int ml_content_init(struct db_env *env);

/** Shutdown ml_content column families.  Called before db_env_close.
 * @param[in] env  The storage environment.
 */
extern void ml_content_shutdown(struct db_env *env);

/** Store multiline content and optional paste secret.
 * Stages put(s) on @a wb so they land atomically with whatever else the
 * caller is committing (history rows for the same msgid).
 * @param[in] wb           Active writebatch.
 * @param[in] msgid        Base message ID.
 * @param[in] sender       Sender nick!user@host mask.
 * @param[in] target       Target channel or nick.
 * @param[in] content      Multiline content (\x1F-separated lines).
 * @param[in] content_len  Length of content.
 * @param[in] paste_secret Paste secret string (NULL if paste not enabled).
 * @return 0 on success, -1 on error.
 */
extern int ml_content_store(struct db_writebatch *wb, const char *msgid,
                            const char *sender, const char *target,
                            const char *content, size_t content_len,
                            const char *paste_secret);

/** Retrieve multiline content by msgid.
 * Reads the env's current state (no snapshot).
 * @param[in]  msgid           Message ID to look up.
 * @param[out] content_len_out Receives content length (may be NULL).
 * @param[out] sender_out      Receives pointer to sender within returned buffer (may be NULL).
 * @param[out] target_out      Receives pointer to target within returned buffer (may be NULL).
 * @return Allocated buffer containing the full value (caller must MyFree), or NULL on miss/error.
 *         sender_out/target_out point into the returned buffer; content starts after target\0.
 */
extern char *ml_content_get(const char *msgid, size_t *content_len_out,
                            const char **sender_out, const char **target_out);

/** Resolve multiline content for a history message.
 * If msg->content starts with the \x1Eml sentinel, looks up the full content
 * via @a snap (or the env's current state if @a snap is NULL) and sets
 * msg->dyn_content. No-op for normal messages.
 * @param[in] snap  Optional snapshot for coherent reads with sibling iter.
 * @param[in] msg   HistoryMessage with msgid and content fields populated.
 * @return 0 on success (or if not a multiline ref), -1 on error.
 */
extern int ml_content_resolve(struct db_snapshot *snap,
                              struct HistoryMessage *msg);

/** Stage a delete on the writebatch.  Harmless no-op for a missing key.
 * @param[in] wb     Active writebatch.
 * @param[in] msgid  Message ID to delete.
 * @return 0 on success, -1 on error.
 */
extern int ml_content_delete(struct db_writebatch *wb, const char *msgid);

/** Look up msgid from paste_id (for HTTP paste serving).
 * @param[in] paste_id  Paste ID (msgid-secret format).
 * @return Static buffer containing msgid, or NULL on miss.
 */
extern const char *ml_content_paste_lookup(const char *paste_id);

/** Check if ml_content is available.
 * @return 1 if initialized, 0 if not.
 */
extern int ml_content_available(void);

#else /* neither backend — stubs */

#define ml_content_available() 0
static inline const char *ml_content_paste_lookup(const char *paste_id) { (void)paste_id; return NULL; }
static inline char *ml_content_get(const char *msgid, size_t *content_len_out,
                                   const char **sender_out, const char **target_out)
{ (void)msgid; (void)content_len_out; (void)sender_out; (void)target_out; return NULL; }

#endif /* USE_ROCKSDB */

/** Multiline reference sentinel: \x1E + "ml" */
#define ML_CONTENT_SENTINEL "\x1E" "ml"
#define ML_CONTENT_SENTINEL_LEN 3

#endif /* INCLUDED_ml_content_h */
