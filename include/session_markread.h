/** @file session_markread.h
 * @brief Hook for session-anchored read-marker cleanup on ephemeral
 *        client exit.
 *
 * The in-memory session-anchored read-marker store lives inside
 * m_markread.c as static state; only this purge entry point is
 * exposed so ephemeral_purge_session() can drop the session's
 * markers when its client disconnects.
 *
 * Account-anchored markers are persisted via metadata_readmarker_set
 * (LMDB) and survive disconnect — unchanged.  This module exists
 * solely for the ephemeral path.
 */
#ifndef INCLUDED_session_markread_h
#define INCLUDED_session_markread_h

/** Drop all in-memory session-anchored read markers for @a session_id.
 *  No-op if @a session_id is NULL/empty or has no stored markers. */
extern void readmarker_ephemeral_purge(const char *session_id);

#endif /* INCLUDED_session_markread_h */
