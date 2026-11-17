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
 *
 * It also carries the hook rename_channel() calls to move a channel's
 * markers, of both kinds, to its new name.
 */
#ifndef INCLUDED_session_markread_h
#define INCLUDED_session_markread_h

/** Drop all in-memory session-anchored read markers for @a session_id.
 *  No-op if @a session_id is NULL/empty or has no stored markers. */
extern void readmarker_ephemeral_purge(const char *session_id);

struct Channel;

/** Copy the read markers of @a chptr's old name @a oldname to its new
 *  one (m_markread.c): its members' account markers and every session
 *  marker.  Called by rename_channel() on every server. */
extern void markread_channel_renamed(struct Channel *chptr,
                                     const char *oldname);

#endif /* INCLUDED_session_markread_h */
