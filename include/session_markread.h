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
 * It also carries the hook rename_channel() and a relocation call to
 * copy a channel's markers, of both kinds, to the new name.
 */
#ifndef INCLUDED_session_markread_h
#define INCLUDED_session_markread_h

/** Drop all in-memory session-anchored read markers for @a session_id.
 *  No-op if @a session_id is NULL/empty or has no stored markers. */
extern void readmarker_ephemeral_purge(const char *session_id);

struct Channel;

/** Copy the read markers stored under @a oldname to @a newname, where
 *  a rename or a relocation moves a channel's community (m_markread.c):
 *  the account markers of @a chptr's members and every session marker.
 *  Called on every server at the point the rename takes effect. */
extern void markread_channel_renamed(const struct Channel *chptr,
                                     const char *oldname,
                                     const char *newname);

#endif /* INCLUDED_session_markread_h */
