/*
 * IRC - Internet Relay Chat, include/bouncer_record.h
 *
 * Decoding of persisted bouncer session records: every on-disk version
 * (v7 onward) read through its frozen layout and migrated to the current
 * struct BounceSessionRecord.  Pure (no ircd calls) so the migrations are
 * unit tested; bounce_db_restore does the I/O, logging and ghost setup.
 */
#ifndef INCLUDED_bouncer_record_h
#define INCLUDED_bouncer_record_h

#ifndef INCLUDED_bouncer_session_h
#include "bouncer_session.h"
#endif
#ifndef INCLUDED_stddef_h
#include <stddef.h>
#define INCLUDED_stddef_h
#endif

/** Outcome of bounce_record_decode(). */
enum BounceRecordStatus {
  BOUNCE_REC_CURRENT,      /**< Current version, copied as written */
  BOUNCE_REC_MIGRATED,     /**< v8..v11, migrated to the current layout */
  BOUNCE_REC_MIGRATED_V7,  /**< v7, migrated; bsr_sessid left empty for
                            *   the caller to mint (v7 ids were short) */
  BOUNCE_REC_BAD_SIZE,     /**< Known version, length is not its size */
  BOUNCE_REC_UNKNOWN       /**< Too short for a version, or unknown one */
};

/** On-disk size of a record version.
 * @param[in] version  Record version.
 * @return Its size in bytes, or 0 when the version is not one we read.
 */
extern size_t bounce_record_size(uint32_t version);

/** Decode a persisted record into the current layout.
 * @param[in] buf      Record bytes (need not be aligned).
 * @param[in] len      Record length.
 * @param[out] out     Current-layout record; valid unless the status is
 *                     BOUNCE_REC_BAD_SIZE or BOUNCE_REC_UNKNOWN.
 * @param[out] version The version the record carried (0 when too short).
 * @return What was done with the record.
 */
extern enum BounceRecordStatus bounce_record_decode(const void *buf, size_t len,
                                                    struct BounceSessionRecord *out,
                                                    uint32_t *version);

/** The bsr_disconnect_time of a record written while its session is
 * ACTIVE, for a session an unclean exit of this server (a crash, SIGKILL,
 * the OOM killer) must bring back held (bounce_record_stamp()).  Not a
 * time: the restore reads it as "held from the restart"
 * (bounce_record_restore()).  A binary from before it reads it as a
 * disconnect one second before the epoch -- expired -- and evicts the
 * record, as it evicted the 0 those binaries wrote for every ACTIVE
 * record: a downgrade loses no more than it did.  On-disk format: never
 * change the value, and never write it as a real disconnect time. */
#define BOUNCE_REC_HELD_AT_RESTART ((int64_t)-1)

/** What bounce_record_stamp() decides from: the facts a disconnect of
 * every connection of ours at once (what an unclean exit is) reads for a
 * session whose record is being written. */
struct bounce_stamp_facts {
  int active;          /**< the session is ACTIVE */
  int primary_live;    /**< its primary is a live, registered user of
                        *   ours (not held, not an alias) */
  int logged_in;       /**< that primary is logged in */
  int bouncer_on;      /**< the bouncer is on for it */
  int wants_hold;      /**< the session's hold preference */
  int remote_devices;  /**< live devices of the session's own copy on
                        *   another server: that server's split promote
                        *   carries the session when we go */
};

/** The disconnect time a session's record carries.  A real time is
 * written as it is: a hold's, or the "now" a clean shutdown gives a live
 * session (bounce_db_shutdown()).  With none (0, an ACTIVE session): the
 * restart marker BOUNCE_REC_HELD_AT_RESTART when an unclean exit now
 * should leave the session held here -- it is active, its primary is
 * ours, live and logged in, the bouncer is on, its hold preference is on,
 * and no device of it is on another server -- else 0 (the restore expires
 * it).
 * @param[in] f               The facts (NULL: none hold).
 * @param[in] disconnect_time The session's hs_disconnect_time.
 * @return The bsr_disconnect_time to write.
 */
extern int64_t bounce_record_stamp(const struct bounce_stamp_facts *f,
                                   int64_t disconnect_time);

/** What a restart does with a persisted record (bounce_record_restore()). */
enum BounceRestoreVerdict {
  BOUNCE_RESTORE_EXPIRED,  /**< not restored; the eviction pass deletes it */
  BOUNCE_RESTORE_HELD      /**< restored as a held session */
};

/** The one rule the restore and its eviction pass read.  0 (a live
 * session no unclean exit brings back, or any ACTIVE record of an older
 * build) is expired; BOUNCE_REC_HELD_AT_RESTART is held from @a now; any
 * other time is held from that time unless more than @a max_hold has
 * passed since (a time before the epoch is expired).
 * @param[in]  disconnect_time The record's bsr_disconnect_time.
 * @param[in]  now             The current time.
 * @param[in]  max_hold        FEAT_BOUNCER_MAX_HOLD.
 * @param[out] held_since      When held: the session's hs_disconnect_time
 *                             (may be NULL).
 * @return The verdict.
 */
extern enum BounceRestoreVerdict bounce_record_restore(int64_t disconnect_time,
                                                       int64_t now,
                                                       int64_t max_hold,
                                                       int64_t *held_since);

#endif /* INCLUDED_bouncer_record_h */
