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
 * time: the restore reads it as "held from the crash" -- the previous
 * run's last heartbeat -- and rewrites it with that real time before it
 * builds any ghost (bounce_record_restore()).  A binary from before it reads it as a
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
  int held_here;       /**< the session is HOLDING and its primary is our
                        *   own held ghost (not another server's hold) */
  int brief_hold;      /**< that hold lasts only until a device on another
                        *   server takes over (the hold preference is off) */
};

/** The disconnect time a session's record carries.  A real time (a
 * hold's) is written as it is for a session held here, by our own ghost,
 * for its full hold; a brief hold (hold off: only until a device
 * elsewhere takes over) or another server's hold carries 0 -- never ours
 * to bring back.  With none (0, an ACTIVE session): the restart marker
 * BOUNCE_REC_HELD_AT_RESTART when an unclean exit now should leave the
 * session held here -- it is active, its primary is ours, live and logged
 * in, the bouncer is on, its hold preference is on, and no device of it
 * is on another server -- else 0 (the restore expires it).
 * @param[in] f               The facts (NULL: none hold).
 * @param[in] disconnect_time The session's hs_disconnect_time.
 * @return The bsr_disconnect_time to write.
 */
extern int64_t bounce_record_stamp(const struct bounce_stamp_facts *f,
                                   int64_t disconnect_time);

/** The disconnect time a clean shutdown (DIE, RESTART, SIGTERM) writes:
 * the crash rule (bounce_record_stamp()) with the shutdown's own time in
 * place of the restart marker -- a session a disconnect would hold here
 * is held from @a now; a held one keeps its time; anything else carries
 * 0, and the shutdown deletes its record (the session ends cleanly: a
 * hold-off session, one with a device on another server -- that server's
 * split promote carries it --, a brief hold, another server's hold, a
 * device of ours whose primary is elsewhere).
 * @param[in] f               The facts (NULL: none hold).
 * @param[in] disconnect_time The session's hs_disconnect_time.
 * @param[in] now             The shutdown's time.
 * @return The bsr_disconnect_time to write, or 0 for none.
 */
extern int64_t bounce_record_shutdown_stamp(const struct bounce_stamp_facts *f,
                                            int64_t disconnect_time,
                                            int64_t now);

/** Whether @a rec carries the restart marker (a live session's record
 * an unclean exit brings back).  A clean shutdown deletes every such
 * record it did not just write: a session it no longer holds. */
extern int bounce_record_marked(const struct BounceSessionRecord *rec);

/** The adaptive hold's figures (testnet spec bouncer-adaptive-hold-spec):
 * BOUNCER_SESSION_HOLD, BOUNCER_MAX_HOLD, BOUNCER_HOLD_DECAY_PERCENT. */
struct bounce_hold_rule {
  int64_t base;       /**< the hold every session gets */
  int64_t max;        /**< the ceiling of the earned hold */
  int decay_pct;      /**< idle share of the earned hold before it decays
                       *   (0: no decay) */
};

/** The hold a session holds for after @a idle seconds held: the earned
 * hold -- @a base, plus a quarter of base per connection, plus an hour
 * per 24 h attached, capped at @a max; @a base alone for a session that
 * never connected -- decayed once @a decay_pct of it has passed idle (the
 * part left at that point halves for every further quarter of the earned
 * hold, never below base).  The one rule the hold timer, BOUNCER INFO,
 * /CHECK and the restore read.
 * @param[in] r             The figures.
 * @param[in] connect_count The session's connections.
 * @param[in] total_active  Seconds it was attached.
 * @param[in] idle          Seconds held (0 or less: none, the earned hold).
 * @return The hold, in seconds.
 */
extern int64_t bounce_hold_length(const struct bounce_hold_rule *r,
                                  uint32_t connect_count, int64_t total_active,
                                  int64_t idle);

/** What a restart reads a record against (bounce_record_restore()). */
struct bounce_restore_clock {
  int64_t now;         /**< the current time */
  int64_t max_hold;    /**< FEAT_BOUNCER_MAX_HOLD */
  int64_t last_alive;  /**< the previous run's last heartbeat
                        *   (BOUNCE_ALIVE_KEY); 0 when unknown */
  struct bounce_hold_rule hold;  /**< the adaptive hold's figures */
};

/** What a restart does with a persisted record (bounce_record_restore()). */
enum BounceRestoreVerdict {
  BOUNCE_RESTORE_EXPIRED,       /**< not restored; the eviction pass
                                 *   deletes it */
  BOUNCE_RESTORE_HELD,          /**< held when this server went: restored
                                 *   held from its own time */
  BOUNCE_RESTORE_HELD_AT_CRASH  /**< live at an unclean exit (the restart
                                 *   marker): restored held from the crash */
};

/** The one rule the restore and its eviction pass read.
 *  - 0 (a live session no unclean exit brings back, or any ACTIVE record
 *    of an older build), or any other time before the epoch: expired.
 *  - BOUNCE_REC_HELD_AT_RESTART: held from the crash -- the latest time
 *    the server is known to have been alive with the session live: the
 *    previous run's last heartbeat, or the record's own bsr_last_active
 *    when later (never after now) -- and expired when the outage outlived
 *    the session's hold (bounce_hold_length() with its own connections and
 *    active time, idle for the outage) or BOUNCER_MAX_HOLD.  With no
 *    heartbeat known (a record of a build without one): held from now.
 *  - Any other time: held from it, unless more than BOUNCER_MAX_HOLD has
 *    passed since (the hold timer ends a shorter hold that ran out: it is
 *    armed with a settling period at the restore).
 * @param[in]  rec        The record (current layout).
 * @param[in]  c          The clock.
 * @param[out] held_since When held: the session's hs_disconnect_time (may
 *                        be NULL).
 * @return The verdict.
 */
extern enum BounceRestoreVerdict
bounce_record_restore(const struct BounceSessionRecord *rec,
                      const struct bounce_restore_clock *c,
                      int64_t *held_since);

/* ---- Outside the bouncer column family ----
 * Two keys in the metadata env's default column family: an old binary's
 * restore iterates only the bouncer CF, and would read anything else
 * there as a bad record. */

/** Key of the heartbeat: when this server was last known alive. */
#define BOUNCE_ALIVE_KEY "bouncer/alive"
/** Key of the boot record: the last start that restored sessions, and
 * the ones it restored because they were live at the crash. */
#define BOUNCE_BOOT_KEY  "bouncer/boot"

/** The heartbeat value's size (version, pad, time). */
#define BOUNCE_ALIVE_REC_SIZE 16

/** Encode the heartbeat @a t into @a buf (BOUNCE_ALIVE_REC_SIZE bytes). */
extern void bounce_alive_rec_encode(void *buf, int64_t t);

/** Decode a heartbeat value.
 * @return 0 and *t, or -1 when @a len or the version is not ours. */
extern int bounce_alive_rec_decode(const void *buf, size_t len, int64_t *t);

/** A start's boot record states. */
enum bounce_boot_state {
  BOUNCE_BOOT_NONE = 0,     /**< no record: the last start that restored
                             *   ended cleanly (or none ever did) */
  BOUNCE_BOOT_RUNNING = 1,  /**< that start is (or was, if we are reading
                             *   it at a boot) inside its crash window */
  BOUNCE_BOOT_SETTLED = 2   /**< that start outlived its crash window */
};

/** Size of a boot record naming @a count sessions (a header, then each
 * session id in BOUNCER_SESSID_LEN bytes, NUL-terminated). */
extern size_t bounce_boot_rec_size(uint32_t count);

/** Write a boot record's header into @a buf (bounce_boot_rec_size(count)
 * bytes); the ids follow by bounce_boot_rec_put_id(). */
extern void bounce_boot_rec_put_header(void *buf,
                                       enum bounce_boot_state state,
                                       int64_t start, uint32_t count);

/** Write session id @a i of a boot record (truncated to
 * BOUNCER_SESSID_LEN - 1 characters, NUL-padded). */
extern void bounce_boot_rec_put_id(void *buf, uint32_t i, const char *id);

/** Decode a boot record.
 * @return 0 with the header's fields, or -1 when the value is not a
 *         well-formed record of ours (a short or long value, an unknown
 *         version or state, an id without its NUL). */
extern int bounce_boot_rec_decode(const void *buf, size_t len,
                                  enum bounce_boot_state *state,
                                  int64_t *start, uint32_t *count);

/** Session id @a i of a boot record bounce_boot_rec_decode() accepted. */
extern const char *bounce_boot_rec_id(const void *buf, uint32_t i);

/** Whether a session restored with verdict @a v goes on this start's
 * boot record, the list the crash-loop breaker skips if this start dies
 * inside its window: only a session restored because it was live at the
 * crash (BOUNCE_RESTORE_HELD_AT_CRASH, the restart marker).  A session
 * held before the crash came back before the crash restore existed, and
 * keeps coming back (ruling 2026-11-06: the skipped sessions are "lost,
 * as before this change").
 * @param[in] v The session's restore verdict.
 * @return 1 to list it, else 0. */
extern int bounce_boot_lists(enum BounceRestoreVerdict v);

/** The crash-loop breaker (user decision 2026-11-06).  A start that
 * restored sessions writes its boot record RUNNING, before it builds any
 * ghost, naming the sessions it restored because they were live at the
 * crash (bounce_boot_lists()); it marks it SETTLED once it has lived
 * BOUNCER_RESTORE_CRASH_WINDOW seconds, and a clean shutdown deletes it.
 * A boot that finds the previous start's record still RUNNING -- it ended
 * uncleanly inside its window: a crash, possibly in the restore or caused
 * by what it restored -- does not restore the sessions that record
 * names.  The heartbeat stands in for a lost settle mark: a start known
 * alive for its window is not one to break.
 * @param[in] prev       The previous start's state.
 * @param[in] prev_start When it started.
 * @param[in] last_alive Its last heartbeat (0: unknown).
 * @param[in] window     BOUNCER_RESTORE_CRASH_WINDOW (0 or less: off).
 * @return 1 to skip what the previous start restored, else 0.
 */
extern int bounce_restore_breaker(enum bounce_boot_state prev,
                                  int64_t prev_start, int64_t last_alive,
                                  int64_t window);

#endif /* INCLUDED_bouncer_record_h */
