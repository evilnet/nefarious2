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

#endif /* INCLUDED_bouncer_record_h */
