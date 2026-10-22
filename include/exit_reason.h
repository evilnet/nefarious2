/*
 * IRC - Internet Relay Chat, include/exit_reason.h
 */
#ifndef INCLUDED_exit_reason_h
#define INCLUDED_exit_reason_h

/** Is @a info one of the texts dead_link() used to write into the
 * realname ("Write error: ...", "Max sendQ exceeded", "Buffer allocation
 * error")?  A held session persisted that text as its realname and every
 * revive and burst replayed it; the revive repairs a realname this says
 * yes to.  Pure: no ircd dependencies (exit_reason_cmocka). */
extern int exit_reason_is_clobbered_info(const char *info);

#endif /* INCLUDED_exit_reason_h */
