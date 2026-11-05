/*
 * IRC - Internet Relay Chat, include/bouncer_transplant.h
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 */
/** @file
 * @brief The one fallible step of a bouncer revive: registering a
 * descriptor another socket gave up for the held ghost's socket.
 *
 * Depends on the event core only (ircd/test/bouncer_transplant_cmocka.c
 * links it with the real ircd_events.o).
 */
#ifndef INCLUDED_bouncer_transplant_h
#define INCLUDED_bouncer_transplant_h

#ifndef INCLUDED_ircd_events_h
#include "ircd_events.h"
#endif

/** Register @a fd, a descriptor another socket gave up with
 * socket_del_keepfd(), for @a sock: socket_add() when @a sock is not
 * active (a ghost restored from the DB, or held through
 * close_connection(), whose ET_DESTROY ran), socket_reattach() when it is.
 *
 * A refusal leaves @a sock as it was: its flags and its fd.  epoll refuses
 * with ENOMEM or ENOSPC (resource exhaustion), and with EEXIST while the
 * descriptor is still registered for another socket -- which is why the
 * caller takes it off the engine first (socket_del_keepfd()).  The event
 * core does not leave the socket as it was: gen_init() sets GEN_ACTIVE
 * before the engine is asked, and a refused socket_add() only unlinks the
 * socket again.  Left so, the socket would read as registered, and the next
 * revive would take socket_reattach() for a socket on no list and with no
 * engine registration (#138's F6-b).
 *
 * @param[in,out] sock Socket that takes the descriptor.
 * @param[in] call Callback for socket_add().
 * @param[in] data Callback data for socket_add().
 * @param[in] fd The descriptor.
 * @param[out] fresh Set to 1 when socket_add() was used, 0 for
 *   socket_reattach().
 * @return Non-zero when registered; zero when refused, with errno the
 *   engine's.
 */
extern int bounce_transplant_register(struct Socket *sock, EventCallBack call,
                                      void *data, int fd, int *fresh);

#endif /* INCLUDED_bouncer_transplant_h */
