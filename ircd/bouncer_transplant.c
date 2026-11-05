/*
 * IRC - Internet Relay Chat, ircd/bouncer_transplant.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * See include/bouncer_transplant.h.  Keep this file to the event core: it
 * is linked with the real ircd_events.o for the cmocka suite.
 */
#include "config.h"

#include "bouncer_transplant.h"

#include <errno.h>

int bounce_transplant_register(struct Socket *sock, EventCallBack call,
                               void *data, int fd, int *fresh)
{
  unsigned int flags = sock->s_header.gh_flags;
  int old_fd = s_fd(sock);
  int old_error = sock->s_error;
  int err;

  *fresh = !(flags & GEN_ACTIVE);
  s_fd(sock) = fd;
  if (*fresh ? socket_add(sock, call, data, SS_CONNECTED,
                          SOCK_EVENT_READABLE, fd)
             : socket_reattach(sock, fd))
    return 1;

  /* Refused: the socket as it was.  socket_add() reset the flags (with
   * GEN_ACTIVE set) and left the error count alone, so the saved flags go
   * back as they were.  socket_reattach() cleared GEN_ERROR and dropped an
   * error still waiting for the loop together with its count: it is put
   * back the same way, so the loop delivers it as it would have. */
  err = errno;
  sock->s_header.gh_flags = *fresh ? flags : (flags & ~GEN_ERR_PENDING);
  s_fd(sock) = old_fd;
  if (!*fresh && (flags & GEN_ERR_PENDING))
    socket_error(sock, old_error);
  errno = err;
  return 0;
}
