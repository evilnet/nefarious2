/*
 * IRC - Internet Relay Chat, common/packet.c
 * Copyright (C) 1990  Jarkko Oikarinen and
 *                     University of Oulu, Computing Center
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
/** @file
 * @brief Input packet handling functions.
 * @version $Id: packet.c 1271 2004-12-11 05:14:07Z klmitch $
 */
#include "config.h"

#include "packet.h"
#include "client.h"
#include "ircd.h"
#include "ircd_chattr.h"
#include "ircd_log.h"
#include "parse.h"
#include "s_bsd.h"
#include "s_misc.h"
#include "s_debug.h"
#include "send.h"
#include "websocket.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */

/** Add a certain number of bytes to a client's received statistics.
 * @param[in,out] cptr Client to update.
 * @param[in] length Number of newly received bytes to add.
 */
static void update_bytes_received(struct Client* cptr, unsigned int length)
{
  cli_receiveB(&me)  += length;     /* Update bytes received */
  cli_receiveB(cptr) += length;
}

/** Add one message to a client's received statistics.
 * @param[in,out] cptr Client to update.
 */
static void update_messages_received(struct Client* cptr)
{
  ++(cli_receiveM(&me));
  ++(cli_receiveM(cptr));
}

/** Handle received data from a directly connected server.
 * @param[in] cptr Peer server that sent us data.
 * @param[in] buffer Input buffer.
 * @param[in] length Number of bytes in input buffer.
 * @return 1 on success or CPTR_KILLED if the client is squit.
 */
int server_dopacket(struct Client* cptr, const char* buffer, int length)
{
  const char* src;
  char*       endp;
  char*       client_buffer;

  assert(0 != cptr);

  update_bytes_received(cptr, length);

  client_buffer = cli_buffer(cptr);
  endp = client_buffer + cli_count(cptr);
  src = buffer;

  while (length-- > 0) {
    *endp = *src++;
    /*
     * Yuck.  Stuck.  To make sure we stay backward compatible,
     * we must assume that either CR or LF terminates the message
     * and not CR-LF.  By allowing CR or LF (alone) into the body
     * of messages, backward compatibility is lost and major
     * problems will arise. - Avalon
     */
    if (IsEol(*endp)) {
      if (endp == client_buffer)
        continue;               /* Skip extra LF/CR's */
      *endp = '\0';

      update_messages_received(cptr);

      {
        int rc;
        /* This link's S2S stash is the current line's tags only while
         * the line is handled: mark the link for that span and no
         * longer, so nothing after it (or a link that died in it)
         * reads the stash as a current line's. */
        sendcmdto_set_inbound_link(cptr);
        rc = parse_server(cptr, cli_buffer(cptr), endp);
        sendcmdto_set_inbound_link(NULL);
        /* The line's event is over: no S2S tag override it armed may
         * stamp a later, unrelated line (audit 0.4b). */
        sendcmdto_reset_s2s_overrides();
        if (rc == CPTR_KILLED)
          return CPTR_KILLED;
      }
      /*
       *  Socket is dead so exit
       */
      if (IsDead(cptr))
        return exit_dead_client(cptr, "Dead socket");
      endp = client_buffer;
    }
    /* Keep the whole line up to FULL_MSG_SIZE - 1 bytes (tags
     * included), leaving room for the NUL this loop never writes but
     * callers (parse_server via cli_buffer) rely on `con_buffer`
     * holding at index FULL_MSG_SIZE - 1 at most -- `con_buffer` is
     * sized exactly FULL_MSG_SIZE (client.h). recv_classify.c already
     * kills a link whose tag region exceeds 8191 bytes or whose body
     * exceeds 512 off the wire; this is just the reader no longer
     * discarding bytes recv_classify already accepted.
     *
     * Residue (not fixed here): a line at both per-region caps
     * (8191 tag + 1 space + 512 body = 8704 bytes) still loses its
     * last 2 bytes against this 8702-byte bound -- FULL_MSG_SIZE
     * (8703) is one byte short of that worst case. No fork sender
     * comes near it today (outbound tag regions stay well under
     * ~4.2 KB), so it's recorded rather than fixed. */
    else if (endp < client_buffer + FULL_MSG_SIZE - 1)
      ++endp;                   /* There is always room for the null */
  }
  cli_count(cptr) = endp - cli_buffer(cptr);
  return 1;
}

/** Handle received data from a new (unregistered) connection.
 * @param[in] cptr Unregistered connection that sent us data.
 * @param[in] buffer Input buffer.
 * @param[in] length Number of bytes in input buffer.
 * @return 1 on success or CPTR_KILLED if the client is squit.
 */
int connect_dopacket(struct Client *cptr, const char *buffer, int length)
{
  const char* src;
  char*       endp;
  char*       client_buffer;

  assert(0 != cptr);

  update_bytes_received(cptr, length);

  Debug((DEBUG_DEBUG, "connect_dopacket: IsWSNeedHandshake=%d, IsSSL=%d, length=%d",
         IsWSNeedHandshake(cptr), IsSSL(cptr), length));

  /* Handle WebSocket handshake if needed */
  if (IsWSNeedHandshake(cptr)) {
    Debug((DEBUG_DEBUG, "Processing WebSocket handshake"));
    int result;
    /* Accumulate data in client buffer for HTTP request */
    client_buffer = cli_buffer(cptr);
    endp = client_buffer + cli_count(cptr);

    /* Copy incoming data to buffer */
    while (length > 0 && (endp - client_buffer) < BUFSIZE - 1) {
      *endp++ = *buffer++;
      length--;
    }
    *endp = '\0';
    cli_count(cptr) = endp - client_buffer;

    /* Try to complete handshake */
    result = websocket_handshake(cptr, client_buffer, cli_count(cptr));
    if (result == 0) {
      /* Need more data */
      return 1;
    } else if (result < 0) {
      /* Handshake failed */
      return exit_client(cptr, cptr, &me, "WebSocket handshake failed");
    }
    /* Handshake succeeded - clear buffer and continue normally */
    cli_count(cptr) = 0;
    /* Process any remaining data after handshake (unlikely) */
    if (length <= 0)
      return 1;
    buffer = buffer; /* Continue with remaining data */
  }

  client_buffer = cli_buffer(cptr);
  endp = client_buffer + cli_count(cptr);
  src = buffer;

  while (length-- > 0)
  {
    *endp = *src++;
    /*
     * Yuck.  Stuck.  To make sure we stay backward compatible,
     * we must assume that either CR or LF terminates the message
     * and not CR-LF.  By allowing CR or LF (alone) into the body
     * of messages, backward compatibility is lost and major
     * problems will arise. - Avalon
     */
    if (IsEol(*endp))
    {
      /* Skip extra LF/CR's */
      if (endp == client_buffer)
        continue;
      *endp = '\0';

      update_messages_received(cptr);

      {
        int rc = parse_client(cptr, cli_buffer(cptr), endp);
        sendcmdto_reset_s2s_overrides();   /* see server_dopacket */
        if (rc == CPTR_KILLED)
          return CPTR_KILLED;
      }
      /* Socket is dead so exit (unless bouncer hold already claimed it) */
      if (IsDead(cptr)) {
        /* Exit it, or hold it like a dropped connection: a held ghost
         * stops processing without exiting. */
        int rc = exit_dead_client(cptr, "Dead socket");
        return rc ? rc : 1;
      }
      else if (IsServer(cptr))
      {
        cli_count(cptr) = 0;
        return server_dopacket(cptr, src, length);
      }
      endp = client_buffer;
    }
    else if (endp < client_buffer + BUFSIZE)
      /* There is always room for the null */
      ++endp;
  }
  cli_count(cptr) = endp - cli_buffer(cptr);
  return 1;
}

/** Handle received data from a local client.
 * @param[in] cptr Local client that sent us data.
 * @param[in] length Total number of bytes in client's input buffer.
 * @return 1 on success or CPTR_KILLED if the client is squit.
 */
int client_dopacket(struct Client *cptr, unsigned int length)
{
  int rc;

  assert(0 != cptr);

  update_bytes_received(cptr, length);
  update_messages_received(cptr);

  rc = parse_client(cptr, cli_buffer(cptr), cli_buffer(cptr) + length);
  sendcmdto_reset_s2s_overrides();   /* see server_dopacket */
  if (CPTR_KILLED == rc)
    return CPTR_KILLED;
  else if (IsDead(cptr)) {
    rc = exit_dead_client(cptr, "Dead socket");   /* or holds it */
    return rc ? rc : 1;
  }

  return 1;
}


