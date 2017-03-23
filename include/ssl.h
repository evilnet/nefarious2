/************************************************************************
 *   IRC - Internet Relay Chat, ircd/ssl.c
 *   Copyright (C) 2013 Matthew Beeching (Jobe)
 *
 *   See file AUTHORS in IRC package for additional names of
 *   the programmers.
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 1, or (at your option)
 *   any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
/** @file
 * @brief Implimentation of common SSL functions.
 * @version $Id:$
 */

#include "config.h"
#include "ircd_osdep.h"

#ifndef INCLUDED_ssl_h
#define INCLUDED_ssl_h

#ifdef USE_SSL

#include <openssl/ssl.h>

struct Socket;
struct Listener;
struct ConfItem;

extern int ssl_init(void);
extern int ssl_reinit(int sig);
extern void ssl_add_connection(struct Listener *listener, int fd);
extern int ssl_murder(void *ssl, int fd, const char *buf);
extern void ssl_free(struct Socket *socketh);
extern int ssl_connect(struct Socket* sock, struct ConfItem *aconf);
extern int ssl_is_init_finished(SSL *s);
extern int ssl_starttls(struct Client *cptr);
extern void ssl_abort(struct Client *cptr);
extern int ssl_accept(struct Client *cptr);

extern IOResult ssl_recv(struct Socket *socket, struct Client *cptr, char* buf, unsigned int length, unsigned int* count_out);
extern IOResult ssl_sendv(struct Socket *socket, struct Client *cptr, struct MsgQ* buf, unsigned int* count_in, unsigned int* count_out);
extern int ssl_send(struct Client *cptr, const char *buf, unsigned int len);

extern char  *ssl_get_cipher(SSL *ssl);
extern char* ssl_get_fingerprint(SSL *ssl);
extern const char* ssl_get_verify_result(SSL *ssl);
extern char *ssl_error_str(int err, int my_errno);

#endif /* USE_SSL */
#endif /* INCLUDED_ssl_h */

