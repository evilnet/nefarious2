/************************************************************************
 *   IRC - Internet Relay Chat, include/s_auth.h
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
 * @brief Interface for DNS and ident lookups.
 * @version $Id: s_auth.h 1925 2010-01-02 20:33:10Z klmitch $
 */
#ifndef INCLUDED_s_auth_h
#define INCLUDED_s_auth_h
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>
#define INCLUDED_sys_types_h
#endif
#ifndef INCLUDED_ircd_events_h
#include "ircd_events.h"
#endif
#ifndef INCLUDED_res_h
#include "res.h"
#endif

struct Client;
struct AuthRequest;
struct StatDesc;

extern void start_auth(struct Client *);
extern int auth_ping_timeout(struct Client *);
extern int auth_set_pong(struct AuthRequest *auth, unsigned int cookie);
extern int auth_set_user(struct AuthRequest *auth, const char *username, const char *hostname, const char *servername, const char *userinfo);
extern int auth_set_nick(struct AuthRequest *auth, const char *nickname);
extern int auth_set_password(struct AuthRequest *auth, const char *password);
extern int auth_set_webirc(struct AuthRequest *auth, const char *password, const char *username, const char *hostname, const char *ip, const char *opts);
extern int auth_set_webirc_trusted(struct AuthRequest *auth, const char *password, const char *username, const char *hostname, const char *ip, const char *opts);
extern void auth_send_event(const char *event, const char *paramstring);
extern int auth_set_account(struct AuthRequest *auth, const char *account);
extern void auth_set_originalip(struct AuthRequest *auth, const struct irc_in_addr addr);
extern int auth_cap_start(struct AuthRequest *auth);
extern int auth_cap_done(struct AuthRequest *auth);
extern void auth_end_loc(struct AuthRequest *auth);
extern void destroy_auth_request(struct AuthRequest *req);

extern int auth_restart(void);
extern int auth_spawn(int argc, char *argv[]);
extern void auth_send_exit(struct Client *cptr);
extern void auth_send_xreply(struct Client *sptr, const char *routing, const char *reply);
extern void auth_mark_closing(void);
extern void auth_close_unused(void);
extern void report_iauth_conf(struct Client *cptr, const struct StatDesc *sd, char *param);
extern void report_iauth_stats(struct Client *cptr, const struct StatDesc *sd, char *param);

/* SASL via IAuth */
extern int auth_iauth_handles_sasl(void);
extern int auth_send_sasl_start(struct Client *cptr, const char *mechanism, const char *certfp);
extern int auth_send_sasl_host(struct Client *cptr, const char *username, const char *host, const char *ip);
extern int auth_send_sasl_data(struct Client *cptr, const char *data);
extern int auth_send_sasl_abort(struct Client *cptr);

#endif /* INCLUDED_s_auth_h */

