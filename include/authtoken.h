/*
 * IRC - Internet Relay Chat, include/authtoken.h
 * Copyright (C) 2026 Evilnet Development
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
 * @brief IRCv3 draft/authtoken: external-service tokens and their claims.
 *
 * A pre-configured external service (Authtoken { } block, one per
 * service key) may receive short-lived, single-use tokens that a user
 * requests with TOKEN GENERATE.  The service hands the token back over
 * its own IRC connection with TOKEN VALIDATE and gets the claims the
 * network vouches for: account, name, member_of, operator_of, scope.
 *
 * Tokens replicate to every IRCv3-aware server (P10 TK G / TK U) so
 * the validator may connect to any server; claims are evaluated live
 * at VALIDATE time from the requester's current channel state.
 */
#ifndef INCLUDED_authtoken_h
#define INCLUDED_authtoken_h

#ifndef INCLUDED_sys_types_h
#include <sys/types.h>
#define INCLUDED_sys_types_h
#endif

struct Client;
struct Channel;

/** Upper bound on configured services (validator authority is kept per
 * connection as a bitmask over service slots). */
#define AUTHTOKEN_MAX_SERVICES 32
/** Length of a service key (vendor/NAME). */
#define AUTHTOKEN_KEYLEN 64
/** Length of the wire token (hex of AUTHTOKEN_BYTES random bytes). */
#define AUTHTOKEN_BYTES 24
#define AUTHTOKEN_LEN (AUTHTOKEN_BYTES * 2)
/** Longest scope we store (a channel name or a nick). */
#define AUTHTOKEN_SCOPELEN 200

/* ---- Configuration (parser-facing) ---- */
extern void authtoken_conf_begin(void);          /* before yyparse */
extern void authtoken_conf_service(const char *key);
extern void authtoken_conf_url(const char *url);
extern void authtoken_conf_description(const char *desc);
extern void authtoken_conf_pass(const char *pass);
extern void authtoken_conf_host(const char *mask);
extern void authtoken_conf_key(const char *b64url_scalar);  /* makes the service a JWT issuer */
extern int  authtoken_conf_end(void);            /* end of one block; 0 = rejected */
extern void authtoken_conf_apply(void);          /* after yyparse */

struct StatDesc;
extern void authtoken_report_stats(struct Client *to, const struct StatDesc *sd, char *param);

/* ---- Queries ---- */
extern int authtoken_service_count(void);
/** URL of the spec-defined FILEHOST service, or NULL. */
extern const char *authtoken_filehost_url(void);

/* ---- Per-connection validator authority ---- */
/** Remember which services @a cptr's PASS authorises it to validate.
 * Called before registration clears the password. */
extern void authtoken_note_pass(struct Client *cptr);

/* ---- Registration burst ---- */
extern void authtoken_send_servicelist(struct Client *sptr);

/* ---- Command handlers (m_token.c) ---- */
extern int m_token(struct Client *cptr, struct Client *sptr, int parc, char *parv[]);
extern int mr_token(struct Client *cptr, struct Client *sptr, int parc, char *parv[]);
extern int ms_token(struct Client *cptr, struct Client *sptr, int parc, char *parv[]);

/* ---- Token table (authtoken.c) ---- */
/** Mint a token for @a user bound to service slot @a svc with @a scope
 * (may be NULL); replicates it.  @return the token string or NULL. */
extern const char *authtoken_generate(struct Client *user, int svc, const char *scope);
/** Learn a token from a peer (TK G). */
extern void authtoken_learn(const char *token, const char *service,
                            const char *yxx, time_t expires, const char *scope);
/** Forget a token (TK U or local consume). */
extern void authtoken_forget(const char *token);
/** Look a service up by key (case-insensitive).  @return slot or -1. */
extern int authtoken_find_service(const char *key);
/** Whether slot @a svc issues signed JWTs instead of opaque tokens. */
extern int authtoken_service_is_jwt(int svc);
/** Whether @a cptr may validate tokens of slot @a svc. */
extern int authtoken_may_validate(struct Client *cptr, int svc);
/** Consume @a token for slot @a svc and emit its claims to @a to.
 * @return 0 on success, -1 if the token is unknown/expired/other
 * service (caller sends FAIL INVALID_TOKEN). */
extern int authtoken_consume(struct Client *to, int svc, const char *token);

#endif /* INCLUDED_authtoken_h */
