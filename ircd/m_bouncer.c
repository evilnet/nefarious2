/*
 * IRC - Internet Relay Chat, ircd/m_bouncer.c
 * Copyright (C) 2025 Nefarious Development
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
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
 * @brief BOUNCER command handler - client-facing bouncer management.
 *
 * User subcommands:
 *   BOUNCER HELP [subcommand]   - Subcommand listing or per-command help
 *   BOUNCER SET HOLD [on|off]   - Set hold preference
 *   BOUNCER INFO                - Show session state and preferences
 *   BOUNCER LISTCLIENTS         - List all connections for the session
 *   BOUNCER HISTORY [sessid]    - Show connection history for a session
 *   BOUNCER RESET [sessid]      - Destroy session and exit all attached
 *                                  connections (force reconnect)
 *
 * Oper-only subcommands (for admin/testing):
 *   BOUNCER TOKEN          - Request a new session token
 *   BOUNCER RESUME <token> - Resume a session by token
 *   BOUNCER LISTSESSIONS [*|all] - List sessions; "*" lists every session on
 *                          this server (account name prefixed each row)
 *   BOUNCER STATUS         - Server-wide bouncer accounting audit;
 *                          compares walker counts against UserStats and
 *                          LocalClientArray and reports drift
 *   BOUNCER DISCONNECT <id>- Disconnect/destroy a session
 *   BOUNCER SETNAME <id> <name> - Name a session
 *   BOUNCER SETTINGS       - Show bouncer subsystem settings
 */
#include "config.h"

#include "bouncer_session.h"
#include "capab.h"
#include "channel.h"
#include "class.h"
#include "client.h"
#include "hash.h"
#include "history.h"
#include "ircd.h"
#include "metadata.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "querycmds.h"
#include "s_misc.h"
#include "replay.h"
#include "s_bsd.h"
#include "send.h"
#include "s_debug.h"

#include <assert.h>
#include <string.h>

/* ---------------------------------------------------------------- */
/* Subcommand: TOKEN                                                 */
/* ---------------------------------------------------------------- */

/** Handle BOUNCER TOKEN - create a new session and return token. */
static int bouncer_token(struct Client *sptr)
{
  struct BouncerSession *session;
  int ret;

  if (!IsAccount(sptr)) {
    send_fail(sptr, "BOUNCER", "ACCOUNT_REQUIRED", NULL,
              "You must be logged in to use bouncer features");
    return 0;
  }

  ret = bounce_create(sptr, &session);
  if (ret < 0) {
    send_fail(sptr, "BOUNCER", "SESSION_LIMIT", NULL,
              "Session limit reached");
    return 0;
  }

  /* Broadcast creation to all servers, then BS A so peers can resolve
   * hs_client to this primary's Client struct.  Without BS A a peer
   * receiving the BS C has hs_client = NULL and cannot route a
   * cross-server alias attach through bounce_setup_local_alias (see
   * matching emit + comment in the BOUNCER SET HOLD on path below). */
  bounce_broadcast(session, 'C', NULL);
  bounce_broadcast(session, 'A', cli_yxx(sptr));

  /* Send token to client */
  sendrawto_one(sptr, ":%s %d %s %s :%s",
                cli_name(&me), RPL_BOUNCETOKEN, cli_name(sptr),
                session->hs_sessid, session->hs_token);

  send_note(sptr, "BOUNCER", "SESSION_CREATED", session->hs_sessid,
            "Session created");

  return 0;
}

/* ---------------------------------------------------------------- */
/* Subcommand: RESUME                                                */
/* ---------------------------------------------------------------- */



/** Handle BOUNCER RESUME <token> - resume an existing session. */
static int bouncer_resume(struct Client *sptr, const char *token)
{
  struct BouncerSession *session;
  time_t since_time;
  int ret;

  if (!token || !*token) {
    send_fail(sptr, "BOUNCER", "NEED_PARAM", "RESUME",
              "Missing required parameter");
    return 0;
  }

  session = bounce_find_by_token(token);
  if (!session) {
    send_fail(sptr, "BOUNCER", "INVALID_TOKEN", NULL,
              "Invalid or expired session token");
    return 0;
  }

  /* Verify account ownership */
  if (!IsAccount(sptr) ||
      0 != ircd_strcmp(cli_account(sptr), session->hs_account)) {
    send_fail(sptr, "BOUNCER", "INVALID_TOKEN", NULL,
              "Invalid or expired session token");
    return 0;
  }

  /* Compute replay "since" time from the ghost's idle time — messages
   * arriving after the user's last activity may not have been read.
   * Fall back to disconnect time if idle time is unavailable. */
  {
    time_t idle = 0;
    if (session->hs_client && cli_user(session->hs_client))
      idle = cli_user(session->hs_client)->last;
    since_time = (idle > 0) ? idle : session->hs_disconnect_time;
  }

  /* Attach client to session */
  ret = bounce_attach(session, sptr);
  if (ret < 0) {
    send_fail(sptr, "BOUNCER", "INVALID_TOKEN", NULL,
              "Session is already in use");
    return 0;
  }

  /* Broadcast attach to all servers */
  bounce_broadcast(session, 'A', cli_yxx(sptr));

  send_note(sptr, "BOUNCER", "SESSION_RESUMED", session->hs_sessid,
            "Session resumed");

  /* Async auto-replay for clients without draft/chathistory. */
  if (!CapOwnHas(sptr, CAP_DRAFT_CHATHISTORY)) {
    replay_start_bouncer(sptr, since_time, 0);
  }

  return 0;
}

/* ---------------------------------------------------------------- */
/* Subcommand: LISTSESSIONS                                          */
/* ---------------------------------------------------------------- */

/** Emit one RPL_BOUNCERSESSION row to sptr.  Shared between the
 * own-account and all-sessions listing paths.  When include_account is
 * non-zero (all-sessions mode), the account name is prefixed onto the
 * info string so opers can see who the session belongs to. */
static void bouncer_listsessions_emit(struct Client *sptr,
                                      struct BouncerSession *s,
                                      int include_account)
{
  const char *state_str;
  char info[320];
  char *p = info;
  int rem = sizeof(info);
  int n;

  state_str = (s->hs_state == BOUNCE_ACTIVE) ? "active" : "holding";

  if (include_account) {
    n = ircd_snprintf(0, p, rem, "%s ", s->hs_account);
    if (n < 0 || n >= rem) return;
    p += n;
    rem -= n;
  }

  if (s->hs_state == BOUNCE_HOLDING && s->hs_disconnect_time) {
    time_t hold_time = bounce_compute_hold_time_ext(s);
    time_t remaining = hold_time -
                       (CurrentTime - s->hs_disconnect_time);
    if (remaining < 0)
      remaining = 0;
    ircd_snprintf(0, p, rem, "%s %s %s %ldm connects:%u aliases:%d",
                  s->hs_sessid,
                  s->hs_name[0] ? s->hs_name : "*",
                  state_str,
                  (long)(remaining / 60),
                  s->hs_connect_count,
                  s->hs_alias_count);
  } else {
    ircd_snprintf(0, p, rem, "%s %s %s connects:%u aliases:%d",
                  s->hs_sessid,
                  s->hs_name[0] ? s->hs_name : "*",
                  state_str,
                  s->hs_connect_count,
                  s->hs_alias_count);
  }

  sendrawto_one(sptr, ":%s %d %s %s",
                cli_name(&me), RPL_BOUNCERSESSION, cli_name(sptr),
                info);
}

/** Walker callback for all-sessions listing mode. */
static void bouncer_listsessions_walker(struct BouncerSession *s, void *data)
{
  struct Client *sptr = (struct Client *)data;
  bouncer_listsessions_emit(sptr, s, 1);
}

/** Handle BOUNCER LISTSESSIONS [scope].
 *
 * Default: list sessions for the requesting account.
 * Scope "*" or "all" (oper-only): list every session known to this server,
 *   including ones whose primary lives on a remote server.  Account name
 *   is prepended to each row in this mode.
 *
 * The all-sessions mode is the canonical way to audit server-wide session
 * state — pairs with BOUNCER STATUS for accounting verification.
 */
static int bouncer_listsessions(struct Client *sptr, int parc, char *parv[])
{
  struct AccountSessions *as;
  struct BouncerSession *s;
  int all_mode = 0;

  if (parc >= 3 && parv[2] && *parv[2]) {
    if (0 == strcmp(parv[2], "*") || 0 == ircd_strcmp(parv[2], "all"))
      all_mode = 1;
  }

  if (all_mode) {
    if (!IsOper(sptr) && !IsAnOper(sptr)) {
      send_fail(sptr, "BOUNCER", "NOPRIVS", "LISTSESSIONS",
                "All-sessions mode requires oper privileges");
      return 0;
    }
    bounce_walk_sessions(bouncer_listsessions_walker, sptr);
    sendrawto_one(sptr, ":%s %d %s :End of session list (all sessions)",
                  cli_name(&me), RPL_BOUNCERSETTINGS, cli_name(sptr));
    return 0;
  }

  if (!IsAccount(sptr)) {
    send_fail(sptr, "BOUNCER", "ACCOUNT_REQUIRED", NULL,
              "You must be logged in to use bouncer features");
    return 0;
  }

  as = bounce_find_by_account(cli_account(sptr));
  if (!as || as->as_count == 0) {
    sendrawto_one(sptr, ":%s %d %s :No active sessions",
                  cli_name(&me), RPL_BOUNCERSETTINGS, cli_name(sptr));
    return 0;
  }

  for (s = as->as_sessions; s; s = s->hs_anext)
    bouncer_listsessions_emit(sptr, s, 0);

  return 0;
}

/* ---------------------------------------------------------------- */
/* Subcommand: STATUS                                                */
/* ---------------------------------------------------------------- */

/** Aggregate counters built up during a bounce_walk_sessions sweep. */
struct BouncerStatusCounts {
  unsigned int total_sessions;
  unsigned int active_sessions;
  unsigned int holding_sessions;
  unsigned int local_primary_active;   /* hs_client local, ACTIVE */
  unsigned int local_primary_holding;  /* hs_client local, HOLDING (ghost) */
  unsigned int remote_primary;         /* hs_client on a remote server */
  unsigned int orphan_session;         /* no hs_client at all */
  unsigned int total_aliases;          /* sum of hs_alias_count */
};

static void bouncer_status_walker(struct BouncerSession *s, void *data)
{
  struct BouncerStatusCounts *c = (struct BouncerStatusCounts *)data;
  c->total_sessions++;
  if (s->hs_state == BOUNCE_ACTIVE)
    c->active_sessions++;
  else if (s->hs_state == BOUNCE_HOLDING)
    c->holding_sessions++;
  if (!s->hs_client)
    c->orphan_session++;
  else if (MyUser(s->hs_client)) {
    if (s->hs_state == BOUNCE_HOLDING)
      c->local_primary_holding++;
    else
      c->local_primary_active++;
  } else {
    c->remote_primary++;
  }
  c->total_aliases += s->hs_alias_count;
}

/** Handle BOUNCER STATUS - server-wide bouncer accounting.
 *
 * Oper-only.  Compares walker-derived session/alias counts against
 * UserStats and the LocalClientArray walk so drift is visible at a
 * glance.  Use in tandem with BOUNCER LISTSESSIONS * for audits.
 */
static int bouncer_status(struct Client *sptr)
{
  struct BouncerStatusCounts c;
  unsigned int la_users = 0;        /* IsUser entries in LocalClientArray */
  unsigned int la_aliases = 0;      /* IsBouncerAlias entries */
  unsigned int la_servers = 0;      /* IsServer entries */
  unsigned int la_unknown = 0;      /* in-progress / unregistered */
  int fd;
  char buf[400];
  long drift;

  memset(&c, 0, sizeof(c));
  bounce_walk_sessions(bouncer_status_walker, &c);

  for (fd = 0; fd <= HighestFd; fd++) {
    struct Client *acptr = LocalClientArray[fd];
    if (!acptr)
      continue;
    if (IsServer(acptr)) {
      la_servers++;
    } else if (IsUser(acptr)) {
      la_users++;
      if (IsBouncerAlias(acptr))
        la_aliases++;
    } else {
      la_unknown++;
    }
  }

  ircd_snprintf(0, buf, sizeof(buf),
                "userstats local_clients=%u clients=%u unknowns=%u "
                "servers=%u local_servers=%u",
                UserStats.local_clients, UserStats.clients,
                UserStats.unknowns, UserStats.servers,
                UserStats.local_servers);
  send_note(sptr, "BOUNCER", "STATUS", "userstats", buf);

  ircd_snprintf(0, buf, sizeof(buf),
                "sessions total=%u active=%u holding=%u "
                "local_primary_active=%u local_primary_holding=%u "
                "remote_primary=%u orphan=%u total_aliases=%u",
                c.total_sessions, c.active_sessions, c.holding_sessions,
                c.local_primary_active, c.local_primary_holding,
                c.remote_primary, c.orphan_session, c.total_aliases);
  send_note(sptr, "BOUNCER", "STATUS", "sessions", buf);

  ircd_snprintf(0, buf, sizeof(buf),
                "localarray fd_attached=%u users=%u aliases=%u "
                "servers=%u unregistered=%u highest_fd=%d",
                la_users + la_servers + la_unknown,
                la_users, la_aliases, la_servers, la_unknown,
                HighestFd);
  send_note(sptr, "BOUNCER", "STATUS", "localarray", buf);

  /* Audit: UserStats.local_clients should equal (LocalClientArray users) +
   * (locally-managed holding ghosts).  Held ghosts have no fd so they
   * are absent from LocalClientArray but still counted in local_clients
   * until the session is destroyed, which is by design.
   *
   * drift > 0 means UserStats.local_clients is inflated relative to
   * the sum of in-list users + holding ghosts → leak.
   * drift < 0 would mean it's deflated → over-decrement somewhere. */
  drift = (long)UserStats.local_clients
        - (long)(la_users + c.local_primary_holding);

  ircd_snprintf(0, buf, sizeof(buf),
                "audit local_clients_drift=%ld "
                "(expected=%u local_clients=%u; "
                "expected = la_users[%u] + local_holding[%u])",
                drift,
                la_users + c.local_primary_holding,
                UserStats.local_clients,
                la_users, c.local_primary_holding);
  send_note(sptr, "BOUNCER", "STATUS", "audit", buf);

  return 0;
}


/* ---------------------------------------------------------------- */
/* Subcommand: DISCONNECT                                            */
/* ---------------------------------------------------------------- */

/** Handle BOUNCER DISCONNECT <session-id> - destroy a session. */
static int bouncer_disconnect(struct Client *sptr, const char *sessid)
{
  struct AccountSessions *as;
  struct BouncerSession *s;

  if (!sessid || !*sessid) {
    send_fail(sptr, "BOUNCER", "NEED_PARAM", "DISCONNECT",
              "Missing required parameter");
    return 0;
  }

  if (!IsAccount(sptr)) {
    send_fail(sptr, "BOUNCER", "ACCOUNT_REQUIRED", NULL,
              "You must be logged in to use bouncer features");
    return 0;
  }

  /* Find session by ID in account's list */
  as = bounce_find_by_account(cli_account(sptr));
  if (!as)
    goto notfound;

  for (s = as->as_sessions; s; s = s->hs_anext) {
    if (0 == strcmp(s->hs_sessid, sessid)) {
      bounce_broadcast(s, 'X', NULL);
      bounce_destroy(s);
      send_note(sptr, "BOUNCER", "SESSION_DISCONNECTED", sessid,
                "Session disconnected");
      return 0;
    }
  }

notfound:
  send_fail(sptr, "BOUNCER", "NO_SUCH_SESSION", sessid,
            "No such session");
  return 0;
}

/* ---------------------------------------------------------------- */
/* Subcommand: RESET                                                  */
/* ---------------------------------------------------------------- */

/** Handle BOUNCER RESET [sessid] - destroy a session AND exit all of
 * its live connections (primary + aliases). DISCONNECT only nukes the
 * session record, leaving the user's clients alive but session-disjoint
 * — typically a worse state than before. RESET forces a clean
 * reconnect by exiting every connection, so on next connect the first
 * server seen becomes the new primary and others attach as aliases.
 *
 * Runnable from primary or alias; the caller is exited last so the
 * teardown of siblings completes against a still-live calling client.
 *
 * If sessid is omitted, the caller's own session is targeted (looked
 * up via the alias's primary or the caller itself).
 */
static int bouncer_reset(struct Client *cptr, struct Client *sptr,
                         const char *sessid)
{
  struct AccountSessions *as;
  struct BouncerSession *s = NULL;
  struct Client *primary;
  struct Client *aliases[BOUNCER_MAX_ALIASES];
  int alias_count = 0;
  int i;

  if (!IsAccount(sptr)) {
    send_fail(sptr, "BOUNCER", "ACCOUNT_REQUIRED", NULL,
              "You must be logged in to use bouncer features");
    return 0;
  }

  as = bounce_find_by_account(cli_account(sptr));
  if (!as)
    goto notfound;

  if (sessid && *sessid) {
    for (s = as->as_sessions; s; s = s->hs_anext)
      if (0 == strcmp(s->hs_sessid, sessid))
        break;
  } else {
    /* Default: the session this connection participates in. */
    struct Client *anchor =
        (IsBouncerAlias(sptr) && cli_alias_primary(sptr))
            ? cli_alias_primary(sptr) : sptr;
    s = bounce_get_session(anchor);
    if (!s)
      s = as->as_sessions; /* fallback: first session for account */
  }

  if (!s)
    goto notfound;

  /* Snapshot all live connections before destroying the session — once
   * bounce_destroy runs, hs_aliases[] is gone. */
  primary = s->hs_client;
  for (i = 0; i < s->hs_alias_count && alias_count < BOUNCER_MAX_ALIASES; i++) {
    struct Client *al = findNUser(s->hs_aliases[i].ba_numeric);
    if (al && IsBouncerAlias(al))
      aliases[alias_count++] = al;
  }

  send_note(sptr, "BOUNCER", "SESSION_RESET", s->hs_sessid,
            "Session reset; all attached connections terminating");

  /* Destroy session record first so exit paths don't try to re-hold
   * the primary or untrack against a vanishing session. */
  bounce_broadcast(s, 'X', NULL);
  bounce_destroy(s);

  /* Exit aliases (skip caller — exited last). */
  for (i = 0; i < alias_count; i++) {
    if (aliases[i] != sptr)
      exit_client(cptr, aliases[i], &me, "Bouncer session reset");
  }

  /* Exit primary (skip caller). */
  if (primary && primary != sptr)
    exit_client(cptr, primary, &me, "Bouncer session reset");

  /* Caller last. Returns CPTR_KILLED iff cptr == sptr. */
  return exit_client(cptr, sptr, &me, "Bouncer session reset");

notfound:
  send_fail(sptr, "BOUNCER", "NO_SUCH_SESSION", sessid ? sessid : "",
            "No such session");
  return 0;
}

/* ---------------------------------------------------------------- */
/* Subcommand: ORESET (oper version of RESET, by account+sessid)     */
/* ---------------------------------------------------------------- */

/** Handle BOUNCER ORESET <account> [sessid] - oper command to destroy
 * a session and exit all of its live connections, identified by the
 * target's account name (and optionally a specific sessid when the
 * target account has multiple sessions).
 *
 * Same destructive semantics as RESET, but the oper invoking the
 * command is not the one being reset, so we don't need the "exit
 * caller last" ordering trick — just exit every targeted connection
 * directly.
 *
 * Without sessid: targets the first session on the account (matches
 * RESET's "default" behaviour for the user's own session).  With
 * sessid: requires exact match, fails with NO_SUCH_SESSION otherwise.
 *
 * Logged to the network notice channel so the action is visible in
 * audit trails.
 */
static int bouncer_oreset(struct Client *cptr, struct Client *sptr,
                          const char *account, const char *sessid)
{
  struct AccountSessions *as;
  struct BouncerSession *s = NULL;
  struct Client *primary;
  struct Client *aliases[BOUNCER_MAX_ALIASES];
  int alias_count = 0;
  int i;

  if (!account || !*account) {
    send_fail(sptr, "BOUNCER", "NEED_PARAM", "ORESET",
              "Usage: BOUNCER ORESET <account> [sessid]");
    return 0;
  }

  as = bounce_find_by_account(account);
  if (!as)
    goto notfound;

  if (sessid && *sessid) {
    for (s = as->as_sessions; s; s = s->hs_anext)
      if (0 == strcmp(s->hs_sessid, sessid))
        break;
  } else {
    s = as->as_sessions; /* first session on the account */
  }

  if (!s)
    goto notfound;

  /* Snapshot live connections before destroying the session record. */
  primary = s->hs_client;
  for (i = 0; i < s->hs_alias_count && alias_count < BOUNCER_MAX_ALIASES; i++) {
    struct Client *al = findNUser(s->hs_aliases[i].ba_numeric);
    if (al && IsBouncerAlias(al))
      aliases[alias_count++] = al;
  }

  /* Audit trail: emit a server notice so other opers can see who did
   * what.  Match the format used by other oper actions (KILL/GLINE). */
  sendto_opmask_butone_global(&me, SNO_OLDSNO,
                              "%s used BOUNCER ORESET on session %s "
                              "(account %s)",
                              cli_name(sptr), s->hs_sessid, account);

  send_note(sptr, "BOUNCER", "SESSION_RESET", s->hs_sessid,
            "Session reset by oper");

  /* Destroy session record first so exit paths don't try to re-hold
   * the primary or untrack against a vanishing session. */
  bounce_broadcast(s, 'X', NULL);
  bounce_destroy(s);

  /* Exit all attached connections.  None of them is the caller (oper
   * is on a different account), so plain order is fine. */
  for (i = 0; i < alias_count; i++)
    exit_client(cptr, aliases[i], &me, "Bouncer session reset by oper");
  if (primary)
    exit_client(cptr, primary, &me, "Bouncer session reset by oper");

  return 0;

notfound:
  send_fail(sptr, "BOUNCER", "NO_SUCH_SESSION", sessid ? sessid : account,
            "No such session");
  return 0;
}

/* ---------------------------------------------------------------- */
/* Subcommand: SETNAME                                               */
/* ---------------------------------------------------------------- */

/** Handle BOUNCER SETNAME <session-id> <name>. */
static int bouncer_setname(struct Client *sptr, const char *sessid,
                           const char *name)
{
  struct AccountSessions *as;
  struct BouncerSession *s;
  char update[64];

  if (!sessid || !*sessid || !name || !*name) {
    send_fail(sptr, "BOUNCER", "NEED_PARAM", "SETNAME",
              "Missing required parameter");
    return 0;
  }

  if (!IsAccount(sptr)) {
    send_fail(sptr, "BOUNCER", "ACCOUNT_REQUIRED", NULL,
              "You must be logged in to use bouncer features");
    return 0;
  }

  as = bounce_find_by_account(cli_account(sptr));
  if (!as)
    goto notfound;

  for (s = as->as_sessions; s; s = s->hs_anext) {
    if (0 == strcmp(s->hs_sessid, sessid)) {
      bounce_setname(s, name);

      ircd_snprintf(0, update, sizeof(update), "name=%s", name);
      bounce_broadcast(s, 'U', update);

      send_note(sptr, "BOUNCER", "SESSION_RENAMED", sessid,
                "Session renamed");
      return 0;
    }
  }

notfound:
  send_fail(sptr, "BOUNCER", "NO_SUCH_SESSION", sessid,
            "No such session");
  return 0;
}

/* ---------------------------------------------------------------- */
/* Subcommand: SET                                                   */
/* ---------------------------------------------------------------- */

/** Handle BOUNCER SET HOLD [on|off]. */
static int bouncer_set(struct Client *sptr, int parc, char *parv[])
{
  /* parv[0] = "BOUNCER", parv[1] = "SET", parv[2] = "HOLD", parv[3] = on/off */
  /* or parv[2] = "SESSION", parv[3] = <id>, parv[4] = "HOLD", parv[5] = on/off */

  if (!IsAccount(sptr)) {
    send_fail(sptr, "BOUNCER", "ACCOUNT_REQUIRED", NULL,
              "You must be logged in to use bouncer features");
    return 0;
  }

  if (parc < 4) {
    send_fail(sptr, "BOUNCER", "NEED_PARAM", "SET",
              "Missing required parameter");
    return 0;
  }

  if (0 == ircd_strcmp(parv[2], "HOLD")) {
    /* Account-wide hold preference - stored in metadata */
    if (0 == ircd_strcmp(parv[3], "on")) {
      metadata_set_client(sptr, "bouncer/hold", "1", METADATA_VIS_PRIVATE);
      /* Propagate to peers — metadata_set_client only handles local
       * memory + LMDB persistence; the S2S broadcast happens in
       * m_metadata.c's user-facing path which we bypass here.  Without
       * this, peer servers don't see the user's hold preference and
       * their bounce_auto_resume rejects subsequent cross-server alias
       * attaches at the "no preference + DEFAULT_HOLD off" early
       * return.  Visibility "P" mirrors the wire format
       * m_metadata.c::metadata_cmd_set uses for PRIVATE metadata —
       * target is the client's nick, key is bouncer/hold. */
      sendcmdto_serv_butone_v3(&me, CMD_METADATA, NULL, "%s %s P :1",
                            cli_name(sptr), "bouncer/hold");

      /* Auto-create session if this client doesn't own one — turning hold on
       * should be sufficient to get bouncer behavior without needing TOKEN.
       * Use bounce_get_session(sptr) instead of bounce_has_sessions() so that
       * stale sessions (whose primaries haven't been cleaned up yet) don't
       * prevent this client from getting its own session. */
      if (!bounce_get_session(sptr)) {
        struct BouncerSession *session = NULL;
        if (bounce_create(sptr, &session) == 0 && session) {
          bounce_broadcast(session, 'C', NULL);
          /* BS A is what makes peer servers resolve hs_client to the
           * primary's Client struct on their side — without it, a peer
           * receiving BS C has session->hs_client = NULL and cannot
           * route a subsequent local SASL connection through
           * bounce_setup_local_alias (it falls back to creating a
           * parallel primary or treating the connection as a regular
           * user).  register_user's BS A emit site at s_user.c only
           * fires when register_user itself created the session — for
           * sessions created here (post-registration via BOUNCER SET
           * HOLD on), we must emit BS A explicitly. */
          bounce_broadcast(session, 'A', cli_yxx(sptr));

          send_note(sptr, "BOUNCER", "SESSION_CREATED", session->hs_sessid,
                    "Hold mode enabled, session created");
        } else {
          send_note(sptr, "BOUNCER", "SETTINGS_UPDATED", NULL,
                    "Hold mode enabled (session limit reached)");
        }
      } else {
        send_note(sptr, "BOUNCER", "SETTINGS_UPDATED", NULL,
                  "Hold mode enabled");
      }
    } else if (0 == ircd_strcmp(parv[3], "off")) {
      metadata_set_client(sptr, "bouncer/hold", "0", METADATA_VIS_PRIVATE);
      /* Propagate "off" to peers — see comment in the "on" branch
       * above.  Without this, peers retain a stale "1" preference. */
      sendcmdto_serv_butone_v3(&me, CMD_METADATA, NULL, "%s %s P :0",
                            cli_name(sptr), "bouncer/hold");

      /* Fix #24: Active teardown — user no longer wants bouncer behavior.
       * Destroy the session (disconnects all aliases) so the primary
       * continues as a normal non-bounced IRC client. */
      {
        struct BouncerSession *session = bounce_get_session(sptr);
        if (session) {
          /* Detach primary before destroy so exit_one_client doesn't
           * try to clean up a destroyed session later. */
          session->hs_client = NULL;
          bounce_broadcast(session, 'X', NULL);
          bounce_destroy(session);
        }
      }

      send_note(sptr, "BOUNCER", "SETTINGS_UPDATED", NULL,
                "Hold mode disabled");
    } else {
      send_fail(sptr, "BOUNCER", "NEED_PARAM", "SET",
                "Value must be 'on' or 'off'");
    }
    return 0;
  }

  if (0 == ircd_strcmp(parv[2], "SESSION")) {
    /* Per-session override */
    struct AccountSessions *as;
    struct BouncerSession *s;

    if (parc < 6) {
      send_fail(sptr, "BOUNCER", "NEED_PARAM", "SET",
                "Usage: BOUNCER SET SESSION <id> HOLD on|off");
      return 0;
    }

    as = bounce_find_by_account(cli_account(sptr));
    if (!as)
      goto notfound;

    for (s = as->as_sessions; s; s = s->hs_anext) {
      if (0 == strcmp(s->hs_sessid, parv[3])) {
        if (0 == ircd_strcmp(parv[5], "on"))
          s->hs_hold_override = 1;
        else if (0 == ircd_strcmp(parv[5], "off"))
          s->hs_hold_override = 0;
        else {
          send_fail(sptr, "BOUNCER", "NEED_PARAM", "SET",
                    "Value must be 'on' or 'off'");
          return 0;
        }
        send_note(sptr, "BOUNCER", "SETTINGS_UPDATED", parv[3],
                  "Session preference updated");
        return 0;
      }
    }

notfound:
    send_fail(sptr, "BOUNCER", "NO_SUCH_SESSION", parv[3],
              "No such session");
    return 0;
  }

  send_fail(sptr, "BOUNCER", "NEED_PARAM", "SET",
            "Unknown setting");
  return 0;
}

/* ---------------------------------------------------------------- */
/* Subcommand: SETTINGS                                              */
/* ---------------------------------------------------------------- */

/** Handle BOUNCER SETTINGS - show current preferences. */
static int bouncer_settings(struct Client *sptr)
{
  int hold;
  int count;
  const char *hold_src = "default";

  if (!IsAccount(sptr)) {
    send_fail(sptr, "BOUNCER", "ACCOUNT_REQUIRED", NULL,
              "You must be logged in to use bouncer features");
    return 0;
  }

  /* Check hold preference — read from persistent (mdbx) store */
  if (IsBncHoldPref(sptr)) {
    hold = 1;
    hold_src = "mode";
  } else {
    char hold_val[64];
    if (metadata_account_get(cli_account(sptr), "bouncer/hold", hold_val) == 0) {
      hold = (hold_val[0] == '1') ? 1 : 0;
      hold_src = "account";
    } else {
      /* Bouncer class defaults to hold; normal class follows feature flag */
      struct ConnectionClass *cls = get_client_class_conf(sptr);
      if (cls && FlagHas(&cls->restrictflags, CRFLAG_BOUNCER)) {
        hold = 1;
        hold_src = "class";
      } else {
        hold = feature_bool(FEAT_BOUNCER_DEFAULT_HOLD);
      }
    }
  }

  count = bounce_count(cli_account(sptr));

  sendrawto_one(sptr, ":%s %d %s :hold=%s(%s) sessions=%d max=%d hold_time=%d",
                cli_name(&me), RPL_BOUNCERSETTINGS, cli_name(sptr),
                hold ? "on" : "off", hold_src,
                count,
                feature_int(FEAT_BOUNCER_MAX_SESSIONS),
                feature_int(FEAT_BOUNCER_SESSION_HOLD));

  return 0;
}

/* ---------------------------------------------------------------- */
/* Subcommand: INFO                                                  */
/* ---------------------------------------------------------------- */

/** Handle BOUNCER LISTCLIENTS - list all connections for the session.
 * Shows primary + alias connections with client IDs, away state,
 * connect time, and IP address.
 *
 * Reply format uses NOTE:
 *   :server NOTE BOUNCER CLIENT id=N type=primary|alias state=present|away since=TIMESTAMP ip=ADDR
 *   :server NOTE BOUNCER LISTCLIENTS_END :End of client list
 */
static int bouncer_listclients(struct Client *sptr)
{
  struct BouncerSession *session;
  const char *state_str;
  char info[512];
  int i;
  int count;

  if (!IsAccount(sptr)) {
    send_fail(sptr, "BOUNCER", "ACCOUNT_REQUIRED", "LISTCLIENTS",
              "You must be logged in to use bouncer features");
    return 0;
  }

  session = bounce_get_session(sptr);
  if (!session) {
    send_fail(sptr, "BOUNCER", "NO_SESSION", "LISTCLIENTS",
              "No active bouncer session");
    return 0;
  }

  count = 0;

  /* Primary connection */
  if (session->hs_client && session->hs_state == BOUNCE_ACTIVE) {
    int away_state = 0;
    if (cli_user(session->hs_client)->away) {
      away_state = 1;
    }
    state_str = away_state ? "away" : "present";
    ircd_snprintf(0, info, sizeof(info),
                  "type=primary state=%s since=%lu ip=%s",
                  state_str,
                  (unsigned long)cli_firsttime(session->hs_client),
                  cli_sock_ip(session->hs_client));
    send_note(sptr, "BOUNCER", "CLIENT", session->hs_sessid, info);
    count++;
  }

  /* Alias connections */
  for (i = 0; i < session->hs_alias_count; i++) {
    struct Client *alias = findNUser(session->hs_aliases[i].ba_numeric);
    if (!alias)
      continue;
    state_str = (cli_user(alias) && cli_user(alias)->away) ? "away" : "present";
    ircd_snprintf(0, info, sizeof(info),
                  "id=%d type=alias state=%s since=%lu ip=%s server=%s",
                  i + 1,
                  state_str,
                  (unsigned long)cli_firsttime(alias),
                  cli_sock_ip(alias),
                  session->hs_aliases[i].ba_server);
    send_note(sptr, "BOUNCER", "CLIENT", session->hs_sessid, info);
    count++;
  }

  {
    char end_msg[128];
    ircd_snprintf(0, end_msg, sizeof(end_msg),
                  "End of client list (%d connections)",
                  count);
    send_note(sptr, "BOUNCER", "LISTCLIENTS_END", session->hs_sessid, end_msg);
  }

  return 0;
}

/* ---------------------------------------------------------------- */

/** Handle BOUNCER INFO - show session state and preferences.
 * Combines session status and hold preferences in a single view.
 * This is the primary user-facing read-only command.
 */
static int bouncer_info(struct Client *sptr)
{
  struct AccountSessions *as;
  struct BouncerSession *s;
  int hold;
  const char *hold_src = "default";

  if (!IsAccount(sptr)) {
    send_fail(sptr, "BOUNCER", "ACCOUNT_REQUIRED", NULL,
              "You must be logged in to use bouncer features");
    return 0;
  }

  /* Determine hold preference — read from persistent (mdbx) store,
   * not cli_metadata which may not be populated after a restart. */
  if (IsBncHoldPref(sptr)) {
    hold = 1;
    hold_src = "account";
  } else {
    char hold_val[64];
    if (metadata_account_get(cli_account(sptr), "bouncer/hold", hold_val) == 0) {
      hold = (hold_val[0] == '1') ? 1 : 0;
      hold_src = "account";
    } else {
      /* Bouncer class defaults to hold; normal class follows feature flag */
      struct ConnectionClass *cls = get_client_class_conf(sptr);
      if (cls && FlagHas(&cls->restrictflags, CRFLAG_BOUNCER)) {
        hold = 1;
        hold_src = "class";
      } else {
        hold = feature_bool(FEAT_BOUNCER_DEFAULT_HOLD);
      }
    }
  }

  as = bounce_find_by_account(cli_account(sptr));

  /* Session state */
  if (as && as->as_count > 0) {
    s = as->as_sessions;
    if (s) {
      const char *state_str = (s->hs_state == BOUNCE_ACTIVE)
                              ? "active" : "holding";
      char info[512];

      if (s->hs_state == BOUNCE_HOLDING && s->hs_disconnect_time) {
        time_t hold_time = bounce_compute_hold_time_ext(s);
        time_t remaining = hold_time -
                           (CurrentTime - s->hs_disconnect_time);
        if (remaining < 0)
          remaining = 0;
        ircd_snprintf(0, info, sizeof(info),
                      "state=%s hold=%s(%s) connects=%u "
                      "hold_time=%ldm session=%s",
                      state_str,
                      hold ? "on" : "off", hold_src,
                      s->hs_connect_count,
                      (long)(remaining / 60),
                      s->hs_sessid);
      } else {
        time_t hold_time = bounce_compute_hold_time_ext(s);
        ircd_snprintf(0, info, sizeof(info),
                      "state=%s hold=%s(%s) connects=%u "
                      "hold_time=%lds live=%d session=%s",
                      state_str,
                      hold ? "on" : "off", hold_src,
                      s->hs_connect_count,
                      (long)hold_time,
                      bounce_connection_count(s),
                      s->hs_sessid);
      }

      sendrawto_one(sptr, ":%s %d %s :%s",
                    cli_name(&me), RPL_BOUNCERSETTINGS, cli_name(sptr),
                    info);
    }
  } else {
    /* No session */
    char info[256];
    ircd_snprintf(0, info, sizeof(info),
                  "state=none hold=%s(%s)",
                  hold ? "on" : "off", hold_src);
    sendrawto_one(sptr, ":%s %d %s :%s",
                  cli_name(&me), RPL_BOUNCERSETTINGS, cli_name(sptr),
                  info);
  }

  return 0;
}

/* ---------------------------------------------------------------- */
/* Subcommand: HISTORY                                               */
/* ---------------------------------------------------------------- */

/** Handle BOUNCER HISTORY - show connection history for the session.
 * Available to the session owner and opers.
 *
 * Reply format uses NOTE:
 *   :server NOTE BOUNCER CONN_HISTORY sessid :ip=ADDR host=HOST connects=N last_connect=TS last_disconnect=TS
 *   :server NOTE BOUNCER HISTORY_END sessid :End of connection history
 */
static int bouncer_history(struct Client *sptr, int parc, char *parv[])
{
  struct BouncerSession *session = NULL;
  int i;
  char info[512];

  if (!IsAccount(sptr)) {
    send_fail(sptr, "BOUNCER", "ACCOUNT_REQUIRED", "HISTORY",
              "You must be logged in to use bouncer features");
    return 0;
  }

  /* Opers can specify a nick as parv[2] to view another user's history */
  if (parc >= 3 && (IsOper(sptr) || IsAnOper(sptr))) {
    struct Client *target = FindUser(parv[2]);
    if (!target) {
      send_fail(sptr, "BOUNCER", "NO_SUCH_NICK", parv[2],
                "No such nick");
      return 0;
    }
    session = bounce_get_session(target);
    if (!session && IsAccount(target)) {
      struct AccountSessions *as = bounce_find_by_account(cli_account(target));
      if (as && as->as_sessions)
        session = as->as_sessions;
    }
    if (!session) {
      send_fail(sptr, "BOUNCER", "NO_SESSION", parv[2],
                "No bouncer session for that user");
      return 0;
    }
  } else {
    /* Find own session */
    session = bounce_get_session(sptr);
    if (!session) {
      /* Check if we have a HOLDING session for this account */
      struct AccountSessions *as = bounce_find_by_account(cli_account(sptr));
      if (as && as->as_sessions)
        session = as->as_sessions;
    }
    if (!session) {
      send_fail(sptr, "BOUNCER", "NO_SESSION", "HISTORY",
                "No active bouncer session");
      return 0;
    }
  }

  for (i = 0; i < session->hs_histcount; i++) {
    struct BounceConnHistory *h = &session->hs_history[i];
    if (h->bch_last_disconnect) {
      ircd_snprintf(0, info, sizeof(info),
                    "ip=%s host=%s connects=%u last_connect=%lu last_disconnect=%lu",
                    h->bch_ip, h->bch_host, h->bch_count,
                    (unsigned long)h->bch_last_connect,
                    (unsigned long)h->bch_last_disconnect);
    } else {
      ircd_snprintf(0, info, sizeof(info),
                    "ip=%s host=%s connects=%u last_connect=%lu status=connected",
                    h->bch_ip, h->bch_host, h->bch_count,
                    (unsigned long)h->bch_last_connect);
    }
    send_note(sptr, "BOUNCER", "CONN_HISTORY", session->hs_sessid, info);
  }

  if (session->hs_histcount == 0) {
    send_note(sptr, "BOUNCER", "HISTORY_END", session->hs_sessid,
              "No connection history");
  } else {
    ircd_snprintf(0, info, sizeof(info),
                  "End of connection history (%d hosts)",
                  session->hs_histcount);
    send_note(sptr, "BOUNCER", "HISTORY_END", session->hs_sessid, info);
  }

  return 0;
}

/* ---------------------------------------------------------------- */
/* Subcommand: HELP                                                  */
/* ---------------------------------------------------------------- */

/** One row of help text. */
struct BouncerHelpRow {
  const char *name;       /* Subcommand name */
  const char *args;       /* Argument syntax (or "" for none) */
  const char *desc;       /* One-line description */
  int oper_only;          /* Non-zero if only opers may call */
};

static const struct BouncerHelpRow bouncer_help_rows[] = {
  /* User-facing */
  { "HELP",         "[subcommand]",
    "Show this help (or detail for one subcommand)",                0 },
  { "INFO",         "",
    "Show your session state, hold preference, and stats",          0 },
  { "SET",          "HOLD on|off|default",
    "Configure session hold preference",                            0 },
  { "LISTCLIENTS",  "",
    "List the primary and aliases attached to your session",        0 },
  { "HISTORY",      "[sessid]",
    "Show connection history for your session",                     0 },
  { "RESET",        "[sessid]",
    "Destroy session and exit all attached connections (force reconnect)", 0 },

  /* Oper-only */
  { "TOKEN",        "",
    "Create a new session and return its resume token",             1 },
  { "RESUME",       "<token>",
    "Resume a session by its token",                                1 },
  { "LISTSESSIONS", "[*|all]",
    "List sessions; \"*\" lists every session on this server",      1 },
  { "STATUS",       "",
    "Server-wide accounting audit (UserStats vs walker counts)",    1 },
  { "DISCONNECT",   "<sessid>",
    "Destroy a session by its ID",                                  1 },
  { "ORESET",       "<account> [sessid]",
    "Force-reset another account's session and exit all attached",  1 },
  { "SETNAME",      "<sessid> <name>",
    "Assign a friendly name to a session",                          1 },
  { "SETTINGS",     "",
    "Show bouncer subsystem settings",                              1 },
};

/** Handle BOUNCER HELP [subcommand]. */
static int bouncer_help(struct Client *sptr, int parc, char *parv[])
{
  unsigned int i;
  int is_oper = (IsOper(sptr) || IsAnOper(sptr));
  const char *target = (parc >= 3 && parv[2] && *parv[2]) ? parv[2] : NULL;
  char line[256];

  if (target) {
    for (i = 0; i < sizeof(bouncer_help_rows)/sizeof(bouncer_help_rows[0]);
         i++) {
      const struct BouncerHelpRow *r = &bouncer_help_rows[i];
      if (0 != ircd_strcmp(target, r->name))
        continue;
      if (r->oper_only && !is_oper)
        break;  /* fall through to "not known" path */
      ircd_snprintf(0, line, sizeof(line), "BOUNCER %s %s",
                    r->name, r->args);
      send_note(sptr, "BOUNCER", "HELP", r->name, line);
      send_note(sptr, "BOUNCER", "HELP", r->name, r->desc);
      if (r->oper_only)
        send_note(sptr, "BOUNCER", "HELP", r->name, "(oper-only)");
      send_note(sptr, "BOUNCER", "HELP_END", r->name,
                "End of subcommand help");
      return 0;
    }
    send_note(sptr, "BOUNCER", "HELP", target,
              "Unknown subcommand");
    send_note(sptr, "BOUNCER", "HELP_END", target,
              "End of subcommand help");
    return 0;
  }

  send_note(sptr, "BOUNCER", "HELP", "*",
            "Bouncer subcommands (use BOUNCER HELP <name> for detail)");

  for (i = 0; i < sizeof(bouncer_help_rows)/sizeof(bouncer_help_rows[0]);
       i++) {
    const struct BouncerHelpRow *r = &bouncer_help_rows[i];
    if (r->oper_only && !is_oper)
      continue;
    ircd_snprintf(0, line, sizeof(line), "%-13s %-22s %s%s",
                  r->name, r->args, r->desc,
                  r->oper_only ? "  [oper]" : "");
    send_note(sptr, "BOUNCER", "HELP", "*", line);
  }

  send_note(sptr, "BOUNCER", "HELP_END", "*", "End of help");
  return 0;
}

/* ---------------------------------------------------------------- */
/* Main command handler                                              */
/* ---------------------------------------------------------------- */

/** Handle BOUNCER command from a local client.
 *
 * User commands: HELP, INFO, SET, LISTCLIENTS, HISTORY
 * Oper-only: TOKEN, RESUME, LISTSESSIONS, STATUS, DISCONNECT, SETNAME,
 *            SETTINGS
 *
 * @param[in] cptr Connected client.
 * @param[in] sptr Source client.
 * @param[in] parc Number of parameters.
 * @param[in] parv Parameters.
 * @return 0 on success.
 */
int m_bouncer(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  const char *subcmd;

  if (!bounce_enabled_for(sptr)) {
    send_fail(sptr, "BOUNCER", "DISABLED", NULL,
              "Bouncer feature is not enabled");
    return 0;
  }

  if (parc < 2) {
    send_fail(sptr, "BOUNCER", "NEED_PARAM", NULL,
              "Usage: BOUNCER <subcommand> [args]");
    return 0;
  }

  subcmd = parv[1];

  /* --- User-facing commands --- */

  if (0 == ircd_strcmp(subcmd, "HELP"))
    return bouncer_help(sptr, parc, parv);

  if (0 == ircd_strcmp(subcmd, "SET"))
    return bouncer_set(sptr, parc, parv);

  if (0 == ircd_strcmp(subcmd, "INFO"))
    return bouncer_info(sptr);

  if (0 == ircd_strcmp(subcmd, "LISTCLIENTS"))
    return bouncer_listclients(sptr);

  if (0 == ircd_strcmp(subcmd, "HISTORY"))
    return bouncer_history(sptr, parc, parv);

  if (0 == ircd_strcmp(subcmd, "RESET"))
    return bouncer_reset(cptr, sptr, (parc >= 3) ? parv[2] : NULL);

  /* --- Oper-only commands (admin/testing) --- */

  if (0 == ircd_strcmp(subcmd, "TOKEN")) {
    if (!IsOper(sptr) && !IsAnOper(sptr)) {
      send_fail(sptr, "BOUNCER", "NOPRIVS", "TOKEN",
                "Insufficient privileges");
      return 0;
    }
    return bouncer_token(sptr);
  }

  if (0 == ircd_strcmp(subcmd, "RESUME")) {
    if (!IsOper(sptr) && !IsAnOper(sptr)) {
      send_fail(sptr, "BOUNCER", "NOPRIVS", "RESUME",
                "Insufficient privileges");
      return 0;
    }
    if (parc < 3) {
      send_fail(sptr, "BOUNCER", "NEED_PARAM", "RESUME",
                "Missing token");
      return 0;
    }
    return bouncer_resume(sptr, parv[2]);
  }

  if (0 == ircd_strcmp(subcmd, "LISTSESSIONS")) {
    if (!IsOper(sptr) && !IsAnOper(sptr)) {
      send_fail(sptr, "BOUNCER", "NOPRIVS", "LISTSESSIONS",
                "Insufficient privileges");
      return 0;
    }
    return bouncer_listsessions(sptr, parc, parv);
  }

  if (0 == ircd_strcmp(subcmd, "STATUS")) {
    if (!IsOper(sptr) && !IsAnOper(sptr)) {
      send_fail(sptr, "BOUNCER", "NOPRIVS", "STATUS",
                "Insufficient privileges");
      return 0;
    }
    return bouncer_status(sptr);
  }

  if (0 == ircd_strcmp(subcmd, "DISCONNECT")) {
    if (!IsOper(sptr) && !IsAnOper(sptr)) {
      send_fail(sptr, "BOUNCER", "NOPRIVS", "DISCONNECT",
                "Insufficient privileges");
      return 0;
    }
    return bouncer_disconnect(sptr, (parc >= 3) ? parv[2] : NULL);
  }

  if (0 == ircd_strcmp(subcmd, "ORESET")) {
    if (!IsOper(sptr) && !IsAnOper(sptr)) {
      send_fail(sptr, "BOUNCER", "NOPRIVS", "ORESET",
                "Insufficient privileges");
      return 0;
    }
    return bouncer_oreset(cptr, sptr,
                          (parc >= 3) ? parv[2] : NULL,
                          (parc >= 4) ? parv[3] : NULL);
  }

  if (0 == ircd_strcmp(subcmd, "SETNAME")) {
    if (!IsOper(sptr) && !IsAnOper(sptr)) {
      send_fail(sptr, "BOUNCER", "NOPRIVS", "SETNAME",
                "Insufficient privileges");
      return 0;
    }
    return bouncer_setname(sptr,
                           (parc >= 3) ? parv[2] : NULL,
                           (parc >= 4) ? parv[3] : NULL);
  }

  if (0 == ircd_strcmp(subcmd, "SETTINGS")) {
    if (!IsOper(sptr) && !IsAnOper(sptr)) {
      send_fail(sptr, "BOUNCER", "NOPRIVS", "SETTINGS",
                "Insufficient privileges");
      return 0;
    }
    return bouncer_settings(sptr);
  }

  send_fail(sptr, "BOUNCER", "NEED_PARAM", NULL,
            "Unknown subcommand");
  return 0;
}

/* ---------------------------------------------------------------- */
/* S2S handler for BS token                                          */
/* ---------------------------------------------------------------- */

/** Handle BS (Bouncer Session) P10 token from server.
 * Delegates to bounce_handle_bs() in bouncer_session.c.
 */
int ms_bouncer_session(struct Client *cptr, struct Client *sptr,
                       int parc, char *parv[])
{
  return bounce_handle_bs(cptr, sptr, parc, parv);
}

/* ---------------------------------------------------------------- */
/* S2S handler for BT token                                          */
/* ---------------------------------------------------------------- */

/** Handle BT (Bouncer Transfer) P10 token from server.
 * Delegates to bounce_handle_bt() in bouncer_session.c.
 */
int ms_bouncer_transfer(struct Client *cptr, struct Client *sptr,
                        int parc, char *parv[])
{
  return bounce_handle_bt(cptr, sptr, parc, parv);
}
