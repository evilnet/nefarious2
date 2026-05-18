/*
 * IRC - Internet Relay Chat, ircd/m_persistence.c
 * Copyright (C) 2026 Nefarious Development Team
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
 */
/** @file
 * @brief Handler for PERSISTENCE command (IRCv3 draft/persistence).
 *
 * Specification: https://github.com/ircv3/ircv3-specifications/pull/503
 *
 * Phase 1 subcommands:
 *   STATUS                  - query effective hold state
 *   GET                     - alias for STATUS (per draft)
 *   SET ON|OFF|DEFAULT      - set the persistence preference
 *
 * Reply form:
 *   :<server> PERSISTENCE STATUS ON|OFF
 *   :<server> PERSISTENCE SET ON|OFF|DEFAULT
 *
 * Storage is the existing `draft/persistence/hold` metadata key (PRIVATE):
 *   ON      -> draft/persistence/hold = "1"
 *   OFF     -> draft/persistence/hold = "0"
 *   DEFAULT -> key deleted; falls back to FEAT_BOUNCER_DEFAULT_HOLD
 *
 * The `bouncer/` prefix is registered as server-managed (see
 * metadata.c::metadata_key_is_server_managed) so client-initiated
 * METADATA SET on this key is refused; PERSISTENCE is the supported
 * interface.
 */
#include "config.h"

#include "client.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "metadata.h"
#include "msg.h"
#include "numeric.h"
#include "s_user.h"
#include "send.h"
#include "bouncer_session.h"
#include "persistence_profile.h"

#include <string.h>

/** Resolve the connection's active profile name.
 * Falls back to PERSISTENCE_PROFILE_DEFAULT when the connection didn't
 * explicitly ATTACH.  Returns a pointer to either the stashed name on
 * the Connection or the constant "default" — never NULL.
 */
static const char *active_profile_for(struct Client *cptr)
{
  if (!cptr || !cli_connect(cptr))
    return PERSISTENCE_PROFILE_DEFAULT;
  {
    const char *p = cli_active_profile(cptr);
    if (p && p[0])
      return p;
  }
  return PERSISTENCE_PROFILE_DEFAULT;
}

/** Compute the effective persistence state for a client.
 * Resolution order (most-specific first), per the Phase 4 design:
 *   1. Active profile's `hold` (walks parent chain through default)
 *   2. Account-global `draft/persistence/hold` (the `PERSISTENCE SET` target)
 *   3. FEAT_BOUNCER_DEFAULT_HOLD
 * @return 1 if persistence is effectively ON, 0 if OFF.
 */
static int persistence_effective_state(struct Client *cptr)
{
  char hold_val[METADATA_VALUE_LEN];

  if (!cptr || !IsAccount(cptr))
    return 0;

  if (persistence_profile_get_effective(cli_account(cptr),
                                         active_profile_for(cptr),
                                         "hold",
                                         hold_val, sizeof(hold_val)) == 0)
    return (hold_val[0] != '0');

  if (metadata_account_get(cli_account(cptr), "draft/persistence/hold", hold_val) == 0)
    return (hold_val[0] != '0');

  return feature_bool(FEAT_BOUNCER_DEFAULT_HOLD) ? 1 : 0;
}

/** Resolve auto-replay state for a client.
 * Resolution chain (most-specific first):
 *   1. Active profile's `auto-replay` (walks parent chain)
 *   2. Account-global `draft/persistence/auto-replay`
 *   3. FEAT_BOUNCER_AUTO_REPLAY
 * Values: "0" / "off" = OFF; anything else (including absent) =
 * default to FEAT_*.  Empty string treated as absent.
 * @return 1 if auto-replay effectively ON, 0 if OFF.
 */
static int persistence_effective_replay(struct Client *cptr)
{
  char val[METADATA_VALUE_LEN];

  if (!cptr || !IsAccount(cptr))
    return 0;

  if (persistence_profile_get_effective(cli_account(cptr),
                                         active_profile_for(cptr),
                                         "auto-replay",
                                         val, sizeof(val)) == 0
      && val[0])
    return (val[0] != '0');

  if (metadata_account_get(cli_account(cptr), "draft/persistence/auto-replay", val) == 0
      && val[0])
    return (val[0] != '0');

  return feature_bool(FEAT_BOUNCER_AUTO_REPLAY) ? 1 : 0;
}

/** Render the effective state as the wire keyword. */
static const char *persistence_state_keyword(struct Client *cptr)
{
  return persistence_effective_state(cptr) ? "ON" : "OFF";
}

/** Emit a server-originated PERSISTENCE reply on the wire.
 *
 * Wire form: `:<server> PERSISTENCE <what> <state>`
 *
 * Uses sendrawto_one because PERSISTENCE has no S2S token registered
 * in msg.h yet — Phase 1 is client-facing only.
 */
static void send_persistence_reply(struct Client *to, const char *what,
                                   const char *state)
{
  if (!to || !MyConnect(to))
    return;
  sendrawto_one(to, ":%s PERSISTENCE %s %s",
                cli_name(&me), what, state);
}

/** Public accessor for the resolved auto-replay state.  Used by
 * replay_start_bouncer call sites in s_user.c and bouncer_session.c
 * to gate the missed-message replay batch.
 */
int persistence_replay_enabled_for(struct Client *cptr)
{
  return persistence_effective_replay(cptr);
}

/** Send `:server PERSISTENCE STATUS ON|OFF` to a client.
 * Public — also called from registration (s_user.c) to emit the
 * unsolicited STATUS once the client has negotiated draft/persistence.
 */
void persistence_send_status(struct Client *to)
{
  if (!to || !MyConnect(to))
    return;
  send_persistence_reply(to, "STATUS", persistence_state_keyword(to));
}

/** Handle STATUS / GET subcommand.  Both report the effective state. */
static int persistence_cmd_status(struct Client *sptr)
{
  if (!IsAccount(sptr)) {
    send_fail(sptr, "PERSISTENCE", "ACCOUNT_REQUIRED", "STATUS",
              "You must be authenticated to use PERSISTENCE");
    return 0;
  }
  persistence_send_status(sptr);
  return 0;
}

/** Handle SET subcommand.
 * `PERSISTENCE SET ON|OFF|DEFAULT`
 *
 * ON / OFF: write `draft/persistence/hold` metadata via the same path as
 * `BOUNCER SET HOLD on/off` in m_bouncer.c (metadata_set_client +
 * explicit S2S broadcast).  ON also auto-creates a session if the
 * client doesn't already own one; OFF tears the session down.
 *
 * DEFAULT: delete the metadata key (locally and on peers).  The
 * session is left untouched — the user has reverted to "follow
 * server default", which the registration-time logic will honour on
 * the next reconnect.
 */
static int persistence_cmd_set(struct Client *sptr, int parc, char *parv[])
{
  const char *arg;

  if (!IsAccount(sptr)) {
    send_fail(sptr, "PERSISTENCE", "ACCOUNT_REQUIRED", "SET",
              "You must be authenticated to use PERSISTENCE");
    return 0;
  }

  if (parc < 3) {
    send_fail(sptr, "PERSISTENCE", "INVALID_PARAMETERS", "SET",
              "SET requires ON, OFF, or DEFAULT");
    return 0;
  }

  arg = parv[2];

  if (0 == ircd_strcmp(arg, "ON")) {
    metadata_set_client(sptr, "draft/persistence/hold", "1", METADATA_VIS_PRIVATE);
    sendcmdto_serv_butone_v3(&me, CMD_METADATA, NULL, "%s %s P :1",
                             cli_name(sptr), "draft/persistence/hold");

    if (!bounce_get_session(sptr)) {
      struct BouncerSession *session = NULL;
      if (bounce_create(sptr, &session) == 0 && session) {
        bounce_broadcast(session, 'C', NULL);
        bounce_broadcast(session, 'A', cli_yxx(sptr));
      }
    }
    send_persistence_reply(sptr, "SET", "ON");
    persistence_send_status(sptr);
    return 0;
  }

  if (0 == ircd_strcmp(arg, "OFF")) {
    metadata_set_client(sptr, "draft/persistence/hold", "0", METADATA_VIS_PRIVATE);
    sendcmdto_serv_butone_v3(&me, CMD_METADATA, NULL, "%s %s P :0",
                             cli_name(sptr), "draft/persistence/hold");

    {
      struct BouncerSession *session = bounce_get_session(sptr);
      if (session) {
        session->hs_client = NULL;
        bounce_broadcast(session, 'X', NULL);
        bounce_destroy(session);
      }
    }
    send_persistence_reply(sptr, "SET", "OFF");
    persistence_send_status(sptr);
    return 0;
  }

  if (0 == ircd_strcmp(arg, "DEFAULT")) {
    metadata_set_client(sptr, "draft/persistence/hold", NULL, METADATA_VIS_PRIVATE);
    sendcmdto_serv_butone_v3(&me, CMD_METADATA, NULL, "%s %s",
                             cli_name(sptr), "draft/persistence/hold");
    send_persistence_reply(sptr, "SET", "DEFAULT");
    persistence_send_status(sptr);
    return 0;
  }

  send_fail_ctx(sptr, "PERSISTENCE", "INVALID_PARAMETERS",
                "SET argument must be ON, OFF, or DEFAULT",
                "SET %s", arg);
  return 0;
}

/* ---- PROFILE subcommand (Phase 4 / M1) ---- */

struct persistence_list_ctx {
  struct Client *to;
  int count;
};

static void persistence_list_cb(const char *name, const char *parent, void *cookie)
{
  struct persistence_list_ctx *ctx = (struct persistence_list_ctx *)cookie;
  if (parent && parent[0])
    sendrawto_one(ctx->to, ":%s PERSISTENCE PROFILE %s parent=%s",
                  cli_name(&me), name, parent);
  else
    sendrawto_one(ctx->to, ":%s PERSISTENCE PROFILE %s",
                  cli_name(&me), name);
  ctx->count++;
}

static int persistence_cmd_profile_list(struct Client *sptr)
{
  struct persistence_list_ctx ctx;
  ctx.to = sptr;
  ctx.count = 0;
  if (persistence_profile_list(cli_account(sptr),
                                persistence_list_cb, &ctx) < 0) {
    send_fail(sptr, "PERSISTENCE", "INTERNAL_ERROR", "PROFILE LIST",
              "Failed to enumerate profiles");
    return 0;
  }
  sendrawto_one(sptr, ":%s PERSISTENCE PROFILE ENDOFLIST",
                cli_name(&me));
  return 0;
}

static int persistence_cmd_profile_create(struct Client *sptr,
                                           int parc, char *parv[])
{
  const char *name;
  const char *parent = NULL;

  if (parc < 4) {
    send_fail(sptr, "PERSISTENCE", "INVALID_PARAMETERS", "PROFILE CREATE",
              "Usage: PROFILE CREATE <name> [FROM <parent>]");
    return 0;
  }
  name = parv[3];
  if (parc >= 6 && ircd_strcmp(parv[4], "FROM") == 0)
    parent = parv[5];

  if (!persistence_profile_name_valid(name)
      || 0 == ircd_strcmp(name, PERSISTENCE_PROFILE_DEFAULT)) {
    send_fail_ctx(sptr, "PERSISTENCE", "INVALID_PARAMETERS",
                  "Invalid profile name", "PROFILE CREATE %s", name);
    return 0;
  }
  if (parent && !persistence_profile_name_valid(parent)) {
    send_fail_ctx(sptr, "PERSISTENCE", "INVALID_PARAMETERS",
                  "Invalid parent profile name",
                  "PROFILE CREATE %s FROM %s", name, parent);
    return 0;
  }
  if (persistence_profile_create(cli_account(sptr), name, parent) < 0) {
    send_fail_ctx(sptr, "PERSISTENCE", "INTERNAL_ERROR",
                  "Profile create failed (already exists, invalid parent, or storage error)",
                  "PROFILE CREATE %s", name);
    return 0;
  }
  sendrawto_one(sptr, ":%s PERSISTENCE PROFILE CREATED %s parent=%s",
                cli_name(&me), name,
                (parent && parent[0]) ? parent : PERSISTENCE_PROFILE_DEFAULT);
  return 0;
}

static int persistence_cmd_profile_delete(struct Client *sptr,
                                           int parc, char *parv[])
{
  const char *name;

  if (parc < 4) {
    send_fail(sptr, "PERSISTENCE", "INVALID_PARAMETERS", "PROFILE DELETE",
              "Usage: PROFILE DELETE <name>");
    return 0;
  }
  name = parv[3];
  if (!persistence_profile_name_valid(name)) {
    send_fail_ctx(sptr, "PERSISTENCE", "INVALID_PARAMETERS",
                  "Invalid profile name", "PROFILE DELETE %s", name);
    return 0;
  }
  if (0 == ircd_strcmp(name, PERSISTENCE_PROFILE_DEFAULT)) {
    send_fail_ctx(sptr, "PERSISTENCE", "INVALID_PARAMETERS",
                  "Cannot delete the implicit default profile",
                  "PROFILE DELETE %s", name);
    return 0;
  }
  if (persistence_profile_delete(cli_account(sptr), name) < 0) {
    send_fail_ctx(sptr, "PERSISTENCE", "INTERNAL_ERROR",
                  "Profile delete failed (default, not found, or has children)",
                  "PROFILE DELETE %s", name);
    return 0;
  }
  sendrawto_one(sptr, ":%s PERSISTENCE PROFILE DELETED %s",
                cli_name(&me), name);
  return 0;
}

static int persistence_cmd_profile_rename(struct Client *sptr,
                                           int parc, char *parv[])
{
  const char *old_name;
  const char *new_name;

  if (parc < 5) {
    send_fail(sptr, "PERSISTENCE", "INVALID_PARAMETERS", "PROFILE RENAME",
              "Usage: PROFILE RENAME <old> <new>");
    return 0;
  }
  old_name = parv[3];
  new_name = parv[4];
  if (!persistence_profile_name_valid(old_name)
      || !persistence_profile_name_valid(new_name)) {
    send_fail_ctx(sptr, "PERSISTENCE", "INVALID_PARAMETERS",
                  "Invalid profile name",
                  "PROFILE RENAME %s %s", old_name, new_name);
    return 0;
  }
  if (0 == ircd_strcmp(old_name, PERSISTENCE_PROFILE_DEFAULT)
      || 0 == ircd_strcmp(new_name, PERSISTENCE_PROFILE_DEFAULT)) {
    send_fail_ctx(sptr, "PERSISTENCE", "INVALID_PARAMETERS",
                  "The default profile cannot be renamed",
                  "PROFILE RENAME %s %s", old_name, new_name);
    return 0;
  }
  if (persistence_profile_rename(cli_account(sptr), old_name, new_name) < 0) {
    send_fail_ctx(sptr, "PERSISTENCE", "INTERNAL_ERROR",
                  "Profile rename failed",
                  "PROFILE RENAME %s %s", old_name, new_name);
    return 0;
  }
  sendrawto_one(sptr, ":%s PERSISTENCE PROFILE RENAMED %s %s",
                cli_name(&me), old_name, new_name);
  return 0;
}

static int persistence_cmd_profile_get(struct Client *sptr,
                                        int parc, char *parv[])
{
  const char *name;
  const char *key;
  char value[METADATA_VALUE_LEN];
  int rc;

  if (parc < 5) {
    send_fail(sptr, "PERSISTENCE", "INVALID_PARAMETERS", "PROFILE GET",
              "Usage: PROFILE GET <name> <key>");
    return 0;
  }
  name = parv[3];
  key = parv[4];
  if (!persistence_profile_name_valid(name)) {
    send_fail_ctx(sptr, "PERSISTENCE", "INVALID_PARAMETERS",
                  "Invalid profile name", "PROFILE GET %s %s", name, key);
    return 0;
  }
  if (!persistence_profile_exists(cli_account(sptr), name)) {
    send_fail_ctx(sptr, "PERSISTENCE", "INVALID_PARAMETERS",
                  "No such profile", "PROFILE GET %s %s", name, key);
    return 0;
  }
  /* `channels` is a set-merge key under M5 — return the effective
   * channel list (parent inheritance applied, `-chan` subtracts
   * honoured).  All other keys use normal shadow-resolve through
   * the parent chain. */
  if (0 == ircd_strcmp(key, "channels")) {
    if (persistence_profile_channels_effective(cli_account(sptr), name,
                                                value, sizeof(value)) < 0) {
      send_fail_ctx(sptr, "PERSISTENCE", "INTERNAL_ERROR",
                    "Profile channels lookup failed",
                    "PROFILE GET %s %s", name, key);
      return 0;
    }
    if (value[0])
      sendrawto_one(sptr, ":%s PERSISTENCE PROFILE %s %s :%s",
                    cli_name(&me), name, key, value);
    else
      sendrawto_one(sptr, ":%s PERSISTENCE PROFILE %s %s",
                    cli_name(&me), name, key);
    return 0;
  }

  rc = persistence_profile_get_effective(cli_account(sptr), name, key,
                                          value, sizeof(value));
  if (rc < 0) {
    send_fail_ctx(sptr, "PERSISTENCE", "INTERNAL_ERROR",
                  "Profile lookup failed",
                  "PROFILE GET %s %s", name, key);
    return 0;
  }
  if (rc == 0)
    sendrawto_one(sptr, ":%s PERSISTENCE PROFILE %s %s :%s",
                  cli_name(&me), name, key, value);
  else
    sendrawto_one(sptr, ":%s PERSISTENCE PROFILE %s %s",
                  cli_name(&me), name, key);
  return 0;
}

static int persistence_cmd_profile_set(struct Client *sptr,
                                        int parc, char *parv[])
{
  const char *name;
  const char *key;
  const char *value = NULL;

  if (parc < 6) {
    send_fail(sptr, "PERSISTENCE", "INVALID_PARAMETERS", "PROFILE SET",
              "Usage: PROFILE SET <name> <key> <value>|DEFAULT");
    return 0;
  }
  name = parv[3];
  key = parv[4];
  if (0 == ircd_strcmp(parv[5], "DEFAULT"))
    value = NULL;
  else
    value = parv[5];

  if (!persistence_profile_name_valid(name)) {
    send_fail_ctx(sptr, "PERSISTENCE", "INVALID_PARAMETERS",
                  "Invalid profile name",
                  "PROFILE SET %s %s", name, key);
    return 0;
  }
  if (!persistence_profile_exists(cli_account(sptr), name)) {
    send_fail_ctx(sptr, "PERSISTENCE", "INVALID_PARAMETERS",
                  "No such profile (CREATE first)",
                  "PROFILE SET %s %s", name, key);
    return 0;
  }

  /* Special-case the `channels` key — set operations (+#x / -#x) and
   * DEFAULT (clear), not whole-value replacement. */
  if (0 == ircd_strcmp(key, "channels")) {
    int rc;
    if (value == NULL) {
      rc = persistence_profile_channels_clear(cli_account(sptr), name);
    } else if (value[0] == '+') {
      rc = persistence_profile_channels_add(cli_account(sptr), name,
                                             value + 1);
    } else if (value[0] == '-') {
      rc = persistence_profile_channels_remove(cli_account(sptr), name,
                                                value + 1);
    } else {
      send_fail_ctx(sptr, "PERSISTENCE", "INVALID_PARAMETERS",
                    "channels value must be +<channel>, -<channel>, "
                    "or DEFAULT",
                    "PROFILE SET %s channels %s", name, value);
      return 0;
    }
    if (rc < 0) {
      send_fail_ctx(sptr, "PERSISTENCE", "INTERNAL_ERROR",
                    "Profile channels edit failed",
                    "PROFILE SET %s channels %s",
                    name, value ? value : "DEFAULT");
      return 0;
    }
    if (value)
      sendrawto_one(sptr, ":%s PERSISTENCE PROFILE %s channels %s",
                    cli_name(&me), name, value);
    else
      sendrawto_one(sptr, ":%s PERSISTENCE PROFILE %s channels",
                    cli_name(&me), name);
    return 0;
  }

  if (persistence_profile_set(cli_account(sptr), name, key, value) < 0) {
    send_fail_ctx(sptr, "PERSISTENCE", "INTERNAL_ERROR",
                  "Profile set failed (cycle, invalid value, or storage error)",
                  "PROFILE SET %s %s", name, key);
    return 0;
  }
  if (value)
    sendrawto_one(sptr, ":%s PERSISTENCE PROFILE %s %s :%s",
                  cli_name(&me), name, key, value);
  else
    sendrawto_one(sptr, ":%s PERSISTENCE PROFILE %s %s",
                  cli_name(&me), name, key);
  return 0;
}

/** Resolve the account name for this client's pending or current
 * authentication.  Pre-CAP-END, FLAG_ACCOUNT isn't set yet (only
 * SASLComplete) — but cli_saslaccount holds the authenticated name.
 * Returns NULL if the client isn't authenticated at all.
 */
static const char *persistence_account_for(struct Client *sptr)
{
  if (!sptr)
    return NULL;
  if (IsAccount(sptr) && cli_user(sptr) && cli_account(sptr)[0])
    return cli_account(sptr);
  if (IsSASLComplete(sptr) && cli_saslaccount(sptr)[0])
    return cli_saslaccount(sptr);
  return NULL;
}

/** Resolve the user's explicitly-set client-setting for auto-replay
 * (the value before FEAT_* fallthrough).  Returns "ON" / "OFF" /
 * "DEFAULT" into `out`.
 */
static void persistence_replay_client_setting(struct Client *cptr,
                                               char *out, size_t out_len)
{
  char val[METADATA_VALUE_LEN];

  if (persistence_profile_get_effective(cli_account(cptr),
                                         active_profile_for(cptr),
                                         "auto-replay",
                                         val, sizeof(val)) == 0
      && val[0]) {
    ircd_strncpy(out, val[0] != '0' ? "ON" : "OFF", out_len);
    return;
  }
  if (metadata_account_get(cli_account(cptr), "draft/persistence/auto-replay", val) == 0
      && val[0]) {
    ircd_strncpy(out, val[0] != '0' ? "ON" : "OFF", out_len);
    return;
  }
  ircd_strncpy(out, "DEFAULT", out_len);
}

/** Emit the REPLAY STATUS line with both client-setting and resolved
 * effective state.  Wire form:
 *   :srv PERSISTENCE REPLAY STATUS <CLIENT> <EFFECTIVE>
 * where <CLIENT> is ON|OFF|DEFAULT and <EFFECTIVE> is ON|OFF.
 */
static void persistence_send_replay_status(struct Client *to)
{
  char client_setting[16];
  const char *eff;
  if (!to || !MyConnect(to) || !IsAccount(to))
    return;
  persistence_replay_client_setting(to, client_setting, sizeof(client_setting));
  eff = persistence_effective_replay(to) ? "ON" : "OFF";
  sendrawto_one(to, ":%s PERSISTENCE REPLAY STATUS %s %s",
                cli_name(&me), client_setting, eff);
}

/** Handle PERSISTENCE REPLAY {GET|SET ON|OFF|DEFAULT}. */
static int persistence_cmd_replay(struct Client *sptr, int parc, char *parv[])
{
  const char *sub;

  if (!IsAccount(sptr)) {
    send_fail(sptr, "PERSISTENCE", "ACCOUNT_REQUIRED", "REPLAY",
              "You must be authenticated to use PERSISTENCE REPLAY");
    return 0;
  }
  if (parc < 3) {
    send_fail(sptr, "PERSISTENCE", "INVALID_PARAMETERS", "REPLAY",
              "REPLAY requires GET or SET");
    return 0;
  }
  sub = parv[2];

  if (0 == ircd_strcmp(sub, "GET")) {
    persistence_send_replay_status(sptr);
    return 0;
  }

  if (0 == ircd_strcmp(sub, "SET")) {
    const char *arg;
    if (parc < 4) {
      send_fail(sptr, "PERSISTENCE", "INVALID_PARAMETERS", "REPLAY SET",
                "REPLAY SET requires ON, OFF, or DEFAULT");
      return 0;
    }
    arg = parv[3];
    if (0 == ircd_strcmp(arg, "ON")) {
      metadata_set_client(sptr, "draft/persistence/auto-replay", "1",
                          METADATA_VIS_PRIVATE);
      sendcmdto_serv_butone_v3(&me, CMD_METADATA, NULL, "%s %s P :1",
                               cli_name(sptr), "draft/persistence/auto-replay");
    } else if (0 == ircd_strcmp(arg, "OFF")) {
      metadata_set_client(sptr, "draft/persistence/auto-replay", "0",
                          METADATA_VIS_PRIVATE);
      sendcmdto_serv_butone_v3(&me, CMD_METADATA, NULL, "%s %s P :0",
                               cli_name(sptr), "draft/persistence/auto-replay");
    } else if (0 == ircd_strcmp(arg, "DEFAULT")) {
      metadata_set_client(sptr, "draft/persistence/auto-replay", NULL,
                          METADATA_VIS_PRIVATE);
      sendcmdto_serv_butone_v3(&me, CMD_METADATA, NULL, "%s %s",
                               cli_name(sptr), "draft/persistence/auto-replay");
    } else {
      send_fail_ctx(sptr, "PERSISTENCE", "INVALID_PARAMETERS",
                    "REPLAY SET argument must be ON, OFF, or DEFAULT",
                    "REPLAY SET %s", arg);
      return 0;
    }
    send_persistence_reply(sptr, "REPLAY SET", arg);
    persistence_send_replay_status(sptr);
    return 0;
  }

  send_fail_ctx(sptr, "PERSISTENCE", "INVALID_PARAMETERS",
                "Unknown REPLAY subcommand", "REPLAY %s", sub);
  return 0;
}

/** Handle PERSISTENCE ATTACH <profile> — pin the active profile for
 * this connection.  Only valid during registration (between SASL
 * success and CAP END / first NICK+USER); refused once the client is
 * fully registered (Q1 — no mid-session profile swap for v1).
 */
static int persistence_cmd_attach(struct Client *sptr, int parc, char *parv[])
{
  const char *name;
  const char *account;

  if (IsUser(sptr)) {
    send_fail(sptr, "PERSISTENCE", "INVALID_PARAMETERS", "ATTACH",
              "PERSISTENCE ATTACH is only valid during registration");
    return 0;
  }
  account = persistence_account_for(sptr);
  if (!account) {
    send_fail(sptr, "PERSISTENCE", "ACCOUNT_REQUIRED", "ATTACH",
              "You must SASL-authenticate before PERSISTENCE ATTACH");
    return 0;
  }
  if (parc < 3) {
    send_fail(sptr, "PERSISTENCE", "INVALID_PARAMETERS", "ATTACH",
              "Usage: PERSISTENCE ATTACH <profile>");
    return 0;
  }
  name = parv[2];
  if (!persistence_profile_name_valid(name)) {
    send_fail_ctx(sptr, "PERSISTENCE", "INVALID_PARAMETERS",
                  "Invalid profile name", "ATTACH %s", name);
    return 0;
  }
  if (!persistence_profile_exists(account, name)) {
    send_fail_ctx(sptr, "PERSISTENCE", "INVALID_PARAMETERS",
                  "No such profile", "ATTACH %s", name);
    return 0;
  }
  ircd_strncpy(cli_active_profile(sptr), name,
               sizeof(con_active_profile(cli_connect(sptr))));
  send_persistence_reply(sptr, "ATTACH", name);
  return 0;
}

static int persistence_cmd_profile(struct Client *sptr, int parc, char *parv[])
{
  const char *sub;

  if (!IsAccount(sptr)) {
    send_fail(sptr, "PERSISTENCE", "ACCOUNT_REQUIRED", "PROFILE",
              "You must be authenticated to manage profiles");
    return 0;
  }
  if (parc < 3) {
    send_fail(sptr, "PERSISTENCE", "INVALID_PARAMETERS", "PROFILE",
              "PROFILE requires a sub-subcommand "
              "(LIST|CREATE|DELETE|RENAME|GET|SET)");
    return 0;
  }
  sub = parv[2];

  if (0 == ircd_strcmp(sub, "LIST"))
    return persistence_cmd_profile_list(sptr);
  if (0 == ircd_strcmp(sub, "CREATE"))
    return persistence_cmd_profile_create(sptr, parc, parv);
  if (0 == ircd_strcmp(sub, "DELETE"))
    return persistence_cmd_profile_delete(sptr, parc, parv);
  if (0 == ircd_strcmp(sub, "RENAME"))
    return persistence_cmd_profile_rename(sptr, parc, parv);
  if (0 == ircd_strcmp(sub, "GET"))
    return persistence_cmd_profile_get(sptr, parc, parv);
  if (0 == ircd_strcmp(sub, "SET"))
    return persistence_cmd_profile_set(sptr, parc, parv);

  send_fail_ctx(sptr, "PERSISTENCE", "INVALID_PARAMETERS",
                "Unknown PROFILE sub-subcommand",
                "PROFILE %s", sub);
  return 0;
}

/** Handle PERSISTENCE DETACH — disconnect the session from this
 * account so the caller proceeds as a normal non-persistent client.
 *
 * Refused with FAIL CANNOT_DETACH when `hs_enforced` is set (the
 * connecting class has CRFLAG_BOUNCER — the user cannot opt out of
 * a class-enforced session).
 *
 * On success: destroys the bouncer session (which exits all aliases
 * and drops the held state); clears the caller's STATUS so subsequent
 * connections see hold=OFF until the user opts back in.
 */
static int persistence_cmd_detach(struct Client *sptr, int parc, char *parv[])
{
  struct BouncerSession *session;

  if (!IsAccount(sptr)) {
    send_fail(sptr, "PERSISTENCE", "ACCOUNT_REQUIRED", "DETACH",
              "You must be authenticated to use PERSISTENCE DETACH");
    return 0;
  }
  (void)parc; (void)parv;  /* Phase 3 v1 ignores the optional <session-id> arg —
                            * one identity per account, only one session. */

  session = bounce_get_session(sptr);
  if (!session) {
    send_persistence_reply(sptr, "DETACH", "NOSESSION");
    return 0;
  }

  if (session->hs_enforced) {
    send_fail(sptr, "PERSISTENCE", "CANNOT_DETACH", "DETACH",
              "Connection class enforces persistence; cannot detach");
    return 0;
  }

  /* Mirror PERSISTENCE SET OFF's tear-down: clear account-global hold
   * preference, broadcast to peers, then destroy the session. */
  metadata_set_client(sptr, "draft/persistence/hold", "0", METADATA_VIS_PRIVATE);
  sendcmdto_serv_butone_v3(&me, CMD_METADATA, NULL, "%s %s P :0",
                           cli_name(sptr), "draft/persistence/hold");

  /* Detach our primary from the session before destroy so
   * exit_one_client cleanup doesn't try to operate on a destroyed
   * session later (matches the SET OFF path). */
  session->hs_client = NULL;
  bounce_broadcast(session, 'X', NULL);
  bounce_destroy(session);

  send_persistence_reply(sptr, "DETACH", "OK");
  /* STATUS now resolves to OFF (no session, hold=0). */
  persistence_send_status(sptr);
  return 0;
}

/** Top-level dispatch for the PERSISTENCE command (registered users).
 * @param[in] cptr Connection that sent the command.
 * @param[in] sptr Source of the command.
 * @param[in] parc Argument count (parv[0] is command name).
 * @param[in] parv Argument vector.
 */
int m_persistence(struct Client *cptr, struct Client *sptr,
                  int parc, char *parv[])
{
  const char *sub;

  if (parc < 2) {
    send_fail(sptr, "PERSISTENCE", "INVALID_PARAMETERS", NULL,
              "PERSISTENCE requires a subcommand");
    return 0;
  }

  sub = parv[1];

  if (0 == ircd_strcmp(sub, "STATUS") || 0 == ircd_strcmp(sub, "GET"))
    return persistence_cmd_status(sptr);

  if (0 == ircd_strcmp(sub, "SET"))
    return persistence_cmd_set(sptr, parc, parv);

  if (0 == ircd_strcmp(sub, "PROFILE"))
    return persistence_cmd_profile(sptr, parc, parv);

  if (0 == ircd_strcmp(sub, "ATTACH"))
    return persistence_cmd_attach(sptr, parc, parv);

  if (0 == ircd_strcmp(sub, "REPLAY"))
    return persistence_cmd_replay(sptr, parc, parv);

  if (0 == ircd_strcmp(sub, "DETACH"))
    return persistence_cmd_detach(sptr, parc, parv);

  send_fail_ctx(sptr, "PERSISTENCE", "INVALID_PARAMETERS",
                "Unknown PERSISTENCE subcommand",
                "%s", sub);
  return 0;
}
