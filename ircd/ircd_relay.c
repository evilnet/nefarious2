/*
 * IRC - Internet Relay Chat, ircd/ircd_relay.c
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
 *
 * See file AUTHORS in IRC package for additional names of
 * the programmers.
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
 * @brief Helper functions to relay various types of messages.
 * @version $Id: ircd_relay.c 1913 2009-07-04 22:46:00Z entrope $
 *
 * There are four basic types of messages, each with four subtypes.
 *
 * The basic types are: channel, directed, masked, and private.
 * Channel messages are (perhaps obviously) sent directly to a
 * channel.  Directed messages are sent to "NICK[%host]@server", but
 * only allowed if the server is a services server (to avoid
 * information leaks for normal clients).  Masked messages are sent to
 * either *@*host.mask or *.server.mask.  Private messages are sent to
 * NICK.
 *
 * The subtypes for each type are: client message, client notice,
 * server message, and server notice.  Client subtypes are sent by a
 * local user, and server subtypes are given to us by a server.
 * Notice subtypes correspond to the NOTICE command, and message
 * subtypes correspond to the PRIVMSG command.
 *
 * As a special note, directed messages do not have server subtypes,
 * since there is no difference in handling them based on origin.
 */
#include "config.h"

#include "ircd_relay.h"
#include "capab.h"
#include "channel.h"
#include "chathistory_ephemeral.h"
#include "client.h"
#include "hash.h"
#include "history.h"
#include "history_trim_codec.h"
#include "ircd.h"
#include "ircd_chattr.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "match.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_debug.h"
#include "s_misc.h"
#include "s_user.h"
#include "send.h"
#include "metadata.h"
#include "handlers.h"
#include "bouncer_session.h"
#include "forwarded_label.h"
#include "webpush.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

/*
 * This file contains message relaying functions for client and server
 * private messages and notices
 * TODO: This file contains a lot of cut and paste code, and needs
 * to be cleaned up a bit. The idea is to factor out the common checks
 * but not introduce any IsOper/IsUser/MyUser/IsServer etc. stuff.
 */

/**
 * Check and optionally sanitize text for UTF-8 validity (UTF8ONLY enforcement).
 *
 * When UTF8ONLY is enabled:
 * - In strict mode: sends FAIL INVALID_UTF8 and returns 0 (reject message)
 * - In warn mode: sanitizes text, sends WARN INVALID_UTF8, returns 1 (proceed)
 *
 * When UTF8ONLY is disabled, always returns 1.
 *
 * @param[in] sptr Client sending the message.
 * @param[in,out] text Message text (may be modified in warn mode).
 * @param[in] command Command name for standard reply (e.g., "PRIVMSG").
 * @return 1 if message should proceed (possibly modified), 0 if rejected.
 */
static int check_utf8_text(struct Client *sptr, char *text, const char *command)
{
  if (!feature_bool(FEAT_UTF8ONLY))
    return 1;

  if (string_is_valid_utf8(text))
    return 1;

  /* Invalid UTF-8 detected */
  if (feature_bool(FEAT_UTF8ONLY_STRICT)) {
    /* Strict mode: reject the message */
    send_fail(sptr, command, "INVALID_UTF8", NULL,
              "Message contains invalid UTF-8 and was rejected");
    return 0;
  }

  /* Warn mode: sanitize and proceed */
  string_sanitize_utf8(text);
  send_warn(sptr, command, "INVALID_UTF8", NULL,
            "Message contained invalid UTF-8 and was sanitized");
  return 1;
}

/** Length of the longest "nick!user@host" a message from @a sptr is
 * shown with, to anyone.  Every client-side prefix is the same three
 * strings (no recipient sees a different host for the same source:
 * ircd_snprintf's %#C takes cli_user()->host whoever the destination),
 * but a bouncer alias's message goes to most recipients under its
 * primary (relay_*_message rewrite the source) and to the sender's own
 * echo under the alias; the two share the primary's face, and the
 * longer is taken in case they ever differ.  Other servers show the
 * same source to their clients: they expand the numeric to the
 * nick!user@host they were told, which is ours. */
static size_t relay_source_len(struct Client *sptr)
{
  struct Client *faces[2];
  size_t best = 0;
  int i, n = 0;

  faces[n++] = sptr;
  if (IsBouncerAlias(sptr) && cli_user(sptr)->alias_primary)
    faces[n++] = cli_user(sptr)->alias_primary;

  for (i = 0; i < n; i++) {
    size_t len;

    if (!cli_user(faces[i]))
      continue;
    /* The relay's prefixes (%#C) show cli_user()->host; the multiline
     * paths show get_displayed_host() (m_batch.c), the real host while
     * the user is not hidden.  They are the same string except for an
     * alias whose face is its primary's while its own real host differs,
     * so the longer counts -- never a hidden user's real host, whose
     * length nobody else is shown. */
    len = ircd_relay_face_len(cli_name(faces[i]),
                              cli_user(faces[i])->username,
                              cli_user(faces[i])->host,
                              IsHiddenHost(faces[i]) ? NULL
                              : cli_user(faces[i])->realhost);
    if (len > best)
      best = len;
  }
  return best;
}

/** Bytes of text a message from @a sptr can carry when every recipient
 * receives it as
 *   ":" <nick!user@host> " " <cmd> " " <target> " :" [<lead>] <text>
 * within 510 bytes after the tags.  That client form is the binding one:
 * the P10 form toward servers (5-character numeric source, 1-letter
 * token) is always shorter, and the far server re-expands it to the
 * same client form for its own clients, legacy servers included.
 *
 * @param[in] sptr        The local user the message comes from.
 * @param[in] cmd         The command its recipients see (MSG_PRIVATE,
 *                        MSG_NOTICE -- WALLCHOPS goes out as NOTICE).
 * @param[in] target_len  Length of the target as shown: the channel's
 *                        own name, the recipient's current nick, a
 *                        statusmsg "@#chan", a $mask or nick@server as
 *                        written.
 * @param[in] lead_len    Bytes the relay puts ahead of the text in the
 *                        trailing parameter (WALLCHOPS' "@ "), else 0.
 * @return The text bytes that fit, or 0 when nothing does.
 */
size_t relay_text_budget(struct Client *sptr, const char *cmd,
                         size_t target_len, size_t lead_len)
{
  size_t room = ircd_relay_text_room(relay_source_len(sptr), strlen(cmd),
                                     target_len, BUFSIZE - 2);

  return room > lead_len ? room - lead_len : 0;
}

/** Cut a local user's message text once, at its origin, to what its
 * relayed form can carry (relay_text_budget), at a UTF-8 boundary.  The
 * cut text is then the message: what is delivered here, echoed to the
 * sender, relayed to other servers, stored in history and pushed --
 * so no recipient-side cut fires later, and live and replay agree.
 *
 * @param[in] sptr        The local user the message comes from.
 * @param[in] cmd         See relay_text_budget().
 * @param[in] target_len  See relay_text_budget().
 * @param[in] lead_len    See relay_text_budget().
 * @param[in] text        The text as the user sent it.
 * @param[out] buf        Room for the cut text when it is cut.
 * @param[in] bufsize     Size of @a buf (BUFSIZE is always enough: a cut
 *                        text is at most 510 bytes).
 * @return @a text when it fits; else @a buf holding its cut copy, which
 *         is empty when the line leaves no room for any text (the
 *         caller refuses the message: an empty PRIVMSG is no message).
 */
const char *relay_cut_text(struct Client *sptr, const char *cmd,
                           size_t target_len, size_t lead_len,
                           const char *text, char *buf, size_t bufsize)
{
  return relay_cut_to(text, relay_text_budget(sptr, cmd, target_len, lead_len),
                      buf, bufsize);
}

/** Cut @a text to at most @a room bytes at a UTF-8 boundary
 * (ircd_utf8_cut_len, the msgq backstop's own cut).
 * @return @a text when it fits, else @a buf holding the cut copy. */
const char *relay_cut_to(const char *text, size_t room, char *buf,
                         size_t bufsize)
{
  size_t len = strlen(text);
  size_t keep;

  assert(bufsize > 0);
  if (len <= room)
    return text;
  if (room > bufsize - 1)
    room = bufsize - 1;
  keep = ircd_utf8_cut_len(text, len, room);
  memcpy(buf, text, keep);
  buf[keep] = '\0';
  return buf;
}

/** Does a DM from @a sptr reach other devices of its bouncer session (a
 * session echo, BX E / BX M toward another server)? */
static int relay_has_session_devices(struct Client *sptr)
{
  struct Client *primary = (IsBouncerAlias(sptr) && cli_user(sptr)->alias_primary)
                           ? cli_user(sptr)->alias_primary : sptr;
  struct BouncerSession *sess;

  if (!IsAccount(primary) || !(sess = bounce_get_session(primary)))
    return 0;
  return sess->hs_alias_count > 0;
}

/** Bytes of text a DM from @a sptr to @a acptr can carry: the client
 * line's room (relay_text_budget), and, when the sender's session has
 * other devices, the room the session echo's BX frame leaves
 * (ircd_bx_echo_text_room) -- a device on another server gets the DM in
 * that frame, which the S2S cut would otherwise shorten, so it would read
 * less than the echo here.  The frame binds only for a short source
 * (under ~27 bytes for BX E, ~45 for a BX M first line).
 * @param[in] msgid_len Length of the DM's msgid (0: none, "*" goes out).
 * @param[in] ctags_len Length of the client-only tags a BX M first line
 *                      carries (multiline), else 0.
 * @param[in] multiline Non-zero for a multiline batch's lines. */
size_t relay_dm_text_budget(struct Client *sptr, const char *cmd,
                            struct Client *acptr, size_t msgid_len,
                            size_t ctags_len, int multiline)
{
  size_t nick_len = strlen(cli_name(acptr));
  size_t room = relay_text_budget(sptr, cmd, nick_len, 0);

  if (relay_has_session_devices(sptr)) {
    size_t bx = ircd_bx_echo_text_room(nick_len, msgid_len ? msgid_len : 1,
                                       ctags_len, multiline, BUFSIZE - 2);
    if (bx < room)
      room = bx;
  }
  return room;
}

/* Effective DM-history identity: account when authenticated, else the
 * per-connection session id.  NEVER the nick — a nick is reusable and
 * keying on it lets a later holder read the prior holder's DM history
 * (F-CH1).  cli_session_id is always populated from make_client
 * (list.c:247) so the unauth branch never yields "".
 *
 * Declared unconditionally in ircd_relay.h and called unconditionally
 * from replay.c / m_chathistory.c / chathistory_ephemeral.c (none of
 * which are USE_ROCKSDB-guarded — the ephemeral ring in particular is
 * explicitly the non-RocksDB storage path), so the definition must
 * live outside the USE_ROCKSDB block below or a non-RocksDB build
 * link-fails. */
static const char *pm_effective_identity(struct Client *cli)
{
  if (IsAccount(cli) && cli_user(cli) && cli_user(cli)->account[0])
    return cli_user(cli)->account;
  return cli_session_id(cli);
}

void history_pm_identity(struct Client *cli, char *buf, size_t buflen)
{
  ircd_strncpy(buf, pm_effective_identity(cli), buflen);
}

/* Match the caller's SINGLE effective identity against one pair-key half.
 * No nick fallback (that reopens F-CH1). */
int history_pm_identity_matches(struct Client *cli, const char *half, size_t half_len)
{
  const char *id = pm_effective_identity(cli);
  return strlen(id) == half_len && ircd_strncmp(id, half, half_len) == 0;
}

#ifdef USE_ROCKSDB
/** Write-forward a channel message to a store (CH W/WB), on a server with
 * no store of its own (CHATHISTORY_STORE off, CHATHISTORY_WRITE_FORWARD
 * on); a no-op on a store.  Called AHEAD of the message's own relay: on the
 * link to the store the order is then [CH W M][M], so a store downstream of
 * this server holds M before it relays M on toward a redactor.  That is a
 * best effort, not an invariant: a message this server relays reaches its
 * store (often its uplink) after passing it, and a REDACT through that
 * store can get there before the CH W.  A store therefore keeps a REDACT
 * of a message it does not hold as a tombstone (redact_apply_row), which
 * hides M when the CH W stores it late.  The CH W line leaves the relay's
 * armed S2S tags alone (ch_write_line).
 * @param[in] sptr Client that sent the message.
 * @param[in] chptr Target channel.
 * @param[in] text Message content.
 * @param[in] type Message type (HISTORY_PRIVMSG or HISTORY_NOTICE).
 * @param[in] msgid Message ID (the relay's).
 * @param[in] timestamp The message's time (the relay's).
 * @param[in] client_tags Client-only tags, or NULL.
 */
static void forward_channel_history(struct Client *sptr, struct Channel *chptr,
                                    const char *text, enum HistoryMessageType type,
                                    const char *msgid, const char *timestamp,
                                    const char *client_tags)
{
  /* history_forward_encode sentinel-escapes the payload and brackets the
   * client tags in \x06 so the storage server can split them back out
   * (process_write_forward) without raw client bytes ever reading as
   * structure. */
  char tagged_content[(512 + 512) * 2 + 3];

  if (!history_is_available() || feature_bool(FEAT_CHATHISTORY_STORE)
      || !feature_bool(FEAT_CHATHISTORY_WRITE_FORWARD))
    return;
  history_forward_encode(tagged_content, sizeof(tagged_content),
                         client_tags, text);
  forward_history_write(chptr, sptr, msgid, timestamp, type, tagged_content);
}

/** Store a channel message in the history database.
 * Stores the message with the provided msgid and timestamp.
 * @param[in] sptr Client that sent the message.
 * @param[in] chptr Target channel.
 * @param[in] text Message content.
 * @param[in] type Message type (HISTORY_PRIVMSG or HISTORY_NOTICE).
 * @param[in] msgid Message ID (same one sent to clients via echo-message).
 * @param[in] timestamp ISO 8601 timestamp.
 */
static void store_channel_history(struct Client *sptr, struct Channel *chptr,
                                   const char *text, enum HistoryMessageType type,
                                   const char *msgid, const char *timestamp,
                                   const char *client_tags)
{
  char sender[HISTORY_SENDER_LEN];
  char owner[HTC_OWNER_MAX];
  const char *account;

  /* WebPush v2: channel-highlight pushes for held members.  PRIVMSG
   * only (channel NOTICEs are bot noise by design); before the history
   * gates so pushes don't depend on chathistory storage. */
  if (type == HISTORY_PRIVMSG)
    webpush_notify_channel(sptr, chptr, text, msgid, timestamp);

  if (!history_is_available())
    return;

  /* No store here: the write-forward went ahead of the relay
   * (forward_channel_history). */
  if (!feature_bool(FEAT_CHATHISTORY_STORE))
    return;

  /* The storage gate every channel row passes (channel_store_wanted, W5
   * Task 13): a local sender's message is ours; a remote one is stored
   * only while a member of ours (non-zombie, MyConnect) is in the channel,
   * so a hub stores nothing for a channel it only relays toward others.
   * A remote alias membership (a device on another server, mirrored here)
   * is not interest: that device's own server stores the row.  And with
   * CHATHISTORY_REQUIRE_AUTH on, a channel with no authenticated member
   * that is not +H stores nothing: no unauthenticated client can ever
   * query it, so the rows would be dead bytes (the delivered msgid still
   * resolves to its mint time intrinsically, 2026-09 repack; no anchor
   * row is needed).  A store with no member here is kept by CH W from a
   * storeless server instead (process_write_forward, not gated). */
  if (!channel_store_wanted(chptr, MyUser(sptr)))
    return;

  /* Build sender string: nick!user@host */
  if (cli_user(sptr))
    ircd_snprintf(0, sender, sizeof(sender), "%s!%s@%s",
                  cli_name(sptr),
                  cli_user(sptr)->username,
                  cli_user(sptr)->host);
  else
    ircd_strncpy(sender, cli_name(sptr), sizeof(sender) - 1);

  /* Get account name if logged in */
  account = (cli_user(sptr) && cli_user(sptr)->account[0])
            ? cli_user(sptr)->account : NULL;
  /* The rows' trim owner: the sender whose account they carry. */
  history_owner_of(owner, sizeof(owner), sptr);

  /* Check if channel has +P (no storage) mode */
  if (chptr->mode.exmode & EXMODE_NOSTORAGE)
    return;

  /* Check if sender has +Y (no storage) user mode — store gap marker */
  if (IsNoStorage(sptr)) {
    history_store_message(msgid, timestamp, chptr->chname, NULL, sender,
                          account, HISTORY_GAP, "", NULL, owner);
    return;
  }

  /* Check if this is a new channel for Layer 1 advertisement */
  int is_new_channel = (history_has_channel(chptr->chname) == 0);

  /* Store in database */
  if (history_store_message(msgid, timestamp, chptr->chname, NULL, sender,
                            account, type, text, client_tags, owner) == 0) {
    /* Layer 1: Broadcast CH A + if this is the first message in the channel */
    if (is_new_channel) {
      broadcast_channel_advertisement(chptr->chname);
    }
  }
}

/** Check if client has opted out of PM history storage.
 * @param[in] cptr Client to check.
 * @return 1 if opted out, 0 otherwise.
 */
int has_pm_optout(struct Client *cptr)
{
  struct MetadataEntry *entry;

  if (!cptr || !IsUser(cptr))
    return 0;

  entry = metadata_get_client(cptr, "chathistory.pm");
  if (!entry)
    return 0;

  /* "0" or empty = opt-out */
  return (!entry->value || !entry->value[0] || entry->value[0] == '0');
}

/** Check if PM should be stored between two clients.
 * Both must be authenticated. Either can opt out via metadata or +y mode.
 * @param[in] sender Message sender.
 * @param[in] recipient Message recipient.
 * @return 1 if should store, 0 otherwise.
 */
static int should_store_pm(struct Client *sender, struct Client *recipient)
{
  /* At least one party must have an account.  LMDB persistence uses the
   * account as the anchor, so a fully-ephemeral pair has no durable
   * identity to key against — storage is skipped (a session-anchored
   * in-memory ring for ephemeral↔ephemeral PMs is on the deferred list).
   * Ephemeral↔account conversations are stored under the account's
   * anchor and remain queryable from both sides via the canonical
   * nick1:nick2 pair-key. */
  if (!IsAccount(sender) && !IsAccount(recipient))
    return 0;

  /* Check opt-out */
  if (has_pm_optout(sender) || has_pm_optout(recipient))
    return 0;

  return 1;
}

/** Store a private (DM) message in the history database.
 * Uses a consistent target format: sorted pair of nicks as "nick1:nick2".
 * @param[in] sptr Client that sent the message.
 * @param[in] acptr Target client.
 * @param[in] text Message content.
 * @param[in] type Message type (HISTORY_PRIVMSG or HISTORY_NOTICE).
 * @param[in] msgid Message ID (same one sent to clients via echo-message).
 * @param[in] timestamp ISO 8601 timestamp.
 */
void store_private_history(struct Client *sptr, struct Client *acptr,
                                   const char *text, enum HistoryMessageType type,
                                   const char *msgid, const char *timestamp,
                                   const char *client_tags)
{
  char sender[HISTORY_SENDER_LEN];
  char target[PM_PAIRKEY_BUFSIZE];  /* identity pair-key */
  char owner[HTC_OWNER_MAX];
  const char *account;
  const char *nick1, *nick2;

  /* WebPush v1 trigger: PM/NOTICE toward a held bouncer session.
   * Deliberately BEFORE the history feature gates -- push delivery
   * must not depend on chathistory storage being enabled.  All gating
   * (hold state, subscriptions, cooldown, FEAT) lives inside. */
  if (type != HISTORY_TAGMSG)
    webpush_notify_pm(sptr, acptr, text, type == HISTORY_NOTICE,
                      msgid, timestamp);

  /* Service traffic is not a conversation: AuthServ's "I recognize you"
   * and "X authed to your account" notices, and the user's own commands
   * to a bot (which can carry a password).  Storing them keyed the rows
   * on the bot's session id -- it has no account -- and put that id in
   * every user's CHATHISTORY TARGETS.  Servers likewise. */
  if (IsServer(sptr) || IsServer(acptr)
      || IsServiceClient(sptr) || IsServiceClient(acptr))
    return;

  if (!history_is_available())
    return;

  /* Check if chathistory storage is enabled */
  if (!feature_bool(FEAT_CHATHISTORY_STORE))
    return;

  /* Check if private message history is enabled (separate feature) */
  if (!feature_bool(FEAT_CHATHISTORY_PRIVATE))
    return;

  /* Opt-out check: honored regardless of which storage backend would
   * receive the message.  Previously this only gated the LMDB path
   * below — the ephemeral-ring path skipped past it and stored
   * unconditionally, leaking PMs that an opted-out party hadn't
   * consented to keep.  Now: if EITHER party opts out (chathistory.pm
   * = "0" or "" via metadata), drop storage entirely; for the LMDB
   * path we still write a gap marker so the conversation pair-key
   * has a presence-witness, but for the ephemeral path there's no
   * gap marker concept — we just don't store. */
  {
    int either_optout = has_pm_optout(sptr) || has_pm_optout(acptr);

    /* Fully-ephemeral pair: in-memory ring only.  Skip both opt-out
     * and the LMDB path. */
    if (!IsAccount(sptr) && !IsAccount(acptr)) {
      if (feature_bool(FEAT_CHATHISTORY_REQUIRE_AUTH))
        return;  /* nobody can query an account-less storage anyway */
      if (either_optout)
        return;  /* honor opt-out, ephemeral ring receives nothing */
      chathistory_ephemeral_store_pair(sptr, acptr, text, type, msgid,
                                        timestamp, client_tags);
      return;
    }
  }

  /* Build sender string: nick!user@host (needed for gap markers below) */
  if (cli_user(sptr))
    ircd_snprintf(0, sender, sizeof(sender), "%s!%s@%s",
                  cli_name(sptr),
                  cli_user(sptr)->username,
                  cli_user(sptr)->host);
  else
    ircd_strncpy(sender, cli_name(sptr), sizeof(sender) - 1);

  /* Build target as sorted pair for consistent lookups
   * Format: lowerNick:higherNick (case-insensitive comparison)
   */
  {
    char id_s[S2S_SESSID_BUFSIZE], id_a[S2S_SESSID_BUFSIZE];
    history_pm_identity(sptr,  id_s, sizeof(id_s));
    history_pm_identity(acptr, id_a, sizeof(id_a));
    if (ircd_strcmp(id_s, id_a) < 0) { nick1 = id_s; nick2 = id_a; }
    else                            { nick1 = id_a; nick2 = id_s; }
    ircd_snprintf(0, target, sizeof(target), "%s:%s", nick1, nick2);
  }

  /* Get account name if logged in */
  account = (cli_user(sptr) && cli_user(sptr)->account[0])
            ? cli_user(sptr)->account : NULL;
  /* The rows' trim owner: the sender whose account they carry. */
  history_owner_of(owner, sizeof(owner), sptr);

  /* Check opt-out — store gap marker if either party opted out
   * (LMDB path: at least one party authed, so we have an anchor for
   * the gap marker and a queryable party who can see it). */
  if (has_pm_optout(sptr) || has_pm_optout(acptr)) {
    history_store_message(msgid, timestamp, target, cli_name(acptr), sender,
                          account, HISTORY_GAP, "", NULL, owner);
    return;
  }

  /* Check +Y no-storage — store gap marker */
  if (IsNoStorage(sptr)) {
    history_store_message(msgid, timestamp, target, cli_name(acptr), sender,
                          account, HISTORY_GAP, "", NULL, owner);
    return;
  }

  /* If either party is ephemeral, embed their session_id as a vendor
   * tag so the chathistory query path can authorize the ephemeral
   * party's future history access (Phase 5a — sessid-based participant
   * check, see check_history_access's PM branch).  Without this tag
   * the record is queryable only by the authed counterparty; with it
   * the ephemeral can match their cli_session_id against the stored
   * tag to prove "I'm the same session as the one that participated."
   *
   * Stored as `+evilnet.github.io/sid=<sessid>` in client_tags
   * (evilnet = the upstream-org vendor namespace, same host as the
   * evilnet.github.io/bouncer-replay batch; records written before
   * 2026-08-29 carry the legacy `+afternet.org/sid=` form, which the
   * auth check still accepts).  Tag is server-injected and trusted:
   * `sid` (along with `ssid`/`rsid` below and `chathistory-gap`) is
   * one of the specific NAMES reserved under `+evilnet.github.io/`
   * at tag capture (parse.c drops a client-supplied tag matching one
   * of them via is_reserved_vendor_tag) -- the rest of that namespace
   * is an ordinary client-only tag now (Seance uses it), but `sid`
   * stays unforgeable.  `+afternet.org/` stays reserved whole
   * (legacy).  Either way, the client_tags appended below cannot
   * carry a forged sid marker and the auth check can rely on this
   * one. */
  {
    char tagbuf[800];
    char filtered_tags[800];
    size_t pos = 0;
    const char *eph_sessid = NULL;

    /* Defence in depth: scrub any reserved vendor tag already sitting
     * in the INCOMING client_tags -- e.g. relayed from another
     * server's S2S ',C' field, which never passes through parse.c's
     * capture-time gate the way a locally-submitted tag does -- before
     * layering this server's own sid/ssid/rsid on top below.  A buggy
     * or hostile fork peer forging one would otherwise sit right next
     * to (not instead of) our own legitimate marker in the stored
     * record. */
    if (client_tags && *client_tags)
      ircd_strip_reserved_vendor_tags(client_tags, filtered_tags, sizeof(filtered_tags));
    else
      filtered_tags[0] = '\0';

    if (!IsAccount(sptr) && cli_session_id(sptr)[0])
      eph_sessid = cli_session_id(sptr);
    else if (!IsAccount(acptr) && cli_session_id(acptr)[0])
      eph_sessid = cli_session_id(acptr);

    if (eph_sessid)
      pos += ircd_snprintf(0, tagbuf + pos, sizeof(tagbuf) - pos,
                           "+evilnet.github.io/sid=%s", eph_sessid);

    /* Both parties' session ids, beside the sender's account: a row is a
     * message from one SESSION to another, and the naming of the
     * conversation later may stand a live client in for a stored nick
     * only when it is the same session (a bouncer primary and its
     * aliases share the id), never merely the same account -- an account
     * can be online under several nicks at once.  Stripped on playback
     * (strip_internal_tags); `sid`/`ssid`/`rsid` are specific NAMES
     * reserved under `+evilnet.github.io/` at tag capture, so a LOCAL
     * client cannot forge them -- the filtering above covers the
     * remaining S2S case. */
    if (cli_session_id(sptr)[0])
      pos += ircd_snprintf(0, tagbuf + pos, sizeof(tagbuf) - pos,
                           "%s+evilnet.github.io/ssid=%s", pos ? ";" : "",
                           cli_session_id(sptr));
    if (cli_session_id(acptr)[0])
      pos += ircd_snprintf(0, tagbuf + pos, sizeof(tagbuf) - pos,
                           "%s+evilnet.github.io/rsid=%s", pos ? ";" : "",
                           cli_session_id(acptr));
    if (*filtered_tags)
      pos += ircd_snprintf(0, tagbuf + pos, sizeof(tagbuf) - pos,
                           "%s%s", pos ? ";" : "", filtered_tags);
    history_store_message(msgid, timestamp, target, cli_name(acptr), sender,
                          account, type, text, pos ? tagbuf : NULL,
                          owner);
  }
}

/** Store a DM that arrived from a server (server_relay_private_message,
 * _notice) -- unless it is a multiline fallback line passing through.
 *
 * A line carrying the fallback mark (,F<msgid>, parse_server) is one of
 * the single-line lines an originating server sent for multiline
 * message <msgid>, which that server stored whole under <msgid>.
 * Stored here as a PM of its own, a server it merely passes through
 * added the preview lines and the "[N more lines]" NOTICE to the pair's
 * history beside the message (a federated CHATHISTORY page showed them
 * as extra rows), and -- since line 1 carries <msgid> and the same time
 * -- a page answered from this store showed line 1 alone in place of
 * the message.  So a server the line passes through (the target is not
 * ours) stores nothing.  Nothing else keys on the row being stored: the
 * pair index, TARGETS, gap markers and the ephemeral ring are all behind
 * store_private_history, and so is its WebPush trigger, which pushes
 * only for a target of this server (webpush_pm_account) -- there, at the
 * target's server, it still fires, once.
 *
 * The target's own server stores the lines as before: they are what its
 * client saw (a fork server whose way fails the origin's ML test, e.g.
 * one with its multiline cap off).
 */
static void store_relayed_pm(struct Client *from, struct Client *acptr,
                             const char *text, enum HistoryMessageType type,
                             const char *msgid, const char *timestamp,
                             const char *client_tags, const char *fallback_of)
{
  if (fallback_of && fallback_of[0] && !MyConnect(acptr))
    return;
  store_private_history(from, acptr, text, type, msgid, timestamp,
                        client_tags);
}
#endif /* USE_ROCKSDB */

/** Relay a local user's message to a channel.
 * Generates an error if the client cannot send to the channel.
 * @param[in] sptr Client that originated the message.
 * @param[in] name Name of target channel.
 * @param[in] text %Message to relay.
 * @param[in] targets Number of targets for the initial PRIVMSG.
 */
void relay_channel_message(struct Client* sptr, const char* name, const char* text, int targets)
{
  struct Channel* chptr;
  const char* mytext = text;
  const char* ch;
  char utf8buf[BUFSIZE];
  char cutbuf[BUFSIZE];
  assert(0 != sptr);
  assert(0 != name);
  assert(0 != text);

  /* UTF8ONLY enforcement */
  if (feature_bool(FEAT_UTF8ONLY) && !string_is_valid_utf8(text)) {
    if (feature_bool(FEAT_UTF8ONLY_STRICT)) {
      send_fail(sptr, "PRIVMSG", "INVALID_UTF8", NULL,
                "Message contains invalid UTF-8 and was rejected");
      return;
    }
    /* Warn mode: copy, sanitize, and use sanitized version */
    ircd_strncpy(utf8buf, text, sizeof(utf8buf) - 1);
    utf8buf[sizeof(utf8buf) - 1] = '\0';
    string_sanitize_utf8(utf8buf);
    send_warn(sptr, "PRIVMSG", "INVALID_UTF8", NULL,
              "Message contained invalid UTF-8 and was sanitized");
    mytext = utf8buf;
    if (EmptyString(mytext)) {
      send_reply(sptr, ERR_NOTEXTTOSEND);
      return;
    }
  }

  if (0 == (chptr = FindChannel(name))) {
    send_reply(sptr, ERR_NOSUCHCHANNEL, name);
    return;
  }
  /*
   * This first: Almost never a server/service
   */
  if (!client_can_send_to_channel(sptr, chptr, 0)) {
    send_reply(sptr, ERR_CANNOTSENDTOCHAN, chptr->chname);
    return;
  }
  if ((chptr->mode.mode & MODE_NOPRIVMSGS) &&
      check_target_limit(sptr, chptr, chptr->chname, 0))
    return;

  if ((chptr->mode.exmode & EXMODE_NOCTCPS) && (*text == '\x01') &&
      ircd_strncmp(text+1, "ACTION", 6)) {
    send_reply(sptr, ERR_CANNOTSENDTOCHAN, chptr->chname);
    return;
  }

  if (((chptr->mode.exmode & EXMODE_NOMULTITARG) ||
       feature_bool(FEAT_NOMULTITARGETS)) && (targets > 1)) {
    send_reply(sptr, ERR_CANNOTSENDTOCHAN, chptr->chname);
    return;
  }

  if (chptr->mode.exmode & EXMODE_NOCOLOR)
    for (ch=text;*ch;ch++)
      if (*ch==COLOR_COLOR || *ch==27 || *ch==COLOR_REVERSE) {
        send_reply(sptr, ERR_CANNOTSENDTOCHAN, chptr->chname);
        return;
      }

  if (chptr->mode.exmode & EXMODE_STRIPCOLOR) {
    mytext = StripColor(text);
    if (EmptyString(mytext)) {
      send_reply(sptr, ERR_NOTEXTTOSEND);
      return;
    }
  }

  /* Cut once, here, to what ":nick!user@host PRIVMSG <chname> :" leaves
   * of 510: the message every member, the echo, other servers and the
   * history row get is this text (relay_cut_text). */
  mytext = relay_cut_text(sptr, MSG_PRIVATE, strlen(chptr->chname), 0,
                          mytext, cutbuf, sizeof(cutbuf));

  RevealDelayedJoinIfNeeded(sptr, chptr);

  /* Generate msgid before channel broadcast so all recipients get the same one */
  {
    char msgid[64] = "";
    char timestamp[32] = "";
    int need_echo = feature_bool(FEAT_CAP_echo_message) && CapOwnHas(sptr, CAP_ECHOMSG);

#ifdef USE_ROCKSDB
    if (feature_bool(FEAT_MSGID)) {
      uint64_t event_ms;
      /* msgid FIRST: minting advances the HLC, and the row time read
       * after it is the msgid's own mint time -- the same number the
       * live @time and the S2S tag carry (one time per message). */
      generate_msgid(msgid, sizeof(msgid));
      event_ms = history_event_time_ms(NULL);
      history_format_ms(timestamp, sizeof(timestamp), event_ms);

      /* Set S2S msgid override so the S2S relay carries the same msgid
       * that we store locally — prevents federation dedup failures. */
      sendcmdto_set_s2s_tags(event_ms, msgid);
    }
#endif

    /* Set msgid override so channel broadcast includes it in client tags */
    if (msgid[0])
      sendcmdto_set_client_event(msgid, history_parse_ms(timestamp));

#ifdef USE_ROCKSDB
    /* No store here: write-forward AHEAD of the relay (forward_channel_history) */
    if (msgid[0]) {
      const char *fwd_ctags = cli_client_tags(sptr);
      forward_channel_history(sptr, chptr, mytext, HISTORY_PRIVMSG, msgid, timestamp,
                              (fwd_ctags && *fwd_ctags) ? fwd_ctags : NULL);
    }
#endif

    /* Alias source rewriting: use primary's numeric for S2S delivery.
     * When primary is remote, use split S2S delivery: primary numeric for
     * most servers, alias numeric for the primary's server direction
     * (to avoid fake direction — the primary's server handles rewriting). */
    {
      struct Client *from = sptr;
      const char *client_tags = cli_client_tags(sptr);

      if (IsBouncerAlias(sptr) && cli_user(sptr)->alias_primary) {
        if (!MyUser(cli_user(sptr)->alias_primary))
          sendcmdto_set_alias_source(sptr);
        from = cli_user(sptr)->alias_primary;
      }

      if (client_tags && *client_tags) {
        sendcmdto_channel_butone_with_client_tags(from, CMD_PRIVATE, chptr, cli_from(sptr),
                           SKIP_DEAF | SKIP_BURST, text[0], client_tags,
                           "%H :%s", chptr, mytext);
      } else {
        sendcmdto_channel_butone(from, CMD_PRIVATE, chptr, cli_from(sptr),
                                 SKIP_DEAF | SKIP_BURST, text[0], "%H :%s", chptr, mytext);
      }
    }

    /* Clear the msgid override after broadcast */
    sendcmdto_set_client_msgid(NULL);

    /* Echo message back to sender if they have echo-message cap */
    if (need_echo) {
      const char *echo_ctags = cli_client_tags(sptr);
      if (echo_ctags && *echo_ctags && CapOwnHas(sptr, CAP_MSGTAGS)) {
        /* Include client tags in echo */
        if (msgid[0])
          sendcmdto_set_client_event(msgid, history_parse_ms(timestamp));
        sendcmdto_one_client_tags(sptr, MSG_PRIVATE, sptr, echo_ctags,
                                  "%H :%s", chptr, mytext);
        sendcmdto_set_client_msgid(NULL);
      } else {
#ifdef USE_ROCKSDB
        /* Arm the event so the echo's @time is the row's time, not the
         * clock at send (the composer only honours it while a client
         * msgid is armed). */
        if (msgid[0])
          sendcmdto_set_client_event(msgid, history_parse_ms(timestamp));
        sendcmdto_one_tags_ext(sptr, CMD_PRIVATE, sptr, msgid,
                               "%H :%s", chptr, mytext);
        sendcmdto_set_client_msgid(NULL);
#else
        sendcmdto_one_tags(sptr, CMD_PRIVATE, sptr, "%H :%s", chptr, mytext);
#endif
      }
    }

#ifdef USE_ROCKSDB
    /* Store message in history database for draft/chathistory.
     * Include client-only tags (+reply, +draft/react) if present. */
    if (msgid[0]) {
      const char *store_ctags = cli_client_tags(sptr);
      store_channel_history(sptr, chptr, mytext, HISTORY_PRIVMSG, msgid, timestamp,
                            (store_ctags && *store_ctags) ? store_ctags : NULL);
    }
#endif
  }
}

/** Relay a local user's notice to a channel.
 * Silently exits if the client cannot send to the channel.
 * @param[in] sptr Client that originated the message.
 * @param[in] name Name of target channel.
 * @param[in] text %Message to relay.
 * @param[in] targets Number of targets for the initial NOTICE
 */
void relay_channel_notice(struct Client* sptr, const char* name, const char* text, int targets)
{
  struct Channel* chptr;
  const char* mytext = text;
  const char* ch;
  char utf8buf[BUFSIZE];
  char cutbuf[BUFSIZE];
  assert(0 != sptr);
  assert(0 != name);
  assert(0 != text);

  /* UTF8ONLY enforcement */
  if (feature_bool(FEAT_UTF8ONLY) && !string_is_valid_utf8(text)) {
    if (feature_bool(FEAT_UTF8ONLY_STRICT)) {
      send_fail(sptr, "NOTICE", "INVALID_UTF8", NULL,
                "Message contains invalid UTF-8 and was rejected");
      return;
    }
    /* Warn mode: copy, sanitize, and use sanitized version */
    ircd_strncpy(utf8buf, text, sizeof(utf8buf) - 1);
    utf8buf[sizeof(utf8buf) - 1] = '\0';
    string_sanitize_utf8(utf8buf);
    send_warn(sptr, "NOTICE", "INVALID_UTF8", NULL,
              "Message contained invalid UTF-8 and was sanitized");
    mytext = utf8buf;
    if (EmptyString(mytext))
      return;
  }

  if (0 == (chptr = FindChannel(name)))
    return;
  /*
   * This first: Almost never a server/service
   */
  if (!client_can_send_to_channel(sptr, chptr, 0))
    return;

  if ((chptr->mode.mode & MODE_NOPRIVMSGS) &&
      check_target_limit(sptr, chptr, chptr->chname, 0))
    return;

  if (chptr->mode.exmode & EXMODE_NONOTICES)
    return;

  if ((chptr->mode.exmode & EXMODE_NOCTCPS) && (*text == '\x01'))
    return;

  if (((chptr->mode.exmode & EXMODE_NOMULTITARG) ||
       feature_bool(FEAT_NOMULTITARGETS)) && (targets > 1))
    return;

  if (chptr->mode.exmode & EXMODE_NOCOLOR)
    for (ch=text;*ch;ch++)
      if (*ch==COLOR_COLOR || *ch==27 || *ch==COLOR_REVERSE)
        return;

  if (chptr->mode.exmode & EXMODE_STRIPCOLOR) {
    mytext = StripColor(text);
    if (EmptyString(mytext))
      return;
  }

  /* Cut once, here (see relay_channel_message). */
  mytext = relay_cut_text(sptr, MSG_NOTICE, strlen(chptr->chname), 0,
                          mytext, cutbuf, sizeof(cutbuf));

  RevealDelayedJoinIfNeeded(sptr, chptr);

  /* Generate msgid before channel broadcast (mirrors relay_channel_message).
   * Setting S2S msgid override ensures the same msgid is used for both
   * local storage and S2S relay — prevents federation dedup failures. */
  {
    char msgid[64] = "";
    char timestamp[32] = "";
    int need_echo = feature_bool(FEAT_CAP_echo_message) && CapOwnHas(sptr, CAP_ECHOMSG);

#ifdef USE_ROCKSDB
    if (feature_bool(FEAT_MSGID)) {
      uint64_t event_ms;
      /* msgid first, then its mint time (see relay_channel_message) */
      generate_msgid(msgid, sizeof(msgid));
      event_ms = history_event_time_ms(NULL);
      history_format_ms(timestamp, sizeof(timestamp), event_ms);

      sendcmdto_set_s2s_tags(event_ms, msgid);
    }
#endif

    /* Set msgid override so channel broadcast includes it in client tags */
    if (msgid[0])
      sendcmdto_set_client_event(msgid, history_parse_ms(timestamp));

#ifdef USE_ROCKSDB
    /* No store here: write-forward AHEAD of the relay (forward_channel_history) */
    if (msgid[0]) {
      const char *fwd_ctags = cli_client_tags(sptr);
      forward_channel_history(sptr, chptr, mytext, HISTORY_NOTICE, msgid, timestamp,
                              (fwd_ctags && *fwd_ctags) ? fwd_ctags : NULL);
    }
#endif

    /* Alias source rewriting (see relay_channel_message) */
    {
      struct Client *from = sptr;
      const char *client_tags = cli_client_tags(sptr);

      if (IsBouncerAlias(sptr) && cli_user(sptr)->alias_primary) {
        if (!MyUser(cli_user(sptr)->alias_primary))
          sendcmdto_set_alias_source(sptr);
        from = cli_user(sptr)->alias_primary;
      }

      if (client_tags && *client_tags) {
        sendcmdto_channel_butone_with_client_tags(from, CMD_NOTICE, chptr, cli_from(sptr),
                           SKIP_DEAF | SKIP_BURST, '\0', client_tags,
                           "%H :%s", chptr, mytext);
      } else {
        sendcmdto_channel_butone(from, CMD_NOTICE, chptr, cli_from(sptr),
                                 SKIP_DEAF | SKIP_BURST, '\0', "%H :%s", chptr, mytext);
      }
    }

    /* Clear the msgid override after broadcast */
    sendcmdto_set_client_msgid(NULL);

    /* Echo notice back to sender if they have echo-message cap */
    if (need_echo) {
      const char *echo_ctags = cli_client_tags(sptr);
      if (echo_ctags && *echo_ctags && CapOwnHas(sptr, CAP_MSGTAGS)) {
        if (msgid[0])
          sendcmdto_set_client_event(msgid, history_parse_ms(timestamp));
        sendcmdto_one_client_tags(sptr, MSG_NOTICE, sptr, echo_ctags,
                                  "%H :%s", chptr, mytext);
        sendcmdto_set_client_msgid(NULL);
      } else {
#ifdef USE_ROCKSDB
        /* Arm the event so the echo's @time is the row's time (see the
         * PRIVMSG echo above). */
        if (msgid[0])
          sendcmdto_set_client_event(msgid, history_parse_ms(timestamp));
        sendcmdto_one_tags_ext(sptr, CMD_NOTICE, sptr, msgid,
                               "%H :%s", chptr, mytext);
        sendcmdto_set_client_msgid(NULL);
#else
        sendcmdto_one_tags(sptr, CMD_NOTICE, sptr, "%H :%s", chptr, mytext);
#endif
      }
    }

#ifdef USE_ROCKSDB
    /* Store notice in history database for draft/chathistory.
     * Include client-only tags (+reply, +draft/react) if present. */
    if (msgid[0]) {
      const char *store_ctags = cli_client_tags(sptr);
      store_channel_history(sptr, chptr, mytext, HISTORY_NOTICE, msgid, timestamp,
                            (store_ctags && *store_ctags) ? store_ctags : NULL);
    }
#endif
  }
}

/** Relay a message to a channel.
 * Generates an error if the client cannot send to the channel,
 * or if the channel is a local channel
 * @param[in] sptr Client that originated the message.
 * @param[in] name Name of target channel.
 * @param[in] text %Message to relay.
 */
void server_relay_channel_message(struct Client* sptr, const char* name, const char* text)
{
  struct Channel* chptr;
  struct Client *one;
  const char *client_tags;

  assert(0 != sptr);
  assert(0 != name);
  assert(0 != text);

  if (IsLocalChannel(name) || 0 == (chptr = FindChannel(name))) {
    send_reply(sptr, ERR_NOSUCHCHANNEL, name);
    return;
  }

  /* Save alias's server link and client tags before potential rewrite.
   * For S2S-relayed messages, client tags arrive in the compact-tag
   * ,C<client_tags> segment, populated by parse_server() into
   * cli_s2s_client_tags(server_link). cli_client_tags(remote_user) is
   * always empty since remote users don't go through parse_client(),
   * so prefer the S2S-incoming form. */
  one = cli_from(sptr);
  {
    const char *s2s_tags = cli_s2s_client_tags(one);
    client_tags = (s2s_tags && *s2s_tags) ? s2s_tags : cli_client_tags(sptr);
  }

  /* Unified msgid: if no incoming S2S msgid, mint one (with its mint
   * time) into the link's stash now so format_s2s_tags() (relay) and
   * storage both use the same msgid and time.  Handles messages from
   * legacy servers without P10_MESSAGE_TAGS. */
  if (feature_bool(FEAT_P10_MESSAGE_TAGS) && one && !cli_s2s_msgid(one)[0])
    s2s_mint_link_event(one);

  /* Alias source rewriting: use primary's P10 numeric for S2S.
   * The alias numeric (from BX C) is only known to BX-aware servers.
   * The primary numeric (from N token) is universally known.
   * Keep 'one' = alias's server link for echo suppression. */
  if (IsBouncerAlias(sptr) && cli_user(sptr)->alias_primary) {
    sendcmdto_set_s2s_cptr(one);  /* Preserve alias's S2S tags */
    if (!MyUser(cli_user(sptr)->alias_primary))
      sendcmdto_set_alias_source(sptr);
    sptr = cli_user(sptr)->alias_primary;
  }

  /*
   * This first: Almost never a server/service
   * Servers may have channel services, need to check for it here
   */
  if (client_can_send_to_channel(sptr, chptr, 1) || IsChannelService(sptr)) {
    /* Set client msgid override so local clients get msgid tag.
     * Use S2S msgid if available, otherwise generate one. */
    char relay_msgid[64] = "";
    if (feature_bool(FEAT_MSGID)) {
      const char *s2s_mid = (feature_bool(FEAT_P10_MESSAGE_TAGS) && one
                             && cli_s2s_msgid(one)[0]) ? cli_s2s_msgid(one) : NULL;
      if (s2s_mid)
        ircd_strncpy(relay_msgid, s2s_mid, sizeof(relay_msgid));
      else
        generate_msgid(relay_msgid, sizeof(relay_msgid));
      sendcmdto_set_client_event(relay_msgid, history_event_time_ms(one));
    }

#ifdef USE_ROCKSDB
    /* No store here: write-forward AHEAD of the relay
     * (forward_channel_history); the same msgid and time as the store
     * below would use. */
    if (relay_msgid[0]) {
      char fwd_ts[32];

      history_format_ms(fwd_ts, sizeof(fwd_ts), history_event_time_ms(one));
      forward_channel_history(sptr, chptr, text, HISTORY_PRIVMSG, relay_msgid, fwd_ts,
                              (client_tags && *client_tags) ? client_tags : NULL);
    }
#endif

    if (client_tags && *client_tags) {
      sendcmdto_channel_butone_with_client_tags(sptr, CMD_PRIVATE, chptr, one,
                         SKIP_DEAF | SKIP_BURST, text[0], client_tags,
                         "%H :%s", chptr, text);
    } else {
      sendcmdto_channel_butone(sptr, CMD_PRIVATE, chptr, one,
                               SKIP_DEAF | SKIP_BURST, text[0], "%H :%s", chptr, text);
    }

    sendcmdto_set_client_msgid(NULL);

#ifdef USE_ROCKSDB
    /* Store server-relayed message in history database.
     * Uses the same msgid that was broadcast to clients above, and the
     * origin's time from the same S2S tag -- the @time this server just
     * delivered live.  It used to stamp the local wall clock here, so
     * the row replayed with a different time than it was delivered with. */
    if (relay_msgid[0]) {
      char timestamp[32];

      history_format_ms(timestamp, sizeof(timestamp), history_event_time_ms(one));
      store_channel_history(sptr, chptr, text, HISTORY_PRIVMSG, relay_msgid, timestamp,
                             (client_tags && *client_tags) ? client_tags : NULL);
    }
#endif
  }
  else
    send_reply(sptr, ERR_CANNOTSENDTOCHAN, chptr->chname);
}

/** Relay a notice to a channel.
 * Generates an error if the client cannot send to the channel,
 * or if the channel is a local channel
 * @param[in] sptr Client that originated the message.
 * @param[in] name Name of target channel.
 * @param[in] text %Message to relay.
 */
void server_relay_channel_notice(struct Client* sptr, const char* name, const char* text)
{
  struct Channel* chptr;
  struct Client *one;
  const char *client_tags;

  assert(0 != sptr);
  assert(0 != name);
  assert(0 != text);

  if (IsLocalChannel(name) || 0 == (chptr = FindChannel(name)))
    return;

  /* Save alias's server link and client tags before potential rewrite.
   * For S2S-relayed messages, prefer cli_s2s_client_tags(server_link)
   * — see server_relay_channel_message. */
  one = cli_from(sptr);
  {
    const char *s2s_tags = cli_s2s_client_tags(one);
    client_tags = (s2s_tags && *s2s_tags) ? s2s_tags : cli_client_tags(sptr);
  }

  /* Unified msgid (see server_relay_channel_message) */
  if (feature_bool(FEAT_P10_MESSAGE_TAGS) && one && !cli_s2s_msgid(one)[0])
    s2s_mint_link_event(one);

  /* Alias source rewriting (see server_relay_channel_message) */
  if (IsBouncerAlias(sptr) && cli_user(sptr)->alias_primary) {
    sendcmdto_set_s2s_cptr(one);  /* Preserve alias's S2S tags */
    if (!MyUser(cli_user(sptr)->alias_primary))
      sendcmdto_set_alias_source(sptr);
    sptr = cli_user(sptr)->alias_primary;
  }

  /*
   * This first: Almost never a server/service
   * Servers may have channel services, need to check for it here.
   *
   * IsServer bypass for +N: server-source NOTICEs are system signals
   * (multiline truncation, etc.), not user speech.  client_can_send_to_channel
   * already exempts IsServer from +n/+m/+M/+R/+Z/+O, so exempting +N keeps
   * +N consistent with the other gating modes.
   */
  if ((client_can_send_to_channel(sptr, chptr, 1) &&
       (!(chptr->mode.exmode & EXMODE_NONOTICES) || IsServer(sptr)))
      || IsChannelService(sptr)) {
    /* Set client msgid override so local clients get msgid tag. */
    char relay_msgid[64] = "";
    if (feature_bool(FEAT_MSGID)) {
      const char *s2s_mid = (feature_bool(FEAT_P10_MESSAGE_TAGS) && one
                             && cli_s2s_msgid(one)[0]) ? cli_s2s_msgid(one) : NULL;
      if (s2s_mid)
        ircd_strncpy(relay_msgid, s2s_mid, sizeof(relay_msgid));
      else
        generate_msgid(relay_msgid, sizeof(relay_msgid));
      sendcmdto_set_client_event(relay_msgid, history_event_time_ms(one));
    }

#ifdef USE_ROCKSDB
    /* No store here: write-forward AHEAD of the relay
     * (forward_channel_history); the same msgid and time as the store
     * below would use. */
    if (relay_msgid[0]) {
      char fwd_ts[32];

      history_format_ms(fwd_ts, sizeof(fwd_ts), history_event_time_ms(one));
      forward_channel_history(sptr, chptr, text, HISTORY_NOTICE, relay_msgid, fwd_ts,
                              (client_tags && *client_tags) ? client_tags : NULL);
    }
#endif

    if (client_tags && *client_tags) {
      sendcmdto_channel_butone_with_client_tags(sptr, CMD_NOTICE, chptr, one,
                         SKIP_DEAF | SKIP_BURST, '\0', client_tags,
                         "%H :%s", chptr, text);
    } else {
      sendcmdto_channel_butone(sptr, CMD_NOTICE, chptr, one,
                               SKIP_DEAF | SKIP_BURST, '\0', "%H :%s", chptr, text);
    }

    sendcmdto_set_client_msgid(NULL);

#ifdef USE_ROCKSDB
    /* Store server-relayed notice in history database.
     * Same msgid and same origin time as the live delivery (see
     * server_relay_channel_message). */
    if (relay_msgid[0]) {
      char timestamp[32];

      history_format_ms(timestamp, sizeof(timestamp), history_event_time_ms(one));
      store_channel_history(sptr, chptr, text, HISTORY_NOTICE, relay_msgid, timestamp,
                             (client_tags && *client_tags) ? client_tags : NULL);
    }
#endif
  }
}

/** Relay a directed message.
 * Generates an error if the named server does not exist, if it is not
 * a services server, or if \a name names a local user and a hostmask
 * is specified but does not match.
 * @param[in] sptr Client that originated the message.
 * @param[in] name Target nickname, with optional "%hostname" suffix.
 * @param[in] server Name of target server.
 * @param[in] text %Message to relay.
 */
void relay_directed_message(struct Client* sptr, char* name, char* server, const char* text)
{
  struct Client* acptr;
  char*          host;

  assert(0 != sptr);
  assert(0 != name);
  assert(0 != text);
  assert(0 != server);

  if ((acptr = FindServer(server + 1)) == NULL || !IsService(acptr))
  {
    send_reply(sptr, ERR_NOSUCHNICK, name);
    return;
  }
  /*
   * NICK[%host]@server addressed? See if <server> is me first
   */
  if (!IsMe(acptr))
  {
    /* Alias source rewrite — emit from the primary numeric so a legacy /
     * non-BX-aware services server (which was never told about the alias
     * via BX C) can resolve the source.  Without this, X3 / similar pseudo
     * targets silently drop commands from a bouncer alias, leaving the
     * client with no reply (no ERR_SERVICESDOWN, no 421).  Keep the alias
     * numeric only when the primary's wire direction IS this very server
     * — sending from primary toward primary's own server would be fake
     * direction.  Mirrors relay_private_message (~:1200-1206). */
    struct Client *from = sptr;
    if (IsBouncerAlias(sptr) && cli_user(sptr)->alias_primary) {
      from = cli_user(sptr)->alias_primary;
      if (!MyUser(from) && cli_from(from) == acptr)
        from = sptr;
    }
    sendcmdto_one(from, CMD_PRIVATE, acptr, "%s :%s", name, text);
    return;
  }
  /*
   * Look for an user whose NICK is equal to <name> and then
   * check if it's hostname matches <host> and if it's a local
   * user.
   */
  *server = '\0';
  if ((host = strchr(name, '%')))
    *host++ = '\0';

  /* As reported by Vampire-, it's possible to brute force finding users
   * by sending a message to each server and see which one succeeded.
   * This means we have to remove error reporting.  Sigh.  Better than
   * removing the ability to send directed messages to client servers 
   * Thanks for the suggestion Vampire=.  -- Isomer 2001-08-28
   * Argh, /ping nick@server, disallow messages to non +k clients :/  I hate
   * this. -- Isomer 2001-09-16
   */
  if (!(acptr = FindUser(name)) || !MyUser(acptr) ||
      (!EmptyString(host) && 0 != match(host, cli_user(acptr)->host)) ||
      !IsChannelService(acptr))
  {
    /*
     * By this stage we might as well not bother because they will
     * know that this server is currently linked because of the
     * increased lag.
     */
    send_reply(sptr, ERR_NOSUCHNICK, name);
    return;
  }

  *server = '@';
  if (host)
    *--host = '%';

  /*
   * +R check, if target is +R and we're not +r (or opered) then
   * deny the message.
   */
  if (IsAccountOnly(acptr) && !IsAccount(sptr) && !IsOper(sptr) && (acptr != sptr)) {
    send_reply(sptr, ERR_ACCOUNTONLY, cli_name(acptr), "PRIVMSG", cli_name(acptr));
    return;
  }

  /*
   * +D check, if target is +D and we're not opered then deny
   * the message.
   */
  if (IsPrivDeaf(acptr) && !IsOper(sptr) && (acptr != sptr)) {
    send_reply(sptr, ERR_PRIVDEAF, cli_name(acptr), "PRIVMSG", cli_name(acptr));
    return;
  }

  if ((IsRestrictPrivMsg(sptr) || IsCommonChansOnly(acptr)) && !IsAnOper(sptr) &&
      !common_chan_count(acptr, sptr, 1) && (sptr != acptr)) {
    send_reply(sptr, ERR_COMMONCHANSONLY, cli_name(acptr), "PRIVMSG");
    return;
  }

  if (!(is_silenced(sptr, acptr, 0))) {
    /* Alias source rewrite — same pattern as relay_private_message.
     * acptr is asserted MyUser above, so the !MyConnect guard never
     * fires; from always resolves to the primary, giving the local
     * recipient the same source numeric they would see from any other
     * PM path. */
    struct Client *from = sptr;
    if (IsBouncerAlias(sptr) && cli_user(sptr)->alias_primary) {
      from = cli_user(sptr)->alias_primary;
      if (!MyUser(from) && !MyConnect(acptr)
          && cli_from(from) == cli_from(acptr))
        from = sptr;
    }
    sendcmdto_one(from, CMD_PRIVATE, acptr, "%s :%s", name, text);
  }
}

/** Relay a directed notice.
 * Generates an error if the named server does not exist, if it is not
 * a services server, or if \a name names a local user and a hostmask
 * is specified but does not match.
 * @param[in] sptr Client that originated the message.
 * @param[in] name Target nickname, with optional "%hostname" suffix.
 * @param[in] server Name of target server.
 * @param[in] text %Message to relay.
 */
void relay_directed_notice(struct Client* sptr, char* name, char* server, const char* text)
{
  struct Client* acptr;
  char*          host;
  char           cutbuf[BUFSIZE];

  assert(0 != sptr);
  assert(0 != name);
  assert(0 != text);
  assert(0 != server);

  if (0 == (acptr = FindServer(server + 1)))
    return;
  /*
   * NICK[%host]@server addressed? See if <server> is me first
   */
  if (!IsMe(acptr)) {
    /* Alias source rewrite — see relay_directed_message for the full
     * rationale.  Without this, NOTICEs from a bouncer alias addressed
     * to nick@services-server arrive at the service with an unknown
     * source numeric and get dropped. */
    struct Client *from = sptr;
    if (IsBouncerAlias(sptr) && cli_user(sptr)->alias_primary) {
      from = cli_user(sptr)->alias_primary;
      if (!MyUser(from) && cli_from(from) == acptr)
        from = sptr;
    }
    sendcmdto_one(from, CMD_NOTICE, acptr, "%s :%s", name, text);
    return;
  }
  /*
   * Look for an user whose NICK is equal to <name> and then
   * check if it's hostname matches <host> and if it's a local
   * user.
   */
  *server = '\0';
  if ((host = strchr(name, '%')))
    *host++ = '\0';

  if (!(acptr = FindUser(name)) || !MyUser(acptr) ||
      (!EmptyString(host) && 0 != match(host, cli_user(acptr)->host)))
    return;

  *server = '@';
  if (host)
    *--host = '%';

  /*
   * +R check, if target is +R and we're not +r (or opered) then
   * deny the message.
   */
  if (IsAccountOnly(acptr) && !IsAccount(sptr) && !IsOper(sptr) && (acptr != sptr)) {
    send_reply(sptr, ERR_ACCOUNTONLY, cli_name(acptr), "NOTICE", cli_name(acptr));
    return;
  }

  /*
   * +D check, if target is +D and we're not opered then deny
   * the message.
   */
  if (IsPrivDeaf(acptr) && !IsOper(sptr) && (acptr != sptr)) {
    send_reply(sptr, ERR_PRIVDEAF, cli_name(acptr), "NOTICE", cli_name(acptr));
    return;
  }

  if ((IsRestrictPrivMsg(sptr) || IsCommonChansOnly(acptr)) && !IsAnOper(sptr) &&
      !common_chan_count(acptr, sptr, 1) && (sptr != acptr)) {
    send_reply(sptr, ERR_COMMONCHANSONLY, cli_name(acptr), "NOTICE");
    return;
  }

  /* Our own user gets ":nick!user@host NOTICE <name as written> :": cut
   * the text to that line here (relay_cut_text) -- unless it is a service
   * (a +k channel service), which reads the whole line as a command; a
   * NOTICE with no room left is dropped without a reply.  (A directed
   * PRIVMSG is not cut at all: its local target is always a +k service,
   * and toward a services server the P10 line is what is read.) */
  if (!IsServiceClient(acptr)) {
    text = relay_cut_text(sptr, MSG_NOTICE, strlen(name), 0, text,
                          cutbuf, sizeof(cutbuf));
    if (!*text)
      return;
  }

  if (!(is_silenced(sptr, acptr, 0))) {
    /* Alias source rewrite — see relay_directed_message IsMe branch. */
    struct Client *from = sptr;
    if (IsBouncerAlias(sptr) && cli_user(sptr)->alias_primary) {
      from = cli_user(sptr)->alias_primary;
      if (!MyUser(from) && !MyConnect(acptr)
          && cli_from(from) == cli_from(acptr))
        from = sptr;
    }
    sendcmdto_one(from, CMD_NOTICE, acptr, "%s :%s", name, text);
  }
}

/** Relay a private message from a local user.
 * Returns an error if the user does not exist or sending to him would
 * exceed the source's free targets.  Sends an AWAY status message if
 * the target is marked as away.
 * @param[in] sptr Client that originated the message.
 * @param[in] name Nickname of target user.
 * @param[in] text %Message to relay.
 */
void relay_private_message(struct Client* sptr, const char* name, const char* text)
{
  struct Client* acptr;
  const char* mytext = text;
  char utf8buf[BUFSIZE];
  char cutbuf[BUFSIZE];
  char pm_msgid[64];
  char pm_timestamp[32];

  assert(0 != sptr);
  assert(0 != name);
  assert(0 != text);

  /* UTF8ONLY enforcement */
  if (feature_bool(FEAT_UTF8ONLY) && !string_is_valid_utf8(text)) {
    if (feature_bool(FEAT_UTF8ONLY_STRICT)) {
      send_fail(sptr, "PRIVMSG", "INVALID_UTF8", NULL,
                "Message contains invalid UTF-8 and was rejected");
      return;
    }
    /* Warn mode: copy, sanitize, and use sanitized version */
    ircd_strncpy(utf8buf, text, sizeof(utf8buf) - 1);
    utf8buf[sizeof(utf8buf) - 1] = '\0';
    string_sanitize_utf8(utf8buf);
    send_warn(sptr, "PRIVMSG", "INVALID_UTF8", NULL,
              "Message contained invalid UTF-8 and was sanitized");
    mytext = utf8buf;
    if (EmptyString(mytext)) {
      send_reply(sptr, ERR_NOTEXTTOSEND);
      return;
    }
  }

  if (0 == (acptr = FindUser(name))) {
    send_reply(sptr, ERR_NOSUCHNICK, name);
    return;
  }
  if ((!IsChannelService(acptr) &&
       check_target_limit(sptr, acptr, cli_name(acptr), 0)) ||
      is_silenced(sptr, acptr, 0))
    return;

  /*
   * +R check, if target is +R and we're not +r (or opered) then
   * deny the message.
   */
  if (IsAccountOnly(acptr) && !IsAccount(sptr) && !IsOper(sptr) && (acptr != sptr)) {
    send_reply(sptr, ERR_ACCOUNTONLY, cli_name(acptr), "PRIVMSG", cli_name(acptr));
    return;
  }

  /*
   * +D check, if target is +D and we're not opered then deny
   * the message.
   */
  if (IsPrivDeaf(acptr) && !IsOper(sptr) && (acptr != sptr)) {
    send_reply(sptr, ERR_PRIVDEAF, cli_name(acptr), "PRIVMSG", cli_name(acptr));
    return;
  }

  if ((IsRestrictPrivMsg(sptr) || IsCommonChansOnly(acptr)) && !IsAnOper(sptr) &&
      !common_chan_count(acptr, sptr, 1) && (sptr != acptr)) {
    send_reply(sptr, ERR_COMMONCHANSONLY, cli_name(acptr), "PRIVMSG");
    return;
  }

  /*
   * send away message if user away
   */
  if (cli_user(acptr) && cli_user(acptr)->away)
    send_reply(sptr, RPL_AWAY, cli_name(acptr), away_text_for(sptr, cli_user(acptr)->away));
  /*
   * deliver the message
   */
  if (MyUser(acptr))
    add_target(acptr, sptr);

  /* Generate shared msgid + timestamp for alias forwarding, echo, and history */
  pm_msgid[0] = '\0';
  pm_timestamp[0] = '\0';
  if (feature_bool(FEAT_MSGID)) {
    /* msgid first, then its mint time (one time per message) */
    generate_msgid(pm_msgid, sizeof(pm_msgid));
    history_format_ms(pm_timestamp, sizeof(pm_timestamp),
                      history_event_time_ms(NULL));
  }

  /* Cut once, here, to what ":nick!user@host PRIVMSG <their nick> :"
   * leaves of 510, and the session echo's BX frame when the sender has
   * other devices (relay_dm_text_budget): the recipient (and its
   * aliases), the sender's echo and session, other servers, the history
   * row and a web push all get this text.  Not for a service: the
   * service reads the P10 line, which carries the whole client line
   * (services traffic is neither stored nor pushed), and a command cut
   * here would run with its argument cut short.  The sender's echo of
   * such a DM is left to the output backstop. */
  if (!IsServiceClient(acptr))
    mytext = relay_cut_to(mytext,
                          relay_dm_text_budget(sptr, MSG_PRIVATE, acptr,
                                               strlen(pm_msgid), 0, 0),
                          cutbuf, sizeof(cutbuf));

  /* Alias source rewriting for S2S legacy compat.
   * If target is on the primary's server direction, keep alias numeric
   * (avoids fake direction — server_relay handles rewriting there). */
  {
    const char *client_tags = cli_client_tags(sptr);
    struct Client *from = sptr;

    if (IsBouncerAlias(sptr) && cli_user(sptr)->alias_primary) {
      from = cli_user(sptr)->alias_primary;
      /* Keep alias numeric for primary's server direction to avoid fake direction */
      if (!MyUser(from) && !MyConnect(acptr)
          && cli_from(from) == cli_from(acptr))
        from = sptr;
    }

    if (acptr == sptr && !(feature_bool(FEAT_CAP_echo_message)
                           && CapOwnHas(sptr, CAP_ECHOMSG))) {
      /* A message to yourself without echo-message: this copy is the
       * delivered message, not the answer to the PRIVMSG, so it carries
       * no label and the PRIVMSG is answered by ACK (labeled-response:
       * only the echo-message copy of a message to oneself is labeled).
       * With echo-message the client is sent the same line twice, and the
       * first -- this one, on the paths below -- keeps the label: the
       * labeled echo, as the client sees it, then the unlabeled copy. */
      if (pm_msgid[0])
        sendcmdto_set_client_event(pm_msgid, history_parse_ms(pm_timestamp));
      sendcmdto_one_delivery(from, CMD_PRIVATE, acptr, client_tags,
                             "%C :%s", acptr, mytext);
      sendcmdto_set_client_msgid(NULL);
    } else if (client_tags && *client_tags && MyConnect(acptr) && CapActive(acptr, CAP_MSGTAGS)) {
      /* Set msgid override so format_message_tags_with_client includes it */
      if (pm_msgid[0])
        sendcmdto_set_client_event(pm_msgid, history_parse_ms(pm_timestamp));
      sendcmdto_one_client_tags(from, MSG_PRIVATE, acptr, client_tags,
                                "%C :%s", acptr, mytext);
      sendcmdto_set_client_msgid(NULL);
    } else {
      /* Use tag-aware send so recipient gets server-time/msgid per caps.
       * For S2S delivery to IRCV3AWARE peers, sendcmdto_one_tags_with_client
       * also adds the @A...,C<client_tags> compact-tag prefix so the
       * remote server can forward client-only tags to its local recipient
       * (per p10-compact-client-tags plan). */
      /* Locally minted: this message's own id and time ride the wire,
       * not whatever was last parsed off the destination link -- also
       * when an alias sends as its remote primary.  A local target takes
       * the same time on its @time (the client event; a remote target's
       * send ignores it), cleared right after the send. */
      if (pm_msgid[0]) {
        sendcmdto_set_client_event(pm_msgid, history_parse_ms(pm_timestamp));
        sendcmdto_set_s2s_tags(history_parse_ms(pm_timestamp), pm_msgid);
      }
      sendcmdto_one_tags_with_client(from, CMD_PRIVATE, acptr,
                                     pm_msgid, client_tags,
                                     "%C :%s", acptr, mytext);
      sendcmdto_set_client_msgid(NULL);
    }
  }

  /* Forward PM to all aliases of the target bouncer primary */
  bounce_forward_pm_to_aliases(sptr, acptr, NULL, CMD_PRIVATE, mytext,
                               pm_msgid, history_parse_ms(pm_timestamp),
                               cli_client_tags(sptr));

  /* The session echo and the sender's own echo carry the event's time
   * too.  Armed here, apart from the forward (its local sends clear the
   * client event), and cleared right after the echoes. */
  if (pm_msgid[0])
    sendcmdto_set_client_event(pm_msgid, history_parse_ms(pm_timestamp));

  /* Echo outgoing PM to other members of the sender's bouncer session */
  bounce_echo_pm_to_session(sptr, acptr, CMD_PRIVATE, mytext, pm_msgid);

  /* Echo private message back to sender if they have echo-message cap */
#ifdef USE_ROCKSDB
  {
    int need_echo = feature_bool(FEAT_CAP_echo_message) && CapOwnHas(sptr, CAP_ECHOMSG);

    if (need_echo) {
      const char *echo_client_tags = cli_client_tags(sptr);
      if (echo_client_tags && *echo_client_tags && CapActive(sptr, CAP_MSGTAGS)) {
        /* Include client-only tags in echo per IRCv3 echo-message spec */
        char echo_tagbuf[4608];
        int tpos = 0;
        echo_tagbuf[0] = '@';
        tpos = 1;
        /* Client tags first */
        tpos += snprintf(echo_tagbuf + tpos, sizeof(echo_tagbuf) - tpos, "%s", echo_client_tags);
        /* Then server tags: label, msgid, time */
        if (cli_label(sptr)[0] && CapActive(sptr, CAP_LABELEDRESP) && !cli_label_responded(sptr)) {
          tpos += snprintf(echo_tagbuf + tpos, sizeof(echo_tagbuf) - tpos, ";label=%s", cli_label(sptr));
          cli_label_responded(sptr) = 1;
        }
        if (pm_msgid[0])
          tpos += snprintf(echo_tagbuf + tpos, sizeof(echo_tagbuf) - tpos, ";msgid=%s", pm_msgid);
        if (feature_bool(FEAT_CAP_server_time) && CapActive(sptr, CAP_SERVERTIME)) {
          /* The echo carries the message's one time (the stored row's),
           * not the wall clock at send. */
          char iso[40];
          history_format_iso_ms(iso, sizeof(iso),
                                pm_timestamp[0] ? history_parse_ms(pm_timestamp)
                                                : history_event_time_ms(NULL));
          tpos += snprintf(echo_tagbuf + tpos, sizeof(echo_tagbuf) - tpos,
                           ";time=%s", iso);
        }
        echo_tagbuf[tpos] = '\0';
        sendrawto_one(sptr, "%s :%s!%s@%s PRIVMSG %C :%s",
                      echo_tagbuf, cli_name(sptr), cli_user(sptr)->username,
                      cli_user(sptr)->host, acptr, mytext);
      } else {
        sendcmdto_one_tags_ext(sptr, CMD_PRIVATE, sptr, pm_msgid,
                               "%C :%s", acptr, mytext);
      }
    }
    sendcmdto_set_client_msgid(NULL);

    /* Store private message in history database (if enabled) */
    if (pm_msgid[0])
      store_private_history(sptr, acptr, mytext, HISTORY_PRIVMSG, pm_msgid, pm_timestamp,
                            cli_client_tags(sptr));
  }
#else
  {
    int need_echo = feature_bool(FEAT_CAP_echo_message) && CapOwnHas(sptr, CAP_ECHOMSG);
    if (need_echo) {
      const char *echo_client_tags = cli_client_tags(sptr);
      if (echo_client_tags && *echo_client_tags && CapActive(sptr, CAP_MSGTAGS)) {
        char echo_tagbuf[4608];
        int tpos = 0;
        echo_tagbuf[0] = '@';
        tpos = 1;
        tpos += snprintf(echo_tagbuf + tpos, sizeof(echo_tagbuf) - tpos, "%s", echo_client_tags);
        if (cli_label(sptr)[0] && CapActive(sptr, CAP_LABELEDRESP) && !cli_label_responded(sptr)) {
          tpos += snprintf(echo_tagbuf + tpos, sizeof(echo_tagbuf) - tpos, ";label=%s", cli_label(sptr));
          cli_label_responded(sptr) = 1;
        }
        if (pm_msgid[0])
          tpos += snprintf(echo_tagbuf + tpos, sizeof(echo_tagbuf) - tpos, ";msgid=%s", pm_msgid);
        if (feature_bool(FEAT_CAP_server_time) && CapActive(sptr, CAP_SERVERTIME)) {
          /* The echo carries the message's one time (the stored row's),
           * not the wall clock at send. */
          char iso[40];
          history_format_iso_ms(iso, sizeof(iso),
                                pm_timestamp[0] ? history_parse_ms(pm_timestamp)
                                                : history_event_time_ms(NULL));
          tpos += snprintf(echo_tagbuf + tpos, sizeof(echo_tagbuf) - tpos,
                           ";time=%s", iso);
        }
        echo_tagbuf[tpos] = '\0';
        sendrawto_one(sptr, "%s :%s!%s@%s PRIVMSG %C :%s",
                      echo_tagbuf, cli_name(sptr), cli_user(sptr)->username,
                      cli_user(sptr)->host, acptr, mytext);
      } else {
        sendcmdto_one_tags_ext(sptr, CMD_PRIVATE, sptr, pm_msgid,
                               "%C :%s", acptr, mytext);
      }
    }
    sendcmdto_set_client_msgid(NULL);
  }
#endif
}

/** Relay a private notice from a local user.
 * Returns an error if the user does not exist or sending to him would
 * exceed the source's free targets.  Sends an AWAY status message if
 * the target is marked as away.
 * @param[in] sptr Client that originated the message.
 * @param[in] name Nickname of target user.
 * @param[in] text %Message to relay.
 */
void relay_private_notice(struct Client* sptr, const char* name, const char* text)
{
  struct Client* acptr;
  const char* mytext = text;
  char utf8buf[BUFSIZE];
  char cutbuf[BUFSIZE];
  char pm_msgid[64];
  char pm_timestamp[32];

  assert(0 != sptr);
  assert(0 != name);
  assert(0 != text);

  /* UTF8ONLY enforcement */
  if (feature_bool(FEAT_UTF8ONLY) && !string_is_valid_utf8(text)) {
    if (feature_bool(FEAT_UTF8ONLY_STRICT)) {
      send_fail(sptr, "NOTICE", "INVALID_UTF8", NULL,
                "Message contains invalid UTF-8 and was rejected");
      return;
    }
    /* Warn mode: copy, sanitize, and use sanitized version */
    ircd_strncpy(utf8buf, text, sizeof(utf8buf) - 1);
    utf8buf[sizeof(utf8buf) - 1] = '\0';
    string_sanitize_utf8(utf8buf);
    send_warn(sptr, "NOTICE", "INVALID_UTF8", NULL,
              "Message contained invalid UTF-8 and was sanitized");
    mytext = utf8buf;
    if (EmptyString(mytext))
      return;
  }

  if (0 == (acptr = FindUser(name)))
    return;
  if ((!IsChannelService(acptr) && 
       check_target_limit(sptr, acptr, cli_name(acptr), 0)) ||
      is_silenced(sptr, acptr, 0))
    return;

  /*
   * +R check, if target is +R and we're not +r (or opered) then
   * deny the message.
   */
  if (IsAccountOnly(acptr) && !IsAccount(sptr) && !IsOper(sptr) && (acptr != sptr)) {
    send_reply(sptr, ERR_ACCOUNTONLY, cli_name(acptr), "NOTICE", cli_name(acptr));
    return;
  }

  /*
   * +D check, if target is +D and we're not opered then deny
   * the message.
   */
  if (IsPrivDeaf(acptr) && !IsOper(sptr) && (acptr != sptr)) {
    send_reply(sptr, ERR_PRIVDEAF, cli_name(acptr), "NOTICE", cli_name(acptr));
    return;
  }

  if ((IsRestrictPrivMsg(sptr) || IsCommonChansOnly(acptr)) && !IsAnOper(sptr) &&
      !common_chan_count(acptr, sptr, 1) && (sptr != acptr)) {
    send_reply(sptr, ERR_COMMONCHANSONLY, cli_name(acptr), "NOTICE");
    return;
  }

  /*
   * deliver the message
   */
  if (MyUser(acptr))
    add_target(acptr, sptr);

  /* Generate shared msgid + timestamp for alias forwarding, echo, and history */
  pm_msgid[0] = '\0';
  pm_timestamp[0] = '\0';
  if (feature_bool(FEAT_MSGID)) {
    /* msgid first, then its mint time (one time per message) */
    generate_msgid(pm_msgid, sizeof(pm_msgid));
    history_format_ms(pm_timestamp, sizeof(pm_timestamp),
                      history_event_time_ms(NULL));
  }

  /* Cut once, here (see relay_private_message); not for a service. */
  if (!IsServiceClient(acptr))
    mytext = relay_cut_to(mytext,
                          relay_dm_text_budget(sptr, MSG_NOTICE, acptr,
                                               strlen(pm_msgid), 0, 0),
                          cutbuf, sizeof(cutbuf));

  /* Alias source rewriting (see relay_private_message) */
  {
    const char *client_tags = cli_client_tags(sptr);
    struct Client *from = sptr;

    if (IsBouncerAlias(sptr) && cli_user(sptr)->alias_primary) {
      from = cli_user(sptr)->alias_primary;
      if (!MyUser(from) && !MyConnect(acptr)
          && cli_from(from) == cli_from(acptr))
        from = sptr;
    }

    if (acptr == sptr && !(feature_bool(FEAT_CAP_echo_message)
                           && CapOwnHas(sptr, CAP_ECHOMSG))) {
      /* A notice to yourself without echo-message: the delivered
       * message, unlabeled; ACK answers (see relay_private_message). */
      if (pm_msgid[0])
        sendcmdto_set_client_event(pm_msgid, history_parse_ms(pm_timestamp));
      sendcmdto_one_delivery(from, CMD_NOTICE, acptr, client_tags,
                             "%C :%s", acptr, mytext);
      sendcmdto_set_client_msgid(NULL);
    } else if (client_tags && *client_tags && MyConnect(acptr) && CapActive(acptr, CAP_MSGTAGS)) {
      if (pm_msgid[0])
        sendcmdto_set_client_event(pm_msgid, history_parse_ms(pm_timestamp));
      sendcmdto_one_client_tags(from, MSG_NOTICE, acptr, client_tags,
                                "%C :%s", acptr, mytext);
      sendcmdto_set_client_msgid(NULL);
    } else {
      /* Tag-aware send; for S2S to IRCV3AWARE peers also includes
       * @A...,C<client_tags> compact-tag prefix.  Locally minted: this
       * message's own id and time ride the wire, not whatever was last
       * parsed off the destination link -- also when an alias sends as
       * its remote primary.  A local target takes the same time on its
       * @time (see relay_private_message). */
      if (pm_msgid[0]) {
        sendcmdto_set_client_event(pm_msgid, history_parse_ms(pm_timestamp));
        sendcmdto_set_s2s_tags(history_parse_ms(pm_timestamp), pm_msgid);
      }
      sendcmdto_one_tags_with_client(from, CMD_NOTICE, acptr,
                                     pm_msgid, client_tags,
                                     "%C :%s", acptr, mytext);
      sendcmdto_set_client_msgid(NULL);
    }
  }

  /* Forward notice to all aliases of the target bouncer primary */
  bounce_forward_pm_to_aliases(sptr, acptr, NULL, CMD_NOTICE, mytext,
                               pm_msgid, history_parse_ms(pm_timestamp),
                               cli_client_tags(sptr));

  /* The session echo and the sender's own echo carry the event's time
   * (see relay_private_message). */
  if (pm_msgid[0])
    sendcmdto_set_client_event(pm_msgid, history_parse_ms(pm_timestamp));

  /* Echo outgoing notice to other members of the sender's bouncer session */
  bounce_echo_pm_to_session(sptr, acptr, CMD_NOTICE, mytext, pm_msgid);

  /* Echo private notice back to sender if they have echo-message cap */
#ifdef USE_ROCKSDB
  {
    int need_echo = feature_bool(FEAT_CAP_echo_message) && CapOwnHas(sptr, CAP_ECHOMSG);

    if (need_echo) {
      sendcmdto_one_tags_ext(sptr, CMD_NOTICE, sptr, pm_msgid,
                             "%C :%s", acptr, mytext);
    }
    sendcmdto_set_client_msgid(NULL);

    /* Store private notice in history database (if enabled) */
    if (pm_msgid[0])
      store_private_history(sptr, acptr, mytext, HISTORY_NOTICE, pm_msgid, pm_timestamp,
                            cli_client_tags(sptr));
  }
#else
  {
    int need_echo = feature_bool(FEAT_CAP_echo_message) && CapOwnHas(sptr, CAP_ECHOMSG);
    if (need_echo) {
      sendcmdto_one_tags_ext(sptr, CMD_NOTICE, sptr, pm_msgid,
                             "%C :%s", acptr, mytext);
    }
    sendcmdto_set_client_msgid(NULL);
  }
#endif
}

/** Relay a private message that arrived from a server.
 * Returns an error if the user does not exist.
 * @param[in] sptr Client that originated the message.
 * @param[in] name Nickname of target user.
 * @param[in] text %Message to relay.
 */
void server_relay_private_message(struct Client* sptr, const char* name, const char* text)
{
  struct Client* acptr;
  struct Client* from;
  const char *client_tags;
  char pm_msgid[64];
  char pm_timestamp[32];
  char fallback_of[S2S_MSGID_BUFSIZE];

  assert(0 != sptr);
  assert(0 != name);
  assert(0 != text);

  /* Save alias context before potential rewrite.
   * For S2S-relayed messages, prefer cli_s2s_client_tags(server_link)
   * — see server_relay_channel_message. */
  {
    struct Client *one = cli_from(sptr);
    const char *s2s_tags = cli_s2s_client_tags(one);
    client_tags = (s2s_tags && *s2s_tags) ? s2s_tags : cli_client_tags(sptr);
    /* A multiline fallback line (,F): see store_relayed_pm(). */
    ircd_strncpy(fallback_of, cli_s2s_fallback(one), sizeof(fallback_of));
  }
  from = sptr;

  /* Alias source rewriting: use primary's numeric for S2S.
   * The recipient's server may not understand BX C alias numerics. */
  if (IsBouncerAlias(sptr) && cli_user(sptr)->alias_primary)
    from = cli_user(sptr)->alias_primary;

  /*
   * nickname addressed?
   */
  if (0 == (acptr = findNUser(name)) || !IsUser(acptr)) {
    send_reply(sptr, SND_EXPLICIT | ERR_NOSUCHNICK, "* :Target left %s. "
	       "Failed to deliver: [%.20s]", feature_str(FEAT_NETWORK),
               text);
    return;
  }
  if (is_silenced(from, acptr, 0))
    return;

  if (MyUser(acptr))
    add_target(acptr, from);

  /* Unified msgid: pre-populate before pm_msgid generation and relay */
  if (feature_bool(FEAT_P10_MESSAGE_TAGS) && cli_from(sptr)
      && !cli_s2s_msgid(cli_from(sptr))[0])
    s2s_mint_link_event(cli_from(sptr));

  /* Generate shared msgid + timestamp for alias forwarding and history.
   * Prefer S2S msgid for federation dedup — sptr is never reassigned
   * in PM relay, so cli_from(sptr) still has the incoming S2S tags. */
  pm_msgid[0] = '\0';
  pm_timestamp[0] = '\0';
  if (feature_bool(FEAT_MSGID)) {
    const char *s2s_mid = NULL;

    if (feature_bool(FEAT_P10_MESSAGE_TAGS) && cli_from(sptr)
        && cli_s2s_msgid(cli_from(sptr))[0])
      s2s_mid = cli_s2s_msgid(cli_from(sptr));

    if (s2s_mid)
      ircd_strncpy(pm_msgid, s2s_mid, sizeof(pm_msgid));
    else
      generate_msgid(pm_msgid, sizeof(pm_msgid));

    /* One time per message: the origin's tag time when the msgid came
     * over the link, else the mint time of the msgid just generated. */
    history_format_ms(pm_timestamp, sizeof(pm_timestamp),
                      history_event_time_ms(s2s_mid ? cli_from(sptr) : NULL));
  }

  /* Per-target direction guard for split S2S delivery:
   * If target is behind the primary's server direction, keep alias numeric
   * to avoid fake direction — that server handles rewriting locally. */
  {
    struct Client *send_from = from;
    if (send_from != sptr && !MyUser(send_from) && !MyConnect(acptr)
        && cli_from(send_from) == cli_from(acptr))
      send_from = sptr;

    /* Set client msgid so local client gets @msgid= tag */
    if (pm_msgid[0])
      sendcmdto_set_client_event(pm_msgid, history_parse_ms(pm_timestamp));

    if (client_tags && *client_tags && MyConnect(acptr) && CapActive(acptr, CAP_MSGTAGS)) {
      sendcmdto_one_client_tags(send_from, MSG_PRIVATE, acptr, client_tags,
                                "%C :%s", acptr, text);
    } else if (MyConnect(acptr)) {
      sendcmdto_one_tags_ext(send_from, CMD_PRIVATE, acptr, pm_msgid,
                             "%C :%s", acptr, text);
    } else {
      /* Onward relay: the event's own msgid and time ride the wire (an
       * aware next hop takes them from the tag region, a legacy one gets
       * the bare line), else the next server mints its own.  With msgids
       * off, the inbound line's own tags are relayed. */
      sendcmdto_set_s2s_cptr(cli_from(sptr));
      if (pm_msgid[0])
        sendcmdto_set_s2s_tags(history_parse_ms(pm_timestamp), pm_msgid);
      if (fallback_of[0])
        sendcmdto_set_s2s_fallback(fallback_of);  /* pass the mark on */
      sendcmdto_one_tags_with_client(send_from, CMD_PRIVATE, acptr,
                                     pm_msgid, client_tags,
                                     "%C :%s", acptr, text);
    }

    sendcmdto_set_client_msgid(NULL);
  }

  /* Forward PM to all aliases of the target bouncer primary -- not
   * a multiline fallback line (,F): the originating server served every
   * device of the target itself (process_multiline_batch), so a copy here
   * gave a device the preview a second time. */
  if (!fallback_of[0])
    bounce_forward_pm_to_aliases(sptr, acptr, cli_from(sptr), CMD_PRIVATE, text,
                                 pm_msgid, history_parse_ms(pm_timestamp),
                                 client_tags);

#ifdef USE_ROCKSDB
  /* Store server-relayed private message in history database (if enabled) */
  if (pm_msgid[0])
    store_relayed_pm(from, acptr, text, HISTORY_PRIVMSG, pm_msgid, pm_timestamp,
                     client_tags, fallback_of);
#endif
}


/** Relay a private notice that arrived from a server.
 * Returns an error if the user does not exist.
 * @param[in] sptr Client that originated the message.
 * @param[in] name Nickname of target user.
 * @param[in] text %Message to relay.
 */
void server_relay_private_notice(struct Client* sptr, const char* name, const char* text)
{
  struct Client* acptr;
  struct Client* from;
  const char *client_tags;
  char pm_msgid[64];
  char pm_timestamp[32];
  char fallback_of[S2S_MSGID_BUFSIZE];

  assert(0 != sptr);
  assert(0 != name);
  assert(0 != text);

  /* Save alias context before potential rewrite.
   * For S2S-relayed messages, prefer cli_s2s_client_tags(server_link)
   * — see server_relay_channel_message. */
  {
    struct Client *one = cli_from(sptr);
    const char *s2s_tags = cli_s2s_client_tags(one);
    client_tags = (s2s_tags && *s2s_tags) ? s2s_tags : cli_client_tags(sptr);
    /* A multiline fallback line (,F): see store_relayed_pm(). */
    ircd_strncpy(fallback_of, cli_s2s_fallback(one), sizeof(fallback_of));
  }
  from = sptr;

  /* Alias source rewriting (see server_relay_private_message) */
  if (IsBouncerAlias(sptr) && cli_user(sptr)->alias_primary)
    from = cli_user(sptr)->alias_primary;

  /*
   * nickname addressed?
   */
  if (0 == (acptr = findNUser(name)) || !IsUser(acptr))
    return;

  if (is_silenced(from, acptr, 0))
    return;

  if (MyUser(acptr))
    add_target(acptr, from);

  /* Unified msgid: pre-populate before pm_msgid generation and relay */
  if (feature_bool(FEAT_P10_MESSAGE_TAGS) && cli_from(sptr)
      && !cli_s2s_msgid(cli_from(sptr))[0])
    s2s_mint_link_event(cli_from(sptr));

  /* Generate shared msgid + timestamp (prefer S2S msgid for federation dedup) */
  pm_msgid[0] = '\0';
  pm_timestamp[0] = '\0';
  if (feature_bool(FEAT_MSGID)) {
    const char *s2s_mid = NULL;

    if (feature_bool(FEAT_P10_MESSAGE_TAGS) && cli_from(sptr)
        && cli_s2s_msgid(cli_from(sptr))[0])
      s2s_mid = cli_s2s_msgid(cli_from(sptr));

    if (s2s_mid)
      ircd_strncpy(pm_msgid, s2s_mid, sizeof(pm_msgid));
    else
      generate_msgid(pm_msgid, sizeof(pm_msgid));

    /* One time per message: the origin's tag time when the msgid came
     * over the link, else the mint time of the msgid just generated. */
    history_format_ms(pm_timestamp, sizeof(pm_timestamp),
                      history_event_time_ms(s2s_mid ? cli_from(sptr) : NULL));
  }

  /* Per-target direction guard (see server_relay_private_message) */
  {
    struct Client *send_from = from;
    int delivered = 0;

    if (send_from != sptr && !MyUser(send_from) && !MyConnect(acptr)
        && cli_from(send_from) == cli_from(acptr))
      send_from = sptr;

    /* Set client msgid so local client gets @msgid= tag */
    if (pm_msgid[0])
      sendcmdto_set_client_event(pm_msgid, history_parse_ms(pm_timestamp));

    /* Check for forwarded label batch in DRAINING state */
    if (MyConnect(acptr) && feature_bool(FEAT_CAP_labeled_response)) {
      const char *incoming_msgid = (cli_from(sptr) && cli_s2s_msgid(cli_from(sptr))[0])
                                    ? cli_s2s_msgid(cli_from(sptr)) : "";
      struct ForwardedLabel *fl = fwd_label_find_draining(acptr, incoming_msgid);
      if (fl) {
        sendcmdto_set_fwd_batch(fl->fl_batch_id);
        sendcmdto_one_tags_ext(send_from, CMD_NOTICE, acptr, pm_msgid,
                               "%C :%s", acptr, text);
        /* Stay DRAINING -- more trailing messages may follow */
        delivered = 1;
      }
    }

    if (!delivered) {
      if (client_tags && *client_tags && MyConnect(acptr) && CapActive(acptr, CAP_MSGTAGS)) {
        sendcmdto_one_client_tags(send_from, MSG_NOTICE, acptr, client_tags,
                                  "%C :%s", acptr, text);
      } else if (MyConnect(acptr)) {
        sendcmdto_one_tags_ext(send_from, CMD_NOTICE, acptr, pm_msgid,
                               "%C :%s", acptr, text);
      } else {
        /* Onward relay under the event's own msgid and time (see
         * server_relay_private_message). */
        sendcmdto_set_s2s_cptr(cli_from(sptr));
        if (pm_msgid[0])
          sendcmdto_set_s2s_tags(history_parse_ms(pm_timestamp), pm_msgid);
        if (fallback_of[0])
          sendcmdto_set_s2s_fallback(fallback_of);  /* pass the mark on */
        sendcmdto_one_tags_with_client(send_from, CMD_NOTICE, acptr,
                                       pm_msgid, client_tags,
                                       "%C :%s", acptr, text);
      }
    }

    sendcmdto_set_client_msgid(NULL);
  }

  /* Forward notice to all aliases of the target bouncer primary -- not
   * a multiline fallback line (,F): the originating server served every
   * device of the target itself (process_multiline_batch), so a copy here
   * gave a device the preview a second time. */
  if (!fallback_of[0])
    bounce_forward_pm_to_aliases(sptr, acptr, cli_from(sptr), CMD_NOTICE, text,
                                 pm_msgid, history_parse_ms(pm_timestamp),
                                 client_tags);

#ifdef USE_ROCKSDB
  /* Store server-relayed private notice in history database (if enabled) */
  if (pm_msgid[0])
    store_relayed_pm(from, acptr, text, HISTORY_NOTICE, pm_msgid, pm_timestamp,
                     client_tags, fallback_of);
#endif
}

/** Relay a masked message from a local user.
 * Sends an error response if there is no top-level domain label in \a
 * mask, or if that TLD contains a wildcard.
 * @param[in] sptr Client that originated the message.
 * @param[in] mask Target mask for the message.
 * @param[in] text %Message to relay.
 */
void relay_masked_message(struct Client* sptr, const char* mask, const char* text)
{
  const char* s;
  int   host_mask = 0;
  char  cutbuf[BUFSIZE];

  assert(0 != sptr);
  assert(0 != mask);
  assert(0 != text);
  /*
   * look for the last '.' in mask and scan forward
   */
  if (0 == (s = strrchr(mask, '.'))) {
    send_reply(sptr, ERR_NOTOPLEVEL, mask);
    return;
  }
  while (*++s) {
    if (*s == '.' || *s == '*' || *s == '?')
       break;
  }
  if (*s == '*' || *s == '?') {
    send_reply(sptr, ERR_WILDTOPLEVEL, mask);
    return;
  }
  s = mask;
  if ('@' == *++s) {
    host_mask = 1;
    ++s;
  }

  /* Every matching user, here and on every server, gets
   * ":nick!user@host PRIVMSG <mask> :": cut the text to that line once,
   * here (relay_cut_text).  A mask so long that it leaves no room for
   * any text is refused rather than sent cut into the mask. */
  text = relay_cut_text(sptr, MSG_PRIVATE, strlen(mask), 0, text,
                        cutbuf, sizeof(cutbuf));
  if (!*text) {
    send_reply(sptr, ERR_INPUTTOOLONG);
    return;
  }

  sendcmdto_match_butone(sptr, CMD_PRIVATE, s,
			 IsServer(cli_from(sptr)) ? cli_from(sptr) : 0,
			 host_mask ? MATCH_HOST : MATCH_SERVER,
			 "%s :%s", mask, text);
}

/** Relay a masked notice from a local user.
 * Sends an error response if there is no top-level domain label in \a
 * mask, or if that TLD contains a wildcard.
 * @param[in] sptr Client that originated the message.
 * @param[in] mask Target mask for the message.
 * @param[in] text %Message to relay.
 */
void relay_masked_notice(struct Client* sptr, const char* mask, const char* text)
{
  const char* s;
  int   host_mask = 0;
  char  cutbuf[BUFSIZE];

  assert(0 != sptr);
  assert(0 != mask);
  assert(0 != text);
  /*
   * look for the last '.' in mask and scan forward
   */
  if (0 == (s = strrchr(mask, '.'))) {
    send_reply(sptr, ERR_NOTOPLEVEL, mask);
    return;
  }
  while (*++s) {
    if (*s == '.' || *s == '*' || *s == '?')
       break;
  }
  if (*s == '*' || *s == '?') {
    send_reply(sptr, ERR_WILDTOPLEVEL, mask);
    return;
  }
  s = mask;
  if ('@' == *++s) {
    host_mask = 1;
    ++s;
  }

  /* Cut here (see relay_masked_message); no room left: dropped. */
  text = relay_cut_text(sptr, MSG_NOTICE, strlen(mask), 0, text,
                        cutbuf, sizeof(cutbuf));
  if (!*text)
    return;

  sendcmdto_match_butone(sptr, CMD_NOTICE, s,
			 IsServer(cli_from(sptr)) ? cli_from(sptr) : 0,
			 host_mask ? MATCH_HOST : MATCH_SERVER,
			 "%s :%s", mask, text);
}

/** Relay a masked message that arrived from a server.
 * @param[in] sptr Client that originated the message.
 * @param[in] mask Target mask for the message.
 * @param[in] text %Message to relay.
 */
void server_relay_masked_message(struct Client* sptr, const char* mask, const char* text)
{
  const char* s = mask;
  int         host_mask = 0;
  assert(0 != sptr);
  assert(0 != mask);
  assert(0 != text);

  if ('@' == *++s) {
    host_mask = 1;
    ++s;
  }
  sendcmdto_match_butone(sptr, CMD_PRIVATE, s,
			 IsServer(cli_from(sptr)) ? cli_from(sptr) : 0,
			 host_mask ? MATCH_HOST : MATCH_SERVER,
			 "%s :%s", mask, text);
}

/** Relay a masked notice that arrived from a server.
 * @param[in] sptr Client that originated the message.
 * @param[in] mask Target mask for the message.
 * @param[in] text %Message to relay.
 */
void server_relay_masked_notice(struct Client* sptr, const char* mask, const char* text)
{
  const char* s = mask;
  int         host_mask = 0;
  assert(0 != sptr);
  assert(0 != mask);
  assert(0 != text);

  if ('@' == *++s) {
    host_mask = 1;
    ++s;
  }
  sendcmdto_match_butone(sptr, CMD_NOTICE, s,
			 IsServer(cli_from(sptr)) ? cli_from(sptr) : 0,
			 host_mask ? MATCH_HOST : MATCH_SERVER,
			 "%s :%s", mask, text);
}

