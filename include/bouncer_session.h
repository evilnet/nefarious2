/*
 * IRC - Internet Relay Chat, include/bouncer_session.h
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
 * @brief Built-in bouncer session management.
 *
 * Implements persistent IRC sessions that survive disconnection.
 * Sessions are BURST'd between servers via P10, following the same
 * distributed model as nicks and channels.
 */
#ifndef INCLUDED_bouncer_session_h
#define INCLUDED_bouncer_session_h

#ifndef INCLUDED_ircd_defs_h
#include "ircd_defs.h"
#endif
#ifndef INCLUDED_ircd_events_h
#include "ircd_events.h"
#endif
#ifndef INCLUDED_capab_h
#include "capab.h"
#endif
#ifndef INCLUDED_dbuf_h
#include "dbuf.h"
#endif
#ifndef INCLUDED_msgq_h
#include "msgq.h"
#endif
#ifndef INCLUDED_res_h
#include "res.h"
#endif
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>
#define INCLUDED_sys_types_h
#endif
#ifndef INCLUDED_stdint_h
#include <stdint.h>
#define INCLUDED_stdint_h
#endif

struct Channel;
struct Client;
struct Listener;

/** Maximum length of a bouncer session token (base64). */
#define BOUNCER_TOKEN_LEN       64
/** Maximum length of a session ID ("XX-NNNNN"). */
#define BOUNCER_SESSID_LEN      16
/** Maximum length of a user-assigned session name. */
#define BOUNCER_NAME_LEN        32
/** Maximum channels tracked per session. */
#define BOUNCER_MAX_CHANNELS    50
/** Maximum alias numerics per bouncer session (multi-server presence). */
#define BOUNCER_MAX_ALIASES     4
/** Maximum connection history entries per session (unique hosts). */
#define BOUNCER_MAX_CONN_HISTORY 10

/** Hash table sizes for session lookups. */
#define BOUNCE_TOKEN_HASHSIZE   1024
#define BOUNCE_ACCOUNT_HASHSIZE 512

/** Session state. */
enum BouncerState {
  BOUNCE_ACTIVE,    /**< Client is connected */
  BOUNCE_HOLDING,   /**< Client disconnected, session preserved */
  BOUNCE_DESTROYING /**< Timer expired, awaiting ET_DESTROY to free */
};

/** A single connection history entry (deduped by IP). */
struct BounceConnHistory {
  char     bch_ip[SOCKIPLEN + 1];    /**< Remote IP as string */
  char     bch_host[HOSTLEN + 1];    /**< Resolved hostname */
  int64_t  bch_last_connect;         /**< Last connect timestamp */
  int64_t  bch_last_disconnect;      /**< Last disconnect timestamp (0=still connected) */
  uint32_t bch_count;                /**< Number of connections from this host */
};

/** Current version of the on-disk bouncer session record. */
#define BOUNCER_DB_VERSION 7

/** On-disk representation of a bouncer session for MDBX persistence.
 * Fixed-width, versioned. All IRC identifiers have known max lengths.
 */
struct BounceSessionRecord {
  uint32_t bsr_version;
  /* Session identity */
  char     bsr_account[ACCOUNTLEN + 1];
  char     bsr_sessid[BOUNCER_SESSID_LEN];
  char     bsr_token[BOUNCER_TOKEN_LEN + 1];
  char     bsr_name[BOUNCER_NAME_LEN];
  char     bsr_origin[NICKLEN + 1];        /**< Server numeric that created this */
  int32_t  bsr_hold_override;
  /* Timestamps */
  int64_t  bsr_created;
  int64_t  bsr_disconnect_time;
  int64_t  bsr_last_active;
  int64_t  bsr_last_msg_time;              /**< Last PRIVMSG time (user idle) */
  int64_t  bsr_total_active;
  uint32_t bsr_attach_count;
  uint32_t bsr_connect_count;
  /* Ghost client identity */
  char     bsr_nick[NICKLEN + 1];
  char     bsr_username[USERLEN + 1];
  char     bsr_realhost[HOSTLEN + 1];
  char     bsr_host[HOSTLEN + 1];          /**< Displayed/hidden host */
  char     bsr_realname[REALLEN + 1];
  char     bsr_account_name[ACCOUNTLEN + 1];
  int64_t  bsr_acc_create;
  /* Last connection metadata (historical, reconciled on revive) */
  struct irc_in_addr bsr_ip;                /**< Last connection IP (binary) */
  char     bsr_sock_ip[SOCKIPLEN + 1];      /**< Last connection IP (string) */
  char     bsr_sockhost[HOSTLEN + 1];       /**< Last resolved hostname */
  uint16_t bsr_listener_port;               /**< Server listener port */
  /* Session-level aggregate counters (lifetime totals from dead connections) */
  uint64_t bsr_agg_sendB;
  uint64_t bsr_agg_receiveB;
  uint32_t bsr_agg_sendM;
  uint32_t bsr_agg_receiveM;
  /* Connection history (unique hosts, most recent first) */
  uint16_t bsr_histcount;
  struct BounceConnHistory bsr_history[BOUNCER_MAX_CONN_HISTORY];
  /* Channel memberships */
  uint16_t bsr_chancount;
  struct {
    char     name[CHANNELLEN + 1];
    uint32_t modes;
    int64_t  join_tv_sec;       /**< Original JOIN time (seconds) */
    int32_t  join_tv_usec;      /**< Original JOIN time (microseconds) */
    char     join_msgid[16];    /**< Original JOIN msgid */
  } bsr_channels[BOUNCER_MAX_CHANNELS];
};

/** Channel membership preserved in a held session. */
struct BounceChannel {
  char name[CHANNELLEN + 1];
  unsigned int modes;         /**< CHFL_CHANOP, CHFL_VOICE, etc. */
  int64_t  join_tv_sec;       /**< Original JOIN time (seconds) */
  int32_t  join_tv_usec;      /**< Original JOIN time (microseconds) */
  char     join_msgid[16];    /**< Original JOIN msgid */
};

/** Tracks an alias numeric for multi-server bouncer presence. */
struct BounceAlias {
  char ba_numeric[6];       /**< Alias P10 numeric (YYXXX) */
  char ba_server[3];        /**< Server numeric hosting this alias (YY) */
};

/** A single bouncer session.
 *
 * Each session represents one logical connection to the IRC network.
 * Sessions are stored in two hash tables: by token (for RESUME lookups)
 * and by account (for per-account enumeration and limits).
 */
struct BouncerSession {
  struct BouncerSession *hs_tnext;    /**< Next in token hash chain */
  struct BouncerSession *hs_anext;    /**< Next in account session list */
  struct BouncerSession **hs_aprev_p; /**< Prev pointer for O(1) removal */

  char hs_account[ACCOUNTLEN + 1];    /**< Owning account name */
  char hs_sessid[BOUNCER_SESSID_LEN]; /**< Session ID (server-numeric + seq) */
  char hs_token[BOUNCER_TOKEN_LEN+1]; /**< Session token (base64) */
  char hs_name[BOUNCER_NAME_LEN];     /**< User-assigned name */

  enum BouncerState hs_state;         /**< Current state */
  struct Client *hs_client;           /**< Connected client (ghost if HOLDING) */
  char hs_origin[NICKLEN + 1];        /**< Server numeric that created this */
  char hs_ghost_numeric[6];           /**< Ghost client numeric during HOLDING */

  int hs_hold_override;               /**< -1=use default, 0=no hold, 1=hold */

  struct BounceChannel hs_channels[BOUNCER_MAX_CHANNELS];
  int hs_chancount;

  /** Alias numerics for multi-server presence. */
  struct BounceAlias hs_aliases[BOUNCER_MAX_ALIASES];
  int hs_alias_count;

  int hs_promoting;                    /**< Nonzero during SQUIT promotion (suppresses alias sync) */

  int hs_effective_away;               /**< Last computed effective away: 0=present, 1=away, 2=all-star */
  char hs_effective_away_msg[AWAYLEN + 1]; /**< Last effective away message */

  int hs_dirty;                       /**< Session state changed, needs periodic persist */

  time_t hs_created;                  /**< When session was created */
  time_t hs_last_active;              /**< Last activity timestamp */
  time_t hs_last_msg_time;            /**< Last PRIVMSG time (user idle baseline) */
  time_t hs_disconnect_time;          /**< When client disconnected (0=active) */
  unsigned int hs_attach_count;       /**< Number of times resumed from HOLDING */
  unsigned int hs_connect_count;      /**< Total connections (resumes + alias attaches) */
  time_t hs_total_active;             /**< Cumulative active time (seconds) */
  struct Timer hs_hold_timer;         /**< Expiry timer for HOLDING state */

  /* Session-level aggregate counters (lifetime totals from dead connections) */
  uint64_t     hs_agg_sendB;         /**< Lifetime bytes sent (dead connections) */
  uint64_t     hs_agg_receiveB;      /**< Lifetime bytes received (dead connections) */
  unsigned int hs_agg_sendM;         /**< Lifetime messages sent (dead connections) */
  unsigned int hs_agg_receiveM;      /**< Lifetime messages received (dead connections) */

  /* Connection history (unique hosts, most recent first) */
  int hs_histcount;
  struct BounceConnHistory hs_history[BOUNCER_MAX_CONN_HISTORY];
};

/** Per-account session list for enumeration and limit enforcement. */
struct AccountSessions {
  struct AccountSessions *as_hnext;   /**< Hash chain */
  char as_account[ACCOUNTLEN + 1];    /**< Account name */
  struct BouncerSession *as_sessions; /**< Linked list of sessions */
  int as_count;                       /**< Number of sessions */
};

/*
 * Session registry API
 */

/** Initialize the bouncer session subsystem. */
extern void bounce_init(void);

/** Create a new session for an authenticated client.
 * @param[in] cptr Client creating the session.
 * @param[out] session Pointer to created session (on success).
 * @return 0 on success, -1 on error (limit reached, not authenticated, etc.)
 */
extern int bounce_create(struct Client *cptr, struct BouncerSession **session);

/** Look up a session by its token.
 * @param[in] token Session token string.
 * @return Session pointer, or NULL if not found/expired.
 */
extern struct BouncerSession *bounce_find_by_token(const char *token);

/** Look up sessions for an account.
 * @param[in] account Account name.
 * @return AccountSessions pointer, or NULL if no sessions.
 */
extern struct AccountSessions *bounce_find_by_account(const char *account);

/** Walk every session known to this server and invoke a callback.
 * Callback must not destroy, rehash, or free the session being visited.
 * @param[in] cb   Callback invoked once per session.
 * @param[in] data Opaque pointer passed through to callback.
 */
extern void bounce_walk_sessions(void (*cb)(struct BouncerSession *,
                                            void *),
                                 void *data);

/** Sync alias join: when primary joins a channel, add local aliases.
 * Called from add_user_to_channel() for non-alias members.
 * @param[in] chptr Channel the primary just joined.
 * @param[in] who   The primary client.
 */
extern void bounce_sync_alias_join(struct Channel *chptr, struct Client *who);

/** Sync alias part: when primary leaves a channel, remove local aliases.
 * Called from remove_user_from_channel() for non-alias members.
 * @param[in] chptr Channel the primary is leaving.
 * @param[in] who   The primary client.
 */
extern void bounce_sync_alias_part(struct Channel *chptr, struct Client *who);

/** Sync channel mode flags (op/halfop/voice) from primary to all aliases.
 * Called after a primary's channel membership status changes.
 */
extern void bounce_sync_alias_chanmodes(struct Channel *chptr, struct Client *primary);

/** Send post-join replies (TOPIC/MARKREAD/NAMES) to local aliases after JOIN echo. */
extern void bounce_send_alias_join_replies(struct Channel *chptr, struct Client *who);

/** Forward a PM/NOTICE to all aliases of the target bouncer primary.
 * @param[in] from    Client that sent the message.
 * @param[in] target  Target client (primary).
 * @param[in] cmd     Long command name (MSG_PRIVATE or MSG_NOTICE).
 * @param[in] tok     Short command token (TOK_PRIVATE or TOK_NOTICE).
 * @param[in] text    Message text.
 */
extern void bounce_forward_pm_to_aliases(struct Client *from,
    struct Client *target, const char *cmd, const char *tok,
    const char *text, const char *msgid);

/** Remove an alias from its session replica's hs_aliases[].
 * Safe to call even if the alias is not found (no-op).
 * Uses the alias's own account (not primary's) to avoid use-after-free.
 * @param[in] alias The alias client being destroyed.
 */
extern void bounce_alias_untrack(struct Client *alias);

/** Free any BX M (multiline alias echo) batches buffered against \a link.
 * Called from exit_one_client when a directly-connected server exits,
 * so partially-accumulated batches whose terminating BX M- token will
 * never arrive don't leak their slots in s2s_bxm_batches[].
 */
extern void s2s_bxm_cleanup_link(struct Client *link);

/** Broadcast BX U identity updates to all aliases when primary changes.
 * @param[in] primary The primary client whose identity changed.
 * @param[in] field   Field name (host, realname, fakehost, etc.).
 * @param[in] value   New value for the field.
 */
extern void bounce_emit_alias_update(struct Client *primary,
    const char *field, const char *value);

/** Synchronize user mode flags from a primary to all its aliases.
 * Call after mode changes on the primary so aliases stay in sync.
 * @param[in] primary The primary client whose modes changed.
 */
extern void bounce_sync_alias_umodes(struct Client *primary);

/** Echo an outgoing PM/NOTICE to all other members of the sender's session.
 * @param[in] sender  Client that sent the PM (primary or alias).
 * @param[in] target  PM recipient (external user).
 * @param[in] cmd     Long command name (e.g. "PRIVMSG").
 * @param[in] tok     Short command token (e.g. "P").
 * @param[in] text    Message text.
 * @param[in] msgid   Message ID for tags (may be NULL or empty).
 */
extern void bounce_echo_pm_to_session(struct Client *sender,
    struct Client *target, const char *cmd, const char *tok,
    const char *text, const char *msgid);

/** Prepare bouncer sessions for SQUIT promotion.
 * Called BEFORE exit_downlinks(). Marks sessions needing promotion,
 * removes departing server's alias entries from session replicas.
 * @param[in] server The departing server.
 */
extern void bounce_prepare_squit_promotions(struct Client *server);

/** Execute SQUIT promotions for bouncer sessions.
 * Called AFTER exit_downlinks(). Promotes winning aliases,
 * restores mode flags, broadcasts BX P + BS T.
 * @param[in] server The departing server.
 */
extern void bounce_execute_squit_promotions(struct Client *server);

/** Promote an alias to primary for a bouncer session.
 * Used by disconnect handlers and SQUIT promotion.
 * @param[in] session Session whose primary is departing.
 * @return 0 on success, -1 if no aliases available.
 */
extern int bounce_promote_alias(struct BouncerSession *session);

/** Attach a client to an existing session (resume).
 * @param[in] session Session to attach to.
 * @param[in] cptr Client to attach.
 * @return 0 on success, -1 on error.
 */
extern int bounce_attach(struct BouncerSession *session, struct Client *cptr);

/** Detach a client from its session (disconnect, entering HOLDING).
 * @param[in] session Session to detach.
 * @return 0 on success.
 */
extern int bounce_detach(struct BouncerSession *session);

/** Destroy a session entirely.
 * @param[in] session Session to destroy.
 */
extern void bounce_destroy(struct BouncerSession *session);

/** Set a session's user-assigned name.
 * @param[in] session Session to rename.
 * @param[in] name New name.
 */
extern void bounce_setname(struct BouncerSession *session, const char *name);

/** Save current channel memberships into a session.
 * Called when a client disconnects and enters HOLDING.
 * @param[in] session Session to update.
 * @param[in] cptr Client whose channels to snapshot.
 */
extern void bounce_snapshot_channels(struct BouncerSession *session,
                                     struct Client *cptr);

/** Find the bouncer session for a client (if any).
 * @param[in] cptr Client to look up.
 * @return Session pointer, or NULL if client has no bouncer session.
 */
extern struct BouncerSession *bounce_get_session(struct Client *cptr);

/** Find any session for an account (ACTIVE or HOLDING).
 * Unlike bounce_find_best_held(), this returns any session.
 * @param[in] account Account name.
 * @return Session pointer, or NULL if no sessions.
 */
extern struct BouncerSession *bounce_find_any_session(const char *account);

/** Get the total number of connections (primary + aliases) for a session.
 * @param[in] session Session to query.
 * @return Number of connections (0 if HOLDING, 1+ if ACTIVE).
 */
extern int bounce_connection_count(struct BouncerSession *session);

/** Compute effective away state across all session connections.
 * @param[in] session Bouncer session.
 * @param[out] effective_state 0=present, 1=away, 2=away-star-only.
 * @param[out] effective_msg Effective away message buffer (AWAYLEN+1).
 * @return 1 if effective state changed, 0 if unchanged.
 */
extern int bounce_compute_effective_away(struct BouncerSession *session,
                                          int *effective_state,
                                          char *effective_msg);

/** Re-aggregate effective away state across a session and broadcast
 * (channel away-notify + S2S AWAY) if the effective state or message
 * changed. Mirrors the result onto cli_user->away of every local
 * session connection. Call when session membership changes (alias
 * attach, detach, ghost revive) so the network-visible away tracks
 * connection presence without requiring a fresh /away.
 *
 * @param[in] session Session to re-aggregate.
 */
extern void bounce_recompute_session_away(struct BouncerSession *session);

/** Replay channel state (JOIN/TOPIC/NAMES) to a client after held session resume.
 * @param[in] cptr Client that just resumed a held session.
 */
extern void bounce_send_channel_state(struct Client *cptr);

/** Build a union CapSet from primary + all alias active capabilities.
 * Used to format outbound messages with the maximal set of tags any
 * connection might need. send_buffer() then strips per-connection.
 * @param[in] session Bouncer session.
 * @param[out] out CapSet to populate with the union of all connections' caps.
 */
extern void bounce_build_union_caps(struct BouncerSession *session,
                                     struct CapSet *out);

/** Check if the *receiving* connection has a capability.
 * With aliases, each connection is a full Client, so this simply
 * checks the client's own active caps.
 * @param[in] cli The client.
 * @param[in] cap The capability to check.
 * @return Non-zero if the client has the capability.
 */
#define CapRecipientHas(cli, cap) CapOwnHas(cli, cap)

/** Recompute cli_active as the union of all session connections' caps.
 * Called after any cap change on primary or alias, and on alias
 * attach/detach.  For non-bouncer clients this is a no-op.
 * @param[in] primary The primary client.
 */
extern void bounce_recompute_session_caps(struct Client *primary);

/*
 * P10 BURST / sync API
 */

/** Send all sessions as BS C messages during server BURST.
 * @param[in] cptr Server to burst to.
 */
extern void bounce_burst(struct Client *cptr);

/** Handle incoming BS P10 message from another server.
 * @param[in] cptr Connected server.
 * @param[in] sptr Source server.
 * @param[in] parc Parameter count.
 * @param[in] parv Parameters.
 * @return 0 on success.
 */
extern int bounce_handle_bs(struct Client *cptr, struct Client *sptr,
                            int parc, char *parv[]);

/** Handle incoming BT (Bouncer Transfer) P10 message.
 * Transfers channel memberships from old client to new client for
 * cross-server resume.
 * @param[in] cptr Connected server.
 * @param[in] sptr Source server.
 * @param[in] parc Parameter count.
 * @param[in] parv Parameters.
 * @return 0 on success.
 */
extern int bounce_handle_bt(struct Client *cptr, struct Client *sptr,
                            int parc, char *parv[]);

/** Initiate a cross-server bouncer transfer.
 * Broadcasts BT to network to transfer ghost channels to new client.
 * @param[in] session The bouncer session.
 * @param[in] new_client The new client that is resuming.
 * @param[in] old_numeric The numeric of the ghost client to transfer from.
 */
extern void bounce_initiate_transfer(struct BouncerSession *session,
                                     struct Client *new_client,
                                     const char *old_numeric);

/** Broadcast a session state change to all other servers.
 * @param[in] session The session that changed.
 * @param[in] subcmd BS subcommand character ('C', 'A', 'D', 'X', 'U').
 * @param[in] extra Optional extra parameter (client numeric, timestamp, etc.)
 */
extern void bounce_broadcast(struct BouncerSession *session, char subcmd,
                             const char *extra);

/*
 * Hold mode API (Phase 2)
 */

/** Transition a client to bouncer HOLDING state.
 * Called when a disconnection is detected for a client with an active session.
 * - Sets client FLAG_BOUNCER_HOLD
 * - Closes the socket but keeps client structure alive
 * - Marks channel memberships as CHFL_HOLDING
 * - Suppresses QUIT message to channels
 * - Broadcasts BS D to other servers
 * @param[in] cptr Client to transition to hold.
 * @param[in] comment Disconnect reason (not sent to channels).
 * @return 0 on success (client is now a ghost), -1 if should exit normally.
 */
extern int bounce_hold_client(struct Client *cptr, const char *comment);

/** Check if a client has an active bouncer session and should enter hold.
 * @param[in] cptr Client to check.
 * @return Session pointer if should hold, NULL if should exit normally.
 */
extern struct BouncerSession *bounce_should_hold(struct Client *cptr);

/** Revive a held ghost client by transplanting a socket from a temp client.
 *
 * Instead of creating a new client and transferring channels, this
 * transplants the temp client's socket directly onto the ghost Client.
 * The ghost "wakes up" with no network visibility — no NICK, no QUIT.
 *
 * For same-server resume only. Cross-server uses transfer protocol.
 *
 * @param[in] session Session to revive (must be HOLDING with local ghost).
 * @param[in] temp Temp client whose socket will be transplanted.
 *                 Socket is stolen; call bounce_free_temp_client() after.
 * @return 0 on success, -1 on error.
 */
extern int bounce_revive(struct BouncerSession *session, struct Client *temp);

/** Free a temporary client after socket transplant.
 *
 * Called after bounce_revive() succeeds. Frees the temp client without
 * sending network messages (it was never introduced) or closing the fd
 * (it was stolen by bounce_revive).
 *
 * @param[in] temp Temporary client to free.
 */
extern void bounce_free_temp_client(struct Client *temp);

/** Rebind a held local ghost to be a remote primary on another server.
 *
 * Called from ms_nick() when an N introduction from a server collides with
 * a held ghost representing the same logical user (same account). Avoids
 * the destructive P10 nick-collision path which would kill both the ghost
 * and the incoming primary because they share user@host.
 *
 * The ghost's Client struct is reused, so channel memberships, msgids,
 * etc. are preserved — no QUIT to channels, no JOIN echo. Ownership,
 * numeric, identity and flags are updated to match the introduced primary.
 *
 * @param[in] ghost  Held ghost client (FLAG_BOUNCER_HOLD set, MyConnect).
 * @param[in] server Server introducing the primary (cli_user->server target).
 * @param[in] new_numeric YXXXX numeric assigned by introducing server.
 * @param[in] new_lastnick Timestamp from N parv[3].
 * @param[in] username Username from N parv[4].
 * @param[in] host     Host from N parv[5].
 * @param[in] new_ip   IP from N parv[parc-3] (NULL = keep ghost's).
 * @param[in] info     Realname from N parv[parc-1].
 * @return 0 on success, -1 on failure (caller should fall through to
 *         existing collision logic).
 */
extern int bounce_rebind_ghost_to_remote_primary(struct Client *ghost,
                                                 struct Client *server,
                                                 const char *new_numeric,
                                                 time_t new_lastnick,
                                                 const char *username,
                                                 const char *host,
                                                 const struct irc_in_addr *new_ip,
                                                 const char *info);

/*
 * Utility
 */


/** Compute adaptive hold time for a session.
 * @param[in] session Session to compute for.
 * @return Hold time in seconds.
 */
extern time_t bounce_compute_hold_time_ext(struct BouncerSession *session);

/** Check if bouncer feature is enabled. */
extern int bounce_enabled(void);

/** Check if bouncer is enabled for a specific client (class flag or global). */
extern int bounce_enabled_for(struct Client *cptr);

/** Check if a bouncer session has any non-TLS connection.
 * Returns 1 if any connection (primary or alias) lacks TLS.
 * Returns 0 for non-bouncer clients or if all connections are TLS.
 */
extern int bounce_session_has_plaintext(struct Client *cptr);

/** Get the number of sessions for an account. */
extern int bounce_count(const char *account);

/** Check if an account has any bouncer sessions (ACTIVE or HOLDING).
 * @param[in] account Account name.
 * @return 1 if the account has sessions, 0 otherwise.
 */
extern int bounce_has_sessions(const char *account);

/** Find the best HOLDING session for an account.
 * Prefers local ghosts and most recently disconnected.
 * @param[in] account Account name.
 * @return Session pointer, or NULL if no held sessions.
 */
extern struct BouncerSession *bounce_find_best_held(const char *account);

/** SASL-triggered automatic resume.
 * If account has a held session, resumes it. Otherwise auto-creates one.
 * Called from register_user() before network introduction.
 * @param[in] cptr Newly authenticated client.
 * @param[out] out_session Set to session if resumed or created.
 * @param[out] out_since_time Set to the user's idle time (user->last) for
 *             replay, falling back to disconnect time if unavailable.
 * @return 1 if resumed,
 *         4 if remote alias path selected (caller must call bounce_setup_local_alias),
 *         5 if local alias path selected (caller must call bounce_setup_local_alias),
 *         0 otherwise.
 */
#define BOUNCE_RESUME_NONE           0
#define BOUNCE_RESUME_HELD           1
#define BOUNCE_RESUME_ALIAS_REMOTE   4
#define BOUNCE_RESUME_ALIAS_LOCAL    5
#define BOUNCE_RESUME_REJECT_DUPLICATE 6
extern int bounce_auto_resume(struct Client *cptr,
                               struct BouncerSession **out_session,
                               time_t *out_since_time);

/** Set up a local alias for a remote bouncer session.
 * Called from register_user() when bounce_auto_resume() returns
 * BOUNCE_RESUME_ALIAS_REMOTE.  Converts the registering client into
 * a first-class alias: own numeric, channels mirrored from primary
 * with CHFL_ALIAS, BX C broadcast to network.
 * @param[in] sptr The registering client (will be converted in place).
 * @param[in] session The remote session to alias into.
 * @return 0 on success, -1 on failure (caller should fall through to normal registration).
 */
extern int bounce_setup_local_alias(struct Client *sptr,
                                     struct BouncerSession *session);

/*
 * MDBX persistence API (FEAT_BOUNCER_PERSIST)
 */

/** Restore bouncer sessions from MDBX after restart.
 * Creates ghost clients, joins them to channels, registers sessions in hash tables.
 * Called from ircd.c after bounce_init() and metadata_lmdb_init().
 * @return Number of sessions restored, or -1 on error.
 */
extern int bounce_db_restore(void);

/** Persist all local bouncer sessions to MDBX before shutdown.
 * Snapshots ACTIVE sessions and writes all local sessions.
 * Called from server_die()/server_restart() before flush_connections().
 */
extern void bounce_db_shutdown(void);

/** Mark a bouncer session as dirty (needs periodic persist).
 * Called from channel.c on JOIN/PART/KICK and MODE changes that affect
 * channel membership state. The periodic persist timer will snapshot
 * and persist dirty sessions.
 * @param[in] cptr Client whose session to mark dirty.
 */
extern void bounce_mark_dirty(struct Client *cptr);

#endif /* INCLUDED_bouncer_session_h */
