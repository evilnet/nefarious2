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
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>
#define INCLUDED_sys_types_h
#endif
#ifndef INCLUDED_stdint_h
#include <stdint.h>
#define INCLUDED_stdint_h
#endif

struct Client;

/** Maximum length of a bouncer session token (base64). */
#define BOUNCER_TOKEN_LEN       64
/** Maximum length of a session ID ("XX-NNNNN"). */
#define BOUNCER_SESSID_LEN      16
/** Maximum length of a user-assigned session name. */
#define BOUNCER_NAME_LEN        32
/** Maximum channels tracked per session. */
#define BOUNCER_MAX_CHANNELS    50
/** Maximum shadow connections per bouncer session. */
#define BOUNCER_MAX_SHADOWS     4

/** Hash table sizes for session lookups. */
#define BOUNCE_TOKEN_HASHSIZE   1024
#define BOUNCE_ACCOUNT_HASHSIZE 512

/** Session state. */
enum BouncerState {
  BOUNCE_ACTIVE,    /**< Client is connected */
  BOUNCE_HOLDING    /**< Client disconnected, session preserved */
};

/** Current version of the on-disk bouncer session record. */
#define BOUNCER_DB_VERSION 2

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
  /* Channel memberships */
  uint16_t bsr_chancount;
  struct {
    char     name[CHANNELLEN + 1];
    uint32_t modes;
  } bsr_channels[BOUNCER_MAX_CHANNELS];
};

/** Shadow connection flags. */
#define SHADOW_FLAGS_DEAD     0x0001  /**< Marked for cleanup */
#define SHADOW_FLAGS_BLOCKED  0x0002  /**< Write blocked (sendQ full) */
#define SHADOW_FLAGS_PINGSENT 0x0004  /**< PING sent, awaiting PONG */

/** Shadow connection — a secondary TCP connection sharing a bouncer session's identity.
 *
 * Shadows piggyback on the "real" Client (the primary connection). They have
 * their own socket, sendQ, recvQ, and CAP state, but are NOT in the nick hash,
 * NOT in channel lists, and have NO P10 numeric.
 *
 * Outbound messages to the primary are duplicated to all shadows (respecting
 * per-shadow CAP filtering). Inbound commands from shadows are forwarded
 * through the primary's handler chain.
 */
struct ShadowConnection {
  struct ShadowConnection *sh_next;     /**< Next shadow in session list */
  unsigned int             sh_id;       /**< Client ID (unique within session) */
  int                      sh_fd;       /**< File descriptor */
  struct Socket            sh_socket;   /**< Physical socket */
  struct MsgQ              sh_sendQ;    /**< Outgoing message queue */
  struct DBuf              sh_recvQ;    /**< Incoming data buffer */
  unsigned int             sh_count;    /**< Bytes in parse buffer */
  char                     sh_buffer[BUFSIZE]; /**< Parse buffer */
  struct CapSet            sh_capab;    /**< Negotiated capabilities (from us) */
  struct CapSet            sh_active;   /**< Active capabilities (to us) */
  unsigned short           sh_capab_version; /**< CAP version */
  char                     sh_label[64]; /**< Current labeled-response label */
  unsigned char            sh_label_responded; /**< Whether response sent for label */
  struct BouncerSession   *sh_session;  /**< Back-pointer to owning session */
  time_t                   sh_lasttime; /**< Last data read from socket */
  time_t                   sh_since;    /**< Last command accepted */
  time_t                   sh_connected; /**< When this shadow connected */
  unsigned char            sh_away_state; /**< Per-connection away: 0=present, 1=away, 2=away-star */
  char                     sh_away_msg[AWAYLEN + 1]; /**< Per-connection away message */
  unsigned int             sh_flags;    /**< Shadow-specific flags */
  char                     sh_sock_ip[SOCKIPLEN + 1]; /**< Remote IP as string */
};

/** Channel membership preserved in a held session. */
struct BounceChannel {
  char name[CHANNELLEN + 1];
  unsigned int modes;         /**< CHFL_CHANOP, CHFL_VOICE, etc. */
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

  /** Shadow connection list (secondary TCP connections sharing this session). */
  struct ShadowConnection *hs_shadows; /**< Linked list of shadow connections */
  int hs_shadow_count;                 /**< Number of attached shadows */
  unsigned int hs_client_id_seq;       /**< Monotonic counter for client IDs */
  unsigned int hs_primary_id;          /**< Client ID of the primary connection */

  struct BounceChannel hs_channels[BOUNCER_MAX_CHANNELS];
  int hs_chancount;

  int hs_effective_away;               /**< Last computed effective away: 0=present, 1=away, 2=all-star */
  char hs_effective_away_msg[AWAYLEN + 1]; /**< Last effective away message */

  int hs_dirty;                       /**< Session state changed, needs periodic persist */

  time_t hs_created;                  /**< When session was created */
  time_t hs_last_active;              /**< Last activity timestamp */
  time_t hs_disconnect_time;          /**< When client disconnected (0=active) */
  unsigned int hs_attach_count;       /**< Number of times resumed from HOLDING */
  unsigned int hs_connect_count;      /**< Total connections (resumes + shadow attaches) */
  time_t hs_total_active;             /**< Cumulative active time (seconds) */
  struct Timer hs_hold_timer;         /**< Expiry timer for HOLDING state */
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

/*
 * Shadow connection API (multi-client support)
 */

/** Add a shadow connection to a bouncer session.
 * The shadow gets its own socket/sendQ/CAP state but shares the session's
 * IRC identity (nick, channels, modes).
 * @param[in] session Active bouncer session.
 * @param[in] fd File descriptor of the new connection.
 * @param[in] sock_ip Remote IP address as string.
 * @return Pointer to new ShadowConnection, or NULL on error.
 */
extern struct ShadowConnection *bounce_add_shadow(struct BouncerSession *session,
                                                   int fd,
                                                   const char *sock_ip);

/** Remove a shadow connection from its session.
 * Cleans up the shadow's sendQ, recvQ, socket, and removes it from the list.
 * @param[in] shadow Shadow connection to remove.
 */
extern void bounce_remove_shadow(struct ShadowConnection *shadow);

/** Promote the first shadow to primary connection.
 * Called when the primary connection disconnects but shadows remain.
 * Transplants the shadow's socket into the Client's Connection struct.
 * @param[in] session Session whose primary disconnected.
 * @return 0 on success, -1 if no shadows available.
 */
extern int bounce_promote_shadow(struct BouncerSession *session);

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

/** Get the total number of connections (primary + shadows) for a session.
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

/** Send IRC registration welcome sequence to a newly attached shadow.
 * @param[in] shadow The newly created shadow connection.
 */
extern void bounce_send_shadow_welcome(struct ShadowConnection *shadow);

/** Replay channel state (JOIN/TOPIC/NAMES) to a client after held session resume.
 * @param[in] cptr Client that just resumed a held session.
 */
extern void bounce_send_channel_state(struct Client *cptr);

/** Build a union CapSet from primary + all shadow active capabilities.
 * Used to format outbound messages with the maximal set of tags any
 * connection might need. send_buffer() then strips per-connection.
 * @param[in] session Bouncer session.
 * @param[out] out CapSet to populate with the union of all connections' caps.
 */
extern void bounce_build_union_caps(struct BouncerSession *session,
                                     struct CapSet *out);

/** Global pointer to the shadow connection that originated the current command.
 * Single-threaded IRCd, so a global is safe. Used for reply routing:
 * when a shadow sends a command, replies should go to the shadow, not the primary.
 * NULL when the primary (or no shadow) is the source.
 */
extern struct ShadowConnection *current_shadow;

/** Check if the *receiving* connection has a capability.
 * When current_shadow is set, checks the shadow's caps.
 * Otherwise checks the primary's own caps (not the session union).
 * Use this for format-sensitive decisions where the wire format must
 * match the actual recipient's negotiated capabilities.
 * @param[in] cli The primary client.
 * @param[in] cap The capability to check.
 * @return Non-zero if the receiving connection has the capability.
 */
#define CapRecipientHas(cli, cap) \
  (current_shadow ? CapHas(&current_shadow->sh_active, (cap)) \
                  : CapHas(cli_active_own(cli), (cap)))

/** Recompute cli_active as the union of all session connections' caps.
 * Called after any cap change on primary or shadow, and on shadow
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

/*
 * Utility
 */

/** Replay missed messages for a resumed session (legacy clients).
 * @param[in] sptr Client to replay to.
 * @param[in] session Session with disconnect timestamp.
 */
extern void bouncer_auto_replay(struct Client *sptr,
                                 struct BouncerSession *session);

/** Compute adaptive hold time for a session.
 * @param[in] session Session to compute for.
 * @return Hold time in seconds.
 */
extern time_t bounce_compute_hold_time_ext(struct BouncerSession *session);

/** Check if bouncer feature is enabled. */
extern int bounce_enabled(void);

/** Check if a bouncer session has any non-TLS connection.
 * Returns 1 if any connection (primary or shadow) lacks TLS.
 * Returns 0 for non-bouncer clients or if all connections are TLS.
 */
extern int bounce_session_has_plaintext(struct Client *cptr);

/** Check shadow liveness — send PINGs and timeout dead shadows.
 * Called from check_pings() for bouncer primaries.
 * @param[in] cptr Primary client of bouncer session.
 * @param[in] max_ping Ping interval in seconds.
 */
extern void bounce_check_shadow_pings(struct Client *cptr, int max_ping);

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
 * @return 1 if resumed, 0 otherwise.
 */
extern int bounce_auto_resume(struct Client *cptr,
                               struct BouncerSession **out_session);

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
