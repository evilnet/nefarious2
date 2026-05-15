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
/** Maximum length of a session ID.  Current: 22-char base64 of UUID v7
 * raw bytes (22 chars + null + slack).  Buffer is sized to also fit the
 * legacy 36-char hyphenated form so old persisted records load without
 * truncation.  v7 used "XX-NNNNN" (server-prefixed — replaced for
 * global uniqueness per redesign A.1). */
#define BOUNCER_SESSID_LEN      40
/** Maximum length of a session ID in the v7 on-disk format ("XX-NNNNN").
 * Used only by the historical-record migration path.  Do not use for
 * new code — use BOUNCER_SESSID_LEN for the v8/current format. */
#define BOUNCER_SESSID_V7_LEN   16
/** Maximum length of a user-assigned session name. */
#define BOUNCER_NAME_LEN        32
/** Maximum channels tracked per session. */
#define BOUNCER_MAX_CHANNELS    50
/** Maximum alias numerics per bouncer session (multi-server presence). */
#define BOUNCER_MAX_ALIASES     4
/** Maximum connection history entries per session (unique hosts). */
#define BOUNCER_MAX_CONN_HISTORY 10
/** Maximum legacy-peer-face entries per session (one face per legacy
 * peer — bounded; few legacy peers in any realistic mixed deployment). */
#define BOUNCER_LEGACY_INTRO_MAX 8

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
#define BOUNCER_DB_VERSION 9

/** Persisted alias roster entry (v8+).  Records "this session has an
 * alias on server YY with numeric NNN, last active at T, with caps C."
 * On restore, peers' BS A bursts confirm/repopulate runtime state;
 * persisted entries serve as expectations to verify, not authoritative
 * live state. */
struct BounceSessionAliasRecord {
  char     bsar_numeric[6];     /**< Alias YYXXX (5 chars + null) */
  char     bsar_server[3];      /**< Server YY (2 chars + null) */
  uint32_t bsar_caps;            /**< BX_CAP_* bitmask */
  int64_t  bsar_last_active;     /**< Per-alias last-activity timestamp */
};

/** On-disk representation of a bouncer session for persistence.
 * Fixed-width, versioned. All IRC identifiers have known max lengths.
 *
 * Per redesign A.1: bsr_sessid is a UUID v7 (22-char base64 of raw bytes).
 * Per redesign B.1: bsr_last_active is the PRIMARY's last-active
 *   (per-connection split — alias values live in bsr_aliases[]).
 * Per redesign B.2 + B.6: bsr_aliases[] persists the alias roster
 *   with per-alias last_active and caps.
 * Per redesign C.1: bsr_origin is HISTORICAL METADATA ONLY and not
 *   used for any authorization or behavior decision.  It records the
 *   server that originally created the session, kept for debugging /
 *   audit value.
 */
struct BounceSessionRecord {
  uint32_t bsr_version;
  /* Session identity */
  char     bsr_account[ACCOUNTLEN + 1];
  char     bsr_sessid[BOUNCER_SESSID_LEN];
  char     bsr_token[BOUNCER_TOKEN_LEN + 1];
  char     bsr_name[BOUNCER_NAME_LEN];
  char     bsr_origin[NICKLEN + 1];        /**< Historical: server numeric that created this.
                                            *   NOT used for authorization or behavior. */
  int32_t  bsr_hold_override;
  /* Timestamps */
  int64_t  bsr_created;
  int64_t  bsr_disconnect_time;
  int64_t  bsr_last_active;                /**< Primary's last-active (per-connection split) */
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
  /* Alias roster (per-alias activity + caps, v8+) */
  uint16_t bsr_aliascount;
  struct BounceSessionAliasRecord bsr_aliases[BOUNCER_MAX_ALIASES];
  /* Session-anchored oper grant (v9+).  Empty bsr_oper_name = not opered.
   * On revival, the new primary inherits IsOper via bounce_apply_oper_grant
   * keyed on bsr_oper_name (looked up in the local O:line config). */
  char     bsr_oper_name[NICKLEN + 1];
  int64_t  bsr_oper_granted_at;
};

/** Frozen v8 layout for migration reads.  Do not modify — must mirror
 * the on-disk layout produced by code with BOUNCER_DB_VERSION=8.  Used
 * exclusively by the v8→v9 migration path in bounce_db_restore (adds
 * the oper-grant fields, zero-initialised — pre-v9 sessions weren't
 * opered as far as we know). */
struct BounceSessionRecord_v8 {
  uint32_t bsr_version;
  char     bsr_account[ACCOUNTLEN + 1];
  char     bsr_sessid[BOUNCER_SESSID_LEN];
  char     bsr_token[BOUNCER_TOKEN_LEN + 1];
  char     bsr_name[BOUNCER_NAME_LEN];
  char     bsr_origin[NICKLEN + 1];
  int32_t  bsr_hold_override;
  int64_t  bsr_created;
  int64_t  bsr_disconnect_time;
  int64_t  bsr_last_active;
  int64_t  bsr_last_msg_time;
  int64_t  bsr_total_active;
  uint32_t bsr_attach_count;
  uint32_t bsr_connect_count;
  char     bsr_nick[NICKLEN + 1];
  char     bsr_username[USERLEN + 1];
  char     bsr_realhost[HOSTLEN + 1];
  char     bsr_host[HOSTLEN + 1];
  char     bsr_realname[REALLEN + 1];
  char     bsr_account_name[ACCOUNTLEN + 1];
  int64_t  bsr_acc_create;
  struct irc_in_addr bsr_ip;
  char     bsr_sock_ip[SOCKIPLEN + 1];
  char     bsr_sockhost[HOSTLEN + 1];
  uint16_t bsr_listener_port;
  uint64_t bsr_agg_sendB;
  uint64_t bsr_agg_receiveB;
  uint32_t bsr_agg_sendM;
  uint32_t bsr_agg_receiveM;
  uint16_t bsr_histcount;
  struct BounceConnHistory bsr_history[BOUNCER_MAX_CONN_HISTORY];
  uint16_t bsr_chancount;
  struct {
    char     name[CHANNELLEN + 1];
    uint32_t modes;
    int64_t  join_tv_sec;
    int32_t  join_tv_usec;
    char     join_msgid[16];
  } bsr_channels[BOUNCER_MAX_CHANNELS];
  uint16_t bsr_aliascount;
  struct BounceSessionAliasRecord bsr_aliases[BOUNCER_MAX_ALIASES];
};

/** Frozen v7 layout for migration reads.  Do not modify — must mirror
 * the on-disk layout produced by code with BOUNCER_DB_VERSION=7.  Used
 * exclusively by the v7→v8 migration path in bounce_db_restore. */
struct BounceSessionRecord_v7 {
  uint32_t bsr_version;
  char     bsr_account[ACCOUNTLEN + 1];
  char     bsr_sessid[BOUNCER_SESSID_V7_LEN];
  char     bsr_token[BOUNCER_TOKEN_LEN + 1];
  char     bsr_name[BOUNCER_NAME_LEN];
  char     bsr_origin[NICKLEN + 1];
  int32_t  bsr_hold_override;
  int64_t  bsr_created;
  int64_t  bsr_disconnect_time;
  int64_t  bsr_last_active;
  int64_t  bsr_last_msg_time;
  int64_t  bsr_total_active;
  uint32_t bsr_attach_count;
  uint32_t bsr_connect_count;
  char     bsr_nick[NICKLEN + 1];
  char     bsr_username[USERLEN + 1];
  char     bsr_realhost[HOSTLEN + 1];
  char     bsr_host[HOSTLEN + 1];
  char     bsr_realname[REALLEN + 1];
  char     bsr_account_name[ACCOUNTLEN + 1];
  int64_t  bsr_acc_create;
  struct irc_in_addr bsr_ip;
  char     bsr_sock_ip[SOCKIPLEN + 1];
  char     bsr_sockhost[HOSTLEN + 1];
  uint16_t bsr_listener_port;
  uint64_t bsr_agg_sendB;
  uint64_t bsr_agg_receiveB;
  uint32_t bsr_agg_sendM;
  uint32_t bsr_agg_receiveM;
  uint16_t bsr_histcount;
  struct BounceConnHistory bsr_history[BOUNCER_MAX_CONN_HISTORY];
  uint16_t bsr_chancount;
  struct {
    char     name[CHANNELLEN + 1];
    uint32_t modes;
    int64_t  join_tv_sec;
    int32_t  join_tv_usec;
    char     join_msgid[16];
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
  unsigned int ba_caps;     /**< Bouncer-relevant cap bitmask (BX_CAP_*).
                                 Updated via BX U caps=<hex>; consulted
                                 by sender to pick BX M vs BX E. */
  int ba_caps_known;        /**< 1 once a BX U caps= has been received
                                 for this alias.  0 means "fall back to
                                 IsMultiline link-level proxy" — needed
                                 because ba_caps == 0 is otherwise
                                 ambiguous (no relevant caps vs. no info
                                 received yet). */
  time_t ba_last_active;    /**< Per-alias last-activity timestamp.  Per
                                 redesign B.1 — primary's last_active
                                 lives on hs_last_active; aliases each
                                 carry their own last_active here.  Used
                                 as the "most-active" disambiguator in
                                 D.2 tiebreaker rules. */
};

/* BX_CAP_* — bouncer-relevant subset of client capabilities, sent
 * across S2S in the BX U caps= field as a hex bitmask.  Curated set
 * (rather than the full cli_active_own flagset) keeps S2S noise
 * bounded and gives forward-compat headroom for new bits.
 *
 * Both DRAFT_MULTILINE + BATCH are required for BX M to be useful:
 * multiline alone gives N PRIVMSGs without the wrapper, batch alone
 * has nothing to wrap. */
#define BX_CAP_DRAFT_MULTILINE 0x01
#define BX_CAP_BATCH           0x02
/* Future: 0x04 MSGTAGS, 0x08 LABELEDRESP, 0x10 ECHOMSG */

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
  char hs_sessid[BOUNCER_SESSID_LEN]; /**< Session ID — 22-char base64 of UUID v7 raw bytes (no padding) */
  char hs_token[BOUNCER_TOKEN_LEN+1]; /**< Session token (base64) */
  char hs_name[BOUNCER_NAME_LEN];     /**< User-assigned name */

  enum BouncerState hs_state;         /**< Current state */
  struct Client *hs_client;           /**< Connected client (ghost if HOLDING) */
  char hs_origin[NICKLEN + 1];        /**< Historical: server numeric that
                                       *   originally created this session.
                                       *   Per redesign C.1: NOT used for
                                       *   authorization or behavior.  Kept
                                       *   for debugging / audit value only.
                                       *   Authoritative replacement for
                                       *   "is this session local?" queries
                                       *   is session_has_local_holder()
                                       *   (Phase 3). */
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

  /* Session-anchored oper state.  Set when any session member runs
   * /OPER; cleared on /DEOPER.  Persisted in BounceSessionRecord so
   * the grant survives restart, and applied to the new primary on
   * revival / promote / demote.  The opername labels the grant for
   * audit; the actual privs are derived per-server from the local
   * O:line config at the time of inheritance.  Empty opername means
   * the session is not opered. */
  char hs_oper_name[NICKLEN + 1];
  time_t hs_oper_granted_at;

  int hs_dirty;                       /**< Session state changed, needs periodic persist */
  int hs_restore_pending;             /**< Set in bounce_db_restore; cleared on first
                                           successful BX R reconciliation, on any client
                                           attach (revive/alias-create), or when a
                                           remote BX R declares us the loser.  Drives
                                           the burst reconcile pass — only restore-
                                           pending sessions emit BX R, and only
                                           restore-pending sessions yield to a remote
                                           winner. */

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

  /* Legacy-face suppression table.  Per design: legacy peers (non-IRCv3-
   * aware) must see exactly one N introduction per bouncer session.  Once
   * a face has been emitted toward a given legacy peer, subsequent N
   * emits for any client of the same session toward that peer are
   * suppressed at the wire layer.  BX-aware peers can demote/promote
   * primary/alias state internally without disturbing the legacy view —
   * the local Client struct of the recorded face stays alive (becomes
   * IsBouncerAlias on demote) and routing back toward legacy uses that
   * alias's numeric.
   *
   * If the recorded face exits, the corresponding entry is cleared so
   * the next legacy emit re-introduces a fresh face (presumably a
   * different session connection that's still alive).  If two N's
   * leak through (race or pre-existing legacy state from before
   * tracking was added), the recovery path is to emit Q to legacy for
   * one of them — there is no other option once two faces are visible. */
  struct {
    char bli_peer[NICKLEN + 1];         /**< legacy peer's server numeric */
    char bli_face[6];                   /**< full YYXXX of introduced client */
  } hs_legacy_intros[BOUNCER_LEGACY_INTRO_MAX];
  int hs_legacy_intro_count;
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
/** Walk all sessions and drop alias entries whose ba_numeric does not
 * resolve to a live Client tagged IsBouncerAlias for the same account.
 * Call from end-of-burst to clean stale entries that accumulate when
 * peers restart, change numeric pool, or BX X cleanup is missed. */
extern void bounce_prune_stale_aliases(void);

/** Post-burst reconcile: detect multi-primary-same-session states
 * (e.g., a peer's primary for our session arrived during burst alongside
 * our own local primary) and merge them by demoting the newer to alias
 * of the older.  Called from end-of-burst once peer's N tokens are in
 * the hash so cli_session_id from ,S compact tags is observable.  Both
 * sides run the same algorithm on the same inputs → deterministic
 * convergence without coordination. */
extern void bounce_post_burst_reconcile(void);

/** Is any bouncer-relevant convergence work in flight that should
 * defer a newly-linked peer's burst-emit?  True iff any session has
 * hs_restore_pending OR any peer (other than exclude_peer) is IsBurst.
 * Called from server_estab to decide whether to gate the new peer's
 * burst, and from bounce_release_idle_gates to re-check gated peers. */
extern int bounce_convergence_pending(struct Client *exclude_peer);

/** Walk gated peers and release any whose convergence wait is now
 * complete.  Called event-driven from hs_restore_pending=0 sites and
 * from ClearBurst sites so the gate releases as soon as the wait is
 * over, rather than running the 1-second timer fallback to expiry. */
extern void bounce_release_idle_gates(void);

/** Does any peer's socket have unread inbound bytes (kernel recvbuf
 * or parsed-but-unprocessed dbuf)?  Used by bounce_auto_resume to
 * avoid creating a parallel primary when peer might be in the middle
 * of broadcasting BS C for the very session this account is about to
 * attach to (steady-state BS C race). */
extern int bounce_peer_has_inbound_data(void);

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

/** Free any deferred BX subcommands pinned to a dying server link.
 * Called from exit_one_client.  Matches entries whose original cptr
 * (incoming link) or sptr (message-source server) numeric corresponds
 * to the exiting server; they couldn't be replayed correctly anyway
 * since the source is gone. */
extern void pending_bx_cleanup_link(struct Client *link);

/* bounce_emit_burst_reconciles + BX R/F/J handlers retired in Phase 5
 * — convergence runs at-N-time per redesign D.1/D.3 with deterministic
 * tiebreaker, no coordination protocol. */

/** Broadcast a BX U caps=<hex> message to all servers when a local
 * bouncer-session client's cap state changes.  Called from m_cap.c's
 * cap_req / cap_ack / cap_clear right after
 * bounce_recompute_session_caps.  Returns silently if the client
 * isn't part of a bouncer session.  Receivers update the matching
 * BounceAlias->ba_caps so the sender of a future BX M can decide
 * BX M vs BX E based on the alias's actual cap state instead of
 * the link-level IsMultiline proxy. */
extern void bounce_emit_alias_caps(struct Client *cptr);

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
extern void bounce_sync_session_umodes(struct Client *source);

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

/** Set the S2S sessid override for an outgoing N introduction so that
 * bouncer-aware peers receive the session-identity hint via the
 * compact-tag ,S segment (per redesign A.2).
 *
 * No-op for clients without a bouncer session.  The override
 * auto-clears after format_s2s_tags_with_client consumes it during
 * the next sendcmdto_* call.
 *
 * @param[in] cptr Client about to be N-introduced.
 */
extern void bounce_set_n_sessid_hint(struct Client *cptr);

/** Generate a UUID v7 session ID and write its 22-char base64 form
 * (followed by nul) to @a buf.  Exposed so list.c can mint a per-Client
 * session ID at make_client time; bouncer-session adoption reuses the
 * Client's value rather than minting independently.
 *
 * @param[out] buf Buffer of at least 23 bytes (typically sized to
 *                 BOUNCER_SESSID_LEN / S2S_SESSID_BUFSIZE).
 */
extern void generate_sessid(char *buf);

/** Purge per-Client ephemeral session-scoped state on exit.
 *
 * Hook called once from exit_one_client() during teardown.  Ephemeral
 * subsystems (CHATHISTORY PM ring, READ_MARKER session table, etc.)
 * each register their cleanup here as those phases land.  Bouncer-
 * backed clients have their persistent state owned by the bouncer
 * record; each subsystem short-circuits in that case based on its
 * own key.
 *
 * Skeleton in Phase A — no consumers yet.  Phases C / D / E fill in
 * the dispatched calls.
 *
 * @param[in] cli Client being exited.
 */
extern void ephemeral_purge_session(struct Client *cli);

/** Record per-connection activity for bouncer-aware tiebreaking.
 *
 * Called from the general idle-update chokepoints (parse.c command
 * dispatch, m_privmsg PRIVMSG/NOTICE) so that every non-trivial
 * activity from a bouncer connection updates the connection-specific
 * last-active timestamp.
 *
 * For primary connections: updates the session's hs_last_active.
 * For aliases: updates the matching ba_last_active entry.
 * For non-bouncer / non-account clients: no-op.
 *
 * Per redesign B.1: enables D.2's primary-identity tiebreaker (oldest
 * cli_firsttime → highest last_active → lex on numeric) to operate on
 * per-connection granularity.
 *
 * @param[in] from Source client whose activity to record.
 */
extern void bounce_record_activity(struct Client *from);

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

/** Demote a live local primary into an alias of an incoming remote
 * primary.  Used by m_nick during net-rejoin to merge two
 * post-split-promote primaries gracefully without disconnecting the
 * local user.
 *
 * Flips channel memberships from primary to alias (CHFL_ALIAS, counter
 * fixup), sets IsBouncerAlias on the client, removes from nick hash,
 * updates session origin, and adds the client to hs_aliases.
 *
 * alias_primary is left NULL — caller must invoke
 * bounce_finish_live_primary_demote() after the new primary's Client
 * struct exists (typically after set_nick_name's IsServer branch
 * creates it).
 *
 * @param[in] acptr Live local primary to demote.
 * @param[in] new_primary_server The introducing server (becomes session origin).
 * @return 0 on success, -1 on no matching session or non-primary input.
 */
extern int bounce_demote_live_primary_to_alias(struct Client *acptr,
                                               struct Client *new_primary_server);

/** Patch up alias_primary and hs_client after the new primary is
 * created by set_nick_name; broadcast BX C so peers learn about the
 * newly-aliased local connection.
 *
 * @param[in] demoted_alias The freshly-demoted local client.
 * @param[in] new_primary   The remote primary client that replaces it.
 * @return 0 on success, -1 on mismatch.
 */
extern int bounce_finish_live_primary_demote(struct Client *demoted_alias,
                                             struct Client *new_primary);

/* bounce_resolve_pending_demotes retired in Phase 5 along with BX R. */

/** Returns nonzero if any directly-connected server is mid-burst.
 * Used to gate fresh-primary registration on burst settle so that a
 * local SASL completion doesn't race a peer's not-yet-arrived N for
 * the same account. */
extern int bounce_burst_in_progress(void);

/** Defer a client's register_user call until burst completes.  The
 * caller (s_auth's check_auth_finished, after auth_set_username) MUST
 * skip register_user when this returns DB_OK.  The client stays in
 * unknown state with auth complete; on the EOB drain
 * (bounce_drain_pending_registrations) register_user is invoked.
 * Returns 0 on success, -1 on alloc failure (caller should fall
 * through to immediate register_user). */
extern int bounce_defer_registration(struct Client *cli);

/** Drain queued post-burst registrations.  Called from
 * ms_end_of_burst after ClearBurst, gated on no remaining peer
 * having FLAG_BURST. */
extern void bounce_drain_pending_registrations(void);

/** Remove a client from the pending-registration queue (cleanup on
 * disconnect-before-drain).  Idempotent; no-op if not queued. */
extern void bounce_remove_pending_registration(struct Client *cli);

/** Returns nonzero if the given client is currently waiting in the
 * pending-registration queue (SASL completed during burst, register_user
 * deferred until burst settles).  m_nick uses this to extend the
 * "mid-SASL defer" branch through the post-SASL defer window — without
 * it, an incoming peer N for the same nick would override-kill the
 * still-Unknown deferred client. */
extern int bounce_is_pending_registration(const struct Client *cli);

/** Frontier introducer (per design intent #135 + #254): defer N
 * emission to legacy peers for fresh bouncer-account users until
 * BX-aware-ring convergence has had time to demote any loser side.
 * Caller (register_user) sets sendcmdto_set_skip_legacy_canon before
 * the N broadcast (BX-aware peers get it now), then registers the
 * client here.  After BOUNCE_PENDING_CANON_SECS the periodic tick
 * emits N to legacy peers if the client is still primary (i.e., didn't
 * become IsBouncerAlias during convergence). */
extern void bounce_pending_canon_register(struct Client *cli);
/** Cleanup hook (exit_one_client / m_nick demote-to-alias). */
extern void bounce_pending_canon_unregister(struct Client *cli);
/** Walk the pending-canon list and emit / drop entries; called from
 * the 1-second bounce_legacy_burst_gate_tick. */
extern void bounce_pending_canon_tick(void);

/* ---------------------------------------------------------------- */
/* Legacy-face suppression                                           */
/* ---------------------------------------------------------------- */

/** Look up the recorded legacy face (full YYXXX) for a session toward a
 * legacy peer.  Returns NULL if no face has been recorded yet for this
 * (session, peer) pair — meaning the next emit toward that peer is
 * authorized to introduce a fresh N.  Caller passes peer_yxx as the
 * legacy peer server's two-character numeric (cli_yxx(peer)). */
extern const char *bounce_session_legacy_face_for(
    struct BouncerSession *session, const char *peer_yxx);

/** Convenience: look up legacy face for any session of an account.  Used
 * at relay-time before broadcasting an N for a remote bouncer client —
 * bounce_get_session(cli) returns NULL when cli isn't this session's
 * canonical primary, so account-level lookup is needed. */
extern const char *bounce_account_legacy_face_for(const char *account,
                                                   const char *peer_yxx);

/** Record that this session has had a face introduced toward peer_yxx.
 * No-op if the entry already exists.  Bounded by BOUNCER_LEGACY_INTRO_MAX
 * (silently drops oversubscribed entries — exotic in practice). */
extern void bounce_session_record_legacy_intro(struct BouncerSession *session,
                                                const char *peer_yxx,
                                                const char *face_yxx);

/** Clear an entry — called from exit_one_client when the recorded face
 * Client is exiting, so the next emit re-introduces a live face. */
extern void bounce_session_clear_legacy_face(struct BouncerSession *session,
                                              const char *face_yxx);

/** Clear all legacy_face entries (across every session) keyed by a
 * departing peer's two-character server numeric.  Called from the SQUIT
 * path so that when the peer reconnects — even reusing the same numeric —
 * we re-emit a fresh N to it instead of suppressing under a stale face
 * record from the prior link.  Without this, restart-on-the-same-numeric
 * leaves the local side believing the peer has already seen the
 * introduction, and the burst goes out with channel members referencing
 * unannounced numerics. */
extern void bounce_clear_legacy_faces_for_peer(const char *peer_yxx);

/** Null any session's hs_client that points at this dying client, across
 * the full tokenHash.  exit_one_client's primary BOUNCER_ACTIVE / HOLDING
 * cleanup is gated on bsess->hs_client == bcptr; if a session's view of
 * its primary is stale (pre-existing burst-desync bug), that gate misses
 * and the dying client's pointer is left dangling in hs_client, causing
 * UAF in any subsequent recompute / lookup that reads hs_client.  Call
 * after the gated cleanup so any session still pointing at the corpse
 * gets nulled. */
extern void bounce_null_hs_client_pointing_at(struct Client *cli);

/** Emit N to all directly-connected legacy peers that don't yet have a
 * face for this client's session, recording each successful emit.
 * No-op if the client is an alias or has no associated session.  Used
 * by the pending-canon ticker (frontier-introducer post-defer release)
 * and by direct emit paths that want per-peer face suppression. */
extern void bounce_emit_legacy_n_intro(struct Client *cli);

/* bounce_session_is_local retired in Phase 5; use session_has_local_holder
 * for the runtime "do we hold this locally?" check. */

/* ---------------------------------------------------------------- */
/* Session state transition funnel                                   */
/* ---------------------------------------------------------------- */

/** Transition kinds.  Every state-changing operation on a
 * BouncerSession goes through bounce_session_transition() with one of
 * these kinds.  The funnel asserts the session invariant on entry and
 * exit; direct mutation of hs_client / hs_aliases[] / hs_state by
 * other code is being phased out.  See .claude/plans/bouncer-state-funnel.md. */
enum bounce_transition_kind {
  BST_REVIVE,                /**< held ghost (this server) -> live primary (this server) */
  BST_ATTACH_LOCAL_ALIAS,    /**< fresh local connection attached as alias of an existing primary */
  BST_DEMOTE_TO_ALIAS,       /**< local primary -> alias of a remote primary */
  BST_REBIND_TO_REMOTE,      /**< local held ghost -> remote-alias replica (peer's primary takes over) */
  BST_PROMOTE_ALIAS,         /**< local alias -> primary (on prior primary's exit) */
  BST_RECEIVE_REMOTE_PRIMARY,/**< peer's BS A says peer holds primary; install hs_client to remote */
  BST_DESTROY                /**< end-of-session (KILL, hold-expiry, BX X) */
};

struct bounce_transition_params {
  /** REVIVE / PROMOTE / REBIND / ATTACH_LOCAL_ALIAS / RECEIVE_REMOTE_PRIMARY:
   * the Client to install as the new primary view.  For ATTACH the
   * Client becomes an alias; for the others it becomes hs_client. */
  struct Client *new_primary;
  /** DEMOTE / REBIND: the local Client being flipped from primary/ghost to alias. */
  struct Client *demoted_alias;
  /** DEMOTE / REBIND: the remote primary the demoted_alias now mirrors. */
  struct Client *peer_primary;
  /** DESTROY: free-text reason for logs and Q broadcasts. */
  const char *reason;
};

/** Apply a single state transition to a session.
 *
 * Asserts the session invariant before and after (see
 * .claude/plans/bouncer-state-funnel.md):
 *   - exactly one canonical primary at rest,
 *   - all hs_aliases[] entries resolve to IsBouncerAlias Clients
 *     pointing to that primary,
 *   - hs_state is consistent with hs_client's flags.
 *
 * Emits the canonical wire signal for the kind (BX C / BX P / BX X /
 * legacy Q + N as appropriate) and persists the post-transition state.
 *
 * Returns 0 on success, negative on rejected transition.  This is the
 * sole supported API for changing session->hs_client, hs_aliases[],
 * hs_state once the call-site conversion is complete (Phase 7). */
extern int bounce_session_transition(
    struct BouncerSession *session,
    enum bounce_transition_kind kind,
    const struct bounce_transition_params *params);

/** Verify the session invariant.  Called at funnel entry/exit and
 * from /CHECK / /BOUNCER STATUS audits.  Returns 0 if the invariant
 * holds, negative with a diagnostic written to LS_USER otherwise.
 * Non-fatal — the goal is observability of state-machine drift, not
 * crashing on it. */
extern int bounce_session_assert_invariant(
    const struct BouncerSession *session, const char *site);

/** Runtime check: do we currently hold this session locally?
 *
 * Returns non-zero iff this server has a local Client* representing this
 * session — either a live primary, a local held-ghost, or any local
 * alias.  Independent of `hs_origin` (which is historical only per C.1).
 *
 * Use this for "do I own this session's persistence / bursting / channel
 * sync responsibility?" decisions.
 */
extern int session_has_local_holder(struct BouncerSession *session);

/** Are there any locally-held bouncer sessions on this server?
 *
 * Used to decide whether a fresh server link's burst needs to be gated
 * for legacy-peer convergence.  No held sessions → no risk of two
 * faces colliding on a legacy peer → no gate needed.
 */
extern int bounce_have_local_sessions(void);

/** Periodic check that walks server connections and force-releases
 * any legacy-peer burst gate whose deadline has expired.  Called once
 * per second from a global timer initialized in bounce_init. */
extern void bounce_legacy_burst_gate_tick(void);

/** Event-callback wrapper for the periodic 1-second tick — registered
 * from ircd.c as a TT_PERIODIC timer at server init. */
struct Event;
extern void bounce_legacy_burst_gate_callback(struct Event *ev);

/** Per-link grace period in seconds for the legacy-peer burst gate.
 * Long enough for typical BX-aware peer link establishment and BX R
 * exchange to complete before legacy peers see N's. */
#define BOUNCE_LEGACY_GATE_SECS 30

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
/** Defer-and-retry: a peer has unread inbound bytes that may carry a
 * BS C announcing the very session this account is about to attach to.
 * Caller (register_user) should bounce_defer_registration and let the
 * drain-on-BS-C path retry the auto_resume once peer data is processed. */
#define BOUNCE_RESUME_DEFER_PEER_INBOUND 7
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
