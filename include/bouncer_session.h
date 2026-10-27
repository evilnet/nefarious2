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
#ifndef INCLUDED_bouncer_deauth_h
#include "bouncer_deauth.h"
#include "account_id.h"
#endif
#ifndef INCLUDED_bouncer_wire_h
#include "bouncer_wire.h"
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
#define BOUNCER_MAX_ALIASES     16
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
#define BOUNCER_DB_VERSION 12

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
  /* Server notice mask (v11+): the session's own, which the oper grant
   * gives back after a restart instead of the O:line default.  Zero
   * bsr_snomask_known (every pre-v11 record) means none was recorded. */
  uint32_t bsr_snomask;
  uint32_t bsr_snomask_known;
  /* The primary's Keycloak id, compact (v12+); "" = none known.  Without
   * it a restored ghost carried no id until it revived, and its restore
   * burst introduced it without one. */
  char     bsr_kc_id[ACCOUNT_ID_LEN + 1];
};

/** Frozen v11 layout for migration reads.  Do not modify — must mirror
 * the on-disk layout produced by code with BOUNCER_DB_VERSION=11.  v12
 * only appends bsr_kc_id, so a v11 record is a prefix of a v12 one
 * (bounce_db_restore checks that at compile time). */
struct BounceSessionRecord_v11 {
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
  struct BounceConnHistory bsr_history[10]; /* frozen: v11 history size */
  /* Channel memberships */
  uint16_t bsr_chancount;
  struct {
    char     name[CHANNELLEN + 1];
    uint32_t modes;
    int64_t  join_tv_sec;       /**< Original JOIN time (seconds) */
    int32_t  join_tv_usec;      /**< Original JOIN time (microseconds) */
    char     join_msgid[16];    /**< Original JOIN msgid */
  } bsr_channels[50]; /* frozen: v11 channel count */
  /* Alias roster (per-alias activity + caps, v8+) */
  uint16_t bsr_aliascount;
  struct BounceSessionAliasRecord bsr_aliases[16]; /* frozen: v11 alias count */
  /* Session-anchored oper grant (v9+).  Empty bsr_oper_name = not opered.
   * On revival, the new primary inherits IsOper via bounce_apply_oper_grant
   * keyed on bsr_oper_name (looked up in the local O:line config). */
  char     bsr_oper_name[NICKLEN + 1];
  int64_t  bsr_oper_granted_at;
  /* Server notice mask (v11+): the session's own, which the oper grant
   * gives back after a restart instead of the O:line default.  Zero
   * bsr_snomask_known (every pre-v11 record) means none was recorded. */
  uint32_t bsr_snomask;
  uint32_t bsr_snomask_known;
};

/** Frozen v10 layout for migration reads.  Do not modify — must mirror
 * the on-disk layout produced by code with BOUNCER_DB_VERSION=10.  v11
 * only appends the snomask fields, so a v10 record is a prefix of a v11
 * one (bounce_db_restore checks that at compile time). */
struct BounceSessionRecord_v10 {
  uint32_t bsr_version;
  /* Session identity */
  char     bsr_account[ACCOUNTLEN + 1];
  char     bsr_sessid[BOUNCER_SESSID_LEN];
  char     bsr_token[BOUNCER_TOKEN_LEN + 1];
  char     bsr_name[BOUNCER_NAME_LEN];
  char     bsr_origin[NICKLEN + 1];
  int32_t  bsr_hold_override;
  /* Timestamps */
  int64_t  bsr_created;
  int64_t  bsr_disconnect_time;
  int64_t  bsr_last_active;
  int64_t  bsr_last_msg_time;
  int64_t  bsr_total_active;
  uint32_t bsr_attach_count;
  uint32_t bsr_connect_count;
  /* Ghost client identity */
  char     bsr_nick[NICKLEN + 1];
  char     bsr_username[USERLEN + 1];
  char     bsr_realhost[HOSTLEN + 1];
  char     bsr_host[HOSTLEN + 1];
  char     bsr_realname[REALLEN + 1];
  char     bsr_account_name[ACCOUNTLEN + 1];
  int64_t  bsr_acc_create;
  /* Last connection metadata */
  struct irc_in_addr bsr_ip;
  char     bsr_sock_ip[SOCKIPLEN + 1];
  char     bsr_sockhost[HOSTLEN + 1];
  uint16_t bsr_listener_port;
  /* Session-level aggregate counters */
  uint64_t bsr_agg_sendB;
  uint64_t bsr_agg_receiveB;
  uint32_t bsr_agg_sendM;
  uint32_t bsr_agg_receiveM;
  /* Connection history */
  uint16_t bsr_histcount;
  struct BounceConnHistory bsr_history[10]; /* frozen: v10 BOUNCER_MAX_CONN_HISTORY */
  /* Channel memberships */
  uint16_t bsr_chancount;
  struct {
    char     name[CHANNELLEN + 1];
    uint32_t modes;
    int64_t  join_tv_sec;
    int32_t  join_tv_usec;
    char     join_msgid[16];
  } bsr_channels[50]; /* frozen: v10 BOUNCER_MAX_CHANNELS */
  /* Alias roster */
  uint16_t bsr_aliascount;
  struct BounceSessionAliasRecord bsr_aliases[16]; /* frozen: v10 BOUNCER_MAX_ALIASES */
  /* Session-anchored oper grant */
  char     bsr_oper_name[NICKLEN + 1];
  int64_t  bsr_oper_granted_at;
};

/** Frozen v9 layout for migration reads.  Do not modify — must mirror
 * the on-disk layout produced by code with BOUNCER_DB_VERSION=9 (when
 * BOUNCER_MAX_ALIASES was 4).  Used exclusively by the v9→v10 migration
 * path in bounce_db_restore; v10 only grows the alias array to the
 * current BOUNCER_MAX_ALIASES. */
struct BounceSessionRecord_v9 {
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
  struct BounceSessionAliasRecord bsr_aliases[4]; /* frozen: v9 array size */
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
  time_t ba_last_active_emitted; /**< Local bookkeeping on the alias's own
                                 server: when its activity was last put on
                                 the wire (BX U la=).  Not replicated. */
  int ba_away;              /**< The alias's OWN away state as its server
                                 reports it (BX U aw=): 0 present, 1 away,
                                 2 AWAY * (draft/pre-away, not looking).
                                 The webpush attention rule and the away
                                 aggregation read this for remote aliases
                                 instead of the session's mirrored aggregate. */
  int ba_away_known;        /**< 1 once a BX U aw= arrived for this alias. */
  char ba_active_profile[33]; /**< Phase 4 M4b: alias's active draft/persistence
                                   profile name (PERSISTENCE_PROFILE_NAME_MAX + NUL).
                                   Empty string resolves to "default" by the
                                   reconciler.  Replicated via BX U profile=<name>
                                   after BX C / on link-up burst.  Drives the
                                   network-membership reconciler's union math. */
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
#define BX_CAP_ECHO_MESSAGE    0x04  /**< echo-message: the connection can display self-sourced messages (session echo) */
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
  /** The Keycloak user the session belongs to, compact; "" = none known
   * (a session begun by an X3 login, a record from before the id was
   * kept).  Set at create and when a session without one adopts a
   * login's (the transition), persisted (bsr_kc_id), replicated by
   * BX U kcid=.  Never changed to a different id (user, 2026-10-23). */
  char hs_kc_id[ACCOUNT_ID_LEN + 1];
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
                                       *   (Phase 3); "where is it held"
                                       *   is bounce_primary_server().  A
                                       *   split reads the origin only for
                                       *   a session with no primary. */
  char hs_ghost_numeric[6];           /**< Ghost client numeric during HOLDING */

  int hs_hold_override;               /**< -1=use default, 0=no hold, 1=hold */
  char hs_hold_reason[128];           /**< Why the last hold happened (the
                                       *   disconnect comment: "Ping timeout",
                                       *   "Read error: ...", a QUIT message,
                                       *   "WebSocket closed", ...).  In-memory
                                       *   diagnostic only -- NOT persisted to
                                       *   MDBX (a restart clears it); echoed
                                       *   at resume + shown in /CHECK. */

  struct BounceChannel hs_channels[BOUNCER_MAX_CHANNELS];
  int hs_chancount;

  /** Alias numerics for multi-server presence. */
  struct BounceAlias hs_aliases[BOUNCER_MAX_ALIASES];
  int hs_alias_count;

  int hs_promoting;                    /**< Nonzero during SQUIT promotion (suppresses alias sync) */
  int hs_enforced;                     /**< Phase 3: set when any connection on a
                                            CRFLAG_BOUNCER class attaches to (or creates)
                                            this session.  PERSISTENCE DETACH refuses while
                                            this is set — the class enforces persistence,
                                            so the user can't opt out.  Cleared when the
                                            session transitions to HELD (no live connection),
                                            so a subsequent non-enforced attach can detach
                                            a stale-enforced session. */

  int hs_primary_away;                 /**< The primary's OWN away state as replicated
                                            (BX U aw=), for servers that do not host it. */
  int hs_primary_away_known;           /**< 1 once a BX U aw= arrived for the primary. */
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
  /* The session's server notice mask.  close_connection() zeroes a
   * held socket's mask but leaves its modes, +s included, so
   * bounce_hold_client() keeps it here for the revive to give back;
   * persisted, it is what the oper grant restores after a restart in
   * place of the O:line default.  hs_snomask_known is 0 until one was
   * recorded (a session restored from a pre-v11 record). */
  unsigned int hs_snomask;
  int hs_snomask_known;
  /* The order of the mask's changes across servers (not persisted): a
   * Lamport stamp -- this server's clock, but past the last stamp seen --
   * taken at every change made here, and the server that made it.  BX K
   * carries both; a receiver keeps the later change, the lower server
   * numeric on a tie, so two servers changing it at once (an /OPER on an
   * alias and the O:line mask the primary's server derives for the +o it
   * relays) settle on the same mask. */
  time_t hs_snomask_ts;
  char hs_snomask_origin[3];

  /** Memory only: the server (YY) whose BS C last announced this session
   * "holding" while our record of it stayed as it was, and the serial of
   * the link that BS C came over (struct Server link_serial); "" when
   * none.  Cleared when that server announces the session otherwise (BS C
   * "active", an attach's BS A, its BS X); a later establishment of the
   * link has another serial.  The post-burst reconcile reads that
   * server's client under this session's id as its held copy, which
   * yields to a live one (BS C), so it never demotes a live primary of
   * ours into it. */
  char hs_peer_holding[3];
  unsigned long hs_peer_holding_serial;

  /** Memory only: the id another server (hs_peer_sessid_server, its YY)
   * announced this session under when ours beat it at BS C in a link
   * burst (the lower id of two of one account), and that server is to
   * take ours.  Its clients
   * keep the id their N carried on our side: a client of that server
   * under this id is in the session too (the post-burst reconcile, the
   * yield at BS A).  "" when none; cleared when our record takes another
   * id, and at a split by that server. */
  char hs_peer_sessid[BOUNCER_SESSID_LEN];
  char hs_peer_sessid_server[3];

  /** Memory only: what we last announced of this session (BS C) on one
   * link: that link's serial (struct Server link_serial), the state
   * ("holding" or not) and the id.  A record that follows the primary of
   * a session the peer then announces under another id ends with the id
   * the peer ends with, which it decides from what we announced
   * (bounce_follow_keeps_id).  One link at a time: the latest burst. */
  unsigned long hs_announced_serial;
  int hs_announced_holding;
  char hs_announced_sessid[BOUNCER_SESSID_LEN];

  int hs_dirty;                       /**< Session state changed, needs periodic persist */
  time_t hs_restore_deadline;         /**< Restore-pending expiry: a HOLDING ghost
                                           nothing claims must stop gating bursts. */
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
  time_t hs_last_active_emitted;      /**< Primary's activity last put on the
                                           wire (BX U la=); local bookkeeping */
  time_t hs_last_msg_time;            /**< Last PRIVMSG time (user idle baseline) */
  time_t hs_disconnect_time;          /**< When client disconnected (0=active) */
  unsigned int hs_attach_count;       /**< Number of times resumed from HOLDING */
  unsigned int hs_connect_count;      /**< Total connections (resumes + alias attaches) */
  time_t hs_total_active;             /**< Cumulative active time (seconds) */
  time_t hs_attach_time;              /**< When the primary last got a live
                                         socket (0 = none); the stretch
                                         hs_total_active accrues at hold */
  struct Timer hs_hold_timer;         /**< Expiry timer for HOLDING state */
  struct Timer hs_promote_timer;      /**< 0-tick deferred-promote timer
                                       *   (cross-server clean-QUIT path)
                                       *   — fires at next event-loop
                                       *   iteration so in-flight BX X
                                       *   for the chosen winner has a
                                       *   chance to settle before we
                                       *   emit BX P.  See
                                       *   bounce_schedule_cross_server_promote.
                                       */

  /* Session-level aggregate counters (lifetime totals from dead connections) */
  uint64_t     hs_agg_sendB;         /**< Lifetime bytes sent (dead connections) */
  uint64_t     hs_agg_receiveB;      /**< Lifetime bytes received (dead connections) */
  unsigned int hs_agg_sendM;         /**< Lifetime messages sent (dead connections) */
  unsigned int hs_agg_receiveM;      /**< Lifetime messages received (dead connections) */

  /* Connection history (unique hosts, most recent first) */
  int hs_histcount;
  struct BounceConnHistory hs_history[BOUNCER_MAX_CONN_HISTORY];

  /* Legacy-face records: the first face (client) of this session our
   * burst introduced to each legacy (non-IRCv3-aware) peer.  Shown by
   * CHECK -b; a BX P swap of that face toward the peer records the new
   * numeric, and a retraction of it, or the peer's split, drops the
   * record.  The burst holds back no client: a legacy peer learns every
   * face of ours, as it learns every N we relay. */
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

/** Apply a runtime change to FEAT_BOUNCER_PERSIST_INTERVAL to the
 * dirty-persist timer.  No-op if the timer is not currently armed
 * (no dirty sessions); the next mark_session_dirty will pick up the
 * new interval via bounce_start_dirty_persist_timer. */
extern void bounce_dirty_persist_restart_timer(void);

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

/** M4b reconciler: test whether any profile across the account
 * (active or HOLD-sticky inactive) effectively wants `channel`.
 * Returns 0 immediately when the account is not held — under the
 * "non-held = not a bouncer session" semantic, profiles are
 * irrelevant for non-held accounts and the reconciler bails.
 *
 * When held, walks every profile defined for the account (via
 * persistence_profile_list) and consults the effective channel set
 * (inheritance-aware).  Any hit returns 1.
 *
 * @param[in] account Account name.
 * @param[in] channel Channel name.
 * @param[in] exclude_profile If non-NULL, this profile is skipped
 *                            in the walk — useful for the m_part
 *                            decision "would the union still want
 *                            the channel if my profile dropped it?"
 * @return 1 if the union contains `channel`, 0 otherwise.
 */
extern int bounce_account_wants_channel(const char *account,
                                         const char *channel,
                                         const char *exclude_profile);

/** M4b: visibility-membership update for an alias.  Adds or removes
 * the alias's CHFL_ALIAS membership for the channel locally and
 * broadcasts BX V to peers so their local replicas of the alias do
 * the same.  Used when a profile-level channel-list change should
 * affect specific aliases without disturbing the primary's
 * network-level membership.
 *
 * @param[in] alias_full Full YYXXX numeric of the alias.
 * @param[in] channel Channel name (must include leading prefix).
 * @param[in] add Non-zero to add CHFL_ALIAS membership; zero to remove.
 */
extern void bounce_visibility_membership(const char *alias_full,
                                          const char *channel,
                                          int add);

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

/** Run bounce_release_idle_gates() at the next timer run, not now.  For a
 * convergence that completes while a server line is handled (a same-nick
 * decision in m_nick): a released gate runs server_finish_burst, whose N
 * lines must not read the line's tags.  Idempotent until it runs. */
extern void bounce_schedule_gate_release(void);

/** Does a link that can carry a BS C (an IRCv3-aware link) have unread
 * inbound bytes (kernel recvbuf or parsed-but-unprocessed dbuf)?  Returns
 * the first such link, or NULL.  Used by bounce_auto_resume to avoid
 * creating a parallel primary when peer might be in the middle of
 * broadcasting BS C for the very session this account is about to attach
 * to (steady-state BS C race).  A legacy link never counts: no BS C comes
 * over it. */
extern struct Client *bounce_peer_has_inbound_data(void);

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

/** Forward a PM/NOTICE to all aliases of the target bouncer primary,
 * under the message's own msgid and time; each alias gets one copy
 * network-wide (see bouncer_session.c).
 * @param[in] from        The original sender, never rewritten to its
 *                        session primary.
 * @param[in] target      Target client (primary).
 * @param[in] inbound     Server link the message arrived on, NULL if local.
 * @param[in] cmd         Long command name (MSG_PRIVATE or MSG_NOTICE).
 * @param[in] tok         Short command token (TOK_PRIVATE or TOK_NOTICE).
 * @param[in] text        Message text.
 * @param[in] msgid       The message's msgid (NULL or empty if none).
 * @param[in] event_ms    The message's time, in epoch milliseconds.
 * @param[in] client_tags The sender's client-only tags, or NULL.
 */
extern void bounce_forward_pm_to_aliases(struct Client *from,
    struct Client *target, struct Client *inbound,
    const char *cmd, const char *tok, const char *text,
    const char *msgid, uint64_t event_ms, const char *client_tags);

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
struct Flags;
/** Copy @a source's user modes (and privileges, snomask) to the other
 * members of its session and tell each local one what changed for it.
 * @param[in] source        The member whose modes changed.
 * @param[in] source_before Its flags before the change, to tell it too
 *                          when it is not @a told; NULL not to.
 * @param[in] told          The connection the change was already echoed
 *                          to (set_user_mode's cptr), or NULL. */
extern void bounce_sync_session_umodes(struct Client *source,
                                       const struct Flags *source_before,
                                       struct Client *told);
extern void bounce_sync_session_snomask(struct Client *source);
extern void bounce_sync_alias_identity(struct Client *primary);

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
 * Called BEFORE exit_downlinks(). Marks the sessions whose primary is a
 * client of the departing server or of a server behind it (by origin
 * only for a session with no primary), and removes their roster entries
 * for aliases behind it.
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
/** Promote an alias to primary for a bouncer session.
 *
 * @param[in] session     Session whose primary is departing.
 * @param[in] local_only  When non-zero, only promote if a local-server
 *                        alias is available.  Returns -1 without
 *                        broadcasting BX P if every alias is on a
 *                        remote server.  Used by the immediate-promote
 *                        path in m_quit.c — for the cross-server case
 *                        (only remote alias), we defer to the existing
 *                        hold-then-expire path so we don't broadcast
 *                        BX P that could race a concurrent BX X from
 *                        the alias's home server.
 * @return 0 on success, -1 if no eligible alias (caller falls through
 *         to bounce_hold_client).
 */
extern int bounce_promote_alias(struct BouncerSession *session,
                                int local_only);

/** Schedule a cross-server alias promotion for the next event-loop
 * tick.  Used by m_quit.c after bounce_hold_client when every alias
 * is on a remote server: we don't promote inline (would race a
 * concurrent BX X from the alias's home server), but we don't want
 * to wait for hold-expire either.  A 0-tick `TT_RELATIVE` timer
 * fires after the current tick's I/O is dispatched, giving any
 * already-queued BX X for the chosen winner a chance to land first.
 * The timer callback re-evaluates the alias list and either runs
 * `bounce_promote_alias(session, 0)` (any alias, including remote)
 * or leaves the session HOLDING for the regular hold-expire path if
 * no live alias remains.
 *
 * Idempotent: a second call before the timer fires is a no-op.
 *
 * @param[in] session Session in BOUNCE_HOLDING state with at least
 *                    one (remote) alias entry.
 */
extern void bounce_schedule_cross_server_promote(struct BouncerSession *session);

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
extern time_t bounce_hold_remaining(struct BouncerSession *session);

/** Destroy a session entirely.
 * @param[in] session Session to destroy.
 */
extern void bounce_destroy(struct BouncerSession *session);

/** End @a session everywhere (BS X, then bounce_destroy()) while its
 * connections carry on outside it: hold turned off (MODE -b, BOUNCER SET
 * HOLD off, PERSISTENCE SET OFF / DETACH) or BOUNCER DISCONNECT.  A local
 * primary, and @a caller, that carry on take a session id of their own:
 * the ended session's id would make the session-id hint stamp it on
 * their N, and a peer would take a client in no session for a member
 * (its rebind and its post-burst merge match on that id).
 *
 * @param[in] session The session to end; freed here.
 * @param[in] caller  The connection that asked, or NULL.
 */
extern void bounce_end_session_keep_clients(struct BouncerSession *session,
                                            struct Client *caller);

/** Force-destroy a session because its primary was network-KILLed
 * (invariant #12: KILL ends the whole session).  Exits every alias
 * with the provided comment, broadcasts BX X for peer cleanup, then
 * calls bounce_destroy.
 *
 * Used by m_kill.c to plug the FLAG_KILLED gap for local-cptr-local-
 * victim KILLs, where m_kill skips FLAG_KILLED so the existing
 * FLAG_KILLED-gated cleanup in exit_one_client doesn't fire.
 *
 * Callers must NOT touch the session pointer after this returns
 * (it is freed by bounce_destroy).
 *
 * @param[in] session Session to kill-destroy.  Must be non-NULL.
 * @param[in] comment KILL reason text for alias exits; defaulted to
 *                    "Session killed" if NULL or empty.
 */
extern void bounce_kill_session(struct BouncerSession *session,
                                const char *comment);

/** Retire a held session of ours: end it (bounce_kill_session: its
 * aliases, BS X toward the aware links) and then exit its ghost (BX X
 * toward the aware links, a Q toward the legacy ones).  The caller makes
 * sure nothing of it is live (bounce_session_held): its aliases would be
 * exited.  BS C's convergence and a same-nick meeting at N time both
 * retire through here.
 *
 * @param[in] s      The session; NULL for a ghost no session names (only
 *                   the ghost exits).  Freed on return.
 * @param[in] ghost  The held ghost; NULL takes s's primary slot.
 * @param[in] link   The link being handled (exit_client's cptr).
 * @param[in] reason The exit reason; NULL or empty: "Bouncer session moved".
 */
extern void bounce_retire_held_session(struct BouncerSession *s,
                                       struct Client *ghost,
                                       struct Client *link,
                                       const char *reason);

/** Set the S2S sessid override for an outgoing N introduction so that
 * bouncer-aware peers receive the session-identity hint via the
 * compact-tag ,S segment (per redesign A.2).
 *
 * A session member (primary, held ghost, roster alias) carries its
 * session's hs_sessid; any other client its own cli_session_id, as does
 * a client two sessions name as their primary.  The session is the one
 * bounce_session_of_primary() finds, and for a client of ours with an
 * account the hold mark (,H) is stamped beside it from the same lookup.
 * The override auto-clears after format_s2s_tags_with_client consumes it
 * during the next sendcmdto_* call.
 *
 * @param[in] cptr Client about to be N-introduced.
 * @return The hold mark staged beside the id (BOUNCE_HOLD_MARK_*), or 0
 *         when none is (not our client, no account, no id).
 */
extern char bounce_set_n_sessid_hint(struct Client *cptr);

/** May the hold mark (compact-tag ,H) on an N introduced by @a home be
 * trusted?  Yes when every server on the path from @a home to us
 * announces SERVER flag H, and so do we: our SERVER line to the link the
 * path arrives on announced it (the announcement the far end judges us
 * by), and we still send marks (P10_MESSAGE_TAGS on).  Both ends of the
 * path are included, so two servers trust each other's marks or neither
 * does: exact for a direct link; multi-hop and runtime-toggle residuals
 * are registered.  The rule itself is bounce_hold_marks_trusted_path()
 * (bouncer_wire.h); this walks the path for it.  A server that does not stamp
 * marks, or does not relay them, leaves the state of the clients behind
 * it unknown (bounce_nick_side_from_mark, bouncer_converge.h).
 *
 * @param[in] home The N's source server (the client's home); never &me,
 *                 whose clients' N are not incoming (0).
 * @return 1 if trusted, else 0.
 */
extern int bounce_hold_marks_trusted(struct Client *home);

/** Record that our burst N for our client @a c went to @a link carrying
 * hold mark @a mark (a link that trusts our marks). */
extern void bounce_note_burst_stamp(struct Client *c, struct Client *link,
                                    char mark);

/** The hold mark our burst N for our client @a c carried to @a link,
 * while that link is still bursting to us and was not gated: the facts
 * its server reads about @a c for a same-nick verdict on the N it sends
 * us.  0 when not known (no such N, another link's, a gated link, the
 * link's burst over): the caller reads @a c as it is now. */
extern char bounce_burst_stamp_for(struct Client *c, struct Client *link);

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
/** A local session connection's own away state changed (0 present, 1 away,
 * 2 AWAY *): put it on the wire (BX U aw=) so other servers judge attention
 * and aggregate away from the connection's own state, not the mirror. */
extern void bounce_note_away_state(struct Client *who, int state);


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

/** Reason recorded at this client's session's last hold, or NULL.
 * Diagnostic: lets the resume path tell the user why the previous
 * connection ended (the information is otherwise destroyed -- holds
 * never emit QUIT or connexit notices). */
extern const char *bounce_last_hold_reason(struct Client *cptr);

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

/** Activity replication: a connection's first message after a quiet
 * period puts its activity on the wire (BX U <numeric> la=<ts>), so every
 * replica's hs_last_active / ba_last_active tracks live use at a bounded
 * cost (one line per connection per quiet period).  The period is this
 * ceiling or half the account's webpush idle window, whichever is
 * shorter (bounce_activity_quiet): a replica's reading is then always
 * fresher than the window it is judged against, whatever WEBPUSH_IDLE or
 * the per-account override is set to. */
#define BOUNCE_ACTIVITY_QUIET 300
extern int bounce_activity_quiet(const char *account);

/** Most recent activity across every connection of @a session: the
 * primary's and each alias's, local from the idle clock, remote from the
 * replicated value.  0 when nothing is known. */
extern time_t bounce_session_last_active(struct BouncerSession *session);

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
                                                 const char *info,
                                                 time_t incoming_acc_ts,
                                                 const char *incoming_kc_id);

/** A held ghost of ours gives its place to a client of the same session
 * another server introduces (a same-nick verdict's drop), reusing the
 * ghost's Client as the rebind does (no QUIT, no JOIN; one BX P per
 * legacy link that may know the face; the counters move to the
 * introducing server's domain).
 *
 * @param[in] session        The session the decision read; its primary
 *                           slot must be @a ghost.
 * @param[in] ghost          Our held ghost (MyConnect).
 * @param[in] server         The introducing server.
 * @param[in] new_numeric    The introduced client's full YYXXX.
 * @param[in] incoming_kc_id The Keycloak id the N carries ("" if none).
 * @param[in] incoming_held  1: the introduced client is the session's
 *                           held ghost there; our record becomes a held
 *                           replica of it (no hold timer here).  0: it is
 *                           the session's live primary; the session goes
 *                           active.
 * @return 0 on success, -1 when the facts do not hold (nothing changed).
 */
extern int bounce_drop_held_ghost(struct BouncerSession *session,
                                  struct Client *ghost, struct Client *server,
                                  const char *new_numeric, time_t new_lastnick,
                                  const char *username, const char *host,
                                  const struct irc_in_addr *new_ip,
                                  const char *info, const char *incoming_kc_id,
                                  int incoming_held);

/** A held ghost of ours whose session the incoming live primary takes
 * over (a same-nick verdict that yields for a held ghost: it has no
 * socket to keep as an alias).  The caller installed @a new_primary from
 * the incoming N, withheld from the legacy links.  Here: the legacy links
 * swap the ghost's face to it (BX P); the session takes the incoming
 * primary's session id (or, when we already have a record of that
 * session, its connections join that record and ours ends with BS X);
 * its primary slot is @a new_primary and it is active; each live alias
 * follows @a new_primary and a local one is announced by BX C; the ghost
 * leaves without a Q (BX X toward the aware links).
 *
 * @param[in] session         The session the decision read; its primary
 *                            slot must be @a ghost.
 * @param[in] ghost           Our held ghost.
 * @param[in] new_primary     The incoming primary, installed.
 * @param[in] link            The link the N came on.
 * @param[in] incoming_sessid The session id the N carried (,S); NULL or
 *                            empty keeps ours.
 * @return 0 on success, -1 when the facts do not hold (nothing changed).
 */
extern int bounce_yield_held_ghost(struct BouncerSession *session,
                                   struct Client *ghost,
                                   struct Client *new_primary,
                                   struct Client *link,
                                   const char *incoming_sessid);

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
 * Runs only when bounce_demote_eligibility() says so at
 * BOUNCE_DEMOTE_PLAN; nothing changes otherwise.
 *
 * @param[in] acptr       Live local primary to demote.
 * @param[in] new_primary The primary it becomes an alias of; its HOME
 *                        server, cli_user(new_primary)->server, becomes
 *                        the session origin (never the link it arrived on).
 * @param[in] session     The session acptr is the primary of (the one the
 *                        finish installs new_primary in).
 * @return 0 on success, -1 when the demote is not eligible.
 */
extern int bounce_demote_live_primary_to_alias(struct Client *acptr,
                                               struct Client *new_primary,
                                               struct BouncerSession *session);

/** May `face` be demoted into an alias of a new primary on `session`?
 * The one decision behind the live-primary demote: the same-nick merge
 * (m_nick.c) asks it before relaying the new primary's N, the post-burst
 * reconcile asks it of each co-session candidate, and the demote and its
 * finish ask it again at their own step.  Reads the facts for the pure
 * bounce_demote_check() (bouncer_wire.h).
 *
 * @param[in] stage       BOUNCE_DEMOTE_PLAN before the demote (face is
 *                        the session's live primary), BOUNCE_DEMOTE_FINISH
 *                        after it (face is the alias, the slot empty).
 * @param[in] face        Our client that becomes (or became) the alias.
 * @param[in] session     The session the demote runs on.
 * @param[in] new_home    The new primary's HOME server (the N's source
 *                        server before its Client exists), or NULL.
 * @param[in] new_account The new primary's account, or NULL.
 * @param[in] new_kc_id   The new primary's Keycloak id ("" or NULL: none);
 *                        one that differs from the session's refuses.
 * @return BOUNCE_DEMOTE_OK, or why not.
 */
extern enum bounce_demote_bar bounce_demote_eligibility(enum bounce_demote_stage stage,
                                                        struct Client *face,
                                                        struct BouncerSession *session,
                                                        struct Client *new_home,
                                                        const char *new_account,
                                                        const char *new_kc_id);

/** The session a same-nick decision about our client @a c acts on: the
 * session whose hs_client is @a c (its primary, or its held ghost),
 * else the first session that lists @a c on its alias roster.  A caller
 * that acts on the session as @a c's own (ends it, drops its ghost,
 * files into it as the primary's) does so only when the result's
 * hs_client is @a c: a roster match is the listing session, not @a c's.
 * Unlike
 * bounce_get_session(), a session that names @a c as its primary wins
 * over one met earlier that only lists it on its roster.  When two
 * sessions both name @a c as their primary (a split that converged
 * across session ids can leave that), neither is the one: NULL, logged
 * (Debug).
 *
 * The verdict's facts about @a c (bounce_nick_side_held(), and
 * local_is_session_primary = the result's hs_client is @a c), the hold
 * mark and session id its N carries (bounce_set_n_sessid_hint) and the
 * session a retire or a ghost drop then acts on all come from this one
 * lookup.  Pass the result on to the action; do not look the session up
 * again another way.
 *
 * @param[in] c The client.
 * @return The session, or NULL (none, or two claim @a c).
 */
extern struct BouncerSession *bounce_session_of_primary(struct Client *c);

/** bounce_session_of_primary() and the facts the verdict reads about @a
 * c, from that one lookup: @a held as bounce_nick_side_held() reads it,
 * and @a primary = the result's hs_client is @a c (the verdict's
 * local_is_session_primary).  A client two sessions name as their
 * primary gives NULL, held 0, primary 0.  The hold mark on @a c's N is
 * stamped from the same call.
 *
 * @param[in]  c       Our client.
 * @param[out] held    Set to the held fact; may be NULL.
 * @param[out] primary Set to the primary fact; may be NULL.
 * @return The session, or NULL.
 */
extern struct BouncerSession *bounce_nick_side_lookup(struct Client *c,
                                                      int *held,
                                                      int *primary);

/** Does @a s have a live device of its own copy on its alias roster: an
 * entry that resolves to an alias following the session's primary (or of
 * a record with no primary), not another copy's device filed here by the
 * session id (bounce_alias_is_own())?  The hold mark, the same-nick
 * verdict and BS C's retire branch read one answer.  NULL has none. */
extern int bounce_session_has_live_alias(struct BouncerSession *s);

/** Is @a c held, read from the session object @a s an action would use:
 * a held ghost whose session has no live alias of its own copy left
 * (bounce_session_has_live_alias())?  A held ghost with one counts as
 * live: ending its session (bounce_kill_session) would exit it.  Another
 * copy's device filed on the roster does not keep it live.  With @a s NULL
 * (a ghost no session names) there is no roster: held.
 *
 * @param[in] s The session; NULL for none.
 * @param[in] c The client.
 * @return 1 if held with no live alias, else 0.
 */
extern int bounce_session_held(struct BouncerSession *s, struct Client *c);

/** Is `cptr` held, as a same-nick verdict (bounce_nick_verdict) reads
 * it?  bounce_session_held() on bounce_session_of_primary(cptr); a
 * client two sessions name as their primary is not held (there is no
 * one session to end).  The hold mark its N carries is stamped from
 * this, so a peer reads the fact we would.
 *
 * @param[in] cptr Our client.
 * @return 1 if held with no live alias, else 0.
 */
extern int bounce_nick_side_held(struct Client *cptr);

/** Patch up alias_primary and hs_client after the new primary is
 * created by set_nick_name; broadcast BX C so peers learn about the
 * newly-aliased local connection, and retract the demoted face from the
 * legacy links that know it (bounce_legacy_face_change).
 *
 * @param[in] demoted_alias The freshly-demoted local client.
 * @param[in] new_primary   The remote primary client that replaces it.
 * @param[in] session       The session the demote ran on (its hs_client
 *                          is NULL until this call installs new_primary).
 * @param[in] legacy_done   1 when the caller already swapped the demoted
 *                          face to new_primary toward the legacy links
 *                          (BX P): no Q is sent then.
 * @return 0 on success, -1 on mismatch.
 */
extern int bounce_finish_live_primary_demote(struct Client *demoted_alias,
                                             struct Client *new_primary,
                                             struct BouncerSession *session,
                                             int legacy_done);

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

/** Remove a client from the pending-registration queue, every entry of
 * it.  remove_client_from_list() calls it for every client it frees, so a
 * client never outlives its queue entry, whatever exit path it took.
 * Idempotent; no-op if not queued. */
extern void bounce_remove_pending_registration(struct Client *cli);

/** Returns nonzero if the given client is currently waiting in the
 * pending-registration queue (SASL completed during burst, register_user
 * deferred until burst settles).  m_nick uses this to extend the
 * "mid-SASL defer" branch through the post-SASL defer window — without
 * it, an incoming peer N for the same nick would override-kill the
 * still-Unknown deferred client. */
extern int bounce_is_pending_registration(const struct Client *cli);

/* ---------------------------------------------------------------- */
/* Legacy-face records                                               */
/* ---------------------------------------------------------------- */

/** Look up the recorded legacy face (full YYXXX) for a session toward a
 * legacy peer: the first face our burst introduced to it.  Returns NULL
 * if none is recorded for this (session, peer) pair.  Caller passes
 * peer_yxx as the legacy peer server's two-character numeric
 * (cli_yxx(peer)). */
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
 * path: a record names a face of the link that left, which a later link
 * of the same peer (even reusing the same numeric) has not been told
 * of. */
extern void bounce_clear_legacy_faces_for_peer(const char *peer_yxx);

/** Forget the session ids BS C left unmirrored here (kept apart from
 * ours, or holding losers of ours) that @a victim or a server behind it
 * announced.  Called from the SQUIT path before the downlinks exit; their
 * next burst announces those sessions again.  The marks are memory only
 * and also go at BS X for the id, or when the id is mirrored or becomes
 * ours. */
extern void bounce_unmirrored_clear_for_server(struct Client *victim);

/** Forget, in every session, the id a server announced it under before
 * taking ours (hs_peer_sessid) when that server is @a victim or behind
 * it: its clients leave with the split.  Called beside
 * bounce_unmirrored_clear_for_server(). */
extern void bounce_peer_sessid_clear_for_server(struct Client *victim);

/** Tell every direct legacy link that may know `face`
 * (bounce_legacy_link_knows, bouncer_wire.h: not IRCv3-aware, not
 * burst-gated, not the face's own direction) that it changed, except
 * toward `except_link`.  The session's burst records do not narrow it.
 *
 * new_numeric != NULL: a swap, "BX P <face> <new_numeric> <sessid|*> <nick>"
 * from us; the link renumbers its user in place, and a record of the face
 * toward that link is replaced by new_numeric.
 * new_numeric == NULL: a retraction, "Q :<reason>" from `face`.
 * Either way no record of the old face is left.
 *
 * Call it while `face` still has the numeric the links know.  Sent per
 * link (sendcmdto_one), never through a serv_butone sender: those rewrite
 * an alias source to its primary for a legacy next hop.  Each send clears
 * the S2S overrides (cptr, msgid, sessid, time): arm any a later send
 * needs after this call.
 *
 * @param[in] face        The client legacy links know by N.
 * @param[in] sess        The session the face belongs to (NULL: none);
 *                        gives the BX P its session id.
 * @param[in] except_link A link to skip (the line's own direction), or NULL.
 * @param[in] new_numeric Full YYXXX to swap the face to, or NULL to retract.
 * @param[in] reason      QUIT reason for a retraction.
 */
extern void bounce_legacy_face_change(struct Client *face,
                                      struct BouncerSession *sess,
                                      struct Client *except_link,
                                      const char *new_numeric,
                                      const char *reason);

/** Null any session's hs_client that points at this dying client, across
 * the full tokenHash.  exit_one_client's primary BOUNCER_ACTIVE / HOLDING
 * cleanup is gated on bsess->hs_client == bcptr; if a session's view of
 * its primary is stale (pre-existing burst-desync bug), that gate misses
 * and the dying client's pointer is left dangling in hs_client, causing
 * UAF in any subsequent recompute / lookup that reads hs_client.  Call
 * after the gated cleanup so any session still pointing at the corpse
 * gets nulled. */
extern void bounce_null_hs_client_pointing_at(struct Client *cli);

/** Guarded install of session->hs_client from a numeric-lookup result.
 * Refuses the install if `candidate`'s cli_account doesn't match the
 * session's hs_account, logging a warning that names the call site.
 * Returns 1 if accepted, 0 if refused (session->hs_client unchanged
 * unless candidate is NULL, in which case it is cleared). */
extern int bounce_hs_client_assign_checked(struct BouncerSession *session,
                                           struct Client *candidate,
                                           const char *site_label);

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
  /** DEMOTE: 1 when the caller already swapped the demoted face to
   * peer_primary toward the legacy links (no retraction Q then). */
  int legacy_done;
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
    struct BouncerSession *session, const char *site);

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

/** The server the session's primary (hs_client, live or a held ghost) is
 * a client of; NULL when the session has none.  This, not `hs_origin`,
 * is where the session is held: the origin a record noted goes stale (a
 * ghost rebind keeps it, a merge points it at the server merged into).
 */
extern struct Client *bounce_primary_server(struct BouncerSession *session);

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
/** A session of this account belongs to a different Keycloak user and is
 * still in use: the login is refused, never attached to it (caller
 * register_user exits the client). */
#define BOUNCE_RESUME_REJECT_KC_CONFLICT 8
/** The Keycloak id a session belongs to, as this server knows it (its
 * primary's or held ghost's, else an alias's); "" when none is known. */
extern const char *bounce_session_kc_id(struct BouncerSession *session);
/** A session that has no Keycloak id adopts @a id (the transition): the
 * session, every member here that carries none, and the network
 * (BX U kcid=).  A session that has one is never changed. */
extern void bounce_session_adopt_kc_id(struct BouncerSession *session,
                                       const char *id);
/** Does a session of @a account belong to a Keycloak id other than
 * @a kc_id?  (A missing id on either side never conflicts.) */
extern int bounce_account_kc_conflict(const char *account, const char *kc_id);
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

/** Apply one BX U field update to a bouncer alias.
 *
 * The single applier for both directions: the local-alias pass inside
 * bounce_emit_alias_update() (aliases on the primary's own server, which
 * the S2S broadcast deliberately skips for loop prevention) and the
 * bounce_alias_update() receiver (aliases reached over BX U).  Having
 * one body is the point -- the two open-coded dispatches had drifted
 * two fields apart, so local aliases silently never learned account or
 * caps changes.
 *
 * @param[in] alias  A bouncer alias with cli_user() set.  The caller has
 *                   already validated IsBouncerAlias().
 * @param[in] id     Field identity from bounce_alias_field_id().
 * @param[in] value  New value; "" clears for account.
 */
extern void bounce_apply_alias_field(struct Client *alias,
                                     enum BounceAliasField id,
                                     const char *value);

/** Apply an account deauthorization to one client, locally.
 *
 * The shared body of every deauth: the AC U receiver (ms_account) and
 * the Keycloak webhook both call it.  They had separate copies and the
 * copies drifted -- the webhook's omitted the session destroy and the
 * metadata clear, so the deauthing server kept a revivable session and a
 * bounce_db record for an account every peer had discarded.
 *
 * Does NOT emit anything on the network and does NOT send the
 * CAP_ACCNOTIFY channel notice: the receiver relays while the originator
 * broadcasts, and each wraps the notice in its own msgid, so both stay
 * at the call site.
 *
 * The account string is still set on entry and cleared on exit -- the
 * metadata and presence lookups key off it.  The account timestamp and
 * the Keycloak id go with it: they are the removed account's, not the
 * next one's.
 *
 * Every session of the account goes, and a held session whose ghost is
 * acptr loses its aliases too (the way a KILL of the ghost would): with
 * the account gone there is nothing to revive into.  The ghost itself is
 * left to the caller, which is still using acptr.
 *
 * @param[in] acptr  A client with IsAccount() set.
 * @return Non-zero when acptr is a local held ghost that the caller must
 *         now exit (ClearBouncerHold + exit_client) once it is done with
 *         it: its session is gone and no timer will ever remove it.
 */
extern int bounce_account_deauth_apply(struct Client *acptr);

/** Null every alias's alias_primary that points at a departing client.
 *
 * The mirror of bounce_null_hs_client_pointing_at() for the other
 * direction.  exit_client() does not promote or reap aliases when hold
 * is disabled (bounce_should_hold() returning NULL, e.g. G-line
 * enforcement), so a surviving alias can outlive its primary; once
 * free_client() recycles the struct, the next alias->primary rewrite in
 * ircd_relay.c reads freed memory.
 *
 * @param[in] gone  The client being removed.
 */
extern void bounce_null_alias_primary_pointing_at(struct Client *gone);

#endif /* INCLUDED_bouncer_session_h */
