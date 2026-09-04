---
name: bouncer-architecture
description: Nefarious bouncer subsystem reference — persistent account-anchored sessions, the alias multi-connection model, connection-class SASL gating, burst/convergence, and the hard invariants and audit rules that prevent cross-server session loss and crashes. Read before writing or modifying bouncer code (bounce_* functions, BS/BX P10 tokens, alias promotion, hold/revive paths).
---

# Bouncer Architecture Skill

Reference for Nefarious's bouncer subsystem: persistent account-anchored sessions, the alias multi-connection model, connection-class gating, and the hard invariants that keep cross-server state consistent. Read this before writing or modifying bouncer code.

> Direction: **sessions are configuration profiles, not identities.** One bouncer identity per account; per-profile channel lists reconcile to a network-membership union. Multi-session-as-multi-identity is OFF the roadmap. The `(account, sessid)` keying shape still works but now means `(account, profile)`.

## Session System

- `bounce_revive()` transplants a new client's socket onto a HOLDING ghost. Must transfer **ALL** connection metadata (IP, listener, confs, sockhost, port) or the ghost retains stale data.
- `bounce_create_ghost()` creates MDBX-restored ghosts via `make_client(NULL, ...)`, which allocates a Connection → `MyConnect(ghost) = TRUE`. Hold-awareness in /CHECK comes from session-state inspection (`bounce_get_session()` / hold_str), and WHO shows held ghosts with a `G` away-flag (the lone `IsBouncerHold` display guard, in `whocmds.c`) — there are no `IsBouncerHold()` guards in CHECK or WHOIS.
- `BounceSessionRecord` persists connection metadata (IP, sockhost, listener port); the on-disk record is at `BOUNCER_DB_VERSION 9` (legacy v7/v8 migration structs still present). Reconciled on revive.
- `cli_session_id` must be synced from `hs_sessid` on every session-establishing path (`bounce_attach`, `bounce_setup_local_alias`, AND `bounce_revive`). Revived ghosts otherwise carry freshly-minted sessids from `bounce_create_ghost`, breaking any code that keys on agreement.
- **Shadow system fully removed**: all shadow functions, structs (`ShadowConnection`), globals (`current_shadow`, `suppress_shadow_dup`, `mirror_to_shadows`) and the BS S/W/N/R/O/XS relay deleted (~3000+ lines across 20+ files). Aliases are the only multi-connection mechanism.

## Alias System

- Each alias connection gets its **own Client struct** with its own P10 numeric, CAP state, and `CHFL_ALIAS` channel memberships. Normal IRC routing works without special duplication.
- Aliases are introduced via **BX C, not the N token** — other servers must never receive a Q token for an alias. `exit_client()` sends **BX X** instead.
- `m_quit()` and the `s_bsd.c` disconnect handler have early returns for aliases — they skip hold logic.
- `bounce_promote_alias()` promotes alias→primary on disconnect — the most recently ACTIVE alias wins (local: idle clock; remote: `ba_last_active`, kept live by `BX U <numeric> la=<ts>` on each connection's first message after 5 min quiet, since 2026-09-03), oldest connection as the tiebreak — and sets `hs_state = BOUNCE_ACTIVE` after promoting. `bounce_session_last_active()` gives the session-wide last activity (WHOIS idle uses it). `m_quit` immediate-promotes local aliases; cross-server (remote-alias-only) still defers.
- **Session move** (cross-server): `bounce_alias_create()` calls `bounce_promote_alias()` then exits the ghost with `FLAG_BOUNCER_INTERNAL_DESTROY` (`SetBouncerInternalDestroy`), gated on promote success — NOT `FLAG_KILLED`, which would trigger whole-session teardown (the opposite of a seamless move). The BX P handler on remote replicas must ALSO set `hs_state = BOUNCE_ACTIVE`.
- `CapRecipientHas(cli, cap)` is simplified to just `CapOwnHas(cli, cap)` — each alias owns its caps. `CapRouteContext` (renamed from `ShadowTagContext`) handles per-connection cap routing in channel send functions.

## Connection Classes

- `CRFLAG_BOUNCER` forces bouncer auto-create/resume per-class.
- `CRFLAG_REQUIRE_SASL` gates connections until SASL is available. The check in `attach_iline()` (s_conf.c) must consider ALL SASL sources: `sasl_local_available()`, `auth_iauth_handles_sasl()`, `get_sasl_mechanisms()`, and the legacy fallback.
- For legacy services (no dynamic mechanism broadcast), `require_sasl` falls back to `FEAT_SASL_DEFAULT_MECHANISMS` + a server-connectivity check.
- `include/class.h` holds the `ClassRestrictFlags` enum.

## Hard Invariants & Audit Rules

These are the rules whose violation has repeatedly caused crashes or session loss. Treat each as a checklist item when touching the relevant path.

1. **`hs_state = BOUNCE_ACTIVE` must be set in BOTH `bounce_promote_alias()` AND the BX P S2S handler** — promote runs locally, BX P runs on replicas. Missing either destroys the session on disconnect.
2. **Every `cli_name(alias)=` rename for a `MyConnect(alias)` must be paired with `sendcmdto_one(alias, CMD_NICK, …)`** — otherwise the alias's own socket never sees the NICK echo (covered by the bouncer-nick-lockstep integration test in the testnet harness).
3. **Any `%s%s` P10-numeric construction in a BS-token handler must use `cli_yxx(sptr)` (live sender), never `session->hs_origin`** (recorded at create-time, stale after cross-server rebind). Using hs_origin caused live-session hijack onto a leftover ghost during burst convergence.
4. **Any new emit between the 005 block and `motd_signon` in `register_user()` must be mirrored on both bouncer fast paths** (`bounce_revive` + `bounce_setup_local_alias`), which hand-roll the welcome block and skip register_user's tail.
5. **Every S2S `CMD_NICK` introduction must call `bounce_set_n_sessid_hint()` before emit.**
6. **Don't add a flag to spare an alias from the session-destroy cascade** — `FLAG_KILLED` on any alias triggers whole-session teardown (s_misc.c:347-369) by design; cross-boundary legacy collision means whole-session loss. Fix outcomes, not consequences. (There is no `FLAG_KILL_NICK_COLLISION` — don't introduce one to gate this.)
7. **The reconcile yield must broadcast Q, not suppress via `FLAG_KILLED`** — enforced in the BS C reconcile handler (`bounce_handle_bsc`): the losing ghost is exited via `exit_client(..., "Bouncer session moved")` so the normal Q cleans up the peer's phantom; suppressing it leaves a stale ghost. (The old BX R token that carried this is retired in Phase 5.)
8. **`set_nick_name` MyUser(sptr) block must use `sptr`, not `cptr`** — alias-source rewrite breaks the historical cptr==sptr invariant and deref's `cli_user(server)==NULL` on cross-server alias rename (SIGSEGV).
9. **UserStats opers/inv_clients must balance across the alias lifecycle** — `bounce_copy_umodes` ++/-- under a MyConnect gate on FLAG_OPER/FLAG_INVISIBLE transitions, and the `exit_one_client` alias/hold branches mirror the normal-path decrement (also MyConnect-gated). Adding only the exit decrement underflows and asserts.
10. **Every S2S egress sourced from a client must rewrite alias→primary for legacy / not-BX-aware peers.** Aliases are introduced via BX C, which legacy peers silently drop, so an alias numeric on the wire toward a legacy peer is an unknown source — the message gets silently dropped on receive (no `ERR_SERVICESDOWN`, no `421`). Audit checklist: any new `sendcmdto_one(sptr, CMD_PRIVATE|CMD_NOTICE, ...)` toward a non-`MyConnect` target needs `from = (IsBouncerAlias(sptr) && cli_user(sptr)->alias_primary) ? cli_user(sptr)->alias_primary : sptr` with the appropriate direction guard (`cli_from(from) == acptr` when acptr is the destination server; `cli_from(from) == cli_from(acptr)` when acptr is a remote user). The pre-existing omission in `relay_directed_message` / `relay_directed_notice` (`ircd_relay.c`) caused `X3 ping`-style Pseudo commands to silently fail for users currently in alias status — fixed by mirroring `relay_private_message`'s rewrite block at all four directed-relay send sites. **Hunt-routed commands** (`hunt_server_cmd` / `hunt_server_prio_cmd`, s_user.c — WHOIS/STATS/LINKS/MOTD/etc.) were the next miss (2026-09-02): an alias's routed `WHOIS nick nick` died silently at the first legacy hop. Both now rewrite alias→primary except toward the primary's own direction. **Companion rule:** `send_buffer` delivers only to the addressed connection, so a reply addressed to the rewritten primary would land on the *other* device — `do_numeric` therefore mirrors S2S-arriving plain numerics for a local primary to its local aliases (never label-batched ones). Any new alias→primary egress rewrite needs a reply-delivery story for the asking connection.

## Burst & Convergence

- The `server_estab` burst gate is dynamic: skipped when `bounce_convergence_pending()` returns 0, with event-driven release at attach/revive/EB. The 30s timer is now a stall-fallback only.
- The N-burst tail is gated dynamically by `bounce_convergence_pending()` and released event-driven by `bounce_release_idle_gates()` at convergence-completion sites (plus a 1s fallback tick). The old `BX F`/`BX R`/`BX J` handshake tokens are **retired (Phase 5) — silently dropped** by the BX handler; `FLAG_BXF_AWARE` is still announced on link but its token handler is now a no-op. Held ghosts remain visible to legacy peers; phantom cleanup is via a normal Q.
- `bounce_post_burst_reconcile` (in `ms_end_of_burst`) merges multi-primary-same-session states that survive cross-sessid convergence and that the D.2 at-N-time check misses (no nick collision). Legacy_face suppression in s_serv.c is session-keyed so non-bouncer same-account clients aren't hidden from legacy peers.
- `bounce_peer_has_inbound_data()` guards `bounce_auto_resume`'s "no session, create new" path; `BOUNCE_RESUME_DEFER_PEER_INBOUND` defers, the BS C handler triggers a drain (steady-state BS C race).

## Key Files

- `ircd/bouncer_session.c` — core bouncer logic
- `include/bouncer_session.h` — session/alias structs
- `ircd/send.c` + `include/send.h` — message routing, `CapRouteContext`
- `ircd/m_check.c` — /CHECK (alias display)
- `ircd/s_user.c` — `register_user()` calls `bounce_auto_resume`
- `include/class.h` — `ClassRestrictFlags`

For the per-fix history behind these rules, see the relevant commit messages (`git log ircd/bouncer_session.c`).
