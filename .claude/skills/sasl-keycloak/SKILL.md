---
name: sasl-keycloak
description: Nefarious SASL and Keycloak reference — local SASL via Keycloak ROPC through libkc, three-tier AUTHENTICATE dispatch (local Keycloak / IAuth / P10 relay), the mechanism support matrix, cross-server cache coherence (CI token), and Keycloak REST gotchas. Use when working on SASL authentication, the libkc integration, or Keycloak-backed accounts.
---

# SASL / Keycloak Skill

Reference for Nefarious's local SASL path (direct Keycloak auth via libkc) and its three-tier dispatch. For the P10 SASL relay wire format see the `p10-protocol` skill; for libkc's event integration see the `nefarious-codebase` skill.

## Local SASL (Keycloak Direct)

- `sasl_auth.c` / `sasl_auth.h` — local SASL PLAIN via a Keycloak ROPC grant through libkc.
- Three-tier dispatch in `m_authenticate.c`: **local Keycloak → IAuth → P10 relay**.
- `sasl_local_available()` checks `sasl_local_initialized && FEAT_SASL_LOCAL && kc_sasl_healthy`.
- Health tracking via `sasl_health_cb` — toggles CAP NEW/DEL for the `sasl` capability.
- libkc `CURLOPT_POSTFIELDSIZE` must be set **before** `CURLOPT_COPYPOSTFIELDS` (per curl docs).

## Mechanism Support

- **PLAIN** — works via SASL_LOCAL, iauthd-ts, and services (X3) relay.
- **OAUTHBEARER** — SASL_LOCAL only.
- **EXTERNAL** — services (X3) relay only.
- **SCRAM / ECDSA** — not implemented anywhere yet; advertised but non-functional.

## Caches & Cross-Server Coherence

- Auth caches: SipHash-2-4 negative/positive; webhook handler with deauth via `AC U`.
- CI token for cross-server cache coherence; multi-URL webhook delivery.
- **CI token**: `CACHEINVAL` / `CI` — a new P10 token, silently ignored by legacy servers. Handled by `ms_cacheinval()` in `sasl_webhook.c`.

## Transition Architecture

Read-only LDAP federation short-term (no services-side changes); Keycloak as authority long-term.

## Keycloak REST Gotchas

- `PUT /admin/realms/{realm}/users/{id}` requires the FULL user representation; omitted fields get cleared. GET → merge → PUT, and update the `kc_user_repr_cache` AFTER merging (not before).
- Strip `credentials` from cached reprs — including them in a PUT ADDS a credential rather than replacing, causing duplicate passwords.
- Concurrent updates to the same user race on the cache: update the cache immediately after merging your changes (before the PUT completes) or the second writer overwrites the first.

## Secrets

`KEYCLOAK_CLIENT_SECRET` and `WEBHOOK_SECRET` are deployment secrets — never paste secret values into this skill, a committed config, or any tracked file. Use templating/externalization for any config that carries them.
