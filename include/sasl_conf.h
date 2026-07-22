/*
 * IRC - Internet Relay Chat, include/sasl_conf.h
 * Copyright (C) 2026 Nefarious Development
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
 * @brief Parsed Keycloak/Webhook configuration blocks.
 *
 * Owns the "pending" (during-parse) and "active" (currently in libkc)
 * representations of the Keycloak {} and Webhook {} config blocks.
 * Parser writes via the set_* APIs during block parsing; s_conf.c calls
 * sasl_conf_reset_pending() before yyparse() and sasl_conf_apply() after
 * feature_mark() to push any change into libkc.
 *
 * When no block is present, falls back to the legacy F_S/F_I features
 * (FEAT_KEYCLOAK_URL/REALM/CLIENT_ID/CLIENT_SECRET and
 *  FEAT_WEBHOOK_PORT/SECRET) for backward compatibility.
 */
#ifndef INCLUDED_sasl_conf_h
#define INCLUDED_sasl_conf_h

/* ---- Parser-facing API (called from ircd_parser.y) ---- */

/** Clear the pending state for both blocks.  Called before each yyparse(). */
extern void sasl_conf_reset_pending(void);

/** Mark that a Keycloak {} block was parsed (called on block entry). */
extern void sasl_conf_keycloak_begin(void);
extern void sasl_conf_keycloak_set_url(const char *s);
extern void sasl_conf_keycloak_set_realm(const char *s);
extern void sasl_conf_keycloak_set_client_id(const char *s);
extern void sasl_conf_keycloak_set_client_secret(const char *s);
extern void sasl_conf_keycloak_set_issuer(const char *s);
extern void sasl_conf_keycloak_set_allowed_clients(const char *s);
extern void sasl_conf_keycloak_set_insecure_token_validation(int v);

/** Mark that a Webhook {} block was parsed (called on block entry). */
extern void sasl_conf_webhook_begin(void);
extern void sasl_conf_webhook_set_port(int port);
extern void sasl_conf_webhook_set_secret(const char *s);
extern void sasl_conf_webhook_set_vhost(const char *s);
extern void sasl_conf_webhook_set_path(const char *s);
extern void sasl_conf_webhook_set_max_connections(int n);
extern void sasl_conf_webhook_set_max_request_size(int n);
extern void sasl_conf_webhook_set_queue_max(int n);
extern void sasl_conf_webhook_set_batch_size(int n);

/** Apply pending state.  Called once per yyparse() at end of read_configuration_file().
 * - If a block was parsed, the block values take effect.
 * - If a block was NOT parsed, falls back to legacy F_S/F_I features.
 * - On any change, re-inits libkc / sasl_webhook accordingly.
 * - Safe to call even before libkc is initialised (boot path); will defer the
 *   actual init until sasl_conf_boot_apply() runs.
 */
extern void sasl_conf_apply(void);

/** Boot-time apply.  Called from ircd.c main() once libkc is up.
 * Forces any pending-but-deferred init to run.  No-op on REHASH (already applied).
 */
extern void sasl_conf_boot_apply(void);

#endif /* INCLUDED_sasl_conf_h */
