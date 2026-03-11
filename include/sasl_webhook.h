/*
 * IRC - Internet Relay Chat, include/sasl_webhook.h
 * Copyright (C) 2026 Afternet Development
 *
 * Keycloak webhook handler for Nefarious.
 * Receives admin events from Keycloak and invalidates auth caches,
 * kills sessions on account disable/delete, etc.
 *
 * TCP/HTTP/JSON infrastructure is provided by libkc's kc_webhook module.
 * This module provides the business-logic callback.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
 * any later version.
 */
#ifndef INCLUDED_sasl_webhook_h
#define INCLUDED_sasl_webhook_h

#include <time.h>

/** Nefarious webhook statistics (business-logic layer). */
struct sasl_webhook_stats {
  unsigned long events_processed;
  unsigned long cache_invalidations;
  unsigned long sessions_killed;
  unsigned long credential_events;
  unsigned long user_events;
  unsigned long session_events;
  time_t        last_event_time;
};

/** Initialize the Keycloak webhook listener.
 *  Requires libkc transport (kc_init) to have been called first.
 *  @param port       Listen port (0 = disabled).
 *  @param secret     Shared secret for X-Webhook-Secret validation (may be NULL).
 *  @return 0 on success, -1 on error.
 */
extern int sasl_webhook_init(int port, const char *secret);

/** Shutdown the webhook listener. */
extern void sasl_webhook_shutdown(void);

/** Get webhook statistics. */
extern void sasl_webhook_stats_get(struct sasl_webhook_stats *out);

#endif /* INCLUDED_sasl_webhook_h */
