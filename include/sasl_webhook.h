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
  unsigned long rejections;            /* refusals the listener reported (all causes) */
  time_t        last_rejection;
  char          last_reject_cause[32];
  /* Webhook plan 4: every server receives every event; these say which
   * path each applied event came by and what was dropped as already applied. */
  unsigned long applied_direct;        /* applied from a delivery to this server */
  unsigned long applied_relay;         /* applied from a peer's CI relay */
  unsigned long applied_catchup;       /* applied from a peer's catch-up at link time */
  unsigned long already_direct;        /* deliveries dropped: already applied */
  unsigned long already_relay;         /* relays (and catch-up lines) dropped: already applied */
  unsigned long relays_sent;           /* five-parameter CI lines this server originated */
  unsigned long relays_forwarded;      /* relays passed on after applying */
  unsigned long catchup_sent;          /* catch-up lines sent to newly linked peers */
  unsigned long catchup_received;
};

struct kc_webhook_config;
struct Client;
struct StatDesc;

/** Initialize the Keycloak webhook listener from the parsed Webhook block.
 *  Requires libkc transport (kc_init) to have been called first.  The
 *  block reaches libkc whole (bind address, path, limits, signature window,
 *  legacy-secret switch, realm); the rejection callback is set here.  The
 *  handler's counters survive a re-init.
 *  @param cfg  The listener configuration (port <= 0 = disabled).
 *  @return 0 on success, -1 on error.
 */
extern int sasl_webhook_init(const struct kc_webhook_config *cfg);

/** Shutdown the webhook listener. */
extern void sasl_webhook_shutdown(void);

/** Get webhook statistics. */
extern void sasl_webhook_stats_get(struct sasl_webhook_stats *out);

/** Catch a newly linked IRCv3-aware peer up on the events applied here
 *  within WEBHOOK_EVENTLOG_WINDOW (webhook plan 4); called at the end of
 *  its burst. */
extern void sasl_webhook_link_catchup(struct Client *cptr);

/** STATS webhook: the listener's transport counters and refusals by cause,
 *  then the handler's counters. */
extern void sasl_webhook_report_stats(struct Client *to, const struct StatDesc *sd, char *param);

#endif /* INCLUDED_sasl_webhook_h */
