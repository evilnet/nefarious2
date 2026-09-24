/*
 * IRC - Internet Relay Chat, include/webhook_eventlog.h
 * Copyright (C) 2026 Afternet
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
 * any later version.
 */
/** @file
 * @brief The applied-events log: the Keycloak webhook events this server
 * has applied, keyed by the event id.
 *
 * Every server receives every event (directly from the SPI, through the
 * CI relay of a peer, or through a peer's catch-up at end of burst), so
 * the same event reaches a server more than once.  This ring remembers
 * what was applied: a copy whose id is already here is answered and
 * counted, never applied or relayed again.  It also feeds the catch-up a
 * server sends a newly linked peer.
 *
 * Pure: no ircd state, no sockets; safe in every build variant.
 */
#ifndef INCLUDED_webhook_eventlog_h
#define INCLUDED_webhook_eventlog_h

#include "ircd_defs.h"      /* ACCOUNTLEN */
#include "account_id.h"     /* ACCOUNT_ID_LEN */
#include <time.h>

/** Longest event id kept, with its terminator (Keycloak's are 36-char uuids). */
#define WH_EVENT_ID_LEN 40
/** Defaults for the WEBHOOK_EVENTLOG_SIZE / _WINDOW features. */
#define WH_EVENTLOG_DEFAULT_SIZE   1024
#define WH_EVENTLOG_DEFAULT_WINDOW 86400

/** The kind letter a relay carries. */
#define WH_RELAY_PURGE      'P'   /**< purge the caches only */
#define WH_RELAY_DELETE     'D'   /**< the account was deleted */
#define WH_RELAY_DISABLE    'X'   /**< the account was disabled */
#define WH_RELAY_RESET      'R'   /**< an admin reset the password */
#define WH_RELAY_CREDENTIAL 'C'   /**< a credential was removed */
#define WH_RELAY_ENABLE     'E'   /**< the account was enabled again */

struct WebhookEventLogEntry {
  char   id[WH_EVENT_ID_LEN];
  char   kind;
  char   kc_id[ACCOUNT_ID_LEN + 1];   /**< "" when unknown */
  char   username[ACCOUNTLEN + 1];    /**< "" when unknown */
  time_t applied;
};

/** Size (or re-size) the log; keeps nothing.  0 = the default size. */
extern void webhook_eventlog_init(unsigned int capacity);

/** 1 when the id may travel the wire and sit in the log: 1 to
 * WH_EVENT_ID_LEN - 1 characters, each of [A-Za-z0-9._:-]. */
extern int webhook_eventlog_valid_id(const char *id);
/** 1 for one of the kind letters above. */
extern int webhook_eventlog_valid_kind(char kind);

/** Remember an applied event.
 * @return 0 when it was recorded now (or the id is not valid: nothing
 *         stored), 1 when it was already there (nothing changed). */
extern int webhook_eventlog_record(const char *id, char kind, const char *kc_id,
                                   const char *username, time_t now);
/** 1 when the id is in the log. */
extern int webhook_eventlog_seen(const char *id);

/** Emit the entries applied at or after @a oldest, oldest first, at most
 * @a max of them.  @return the number emitted. */
extern unsigned int webhook_eventlog_since(time_t oldest,
                                           void (*emit)(const struct WebhookEventLogEntry *, void *),
                                           void *data, unsigned int max);
/** Entries in the log. */
extern unsigned int webhook_eventlog_count(void);
/** The earliest applied time in the log, 0 when empty. */
extern time_t webhook_eventlog_oldest(void);

/** A relay line as it travels the wire:
 *  CI <username|*> <kc_id|*> <event_id> <kind> [B]
 *  The trailing B marks a catch-up line sent at end of burst. */
struct WebhookRelay {
  const char *username;   /**< NULL when the line says "*" */
  const char *kc_id;      /**< NULL when the line says "*" (its alphabet is the caller's check) */
  const char *event_id;
  char        kind;
  int         catchup;
};

/** Parse parv[1..] of a five- or six-parameter CI.  @return 1 and fill
 * @a out, or 0 when the line is not one to apply (too short, an event id
 * or kind that may not travel the wire, an empty name, a marker other
 * than B). */
extern int webhook_relay_parse(int parc, char *parv[], struct WebhookRelay *out);

#endif /* INCLUDED_webhook_eventlog_h */
