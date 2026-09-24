/*
 * IRC - Internet Relay Chat, ircd/webhook_eventlog.c
 * Copyright (C) 2026 Afternet
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
 * any later version.
 */
/** @file
 * @brief The applied-events log (see webhook_eventlog.h).
 *
 * A ring of entries overwritten oldest-first at capacity.  Scans are
 * linear: the log holds at most a few thousand entries, a lookup happens
 * once per delivered or relayed event, and the ordered walk once per
 * link.  Only libc is used, so the cmocka suite and every build variant
 * see the same code.
 */
#include "webhook_eventlog.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static struct WebhookEventLogEntry *ring = NULL;
static unsigned int ring_cap = 0;
static unsigned int ring_next = 0;    /* the slot the next new entry takes */
static unsigned int ring_count = 0;

void webhook_eventlog_init(unsigned int capacity)
{
  free(ring);
  ring_cap = capacity ? capacity : WH_EVENTLOG_DEFAULT_SIZE;
  ring = (struct WebhookEventLogEntry *)calloc(ring_cap, sizeof(*ring));
  if (!ring)
    ring_cap = 0;
  ring_next = 0;
  ring_count = 0;
}

int webhook_eventlog_valid_id(const char *id)
{
  size_t i;

  if (!id || !id[0])
    return 0;
  for (i = 0; id[i]; i++) {
    unsigned char c = (unsigned char)id[i];
    if (i >= WH_EVENT_ID_LEN - 1)
      return 0;
    if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
          || c == '.' || c == '_' || c == ':' || c == '-'))
      return 0;
  }
  return 1;
}

int webhook_eventlog_valid_kind(char kind)
{
  switch (kind) {
  case WH_RELAY_PURGE:
  case WH_RELAY_DELETE:
  case WH_RELAY_DISABLE:
  case WH_RELAY_RESET:
  case WH_RELAY_CREDENTIAL:
  case WH_RELAY_ENABLE:
    return 1;
  default:
    return 0;
  }
}

/** The slot holding @a id, or -1. */
static int find_slot(const char *id)
{
  unsigned int i;

  for (i = 0; i < ring_count; i++)
    if (strcmp(ring[i].id, id) == 0)
      return (int)i;
  return -1;
}

int webhook_eventlog_record(const char *id, char kind, const char *kc_id,
                            const char *names, time_t now)
{
  struct WebhookEventLogEntry *e;

  if (!ring || !webhook_eventlog_valid_id(id))
    return 0;
  if (find_slot(id) >= 0)
    return 1;

  e = &ring[ring_next];
  memset(e, 0, sizeof(*e));
  snprintf(e->id, sizeof(e->id), "%s", id);
  e->kind = kind;
  if (kc_id)
    snprintf(e->kc_id, sizeof(e->kc_id), "%s", kc_id);
  if (names && strcmp(names, "*") != 0)
    snprintf(e->names, sizeof(e->names), "%s", names);
  e->applied = now;

  ring_next = (ring_next + 1) % ring_cap;
  if (ring_count < ring_cap)
    ring_count++;
  return 0;
}

int webhook_eventlog_seen(const char *id)
{
  if (!ring || !id || !id[0])
    return 0;
  return find_slot(id) >= 0;
}

static int by_applied(const void *a, const void *b)
{
  const struct WebhookEventLogEntry *ea = *(const struct WebhookEventLogEntry *const *)a;
  const struct WebhookEventLogEntry *eb = *(const struct WebhookEventLogEntry *const *)b;
  if (ea->applied < eb->applied) return -1;
  if (ea->applied > eb->applied) return 1;
  return 0;
}

unsigned int webhook_eventlog_since(time_t oldest,
                                    void (*emit)(const struct WebhookEventLogEntry *, void *),
                                    void *data, unsigned int max)
{
  const struct WebhookEventLogEntry **order;
  unsigned int i, n = 0, sent = 0;

  if (!ring || !emit || !ring_count || !max)
    return 0;
  order = (const struct WebhookEventLogEntry **)calloc(ring_count, sizeof(*order));
  if (!order)
    return 0;
  for (i = 0; i < ring_count; i++)
    if (ring[i].applied >= oldest)
      order[n++] = &ring[i];
  qsort(order, n, sizeof(*order), by_applied);
  for (i = 0; i < n && sent < max; i++, sent++)
    emit(order[i], data);
  free(order);
  return sent;
}

unsigned int webhook_eventlog_count(void)
{
  return ring_count;
}

time_t webhook_eventlog_oldest(void)
{
  unsigned int i;
  time_t oldest = 0;

  for (i = 0; i < ring_count; i++)
    if (!oldest || ring[i].applied < oldest)
      oldest = ring[i].applied;
  return oldest;
}

int webhook_relay_parse(int parc, char *parv[], struct WebhookRelay *out)
{
  if (!parv || !out || parc < 5)
    return 0;
  if (!parv[1] || !parv[1][0] || !parv[2] || !parv[2][0] || !parv[3] || !parv[4])
    return 0;
  if (!webhook_eventlog_valid_id(parv[3]))
    return 0;
  if (parv[4][0] == '\0' || parv[4][1] != '\0' || !webhook_eventlog_valid_kind(parv[4][0]))
    return 0;
  if (parc >= 6 && (!parv[5] || strcmp(parv[5], "B") != 0))
    return 0;

  out->username = strcmp(parv[1], "*") == 0 ? NULL : parv[1];
  out->kc_id    = strcmp(parv[2], "*") == 0 ? NULL : parv[2];
  out->event_id = parv[3];
  out->kind     = parv[4][0];
  out->catchup  = parc >= 6;
  return 1;
}
