/*
 * IRC - Internet Relay Chat, ircd/chathistory_ephemeral.c
 * Copyright (C) 2026 Nefarious Development Team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
/** @file
 * @brief In-memory PM ring for ephemeral↔ephemeral conversations.
 */
#include "config.h"

#include "chathistory_ephemeral.h"

#include "client.h"
#include "history.h"
#include "ircd_alloc.h"
#include "ircd_features.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "s_user.h"
#include "struct.h"        /* full struct User layout for cli_user()->username/host */

#include <stddef.h>
#include <string.h>

/** Conservative per-Client byte cap floor.  Even with a misconfigured
 * FEAT_EPHEMERAL_HISTORY_BYTES we keep enough space for at least a
 * couple of messages, otherwise insertion would drop entries faster
 * than it can add them and the ring would always be empty. */
#define EPHEMERAL_RING_MIN_BYTES 2048u

static size_t ring_byte_cap(void)
{
  int v = feature_int(FEAT_EPHEMERAL_HISTORY_BYTES);
  if (v < (int)EPHEMERAL_RING_MIN_BYTES)
    return EPHEMERAL_RING_MIN_BYTES;
  return (size_t)v;
}

/** Estimate the in-memory footprint of a new entry.  Used for the
 * byte-cap accounting; doesn't have to be exact, just monotone with
 * actual allocation cost. */
static size_t entry_bytes(const char *content, const char *tags)
{
  return sizeof(struct EphemeralPmEntry)
         + (content ? strlen(content) : 0)
         + (tags    ? strlen(tags)    : 0);
}

/** Build the canonical "lowerNick:higherNick" pair-key for two
 * clients, matching store_private_history's ordering exactly so both
 * sides agree on the target string. */
static void build_pair_target(const struct Client *a, const struct Client *b,
                              char *out, size_t outsz)
{
  const char *n1, *n2;
  if (ircd_strcmp(cli_name(a), cli_name(b)) < 0) {
    n1 = cli_name(a); n2 = cli_name(b);
  } else {
    n1 = cli_name(b); n2 = cli_name(a);
  }
  ircd_snprintf(0, out, outsz, "%s:%s", n1, n2);
}

/** Build "nick!user@host" sender form to mirror what history.c does
 * on retrieval; clients can ignore it but having it match the LMDB
 * format keeps the replay layer simpler. */
static void build_sender(const struct Client *cli, char *out, size_t outsz)
{
  if (cli_user(cli))
    ircd_snprintf(0, out, outsz, "%s!%s@%s",
                  cli_name(cli),
                  cli_user(cli)->username,
                  cli_user(cli)->host);
  else
    ircd_strncpy(out, cli_name(cli), outsz - 1);
}

/** Allocate the ring on first use.  Returns the (possibly new) ring;
 * never NULL unless @a cli is bad. */
static struct EphemeralPmRing *ring_get(struct Client *cli)
{
  if (!cli)
    return NULL;
  if (!cli_ephemeral_pm(cli))
    cli_ephemeral_pm(cli) =
        (struct EphemeralPmRing *)MyCalloc(1, sizeof(struct EphemeralPmRing));
  return cli_ephemeral_pm(cli);
}

/** Drop the oldest entry; updates accounting.  Caller must ensure
 * head is non-NULL. */
static void ring_drop_oldest(struct EphemeralPmRing *r)
{
  struct EphemeralPmEntry *doomed = r->head;
  r->head = doomed->next;
  if (!r->head)
    r->tail = NULL;
  r->total_bytes -= doomed->bytes;
  r->count--;
  MyFree(doomed);
}

/** Append @a e to @a r and evict oldest entries until the total
 * footprint is under the configured cap.  Takes ownership of @a e. */
static void ring_append(struct EphemeralPmRing *r, struct EphemeralPmEntry *e)
{
  size_t cap = ring_byte_cap();
  e->next = NULL;
  if (r->tail)
    r->tail->next = e;
  else
    r->head = e;
  r->tail = e;
  r->total_bytes += e->bytes;
  r->count++;
  while (r->head && r->total_bytes > cap)
    ring_drop_oldest(r);
}

/** Build one entry from the source data; returns NULL if it would
 * exceed the cap on its own (huge single message). */
static struct EphemeralPmEntry *make_entry(struct Client *sender,
                                            struct Client *recipient,
                                            const char *text,
                                            enum HistoryMessageType type,
                                            const char *msgid,
                                            const char *timestamp,
                                            const char *client_tags)
{
  struct EphemeralPmEntry *e;
  size_t bytes = entry_bytes(text, client_tags);
  if (bytes > ring_byte_cap())
    return NULL;
  e = (struct EphemeralPmEntry *)MyCalloc(1, sizeof(*e));
  ircd_strncpy(e->msgid, msgid ? msgid : "", sizeof(e->msgid) - 1);
  ircd_strncpy(e->timestamp, timestamp ? timestamp : "", sizeof(e->timestamp) - 1);
  build_pair_target(sender, recipient, e->target, sizeof(e->target));
  ircd_strncpy(e->original_target, cli_name(recipient), sizeof(e->original_target) - 1);
  build_sender(sender, e->sender, sizeof(e->sender));
  e->type = type;
  if (text)
    ircd_strncpy(e->content, text, sizeof(e->content) - 1);
  if (client_tags)
    ircd_strncpy(e->client_tags, client_tags, sizeof(e->client_tags) - 1);
  e->bytes = bytes;
  return e;
}

void chathistory_ephemeral_store_pair(struct Client *sender,
                                       struct Client *recipient,
                                       const char *text,
                                       enum HistoryMessageType type,
                                       const char *msgid,
                                       const char *timestamp,
                                       const char *client_tags)
{
  if (!sender || !recipient || !text || !msgid || !timestamp)
    return;
  /* Each side gets its own copy on its own server.  We only have
   * access to rings of locally-connected Clients; the remote side
   * stores via its own server's relay path when the message lands
   * there.  No-op for an end that isn't local — keeps the ring memory
   * proportional to local users.
   *
   * Each ring's eviction state is also independent, so even when both
   * sides are local we allocate two entries rather than aliasing one
   * (a shared entry would be a use-after-free hazard when one side
   * hits the cap and frees while the other still references it). */
  if (MyConnect(sender)) {
    struct EphemeralPmEntry *e =
        make_entry(sender, recipient, text, type, msgid, timestamp, client_tags);
    if (e) {
      struct EphemeralPmRing *r = ring_get(sender);
      if (r) ring_append(r, e);
      else   MyFree(e);
    }
  }
  if (MyConnect(recipient)) {
    struct EphemeralPmEntry *e =
        make_entry(sender, recipient, text, type, msgid, timestamp, client_tags);
    if (e) {
      struct EphemeralPmRing *r = ring_get(recipient);
      if (r) ring_append(r, e);
      else   MyFree(e);
    }
  }
}

/** Allocate a HistoryMessage and copy fields from a ring entry.
 * Returns NULL on allocation failure (caller has nothing to clean
 * up). */
static struct HistoryMessage *entry_to_history(const struct EphemeralPmEntry *e)
{
  struct HistoryMessage *m =
      (struct HistoryMessage *)MyCalloc(1, sizeof(struct HistoryMessage));
  if (!m)
    return NULL;
  ircd_strncpy(m->msgid, e->msgid, sizeof(m->msgid) - 1);
  ircd_strncpy(m->timestamp, e->timestamp, sizeof(m->timestamp) - 1);
  ircd_strncpy(m->target, e->target, sizeof(m->target) - 1);
  ircd_strncpy(m->original_target, e->original_target, sizeof(m->original_target) - 1);
  ircd_strncpy(m->sender, e->sender, sizeof(m->sender) - 1);
  m->type = e->type;
  ircd_strncpy(m->content, e->content, sizeof(m->content) - 1);
  ircd_strncpy(m->client_tags, e->client_tags, sizeof(m->client_tags) - 1);
  /* account, dyn_content, raw_content all stay zero — ephemeral
   * conversations have no account anchor and no multiline carrier. */
  return m;
}

int chathistory_ephemeral_query(struct Client *cli,
                                 const char *canonical_target,
                                 int limit,
                                 struct HistoryMessage **result_head)
{
  struct EphemeralPmRing *r;
  struct EphemeralPmEntry *e;
  struct HistoryMessage *tail = NULL;
  int produced = 0;

  if (!cli || !canonical_target || !result_head)
    return 0;
  if (limit <= 0)
    return 0;
  r = cli_ephemeral_pm(cli);
  if (!r || !r->head)
    return 0;

  /* Find existing tail of *result_head so we append in order. */
  if (*result_head) {
    tail = *result_head;
    while (tail->next)
      tail = tail->next;
  }

  for (e = r->head; e && produced < limit; e = e->next) {
    struct HistoryMessage *m;
    if (0 != ircd_strcmp(e->target, canonical_target))
      continue;
    m = entry_to_history(e);
    if (!m)
      break;
    if (tail)
      tail->next = m;
    else
      *result_head = m;
    tail = m;
    produced++;
  }

  return produced;
}

int chathistory_ephemeral_has_target(struct Client *cli,
                                      const char *canonical_target)
{
  struct EphemeralPmRing *r;
  struct EphemeralPmEntry *e;
  if (!cli || !canonical_target)
    return 0;
  r = cli_ephemeral_pm(cli);
  if (!r)
    return 0;
  for (e = r->head; e; e = e->next) {
    if (0 == ircd_strcmp(e->target, canonical_target))
      return 1;
  }
  return 0;
}

void chathistory_ephemeral_purge(struct Client *cli)
{
  struct EphemeralPmRing *r;
  if (!cli)
    return;
  r = cli_ephemeral_pm(cli);
  if (!r)
    return;
  while (r->head) {
    struct EphemeralPmEntry *next = r->head->next;
    MyFree(r->head);
    r->head = next;
  }
  MyFree(r);
  cli_ephemeral_pm(cli) = NULL;
}
