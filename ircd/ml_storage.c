/*
 * IRC - Internet Relay Chat, ircd/ml_storage.c
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
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
/** @file
 * @brief Multiline message storage implementation.
 *
 * In-memory hash table storage for truncated multiline messages.
 * Allows legacy clients to retrieve full content via /join &ml-<msgid>.
 */
#include "config.h"

#include "ml_storage.h"
#include "client.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "list.h"
#include "msg.h"
#include "numeric.h"
#include "s_misc.h"
#include "send.h"

#include <string.h>
#include <stdlib.h>

/** Hash table for stored messages */
static struct ml_stored_msg *ml_storage_table[ML_STORAGE_HASHSIZE];

/** Current count of stored entries */
static int ml_storage_count = 0;

/** Total bytes used by stored content */
static size_t ml_storage_bytes = 0;

/** Simple hash function for msgid strings */
static unsigned int ml_hash(const char *msgid)
{
  unsigned int hash = 0;
  const char *p;

  for (p = msgid; *p; p++)
    hash = hash * 31 + (unsigned char)*p;

  return hash % ML_STORAGE_HASHSIZE;
}

/** Allocate and initialize a storage entry */
static struct ml_stored_msg *ml_entry_alloc(const char *msgid,
                                             const char *sender,
                                             const char *target,
                                             const char *lines_data,
                                             int line_count)
{
  struct ml_stored_msg *entry;

  entry = (struct ml_stored_msg *)MyMalloc(sizeof(struct ml_stored_msg));
  if (!entry)
    return NULL;

  ircd_strncpy(entry->msgid, msgid, ML_STORAGE_MSGID_LEN - 1);
  entry->msgid[ML_STORAGE_MSGID_LEN - 1] = '\0';

  ircd_strncpy(entry->sender, sender, NICKLEN);
  entry->sender[NICKLEN] = '\0';

  ircd_strncpy(entry->target, target, CHANNELLEN);
  entry->target[CHANNELLEN] = '\0';

  DupString(entry->lines, lines_data);
  entry->line_count = line_count;
  entry->stored = CurrentTime;
  entry->expires = CurrentTime + feature_int(FEAT_MULTILINE_STORAGE_TTL);
  entry->next = NULL;

  return entry;
}

/** Free a storage entry */
static void ml_entry_free(struct ml_stored_msg *entry)
{
  if (!entry)
    return;

  if (entry->lines) {
    ml_storage_bytes -= strlen(entry->lines) + 1;
    MyFree(entry->lines);
  }

  MyFree(entry);
  ml_storage_count--;
}

void ml_storage_init(void)
{
  int i;

  for (i = 0; i < ML_STORAGE_HASHSIZE; i++)
    ml_storage_table[i] = NULL;

  ml_storage_count = 0;
  ml_storage_bytes = 0;

  log_write(LS_SYSTEM, L_INFO, 0, "Multiline storage initialized");
}

void ml_storage_shutdown(void)
{
  int i;
  struct ml_stored_msg *entry, *next;

  for (i = 0; i < ML_STORAGE_HASHSIZE; i++) {
    for (entry = ml_storage_table[i]; entry; entry = next) {
      next = entry->next;
      ml_entry_free(entry);
    }
    ml_storage_table[i] = NULL;
  }

  ml_storage_count = 0;
  ml_storage_bytes = 0;

  log_write(LS_SYSTEM, L_INFO, 0, "Multiline storage shutdown");
}

int ml_storage_store(const char *msgid, const char *sender,
                     const char *target, struct SLink *lines, int count)
{
  unsigned int hash;
  struct ml_stored_msg *entry;
  struct SLink *lp;
  char *lines_data;
  size_t total_len = 0;
  char *p;
  int max_entries;

  if (!msgid || !sender || !target || !lines || count <= 0)
    return -1;

  /* Check storage limit */
  max_entries = feature_int(FEAT_MULTILINE_STORAGE_MAX);
  if (ml_storage_count >= max_entries) {
    log_write(LS_SYSTEM, L_WARNING, 0,
              "ml_storage: storage full (%d entries), rejecting msgid %s",
              ml_storage_count, msgid);
    return -1;
  }

  /* Calculate total length needed for all lines */
  for (lp = lines; lp; lp = lp->next) {
    if (lp->value.cp) {
      /* Skip first byte (concat flag), get text */
      const char *text = lp->value.cp + 1;
      total_len += strlen(text) + 1;  /* +1 for newline/null */
    }
  }

  if (total_len == 0)
    return -1;

  /* Allocate buffer for all lines */
  lines_data = (char *)MyMalloc(total_len);
  if (!lines_data)
    return -1;

  /* Concatenate all lines with newlines */
  p = lines_data;
  for (lp = lines; lp; lp = lp->next) {
    if (lp->value.cp) {
      const char *text = lp->value.cp + 1;
      size_t len = strlen(text);
      memcpy(p, text, len);
      p += len;
      if (lp->next)
        *p++ = '\n';
    }
  }
  *p = '\0';

  /* Create entry */
  entry = ml_entry_alloc(msgid, sender, target, lines_data, count);
  MyFree(lines_data);

  if (!entry)
    return -1;

  /* Add to hash table */
  hash = ml_hash(msgid);
  entry->next = ml_storage_table[hash];
  ml_storage_table[hash] = entry;

  ml_storage_count++;
  ml_storage_bytes += strlen(entry->lines) + 1;

  log_write(LS_SYSTEM, L_DEBUG, 0,
            "ml_storage: stored msgid %s from %s to %s (%d lines, %zu bytes)",
            msgid, sender, target, count, strlen(entry->lines));

  return 0;
}

struct ml_stored_msg *ml_storage_get(const char *msgid)
{
  unsigned int hash;
  struct ml_stored_msg *entry;

  if (!msgid)
    return NULL;

  hash = ml_hash(msgid);

  for (entry = ml_storage_table[hash]; entry; entry = entry->next) {
    if (ircd_strcmp(entry->msgid, msgid) == 0) {
      /* Check expiration */
      if (entry->expires <= CurrentTime)
        return NULL;  /* Expired, will be cleaned up later */
      return entry;
    }
  }

  return NULL;
}

int ml_storage_remove(const char *msgid)
{
  unsigned int hash;
  struct ml_stored_msg **pp, *entry;

  if (!msgid)
    return 1;

  hash = ml_hash(msgid);

  for (pp = &ml_storage_table[hash]; *pp; pp = &(*pp)->next) {
    if (ircd_strcmp((*pp)->msgid, msgid) == 0) {
      entry = *pp;
      *pp = entry->next;
      ml_entry_free(entry);
      return 0;
    }
  }

  return 1;  /* Not found */
}

int ml_storage_expire(void)
{
  int i;
  int expired = 0;
  struct ml_stored_msg **pp, *entry;
  time_t now = CurrentTime;

  for (i = 0; i < ML_STORAGE_HASHSIZE; i++) {
    pp = &ml_storage_table[i];
    while (*pp) {
      if ((*pp)->expires <= now) {
        entry = *pp;
        *pp = entry->next;
        log_write(LS_SYSTEM, L_DEBUG, 0,
                  "ml_storage: expired msgid %s", entry->msgid);
        ml_entry_free(entry);
        expired++;
      } else {
        pp = &(*pp)->next;
      }
    }
  }

  if (expired > 0) {
    log_write(LS_SYSTEM, L_DEBUG, 0,
              "ml_storage: expired %d entries, %d remaining",
              expired, ml_storage_count);
  }

  return expired;
}

void ml_storage_stats(int *count, int *max, size_t *bytes)
{
  if (count)
    *count = ml_storage_count;
  if (max)
    *max = feature_int(FEAT_MULTILINE_STORAGE_MAX);
  if (bytes)
    *bytes = ml_storage_bytes;
}

int ml_storage_deliver(struct Client *sptr, const char *msgid)
{
  struct ml_stored_msg *msg;
  char *line, *end;
  int line_num = 0;

  if (!sptr || !msgid)
    return 0;

  msg = ml_storage_get(msgid);

  if (!msg) {
    sendcmdto_one(&me, CMD_NOTICE, sptr,
                  "%C :Multiline message %s not found or expired",
                  sptr, msgid);
    return 0;
  }

  /* Send header */
  sendcmdto_one(&me, CMD_NOTICE, sptr,
                "%C :=== Multiline message from %s to %s ===",
                sptr, msg->sender, msg->target);

  /* Send each line - work on a copy since we modify the string */
  line = msg->lines;
  while (line && *line) {
    end = strchr(line, '\n');
    if (end) {
      *end = '\0';
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :<%s> %s",
                    sptr, msg->sender, line);
      *end = '\n';  /* Restore for next iteration */
      line = end + 1;
    } else {
      /* Last line (no trailing newline) */
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :<%s> %s",
                    sptr, msg->sender, line);
      break;
    }
    line_num++;
  }

  /* Send footer with metadata */
  sendcmdto_one(&me, CMD_NOTICE, sptr,
                "%C :=== End of message (%d lines, stored %s) ===",
                sptr, msg->line_count, myctime(msg->stored));

  return 0;
}

int ml_storage_is_virtual_channel(const char *name)
{
  if (!name)
    return 0;

  /* Check for &ml- prefix */
  if (name[0] == '&' && name[1] == 'm' && name[2] == 'l' && name[3] == '-')
    return 1;

  return 0;
}

void ml_storage_meminfo(struct Client *cptr)
{
  int count, max;
  size_t bytes;

  ml_storage_stats(&count, &max, &bytes);

  send_reply(cptr, SND_EXPLICIT | RPL_STATSDEBUG,
             ":multiline storage: %d entries (%d max), %zu bytes",
             count, max, bytes);
}
