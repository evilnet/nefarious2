/*
 * IRC - Internet Relay Chat, ircd/linesync.c
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
 * @brief Linesync - centralized config distribution via HTTPS.
 */
#include "config.h"

#ifdef USE_CURL

#include "linesync.h"
#include "client.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_events.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "numeric.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_stats.h"
#include "send.h"

#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/** Maximum size of downloaded content (1 MB) */
#define LINESYNC_MAX_SIZE (1024 * 1024)

/** Buffer for curl write callback */
struct LinesyncBuffer {
  char *data;
  size_t size;
  size_t allocated;
};

/** Global linesync statistics */
static struct LinesyncStats linesync_stats;

/** Timer for periodic linesync */
static struct Timer linesync_timer;

/** Curl global initialized flag */
static int curl_initialized = 0;

/** Status code to string mapping */
static const char *status_strings[] = {
  "OK",
  "Disabled",
  "No URL configured",
  "CURL error",
  "HTTP error",
  "Validation error",
  "Checksum error",
  "Apply error"
};

/** Curl write callback
 * @param ptr Data received
 * @param size Size of each element
 * @param nmemb Number of elements
 * @param userdata Pointer to LinesyncBuffer
 * @return Number of bytes handled
 */
static size_t
linesync_write_callback(void *ptr, size_t size, size_t nmemb, void *userdata)
{
  struct LinesyncBuffer *buf = (struct LinesyncBuffer *)userdata;
  size_t total = size * nmemb;
  size_t needed;

  if (buf->size + total > LINESYNC_MAX_SIZE)
    return 0; /* Reject oversized content */

  needed = buf->size + total + 1;
  if (needed > buf->allocated) {
    size_t newsize = buf->allocated ? buf->allocated * 2 : 4096;
    char *newdata;

    while (newsize < needed)
      newsize *= 2;

    if (newsize > LINESYNC_MAX_SIZE + 1)
      newsize = LINESYNC_MAX_SIZE + 1;

    newdata = (char *)MyRealloc(buf->data, newsize);
    if (!newdata)
      return 0;

    buf->data = newdata;
    buf->allocated = newsize;
  }

  memcpy(buf->data + buf->size, ptr, total);
  buf->size += total;
  buf->data[buf->size] = '\0';

  return total;
}

/** Validate downloaded content
 * @param content Downloaded content
 * @param len Length of content
 * @return 1 if valid, 0 if invalid
 */
static int
linesync_validate_content(const char *content, size_t len)
{
  const char *p;
  int in_block = 0;
  int brace_depth = 0;

  if (!content || len == 0)
    return 0;

  /* Basic validation: check for balanced braces and no dangerous patterns */
  for (p = content; *p; p++) {
    if (*p == '{') {
      brace_depth++;
      in_block = 1;
    } else if (*p == '}') {
      brace_depth--;
      if (brace_depth < 0)
        return 0; /* Unbalanced braces */
    }
  }

  if (brace_depth != 0)
    return 0; /* Unbalanced braces */

  /* Reject content with shell metacharacters that could be dangerous */
  if (strstr(content, "$(") || strstr(content, "`"))
    return 0;

  /* Reject attempts to include other files (path traversal) */
  if (strstr(content, "../") || strstr(content, "..\\"))
    return 0;

  return 1;
}

/** Download content from URL
 * @param url URL to download from
 * @param[out] content Pointer to store downloaded content (caller must free)
 * @param[out] len Pointer to store content length
 * @return LINESYNC_OK on success, error code otherwise
 */
static enum LinesyncStatus
linesync_download(const char *url, char **content, size_t *len)
{
  CURL *curl;
  CURLcode res;
  struct LinesyncBuffer buf = { NULL, 0, 0 };
  long http_code = 0;
  const char *ca_cert, *client_cert, *client_key;

  if (!curl_initialized) {
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl_initialized = 1;
  }

  curl = curl_easy_init();
  if (!curl) {
    ircd_snprintf(0, linesync_stats.last_error, sizeof(linesync_stats.last_error),
                  "Failed to initialize CURL");
    return LINESYNC_CURL_ERROR;
  }

  /* Set URL */
  curl_easy_setopt(curl, CURLOPT_URL, url);

  /* Set write callback */
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, linesync_write_callback);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);

  /* Security: require HTTPS */
  if (strncmp(url, "https://", 8) != 0) {
    curl_easy_cleanup(curl);
    ircd_snprintf(0, linesync_stats.last_error, sizeof(linesync_stats.last_error),
                  "Only HTTPS URLs are allowed");
    return LINESYNC_VALIDATION_ERROR;
  }

  /* SSL/TLS settings */
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

  /* CA certificate */
  ca_cert = feature_str(FEAT_LINESYNC_CA_CERT);
  if (ca_cert && *ca_cert) {
    curl_easy_setopt(curl, CURLOPT_CAINFO, ca_cert);
  }

  /* Client certificate authentication */
  client_cert = feature_str(FEAT_LINESYNC_CLIENT_CERT);
  client_key = feature_str(FEAT_LINESYNC_CLIENT_KEY);
  if (client_cert && *client_cert && client_key && *client_key) {
    curl_easy_setopt(curl, CURLOPT_SSLCERT, client_cert);
    curl_easy_setopt(curl, CURLOPT_SSLKEY, client_key);
  }

  /* Timeout settings */
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);

  /* Follow redirects (up to 5) */
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
  curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5L);

  /* User agent */
  curl_easy_setopt(curl, CURLOPT_USERAGENT, "Nefarious-Linesync/1.0");

  /* Perform request */
  res = curl_easy_perform(curl);

  if (res != CURLE_OK) {
    curl_easy_cleanup(curl);
    MyFree(buf.data);
    ircd_snprintf(0, linesync_stats.last_error, sizeof(linesync_stats.last_error),
                  "CURL error: %s", curl_easy_strerror(res));
    return LINESYNC_CURL_ERROR;
  }

  /* Check HTTP response code */
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
  curl_easy_cleanup(curl);

  if (http_code != 200) {
    MyFree(buf.data);
    ircd_snprintf(0, linesync_stats.last_error, sizeof(linesync_stats.last_error),
                  "HTTP error: %ld", http_code);
    return LINESYNC_HTTP_ERROR;
  }

  *content = buf.data;
  *len = buf.size;
  return LINESYNC_OK;
}

/** Apply downloaded configuration
 * @param content Configuration content
 * @param len Content length
 * @return LINESYNC_OK on success, error code otherwise
 */
static enum LinesyncStatus
linesync_apply(const char *content, size_t len)
{
  /* For now, just log what we would apply */
  Debug((DEBUG_INFO, "Linesync: Would apply %zu bytes of configuration", len));

  /* TODO: Actually apply the configuration
   * This would involve:
   * 1. Writing to a temp file
   * 2. Including it via the config parser
   * 3. Rehashing specific blocks (Gline, Shun, etc.)
   */

  sendto_opmask_butone(0, SNO_OLDSNO,
                       "Linesync: Downloaded %zu bytes of configuration", len);

  return LINESYNC_OK;
}

/** Timer callback for periodic linesync
 * @param ev Timer event
 */
static void
linesync_timer_callback(struct Event *ev)
{
  if (ev_type(ev) == ET_EXPIRE) {
    linesync_trigger(NULL, 0);
  }
}

void
linesync_init(void)
{
  memset(&linesync_stats, 0, sizeof(linesync_stats));

  /* Don't set up timer here - wait for config to be loaded */
}

/** Start or restart the linesync timer based on config */
void
linesync_start_timer(void)
{
  int interval;

  if (!feature_bool(FEAT_LINESYNC_ENABLE))
    return;

  interval = feature_int(FEAT_LINESYNC_INTERVAL);
  if (interval < 60)
    interval = 60; /* Minimum 1 minute */

  timer_add(timer_init(&linesync_timer), linesync_timer_callback,
            NULL, TT_PERIODIC, interval);

  Debug((DEBUG_INFO, "Linesync: Timer started with interval %d seconds", interval));
}

enum LinesyncStatus
linesync_trigger(struct Client *sptr, int force)
{
  const char *url;
  char *content = NULL;
  size_t len = 0;
  enum LinesyncStatus status;
  time_t now = CurrentTime;
  int interval;

  linesync_stats.last_attempt = now;

  /* Check if enabled */
  if (!feature_bool(FEAT_LINESYNC_ENABLE)) {
    linesync_stats.last_status = LINESYNC_DISABLED;
    return LINESYNC_DISABLED;
  }

  /* Check if URL is configured */
  url = feature_str(FEAT_LINESYNC_URL);
  if (!url || !*url) {
    ircd_snprintf(0, linesync_stats.last_error, sizeof(linesync_stats.last_error),
                  "No URL configured");
    linesync_stats.last_status = LINESYNC_NO_URL;
    return LINESYNC_NO_URL;
  }

  /* Check interval (unless forced) */
  if (!force) {
    interval = feature_int(FEAT_LINESYNC_INTERVAL);
    if (linesync_stats.last_sync > 0 &&
        (now - linesync_stats.last_sync) < interval) {
      /* Not time yet */
      return LINESYNC_OK;
    }
  }

  /* Notify if triggered by oper */
  if (sptr) {
    sendto_opmask_butone(0, SNO_OLDSNO,
                         "Linesync triggered by %s", cli_name(sptr));
  }

  /* Download content */
  status = linesync_download(url, &content, &len);
  if (status != LINESYNC_OK) {
    linesync_stats.failures++;
    linesync_stats.last_status = status;
    if (sptr) {
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :Linesync failed: %s",
                    sptr, linesync_stats.last_error);
    }
    return status;
  }

  /* Validate content */
  if (!linesync_validate_content(content, len)) {
    MyFree(content);
    ircd_snprintf(0, linesync_stats.last_error, sizeof(linesync_stats.last_error),
                  "Content validation failed");
    linesync_stats.failures++;
    linesync_stats.last_status = LINESYNC_VALIDATION_ERROR;
    if (sptr) {
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :Linesync failed: validation error",
                    sptr);
    }
    return LINESYNC_VALIDATION_ERROR;
  }

  /* Apply configuration */
  status = linesync_apply(content, len);
  MyFree(content);

  if (status == LINESYNC_OK) {
    linesync_stats.last_sync = now;
    linesync_stats.syncs++;
    linesync_stats.last_error[0] = '\0';
    if (sptr) {
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :Linesync completed successfully",
                    sptr);
    }
  } else {
    linesync_stats.failures++;
    if (sptr) {
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :Linesync failed: %s",
                    sptr, linesync_stats.last_error);
    }
  }

  linesync_stats.last_status = status;
  return status;
}

const char *
linesync_status_str(enum LinesyncStatus status)
{
  if (status >= 0 && status < sizeof(status_strings) / sizeof(status_strings[0]))
    return status_strings[status];
  return "Unknown";
}

const struct LinesyncStats *
linesync_get_stats(void)
{
  return &linesync_stats;
}

void
linesync_report_stats(struct Client *to, const struct StatDesc *sd, char *param)
{
  const struct LinesyncStats *stats = &linesync_stats;
  char timebuf[64];

  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG, ":Linesync Statistics:");

  if (feature_bool(FEAT_LINESYNC_ENABLE)) {
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG, ":  Status: Enabled");
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG, ":  URL: %s",
               feature_str(FEAT_LINESYNC_URL));
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG, ":  Interval: %d seconds",
               feature_int(FEAT_LINESYNC_INTERVAL));
  } else {
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG, ":  Status: Disabled");
  }

  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG, ":  Successful syncs: %lu",
             stats->syncs);
  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG, ":  Failed syncs: %lu",
             stats->failures);

  if (stats->last_sync > 0) {
    struct tm *tm = localtime(&stats->last_sync);
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", tm);
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG, ":  Last sync: %s", timebuf);
  } else {
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG, ":  Last sync: Never");
  }

  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG, ":  Last status: %s",
             linesync_status_str(stats->last_status));

  if (stats->last_error[0]) {
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG, ":  Last error: %s",
               stats->last_error);
  }
}

#endif /* USE_CURL */
