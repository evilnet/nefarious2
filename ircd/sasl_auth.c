/*
 * IRC - Internet Relay Chat, ircd/sasl_auth.c
 * Copyright (C) 2026 Afternet Development
 *
 * Local SASL authentication via Keycloak (libkc).
 * Handles SASL PLAIN directly in the IRCd without relaying through X3 services.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
 * any later version.
 */
#include "config.h"

#include "sasl_auth.h"
#include "capab.h"
#include "client.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "random.h"
#include "send.h"
#include "bouncer_session.h"
#include "s_auth.h"
#include "s_bsd.h"
#include "s_misc.h"
#include "s_user.h"
#include "metadata.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdlib.h>

#ifdef USE_LIBKC
#include <kc/kc_keycloak.h>
#include <kc/kc_jwt.h>
#endif

/* Forward declarations */
static void sasl_local_timeout_cb(struct Event *ev);
#ifdef USE_LIBKC
static void sasl_health_cb(int result, const struct kc_access_token *token, void *data);
#endif

/* ---- Health tracking ---- */

/** Whether the Keycloak SASL backend is currently healthy. */
static int kc_sasl_healthy = 0;

/** Whether sasl_local_init() succeeded. */
static int sasl_local_initialized = 0;

/** Timer for periodic health retry when Keycloak is unhealthy. */
static struct Timer sasl_health_retry_timer;
static int sasl_health_retry_timer_active = 0;

#ifdef USE_LIBKC
static void sasl_health_retry_timer_cb(struct Event *ev);
static void sasl_start_health_retry(void);
static void sasl_stop_health_retry(void);
static void sasl_mark_unhealthy(int result);
static void sasl_mark_healthy(void);
#endif

/* ==================================================================
 * Auth cache — negative (failed) and positive (successful) PLAIN
 * results, keyed by SipHash-2-4 of lowercase(username)+NUL+password.
 * ================================================================== */

#define AUTHCACHE_BUCKETS 1024

/** SipHash-2-4 reference implementation (public domain, J-P Aumasson / D.J. Bernstein). */
static inline uint64_t rotl64(uint64_t x, int b) { return (x << b) | (x >> (64 - b)); }

#define SIPROUND do { \
  v0 += v1; v1 = rotl64(v1, 13); v1 ^= v0; v0 = rotl64(v0, 32); \
  v2 += v3; v3 = rotl64(v3, 16); v3 ^= v2; \
  v0 += v3; v3 = rotl64(v3, 21); v3 ^= v0; \
  v2 += v1; v1 = rotl64(v1, 17); v1 ^= v2; v2 = rotl64(v2, 32); \
} while(0)

static uint64_t siphash24(const void *src, size_t len, const uint8_t key[16])
{
  const uint8_t *m = (const uint8_t *)src;
  uint64_t k0, k1;
  uint64_t v0, v1, v2, v3;
  uint64_t mi;
  int i, blocks;

  memcpy(&k0, key, 8);
  memcpy(&k1, key + 8, 8);

  v0 = k0 ^ UINT64_C(0x736f6d6570736575);
  v1 = k1 ^ UINT64_C(0x646f72616e646f6d);
  v2 = k0 ^ UINT64_C(0x6c7967656e657261);
  v3 = k1 ^ UINT64_C(0x7465646279746573);

  blocks = (int)(len / 8);
  for (i = 0; i < blocks; i++) {
    memcpy(&mi, m + i * 8, 8);
    v3 ^= mi;
    SIPROUND; SIPROUND;
    v0 ^= mi;
  }

  mi = ((uint64_t)len) << 56;
  switch (len & 7) {
    case 7: mi |= (uint64_t)m[blocks * 8 + 6] << 48; /* fall through */
    case 6: mi |= (uint64_t)m[blocks * 8 + 5] << 40; /* fall through */
    case 5: mi |= (uint64_t)m[blocks * 8 + 4] << 32; /* fall through */
    case 4: mi |= (uint64_t)m[blocks * 8 + 3] << 24; /* fall through */
    case 3: mi |= (uint64_t)m[blocks * 8 + 2] << 16; /* fall through */
    case 2: mi |= (uint64_t)m[blocks * 8 + 1] << 8;  /* fall through */
    case 1: mi |= (uint64_t)m[blocks * 8 + 0];
  }

  v3 ^= mi;
  SIPROUND; SIPROUND;
  v0 ^= mi;
  v2 ^= 0xff;
  SIPROUND; SIPROUND; SIPROUND; SIPROUND;
  return v0 ^ v1 ^ v2 ^ v3;
}

/** Random SipHash key, set once at init. */
static uint8_t authcache_siphash_key[16];
static int     authcache_initialized = 0;

/** Compute SipHash of lowercase(username) + NUL + password. */
static uint64_t authcache_hash(const char *username, const char *password)
{
  char buf[ACCOUNTLEN + 1 + 512 + 1]; /* username + NUL + password */
  size_t ulen = strlen(username);
  size_t plen = strlen(password);
  size_t total, i;

  if (ulen > ACCOUNTLEN)
    ulen = ACCOUNTLEN;
  if (plen > 512)
    plen = 512;
  total = ulen + 1 + plen;

  /* Lowercase username into buffer */
  for (i = 0; i < ulen; i++)
    buf[i] = ToLower(username[i]);
  buf[ulen] = '\0';
  memcpy(buf + ulen + 1, password, plen);

  return siphash24(buf, total, authcache_siphash_key);
}

/* ---- Negative auth cache ---- */

struct negcache_entry {
  struct negcache_entry *next;
  uint64_t              hash;
  char                  username[ACCOUNTLEN + 1];
  time_t                timestamp;
};

static struct negcache_entry *negcache_table[AUTHCACHE_BUCKETS];

static struct sasl_cache_stats cache_stats;

/** Insert or update a negative cache entry. */
static void negcache_insert(const char *username, uint64_t hash)
{
  unsigned int bucket = (unsigned int)(hash % AUTHCACHE_BUCKETS);
  struct negcache_entry *e;

  /* Check for existing entry with same hash */
  for (e = negcache_table[bucket]; e; e = e->next) {
    if (e->hash == hash) {
      e->timestamp = CurrentTime;
      return;
    }
  }

  /* Allocate new entry */
  e = (struct negcache_entry *)MyMalloc(sizeof(struct negcache_entry));
  e->hash = hash;
  ircd_strncpy(e->username, username, sizeof(e->username));
  e->timestamp = CurrentTime;
  e->next = negcache_table[bucket];
  negcache_table[bucket] = e;
  cache_stats.neg_inserts++;
}

/** Check if credentials are in the negative cache.
 *  @return 1 if cached (recent failure), 0 if not.
 */
static int negcache_check(uint64_t hash)
{
  unsigned int bucket = (unsigned int)(hash % AUTHCACHE_BUCKETS);
  struct negcache_entry *e;
  int ttl = feature_int(FEAT_SASL_NEGCACHE_TTL);

  if (ttl <= 0)
    return 0;

  for (e = negcache_table[bucket]; e; e = e->next) {
    if (e->hash == hash) {
      if (CurrentTime - e->timestamp <= ttl) {
        cache_stats.neg_hits++;
        return 1;
      }
      /* Expired — will be cleaned up by sweep */
      cache_stats.neg_misses++;
      return 0;
    }
  }
  cache_stats.neg_misses++;
  return 0;
}

/** Remove a specific hash from the negative cache. */
static void negcache_remove(uint64_t hash)
{
  unsigned int bucket = (unsigned int)(hash % AUTHCACHE_BUCKETS);
  struct negcache_entry **pp = &negcache_table[bucket];
  struct negcache_entry *e;

  while ((e = *pp) != NULL) {
    if (e->hash == hash) {
      *pp = e->next;
      MyFree(e);
      return;
    }
    pp = &e->next;
  }
}

/** Invalidate all negative cache entries for a username (webhook use). */
static void negcache_invalidate_user(const char *username)
{
  unsigned int i;

  for (i = 0; i < AUTHCACHE_BUCKETS; i++) {
    struct negcache_entry **pp = &negcache_table[i];
    struct negcache_entry *e;

    while ((e = *pp) != NULL) {
      if (0 == ircd_strcmp(e->username, username)) {
        *pp = e->next;
        MyFree(e);
        cache_stats.neg_invalidations++;
      } else {
        pp = &e->next;
      }
    }
  }
}

/* ---- Positive auth cache ---- */

struct poscache_entry {
  struct poscache_entry *next;
  uint64_t              hash;
  char                  username[ACCOUNTLEN + 1];
  char                  account[ACCOUNTLEN + 1];
  time_t                timestamp;
  time_t                created_at;   /**< Account creation time (epoch), 0 = unknown */
};

static struct poscache_entry *poscache_table[AUTHCACHE_BUCKETS];

/** Insert or update a positive cache entry. */
static void poscache_insert(const char *username, const char *account,
                            uint64_t hash, time_t created_at)
{
  unsigned int bucket = (unsigned int)(hash % AUTHCACHE_BUCKETS);
  struct poscache_entry *e;

  /* Check for existing entry with same hash */
  for (e = poscache_table[bucket]; e; e = e->next) {
    if (e->hash == hash) {
      e->timestamp = CurrentTime;
      e->created_at = created_at;
      ircd_strncpy(e->account, account, sizeof(e->account));
      return;
    }
  }

  /* Allocate new entry */
  e = (struct poscache_entry *)MyMalloc(sizeof(struct poscache_entry));
  e->hash = hash;
  ircd_strncpy(e->username, username, sizeof(e->username));
  ircd_strncpy(e->account, account, sizeof(e->account));
  e->timestamp = CurrentTime;
  e->created_at = created_at;
  e->next = poscache_table[bucket];
  poscache_table[bucket] = e;
  cache_stats.pos_inserts++;
}

/** Check if credentials are in the positive cache.
 *  @param[out] account     Filled with cached account name on hit.
 *  @param[out] created_at  Filled with cached creation timestamp on hit.
 *  @return 1 if cached (recent success), 0 if not.
 */
static int poscache_check(uint64_t hash, char *account, size_t account_size,
                          time_t *created_at)
{
  unsigned int bucket = (unsigned int)(hash % AUTHCACHE_BUCKETS);
  struct poscache_entry *e;
  int ttl = feature_int(FEAT_SASL_POSCACHE_TTL);

  if (ttl <= 0)
    return 0;

  for (e = poscache_table[bucket]; e; e = e->next) {
    if (e->hash == hash) {
      if (CurrentTime - e->timestamp <= ttl) {
        ircd_strncpy(account, e->account, account_size);
        if (created_at)
          *created_at = e->created_at;
        cache_stats.pos_hits++;
        return 1;
      }
      cache_stats.pos_misses++;
      return 0;
    }
  }
  cache_stats.pos_misses++;
  return 0;
}

/** Remove a specific hash from the positive cache. */
static void poscache_remove(uint64_t hash)
{
  unsigned int bucket = (unsigned int)(hash % AUTHCACHE_BUCKETS);
  struct poscache_entry **pp = &poscache_table[bucket];
  struct poscache_entry *e;

  while ((e = *pp) != NULL) {
    if (e->hash == hash) {
      *pp = e->next;
      MyFree(e);
      return;
    }
    pp = &e->next;
  }
}

/** Invalidate all positive cache entries for a username (webhook use). */
static void poscache_invalidate_user(const char *username)
{
  unsigned int i;

  for (i = 0; i < AUTHCACHE_BUCKETS; i++) {
    struct poscache_entry **pp = &poscache_table[i];
    struct poscache_entry *e;

    while ((e = *pp) != NULL) {
      if (0 == ircd_strcmp(e->username, username)) {
        *pp = e->next;
        MyFree(e);
        cache_stats.pos_invalidations++;
      } else {
        pp = &e->next;
      }
    }
  }
}

/** Sweep expired entries from both caches. Called periodically. */
static void authcache_expire_sweep(void)
{
  unsigned int i;
  int neg_ttl = feature_int(FEAT_SASL_NEGCACHE_TTL);
  int pos_ttl = feature_int(FEAT_SASL_POSCACHE_TTL);

  for (i = 0; i < AUTHCACHE_BUCKETS; i++) {
    /* Negative cache */
    if (neg_ttl > 0) {
      struct negcache_entry **pp = &negcache_table[i];
      struct negcache_entry *e;
      while ((e = *pp) != NULL) {
        if (CurrentTime - e->timestamp > neg_ttl) {
          *pp = e->next;
          MyFree(e);
          cache_stats.neg_expirations++;
        } else {
          pp = &e->next;
        }
      }
    }

    /* Positive cache */
    if (pos_ttl > 0) {
      struct poscache_entry **pp = &poscache_table[i];
      struct poscache_entry *e;
      while ((e = *pp) != NULL) {
        if (CurrentTime - e->timestamp > pos_ttl) {
          *pp = e->next;
          MyFree(e);
          cache_stats.pos_expirations++;
        } else {
          pp = &e->next;
        }
      }
    }
  }
}

/** Timer for periodic cache sweep. */
static struct Timer authcache_sweep_timer;

static void authcache_sweep_timer_cb(struct Event *ev)
{
  if (ev_type(ev) == ET_EXPIRE)
    authcache_expire_sweep();
}

/** Initialize auth caches. Called from sasl_local_init(). */
static void authcache_init(void)
{
  if (authcache_initialized)
    return;

  /* Generate random SipHash key via OpenSSL */
  RAND_bytes(authcache_siphash_key, sizeof(authcache_siphash_key));

  memset(negcache_table, 0, sizeof(negcache_table));
  memset(poscache_table, 0, sizeof(poscache_table));
  memset(&cache_stats, 0, sizeof(cache_stats));

  /* Periodic sweep every 60 seconds */
  timer_add(timer_init(&authcache_sweep_timer), authcache_sweep_timer_cb,
            NULL, TT_PERIODIC, 60);

  authcache_initialized = 1;
  log_write(LS_SYSTEM, L_NOTICE, 0,
            "SASL AUTH CACHE: Initialized (neg_ttl=%d, pos_ttl=%d)",
            feature_int(FEAT_SASL_NEGCACHE_TTL),
            feature_int(FEAT_SASL_POSCACHE_TTL));
}

/* ---- Public cache API for webhook invalidation ---- */

/** Invalidate all auth cache entries for a user (called from webhook handler). */
void sasl_cache_invalidate_user(const char *username)
{
  if (!authcache_initialized)
    return;
  negcache_invalidate_user(username);
  poscache_invalidate_user(username);
  log_write(LS_SYSTEM, L_DEBUG, 0,
            "SASL AUTH CACHE: Invalidated caches for user %s", username);
}

/** Get auth cache statistics. */
void sasl_cache_stats_get(struct sasl_cache_stats *out)
{
  if (out)
    memcpy(out, &cache_stats, sizeof(cache_stats));
}

/* ---- Base64 helpers ---- */

/** Decode standard base64 into output buffer.
 *  @return 1 on success, 0 on failure.
 */
static int sasl_base64_decode(const char *input, unsigned char *output,
                              size_t output_size, size_t *decoded_len)
{
  int inlen = strlen(input);
  int outlen;

  if (inlen == 0) {
    *decoded_len = 0;
    return 1;
  }

  /* EVP_DecodeBlock writes (inlen/4)*3 bytes before padding adjustment.
   * Use a temporary buffer to avoid overflowing output when the raw
   * decode is larger than the final padded result. */
  {
    size_t raw_len = ((size_t)inlen / 4) * 3;
    unsigned char tmp[SASL_DATA_MAX];

    if (raw_len > sizeof(tmp))
      return 0;

    outlen = EVP_DecodeBlock(tmp, (const unsigned char *)input, inlen);
    if (outlen < 0)
      return 0;

    /* EVP_DecodeBlock doesn't account for padding, adjust for = characters */
    if (inlen > 0 && input[inlen - 1] == '=') {
      outlen--;
      if (inlen > 1 && input[inlen - 2] == '=')
        outlen--;
    }

    if ((size_t)outlen > output_size)
      return 0;

    memcpy(output, tmp, outlen);
  }

  *decoded_len = outlen;
  return 1;
}

/* ---- Session management ---- */

/** Allocate and initialize a new SASL session. */
static struct SASLSession *sasl_session_alloc(enum SASLMechanism mech)
{
  struct SASLSession *s = (struct SASLSession *)MyCalloc(1, sizeof(struct SASLSession));
  s->mech = mech;
  s->state = SASL_STATE_INIT;
  return s;
}

/** Free a SASL session and all its resources. */
void sasl_session_free(struct Client *sptr)
{
  struct SASLSession *s = cli_saslsession(sptr);
  if (!s)
    return;

  if (s->accumulated_data) {
    MyFree(s->accumulated_data);
    s->accumulated_data = NULL;
  }
  if (s->scram_client_first_bare)
    MyFree(s->scram_client_first_bare);
  if (s->scram_server_first)
    MyFree(s->scram_server_first);
  if (s->scram_combined_nonce)
    MyFree(s->scram_combined_nonce);
  if (s->scram_salt_b64)
    MyFree(s->scram_salt_b64);
  MyFree(s);
  cli_saslsession(sptr) = NULL;
}

/* ---- sasl_complete_login: shared between local and P10 paths ---- */

/** Complete a successful SASL login.
 *
 *  This is the shared function called by both the local Keycloak SASL path
 *  and the P10 relay path (ms_sasl D/S handler).  It performs:
 *   1. Set cli_saslaccount
 *   2. Send RPL_LOGGEDIN to client
 *   3. auth_set_account (pre-registration)
 *   4. SetHiddenHost (pre-registration, if configured)
 *   5. SetSASLComplete + RPL_SASLSUCCESS
 *   6. For registered users: metadata_load_account, account update,
 *      bounce_emit_alias_update, account-notify, AC broadcast, hide_hostmask
 *   7. auth_sasl_done to unblock registration
 *   8. Clean up SASL session state and timer
 */
void sasl_complete_login(struct Client *sptr, const char *account,
                         time_t acc_create)
{
  /* 1. Set account name */
  ircd_strncpy(cli_saslaccount(sptr), account, ACCOUNTLEN + 1);

  /* 2. Send RPL_LOGGEDIN */
  send_reply(sptr, RPL_LOGGEDIN,
             BadPtr(cli_name(sptr)) ? "*" : cli_name(sptr),
             (!cli_user(sptr) || BadPtr(cli_user(sptr)->username)) ? "*" : cli_user(sptr)->username,
             (!cli_user(sptr) || BadPtr(cli_user(sptr)->host)) ? "*" : cli_user(sptr)->host,
             cli_saslaccount(sptr), cli_saslaccount(sptr));

  /* 3. Set account in auth request (pre-registration) */
  if (cli_auth(sptr))
    auth_set_account(cli_auth(sptr), cli_saslaccount(sptr));

  /* 4. Set account creation time */
  if (acc_create)
    cli_saslacccreate(sptr) = acc_create;

  /* 5. Pre-registration hidden host setup */
  if (((feature_int(FEAT_HOST_HIDING_STYLE) == 1) ||
       (feature_int(FEAT_HOST_HIDING_STYLE) == 3)) &&
      feature_bool(FEAT_SASL_AUTOHIDEHOST)) {
    SetHiddenHost(sptr);
  }

  /* 6. SetSASLComplete + RPL_SASLSUCCESS */
  SetSASLComplete(sptr);
  send_reply(sptr, RPL_SASLSUCCESS);

  /* 7. Post-registration account update (reauth or if already registered) */
  if (IsRegistered(sptr) && cli_user(sptr) && cli_saslaccount(sptr)[0]) {
    char type = IsAccount(sptr) ? 'M' : 'R';

    if (ircd_strcmp(cli_user(sptr)->account, cli_saslaccount(sptr)) != 0) {
      /* Load account-linked metadata BEFORE setting account flag */
      metadata_load_account(sptr, cli_saslaccount(sptr));

      ircd_strncpy(cli_user(sptr)->account, cli_saslaccount(sptr), ACCOUNTLEN + 1);
      SetAccount(sptr);

      bounce_emit_alias_update(sptr, "account", cli_user(sptr)->account);

      if (cli_saslacccreate(sptr))
        cli_user(sptr)->acc_create = cli_saslacccreate(sptr);

      /* Notify channel members with account-notify capability */
      sendcmdto_common_channels_capab_butone(sptr, CMD_ACCOUNT, sptr,
                                              CAP_ACCNOTIFY, CAP_NONE,
                                              "%s", cli_user(sptr)->account);

      /* Propagate to other servers */
      if (feature_bool(FEAT_EXTENDED_ACCOUNTS)) {
        if (cli_user(sptr)->acc_create) {
          sendcmdto_serv_butone(&me, CMD_ACCOUNT, NULL, "%C %c %s %Tu",
                                sptr, type, cli_user(sptr)->account,
                                cli_user(sptr)->acc_create);
        } else {
          sendcmdto_serv_butone(&me, CMD_ACCOUNT, NULL, "%C %c %s",
                                sptr, type, cli_user(sptr)->account);
        }
      } else {
        if (cli_user(sptr)->acc_create) {
          sendcmdto_serv_butone(&me, CMD_ACCOUNT, NULL, "%C %s %Tu",
                                sptr, cli_user(sptr)->account,
                                cli_user(sptr)->acc_create);
        } else {
          sendcmdto_serv_butone(&me, CMD_ACCOUNT, NULL, "%C %s",
                                sptr, cli_user(sptr)->account);
        }
      }

      /* Apply hidden host if applicable */
      if (((feature_int(FEAT_HOST_HIDING_STYLE) == 1) ||
           (feature_int(FEAT_HOST_HIDING_STYLE) == 3)) &&
          IsHiddenHost(sptr))
        hide_hostmask(sptr);
    }
  }

  /* 8. Clean up SASL session state */
  if ((cli_saslagent(sptr) != NULL) && cli_saslagentref(cli_saslagent(sptr)))
    cli_saslagentref(cli_saslagent(sptr))--;
  cli_saslagent(sptr) = NULL;
  cli_saslcookie(sptr) = 0;
  cli_saslstart(sptr) = 0;
  if (t_active(&cli_sasltimeout(sptr)))
    timer_del(&cli_sasltimeout(sptr));

  /* Free local SASL session if present */
  sasl_session_free(sptr);

  /* 9. Unblock registration */
  if (cli_auth(sptr))
    auth_sasl_done(cli_auth(sptr));
}

/* ---- PLAIN mechanism handler ---- */

#ifdef USE_LIBKC

/** Callback from kc_user_verify_password(). */
static void sasl_plain_cb(int result, const struct kc_access_token *token, void *data)
{
  struct sasl_cb_ctx *ctx = (struct sasl_cb_ctx *)data;
  struct Client *acptr;
  struct SASLSession *session;

  /* Re-resolve client via FD + cookie (use-after-free protection) */
  acptr = LocalClientArray[ctx->fd];
  if (!acptr || cli_saslcookie(acptr) != ctx->cookie) {
    MyFree(ctx);
    return;  /* Client disconnected or FD reused */
  }
  MyFree(ctx);

  session = cli_saslsession(acptr);
  if (!session || session->state != SASL_STATE_WAITING_KC) {
    log_write(LS_SYSTEM, L_WARNING, 0,
              "SASL PLAIN: Callback for %C but session state is wrong", acptr);
    return;
  }

  if (result == KC_SUCCESS) {
    const char *login_as = session->authzid[0] ? session->authzid : session->authcid;

    /* Successful auth confirms Keycloak is reachable */
    if (!kc_sasl_healthy)
      sasl_mark_healthy();

    /* Update auth caches */
    if (session->cred_hash_valid) {
      poscache_insert(session->authcid, login_as, session->cred_hash,
                      token ? token->created_at : 0);
      negcache_remove(session->cred_hash);
    }

    log_write(LS_SYSTEM, L_INFO, 0,
              "SASL PLAIN: Successful authentication for %s (client %C)",
              login_as, acptr);
    sasl_complete_login(acptr, login_as,
                        token && token->created_at ? token->created_at : 0);
  } else {
    /* Distinguish auth failures from connectivity errors.
     * KC_FORBIDDEN = wrong password (HTTP 401/400) — Keycloak is working fine.
     * KC_NOT_FOUND = user doesn't exist — Keycloak is working fine.
     * Everything else (KC_ERROR, KC_UNAVAILABLE, KC_TIMEOUT, KC_TOKEN_ERROR,
     * KC_INVALID_RESPONSE) indicates a connectivity or service problem.
     */
    if (result != KC_FORBIDDEN && result != KC_NOT_FOUND) {
      sasl_mark_unhealthy(result);
    }

    /* Update auth caches — only for actual auth failures, not connectivity errors */
    if ((result == KC_FORBIDDEN || result == KC_NOT_FOUND) && session->cred_hash_valid) {
      negcache_insert(session->authcid, session->cred_hash);
      poscache_remove(session->cred_hash);
    }

    log_write(LS_SYSTEM, L_INFO, 0,
              "SASL PLAIN: Failed authentication for %s (client %C, result %d)",
              session->authcid, acptr, result);
    /* Send failure and clean up */
    send_reply(acptr, ERR_SASLFAIL, "");
    session->state = SASL_STATE_FAILED;
    cli_saslcookie(acptr) = 0;
    cli_saslstart(acptr) = 0;
    if (t_active(&cli_sasltimeout(acptr)))
      timer_del(&cli_sasltimeout(acptr));
    sasl_session_free(acptr);
    if (cli_auth(acptr))
      auth_sasl_done(cli_auth(acptr));
  }
}

/** Handle decoded PLAIN data: authzid\0authcid\0password */
static int sasl_handle_plain(struct Client *sptr, const unsigned char *decoded, size_t len)
{
  struct SASLSession *session = cli_saslsession(sptr);
  const char *authzid_str;
  const char *authcid_str;
  const char *password_str;
  const char *p;
  const char *end = (const char *)decoded + len;
  struct sasl_cb_ctx *ctx;

  /* Parse PLAIN: authzid\0authcid\0password
   * authzid may be empty (starts with \0).
   */
  authzid_str = (const char *)decoded;

  /* Find first NUL — boundary between authzid and authcid */
  p = memchr(decoded, '\0', len);
  if (!p || p >= end - 1) {
    send_reply(sptr, ERR_SASLFAIL, ": malformed PLAIN data");
    return -1;
  }
  authcid_str = p + 1;

  /* Find second NUL — boundary between authcid and password */
  p = memchr(authcid_str, '\0', end - authcid_str);
  if (!p || p >= end - 1) {
    send_reply(sptr, ERR_SASLFAIL, ": malformed PLAIN data");
    return -1;
  }
  password_str = p + 1;

  /* Validate authcid and password are non-empty */
  if (!*authcid_str || !*password_str) {
    send_reply(sptr, ERR_SASLFAIL, ": empty username or password");
    return -1;
  }

  /* Validate lengths */
  if (strlen(authcid_str) > ACCOUNTLEN) {
    send_reply(sptr, ERR_SASLFAIL, ": username too long");
    return -1;
  }

  /* Save authcid and authzid in session */
  ircd_strncpy(session->authcid, authcid_str, sizeof(session->authcid));
  if (*authzid_str && ircd_strcmp(authzid_str, authcid_str) != 0) {
    if (strlen(authzid_str) > ACCOUNTLEN) {
      send_reply(sptr, ERR_SASLFAIL, ": authzid too long");
      return -1;
    }
    ircd_strncpy(session->authzid, authzid_str, sizeof(session->authzid));
    /* TODO: Validate authcid is authorized to assert authzid (service account check) */
    log_write(LS_SYSTEM, L_INFO, 0,
              "SASL PLAIN: authzid impersonation: %s acting as %s (client %C)",
              authcid_str, authzid_str, sptr);
  }

  /* Auth cache check — avoids Keycloak round-trip for repeated attempts */
  if (authcache_initialized) {
    uint64_t cred_hash = authcache_hash(authcid_str, password_str);

    /* 1. Negative cache — reject known-bad credentials immediately */
    if (negcache_check(cred_hash)) {
      log_write(LS_SYSTEM, L_DEBUG, 0,
                "SASL PLAIN: Negative cache hit for %s (client %C)",
                authcid_str, sptr);
      send_reply(sptr, ERR_SASLFAIL, "");
      session->state = SASL_STATE_FAILED;
      cli_saslcookie(sptr) = 0;
      cli_saslstart(sptr) = 0;
      if (t_active(&cli_sasltimeout(sptr)))
        timer_del(&cli_sasltimeout(sptr));
      sasl_session_free(sptr);
      if (cli_auth(sptr))
        auth_sasl_done(cli_auth(sptr));
      return 0;
    }

    /* 2. Positive cache — accept known-good credentials immediately */
    {
      char cached_account[ACCOUNTLEN + 1];
      time_t cached_created_at = 0;
      if (poscache_check(cred_hash, cached_account, sizeof(cached_account),
                         &cached_created_at)) {
        const char *login_as = session->authzid[0] ? session->authzid : cached_account;
        log_write(LS_SYSTEM, L_DEBUG, 0,
                  "SASL PLAIN: Positive cache hit for %s (client %C)",
                  authcid_str, sptr);
        sasl_complete_login(sptr, login_as, cached_created_at);
        return 0;
      }
    }

    /* Save hash in session for callback to update caches */
    session->cred_hash = cred_hash;
    session->cred_hash_valid = 1;
  }

  /* Set state to waiting for Keycloak response */
  session->state = SASL_STATE_WAITING_KC;

  /* Allocate callback context — NEVER pass raw Client pointer */
  ctx = (struct sasl_cb_ctx *)MyMalloc(sizeof(struct sasl_cb_ctx));
  ctx->fd = cli_fd(sptr);
  ctx->cookie = cli_saslcookie(sptr);

  /* Fire async Keycloak password verification */
  log_write(LS_SYSTEM, L_DEBUG, 0,
            "SASL PLAIN: Verifying credentials for %s via Keycloak (client %C)",
            authcid_str, sptr);
  kc_user_verify_password(authcid_str, password_str, sasl_plain_cb, ctx);

  return 0;
}

/* ---- EXTERNAL mechanism handler ---- */

/** Callback from kc_user_search() for fingerprint lookup. */
static void sasl_external_cb(int result, const struct kc_user *users, int count, void *data)
{
  struct sasl_cb_ctx *ctx = (struct sasl_cb_ctx *)data;
  struct Client *acptr;
  struct SASLSession *session;

  /* Re-resolve client via FD + cookie (use-after-free protection) */
  acptr = LocalClientArray[ctx->fd];
  if (!acptr || cli_saslcookie(acptr) != ctx->cookie) {
    MyFree(ctx);
    return;
  }
  MyFree(ctx);

  session = cli_saslsession(acptr);
  if (!session || session->state != SASL_STATE_WAITING_KC) {
    log_write(LS_SYSTEM, L_WARNING, 0,
              "SASL EXTERNAL: Callback for %C but session state is wrong", acptr);
    return;
  }

  if (result == KC_SUCCESS && count == 1) {
    /* Successful lookup confirms Keycloak is reachable */
    if (!kc_sasl_healthy)
      sasl_mark_healthy();
    log_write(LS_SYSTEM, L_INFO, 0,
              "SASL EXTERNAL: Fingerprint matched user %s (client %C)",
              users[0].username, acptr);
    sasl_complete_login(acptr, users[0].username,
                        users[0].created_at ? users[0].created_at : 0);
  } else if (count > 1) {
    log_write(LS_SYSTEM, L_WARNING, 0,
              "SASL EXTERNAL: Fingerprint collision — %d users matched (client %C)",
              count, acptr);
    send_reply(acptr, ERR_SASLFAIL, "");
    session->state = SASL_STATE_FAILED;
    cli_saslcookie(acptr) = 0;
    cli_saslstart(acptr) = 0;
    if (t_active(&cli_sasltimeout(acptr)))
      timer_del(&cli_sasltimeout(acptr));
    sasl_session_free(acptr);
    if (cli_auth(acptr))
      auth_sasl_done(cli_auth(acptr));
  } else {
    /* Distinguish connectivity errors from "user not found" */
    if (result != KC_SUCCESS && result != KC_NOT_FOUND)
      sasl_mark_unhealthy(result);
    log_write(LS_SYSTEM, L_INFO, 0,
              "SASL EXTERNAL: No user found for fingerprint (client %C, result %d)",
              acptr, result);
    send_reply(acptr, ERR_SASLFAIL, "");
    session->state = SASL_STATE_FAILED;
    cli_saslcookie(acptr) = 0;
    cli_saslstart(acptr) = 0;
    if (t_active(&cli_sasltimeout(acptr)))
      timer_del(&cli_sasltimeout(acptr));
    sasl_session_free(acptr);
    if (cli_auth(acptr))
      auth_sasl_done(cli_auth(acptr));
  }
}

/** Handle EXTERNAL mechanism — lookup client certificate fingerprint in Keycloak. */
static int sasl_handle_external(struct Client *sptr, const unsigned char *decoded, size_t len)
{
  struct SASLSession *session = cli_saslsession(sptr);
  const char *fingerprint = cli_sslclifp(sptr);
  char query[256];
  struct sasl_cb_ctx *ctx;

  /* Client must have a TLS client certificate */
  if (!fingerprint || !*fingerprint) {
    log_write(LS_SYSTEM, L_INFO, 0,
              "SASL EXTERNAL: No client certificate for %C", sptr);
    send_reply(sptr, ERR_SASLFAIL, ": no client certificate");
    return -1;
  }

  /* If client sent an authzid, save it (for authorization identity assertion) */
  if (decoded && len > 0) {
    size_t zlen = len < ACCOUNTLEN ? len : ACCOUNTLEN;
    memcpy(session->authzid, decoded, zlen);
    session->authzid[zlen] = '\0';
  }

  session->state = SASL_STATE_WAITING_KC;

  /* Allocate callback context */
  ctx = (struct sasl_cb_ctx *)MyMalloc(sizeof(struct sasl_cb_ctx));
  ctx->fd = cli_fd(sptr);
  ctx->cookie = cli_saslcookie(sptr);

  /* Search Keycloak for user with matching x509_fingerprints attribute */
  snprintf(query, sizeof(query), "x509_fingerprints:%s", fingerprint);
  log_write(LS_SYSTEM, L_DEBUG, 0,
            "SASL EXTERNAL: Searching for fingerprint %s (client %C)",
            fingerprint, sptr);
  kc_user_search(query, true, sasl_external_cb, ctx);

  return 0;
}

/* ---- OAUTHBEARER mechanism handler ---- */

/** Parse RFC 7628 OAUTHBEARER initial client response.
 *  Format: gs2-header kvsep *kvpair kvsep
 *  gs2-header = "n" / "y" / "p=..." "," [authzid] ","
 *  kvpair = key "=" value (separated by \x01)
 *
 *  Example: n,a=user,\x01auth=Bearer <token>\x01\x01
 *  Example: n,,\x01auth=Bearer <token>\x01\x01
 *
 *  @return 0 on success (token extracted), -1 on parse error.
 */
static int oauthbearer_parse(const unsigned char *data, size_t len,
                             char *authzid_out, size_t authzid_size,
                             const char **token_out, size_t *token_len_out)
{
  const char *p = (const char *)data;
  const char *end = p + len;
  const char *comma;

  /* Must start with gs2-cb-flag: 'n' (no channel binding), 'y', or 'p=' */
  if (p >= end || (*p != 'n' && *p != 'y' && *p != 'p'))
    return -1;

  /* Skip gs2-cb-flag to first comma */
  comma = memchr(p, ',', end - p);
  if (!comma)
    return -1;
  p = comma + 1;

  /* Optional authzid: "a=<value>" or empty */
  comma = memchr(p, ',', end - p);
  if (!comma)
    return -1;

  if (comma > p && p[0] == 'a' && p[1] == '=') {
    size_t azlen = comma - p - 2;
    if (azlen > 0 && azlen < authzid_size) {
      memcpy(authzid_out, p + 2, azlen);
      authzid_out[azlen] = '\0';
    }
  }
  p = comma + 1;

  /* Now at key-value pairs separated by \x01.
   * Must start with \x01, then key=value pairs. */
  if (p >= end || *p != '\x01')
    return -1;
  p++;

  /* Search for "auth=Bearer " key-value pair */
  while (p < end && *p != '\x01') {
    const char *kvsep = memchr(p, '\x01', end - p);
    if (!kvsep)
      kvsep = end;

    if (kvsep - p > 12 && strncmp(p, "auth=Bearer ", 12) == 0) {
      *token_out = p + 12;
      *token_len_out = kvsep - p - 12;
      return 0;
    }

    p = kvsep;
    if (p < end && *p == '\x01')
      p++;
  }

  return -1;  /* No bearer token found */
}

/** Callback from kc_token_introspect() for OAUTHBEARER fallback. */
static void sasl_oauth_introspect_cb(int result, const struct kc_token_info *info, void *data)
{
  struct sasl_cb_ctx *ctx = (struct sasl_cb_ctx *)data;
  struct Client *acptr;
  struct SASLSession *session;

  acptr = LocalClientArray[ctx->fd];
  if (!acptr || cli_saslcookie(acptr) != ctx->cookie) {
    MyFree(ctx);
    return;
  }
  MyFree(ctx);

  session = cli_saslsession(acptr);
  if (!session || session->state != SASL_STATE_WAITING_KC) {
    log_write(LS_SYSTEM, L_WARNING, 0,
              "SASL OAUTHBEARER: Introspect callback for %C but session state is wrong", acptr);
    return;
  }

  if (result == KC_SUCCESS && info && info->active && info->username) {
    /* Successful introspect confirms Keycloak is reachable */
    if (!kc_sasl_healthy)
      sasl_mark_healthy();
    /* Use authzid if set, otherwise username from token */
    const char *login_as = session->authzid[0] ? session->authzid : info->username;
    log_write(LS_SYSTEM, L_INFO, 0,
              "SASL OAUTHBEARER: Introspect success for %s (client %C)",
              login_as, acptr);
    sasl_complete_login(acptr, login_as,
                        info->created_at ? info->created_at : 0);
  } else {
    /* Connectivity errors should degrade health; invalid/inactive tokens should not */
    if (result != KC_SUCCESS && result != KC_FORBIDDEN)
      sasl_mark_unhealthy(result);
    log_write(LS_SYSTEM, L_INFO, 0,
              "SASL OAUTHBEARER: Introspect failed for %C (result %d, active=%d)",
              acptr, result, info ? info->active : 0);
    /* RFC 7628 §3.2.3: Send error challenge, then wait for client to send
     * "*" (abort).  The abort triggers sasl_abort_local → ERR_SASLFAIL. */
    sendrawto_one(acptr, MSG_AUTHENTICATE " "
                  "eyJzdGF0dXMiOiJpbnZhbGlkX3Rva2VuIn0=");  /* {"status":"invalid_token"} */
    session->state = SASL_STATE_FAILED;
  }
}

/** Handle decoded OAUTHBEARER data. */
static int sasl_handle_oauthbearer(struct Client *sptr, const unsigned char *decoded, size_t len)
{
  struct SASLSession *session = cli_saslsession(sptr);
  char authzid[ACCOUNTLEN + 1] = {0};
  const char *token_str = NULL;
  size_t token_len = 0;
  char *token_nul = NULL;
  struct kc_realm realm;
  struct kc_token_info *info = NULL;
  int rc;

  /* Parse OAUTHBEARER format */
  if (oauthbearer_parse(decoded, len, authzid, sizeof(authzid),
                        &token_str, &token_len) != 0 || !token_str || token_len == 0) {
    log_write(LS_SYSTEM, L_INFO, 0,
              "SASL OAUTHBEARER: Malformed data from %C", sptr);
    send_reply(sptr, ERR_SASLFAIL, ": malformed OAUTHBEARER data");
    return -1;
  }

  /* Save authzid if present */
  if (authzid[0])
    ircd_strncpy(session->authzid, authzid, sizeof(session->authzid));

  /* NUL-terminate token for libkc (which expects C strings) */
  token_nul = (char *)MyMalloc(token_len + 1);
  memcpy(token_nul, token_str, token_len);
  token_nul[token_len] = '\0';

  /* Strategy 1: Try local JWKS validation (synchronous, fast if cached) */
  realm.base_url = feature_str(FEAT_KEYCLOAK_URL);
  realm.realm = feature_str(FEAT_KEYCLOAK_REALM);

  rc = kc_jwt_validate_local(realm, token_nul, &info);
  if (rc == KC_SUCCESS && info && info->username) {
    const char *login_as = session->authzid[0] ? session->authzid : info->username;
    {
      time_t jwt_created_at = info->created_at ? info->created_at : 0;
      log_write(LS_SYSTEM, L_INFO, 0,
                "SASL OAUTHBEARER: JWT validated locally for %s (client %C)",
                login_as, sptr);
      MyFree(token_nul);
      sasl_complete_login(sptr, login_as, jwt_created_at);
      kc_jwt_token_info_free(info);
      return 0;
    }
  }

  if (info) {
    kc_jwt_token_info_free(info);
    info = NULL;
  }

  /* Strategy 2: Fall back to async token introspection */
  log_write(LS_SYSTEM, L_DEBUG, 0,
            "SASL OAUTHBEARER: JWT local validation failed (rc=%d), "
            "falling back to introspection for %C", rc, sptr);

  session->state = SASL_STATE_WAITING_KC;

  {
    struct sasl_cb_ctx *ctx = (struct sasl_cb_ctx *)MyMalloc(sizeof(struct sasl_cb_ctx));
    ctx->fd = cli_fd(sptr);
    ctx->cookie = cli_saslcookie(sptr);

    if (kc_token_introspect(token_nul, sasl_oauth_introspect_cb, ctx) != 0) {
      MyFree(ctx);
      MyFree(token_nul);
      log_write(LS_SYSTEM, L_WARNING, 0,
                "SASL OAUTHBEARER: Failed to submit introspection for %C", sptr);
      send_reply(sptr, ERR_SASLFAIL, ": introspection unavailable");
      return -1;
    }
  }

  MyFree(token_nul);
  return 0;
}

/* ---- SCRAM-SHA-256 mechanism handler ---- */

/** Base64 encode helper (returns MyMalloc'd string, caller must MyFree). */
static char *sasl_base64_encode(const unsigned char *input, size_t len)
{
  int outlen = ((len + 2) / 3) * 4;
  char *output = (char *)MyMalloc(outlen + 1);
  EVP_EncodeBlock((unsigned char *)output, input, len);
  return output;
}

/** XOR two byte arrays of equal length. */
static void xor_bytes(unsigned char *out, const unsigned char *a,
                      const unsigned char *b, size_t len)
{
  size_t i;
  for (i = 0; i < len; i++)
    out[i] = a[i] ^ b[i];
}

/** Compute HMAC-SHA-256.  Output must be 32 bytes. */
static int hmac_sha256(const unsigned char *key, size_t key_len,
                       const unsigned char *data, size_t data_len,
                       unsigned char *out)
{
  unsigned int out_len = 32;
  if (!HMAC(EVP_sha256(), key, key_len, data, data_len, out, &out_len))
    return -1;
  return 0;
}

/** Compute SHA-256 hash. Output must be 32 bytes. */
static int sha256_hash(const unsigned char *data, size_t len, unsigned char *out)
{
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx)
    return -1;
  if (!EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) ||
      !EVP_DigestUpdate(ctx, data, len) ||
      !EVP_DigestFinal_ex(ctx, out, NULL)) {
    EVP_MD_CTX_free(ctx);
    return -1;
  }
  EVP_MD_CTX_free(ctx);
  return 0;
}

/** Callback from kc_user_get() — received SCRAM credentials. */
static void sasl_scram_creds_cb(int result, const struct kc_user *user, void *data)
{
  struct sasl_cb_ctx *ctx = (struct sasl_cb_ctx *)data;
  struct Client *acptr;
  struct SASLSession *session;
  unsigned char nonce_bytes[18];
  char *nonce_b64;
  char combined_nonce[128];
  char server_first[512];
  char *server_first_b64;
  size_t decoded_len;

  acptr = LocalClientArray[ctx->fd];
  if (!acptr || cli_saslcookie(acptr) != ctx->cookie) {
    MyFree(ctx);
    return;
  }
  MyFree(ctx);

  session = cli_saslsession(acptr);
  if (!session || session->state != SASL_STATE_WAITING_KC) {
    log_write(LS_SYSTEM, L_WARNING, 0,
              "SASL SCRAM: Creds callback for %C but session state is wrong", acptr);
    return;
  }

  /* Check that SCRAM credentials exist for this user */
  if (result != KC_SUCCESS || !user || !user->scram_salt ||
      !user->scram_stored_key || !user->scram_server_key ||
      user->scram_iterations < 1) {
    /* Distinguish connectivity errors from missing credentials */
    if (result != KC_SUCCESS && result != KC_NOT_FOUND)
      sasl_mark_unhealthy(result);
    log_write(LS_SYSTEM, L_INFO, 0,
              "SASL SCRAM: No SCRAM credentials for %s (client %C)",
              session->authcid, acptr);
    send_reply(acptr, ERR_SASLFAIL, "");
    session->state = SASL_STATE_FAILED;
    cli_saslcookie(acptr) = 0;
    cli_saslstart(acptr) = 0;
    if (t_active(&cli_sasltimeout(acptr)))
      timer_del(&cli_sasltimeout(acptr));
    sasl_session_free(acptr);
    if (cli_auth(acptr))
      auth_sasl_done(cli_auth(acptr));
    return;
  }

  /* Successful credential lookup confirms Keycloak is reachable */
  if (!kc_sasl_healthy)
    sasl_mark_healthy();

  /* Decode stored key and server key from base64 */
  if (!sasl_base64_decode(user->scram_stored_key, session->scram_stored_key,
                          sizeof(session->scram_stored_key), &decoded_len) ||
      decoded_len != 32) {
    log_write(LS_SYSTEM, L_WARNING, 0,
              "SASL SCRAM: Invalid StoredKey for %s", session->authcid);
    send_reply(acptr, ERR_SASLFAIL, "");
    sasl_abort_local(acptr);
    return;
  }
  if (!sasl_base64_decode(user->scram_server_key, session->scram_server_key,
                          sizeof(session->scram_server_key), &decoded_len) ||
      decoded_len != 32) {
    log_write(LS_SYSTEM, L_WARNING, 0,
              "SASL SCRAM: Invalid ServerKey for %s", session->authcid);
    send_reply(acptr, ERR_SASLFAIL, "");
    sasl_abort_local(acptr);
    return;
  }

  DupString(session->scram_salt_b64, user->scram_salt);
  session->scram_iterations = user->scram_iterations;
  session->acc_created_at = user->created_at;

  /* Generate server nonce (18 random bytes → 24 base64 chars) */
  {
    int i;
    for (i = 0; i < 18; i++)
      nonce_bytes[i] = (unsigned char)(ircrandom() & 0xFF);
  }
  nonce_b64 = sasl_base64_encode(nonce_bytes, 18);

  /* Combined nonce = client_nonce + server_nonce */
  {
    /* Extract client nonce from client-first-bare: "n=user,r=<nonce>" */
    const char *r = strstr(session->scram_client_first_bare, ",r=");
    if (!r) {
      MyFree(nonce_b64);
      send_reply(acptr, ERR_SASLFAIL, "");
      sasl_abort_local(acptr);
      return;
    }
    snprintf(combined_nonce, sizeof(combined_nonce), "%s%s", r + 3, nonce_b64);
  }
  MyFree(nonce_b64);

  DupString(session->scram_combined_nonce, combined_nonce);

  /* Build server-first message: r=<combined>,s=<salt>,i=<iterations> */
  snprintf(server_first, sizeof(server_first), "r=%s,s=%s,i=%d",
           combined_nonce, session->scram_salt_b64, session->scram_iterations);

  DupString(session->scram_server_first, server_first);

  /* Base64 encode and send as AUTHENTICATE challenge */
  server_first_b64 = sasl_base64_encode((const unsigned char *)server_first,
                                         strlen(server_first));

  {
    char sendbuf[600];
    snprintf(sendbuf, sizeof(sendbuf), "%s %s", MSG_AUTHENTICATE, server_first_b64);
    sendrawto_one(acptr, sendbuf);
  }
  MyFree(server_first_b64);

  /* Reset chunk accumulation for the next client message (client-final) */
  if (session->accumulated_data) {
    MyFree(session->accumulated_data);
    session->accumulated_data = NULL;
    session->data_len = 0;
    session->data_alloc = 0;
    session->chunks_received = 0;
  }

  /* Now waiting for client-final message */
  session->state = SASL_STATE_SCRAM_SENT;

  log_write(LS_SYSTEM, L_DEBUG, 0,
            "SASL SCRAM: Sent server-first for %s (client %C)",
            session->authcid, acptr);
}

/** Handle SCRAM client-first message: n,,n=<user>,r=<nonce>
 *  Parses username and client nonce, then async-fetches SCRAM creds from KC.
 */
static int sasl_scram_client_first(struct Client *sptr,
                                    const unsigned char *decoded, size_t len)
{
  struct SASLSession *session = cli_saslsession(sptr);
  const char *msg = (const char *)decoded;
  const char *bare;
  const char *n_field;
  const char *r_field;
  char username[ACCOUNTLEN + 1];
  struct sasl_cb_ctx *ctx;

  /* Must start with "n,," (no channel binding, no authzid) or "n,a=..," */
  if (len < 5 || msg[0] != 'n' || msg[1] != ',')
    return -1;

  /* Find the start of client-first-message-bare (after "n,,") */
  {
    const char *second_comma = memchr(msg + 2, ',', len - 2);
    if (!second_comma)
      return -1;
    bare = second_comma + 1;
  }

  /* Extract authzid if present */
  if (msg[2] == 'a' && msg[3] == '=') {
    const char *comma = memchr(msg + 4, ',', len - 4);
    if (comma) {
      size_t azlen = comma - msg - 4;
      if (azlen > 0 && azlen < ACCOUNTLEN)  {
        memcpy(session->authzid, msg + 4, azlen);
        session->authzid[azlen] = '\0';
      }
    }
  }

  /* Parse n=<username> */
  n_field = bare;
  if (strncmp(n_field, "n=", 2) != 0)
    return -1;

  r_field = strstr(n_field, ",r=");
  if (!r_field)
    return -1;

  {
    size_t ulen = r_field - n_field - 2;
    if (ulen == 0 || ulen > ACCOUNTLEN) {
      send_reply(sptr, ERR_SASLFAIL, ": invalid SCRAM username");
      return -1;
    }
    memcpy(username, n_field + 2, ulen);
    username[ulen] = '\0';
  }

  /* Save authcid and client-first-message-bare for later verification */
  ircd_strncpy(session->authcid, username, sizeof(session->authcid));
  DupString(session->scram_client_first_bare, bare);

  /* Async fetch user from Keycloak to get SCRAM credentials */
  session->state = SASL_STATE_WAITING_KC;

  ctx = (struct sasl_cb_ctx *)MyMalloc(sizeof(struct sasl_cb_ctx));
  ctx->fd = cli_fd(sptr);
  ctx->cookie = cli_saslcookie(sptr);

  log_write(LS_SYSTEM, L_DEBUG, 0,
            "SASL SCRAM: Fetching credentials for %s (client %C)",
            username, sptr);
  kc_user_get(username, sasl_scram_creds_cb, ctx);

  return 0;
}

/** Handle SCRAM client-final message: c=<binding>,r=<nonce>,p=<proof>
 *  Verifies the client proof using stored credentials.
 */
static int sasl_scram_client_final(struct Client *sptr,
                                    const unsigned char *decoded, size_t len)
{
  struct SASLSession *session = cli_saslsession(sptr);
  const char *msg = (const char *)decoded;
  const char *msg_end = msg + len;
  const char *p_field;
  const char *proof_b64;
  unsigned char client_proof[32];
  unsigned char client_key[32];
  unsigned char stored_key_check[32];
  unsigned char client_sig[32];
  unsigned char server_sig[32];
  char *server_sig_b64;
  char auth_message[2048];
  const char *client_final_without_proof;
  size_t cfwp_len;
  size_t decoded_len;

  /* Find p=<proof> at end of message */
  p_field = strstr(msg, ",p=");
  if (!p_field) {
    send_reply(sptr, ERR_SASLFAIL, ": malformed SCRAM client-final");
    return -1;
  }
  proof_b64 = p_field + 3;

  /* Verify the nonce matches */
  {
    const char *r_field = strstr(msg, ",r=");
    if (!r_field || r_field > p_field) {
      send_reply(sptr, ERR_SASLFAIL, ": missing nonce in client-final");
      return -1;
    }
    {
      size_t nonce_len = p_field - r_field - 3;
      if (nonce_len != strlen(session->scram_combined_nonce) ||
          strncmp(r_field + 3, session->scram_combined_nonce, nonce_len) != 0) {
        send_reply(sptr, ERR_SASLFAIL, ": nonce mismatch");
        return -1;
      }
    }
  }

  /* Decode client proof from base64 */
  if (!sasl_base64_decode(proof_b64, client_proof, sizeof(client_proof), &decoded_len) ||
      decoded_len != 32) {
    send_reply(sptr, ERR_SASLFAIL, ": invalid client proof");
    return -1;
  }

  /* Build AuthMessage = client-first-bare + "," + server-first + "," + client-final-without-proof */
  client_final_without_proof = msg;
  cfwp_len = p_field - msg;
  snprintf(auth_message, sizeof(auth_message), "%s,%s,%.*s",
           session->scram_client_first_bare,
           session->scram_server_first,
           (int)cfwp_len, client_final_without_proof);

  /* ClientSignature = HMAC(StoredKey, AuthMessage) */
  if (hmac_sha256(session->scram_stored_key, 32,
                  (const unsigned char *)auth_message, strlen(auth_message),
                  client_sig) != 0) {
    send_reply(sptr, ERR_SASLFAIL, ": HMAC computation failed");
    return -1;
  }

  /* ClientKey = ClientProof XOR ClientSignature */
  xor_bytes(client_key, client_proof, client_sig, 32);

  /* StoredKey' = H(ClientKey) — should match stored StoredKey */
  if (sha256_hash(client_key, 32, stored_key_check) != 0) {
    send_reply(sptr, ERR_SASLFAIL, ": hash computation failed");
    return -1;
  }

  if (memcmp(stored_key_check, session->scram_stored_key, 32) != 0) {
    log_write(LS_SYSTEM, L_INFO, 0,
              "SASL SCRAM: Proof verification failed for %s (client %C)",
              session->authcid, sptr);
    send_reply(sptr, ERR_SASLFAIL, "");
    return -1;
  }

  /* Verification passed! Compute ServerSignature for mutual auth */
  /* ServerSignature = HMAC(ServerKey, AuthMessage) */
  if (hmac_sha256(session->scram_server_key, 32,
                  (const unsigned char *)auth_message, strlen(auth_message),
                  server_sig) != 0) {
    send_reply(sptr, ERR_SASLFAIL, ": HMAC computation failed");
    return -1;
  }

  /* Send server-final: v=<server_signature> */
  {
    char server_final[128];
    char *sf_b64;

    server_sig_b64 = sasl_base64_encode(server_sig, 32);
    snprintf(server_final, sizeof(server_final), "v=%s", server_sig_b64);
    MyFree(server_sig_b64);

    sf_b64 = sasl_base64_encode((const unsigned char *)server_final,
                                 strlen(server_final));

    {
      char sendbuf[600];
      snprintf(sendbuf, sizeof(sendbuf), "%s %s", MSG_AUTHENTICATE, sf_b64);
      sendrawto_one(sptr, sendbuf);
    }
    MyFree(sf_b64);
  }

  /* Proof verified — wait for client's final ack before completing login */
  session->state = SASL_STATE_SCRAM_VERIFY;

  /* Reset chunk accumulation for the ack */
  if (session->accumulated_data) {
    MyFree(session->accumulated_data);
    session->accumulated_data = NULL;
    session->data_len = 0;
    session->data_alloc = 0;
    session->chunks_received = 0;
  }

  return 0;
}

/** Handle SCRAM client ack after server-final — complete login. */
static int sasl_scram_complete(struct Client *sptr)
{
  struct SASLSession *session = cli_saslsession(sptr);
  const char *login_as = session->authzid[0] ? session->authzid : session->authcid;

  log_write(LS_SYSTEM, L_INFO, 0,
            "SASL SCRAM: Successful authentication for %s (client %C)",
            login_as, sptr);
  sasl_complete_login(sptr, login_as,
                      session->acc_created_at ? session->acc_created_at : 0);
  return 0;
}

/* ---- ECDSA-NIST256P-CHALLENGE mechanism handler ---- */

/** Callback from kc_user_get() — received ECDSA public key. */
static void sasl_ecdsa_key_cb(int result, const struct kc_user *user, void *data)
{
  struct sasl_cb_ctx *ctx = (struct sasl_cb_ctx *)data;
  struct Client *acptr;
  struct SASLSession *session;
  unsigned char challenge[32];
  char *challenge_b64;
  int i;

  acptr = LocalClientArray[ctx->fd];
  if (!acptr || cli_saslcookie(acptr) != ctx->cookie) {
    MyFree(ctx);
    return;
  }
  MyFree(ctx);

  session = cli_saslsession(acptr);
  if (!session || session->state != SASL_STATE_WAITING_KC) {
    return;
  }

  if (result != KC_SUCCESS || !user || !user->ecdsa_pubkey) {
    /* Distinguish connectivity errors from missing credentials */
    if (result != KC_SUCCESS && result != KC_NOT_FOUND)
      sasl_mark_unhealthy(result);
    log_write(LS_SYSTEM, L_INFO, 0,
              "SASL ECDSA: No ECDSA key for %s (client %C)",
              session->authcid, acptr);
    send_reply(acptr, ERR_SASLFAIL, "");
    sasl_abort_local(acptr);
    return;
  }

  /* Successful key lookup confirms Keycloak is reachable */
  if (!kc_sasl_healthy)
    sasl_mark_healthy();

  /* Save the public key PEM for later verification */
  DupString(session->scram_client_first_bare, user->ecdsa_pubkey);
  /* (Reusing scram_client_first_bare to store ecdsa_pubkey — it's just a string slot) */
  session->acc_created_at = user->created_at;

  /* Generate 32-byte random challenge */
  for (i = 0; i < 32; i++)
    challenge[i] = (unsigned char)(ircrandom() & 0xFF);

  /* Save challenge for verification (reusing scram_stored_key — 32 bytes) */
  memcpy(session->scram_stored_key, challenge, 32);

  /* Send challenge as AUTHENTICATE <base64(challenge)> */
  challenge_b64 = sasl_base64_encode(challenge, 32);
  {
    char sendbuf[600];
    snprintf(sendbuf, sizeof(sendbuf), "%s %s", MSG_AUTHENTICATE, challenge_b64);
    sendrawto_one(acptr, sendbuf);
  }
  MyFree(challenge_b64);

  /* Waiting for signed response */
  session->state = SASL_STATE_SCRAM_SENT;  /* Reuse this state for "challenge sent" */

  /* Reset chunk accumulation for the response */
  if (session->accumulated_data) {
    MyFree(session->accumulated_data);
    session->accumulated_data = NULL;
    session->data_len = 0;
    session->data_alloc = 0;
    session->chunks_received = 0;
  }
}

/** Handle ECDSA client-first: just the authcid (username). */
static int sasl_ecdsa_client_first(struct Client *sptr,
                                    const unsigned char *decoded, size_t len)
{
  struct SASLSession *session = cli_saslsession(sptr);
  const char *username = (const char *)decoded;
  struct sasl_cb_ctx *ctx;

  if (len == 0 || len > ACCOUNTLEN) {
    send_reply(sptr, ERR_SASLFAIL, ": invalid ECDSA username");
    return -1;
  }

  ircd_strncpy(session->authcid, username, sizeof(session->authcid));

  session->state = SASL_STATE_WAITING_KC;

  ctx = (struct sasl_cb_ctx *)MyMalloc(sizeof(struct sasl_cb_ctx));
  ctx->fd = cli_fd(sptr);
  ctx->cookie = cli_saslcookie(sptr);

  log_write(LS_SYSTEM, L_DEBUG, 0,
            "SASL ECDSA: Fetching public key for %s (client %C)",
            session->authcid, sptr);
  kc_user_get(session->authcid, sasl_ecdsa_key_cb, ctx);

  return 0;
}

/** Verify ECDSA signature over the challenge. */
static int sasl_ecdsa_verify(struct Client *sptr,
                              const unsigned char *signature, size_t sig_len)
{
  struct SASLSession *session = cli_saslsession(sptr);
  const char *pubkey_pem = session->scram_client_first_bare;  /* Stored earlier */
  BIO *bio = NULL;
  EVP_PKEY *pkey = NULL;
  EVP_MD_CTX *md_ctx = NULL;
  int rc = -1;

  if (!pubkey_pem || !*pubkey_pem) {
    send_reply(sptr, ERR_SASLFAIL, ": no public key");
    return -1;
  }

  /* Load PEM public key */
  bio = BIO_new_mem_buf(pubkey_pem, -1);
  if (!bio)
    goto cleanup;

  pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
  if (!pkey) {
    log_write(LS_SYSTEM, L_WARNING, 0,
              "SASL ECDSA: Failed to parse public key for %s", session->authcid);
    goto cleanup;
  }

  /* Verify signature over the challenge */
  md_ctx = EVP_MD_CTX_new();
  if (!md_ctx)
    goto cleanup;

  if (EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, pkey) != 1)
    goto cleanup;

  if (EVP_DigestVerifyUpdate(md_ctx, session->scram_stored_key, 32) != 1)
    goto cleanup;

  if (EVP_DigestVerifyFinal(md_ctx, signature, sig_len) == 1) {
    rc = 0;  /* Signature valid */
  }

cleanup:
  if (md_ctx)
    EVP_MD_CTX_free(md_ctx);
  if (pkey)
    EVP_PKEY_free(pkey);
  if (bio)
    BIO_free(bio);

  return rc;
}

/** Handle ECDSA client response: the signed challenge. */
static int sasl_ecdsa_client_response(struct Client *sptr,
                                       const unsigned char *decoded, size_t len)
{
  struct SASLSession *session = cli_saslsession(sptr);

  if (sasl_ecdsa_verify(sptr, decoded, len) == 0) {
    const char *login_as = session->authzid[0] ? session->authzid : session->authcid;
    log_write(LS_SYSTEM, L_INFO, 0,
              "SASL ECDSA: Successful authentication for %s (client %C)",
              login_as, sptr);
    sasl_complete_login(sptr, login_as,
                        session->acc_created_at ? session->acc_created_at : 0);
    return 0;
  }

  log_write(LS_SYSTEM, L_INFO, 0,
            "SASL ECDSA: Signature verification failed for %s (client %C)",
            session->authcid, sptr);
  send_reply(sptr, ERR_SASLFAIL, "");
  return -1;
}

/** Top-level ECDSA handler — dispatches based on progress. */
static int sasl_handle_ecdsa(struct Client *sptr, const unsigned char *decoded, size_t len)
{
  struct SASLSession *session = cli_saslsession(sptr);

  if (!session->scram_client_first_bare) {
    /* First message: username */
    return sasl_ecdsa_client_first(sptr, decoded, len);
  } else {
    /* Second message: signed challenge */
    return sasl_ecdsa_client_response(sptr, decoded, len);
  }
}

/** Top-level SCRAM-SHA-256 handler — dispatches based on SCRAM progress.
 *  Uses presence of scram_server_first to distinguish client-first from client-final,
 *  since sasl_continue's chunk accumulation overwrites session->state to WAITING_DATA.
 */
static int sasl_handle_scram(struct Client *sptr, const unsigned char *decoded, size_t len)
{
  struct SASLSession *session = cli_saslsession(sptr);

  if (session->state == SASL_STATE_SCRAM_VERIFY) {
    /* Client ack after server-final v= message — complete login */
    return sasl_scram_complete(sptr);
  } else if (!session->scram_server_first) {
    /* Haven't sent server-first yet — this is client-first */
    return sasl_scram_client_first(sptr, decoded, len);
  } else {
    /* Already sent server-first — this is client-final */
    return sasl_scram_client_final(sptr, decoded, len);
  }
}

#endif /* USE_LIBKC */

/* ---- Framework functions ---- */

int sasl_local_available(void)
{
#ifdef USE_LIBKC
  return sasl_local_initialized && feature_bool(FEAT_SASL_LOCAL) && kc_sasl_healthy;
#else
  return 0;
#endif
}

const char *sasl_local_mechanisms(void)
{
  const char *mechs;
  if (!sasl_local_available())
    return NULL;
  mechs = feature_str(FEAT_SASL_LOCAL_MECHANISMS);
  return (mechs && *mechs) ? mechs : "PLAIN,OAUTHBEARER";
}

/** Check if a mechanism name appears in a comma-separated list. */
static int sasl_mech_enabled(const char *mechanism)
{
  const char *list = feature_str(FEAT_SASL_LOCAL_MECHANISMS);
  const char *p;
  size_t len;

  if (!list || !*list)
    return 0;

  len = strlen(mechanism);
  for (p = list; *p; ) {
    if (ircd_strncmp(p, mechanism, len) == 0
        && (p[len] == ',' || p[len] == '\0'))
      return 1;
    p = strchr(p, ',');
    if (!p)
      break;
    p++;  /* skip comma */
  }
  return 0;
}

int sasl_start(struct Client *sptr, const char *mechanism)
{
  enum SASLMechanism mech;

  if (!sasl_local_available())
    return -1;

  /* Parse mechanism name */
  if (ircd_strcmp(mechanism, "PLAIN") == 0)
    mech = SASL_MECH_PLAIN;
  else if (ircd_strcmp(mechanism, "EXTERNAL") == 0)
    mech = SASL_MECH_EXTERNAL;
  else if (ircd_strcmp(mechanism, "OAUTHBEARER") == 0)
    mech = SASL_MECH_OAUTHBEARER;
  else if (ircd_strcmp(mechanism, "SCRAM-SHA-256") == 0)
    mech = SASL_MECH_SCRAM_SHA256;
  else if (ircd_strcmp(mechanism, "ECDSA-NIST256P-CHALLENGE") == 0)
    mech = SASL_MECH_ECDSA;
  else
    return -1;  /* Unknown mechanism — fall through to P10 */

  /* Check if this mechanism is enabled in SASL_LOCAL_MECHANISMS */
  if (!sasl_mech_enabled(mechanism))
    return -1;  /* Disabled — fall through to P10 */

#ifdef USE_LIBKC
  {
    struct SASLSession *session;

    /* Allocate session */
    session = sasl_session_alloc(mech);
    cli_saslsession(sptr) = session;

    /* Generate SASL cookie if needed */
    if (!cli_saslcookie(sptr)) {
      do {
        cli_saslcookie(sptr) = ircrandom() & 0x7fffffff;
      } while (!cli_saslcookie(sptr));
      cli_saslstart(sptr) = CurrentTime;
      if (cli_auth(sptr))
        auth_sasl_start(cli_auth(sptr));
    }

    /* Send AUTHENTICATE + to request client data */
    sendrawto_one(sptr, MSG_AUTHENTICATE " +");

    /* Start timeout timer */
    if (!t_active(&cli_sasltimeout(sptr)))
      timer_add(timer_init(&cli_sasltimeout(sptr)), sasl_local_timeout_cb, (void *)sptr,
                TT_RELATIVE, feature_int(FEAT_SASL_TIMEOUT));

    return 0;
  }
#else
  return -1;
#endif
}

int sasl_continue(struct Client *sptr, const char *data)
{
  struct SASLSession *session = cli_saslsession(sptr);

  if (!session)
    return -1;

  /* OAUTHBEARER §3.2.3: After server sends error challenge, client responds
   * with dummy data or "*".  Either way, we send ERR_SASLFAIL and clean up. */
  if (session->state == SASL_STATE_FAILED) {
    send_reply(sptr, ERR_SASLFAIL, "");
    sasl_abort_local(sptr);
    return 0;
  }

  /* Only accept data in states that expect client messages.
   * SCRAM_SENT also accepts data (client-final after server-first).
   * SCRAM_VERIFY accepts the final client ack after server-final. */
  if (session->state != SASL_STATE_INIT &&
      session->state != SASL_STATE_WAITING_DATA &&
      session->state != SASL_STATE_SCRAM_SENT &&
      session->state != SASL_STATE_SCRAM_VERIFY)
    return -1;

  /* Handle chunk accumulation per IRCv3 SASL spec:
   * - Exactly 400 bytes = more data follows
   * - "+" alone after a 400-byte chunk = previous chunk was final
   * - < 400 bytes = final chunk
   */
  if (data[0] == '+' && data[1] == '\0') {
    /* Empty continuation or final marker after 400-byte chunk */
    if (!session->accumulated_data || session->data_len == 0) {
      /* No accumulated data — this is an empty response (valid for some mechs) */
      goto dispatch;
    }
    /* Previous 400-byte chunk was the last one — dispatch accumulated data */
    goto dispatch;
  }

  {
    size_t chunk_len = strlen(data);

    /* Accumulate data */
    if (!session->accumulated_data) {
      session->data_alloc = (chunk_len < 400) ? chunk_len + 1 : SASL_DATA_MAX;
      session->accumulated_data = (char *)MyMalloc(session->data_alloc);
      session->data_len = 0;
    }

    /* Check for overflow */
    if (session->data_len + chunk_len >= session->data_alloc) {
      size_t new_alloc = session->data_len + chunk_len + 1;
      if (new_alloc > SASL_DATA_MAX) {
        send_reply(sptr, ERR_SASLTOOLONG);
        sasl_abort_local(sptr);
        return 0;
      }
      session->accumulated_data = (char *)MyRealloc(session->accumulated_data, new_alloc);
      session->data_alloc = new_alloc;
    }

    memcpy(session->accumulated_data + session->data_len, data, chunk_len);
    session->data_len += chunk_len;
    session->accumulated_data[session->data_len] = '\0';
    session->chunks_received++;
    session->state = SASL_STATE_WAITING_DATA;

    /* If exactly 400 bytes, more data expected */
    if (chunk_len == 400)
      return 0;
  }

dispatch:
  /* We have all the data — decode base64 and dispatch to mechanism handler */
  {
    unsigned char decoded[SASL_DATA_MAX];
    size_t decoded_len = 0;
    int rc;

    if (session->accumulated_data && session->data_len > 0) {
      if (!sasl_base64_decode(session->accumulated_data, decoded,
                              sizeof(decoded) - 1, &decoded_len)) {
        send_reply(sptr, ERR_SASLFAIL, ": base64 decode failed");
        sasl_abort_local(sptr);
        return 0;
      }
    }
    /* Null-terminate — SCRAM handlers use strstr/strlen on decoded text */
    decoded[decoded_len] = '\0';

    switch (session->mech) {
#ifdef USE_LIBKC
      case SASL_MECH_PLAIN:
        rc = sasl_handle_plain(sptr, decoded, decoded_len);
        if (rc < 0) {
          sasl_abort_local(sptr);
          return 0;
        }
        break;
      case SASL_MECH_EXTERNAL:
        rc = sasl_handle_external(sptr, decoded, decoded_len);
        if (rc < 0) {
          sasl_abort_local(sptr);
          return 0;
        }
        break;
      case SASL_MECH_OAUTHBEARER:
        rc = sasl_handle_oauthbearer(sptr, decoded, decoded_len);
        if (rc < 0) {
          sasl_abort_local(sptr);
          return 0;
        }
        break;
      case SASL_MECH_SCRAM_SHA256:
        rc = sasl_handle_scram(sptr, decoded, decoded_len);
        if (rc < 0) {
          sasl_abort_local(sptr);
          return 0;
        }
        break;
      case SASL_MECH_ECDSA:
        rc = sasl_handle_ecdsa(sptr, decoded, decoded_len);
        if (rc < 0) {
          sasl_abort_local(sptr);
          return 0;
        }
        break;
#endif
      default:
        send_reply(sptr, ERR_SASLFAIL, ": unsupported mechanism");
        sasl_abort_local(sptr);
        return 0;
    }
  }

  return 0;
}

int sasl_abort_local(struct Client *sptr)
{
  struct SASLSession *session = cli_saslsession(sptr);

  if (!session)
    return 0;

  /* Clean up timer */
  if (t_active(&cli_sasltimeout(sptr)))
    timer_del(&cli_sasltimeout(sptr));

  /* Clean up session state */
  cli_saslcookie(sptr) = 0;
  cli_saslstart(sptr) = 0;
  sasl_session_free(sptr);

  /* Unblock registration */
  if (cli_auth(sptr))
    auth_sasl_done(cli_auth(sptr));

  return 0;
}

/* ---- Timeout callback for local SASL ---- */

static void sasl_local_timeout_cb(struct Event *ev)
{
  struct Client *cptr;

  assert(0 != ev_timer(ev));
  assert(0 != t_data(ev_timer(ev)));

  if (ev_type(ev) == ET_EXPIRE) {
    cptr = (struct Client *)t_data(ev_timer(ev));

    if (cli_saslsession(cptr)) {
      /* Local SASL timeout */
      log_write(LS_SYSTEM, L_INFO, 0,
                "SASL: Local session timeout for %C", cptr);
      send_reply(cptr, ERR_SASLFAIL, ": request timed out");
      sasl_abort_local(cptr);
    }
  }
}

/* ---- Initialization and health tracking ---- */

int sasl_local_init(void)
{
#ifdef USE_LIBKC
  if (!feature_bool(FEAT_SASL_LOCAL))
    return 0;  /* Not an error — just not configured */

  /* Verify Keycloak config is present */
  if (EmptyString(feature_str(FEAT_KEYCLOAK_URL)) ||
      EmptyString(feature_str(FEAT_KEYCLOAK_CLIENT_ID)) ||
      EmptyString(feature_str(FEAT_KEYCLOAK_CLIENT_SECRET))) {
    log_write(LS_SYSTEM, L_WARNING, 0,
              "SASL LOCAL: Missing Keycloak configuration (URL/CLIENT_ID/CLIENT_SECRET)");
    return -1;
  }

  sasl_local_initialized = 1;
  kc_sasl_healthy = 1;  /* Optimistic — kc_keycloak_init() already succeeded */

  /* Initialize auth caches */
  authcache_init();

  log_write(LS_SYSTEM, L_NOTICE, 0,
            "SASL LOCAL: Initialized — will validate credentials via Keycloak");

  /* Prime the Keycloak client credentials token (async — fires callback
   * when complete, which also validates Keycloak availability) */
  kc_token_ensure(sasl_health_cb, NULL);

  /* Prime the JWKS cache for offline JWT validation (sync HTTP — blocks
   * briefly on first fetch, then cached for 1 hour) */
  {
    struct kc_realm realm;
    realm.base_url = feature_str(FEAT_KEYCLOAK_URL);
    realm.realm = feature_str(FEAT_KEYCLOAK_REALM);
    if (kc_jwt_prime_cache(realm) == KC_SUCCESS) {
      log_write(LS_SYSTEM, L_NOTICE, 0,
                "SASL LOCAL: JWKS cache primed for OAUTHBEARER");
    } else {
      log_write(LS_SYSTEM, L_WARNING, 0,
                "SASL LOCAL: Failed to prime JWKS cache — OAUTHBEARER will fetch on first use");
    }
  }

  return 0;
#else
  return -1;
#endif
}

/** Start periodic health retry timer (called when Keycloak becomes unhealthy). */
#ifdef USE_LIBKC
static void sasl_start_health_retry(void)
{
  int interval;

  if (sasl_health_retry_timer_active)
    return;

  interval = feature_int(FEAT_SASL_HEALTH_INTERVAL);
  if (interval <= 0)
    interval = 30;

  timer_add(timer_init(&sasl_health_retry_timer), sasl_health_retry_timer_cb,
            NULL, TT_PERIODIC, interval);
  sasl_health_retry_timer_active = 1;

  log_write(LS_SYSTEM, L_DEBUG, 0,
            "SASL LOCAL: Health retry timer started (interval %d seconds)", interval);
}

/** Stop periodic health retry timer (called when Keycloak recovers). */
static void sasl_stop_health_retry(void)
{
  if (!sasl_health_retry_timer_active)
    return;

  timer_del(&sasl_health_retry_timer);
  sasl_health_retry_timer_active = 0;

  log_write(LS_SYSTEM, L_DEBUG, 0,
            "SASL LOCAL: Health retry timer stopped — Keycloak is healthy");
}

/** Periodic health retry timer callback — probes Keycloak when unhealthy. */
static void sasl_health_retry_timer_cb(struct Event *ev)
{
  if (ev_type(ev) == ET_EXPIRE) {
    if (kc_sasl_healthy) {
      /* Already recovered (e.g. via sasl_plain_cb path) — stop retrying */
      sasl_stop_health_retry();
      return;
    }
    log_write(LS_SYSTEM, L_DEBUG, 0,
              "SASL LOCAL: Health retry — probing Keycloak availability");
    kc_token_ensure(sasl_health_cb, NULL);
  } else if (ev_type(ev) == ET_DESTROY) {
    sasl_health_retry_timer_active = 0;
  }
}

/** Mark Keycloak as unhealthy and start retry timer.
 *  Sends CAP DEL if transitioning from healthy to unhealthy.
 */
static void sasl_mark_unhealthy(int result)
{
  int was_healthy = kc_sasl_healthy;

  kc_sasl_healthy = 0;
  if (was_healthy && sasl_local_initialized) {
    log_write(LS_SYSTEM, L_WARNING, 0,
              "SASL LOCAL: Keycloak became unreachable (result %d) — removing SASL", result);
    send_cap_notify("sasl", 0, NULL);
  }
  sasl_start_health_retry();
}

/** Mark Keycloak as healthy and stop retry timer.
 *  Sends CAP NEW if transitioning from unhealthy to healthy.
 */
static void sasl_mark_healthy(void)
{
  int was_healthy = kc_sasl_healthy;

  kc_sasl_healthy = 1;
  if (!was_healthy && sasl_local_initialized) {
    log_write(LS_SYSTEM, L_NOTICE, 0,
              "SASL LOCAL: Keycloak is now reachable — advertising SASL");
    send_cap_notify("sasl", 1, sasl_local_mechanisms());
  }
  sasl_stop_health_retry();
}

/** Health check callback — called from kc_token_ensure() result. */
static void sasl_health_cb(int result, const struct kc_access_token *token, void *data)
{
  if (result == KC_SUCCESS) {
    sasl_mark_healthy();
  } else {
    sasl_mark_unhealthy(result);
  }
}
#endif

void sasl_health_check(void)
{
#ifdef USE_LIBKC
  if (!sasl_local_initialized || !feature_bool(FEAT_SASL_LOCAL))
    return;
  kc_token_ensure(sasl_health_cb, NULL);
#endif
}
