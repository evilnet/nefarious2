/*
 * IRC - Internet Relay Chat, ircd/authtoken.c
 * Copyright (C) 2026 Evilnet Development
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
 * @brief IRCv3 draft/authtoken: service table, token table, claims.
 *
 * Services come from Authtoken { } blocks and live in fixed slots so a
 * validator connection's authority (a bitmask kept on the Connection)
 * survives a rehash that keeps the service.  Tokens are random,
 * single-use and short-lived; every one is replicated to IRCv3-aware
 * peers (TK G) and its consumption too (TK U), so the external service
 * may validate against any server in the network.  Claims are derived
 * from the requester's live channel state at VALIDATE time, per the
 * spec's recommendation, so a token minted while opped does not carry
 * the op after a deop.  See docs/features/authtoken.md in the testnet.
 */
#include "config.h"

#include "authtoken.h"
#include "capab.h"
#include "channel.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "match.h"
#include "msg.h"
#include "numnicks.h"
#include "s_debug.h"
#include "s_user.h"
#include "send.h"
#include "struct.h"

#ifdef USE_SSL
#include <openssl/rand.h>
#endif

#include <stdio.h>
#include <string.h>

/** Validator source masks per service. */
#define AUTHTOKEN_MAX_HOSTS 8
/** Outstanding tokens one user may hold; the oldest is evicted. */
#define AUTHTOKEN_PER_USER 16
/** Claim values are split so a line stays well inside 512 bytes. */
#define AUTHTOKEN_CLAIM_CHUNK 400

struct AuthtokenHost {
  struct irc_in_addr addr;
  unsigned char bits;
};

struct AuthtokenService {
  int used;
  char key[AUTHTOKEN_KEYLEN + 1];
  char url[512];
  char desc[256];
  char pass[PASSWDLEN + 1];
  struct AuthtokenHost hosts[AUTHTOKEN_MAX_HOSTS];
  int nhosts;
};

struct Authtoken {
  struct Authtoken *next;
  char token[AUTHTOKEN_LEN + 1];
  char key[AUTHTOKEN_KEYLEN + 1];
  char yxx[8];
  time_t expires;
  char scope[AUTHTOKEN_SCOPELEN + 1];
};

static struct AuthtokenService services[AUTHTOKEN_MAX_SERVICES];
static struct AuthtokenService pending[AUTHTOKEN_MAX_SERVICES];
static int npending;
static struct AuthtokenService cur;     /* block being parsed */
static int cur_open;

static struct Authtoken *tokens;
static int ntokens;

/* ------------------------------------------------------------------ */
/* Configuration                                                       */
/* ------------------------------------------------------------------ */

void authtoken_conf_begin(void)
{
  memset(pending, 0, sizeof(pending));
  npending = 0;
  memset(&cur, 0, sizeof(cur));
  cur_open = 0;
}

void authtoken_conf_service(const char *key)
{
  memset(&cur, 0, sizeof(cur));
  cur_open = 1;
  if (key)
    ircd_strncpy(cur.key, key, sizeof(cur.key));
}

void authtoken_conf_url(const char *url)
{
  if (url)
    ircd_strncpy(cur.url, url, sizeof(cur.url));
}

void authtoken_conf_description(const char *desc)
{
  if (desc)
    ircd_strncpy(cur.desc, desc, sizeof(cur.desc));
}

void authtoken_conf_pass(const char *pass)
{
  if (!pass)
    return;
  /* PASS is stored in PASSWDLEN bytes on the connection; a longer
   * secret could never match, so refuse it loudly rather than truncate. */
  if (strlen(pass) > PASSWDLEN) {
    log_write(LS_CONFIG, L_ERROR, 0,
              "Authtoken \"%s\": pass longer than %d characters", cur.key, PASSWDLEN);
    return;
  }
  ircd_strncpy(cur.pass, pass, sizeof(cur.pass));
}

void authtoken_conf_host(const char *mask)
{
  struct AuthtokenHost h;
  if (!mask || cur.nhosts >= AUTHTOKEN_MAX_HOSTS)
    return;
  memset(&h, 0, sizeof(h));
  if (!ipmask_parse(mask, &h.addr, &h.bits)) {
    log_write(LS_CONFIG, L_ERROR, 0,
              "Authtoken \"%s\": bad host mask \"%s\"", cur.key, mask);
    return;
  }
  cur.hosts[cur.nhosts++] = h;
}

/** Validate a service key: vendor/NAME or a spec-defined bare name. */
static int valid_service_key(const char *key)
{
  const char *p;
  if (EmptyString(key) || strlen(key) > AUTHTOKEN_KEYLEN)
    return 0;
  for (p = key; *p; ++p)
    if (!IsAlnum(*p) && *p != '/' && *p != '.' && *p != '-' && *p != '_')
      return 0;
  return 1;
}

int authtoken_conf_end(void)
{
  int i;
  cur_open = 0;
  if (!valid_service_key(cur.key)) {
    log_write(LS_CONFIG, L_ERROR, 0, "Authtoken block: bad service key \"%s\"", cur.key);
    return 0;
  }
  if (EmptyString(cur.url)) {
    log_write(LS_CONFIG, L_ERROR, 0, "Authtoken \"%s\": url required", cur.key);
    return 0;
  }
  if (EmptyString(cur.pass) && cur.nhosts == 0) {
    log_write(LS_CONFIG, L_ERROR, 0,
              "Authtoken \"%s\": a validator credential (pass and/or host) is required", cur.key);
    return 0;
  }
  if (EmptyString(cur.desc))
    ircd_strncpy(cur.desc, cur.key, sizeof(cur.desc));
  for (i = 0; i < npending; ++i)
    if (!ircd_strcmp(pending[i].key, cur.key)) {
      log_write(LS_CONFIG, L_ERROR, 0, "Authtoken \"%s\": duplicate block", cur.key);
      return 0;
    }
  if (npending >= AUTHTOKEN_MAX_SERVICES) {
    log_write(LS_CONFIG, L_ERROR, 0, "Authtoken \"%s\": too many services (max %d)",
              cur.key, AUTHTOKEN_MAX_SERVICES);
    return 0;
  }
  cur.used = 1;
  pending[npending++] = cur;
  memset(&cur, 0, sizeof(cur));
  return 1;
}

/** Tell every local client that negotiated batch + authtoken. */
static void notify_users(const char *fmt, const char *key, const char *url)
{
  struct Client *cptr;
  for (cptr = GlobalClientList; cptr; cptr = cli_next(cptr)) {
    if (!MyConnect(cptr) || !IsUser(cptr))
      continue;
    if (!CapActive(cptr, CAP_BATCH) || !CapActive(cptr, CAP_DRAFT_AUTHTOKEN))
      continue;
    if (url)
      sendcmdto_one(&me, CMD_TOKEN, cptr, fmt, key, url);
    else
      sendcmdto_one(&me, CMD_TOKEN, cptr, fmt, key);
  }
}

/** Drop slot @a i's validator authority from every local connection. */
static void revoke_slot_auth(int i)
{
  struct Client *cptr;
  for (cptr = GlobalClientList; cptr; cptr = cli_next(cptr))
    if (MyConnect(cptr) && cli_connect(cptr))
      cli_token_auth(cptr) &= ~(1u << i);
}

static void drop_tokens_of(const char *key)
{
  struct Authtoken **pp = &tokens, *t;
  while ((t = *pp)) {
    if (!ircd_strcmp(t->key, key)) {
      *pp = t->next;
      MyFree(t);
      --ntokens;
    } else
      pp = &t->next;
  }
}

void authtoken_conf_apply(void)
{
  int i, j, before = authtoken_service_count(), after;
  int seen[AUTHTOKEN_MAX_SERVICES];

  memset(seen, 0, sizeof(seen));

  /* Update or create the slot for every pending service. */
  for (i = 0; i < npending; ++i) {
    int slot = authtoken_find_service(pending[i].key);
    if (slot < 0) {
      for (j = 0; j < AUTHTOKEN_MAX_SERVICES; ++j)
        if (!services[j].used) { slot = j; break; }
      if (slot < 0)
        break;                                  /* cannot happen: npending capped */
      services[slot] = pending[i];
      seen[slot] = 1;
      notify_users("NEW %s %s", services[slot].key, services[slot].url);
      continue;
    }
    seen[slot] = 1;
    if (strcmp(services[slot].url, pending[i].url))
      notify_users("NEW %s %s", pending[i].key, pending[i].url);
    if (strcmp(services[slot].pass, pending[i].pass))
      revoke_slot_auth(slot);                   /* old PASS no longer vouches */
    services[slot] = pending[i];
  }

  /* Retire slots no longer configured. */
  for (i = 0; i < AUTHTOKEN_MAX_SERVICES; ++i) {
    if (!services[i].used || seen[i])
      continue;
    notify_users("DEL %s", services[i].key, NULL);
    revoke_slot_auth(i);
    drop_tokens_of(services[i].key);
    memset(&services[i], 0, sizeof(services[i]));
  }

  after = authtoken_service_count();
  if (feature_bool(FEAT_CAP_draft_authtoken) && (before == 0) != (after == 0))
    send_cap_notify("draft/authtoken", after > 0, NULL);
  npending = 0;
}

int authtoken_service_count(void)
{
  int i, n = 0;
  for (i = 0; i < AUTHTOKEN_MAX_SERVICES; ++i)
    if (services[i].used)
      ++n;
  return n;
}

int authtoken_find_service(const char *key)
{
  int i;
  if (EmptyString(key))
    return -1;
  for (i = 0; i < AUTHTOKEN_MAX_SERVICES; ++i)
    if (services[i].used && !ircd_strcmp(services[i].key, key))
      return i;
  return -1;
}

const char *authtoken_filehost_url(void)
{
  int i = authtoken_find_service("FILEHOST");
  return i < 0 ? NULL : services[i].url;
}

/* ------------------------------------------------------------------ */
/* Validator authority                                                  */
/* ------------------------------------------------------------------ */

/** Constant-time string equality (the secret is compared against
 * attacker-chosen input on every VALIDATE). */
static int ct_equal(const char *a, const char *b)
{
  size_t la = strlen(a), lb = strlen(b), i;
  unsigned char diff = (unsigned char)(la ^ lb);
  for (i = 0; i < la; ++i)
    diff |= (unsigned char)(a[i] ^ b[i % (lb ? lb : 1)]);
  return diff == 0;
}

static int pass_matches(struct Client *cptr, int i)
{
  return !EmptyString(services[i].pass)
      && !EmptyString(cli_passwd(cptr))
      && ct_equal(services[i].pass, cli_passwd(cptr));
}

void authtoken_note_pass(struct Client *cptr)
{
  int i;
  if (!cli_connect(cptr) || EmptyString(cli_passwd(cptr)))
    return;
  for (i = 0; i < AUTHTOKEN_MAX_SERVICES; ++i)
    if (services[i].used && pass_matches(cptr, i))
      cli_token_auth(cptr) |= (1u << i);
}

int authtoken_may_validate(struct Client *cptr, int svc)
{
  const struct AuthtokenService *s;
  int i;

  if (svc < 0 || svc >= AUTHTOKEN_MAX_SERVICES || !services[svc].used || !MyConnect(cptr))
    return 0;
  s = &services[svc];

  if (!EmptyString(s->pass)) {
    if (!(cli_token_auth(cptr) & (1u << svc)) && !pass_matches(cptr, svc))
      return 0;
  }
  if (s->nhosts) {
    for (i = 0; i < s->nhosts; ++i)
      if (ipmask_check(&cli_ip(cptr), &s->hosts[i].addr, s->hosts[i].bits))
        break;
    if (i == s->nhosts)
      return 0;
  }
  return 1;
}

/* ------------------------------------------------------------------ */
/* Service list                                                         */
/* ------------------------------------------------------------------ */

/** Emit one line of a server-originated draft/authtoken batch (or bare
 * when @a sptr has no batch). */
static void emit(struct Client *sptr, const char *fmt, ...)
{
  char line[512];
  va_list vl;

  va_start(vl, fmt);
  ircd_vsnprintf(sptr, line, sizeof(line), fmt, vl);
  va_end(vl);

  if (cli_batch_id(sptr)[0])
    sendrawto_one(sptr, "@batch=%s :%s %s", cli_batch_id(sptr), cli_name(&me), line);
  else
    sendrawto_one(sptr, ":%s %s", cli_name(&me), line);
}

void authtoken_send_servicelist(struct Client *sptr)
{
  int i;

  if (!MyConnect(sptr))
    return;
  if (authtoken_service_count() == 0) {
    send_note(sptr, "TOKEN", "NO_SERVICES", NULL, "No services are defined for this network");
    return;
  }
  send_batch_start(sptr, "draft/authtoken *");
  for (i = 0; i < AUTHTOKEN_MAX_SERVICES; ++i)
    if (services[i].used)
      emit(sptr, "TOKEN SERVICE %s %s :%s", services[i].key, services[i].url, services[i].desc);
  send_batch_end(sptr);
}

/* ------------------------------------------------------------------ */
/* Token table                                                          */
/* ------------------------------------------------------------------ */

static void expire_tokens(void)
{
  struct Authtoken **pp = &tokens, *t;
  while ((t = *pp)) {
    if (t->expires <= CurrentTime) {
      *pp = t->next;
      MyFree(t);
      --ntokens;
    } else
      pp = &t->next;
  }
}

static struct Authtoken *find_token(const char *token)
{
  struct Authtoken *t;
  if (EmptyString(token))
    return NULL;
  for (t = tokens; t; t = t->next)
    if (!strcmp(t->token, token))
      return t;
  return NULL;
}

static void unlink_token(struct Authtoken *victim)
{
  struct Authtoken **pp = &tokens, *t;
  while ((t = *pp)) {
    if (t == victim) {
      *pp = t->next;
      MyFree(t);
      --ntokens;
      return;
    }
    pp = &t->next;
  }
}

/** Keep one user under AUTHTOKEN_PER_USER and the table under
 * AUTHTOKEN_MAX: the oldest entries (tail of the list) go first. */
static void make_room(const char *yxx)
{
  struct Authtoken *t, *oldest;
  int mine = 0;

  expire_tokens();
  for (t = tokens; t; t = t->next)
    if (!strcmp(t->yxx, yxx))
      ++mine;
  while (mine >= AUTHTOKEN_PER_USER) {
    oldest = NULL;
    for (t = tokens; t; t = t->next)
      if (!strcmp(t->yxx, yxx))
        oldest = t;                            /* list is newest-first */
    if (!oldest)
      break;
    sendcmdto_serv_butone_v3(&me, CMD_TOKEN, NULL, "U %s", oldest->token);
    unlink_token(oldest);
    --mine;
  }
  while (ntokens >= feature_int(FEAT_AUTHTOKEN_MAX) && tokens) {
    for (t = tokens; t->next; t = t->next)
      ;
    unlink_token(t);
  }
}

/** Fill @a buf with CSPRNG bytes: OpenSSL's RAND_bytes, else the
 * kernel's /dev/urandom.  Never the ircd's PRNG -- a guessable token is
 * an account.  @return 1 on success. */
static int fill_random(unsigned char *buf, size_t len)
{
#ifdef USE_SSL
  if (RAND_bytes(buf, (int)len) == 1)
    return 1;
#endif
  {
    FILE *f = fopen("/dev/urandom", "rb");
    size_t got = 0;
    if (!f)
      return 0;
    got = fread(buf, 1, len, f);
    fclose(f);
    return got == len;
  }
}

static struct Authtoken *insert_token(const char *token, const char *key,
                                      const char *yxx, time_t expires,
                                      const char *scope)
{
  struct Authtoken *t = (struct Authtoken *)MyCalloc(1, sizeof(*t));
  ircd_strncpy(t->token, token, sizeof(t->token));
  ircd_strncpy(t->key, key, sizeof(t->key));
  ircd_strncpy(t->yxx, yxx, sizeof(t->yxx));
  t->expires = expires;
  if (scope && strcmp(scope, "*"))
    ircd_strncpy(t->scope, scope, sizeof(t->scope));
  t->next = tokens;
  tokens = t;
  ++ntokens;
  return t;
}

const char *authtoken_generate(struct Client *user, int svc, const char *scope)
{
  static char token[AUTHTOKEN_LEN + 1];
  static const char hex[] = "0123456789abcdef";
  unsigned char raw[AUTHTOKEN_BYTES];
  struct Authtoken *t;
  int i;

  if (svc < 0 || svc >= AUTHTOKEN_MAX_SERVICES || !services[svc].used)
    return NULL;

  if (!fill_random(raw, sizeof(raw)))
    return NULL;                                /* caller: INTERNAL_ERROR */
  for (i = 0; i < (int)sizeof(raw); ++i) {
    token[2 * i] = hex[raw[i] >> 4];
    token[2 * i + 1] = hex[raw[i] & 15];
  }
  token[AUTHTOKEN_LEN] = '\0';

  {
    char yxx[8];
    ircd_snprintf(0, yxx, sizeof(yxx), "%s%s", NumNick(user));
    make_room(yxx);
    t = insert_token(token, services[svc].key, yxx,
                     CurrentTime + feature_int(FEAT_AUTHTOKEN_EXPIRE), scope);
  }
  sendcmdto_serv_butone_v3(&me, CMD_TOKEN, NULL, "G %s %s %s %Tu %s",
                           t->token, t->key, t->yxx, t->expires,
                           t->scope[0] ? t->scope : "*");
  return token;
}

void authtoken_learn(const char *token, const char *service, const char *yxx,
                     time_t expires, const char *scope)
{
  if (EmptyString(token) || strlen(token) > AUTHTOKEN_LEN || !valid_service_key(service)
      || EmptyString(yxx) || strlen(yxx) > 5)
    return;
  if (find_token(token))
    return;
  expire_tokens();
  if (expires <= CurrentTime)
    return;
  while (ntokens >= feature_int(FEAT_AUTHTOKEN_MAX) && tokens) {
    struct Authtoken *t;
    for (t = tokens; t->next; t = t->next)
      ;
    unlink_token(t);
  }
  insert_token(token, service, yxx, expires, scope);
}

void authtoken_forget(const char *token)
{
  struct Authtoken *t = find_token(token);
  if (t)
    unlink_token(t);
}

/* ------------------------------------------------------------------ */
/* Claims                                                               */
/* ------------------------------------------------------------------ */

/** Emit a possibly long space-separated claim as chunked lines; every
 * continuation starts with the separator so the values concatenate. */
struct ClaimBuf {
  struct Client *to;
  const char *key;
  char buf[AUTHTOKEN_CLAIM_CHUNK + CHANNELLEN + 4];
  int len;
  int any;
};

static void claim_flush(struct ClaimBuf *cb)
{
  if (cb->len == 0)
    return;
  emit(cb->to, "TOKEN CLAIM %s :%s", cb->key, cb->buf);
  cb->len = 0;
  cb->buf[0] = '\0';
}

static void claim_add(struct ClaimBuf *cb, const char *word)
{
  int wl = (int)strlen(word);
  if (cb->len && cb->len + 1 + wl > AUTHTOKEN_CLAIM_CHUNK)
    claim_flush(cb);
  if (cb->any) {
    cb->buf[cb->len++] = ' ';
    cb->buf[cb->len] = '\0';
  }
  ircd_strncpy(cb->buf + cb->len, word, sizeof(cb->buf) - cb->len);
  cb->len += wl;
  cb->any = 1;
}

/** Whether channel @a chptr shows up in claims: +s channels are the
 * user's own business unless the token was scoped to them. */
static int claim_visible(struct Channel *chptr, const char *scope)
{
  if (!SecretChannel(chptr))
    return 1;
  return scope && !ircd_strcmp(chptr->chname, scope);
}

static void send_claims(struct Client *to, struct Client *user, const struct Authtoken *t)
{
  struct Membership *m;
  struct ClaimBuf cb;
  char type[AUTHTOKEN_KEYLEN + 32];

  ircd_snprintf(0, type, sizeof(type), "draft/authtoken %s", t->key);
  send_batch_start(to, type);

  if (IsAccount(user))
    emit(to, "TOKEN CLAIM account :%s", cli_user(user)->account);
  emit(to, "TOKEN CLAIM name :%s", cli_name(user));

  memset(&cb, 0, sizeof(cb));
  cb.to = to; cb.key = "member_of";
  for (m = cli_user(user)->channel; m; m = m->next_channel) {
    if (IsZombie(m) || !claim_visible(m->channel, t->scope))
      continue;
    claim_add(&cb, m->channel->chname);
  }
  claim_flush(&cb);

  memset(&cb, 0, sizeof(cb));
  cb.to = to; cb.key = "operator_of";
  for (m = cli_user(user)->channel; m; m = m->next_channel) {
    if (IsZombie(m) || !claim_visible(m->channel, t->scope))
      continue;
    if (!IsChanOp(m) && !IsHalfOp(m))
      continue;
    claim_add(&cb, m->channel->chname);
  }
  claim_flush(&cb);

  if (t->scope[0])
    emit(to, "TOKEN CLAIM scope :%s", t->scope);

  send_batch_end(to);
}

int authtoken_consume(struct Client *to, int svc, const char *token)
{
  struct Authtoken *t;
  struct Client *user;

  expire_tokens();
  if (svc < 0 || svc >= AUTHTOKEN_MAX_SERVICES || !services[svc].used)
    return -1;
  t = find_token(token);
  if (!t)
    return -1;
  if (ircd_strcmp(t->key, services[svc].key))
    return -1;                                  /* token confusion: keep it */
  user = findNUser(t->yxx);
  if (!user || !IsUser(user)) {
    sendcmdto_serv_butone_v3(&me, CMD_TOKEN, NULL, "U %s", t->token);
    unlink_token(t);
    return -1;                                  /* requester is gone */
  }
  send_claims(to, user, t);
  sendcmdto_serv_butone_v3(&me, CMD_TOKEN, NULL, "U %s", t->token);
  unlink_token(t);
  return 0;
}
