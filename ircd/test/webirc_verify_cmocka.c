/*
 * webirc_verify_cmocka.c - WEBIRC's asynchronous password check
 *
 * m_webirc() hands a WebIRC block's password check to the thread pool,
 * holds the client's registration (auth_webirc_hold()) and keeps only the
 * password (hash) checked against, the requested address and host, and a
 * refind cookie; webirc_password_verified() runs a loop pass or more later,
 * judges the result by the configuration in force then, applies the real
 * address BEFORE it ends the hold (auth_webirc_release_later()), or exits
 * the client.  A block that matches the gateway is checked here even when
 * IAuth asks for WEBIRC lines (policy w): IAuth is told the trusted w once
 * it is applied, and is handed the untrusted W only where no block matches
 * or the password is wrong (as stock ircu/Nefarious master does).
 *
 * This includes the real m_webirc.c, compiled with -ffunction-sections and
 * linked with --gc-sections; the conf lookups, the auth request calls, the
 * thread pool, IPcheck and the exits are stubs that record.
 */
#include "config.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

#include "../m_webirc.c"

/* ------------------------------------------------------------------ */
/* The ircd around WEBIRC                                              */
/* ------------------------------------------------------------------ */

struct Client *LocalClientArray[MAXCONNECTIONS];
struct Client me;
int log_inassert;

void debug(int level, const char *form, ...) {}
void log_write(enum LogSys subsys, enum LogLevel severity, unsigned int flags,
               const char *fmt, ...) {}
int feature_bool(enum Feature feat) { return 0; }
int feature_int(enum Feature feat) { return 0; }
unsigned int ircrandom(void) { static unsigned int r = 40; return r += 2; }
void geoip_apply(struct Client *cptr) {}
int find_except_conf(struct Client *cptr, int flags) { return 0; }
void IPcheck_connect_fail(const struct Client *cptr, int disconnect) {}
int IPcheck_remote_connect(struct Client *cptr, int is_burst) { return 1; }
int need_more_params(struct Client *cptr, const char *cmd)
{ fail_msg("need_more_params: %s", cmd); return 0; }

static char last_sno[512];
void sendto_opmask_butone_global(struct Client *one, unsigned int mask,
                                 const char *pattern, ...)
{
  va_list vl;

  va_start(vl, pattern);
  vsnprintf(last_sno, sizeof(last_sno), pattern, vl);
  va_end(vl);
}

/** The exit, if any: its reason. */
static const char *exit_reason;
int exit_client(struct Client *cptr, struct Client *victim,
                struct Client *killer, const char *comment)
{
  exit_reason = comment;
  return CPTR_KILLED;
}

/* The auth request (registration): what was asked of it, and the client's
 * address when its hold ended. */
static int holds, releases, dnsbl_restarts, iauth_told, sync_checks;
static char ip_at_release[SOCKIPLEN + 1];
/* IAuth's policy has w (it is sent WEBIRC lines); the untrusted W it was
 * handed, if any. */
static int iauth_w, untrusted_told;
static char untrusted_line[256];
int auth_set_webirc(struct AuthRequest *auth, const char *password,
                    const char *username, const char *hostname,
                    const char *ip, const char *opts)
{
  if (!iauth_w)
    return -1;
  untrusted_told++;
  snprintf(untrusted_line, sizeof(untrusted_line), "W %s %s %s %s%s%s",
           password, username, hostname, ip, opts ? " :" : "",
           opts ? opts : "");
  return 0;
}
int auth_set_webirc_trusted(struct AuthRequest *auth, const char *password,
                            const char *username, const char *hostname,
                            const char *ip, const char *opts)
{ iauth_told++; return 0; }
void auth_set_originalip(struct AuthRequest *auth, const struct irc_in_addr addr) {}
void auth_webirc_hold(struct AuthRequest *auth) { holds++; }
void auth_webirc_release_later(struct AuthRequest *auth);
void auth_dnsbl_restart(struct AuthRequest *auth) { dnsbl_restarts++; }

/* The thread pool: a submitted check finishes when the case says so. */
static int submitted, async_available;
static crypt_verify_callback pending_cb;
static void *pending_ctx;
int ircd_crypt_async_available(void) { return async_available; }
int ircd_crypt_verify_async(const char *password, const char *hash,
                            crypt_verify_callback callback, void *ctx)
{
  submitted++;
  pending_cb = callback;
  pending_ctx = ctx;
  return 0;
}
static void finish_check(int result)
{
  crypt_verify_callback cb = pending_cb;

  assert_non_null(cb);
  pending_cb = NULL;
  cb(result, pending_ctx);
}

/* The WebIRC blocks in force (a rehash replaces them): one, or none. */
static struct WebIRCConf block;
static int have_block;
struct WebIRCConf *find_webirc_conf_by_host(struct Client *cptr)
{ return have_block ? &block : NULL; }
struct WebIRCConf *find_webirc_conf(struct Client *cptr, char *passwd, int *status)
{
  sync_checks++;
  if (!have_block) {
    *status = 2;
    return NULL;
  }
  if (block.passwd && strcmp(passwd, "pw")) {    /* "$X$pw" is "pw"'s */
    *status = 1;
    return NULL;
  }
  *status = 0;
  return &block;
}

/* ------------------------------------------------------------------ */
/* An unregistered local client behind a gateway                       */
/* ------------------------------------------------------------------ */

static struct Client client, other;
static struct Connection con, other_con;
static struct User user, other_user;
/** Any non-NULL request: the stubs above never look inside. */
static struct AuthRequest *const the_auth = (struct AuthRequest *) &con;

/* m_authenticate.c: the AUTHENTICATE lines held for the check, replayed
 * (an exchange starts) -- after the real address, before registration. */
static int replays, replay_kills;
static char ip_at_replay[SOCKIPLEN + 1];
int authenticate_replay(struct Client *cptr)
{
  assert_int_equal(releases, 0);
  replays++;
  ircd_strncpy(ip_at_replay, cli_sock_ip(cptr), sizeof(ip_at_replay));
  return replay_kills ? CPTR_KILLED : 0;
}

void auth_webirc_release_later(struct AuthRequest *auth)
{
  assert_ptr_equal(auth, the_auth);
  releases++;
  ircd_strncpy(ip_at_release, cli_sock_ip(&client), sizeof(ip_at_release));
}

static void make_client(struct Client *c, struct Connection *cn, struct User *u,
                        int fd)
{
  memset(c, 0, sizeof(*c));
  memset(cn, 0, sizeof(*cn));
  memset(u, 0, sizeof(*u));
  cli_connect(c) = cn;
  cli_from(c) = c;
  con_client(cn) = c;
  s_fd(&con_socket(cn)) = fd;
  cli_user(c) = u;
  cli_status(c) = STAT_UNKNOWN_USER;
  ipmask_parse("127.0.0.1", &cli_ip(c), NULL);
  ircd_strncpy(cli_sock_ip(c), "127.0.0.1", SOCKIPLEN + 1);
  ircd_strncpy(cli_sockhost(c), "gateway.test", HOSTLEN + 1);
  ircd_strncpy(cli_username(c), "u", USERLEN + 1);
  LocalClientArray[fd] = c;
}

static int setup(void **state)
{
  (void)state;
  memset(LocalClientArray, 0, sizeof(LocalClientArray));
  make_client(&client, &con, &user, 9);
  cli_auth(&client) = the_auth;
  memset(&block, 0, sizeof(block));
  block.passwd = "$X$pw";
  block.ident = "gwident";
  block.description = "gw";
  have_block = 1;
  holds = releases = dnsbl_restarts = iauth_told = sync_checks = submitted = 0;
  ip_at_release[0] = '\0';
  ip_at_replay[0] = '\0';
  replays = replay_kills = 0;
  iauth_w = untrusted_told = 0;
  untrusted_line[0] = '\0';
  async_available = 1;
  last_sno[0] = '\0';
  exit_reason = NULL;
  pending_cb = NULL;
  return 0;
}

static int webirc(char *pass)
{
  char *parv[] = { "*", pass, "gateway", "spoofed.example", "192.0.2.77", NULL };
  return m_webirc(&client, &client, 5, parv);
}

/* ------------------------------------------------------------------ */
/* Cases                                                               */
/* ------------------------------------------------------------------ */

/** The check holds registration; when it finishes with the block
 * unchanged, the real address, host and the block's ident are in place
 * BEFORE the hold ends, and the DNSBL is asked about the real address. */
static void match_applies_before_releasing(void **state)
{
  webirc("pw");
  assert_int_equal(submitted, 1);
  assert_int_equal(holds, 1);
  assert_true(IsWebIRCPending(&client));
  assert_string_equal(cli_sock_ip(&client), "127.0.0.1");   /* not yet */

  finish_check(CRYPT_VERIFY_MATCH);
  assert_null(exit_reason);
  assert_int_equal(releases, 1);
  assert_string_equal(ip_at_release, "192.0.2.77");
  assert_string_equal(cli_sockhost(&client), "spoofed.example");
  assert_string_equal(cli_username(&client), "gwident");
  assert_true(IsWebIRC(&client));
  assert_int_equal(dnsbl_restarts, 1);
  assert_false(IsWebIRCPending(&client));
  assert_int_equal(cli_checkcookie(&client), 0);
}

/** The rehash removed the block: the client is refused, never released,
 * and the notice names what was found when the check finished. */
static void removed_block_refused(void **state)
{
  webirc("pw");
  have_block = 0;
  finish_check(CRYPT_VERIFY_MATCH);
  assert_string_equal(exit_reason, "WEBIRC Not authorized from your host");
  assert_int_equal(releases, 0);
  assert_string_equal(cli_sock_ip(&client), "127.0.0.1");
  assert_non_null(strstr(last_sno, "no WebIRC block when the password check finished"));
}

/** The rehash changed the block's password: refused. */
static void changed_password_refused(void **state)
{
  webirc("pw");
  block.passwd = "$X$new";
  finish_check(CRYPT_VERIFY_MATCH);
  assert_string_equal(exit_reason, "WEBIRC Password invalid for your host");
  assert_int_equal(releases, 0);
}

/** A wrong password (or the pool going away: CRYPT_VERIFY_ERROR): refused,
 * never registered. */
static void wrong_password_refused(void **state)
{
  webirc("wrong");
  finish_check(CRYPT_VERIFY_NOMATCH);
  assert_string_equal(exit_reason, "WEBIRC Password invalid for your host");
  assert_int_equal(releases, 0);

  setup(state);
  webirc("pw");
  finish_check(CRYPT_VERIFY_ERROR);
  assert_non_null(exit_reason);
  assert_int_equal(releases, 0);
}

/** The descriptor is another connection's now: the result goes to
 * nobody. */
static void another_connection_gets_nothing(void **state)
{
  webirc("pw");
  make_client(&other, &other_con, &other_user, 9);
  finish_check(CRYPT_VERIFY_MATCH);
  assert_null(exit_reason);
  assert_int_equal(releases, 0);
  assert_false(IsWebIRC(&other));
}

/** A second WEBIRC while the first is pending is ignored: one check. */
static void second_webirc_ignored(void **state)
{
  webirc("pw");
  webirc("pw");
  assert_int_equal(submitted, 1);
  assert_int_equal(holds, 1);
}

/** Without an auth request (registration can no longer wait), the check
 * is not made asynchronously: the synchronous path answers at once. */
static void no_auth_request_checks_synchronously(void **state)
{
  cli_auth(&client) = NULL;
  webirc("pw");
  assert_int_equal(submitted, 0);
  assert_int_equal(holds, 0);
  assert_int_equal(sync_checks, 1);
  assert_string_equal(cli_sock_ip(&client), "192.0.2.77");
}

/** AUTHENTICATE lines held for the check start their exchange when it
 * finishes: on the real address, before registration goes on.  A replay
 * that exits the client ends the completion there (no release). */
static void held_authenticate_replayed_on_the_real_address(void **state)
{
  webirc("pw");
  finish_check(CRYPT_VERIFY_MATCH);
  assert_int_equal(replays, 1);
  assert_string_equal(ip_at_replay, "192.0.2.77");
  assert_int_equal(releases, 1);

  setup(state);
  replay_kills = 1;
  webirc("pw");
  finish_check(CRYPT_VERIFY_MATCH);
  assert_int_equal(replays, 1);
  assert_int_equal(releases, 0);

  setup(state);                            /* a refused check: no replay */
  webirc("wrong");
  finish_check(CRYPT_VERIFY_NOMATCH);
  assert_int_equal(replays, 0);
}

/** IAuth asks for WEBIRC lines (w), and a block matches the gateway: the
 * password is checked here (IAuth is not handed an untrusted W, which the
 * shipped scripts ignore), and once the real address is applied IAuth is
 * told the trusted w. */
static void iauth_w_matching_block_checked_here(void **state)
{
  iauth_w = 1;
  webirc("pw");
  assert_int_equal(untrusted_told, 0);
  assert_int_equal(submitted, 1);
  assert_int_equal(holds, 1);
  assert_true(IsWebIRCPending(&client));

  finish_check(CRYPT_VERIFY_MATCH);
  assert_null(exit_reason);
  assert_int_equal(untrusted_told, 0);
  assert_int_equal(iauth_told, 1);
  assert_int_equal(releases, 1);
  assert_string_equal(ip_at_release, "192.0.2.77");
  assert_true(IsWebIRC(&client));
}

/** The same with a block that has no password: applied at once. */
static void iauth_w_passwordless_block_applied_at_once(void **state)
{
  iauth_w = 1;
  block.passwd = NULL;
  webirc("anything");
  assert_int_equal(untrusted_told, 0);
  assert_int_equal(submitted, 0);
  assert_int_equal(holds, 0);
  assert_null(exit_reason);
  assert_string_equal(cli_sock_ip(&client), "192.0.2.77");
  assert_true(IsWebIRC(&client));
  assert_int_equal(iauth_told, 1);
}

/** The same without the thread pool (the check made at once): a right
 * password is applied, IAuth told w; a wrong one is handed to IAuth as
 * the untrusted W, the client kept on the gateway's address. */
static void iauth_w_synchronous_check(void **state)
{
  iauth_w = 1;
  async_available = 0;
  webirc("pw");
  assert_int_equal(submitted, 0);
  assert_int_equal(sync_checks, 1);
  assert_int_equal(untrusted_told, 0);
  assert_null(exit_reason);
  assert_string_equal(cli_sock_ip(&client), "192.0.2.77");
  assert_int_equal(iauth_told, 1);

  setup(state);
  iauth_w = 1;
  async_available = 0;
  webirc("wrong");
  assert_null(exit_reason);
  assert_int_equal(untrusted_told, 1);
  assert_string_equal(untrusted_line, "W wrong gateway spoofed.example 192.0.2.77");
  assert_string_equal(cli_sock_ip(&client), "127.0.0.1");
  assert_false(IsWebIRC(&client));
  assert_int_equal(iauth_told, 0);
}

/** A wrong password while IAuth asks for WEBIRC lines: IAuth is handed
 * the untrusted W when the check finishes (it may know the gateway), not
 * refused; the hold ends with the gateway's address, and AUTHENTICATE
 * lines held meanwhile go on.  Without w the client is refused
 * (wrong_password_refused). */
static void iauth_w_wrong_password_handed_to_iauth(void **state)
{
  char *parv[] = { "*", "wrong", "gateway", "spoofed.example", "192.0.2.77",
                   "secure", NULL };

  iauth_w = 1;
  m_webirc(&client, &client, 6, parv);
  assert_int_equal(submitted, 1);
  assert_int_equal(untrusted_told, 0);          /* not while it is checked */

  finish_check(CRYPT_VERIFY_NOMATCH);
  assert_null(exit_reason);
  assert_int_equal(untrusted_told, 1);
  assert_string_equal(untrusted_line,
                      "W wrong gateway spoofed.example 192.0.2.77 :secure");
  assert_int_equal(iauth_told, 0);
  assert_int_equal(replays, 1);
  assert_string_equal(ip_at_replay, "127.0.0.1");
  assert_int_equal(releases, 1);
  assert_string_equal(ip_at_release, "127.0.0.1");
  assert_false(IsWebIRC(&client));
  assert_false(IsWebIRCPending(&client));
  assert_int_equal(cli_checkcookie(&client), 0);
  assert_int_equal(dnsbl_restarts, 0);

  setup(state);                    /* a replay that exits: no release */
  iauth_w = 1;
  replay_kills = 1;
  webirc("wrong");
  finish_check(CRYPT_VERIFY_NOMATCH);
  assert_int_equal(untrusted_told, 1);
  assert_int_equal(replays, 1);
  assert_int_equal(releases, 0);
}

/** A rehash during the check removed the block, or changed its password:
 * judged as a WEBIRC arriving now would be -- handed to IAuth when it asks
 * for WEBIRC lines. */
static void iauth_w_rehash_refusal_handed_to_iauth(void **state)
{
  iauth_w = 1;
  webirc("pw");
  have_block = 0;
  finish_check(CRYPT_VERIFY_MATCH);
  assert_null(exit_reason);
  assert_int_equal(untrusted_told, 1);
  assert_int_equal(releases, 1);
  assert_false(IsWebIRC(&client));

  setup(state);
  iauth_w = 1;
  webirc("pw");
  block.passwd = "$X$new";
  finish_check(CRYPT_VERIFY_MATCH);
  assert_null(exit_reason);
  assert_int_equal(untrusted_told, 1);
  assert_int_equal(releases, 1);
  assert_false(IsWebIRC(&client));
}

/** No block matches the gateway: IAuth is handed the untrusted W at once
 * when it asks for WEBIRC lines; else the client is refused. */
static void no_block_handed_to_iauth_or_refused(void **state)
{
  have_block = 0;
  iauth_w = 1;
  webirc("pw");
  assert_null(exit_reason);
  assert_int_equal(untrusted_told, 1);
  assert_int_equal(submitted, 0);
  assert_int_equal(holds, 0);
  assert_string_equal(cli_sock_ip(&client), "127.0.0.1");

  setup(state);
  have_block = 0;
  webirc("pw");
  assert_string_equal(exit_reason, "WEBIRC Not authorized from your host");
  assert_int_equal(untrusted_told, 0);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test_setup(match_applies_before_releasing, setup),
    cmocka_unit_test_setup(removed_block_refused, setup),
    cmocka_unit_test_setup(changed_password_refused, setup),
    cmocka_unit_test_setup(wrong_password_refused, setup),
    cmocka_unit_test_setup(another_connection_gets_nothing, setup),
    cmocka_unit_test_setup(second_webirc_ignored, setup),
    cmocka_unit_test_setup(no_auth_request_checks_synchronously, setup),
    cmocka_unit_test_setup(held_authenticate_replayed_on_the_real_address, setup),
    cmocka_unit_test_setup(iauth_w_matching_block_checked_here, setup),
    cmocka_unit_test_setup(iauth_w_passwordless_block_applied_at_once, setup),
    cmocka_unit_test_setup(iauth_w_synchronous_check, setup),
    cmocka_unit_test_setup(iauth_w_wrong_password_handed_to_iauth, setup),
    cmocka_unit_test_setup(iauth_w_rehash_refusal_handed_to_iauth, setup),
    cmocka_unit_test_setup(no_block_handed_to_iauth_or_refused, setup),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
