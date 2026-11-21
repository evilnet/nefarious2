/*
 * IRC - Internet Relay Chat, ircd/sasl_mechs.c
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
 * @brief The stored SASL mechanism list: the one services announce
 * ("<server> SASL * * M :<list>", ms_sasl()) or IAuth's
 * (iauth_cmd_sasl_global_mechs()).  cap_sasl_mechanisms() gives it to CAP
 * LS and RPL_SASLMECHS after the server's own Keycloak mechanisms.
 */
#include "config.h"

#include "capab.h"
#include "client.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_string.h"
#include "match.h"
#include "s_auth.h"

#include <string.h>

/** SASL mechanism list received from services. Empty means use default. */
static char SaslMechanisms[SASL_MECHS_LEN] = "";

/** Non-zero while SaslMechanisms holds a list services announced
 * ("SASL * * M", sasl_mechanisms_announced()) rather than IAuth's.  A
 * change of such a list is told by what CAP LS now says (sasl_tell_now());
 * IAuth's list, on a server that never receives the line, keeps the
 * notifications it always had (sasl_store_legacy()). */
static int sasl_list_announced;

/** What CAP LS says of sasl: whether it is offered, and its value
 * (cap_sasl_mechanisms(); empty for none). */
struct sasl_told {
  int offered;
  char value[512];
};

/** What cap-notify clients were last told of sasl (a CAP NEW with its
 * value, or a CAP DEL); set at the end of start-up, before any client is
 * accepted (sasl_told_set_now()). */
static struct sasl_told sasl_last_told;

/** What CAP LS says of sasl now.
 * @param[out] told Filled in.
 */
static void sasl_told_now(struct sasl_told *told)
{
  const char *value = cap_sasl_mechanisms();

  told->offered = cap_sasl_offered();
  ircd_strncpy(told->value, value ? value : "", sizeof(told->value));
}

/** Send a CAP NEW (with @a value, NULL or empty for none) or a CAP DEL of
 * sasl, and remember it as what clients were last told.
 * @param[in] available Non-zero for CAP NEW, zero for CAP DEL.
 * @param[in] value The CAP NEW's value.
 */
static void sasl_notify(int available, const char *value)
{
  send_cap_notify("sasl", available, value);
  sasl_last_told.offered = available;
  ircd_strncpy(sasl_last_told.value, available && value ? value : "",
               sizeof(sasl_last_told.value));
}

/** Tell clients the difference between @a was and @a now, nothing when
 * there is none: CAP NEW with the value of @a now when sasl became offered
 * or its value changed, CAP DEL when it stopped being offered.
 * @return 1 for a CAP NEW, -1 for a CAP DEL, 0 when nothing was sent.
 */
static int sasl_tell_difference(const struct sasl_told *was,
                                const struct sasl_told *now)
{
  if (!now->offered) {
    if (was->offered) {
      sasl_notify(0, NULL);
      return -1;
    }
  } else if (!was->offered || strcmp(was->value, now->value) != 0) {
    sasl_notify(1, now->value[0] ? now->value : NULL);
    return 1;
  }
  return 0;
}

/** Tell cap-notify clients what changed in what CAP LS says of sasl since
 * they were last told, nothing when nothing did, and remember what CAP LS
 * says now.  Called after every change it can depend on is in effect: a
 * stored list, the local Keycloak tier's health, a server leaving, any
 * server's end of burst, the end of start-up and of a rehash.  Never the
 * stored list itself: the server's own Keycloak mechanisms come before it
 * (cap_sasl_mechanisms()).  What it sends is logged, with @a event.
 * @param[in] event What happened, for the log.
 * @return 1 for a CAP NEW, -1 for a CAP DEL, 0 when nothing was sent.
 */
int sasl_tell_now(const char *event)
{
  struct sasl_told was = sasl_last_told, now;
  int sent;

  sasl_told_now(&now);
  sent = sasl_tell_difference(&was, &now);
  sasl_last_told = now;
  if (sent > 0)
    log_write(LS_SYSTEM, L_INFO, 0, "SASL: told clients CAP NEW :sasl%s%s (%s)",
              now.value[0] ? "=" : "", now.value, event);
  else if (sent < 0)
    log_write(LS_SYSTEM, L_INFO, 0, "SASL: told clients CAP DEL :sasl (%s)",
              event);
  return sent;
}

/** The end of a rehash (rehash(), after a removed IAuth program is gone):
 * tell the difference -- unless an IAuth program's policy is still to come
 * (auth_iauth_policy_pending(): a program the rehash started).  Until it
 * comes CAP LS does not say what the program will offer, and IAuth's own
 * paths tell what they always did; what clients were last told stays, and
 * the next event tells the difference. */
void sasl_tell_after_rehash(void)
{
  if (auth_iauth_policy_pending())
    return;
  sasl_tell_now("rehash");
}

/** Remember what CAP LS says of sasl as what clients were last told,
 * telling nobody: the end of start-up, before any client is accepted
 * (main()). */
void sasl_told_set_now(void)
{
  sasl_told_now(&sasl_last_told);
}

/** Copy a list into SaslMechanisms (NULL or empty clears it). */
static void sasl_store(const char *mechs)
{
  if (mechs && *mechs) {
    ircd_strncpy(SaslMechanisms, mechs, SASL_MECHS_LEN - 1);
    SaslMechanisms[SASL_MECHS_LEN - 1] = '\0';
  } else
    SaslMechanisms[0] = '\0';
}

/** Store a list and tell clients what that changes in what CAP LS says of
 * sasl (sasl_tell_now()).
 * @param[in] mechs List to store; NULL or empty clears.
 * @param[in] announced Non-zero: it is the list services announced.
 */
static void sasl_store_told(const char *mechs, int announced)
{
  sasl_store(mechs);
  sasl_list_announced = announced && SaslMechanisms[0];
  sasl_tell_now("mechanism list");
}

/** Store IAuth's list (or clear it) with the notifications it has always
 * had: CAP NEW with the list when one is stored where none was, CAP NEW
 * when it changed and is the advertised value, CAP DEL when it is
 * cleared.  What it sends is what clients were last told. */
static void sasl_store_legacy(const char *mechs)
{
  int was_available = (SaslMechanisms[0] != '\0');
  char was[SASL_MECHS_LEN];

  ircd_strncpy(was, SaslMechanisms, sizeof(was));
  if (mechs && *mechs) {
    sasl_store(mechs);

    /* Send CAP NEW if SASL just became available */
    if (!was_available)
      sasl_notify(1, SaslMechanisms);
    /* ... and when its list changed, if it is the list the capability
     * advertises (the local Keycloak tier's takes priority): CAP NEW
     * "can also update the value of an existing capability". */
    else if (strcmp(was, SaslMechanisms) != 0) {
      const char *adv = cap_sasl_mechanisms();
      if (adv && strcmp(adv, SaslMechanisms) == 0)
        sasl_notify(1, SaslMechanisms);
    }
  } else {
    /* Send CAP DEL if SASL was available and is now removed */
    if (was_available)
      sasl_notify(0, NULL);

    SaslMechanisms[0] = '\0';
  }
}

/** Set the SASL mechanism list: IAuth's (iauth_cmd_sasl_global_mechs()),
 * or none (a server matching SASL_SERVER left).  A list services
 * announced is replaced (or cleared) as a change of what clients are told
 * (sasl_store_told()); otherwise the stored list is IAuth's or none, told
 * as it always was.  The list stored afterwards is not services'
 * announcement.
 * @param[in] mechs Comma-separated list of mechanism names; NULL or empty
 *   clears.
 */
void set_sasl_mechanisms(const char *mechs)
{
  if (sasl_list_announced)
    sasl_store_told(mechs, 0);
  else
    sasl_store_legacy(mechs);
}

/** Get the SASL mechanism list for CAP LS.
 * @return Mechanism list, or NULL if none set.
 */
const char* get_sasl_mechanisms(void)
{
  return SaslMechanisms[0] ? SaslMechanisms : NULL;
}

/** Store the list services announced ("<server> SASL * * M :<list>",
 * ms_sasl()); it replaces whatever list is stored, IAuth's included.
 * Clients are told only what changes in what CAP LS says of sasl.  An
 * empty list withdraws a list services announced, and leaves IAuth's.
 * @param[in] mechs Comma-separated list of mechanism names.
 */
void sasl_mechanisms_announced(const char *mechs)
{
  if (EmptyString(mechs)) {
    if (sasl_list_announced) {
      sasl_store_told(NULL, 0);
      log_write(LS_SYSTEM, L_INFO, 0, "SASL mechanisms withdrawn by services");
    }
    return;
  }
  sasl_store_told(mechs, 1);
  log_write(LS_SYSTEM, L_INFO, 0, "SASL mechanisms set to: %s", mechs);
}

/** A server left (free_client(): it is already out of the server table).
 * One matching SASL_SERVER clears the stored list -- under the default
 * "*" any server does, so fork servers name the services server -- and
 * IAuth's list, when IAuth handles SASL, takes its place.  Then, for any
 * server, clients are told what CAP LS now says (sasl_tell_now()); while
 * IAuth handles SASL they are told what they always were instead.
 * @param[in] cptr The server.
 */
void sasl_mechanisms_server_gone(struct Client *cptr)
{
  /* If a server is disconnecting and it matches the SASL server pattern,
   * clear the services-provided SASL mechanism list.
   * However, don't send CAP DEL if IAUTH is also providing SASL -
   * clients can still authenticate via IAUTH even without services.
   */
  const char *sasl_server = feature_str(FEAT_SASL_SERVER);
  int is_services = (!strcmp(sasl_server, "*") || match(sasl_server, cli_name(cptr)) == 0);

  if (is_services) {
    /* Check if SASL was available (either dynamic or default mechanisms) */
    const char *default_mechs = feature_str(FEAT_SASL_DEFAULT_MECHANISMS);
    int had_dynamic = (get_sasl_mechanisms() != NULL);
    int had_default = (default_mechs && *default_mechs);

    if (had_dynamic || had_default) {
      if (auth_iauth_handles_sasl()) {
        /* IAUTH still provides SASL - clear the services mechanism list
         * and fall back to IAUTH's advertised mechanisms for CAP LS. */
        const char *iauth_mechs = auth_iauth_sasl_mechs();
        log_write(LS_SYSTEM, L_INFO, 0,
                  "Services disconnect: falling back to IAUTH SASL%s%s (%C)",
                  iauth_mechs ? ", mechanisms: " : "",
                  iauth_mechs ? iauth_mechs : "", cptr);
        if (sasl_list_announced) {
          /* Services' list gives way to IAuth's (or to none): one change,
           * from what CAP LS said the moment before the server left. */
          struct sasl_told before, after;

          sasl_told_now(&before);
          sasl_store(iauth_mechs);
          sasl_list_announced = 0;
          sasl_told_now(&after);
          sasl_tell_difference(&before, &after);
        } else {
          if (had_dynamic)
            sasl_store_legacy(NULL);  /* Triggers CAP DEL */
          else
            sasl_notify(0, NULL);  /* CAP DEL for default-only */
          if (iauth_mechs)
            sasl_store_legacy(iauth_mechs);  /* Triggers CAP NEW :sasl=PLAIN */
          else
            sasl_notify(1, NULL);  /* Re-advertise without mechanism list */
        }
      } else if (had_dynamic) {
        log_write(LS_SYSTEM, L_INFO, 0,
                  "Services disconnect: clearing SASL (%C)", cptr);
        set_sasl_mechanisms(NULL);  /* told below for services' list */
      }
    }
  }

  /* Any server leaving can change what CAP LS says (the services server,
   * or a hub it was behind).  IAuth's branch above told its own. */
  if (!auth_iauth_handles_sasl())
    sasl_tell_now("a server left");
}

/** A server finished its burst (ms_end_of_burst()): it, and any server
 * its net burst brought (a services server returning behind a hub sends
 * no end of burst of its own), is in the server table.  Clients are told
 * what CAP LS now says (sasl_tell_now()).  While IAuth handles SASL, they
 * are told what they always were: with a server matching SASL_SERVER, no
 * list stored and SASL_DEFAULT_MECHANISMS set, CAP NEW with the default.
 * @param[in] sptr The server.
 */
void sasl_mechanisms_server_linked(struct Client *sptr)
{
  /* Check if the linking server is the SASL server (for legacy X3 support).
   * If SASL_DEFAULT_MECHANISMS is set and no dynamic mechanisms have been
   * received yet, enable SASL with the default mechanisms.
   */
  const char *sasl_server = feature_str(FEAT_SASL_SERVER);
  int is_sasl_server = (!strcmp(sasl_server, "*") ||
                        match(sasl_server, cli_name(sptr)) == 0);
  const char *default_mechs = feature_str(FEAT_SASL_DEFAULT_MECHANISMS);
  /* In wildcard mode, SASL was already being advertised (UserStats.servers > 0
   * is always true due to local server), using these same default mechanisms.
   * In specific server mode, SASL wasn't advertised before. */
  int enables_default = (is_sasl_server && !get_sasl_mechanisms()
                         && default_mechs && *default_mechs
                         && strcmp(sasl_server, "*") != 0);

  if (auth_iauth_handles_sasl()) {
    if (enables_default) {
      log_write(LS_SYSTEM, L_INFO, 0,
                "SASL server linked (%C), enabling SASL with default mechanisms: %s",
                sptr, default_mechs);
      sasl_notify(1, default_mechs);
    }
    return;
  }

  if (sasl_tell_now("end of burst") > 0 && enables_default)
    log_write(LS_SYSTEM, L_INFO, 0,
              "SASL server linked (%C), enabling SASL with default mechanisms: %s",
              sptr, default_mechs);
}
