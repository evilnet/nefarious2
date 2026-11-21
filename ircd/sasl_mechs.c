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
char SaslMechanisms[SASL_MECHS_LEN] = "";

/** Non-zero while SaslMechanisms holds a list services announced
 * ("SASL * * M", sasl_mechanisms_announced()) rather than IAuth's.  A
 * change of such a list is told by what clients are actually told
 * (sasl_store_told()); IAuth's list, on a server that never receives the
 * line, keeps the notifications it always had (sasl_store_legacy()). */
static int sasl_list_announced;

/** What CAP LS says of sasl now.
 * @param[out] told Filled in.
 * @param[in] sasl_server_leaving Non-zero: as the moment before a server
 *   matching SASL_SERVER left (cap_sasl_offered()).
 */
static void sasl_told_now(struct sasl_told *told, int sasl_server_leaving)
{
  const char *value = cap_sasl_mechanisms();

  told->offered = cap_sasl_offered(sasl_server_leaving);
  ircd_strncpy(told->value, value ? value : "", sizeof(told->value));
}

/** What CAP LS says of sasl now, before something it depends on changes
 * (the local Keycloak tier's health: sasl_mark_unhealthy() /
 * sasl_mark_healthy()); sasl_tell_change() tells the difference after.
 * @param[out] before Filled in.
 */
void sasl_told_snapshot(struct sasl_told *before)
{
  sasl_told_now(before, 0);
}

/** Tell clients what changed in what CAP LS says of sasl since @a before,
 * nothing when nothing did: CAP NEW with the value CAP LS now gives when
 * sasl became offered or its value changed, CAP DEL when it stopped being
 * offered.
 * @param[in] before What CAP LS said before the change.
 */
void sasl_tell_change(const struct sasl_told *before)
{
  struct sasl_told after;

  sasl_told_now(&after, 0);
  if (!after.offered) {
    if (before->offered)
      send_cap_notify("sasl", 0, NULL);
  } else if (!before->offered || strcmp(before->value, after.value) != 0)
    send_cap_notify("sasl", 1, after.value[0] ? after.value : NULL);
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

/** Store a list and tell clients what changed in what CAP LS says of
 * sasl (sasl_tell_change()).  Never the stored list itself: the server's
 * own Keycloak mechanisms come before it (cap_sasl_mechanisms()).
 * @param[in] mechs List to store; NULL or empty clears.
 * @param[in] announced Non-zero: it is the list services announced.
 * @param[in] sasl_server_leaving Non-zero: the change is a server matching
 *   SASL_SERVER leaving (already out of the server table).
 */
static void sasl_store_told(const char *mechs, int announced,
                            int sasl_server_leaving)
{
  struct sasl_told before;

  sasl_told_now(&before, sasl_server_leaving);
  sasl_store(mechs);
  sasl_list_announced = announced && SaslMechanisms[0];
  sasl_tell_change(&before);
}

/** Store IAuth's list (or clear it) with the notifications it has always
 * had: CAP NEW with the list when one is stored where none was, CAP NEW
 * when it changed and is the advertised value, CAP DEL when it is
 * cleared. */
static void sasl_store_legacy(const char *mechs)
{
  int was_available = (SaslMechanisms[0] != '\0');
  char was[SASL_MECHS_LEN];

  ircd_strncpy(was, SaslMechanisms, sizeof(was));
  if (mechs && *mechs) {
    sasl_store(mechs);

    /* Send CAP NEW if SASL just became available */
    if (!was_available)
      send_cap_notify("sasl", 1, SaslMechanisms);
    /* ... and when its list changed, if it is the list the capability
     * advertises (the local Keycloak tier's takes priority): CAP NEW
     * "can also update the value of an existing capability". */
    else if (strcmp(was, SaslMechanisms) != 0) {
      const char *adv = cap_sasl_mechanisms();
      if (adv && strcmp(adv, SaslMechanisms) == 0)
        send_cap_notify("sasl", 1, SaslMechanisms);
    }
  } else {
    /* Send CAP DEL if SASL was available and is now removed */
    if (was_available)
      send_cap_notify("sasl", 0, NULL);

    SaslMechanisms[0] = '\0';
  }
}

/** Replace or clear the stored list, for a source other than services'
 * announcement.  A list services announced is replaced (or cleared) as a
 * change of what clients are told (sasl_store_told()); otherwise the
 * stored list is IAuth's or none, told as it always was.
 * @param[in] mechs List; NULL or empty clears.
 * @param[in] sasl_server_leaving As for sasl_store_told().
 */
static void sasl_replace(const char *mechs, int sasl_server_leaving)
{
  if (sasl_list_announced)
    sasl_store_told(mechs, 0, sasl_server_leaving);
  else
    sasl_store_legacy(mechs);
}

/** Set the SASL mechanism list: IAuth's (iauth_cmd_sasl_global_mechs()).
 * The list stored afterwards is not services' announcement.
 * @param[in] mechs Comma-separated list of mechanism names; NULL or empty
 *   clears.
 */
void set_sasl_mechanisms(const char *mechs)
{
  sasl_replace(mechs, 0);
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
      sasl_store_told(NULL, 0, 0);
      log_write(LS_SYSTEM, L_INFO, 0, "SASL mechanisms withdrawn by services");
    }
    return;
  }
  sasl_store_told(mechs, 1, 0);
  log_write(LS_SYSTEM, L_INFO, 0, "SASL mechanisms set to: %s", mechs);
}

/** A server left (free_client(): it is already out of the server table).
 * One matching SASL_SERVER clears the stored list -- under the default
 * "*" any server does, so fork servers name the services server -- and
 * IAuth's list, when IAuth handles SASL, takes its place.
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
        if (sasl_list_announced)
          /* Services' list gives way to IAuth's (or to none): one change,
           * told as what clients are told now. */
          sasl_store_told(iauth_mechs, 0, 1);
        else {
          if (had_dynamic)
            sasl_store_legacy(NULL);  /* Triggers CAP DEL */
          else
            send_cap_notify("sasl", 0, NULL);  /* CAP DEL for default-only */
          if (iauth_mechs)
            sasl_store_legacy(iauth_mechs);  /* Triggers CAP NEW :sasl=PLAIN */
          else
            send_cap_notify("sasl", 1, NULL);  /* Re-advertise without mechanism list */
        }
      } else {
        log_write(LS_SYSTEM, L_INFO, 0,
                  "Services disconnect: clearing SASL (%C)", cptr);
        if (had_dynamic)
          sasl_replace(NULL, 1);  /* CAP DEL, or what changed for services' list */
        else
          send_cap_notify("sasl", 0, NULL);  /* CAP DEL for default-only */
      }
    }
  }
}
