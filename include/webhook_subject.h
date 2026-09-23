/*
 * IRC - Internet Relay Chat, include/webhook_subject.h
 *
 * What a Keycloak USER admin event asks of the ircd, decided from the
 * event alone.  Keycloak names the subject of delete, disable and
 * password-reset events only by uuid (resourcePath "users/<uuid>"); the
 * compact form of that uuid is the Keycloak id every logged-in client and
 * positive-cache entry carries (step 5), so the ircd resolves the subject
 * itself.  Pure: no ircd headers, unit tested against real payloads.
 */
#ifndef INCLUDED_webhook_subject_h
#define INCLUDED_webhook_subject_h

#include "account_id.h"
#include "kc/kc_webhook.h"

enum WebhookSubjectKind {
  WH_SUBJECT_NONE = 0,        /**< nothing for the ircd to do */
  WH_SUBJECT_DELETE,          /**< USER/DELETE */
  WH_SUBJECT_DISABLE,         /**< USER/UPDATE whose representation carries enabled:false */
  WH_SUBJECT_ENABLE,          /**< USER/UPDATE carrying enabled:true (log only) */
  WH_SUBJECT_PASSWORD_RESET,  /**< USER/ACTION users/<uuid>/reset-password */
  WH_SUBJECT_CREDENTIAL_REMOVED, /**< users/<uuid>/credentials/<id>, DELETE or ACTION: a credential is gone */
  WH_SUBJECT_LOGOUT           /**< USER/ACTION users/<uuid>/logout (log only) */
};

struct WebhookSubject {
  enum WebhookSubjectKind kind;
  /** Compact Keycloak id of resourcePath's uuid; "" when the event has none or it is malformed. */
  char kc_id[ACCOUNT_ID_LEN + 1];
  /** The subject's own name when the payload carries one (root-level, or a
   * full representation); NULL otherwise.  Never the acting admin. */
  const char *username;
};

/** Decide what ev asks for.  out is always filled (kind NONE when there is
 * nothing to do, including a subject nobody can name).  Only the bare path
 * "users/<uuid>" (or no path at all, a synthetic name-carrying event) is
 * the user; a DELETE or UPDATE on a sub-resource of the user (a federated
 * identity link, a consent, a group) is nothing to do, and a credential
 * removal is a cache purge.
 * @return 1 when out->kind != WH_SUBJECT_NONE. */
extern int webhook_subject_resolve(const struct kc_webhook_event *ev,
                                   struct WebhookSubject *out);

/** A short lower-case name for logs ("delete", "disable", ...). */
extern const char *webhook_subject_kind_name(enum WebhookSubjectKind kind);

#endif /* INCLUDED_webhook_subject_h */
