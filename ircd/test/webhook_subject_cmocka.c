/* cmocka suite for the pure webhook subject decision
 * (include/webhook_subject.h), over the real USER admin-event shapes the
 * bed realm produced (the json files under fixtures/webhook; nine are
 * synthetic and say so in their names: -disable, -disable-bare, -actor-named,
 * -bad-path, -root-username, -federated-identity, -credential, -subpath).  Run from ircd/test: the fixture path is relative to
 * srcdir, as the test-cmocka gate does. */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>
#include <stdio.h>
#include <cmocka.h>
#include <jansson.h>

#include "../../include/webhook_subject.h"

#ifndef WEBHOOK_FIXTURE_DIR
#define WEBHOOK_FIXTURE_DIR "fixtures/webhook"
#endif

/* The parts of the payload the decision reads, filled the way the libkc
 * parser fills them after Task 5 (root username, then the representation's
 * own username; the acting admin's authDetails never). */
struct fixture {
  json_t *root;
  json_t *rep;
  char user_id[40];
  struct kc_webhook_event ev;
};

static const char *str(json_t *o, const char *k)
{
  json_t *v = o ? json_object_get(o, k) : NULL;
  return (v && json_is_string(v)) ? json_string_value(v) : NULL;
}

static void load(struct fixture *f, const char *name)
{
  char path[512];
  const char *s;
  memset(f, 0, sizeof(*f));
  snprintf(path, sizeof(path), "%s/%s", WEBHOOK_FIXTURE_DIR, name);
  f->root = json_load_file(path, 0, NULL);
  assert_non_null(f->root);
  s = str(f->root, "resourceType");
  f->ev.resource_type = (s && 0 == strcmp(s, "USER")) ? KC_WH_RESOURCE_USER : KC_WH_RESOURCE_UNKNOWN;
  s = str(f->root, "operationType");
  f->ev.operation_type = !s ? KC_WH_OP_UNKNOWN
                       : 0 == strcmp(s, "CREATE") ? KC_WH_OP_CREATE
                       : 0 == strcmp(s, "UPDATE") ? KC_WH_OP_UPDATE
                       : 0 == strcmp(s, "DELETE") ? KC_WH_OP_DELETE
                       : 0 == strcmp(s, "ACTION") ? KC_WH_OP_ACTION : KC_WH_OP_UNKNOWN;
  f->ev.resource_path = str(f->root, "resourcePath");
  if (f->ev.resource_path && 0 == strncmp(f->ev.resource_path, "users/", 6)
      && strlen(f->ev.resource_path + 6) >= 36) {
    memcpy(f->user_id, f->ev.resource_path + 6, 36);
    f->user_id[36] = '\0';
    f->ev.user_id = f->user_id;
  }
  s = str(f->root, "representation");
  if (s) {
    f->rep = json_loads(s, 0, NULL);
    f->ev.representation = f->rep;
  }
  f->ev.username = str(f->root, "username");
  if (!f->ev.username && f->rep)
    f->ev.username = str(f->rep, "username");
}

static void unload(struct fixture *f)
{
  if (f->rep) json_decref(f->rep);
  if (f->root) json_decref(f->root);
}

static void test_delete_resolves_by_id(void **state)
{
  struct fixture f; struct WebhookSubject s;
  (void)state;
  load(&f, "user-delete.json");
  assert_int_equal(webhook_subject_resolve(&f.ev, &s), 1);
  assert_int_equal(s.kind, WH_SUBJECT_DELETE);
  assert_int_equal((int)strlen(s.kc_id), ACCOUNT_ID_LEN);
  assert_null(s.username);                         /* nothing in the payload names the subject */
  unload(&f);
}

static void test_reset_password_is_a_cache_purge(void **state)
{
  struct fixture f; struct WebhookSubject s;
  (void)state;
  load(&f, "user-action-reset-password.json");
  assert_int_equal(webhook_subject_resolve(&f.ev, &s), 1);
  assert_int_equal(s.kind, WH_SUBJECT_PASSWORD_RESET);
  assert_int_equal((int)strlen(s.kc_id), ACCOUNT_ID_LEN);
  unload(&f);
}

static void test_disable_needs_enabled_false(void **state)
{
  struct fixture f; struct WebhookSubject s;
  (void)state;
  /* A console save sends the full representation (name included). */
  load(&f, "user-update-disable.json");
  assert_int_equal(webhook_subject_resolve(&f.ev, &s), 1);
  assert_int_equal(s.kind, WH_SUBJECT_DISABLE);
  assert_int_equal((int)strlen(s.kc_id), ACCOUNT_ID_LEN);
  assert_non_null(s.username);                     /* a full representation names the subject */
  unload(&f);

  /* A bare toggle sends {"enabled":false} and nothing else: the id alone
   * names the subject. */
  load(&f, "user-update-disable-bare.json");
  assert_int_equal(webhook_subject_resolve(&f.ev, &s), 1);
  assert_int_equal(s.kind, WH_SUBJECT_DISABLE);
  assert_int_equal((int)strlen(s.kc_id), ACCOUNT_ID_LEN);
  assert_null(s.username);
  unload(&f);

  /* Review focus 2: a partial put that did not touch enabled is nothing. */
  load(&f, "user-update-partial.json");
  assert_int_equal(webhook_subject_resolve(&f.ev, &s), 0);
  assert_int_equal(s.kind, WH_SUBJECT_NONE);
  unload(&f);
}

static void test_create_is_nothing(void **state)
{
  struct fixture f; struct WebhookSubject s;
  (void)state;
  load(&f, "user-create.json");
  assert_int_equal(webhook_subject_resolve(&f.ev, &s), 0);
  unload(&f);
}

static void test_actor_and_bad_path_are_nothing(void **state)
{
  struct fixture f; struct WebhookSubject s;
  (void)state;
  /* Review focus 3 and 4: no uuid, and the named admin is not the subject. */
  load(&f, "user-delete-actor-named.json");
  assert_int_equal(webhook_subject_resolve(&f.ev, &s), 0);
  assert_string_equal(s.kc_id, "");
  assert_null(s.username);
  unload(&f);
  load(&f, "user-delete-bad-path.json");
  assert_int_equal(webhook_subject_resolve(&f.ev, &s), 0);
  unload(&f);
}

static void test_root_username_still_resolves(void **state)
{
  struct fixture f; struct WebhookSubject s;
  (void)state;
  /* Review focus 5: a synthetic event names the subject at the root and
   * carries no path -- resolved by name, no id. */
  load(&f, "user-delete-root-username.json");
  assert_int_equal(webhook_subject_resolve(&f.ev, &s), 1);
  assert_int_equal(s.kind, WH_SUBJECT_DELETE);
  assert_string_equal(s.kc_id, "");
  assert_string_equal(s.username, "testaccXu");
  unload(&f);
}

static void test_non_user_resources_and_null(void **state)
{
  struct fixture f; struct WebhookSubject s;
  (void)state;
  load(&f, "user-delete.json");
  f.ev.resource_type = KC_WH_RESOURCE_GROUP;
  assert_int_equal(webhook_subject_resolve(&f.ev, &s), 0);
  unload(&f);
  assert_int_equal(webhook_subject_resolve(NULL, &s), 0);
  assert_int_equal(s.kind, WH_SUBJECT_NONE);
  assert_string_equal(webhook_subject_kind_name(WH_SUBJECT_DISABLE), "disable");
}

static void test_subresource_delete_or_update_is_not_the_user(void **state)
{
  struct fixture f; struct WebhookSubject s;
  (void)state;
  /* Review focus 3, the case the first pass missed: Keycloak records the
   * removal of a user's federated identity link as USER/DELETE on
   * users/<uuid>/federated-identity/<provider>.  Only the bare path is the
   * user's own deletion. */
  load(&f, "user-delete-federated-identity.json");
  assert_int_equal(webhook_subject_resolve(&f.ev, &s), 0);
  assert_int_equal(s.kind, WH_SUBJECT_NONE);
  unload(&f);
  load(&f, "user-update-subpath.json");
  assert_int_equal(webhook_subject_resolve(&f.ev, &s), 0);
  assert_int_equal(s.kind, WH_SUBJECT_NONE);
  unload(&f);
}

static void test_credential_removal_purges(void **state)
{
  struct fixture f; struct WebhookSubject s;
  (void)state;
  /* An admin removing the password credential leaves nothing behind it in
   * Keycloak, but the positive cache still answers the old password; the
   * path users/<uuid>/credentials/<id> is a purge whichever operation
   * Keycloak recorded. */
  load(&f, "user-delete-credential.json");
  assert_int_equal(webhook_subject_resolve(&f.ev, &s), 1);
  assert_int_equal(s.kind, WH_SUBJECT_CREDENTIAL_REMOVED);
  assert_int_equal((int)strlen(s.kc_id), ACCOUNT_ID_LEN);
  unload(&f);
  load(&f, "user-action-credential.json");
  assert_int_equal(webhook_subject_resolve(&f.ev, &s), 1);
  assert_int_equal(s.kind, WH_SUBJECT_CREDENTIAL_REMOVED);
  unload(&f);
}

static void test_bad_username_is_dropped(void **state)
{
  struct fixture f; struct WebhookSubject s;
  (void)state;
  /* Review focus 4: a payload's name reaches the P10 wire (CI, AC U) and the
   * cache lookups; anything that cannot travel as one token is not a name. */
  load(&f, "user-delete-root-username.json");
  f.ev.username = "has space";
  assert_int_equal(webhook_subject_resolve(&f.ev, &s), 0);     /* no id, no usable name */
  f.ev.username = "colon:inside";
  assert_int_equal(webhook_subject_resolve(&f.ev, &s), 0);
  f.ev.username = "ctrl\x01char";
  assert_int_equal(webhook_subject_resolve(&f.ev, &s), 0);
  f.ev.username = "this-name-is-far-longer-than-any-account-name-the-ircd-will-ever-carry";
  assert_int_equal(webhook_subject_resolve(&f.ev, &s), 0);
  f.ev.username = "fine_name-1";
  assert_int_equal(webhook_subject_resolve(&f.ev, &s), 1);
  assert_string_equal(s.username, "fine_name-1");
  unload(&f);
}

/* Webhook plan 4: the kind letter a relay carries maps to and from the
 * subject kind; the two log-only kinds are not relayed. */
static void test_relay_kind_round_trip(void **s)
{
  (void)s;
  assert_int_equal(webhook_relay_kind_for(WH_SUBJECT_DELETE), 'D');
  assert_int_equal(webhook_relay_kind_for(WH_SUBJECT_DISABLE), 'X');
  assert_int_equal(webhook_relay_kind_for(WH_SUBJECT_ENABLE), 'E');
  assert_int_equal(webhook_relay_kind_for(WH_SUBJECT_PASSWORD_RESET), 'R');
  assert_int_equal(webhook_relay_kind_for(WH_SUBJECT_CREDENTIAL_REMOVED), 'C');
  assert_int_equal(webhook_relay_kind_for(WH_SUBJECT_LOGOUT), 0);
  assert_int_equal(webhook_relay_kind_for(WH_SUBJECT_NONE), 0);
  assert_int_equal(webhook_subject_kind_for_relay('D'), WH_SUBJECT_DELETE);
  assert_int_equal(webhook_subject_kind_for_relay('X'), WH_SUBJECT_DISABLE);
  assert_int_equal(webhook_subject_kind_for_relay('E'), WH_SUBJECT_ENABLE);
  assert_int_equal(webhook_subject_kind_for_relay('R'), WH_SUBJECT_PASSWORD_RESET);
  assert_int_equal(webhook_subject_kind_for_relay('C'), WH_SUBJECT_CREDENTIAL_REMOVED);
  assert_int_equal(webhook_subject_kind_for_relay('P'), WH_SUBJECT_NONE);   /* purge only: no subject action */
  assert_int_equal(webhook_subject_kind_for_relay('Z'), WH_SUBJECT_NONE);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_delete_resolves_by_id),
    cmocka_unit_test(test_reset_password_is_a_cache_purge),
    cmocka_unit_test(test_disable_needs_enabled_false),
    cmocka_unit_test(test_create_is_nothing),
    cmocka_unit_test(test_actor_and_bad_path_are_nothing),
    cmocka_unit_test(test_root_username_still_resolves),
    cmocka_unit_test(test_non_user_resources_and_null),
    cmocka_unit_test(test_subresource_delete_or_update_is_not_the_user),
    cmocka_unit_test(test_credential_removal_purges),
    cmocka_unit_test(test_bad_username_is_dropped),
    cmocka_unit_test(test_relay_kind_round_trip),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
