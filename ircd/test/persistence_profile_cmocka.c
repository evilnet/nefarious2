/*
 * persistence_profile_cmocka.c - profile delete, rename and listing reach
 * every stored profile key, however long
 *
 * A profile's settings are stored as account metadata under
 * draft/persistence/profile/<name>/<setting>.  With a name of up to
 * PERSISTENCE_PROFILE_NAME_MAX characters that key is often 64 bytes or
 * more, which metadata_account_list() cannot hold and skips: DELETE and
 * RENAME left such rows behind, and LIST did not show such a profile.
 *
 * This includes the real persistence_profile.c over an in-memory account
 * store.  metadata_account_list() is stubbed the way the real one behaves
 * (keys of METADATA_KEY_LEN bytes or more are skipped) so the cases hold
 * whichever walk the code uses.
 */
#include "config.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

#include "../persistence_profile.c"

/* ------------------------------------------------------------------ */
/* The ircd around it                                                  */
/* ------------------------------------------------------------------ */

struct Client me;
time_t CurrentTime;
int log_inassert;

void debug(int level, const char *form, ...) { (void)level; (void)form; }
void log_write(enum LogSys subsys, enum LogLevel severity, unsigned int flags,
               const char *fmt, ...)
{
  (void)subsys; (void)severity; (void)flags; (void)fmt;
}

/* ------------------------------------------------------------------ */
/* One account's metadata, in key order like the store                 */
/* ------------------------------------------------------------------ */

#define NROWS 64
struct row { char key[200]; char value[128]; int used; };
static struct row rows[NROWS];

static int row_find(const char *key)
{
  int i;
  for (i = 0; i < NROWS; i++)
    if (rows[i].used && !strcmp(rows[i].key, key))
      return i;
  return -1;
}

static int row_cmp(const void *a, const void *b)
{
  const struct row *ra = a, *rb = b;
  if (ra->used != rb->used)
    return rb->used - ra->used;   /* used rows first */
  return strcmp(ra->key, rb->key);
}

int metadata_account_write(struct Client *src, const char *account,
                           const char *key, const char *value, int vis)
{
  int i = row_find(key);
  (void)src; (void)account; (void)vis;
  if (!value) {
    if (i >= 0)
      rows[i].used = 0;
  } else {
    if (i < 0)
      for (i = 0; i < NROWS && rows[i].used; i++)
        ;
    assert_true(i < NROWS);
    snprintf(rows[i].key, sizeof(rows[i].key), "%s", key);
    snprintf(rows[i].value, sizeof(rows[i].value), "%s", value);
    rows[i].used = 1;
  }
  qsort(rows, NROWS, sizeof(rows[0]), row_cmp);
  return 0;
}

int metadata_account_get(const char *account, const char *key, char *value)
{
  int i = row_find(key);
  (void)account;
  if (i < 0)
    return 1;
  strcpy(value, rows[i].value);
  return 0;
}

int metadata_account_foreach_version(const char *account,
                     int (*cb)(const char *key, const struct md_version *v, void *arg),
                     void *arg)
{
  int i, n = 0;
  (void)account;
  for (i = 0; i < NROWS; i++) {
    struct md_version v;
    if (!rows[i].used)
      continue;
    memset(&v, 0, sizeof(v));
    v.value = rows[i].value;
    v.vlen = strlen(rows[i].value);
    cb(rows[i].key, &v, arg);
    n++;
  }
  return n;
}

struct MetadataEntry *metadata_account_list(const char *account)
{
  struct MetadataEntry *head = NULL, **tail = &head;
  int i;
  (void)account;
  for (i = 0; i < NROWS; i++) {
    struct MetadataEntry *e;
    if (!rows[i].used || strlen(rows[i].key) >= METADATA_KEY_LEN)
      continue;                   /* as the real one: no room for it */
    e = calloc(1, sizeof(*e));
    strcpy(e->key, rows[i].key);
    e->value = strdup(rows[i].value);
    *tail = e;
    tail = &e->next;
  }
  return head;
}

void metadata_free_entry(struct MetadataEntry *e)
{
  free(e->value);
  free(e);
}

/* ------------------------------------------------------------------ */
/* Cases                                                               */
/* ------------------------------------------------------------------ */

#define ACCT "acct"
/* 32 characters: draft/persistence/profile/<name>/channels is 67 bytes */
#define LONG_NAME "abcdefghijklmnopqrstuvwxyz012345"
#define LONG_NAME2 "ABCDEFGHIJKLMNOPQRSTUVWXYZ-_6789"

static int setup(void **state)
{
  (void)state;
  memset(rows, 0, sizeof(rows));
  return 0;
}

static int count_prefix(const char *prefix)
{
  int i, n = 0;
  for (i = 0; i < NROWS; i++)
    if (rows[i].used && !strncmp(rows[i].key, prefix, strlen(prefix)))
      n++;
  return n;
}

static void delete_removes_long_keys(void **state)
{
  (void)state;
  assert_int_equal(persistence_profile_create(ACCT, LONG_NAME, NULL), 0);
  assert_int_equal(persistence_profile_set(ACCT, LONG_NAME, "channels",
                                           "#a,#b"), 0);
  assert_int_equal(count_prefix(PROFILE_KEY_PREFIX LONG_NAME "/"), 2);

  assert_int_equal(persistence_profile_delete(ACCT, LONG_NAME), 0);
  assert_int_equal(count_prefix(PROFILE_KEY_PREFIX LONG_NAME "/"), 0);
}

static void rename_moves_long_keys(void **state)
{
  char val[128];

  (void)state;
  assert_int_equal(persistence_profile_create(ACCT, "short", NULL), 0);
  assert_int_equal(persistence_profile_set(ACCT, "short", "channels",
                                           "#x"), 0);

  assert_int_equal(persistence_profile_rename(ACCT, "short", LONG_NAME), 0);
  assert_int_equal(persistence_profile_get_own(ACCT, LONG_NAME, "channels",
                                               val, sizeof(val)), 0);
  assert_string_equal(val, "#x");
  assert_int_equal(count_prefix(PROFILE_KEY_PREFIX "short/"), 0);

  /* and from a long name to another long name */
  assert_int_equal(persistence_profile_rename(ACCT, LONG_NAME, LONG_NAME2), 0);
  assert_int_equal(count_prefix(PROFILE_KEY_PREFIX LONG_NAME "/"), 0);
  assert_int_equal(persistence_profile_get_own(ACCT, LONG_NAME2, "channels",
                                               val, sizeof(val)), 0);
  assert_string_equal(val, "#x");
}

static void rename_repoints_long_children(void **state)
{
  char val[128];

  (void)state;
  assert_int_equal(persistence_profile_create(ACCT, "parentp", NULL), 0);
  assert_int_equal(persistence_profile_create(ACCT, LONG_NAME, "parentp"), 0);
  assert_int_equal(persistence_profile_rename(ACCT, "parentp", "newp"), 0);
  assert_int_equal(persistence_profile_get_own(ACCT, LONG_NAME, "parent",
                                               val, sizeof(val)), 0);
  assert_string_equal(val, "newp");
}

static void delete_sees_long_children(void **state)
{
  (void)state;
  assert_int_equal(persistence_profile_create(ACCT, "parentp", NULL), 0);
  assert_int_equal(persistence_profile_create(ACCT, LONG_NAME, "parentp"), 0);
  /* a profile others inherit from is not deleted */
  assert_int_equal(persistence_profile_delete(ACCT, "parentp"), -1);
}

static int listed;
static char listed_long;

static void list_cb(const char *name, const char *parent, void *cookie)
{
  (void)parent; (void)cookie;
  listed++;
  if (!strcmp(name, LONG_NAME))
    listed_long = 1;
}

static void list_shows_long_names(void **state)
{
  (void)state;
  assert_int_equal(persistence_profile_create(ACCT, LONG_NAME, NULL), 0);
  listed = 0;
  listed_long = 0;
  assert_int_equal(persistence_profile_list(ACCT, list_cb, NULL), 0);
  assert_true(listed_long);
  assert_int_equal(listed, 2);    /* and the implicit default */
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test_setup(delete_removes_long_keys, setup),
    cmocka_unit_test_setup(rename_moves_long_keys, setup),
    cmocka_unit_test_setup(rename_repoints_long_children, setup),
    cmocka_unit_test_setup(delete_sees_long_children, setup),
    cmocka_unit_test_setup(list_shows_long_names, setup),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
