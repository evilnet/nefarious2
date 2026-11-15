/*
 * gitsync_content_cmocka.c - what a sync does with the content it pulled
 *
 * gitsync_content_hash() tells GitSync whether the content it pulled is
 * the content it applied last (then nothing is written or rehashed): it
 * must change when any byte does, wherever it is.
 *
 * gitsync_content_verdict() decides: content applied last is left alone;
 * content refused last (it did not parse, the backup was restored) is
 * left alone too, until it changes, unless the sync was forced (an
 * operator's GITSYNC force, or GitSync starting); anything else is
 * applied.
 */
#include "config.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cmocka.h>

#include "gitsync_content.h"

static char *content_of(size_t len, char fill)
{
  char *c = malloc(len + 1);

  assert_non_null(c);
  memset(c, fill, len);
  c[len] = '\0';
  return c;
}

static int same_hash(const char *a, size_t alen, const char *b, size_t blen)
{
  char ha[GITSYNC_HASHLEN], hb[GITSYNC_HASHLEN];

  gitsync_content_hash(a, alen, ha, sizeof(ha));
  gitsync_content_hash(b, blen, hb, sizeof(hb));
  return 0 == strcmp(ha, hb);
}

/** The same content hashes the same. */
static void same_content_same_hash(void **state)
{
  char *a = content_of(5000, 'k'), *b = content_of(5000, 'k');

  (void)state;
  assert_true(same_hash(a, 5000, b, 5000));
  free(a);
  free(b);
}

/** A byte changed near the start. */
static void change_at_start(void **state)
{
  char *a = content_of(5000, 'k'), *b = content_of(5000, 'k');

  (void)state;
  b[10] = 'x';
  assert_false(same_hash(a, 5000, b, 5000));
  free(a);
  free(b);
}

/** A byte changed past the first kilobyte, the length the same (a
 * K-line's reason edited, an address changed): a different hash. */
static void change_past_first_kilobyte(void **state)
{
  char *a = content_of(5000, 'k'), *b = content_of(5000, 'k');

  (void)state;
  b[2000] = 'x';
  assert_false(same_hash(a, 5000, b, 5000));
  b[2000] = 'k';
  b[4999] = 'x';
  assert_false(same_hash(a, 5000, b, 5000));
  free(a);
  free(b);
}

/** Two bytes swapped: a different hash. */
static void bytes_swapped(void **state)
{
  char a[] = "Kill { host = \"*@10.0.0.1\"; reason = \"ab\"; };";
  char b[] = "Kill { host = \"*@10.0.0.1\"; reason = \"ba\"; };";

  (void)state;
  assert_false(same_hash(a, strlen(a), b, strlen(b)));
}

/** A different length. */
static void different_length(void **state)
{
  char *a = content_of(5000, 'k');

  (void)state;
  assert_false(same_hash(a, 5000, a, 4999));
  free(a);
}

/* ------------------------------------------------------------------ */
/* The verdict                                                          */
/* ------------------------------------------------------------------ */

/** Nothing applied or refused yet (a first sync): apply. */
static void first_content_is_applied(void **state)
{
  (void)state;
  assert_int_equal(GITSYNC_CONTENT_APPLY, gitsync_content_verdict("a", "", "", 0));
  assert_int_equal(GITSYNC_CONTENT_APPLY, gitsync_content_verdict("a", "", "", 1));
}

/** The content applied last: nothing, forced or not. */
static void applied_content_is_unchanged(void **state)
{
  (void)state;
  assert_int_equal(GITSYNC_CONTENT_UNCHANGED, gitsync_content_verdict("a", "a", "", 0));
  assert_int_equal(GITSYNC_CONTENT_UNCHANGED, gitsync_content_verdict("a", "a", "b", 1));
}

/** The content refused last: a periodic sync leaves it alone. */
static void refused_content_is_skipped(void **state)
{
  (void)state;
  assert_int_equal(GITSYNC_CONTENT_REFUSED, gitsync_content_verdict("b", "a", "b", 0));
  assert_int_equal(GITSYNC_CONTENT_REFUSED, gitsync_content_verdict("b", "", "b", 0));
}

/** A forced sync (GITSYNC force, GitSync starting) tries it again. */
static void forced_sync_retries_refused_content(void **state)
{
  (void)state;
  assert_int_equal(GITSYNC_CONTENT_APPLY, gitsync_content_verdict("b", "a", "b", 1));
}

/** Content that changed since it was refused is applied. */
static void changed_content_is_applied(void **state)
{
  (void)state;
  assert_int_equal(GITSYNC_CONTENT_APPLY, gitsync_content_verdict("c", "a", "b", 0));
}

/* ------------------------------------------------------------------ */
/* GITSYNC_LOCAL_PATH: what a sync refuses to touch                    */
/* ------------------------------------------------------------------ */

/** The judgement on an already resolved path (as if no component were a
 * symbolic link): spelt against /srv/ircd, ircd.conf in /srv/ircd/lib. */
static const char *refusal(const char *local_path)
{
  static char resolved[1024];

  if (gitsync_path_spell(local_path, "/srv/ircd", resolved, sizeof(resolved)))
    return "too long";
  return gitsync_local_path_refusal(local_path, resolved, "/srv/ircd");
}

/** A directory of its own, relative or absolute: accepted. */
static void own_directory_accepted(void **state)
{
  (void)state;
  assert_null(refusal("gitsync"));
  assert_null(refusal("./gitsync"));
  assert_null(refusal("data/gitsync"));
  assert_null(refusal("/tmp/gitsync"));
  assert_null(refusal("/srv/ircd/gitsync"));
  assert_null(refusal("lib/gitsync"));     /* beside ircd.conf, not above it */
}

/** Empty, the root, the server's directory or any of its parents. */
static void dangerous_directories_refused(void **state)
{
  (void)state;
  assert_non_null(refusal(""));
  assert_non_null(refusal("/"));
  assert_non_null(refusal("//"));
  assert_non_null(refusal("."));
  assert_non_null(refusal("./"));
  assert_non_null(refusal(".//."));
  assert_non_null(refusal("/srv"));
  assert_non_null(refusal("/srv/ircd"));
  assert_non_null(refusal("/srv/ircd/"));
  assert_non_null(refusal("/srv/./ircd"));
}

/** The directory holding ircd.conf (or the SSH key) is the operator's
 * choice: nothing is ever deleted, so it is accepted. */
static void conf_directory_accepted(void **state)
{
  (void)state;
  assert_null(refusal("lib"));
  assert_null(refusal("/srv/ircd/lib"));
}

/** gitsync_path_under(): a path at or below a directory, by components. */
static void path_under_rules(void **state)
{
  (void)state;
  assert_true(gitsync_path_under("/srv/ircd/gitsync/key", "/srv/ircd/gitsync"));
  assert_true(gitsync_path_under("/srv/ircd/gitsync", "/srv/ircd/gitsync"));
  assert_false(gitsync_path_under("/srv/ircd/gitsync2/key", "/srv/ircd/gitsync"));
  assert_false(gitsync_path_under("/srv/ircd/gitsync.conf", "/srv/ircd/gitsync"));
  assert_true(gitsync_path_under("/anything", "/"));
}

/* ------------------------------------------------------------------ */
/* The checkout: fetch, adopt, re-clone or refuse                       */
/* ------------------------------------------------------------------ */

/** Its origin is the configured repository: fetch; unmarked (an older
 * build's or the operator's checkout) -> fetch and mark. */
static void same_origin_fetched(void **state)
{
  (void)state;
  assert_int_equal(GITSYNC_CHECKOUT_FETCH, gitsync_checkout_action(1, 1));
  assert_int_equal(GITSYNC_CHECKOUT_FETCH_ADOPT, gitsync_checkout_action(1, 0));
}

/** Another origin: GitSync's own checkout is re-pointed in place; a
 * repository without the mark is someone else's and is not touched. */
static void other_origin_rules(void **state)
{
  (void)state;
  assert_int_equal(GITSYNC_CHECKOUT_REPOINT, gitsync_checkout_action(0, 1));
  assert_int_equal(GITSYNC_CHECKOUT_REFUSE_FOREIGN, gitsync_checkout_action(0, 0));
}

/* ------------------------------------------------------------------ */
/* Resolved: symbolic links in GITSYNC_LOCAL_PATH                        */
/* ------------------------------------------------------------------ */

static char olddir[1024];
static char top[1024];          /* the test's own tree, absolute */

/** A tree: top/srv/ircd (the server's directory, cwd), top/srv/ircd/lib
 * holding ircd.conf, top/other; links in top/srv/ircd pointing at the
 * server's directory, its parent, "/", the conf directory, a dangling
 * target, and a legitimate directory elsewhere. */
static int link_setup(void **state)
{
  char p[1200];

  (void)state;
  assert_non_null(getcwd(olddir, sizeof(olddir)));
  strcpy(top, "gitsync_content_test.XXXXXX");
  assert_non_null(mkdtemp(top));
  assert_non_null(realpath(top, p));
  strcpy(top, p);
#define MK(fmt) do { snprintf(p, sizeof(p), fmt, top); assert_int_equal(0, mkdir(p, 0700)); } while (0)
#define LN(target, fmt) do { snprintf(p, sizeof(p), fmt, top); assert_int_equal(0, symlink(target, p)); } while (0)
  MK("%s/srv"); MK("%s/srv/ircd"); MK("%s/srv/ircd/lib"); MK("%s/other");
  snprintf(p, sizeof(p), "%s/srv/ircd/lib/ircd.conf", top);
  fclose(fopen(p, "w"));
  assert_int_equal(0, chdir(strcat(strcpy(p, top), "/srv/ircd")));
  LN(".", "%s/srv/ircd/here");
  LN("..", "%s/srv/ircd/up");
  LN("/", "%s/srv/ircd/root");
  LN("lib", "%s/srv/ircd/libdir");
  LN("nowhere/at/all", "%s/srv/ircd/dangling");
  {
    char other[1200];

    snprintf(other, sizeof(other), "%s/other", top);
    LN(other, "%s/srv/ircd/elsewhere");
  }
#undef MK
#undef LN
  return 0;
}

static int link_teardown(void **state)
{
  char cmd[1300];

  (void)state;
  assert_int_equal(0, chdir(olddir));
  snprintf(cmd, sizeof(cmd), "rm -rf '%s'", top);
  assert_int_equal(0, system(cmd));
  return 0;
}

static const char *checked(const char *local_path)
{
  static char resolved[1024];

  return gitsync_local_path_check(local_path, resolved, sizeof(resolved));
}

/** A link to the server's directory, to its parent or to "/" -- as the
 * last component or inside the path -- is judged as what it reaches:
 * refused. */
static void links_to_dangerous_places_refused(void **state)
{
  (void)state;
  assert_non_null(checked("here"));
  assert_non_null(checked("up"));
  assert_non_null(checked("root"));
  assert_non_null(checked("up/ircd"));          /* the server's dir again */
  assert_non_null(checked("up/."));             /* its parent */
  assert_null(checked("up/ircd/lib/gitsync"));  /* below it, via a link */
}

/** The final component a link (even to a harmless place, or dangling):
 * refused -- what it names can be swapped after the check. */
static void final_link_refused(void **state)
{
  (void)state;
  assert_non_null(checked("elsewhere"));
  assert_non_null(checked("dangling"));
}

/** A link inside the path to a harmless place resolves to it: accepted,
 * and the resolved path is what is used. */
static void link_inside_to_harmless_place(void **state)
{
  char resolved[1024], want[1200];

  (void)state;
  {
    const char *why = gitsync_local_path_check("elsewhere/gitsync",
                                               resolved, sizeof(resolved));
    if (why)
      fail_msg("refused: %s", why);
  }
  snprintf(want, sizeof(want), "%s/other/gitsync", top);
  assert_string_equal(want, resolved);
  assert_null(gitsync_local_path_check("gitsync", resolved, sizeof(resolved)));
  snprintf(want, sizeof(want), "%s/srv/ircd/gitsync", top);
  assert_string_equal(want, resolved);
}

/* ------------------------------------------------------------------ */
/* The install layouts in use                                          */
/* ------------------------------------------------------------------ */

/** Make directories under the test tree, then chdir to the first. */
static void layout(const char *cwd, const char *const *dirs, const char *conf)
{
  char p[1200];
  int i;

  for (i = 0; dirs[i]; i++) {
    char *q;

    snprintf(p, sizeof(p), "%s%s", top, dirs[i]);
    for (q = p + strlen(top) + 1; (q = strchr(q, '/')); q++) {
      *q = '\0';
      mkdir(p, 0700);
      *q = '/';
    }
    mkdir(p, 0700);
  }
  snprintf(p, sizeof(p), "%s%s", top, conf);
  fclose(fopen(p, "w"));
  snprintf(p, sizeof(p), "%s%s", top, cwd);
  assert_int_equal(0, chdir(p));
}

static const char *layout_check(const char *value, int absolute)
{
  static char v[1200], resolved[1200];

  if (absolute)
    snprintf(v, sizeof(v), "%s%s", top, value);
  else
    snprintf(v, sizeof(v), "%s", value);
  return gitsync_local_path_check(v, resolved, sizeof(resolved));
}

/** The maintainers' layout: one directory (/home/u/ircd) is the working
 * directory and holds ircd.conf; GITSYNC_LOCAL_PATH is an absolute path
 * to a subdirectory of it. */
static void layout_one_directory(void **state)
{
  static const char *const dirs[] = { "/home/u/ircd", "/home/u/.ssh", NULL };

  (void)state;
  layout("/home/u/ircd", dirs, "/home/u/ircd/ircd.conf");
  assert_null(layout_check("/home/u/ircd/gitsync", 1));
  assert_null(layout_check("gitsync", 0));
  assert_non_null(layout_check("/home/u/ircd", 1));
  assert_non_null(layout_check("/home/u", 1));
}

/** The default ./configure layout: prefix $HOME, DPATH (the working
 * directory, holding ircd.conf) $HOME/lib, binaries in $HOME/bin. */
static void layout_configure_default(void **state)
{
  static const char *const dirs[] = { "/home/u/lib", "/home/u/bin", NULL };

  (void)state;
  layout("/home/u/lib", dirs, "/home/u/lib/ircd.conf");
  assert_null(layout_check("gitsync", 0));                /* the default */
  assert_null(layout_check("/home/u/gitsync-data", 1));   /* a sibling */
  assert_non_null(layout_check("/home/u", 1));            /* the prefix */
  assert_non_null(layout_check("/home/u/lib", 1));
}

/** The Docker / test-bed layout: working directory /home/nefarious/ircd,
 * checkout in /tmp/gitsync, the conf file and key in a gitsync/ volume
 * under the working directory (not the checkout). */
static void layout_docker(void **state)
{
  static const char *const dirs[] = { "/home/nefarious/ircd/gitsync", "/tmp",
                                      NULL };

  (void)state;
  layout("/home/nefarious/ircd", dirs, "/home/nefarious/ircd/ircd.conf");
  assert_null(layout_check("/tmp/gitsync", 1));
}

/** A commit's entries: regular files and trees only. */
static void tree_entry_modes(void **state)
{
  (void)state;
  assert_true(gitsync_filemode_allowed(0100644));
  assert_true(gitsync_filemode_allowed(0100755));
  assert_true(gitsync_filemode_allowed(0040000));
  assert_false(gitsync_filemode_allowed(0120000));    /* symbolic link */
  assert_false(gitsync_filemode_allowed(0160000));    /* submodule */
  assert_false(gitsync_filemode_allowed(0100664));    /* legacy */
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(own_directory_accepted),
    cmocka_unit_test(dangerous_directories_refused),
    cmocka_unit_test(conf_directory_accepted),
    cmocka_unit_test(path_under_rules),
    cmocka_unit_test(same_origin_fetched),
    cmocka_unit_test(other_origin_rules),
    cmocka_unit_test(tree_entry_modes),
    cmocka_unit_test_setup_teardown(links_to_dangerous_places_refused, link_setup, link_teardown),
    cmocka_unit_test_setup_teardown(final_link_refused, link_setup, link_teardown),
    cmocka_unit_test_setup_teardown(link_inside_to_harmless_place, link_setup, link_teardown),
    cmocka_unit_test_setup_teardown(layout_one_directory, link_setup, link_teardown),
    cmocka_unit_test_setup_teardown(layout_configure_default, link_setup, link_teardown),
    cmocka_unit_test_setup_teardown(layout_docker, link_setup, link_teardown),
    cmocka_unit_test(first_content_is_applied),
    cmocka_unit_test(applied_content_is_unchanged),
    cmocka_unit_test(refused_content_is_skipped),
    cmocka_unit_test(forced_sync_retries_refused_content),
    cmocka_unit_test(changed_content_is_applied),
    cmocka_unit_test(same_content_same_hash),
    cmocka_unit_test(change_at_start),
    cmocka_unit_test(change_past_first_kilobyte),
    cmocka_unit_test(bytes_swapped),
    cmocka_unit_test(different_length),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
