/*
 * conf_include_cmocka.c - an include whose file does not exist is decided
 * once the whole configuration has been read: GitSync's configuration
 * file, with GitSync enabled, is an empty file until the first sync writes
 * it; any other missing include is the parse error it always was
 *
 * The lexer (ircd_lexer.l init_lexer_file()) hands an include it cannot
 * open for want of the file (ENOENT) to conf_include_absent(), which notes
 * the name with the file and line of the include.  read_configuration_file()
 * settles the notes right after feature_mark(), when the features have
 * their final values and before the steps that read the error flag
 * (auth_conf_apply(): a pass with errors leaves IAuth as it was).
 *
 * This includes the real s_conf.c, compiled with -ffunction-sections and
 * linked with --gc-sections, so the program keeps read_configuration_file()
 * and what it calls.  The parse is a stub (yyparse() below) that does what
 * the lexer and the Features block do, in the order a test asks for.
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

#include "../s_conf.c"

/* ------------------------------------------------------------------ */
/* The ircd around read_configuration_file()                           */
/* ------------------------------------------------------------------ */

time_t CurrentTime;
int log_inassert;
struct Client me;

/** The log lines, one per call. */
static char logs[8][600];
static enum LogLevel log_levels[8];
static int nlogs;

void log_write(enum LogSys subsys, enum LogLevel severity, unsigned int flags,
               const char *fmt, ...)
{
  va_list vl;

  (void)subsys; (void)flags;
  assert_true(nlogs < 8);
  log_levels[nlogs] = severity;
  va_start(vl, fmt);
  vsnprintf(logs[nlogs++], sizeof(logs[0]), fmt, vl);
  va_end(vl);
}

void debug(int level, const char *form, ...)
{
  (void)level; (void)form;
}

void *DoMalloc(size_t len, const char *type, const char *file, int line)
{
  void *p = malloc(len);

  (void)type; (void)file; (void)line;
  assert_non_null(p);
  return p;
}

void *DoMallocZero(size_t len, const char *type, const char *file, int line)
{
  void *p = calloc(1, len);

  (void)type; (void)file; (void)line;
  assert_non_null(p);
  return p;
}

/** The operator notices, one per line. */
static char notices[8][600];
static int nnotices;

void sendto_opmask_butone(struct Client *one, unsigned int mask,
                          const char *pattern, ...)
{
  va_list vl;

  (void)one; (void)mask;
  assert_true(nnotices < 8);
  va_start(vl, pattern);
  vsnprintf(notices[nnotices++], sizeof(notices[0]), pattern, vl);
  va_end(vl);
}

/* The features GitSync's decision reads, as the stub parse sets them.
 * feature_unmark()/feature_mark() bracket the parse as in the ircd. */
static int f_gitsync_enable;
static const char *f_gitsync_conf_file;

int feature_bool(enum Feature feat)
{
#ifdef USE_LIBGIT2
  if (feat == FEAT_GITSYNC_ENABLE)
    return f_gitsync_enable;
#endif
  (void)feat;
  return 0;
}

#ifdef USE_LIBGIT2
/** gitsync_timer.c's: told each time a placeholder is written. */
static int nlost;

void gitsync_conf_file_lost(void)
{
  nlost++;
}

/** gitsync.c's: the configured GITSYNC_CONF_FILE, "gitsync.conf" when
 * empty. */
const char *gitsync_conf_file(void)
{
  return (f_gitsync_conf_file && *f_gitsync_conf_file) ? f_gitsync_conf_file
    : "gitsync.conf";
}
#endif

void feature_unmark(void) { }
void feature_mark(void) { }
void clear_nameservers(void) { }
void sasl_conf_reset_pending(void) { }
void sasl_conf_apply(void) { }
void authtoken_conf_begin(void) { }
void authtoken_conf_apply(void) { }
void auth_conf_begin(void) { }

/** What the IAuth step saw: the error flag at its time. */
static int auth_apply_saw_error = -1;

void auth_conf_apply(void)
{
  auth_apply_saw_error = conf_get_error_flag();
}

/* ------------------------------------------------------------------ */
/* The ircd around rehash()                                            */
/* ------------------------------------------------------------------ */

/* The IAuth close and the sasl telling at the end of a rehash, in the
 * order they ran; the telling's calls. */
static char rehash_order[64];
static int ntells;

void auth_close_unused(void)
{
  strcat(rehash_order, "close ");
}

void sasl_tell_after_rehash(void)
{
  ntells++;
  strcat(rehash_order, "tell ");
}

/* The rest, as nothing: no configuration in use, no local connection. */
char *configfile = "ircd.conf";
int HighestFd = -1;
struct Client *LocalClientArray[MAXCONNECTIONS];
static int fake_file;
FBFILE *lexer_open_config(void) { return (FBFILE *)&fake_file; }
void lexer_close_config(void) { }
/* The REHASH precheck ("ircd -k" in a process of its own) is not what
 * these tests are about: it passes. */
enum conf_precheck_result
conf_precheck_run(const char *exe, const char *dpath, const char *conf,
                  int timeout_ms, char *out, size_t outlen)
{
  (void)exe; (void)dpath; (void)conf; (void)timeout_ms;
  if (outlen)
    out[0] = '\0';
  return CONF_PRECHECK_OK;
}
int fbstat(struct stat *sb, FBFILE *fb)
{
  (void)fb;
  /* A test that rehashes points configfile at a real file, which the
   * rehash's own stat() of the name must find the same. */
  if (!stat(configfile, sb))
    return 0;
  memset(sb, 0, sizeof(*sb));
  sb->st_mode = S_IFREG;
  sb->st_size = 1;
  return 0;
}
FBFILE *fbopen(const char *filename, const char *mode)
{ (void)filename; (void)mode; return NULL; }
char *fbgets(char *buf, size_t len, FBFILE *fb)
{ (void)buf; (void)len; (void)fb; return NULL; }
void fbclose(FBFILE *fb) { (void)fb; }
void auth_mark_closing(void) { }
void auth_send_event(const char *event, const char *paramstring)
{ (void)event; (void)paramstring; }
int bounce_forced_exit(struct Client *cptr, struct Client *victim,
                       enum bounce_forced_exit why, const char *comment)
{ (void)cptr; (void)victim; (void)why; (void)comment; return 0; }
void bounce_restamp_sessions(void) { }
void class_delete_marked(void) { }
void class_mark_delete(void) { }
void clearNickJupes(void) { }
void close_listeners(void) { }
void mark_listeners_closing(void) { }
void crule_free(struct CRuleNode **elem) { (void)elem; }
void delete_resolver_queries(const void *vptr) { (void)vptr; }
void restart_resolver(void) { }
void dnsbl_clear_servers(void) { }
int exit_client(struct Client *cptr, struct Client *bcptr,
                struct Client *sptr, const char *comment)
{ (void)cptr; (void)bcptr; (void)sptr; (void)comment; return 0; }
void free_link(struct SLink *lp) { (void)lp; }
struct SLink *make_link(void) { return calloc(1, sizeof(struct SLink)); }
void geoip_init(void) { }
const char *get_client_name(const struct Client *sptr, int showip)
{ (void)showip; return cli_name(sptr); }
struct Gline *gline_lookup(struct Client *cptr, unsigned int flags)
{ (void)cptr; (void)flags; return NULL; }
struct Zline *zline_lookup(struct Client *cptr, unsigned int flags)
{ (void)cptr; (void)flags; return NULL; }
void init_isupport(void) { }
void send_isupport_update(void) { }
void log_reopen(void) { }
void motd_clear(void) { }
int send_reply(struct Client *to, int reply, ...)
{ (void)to; (void)reply; return 0; }
int unregister_mapping(struct s_map *map) { (void)map; return 0; }

int init_lexer(void)
{
  lineno = 1;
  linefile = strdup("ircd.conf");
  return 1;
}

void deinit_lexer(void)
{
  free(linefile);
  linefile = NULL;
}

/** One step of the stub parse. */
struct step {
  enum { INCLUDE_ABSENT, SET_ENABLE, SET_CONF_FILE, END } what;
  const char *text;     /**< The include name, or the conf file value. */
  int line;             /**< The line the step is on. */
};

static const struct step *parse_steps;

void yyparse(void)
{
  const struct step *s;

  for (s = parse_steps; s->what != END; s++) {
    lineno = s->line;
    switch (s->what) {
    case INCLUDE_ABSENT:
      conf_include_absent(s->text);
      break;
    case SET_ENABLE:
      f_gitsync_enable = 1;
      break;
    case SET_CONF_FILE:
      f_gitsync_conf_file = s->text;
      break;
    case END:
      break;
    }
  }
}

/* ------------------------------------------------------------------ */
/* Fixture: each test runs in an empty directory of its own            */
/* ------------------------------------------------------------------ */

static char testdir[64];
static char olddir[1024];

static int setup(void **state)
{
  (void)state;
  nlogs = nnotices = 0;
  memset(logs, 0, sizeof(logs));
  memset(notices, 0, sizeof(notices));
  f_gitsync_enable = 0;
  f_gitsync_conf_file = NULL;
  auth_apply_saw_error = -1;
  conf_already_read = 1;     /* nothing to stderr */
  conf_checking = 0;
#ifdef USE_LIBGIT2
  nlost = 0;
#endif
  assert_non_null(getcwd(olddir, sizeof(olddir)));
  strcpy(testdir, "conf_include_test.XXXXXX");
  assert_non_null(mkdtemp(testdir));
  assert_int_equal(0, chdir(testdir));
  return 0;
}

static void rm(const char *name)
{
  unlink(name);
}

static int teardown(void **state)
{
  (void)state;
  rm("gitsync.conf");
  rm("synced.conf");
  rm("other.conf");
  assert_int_equal(0, chdir(olddir));
  assert_int_equal(0, rmdir(testdir));
  return 0;
}

static int exists(const char *name)
{
  struct stat st;

  return 0 == stat(name, &st);
}

/** The notice that contains \a text, or NULL. */
static const char *notice_with(const char *text)
{
  int i;

  for (i = 0; i < nnotices; i++)
    if (strstr(notices[i], text))
      return notices[i];
  return NULL;
}

static const char *log_with(const char *text)
{
  int i;

  for (i = 0; i < nlogs; i++)
    if (strstr(logs[i], text))
      return logs[i];
  return NULL;
}

static void run(const struct step *steps)
{
  parse_steps = steps;
  assert_int_equal(1, read_configuration_file());
}

/* ------------------------------------------------------------------ */
/* GitSync's file, GitSync enabled: an empty include                   */
/* ------------------------------------------------------------------ */

#ifdef USE_LIBGIT2

/** Case A: the include comes before the Features block that enables
 * GitSync.  No error; a placeholder is written; one log line says so. */
static void include_before_enable_is_empty(void **state)
{
  static const struct step steps[] = {
    { INCLUDE_ABSENT, "gitsync.conf", 6 },
    { SET_ENABLE, NULL, 7 },
    { END, NULL, 0 }
  };

  (void)state;
  run(steps);
  assert_int_equal(0, conf_get_error_flag());
  assert_int_equal(0, auth_apply_saw_error);
  assert_null(notice_with("Config parse error"));
  assert_true(exists("gitsync.conf"));
  assert_int_equal(1, nlogs);
  assert_non_null(log_with("gitsync.conf"));
  assert_non_null(log_with("does not exist yet"));
  assert_int_equal(L_NOTICE, log_levels[0]);
  assert_int_equal(1, nlost);   /* GitSync told: sync soon */
}

/** Case B: enabled first, then the include. */
static void include_after_enable_is_empty(void **state)
{
  static const struct step steps[] = {
    { SET_ENABLE, NULL, 6 },
    { INCLUDE_ABSENT, "gitsync.conf", 7 },
    { END, NULL, 0 }
  };

  (void)state;
  run(steps);
  assert_int_equal(0, conf_get_error_flag());
  assert_true(exists("gitsync.conf"));
}

/** Case C: GITSYNC_CONF_FILE names another file, set after ENABLE, both
 * before the include: the configured name is tolerated and written, and
 * nothing appears under the default name. */
static void configured_name_is_empty(void **state)
{
  static const struct step steps[] = {
    { SET_ENABLE, NULL, 6 },
    { SET_CONF_FILE, "synced.conf", 6 },
    { INCLUDE_ABSENT, "synced.conf", 7 },
    { END, NULL, 0 }
  };

  (void)state;
  run(steps);
  assert_int_equal(0, conf_get_error_flag());
  assert_true(exists("synced.conf"));
  assert_false(exists("gitsync.conf"));
}

/** The configured name set after the include line: still the final value
 * decides. */
static void configured_name_after_include_is_empty(void **state)
{
  static const struct step steps[] = {
    { INCLUDE_ABSENT, "synced.conf", 5 },
    { SET_CONF_FILE, "synced.conf", 6 },
    { SET_ENABLE, NULL, 6 },
    { END, NULL, 0 }
  };

  (void)state;
  run(steps);
  assert_int_equal(0, conf_get_error_flag());
  assert_true(exists("synced.conf"));
  assert_false(exists("gitsync.conf"));
}

/** ircd -k: tolerated, logged, nothing written. */
static void check_only_writes_nothing(void **state)
{
  static const struct step steps[] = {
    { INCLUDE_ABSENT, "gitsync.conf", 6 },
    { SET_ENABLE, NULL, 7 },
    { END, NULL, 0 }
  };

  (void)state;
  conf_set_check_only();
  run(steps);
  assert_int_equal(0, conf_get_error_flag());
  assert_false(exists("gitsync.conf"));
  assert_int_equal(1, nlogs);
  assert_non_null(log_with("does not exist yet"));
  assert_int_equal(0, nlost);
}

/** A file that appears between the include and the decision (an earlier
 * include of the same name already wrote it) is not overwritten, and
 * the second include says nothing more. */
static void second_include_same_name(void **state)
{
  static const struct step steps[] = {
    { SET_ENABLE, NULL, 3 },
    { INCLUDE_ABSENT, "gitsync.conf", 6 },
    { INCLUDE_ABSENT, "gitsync.conf", 9 },
    { END, NULL, 0 }
  };

  (void)state;
  run(steps);
  assert_int_equal(0, conf_get_error_flag());
  assert_true(exists("gitsync.conf"));
  assert_int_equal(1, nlogs);
  assert_int_equal(1, nlost);
}

/** The same path spelt another way: "./gitsync.conf" is GitSync's
 * "gitsync.conf" (the tip accepted it when the Features came first). */
static void dot_slash_name_is_empty(void **state)
{
  static const struct step steps[] = {
    { SET_ENABLE, NULL, 3 },
    { INCLUDE_ABSENT, "./gitsync.conf", 6 },
    { END, NULL, 0 }
  };

  (void)state;
  run(steps);
  assert_int_equal(0, conf_get_error_flag());
  assert_null(notice_with("Config parse error"));
  assert_true(exists("gitsync.conf"));
}

/** The absolute path of the working directory's file is the same file. */
static void absolute_name_is_empty(void **state)
{
  static char abs_name[1200];
  struct step steps[] = {
    { SET_ENABLE, NULL, 3 },
    { INCLUDE_ABSENT, abs_name, 6 },
    { END, NULL, 0 }
  };
  char cwd[1024];

  (void)state;
  assert_non_null(getcwd(cwd, sizeof(cwd)));
  snprintf(abs_name, sizeof(abs_name), "%s//gitsync.conf", cwd);
  run(steps);
  assert_int_equal(0, conf_get_error_flag());
  assert_true(exists("gitsync.conf"));
}

/** ".." is not resolved: "sub/../gitsync.conf" is another name, and a
 * missing include. */
static void dot_dot_name_fails(void **state)
{
  static const struct step steps[] = {
    { SET_ENABLE, NULL, 3 },
    { INCLUDE_ABSENT, "sub/../gitsync.conf", 6 },
    { END, NULL, 0 }
  };

  (void)state;
  run(steps);
  assert_int_equal(1, conf_get_error_flag());
  assert_non_null(notice_with("on line 6: Cannot include sub/../gitsync.conf: "
                              "No such file or directory"));
  assert_false(exists("gitsync.conf"));
}

/** The comparison itself, against a fixed working directory. */
static void same_path_rules(void **state)
{
  static const char *cwd = "/srv/ircd";

  (void)state;
  assert_true(conf_same_path("gitsync.conf", "gitsync.conf", cwd));
  assert_true(conf_same_path("./gitsync.conf", "gitsync.conf", cwd));
  assert_true(conf_same_path("gitsync.conf", ".//./gitsync.conf", cwd));
  assert_true(conf_same_path("/srv/ircd/gitsync.conf", "gitsync.conf", cwd));
  assert_true(conf_same_path("//srv//ircd/./gitsync.conf", "./gitsync.conf", cwd));
  assert_true(conf_same_path("gitsync/gitsync.conf", "./gitsync//gitsync.conf", cwd));
  assert_false(conf_same_path("sub/../gitsync.conf", "gitsync.conf", cwd));
  assert_false(conf_same_path("/srv/other/gitsync.conf", "gitsync.conf", cwd));
  assert_false(conf_same_path("other.conf", "gitsync.conf", cwd));
  assert_false(conf_same_path("gitsync.conf.bak", "gitsync.conf", cwd));
  assert_false(conf_same_path("Gitsync.conf", "gitsync.conf", cwd));
}

/** Case C on the tip: the default name with another one configured is a
 * missing include like any other. */
static void default_name_with_other_configured_fails(void **state)
{
  static const struct step steps[] = {
    { SET_ENABLE, NULL, 3 },
    { SET_CONF_FILE, "synced.conf", 3 },
    { INCLUDE_ABSENT, "gitsync.conf", 6 },
    { END, NULL, 0 }
  };

  (void)state;
  run(steps);
  assert_int_equal(1, conf_get_error_flag());
  assert_non_null(notice_with("on line 6: Cannot include gitsync.conf"));
  assert_false(exists("gitsync.conf"));
  assert_false(exists("synced.conf"));
}

#endif /* USE_LIBGIT2 */

/* ------------------------------------------------------------------ */
/* Every other missing include: the error it always was                */
/* ------------------------------------------------------------------ */

/** Case E: GitSync enabled, another file missing: the error, with the
 * include's own file and line, set before the IAuth step looks. */
static void other_missing_include_fails(void **state)
{
  static const struct step steps[] = {
    { SET_ENABLE, NULL, 3 },
    { INCLUDE_ABSENT, "other.conf", 6 },
    { END, NULL, 0 }
  };

  (void)state;
  run(steps);
  assert_int_equal(1, conf_get_error_flag());
  assert_int_equal(1, auth_apply_saw_error);
  assert_non_null(notice_with("Config parse error in file ircd.conf on line 6: "
                              "Cannot include other.conf: No such file or "
                              "directory"));
  assert_non_null(log_with("Config parse error in file ircd.conf on line 6: "
                           "Cannot include other.conf: No such file or "
                           "directory"));
  assert_false(exists("other.conf"));
  assert_false(exists("gitsync.conf"));
}

/** Case F: GitSync disabled, its default name missing: the error. */
static void gitsync_disabled_fails(void **state)
{
  static const struct step steps[] = {
    { INCLUDE_ABSENT, "gitsync.conf", 6 },
    { END, NULL, 0 }
  };

  (void)state;
  run(steps);
  assert_int_equal(1, conf_get_error_flag());
  assert_int_equal(1, auth_apply_saw_error);
  assert_non_null(notice_with("on line 6: Cannot include gitsync.conf: No "
                              "such file or directory"));
  assert_false(exists("gitsync.conf"));
}

/** The notes are the pass's own: a later clean pass sees none of them. */
static void notes_do_not_outlive_the_pass(void **state)
{
  static const struct step bad[] = {
    { INCLUDE_ABSENT, "other.conf", 6 },
    { END, NULL, 0 }
  };
  static const struct step clean[] = {
    { END, NULL, 0 }
  };

  (void)state;
  run(bad);
  assert_int_equal(1, conf_get_error_flag());
  nnotices = 0;
  run(clean);
  assert_int_equal(0, conf_get_error_flag());
  assert_int_equal(0, auth_apply_saw_error);
  assert_int_equal(0, nnotices);
}

/* ------------------------------------------------------------------ */
/* The sasl telling at the end of a rehash                             */
/* ------------------------------------------------------------------ */

/** Reading the configuration tells nothing of sasl, at the first read
 * (start-up sets what clients start from) and at any later one; a rehash
 * tells once, after a removed IAuth program is closed
 * (sasl_tell_after_rehash() itself waits while a new program's policy is
 * unknown: sasl_mechs_cmocka). */
static void rehash_tells_sasl_once_after_iauth_close(void **state)
{
  static const struct step steps[] = { { END, NULL, 0 } };
  static struct Server me_serv;          /* no servers below this one */

  (void)state;
  cli_serv(&me) = &me_serv;
  rehash_order[0] = '\0';
  ntells = 0;
  run(steps);
  assert_int_equal(0, ntells);

  parse_steps = steps;
  {
    char conf[] = "/tmp/conf_include_cmocka.XXXXXX";
    char *was = configfile;
    int fd = mkstemp(conf);

    assert_true(fd >= 0);
    assert_int_equal(1, write(fd, "\n", 1));
    close(fd);
    configfile = conf;
    rehash(&me, 0);
    configfile = was;
    unlink(conf);
  }
  assert_int_equal(1, ntells);
  assert_string_equal(rehash_order, "close tell ");
}

int main(void)
{
  const struct CMUnitTest tests[] = {
#ifdef USE_LIBGIT2
    cmocka_unit_test_setup_teardown(include_before_enable_is_empty, setup, teardown),
    cmocka_unit_test_setup_teardown(include_after_enable_is_empty, setup, teardown),
    cmocka_unit_test_setup_teardown(configured_name_is_empty, setup, teardown),
    cmocka_unit_test_setup_teardown(configured_name_after_include_is_empty, setup, teardown),
    cmocka_unit_test_setup_teardown(second_include_same_name, setup, teardown),
    cmocka_unit_test_setup_teardown(dot_slash_name_is_empty, setup, teardown),
    cmocka_unit_test_setup_teardown(absolute_name_is_empty, setup, teardown),
    cmocka_unit_test_setup_teardown(dot_dot_name_fails, setup, teardown),
    cmocka_unit_test(same_path_rules),
    cmocka_unit_test_setup_teardown(default_name_with_other_configured_fails, setup, teardown),
#endif
    cmocka_unit_test_setup_teardown(other_missing_include_fails, setup, teardown),
    cmocka_unit_test_setup_teardown(gitsync_disabled_fails, setup, teardown),
    cmocka_unit_test_setup_teardown(notes_do_not_outlive_the_pass, setup, teardown),
    cmocka_unit_test_setup_teardown(rehash_tells_sasl_once_after_iauth_close, setup, teardown),
#ifdef USE_LIBGIT2
    cmocka_unit_test_setup_teardown(check_only_writes_nothing, setup, teardown),
#endif
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
