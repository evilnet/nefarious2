/*
 * conf_reattach_cmocka.c - after a rehash, a registered server link is put
 * under the new Connect block that admits it, or keeps the one it linked
 * under; the ConfItem and class reference counts follow
 *
 * rehash() marks every conf in use illegal.  For a registered server
 * link, rehash_reattach_server() looks for the new configuration's
 * Connect block that would admit the link if it linked now -- named for
 * it, matching the host or address it was recorded under, with its SSL
 * fingerprint -- and attaches it before detaching the old one, which is
 * freed with its last holder.  With no such block the link keeps the old
 * one.  Either way operators are told, and the servers already behind the
 * link that the new limits would refuse are named.
 *
 * This includes the real s_conf.c, compiled with -ffunction-sections and
 * linked with --gc-sections, so the program keeps rehash_reattach_server()
 * and what it calls (the conf finders, attach_conf, detach_conf,
 * free_conf, verify_sslclifp) and nothing else of s_conf.c: only those
 * need the ircd around them here.  Links, blocks and classes are built
 * by hand, as rehash() leaves them.
 */
#include "config.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

/* verify_sslclifp() tests cli_sslclifp(), an array, against NULL: -Wall's
 * -Waddress reports it; it is s_conf.c's, not ours. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Waddress"
#include "../s_conf.c"
#pragma GCC diagnostic pop

/* ------------------------------------------------------------------ */
/* The ircd around rehash_reattach_server()                            */
/* ------------------------------------------------------------------ */

time_t CurrentTime;
int log_inassert;
struct Client me;

void log_write(enum LogSys subsys, enum LogLevel severity, unsigned int flags,
               const char *fmt, ...)
{
  (void)subsys; (void)severity; (void)flags; (void)fmt;
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

void delete_resolver_queries(const void *vptr)
{
  (void)vptr;
}

static int links_out;           /* SLinks made and not yet freed */

struct SLink *make_link(void)
{
  links_out++;
  return calloc(1, sizeof(struct SLink));
}

void free_link(struct SLink *lp)
{
  links_out--;
  free(lp);
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

/** The notice that contains \a text, or NULL. */
static const char *notice_with(const char *text)
{
  int i;

  for (i = 0; i < nnotices; i++)
    if (strstr(notices[i], text))
      return notices[i];
  return NULL;
}

/* ------------------------------------------------------------------ */
/* Fixture                                                             */
/* ------------------------------------------------------------------ */

struct link {
  struct Client cli;
  struct Connection con;
  struct Server serv;
};

static struct ConnectionClass class_a, class_b;
static int confs_freed_before;

static void make_class_named(struct ConnectionClass *cl, const char *name)
{
  memset(cl, 0, sizeof(*cl));
  cl->cc_name = (char *) name;
  cl->valid = 1;
  cl->ref_count = 1;
}

static void make_link_client(struct link *l, const char *name, const char *ip)
{
  memset(l, 0, sizeof(*l));
  cli_connect(&l->cli) = &l->con;
  cli_serv(&l->cli) = &l->serv;
  cli_status(&l->cli) = STAT_SERVER;
  ircd_strncpy(cli_name(&l->cli), name, sizeof(cli_name(&l->cli)));
  ircd_strncpy(cli_sockhost(&l->cli), ip, HOSTLEN + 1);
  assert_true(ircd_aton(&cli_ip(&l->cli), ip));
  cli_max_sendq(&l->cli) = 12345;      /* a cached limit */
}

/** A Connect block as the parser makes one. */
static struct ConfItem *connect_conf(const char *name, const char *host,
                                     const char *hub, unsigned int maxhops,
                                     struct ConnectionClass *cl,
                                     const char *passwd)
{
  struct ConfItem *aconf = calloc(1, sizeof(*aconf));
  unsigned char bits;

  assert_non_null(aconf);
  ++GlobalConfCount;
  aconf->status = CONF_SERVER;
  aconf->name = strdup(name);
  aconf->host = strdup(host);
  aconf->from_host = strdup(host);
  aconf->from_addrbits = ipmask_parse(host, &aconf->from_address, &bits)
                         ? bits : -1;
  ircd_aton(&aconf->address.addr, host);   /* stays unset for a name */
  aconf->passwd = strdup(passwd);
  aconf->hub_limit = hub ? strdup(hub) : NULL;
  aconf->maximum = maxhops;
  aconf->conn_class = cl;
  return aconf;
}

/** What rehash() leaves: the block in use flagged illegal and out of the
 * list, and the new configuration's blocks in it. */
static void rehash_marks(struct ConfItem *old)
{
  old->status |= CONF_ILLEGAL;
}

static void list_add(struct ConfItem *aconf)
{
  aconf->next = GlobalConfList;
  GlobalConfList = aconf;
}

/** The link's only Connect block. */
static struct ConfItem *link_connect(struct link *l)
{
  struct SLink *lp;
  struct ConfItem *found = NULL;
  int n = 0;

  for (lp = cli_confs(&l->cli); lp; lp = lp->next)
    if (lp->value.aconf->status & CONF_SERVER) {
      found = lp->value.aconf;
      n++;
    }
  assert_int_equal(n, 1);
  return found;
}

static int setup(void **state)
{
  (void)state;
  GlobalConfList = NULL;
  nnotices = 0;
  links_out = 0;
  make_class_named(&class_a, "ClassA");
  make_class_named(&class_b, "ClassB");
  confs_freed_before = GlobalConfCount;
  return 0;
}

/* A changed block of the same name that admits the link: attached, the
 * old one freed, the class counts moved, the cached SendQ dropped, and
 * operators told what changed and which servers behind are now out of
 * mask. */
static void changed_block_is_attached_and_old_freed(void **state)
{
  struct link l, behind;
  struct DLink down = { 0 };
  struct ConfItem *old, *new;
  int count;

  (void)state;
  make_link_client(&l, "leafa.test", "127.0.0.1");
  make_link_client(&behind, "far.test", "127.0.0.9");
  cli_hopcount(&behind.cli) = 2;
  down.value.cptr = &behind.cli;
  l.serv.down = &down;

  old = connect_conf("leafa.test", "127.0.0.1", "*", 65535, &class_a, "pw");
  assert_int_equal(attach_conf(&l.cli, old), ACR_OK);
  assert_int_equal(Links(&class_a), 2);
  rehash_marks(old);
  new = connect_conf("leafa.test", "127.0.0.1", "allowed.*", 65535, &class_b,
                     "pw2");
  list_add(new);
  count = GlobalConfCount;

  rehash_reattach_server(&l.cli);

  assert_ptr_equal(link_connect(&l), new);
  assert_int_equal(new->clients, 1);
  assert_int_equal(GlobalConfCount, count - 1);      /* old freed */
  assert_int_equal(Links(&class_a), 1);
  assert_int_equal(Links(&class_b), 2);
  assert_int_equal(cli_max_sendq(&l.cli), 0);
  assert_non_null(notice_with("leafa.test is now under its new Connect block"));
  assert_non_null(notice_with("hub mask * -> allowed.*"));
  assert_non_null(notice_with("class ClassA -> ClassB"));
  assert_non_null(notice_with("password changed"));
  assert_non_null(notice_with("1 server behind leafa.test"));
  assert_non_null(notice_with(": far.test"));
  assert_int_equal(links_out, 1);                    /* the link's own */
}

/* A block removed from the configuration: the link keeps the old one,
 * nothing is freed or moved, and operators are told why. */
static void removed_block_is_kept(void **state)
{
  struct link l;
  struct ConfItem *old;

  (void)state;
  make_link_client(&l, "leafa.test", "127.0.0.1");
  old = connect_conf("leafa.test", "127.0.0.1", "*", 65535, &class_a, "pw");
  attach_conf(&l.cli, old);
  rehash_marks(old);
  list_add(connect_conf("other.test", "127.0.0.1", "*", 65535, &class_b, "pw"));

  rehash_reattach_server(&l.cli);

  assert_ptr_equal(link_connect(&l), old);
  assert_int_equal(old->clients, 1);
  assert_int_equal(Links(&class_a), 2);
  assert_int_equal(cli_max_sendq(&l.cli), 12345);
  assert_non_null(notice_with("keeps the Connect block it linked under"));
  assert_non_null(notice_with("was removed"));
  assert_int_equal(links_out, 1);
}

/* A same-name block that names another address does not admit the link:
 * kept, and said so. */
static void readdressed_block_is_kept(void **state)
{
  struct link l;
  struct ConfItem *old, *new;

  (void)state;
  make_link_client(&l, "leafa.test", "127.0.0.1");
  old = connect_conf("leafa.test", "127.0.0.1", "*", 65535, &class_a, "pw");
  attach_conf(&l.cli, old);
  rehash_marks(old);
  new = connect_conf("leafa.test", "127.0.0.2", "*", 65535, &class_b, "pw");
  list_add(new);

  rehash_reattach_server(&l.cli);

  assert_ptr_equal(link_connect(&l), old);
  assert_int_equal(new->clients, 0);
  assert_int_equal(Links(&class_b), 1);
  assert_non_null(notice_with("does not admit it (host or address)"));
}

/* A block that names the peer by a host name its DNS lookup has not
 * resolved yet (as right after a rehash): the same host as the old block
 * admits the link as the old block did. */
static void same_host_name_admits_while_unresolved(void **state)
{
  struct link l;
  struct ConfItem *old, *new;

  (void)state;
  make_link_client(&l, "leafa.test", "10.0.0.5");
  old = connect_conf("leafa.test", "leafa.example.org", "*", 65535, &class_a,
                     "pw");
  attach_conf(&l.cli, old);
  rehash_marks(old);
  new = connect_conf("leafa.test", "leafa.example.org", "*", 3, &class_a, "pw");
  assert_false(irc_in_addr_valid(&new->address.addr));
  list_add(new);

  rehash_reattach_server(&l.cli);

  assert_ptr_equal(link_connect(&l), new);
  assert_non_null(notice_with("maxhops 65535 -> 3"));
  assert_int_equal(Links(&class_a), 2);              /* moved within A */
}

/* A block whose SSL fingerprint is not the link's does not admit it. */
static void fingerprint_mismatch_is_kept(void **state)
{
  struct link l;
  struct ConfItem *old, *new;

  (void)state;
  make_link_client(&l, "leafa.test", "127.0.0.1");
  ircd_strncpy(cli_sslclifp(&l.cli), "aaaa", sizeof(cli_sslclifp(&l.cli)));
  old = connect_conf("leafa.test", "127.0.0.1", "*", 65535, &class_a, "pw");
  attach_conf(&l.cli, old);
  rehash_marks(old);
  new = connect_conf("leafa.test", "127.0.0.1", "*", 65535, &class_a, "pw");
  new->sslfp = strdup("bbbb");
  list_add(new);

  rehash_reattach_server(&l.cli);

  assert_ptr_equal(link_connect(&l), old);
  assert_non_null(notice_with("does not admit it (SSL fingerprint)"));
}

/* An unchanged block: re-attached silently, the old one freed. */
static void unchanged_block_is_attached_silently(void **state)
{
  struct link l;
  struct ConfItem *old, *new;
  int count;

  (void)state;
  make_link_client(&l, "leafa.test", "127.0.0.1");
  old = connect_conf("leafa.test", "127.0.0.1", "*", 65535, &class_a, "pw");
  attach_conf(&l.cli, old);
  rehash_marks(old);
  new = connect_conf("leafa.test", "127.0.0.1", "*", 65535, &class_a, "pw");
  list_add(new);
  count = GlobalConfCount;

  rehash_reattach_server(&l.cli);

  assert_ptr_equal(link_connect(&l), new);
  assert_int_equal(GlobalConfCount, count - 1);
  assert_int_equal(nnotices, 0);
}

/* A wildcard block held by two links: the first link moves and the old
 * block stays for the second; it is freed when the second moves too. */
static void block_another_link_holds_is_not_freed(void **state)
{
  struct link a, b;
  struct ConfItem *old, *new;
  int count;

  (void)state;
  make_link_client(&a, "a.test", "127.0.0.1");
  make_link_client(&b, "b.test", "127.0.0.1");
  old = connect_conf("*.test", "127.0.0.1", "*", 65535, &class_a, "pw");
  attach_conf(&a.cli, old);
  attach_conf(&b.cli, old);
  rehash_marks(old);
  new = connect_conf("*.test", "127.0.0.1", "x.*", 65535, &class_a, "pw");
  list_add(new);
  count = GlobalConfCount;

  rehash_reattach_server(&a.cli);
  assert_ptr_equal(link_connect(&a), new);
  assert_ptr_equal(link_connect(&b), old);
  assert_int_equal(old->clients, 1);
  assert_int_equal(GlobalConfCount, count);          /* not freed */
  assert_string_equal(old->name, "*.test");          /* still readable */

  rehash_reattach_server(&b.cli);
  assert_ptr_equal(link_connect(&b), new);
  assert_int_equal(new->clients, 2);
  assert_int_equal(GlobalConfCount, count - 1);
  assert_int_equal(Links(&class_a), 3);
}

/* A link whose block was not replaced (no rehash marked it) is left as
 * it is. */
static void block_not_replaced_is_left_alone(void **state)
{
  struct link l;
  struct ConfItem *cur;

  (void)state;
  make_link_client(&l, "leafa.test", "127.0.0.1");
  cur = connect_conf("leafa.test", "127.0.0.1", "*", 65535, &class_a, "pw");
  list_add(cur);
  attach_conf(&l.cli, cur);

  rehash_reattach_server(&l.cli);

  assert_ptr_equal(link_connect(&l), cur);
  assert_int_equal(cur->clients, 1);
  assert_int_equal(nnotices, 0);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test_setup(changed_block_is_attached_and_old_freed, setup),
    cmocka_unit_test_setup(removed_block_is_kept, setup),
    cmocka_unit_test_setup(readdressed_block_is_kept, setup),
    cmocka_unit_test_setup(same_host_name_admits_while_unresolved, setup),
    cmocka_unit_test_setup(fingerprint_mismatch_is_kept, setup),
    cmocka_unit_test_setup(unchanged_block_is_attached_silently, setup),
    cmocka_unit_test_setup(block_another_link_holds_is_not_freed, setup),
    cmocka_unit_test_setup(block_not_replaced_is_left_alone, setup),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
