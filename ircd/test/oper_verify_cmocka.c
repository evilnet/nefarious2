/*
 * oper_verify_cmocka.c - an OPER whose password check finishes after a
 * REHASH is judged by the configuration in force then
 *
 * can_oper() hands the password check to the thread pool and keeps only
 * the Operator block's name and the password (hash) it checked against;
 * oper_password_verified() runs a loop pass or more later -- after a
 * REHASH that may have freed the block -- and asks oper_live_block() for
 * the block the live configuration gives the client: found by name and
 * host again, with the same password and the client's SSL fingerprint.
 *
 * This includes the real m_oper.c, compiled with -ffunction-sections and
 * linked with --gc-sections, so the program keeps oper_live_block() and
 * what it calls; find_conf_exact() and verify_sslclifp() are stubs over a
 * list of blocks the test builds as a configuration pass would.
 */
#include "config.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

#include "../m_oper.c"

/* ------------------------------------------------------------------ */
/* The configuration in force                                          */
/* ------------------------------------------------------------------ */

/** The live Operator blocks (a rehash replaces them all). */
static struct ConfItem blocks[4];
static int nblocks;
/** The host each block admits ("*" for any). */
static const char *block_host[4];
/** The SSL fingerprint each block requires ("" for none). */
static const char *block_fp[4];

static const char *client_host;
static const char *client_fp;

struct ConfItem *find_conf_exact(const char *name, struct Client *cptr,
                                 int statmask)
{
  int i;

  (void)cptr;
  assert_int_equal(CONF_OPERATOR, statmask);
  for (i = 0; i < nblocks; i++)
    if (!strcmp(blocks[i].name, name)
        && (!strcmp(block_host[i], "*") || !strcmp(block_host[i], client_host)))
      return &blocks[i];
  return NULL;
}

int verify_sslclifp(struct Client *cptr, struct ConfItem *aconf)
{
  (void)cptr;
  return !*block_fp[aconf - blocks] || !strcmp(block_fp[aconf - blocks], client_fp);
}

static void add_block(const char *name, const char *passwd, const char *host,
                      const char *fp)
{
  memset(&blocks[nblocks], 0, sizeof(blocks[nblocks]));
  blocks[nblocks].status = CONF_OPERATOR;
  blocks[nblocks].name = (char *) name;
  blocks[nblocks].passwd = (char *) passwd;
  block_host[nblocks] = host;
  block_fp[nblocks] = fp;
  nblocks++;
}

static struct Client client;

static int setup(void **state)
{
  (void)state;
  nblocks = 0;
  client_host = "10.0.0.1";
  client_fp = "";
  return 0;
}

/* ------------------------------------------------------------------ */
/* Cases: the check was made against "op" with password "$X$old"       */
/* ------------------------------------------------------------------ */

/** Nothing changed (or the block was replaced by an identical one): the
 * live block, not the one the check started with. */
static void unchanged_block_is_the_live_one(void **state)
{
  const char *why = "";

  (void)state;
  add_block("other", "$X$old", "*", "");
  add_block("op", "$X$old", "*", "");
  assert_ptr_equal(&blocks[1], oper_live_block(&client, "op", "$X$old", &why));
}

/** The rehash removed the block: no oper. */
static void removed_block_fails(void **state)
{
  const char *why = "";

  (void)state;
  add_block("other", "$X$old", "*", "");
  assert_null(oper_live_block(&client, "op", "$X$old", &why));
  assert_string_equal("no operator block", why);
}

/** Retired (flagged illegal, still held by someone): no oper. */
static void illegal_block_fails(void **state)
{
  const char *why = "";

  (void)state;
  add_block("op", "$X$old", "*", "");
  blocks[0].status |= CONF_ILLEGAL;
  assert_null(oper_live_block(&client, "op", "$X$old", &why));
  assert_string_equal("no operator block", why);
}

/** Its password changed: the old one does not grant oper. */
static void changed_password_fails(void **state)
{
  const char *why = "";

  (void)state;
  add_block("op", "$X$new", "*", "");
  assert_null(oper_live_block(&client, "op", "$X$old", &why));
  assert_string_equal("password mis-match", why);
}

/** It no longer admits the client's host. */
static void narrowed_host_fails(void **state)
{
  const char *why = "";

  (void)state;
  add_block("op", "$X$old", "10.9.9.9", "");
  assert_null(oper_live_block(&client, "op", "$X$old", &why));
  assert_string_equal("no operator block", why);
}

/** It now requires an SSL fingerprint the client does not have. */
static void new_fingerprint_fails(void **state)
{
  const char *why = "";

  (void)state;
  add_block("op", "$X$old", "*", "AB:CD");
  client_fp = "EF:01";
  assert_null(oper_live_block(&client, "op", "$X$old", &why));
  assert_string_equal("SSL fingerprint mismatch", why);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test_setup(unchanged_block_is_the_live_one, setup),
    cmocka_unit_test_setup(removed_block_fails, setup),
    cmocka_unit_test_setup(illegal_block_fails, setup),
    cmocka_unit_test_setup(changed_password_fails, setup),
    cmocka_unit_test_setup(narrowed_host_fails, setup),
    cmocka_unit_test_setup(new_fingerprint_fails, setup),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
