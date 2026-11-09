/*
 * ircd_crypt_concurrency_cmocka.c - password checks running at the same
 * time never read each other's result, and the async check frees what it
 * computed
 *
 * Every crypt mechanism hands back a static buffer: crypt(3)'s own (the
 * native and bcrypt mechanisms, and ircd_crypt()'s untagged fallback),
 * smd5's passwd[120], pbkdf2's result[256] and result[512].  ircd_crypt()
 * copies that buffer to the heap only after the mechanism returns.  The
 * async checks (OPER, SETHOST, WEBIRC) run ircd_crypt() on the thread
 * pool's workers, and the main thread still runs it for the synchronous
 * checks, so two checks at once wrote and read the same buffer: a right
 * password could fail, and a wrong one, checked against the same stored
 * hash as a right one, could pick up the right one's result and match.
 * And crypt_verify_work() never freed the string ircd_crypt() returned:
 * one block lost per async check.
 *
 * This links the REAL ircd_crypt.o, ircd_crypt_async.o, thread_pool.o and
 * every mechanism object.  (ircd_crypt_cmocka.c re-implements ircd_crypt()
 * inline, so it cannot see what the real one serializes.)  MyMalloc's
 * DoMalloc() is defined here and free() is wrapped (-Wl,--wrap=free) to
 * count the blocks the ircd code holds, so a case can see a block that is
 * never given back.  Every mechanism runs on real inputs; the slow ones run
 * at their cheapest settings (sha512-crypt rounds=1000, bcrypt cost 4,
 * PBKDF2 1000 iterations) so a case can run thousands of checks.
 * In the environment, CRYPT_RACE_CALLS sets the calls per thread per
 * mechanism (default 100; use fewer under valgrind), CRYPT_RACE_MECH runs
 * only the mechanism of that name, and CRYPT_TEST_FILTER only the matching
 * cases.
 */
#include "config.h"

#include <poll.h>
#include <pthread.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <cmocka.h>

#include "ircd_crypt.h"
#include "ircd_crypt_native.h"
#include "ircd_crypt_smd5.h"
#include "ircd_log.h"
#include "thread_pool.h"

/* ------------------------------------------------------------------ */
/* The ircd around the crypt code (the linked objects need it with or  */
/* without pthreads)                                                   */
/* ------------------------------------------------------------------ */

int log_inassert;

void log_write(enum LogSys subsys, enum LogLevel severity, unsigned int flags,
               const char *fmt, ...)
{
  (void)subsys; (void)severity; (void)flags; (void)fmt;
}

void debug(int level, const char *form, ...)
{
  (void)level; (void)form;
}

/** Blocks the ircd code holds: DoMalloc() adds one, free() takes one.
 * The workers allocate and free too, hence the atomics. */
static long live_blocks;

void *DoMalloc(size_t len, const char *type, const char *file, int line)
{
  void *p = malloc(len);
  (void)type; (void)file; (void)line;
  if (p)
    __atomic_add_fetch(&live_blocks, 1, __ATOMIC_SEQ_CST);
  return p;
}

void *DoMallocZero(size_t len, const char *type, const char *file, int line)
{
  void *p = calloc(1, len);
  (void)type; (void)file; (void)line;
  if (p)
    __atomic_add_fetch(&live_blocks, 1, __ATOMIC_SEQ_CST);
  return p;
}

/* Every free() in this program and in the ircd objects it links comes
 * here (-Wl,--wrap=free); every block they free came from DoMalloc(). */
void __real_free(void *p);
void __wrap_free(void *p)
{
  if (p)
    __atomic_sub_fetch(&live_blocks, 1, __ATOMIC_SEQ_CST);
  __real_free(p);
}

#ifdef HAVE_PTHREAD

static long blocks_held(void)
{
  return __atomic_load_n(&live_blocks, __ATOMIC_SEQ_CST);
}

/* ------------------------------------------------------------------ */
/* Stored hashes                                                       */
/* ------------------------------------------------------------------ */

#define NTHREADS 8

enum mech {
  M_SMD5,         /* $SMD5$: smd5's static passwd[120] */
  M_CRYPT_MD5,    /* $CRYPT$ + md5-crypt: crypt(3)'s buffer */
  M_CRYPT_SHA512, /* $CRYPT$ + sha512-crypt */
  M_NATIVE,       /* untagged md5-crypt: ircd_crypt()'s native fallback */
  M_BCRYPT,       /* untagged $2b$: ircd_crypt()'s bcrypt branch */
  M_PBKDF2,       /* $PBKDF2$: pbkdf2's static result[256] */
  M_PBKDF2_512,   /* $PBKDF2-SHA512$: static result[512] */
  M_COUNT
};

static const char *mech_name[M_COUNT] = {
  "smd5", "crypt-md5", "crypt-sha512", "native-untagged", "bcrypt",
  "pbkdf2", "pbkdf2-sha512"
};

/** One stored hash: the right key, a wrong key, and what ircd_crypt()
 * returns for each, computed with nothing else running. */
struct pair {
  char key[32];
  char wrong[32];
  char *stored;     /* the right key's hash: ircd_crypt(key, stored) == stored */
  char *for_wrong;  /* ircd_crypt(wrong, stored): a different hash, or NULL */
};

static struct pair pairs[M_COUNT][NTHREADS];

static char *dup_plain(const char *s)
{
  char *d;
  if (!s)
    return NULL;
  d = DoMalloc(strlen(s) + 1, "test", __FILE__, __LINE__);
  strcpy(d, s);
  return d;
}

/** The seed salt for mechanism m, thread t: distinct for every pair. */
static void seed_salt(enum mech m, int t, char *buf, size_t len)
{
  switch (m) {
  case M_SMD5:
    snprintf(buf, len, "$SMD5$sm%02dsalt", t);
    break;
  case M_CRYPT_MD5:
  case M_NATIVE:
    snprintf(buf, len, "$CRYPT$$1$md%02dsalt$", t);
    break;
  case M_CRYPT_SHA512:
    snprintf(buf, len, "$CRYPT$$6$rounds=1000$sh%02dsalt$", t);
    break;
  case M_BCRYPT:
    snprintf(buf, len, "$CRYPT$$2b$04$bcryptSaltForThr%02dabcu", t);
    break;
  /* PBKDF2 hashes are stored tagged twice ($PBKDF2$$PBKDF2$iter$...): the
   * mechanism keeps its own tag, which umkpasswd and ircd_crypt() both add
   * again.  A singly tagged seed would make a fresh 100000-iteration hash. */
  case M_PBKDF2:
    snprintf(buf, len, "$PBKDF2$$PBKDF2$1000$saltForThread%02dAbcdefg$", t);
    break;
  case M_PBKDF2_512:
    snprintf(buf, len, "$PBKDF2-SHA512$$PBKDF2-SHA512$1000$saltForThread%02dAbcdefg$", t);
    break;
  default:
    buf[0] = '\0';
  }
}

static void make_pairs(void)
{
  int m, t;
  char seed[96];
  char *full;

  for (m = 0; m < M_COUNT; m++) {
    for (t = 0; t < NTHREADS; t++) {
      struct pair *p = &pairs[m][t];

      snprintf(p->key, sizeof(p->key), "right-%s-%d", mech_name[m], t);
      snprintf(p->wrong, sizeof(p->wrong), "wrong-%s-%d", mech_name[m], t);
      seed_salt(m, t, seed, sizeof(seed));

      full = ircd_crypt(p->key, seed);
      assert_non_null(full);
      if (m == M_NATIVE || m == M_BCRYPT) {
        /* untagged: the stored hash is crypt(3)'s output as is */
        assert_int_equal(strncmp(full, "$CRYPT$", 7), 0);
        p->stored = dup_plain(full + 7);
      } else {
        p->stored = dup_plain(full);
      }
      free(full);
      if (m == M_PBKDF2 || m == M_PBKDF2_512)
        assert_non_null(strstr(p->stored, "$1000$"));  /* the cheap setting */

      /* the stored hash verifies against the right key ... */
      full = ircd_crypt(p->key, p->stored);
      assert_non_null(full);
      assert_string_equal(full, p->stored);
      free(full);

      /* ... and not against the wrong one */
      p->for_wrong = ircd_crypt(p->wrong, p->stored);
      if (p->for_wrong)
        assert_string_not_equal(p->for_wrong, p->stored);
    }
  }
}

static void free_pairs(void)
{
  int m, t;
  for (m = 0; m < M_COUNT; m++)
    for (t = 0; t < NTHREADS; t++) {
      free(pairs[m][t].stored);
      free(pairs[m][t].for_wrong);
      pairs[m][t].stored = pairs[m][t].for_wrong = NULL;
    }
}

static int race_calls(void)
{
  const char *e = getenv("CRYPT_RACE_CALLS");
  int n = e ? atoi(e) : 0;
  return n > 0 ? n : 100;
}

/** Whether CRYPT_RACE_MECH (unset: every mechanism) selects mechanism m. */
static int mech_selected(int m)
{
  const char *e = getenv("CRYPT_RACE_MECH");
  return !e || !*e || !strcmp(mech_name[m], e);
}

static int group_setup(void **state)
{
  (void)state;
  ircd_crypt_init();
  make_pairs();
  return 0;
}

static int group_teardown(void **state)
{
  crypt_mechs_t *node, *next;
  (void)state;
  free_pairs();
  for (node = crypt_mechs_root->next; node; node = next) {
    next = node->next;
    free(node->mech);
    free(node);
  }
  free(crypt_mechs_root);
  crypt_mechs_root = NULL;
  return 0;
}

/* ------------------------------------------------------------------ */
/* ircd_crypt() from many threads at once                              */
/* ------------------------------------------------------------------ */

struct racer {
  enum mech m;
  int t;
  int calls;
  int *ready;        /* threads at the start line; all go together */
  long *mismatches;
};

static void *racer_main(void *arg)
{
  struct racer *r = arg;
  struct pair *p = &pairs[r->m][r->t];
  int i;

  __atomic_add_fetch(r->ready, 1, __ATOMIC_SEQ_CST);
  while (__atomic_load_n(r->ready, __ATOMIC_SEQ_CST) < NTHREADS)
    ;
  for (i = 0; i < r->calls; i++) {
    int right = !(i & 1);
    const char *want = right ? p->stored : p->for_wrong;
    char *got = ircd_crypt(right ? p->key : p->wrong, p->stored);
    int ok = (!got && !want) || (got && want && !strcmp(got, want));

    if (!ok)
      __atomic_add_fetch(r->mismatches, 1, __ATOMIC_SEQ_CST);
    free(got);
  }
  return NULL;
}

/* NTHREADS threads run ircd_crypt() at once on the same mechanism, each
 * with its own key and stored hash, alternating the right key and a
 * wrong one; every result must be the one ircd_crypt() gives with nothing
 * else running. */
static void test_concurrent_ircd_crypt_gets_its_own_result(void **state)
{
  pthread_t tid[NTHREADS];
  struct racer racers[NTHREADS];
  int ready;
  long mismatches[M_COUNT];
  long total = 0, calls = 0;
  long before = blocks_held();
  int m, t;

  (void)state;

  for (m = 0; m < M_COUNT; m++) {
    mismatches[m] = 0;
    if (!mech_selected(m))
      continue;
    ready = 0;
    for (t = 0; t < NTHREADS; t++) {
      racers[t].m = m;
      racers[t].t = t;
      racers[t].calls = race_calls();
      racers[t].ready = &ready;
      racers[t].mismatches = &mismatches[m];
      assert_int_equal(pthread_create(&tid[t], NULL, racer_main, &racers[t]), 0);
    }
    for (t = 0; t < NTHREADS; t++)
      pthread_join(tid[t], NULL);

    calls += (long)NTHREADS * race_calls();
    total += mismatches[m];
    print_message("  %-16s %ld of %d results were another check's\n",
                  mech_name[m], mismatches[m], NTHREADS * race_calls());
  }

  print_message("  %ld wrong results in %ld concurrent ircd_crypt() calls\n",
                total, calls);
  assert_int_equal(total, 0);
  assert_int_equal(blocks_held(), before);
}

/* ------------------------------------------------------------------ */
/* A direct mechanism caller (m_mkpasswd) under the same lock          */
/* ------------------------------------------------------------------ */

struct waiter {
  struct pair *p;
  int finished;
  char *got;
};

static void *waiter_main(void *arg)
{
  struct waiter *w = arg;
  w->got = ircd_crypt(w->p->key, w->p->stored);
  __atomic_store_n(&w->finished, 1, __ATOMIC_SEQ_CST);
  return NULL;
}

/* ircd_crypt() takes the lock a direct mechanism caller holds: while it is
 * held, a check on another thread waits, and runs once it is released. */
static void test_ircd_crypt_waits_for_the_crypt_lock(void **state)
{
  struct waiter w;
  pthread_t tid;

  (void)state;
  w.p = &pairs[M_SMD5][0];
  w.finished = 0;
  w.got = NULL;

  ircd_crypt_lock();
  assert_int_equal(pthread_create(&tid, NULL, waiter_main, &w), 0);
  usleep(200 * 1000);
  assert_int_equal(__atomic_load_n(&w.finished, __ATOMIC_SEQ_CST), 0);
  ircd_crypt_unlock();

  pthread_join(tid, NULL);
  assert_int_equal(w.finished, 1);
  assert_non_null(w.got);
  assert_string_equal(w.got, w.p->stored);
  free(w.got);
}

struct direct {
  int t;
  int calls;
  int *ready;
  long *mismatches;
};

/* m_mkpasswd's pattern: the mechanism itself, called and copied out under
 * the crypt lock.  Odd threads call smd5, even threads crypt(3). */
static void *direct_main(void *arg)
{
  struct direct *d = arg;
  int smd5 = d->t & 1;
  struct pair *p = &pairs[smd5 ? M_SMD5 : M_NATIVE][d->t];
  /* smd5 takes its stored hash untagged: "salt$hash" */
  const char *salt = smd5 ? p->stored + 6 : p->stored;
  char got[256];
  int i;

  __atomic_add_fetch(d->ready, 1, __ATOMIC_SEQ_CST);
  while (__atomic_load_n(d->ready, __ATOMIC_SEQ_CST) < NTHREADS)
    ;
  for (i = 0; i < d->calls; i++) {
    const char *r;

    ircd_crypt_lock();
    r = smd5 ? ircd_crypt_smd5(p->key, salt) : ircd_crypt_native(p->key, salt);
    snprintf(got, sizeof(got), "%s", r ? r : "");
    ircd_crypt_unlock();

    if (strcmp(got, salt))
      __atomic_add_fetch(d->mismatches, 1, __ATOMIC_SEQ_CST);
  }
  return NULL;
}

/* Direct mechanism callers holding the lock (as m_mkpasswd does) beside
 * ircd_crypt() callers on the same two buffers: each gets its own result. */
static void test_direct_mechanism_calls_under_the_lock(void **state)
{
  pthread_t tid[NTHREADS];
  struct racer racers[NTHREADS];
  struct direct directs[NTHREADS];
  int ready = 0;
  long direct_bad = 0, crypt_bad = 0;
  int t;

  (void)state;

  for (t = 0; t < NTHREADS; t++) {
    if (t < NTHREADS / 2) {
      directs[t].t = t;
      directs[t].calls = race_calls();
      directs[t].ready = &ready;
      directs[t].mismatches = &direct_bad;
      assert_int_equal(pthread_create(&tid[t], NULL, direct_main, &directs[t]), 0);
    } else {
      racers[t].m = (t & 1) ? M_SMD5 : M_NATIVE;
      racers[t].t = t;
      racers[t].calls = race_calls();
      racers[t].ready = &ready;
      racers[t].mismatches = &crypt_bad;
      assert_int_equal(pthread_create(&tid[t], NULL, racer_main, &racers[t]), 0);
    }
  }
  for (t = 0; t < NTHREADS; t++)
    pthread_join(tid[t], NULL);

  print_message("  direct calls: %ld wrong; ircd_crypt() calls: %ld wrong "
                "(of %d each)\n", direct_bad, crypt_bad,
                NTHREADS / 2 * race_calls());
  assert_int_equal(direct_bad, 0);
  assert_int_equal(crypt_bad, 0);
}

/* ------------------------------------------------------------------ */
/* The async check, through the real thread pool                       */
/* ------------------------------------------------------------------ */

#define ASYNC_WORKERS 8

struct verdict {
  int done;
  int result;
};

static void verified(int result, void *ctx)
{
  struct verdict *v = ctx;   /* runs on the main thread, in thread_pool_poll() */
  v->result = result;
  v->done = 1;
}

/** Run the main loop's share: wait for a completion signal, deliver them. */
static void pump(int timeout_ms)
{
  struct pollfd pfd;
  pfd.fd = thread_pool_get_signal_fd();
  pfd.events = POLLIN;
  pfd.revents = 0;
  poll(&pfd, 1, timeout_ms);
  thread_pool_poll();
}

/** Submit a check, waiting for room when the queue is full. */
static void submit(const char *password, const char *hash, struct verdict *v)
{
  int tries = 0;
  v->done = 0;
  v->result = 99;
  while (ircd_crypt_verify_async(password, hash, verified, v) < 0) {
    assert_true(++tries < 10000);
    pump(10);
  }
}

static int all_done(struct verdict *v, int n)
{
  int i;
  for (i = 0; i < n; i++)
    if (!v[i].done)
      return 0;
  return 1;
}

static void wait_all(struct verdict *v, int n)
{
  time_t deadline = time(NULL) + 300;
  while (!all_done(v, n)) {
    assert_true(time(NULL) < deadline);
    pump(100);
  }
}

static int pool_setup(void **state)
{
  (void)state;
  return thread_pool_init(ASYNC_WORKERS);
}

static int pool_teardown(void **state)
{
  (void)state;
  thread_pool_shutdown();
  return 0;
}

/* An async check gives back every block it took, the hash it computed
 * included, once its callback has run. */
static void test_async_check_frees_what_it_computed(void **state)
{
  struct verdict v[2];
  struct pair *p = &pairs[M_SMD5][0];
  long before;

  (void)state;
  assert_true(ircd_crypt_async_available());

  /* one at a time: this case is about the blocks, not the race */
  before = blocks_held();
  submit(p->key, p->stored, &v[0]);
  wait_all(&v[0], 1);
  submit(p->wrong, p->stored, &v[1]);
  wait_all(&v[1], 1);

  assert_int_equal(v[0].result, CRYPT_VERIFY_MATCH);
  assert_int_equal(v[1].result, CRYPT_VERIFY_NOMATCH);
  print_message("  %ld block(s) still held after 2 async checks\n",
                blocks_held() - before);
  assert_int_equal(blocks_held(), before);
}

#ifndef SHARED_CHECKS
#define SHARED_CHECKS 400   /* per mechanism; -DSHARED_CHECKS=n for more */
#endif

/* A shared password (one WEBIRC, SETHOST or OPER block) checked by many
 * clients at once: the right password and wrong ones against the SAME
 * stored hash, on every worker.  A right one always matches, a wrong one
 * never does, and nothing is left held. */
static void test_async_shared_hash_wrong_password_never_matches(void **state)
{
  static struct verdict v[SHARED_CHECKS];
  long right_failed[M_COUNT], wrong_matched[M_COUNT];
  long right_total = 0, wrong_total = 0, checks = 0;
  long before;
  int m, i;

  (void)state;
  assert_true(ircd_crypt_async_available());

  before = blocks_held();
  for (m = 0; m < M_COUNT; m++) {
    struct pair *p = &pairs[m][0];

    right_failed[m] = wrong_matched[m] = 0;
    if (!mech_selected(m))
      continue;
    for (i = 0; i < SHARED_CHECKS; i++)
      submit((i & 1) ? p->wrong : p->key, p->stored, &v[i]);
    wait_all(v, SHARED_CHECKS);
    checks += SHARED_CHECKS;

    for (i = 0; i < SHARED_CHECKS; i++) {
      if (i & 1) {
        if (v[i].result == CRYPT_VERIFY_MATCH)
          wrong_matched[m]++;
      } else if (v[i].result != CRYPT_VERIFY_MATCH) {
        right_failed[m]++;
      }
    }
    right_total += right_failed[m];
    wrong_total += wrong_matched[m];
    print_message("  %-16s right password failed %ld/%d, wrong password "
                  "matched %ld/%d\n", mech_name[m], right_failed[m],
                  SHARED_CHECKS / 2, wrong_matched[m], SHARED_CHECKS / 2);
  }

  print_message("  %ld block(s) still held after %ld async checks\n",
                blocks_held() - before, checks);
  assert_int_equal(wrong_total, 0);
  assert_int_equal(right_total, 0);
  assert_int_equal(blocks_held(), before);
}

int main(void)
{
  /* CRYPT_TEST_FILTER runs only the matching cases (cmocka's pattern). */
  const char *filter = getenv("CRYPT_TEST_FILTER");
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_concurrent_ircd_crypt_gets_its_own_result),
    cmocka_unit_test(test_ircd_crypt_waits_for_the_crypt_lock),
    cmocka_unit_test(test_direct_mechanism_calls_under_the_lock),
    cmocka_unit_test_setup_teardown(test_async_check_frees_what_it_computed,
                                    pool_setup, pool_teardown),
    cmocka_unit_test_setup_teardown(test_async_shared_hash_wrong_password_never_matches,
                                    pool_setup, pool_teardown),
  };

  if (filter && *filter)
    cmocka_set_test_filter(filter);
  return cmocka_run_group_tests(tests, group_setup, group_teardown);
}

#else /* !HAVE_PTHREAD */

int main(void)
{
  puts("ircd_crypt_concurrency_cmocka: built without pthreads, no thread "
       "pool and nothing runs at once");
  return 0;
}

#endif /* HAVE_PTHREAD */
