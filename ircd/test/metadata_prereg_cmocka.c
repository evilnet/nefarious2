/* cmocka suite for the before-connect merge rule (include/metadata_prereg.h):
 * what a client's METADATA writes made before registration do to the
 * account it logs in to during registration.  The merge loop under test is
 * the ircd's own (md_prereg_merge()); only its outward calls -- the store,
 * telling the account's connections, sending to peers, refusing -- are the
 * suite's fakes, over a small in-memory account. */
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <cmocka.h>

#include "../../include/metadata_prereg.h"

#define VIS_PUBLIC  0
#define VIS_PRIVATE 1

static struct md_version live(uint64_t ms, const char *value, int vis)
{
  struct md_version v;

  memset(&v, 0, sizeof(v));
  v.st.ms = ms;
  v.st.node = 1;
  v.vis = vis;
  v.value = value;
  v.vlen = strlen(value);
  return v;
}

static struct md_version tomb(uint64_t ms)
{
  struct md_version v;

  memset(&v, 0, sizeof(v));
  v.st.ms = ms;
  v.st.node = 1;
  v.tombstone = 1;
  return v;
}

/* --- The fake account (a store's rows), and what the merge told whom --- */
#define ACCT_MAX 16
#define LOG_MAX 32
struct acct_row { char key[MD_PREREG_KEY_LEN]; char value[64]; struct md_version v; int used; };
struct fake {
  struct acct_row rows[ACCT_MAX];
  int store_fails;                    /* row() and store() fail */
  int store_keeps;                    /* store() keeps its own row (0) */
  const char *mode_key;               /* the one key whose no-row is a state */
  int napplied, nsent, nrefused;
  char applied[LOG_MAX][MD_PREREG_KEY_LEN];
  char sent[LOG_MAX][MD_PREREG_KEY_LEN];
  struct md_stamp sent_st[LOG_MAX];
  char refused[LOG_MAX][MD_PREREG_KEY_LEN];
  enum md_prereg_verdict refused_why[LOG_MAX];
};

static struct acct_row *row_find(struct fake *f, const char *key)
{
  int i;

  for (i = 0; i < ACCT_MAX; i++)
    if (f->rows[i].used && !strcmp(f->rows[i].key, key))
      return &f->rows[i];
  return NULL;
}

static void row_put(struct fake *f, const char *key, const struct md_version *v)
{
  struct acct_row *r = row_find(f, key);
  int i;

  if (!r)
    for (i = 0; i < ACCT_MAX && !r; i++)
      if (!f->rows[i].used)
        r = &f->rows[i];
  assert_non_null(r);
  strcpy(r->key, key);
  r->v = *v;
  if (!v->tombstone) {
    assert_true(v->vlen < sizeof(r->value));
    memcpy(r->value, v->value, v->vlen);
    r->value[v->vlen] = '\0';
    r->v.value = r->value;
  } else
    r->v.value = NULL;
  r->used = 1;
}

/* The receiving end of a peer's row (ms_metadata_stamped): LWW. */
static int lww_merge(struct fake *f, const char *key, const struct md_version *in)
{
  struct acct_row *r = row_find(f, key);

  if (!md_lww_take(r ? &r->v : NULL, in))
    return 0;
  row_put(f, key, in);
  return 1;
}

static int f_row(void *ctx, const char *key, struct md_version *out,
                 char *valbuf, size_t vlen)
{
  struct fake *f = ctx;
  struct acct_row *r = row_find(f, key);

  if (f->store_fails)
    return -1;
  if (!r)
    return 1;
  *out = r->v;
  if (!r->v.tombstone) {
    assert_true(r->v.vlen < vlen);
    memcpy(valbuf, r->value, r->v.vlen + 1);
    out->value = valbuf;
  }
  return 0;
}

static int f_store(void *ctx, const char *key, const struct md_version *w)
{
  struct fake *f = ctx;

  if (f->store_fails)
    return -1;
  if (f->store_keeps)
    return 0;
  return lww_merge(f, key, w);
}

static void f_apply(void *ctx, const char *key, const struct md_version *w)
{
  struct fake *f = ctx;

  (void)w;
  assert_true(f->napplied < LOG_MAX);
  strcpy(f->applied[f->napplied++], key);
}

static void f_send(void *ctx, const char *key, const struct md_version *w)
{
  struct fake *f = ctx;

  assert_true(f->nsent < LOG_MAX);
  f->sent_st[f->nsent] = w->st;
  strcpy(f->sent[f->nsent++], key);
}

static void f_refuse(void *ctx, const char *key, enum md_prereg_verdict why)
{
  struct fake *f = ctx;

  assert_true(f->nrefused < LOG_MAX);
  f->refused_why[f->nrefused] = why;
  strcpy(f->refused[f->nrefused++], key);
}

static int f_no_row_is_state(void *ctx, const char *key)
{
  struct fake *f = ctx;

  return f->mode_key && !strcmp(f->mode_key, key);
}

/* Every live key, collected first (the ircd's walk does the same). */
static void f_clear_keys(void *ctx, void (*each)(void *arg, const char *key, int vis),
                         void *arg)
{
  struct fake *f = ctx;
  char keys[ACCT_MAX][MD_PREREG_KEY_LEN];
  int vis[ACCT_MAX];
  int i, n = 0;

  for (i = 0; i < ACCT_MAX; i++)
    if (f->rows[i].used && !f->rows[i].v.tombstone) {
      strcpy(keys[n], f->rows[i].key);
      vis[n++] = f->rows[i].v.vis;
    }
  for (i = 0; i < n; i++)
    each(arg, keys[i], vis[i]);
}

static const struct md_prereg_ops store_ops = {
  f_row, f_store, f_apply, f_send, f_refuse, f_no_row_is_state, f_clear_keys
};
static const struct md_prereg_ops nostore_ops = {
  NULL, NULL, f_apply, f_send, f_refuse, f_no_row_is_state, NULL
};

static int live_keys(const struct fake *f)
{
  int i, n = 0;

  for (i = 0; i < ACCT_MAX; i++)
    if (f->rows[i].used && !f->rows[i].v.tombstone)
      n++;
  return n;
}

static const char *value_of(struct fake *f, const char *key)
{
  struct acct_row *r = row_find(f, key);

  return (r && !r->v.tombstone) ? r->value : NULL;
}

static int logged(char log[][MD_PREREG_KEY_LEN], int n, const char *key)
{
  int i;

  for (i = 0; i < n; i++)
    if (!strcmp(log[i], key))
      return 1;
  return 0;
}

/* --- The client's notes ------------------------------------------------- */
#define NOTES_MAX 8
struct notes { struct MetadataPrereg n[NOTES_MAX]; int count; };

static void note(struct notes *ns, const char *key, const char *value, uint64_t ms)
{
  struct MetadataPrereg *p = &ns->n[ns->count];

  assert_true(ns->count < NOTES_MAX);
  memset(p, 0, sizeof(*p));
  strcpy(p->key, key);
  p->value = (char *)value;
  p->visibility = VIS_PUBLIC;
  p->st.ms = ms;
  p->st.node = 2;
  if (ns->count)
    ns->n[ns->count - 1].next = p;
  ns->count++;
}

/* A CLEAR noted in place (a hand-built list may put notes before it). */
static void note_clear(struct notes *ns, uint64_t ms)
{
  note(ns, "", NULL, ms);
  ns->n[ns->count - 1].clear = 1;
}

/* The ircd's merge, the ircd's way: the account's live key count, the cap. */
static int merge(struct fake *f, struct notes *ns, int max_keys)
{
  return md_prereg_merge(ns->count ? &ns->n[0] : NULL, live_keys(f), max_keys,
                         300, &store_ops, f);
}

/* ------------------------------------------------------------------ */

static void test_should_merge(void **state)
{
  (void)state;
  assert_true(md_prereg_should_merge(1, 1));
  assert_false(md_prereg_should_merge(0, 1));   /* no login: its own keys */
  assert_false(md_prereg_should_merge(1, 0));   /* never metadata-aware */
  assert_false(md_prereg_should_merge(0, 0));
}

/* The before-connect value wins for its key, is stored, told and sent;
 * every other key is the account's, untouched. */
static void test_prereg_wins_per_key_untouched_from_account(void **state)
{
  struct fake f;
  struct notes ns;
  struct md_version v;

  (void)state;
  memset(&f, 0, sizeof(f));
  memset(&ns, 0, sizeof(ns));
  v = live(100, "stored", VIS_PUBLIC); row_put(&f, "display-name", &v);
  v = live(100, "they", VIS_PUBLIC);   row_put(&f, "pronouns", &v);
  v = live(100, "http://x", VIS_PRIVATE); row_put(&f, "url", &v);

  note(&ns, "display-name", "mine", 200);
  note(&ns, "status", "here", 201);
  assert_int_equal(merge(&f, &ns, 20), 2);

  assert_string_equal(value_of(&f, "display-name"), "mine");
  assert_true(row_find(&f, "display-name")->v.st.ms == 200);   /* the SET's time */
  assert_string_equal(value_of(&f, "status"), "here");
  assert_string_equal(value_of(&f, "pronouns"), "they");
  assert_string_equal(value_of(&f, "url"), "http://x");
  assert_int_equal(row_find(&f, "url")->v.vis, VIS_PRIVATE);
  assert_int_equal(f.napplied, 2);
  assert_int_equal(f.nsent, 2);
  assert_false(logged(f.applied, f.napplied, "pronouns"));
  assert_false(logged(f.sent, f.nsent, "pronouns"));
  assert_int_equal(f.nrefused, 0);
}

/* An identical value tells nobody on this server (the peers that take its
 * row announce it as for any SET).  Under an older stamp it is still
 * stored and sent under the SET's (review a1: the login's pull would
 * otherwise bring back a peer's write this server missed); under a newer
 * or equal one, nothing at all.  The same value at another visibility is
 * a change. */
static void test_identical_value(void **state)
{
  struct md_version stored = live(100, "same", VIS_PUBLIC);
  struct md_version w = live(500, "same", VIS_PUBLIC);
  struct md_version wp = live(500, "same", VIS_PRIVATE);
  int keys = 3;

  (void)state;
  assert_int_equal(md_prereg_decide(&stored, &w, 0, &keys, 20, 300), MD_PREREG_STAMP);
  assert_int_equal(keys, 3);
  assert_int_equal(md_prereg_decide(&stored, &wp, 0, &keys, 20, 300), MD_PREREG_APPLY);
  assert_int_equal(keys, 3);
  stored.st.ms = 900;
  assert_int_equal(md_prereg_decide(&stored, &w, 0, &keys, 20, 300), MD_PREREG_SAME);
  stored.st.ms = 500;
  stored.st.node = 2;
  w.st.node = 2;
  assert_int_equal(md_prereg_decide(&stored, &w, 0, &keys, 20, 300), MD_PREREG_SAME);
}

/* Review a1, the scenario: this server holds k=v@100, a peer k=w@150 this
 * server missed during a split; the client's SET k v is @200.  The merge
 * stores and sends v@200 and tells nobody here; the login's pull then brings
 * w@150, which loses. */
static void test_same_value_survives_the_pull(void **state)
{
  struct fake f;
  struct notes ns;
  struct md_version v = live(100, "v", VIS_PUBLIC);
  struct md_version peer = live(150, "w", VIS_PUBLIC);

  (void)state;
  memset(&f, 0, sizeof(f));
  memset(&ns, 0, sizeof(ns));
  row_put(&f, "k", &v);
  note(&ns, "k", "v", 200);
  assert_int_equal(merge(&f, &ns, 20), 0);
  assert_int_equal(f.napplied, 0);              /* nothing changed here */
  assert_int_equal(f.nsent, 1);
  assert_true(f.sent_st[0].ms == 200);
  assert_true(row_find(&f, "k")->v.st.ms == 200);

  assert_int_equal(lww_merge(&f, "k", &peer), 0);   /* the pull's answer */
  assert_string_equal(value_of(&f, "k"), "v");
}

/* A delete: of a stored key, applied (one key fewer); of a key with no row
 * here, a tombstone stored and sent under the SET's stamp, nobody here told --
 * a peer's older row then loses; of a key already deleted here, the same
 * when the SET is newer, else nothing. */
static void test_delete(void **state)
{
  struct fake f;
  struct notes ns;
  struct md_version v = live(100, "x", VIS_PUBLIC);
  struct md_version gone_old = tomb(50);
  struct md_version gone_new = tomb(900);
  struct md_version peer = live(150, "w", VIS_PUBLIC);

  (void)state;
  memset(&f, 0, sizeof(f));
  memset(&ns, 0, sizeof(ns));
  row_put(&f, "held", &v);
  row_put(&f, "old", &gone_old);
  row_put(&f, "new", &gone_new);
  note(&ns, "held", NULL, 200);
  note(&ns, "nowhere", NULL, 201);
  note(&ns, "old", NULL, 202);
  note(&ns, "new", NULL, 203);
  assert_int_equal(merge(&f, &ns, 20), 1);

  assert_null(value_of(&f, "held"));
  assert_true(logged(f.applied, f.napplied, "held"));
  assert_int_equal(f.napplied, 1);
  assert_true(logged(f.sent, f.nsent, "held"));
  assert_true(logged(f.sent, f.nsent, "nowhere"));
  assert_true(logged(f.sent, f.nsent, "old"));
  assert_false(logged(f.sent, f.nsent, "new"));
  assert_true(row_find(&f, "nowhere")->v.tombstone);
  assert_true(row_find(&f, "nowhere")->v.st.ms == 201);
  assert_true(row_find(&f, "old")->v.st.ms == 202);
  assert_true(row_find(&f, "new")->v.st.ms == 900);

  assert_int_equal(lww_merge(&f, "nowhere", &peer), 0);   /* the pull's answer */
  assert_null(value_of(&f, "nowhere"));
}

/* A delete of a mode-synced key with no row: a tombstone turns the mode
 * off where no row left the default -- the account's connections change,
 * so it is applied (told), not only stamped. */
static void test_delete_of_a_mode_key_without_row(void **state)
{
  struct fake f;
  struct notes ns;
  int keys = 0;
  struct md_version d = tomb(200);

  (void)state;
  assert_int_equal(md_prereg_decide(NULL, &d, 1, &keys, 20, 300), MD_PREREG_APPLY);
  assert_int_equal(keys, 0);

  memset(&f, 0, sizeof(f));
  memset(&ns, 0, sizeof(ns));
  f.mode_key = "umode.invisible";
  note(&ns, "umode.invisible", NULL, 200);
  assert_int_equal(merge(&f, &ns, 20), 1);
  assert_true(logged(f.applied, f.napplied, "umode.invisible"));
  assert_true(row_find(&f, "umode.invisible")->v.tombstone);
}

/* The account's row written after the client's SET (a newer stamp) stands,
 * for a set and for a delete; a row never stamped (0.0.0) is older than
 * anything. */
static void test_newer_account_row_stands(void **state)
{
  struct md_version stored = live(300, "later", VIS_PUBLIC);
  struct md_version later_delete = tomb(300);
  struct md_version legacy = live(0, "old", VIS_PUBLIC);
  struct md_version w = live(200, "mine", VIS_PUBLIC);
  struct md_version del = tomb(200);
  int keys = 1;

  (void)state;
  legacy.st.node = 0;
  assert_int_equal(md_prereg_decide(&stored, &w, 0, &keys, 20, 300), MD_PREREG_SUPERSEDED);
  assert_int_equal(md_prereg_decide(&stored, &del, 0, &keys, 20, 300), MD_PREREG_SUPERSEDED);
  assert_int_equal(md_prereg_decide(&later_delete, &w, 0, &keys, 20, 300), MD_PREREG_SUPERSEDED);
  assert_int_equal(keys, 1);
  assert_int_equal(md_prereg_decide(&legacy, &w, 0, &keys, 20, 300), MD_PREREG_APPLY);
  assert_int_equal(keys, 1);
}

/* Over the key cap at the merge: a new key is refused (LIMIT_KEYS, before
 * anything is stored for it), an update of a key the account holds fits,
 * and a delete the client sent earlier frees a place for a later new key. */
static void test_over_cap(void **state)
{
  struct fake f;
  struct notes ns;
  struct md_version v;

  (void)state;
  memset(&f, 0, sizeof(f));
  memset(&ns, 0, sizeof(ns));
  v = live(100, "a", VIS_PUBLIC); row_put(&f, "k1", &v);
  v = live(100, "b", VIS_PUBLIC); row_put(&f, "k2", &v);
  v = live(100, "c", VIS_PUBLIC); row_put(&f, "k3", &v);
  v = live(100, "d", VIS_PUBLIC); row_put(&f, "k4", &v);

  note(&ns, "k5", "new", 200);
  note(&ns, "k1", "changed", 201);
  note(&ns, "k2", NULL, 202);
  note(&ns, "k6", "fits", 203);
  assert_int_equal(merge(&f, &ns, 4), 3);

  assert_int_equal(f.nrefused, 1);
  assert_string_equal(f.refused[0], "k5");
  assert_int_equal(f.refused_why[0], MD_PREREG_LIMIT_KEYS);
  assert_null(row_find(&f, "k5"));
  assert_false(logged(f.sent, f.nsent, "k5"));
  assert_string_equal(value_of(&f, "k1"), "changed");
  assert_null(value_of(&f, "k2"));
  assert_string_equal(value_of(&f, "k6"), "fits");
  assert_int_equal(live_keys(&f), 4);
}

/* A negative METADATA_MAX_KEYS is 0, as metadata_check_limits() reads it. */
static void test_negative_cap_is_zero(void **state)
{
  struct md_version w = live(200, "v", VIS_PUBLIC);
  int keys = 0;

  (void)state;
  assert_int_equal(md_prereg_decide(NULL, &w, 0, &keys, -1, 300), MD_PREREG_LIMIT_KEYS);
  assert_int_equal(keys, 0);
}

/* A value over the value limit at the merge (lowered since the SET). */
static void test_value_limit(void **state)
{
  struct md_version w = live(200, "0123456789", VIS_PUBLIC);
  struct md_version stored = live(100, "short", VIS_PUBLIC);
  int keys = 1;

  (void)state;
  assert_int_equal(md_prereg_decide(&stored, &w, 0, &keys, 20, 9), MD_PREREG_LIMIT_VALUE);
  assert_int_equal(md_prereg_decide(&stored, &w, 0, &keys, 20, 10), MD_PREREG_APPLY);
  assert_int_equal(keys, 1);
}

/* A store that fails: the write is reported, nothing told or sent. */
static void test_store_error(void **state)
{
  struct fake f;
  struct notes ns;

  (void)state;
  memset(&f, 0, sizeof(f));
  memset(&ns, 0, sizeof(ns));
  f.store_fails = 1;
  note(&ns, "k", "v", 200);
  assert_int_equal(merge(&f, &ns, 20), 0);
  assert_int_equal(f.nrefused, 1);
  assert_int_equal(f.refused_why[0], MD_PREREG_ERROR);
  assert_int_equal(f.napplied + f.nsent, 0);
}

/* Review 2, item 1: the value limit comes before the identical-value test.
 * After a rehash lowers METADATA_MAX_VALUE_BYTES, a value identical to the
 * account's (now over the limit) is refused, as a SET is -- not re-stamped
 * and sent to peers whose limit refuses it. */
static void test_value_limit_before_identical(void **state)
{
  struct fake f;
  struct notes ns;
  struct md_version stored = live(100, "0123456789", VIS_PUBLIC);
  struct md_version w = live(200, "0123456789", VIS_PUBLIC);
  int keys = 1;

  (void)state;
  assert_int_equal(md_prereg_decide(&stored, &w, 0, &keys, 20, 9), MD_PREREG_LIMIT_VALUE);
  assert_int_equal(md_prereg_decide(&stored, &w, 0, &keys, 20, 10), MD_PREREG_STAMP);

  memset(&f, 0, sizeof(f));
  memset(&ns, 0, sizeof(ns));
  row_put(&f, "k", &stored);
  note(&ns, "k", "0123456789", 200);
  assert_int_equal(md_prereg_merge(&ns.n[0], 1, 20, 9, &store_ops, &f), 0);
  assert_int_equal(f.nrefused, 1);
  assert_int_equal(f.refused_why[0], MD_PREREG_LIMIT_VALUE);
  assert_int_equal(f.nsent + f.napplied, 0);
  assert_true(row_find(&f, "k")->v.st.ms == 100);
}

/* Review 2, item 2: a store that keeps its own row although the decision
 * read the write as the newer -- the write is lost: reported as an error
 * (as 523f91c3 did), nothing told or sent. */
static void test_store_keeps_its_row(void **state)
{
  struct fake f;
  struct notes ns;

  (void)state;
  memset(&f, 0, sizeof(f));
  memset(&ns, 0, sizeof(ns));
  f.store_keeps = 1;
  note(&ns, "k", "v", 200);
  note(&ns, "gone", NULL, 201);
  assert_int_equal(merge(&f, &ns, 20), 0);
  assert_int_equal(f.nrefused, 2);
  assert_int_equal(f.refused_why[0], MD_PREREG_ERROR);
  assert_int_equal(f.refused_why[1], MD_PREREG_ERROR);
  assert_int_equal(f.napplied + f.nsent, 0);
}

/* No store: every key reads as no row -- a set is applied and sent, a
 * delete sent only. */
static void test_no_store(void **state)
{
  struct fake f;
  struct notes ns;

  (void)state;
  memset(&f, 0, sizeof(f));
  memset(&ns, 0, sizeof(ns));
  note(&ns, "a", "1", 200);
  note(&ns, "b", NULL, 201);
  assert_int_equal(md_prereg_merge(&ns.n[0], 0, INT_MAX, 300, &nostore_ops, &f), 1);
  assert_true(logged(f.applied, f.napplied, "a"));
  assert_false(logged(f.applied, f.napplied, "b"));
  assert_int_equal(f.nsent, 2);
}

/* The note list's own bound: METADATA_MAX_KEYS sets and as many deletes;
 * a key already noted is replaced, counted in its new kind. */
static void test_note_bound(void **state)
{
  struct notes ns;
  (void)state;
  memset(&ns, 0, sizeof(ns));
  assert_true(md_prereg_fits(NULL, "a", 0, 2));
  assert_false(md_prereg_fits(NULL, "a", 0, 0));
  assert_false(md_prereg_fits(NULL, "a", 1, -1));
  note(&ns, "s1", "1", 1);
  note(&ns, "s2", "2", 2);
  note(&ns, "d1", NULL, 3);
  assert_false(md_prereg_fits(&ns.n[0], "s3", 0, 2));   /* a third set */
  assert_true(md_prereg_fits(&ns.n[0], "s1", 0, 2));    /* a set replaced */
  assert_true(md_prereg_fits(&ns.n[0], "d2", 1, 2));    /* a second delete */
  assert_true(md_prereg_fits(&ns.n[0], "S1", 1, 2));    /* s1 becomes a delete */
  assert_true(md_prereg_fits(&ns.n[0], "d1", 1, 1));    /* d1 replaced */
  assert_false(md_prereg_fits(&ns.n[0], "d2", 1, 1));
  /* A CLEAR is not a delete note: it does not count. */
  memset(&ns, 0, sizeof(ns));
  note_clear(&ns, 1);
  note(&ns, "d1", NULL, 2);
  assert_true(md_prereg_fits(&ns.n[0], "d2", 1, 2));
  assert_false(md_prereg_fits(&ns.n[0], "d2", 1, 1));
}

/* --- A CLEAR before registration (owner, 2026-11-13: it clears it all) --- */

static int released;
static void count_release(struct MetadataPrereg *n) { (void)n; released++; }

/* Noting a CLEAR voids every earlier note; a second CLEAR replaces the
 * first. */
static void test_note_clear(void **state)
{
  struct notes ns;
  struct MetadataPrereg *list, m1, m2;

  (void)state;
  memset(&ns, 0, sizeof(ns));
  memset(&m1, 0, sizeof(m1));
  memset(&m2, 0, sizeof(m2));
  note(&ns, "a", "1", 1);
  note(&ns, "b", NULL, 2);
  list = &ns.n[0];
  released = 0;
  m1.st.ms = 3;
  md_prereg_note_clear(&list, &m1, count_release);
  assert_int_equal(released, 2);
  assert_ptr_equal(list, &m1);
  assert_true(m1.clear);
  assert_null(m1.next);
  m2.st.ms = 4;
  md_prereg_note_clear(&list, &m2, count_release);
  assert_int_equal(released, 3);
  assert_ptr_equal(list, &m2);
}

/* A CLEAR then a set: every live key of the account is deleted under the
 * CLEAR's stamp (told and sent), then the set applies -- including a set
 * of a key the CLEAR just deleted. */
static void test_clear_then_set(void **state)
{
  struct fake f;
  struct notes ns;
  struct md_version v;

  (void)state;
  memset(&f, 0, sizeof(f));
  memset(&ns, 0, sizeof(ns));
  v = live(100, "x", VIS_PUBLIC);  row_put(&f, "a", &v);
  v = live(100, "y", VIS_PRIVATE); row_put(&f, "b", &v);
  v = tomb(100);                   row_put(&f, "c", &v);
  note_clear(&ns, 200);
  note(&ns, "b", "new", 201);
  assert_int_equal(merge(&f, &ns, 20), 3);   /* a, b deleted; b set */
  assert_null(value_of(&f, "a"));
  assert_true(row_find(&f, "a")->v.st.ms == 200);
  assert_string_equal(value_of(&f, "b"), "new");
  assert_true(row_find(&f, "b")->v.st.ms == 201);
  assert_true(row_find(&f, "c")->v.st.ms == 100);   /* already gone: untouched */
  assert_true(logged(f.applied, f.napplied, "a"));
  assert_true(logged(f.sent, f.nsent, "a"));
  assert_int_equal(f.nsent, 3);
}

/* Notes before a CLEAR never apply (a hand-built list: the ircd voids them
 * when the CLEAR is noted, the merge as well); with two CLEARs only the
 * last counts. */
static void test_set_then_clear_and_two_clears(void **state)
{
  struct fake f;
  struct notes ns;
  struct md_version v;

  (void)state;
  memset(&f, 0, sizeof(f));
  memset(&ns, 0, sizeof(ns));
  v = live(100, "x", VIS_PUBLIC); row_put(&f, "a", &v);
  note(&ns, "early", "1", 200);
  note_clear(&ns, 201);
  note(&ns, "mid", "2", 202);
  note_clear(&ns, 203);
  note(&ns, "late", "3", 204);
  merge(&f, &ns, 20);
  assert_null(row_find(&f, "early"));
  assert_null(row_find(&f, "mid"));
  assert_string_equal(value_of(&f, "late"), "3");
  assert_null(value_of(&f, "a"));
  assert_true(row_find(&f, "a")->v.st.ms == 203);   /* the last CLEAR's stamp */
}

/* A row written after the CLEAR (another device, another server) stands. */
static void test_clear_newer_row_survives(void **state)
{
  struct fake f;
  struct notes ns;
  struct md_version v;

  (void)state;
  memset(&f, 0, sizeof(f));
  memset(&ns, 0, sizeof(ns));
  v = live(300, "later", VIS_PUBLIC); row_put(&f, "a", &v);
  v = live(100, "old", VIS_PUBLIC);   row_put(&f, "b", &v);
  note_clear(&ns, 200);
  assert_int_equal(merge(&f, &ns, 20), 1);
  assert_string_equal(value_of(&f, "a"), "later");
  assert_false(logged(f.sent, f.nsent, "a"));
  assert_null(value_of(&f, "b"));
}

/* The CLEAR frees places: an account at its cap takes as many new keys
 * after it; without it the first new key is refused. */
static void test_clear_and_the_cap(void **state)
{
  struct fake f;
  struct notes ns;
  struct md_version v;

  (void)state;
  memset(&f, 0, sizeof(f));
  memset(&ns, 0, sizeof(ns));
  v = live(100, "a", VIS_PUBLIC); row_put(&f, "k1", &v); row_put(&f, "k2", &v);
  note_clear(&ns, 200);
  note(&ns, "n1", "1", 201);
  note(&ns, "n2", "2", 202);
  assert_int_equal(merge(&f, &ns, 2), 4);
  assert_int_equal(f.nrefused, 0);
  assert_int_equal(live_keys(&f), 2);
  assert_string_equal(value_of(&f, "n2"), "2");

  memset(&f, 0, sizeof(f));
  memset(&ns, 0, sizeof(ns));
  row_put(&f, "k1", &v); row_put(&f, "k2", &v);
  note(&ns, "n1", "1", 201);
  merge(&f, &ns, 2);
  assert_int_equal(f.nrefused, 1);
  assert_int_equal(f.refused_why[0], MD_PREREG_LIMIT_KEYS);
}

/* A CLEAR with no store deletes nothing of the account's; and no merge at
 * all without a login or for a client that is not metadata-aware (the
 * ircd asks md_prereg_should_merge() first: the CLEAR then meant the
 * client's own keys, already gone from its memory). */
static void test_clear_without_store_or_merge(void **state)
{
  struct fake f;
  struct notes ns;

  (void)state;
  memset(&f, 0, sizeof(f));
  memset(&ns, 0, sizeof(ns));
  note_clear(&ns, 200);
  note(&ns, "a", "1", 201);
  assert_int_equal(md_prereg_merge(&ns.n[0], 0, INT_MAX, 300, &nostore_ops, &f), 1);
  assert_int_equal(f.nsent, 1);
  assert_false(md_prereg_should_merge(0, 1));
  assert_false(md_prereg_should_merge(1, 0));
}

/* No login, or not metadata-aware when registration ends: the account is
 * not touched at all (metadata.c asks md_prereg_should_merge() first). */
static void test_no_merge_without_login_or_awareness(void **state)
{
  (void)state;
  assert_false(md_prereg_should_merge(0, 1));
  assert_false(md_prereg_should_merge(1, 0));
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_should_merge),
    cmocka_unit_test(test_prereg_wins_per_key_untouched_from_account),
    cmocka_unit_test(test_identical_value),
    cmocka_unit_test(test_same_value_survives_the_pull),
    cmocka_unit_test(test_delete),
    cmocka_unit_test(test_delete_of_a_mode_key_without_row),
    cmocka_unit_test(test_newer_account_row_stands),
    cmocka_unit_test(test_over_cap),
    cmocka_unit_test(test_negative_cap_is_zero),
    cmocka_unit_test(test_value_limit),
    cmocka_unit_test(test_store_error),
    cmocka_unit_test(test_value_limit_before_identical),
    cmocka_unit_test(test_store_keeps_its_row),
    cmocka_unit_test(test_no_store),
    cmocka_unit_test(test_note_bound),
    cmocka_unit_test(test_note_clear),
    cmocka_unit_test(test_clear_then_set),
    cmocka_unit_test(test_set_then_clear_and_two_clears),
    cmocka_unit_test(test_clear_newer_row_survives),
    cmocka_unit_test(test_clear_and_the_cap),
    cmocka_unit_test(test_clear_without_store_or_merge),
    cmocka_unit_test(test_no_merge_without_login_or_awareness),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
