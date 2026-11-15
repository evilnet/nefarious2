/*
 * fwd_match_cmocka.c - which forwarded command a reply without a msgid
 * answers (ircd/fwd_match.c): the family table, subject extraction,
 * terminal detection, and fwd_pick()'s choice among pending commands --
 * including every way the arrival-order rule of PR #211 filed a reply
 * under the wrong label.
 */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>

#include "fwd_match.h"

#define FIT(fam, subj, num, params) fwd_reply_fit(FWD_FAM_##fam, subj, num, params)

/* ---- the family table ---- */

static void test_families_by_command(void **state)
{
  (void)state;
  assert_int_equal(fwd_family_of("WHOIS"), FWD_FAM_WHOIS);
  assert_int_equal(fwd_family_of("whowas"), FWD_FAM_WHOWAS);
  assert_int_equal(fwd_family_of("STATS"), FWD_FAM_STATS);
  assert_int_equal(fwd_family_of("NAMES"), FWD_FAM_NAMES);
  assert_int_equal(fwd_family_of("CONNECT"), FWD_FAM_NONE);
  assert_int_equal(fwd_family_of("RPING"), FWD_FAM_NONE);
  assert_int_equal(fwd_family_of(NULL), FWD_FAM_NONE);
  assert_string_equal(fwd_family_name(FWD_FAM_TRACE), "TRACE");
  assert_int_equal(fwd_family_subject(FWD_FAM_WHOIS), FWD_SUBJ_PARV2);
  assert_int_equal(fwd_family_subject(FWD_FAM_TIME), FWD_SUBJ_SERVER);
  assert_int_equal(fwd_family_subject(FWD_FAM_LUSERS), FWD_SUBJ_NONE);
  assert_true(fwd_family_hops_answer(FWD_FAM_TRACE));
  assert_false(fwd_family_hops_answer(FWD_FAM_WHOIS));
  assert_true(fwd_families_overlap(FWD_FAM_WHOIS, FWD_FAM_WHOWAS));
  assert_false(fwd_families_overlap(FWD_FAM_WHOIS, FWD_FAM_VERSION));
  assert_false(fwd_families_overlap(FWD_FAM_LUSERS, FWD_FAM_STATS));
  assert_int_equal(fwd_list_count("#x,#y"), 2);
  assert_int_equal(fwd_list_count("nick"), 1);
  assert_true(fwd_numeric_generic(402));
  assert_true(fwd_numeric_generic(481));
  assert_false(fwd_numeric_generic(401));
}

/* WHOIS: every per-nick numeric names the nick; 318 the list; stock's
 * 401 goes on to 318, X3's "<nick>@<x3>" is the whole answer. */
static void test_whois_subject_and_terminal(void **state)
{
  (void)state;
  assert_int_equal(FIT(WHOIS, "muser", 311, "muser ~muser 127.0.0.1 * :M User"), FWD_FIT_BODY);
  assert_int_equal(FIT(WHOIS, "muser", 311, "MUSER ~muser 127.0.0.1 * :M User"), FWD_FIT_BODY);
  assert_int_equal(FIT(WHOIS, "muser", 311, "fuser ~fuser 127.0.0.1 * :F User"), FWD_FIT_NO);
  assert_int_equal(FIT(WHOIS, "muser", 312, "muser m.test :stock"), FWD_FIT_BODY);
  assert_int_equal(FIT(WHOIS, "muser", 317, "muser 3 1700000000 :seconds idle, signon time"), FWD_FIT_BODY);
  assert_int_equal(FIT(WHOIS, "muser", 318, "muser :End of /WHOIS list."), FWD_FIT_END);
  assert_int_equal(FIT(WHOIS, "muser", 318, "fuser :End of /WHOIS list."), FWD_FIT_NO);
  assert_int_equal(FIT(WHOIS, "a,b", 311, "b ~b h * :b"), FWD_FIT_BODY);
  assert_int_equal(FIT(WHOIS, "a,b", 318, "a,b :End of /WHOIS list."), FWD_FIT_END);
  assert_int_equal(FIT(WHOIS, "a,b", 318, "a :End of /WHOIS list."), FWD_FIT_END);  /* 416 cut */
  assert_int_equal(FIT(WHOIS, "a,b", 318, "a,c :End of /WHOIS list."), FWD_FIT_NO);
  assert_int_equal(FIT(WHOIS, "a", 318, "a,b :End of /WHOIS list."), FWD_FIT_NO);
  assert_int_equal(FIT(WHOIS, "zzz", 401, "zzz :No such nick"), FWD_FIT_BODY);
  assert_int_equal(FIT(WHOIS, "NoSuch", 401, "NoSuch@x3.test :No such nick"), FWD_FIT_END);
  assert_int_equal(FIT(WHOIS, "other", 401, "NoSuch@x3.test :No such nick"), FWD_FIT_NO);
  assert_int_equal(FIT(WHOIS, "muser", 351, "u2.10 m.test :x"), FWD_FIT_NO);
  assert_int_equal(FIT(WHOIS, "muser", 200, "Link u2.10 muser m.test"), FWD_FIT_NO);
  assert_int_equal(FIT(WHOIS, "muser", 760, "muser avatar * :http://x"), FWD_FIT_BODY);
}

static void test_server_named_families(void **state)
{
  (void)state;
  /* VERSION: stock/fork "<v> <server> :<c>", X3 "x3 <v> <server>" */
  assert_int_equal(FIT(VERSION, "m.test", 351, "u2.10.12.14+[1.0].0 m.test :B30AeEFfIKMp"), FWD_FIT_END);
  assert_int_equal(FIT(VERSION, "n.test", 351, "u2.10.12.14+[1.0].0 m.test :B30"), FWD_FIT_NO);
  assert_int_equal(FIT(VERSION, "x3.test", 351, "x3 1.9+[fake] x3.test"), FWD_FIT_END);
  /* TIME */
  assert_int_equal(FIT(TIME, "m.test", 391, "m.test 1700000000 0 :Tuesday"), FWD_FIT_END);
  assert_int_equal(FIT(TIME, "x3.test", 391, "m.test 1700000000 0 :Tuesday"), FWD_FIT_NO);
  /* ADMIN: stock names it as a parameter, X3 in its text */
  assert_int_equal(FIT(ADMIN, "m.test", 256, "m.test :Administrative info"), FWD_FIT_BODY);
  assert_int_equal(FIT(ADMIN, "x3.test", 256, ":Administrative info about x3.test"), FWD_FIT_BODY);
  assert_int_equal(FIT(ADMIN, "m.test", 256, ":Administrative info about x3.test"), FWD_FIT_NO);
  assert_int_equal(FIT(ADMIN, "m.test", 257, ":somewhere"), FWD_FIT_BODY);
  assert_int_equal(FIT(ADMIN, "m.test", 259, ":nobody"), FWD_FIT_END);
  assert_int_equal(FIT(ADMIN, "m.test", 423, "m.test :No administrative info available"), FWD_FIT_END);
  assert_int_equal(FIT(ADMIN, "m.test", 423, "n.test :No administrative info available"), FWD_FIT_NO);
  assert_int_equal(FIT(ADMIN, "x3.test", 423, ":No administrative info available"), FWD_FIT_END);
  /* MOTD */
  assert_int_equal(FIT(MOTD, "m.test", 375, ":- m.test Message of the Day - "), FWD_FIT_BODY);
  assert_int_equal(FIT(MOTD, "n.test", 375, ":- m.test Message of the Day - "), FWD_FIT_NO);
  assert_int_equal(FIT(MOTD, "m.test", 372, ":- hello"), FWD_FIT_BODY);
  assert_int_equal(FIT(MOTD, "m.test", 376, ":End of /MOTD command."), FWD_FIT_END);
  assert_int_equal(FIT(MOTD, "m.test", 422, ":MOTD File is missing"), FWD_FIT_END);
  /* RULES / OPERMOTD */
  assert_int_equal(FIT(RULES, "m.test", 308, ":- m.test Network Rules - "), FWD_FIT_BODY);
  assert_int_equal(FIT(RULES, "m.test", 434, ":RULES File is missing"), FWD_FIT_END);
  assert_int_equal(FIT(OPERMOTD, "m.test", 535, ":m.test IRC Operator MOTD"), FWD_FIT_BODY);
  assert_int_equal(FIT(OPERMOTD, "m.test", 537, ":End of IRC Operator MOTD."), FWD_FIT_END);
}

static void test_subjectless_and_listed_families(void **state)
{
  (void)state;
  assert_int_equal(FIT(LUSERS, "", 251, ":There are 3 users"), FWD_FIT_BODY);
  assert_int_equal(FIT(LUSERS, "", 254, "2 :channels formed"), FWD_FIT_BODY);
  assert_int_equal(FIT(LUSERS, "", 266, ":Current global users: 3 Max: 3"), FWD_FIT_END);
  assert_int_equal(FIT(LUSERS, "", 250, ":Highest connection count"), FWD_FIT_NO);
  assert_int_equal(FIT(INFO, "", 371, ":Nefarious"), FWD_FIT_BODY);
  assert_int_equal(FIT(INFO, "", 374, ":End of /INFO list."), FWD_FIT_END);
  assert_int_equal(FIT(STATS, "u", 242, ":Server Up 0 days"), FWD_FIT_BODY);
  assert_int_equal(FIT(STATS, "u", 250, ":Highest connection count: 3 (2 clients)"), FWD_FIT_BODY);
  assert_int_equal(FIT(STATS, "u", 219, "u :End of /STATS report"), FWD_FIT_END);
  assert_int_equal(FIT(STATS, "u", 219, "k :End of /STATS report"), FWD_FIT_NO);
  assert_int_equal(FIT(STATS, "u", 266, ":Current"), FWD_FIT_NO);
  assert_int_equal(FIT(LINKS, "*", 364, "m.test b.test :2 P10 stock"), FWD_FIT_BODY);
  assert_int_equal(FIT(LINKS, "*", 365, "* :End of /LINKS list."), FWD_FIT_END);
  assert_int_equal(FIT(LINKS, "*", 365, "*.test :End of /LINKS list."), FWD_FIT_NO);
  assert_int_equal(FIT(TRACE, "", 200, "Link u2.10 m.test m.test"), FWD_FIT_BODY);
  assert_int_equal(FIT(TRACE, "", 205, "User 1 muser[127.0.0.1] 3"), FWD_FIT_BODY);
  assert_int_equal(FIT(TRACE, "", 262, ":End of TRACE"), FWD_FIT_END);
  assert_int_equal(FIT(NAMES, "#x,#y", 353, "= #x :@a b"), FWD_FIT_BODY);
  assert_int_equal(FIT(NAMES, "#x,#y", 353, "= #z :@a b"), FWD_FIT_NO);
  assert_int_equal(FIT(NAMES, "#x,#y", 366, "#Y :End of /NAMES list."), FWD_FIT_ELEMENT_END);
  assert_int_equal(FIT(NAMES, "#x,#y", 366, "#z :End of /NAMES list."), FWD_FIT_NO);
  assert_int_equal(FIT(WHOWAS, "gone", 314, "gone ~g h * :real"), FWD_FIT_BODY);
  assert_int_equal(FIT(WHOWAS, "gone", 312, "gone m.test :Sat Nov 14"), FWD_FIT_BODY);
  assert_int_equal(FIT(WHOWAS, "never", 406, "never :There was no such nickname"), FWD_FIT_BODY);
  assert_int_equal(FIT(WHOWAS, "gone", 369, "gone :End of WHOWAS"), FWD_FIT_END);
  /* a parameter longer than any subject is no subject's */
  {
    char longp[400];
    memset(longp, 'x', sizeof(longp) - 1);
    longp[sizeof(longp) - 1] = '\0';
    assert_int_equal(FIT(WHOIS, "x", 311, longp), FWD_FIT_NO);
  }
}

/* ---- fwd_pick(): one reply, several pending commands ---- */

/* the asker's pending commands, built per test */
static struct FwdView v[8];
static int nv;
static unsigned char cand[8];

static void add(int fam, const char *subj, const char *dest, const char *link,
                unsigned long seq)
{
  v[nv].fam = fam;
  v[nv].subject = subj;
  v[nv].dest = dest;
  v[nv].link = link;
  v[nv].seq = seq;
  v[nv].age = 1;
  nv++;
}

static int setup(void **state)
{
  (void)state;
  memset(v, 0, sizeof(v));
  nv = 0;
  return 0;
}

#define PICK(num, params, link, src, src_true) \
  fwd_pick(v, nv, num, params, link, src, src_true, 0, cand, &fit, &amb)
#define PICKU(num, params, link, src, src_true, untracked) \
  fwd_pick(v, nv, num, params, link, src, src_true, untracked, cand, &fit, &amb)

/* A reply to a command the asker never had tracked (an unlabeled one
 * from before, a stray numeric) matches nothing: it goes out plain. */
static void test_pick_untracked_reply_matches_nothing(void **state)
{
  int fit, amb;

  (void)state;
  add(FWD_FAM_WHOIS, "muser", "Mm", "Bb", 1);
  assert_int_equal(PICK(311, "fuser ~f h * :F", "Bb", "Bb", 0), -1);
  assert_int_equal(PICK(251, ":There are 3 users", "Bb", "Bb", 0), -1);  /* unasked LUSERS */
  assert_int_equal(PICK(200, "Link u2.10 m.test m.test", "Bb", "Bb", 0), -1); /* a hop's TRACE line */
}

/* Two servers behind one link: `WHOIS muser muser` then `WHOIS fuser
 * fuser`, the second answering first -- each reply is its own nick's. */
static void test_pick_same_family_other_subject(void **state)
{
  int fit, amb, i;

  (void)state;
  add(FWD_FAM_WHOIS, "muser", "Mm", "Bb", 1);
  add(FWD_FAM_WHOIS, "fuser", "Ff", "Bb", 2);
  i = PICK(311, "fuser ~f h * :F", "Bb", "Bb", 0);
  assert_int_equal(i, 1);
  assert_false(amb);
  assert_int_equal(fit, FWD_FIT_BODY);
  assert_int_equal(PICK(318, "fuser :End of /WHOIS list.", "Bb", "Bb", 0), 1);
  assert_int_equal(fit, FWD_FIT_END);
  assert_int_equal(PICK(311, "muser ~m h * :M", "Bb", "Bb", 0), 0);
  assert_false(amb);
}

/* The same command twice (one server, one stream): oldest first. */
static void test_pick_identical_pending_oldest_first(void **state)
{
  int fit, amb;

  (void)state;
  add(FWD_FAM_WHOIS, "muser", "Mm", "Bb", 7);
  add(FWD_FAM_WHOIS, "muser", "Mm", "Bb", 3);
  assert_int_equal(PICK(311, "muser ~m h * :M", "Bb", "Bb", 0), 1);
  assert_false(amb);
  assert_int_equal(cand[0] + cand[1], 2);
}

/* No subject and two destinations behind one link (MOTD of two servers
 * for a non-oper, whose replies every hop renames as its own): the
 * lines cannot be told apart -- ambiguous, both are candidates. */
static void test_pick_subjectless_two_servers_is_ambiguous(void **state)
{
  int fit, amb, i;

  (void)state;
  add(FWD_FAM_MOTD, "m.test", "Mm", "Bb", 1);
  add(FWD_FAM_MOTD, "f.test", "Ff", "Bb", 2);
  i = PICK(372, ":- line", "Bb", "Bb", 0);
  assert_int_equal(i, 0);
  assert_true(amb);
  assert_true(cand[0] && cand[1]);
  /* its first line names the server: that one is not ambiguous */
  assert_int_equal(PICK(375, ":- f.test Message of the Day - ", "Bb", "Bb", 0), 1);
  assert_false(amb);
  /* for an oper the source is the origin: it tells them apart */
  assert_int_equal(PICK(372, ":- line", "Bb", "Ff", 1), 1);
  assert_false(amb);
  assert_int_equal(cand[0], 0);
  /* ... but not a source that is neither (a renaming hop) */
  PICK(372, ":- line", "Bb", "Bb", 1);
  assert_true(amb);
}

/* TRACE lines come from the hops too: the source tells nothing. */
static void test_pick_trace_source_not_trusted(void **state)
{
  int fit, amb;

  (void)state;
  add(FWD_FAM_TRACE, "", "Mm", "Bb", 1);
  add(FWD_FAM_TRACE, "", "Ff", "Bb", 2);
  PICK(200, "Link u2.10 f.test b.test", "Bb", "Mm", 1);
  assert_true(amb);
}

/* A reply over another link is not for a command sent over this one. */
static void test_pick_other_link(void **state)
{
  int fit, amb;

  (void)state;
  add(FWD_FAM_WHOIS, "muser", "Mm", "Bb", 1);
  assert_int_equal(PICK(311, "muser ~m h * :M", "Nn", "Nn", 0), -1);
}

/* Past the deadline a pending command takes nothing: a TIME that X3
 * never answered does not take the reply of a later TIME. */
static void test_pick_stale_entry_takes_nothing(void **state)
{
  int fit, amb;

  (void)state;
  add(FWD_FAM_TIME, "m.test", "Mm", "Bb", 1);
  v[0].age = FWD_DEADLINE + 1;
  add(FWD_FAM_TIME, "m.test", "Mm", "Bb", 2);
  assert_int_equal(PICK(391, "m.test 1 0 :now", "Bb", "Bb", 0), 1);
  assert_false(amb);
  assert_int_equal(cand[0], 0);
}

/* Services that never answer: `TIME x3` then `WHOIS ChanServ ChanServ`
 * -- the WHOIS reply is the WHOIS's; and VERSION of two servers is told
 * apart by the server its 351 names. */
static void test_pick_services_unanswered_and_named(void **state)
{
  int fit, amb;

  (void)state;
  add(FWD_FAM_TIME, "x3.test", "Xx", "Bb", 1);
  add(FWD_FAM_WHOIS, "ChanServ", "Xx", "Bb", 2);
  assert_int_equal(PICK(311, "ChanServ chanserv services.test * :x", "Bb", "Bb", 0), 1);
  assert_false(amb);
  assert_int_equal(PICK(318, "ChanServ :End of /WHOIS list", "Bb", "Bb", 0), 1);
  assert_int_equal(fit, FWD_FIT_END);
  setup(NULL);
  add(FWD_FAM_VERSION, "m.test", "Mm", "Bb", 1);
  add(FWD_FAM_VERSION, "x3.test", "Xx", "Bb", 2);
  assert_int_equal(PICK(351, "x3 1.9+[fake] x3.test", "Bb", "Bb", 0), 1);
  assert_false(amb);
  assert_int_equal(fit, FWD_FIT_END);
}

/* WHOIS and WHOWAS of the same nick share 312: one server, oldest; two
 * servers, ambiguous. */
static void test_pick_overlapping_families(void **state)
{
  int fit, amb;

  (void)state;
  add(FWD_FAM_WHOWAS, "muser", "Mm", "Bb", 1);
  add(FWD_FAM_WHOIS, "muser", "Mm", "Bb", 2);
  assert_int_equal(PICK(312, "muser m.test :x", "Bb", "Bb", 0), 0);
  assert_false(amb);
  assert_int_equal(PICK(311, "muser ~m h * :M", "Bb", "Bb", 0), 1);  /* WHOIS only */
  v[0].dest = "Ff";
  PICK(312, "muser m.test :x", "Bb", "Bb", 0);
  assert_true(amb);
}

/* A hop's refusal (402 "* :Server has disconnected", 481) names no
 * subject: it is a command's only if it is the only one on that link. */
static void test_pick_generic_errors(void **state)
{
  int fit, amb;

  (void)state;
  add(FWD_FAM_STATS, "k", "Mm", "Bb", 1);
  assert_int_equal(PICK(481, ":Permission Denied", "Bb", "Bb", 0), 0);
  assert_int_equal(fit, FWD_FIT_END);
  assert_false(amb);
  add(FWD_FAM_VERSION, "f.test", "Ff", "Bb", 2);
  PICK(402, "* :Server has disconnected", "Bb", "Bb", 1);
  assert_true(amb);   /* a hop's refusal: even an oper's source tells nothing */
}

/* NAMES of two channels: one 366 each, the last ends it (caller counts). */
static void test_pick_names_elements(void **state)
{
  int fit, amb;

  (void)state;
  add(FWD_FAM_NAMES, "#x,#y", "Mm", "Bb", 1);
  assert_int_equal(PICK(366, "#x :End of /NAMES list.", "Bb", "Bb", 0), 0);
  assert_int_equal(fit, FWD_FIT_ELEMENT_END);
  assert_int_equal(PICK(366, "#q :End of /NAMES list.", "Bb", "Bb", 0), -1);
}

/* (review M1, S1, N1) A command the asker's connection -- or another
 * connection of its bouncer session -- sent untracked (no labeled-response
 * then, a full FIFO, INVITE's 401) may be answered by any reply of its
 * family: a labeled command of that family pending on the link is not
 * the reply's for sure.  B1: the primary (no labeled-response) asked
 * MOTD m.test, its device @label=d1 MOTD o.test; m.test's 372 reached
 * d1's batch. */
static void test_pick_untracked_same_family_is_ambiguous(void **state)
{
  int fit, amb, i;

  (void)state;
  add(FWD_FAM_MOTD, "o.test", "Oo", "Bb", 2);          /* the device's d1 */
  i = PICKU(372, ":- remote motd of m.test", "Bb", "Bb", 0, 1u << FWD_FAM_MOTD);
  assert_int_equal(i, 0);
  assert_true(amb);
  /* a reply of another family is unaffected */
  setup(NULL);
  add(FWD_FAM_WHOIS, "muser", "Mm", "Bb", 2);
  PICKU(311, "muser ~m h * :M", "Bb", "Bb", 0, 1u << FWD_FAM_MOTD);
  assert_false(amb);
  /* ... unless the untracked family has the numeric: WHOWAS shares 312 */
  PICKU(312, "muser m.test :x", "Bb", "Bb", 0, 1u << FWD_FAM_WHOWAS);
  assert_true(amb);
  /* INVITE's target gone (review N1, B3): its 401 is not told from the
   * WHOIS's; the rest of the WHOIS is */
  PICKU(401, "muser :No such nick", "Bb", "Bb", 0, FWD_UNTRACKED_NOSUCHNICK);
  assert_true(amb);
  PICKU(311, "muser ~m h * :M", "Bb", "Bb", 0, FWD_UNTRACKED_NOSUCHNICK);
  assert_false(amb);
}

/* (review M1) Once the primary's command is tracked too (unlabeled, an
 * entry of its own), the 375 that names m.test is the primary's and the
 * device's batch takes nothing of it; the lines that name nothing are
 * ambiguous between two servers. */
static void test_pick_session_members_both_tracked(void **state)
{
  int fit, amb;

  (void)state;
  add(FWD_FAM_MOTD, "m.test", "Mm", "Bb", 1);          /* primary, plain */
  add(FWD_FAM_MOTD, "o.test", "Oo", "Bb", 2);          /* device d1 */
  assert_int_equal(PICK(375, ":- m.test Message of the Day - ", "Bb", "Bb", 0), 0);
  assert_false(amb);
  PICK(372, ":- remote motd of m.test", "Bb", "Bb", 0);
  assert_true(amb);
}

/* (review N2) A 402/481 while a command of unknown replies (CONNECT,
 * RPING, ...) is outstanding may be that command's: it ends no label. */
static void test_pick_generic_with_untracked_unknown(void **state)
{
  int fit, amb;

  (void)state;
  add(FWD_FAM_STATS, "k", "Mm", "Bb", 1);
  assert_int_equal(PICKU(481, ":Permission Denied", "Bb", "Bb", 0, FWD_UNTRACKED_GENERIC), -1);
  assert_int_equal(PICKU(219, "k :End of /STATS report", "Bb", "Bb", 0, FWD_UNTRACKED_GENERIC), 0);
  assert_false(amb);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_families_by_command),
    cmocka_unit_test(test_whois_subject_and_terminal),
    cmocka_unit_test(test_server_named_families),
    cmocka_unit_test(test_subjectless_and_listed_families),
    cmocka_unit_test_setup(test_pick_untracked_reply_matches_nothing, setup),
    cmocka_unit_test_setup(test_pick_same_family_other_subject, setup),
    cmocka_unit_test_setup(test_pick_identical_pending_oldest_first, setup),
    cmocka_unit_test_setup(test_pick_subjectless_two_servers_is_ambiguous, setup),
    cmocka_unit_test_setup(test_pick_trace_source_not_trusted, setup),
    cmocka_unit_test_setup(test_pick_other_link, setup),
    cmocka_unit_test_setup(test_pick_stale_entry_takes_nothing, setup),
    cmocka_unit_test_setup(test_pick_services_unanswered_and_named, setup),
    cmocka_unit_test_setup(test_pick_overlapping_families, setup),
    cmocka_unit_test_setup(test_pick_generic_errors, setup),
    cmocka_unit_test_setup(test_pick_names_elements, setup),
    cmocka_unit_test_setup(test_pick_untracked_same_family_is_ambiguous, setup),
    cmocka_unit_test_setup(test_pick_session_members_both_tracked, setup),
    cmocka_unit_test_setup(test_pick_generic_with_untracked_unknown, setup),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
