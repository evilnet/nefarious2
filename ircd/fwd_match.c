/** @file fwd_match.c
 * @brief Which forwarded command a reply without a msgid answers.
 *
 * See include/fwd_match.h.  The family table below is what a server
 * sends a remote asker for each command hunt_server_cmd() forwards:
 * stock Nefarious (upstream master), this fork, and X3's answers
 * (proto-p10.c cmd_whois; proto-common.c cmd_version, cmd_admin,
 * cmd_stats -- X3 answers nothing else).
 */
#include "config.h"

#include "fwd_match.h"
#include "ircd_string.h"

#include <string.h>

/** Where a numeric names its command's subject. */
enum FwdWhere {
  W_NONE = 0,  /**< names nothing (a MOTD line, LUSERS' counts) */
  W_P0,        /**< its first parameter is one element of the subject list */
  W_P0_AT,     /**< as W_P0; "<nick>@<server>" (X3's 401) ends the command */
  W_P0_LIST,   /**< its first parameter is the subject list, or the leading
                *   elements of it (WHOIS' 318 when 416 cut it short) */
  W_P0_EQ,     /**< its first parameter is the subject (STATS' 219) */
  W_P1,        /**< its second parameter is one element (NAMES' 353) */
  W_SRV,       /**< it names the server as a parameter or a word of its
                *   text; one that does not is another server's */
  W_SRV_OPT    /**< as W_SRV, but it may name none (X3's 423) */
};

/** One numeric of a family. */
struct FwdNum {
  unsigned short num;    /**< numeric */
  unsigned short last;   /**< last of a range starting at num (0: just num) */
  unsigned char where;   /**< enum FwdWhere */
  unsigned char fit;     /**< FWD_FIT_BODY, _END or _ELEMENT_END */
};

#define B FWD_FIT_BODY
#define E FWD_FIT_END
#define EE FWD_FIT_ELEMENT_END

/* WHOIS: do_whois() (stock and fork: 311 319 312 301 313 310 316 320 325
 * 330 335 338 339 343 616 671, the fork's 672 and 760), 401 for a nick
 * not found and 416 when the list is cut short -- the reply goes on to
 * 318 after both.  X3: 311 319 312 301 313 330 338 317 318, and for a
 * nick it does not have 401 "<nick>@<x3>" with no 318 after it. */
static const struct FwdNum fam_whois[] = {
  { 301, 0, W_P0, B }, { 310, 0, W_P0, B }, { 311, 0, W_P0, B },
  { 312, 0, W_P0, B }, { 313, 0, W_P0, B }, { 316, 0, W_P0, B },
  { 317, 0, W_P0, B }, { 319, 0, W_P0, B }, { 320, 0, W_P0, B },
  { 325, 0, W_P0, B }, { 330, 0, W_P0, B }, { 335, 0, W_P0, B },
  { 338, 0, W_P0, B }, { 339, 0, W_P0, B }, { 343, 0, W_P0, B },
  { 616, 0, W_P0, B }, { 671, 0, W_P0, B }, { 672, 0, W_P0, B },
  { 760, 0, W_P0, B },
  { 401, 0, W_P0_AT, B },
  { 416, 0, W_P0_LIST, B },
  { 318, 0, W_P0_LIST, E },
  { 0, 0, 0, 0 }
};

/* WHOWAS: 314 312 (338) (301) per entry, 406 for a nick with none, 369
 * for the list (stock and fork alike). */
static const struct FwdNum fam_whowas[] = {
  { 314, 0, W_P0, B }, { 312, 0, W_P0, B }, { 338, 0, W_P0, B },
  { 301, 0, W_P0, B }, { 406, 0, W_P0, B },
  { 369, 0, W_P0_LIST, E },
  { 0, 0, 0, 0 }
};

/* VERSION: 351 "<version> <server> :<comments>" (X3: "x3 <version>
 * <server>").  A remote oper's library NOTICEs come after it from stock
 * servers, before it from the fork (with the msgid). */
static const struct FwdNum fam_version[] = {
  { 351, 0, W_SRV, E },
  { 0, 0, 0, 0 }
};

/* TIME: 391 "<server> <ts> <offset> :<date>". */
static const struct FwdNum fam_time[] = {
  { 391, 0, W_SRV, E },
  { 0, 0, 0, 0 }
};

/* ADMIN: 256 "<server> :Administrative info" (X3: ":Administrative info
 * about <server>"), 257 258 259; 423 "<server> :No administrative info"
 * (X3's names no server).  X3 sends as many of 257.. as it has lines, so
 * with fewer than three no 259 comes: such an answer ends at the
 * deadline. */
static const struct FwdNum fam_admin[] = {
  { 256, 0, W_SRV, B }, { 257, 0, W_NONE, B }, { 258, 0, W_NONE, B },
  { 259, 0, W_NONE, E }, { 423, 0, W_SRV_OPT, E },
  { 0, 0, 0, 0 }
};

/* MOTD: 375 ":- <server> Message of the Day - ", 372 per line, 376; or
 * 422 alone. */
static const struct FwdNum fam_motd[] = {
  { 375, 0, W_SRV, B }, { 372, 0, W_NONE, B }, { 376, 0, W_NONE, E },
  { 422, 0, W_NONE, E },
  { 0, 0, 0, 0 }
};

/* RULES: 308 ":- <server> Network Rules - ", 232 per line, 309; or 434
 * (no rules) or 517 (disabled). */
static const struct FwdNum fam_rules[] = {
  { 308, 0, W_SRV, B }, { 232, 0, W_NONE, B }, { 309, 0, W_NONE, E },
  { 434, 0, W_NONE, E }, { 517, 0, W_NONE, E },
  { 0, 0, 0, 0 }
};

/* OPERMOTD: 535 ":<server> IRC Operator MOTD", 536 per line, 537; or 568
 * (none) or 517 (disabled). */
static const struct FwdNum fam_opermotd[] = {
  { 535, 0, W_SRV, B }, { 536, 0, W_NONE, B }, { 537, 0, W_NONE, E },
  { 568, 0, W_NONE, E }, { 517, 0, W_NONE, E },
  { 0, 0, 0, 0 }
};

/* LUSERS: 251 (252 253 254) 255 265 266, then (stock) a NOTICE; nothing
 * names the server. */
static const struct FwdNum fam_lusers[] = {
  { 251, 255, W_NONE, B }, { 265, 0, W_NONE, B }, { 266, 0, W_NONE, E },
  { 0, 0, 0, 0 }
};

/* INFO: 371 per line, 374. */
static const struct FwdNum fam_info[] = {
  { 371, 0, W_NONE, B }, { 374, 0, W_NONE, E },
  { 0, 0, 0, 0 }
};

/* LINKS: 364 per server, 365 "<mask> :End of /LINKS list." */
static const struct FwdNum fam_links[] = {
  { 364, 0, W_NONE, B }, { 365, 0, W_P0_EQ, E },
  { 0, 0, 0, 0 }
};

/* STATS: whatever the letter lists (211-218, 220-250, 275, 276, 542,
 * 546), 219 "<letter> :End of /STATS report".  X3 (STATS u): 242 250 219. */
static const struct FwdNum fam_stats[] = {
  { 211, 218, W_NONE, B }, { 220, 250, W_NONE, B }, { 275, 276, W_NONE, B },
  { 542, 0, W_NONE, B }, { 546, 0, W_NONE, B },
  { 219, 0, W_P0_EQ, E },
  { 0, 0, 0, 0 }
};

/* TRACE: 200 from every server on the way, then the destination's
 * 201-209 and 262 ":End of TRACE"; nothing names the destination. */
static const struct FwdNum fam_trace[] = {
  { 200, 209, W_NONE, B }, { 262, 0, W_NONE, E },
  { 0, 0, 0, 0 }
};

/* NAMES <channels> <server>: 353 "<type> <channel> :<names>" and one 366
 * "<channel> :End of /NAMES list." per channel. */
static const struct FwdNum fam_names[] = {
  { 353, 0, W_P1, B }, { 366, 0, W_P0, EE },
  { 0, 0, 0, 0 }
};

/* CHECK <server> <target> [-flags] (opers only; stock and fork alike):
 * 286 heads each section, 287 per user of a channel, 290 for every other
 * line, 291 once at the end.  292 alone when nothing matched; 517 alone
 * when the destination refuses the command.  None names the target or
 * the server -- but the asker is an oper, so the lines come under their
 * origin's name and fwd_pick() tells two CHECKs apart by it. */
static const struct FwdNum fam_check[] = {
  { 286, 287, W_NONE, B }, { 290, 0, W_NONE, B }, { 291, 0, W_NONE, E },
  { 292, 0, W_NONE, E }, { 517, 0, W_NONE, E },
  { 0, 0, 0, 0 }
};

#undef B
#undef E
#undef EE

/** The families, indexed by enum FwdFamily. */
static const struct {
  const char *cmd;
  unsigned char subject;      /**< enum FwdSubjectFrom */
  unsigned char hops;         /**< servers on the way add lines */
  const struct FwdNum *nums;
} families[FWD_FAM_COUNT] = {
  { "",         FWD_SUBJ_NONE,   0, NULL },
  { "WHOIS",    FWD_SUBJ_PARV2,  0, fam_whois },
  { "WHOWAS",   FWD_SUBJ_PARV1,  0, fam_whowas },
  { "VERSION",  FWD_SUBJ_SERVER, 0, fam_version },
  { "TIME",     FWD_SUBJ_SERVER, 0, fam_time },
  { "ADMIN",    FWD_SUBJ_SERVER, 0, fam_admin },
  { "MOTD",     FWD_SUBJ_SERVER, 0, fam_motd },
  { "RULES",    FWD_SUBJ_SERVER, 0, fam_rules },
  { "OPERMOTD", FWD_SUBJ_SERVER, 0, fam_opermotd },
  { "LUSERS",   FWD_SUBJ_NONE,   0, fam_lusers },
  { "INFO",     FWD_SUBJ_NONE,   0, fam_info },
  { "LINKS",    FWD_SUBJ_PARV2,  0, fam_links },
  { "STATS",    FWD_SUBJ_PARV1,  0, fam_stats },
  { "TRACE",    FWD_SUBJ_NONE,   1, fam_trace },
  { "NAMES",    FWD_SUBJ_PARV1,  0, fam_names },
  { "CHECK",    FWD_SUBJ_NONE,   0, fam_check },
};

int fwd_family_of(const char *cmd)
{
  int i;

  if (!cmd)
    return FWD_FAM_NONE;
  for (i = 1; i < FWD_FAM_COUNT; i++)
    if (!ircd_strcmp(cmd, families[i].cmd))
      return i;
  return FWD_FAM_NONE;
}

const char *fwd_family_name(int fam)
{
  return (fam > 0 && fam < FWD_FAM_COUNT) ? families[fam].cmd : "";
}

int fwd_family_subject(int fam)
{
  return (fam > 0 && fam < FWD_FAM_COUNT) ? families[fam].subject : FWD_SUBJ_NONE;
}

int fwd_family_hops_answer(int fam)
{
  return (fam > 0 && fam < FWD_FAM_COUNT) ? families[fam].hops : 0;
}

/** The entry of \a numeric in family \a fam, or NULL. */
static const struct FwdNum *fam_num(int fam, int numeric)
{
  const struct FwdNum *p;

  if (fam <= 0 || fam >= FWD_FAM_COUNT)
    return NULL;
  for (p = families[fam].nums; p->num; p++)
    if (numeric == p->num || (p->last && numeric > p->num && numeric <= p->last))
      return p;
  return NULL;
}

int fwd_families_overlap(int a, int b)
{
  const struct FwdNum *p;
  int n;

  if (a == b)
    return a > 0 && a < FWD_FAM_COUNT;
  if (a <= 0 || a >= FWD_FAM_COUNT || b <= 0 || b >= FWD_FAM_COUNT)
    return 0;
  for (p = families[a].nums; p->num; p++)
    for (n = p->num; n <= (p->last ? p->last : p->num); n++)
      if (fam_num(b, n))
        return 1;
  return 0;
}

int fwd_numeric_generic(int numeric)
{
  return numeric == 402 || numeric == 481;
}

int fwd_list_count(const char *list)
{
  int n = 0;

  if (!list || !*list)
    return 0;
  for (n = 1; *list; list++)
    if (*list == ',')
      n++;
  return n;
}

/** Copy parameter \a idx (0-based) of \a params into \a buf: a middle
 * parameter, never the trailing one (":..."). */
static int param_n(const char *params, int idx, char *buf, size_t len)
{
  const char *p = params, *e;

  while (*p == ' ')
    p++;
  for (;;) {
    if (!*p || *p == ':')
      return 0;
    e = strchr(p, ' ');
    if (!e)
      e = p + strlen(p);
    if (!idx--) {
      size_t n = e - p;
      if (n >= len)
        return 0;
      memcpy(buf, p, n);
      buf[n] = '\0';
      return 1;
    }
    p = e;
    while (*p == ' ')
      p++;
  }
}

/** Whether \a word (length \a n) equals \a s, case-insensitively. */
static int word_is(const char *word, size_t n, const char *s)
{
  return strlen(s) == n && !ircd_strncmp(word, s, n);
}

/** Whether \a elem is one element of the comma-separated \a list. */
static int list_has(const char *list, const char *elem, size_t n)
{
  const char *p = list, *e;

  if (!n)
    return 0;
  for (;;) {
    e = strchr(p, ',');
    if (!e)
      e = p + strlen(p);
    if ((size_t)(e - p) == n && !ircd_strncmp(p, elem, n))
      return 1;
    if (!*e)
      return 0;
    p = e + 1;
  }
}

/** Whether \a got is \a list or its leading elements, element by element. */
static int list_prefix(const char *list, const char *got)
{
  const char *a = list, *b = got;

  if (!*got)
    return 0;
  for (;;) {
    const char *ae = strchr(a, ','), *be = strchr(b, ',');
    size_t an, bn;

    if (!ae)
      ae = a + strlen(a);
    if (!be)
      be = b + strlen(b);
    an = ae - a;
    bn = be - b;
    if (an != bn || ircd_strncmp(a, b, an))
      return 0;
    if (!*be)
      return 1;              /* got ends: it is the list or its start */
    if (!*ae)
      return 0;              /* got goes on past the list */
    a = ae + 1;
    b = be + 1;
  }
}

/** Whether \a params name the server \a name: as a middle parameter, or
 * as a word of the trailing one. */
static int names_server(const char *params, const char *name)
{
  const char *p = params, *e;

  if (!*name)
    return 0;
  while (*p) {
    while (*p == ' ')
      p++;
    if (*p == ':')
      p++;                   /* the trailing parameter's words count too */
    e = p;
    while (*e && *e != ' ')
      e++;
    if (e > p && word_is(p, e - p, name))
      return 1;
    p = e;
  }
  return 0;
}

int fwd_reply_fit(int fam, const char *subject, int numeric, const char *params)
{
  const struct FwdNum *n = fam_num(fam, numeric);
  char p0[FWD_SUBJECT_MAX + 64];

  if (!n)
    return FWD_FIT_NO;
  if (!subject)
    subject = "";
  if (!params)
    params = "";

  switch (n->where) {
  case W_NONE:
    return n->fit;

  case W_P0:
  case W_P0_AT:
    if (!param_n(params, 0, p0, sizeof(p0)))
      return FWD_FIT_NO;
    if (list_has(subject, p0, strlen(p0)))
      return n->fit;
    if (n->where == W_P0_AT) {
      /* X3's 401 names "<nick>@<its name>" and ends the answer; a nick
       * asked with an '@' in it is matched whole, above. */
      char *at = strchr(p0, '@');
      if (at && at > p0 && list_has(subject, p0, at - p0))
        return FWD_FIT_END;
    }
    return FWD_FIT_NO;

  case W_P0_LIST:
    if (!param_n(params, 0, p0, sizeof(p0)))
      return FWD_FIT_NO;
    return list_prefix(subject, p0) ? n->fit : FWD_FIT_NO;

  case W_P0_EQ:
    if (!param_n(params, 0, p0, sizeof(p0)))
      return FWD_FIT_NO;
    return ircd_strcmp(p0, subject) ? FWD_FIT_NO : n->fit;

  case W_P1:
    if (!param_n(params, 1, p0, sizeof(p0)))
      return FWD_FIT_NO;
    return list_has(subject, p0, strlen(p0)) ? n->fit : FWD_FIT_NO;

  case W_SRV:
    return names_server(params, subject) ? n->fit : FWD_FIT_NO;

  case W_SRV_OPT:
    /* Naming a server is enough to tell: one that names another is not
     * ours.  One that names none could be any server's (X3's 423). */
    if (names_server(params, subject))
      return n->fit;
    {
      char w[FWD_SUBJECT_MAX + 64];
      return param_n(params, 0, w, sizeof(w)) && strchr(w, '.') ? FWD_FIT_NO : n->fit;
    }
  }
  return FWD_FIT_NO;
}

int fwd_pick(const struct FwdView *v, int n, int numeric,
             const char *params, const char *link, const char *source,
             int source_true, unsigned int untracked,
             unsigned char *cand, int *fit, int *ambiguous)
{
  int generic = fwd_numeric_generic(numeric);
  int i, pick = -1, ncand = 0, nsrc = 0, hops = 0, same = 1, tainted = 0;
  const char *dest = NULL;

  *fit = FWD_FIT_NO;
  *ambiguous = 0;
  for (i = 0; i < n; i++) {
    cand[i] = 0;
    if (v[i].fam <= FWD_FAM_NONE || v[i].fam >= FWD_FAM_COUNT || !link
        || strcmp(v[i].link, link) || v[i].age > FWD_DEADLINE)
      continue;
    if (!generic && fwd_reply_fit(v[i].fam, v[i].subject, numeric, params) == FWD_FIT_NO)
      continue;
    cand[i] = 1;
    ncand++;
    if (fwd_family_hops_answer(v[i].fam))
      hops = 1;
    if (source && !strcmp(v[i].dest, source))
      nsrc++;
  }
  if (!ncand)
    return -1;

  /* A refusal while a command of unknown replies is out may be its. */
  if (generic && (untracked & FWD_UNTRACKED_GENERIC)) {
    for (i = 0; i < n; i++)
      cand[i] = 0;
    return -1;
  }

  /* An oper's reply names its true origin: only a command sent there can
   * be the one answered -- when no other server could have sent the line
   * (a hop's TRACE line, a hop's refusal); one from a server none of them
   * went to is none of theirs. */
  if (source_true && source && !hops && !generic && !nsrc) {
    for (i = 0; i < n; i++)
      cand[i] = 0;
    return -1;
  }
  if (source_true && source && nsrc && nsrc < ncand && !hops && !generic) {
    for (i = 0; i < n; i++)
      if (cand[i] && strcmp(v[i].dest, source)) {
        cand[i] = 0;
        ncand--;
      }
  }

  for (i = 0; i < n; i++) {
    if (!cand[i])
      continue;
    if (!dest)
      dest = v[i].dest;
    else if (strcmp(dest, v[i].dest))
      same = 0;
    if (pick < 0 || v[i].seq < v[pick].seq)
      pick = i;
  }
  /* An untracked command whose family has this numeric may be answered
   * by it (WHOIS's 401 also answers an INVITE's target gone; WHOWAS
   * shares 312 with WHOIS). */
  if (!generic)
    for (i = 1; i < FWD_FAM_COUNT; i++)
      if (((untracked >> i) & 1) && fam_num(i, numeric))
        tainted = 1;
  if (numeric == 401 && (untracked & FWD_UNTRACKED_NOSUCHNICK))
    tainted = 1;
  /* Ambiguous: candidates sent to different servers; or more than one
   * of a family whose hops add lines (a hop's line for the later command
   * comes before the destination's answer to the earlier); or a command
   * of that family went out untracked and this may be its reply. */
  *ambiguous = (ncand > 1 && (!same || hops)) || tainted;
  *fit = generic ? FWD_FIT_END
                 : fwd_reply_fit(v[pick].fam, v[pick].subject, numeric, params);
  return pick;
}
