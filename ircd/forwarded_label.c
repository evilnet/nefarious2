/** @file forwarded_label.c
 * @brief Labeled-response support for commands forwarded via hunt_server_cmd.
 *
 * Manages per-connection ForwardedLabel FIFO entries that track the
 * commands a labeled-response client has forwarded (labeled or not),
 * correlate their replies -- by the compact msgid a fork server echoes,
 * else by the family and subject the reply names (fwd_match.c) -- and
 * handle the batch lifecycle (PENDING → ACTIVE → DRAINING → EMPTY).  A
 * reply that matches no command, or matches several that cannot be told
 * apart, is delivered unlabeled: it is never filed under another label.
 */
#include "config.h"

#include "forwarded_label.h"
#include "client.h"
#include "crdt_hlc.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_string.h"
#include "match.h"
#include "fwd_match.h"
#include "msg.h"
#include "numnicks.h"
#include "send.h"
#include "s_bsd.h"

#include <string.h>
#include <stdio.h>
#include <sys/time.h>

/** Terminal numeric table for forwarded commands.
 * Maps command names to their terminal numeric(s). Error numerics
 * 401 (ERR_NOSUCHNICK) and 402 (ERR_NOSUCHSERVER) are always terminal.
 */
static const struct {
  const char    *cmd;
  unsigned short terminal;
  unsigned short terminal2;
} fwd_terminals[] = {
  { "WHOIS",    318, 0   },  /* RPL_ENDOFWHOIS */
  { "STATS",    219, 0   },  /* RPL_ENDOFSTATS */
  { "LINKS",    365, 0   },  /* RPL_ENDOFLINKS */
  { "INFO",     374, 0   },  /* RPL_ENDOFINFO */
  { "MOTD",     376, 422 },  /* RPL_ENDOFMOTD / ERR_NOMOTD */
  { "TRACE",    262, 0   },  /* RPL_TRACEEND */
  { "ADMIN",    259, 0   },  /* RPL_ADMINEMAIL (last in fixed sequence) */
  { "VERSION",  351, 0   },  /* RPL_VERSION (single numeric) */
  { "TIME",     391, 0   },  /* RPL_TIME (single numeric) */
  { "LUSERS",   266, 0   },  /* RPL_CURRENT_GLOBAL (last numeric) */
  { "RULES",    309, 0   },  /* RPL_ENDOFRULES */
  { "OPERMOTD", 537, 0   },  /* RPL_ENDOFOMOTD */
  { "WHOWAS",   369, 0   },  /* RPL_ENDOFWHOWAS (406 precedes it on miss) */
  { "NAMES",    366, 0   },  /* RPL_ENDOFNAMES */
  { NULL, 0, 0 }
};

/** Counter for generating unique forwarded batch IDs. */
static unsigned long fwd_batch_counter = 0;

/** Timeout in seconds for PENDING/ACTIVE entries. */
#define FWD_TIMEOUT_NORMAL  FWD_DEADLINE

/** Timeout in seconds for DRAINING entries. */
#define FWD_TIMEOUT_DRAIN   5

/** Whether the labeled batch \a from's handler opened can be taken over
 * by a forwarded label: it is the innermost frame, at the top level (its
 * BATCH - will need no parent tag, and nothing encloses it to end first),
 * on the wire, and not deferred.  Only then can it outlive its line. */
static int fwd_label_adoptable(struct Client *from)
{
  struct Connection *con = cli_connect(from);
  unsigned int at = con->con_labeled_batch;

  if (!at || at != con->con_batch_depth || con->con_batch_over
      || con->con_fwd_adopted)
    return 0;
  if (con->con_batch[at - 1].parent[0] || !con->con_batch[at - 1].id[0])
    return 0;
  return !con_batch_hold(con);
}

/** Send \a acptr a labeled ACK for \a label (a forwarded command's,
 * not the line being handled: the connection's own label state is set
 * aside around it). */
static void fwd_label_ack(struct Client *acptr, const char *label)
{
  char saved[sizeof(cli_label(acptr))];
  unsigned char responded = cli_label_responded(acptr);

  if (!label[0])
    return;
  memcpy(saved, cli_label(acptr), sizeof(saved));
  ircd_strncpy(cli_label(acptr), label, sizeof(saved));
  cli_label_responded(acptr) = 0;
  send_labeled_ack(acptr);
  memcpy(cli_label(acptr), saved, sizeof(saved));
  cli_label_responded(acptr) = responded;
}

/** A forwarded command's answer did not come in time: its label is
 * answered now and the entry freed.  "The local server notices that the
 * remote server is unavailable and sends a labeled ACK" -- a PENDING
 * entry (nothing of the answer sent) is ACKed, an ACTIVE one has its
 * batch ended ("the batched response ends early").  Freed without an
 * answer, the label taken from the client at forwarding was never
 * answered at all.  Anything of the answer that comes later goes out
 * as it would without labeled-response. */
static void fwd_label_give_up(struct Client *acptr, struct ForwardedLabel *fl)
{
  if (fl->fl_state == FWD_LABEL_PENDING && MyConnect(acptr))
    fwd_label_ack(acptr, fl->fl_label);
  fwd_label_close_batch(acptr, fl);
}

/** Send order of tracked forwarded commands (fl_seq). */
static unsigned long fwd_seq_counter = 0;

/** Index of \a cmd in the terminal table, or -1. */
static int fwd_terminal_index(const char *cmd)
{
  int i;

  for (i = 0; fwd_terminals[i].cmd; i++)
    if (ircd_strcmp(cmd, fwd_terminals[i].cmd) == 0)
      return i;
  return -1;
}

/** The subject of a command of family \a fam forwarded to \a dest with
 * \a parv (fwd_match.h), into \a buf.
 * @return 1, or 0 if it has none that fits (the command is then left
 *   untracked). */
static int fwd_subject(int fam, struct Client *dest, int parc, char *parv[],
                       char *buf, size_t len)
{
  const char *s = "";
  int idx = 0;

  switch (fwd_family_subject(fam)) {
  case FWD_SUBJ_NONE:
    buf[0] = '\0';
    return 1;
  case FWD_SUBJ_SERVER:
    s = cli_name(dest);
    break;
  case FWD_SUBJ_PARV1:
    idx = 1;
    break;
  case FWD_SUBJ_PARV2:
    idx = 2;
    break;
  }
  if (idx) {
    s = (idx < parc && parv[idx]) ? parv[idx] : "";
    if (fam == FWD_FAM_LINKS && !*s)
      s = "*";                      /* ms_links answers "*" for no mask */
  }
  if (!*s || strlen(s) >= len)
    return 0;
  ircd_strncpy(buf, s, len);
  if (fam == FWD_FAM_LINKS)
    collapse(buf);                  /* as ms_links does before its 365 */
  return 1;
}

/** Whether a command of family \a fam that \a from forwarded was left
 * untracked recently enough that its replies may still come: until then
 * a reply of that family could be its, and none can be labeled. */
static int fwd_untracked_recent(struct Client *from, int fam)
{
  struct Connection *con = cli_connect(from);

  if (con->con_fwd_untracked
      && CurrentTime - con->con_fwd_untracked_at > FWD_DEADLINE)
    con->con_fwd_untracked = 0;
  return (con->con_fwd_untracked >> fam) & 1;
}

/** Stop labeling a tracked command's reply: its label is answered now --
 * an ACK if nothing of the reply went out, the end of its batch if some
 * did ("the batched response ends early") -- and the entry stays as an
 * unlabeled one (fl_plain), still taking its own replies, which now go
 * out as they would without labeled-response. */
static void fwd_label_unlabel(struct Client *owner, struct ForwardedLabel *fl)
{
  if (fl->fl_plain)
    return;
  if (fl->fl_state == FWD_LABEL_PENDING)
    fwd_label_ack(owner, fl->fl_label);
  else if (MyConnect(owner) && CapOwnHas(owner, CAP_BATCH))
    send_batch_marker(owner, '-', fl->fl_batch_id, NULL, NULL, NULL, NULL);
  fl->fl_label[0] = '\0';
  fl->fl_batch_id[0] = '\0';
  fl->fl_state = FWD_LABEL_PENDING;
  fl->fl_plain = 1;
}

/** \a from forwarded a command of family \a fam that is not tracked (no
 * subject that fits, no free slot): its replies will match nothing, and
 * could be taken for a tracked command's of the same family or one that
 * shares its numerics.  Those stop being labeled now, and none is for
 * FWD_DEADLINE (fwd_untracked_recent()). */
static void fwd_label_untrack(struct Client *from, int fam)
{
  struct Connection *con = cli_connect(from);
  int f, i;

  for (f = 1; f < FWD_FAM_COUNT; f++)
    if (fwd_families_overlap(fam, f))
      con->con_fwd_untracked |= 1u << f;
  con->con_fwd_untracked_at = CurrentTime;
  for (i = 0; i < MAX_FORWARDED_LABELS; i++) {
    struct ForwardedLabel *fl = &cli_fwd_labels(from)[i];
    if (fl->fl_state != FWD_LABEL_EMPTY
        && ((con->con_fwd_untracked >> fl->fl_family) & 1))
      fwd_label_unlabel(from, fl);
  }
}

int fwd_label_forward(struct Client *from, const char *cmd, struct Client *dest,
                      int parc, char *parv[], char *msgid, uint64_t *time_out)
{
  struct ForwardedLabel *fl = NULL;
  struct HLC hlc;
  char logical_b64[4], counter_b64[10];
  char subject[FWD_SUBJECT_MAX];
  int i, t, fam, labeled;

  if (!from || !MyConnect(from) || !cmd || !dest || !cli_from(dest))
    return 0;

  /* A client that is never answered with labels has nothing to keep
   * apart: its replies go out plain whatever comes back. */
  if (!feature_bool(FEAT_CAP_labeled_response) || !LabeledResponseInUse(from))
    return 0;
  if (!feature_bool(FEAT_CAP_batch))
    return 0;

  /* A command whose replies we do not know (CONNECT, REHASH, RPING, ...)
   * is not tracked: its label is ACKed at the end of the line, as
   * always, and its replies go out plain.  None of them shares a
   * numeric with a tracked family. */
  fam = fwd_family_of(cmd);
  if (!fam || (t = fwd_terminal_index(cmd)) < 0)
    return 0;

  /* The label is the reply's to carry, unless it has been answered: by
   * the BATCH + of the labeled batch its handler opened before forwarding
   * (TRACE, which answers a line of its own, and WHOWAS) -- the forwarded
   * reply then joins that batch if it can be taken over
   * (fwd_label_adoptable()), else the command is tracked unlabeled and
   * its reply goes out plain. */
  labeled = cli_label(from)[0]
            && (!cli_label_responded(from) || fwd_label_adoptable(from));

  if (fwd_subject(fam, dest, parc, parv, subject, sizeof(subject))
      && !fwd_untracked_recent(from, fam)) {
    for (i = 0; i < MAX_FORWARDED_LABELS; i++)
      if (cli_fwd_labels(from)[i].fl_state == FWD_LABEL_EMPTY) {
        fl = &cli_fwd_labels(from)[i];
        break;
      }
  }
  if (!fl) {
    /* Untracked: a labeled one is ACKed at the end of the line (its
     * label is not taken), and replies of its family are labeled for
     * none of the client's commands until they can no longer come. */
    fwd_label_untrack(from, fam);
    return 0;
  }

  memset(fl, 0, sizeof(*fl));
  fl->fl_terminal = fwd_terminals[t].terminal;
  fl->fl_terminal2 = fwd_terminals[t].terminal2;
  fl->fl_family = fam;
  ircd_strncpy(fl->fl_subject, subject, sizeof(fl->fl_subject));
  ircd_strncpy(fl->fl_dest, cli_yxx(dest), sizeof(fl->fl_dest));
  ircd_strncpy(fl->fl_link, cli_yxx(cli_from(dest)), sizeof(fl->fl_link));
  fl->fl_seq = ++fwd_seq_counter;
  fl->fl_remaining = fam == FWD_FAM_NAMES ? fwd_list_count(subject) : 1;
  fl->fl_created = CurrentTime;
  fl->fl_state = FWD_LABEL_PENDING;

  if (labeled) {
    ircd_strncpy(fl->fl_label, cli_label(from), sizeof(fl->fl_label));
    if (cli_label_responded(from)) {
      /* The handler's labeled batch: the forwarded reply joins it.  The
       * entry takes it over -- its id, ACTIVE (its BATCH + is out) -- and
       * con_fwd_adopted marks the frame, so the handler's end of it (and
       * parse_client()'s) only takes it off the stack: it ends with the
       * forwarded reply, fwd_label_close_batch(). */
      struct Connection *con = cli_connect(from);

      ircd_strncpy(fl->fl_batch_id, con->con_batch[con->con_labeled_batch - 1].id,
                   sizeof(fl->fl_batch_id));
      con->con_fwd_adopted = con->con_labeled_batch;
      fl->fl_state = FWD_LABEL_ACTIVE;
    } else {
      /* Generate batch ID: fwd<counter> -- a reference for the client
       * alone (letters and digits only: the server numeric it carried
       * could put a '[' or ']' in it); the counter is unique in this
       * server. */
      snprintf(fl->fl_batch_id, sizeof(fl->fl_batch_id), "fwd%lu",
               ++fwd_batch_counter);
    }
    /* Suppress ACK and clear label from client */
    cli_label_responded(from) = 1;
    cli_label(from)[0] = '\0';
  } else
    fl->fl_plain = 1;

  /* Generate HLC msgid for compact tag correlation -- for an unlabeled
   * command too: a fork server's reply then comes back with it and is
   * matched to this entry exactly, never left for the matching of
   * replies without one. */
  hlc = hlc_global_event();
  inttobase64_64(logical_b64, (uint64_t)hlc.logical, 3);
  inttobase64_64(counter_b64, (uint64_t)(++fwd_batch_counter), 9);
  snprintf(fl->fl_msgid, sizeof(fl->fl_msgid), "%s%s%s",
           cli_yxx(&me), logical_b64, counter_b64);

  /* Output for caller to attach to S2S compact tag */
  ircd_strncpy(msgid, fl->fl_msgid, 15);
  *time_out = hlc_global()->physical_ms;
  return 1;
}

int fwd_label_is_echo(const char *msgid)
{
  size_t n = strlen(cli_yxx(&me));

  return msgid && n && !strncmp(msgid, cli_yxx(&me), n);
}

struct ForwardedLabel *fwd_label_find(struct Client *acptr, const char *msgid)
{
  int i;

  if (!acptr || !MyConnect(acptr))
    return NULL;

  for (i = 0; i < MAX_FORWARDED_LABELS; i++) {
    struct ForwardedLabel *fl = &cli_fwd_labels(acptr)[i];
    if (fl->fl_state == FWD_LABEL_EMPTY)
      continue;

    /* Timeout check */
    if (fl->fl_state == FWD_LABEL_DRAINING) {
      if (CurrentTime - fl->fl_created > FWD_TIMEOUT_DRAIN) {
        fwd_label_close_batch(acptr, fl);
        continue;
      }
    } else if (CurrentTime - fl->fl_created > FWD_TIMEOUT_NORMAL) {
      fwd_label_give_up(acptr, fl);
      continue;
    }

    /* Exact msgid correlation only.  There is deliberately NO
     * positional fallback: a numeric without a compact msgid is one
     * a legacy server produced, and it can belong to ANY command --
     * the old "first non-empty entry" fallback captured unrelated,
     * unlabeled remote WHOIS replies into a stale batch the client had
     * already closed, so they were silently discarded.  Labels are
     * only ever created toward IRCv3-aware destinations (s_user.c), so
     * every correlatable reply carries its msgid. */
    if (msgid && msgid[0] && fl->fl_msgid[0]
        && ircd_strcmp(fl->fl_msgid, msgid) == 0) {
      /* labeled-response is inert now (LabeledResponseInUse: the client
       * dropped batch or labeled-response): the entry is forgotten and
       * the answer goes out as it would to a client without
       * labeled-response -- never into a batch the client cannot have.
       * (A CAP change that makes labels inert closes or forgets every
       * entry at once, fwd_label_drop_all(); this is the backstop.) */
      if (!LabeledResponseInUse(acptr)) {
        memset(fl, 0, sizeof(*fl));
        return NULL;
      }
      return fl;
    }
  }

  return NULL;
}

/** Most connections whose forwarded commands a reply to one client can
 * answer (fwd_label_owners()). */
#define FWD_OWNERS_MAX 1

/** The local connections whose forwarded commands a reply addressed to
 * \a acptr may answer: \a acptr's own.
 * @return How many were put in \a owners. */
static int fwd_label_owners(struct Client *acptr, struct Client **owners, int max)
{
  if (max < 1)
    return 0;
  owners[0] = acptr;
  return 1;
}

struct ForwardedLabel *fwd_label_match(struct Client *acptr, int numeric,
                                       const char *params, struct Client *link,
                                       struct Client *source,
                                       struct Client **owner, int *fit)
{
  struct Client *owners[FWD_OWNERS_MAX];
  struct FwdView v[FWD_OWNERS_MAX * MAX_FORWARDED_LABELS];
  struct ForwardedLabel *fls[FWD_OWNERS_MAX * MAX_FORWARDED_LABELS];
  struct Client *who[FWD_OWNERS_MAX * MAX_FORWARDED_LABELS];
  unsigned char cand[FWD_OWNERS_MAX * MAX_FORWARDED_LABELS];
  int no, o, i, n = 0, pick, ambiguous;

  *owner = NULL;
  *fit = FWD_FIT_NO;
  if (!acptr || !MyConnect(acptr) || !link || !IsServer(link))
    return NULL;

  no = fwd_label_owners(acptr, owners, FWD_OWNERS_MAX);
  for (o = 0; o < no; o++) {
    for (i = 0; i < MAX_FORWARDED_LABELS; i++) {
      struct ForwardedLabel *fl = &cli_fwd_labels(owners[o])[i];

      if (fl->fl_state == FWD_LABEL_EMPTY || !fl->fl_family)
        continue;
      if (fl->fl_state != FWD_LABEL_DRAINING
          && CurrentTime - fl->fl_created > FWD_DEADLINE) {
        fwd_label_give_up(owners[o], fl);   /* never captures a later reply */
        continue;
      }
      v[n].fam = fl->fl_family;
      v[n].subject = fl->fl_subject;
      v[n].dest = fl->fl_dest;
      v[n].link = fl->fl_link;
      v[n].seq = fl->fl_seq;
      v[n].age = (long)(CurrentTime - fl->fl_created);
      fls[n] = fl;
      who[n] = owners[o];
      n++;
    }
  }
  if (!n)
    return NULL;

  /* An oper's replies name their true source: no server relays a
   * numeric to an oper under its own name (do_numeric()'s HIS_REWRITE),
   * so that is the server that sent it. */
  pick = fwd_pick(v, n, numeric, params, cli_yxx(link),
                  (source && IsServer(source)) ? cli_yxx(source) : NULL,
                  IsOper(acptr), cand, fit, &ambiguous);
  if (pick < 0)
    return NULL;

  if (ambiguous) {
    /* Commands to different servers behind this link that the reply
     * cannot tell apart: none of them is labeled from here on.  The
     * reply goes out unlabeled; the oldest still counts it (an end
     * frees it). */
    for (i = 0; i < n; i++)
      if (cand[i])
        fwd_label_unlabel(who[i], fls[i]);
  }
  /* labeled-response gone inert: forgotten (see fwd_label_find()) */
  if (!fls[pick]->fl_plain && !LabeledResponseInUse(who[pick])) {
    memset(fls[pick], 0, sizeof(*fls[pick]));
    return NULL;
  }
  *owner = who[pick];
  return fls[pick];
}

int fwd_label_reply_ends(struct Client *owner, struct ForwardedLabel *fl, int fit)
{
  if (fit == FWD_FIT_ELEMENT_END && fl->fl_remaining > 1) {
    fl->fl_remaining--;
    return 0;
  }
  if (fit != FWD_FIT_END && fit != FWD_FIT_ELEMENT_END)
    return 0;
  fwd_label_close_batch(owner, fl);
  return 1;
}

void fwd_label_open_batch(struct Client *acptr, struct ForwardedLabel *fl)
{
  char timebuf[48];

  if (!acptr || !fl)
    return;

  /* @label=xxx, optionally with time=xxx.  A forwarded command's batch is
   * its own (the answer comes on later turns), never nested: written by
   * the one BATCH line writer, send_batch_marker(). */
  timebuf[0] = '\0';
  if (feature_bool(FEAT_CAP_server_time) && CapActive(acptr, CAP_SERVERTIME)) {
    struct timeval tv;
    struct tm tm;
    gettimeofday(&tv, NULL);
    gmtime_r(&tv.tv_sec, &tm);
    snprintf(timebuf, sizeof(timebuf),
             "time=%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec,
             (long)(tv.tv_usec / 1000));
  }

  send_batch_marker(acptr, '+', fl->fl_batch_id, NULL, "labeled-response",
                    fl->fl_label, timebuf);

  fl->fl_state = FWD_LABEL_ACTIVE;
}

void fwd_label_close_batch(struct Client *acptr, struct ForwardedLabel *fl)
{
  if (!acptr || !fl)
    return;

  /* BATCH - only to a client that holds batch (one that dropped it is
   * sent no batch lines; its entry is just forgotten). */
  if ((fl->fl_state == FWD_LABEL_ACTIVE || fl->fl_state == FWD_LABEL_DRAINING)
      && MyConnect(acptr) && CapOwnHas(acptr, CAP_BATCH))
    send_batch_marker(acptr, '-', fl->fl_batch_id, NULL, NULL, NULL, NULL);

  memset(fl, 0, sizeof(*fl));
}

int fwd_label_is_terminal(struct ForwardedLabel *fl, int numeric)
{
  if (!fl)
    return 0;

  /* Generic error numerics are always terminal */
  if (numeric == 401 || numeric == 402)
    return 1;

  if (fl->fl_terminal && numeric == fl->fl_terminal)
    return 1;
  if (fl->fl_terminal2 && numeric == fl->fl_terminal2)
    return 1;

  return 0;
}

/** Periodic expiry sweep (timer-driven).  The lazy checks inside
 * fwd_label_find*() only run when a numeric or client command arrives
 * -- an idle client's stale entries otherwise live forever: a
 * DRAINING batch stayed open (client buffers the response), and four
 * stranded PENDING entries exhausted the FIFO so later labels
 * degraded to plain ACK. */
void fwd_label_expire_all(void)
{
  int fd, i;

  for (fd = HighestFd; fd >= 0; fd--) {
    struct Client *acptr = LocalClientArray[fd];
    if (!acptr || !cli_connect(acptr))
      continue;
    for (i = 0; i < MAX_FORWARDED_LABELS; i++) {
      struct ForwardedLabel *fl = &cli_fwd_labels(acptr)[i];
      if (fl->fl_state == FWD_LABEL_EMPTY)
        continue;
      if (fl->fl_state == FWD_LABEL_DRAINING) {
        if (CurrentTime - fl->fl_created > FWD_TIMEOUT_DRAIN)
          fwd_label_close_batch(acptr, fl);
      } else if (CurrentTime - fl->fl_created > FWD_TIMEOUT_NORMAL)
        fwd_label_give_up(acptr, fl);
    }
  }
}

void fwd_label_close_draining(struct Client *acptr)
{
  int i;

  if (!acptr || !MyConnect(acptr))
    return;

  for (i = 0; i < MAX_FORWARDED_LABELS; i++) {
    struct ForwardedLabel *fl = &cli_fwd_labels(acptr)[i];
    if (fl->fl_state == FWD_LABEL_DRAINING)
      fwd_label_close_batch(acptr, fl);
  }
}

void fwd_label_drop_all(struct Client *cptr, int send_end)
{
  int i;

  if (!cptr || !MyConnect(cptr))
    return;

  /* cap_dependents_drop(), before the CAP ACK: a batch the client was sent
   * the start of is ended now (@a send_end: it held batch until this
   * change), so it is never left open.  The rest (PENDING: nothing sent
   * yet) is forgotten. */
  for (i = 0; i < MAX_FORWARDED_LABELS; i++) {
    struct ForwardedLabel *fl = &cli_fwd_labels(cptr)[i];
    if (send_end && (fl->fl_state == FWD_LABEL_ACTIVE
                     || fl->fl_state == FWD_LABEL_DRAINING))
      send_batch_marker(cptr, '-', fl->fl_batch_id, NULL, NULL, NULL, NULL);
  }
  fwd_label_cleanup(cptr);
}

void fwd_label_cleanup(struct Client *cptr)
{
  if (!cptr || !MyConnect(cptr))
    return;

  memset(cli_fwd_labels(cptr), 0,
         sizeof(struct ForwardedLabel) * MAX_FORWARDED_LABELS);
  cli_connect(cptr)->con_fwd_untracked = 0;
}
