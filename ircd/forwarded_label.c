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
#include "bouncer_session.h"
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
  { "CHECK",    291, 292 },  /* RPL_ENDOFCHECK / ERR_SEARCHNOMATCH */
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

/** Every family, and the commands of unknown replies: what a connection
 * marks untracked when it cannot tell what is outstanding. */
#define FWD_UNTRACKED_ALL (FWD_UNTRACKED_GENERIC | (((1u << FWD_FAM_COUNT) - 1) & ~1u))

/** The families (and FWD_UNTRACKED_GENERIC) of which \a cptr sent a
 * command that is not tracked recently enough that its replies may still
 * come (con_fwd_untracked): a reply that numeric of such a family could
 * be its, so none is labeled (fwd_pick()). */
static unsigned int fwd_untracked_mask(struct Client *cptr)
{
  struct Connection *con = cli_connect(cptr);

  if (con->con_fwd_untracked
      && CurrentTime - con->con_fwd_untracked_at > FWD_DEADLINE)
    con->con_fwd_untracked = 0;
  return con->con_fwd_untracked;
}

/** Mark \a bits (families, FWD_UNTRACKED_GENERIC) untracked on \a cptr
 * for FWD_DEADLINE from now.  Never cleared before that -- not by a CAP
 * change, which forgets the entries, not the commands they stood for. */
static void fwd_mark_untracked(struct Client *cptr, unsigned int bits)
{
  struct Connection *con = cli_connect(cptr);

  (void)fwd_untracked_mask(cptr);      /* an old window has run out */
  con->con_fwd_untracked |= bits;
  con->con_fwd_untracked_at = CurrentTime;
}

void fwd_label_note_untracked(struct Client *cptr, unsigned int bits)
{
  if (cptr && MyConnect(cptr) && bits)
    fwd_mark_untracked(cptr, bits);
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
 * FWD_DEADLINE (fwd_untracked_mask(), fwd_pick()). */
static void fwd_label_untrack(struct Client *from, int fam)
{
  int i;

  fwd_mark_untracked(from, 1u << fam);
  for (i = 0; i < MAX_FORWARDED_LABELS; i++) {
    struct ForwardedLabel *fl = &cli_fwd_labels(from)[i];
    if (fl->fl_state != FWD_LABEL_EMPTY && fwd_families_overlap(fam, fl->fl_family))
      fwd_label_unlabel(from, fl);
  }
}

/** Most connections whose forwarded commands a reply to one client can
 * answer (fwd_label_owners()): a session's primary and its devices. */
#define FWD_OWNERS_MAX (1 + BOUNCER_MAX_ALIASES)

/** The local connections whose forwarded commands a reply addressed to
 * \a acptr may answer: \a acptr's own, and -- for a bouncer session's
 * primary -- its devices on this server.  hunt_server_cmd() sends a
 * device's command on under the primary's numeric (bouncer invariant
 * #10: legacy servers do not know the device), so its replies come back
 * addressed to the primary; the device's own Connection holds the entry,
 * for the label is the connection's that sent the command.  \a acptr may
 * be a primary on another server: the reply is then passing through, and
 * the owners are that primary's devices here.
 * @param[out] remote Set (if not NULL) when the session has a device on
 *   another server.
 * @return How many were put in \a owners. */
static int fwd_label_owners(struct Client *acptr, struct Client **owners, int max,
                            int *remote)
{
  struct BouncerSession *bs;
  int n = 0, ai;

  if (remote)
    *remote = 0;
  if (max < 1)
    return 0;
  /* \a acptr itself only when it is our connection: a primary on another
   * server has no entries here (its Connection is its link's), its
   * devices here do. */
  if (MyConnect(acptr))
    owners[n++] = acptr;
  if (IsBouncerAlias(acptr) || !(bs = bounce_get_session(acptr)))
    return n;
  for (ai = 0; ai < bs->hs_alias_count; ai++) {
    struct Client *alias = findNUser(bs->hs_aliases[ai].ba_numeric);
    if (!alias || alias == acptr || !IsBouncerAlias(alias) || !cli_user(alias)
        || cli_user(alias)->alias_primary != acptr)
      continue;
    if (!MyConnect(alias)) {
      if (remote)
        *remote = 1;
    } else if (n < max)
      owners[n++] = alias;
  }
  return n;
}

/** Whether the replies to \a from's forwarded command have to be told
 * apart from another command's on this server:
 *  - \a from uses labeled-response, or another connection of its bouncer
 *    session here does (the reply may have to carry a label, or must not
 *    be taken for a labeled command's);
 *  - \a from is a bouncer device: its command goes out under its
 *    primary's numeric, or toward its primary's server, and the reply
 *    comes back addressed to the primary;
 *  - \a from is a primary whose session has another connection, here or
 *    on another server: that connection's replies come addressed to it.
 * Remembered for none of them, a reply was copied to every connection of
 * the session on the primary's server, and never reached a device on
 * another one.  Remembered, it goes to the connection whose command it
 * answers (do_numeric()), labels or not. */
static int fwd_labels_in_session(struct Client *from)
{
  struct Client *owners[FWD_OWNERS_MAX];
  int n, remote;

  if (LabeledResponseInUse(from))
    return 1;
  if (IsBouncerAlias(from) && cli_user(from) && cli_user(from)->alias_primary)
    return 1;
  n = fwd_label_owners(from, owners, FWD_OWNERS_MAX, &remote);
  return n > 1 || remote;
}

int fwd_label_forward(struct Client *from, struct Client *asker,
                      const char *cmd, struct Client *dest,
                      int parc, char *parv[], char *msgid, uint64_t *time_out)
{
  struct ForwardedLabel *fl = NULL;
  struct HLC hlc;
  char logical_b64[4], counter_b64[10];
  char subject[FWD_SUBJECT_MAX];
  int i, t, fam, labeled;

  if (!from || !MyConnect(from) || !cmd || !dest || !cli_from(dest))
    return 0;

  if (!feature_bool(FEAT_CAP_labeled_response) || !feature_bool(FEAT_CAP_batch))
    return 0;

  /* A command whose replies we do not know (CONNECT, REHASH, RPING, ...)
   * is not tracked: its label is ACKed at the end of the line, as
   * always, and its replies go out plain.  Its refusal (402, 481) could
   * be taken for another command's, so it is marked. */
  fam = fwd_family_of(cmd);
  if (!fam || (t = fwd_terminal_index(cmd)) < 0) {
    fwd_mark_untracked(from, FWD_UNTRACKED_GENERIC);
    return 0;
  }

  /* A connection with nothing to keep apart -- no labels in use on it or
   * on another connection of its bouncer session here, and no other
   * connection of that session here whose replies come addressed to the
   * same primary -- is not tracked.  The command is marked: if labels
   * come into use before its replies are in, they are not taken for a
   * labeled command's. */
  if (!asker && !fwd_labels_in_session(from)) {
    fwd_mark_untracked(from, 1u << fam);
    return 0;
  }

  /* The label is the reply's to carry, unless it has been answered: by
   * the BATCH + of the labeled batch its handler opened before forwarding
   * (TRACE, which answers a line of its own, and WHOWAS) -- the forwarded
   * reply then joins that batch if it can be taken over
   * (fwd_label_adoptable()), else the command is tracked unlabeled and
   * its reply goes out plain. */
  labeled = !asker && LabeledResponseInUse(from) && cli_label(from)[0]
            && (!cli_label_responded(from) || fwd_label_adoptable(from));

  /* (A family marked untracked is still tracked: a reply that may be the
   * untracked command's is labeled for none, fwd_pick().) */
  if (fwd_subject(fam, dest, parc, parv, subject, sizeof(subject))) {
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

  if (asker) {
    /* Sent on for a device on another server: the entry is its primary's
     * (\a from), and says whose reply it is.  The msgid the command
     * arrived with is kept, so the device's own server matches the reply
     * by it too when we hand it back. */
    struct Client *link = cli_from(asker);

    snprintf(fl->fl_asker, sizeof(fl->fl_asker), "%s%s", NumNick(asker));
    if (feature_bool(FEAT_P10_MESSAGE_TAGS) && link
        && sendcmdto_stash_is_current(link) && cli_s2s_msgid(link)[0]
        && strlen(cli_s2s_msgid(link)) < sizeof(fl->fl_msgid)) {
      ircd_strncpy(fl->fl_msgid, cli_s2s_msgid(link), sizeof(fl->fl_msgid));
      ircd_strncpy(msgid, fl->fl_msgid, 15);
      *time_out = cli_s2s_time_ms(link);
      return 1;
    }
  }

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
     * already closed, so they were silently discarded.  A reply
     * without a msgid is matched by fwd_label_match() instead, by the
     * family and subject it names. */
    if (msgid && msgid[0] && fl->fl_msgid[0]
        && ircd_strcmp(fl->fl_msgid, msgid) == 0) {
      /* labeled-response is inert now (LabeledResponseInUse: the client
       * dropped batch or labeled-response): the entry is forgotten and
       * the answer goes out as it would to a client without
       * labeled-response -- never into a batch the client cannot have.
       * (A CAP change that makes labels inert closes or forgets every
       * entry at once, fwd_label_drop_all(); this is the backstop.)
       * An unlabeled command's entry needs no labels: it only says
       * whose reply this is. */
      if (!fl->fl_plain && !LabeledResponseInUse(acptr)) {
        memset(fl, 0, sizeof(*fl));
        return NULL;
      }
      return fl;
    }
  }

  return NULL;
}

struct Client *fwd_label_asker(struct Client *owner, struct ForwardedLabel *fl)
{
  struct Client *device;

  if (!fl || !fl->fl_asker[0])
    return owner;
  device = findNUser(fl->fl_asker);
  if (device && IsBouncerAlias(device) && cli_user(device)
      && cli_user(device)->alias_primary == owner)
    return device;
  return NULL;
}

struct ForwardedLabel *fwd_label_find_for(struct Client *acptr, const char *msgid,
                                          struct Client **owner)
{
  struct Client *owners[FWD_OWNERS_MAX];
  struct ForwardedLabel *fl;
  int no, o;

  *owner = NULL;
  if (!acptr || !IsUser(acptr) || !msgid || !msgid[0])
    return NULL;
  no = fwd_label_owners(acptr, owners, FWD_OWNERS_MAX, NULL);
  for (o = 0; o < no; o++)
    if ((fl = fwd_label_find(owners[o], msgid))) {
      *owner = owners[o];
      return fl;
    }
  return NULL;
}

struct ForwardedLabel *fwd_label_match(struct Client *acptr, int numeric,
                                       const char *params, struct Client *link,
                                       struct Client *source,
                                       struct Client **owner, int *fit,
                                       struct Client **askers, int max_askers,
                                       int *n_askers)
{
  struct Client *owners[FWD_OWNERS_MAX];
  struct FwdView v[FWD_OWNERS_MAX * MAX_FORWARDED_LABELS];
  struct ForwardedLabel *fls[FWD_OWNERS_MAX * MAX_FORWARDED_LABELS];
  struct Client *who[FWD_OWNERS_MAX * MAX_FORWARDED_LABELS];
  unsigned char cand[FWD_OWNERS_MAX * MAX_FORWARDED_LABELS];
  unsigned int untracked = 0;
  int no, o, i, n = 0, pick, ambiguous, remote;

  *owner = NULL;
  *fit = FWD_FIT_NO;
  if (n_askers)
    *n_askers = 0;
  if (!acptr || !IsUser(acptr) || !link || !IsServer(link))
    return NULL;

  /* What none of these connections tracked may be answered by this reply
   * too: their untracked commands.  (A session's device on another server
   * used to make every reply one of those: its commands came back here
   * unseen.  They are remembered now by the server that sends them on
   * under the primary's numeric -- this one, in its primary's entries
   * with fl_asker, or the device's own.) */
  no = fwd_label_owners(acptr, owners, FWD_OWNERS_MAX, &remote);
  (void)remote;
  for (o = 0; o < no; o++) {
    untracked |= fwd_untracked_mask(owners[o]);
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
                  IsOper(acptr), untracked, cand, fit, &ambiguous);
  if (pick < 0)
    return NULL;

  if (ambiguous) {
    /* Commands to different servers behind this link that the reply
     * cannot tell apart, or one that may be an untracked command's: none
     * of them is labeled from here on.  The reply goes out unlabeled;
     * the oldest still counts it (an end frees it). */
    int ids[FWD_OWNERS_MAX * MAX_FORWARDED_LABELS];
    struct Client *seen[FWD_OWNERS_MAX * MAX_FORWARDED_LABELS];
    int nseen = 0, k;

    for (i = 0; i < n; i++) {
      ids[i] = -1;
      if (!cand[i])
        continue;
      fwd_label_unlabel(who[i], fls[i]);
      /* Whose it may be: when the candidates are several connections',
       * the caller sends the reply to each of them (fwd_cand_askers()). */
      {
        struct Client *a = fwd_label_asker(who[i], fls[i]);

        for (k = 0; k < nseen; k++)
          if (seen[k] == a)
            break;
        if (k == nseen)
          seen[nseen++] = a;
        ids[i] = k;
      }
    }
    if (askers && n_askers && fwd_cand_askers(ids, cand, n) > 1) {
      for (k = 0; k < nseen && *n_askers < max_askers; k++)
        if (seen[k])
          askers[(*n_askers)++] = seen[k];
    }
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
  if (!fl->fl_plain
      && (fl->fl_state == FWD_LABEL_ACTIVE || fl->fl_state == FWD_LABEL_DRAINING)
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

int fwd_label_exact_ends(struct ForwardedLabel *fl, int numeric)
{
  if (!fwd_label_is_terminal(fl, numeric))
    return 0;
  /* NAMES of several channels: a 366 each, the last one ends it. */
  if (fl->fl_family == FWD_FAM_NAMES && numeric == fl->fl_terminal
      && fl->fl_remaining > 1) {
    fl->fl_remaining--;
    return 0;
  }
  return 1;
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
    /* A plain entry waiting for the rest of its reply is no batch to
     * end: its terminal, or the sweep, frees it. */
    if (fl->fl_state == FWD_LABEL_DRAINING && !fl->fl_plain)
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
    /* (A plain entry is no batch, DRAINING or not.) */
    if (send_end && !fl->fl_plain
        && (fl->fl_state == FWD_LABEL_ACTIVE
            || fl->fl_state == FWD_LABEL_DRAINING))
      send_batch_marker(cptr, '-', fl->fl_batch_id, NULL, NULL, NULL, NULL);
  }
  /* The entries go; the commands they stood for may still be answered.
   * Until they cannot be, no reply is taken for a labeled command's
   * should labels come back into use (the untracked marks are kept, and
   * every family is marked). */
  memset(cli_fwd_labels(cptr), 0,
         sizeof(struct ForwardedLabel) * MAX_FORWARDED_LABELS);
  fwd_mark_untracked(cptr, FWD_UNTRACKED_ALL);
}

void fwd_label_server_gone(struct Client *server)
{
  const char *yxx;
  int fd, i;

  if (!server || !IsServer(server) || !*(yxx = cli_yxx(server)))
    return;
  for (fd = HighestFd; fd >= 0; fd--) {
    struct Client *acptr = LocalClientArray[fd];
    if (!acptr || !cli_connect(acptr) || !IsUser(acptr))
      continue;
    for (i = 0; i < MAX_FORWARDED_LABELS; i++) {
      struct ForwardedLabel *fl = &cli_fwd_labels(acptr)[i];
      if (fl->fl_state != FWD_LABEL_EMPTY && fl->fl_family
          && (!strcmp(fl->fl_dest, yxx) || !strcmp(fl->fl_link, yxx)))
        fwd_label_give_up(acptr, fl);
    }
  }
}

void fwd_label_cleanup(struct Client *cptr)
{
  if (!cptr || !MyConnect(cptr))
    return;

  memset(cli_fwd_labels(cptr), 0,
         sizeof(struct ForwardedLabel) * MAX_FORWARDED_LABELS);
  cli_connect(cptr)->con_fwd_untracked = 0;
}
