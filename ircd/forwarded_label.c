/** @file forwarded_label.c
 * @brief Labeled-response support for commands forwarded via hunt_server_cmd.
 *
 * Manages per-connection ForwardedLabel FIFO entries that track pending
 * forwarded labels, correlate responses via compact tag msgids, and handle
 * batch lifecycle (PENDING → ACTIVE → DRAINING → EMPTY).
 */
#include "config.h"

#include "forwarded_label.h"
#include "client.h"
#include "crdt_hlc.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_string.h"
#include "msg.h"
#include "numnicks.h"
#include "send.h"
#include "s_bsd.h"
#include "struct.h"

#include <string.h>
#include <stdio.h>
#include <sys/time.h>

/** Terminal numeric table for forwarded commands.
 * Maps command names to their terminal numeric(s).  On a tagged route
 * the error numerics 401 (ERR_NOSUCHNICK) and 402 (ERR_NOSUCHSERVER)
 * are always terminal.  On an order route (see fwd_label_forward) any
 * error ends the reply except the one a command's reply goes on past,
 * \a cont.
 */
static const struct {
  const char    *cmd;
  unsigned short terminal;
  unsigned short terminal2;
  unsigned short cont;
} fwd_terminals[] = {
  { "WHOIS",    318, 0,   401 },  /* RPL_ENDOFWHOIS (401 per missing nick) */
  { "STATS",    219, 0,   0   },  /* RPL_ENDOFSTATS */
  { "LINKS",    365, 0,   0   },  /* RPL_ENDOFLINKS */
  { "INFO",     374, 0,   0   },  /* RPL_ENDOFINFO */
  { "MOTD",     376, 422, 0   },  /* RPL_ENDOFMOTD / ERR_NOMOTD */
  { "TRACE",    262, 0,   0   },  /* RPL_TRACEEND */
  { "ADMIN",    259, 0,   0   },  /* RPL_ADMINEMAIL (last in fixed sequence) */
  { "VERSION",  351, 0,   0   },  /* RPL_VERSION (single numeric) */
  { "TIME",     391, 0,   0   },  /* RPL_TIME (single numeric) */
  { "LUSERS",   266, 0,   0   },  /* RPL_CURRENT_GLOBAL (last numeric) */
  { "RULES",    309, 0,   0   },  /* RPL_ENDOFRULES */
  { "OPERMOTD", 537, 0,   0   },  /* RPL_ENDOFOMOTD */
  { "WHOWAS",   369, 0,   406 },  /* RPL_ENDOFWHOWAS (406 precedes it on miss) */
  { "NAMES",    366, 0,   0   },  /* RPL_ENDOFNAMES */
  { NULL, 0, 0, 0 }
};

/** Counter for generating unique forwarded batch IDs. */
static unsigned long fwd_batch_counter = 0;

/** Send order of order-route entries (fl_seq). */
static unsigned long fwd_order_counter = 0;

/** Timeout in seconds for PENDING/ACTIVE entries. */
#define FWD_TIMEOUT_NORMAL  60

/** Timeout in seconds for DRAINING entries. */
#define FWD_TIMEOUT_DRAIN   5

/** Find \a cmd in the terminal table.
 * @return Its index, or -1 for a command the table does not know. */
static int fwd_terminal_index(const char *cmd)
{
  int i;

  for (i = 0; fwd_terminals[i].cmd; i++)
    if (ircd_strcmp(cmd, fwd_terminals[i].cmd) == 0)
      return i;
  return -1;
}

/** Claim an empty slot of \a from's FIFO for \a cmd (table index \a t).
 * @return The slot, zeroed but for its terminals and time, or NULL. */
static struct ForwardedLabel *fwd_label_claim(struct Client *from, int t)
{
  struct ForwardedLabel *fl;
  int i;

  for (i = 0; i < MAX_FORWARDED_LABELS; i++) {
    fl = &cli_fwd_labels(from)[i];
    if (fl->fl_state != FWD_LABEL_EMPTY)
      continue;
    memset(fl, 0, sizeof(*fl));
    fl->fl_terminal = fwd_terminals[t].terminal;
    fl->fl_terminal2 = fwd_terminals[t].terminal2;
    fl->fl_cont = fwd_terminals[t].cont;
    fl->fl_created = CurrentTime;
    fl->fl_state = FWD_LABEL_PENDING;
    return fl;
  }
  return NULL;
}

/** Hand \a from's label to \a fl: the forwarded reply is the labeled
 * response now, so no ACK goes out for the command.  A handler that
 * opened its labeled-response batch before it forwarded (TRACE, which
 * also answers a line of its own, and WHOWAS) has already sent the
 * label on that batch's BATCH +: the forwarded reply joins that batch
 * instead of opening a second one with the same label.  The batch then
 * stays open past the handler -- labeled_batch_end() sees 2 and only
 * forgets it -- and closes with the forwarded reply. */
static void fwd_label_take(struct Client *from, struct ForwardedLabel *fl)
{
  ircd_strncpy(fl->fl_label, cli_label(from), sizeof(fl->fl_label));

  if (cli_labeled_batch(from) == 1 && cli_batch_id(from)[0]) {
    ircd_strncpy(fl->fl_batch_id, cli_batch_id(from), sizeof(fl->fl_batch_id));
    fl->fl_state = FWD_LABEL_ACTIVE;
    cli_labeled_batch(from) = 2;
  } else {
    /* Generate batch ID: fwd<counter><server_yxx> */
    snprintf(fl->fl_batch_id, sizeof(fl->fl_batch_id), "fwd%lu%s",
             ++fwd_batch_counter, cli_yxx(&me));
  }

  /* Suppress ACK and clear label from client */
  cli_label_responded(from) = 1;
  cli_label(from)[0] = '\0';
}

/** Mint a compact msgid for a forwarded command (fl_msgid's form: our
 * numeric, the HLC logical counter, a running counter).
 * @param[out] msgid    Buffer of at least 16 bytes.
 * @param[out] time_out The HLC physical time for the compact tag. */
static void fwd_correlation_id(char *msgid, uint64_t *time_out)
{
  struct HLC hlc;
  char logical_b64[4], counter_b64[10];

  hlc = hlc_global_event();
  inttobase64_64(logical_b64, (uint64_t)hlc.logical, 3);
  inttobase64_64(counter_b64, (uint64_t)(++fwd_batch_counter), 9);
  snprintf(msgid, 16, "%s%s%s", cli_yxx(&me), logical_b64, counter_b64);
  *time_out = hlc_global()->physical_ms;
}

int fwd_label_save(struct Client *from, const char *cmd,
                   char *msgid, uint64_t *time_out)
{
  struct ForwardedLabel *fl;
  int t;

  if (!from || !MyConnect(from) || !cmd)
    return 0;

  /* Must have label + labeled-response + batch caps */
  if (!cli_label(from)[0])
    return 0;
  if (!feature_bool(FEAT_CAP_labeled_response) || !CapActive(from, CAP_LABELEDRESP))
    return 0;
  if (!feature_bool(FEAT_CAP_batch) || !CapActive(from, CAP_BATCH))
    return 0;

  if ((t = fwd_terminal_index(cmd)) < 0)
    return 0;  /* Unknown command — don't handle */

  if (!(fl = fwd_label_claim(from, t)))
    return 0;  /* No room */

  /* Generate HLC msgid for compact tag correlation */
  fwd_correlation_id(fl->fl_msgid, time_out);

  /* Output for caller to attach to S2S compact tag */
  ircd_strncpy(msgid, fl->fl_msgid, 15);

  fwd_label_take(from, fl);

  return 1;
}

/** Whether a reply from \a dest comes back carrying the compact msgid
 * of the command it answers: we send S2S tags, and every server on the
 * way to \a dest is IRCv3-aware.  A legacy server neither receives the
 * tag (send.c gates the @A prefix on IsIRCv3Aware) nor passes one on,
 * whether it is the destination or a hop on the way; a fork server
 * behind a legacy hop is seen without its 'v' flag, which a legacy
 * server does not relay. */
static int fwd_route_tagged(struct Client *dest)
{
  struct Client *srv;

  if (!feature_bool(FEAT_P10_MESSAGE_TAGS))
    return 0;
  for (srv = dest; srv && !IsMe(srv); srv = cli_serv(srv)->up)
    if (!cli_serv(srv) || !IsIRCv3Aware(srv))
      return 0;
  return srv != NULL;
}

/** Track a command forwarded over an order route (see fwd_label_forward).
 * @return 1 if tracked, 0 if not (the caller marks the client). */
static int fwd_label_save_order(struct Client *from, const char *cmd,
                                struct Client *dest, int labeled)
{
  struct ForwardedLabel *fl;
  struct Client *link = cli_from(dest);
  int t, i;

  if ((t = fwd_terminal_index(cmd)) < 0)
    return 0;  /* replies of unknown shape */

  /* An untracked command's replies may still be on their way: until
   * they cannot be, a label here would take them for its own. */
  if (labeled && cli_fwd_untracked(from)
      && CurrentTime - cli_fwd_untracked(from) <= FWD_TIMEOUT_NORMAL)
    return 0;

  /* Replies are matched by the link they come over (fwd_label_find_order),
   * and two servers behind one link need not answer in the order they
   * were asked: one destination per link at a time. */
  for (i = 0; i < MAX_FORWARDED_LABELS; i++) {
    struct ForwardedLabel *other = &cli_fwd_labels(from)[i];
    if (other->fl_state != FWD_LABEL_EMPTY && other->fl_link[0]
        && !strcmp(other->fl_link, cli_yxx(link))
        && strcmp(other->fl_server, cli_yxx(dest)))
      return 0;
  }

  if (!(fl = fwd_label_claim(from, t)))
    return 0;

  ircd_strncpy(fl->fl_server, cli_yxx(dest), sizeof(fl->fl_server));
  ircd_strncpy(fl->fl_link, cli_yxx(link), sizeof(fl->fl_link));
  fl->fl_seq = ++fwd_order_counter;
  if (labeled)
    fwd_label_take(from, fl);
  else
    fl->fl_plain = 1;
  return 1;
}

int fwd_label_forward(struct Client *from, const char *cmd,
                      struct Client *dest, char *msgid, uint64_t *time_out)
{
  int labeled;

  if (!from || !MyConnect(from) || !cmd || !dest)
    return 0;

  /* A client that never gets a labeled response has nothing to keep
   * apart: its replies go out plain whatever the route. */
  if (!feature_bool(FEAT_CAP_labeled_response) || !CapActive(from, CAP_LABELEDRESP)
      || !feature_bool(FEAT_CAP_batch) || !CapActive(from, CAP_BATCH))
    return 0;
  labeled = cli_label(from)[0] != '\0';

  if (fwd_route_tagged(dest)) {
    if (labeled && fwd_label_save(from, cmd, msgid, time_out))
      return 1;
    /* Not labeled (or not saved): it carries a compact msgid all the
     * same, so that its reply comes back with one and is never taken
     * for an order route's (fwd_label_find_order matches only replies
     * without a msgid).  No entry: the reply goes out plain.  A command
     * the table does not know (CONNECT, REHASH, ...) goes untagged, as
     * it always has, and is left untracked like one on an order route. */
    if (fwd_terminal_index(cmd) >= 0) {
      fwd_correlation_id(msgid, time_out);
      return 1;
    }
    cli_fwd_untracked(from) = CurrentTime;
    return 0;
  }

  /* Order route: a command left untracked -- of unknown shape, a full
   * FIFO, a label refused just above -- gets its replies plain, and
   * holds off labels on order routes until they have had time to come
   * in (a labeled command so refused gets the plain ACK, as before). */
  if (!fwd_label_save_order(from, cmd, dest, labeled))
    cli_fwd_untracked(from) = CurrentTime;
  return 0;
}

struct ForwardedLabel *fwd_label_find_order(struct Client *acptr,
                                            struct Client *source)
{
  struct ForwardedLabel *found = NULL;
  const char *link;
  int i;

  if (!acptr || !MyConnect(acptr) || !source || !IsServer(source)
      || !cli_from(source))
    return NULL;

  /* Matched by the link the reply came over, not by its source: every
   * server that relays a numeric to a non-oper names itself as its
   * source (HIS_REWRITE), so the source is the destination for an oper
   * and the next hop for anyone else. */
  link = cli_yxx(cli_from(source));

  for (i = 0; i < MAX_FORWARDED_LABELS; i++) {
    struct ForwardedLabel *fl = &cli_fwd_labels(acptr)[i];
    if (fl->fl_state == FWD_LABEL_EMPTY || !fl->fl_link[0])
      continue;
    if (CurrentTime - fl->fl_created > FWD_TIMEOUT_NORMAL) {
      fwd_label_close_batch(acptr, fl);
      continue;
    }
    if (strcmp(fl->fl_link, link))
      continue;
    if (!found || fl->fl_seq < found->fl_seq)
      found = fl;
  }
  return found;
}

int fwd_label_order_done(struct ForwardedLabel *fl, int numeric)
{
  if (!fl)
    return 0;
  if (numeric == fl->fl_terminal
      || (fl->fl_terminal2 && numeric == fl->fl_terminal2))
    return 1;
  /* An error is the whole reply (ERR_NOPRIVILEGES from the far side's
   * hunt, a HIS refusal, ERR_NOADMININFO) unless the command's reply goes
   * on past it.  Left open, the entry would take the replies to the
   * client's next command to that server for its own. */
  return numeric >= 400 && numeric < 600 && numeric != fl->fl_cont;
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
      if (fl->fl_state == FWD_LABEL_ACTIVE)
        fwd_label_close_batch(acptr, fl);
      else
        memset(fl, 0, sizeof(*fl));
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
        && ircd_strcmp(fl->fl_msgid, msgid) == 0)
      return fl;
  }

  return NULL;
}

void fwd_label_open_batch(struct Client *acptr, struct ForwardedLabel *fl)
{
  char tagbuf[256];
  int pos = 0;

  if (!acptr || !fl)
    return;

  /* Build @label=xxx tag, optionally with ;time=xxx */
  tagbuf[0] = '@';
  pos = 1;
  pos += snprintf(tagbuf + pos, sizeof(tagbuf) - pos, "label=%s", fl->fl_label);

  if (feature_bool(FEAT_CAP_server_time) && CapActive(acptr, CAP_SERVERTIME)) {
    struct timeval tv;
    struct tm tm;
    if (pos < (int)sizeof(tagbuf) - 1)
      tagbuf[pos++] = ';';
    gettimeofday(&tv, NULL);
    gmtime_r(&tv.tv_sec, &tm);
    pos += snprintf(tagbuf + pos, sizeof(tagbuf) - pos,
                    "time=%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ",
                    tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                    tm.tm_hour, tm.tm_min, tm.tm_sec,
                    (long)(tv.tv_usec / 1000));
  }

  tagbuf[pos] = '\0';

  sendrawto_one(acptr, "%s :%s " MSG_BATCH_CMD " +%s labeled-response",
                tagbuf, cli_name(&me), fl->fl_batch_id);

  fl->fl_state = FWD_LABEL_ACTIVE;
}

void fwd_label_close_batch(struct Client *acptr, struct ForwardedLabel *fl)
{
  if (!acptr || !fl)
    return;

  if (fl->fl_state == FWD_LABEL_ACTIVE || fl->fl_state == FWD_LABEL_DRAINING) {
    sendrawto_one(acptr, ":%s " MSG_BATCH_CMD " -%s",
                  cli_name(&me), fl->fl_batch_id);
  }

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

struct ForwardedLabel *fwd_label_find_draining(struct Client *acptr,
                                                const char *msgid)
{
  int i;

  if (!acptr || !MyConnect(acptr))
    return NULL;

  for (i = 0; i < MAX_FORWARDED_LABELS; i++) {
    struct ForwardedLabel *fl = &cli_fwd_labels(acptr)[i];
    if (fl->fl_state != FWD_LABEL_DRAINING)
      continue;

    /* Timeout check */
    if (CurrentTime - fl->fl_created > FWD_TIMEOUT_DRAIN) {
      fwd_label_close_batch(acptr, fl);
      continue;
    }

    /* Exact msgid correlation only (see fwd_label_find). */
    if (msgid && msgid[0] && fl->fl_msgid[0]
        && ircd_strcmp(fl->fl_msgid, msgid) == 0)
      return fl;
  }

  return NULL;
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
      } else if (CurrentTime - fl->fl_created > FWD_TIMEOUT_NORMAL) {
        if (fl->fl_state == FWD_LABEL_ACTIVE)
          fwd_label_close_batch(acptr, fl);
        else
          memset(fl, 0, sizeof(*fl));
      }
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

void fwd_label_cleanup(struct Client *cptr)
{
  if (!cptr || !MyConnect(cptr))
    return;

  memset(cli_fwd_labels(cptr), 0,
         sizeof(struct ForwardedLabel) * MAX_FORWARDED_LABELS);
}
