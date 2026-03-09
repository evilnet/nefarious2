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

#include <string.h>
#include <stdio.h>

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
  { NULL, 0, 0 }
};

/** Counter for generating unique forwarded batch IDs. */
static unsigned long fwd_batch_counter = 0;

/** Timeout in seconds for PENDING/ACTIVE entries. */
#define FWD_TIMEOUT_NORMAL  60

/** Timeout in seconds for DRAINING entries. */
#define FWD_TIMEOUT_DRAIN   5

int fwd_label_save(struct Client *from, const char *cmd,
                   char *msgid, uint64_t *time_out)
{
  struct ForwardedLabel *fl;
  struct HLC hlc;
  char logical_b64[4], counter_b64[10];
  int i, slot = -1;

  if (!from || !MyConnect(from) || !cmd)
    return 0;

  /* Must have label + labeled-response + batch caps */
  if (!cli_label(from)[0])
    return 0;
  if (!feature_bool(FEAT_CAP_labeled_response) || !CapActive(from, CAP_LABELEDRESP))
    return 0;
  if (!feature_bool(FEAT_CAP_batch) || !CapActive(from, CAP_BATCH))
    return 0;

  /* Look up command in terminal table */
  for (i = 0; fwd_terminals[i].cmd; i++) {
    if (ircd_strcmp(cmd, fwd_terminals[i].cmd) == 0)
      break;
  }
  if (!fwd_terminals[i].cmd)
    return 0;  /* Unknown command — don't handle */

  /* Find empty slot */
  for (i = 0; i < MAX_FORWARDED_LABELS; i++) {
    if (cli_fwd_labels(from)[i].fl_state == FWD_LABEL_EMPTY) {
      slot = i;
      break;
    }
  }
  if (slot < 0)
    return 0;  /* No room */

  fl = &cli_fwd_labels(from)[slot];

  /* Look up terminal again (we reused i) */
  {
    int j;
    for (j = 0; fwd_terminals[j].cmd; j++) {
      if (ircd_strcmp(cmd, fwd_terminals[j].cmd) == 0)
        break;
    }
    fl->fl_terminal = fwd_terminals[j].terminal;
    fl->fl_terminal2 = fwd_terminals[j].terminal2;
  }

  /* Copy label */
  ircd_strncpy(fl->fl_label, cli_label(from), sizeof(fl->fl_label));

  /* Generate batch ID: fwd<counter><server_yxx> */
  snprintf(fl->fl_batch_id, sizeof(fl->fl_batch_id), "fwd%lu%s",
           ++fwd_batch_counter, cli_yxx(&me));

  /* Generate HLC msgid for compact tag correlation */
  hlc = hlc_global_event();
  inttobase64_64(logical_b64, (uint64_t)hlc.logical, 3);
  inttobase64_64(counter_b64, (uint64_t)(++fwd_batch_counter), 9);
  snprintf(fl->fl_msgid, sizeof(fl->fl_msgid), "%s%s%s",
           cli_yxx(&me), logical_b64, counter_b64);

  /* Output for caller to attach to S2S compact tag */
  ircd_strncpy(msgid, fl->fl_msgid, 15);
  *time_out = hlc_global()->physical_ms;

  fl->fl_state = FWD_LABEL_PENDING;
  fl->fl_created = CurrentTime;

  /* Suppress ACK and clear label from client */
  cli_label_responded(from) = 1;
  cli_label(from)[0] = '\0';

  return 1;
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
        if (fl->fl_state == FWD_LABEL_ACTIVE || fl->fl_state == FWD_LABEL_DRAINING)
          fwd_label_close_batch(acptr, fl);
        else
          memset(fl, 0, sizeof(*fl));
        continue;
      }
    } else if (CurrentTime - fl->fl_created > FWD_TIMEOUT_NORMAL) {
      if (fl->fl_state == FWD_LABEL_ACTIVE)
        fwd_label_close_batch(acptr, fl);
      else
        memset(fl, 0, sizeof(*fl));
      continue;
    }

    /* Match by msgid if provided */
    if (msgid && msgid[0]) {
      if (fl->fl_msgid[0] && ircd_strcmp(fl->fl_msgid, msgid) == 0)
        return fl;
    } else {
      /* FIFO fallback — return first non-empty entry */
      return fl;
    }
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

    /* Match by msgid if provided */
    if (msgid && msgid[0]) {
      if (fl->fl_msgid[0] && ircd_strcmp(fl->fl_msgid, msgid) == 0)
        return fl;
    } else {
      /* FIFO fallback */
      return fl;
    }
  }

  return NULL;
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
