/*
 * IRC - Internet Relay Chat, ircd/metadata_sync.c
 *
 * Per-link state and wire emission for the W4 stamped account-metadata
 * sync protocol (MD =account / !sessid / ? / .).  This task (Task 3)
 * implements the chunk-reassembly accessor/destructor and the emitter;
 * the SESSION/PULL/PULL_END receivers are Task 4.
 */
#include "config.h"

#include "channel.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_string.h"
#include "metadata.h"
#include "metadata_lww.h"
#include "metadata_sync.h"
#include "msg.h"
#include "send.h"
#include "struct.h"

#include <string.h>

/** Largest value slice sent on one MD =account wire line (W4 plan's
 * "chunk <=300 value bytes per line" bound). */
#define MDSYNC_CHUNK_BYTES 300

struct md_chunk *mdsync_link_chunk(struct Client *link)
{
  struct Server *serv;

  if (!link)
    return NULL;
  serv = cli_serv(link);
  if (!serv)
    return NULL;

  if (!serv->mdsync) {
    serv->mdsync = (struct MdSyncLink *)MyMalloc(sizeof(struct MdSyncLink));
    if (!serv->mdsync)
      return NULL;
    memset(serv->mdsync, 0, sizeof(struct MdSyncLink));
  }

  return &serv->mdsync->chunk;
}

void mdsync_link_free(struct Client *server)
{
  struct Server *serv;

  if (!server)
    return;
  serv = cli_serv(server);
  if (!serv || !serv->mdsync)
    return;

  MyFree(serv->mdsync);
  serv->mdsync = NULL;
}

/** Send one already-formatted MD =account line to its destination(s):
 * a single client/link when @a one is non-NULL, else every IRCv3-aware
 * server except @a butone. */
static void mdsync_send_line(struct Client *src, struct Client *one,
                             struct Client *butone, const char *account,
                             const char *stamp_text, const char *key,
                             const char *flags, const char *piece)
{
  if (one) {
    /* This task (Task 4, the pull reply to cptr) is this single-target
     * path's first caller.  A pull request is itself only ever accepted
     * from a direct, already-identified-as-server link (ms_metadata_pull),
     * but that link need not be IRCv3-aware (a confused/hostile sender
     * could still forge the request) -- never send it one of these new
     * forms, which an older/non-aware peer cannot parse. */
    if (!IsIRCv3Aware(one))
      return;
    if (piece)
      sendcmdto_one(src, CMD_METADATA, one, "=%s %s %s %s :%s",
                   account, stamp_text, key, flags, piece);
    else
      sendcmdto_one(src, CMD_METADATA, one, "=%s %s %s %s",
                   account, stamp_text, key, flags);
  } else {
    if (piece)
      sendcmdto_serv_butone_v3(src, CMD_METADATA, butone, "=%s %s %s %s :%s",
                               account, stamp_text, key, flags, piece);
    else
      sendcmdto_serv_butone_v3(src, CMD_METADATA, butone, "=%s %s %s %s",
                               account, stamp_text, key, flags);
  }
}

void metadata_emit_versioned(struct Client *src, struct Client *one,
                             struct Client *butone, const char *account,
                             const char *key, const struct md_version *v)
{
  char stamp_text[MD_STAMP_BUFSIZE];
  char piece[MDSYNC_CHUNK_BYTES + 1];
  const char *flag_base;
  size_t sent, total;

  if (!src || !account || !key || !v)
    return;

  if (md_stamp_format(stamp_text, sizeof(stamp_text), &v->st) < 0)
    return;

  if (v->tombstone) {
    mdsync_send_line(src, one, butone, account, stamp_text, key, "D", NULL);
    return;
  }

  flag_base = (v->vis == METADATA_VIS_PRIVATE) ? "P" : "*";
  total = v->vlen;

  if (total == 0) {
    /* A live row with an empty value: one line, no continuation. */
    mdsync_send_line(src, one, butone, account, stamp_text, key, flag_base, "");
    return;
  }

  for (sent = 0; sent < total; ) {
    size_t chunklen = total - sent;
    int more;

    if (chunklen > MDSYNC_CHUNK_BYTES)
      chunklen = MDSYNC_CHUNK_BYTES;
    more = (sent + chunklen) < total;

    memcpy(piece, v->value + sent, chunklen);
    piece[chunklen] = '\0';

    if (more) {
      char flags[3];
      flags[0] = flag_base[0];
      flags[1] = '+';
      flags[2] = '\0';
      mdsync_send_line(src, one, butone, account, stamp_text, key, flags, piece);
    } else {
      mdsync_send_line(src, one, butone, account, stamp_text, key, flag_base, piece);
    }

    sent += chunklen;
  }
}

/** Largest number of rows (live + tombstone) a pull reply sends for one
 * account (W4 plan bound: "MDSYNC_MAX_ROWS"). */
#define MDSYNC_MAX_ROWS 128

/** Largest number of read markers a pull reply sends for one account --
 * the newest by timestamp (W4 plan bound: "MDSYNC_MAX_MARKERS"). */
#define MDSYNC_MAX_MARKERS 256

/** metadata_account_foreach_version callback: emit each row to the
 * pulling link until MDSYNC_MAX_ROWS is reached, then stop the walk. */
struct mdsync_row_arg {
  struct Client *link;
  const char *account;
  int sent;
};

static int mdsync_row_cb(const char *key, const struct md_version *v, void *arg)
{
  struct mdsync_row_arg *a = (struct mdsync_row_arg *)arg;

  if (a->sent >= MDSYNC_MAX_ROWS)
    return 1;   /* stop: the row cap for this account is already full */

  metadata_emit_versioned(&me, a->link, NULL, a->account, key, v);
  a->sent++;
  return 0;
}

/** One kept read-marker candidate.  mdsync_marker_arg::markers is kept in
 * ascending timestamp order (index 0 is the OLDEST of the kept set), so
 * once the cap is full, [0] is exactly the one a newer marker evicts. */
struct mdsync_marker {
  char target[CHANNELLEN + 1];
  char ts[32];
};

struct mdsync_marker_arg {
  int count;
  struct mdsync_marker markers[MDSYNC_MAX_MARKERS];
};

/** metadata_readmarker_foreach callback: keep the MDSYNC_MAX_MARKERS
 * newest-by-timestamp markers seen so far, via insertion into (and, once
 * full, eviction from) the ascending-order array above.  Timestamps
 * compare correctly with strcmp only because they are always the same
 * "seconds.milliseconds" decimal width -- the same assumption
 * metadata_readmarker_set already makes for its own newer-than check. */
static int mdsync_marker_cb(const char *target, const char *ts, void *arg)
{
  struct mdsync_marker_arg *a = (struct mdsync_marker_arg *)arg;
  int i;

  if (a->count < MDSYNC_MAX_MARKERS) {
    i = a->count++;
    while (i > 0 && strcmp(a->markers[i - 1].ts, ts) > 0) {
      a->markers[i] = a->markers[i - 1];
      i--;
    }
  } else {
    if (strcmp(ts, a->markers[0].ts) <= 0)
      return 0;   /* not newer than the smallest kept -- discard */
    i = 0;
    while (i + 1 < MDSYNC_MAX_MARKERS && strcmp(a->markers[i + 1].ts, ts) < 0) {
      a->markers[i] = a->markers[i + 1];
      i++;
    }
  }
  ircd_strncpy(a->markers[i].target, target, sizeof(a->markers[i].target));
  ircd_strncpy(a->markers[i].ts, ts, sizeof(a->markers[i].ts));
  return 0;
}

void mdsync_answer_pull(struct Client *link, unsigned long seq, char scope,
                        char *accounts[], int n)
{
  int i;

  if (!link || !accounts || n <= 0)
    return;

  /* metadata_emit_versioned's single-target path already screens for
   * IsIRCv3Aware (see mdsync_send_line), but the MR lines and the
   * closing "MD . seq" below go straight through sendcmdto_one and
   * never pass through it -- this blanket guard is what keeps every
   * form in this reply off a link that cannot parse any of it. */
  if (!IsIRCv3Aware(link))
    return;

  for (i = 0; i < n; i++) {
    struct mdsync_row_arg rows;

    rows.link = link;
    rows.account = accounts[i];
    rows.sent = 0;
    metadata_account_foreach_version(accounts[i], mdsync_row_cb, &rows);

    if (scope == 'A') {
      /* Heap-allocated: ~59KB (MDSYNC_MAX_MARKERS * sizeof(struct
       * mdsync_marker)) is too much to put on the stack once per
       * account in this loop. */
      struct mdsync_marker_arg *ma =
        (struct mdsync_marker_arg *)MyMalloc(sizeof(struct mdsync_marker_arg));
      int j;

      if (!ma)
        continue;
      ma->count = 0;

      metadata_readmarker_foreach(accounts[i], mdsync_marker_cb, ma);

      for (j = 0; j < ma->count; j++) {
        struct Channel *chptr = FindChannel(ma->markers[j].target);
        const char *display = chptr ? chptr->chname : ma->markers[j].target;

        sendcmdto_one(&me, CMD_MARKREAD, link, "%s %s %s",
                     accounts[i], display, ma->markers[j].ts);
      }
      MyFree(ma);
    }
  }

  sendcmdto_one(&me, CMD_METADATA, link, ". %lu", seq);
}
