/*
 * IRC - Internet Relay Chat, ircd/metadata_sync.c
 *
 * Per-link state and wire emission for the W4 stamped account-metadata
 * sync protocol (MD =account / !sessid / ? / .).  This task (Task 3)
 * implements the chunk-reassembly accessor/destructor and the emitter;
 * the SESSION/PULL/PULL_END receivers are Task 4.
 */
#include "config.h"

#include "client.h"
#include "ircd_alloc.h"
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
