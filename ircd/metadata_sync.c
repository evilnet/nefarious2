/*
 * IRC - Internet Relay Chat, ircd/metadata_sync.c
 *
 * Per-link state and wire emission for the W4 stamped account-metadata
 * sync protocol (MD =account / !sessid / ? / .): the per-link
 * chunk-reassembly state (accessor and destructor), the stamped-row
 * emitter, the pull-reply responder and the per-link over-limit notice.
 * The receivers themselves live in m_metadata.c (ms_metadata and its
 * per-form handlers).
 */
#include "config.h"

#include "channel.h"
#include "client.h"
#include "db_casefold.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_string.h"
#include "list.h"
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

/** Lazily allocate and return cli_serv(@a link)->mdsync, or NULL if
 * @a link has no Server block.  Shared by mdsync_link_chunk() (the
 * chunk-reassembly state) and mdsync_limit_notice() (the per-link
 * over-limit notice throttle, Task 5) -- both hang their state off the
 * same per-link struct, allocated on whichever one touches it first.
 * @param[in] link The server Client whose per-link state is wanted.
 */
static struct MdSyncLink *mdsync_link_state(struct Client *link)
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

  return serv->mdsync;
}

struct md_chunk *mdsync_link_chunk(struct Client *link)
{
  struct MdSyncLink *st = mdsync_link_state(link);

  return st ? &st->chunk : NULL;
}

void mdsync_link_free(struct Client *server)
{
  struct Server *serv;

  if (!server)
    return;
  serv = cli_serv(server);
  if (!serv || !serv->mdsync)
    return;

  /* Task 10: the EOB re-pull queue dies with the link -- nothing left
   * to drain it once this server's Client goes away. */
  MyFree(serv->mdsync->eob_queue);
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
    /* metadata_emit_versioned has already refused a @a one that is not
     * IRCv3-aware; checked again here so this helper is safe alone. */
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

  /* A single link that is not IRCv3-aware never gets this form, which
   * an older or non-aware peer cannot parse (the wire table's "=account"
   * row).  Its callers: the pull reply to cptr (mdsync_answer_pull: a
   * pull is only accepted from a direct link, but that link need not be
   * IRCv3-aware -- a confused or hostile sender could still forge the
   * request) and the link burst (s_serv.c, which is itself gated on the
   * link being IRCv3-aware).  The broadcast form goes through
   * sendcmdto_serv_butone_v3, which skips non-aware links itself. */
  if (one && !IsIRCv3Aware(one))
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

int metadata_account_write(struct Client *src, const char *account,
                           const char *key, const char *value, int vis)
{
  struct md_stamp st;
  struct md_version v;

  if (!src || !account || !account[0] || !key)
    return -1;

  st = metadata_stamp_now();

  /* Store first, and nothing else when the store refuses the write: a
   * row peers keep under a stamp this server never stored would be
   * undone here by the next pull.  With no store at all (storage not
   * configured), memory and peers still get it, as metadata_set_client
   * plus the account-form broadcast used to. */
  if (metadata_lmdb_is_available()
      && metadata_account_put_versioned(account, key, value, vis, &st) < 0) {
    log_write(LS_SYSTEM, L_WARNING, 0,
              "metadata_account_write: store refused %s/%s - not applied, "
              "not sent", account, key);
    return -1;
  }

  metadata_account_apply_memory(account, key, value, vis);

  v.st = st;
  v.tombstone = (value == NULL);
  v.vis = vis;
  v.value = value;
  v.vlen = value ? strlen(value) : 0;
  metadata_emit_versioned(src, NULL, NULL, account, key, &v);
  return 0;
}

int metadata_session_addressable(struct Client *target)
{
  /* Every server that learned this client with message tags on took the
   * session id its N carried (the ,S compact-tag segment; make_client
   * adopts it, and every N relay re-stages it: bounce_set_n_sessid_hint).
   * With P10_MESSAGE_TAGS off no N of ours carries one
   * (format_s2s_tags_with_client returns NULL, and the send path adds no
   * tag region), so each peer minted its own and a "!sessid" would name
   * nobody there.  A client with the account flag but an empty account
   * name is skipped by the session-form receiver (it refuses IsAccount
   * matches). */
  return feature_bool(FEAT_P10_MESSAGE_TAGS) && target && cli_user(target)
         && !cli_user(target)->account[0] && !IsAccount(target)
         && cli_session_id(target)[0];
}

int metadata_client_write(struct Client *src, struct Client *target,
                          const char *key, const char *value, int vis)
{
  const char *vis_tok = (vis == METADATA_VIS_PRIVATE) ? "P" : "*";

  if (!src || !target || !key || !cli_user(target))
    return -1;

  if (cli_user(target)->account[0])
    return metadata_account_write(src, cli_user(target)->account, key,
                                  value, vis);

  /* No account: this client's own memory (metadata_set_client writes
   * no store row without one) and its subscribers. */
  if (metadata_set_client(target, key, value, vis) < 0)
    return -1;
  metadata_notify_subscribers(cli_name(target), key, value, vis);

  /* Addressed by session id (metadata_session_addressable), else the
   * nick form -- which the receiver accepts only from the target's own
   * server, the target itself, an alias of it or an oper
   * (md_sender_owns_client), so @a src must be one of those. */
  if (metadata_session_addressable(target)) {
    if (value)
      sendcmdto_serv_butone_v3(src, CMD_METADATA, NULL, "!%s %s %s :%s",
                               cli_session_id(target), key, vis_tok, value);
    else
      sendcmdto_serv_butone_v3(src, CMD_METADATA, NULL, "!%s %s",
                               cli_session_id(target), key);
  } else {
    if (value)
      sendcmdto_serv_butone_v3(src, CMD_METADATA, NULL, "%s %s %s :%s",
                               cli_name(target), key, vis_tok, value);
    else
      sendcmdto_serv_butone_v3(src, CMD_METADATA, NULL, "%s %s",
                               cli_name(target), key);
  }
  return 0;
}

/** Minimum gap between SNO_NETWORK notices for the same link's
 * over-limit MD writes (W4 plan 1.8: "at most once per link per
 * 600 s"). */
#define MDSYNC_LIMIT_NOTICE_INTERVAL_S 600

void mdsync_limit_notice(struct Client *link, const char *target,
                         const char *key, const char *why)
{
  struct MdSyncLink *st;

  if (!link || !target || !key || !why)
    return;

  /* Logged on every hit, independent of the oper-notice throttle below:
   * this is the line that lets a sysadmin reconstruct exactly which
   * target/key pairs were relayed-unapplied even between two throttled
   * notices. */
  log_write(LS_SYSTEM, L_WARNING, 0,
            "ms_metadata: %s/%s from %C exceeds this server's METADATA "
            "limits (%s) - relayed, not applied", target, key, link, why);

  st = mdsync_link_state(link);
  if (!st)
    return;
  if ((CurrentTime - st->limit_notice_last) < MDSYNC_LIMIT_NOTICE_INTERVAL_S)
    return;
  st->limit_notice_last = CurrentTime;

  sendto_opmask_butone(0, SNO_NETWORK,
                       "METADATA from %C exceeds this server's METADATA "
                       "limits (%s); METADATA_MAX_KEYS / "
                       "METADATA_MAX_VALUE_BYTES differ between servers",
                       link, why);
}

/** Largest number of rows (live + tombstone) a pull reply sends for one
 * account (W4 plan bound: "MDSYNC_MAX_ROWS"). */
#define MDSYNC_MAX_ROWS 128

/** Largest number of rows (live + tombstone) a pull reply's row walk
 * VISITS for one account, before stopping outright (fix round 1
 * follow-up, security review 2026-11-02): row_select_cb's own "never
 * stop early" rule (needed to find the true newest MDSYNC_MAX_ROWS
 * regardless of raw key order) made the walk unbounded -- an account
 * can carry an unlimited number of tombstones (SET then DELETE many
 * distinct key names within METADATA_TOMBSTONE_TTL, no per-account
 * tombstone cap exists), each one a full O(rows) scan step on the main
 * loop, so a user could stall a pull of their own account arbitrarily.
 * 32x MDSYNC_MAX_ROWS: generous enough that a reply is essentially
 * never actually visit-capped in practice (an account would need to
 * carry 32x its own row-reply budget in distinct historical keys/
 * tombstones), while still bounding the walk to a fixed, small multiple
 * of the existing reply-size bound rather than the account's unbounded
 * tombstone count. */
#define MDSYNC_MAX_VISIT (32 * MDSYNC_MAX_ROWS)

/** Largest number of read markers a pull reply sends for one account --
 * the newest by timestamp (W4 plan bound: "MDSYNC_MAX_MARKERS"). */
#define MDSYNC_MAX_MARKERS 256

/** One candidate row held during a pull reply's bounded top-N-by-stamp
 * selection (fix round 1, 2026-11-02): metadata_account_foreach_version's
 * own key/value buffers are reused by the very next row before this
 * row's callback returns, so a row kept as a candidate must own a COPY
 * of its key and value, not a pointer into those buffers. Sized from
 * metadata.c's own per-row key buffer (160 bytes -- "draft/persistence/..."
 * keys run up to 127) and METADATA_VALUE_LEN for the value. */
struct mdsync_row_candidate {
  char key[160];
  struct md_stamp st;
  int tombstone;
  int vis;
  size_t vlen;
  char value[METADATA_VALUE_LEN];
};

/** metadata_account_foreach_version callback: keep the MDSYNC_MAX_ROWS
 * newest-by-stamp rows seen so far (live or tombstone), via
 * md_topn_insert -- md_topn_place's pure insertion-position decision
 * plus the shift, done on the stamps and a small index array only.
 * Mirrors mdsync_marker_cb's "ascending kept array, evict the oldest"
 * shape, generalized from a timestamp string to a struct md_stamp.
 * Unlike the old row_cb, this does not stop at MDSYNC_MAX_ROWS:
 * metadata.c's own walk is raw LMDB key order, not stamp order, so the
 * single newest row can arrive anywhere, including dead last (the
 * row-cap bug this replaces: a key that sorted after the 128th by raw
 * key order was never sent by any pull, ever, ranking-review 2026-11-02)
 * -- it DOES still stop, at the separate, much larger MDSYNC_MAX_VISIT
 * (security review 2026-11-02, same day): an account's tombstone count
 * has no cap of its own, so visiting every row unconditionally would
 * make the walk an unbounded, user-triggerable main-loop scan.
 *
 * Memory: bounded at exactly MDSYNC_MAX_ROWS candidates
 * (~1192 bytes each -- 160 + stamp + 2 ints + size_t + 1024 -- about
 * 153KB total for the full cap), never grown past that regardless of
 * how many rows the account actually has; heap-allocated by the caller
 * (mdsync_answer_pull), same reasoning as the pre-existing marker
 * struct's own heap allocation just below.  The candidates sit in a
 * pool and never move once written (push-2 final fix wave, M-4): an
 * insert shifts the 16-byte stamps and the int slot[] index, not the
 * ~1.2KB rows -- an account whose stamps ascend in key order used to
 * cost ~127 whole-row shifts per visited row, ~600MB of memmove per
 * pull at the visit cap. The walk itself is bounded separately, at
 * MDSYNC_MAX_VISIT rows visited (see mdsync_row_select_cb). */
struct mdsync_row_select {
  struct Client *link;
  const char *account;
  int count;             /**< number of candidates held, 0..MDSYNC_MAX_ROWS */
  int visited;           /**< rows visited so far this walk, 0..MDSYNC_MAX_VISIT */
  int capped;            /**< 1 once the row-cap L_WARNING has been logged
                           *   for this account's walk -- logged once. */
  int visit_capped;      /**< 1 once the visit-cap L_WARNING has been
                           *   logged -- logged once, distinct from capped. */
  struct md_stamp stamps[MDSYNC_MAX_ROWS];  /**< ascending by stamp:
                           *   the held rows' stamps, by ordered position */
  int slot[MDSYNC_MAX_ROWS];  /**< the pool slot (rows[]) of the row at
                           *   each ordered position */
  struct mdsync_row_candidate rows[MDSYNC_MAX_ROWS];  /**< the pool: a
                           *   row is written once, into the slot
                           *   md_topn_insert hands out, and never moved */
};

static int mdsync_row_select_cb(const char *key, const struct md_version *v, void *arg)
{
  struct mdsync_row_select *a = (struct mdsync_row_select *)arg;
  int ps;
  size_t vlen;

  /* Hard visit cap (fix round 1 follow-up, security review
   * 2026-11-02): checked and counted BEFORE anything else, so it
   * bounds the walk regardless of how many of the visited rows are
   * actually kept -- an unbounded number of tombstones (no per-account
   * cap exists) would otherwise make this a user-triggerable
   * unbounded main-loop scan via "never stop early" below. Stopping
   * the walk here still keeps whatever MDSYNC_MAX_ROWS newest rows
   * were found among the MDSYNC_MAX_VISIT visited -- a smaller,
   * bounded reply, not a correctness regression on top of the
   * (already bounded-reply) row cap. */
  a->visited++;
  if (a->visited > MDSYNC_MAX_VISIT) {
    if (!a->visit_capped) {
      log_write(LS_SYSTEM, L_WARNING, 0,
                "mdsync_answer_pull: visit cap (%d) reached for account %s "
                "pulled by %C - row walk stopped early",
                MDSYNC_MAX_VISIT, a->account, a->link);
      a->visit_capped = 1;
    }
    return 1;   /* stop the walk outright */
  }

  /* An internal key (last_present: this server's own observation, a TTL
   * row; a key the wire validator refuses) stays here: never sent, and
   * it takes no place among the newest MDSYNC_MAX_ROWS (push-2 final
   * fix wave, M-2). */
  if (!md_key_replicable(key))
    return 0;

  if (a->count >= MDSYNC_MAX_ROWS && !a->capped) {
    /* Reached the first time a row arrives once the cap is already
     * full, whether or not THIS particular row ends up kept -- from
     * here on the account has more rows than MDSYNC_MAX_ROWS and the
     * reply is truncated to the newest, logged once per account per
     * pull, not once per such row. */
    log_write(LS_SYSTEM, L_WARNING, 0,
              "mdsync_answer_pull: row cap (%d) reached for account %s "
              "pulled by %C - reply truncated to the newest",
              MDSYNC_MAX_ROWS, a->account, a->link);
    a->capped = 1;
  }

  if (strlen(key) >= sizeof(a->rows[0].key))
    return 0;   /* defensive only: metadata.c's own keybuf is smaller */

  ps = md_topn_insert(a->stamps, a->slot, &a->count, MDSYNC_MAX_ROWS, &v->st);
  if (ps < 0)
    return 0;   /* not newer than anything kept -- discard */

  vlen = v->vlen;
  if (vlen >= sizeof(a->rows[ps].value))
    vlen = sizeof(a->rows[ps].value) - 1;   /* defensive; v->vlen is
                                              * already <= METADATA_VALUE_LEN */

  ircd_strncpy(a->rows[ps].key, key, sizeof(a->rows[ps].key));
  a->rows[ps].st = v->st;
  a->rows[ps].tombstone = v->tombstone;
  a->rows[ps].vis = v->vis;
  a->rows[ps].vlen = vlen;
  if (vlen)
    memcpy(a->rows[ps].value, v->value, vlen);
  a->rows[ps].value[vlen] = '\0';

  return 0;   /* keep walking (bounded by MDSYNC_MAX_VISIT above) --
               * every visited row must be considered to find the true
               * newest MDSYNC_MAX_ROWS among them */
}

/** One kept read-marker candidate.  mdsync_marker_arg::markers is kept in
 * ascending timestamp order (index 0 is the OLDEST of the kept set), so
 * once the cap is full, [0] is exactly the one a newer marker evicts. */
struct mdsync_marker {
  char target[CHANNELLEN + 1];
  char ts[32];
};

struct mdsync_marker_arg {
  struct Client *link;
  const char *account;
  int count;
  int capped;   /**< 1 once the cap-hit L_WARNING has been logged for
                 *   this account's walk -- logged once, not once per
                 *   evicted/discarded marker. */
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
    /* Every marker from here on is either discarded or evicts the
     * current oldest kept one -- either way the account has more
     * markers than MDSYNC_MAX_MARKERS and the reply is truncated.
     * Logged once per account per pull (the first time this branch is
     * reached), not once per such marker. */
    if (!a->capped) {
      log_write(LS_SYSTEM, L_WARNING, 0,
                "mdsync_answer_pull: marker cap (%d) reached for account "
                "%s pulled by %C - reply truncated to the newest",
                MDSYNC_MAX_MARKERS, a->account, a->link);
      a->capped = 1;
    }
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
    /* Heap-allocated: ~153KB (MDSYNC_MAX_ROWS * sizeof(struct
     * mdsync_row_candidate), plus the parallel stamps[] array) is
     * well past what belongs on the stack once per account in this
     * loop -- same reasoning as the marker struct just below, bigger
     * only because a row's value (up to METADATA_VALUE_LEN) dwarfs a
     * marker's fixed-width timestamp. */
    struct mdsync_row_select *rows =
      (struct mdsync_row_select *)MyMalloc(sizeof(struct mdsync_row_select));
    int j;

    if (rows) {
      rows->link = link;
      rows->account = accounts[i];
      rows->count = 0;
      rows->visited = 0;
      rows->capped = 0;
      rows->visit_capped = 0;
      metadata_account_foreach_version(accounts[i], mdsync_row_select_cb, rows);

      /* Emission order is free (each row merges independently on the
       * receiver, metadata_lww.c's md_lww_take) -- ascending by stamp
       * (oldest-of-the-selected-set first), the slot[] index's own
       * order, needs no extra sort pass. */
      for (j = 0; j < rows->count; j++) {
        const struct mdsync_row_candidate *rc = &rows->rows[rows->slot[j]];
        struct md_version ev;

        ev.st = rc->st;
        ev.tombstone = rc->tombstone;
        ev.vis = rc->vis;
        ev.value = rc->tombstone ? NULL : rc->value;
        ev.vlen = rc->vlen;
        metadata_emit_versioned(&me, link, NULL, accounts[i], rc->key, &ev);
      }
      MyFree(rows);
    }

    if (scope == 'A') {
      /* Heap-allocated: ~59KB (MDSYNC_MAX_MARKERS * sizeof(struct
       * mdsync_marker)) is too much to put on the stack once per
       * account in this loop. */
      struct mdsync_marker_arg *ma =
        (struct mdsync_marker_arg *)MyMalloc(sizeof(struct mdsync_marker_arg));
      int j;

      if (!ma)
        continue;
      ma->link = link;
      ma->account = accounts[i];
      ma->count = 0;
      ma->capped = 0;

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

/** Minimum gap between two attach-triggered pulls for the SAME account
 * (W4 plan Bounds: "MDSYNC_PULL_INTERVAL"). */
#define MDSYNC_PULL_INTERVAL 60

/** Size of the attach-pull dedup table (W4 plan Bounds: "a 4096-entry
 * table; a full table is cleared").  Open-addressed, no per-entry
 * deletion: a full table (every slot holds some other account, within
 * or outside the window) is wiped and the new entry starts a fresh
 * table, rather than evicting one account to make room for another. */
#define MDSYNC_PULL_TABLE_SIZE 4096

/** One account's most recent attach pull: the scope it was pulled at
 * ('A' or 'R') and when.  An empty account[0] marks a free slot. */
struct mdsync_pull_record {
  char   account[ACCOUNTLEN + 1];
  char   scope;
  time_t at;
};

static struct mdsync_pull_record mdsync_pull_table[MDSYNC_PULL_TABLE_SIZE];
static unsigned int mdsync_pull_table_used;

/** FNV-1a over @a key's bytes, same construction as mdsync_marker_cb's
 * neighbours elsewhere in this file use for their own small hashes. */
static unsigned int mdsync_pull_hash(const char *key)
{
  unsigned int h = 2166136261u;
  const unsigned char *p;

  for (p = (const unsigned char *)key; *p; p++) {
    h ^= *p;
    h *= 16777619u;
  }
  return h;
}

/** Find @a key's slot (already casefolded, NUL-terminated) without
 * creating one.  Open addressing with no deletions means the first free
 * slot probed is proof no match follows it -- the walk can stop there
 * instead of scanning the whole table.
 * @return the slot, or NULL if @a key is not present.
 */
static struct mdsync_pull_record *mdsync_pull_find(const char *key)
{
  unsigned int h = mdsync_pull_hash(key) % MDSYNC_PULL_TABLE_SIZE;
  unsigned int i;

  for (i = 0; i < MDSYNC_PULL_TABLE_SIZE; i++) {
    struct mdsync_pull_record *r =
      &mdsync_pull_table[(h + i) % MDSYNC_PULL_TABLE_SIZE];

    if (!r->account[0])
      return NULL;
    if (0 == strcmp(r->account, key))
      return r;
  }
  return NULL;   /* every slot full, none matched -- treated as absent */
}

/** Find @a key's slot, creating one (clearing the whole table first if
 * it is completely full of other accounts).
 */
static struct mdsync_pull_record *mdsync_pull_slot(const char *key)
{
  struct mdsync_pull_record *r = mdsync_pull_find(key);
  unsigned int h, i;

  if (r)
    return r;

  if (mdsync_pull_table_used >= MDSYNC_PULL_TABLE_SIZE) {
    memset(mdsync_pull_table, 0, sizeof(mdsync_pull_table));
    mdsync_pull_table_used = 0;
  }

  h = mdsync_pull_hash(key) % MDSYNC_PULL_TABLE_SIZE;
  for (i = 0; i < MDSYNC_PULL_TABLE_SIZE; i++) {
    struct mdsync_pull_record *slot =
      &mdsync_pull_table[(h + i) % MDSYNC_PULL_TABLE_SIZE];

    if (!slot->account[0]) {
      mdsync_pull_table_used++;
      return slot;
    }
  }
  return NULL;   /* unreachable: mdsync_pull_table_used < SIZE guarantees
                  * a free slot exists */
}

/** Casefold @a account (db_casefold_bytes, the same fold every store key
 * uses) into @a out, truncated to ACCOUNTLEN like every other account
 * buffer in this file.
 */
static void mdsync_pull_key(char *out, const char *account)
{
  size_t len = strlen(account);

  if (len > ACCOUNTLEN)
    len = ACCOUNTLEN;
  db_casefold_bytes(out, account, len);
  out[len] = '\0';
}

void mdsync_note_pulled(const char *account, char scope)
{
  char key[ACCOUNTLEN + 1];
  struct mdsync_pull_record *r;

  if (!account || !account[0])
    return;

  mdsync_pull_key(key, account);
  r = mdsync_pull_slot(key);
  if (!r)
    return;

  if (!r->account[0])
    ircd_strncpy(r->account, key, sizeof(r->account));
  r->scope = scope;
  r->at = CurrentTime;
}

/** Whether @a account was already pulled, within MDSYNC_PULL_INTERVAL,
 * at a scope that covers @a scope -- 'A' (rows + markers) covers both
 * 'A' and 'R' (rows only); 'R' covers only another 'R'.
 */
static int mdsync_pull_recent(const char *account, char scope)
{
  char key[ACCOUNTLEN + 1];
  struct mdsync_pull_record *r;

  mdsync_pull_key(key, account);
  r = mdsync_pull_find(key);
  if (!r)
    return 0;
  if ((CurrentTime - r->at) >= MDSYNC_PULL_INTERVAL)
    return 0;
  return (r->scope == 'A') || (r->scope == scope);
}

/** Send one "MD ? <seq> <scope> <acct>[,<acct>...]" pull request to
 * @a link: up to 16 comma-joined account names.  Shared by
 * mdsync_on_attach (a single account, seq 0 -- unqueued, no reply
 * tracked) and Task 10's EOB queue (mdsync_eob_send_next, up to 16
 * accounts per batch, seq = that link's own outstanding request
 * number).  A no-op on a link that is not IRCv3-aware, matching every
 * other new MD form's guard (metadata_emit_versioned, mdsync_answer_pull):
 * an older fork peer would otherwise see a wire form it cannot parse.
 * @param[in] link The directly-connected server to ask.
 * @param[in] seq The request's sequence number (0 = unqueued).
 * @param[in] scope 'A' (rows + markers) or 'R' (rows only).
 * @param[in] accounts Account names to ask about.
 * @param[in] n Number of entries in @a accounts (1-16).
 */
static void mdsync_send_pull(struct Client *link, unsigned long seq,
                             char scope, const char * const *accounts, int n)
{
  char joined[16 * (ACCOUNTLEN + 1)];
  size_t len = 0;
  int i;

  if (!link || !IsIRCv3Aware(link) || !accounts || n <= 0)
    return;

  for (i = 0; i < n; i++) {
    size_t alen = strlen(accounts[i]);
    size_t sep = (i > 0) ? 1 : 0;

    if (len + sep + alen >= sizeof(joined))
      break;   /* unreachable in practice: callers cap at 16 names of
                * at most ACCOUNTLEN bytes each */
    if (sep)
      joined[len++] = ',';
    memcpy(joined + len, accounts[i], alen);
    len += alen;
  }
  joined[len] = '\0';

  sendcmdto_one(&me, CMD_METADATA, link, "? %lu %c %s", seq, scope, joined);
}

void mdsync_on_attach(struct Client *cptr, const char *account)
{
  char scope;
  struct DLink *lp;
  int sent = 0;

  if (!cptr || !account || !account[0])
    return;
  if (!metadata_lmdb_is_available())
    return;

  scope = MyConnect(cptr) ? 'A' : 'R';

  /* A remote client still mid-burst from our point of view: its own
   * server has not finished telling us about it yet, so a pull now
   * would race the burst rather than fill a real gap.  Task 10's EOB
   * queue re-pulls every account this link introduced once its burst
   * ends; this attach is simply skipped here. */
  if (!MyConnect(cptr) && cli_from(cptr) && IsBurst(cli_from(cptr)))
    return;

  if (mdsync_pull_recent(account, scope))
    return;

  /* Noted only once something actually went out below -- an attach with
   * no eligible link (split off, or every link mid-burst) accomplishes
   * nothing, and must not consume the dedup window a LATER attach of the
   * same account could use once a link is actually there to ask.  Two
   * local attaches of one account (e.g. the hub during a split, then
   * again once it heals) must not have the first, link-less one block
   * the second, useful one within MDSYNC_PULL_INTERVAL. */
  for (lp = cli_serv(&me)->down; lp; lp = lp->next) {
    struct Client *link = lp->value.cptr;
    const char *one[1];

    if (!IsIRCv3Aware(link) || IsBurst(link))
      continue;
    one[0] = account;
    mdsync_send_pull(link, 0, scope, one, 1);
    sent = 1;
  }

  if (sent)
    mdsync_note_pulled(account, scope);
}

/* ------------------------------------------------------------------ */
/* Task 10: end-of-burst re-pull queue                                 */
/* ------------------------------------------------------------------ */

/** Transient dedup table used only while building one link's EOB
 * re-pull queue (mdsync_link_eob): maps a casefolded account name to
 * the scope ('A' or 'R') it will be queued at, so a LATER local match
 * can upgrade an earlier remote-only entry from 'R' to 'A' via a
 * direct lookup instead of a linear search over everything already
 * appended.  Sized and probed the same way as mdsync_pull_table above
 * (same mdsync_pull_hash); on the same impossibly-unlikely "every slot
 * full of other accounts" overflow, the account being inserted is
 * simply skipped (logged at L_WARNING) rather than clearing a table
 * that is only alive for the one mdsync_link_eob() call that built it. */
#define MDSYNC_EOB_DEDUP_SIZE MDSYNC_PULL_TABLE_SIZE

struct mdsync_eob_dedup {
  char account[ACCOUNTLEN + 1];
  char scope;
  unsigned char used;
};

/** Find @a key's slot in @a table, creating one if @a key is not
 * already present.  Open addressing, no deletions (the table lives
 * only for the duration of one mdsync_link_eob() call).
 * @return the slot, or NULL if every slot is used by some OTHER key.
 */
static struct mdsync_eob_dedup *mdsync_eob_dedup_slot(
    struct mdsync_eob_dedup *table, const char *key)
{
  unsigned int h = mdsync_pull_hash(key) % MDSYNC_EOB_DEDUP_SIZE;
  unsigned int i;

  for (i = 0; i < MDSYNC_EOB_DEDUP_SIZE; i++) {
    struct mdsync_eob_dedup *slot =
      &table[(h + i) % MDSYNC_EOB_DEDUP_SIZE];

    if (!slot->used || 0 == strcmp(slot->account, key))
      return slot;
  }
  return NULL;
}

/** Send @a link's next EOB batch (<=16 accounts, one scope), or --
 * once its queue is exhausted -- log the completion line and free it.
 * Called once by mdsync_link_eob() to start a sweep, and once more by
 * mdsync_on_pull_end() for every "MD . seq" that closes the previous
 * batch (W4 plan Task 10: "one outstanding request; the next batch
 * goes out only on MD . <outstanding seq>").  A batch never mixes
 * scope -- the wire form carries exactly one scope token -- so it
 * stops either at 16 entries or at the point (if any) where the
 * queued scope changes, even though the two scope blocks are built
 * contiguously by mdsync_link_eob().
 * @param[in] link The link being asked (unchanged across the sweep).
 * @param[in] st @a link's per-link state, already allocated by the
 *            caller (mdsync_link_state(link)).
 */
static void mdsync_eob_send_next(struct Client *link, struct MdSyncLink *st)
{
  const char *batch[16];
  char scope;
  int n = 0;
  unsigned int i;

  if (st->eob_queue_next >= st->eob_queue_count) {
    /* Reached only once a real sweep's queue (always built with at
     * least one entry -- mdsync_link_eob never starts one with zero)
     * has fully drained, so eob_queue_count here is never 0. */
    log_write(LS_SYSTEM, L_INFO, 0,
              "metadata sync with %C: %u accounts in %u requests",
              link, st->eob_queue_count, st->eob_requests_sent);
    MyFree(st->eob_queue);
    st->eob_queue = NULL;
    st->eob_queue_count = 0;
    st->eob_queue_next = 0;
    st->eob_outstanding_seq = 0;
    return;
  }

  scope = st->eob_queue[st->eob_queue_next].scope;
  for (i = st->eob_queue_next;
       i < st->eob_queue_count && n < 16 && st->eob_queue[i].scope == scope;
       i++)
    batch[n++] = st->eob_queue[i].account;

  st->eob_seq_next++;
  if (st->eob_seq_next == 0)   /* wrapped past ULONG_MAX: 0 means "unqueued" */
    st->eob_seq_next = 1;
  st->eob_outstanding_seq = st->eob_seq_next;

  mdsync_send_pull(link, st->eob_outstanding_seq, scope, batch, n);
  st->eob_requests_sent++;
  st->eob_queue_next += (unsigned int)n;
}

void mdsync_link_eob(struct Client *link)
{
  struct MdSyncLink *st;
  struct mdsync_eob_dedup *dedup;
  struct Client *acptr;
  unsigned int a_count, r_count, total, idx;
  int i;

  if (!link || !IsIRCv3Aware(link))
    return;
  if (!metadata_lmdb_is_available())
    return;

  dedup = (struct mdsync_eob_dedup *)MyMalloc(MDSYNC_EOB_DEDUP_SIZE *
                                              sizeof(*dedup));
  if (!dedup)
    return;
  memset(dedup, 0, MDSYNC_EOB_DEDUP_SIZE * sizeof(*dedup));

  /* Every attached account on the whole network, not just the ones
   * this link introduced: a relink can follow a split during which
   * THIS link's view went stale regardless of which "side" an account
   * is nominally on (W4 plan Task 10). */
  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr)) {
    char key[ACCOUNTLEN + 1];
    struct mdsync_eob_dedup *slot;
    char scope;
    const char *account;

    if (!IsUser(acptr) || !IsAccount(acptr))
      continue;
    account = cli_user(acptr)->account;
    if (!account[0])
      continue;

    mdsync_pull_key(key, account);
    /* A held ghost is still MyConnect (bouncer hold/revive keeps the
     * local Client around) -- counts as local here exactly as
     * mdsync_on_attach's own scope rule does. */
    scope = MyConnect(acptr) ? 'A' : 'R';

    slot = mdsync_eob_dedup_slot(dedup, key);
    if (!slot) {
      log_write(LS_SYSTEM, L_WARNING, 0,
                "mdsync_link_eob: dedup table full building the EOB "
                "re-pull queue for %C - account %s skipped",
                link, key);
      continue;
    }
    if (!slot->used) {
      slot->used = 1;
      ircd_strncpy(slot->account, key, sizeof(slot->account));
      slot->scope = scope;
    } else if (scope == 'A' && slot->scope == 'R') {
      /* A local client of this account exists too -- 'A' always wins
       * over an earlier 'R' seen from some other client of the same
       * account, independent of which one this walk reached first. */
      slot->scope = 'A';
    }
  }

  a_count = 0;
  r_count = 0;
  for (idx = 0; idx < MDSYNC_EOB_DEDUP_SIZE; idx++) {
    if (!dedup[idx].used)
      continue;
    if (dedup[idx].scope == 'A')
      a_count++;
    else
      r_count++;
  }
  total = a_count + r_count;

  if (total == 0) {
    MyFree(dedup);
    return;
  }

  st = mdsync_link_state(link);
  if (!st) {
    MyFree(dedup);
    return;
  }

  /* A fresh queue replaces anything left over from an earlier sweep.
   * Should never still be non-NULL here -- a queue always drains to
   * NULL (mdsync_eob_send_next) long before this same link could end
   * another burst -- but freed defensively rather than assumed. */
  MyFree(st->eob_queue);

  st->eob_queue =
    (struct MdSyncEobEntry *)MyMalloc(total * sizeof(struct MdSyncEobEntry));
  if (!st->eob_queue) {
    MyFree(dedup);
    return;
  }

  /* 'A' entries first, then 'R' (W4 plan Task 10 rule) -- two passes
   * over the dedup table rather than one, since open addressing gives
   * no insertion order to rely on. */
  idx = 0;
  for (i = 0; i < (int)MDSYNC_EOB_DEDUP_SIZE; i++) {
    if (dedup[i].used && dedup[i].scope == 'A') {
      ircd_strncpy(st->eob_queue[idx].account, dedup[i].account,
                  sizeof(st->eob_queue[idx].account));
      st->eob_queue[idx].scope = 'A';
      idx++;
    }
  }
  for (i = 0; i < (int)MDSYNC_EOB_DEDUP_SIZE; i++) {
    if (dedup[i].used && dedup[i].scope == 'R') {
      ircd_strncpy(st->eob_queue[idx].account, dedup[i].account,
                  sizeof(st->eob_queue[idx].account));
      st->eob_queue[idx].scope = 'R';
      idx++;
    }
  }

  MyFree(dedup);

  /* eob_seq_next is deliberately NOT reset here: it only ever counts
   * up for this link's whole lifetime, so a stray "MD ." reply left
   * over from an abandoned earlier sweep (this link bursting twice in
   * one session, however unlikely) can never alias onto THIS sweep's
   * first request -- mdsync_on_pull_end's exact-match check already
   * ignores a non-matching seq, but only a counter that never repeats
   * keeps that guarantee even across two sweeps on the same link. */
  st->eob_queue_count = total;
  st->eob_queue_next = 0;
  st->eob_requests_sent = 0;
  st->eob_outstanding_seq = 0;

  /* Each queued account is noted pulled right away -- not only once
   * its batch actually sends -- so a near-simultaneous attach pull
   * (mdsync_on_attach) sees it as already covered and does not fire a
   * second, redundant ask while this sweep is still working through
   * its own queue (W4 plan Task 10). */
  for (i = 0; i < (int)total; i++)
    mdsync_note_pulled(st->eob_queue[i].account, st->eob_queue[i].scope);

  mdsync_eob_send_next(link, st);
}

void mdsync_on_pull_end(struct Client *link, unsigned long seq)
{
  struct Server *serv;
  struct MdSyncLink *st;

  if (!link)
    return;

  serv = cli_serv(link);
  /* Read-only lookup -- never mdsync_link_state(), which would
   * allocate a struct MdSyncLink for a link that has none because it
   * never got an EOB sweep (a peer not yet past its own burst, or one
   * with nothing to ask). */
  st = serv ? serv->mdsync : NULL;

  if (!st || !st->eob_outstanding_seq || seq != st->eob_outstanding_seq) {
    log_write(LS_SYSTEM, L_DEBUG, 0,
              "mdsync_on_pull_end: stray or stale seq %lu from %C "
              "(outstanding %lu) - ignored",
              seq, link, st ? st->eob_outstanding_seq : 0UL);
    return;
  }

  st->eob_outstanding_seq = 0;
  mdsync_eob_send_next(link, st);
}
