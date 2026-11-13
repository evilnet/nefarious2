/*
 * IRC - Internet Relay Chat, include/metadata_sync.h
 *
 * Per-link state and wire emission for the W4 stamped account-metadata
 * sync protocol (MD =account / !sessid / ? / .).  See the W4 plan
 * (.claude/para/projects/2026-10-24-s2s-w4-account-state.md) for the
 * full wire reference.
 */
#ifndef INCLUDED_metadata_sync_h
#define INCLUDED_metadata_sync_h

#ifndef INCLUDED_metadata_lww_h
#include "metadata_lww.h"
#endif
#ifndef INCLUDED_ircd_defs_h
#include "ircd_defs.h"          /* ACCOUNTLEN */
#endif

struct Client;

/** One account queued in a link's EOB re-pull sweep (Task 10): its
 * folded name (the same casefold every store key and the attach-pull
 * dedup table use) and the scope ('A' or 'R') it will be asked at.
 */
struct MdSyncEobEntry {
  char account[ACCOUNTLEN + 1];
  char scope;
};

/** Per-link state for the stamped account-metadata sync protocol,
 * hung off cli_serv(link)->mdsync.  Task 3 only needed the
 * chunk-reassembly state for a `+`-continued "=account" row; Task 10
 * adds this link's EOB re-pull queue to the SAME struct -- kept a real
 * struct, not an opaque buffer, so that addition is a field, not a
 * redesign.
 */
/** Size of a link's pull-back ring (MdSyncLink.pullback). */
#define MDSYNC_PULLBACK_RING 64

struct MdSyncLink {
  struct md_chunk chunk;  /**< reassembly state for a `+`-continued row */
  time_t limit_notice_last;  /**< CurrentTime of the last SNO_NETWORK
                               *   over-limit notice sent for this link
                               *   (0 = none yet); Task 5, W4 plan 1.8. */

  /** Task 10: this link's end-of-burst re-pull queue.  Built once by
   * mdsync_link_eob() (every attached account on the whole network,
   * 'A'-scope entries first, then 'R'-scope), drained in <=16-account
   * batches by mdsync_eob_send_next(), one batch in flight at a time.
   * NULL when no sweep is in progress (also its state right after
   * mdsync_link_free() -- the queue dies with the link). */
  struct MdSyncEobEntry *eob_queue;
  unsigned int eob_queue_count;    /**< total entries in eob_queue */
  unsigned int eob_queue_next;     /**< index of the next entry to send */
  unsigned long eob_seq_next;      /**< next sequence number to hand out,
                                      *   incremented before use; never 0
                                      *   (0 means "unqueued", mdsync_on_attach) */
  unsigned long eob_outstanding_seq; /**< the one in-flight request's
                                        *   sequence number, 0 = none */
  unsigned int eob_requests_sent;  /**< "MD ?" batches sent so far this
                                      *   sweep, for the completion log line */

  /** Review b4: the accounts this server pulled back from this link after
   * answering its pull of an account we hold a CLEAR floor for, with when
   * -- one pull back per account per link per MDSYNC_PULL_INTERVAL, so two
   * servers that both hold floors stop after one pull each way.  A ring;
   * the casefolded account name ("" = free). */
  struct {
    char account[ACCOUNTLEN + 1];
    time_t at;
  } pullback[MDSYNC_PULLBACK_RING];
  unsigned int pullback_next;      /**< the ring's next slot to reuse */
};

/** Return this link's chunk-reassembly state, lazily allocating
 * cli_serv(link)->mdsync on first use.
 * @param[in] link The directly-connected server whose line is being fed.
 * @return The link's struct md_chunk, or NULL if @a link has no Server
 *         block (cli_serv(link) is NULL) or allocation failed.
 */
extern struct md_chunk *mdsync_link_chunk(struct Client *link);

/** Free a link's struct MdSyncLink (and anything it holds), called as
 * the server's Client is torn down.  Safe to call on a server with no
 * struct MdSyncLink allocated (no-op).
 * @param[in] server The server Client being freed.
 */
extern void mdsync_link_free(struct Client *server);

/** Emit a stamped account-metadata row (MD =account form).  Splits a
 * live value into <=300-byte `+`-continued pieces; a tombstone is a
 * single line with flags token "D" and no value.
 * @param[in] src Client to attribute the emission to (the P10 prefix).
 * @param[in] one If non-NULL, send only to this one link -- nothing at
 *            all when it is not IRCv3-aware.
 * @param[in] butone If @a one is NULL, send to every IRCv3-aware server
 *            except this one (NULL sends to all of them).
 * @param[in] account Account name.
 * @param[in] key Metadata key.
 * @param[in] v Version to emit (stamp, tombstone/vis/value).
 */
extern void metadata_emit_versioned(struct Client *src, struct Client *one,
                                    struct Client *butone,
                                    const char *account, const char *key,
                                    const struct md_version *v);

/** Write one account-store row as this server's own event: mint a stamp,
 * store the row (or its tombstone), apply it to every client logged
 * into @a account (local or remote, metadata_account_apply_memory:
 * memory, mode-sync flags, subscriber notifications), and send it as a
 * stamped "MD =account" row to every IRCv3-aware server.  When the
 * store refuses the write nothing is applied or sent.  With no store
 * configured, memory and peers still get it.
 * @param[in] src Client to attribute the emission to (&me, or the user
 *            that asked).
 * @param[in] account Account name (non-empty).
 * @param[in] key Metadata key (a draft/persistence/... key of any length
 *            up to 127 bytes; memory skips one of METADATA_KEY_LEN or
 *            longer).
 * @param[in] value New value, or NULL to delete (tombstone).
 * @param[in] vis METADATA_VIS_PUBLIC or METADATA_VIS_PRIVATE.
 * @return 0 on success, -1 when nothing was applied.
 */
extern int metadata_account_write(struct Client *src, const char *account,
                                  const char *key, const char *value, int vis);

/** Whether a user's metadata goes to other servers by its session id
 * ("MD !<sessid>"): it has no account, it has a session id, and
 * P10_MESSAGE_TAGS is on -- the only way every peer holds the same
 * session id for it (its N's ,S compact tag).  Otherwise, with no
 * account, the nick form.
 * @param[in] target The user.
 * @return Nonzero when "!sessid" addresses @a target.
 */
extern int metadata_session_addressable(struct Client *target);

/** Write one key of a user's metadata, addressed the W4 way: by account
 * (metadata_account_write) when @a target is logged in; otherwise
 * @a target's own memory, its subscribers, and "MD !<sessid>" to every
 * IRCv3-aware server -- or, with P10_MESSAGE_TAGS off (no session id
 * crosses then), the nick form, which receivers accept only from the
 * target's own server, the target, an alias of it or an oper.
 * @param[in] src Client to attribute the emission to.
 * @param[in] target The user whose metadata changes.
 * @param[in] key Metadata key.
 * @param[in] value New value, or NULL to delete.
 * A client of ours still registering writes its own memory and a note
 * of the write only (metadata_prereg_record()), whatever account it
 * carries: what becomes of it is decided when registration ends.
 * @param[in] vis METADATA_VIS_PUBLIC or METADATA_VIS_PRIVATE.
 * @return 0 on success, -1 when nothing was applied, -2 when a
 *   registering client's write is over the bound on what it may make us
 *   keep (metadata_prereg_record(); refused: LIMIT_REACHED).
 */
extern int metadata_client_write(struct Client *src, struct Client *target,
                                 const char *key, const char *value, int vis);

/** Answer a hop-local "MD ?" pull request from @a link: for each of the
 * @a n account names in @a accounts, send every stored version (live row
 * or tombstone, up to 128) via metadata_emit_versioned(&me, link, NULL,
 * ...); when @a scope is 'A', also send up to 256 of that account's
 * newest-by-timestamp read markers as "MR account target ts" (the
 * channel's canonical spelling when the target names a live channel).
 * Finishes with "MD . seq" regardless of scope or whether anything else
 * was sent. A no-op when @a link is not IRCv3-aware.
 * @param[in] link The server that asked (every line goes only to it).
 * @param[in] seq The request's sequence number, echoed back in "MD .".
 * @param[in] scope 'A' (rows + markers) or 'R' (rows only).
 * @param[in] accounts Account names to answer for.
 * @param[in] n Number of entries in @a accounts.
 */
extern void mdsync_answer_pull(struct Client *link, unsigned long seq,
                               char scope, char *accounts[], int n);

/** Notice an MD write that exceeded this server's own METADATA limits
 * (FEAT_METADATA_MAX_KEYS / FEAT_METADATA_MAX_VALUE_BYTES) on receipt
 * from a server link -- relayed unapplied rather than enforced
 * sender-side (W4 plan 1.8: "every form" of the MD wire table obeys
 * this same rule).  Always logs L_WARNING; throttles the oper-visible
 * SNO_NETWORK notice to once per @a link per
 * MDSYNC_LIMIT_NOTICE_INTERVAL_S (600) seconds, via state hung off the
 * same per-link struct mdsync_link_chunk() lazily allocates.
 * @param[in] link The server link the offending MD line arrived on
 *            (the direct connection, i.e. cptr at the call site).
 * @param[in] target The MD target token as it appeared on the wire
 *            (a nick, #channel, *account, !sessid or =account).
 * @param[in] key The metadata key.
 * @param[in] why One of "value is not UTF-8", "value over
 *            METADATA_MAX_VALUE_BYTES %d" or "key count at
 *            METADATA_MAX_KEYS %d", the latter two already formatted
 *            with the live limit by the caller.
 */
extern void mdsync_limit_notice(struct Client *link, const char *target,
                                const char *key, const char *why);

/** Pull an account's rows (and, for a local attach, its read markers)
 * from every other direct fork peer, called at the end of
 * metadata_load_account() -- i.e. at every point an account attaches to
 * a client, local or remote (register_user, SVSMODE/server MODE +r,
 * post-reg REGISTER, S2S ACCOUNT R/M/legacy-AC, the pre-reg LOC reply,
 * SASL reauth, and bouncer ghost restore at startup).
 *
 * A no-op when storage is unavailable.  Scope is 'A' (rows + markers)
 * when @a cptr is a local client (MyConnect), else 'R' (rows only) --
 * markers are only useful to notify a client THIS server owns.  Skips a
 * remote @a cptr still mid-burst from this server's point of view
 * (Task 10's EOB queue re-pulls it once the burst ends instead).  Skips
 * when @a account was already pulled within MDSYNC_PULL_INTERVAL at a
 * scope that covers this one (mdsync_note_pulled's table).  Otherwise
 * sends "MD ? 0 <scope> <account>" (seq 0: unqueued, Task 10's EOB queue
 * numbers its own requests) to every directly-connected IRCv3-aware
 * server link not itself mid-burst.  Replies come back through the
 * existing "=account" row receiver and ms_markread.
 * @param[in] cptr The client that just attached @a account.
 * @param[in] account Account name.
 */
extern void mdsync_on_attach(struct Client *cptr, const char *account);

/** Record that @a account was just pulled at @a scope, for
 * mdsync_on_attach's dedup table (and Task 10's EOB re-pull, which
 * shares it).  Keyed by @a account casefolded the way every store key
 * is; the table holds MDSYNC_PULL_TABLE_SIZE accounts and is cleared
 * whole, not evicted one at a time, when a new account finds it full.
 * @param[in] account Account name.
 * @param[in] scope 'A' (rows + markers) or 'R' (rows only).
 */
extern void mdsync_note_pulled(const char *account, char scope);

/** Re-pull every attached account from @a link at the end of its
 * burst to us (ms_end_of_burst's MyConnect(sptr) branch): a relink can
 * follow a split during which THIS link, not the account's own side,
 * missed writes, so every account attached anywhere on the network is
 * asked of it, not just the ones it introduced.  Walks GlobalClientList
 * for IsUser && IsAccount clients, dedupes by folded account name, and
 * scopes each one 'A' if any client of it is local (MyConnect; a held
 * ghost counts) or 'R' otherwise.  Queues every one of them regardless
 * of mdsync_on_attach's 60s window (another peer's pull may have
 * already satisfied it; this relinking link still needs asking), 'A'
 * entries first, then 'R', and immediately calls mdsync_note_pulled on
 * each so a near-simultaneous attach pull does not also ask for it.
 * Sends the first <=16-account "MD ? <seq> <scope> ..." batch itself;
 * mdsync_on_pull_end sends the rest, one batch in flight at a time.  A
 * no-op when @a link is not IRCv3-aware, storage is unavailable, or no
 * account is attached anywhere.  The queue is freed with the link
 * (mdsync_link_free) if it never finishes draining.
 * @param[in] link The directly-connected server that just finished its
 *            burst to us.
 */
extern void mdsync_link_eob(struct Client *link);

/** Handle "MD . <seq>" from @a link: if @a seq matches @a link's one
 * outstanding EOB re-pull request (mdsync_link_eob /
 * mdsync_on_pull_end's own previous call), clear it and send the
 * queue's next batch, if any remain, logging the L_INFO completion
 * line once the queue is empty.  A @a seq that does not match the
 * outstanding one (including when @a link has no queue at all, e.g.
 * it never ran Task 9/10 or has nothing to ask) is a stray or stale
 * reply and is ignored, logged at L_DEBUG only -- never a sign of a
 * real desync, since this link's own queue is unaffected either way.
 * @param[in] link The link whose pull-end this is.
 * @param[in] seq The sequence number it echoed back.
 */
extern void mdsync_on_pull_end(struct Client *link, unsigned long seq);

#endif /* INCLUDED_metadata_sync_h */
