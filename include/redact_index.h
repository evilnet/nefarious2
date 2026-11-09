/*
 * redact_index.h -- the redaction catch-up index (design B, chathistory).
 *
 * Every store that applies a redaction keeps a time-ordered index row so a
 * store that was absent can ask "redactions since T" and apply what it
 * missed.  This module is PURE (no IRCd deps) so the cmocka harness gates it:
 * key/value encoding for the index column family and the CH D reply parser,
 * the REDACT authorization rule, and what applying a redaction stores and
 * where a catch-up round leaves the watermark.
 */
#ifndef INCLUDED_redact_index_h
#define INCLUDED_redact_index_h
#include <stdint.h>
#include <stddef.h>

#define RDX_MSGID_MAX   64
#define RDX_KEY_MAX     (8 + RDX_MSGID_MAX)
#define RDX_TARGET_MAX  256
#define RDX_SENDER_MAX  192
#define RDX_ACCOUNT_MAX 64
#define RDX_REASON_MAX  400
#define RDX_VAL_MAX     (RDX_TARGET_MAX + RDX_MSGID_MAX + RDX_SENDER_MAX + RDX_ACCOUNT_MAX + RDX_REASON_MAX + 8)

struct rdx_val {
  char target[RDX_TARGET_MAX];        /**< storage key of the redacted row */
  char parent_msgid[RDX_MSGID_MAX];   /**< the redacted message */
  char sender[RDX_SENDER_MAX];        /**< who redacted (nick!user@host or server) */
  char account[RDX_ACCOUNT_MAX];      /**< their account, "" if none */
  char reason[RDX_REASON_MAX];        /**< "" if none */
};

struct rdx_reply {
  char     reqid[32];
  uint64_t time_ms;                   /**< the REDACT event time */
  char     redact_msgid[RDX_MSGID_MAX];
  struct rdx_val v;
};

/* key = <time_ms big-endian 8 bytes><redact_msgid bytes> (no NUL) -> time-ordered */
int rdx_key_build(unsigned char *buf, size_t size, uint64_t time_ms, const char *redact_msgid);
int rdx_key_parse(const void *key, size_t klen, uint64_t *time_ms, char *msgid, size_t msz);
/* value = target NUL parent NUL sender NUL account NUL reason (reason unterminated) */
int rdx_val_pack(char *buf, size_t size, const struct rdx_val *v);
int rdx_val_parse(const void *val, size_t vlen, struct rdx_val *out);
/* CH D <reqid> <time_ms> <redact_msgid> <target> <parent_msgid> <sender> <account|*> :<reason>
 * parv[1] == "D"; 0 on success, -1 if short/malformed. */
int rdx_reply_parse(int parc, char **parv, struct rdx_reply *out);

/* CH E <reqid> <count> [flags] -- the optional trailing flags param, letters
 * in any order: T = this responder's result was truncated (more exists);
 * U = this responder never answered the query at all (no store, an unknown
 * subcommand, or a read error) -- distinct from a genuine zero-row answer.
 * NULL-safe; unrecognized letters are ignored. */
#define CH_E_TRUNCATED   0x1
#define CH_E_UNANSWERED  0x2
unsigned int ch_e_flags(const char *param);

/* CH A S <retention_days> [<features>] -- feature letters a store advertises
 * with its storage ad, any order: K = it answers CH Q K, the context children
 * of named msgids (W5 Task 14).  NULL-safe; unknown letters ignored, so later
 * features add letters. */
#define CH_AD_CHILDREN   0x1
unsigned int ch_ad_features(const char *param);

/* The letters of a CH A S <days> [<features>] as a receiver keeps them to
 * relay and re-flood with the ad: the [A-Za-z] characters of @a param, in
 * order, known or not, so a later feature survives a hop that does not know
 * it (fix round 1).  At most @a outsz - 1 of them (CH_AD_LETTERS_MAX + 1 is
 * the buffer a receiver keeps).  NULL-safe; @a out is always terminated
 * when @a outsz > 0.  @return the letters kept. */
#define CH_AD_LETTERS_MAX 8
size_t ch_ad_letters(const char *param, char *out, size_t outsz);

/* Applying one redaction (a peer's live REDACT, a catch-up row, or a
 * write-forwarded one) to this server's store.  @a parent_lookup_rc is
 * history_lookup_message's answer for the redacted message (0 found, 1 not
 * found, < 0 read error); @a already_redacted is history_message_is_redacted's
 * (1 yes, 0 no, < 0 read error), read whenever the lookup did not fail -- a
 * REDACT row annotates a message through the reply index whether or not the
 * message itself is here.  In order:
 *  RETRY        -- either read failed: store nothing; a catch-up round is cut,
 *                  so its watermark stays and the row is asked for again;
 *  SKIP_APPLIED -- a REDACT row already annotates it (live, an earlier
 *                  catch-up, or a tombstone): store no second one;
 *  SKIP_ORPHAN  -- the message is not here (it never reached this store, or
 *                  the trim evicted it): the caller stores the REDACT row as
 *                  a TOMBSTONE (user decision 2026-11-08) -- it hides the
 *                  message if the message is stored here later -- and shows
 *                  a catch-up row to no client;
 *  APPLY        -- store the REDACT row. */
enum rdx_row { RDX_ROW_APPLY, RDX_ROW_SKIP_APPLIED, RDX_ROW_SKIP_ORPHAN, RDX_ROW_RETRY };
enum rdx_row rdx_row_decide(int parent_lookup_rc, int already_redacted);

/* Where a finished redaction catch-up round (CH Q * D) leaves the watermark,
 * the time before which this store holds every redaction a peer had.  In
 * order:
 *  @a cut (a timeout, a CH E U, a row the store could not read) -> KEEP;
 *  @a truncated (more rows exist) with no row fetched (@a last_ms 0) -> KEEP;
 *  @a truncated below @a max_rounds -> SET_CONTINUE at @a last_ms (the newest
 *    row fetched; the next round asks from there);
 *  @a truncated at @a max_rounds -> SET at @a last_ms: the rows after it were
 *    never fetched, so the next catch-up asks from there;
 *  complete -> SET at @a start_ms (when this round was asked).
 * @a round counts from 1.  *wm_out is written only on SET/SET_CONTINUE, and
 * wm_out may be NULL. */
enum rdx_wm  { RDX_WM_KEEP, RDX_WM_SET, RDX_WM_SET_CONTINUE };
enum rdx_wm  rdx_watermark_decide(int cut, int truncated, int round, int max_rounds,
                                  uint64_t last_ms, uint64_t start_ms, uint64_t *wm_out);

/* The one REDACT authorization rule, for a row found in this server's
 * store (m_redact) and for one a storage peer returned (complete_redact_fed,
 * m_chathistory.c), in order:
 *  1. a row that is not a PRIVMSG/NOTICE/TAGMSG/MULTILINE -> NOT_MESSAGE;
 *  2. an oper: within oper_window -> OK, else EXPIRED (*window_out = oper_window);
 *  3. the row's account owner (both accounts set, ircd_strcmp) -> OK, no window;
 *  4. both accounts empty, the header not repaired, req_mask == msg_sender
 *     (ircd_strcmp) -> OK;
 *  5. everyone else: outside window -> EXPIRED (*window_out = window); a
 *     chanop with chanop_others -> OK; else FORBIDDEN.
 * "Within" a window: 0 = no window, else (now - msg_time) <= window.
 * NULL strings read as "".  *window_out is written only on EXPIRED, and
 * window_out may be NULL. */
enum redact_auth { REDACT_AUTH_OK, REDACT_AUTH_NOT_MESSAGE, REDACT_AUTH_EXPIRED, REDACT_AUTH_FORBIDDEN };
struct redact_auth_in {
  int msg_type;                       /* enum HistoryMessageType value (history.h) */
  long msg_time, now;                 /* unix seconds */
  const char *msg_account, *msg_sender, *req_account, *req_mask;   /* "" when none */
  int header_repaired;                /* row header repaired on read (ce441a04); 1 for every federated row */
  int is_oper, is_chanop, chanop_others;
  long window, oper_window;           /* REDACT_WINDOW, REDACT_OPER_WINDOW; 0 = none */
};
enum redact_auth redact_authorize(const struct redact_auth_in *in, long *window_out);

#endif
