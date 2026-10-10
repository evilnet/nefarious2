/*
 * redact_index.h -- the redaction catch-up index (design B, chathistory).
 *
 * Every store that applies a redaction keeps a time-ordered index row so a
 * store that was absent can ask "redactions since T" and apply what it
 * missed.  This module is PURE (no IRCd deps) so the cmocka harness gates it:
 * key/value encoding for the index column family and the CH D reply parser.
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

#endif
