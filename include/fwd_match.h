/** @file fwd_match.h
 * @brief Which forwarded command a reply without a msgid answers.
 *
 * A command hunt_server_cmd() forwards is answered by numerics (and a few
 * NOTICEs) that come back over the link it went out on.  Between fork
 * servers they carry the command's compact msgid and are matched to it
 * exactly (forwarded_label.c).  A legacy server -- stock Nefarious, X3 --
 * neither receives nor returns that msgid: its replies are matched here,
 * by what they say rather than by when they arrive.
 *
 * A reply fits a pending command when its numeric belongs to the
 * command's FAMILY (the numerics stock and fork servers, and X3, send in
 * answer to that command) and, where the numeric names a SUBJECT (the
 * nick a WHOIS asked about, the server a VERSION went to, the STATS
 * letter, the channel of a NAMES), the subject is the command's.  The
 * family's terminal numeric (or an error that is the whole answer) ends
 * the command.
 *
 * Several pending commands may fit one reply.  Those sent to the same
 * server are answered in the order they were sent (one server, one link,
 * one TCP stream), so the oldest is the one being answered.  Those sent
 * to DIFFERENT servers behind the same link may be answered in any order
 * and interleaved; when the reply names nothing that tells them apart it
 * is AMBIGUOUS, and the caller labels none of them (fwd_pick()).
 *
 * Pure functions, no ircd state: unit-tested by fwd_match_cmocka.
 */
#ifndef INCLUDED_fwd_match_h
#define INCLUDED_fwd_match_h

/** Families of forwarded commands (0 = a command we do not track). */
enum FwdFamily {
  FWD_FAM_NONE = 0,
  FWD_FAM_WHOIS,
  FWD_FAM_WHOWAS,
  FWD_FAM_VERSION,
  FWD_FAM_TIME,
  FWD_FAM_ADMIN,
  FWD_FAM_MOTD,
  FWD_FAM_RULES,
  FWD_FAM_OPERMOTD,
  FWD_FAM_LUSERS,
  FWD_FAM_INFO,
  FWD_FAM_LINKS,
  FWD_FAM_STATS,
  FWD_FAM_TRACE,
  FWD_FAM_NAMES,
  FWD_FAM_CHECK,
  FWD_FAM_COUNT
};

/** Where a forwarded command's subject is taken from. */
enum FwdSubjectFrom {
  FWD_SUBJ_NONE = 0,   /**< its replies name nothing (LUSERS, INFO, TRACE, CHECK) */
  FWD_SUBJ_PARV1,      /**< parv[1] of the forwarded command (WHOWAS, STATS, NAMES) */
  FWD_SUBJ_PARV2,      /**< parv[2] (WHOIS's nick list, LINKS' mask) */
  FWD_SUBJ_SERVER      /**< the destination server's name (VERSION, TIME, ...) */
};

/** How a reply fits a pending command. */
enum FwdFit {
  FWD_FIT_NO = 0,      /**< not this command's */
  FWD_FIT_BODY,        /**< one of its lines; more to come */
  FWD_FIT_END,         /**< its last line: the command is answered */
  FWD_FIT_ELEMENT_END  /**< the last line for one element of its list (NAMES' 366) */
};

/** Longest subject kept (a WHOIS nick list, a server name, a mask). */
#define FWD_SUBJECT_MAX 96

/** Seconds a forwarded command waits for its answer.  Past it the
 * command is given up -- its label answered (ACK, or its batch ended) --
 * and nothing that comes later is taken for its answer. */
#define FWD_DEADLINE 60

/** The family of a forwarded command, by its long name; FWD_FAM_NONE for
 * one whose replies we do not track (CONNECT, REHASH, RPING, ...). */
extern int fwd_family_of(const char *cmd);

/** A family's name ("WHOIS"), for logs and tests; "" for none. */
extern const char *fwd_family_name(int fam);

/** Where a family's subject comes from (enum FwdSubjectFrom). */
extern int fwd_family_subject(int fam);

/** Whether servers on the way, not only the destination, add lines to a
 * family's answer (TRACE: every hop sends its RPL_TRACELINK). */
extern int fwd_family_hops_answer(int fam);

/** Whether the two families have a numeric in common (WHOIS and WHOWAS:
 * 301, 312, 338). */
extern int fwd_families_overlap(int a, int b);

/** The number of elements of a comma-separated list (NAMES' channels). */
extern int fwd_list_count(const char *list);

/** Whether \a numeric is an error a server on the way can answer any
 * forwarded command with -- ERR_NOSUCHSERVER (the destination split
 * while the command was on its way), ERR_NOPRIVILEGES (its hunt refused
 * a non-oper) -- and that names no subject of the command. */
extern int fwd_numeric_generic(int numeric);

/** How a reply fits a pending command of family \a fam asked about
 * \a subject.
 * @param[in] fam Family of the pending command.
 * @param[in] subject Its subject ("" when its family has none).
 * @param[in] numeric The reply's numeric.
 * @param[in] params The reply's parameters after its target, as they
 *   came over the link ("muser ~u host * :real name").
 * @return enum FwdFit.
 */
extern int fwd_reply_fit(int fam, const char *subject, int numeric,
                         const char *params);

/** A pending forwarded command, as fwd_pick() sees it. */
struct FwdView {
  int fam;                  /**< family; FWD_FAM_NONE for a free slot */
  const char *subject;      /**< its subject ("" for none) */
  const char *dest;         /**< numeric (YY) of the server it was sent to */
  const char *link;         /**< numeric of our link it went out on */
  unsigned long seq;        /**< send order: smaller is older */
  long age;                 /**< seconds since it was sent */
};

/** Bit of an fwd_pick() \a untracked mask: a command whose replies are
 * not known (CONNECT, RPING, REHASH, ...) is outstanding -- it can be
 * refused with ERR_NOSUCHSERVER or ERR_NOPRIVILEGES. */
#define FWD_UNTRACKED_GENERIC (1u << 31)

/** Bit of an fwd_pick() \a untracked mask: a command that a remote
 * server may answer with ERR_NOSUCHNICK (INVITE of a user there) is
 * outstanding -- a 401 naming that nick is not told from a WHOIS's. */
#define FWD_UNTRACKED_NOSUCHNICK (1u << 30)

/** Pick the pending command a reply without a msgid answers.
 *
 * Candidates are the commands sent out over \a link, no longer ago than
 * FWD_DEADLINE, whose family and subject the reply fits (an
 * fwd_numeric_generic() error fits every command on \a link).  When the
 * reply's source is its true origin (\a source_true: the asker is an
 * oper, whose replies no server relays under its own name), candidates
 * sent to another server than \a source are dropped -- unless a
 * candidate's family has lines from the hops on the way, or the reply is
 * a generic error, either of which a server other than the destination
 * can send; and a reply from a server none of them went to is none of
 * theirs.  Of what is left, the oldest is picked; the reply is
 * \a ambiguous -- the caller must label it for none of them -- if they
 * were not all sent to the same server, if their family has lines from
 * the hops (one hop's line cannot be told from another command's), or if
 * a command of a candidate's family that is not tracked may be answered
 * by it (\a untracked).  A generic error while a command of unknown
 * replies is outstanding (FWD_UNTRACKED_GENERIC) is nobody's.
 *
 * @param[in] v The asker's pending commands.
 * @param[in] n Number of them.
 * @param[in] numeric The reply's numeric.
 * @param[in] params Its parameters (see fwd_reply_fit()).
 * @param[in] link Numeric of the link the reply came over.
 * @param[in] source Numeric of the server the reply names as its source.
 * @param[in] source_true Whether \a source is the reply's origin.
 * @param[in] untracked Families (1 << enum FwdFamily) of which a command
 *   the asker sent is not tracked and may still be answered,
 *   FWD_UNTRACKED_GENERIC and FWD_UNTRACKED_NOSUCHNICK.
 * @param[out] cand cand[i] set to 1 for every candidate, else 0 (n entries).
 * @param[out] fit How the reply fits the picked command (enum FwdFit).
 * @param[out] ambiguous Set to 1 if the candidates could not be told apart.
 * @return Index of the picked command, or -1 if the reply fits none.
 */
extern int fwd_pick(const struct FwdView *v, int n, int numeric,
                    const char *params, const char *link, const char *source,
                    int source_true, unsigned int untracked,
                    unsigned char *cand, int *fit, int *ambiguous);

#endif /* INCLUDED_fwd_match_h */
