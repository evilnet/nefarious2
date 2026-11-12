/*
 * ml_fallback.h - what the single-line fallback of a multiline batch shows
 *
 * A recipient that cannot take a multiline batch (a client without the
 * draft/multiline cap, a legacy server, a way that does not carry ML) gets
 * a bounded preview of its lines and, when lines are left, one NOTICE
 * "[N more lines]".  Every sender of a fallback -- the local client
 * fallback (send_multiline_fallback), the originating server's DM fallback
 * (ml_send_dm_fallback), the channel fallback toward legacy links at the
 * origin and at a relay -- decides which lines to show and what N is here,
 * by one rule.
 *
 * The rule: the stored lines (flag byte + text, as m_batch.c keeps them)
 * are walked in order; a blank line is neither shown nor counted; every
 * other line is a unit (ml_fallback_starts_unit); the first max_preview
 * units are shown and N counts the units left.  Today a unit is one stored
 * line -- each draft/multiline-concat part counts on its own.  To count
 * logical lines instead (a line and its concat parts as one), only
 * ml_fallback_starts_unit() changes: ml_fallback_next() then sends a
 * shown unit's concat parts with it and ml_fallback_plan() counts units.
 */
#ifndef INCLUDED_ml_fallback_h
#define INCLUDED_ml_fallback_h

struct SLink;

/** Whether a stored line is shown by the fallback at all (it has text). */
extern int ml_fallback_shows(const char *rec);

/** Whether a stored line that is shown starts a new unit of the preview
 * budget and of "[N more lines]". */
extern int ml_fallback_starts_unit(const char *rec);

/** How many units the fallback of \a messages shows within \a max_preview
 * (*shown) and how many it leaves for "[N more lines]" (*left; 0: no
 * NOTICE). */
extern void ml_fallback_plan(const struct SLink *messages, int max_preview,
                             int *shown, int *left);

/** The next stored line to send at or after \a lp, given that \a *units
 * units have been started and \a shown may be: NULL when the preview is
 * done.  Walk with
 *   for (lp = ml_fallback_next(msgs, &u, shown); lp;
 *        lp = ml_fallback_next(lp->next, &u, shown))
 * starting from u = 0. */
extern const struct SLink *ml_fallback_next(const struct SLink *lp,
                                            int *units, int shown);

#endif /* INCLUDED_ml_fallback_h */
