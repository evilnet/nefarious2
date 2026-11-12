/*
 * IRC - Internet Relay Chat, include/ml_split.h
 */
/** @file
 * @brief Split the lines of a client's multiline batch to fit their
 *        relayed form.
 */
#ifndef INCLUDED_ml_split_h
#define INCLUDED_ml_split_h

#include <stddef.h>

struct SLink;

extern int ml_split_lines(struct SLink *lines, size_t room);

/** A per-line send check of a multiline batch (ml_lines_check): the text
 * to keep for the line -- \a text itself, or a transformed copy -- or
 * NULL when the line, and so the batch, is refused. */
typedef const char *(*ml_line_check)(const char *text, void *ctx);

extern int ml_lines_check(struct SLink *lines, ml_line_check check, void *ctx);
extern void ml_line_set_text(struct SLink *line, const char *text);
extern int ml_lines_bytes(const struct SLink *lines);

#endif /* INCLUDED_ml_split_h */
