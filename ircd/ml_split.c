/*
 * IRC - Internet Relay Chat, ircd/ml_split.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
 * any later version.
 */
/** @file
 * @brief Split the lines of a client's multiline batch to fit their
 *        relayed form (kept apart from m_batch.c so it is unit-tested).
 */
#include "config.h"

#include "ml_split.h"
#include "ircd_alloc.h"
#include "ircd_string.h"
#include "list.h"

#include <string.h>

/** Split every line of a multiline batch longer than \a room bytes into
 * parts of at most \a room (ircd_split_len: a UTF-8 boundary, never inside
 * a colour code), each part after the first marked concat, so the joined
 * message is byte-identical to the client's.  A line is a string whose
 * first byte is its concat flag (1 = joins its predecessor with nothing
 * between, 0 = with a line feed) followed by the text, as
 * multiline_add_message() stores it.  A part keeps its line's flag only
 * on the first piece.  \a room 0 splits nothing.
 * @param[in,out] lines The batch's line list (SLink value.cp).
 * @param[in] room The bytes of text a relayed line can carry.
 * @return The number of lines after the split.
 */
int ml_split_lines(struct SLink *lines, size_t room)
{
  struct SLink *lp;
  int count = 0;

  for (lp = lines; lp; lp = lp->next) {
    char *text = lp->value.cp + 1;
    size_t len = strlen(text);

    count++;
    while (room > 0 && len > room) {
      size_t keep = ircd_split_len(text, len, room);
      struct SLink *part;
      char *copy;

      copy = (char *)MyMalloc(len - keep + 2);
      copy[0] = 1;  /* concat */
      memcpy(copy + 1, text + keep, len - keep + 1);
      text[keep] = '\0';

      part = make_link();
      part->value.cp = copy;
      part->next = lp->next;
      lp->next = part;

      lp = part;
      text = copy + 1;
      len -= keep;
      count++;
    }
  }
  return count;
}

/** Replace the text of one batch line, keeping its concat flag.
 * @param[in,out] line The line (SLink value.cp: flag byte + text).
 * @param[in] text The new text; may point anywhere but into the line. */
void ml_line_set_text(struct SLink *line, const char *text)
{
  size_t len = strlen(text);
  char *copy = (char *)MyMalloc(len + 2);

  copy[0] = line->value.cp[0];
  memcpy(copy + 1, text, len + 1);
  MyFree(line->value.cp);
  line->value.cp = copy;
}

/** Run a send check over every line of a multiline batch that has text,
 * in order, as each line would be checked as a single message: a line
 * the check transforms takes the new text (its concat flag kept); the
 * first line it refuses stops the walk and refuses the batch, the lines
 * after it untouched.  A blank line is no message of its own (it is
 * never sent as one) and is not checked.
 * @param[in,out] lines The batch's line list.
 * @param[in] check The check.
 * @param[in] ctx Passed to \a check.
 * @return 0 when every line passed, -1 when one was refused.
 */
int ml_lines_check(struct SLink *lines, ml_line_check check, void *ctx)
{
  struct SLink *lp;

  for (lp = lines; lp; lp = lp->next) {
    const char *text = lp->value.cp + 1;
    const char *out;

    if (!*text)
      continue;
    if (!(out = check(text, ctx)))
      return -1;
    if (out != text)
      ml_line_set_text(lp, out);
  }
  return 0;
}

/** A batch's size as multiline_add_message() counts it while the batch
 * is built: the lines' text, and one byte for each line feed that joins
 * a line to the one before (a concat line joins with none).
 * @param[in] lines The batch's line list.
 * @return The byte count. */
int ml_lines_bytes(const struct SLink *lines)
{
  const struct SLink *lp;
  int total = 0;

  for (lp = lines; lp; lp = lp->next)
    total += (int)strlen(lp->value.cp + 1)
             + ((lp != lines && !lp->value.cp[0]) ? 1 : 0);
  return total;
}
