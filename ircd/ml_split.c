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
