/*
 * IRC - Internet Relay Chat, ircd/ml_fallback.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
/** @file
 * @brief The one rule for the preview a multiline fallback shows and the
 *   count in its "[N more lines]" NOTICE (see ml_fallback.h).  Pure:
 *   ircd/test/ml_fallback_cmocka.c links it alone.
 */
#include "config.h"

#include "ml_fallback.h"

#include "list.h"

#include <stddef.h>

int ml_fallback_shows(const char *rec)
{
  return rec && rec[1] != '\0';
}

int ml_fallback_starts_unit(const char *rec)
{
  /* Each stored line with text is a unit, a concat part included.  For
   * logical lines: return ml_fallback_shows(rec) && !rec[0]. */
  return ml_fallback_shows(rec);
}

void ml_fallback_plan(const struct SLink *messages, int max_preview,
                      int *shown, int *left)
{
  const struct SLink *lp;
  int units = 0;

  for (lp = messages; lp; lp = lp->next)
    if (ml_fallback_shows(lp->value.cp) && ml_fallback_starts_unit(lp->value.cp))
      units++;
  if (max_preview < 0)
    max_preview = 0;
  *shown = units < max_preview ? units : max_preview;
  *left = units - *shown;
}

const struct SLink *ml_fallback_next(const struct SLink *lp, int *units,
                                     int shown)
{
  for (; lp; lp = lp->next) {
    const char *rec = lp->value.cp;

    if (!ml_fallback_shows(rec))
      continue;
    if (ml_fallback_starts_unit(rec)) {
      if (*units >= shown)
        return NULL;
      (*units)++;
    } else if (*units == 0) {
      continue;  /* a part with no unit started before it: never shown */
    }
    return lp;
  }
  return NULL;
}
