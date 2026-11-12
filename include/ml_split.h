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

#endif /* INCLUDED_ml_split_h */
