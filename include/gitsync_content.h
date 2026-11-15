/*
 * IRC - Internet Relay Chat, include/gitsync_content.h
 * Copyright (C) 2025 Nefarious Development
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
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
 * @brief GitSync - what a sync does with the content it pulled (pure).
 */
#ifndef INCLUDED_gitsync_content_h
#define INCLUDED_gitsync_content_h

#include <stddef.h>

/** Size of a buffer for gitsync_content_hash(). */
#define GITSYNC_HASHLEN 64

extern void gitsync_content_hash(const char *content, size_t len,
                                 char *hash, size_t hashlen);

#endif /* INCLUDED_gitsync_content_h */
