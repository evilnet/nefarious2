/*
 * IRC - Internet Relay Chat, ircd/querycmds.c (formerly ircd/s_serv.c)
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
 *
 * See file AUTHORS in IRC package for additional names of
 * the programmers.
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
 * @brief Implementation of client counting functions.
 * @version $Id: querycmds.c 1212 2004-10-03 17:02:23Z entrope $
 */
#include "config.h"

#include "client.h"
#include "ircd_snprintf.h"
#include "querycmds.h"
#include "s_debug.h"
#include "send.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/** Counters of clients, servers etc. */
struct UserStatistics UserStats;

/** Initialize global #UserStats variable. */
void init_counters(void)
{
  memset(&UserStats, 0, sizeof(UserStats));
  UserStats.servers = 1;
}

/** Saves the tunefile which keeps the current local and global
 * max user counts.
 */
void save_tunefile(void)
{
  FILE *tunefile;
  char tfile[1024];

  ircd_snprintf(0, tfile, sizeof(tfile), "%s/%s", DPATH,
                feature_str(FEAT_TPATH));
  tunefile = fopen(tfile, "w");
  if (!tunefile) {
    sendto_opmask_butone(0, SNO_OLDSNO, "Unable to write tunefile..");
    return;
  }
  fprintf(tunefile, "%d\n", UserStats.local_clients_max);
  fprintf(tunefile, "%d\n", UserStats.clients_max);
  fclose(tunefile);
}

/** Loads the tunefile which keeps the current local and global
 * max user counts.
 */
void load_tunefile(void)
{
  FILE *tunefile;
  char buf[1024];

  char tfile[1024];
  ircd_snprintf(0, tfile, sizeof(tfile), "%s/%s", DPATH,
                feature_str(FEAT_TPATH));
  tunefile = fopen(tfile, "r");
  if (!tunefile)
    return;
  Debug((DEBUG_DEBUG, "Reading tune file"));

  (void)!fgets(buf, 1023, tunefile);
  UserStats.local_clients_max = atol(buf);
  (void)!fgets(buf, 1023, tunefile);
  UserStats.clients_max = atol(buf);
  fclose(tunefile);
}

