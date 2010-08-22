/*
 * IRC - Internet Relay Chat, ircd/m_mkpasswd.c
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
 *
 * $Id$
 */
#include "config.h"

#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_crypt.h"
#include "ircd_crypt_native.h"
#include "ircd_crypt_plain.h"
#include "ircd_crypt_smd5.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "send.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */

static char saltChars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./";

static char *make_salt(void)
{
  static char salt[3];
  srandom(CurrentTime); /* may not be the BEST salt, but its close */
  salt[0] = saltChars[random() % 64];
  salt[1] = saltChars[random() % 64];
  salt[2] = '\0';
  return salt;
}

static char *make_md5_salt(void)
{
  static char salt[13];
  int i;
  srandom(CurrentTime); /* may not be the BEST salt, but its close */
  salt[0] = '$';
  salt[1] = '1';
  salt[2] = '$';
  for (i=3; i<11; i++)
    salt[i] = saltChars[random() % 64];
  salt[11] = '$';
  salt[12] = '\0';
  return salt;
}

/*
 * m_mkpasswd - generic message handler
 */
int m_mkpasswd(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  const char *pass;
  const char *prefix = "";

  if (parc < 2)
    return need_more_params(sptr, "MKPASSWD");

  if (parc == 3) {
    if (!ircd_strcmp(parv[2], "DES")) {
      pass = ircd_crypt_native(parv[1], make_salt());
    } else if (!ircd_strcmp(parv[2], "MD5")) {
      pass = ircd_crypt_native(parv[1], make_md5_salt());
    } else if (!ircd_strcmp(parv[2], "SMD5")) {
      pass = ircd_crypt_smd5(parv[1], make_salt());
      prefix = "$SMD5$";
    } else if (!ircd_strcmp(parv[2], "PLAIN")) {
      pass = ircd_crypt_plain(parv[1], "plain");
      prefix = "$PLAIN$";
    } else {
      sendcmdto_one(&me, CMD_NOTICE, sptr,
                    "%C :MKPASSWD syntax error: MKPASSWD <pass> [DES|MD5|SMD5|PLAIN]",
                    sptr);
      return 0;
    }
  } else {
    pass = ircd_crypt_native(parv[1], make_salt());
  }

  sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :Encryption for [%s]: %s%s",
                sptr, parv[1], prefix, pass);

  return 0;
}

