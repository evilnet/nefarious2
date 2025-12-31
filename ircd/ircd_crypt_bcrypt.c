/*
 * IRC - Internet Relay Chat, ircd/ircd_crypt_bcrypt.c
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
/**
 * @file
 * @brief Bcrypt password hashing routines
 *
 * Provides bcrypt ($2y$) password hashing using the system's crypt() function.
 * Requires a system with bcrypt support in libcrypt (glibc 2.7+ or libxcrypt).
 */
#define _XOPEN_SOURCE 500

#include "config.h"
#include "ircd_crypt.h"
#include "ircd_crypt_bcrypt.h"
#include "ircd_log.h"
#include "s_debug.h"
#include "ircd_alloc.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <fcntl.h>
#ifdef HAVE_CRYPT_H
#include <crypt.h>
#endif

/* Bcrypt uses a custom base64 alphabet */
static const char bcrypt_base64[] =
  "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/* Default cost factor (2^12 = 4096 iterations) */
#define BCRYPT_DEFAULT_COST 12

/** Generate random bytes from /dev/urandom
 * @param buf Buffer to fill
 * @param len Number of bytes to generate
 * @return 0 on success, -1 on failure
 */
static int get_random_bytes(unsigned char* buf, size_t len)
{
  int fd;
  ssize_t n;

  fd = open("/dev/urandom", O_RDONLY);
  if (fd < 0)
    return -1;

  n = read(fd, buf, len);
  close(fd);

  return (n == (ssize_t)len) ? 0 : -1;
}

/** Generate a bcrypt salt string
 * @param salt Buffer to store the salt (must be at least 30 bytes)
 * @param cost Cost factor (4-31, recommend 10-12)
 * @return Pointer to salt, or NULL on failure
 */
static char* generate_bcrypt_salt(char* salt, int cost)
{
  unsigned char raw[16];
  int i;
  unsigned long v;

  if (cost < 4) cost = 4;
  if (cost > 31) cost = 31;

  if (get_random_bytes(raw, 16) < 0)
    return NULL;

  /* Format: $2y$XX$ followed by 22 base64 characters */
  sprintf(salt, "$2y$%02d$", cost);

  /* Encode 16 bytes (128 bits) into 22 base64 characters */
  /* Each group of 3 bytes becomes 4 base64 chars, with padding handled specially */
  for (i = 0; i < 5; i++) {
    v = (raw[i*3] << 16) | (raw[i*3+1] << 8) | raw[i*3+2];
    salt[7 + i*4]     = bcrypt_base64[(v >> 18) & 0x3f];
    salt[7 + i*4 + 1] = bcrypt_base64[(v >> 12) & 0x3f];
    salt[7 + i*4 + 2] = bcrypt_base64[(v >> 6) & 0x3f];
    salt[7 + i*4 + 3] = bcrypt_base64[v & 0x3f];
  }
  /* Last byte */
  v = raw[15];
  salt[27] = bcrypt_base64[(v >> 2) & 0x3f];
  salt[28] = bcrypt_base64[(v << 4) & 0x3f];
  salt[29] = '\0';

  return salt;
}

/** Bcrypt password hashing function
 * @param key The password to hash
 * @param salt The salt (if starts with $2, use as-is; otherwise generate new)
 * @return The hashed password, or NULL on failure
 *
 * When called with an existing bcrypt hash as salt, extracts and uses that salt.
 * When called with a simple salt (for new password generation), generates a
 * proper bcrypt salt.
 */
const char* ircd_crypt_bcrypt(const char* key, const char* salt)
{
  static char newsalt[30];
  const char* result;

  assert(NULL != key);
  assert(NULL != salt);

  Debug((DEBUG_DEBUG, "ircd_crypt_bcrypt: key = %s", key));
  Debug((DEBUG_DEBUG, "ircd_crypt_bcrypt: salt = %s", salt));

  /* If salt is already a bcrypt hash/salt, use it directly */
  if (strlen(salt) >= 28 && salt[0] == '$' && salt[1] == '2' &&
      (salt[2] == 'a' || salt[2] == 'b' || salt[2] == 'y') && salt[3] == '$')
  {
    result = crypt(key, salt);
  }
  else
  {
    /* Generate a new bcrypt salt */
    if (generate_bcrypt_salt(newsalt, BCRYPT_DEFAULT_COST) == NULL)
    {
      Debug((DEBUG_DEBUG, "ircd_crypt_bcrypt: failed to generate salt"));
      return NULL;
    }
    Debug((DEBUG_DEBUG, "ircd_crypt_bcrypt: generated salt = %s", newsalt));
    result = crypt(key, newsalt);
  }

  if (result == NULL)
  {
    Debug((DEBUG_DEBUG, "ircd_crypt_bcrypt: crypt() returned NULL"));
    return NULL;
  }

  /* Verify it's actually a bcrypt result (starts with $2) */
  if (result[0] != '$' || result[1] != '2')
  {
    Debug((DEBUG_DEBUG, "ircd_crypt_bcrypt: crypt() did not return bcrypt hash"));
    return NULL;
  }

  Debug((DEBUG_DEBUG, "ircd_crypt_bcrypt: result = %s", result));
  return result;
}

/** Register the bcrypt mechanism */
void ircd_register_crypt_bcrypt(void)
{
  crypt_mech_t* crypt_mech;

  if ((crypt_mech = (crypt_mech_t*)MyMalloc(sizeof(crypt_mech_t))) == NULL)
  {
    Debug((DEBUG_MALLOC, "Could not allocate space for crypt_bcrypt"));
    return;
  }

  crypt_mech->mechname = "bcrypt";
  crypt_mech->shortname = "crypt_bcrypt";
  crypt_mech->description = "Bcrypt password hash ($2y$).";
  crypt_mech->crypt_function = &ircd_crypt_bcrypt;
  /* Note: We use an empty token because bcrypt hashes are detected
   * directly by their $2y$ prefix in ircd_crypt(), not via the
   * normal token mechanism. This registration is primarily for
   * umkpasswd to generate bcrypt passwords. */
  crypt_mech->crypt_token = "";
  crypt_mech->crypt_token_size = 0;

  ircd_crypt_register_mech(crypt_mech);
}
