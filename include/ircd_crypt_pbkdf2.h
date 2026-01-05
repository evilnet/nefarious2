/*
 * IRC - Internet Relay Chat, include/ircd_crypt_pbkdf2.h
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
 * @brief PBKDF2 password hashing APIs (SHA256 and SHA512).
 */
#ifndef INCLUDED_ircd_crypt_pbkdf2_h
#define INCLUDED_ircd_crypt_pbkdf2_h

/* PBKDF2-SHA256 ($PBKDF2$) */
extern void ircd_register_crypt_pbkdf2(void);
extern const char* ircd_crypt_pbkdf2(const char* key, const char* salt);

/* PBKDF2-SHA512 ($PBKDF2-SHA512$) */
extern void ircd_register_crypt_pbkdf2_sha512(void);
extern const char* ircd_crypt_pbkdf2_sha512(const char* key, const char* salt);

#endif /* INCLUDED_ircd_crypt_pbkdf2_h */
