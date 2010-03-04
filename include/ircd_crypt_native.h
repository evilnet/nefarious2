/** @file
 * @brief Native crypt() function declarations.
 * @version $Id: ircd_crypt_native.h 1231 2004-10-05 04:21:37Z entrope $
 */
#ifndef INCLUDED_ircd_crypt_native_h
#define INCLUDED_ircd_crypt_native_h

extern const char* ircd_crypt_native(const char* key, const char* salt);
extern void ircd_register_crypt_native(void);

#endif /* INCLUDED_ircd_crypt_native_h */

