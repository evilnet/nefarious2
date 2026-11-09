/*
 * IRC - Internet Relay Chat, ircd/ircd_crypt.c
 * Copyright (C) 2002 hikari
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
 */

/**
 * @file
 * @brief Core password encryption routines.
 * @version $Id: ircd_crypt.c 1435 2005-06-24 13:57:21Z a1kmm $
 * 
 * This is a new look crypto API for ircu, it can handle different
 * password formats by the grace of magic tokens at the beginning of the 
 * password e.g. $SMD5 for Salted MD5, $CRYPT for native crypt(), etc.
 *
 * Currently crypt routines are implemented for: the native crypt() 
 * function, Salted MD5 and a plain text mechanism which should only
 * be used for testing.  I intend to add Blowfish, 3DES and possibly
 * SHA1 support as well at some point, but I'll need to check the
 * possible problems that'll cause with stupid crypto laws.
 *
 * It's also designed to be "ready" for the modularisation of ircu, so 
 * someone get round to doing it, because I'm not doing it ;)
 * 
 * The plan for Stage B is to semi-modularise the authentication
 * mechanism to allow authentication against some other sources than 
 * the conf file (whatever takes someones fancy, kerberos, ldap, sql, etc).
 *
 *                   -- blessed be, hikari.
 */

#include "config.h"
#include "ircd_crypt.h"
#include "ircd_alloc.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_string.h"
#include "s_debug.h"

/* while we're not modular, we need their init functions */
#include "ircd_crypt_native.h"
#include "ircd_crypt_plain.h"
#include "ircd_crypt_smd5.h"
#include "ircd_crypt_bcrypt.h"
#include "ircd_crypt_pbkdf2.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <unistd.h>
#include <string.h>
#include <openssl/crypto.h>
#ifdef HAVE_PTHREAD
#include <pthread.h>
#endif

/* evil global */
crypt_mechs_t* crypt_mechs_root;

#ifdef HAVE_PTHREAD
/* The crypt lock serializes every use of the crypt mechanisms.  Each one
 * returns a static buffer -- crypt(3)'s own (native, bcrypt), smd5's,
 * pbkdf2's -- and the async checks run on several thread pool workers while
 * the main thread hashes too, so without it two checks read each other's
 * result (a wrong password checked beside a right one against the same
 * stored hash could match) and ircd_crypt()'s heap copy could overrun its
 * block when the buffer grew under it.
 *
 * The main thread goes first.  A plain mutex lets the worker that releases
 * it take it straight back for the next queued check, so a main-thread
 * check (MKPASSWD, a remote OPER, DIE, RESTART, a fallback when the queue
 * is full) waited for the whole queue -- up to THREAD_POOL_MAX_PENDING
 * hashes, tens of seconds of a stalled main loop.  Here a worker does not
 * take the lock while a main-thread caller waits for it, so that caller
 * waits for the one hash running at most.
 *
 * Statically initialized: usable before ircd_crypt_init() and in a process
 * that never starts the thread pool. */
static pthread_mutex_t crypt_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t crypt_cond = PTHREAD_COND_INITIALIZER;
static int crypt_busy;          /**< someone holds the crypt lock */
static int crypt_main_waiting;  /**< main-thread callers waiting for it */

/** Take the crypt lock.
 * @param[in] worker Nonzero for a thread pool worker, which yields to every
 * main-thread caller waiting; zero for the main thread. */
static void crypt_acquire(int worker)
{
  pthread_mutex_lock(&crypt_mutex);
  if (!worker)
    crypt_main_waiting++;
  while (crypt_busy || (worker && crypt_main_waiting))
    pthread_cond_wait(&crypt_cond, &crypt_mutex);
  if (!worker)
    crypt_main_waiting--;
  crypt_busy = 1;
  pthread_mutex_unlock(&crypt_mutex);
}

/** Release the crypt lock and wake everyone waiting for it: a waiting
 * main-thread caller takes it, and the workers check again. */
static void crypt_release(void)
{
  pthread_mutex_lock(&crypt_mutex);
  crypt_busy = 0;
  pthread_cond_broadcast(&crypt_cond);
  pthread_mutex_unlock(&crypt_mutex);
}
#else
/* Without pthreads there is no thread pool and nothing runs at once. */
#define crypt_acquire(worker) ((void)0)
#define crypt_release() ((void)0)
#endif

/** Take the lock every caller of a crypt mechanism holds from the call
 * until it has copied the result out of the mechanism's static buffer,
 * with the main thread's priority.  ircd_crypt() takes it itself; a caller
 * that runs a mechanism directly (m_mkpasswd) takes it around the call and
 * the copy.  Not recursive: never call ircd_crypt() while holding it. */
void ircd_crypt_lock(void)
{
  crypt_acquire(0);
}

/** Release the lock ircd_crypt_lock() took. */
void ircd_crypt_unlock(void)
{
  crypt_release();
}

/** Add a crypt mechanism to the list 
 * @param mechanism Pointer to the mechanism details struct
 * @return 0 on success, anything else on fail.
 * 
 * This routine registers a new crypt mechanism in the loaded mechanisms list, 
 * making it availabe for comparing passwords.
*/
int ircd_crypt_register_mech(crypt_mech_t* mechanism)
{
crypt_mechs_t* crypt_mech;

 Debug((DEBUG_INFO, "ircd_crypt_register_mech: registering mechanism: %s", mechanism->shortname));

 /* try to allocate some memory for the new mechanism */
 if ((crypt_mech = (crypt_mechs_t*)MyMalloc(sizeof(crypt_mechs_t))) == NULL)
 {
  /* aww poot, we couldn't get any memory, scream a little then back out */
  Debug((DEBUG_MALLOC, "ircd_crypt_register_mech: could not allocate memory for %s", mechanism->shortname));
  return -1;
 }

 /* ok, we have memory, initialise it */
 memset(crypt_mech, 0, sizeof(crypt_mechs_t));

 /* assign the data */
 crypt_mech->mech = mechanism;
 crypt_mech->next = crypt_mech->prev = NULL;

 /* first of all, is there anything there already? */
 if(crypt_mechs_root->next == NULL)
 {
  /* nope, just add ourself */
  crypt_mechs_root->next = crypt_mechs_root->prev = crypt_mech;
 } else {
  /* nice and simple, put ourself at the end */
  crypt_mech->prev = crypt_mechs_root->prev;
  crypt_mech->next = NULL;
  crypt_mechs_root->prev = crypt_mech->prev->next = crypt_mech;
 }
  
 /* we're done */
 Debug((DEBUG_INFO, "ircd_crypt_register_mech: registered mechanism: %s, crypt_function is at 0x%X.", crypt_mech->mech->shortname, &crypt_mech->mech->crypt_function));
 Debug((DEBUG_INFO, "ircd_crypt_register_mech: %s: %s", crypt_mech->mech->shortname, crypt_mech->mech->description));
 return 0;
}

/** Remove a crypt mechanism from the list 
 * @param mechanism Pointer to the mechanism we want to remove
 * @return 0 on success, anything else on fail.
*/
int ircd_crypt_unregister_mech(crypt_mech_t* mechanism)
{

return 0;
}

/** ircd_crypt()'s body, run with the crypt lock held: it calls the
 * mechanisms and copies their static result to the heap. */
static char* crypt_locked(const char* key, const char* salt)
{
char *hashed_pass = NULL;
const char *temp_hashed_pass, *mysalt;
crypt_mechs_t* crypt_mech;

 assert(NULL != key);
 assert(NULL != salt);

 Debug((DEBUG_DEBUG, "ircd_crypt: key is %s", key));
 Debug((DEBUG_DEBUG, "ircd_crypt: salt is %s", salt));

 crypt_mech = crypt_mechs_root->next;

 /* by examining the first n characters of a password string we
  * can discover what kind of password it is.  hopefully. */
 for (;crypt_mech;)
 {
  if (strlen(salt) < crypt_mech->mech->crypt_token_size)
  {
   /* try the next mechanism instead */
   Debug((DEBUG_DEBUG, "ircd_crypt: salt is too short, will try next mech at 0x%X", crypt_mech->next));
   crypt_mech = crypt_mech->next;
   continue;
  }

  Debug((DEBUG_DEBUG, "ircd_crypt: comparing %s with %s", 
   salt, crypt_mech->mech->crypt_token));

  if(0 == ircd_strncmp(crypt_mech->mech->crypt_token, salt, crypt_mech->mech->crypt_token_size))
  {
   Debug((DEBUG_DEBUG, "ircd_crypt: type is %s", 
    crypt_mech->mech->shortname));

   /* before we send this all off to the crypt_function, we need to remove
      the tag from it */

   /* make sure we won't end up with a password comprised entirely of 
      a single \0 */
   if(strlen(salt) < crypt_mech->mech->crypt_token_size + 1)
    return NULL;

   mysalt = salt + crypt_mech->mech->crypt_token_size;

   if(NULL == (temp_hashed_pass = crypt_mech->mech->crypt_function(key, mysalt)))
    return NULL;

   Debug((DEBUG_DEBUG, "ircd_crypt: untagged pass is %s", temp_hashed_pass));

   /* ok, now we need to prefix the password we just got back
      with the right tag */
   if(NULL == (hashed_pass = (char *)MyMalloc(sizeof(char)*strlen(temp_hashed_pass) + crypt_mech->mech->crypt_token_size + 1)))
   {
    Debug((DEBUG_MALLOC, "ircd_crypt: unable to allocate memory for temp_hashed_pass"));
    return NULL;
   }
   memset(hashed_pass, 0, sizeof(char)*strlen(temp_hashed_pass)
    +crypt_mech->mech->crypt_token_size + 1);
   ircd_strncpy(hashed_pass, crypt_mech->mech->crypt_token,
    crypt_mech->mech->crypt_token_size + 1);
   ircd_strncpy(hashed_pass + crypt_mech->mech->crypt_token_size, temp_hashed_pass, strlen(temp_hashed_pass) + 1);
   Debug((DEBUG_DEBUG, "ircd_crypt: tagged pass is %s", hashed_pass));
  } else {
   Debug((DEBUG_DEBUG, "ircd_crypt: will try next mechanism at 0x%X", 
    crypt_mech->next));
   crypt_mech = crypt_mech->next;
   continue;
  }
  return hashed_pass;
 }

 /* try bcrypt ($2a$, $2b$, $2x$, $2y$) - pass directly to system crypt */
 if (strlen(salt) > 4 && salt[0] == '$' && salt[1] == '2' &&
     (salt[2] == 'a' || salt[2] == 'b' || salt[2] == 'x' || salt[2] == 'y') && salt[3] == '$')
 {
   char *s;
   Debug((DEBUG_DEBUG, "ircd_crypt: detected bcrypt hash"));
   if (NULL == (temp_hashed_pass = (char*)ircd_crypt_native(key, salt)))
     return NULL;
   if (!ircd_strcmp(temp_hashed_pass, salt))
   {
     DupString(s, temp_hashed_pass);
     return s;
   }
 }

 /* try to use native crypt for an old-style (untagged) password */
 if (strlen(salt) > 2)
 {
   char *s;
   if (NULL == (temp_hashed_pass = (char*)ircd_crypt_native(key, salt)))
     return NULL;
   if (!ircd_strcmp(temp_hashed_pass, salt))
   {
     DupString(s, temp_hashed_pass);
     return s;
   }
 }

 return NULL;
}

/** Wrapper for generating a hashed password passed on the supplied password
 * @param key Pointer to the password we want crypted
 * @param salt Pointer to the password we're comparing to (for the salt)
 * @return Pointer to the generated password (must be MyFree()'d).
 *
 * This is a wrapper function which attempts to establish the password
 * format and funnel it off to the correct mechanism handler function.  The
 * returned password is compared in the oper_password_match() routine.
 *
 * For the main thread: it holds the crypt lock, with the main thread's
 * priority, from the mechanism call through the heap copy, so the result
 * is this call's own.  A thread pool worker calls ircd_crypt_worker().
*/
char* ircd_crypt(const char* key, const char* salt)
{
 char *hashed_pass;

 crypt_acquire(0);
 hashed_pass = crypt_locked(key, salt);
 crypt_release();
 return hashed_pass;
}

/** ircd_crypt() for a thread pool worker: the same result, under the same
 * lock held through the heap copy, but it waits while a main-thread caller
 * waits, so the main loop never queues behind the workers' backlog.
 * @param key Pointer to the password we want crypted
 * @param salt Pointer to the password we're comparing to (for the salt)
 * @return Pointer to the generated password (must be MyFree()'d).
 */
char* ircd_crypt_worker(const char* key, const char* salt)
{
 char *hashed_pass;

 crypt_acquire(1);
 hashed_pass = crypt_locked(key, salt);
 crypt_release();
 return hashed_pass;
}

/** Some basic init.
 * This function loads initalises the crypt mechanisms linked list and 
 * currently loads the default mechanisms (Salted MD5, Crypt() and PLAIN).  
 * The last step is only needed while ircu is not properly modular.
 *  
 * When ircu is modular this will be the entry function for the ircd_crypt
 * module.
 * 
*/
void ircd_crypt_init(void)
{

 if((crypt_mechs_root = MyMalloc(sizeof(crypt_mechs_t))) == NULL)
 {
  /* awooga - can't allocate memory for the root structure */
  Debug((DEBUG_MALLOC, "init_crypt: Could not allocate memory for crypt_mechs_root"));
  return;
 }

 crypt_mechs_root->mech = NULL;
 crypt_mechs_root->next = crypt_mechs_root->prev = NULL;

/* temporary kludge until we're modular.  manually call the
   register functions for crypt mechanisms */
 ircd_register_crypt_smd5();
 ircd_register_crypt_plain();
 ircd_register_crypt_native();
 ircd_register_crypt_bcrypt();
 ircd_register_crypt_pbkdf2();
 ircd_register_crypt_pbkdf2_sha512();

return;
}

int oper_password_match(const char* to_match, const char* passwd)
{
  char *crypted;
  int res;
  size_t crypted_len, passwd_len, cmp_len;
  /*
   * use first two chars of the password they send in as salt
   *
   * passwd may be NULL. Head it off at the pass...
   */
  if (!to_match || !passwd)
    return 0;

  /* we no longer do a CRYPT_OPER_PASSWORD check because a clear
     text passwords just handled by a fallback mechanism called
     crypt_clear if it's enabled -- hikari */
  crypted = ircd_crypt(to_match, passwd);

  if (!crypted)
   return 0;

  /* Use constant-time comparison to prevent timing attacks.
   * Always perform comparison to avoid leaking length info. */
  crypted_len = strlen(crypted);
  passwd_len = strlen(passwd);
  cmp_len = (crypted_len < passwd_len) ? crypted_len : passwd_len;
  res = CRYPTO_memcmp(crypted, passwd, cmp_len);
  /* Lengths must also match - XOR is non-zero if different */
  res |= (crypted_len ^ passwd_len);

  MyFree(crypted);
  return 0 == res;
}
