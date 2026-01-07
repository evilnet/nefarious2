/*
 * IRC - Internet Relay Chat, ircd/ircd_crypt_async.c
 * Copyright (C) 2025 AfterNET Development Team
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

/**
 * @file
 * @brief Async password verification wrapper.
 *
 * Provides non-blocking password verification by offloading CPU-intensive
 * bcrypt/PBKDF2 hashing to the thread pool. This prevents the main event
 * loop from blocking during SASL authentication or OPER commands.
 */

#include "config.h"
#include "ircd_crypt.h"
#include "thread_pool.h"
#include "ircd_alloc.h"
#include "ircd_string.h"
#include "s_debug.h"

#include <string.h>

/** Context for async password verification */
struct crypt_verify_ctx {
  char *password;               /**< Copy of plaintext password */
  char *hash;                   /**< Copy of stored hash */
  crypt_verify_callback callback; /**< User callback */
  void *user_ctx;               /**< User context */
};

/**
 * Work function - runs in thread pool worker.
 * This is the CPU-intensive part that we're offloading.
 */
static void *crypt_verify_work(void *arg)
{
  struct crypt_verify_ctx *ctx = arg;
  int *result;
  const char *computed;

  result = (int *)MyMalloc(sizeof(int));
  if (!result) {
    *result = CRYPT_VERIFY_ERROR;
    return result;
  }

  /* Call the blocking crypt function - this is the slow part */
  computed = ircd_crypt(ctx->password, ctx->hash);

  if (!computed) {
    *result = CRYPT_VERIFY_ERROR;
  } else if (strcmp(computed, ctx->hash) == 0) {
    *result = CRYPT_VERIFY_MATCH;
  } else {
    *result = CRYPT_VERIFY_NOMATCH;
  }

  Debug((DEBUG_DEBUG, "crypt_verify_work: result=%d for hash prefix %.8s...",
         *result, ctx->hash));

  return result;
}

/**
 * Completion callback - runs in main thread via thread_pool_poll().
 * Invokes the user's callback with the verification result.
 */
static void crypt_verify_done(void *result, void *arg)
{
  struct crypt_verify_ctx *ctx = arg;
  int *presult = result;
  int final_result;

  if (presult) {
    final_result = *presult;
    MyFree(presult);
  } else {
    /* NULL result indicates cancellation or error */
    final_result = CRYPT_VERIFY_ERROR;
  }

  /* Invoke user callback */
  if (ctx->callback) {
    ctx->callback(final_result, ctx->user_ctx);
  }

  /* Clean up context */
  MyFree(ctx->password);
  MyFree(ctx->hash);
  MyFree(ctx);
}

/**
 * Asynchronously verify a password against a hash.
 */
int ircd_crypt_verify_async(const char *password, const char *hash,
                            crypt_verify_callback callback, void *ctx)
{
  struct crypt_verify_ctx *vctx;

  /* Check if thread pool is available */
  if (!thread_pool_is_running()) {
    Debug((DEBUG_DEBUG, "ircd_crypt_verify_async: thread pool not running, "
           "falling back to sync"));
    return -1;
  }

  if (!password || !hash || !callback) {
    Debug((DEBUG_ERROR, "ircd_crypt_verify_async: invalid parameters"));
    return -1;
  }

  /* Allocate verification context */
  vctx = (struct crypt_verify_ctx *)MyMalloc(sizeof(struct crypt_verify_ctx));
  if (!vctx) {
    return -1;
  }

  /* Copy strings - they may be freed before the async operation completes */
  DupString(vctx->password, password);
  DupString(vctx->hash, hash);
  vctx->callback = callback;
  vctx->user_ctx = ctx;

  /* Submit to thread pool */
  if (thread_pool_submit(crypt_verify_work, vctx, crypt_verify_done, vctx) < 0) {
    Debug((DEBUG_ERROR, "ircd_crypt_verify_async: thread_pool_submit failed"));
    MyFree(vctx->password);
    MyFree(vctx->hash);
    MyFree(vctx);
    return -1;
  }

  Debug((DEBUG_DEBUG, "ircd_crypt_verify_async: submitted verification for "
         "hash prefix %.8s...", hash));
  return 0;
}

/**
 * Check if async password verification is available.
 */
int ircd_crypt_async_available(void)
{
  return thread_pool_is_running();
}
