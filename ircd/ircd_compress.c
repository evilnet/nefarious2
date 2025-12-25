/*
 * IRC - Internet Relay Chat, ircd/ircd_compress.c
 * Copyright (C) 2024 AfterNET Development Team
 *
 * Zstandard compression support for LMDB-backed storage.
 * Provides transparent compression for chathistory and metadata.
 */
#include "config.h"

#ifdef USE_ZSTD

#include "ircd_compress.h"
#include "ircd_log.h"
#include "ircd_snprintf.h"
#include "s_debug.h"
#include <zstd.h>
#include <string.h>

/** Current compression threshold */
static size_t compression_threshold = COMPRESS_THRESHOLD_DEFAULT;

/** Current compression level */
static int compression_level = COMPRESS_LEVEL_DEFAULT;

/** Initialize compression subsystem */
void compress_init(size_t threshold, int level)
{
  if (threshold > 0)
    compression_threshold = threshold;
  if (level >= 1 && level <= ZSTD_maxCLevel())
    compression_level = level;

  Debug((DEBUG_INFO, "Compression initialized: threshold=%zu, level=%d",
         compression_threshold, compression_level));
}

/** Check if data appears to be compressed */
int is_compressed(const unsigned char *data, size_t len)
{
  return (len > 1 && data[0] == COMPRESS_MAGIC);
}

/** Compress data if it exceeds the threshold */
int compress_data(const unsigned char *input, size_t input_len,
                  unsigned char *output, size_t output_size, size_t *output_len)
{
  size_t compressed_size;

  /* Don't compress small values */
  if (input_len < compression_threshold) {
    if (input_len > output_size)
      return -1;
    memcpy(output, input, input_len);
    *output_len = input_len;
    return 0;
  }

  /* Need room for magic byte + compressed data */
  if (output_size < 2)
    return -1;

  /* Compress with zstd */
  compressed_size = ZSTD_compress(output + 1, output_size - 1,
                                   input, input_len, compression_level);

  if (ZSTD_isError(compressed_size)) {
    log_write(LS_SYSTEM, L_WARNING, 0,
              "compress_data: zstd compression failed: %s",
              ZSTD_getErrorName(compressed_size));
    /* Fall back to uncompressed */
    if (input_len > output_size)
      return -1;
    memcpy(output, input, input_len);
    *output_len = input_len;
    return 0;
  }

  /* Only use compression if it actually saves space */
  if (compressed_size + 1 >= input_len) {
    if (input_len > output_size)
      return -1;
    memcpy(output, input, input_len);
    *output_len = input_len;
    return 0;
  }

  /* Add magic byte */
  output[0] = COMPRESS_MAGIC;
  *output_len = compressed_size + 1;
  return 1;
}

/** Decompress data if it has compression magic byte */
int decompress_data(const unsigned char *input, size_t input_len,
                    unsigned char *output, size_t output_size, size_t *output_len)
{
  size_t decompressed_size;

  /* Check for magic byte */
  if (!is_compressed(input, input_len)) {
    if (input_len > output_size) {
      log_write(LS_SYSTEM, L_ERROR, 0,
                "decompress_data: output buffer too small");
      return -1;
    }
    memcpy(output, input, input_len);
    *output_len = input_len;
    return 0;
  }

  /* Decompress (skip magic byte) */
  decompressed_size = ZSTD_decompress(output, output_size,
                                       input + 1, input_len - 1);

  if (ZSTD_isError(decompressed_size)) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "decompress_data: zstd decompression failed: %s",
              ZSTD_getErrorName(decompressed_size));
    return -1;
  }

  /* Safety check */
  if (decompressed_size > COMPRESS_MAX_UNCOMPRESSED) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "decompress_data: decompressed size too large: %zu",
              decompressed_size);
    return -1;
  }

  *output_len = decompressed_size;
  return 1;
}

/** Get current compression threshold */
size_t compress_get_threshold(void)
{
  return compression_threshold;
}

/** Set compression threshold */
void compress_set_threshold(size_t threshold)
{
  compression_threshold = threshold;
}

/** Get current compression level */
int compress_get_level(void)
{
  return compression_level;
}

/** Set compression level */
void compress_set_level(int level)
{
  if (level >= 1 && level <= ZSTD_maxCLevel())
    compression_level = level;
}

#endif /* USE_ZSTD */
