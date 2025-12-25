/*
 * IRC - Internet Relay Chat, include/ircd_compress.h
 * Copyright (C) 2024 AfterNET Development Team
 *
 * Zstandard compression support for LMDB-backed storage.
 * Provides transparent compression for chathistory and metadata.
 */
#ifndef INCLUDED_ircd_compress_h
#define INCLUDED_ircd_compress_h

#include <stddef.h>

#ifdef USE_ZSTD

/** Magic byte to identify compressed data */
#define COMPRESS_MAGIC 0x1F

/** Default compression threshold in bytes */
#define COMPRESS_THRESHOLD_DEFAULT 256

/** Default compression level (1-22, 3 is fast with good ratio) */
#define COMPRESS_LEVEL_DEFAULT 3

/** Maximum uncompressed size we'll accept (safety limit) */
#define COMPRESS_MAX_UNCOMPRESSED 65536

/**
 * Initialize compression subsystem.
 * @param[in] threshold Minimum size to trigger compression (0 = use default)
 * @param[in] level Compression level 1-22 (0 = use default)
 */
void compress_init(size_t threshold, int level);

/**
 * Check if data appears to be compressed.
 * @param[in] data Data buffer
 * @param[in] len Data length
 * @return 1 if compressed, 0 if not
 */
int is_compressed(const unsigned char *data, size_t len);

/**
 * Compress data if it exceeds the threshold.
 * @param[in] input Input data
 * @param[in] input_len Input length
 * @param[out] output Output buffer
 * @param[in] output_size Size of output buffer
 * @param[out] output_len Actual output length
 * @return 1 if compressed, 0 if passed through unchanged, -1 on error
 */
int compress_data(const unsigned char *input, size_t input_len,
                  unsigned char *output, size_t output_size, size_t *output_len);

/**
 * Decompress data if it has compression magic byte.
 * @param[in] input Input data (possibly compressed)
 * @param[in] input_len Input length
 * @param[out] output Output buffer
 * @param[in] output_size Size of output buffer
 * @param[out] output_len Actual output length
 * @return 1 if decompressed, 0 if passed through unchanged, -1 on error
 */
int decompress_data(const unsigned char *input, size_t input_len,
                    unsigned char *output, size_t output_size, size_t *output_len);

/**
 * Get current compression threshold.
 * @return Current threshold in bytes
 */
size_t compress_get_threshold(void);

/**
 * Set compression threshold.
 * @param[in] threshold New threshold in bytes
 */
void compress_set_threshold(size_t threshold);

/**
 * Get current compression level.
 * @return Current compression level (1-22)
 */
int compress_get_level(void);

/**
 * Set compression level.
 * @param[in] level New compression level (1-22)
 */
void compress_set_level(int level);

#else /* !USE_ZSTD */

/* Stub macros when zstd is not available */
#define compress_init(t, l)                     do {} while(0)
#define is_compressed(d, l)                     (0)
#define compress_data(i, il, o, os, ol)         (*(ol) = (il), memcpy((o), (i), (il)), 0)
#define decompress_data(i, il, o, os, ol)       (*(ol) = (il), memcpy((o), (i), (il)), 0)
#define compress_get_threshold()                (0)
#define compress_set_threshold(t)               do {} while(0)
#define compress_get_level()                    (0)
#define compress_set_level(l)                   do {} while(0)

#endif /* USE_ZSTD */

#endif /* INCLUDED_ircd_compress_h */
