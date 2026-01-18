/*
 * ircd_compress_cmocka.c - CMocka unit tests for zstd compression utilities
 *
 * Tests the compression/decompression functions used for LMDB-backed storage
 * (chathistory, metadata). These functions provide transparent compression
 * with a configurable threshold.
 *
 * Copyright (C) 2024 AfterNET Development Team
 */

#include "config.h"

#ifdef USE_ZSTD

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>
#include <cmocka.h>

#include "ircd_compress.h"

/* Test buffer sizes */
#define TEST_BUF_SIZE 4096


/* ========== is_compressed() tests ========== */

static void test_is_compressed_with_magic(void **state)
{
    (void)state;
    unsigned char data[] = { COMPRESS_MAGIC, 0x28, 0xB5, 0x2F, 0xFD };

    /* Data starting with magic byte should be detected as compressed */
    assert_true(is_compressed(data, sizeof(data)));
}

static void test_is_compressed_without_magic(void **state)
{
    (void)state;
    unsigned char data[] = { 'H', 'e', 'l', 'l', 'o' };

    /* Normal data without magic byte should not be detected as compressed */
    assert_false(is_compressed(data, sizeof(data)));
}

static void test_is_compressed_empty(void **state)
{
    (void)state;
    unsigned char data[] = { 0 };

    /* Empty or single-byte data should not be detected as compressed */
    assert_false(is_compressed(data, 0));
    assert_false(is_compressed(data, 1));
}

static void test_is_compressed_magic_only(void **state)
{
    (void)state;
    unsigned char data[] = { COMPRESS_MAGIC };

    /* Single magic byte alone - len must be > 1 */
    assert_false(is_compressed(data, 1));
}


/* ========== compress_data() tests ========== */

static void test_compress_below_threshold(void **state)
{
    (void)state;
    unsigned char input[] = "Short string";
    unsigned char output[TEST_BUF_SIZE];
    size_t output_len;
    int result;

    /* Ensure threshold is at default (256 bytes) */
    compress_set_threshold(COMPRESS_THRESHOLD_DEFAULT);

    /* Data below threshold should pass through unchanged */
    result = compress_data(input, sizeof(input) - 1, output, TEST_BUF_SIZE, &output_len);

    assert_int_equal(result, 0);  /* 0 = passed through unchanged */
    assert_int_equal(output_len, sizeof(input) - 1);
    assert_memory_equal(output, input, output_len);
}

static void test_compress_above_threshold(void **state)
{
    (void)state;
    unsigned char input[512];
    unsigned char output[TEST_BUF_SIZE];
    size_t output_len;
    int result;

    /* Create compressible data (repeated pattern compresses well) */
    memset(input, 'A', sizeof(input));

    compress_set_threshold(COMPRESS_THRESHOLD_DEFAULT);

    result = compress_data(input, sizeof(input), output, TEST_BUF_SIZE, &output_len);

    /* Should be compressed (repeated data compresses very well) */
    assert_int_equal(result, 1);  /* 1 = compressed */
    assert_true(output_len < sizeof(input));  /* Should be smaller */
    assert_int_equal(output[0], COMPRESS_MAGIC);  /* Magic byte present */
}

static void test_compress_at_threshold(void **state)
{
    (void)state;
    unsigned char input[COMPRESS_THRESHOLD_DEFAULT];
    unsigned char output[TEST_BUF_SIZE];
    size_t output_len;
    int result;

    /* Exactly at threshold with compressible data */
    memset(input, 'B', sizeof(input));

    compress_set_threshold(COMPRESS_THRESHOLD_DEFAULT);

    result = compress_data(input, sizeof(input), output, TEST_BUF_SIZE, &output_len);

    /* At threshold, should attempt compression */
    /* Result depends on whether compression saves space */
    assert_true(result == 0 || result == 1);
}

static void test_compress_incompressible(void **state)
{
    (void)state;
    unsigned char input[512];
    unsigned char output[TEST_BUF_SIZE];
    size_t output_len;
    int result;

    /* Create random-ish data that doesn't compress well */
    for (size_t i = 0; i < sizeof(input); i++) {
        input[i] = (unsigned char)(i * 17 + 31);  /* Pseudo-random pattern */
    }

    compress_set_threshold(COMPRESS_THRESHOLD_DEFAULT);

    result = compress_data(input, sizeof(input), output, TEST_BUF_SIZE, &output_len);

    /* If compression doesn't save space, should pass through unchanged */
    /* Either compressed (1) or passed through (0), never error (-1) for valid input */
    assert_true(result >= 0);
}

static void test_compress_output_too_small(void **state)
{
    (void)state;
    unsigned char input[] = "Test data";
    unsigned char output[2];  /* Too small */
    size_t output_len;
    int result;

    compress_set_threshold(1);  /* Force compression attempt */

    result = compress_data(input, sizeof(input), output, sizeof(output), &output_len);

    /* Should fail with -1 when output buffer too small */
    assert_int_equal(result, -1);
}


/* ========== decompress_data() tests ========== */

static void test_decompress_uncompressed(void **state)
{
    (void)state;
    unsigned char input[] = "Not compressed data";
    unsigned char output[TEST_BUF_SIZE];
    size_t output_len;
    int result;

    /* Data without magic byte should pass through unchanged */
    result = decompress_data(input, sizeof(input) - 1, output, TEST_BUF_SIZE, &output_len);

    assert_int_equal(result, 0);  /* 0 = passed through unchanged */
    assert_int_equal(output_len, sizeof(input) - 1);
    assert_memory_equal(output, input, output_len);
}

static void test_decompress_compressed(void **state)
{
    (void)state;
    unsigned char original[512];
    unsigned char compressed[TEST_BUF_SIZE];
    unsigned char decompressed[TEST_BUF_SIZE];
    size_t compressed_len, decompressed_len;
    int result;

    /* Create and compress data */
    memset(original, 'C', sizeof(original));

    compress_set_threshold(COMPRESS_THRESHOLD_DEFAULT);
    result = compress_data(original, sizeof(original), compressed, TEST_BUF_SIZE, &compressed_len);
    assert_int_equal(result, 1);  /* Should compress */

    /* Now decompress */
    result = decompress_data(compressed, compressed_len, decompressed, TEST_BUF_SIZE, &decompressed_len);

    assert_int_equal(result, 1);  /* 1 = decompressed */
    assert_int_equal(decompressed_len, sizeof(original));
    assert_memory_equal(decompressed, original, sizeof(original));
}


/* ========== Round-trip tests ========== */

static void test_roundtrip_compressible(void **state)
{
    (void)state;
    unsigned char original[1024];
    unsigned char compressed[TEST_BUF_SIZE];
    unsigned char decompressed[TEST_BUF_SIZE];
    size_t compressed_len, decompressed_len;
    int comp_result, decomp_result;

    /* Create compressible data */
    for (size_t i = 0; i < sizeof(original); i++) {
        original[i] = (unsigned char)(i % 10 + 'A');
    }

    compress_set_threshold(COMPRESS_THRESHOLD_DEFAULT);

    /* Compress */
    comp_result = compress_data(original, sizeof(original), compressed, TEST_BUF_SIZE, &compressed_len);
    assert_true(comp_result >= 0);

    /* Decompress */
    decomp_result = decompress_data(compressed, compressed_len, decompressed, TEST_BUF_SIZE, &decompressed_len);
    assert_true(decomp_result >= 0);

    /* Verify round-trip */
    assert_int_equal(decompressed_len, sizeof(original));
    assert_memory_equal(decompressed, original, sizeof(original));
}

static void test_roundtrip_small_data(void **state)
{
    (void)state;
    unsigned char original[] = "Small data that won't be compressed";
    unsigned char intermediate[TEST_BUF_SIZE];
    unsigned char final[TEST_BUF_SIZE];
    size_t intermediate_len, final_len;

    compress_set_threshold(COMPRESS_THRESHOLD_DEFAULT);

    /* Compress (should pass through) */
    compress_data(original, sizeof(original) - 1, intermediate, TEST_BUF_SIZE, &intermediate_len);

    /* Decompress (should also pass through) */
    decompress_data(intermediate, intermediate_len, final, TEST_BUF_SIZE, &final_len);

    /* Verify round-trip */
    assert_int_equal(final_len, sizeof(original) - 1);
    assert_memory_equal(final, original, final_len);
}


/* ========== Accessor tests ========== */

static void test_threshold_accessors(void **state)
{
    (void)state;
    size_t original_threshold;

    /* Save original */
    original_threshold = compress_get_threshold();

    /* Set new value */
    compress_set_threshold(512);
    assert_int_equal(compress_get_threshold(), 512);

    /* Set another value */
    compress_set_threshold(1024);
    assert_int_equal(compress_get_threshold(), 1024);

    /* Restore original */
    compress_set_threshold(original_threshold);
    assert_int_equal(compress_get_threshold(), original_threshold);
}

static void test_level_accessors(void **state)
{
    (void)state;
    int original_level;

    /* Save original */
    original_level = compress_get_level();

    /* Set valid levels */
    compress_set_level(1);
    assert_int_equal(compress_get_level(), 1);

    compress_set_level(10);
    assert_int_equal(compress_get_level(), 10);

    /* Invalid levels should be ignored */
    compress_set_level(0);  /* Too low */
    assert_int_equal(compress_get_level(), 10);  /* Should remain 10 */

    compress_set_level(-1);  /* Negative */
    assert_int_equal(compress_get_level(), 10);  /* Should remain 10 */

    /* Restore original */
    compress_set_level(original_level);
}


int main(void)
{
    const struct CMUnitTest tests[] = {
        /* is_compressed */
        cmocka_unit_test(test_is_compressed_with_magic),
        cmocka_unit_test(test_is_compressed_without_magic),
        cmocka_unit_test(test_is_compressed_empty),
        cmocka_unit_test(test_is_compressed_magic_only),

        /* compress_data */
        cmocka_unit_test(test_compress_below_threshold),
        cmocka_unit_test(test_compress_above_threshold),
        cmocka_unit_test(test_compress_at_threshold),
        cmocka_unit_test(test_compress_incompressible),
        cmocka_unit_test(test_compress_output_too_small),

        /* decompress_data */
        cmocka_unit_test(test_decompress_uncompressed),
        cmocka_unit_test(test_decompress_compressed),

        /* Round-trip */
        cmocka_unit_test(test_roundtrip_compressible),
        cmocka_unit_test(test_roundtrip_small_data),

        /* Accessors */
        cmocka_unit_test(test_threshold_accessors),
        cmocka_unit_test(test_level_accessors),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

#else /* !USE_ZSTD */

/* Stub main when zstd is not available */
#include <stdio.h>

int main(void)
{
    printf("ircd_compress tests skipped: USE_ZSTD not defined\n");
    return 0;
}

#endif /* USE_ZSTD */
