/*
 * dbuf_cmocka.c - CMocka unit tests for dynamic buffer functions
 *
 * Tests the DBuf data structure used for queuing data to be sent to clients.
 * DBuf provides a linked list of fixed-size buffers (2048 bytes each) with
 * efficient append and consume operations.
 *
 * Copyright (C) 2024 AfterNET Development Team
 */

#include "config.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>
#include <stdlib.h>
#include <cmocka.h>

/* Stubs for dependencies */

/* Stub for feature_int - return large buffer pool */
int feature_int(int feat) {
    (void)feat;
    return 10 * 1024 * 1024;  /* 10MB buffer pool */
}

/* Stub for feature_bool */
int feature_bool(int feat) {
    (void)feat;
    return 0;  /* Disable Ferguson flusher */
}

/* Stub for flush_connections */
void flush_connections(void *cptr) {
    (void)cptr;
}

/* Stub for MyMalloc - use real malloc */
void *MyMalloc(size_t size) {
    return malloc(size);
}

/* Stub for MyFree */
void MyFree(void *ptr) {
    free(ptr);
}

/* Now include the dbuf source */
#include "ircd_chattr.h"
#include "dbuf.h"

#include <stdio.h>

/* Need to define IRCD_MIN if not available */
#ifndef IRCD_MIN
#define IRCD_MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

/* Override assert macro for the inlined code */
#undef assert
#define assert(x) do { if (!(x)) { fprintf(stderr, "Assertion failed: %s\n", #x); abort(); } } while(0)

/* We need to manually include dbuf.c content to avoid linker issues */
/* The key definitions from dbuf.c: */

#define DBUF_SIZE 2048

struct DBufBuffer {
    struct DBufBuffer *next;
    char *start;
    char *end;
    char data[DBUF_SIZE];
};

/* Global counters */
int DBufAllocCount = 0;
int DBufUsedCount = 0;
static struct DBufBuffer *dbufFreeList = 0;

static struct DBufBuffer *dbuf_alloc(void)
{
    struct DBufBuffer* db = dbufFreeList;

    if (db) {
        dbufFreeList = db->next;
        ++DBufUsedCount;
    }
    else if (DBufAllocCount * DBUF_SIZE < feature_int(0)) {
        db = (struct DBufBuffer*) MyMalloc(sizeof(struct DBufBuffer));
        assert(0 != db);
        ++DBufAllocCount;
        ++DBufUsedCount;
    }
    return db;
}

static void dbuf_free(struct DBufBuffer *db)
{
    assert(0 != db);
    --DBufUsedCount;
    db->next = dbufFreeList;
    dbufFreeList = db;
}

static int dbuf_malloc_error(struct DBuf *dyn)
{
    struct DBufBuffer *db;
    struct DBufBuffer *next;

    for (db = dyn->head; db; db = next)
    {
        next = db->next;
        dbuf_free(db);
    }
    dyn->tail = dyn->head = 0;
    dyn->length = 0;
    return 0;
}

int dbuf_put(struct DBuf *dyn, const char *buf, unsigned int length)
{
    struct DBufBuffer** h;
    struct DBufBuffer*  db;
    unsigned int chunk;

    assert(0 != dyn);
    assert(0 != buf);

    if (!dyn->length)
        h = &(dyn->head);
    else
        h = &(dyn->tail);

    dyn->length += length;

    for (; length > 0; h = &(db->next)) {
        if (0 == (db = *h)) {
            if (0 == (db = dbuf_alloc())) {
                if (feature_bool(0)) {
                    flush_connections(0);
                    db = dbuf_alloc();
                }
                if (0 == db)
                    return dbuf_malloc_error(dyn);
            }
            dyn->tail = db;
            *h = db;
            db->next = 0;
            db->start = db->end = db->data;
        }
        chunk = (db->data + DBUF_SIZE) - db->end;
        if (chunk) {
            if (chunk > length)
                chunk = length;
            memcpy(db->end, buf, chunk);
            length -= chunk;
            buf += chunk;
            db->end += chunk;
        }
    }
    return 1;
}

const char *dbuf_map(const struct DBuf* dyn, unsigned int* length)
{
    assert(0 != dyn);
    assert(0 != length);

    if (0 == dyn->length)
    {
        *length = 0;
        return 0;
    }
    assert(0 != dyn->head);

    *length = dyn->head->end - dyn->head->start;
    return dyn->head->start;
}

void dbuf_delete(struct DBuf *dyn, unsigned int length)
{
    struct DBufBuffer *db;
    unsigned int chunk;

    if (length > dyn->length)
        length = dyn->length;

    while (length > 0)
    {
        if (0 == (db = dyn->head))
            break;
        chunk = db->end - db->start;
        if (chunk > length)
            chunk = length;

        length -= chunk;
        dyn->length -= chunk;
        db->start += chunk;

        if (db->start == db->end)
        {
            dyn->head = db->next;
            dbuf_free(db);
        }
    }
    if (0 == dyn->head)
    {
        dyn->length = 0;
        dyn->tail = 0;
    }
}

unsigned int dbuf_get(struct DBuf *dyn, char *buf, unsigned int length)
{
    unsigned int moved = 0;
    unsigned int chunk;
    const char *b;

    assert(0 != dyn);
    assert(0 != buf);

    while (length > 0 && (b = dbuf_map(dyn, &chunk)) != 0)
    {
        if (chunk > length)
            chunk = length;

        memcpy(buf, b, chunk);
        dbuf_delete(dyn, chunk);

        buf += chunk;
        length -= chunk;
        moved += chunk;
    }
    return moved;
}

static unsigned int dbuf_flush(struct DBuf *dyn)
{
    struct DBufBuffer *db = dyn->head;

    if (0 == db)
        return 0;

    assert(db->start < db->end);

    while (IsEol(*db->start))
    {
        if (++db->start == db->end)
        {
            dyn->head = db->next;
            dbuf_free(db);
            if (0 == (db = dyn->head))
            {
                dyn->tail = 0;
                dyn->length = 0;
                break;
            }
        }
        --dyn->length;
    }
    return dyn->length;
}

unsigned int dbuf_getmsg(struct DBuf *dyn, char *buf, unsigned int length)
{
    struct DBufBuffer *db;
    char *start;
    char *end;
    unsigned int count;
    unsigned int copied = 0;

    assert(0 != dyn);
    assert(0 != buf);

    if (0 == dbuf_flush(dyn))
        return 0;

    assert(0 != dyn->head);

    db = dyn->head;
    start = db->start;

    assert(start < db->end);

    if (length > dyn->length)
        length = dyn->length;

    while (length > 0)
    {
        end = IRCD_MIN(db->end, (start + length));
        while (start < end && !IsEol(*start))
            *buf++ = *start++;

        count = start - db->start;
        if (start < end)
        {
            *buf = '\0';
            copied += count;
            dbuf_delete(dyn, copied);
            dbuf_flush(dyn);
            return copied;
        }
        if (0 == (db = db->next))
            break;
        copied += count;
        length -= count;
        start = db->start;
    }
    return 0;
}

void dbuf_count_memory(size_t *allocated, size_t *used)
{
    assert(0 != allocated);
    assert(0 != used);
    *allocated = DBufAllocCount * sizeof(struct DBufBuffer);
    *used = DBufUsedCount * sizeof(struct DBufBuffer);
}


/* ========== Test fixtures ========== */

static int setup_dbuf(void **state)
{
    struct DBuf *dyn = malloc(sizeof(struct DBuf));
    memset(dyn, 0, sizeof(*dyn));
    *state = dyn;
    return 0;
}

static int teardown_dbuf(void **state)
{
    struct DBuf *dyn = *state;
    DBufClear(dyn);
    free(dyn);
    return 0;
}


/* ========== DBufLength / empty buffer tests ========== */

static void test_empty_dbuf(void **state)
{
    struct DBuf *dyn = *state;

    assert_int_equal(0, DBufLength(dyn));
    assert_null(dyn->head);
    assert_null(dyn->tail);
}


/* ========== dbuf_put tests ========== */

static void test_dbuf_put_small(void **state)
{
    struct DBuf *dyn = *state;
    const char *data = "Hello, World!";
    int result;

    result = dbuf_put(dyn, data, strlen(data));

    assert_int_equal(1, result);  /* Success */
    assert_int_equal(strlen(data), DBufLength(dyn));
    assert_non_null(dyn->head);
    assert_non_null(dyn->tail);
}

static void test_dbuf_put_multiple(void **state)
{
    struct DBuf *dyn = *state;
    const char *data1 = "First";
    const char *data2 = "Second";
    int result;

    result = dbuf_put(dyn, data1, strlen(data1));
    assert_int_equal(1, result);

    result = dbuf_put(dyn, data2, strlen(data2));
    assert_int_equal(1, result);

    assert_int_equal(strlen(data1) + strlen(data2), DBufLength(dyn));
}

static void test_dbuf_put_exact_buffer(void **state)
{
    struct DBuf *dyn = *state;
    char data[DBUF_SIZE];
    int result;

    memset(data, 'A', sizeof(data));

    result = dbuf_put(dyn, data, sizeof(data));

    assert_int_equal(1, result);
    assert_int_equal(DBUF_SIZE, DBufLength(dyn));
}

static void test_dbuf_put_cross_buffer(void **state)
{
    struct DBuf *dyn = *state;
    char data[DBUF_SIZE + 100];
    int result;

    memset(data, 'B', sizeof(data));

    result = dbuf_put(dyn, data, sizeof(data));

    assert_int_equal(1, result);
    assert_int_equal(DBUF_SIZE + 100, DBufLength(dyn));
    /* Should have allocated 2 buffers */
    assert_non_null(dyn->head);
    assert_non_null(dyn->head->next);
}


/* ========== dbuf_map tests ========== */

static void test_dbuf_map_empty(void **state)
{
    struct DBuf *dyn = *state;
    unsigned int length;
    const char *mapped;

    mapped = dbuf_map(dyn, &length);

    assert_null(mapped);
    assert_int_equal(0, length);
}

static void test_dbuf_map_data(void **state)
{
    struct DBuf *dyn = *state;
    const char *data = "Test data";
    unsigned int length;
    const char *mapped;

    dbuf_put(dyn, data, strlen(data));

    mapped = dbuf_map(dyn, &length);

    assert_non_null(mapped);
    assert_int_equal(strlen(data), length);
    assert_memory_equal(data, mapped, length);
}


/* ========== dbuf_delete tests ========== */

static void test_dbuf_delete_partial(void **state)
{
    struct DBuf *dyn = *state;
    const char *data = "Hello, World!";

    dbuf_put(dyn, data, strlen(data));
    dbuf_delete(dyn, 7);  /* Delete "Hello, " */

    assert_int_equal(strlen(data) - 7, DBufLength(dyn));
}

static void test_dbuf_delete_all(void **state)
{
    struct DBuf *dyn = *state;
    const char *data = "Hello, World!";

    dbuf_put(dyn, data, strlen(data));
    dbuf_delete(dyn, strlen(data));

    assert_int_equal(0, DBufLength(dyn));
    assert_null(dyn->head);
    assert_null(dyn->tail);
}

static void test_dbuf_delete_more_than_exists(void **state)
{
    struct DBuf *dyn = *state;
    const char *data = "Short";

    dbuf_put(dyn, data, strlen(data));
    dbuf_delete(dyn, 1000);  /* Try to delete more than exists */

    assert_int_equal(0, DBufLength(dyn));
}

static void test_dbuf_delete_cross_buffer(void **state)
{
    struct DBuf *dyn = *state;
    char data[DBUF_SIZE + 100];

    memset(data, 'X', sizeof(data));
    dbuf_put(dyn, data, sizeof(data));

    /* Delete first buffer and some of second */
    dbuf_delete(dyn, DBUF_SIZE + 50);

    assert_int_equal(50, DBufLength(dyn));
}


/* ========== dbuf_get tests ========== */

static void test_dbuf_get_all(void **state)
{
    struct DBuf *dyn = *state;
    const char *data = "Hello, World!";
    char buf[64];
    unsigned int got;

    dbuf_put(dyn, data, strlen(data));
    got = dbuf_get(dyn, buf, sizeof(buf));

    assert_int_equal(strlen(data), got);
    assert_memory_equal(data, buf, got);
    assert_int_equal(0, DBufLength(dyn));
}

static void test_dbuf_get_partial(void **state)
{
    struct DBuf *dyn = *state;
    const char *data = "Hello, World!";
    char buf[5];
    unsigned int got;

    dbuf_put(dyn, data, strlen(data));
    got = dbuf_get(dyn, buf, sizeof(buf));

    assert_int_equal(5, got);
    assert_memory_equal(data, buf, got);
    assert_int_equal(strlen(data) - 5, DBufLength(dyn));
}

static void test_dbuf_get_empty(void **state)
{
    struct DBuf *dyn = *state;
    char buf[64];
    unsigned int got;

    got = dbuf_get(dyn, buf, sizeof(buf));

    assert_int_equal(0, got);
}


/* ========== dbuf_getmsg tests ========== */

static void test_dbuf_getmsg_simple(void **state)
{
    struct DBuf *dyn = *state;
    const char *data = "Line one\r\nLine two\r\n";
    char buf[64];
    unsigned int got;

    dbuf_put(dyn, data, strlen(data));
    got = dbuf_getmsg(dyn, buf, sizeof(buf));

    assert_int_equal(8, got);  /* "Line one" without \r\n */
    assert_string_equal("Line one", buf);
}

static void test_dbuf_getmsg_multiple(void **state)
{
    struct DBuf *dyn = *state;
    const char *data = "First\r\nSecond\r\n";
    char buf[64];
    unsigned int got;

    dbuf_put(dyn, data, strlen(data));

    got = dbuf_getmsg(dyn, buf, sizeof(buf));
    assert_int_equal(5, got);
    assert_string_equal("First", buf);

    got = dbuf_getmsg(dyn, buf, sizeof(buf));
    assert_int_equal(6, got);
    assert_string_equal("Second", buf);
}

static void test_dbuf_getmsg_no_eol(void **state)
{
    struct DBuf *dyn = *state;
    const char *data = "No line ending";
    char buf[64];
    unsigned int got;

    dbuf_put(dyn, data, strlen(data));
    got = dbuf_getmsg(dyn, buf, sizeof(buf));

    /* Should return 0 when no complete line available */
    assert_int_equal(0, got);
}

static void test_dbuf_getmsg_leading_eol(void **state)
{
    struct DBuf *dyn = *state;
    const char *data = "\r\n\r\nActual line\r\n";
    char buf[64];
    unsigned int got;

    dbuf_put(dyn, data, strlen(data));
    got = dbuf_getmsg(dyn, buf, sizeof(buf));

    /* Should skip leading EOLs and get "Actual line" */
    assert_int_equal(11, got);
    assert_string_equal("Actual line", buf);
}


/* ========== DBufClear tests ========== */

static void test_dbuf_clear(void **state)
{
    struct DBuf *dyn = *state;
    char data[DBUF_SIZE * 3];

    memset(data, 'Z', sizeof(data));
    dbuf_put(dyn, data, sizeof(data));

    assert_true(DBufLength(dyn) > 0);

    DBufClear(dyn);

    assert_int_equal(0, DBufLength(dyn));
    assert_null(dyn->head);
    assert_null(dyn->tail);
}


/* ========== Memory accounting tests ========== */

static void test_dbuf_count_memory(void **state)
{
    struct DBuf *dyn = *state;
    size_t allocated, used;
    char data[DBUF_SIZE + 1];

    memset(data, 'M', sizeof(data));
    dbuf_put(dyn, data, sizeof(data));

    dbuf_count_memory(&allocated, &used);

    /* Should have allocated at least 2 buffers */
    assert_true(allocated >= 2 * sizeof(struct DBufBuffer));
    assert_true(used >= 2 * sizeof(struct DBufBuffer));
}


/* ========== Round-trip tests ========== */

static void test_dbuf_roundtrip_small(void **state)
{
    struct DBuf *dyn = *state;
    const char *original = "Round trip test data";
    char result[64];
    unsigned int got;

    dbuf_put(dyn, original, strlen(original));
    got = dbuf_get(dyn, result, sizeof(result));

    assert_int_equal(strlen(original), got);
    assert_memory_equal(original, result, got);
}

static void test_dbuf_roundtrip_large(void **state)
{
    struct DBuf *dyn = *state;
    char original[DBUF_SIZE * 3];
    char result[DBUF_SIZE * 3];
    unsigned int got;

    /* Fill with pattern */
    for (size_t i = 0; i < sizeof(original); i++) {
        original[i] = (char)('A' + (i % 26));
    }

    dbuf_put(dyn, original, sizeof(original));
    got = dbuf_get(dyn, result, sizeof(result));

    assert_int_equal(sizeof(original), got);
    assert_memory_equal(original, result, got);
}


int main(void)
{
    const struct CMUnitTest tests[] = {
        /* Empty buffer */
        cmocka_unit_test_setup_teardown(test_empty_dbuf, setup_dbuf, teardown_dbuf),

        /* dbuf_put */
        cmocka_unit_test_setup_teardown(test_dbuf_put_small, setup_dbuf, teardown_dbuf),
        cmocka_unit_test_setup_teardown(test_dbuf_put_multiple, setup_dbuf, teardown_dbuf),
        cmocka_unit_test_setup_teardown(test_dbuf_put_exact_buffer, setup_dbuf, teardown_dbuf),
        cmocka_unit_test_setup_teardown(test_dbuf_put_cross_buffer, setup_dbuf, teardown_dbuf),

        /* dbuf_map */
        cmocka_unit_test_setup_teardown(test_dbuf_map_empty, setup_dbuf, teardown_dbuf),
        cmocka_unit_test_setup_teardown(test_dbuf_map_data, setup_dbuf, teardown_dbuf),

        /* dbuf_delete */
        cmocka_unit_test_setup_teardown(test_dbuf_delete_partial, setup_dbuf, teardown_dbuf),
        cmocka_unit_test_setup_teardown(test_dbuf_delete_all, setup_dbuf, teardown_dbuf),
        cmocka_unit_test_setup_teardown(test_dbuf_delete_more_than_exists, setup_dbuf, teardown_dbuf),
        cmocka_unit_test_setup_teardown(test_dbuf_delete_cross_buffer, setup_dbuf, teardown_dbuf),

        /* dbuf_get */
        cmocka_unit_test_setup_teardown(test_dbuf_get_all, setup_dbuf, teardown_dbuf),
        cmocka_unit_test_setup_teardown(test_dbuf_get_partial, setup_dbuf, teardown_dbuf),
        cmocka_unit_test_setup_teardown(test_dbuf_get_empty, setup_dbuf, teardown_dbuf),

        /* dbuf_getmsg */
        cmocka_unit_test_setup_teardown(test_dbuf_getmsg_simple, setup_dbuf, teardown_dbuf),
        cmocka_unit_test_setup_teardown(test_dbuf_getmsg_multiple, setup_dbuf, teardown_dbuf),
        cmocka_unit_test_setup_teardown(test_dbuf_getmsg_no_eol, setup_dbuf, teardown_dbuf),
        cmocka_unit_test_setup_teardown(test_dbuf_getmsg_leading_eol, setup_dbuf, teardown_dbuf),

        /* DBufClear */
        cmocka_unit_test_setup_teardown(test_dbuf_clear, setup_dbuf, teardown_dbuf),

        /* Memory accounting */
        cmocka_unit_test_setup_teardown(test_dbuf_count_memory, setup_dbuf, teardown_dbuf),

        /* Round-trip */
        cmocka_unit_test_setup_teardown(test_dbuf_roundtrip_small, setup_dbuf, teardown_dbuf),
        cmocka_unit_test_setup_teardown(test_dbuf_roundtrip_large, setup_dbuf, teardown_dbuf),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
