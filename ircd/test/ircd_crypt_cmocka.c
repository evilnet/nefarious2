/*
 * ircd_crypt_cmocka.c - CMocka unit tests for password hashing
 *
 * Tests the password encryption and verification system used for oper
 * authentication. Supports multiple mechanisms: PLAIN (testing only),
 * SMD5 (Salted MD5), and native crypt().
 *
 * Copyright (C) 2024 AfterNET Development Team
 */

#include "config.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <cmocka.h>

/* Stubs for dependencies */
void *MyMalloc(size_t size) {
    return malloc(size);
}

void MyFree(void *ptr) {
    free(ptr);
}

/* Stub for DupString macro */
#define DupString(x, y) do { x = malloc(strlen(y) + 1); strcpy(x, y); } while(0)

/* Stub for Debug macro */
#define Debug(x)

/* Stub for assert */
#undef assert
#define assert(x) do { if (!(x)) { fprintf(stderr, "Assertion failed: %s\n", #x); abort(); } } while(0)

/* Include the headers */
#include "ircd_crypt.h"
#include "ircd_md5.h"
#include "ircd_string.h"

/* We need to provide ircd_crypt_native stub */
const char* ircd_crypt_native(const char* key, const char* salt)
{
    /* Simple stub - in real code this calls system crypt() */
    /* For testing, we just return NULL to indicate no match */
    (void)key;
    (void)salt;
    return NULL;
}

/* Forward declarations for mechanism functions */
const char* ircd_crypt_plain(const char* key, const char* salt);
const char* ircd_crypt_smd5(const char* key, const char* salt);
void ircd_register_crypt_plain(void);
void ircd_register_crypt_smd5(void);

/* Global from ircd_crypt.c */
crypt_mechs_t* crypt_mechs_root = NULL;

/* Inline ircd_crypt_register_mech */
int ircd_crypt_register_mech(crypt_mech_t* mechanism)
{
    crypt_mechs_t* crypt_mech;

    if ((crypt_mech = (crypt_mechs_t*)MyMalloc(sizeof(crypt_mechs_t))) == NULL)
        return -1;

    memset(crypt_mech, 0, sizeof(crypt_mechs_t));
    crypt_mech->mech = mechanism;
    crypt_mech->next = crypt_mech->prev = NULL;

    if(crypt_mechs_root->next == NULL)
    {
        crypt_mechs_root->next = crypt_mechs_root->prev = crypt_mech;
    } else {
        crypt_mech->prev = crypt_mechs_root->prev;
        crypt_mech->next = NULL;
        crypt_mechs_root->prev = crypt_mech->prev->next = crypt_mech;
    }

    return 0;
}

/* Inline ircd_crypt_plain */
const char* ircd_crypt_plain(const char* key, const char* salt)
{
    assert(NULL != salt);
    assert(NULL != key);
    return key;
}

/* Register plain mechanism */
void ircd_register_crypt_plain(void)
{
    crypt_mech_t* crypt_mech;

    if ((crypt_mech = (crypt_mech_t*)MyMalloc(sizeof(crypt_mech_t))) == NULL)
        return;

    crypt_mech->mechname = "plain";
    crypt_mech->shortname = "crypt_plain";
    crypt_mech->description = "Plain text crypt mechanism.";
    crypt_mech->crypt_function = &ircd_crypt_plain;
    crypt_mech->crypt_token = "$PLAIN$";
    crypt_mech->crypt_token_size = 7;

    ircd_crypt_register_mech(crypt_mech);
}

/* Inline to64 helper for SMD5 */
static unsigned char itoa64[] =
"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

static void to64(char *s, unsigned long v, int n)
{
    while (--n >= 0) {
        *s++ = itoa64[v & 0x3f];
        v >>= 6;
    }
}

/* Inline ircd_crypt_smd5 */
const char* ircd_crypt_smd5(const char* key, const char* salt)
{
    const char *magic = "$1$";
    static char passwd[120];
    char *p;
    const char *sp, *ep;
    unsigned char final[16];
    int sl, pl, i, j;
    MD5_CTX ctx, ctx1;
    unsigned long l;

    assert(NULL != key);
    assert(NULL != salt);

    ep = sp = salt;
    for (ep = sp; *ep && *ep != '$' && ep < (sp + 8); ep++)
        continue;
    sl = ep - sp;

    MD5Init(&ctx);
    MD5Update(&ctx,(unsigned const char *)key,strlen(key));
    MD5Update(&ctx,(unsigned const char *)magic,strlen(magic));
    MD5Update(&ctx,(unsigned const char *)sp,sl);

    MD5Init(&ctx1);
    MD5Update(&ctx1,(unsigned const char *)key,strlen(key));
    MD5Update(&ctx1,(unsigned const char *)sp,sl);
    MD5Update(&ctx1,(unsigned const char *)key,strlen(key));
    MD5Final(final,&ctx1);
    for (pl = strlen(key); pl > 0; pl -= 16)
        MD5Update(&ctx,(unsigned const char *)final,pl>16 ? 16 : pl);

    memset(final, 0, sizeof final);

    for (j = 0, i = strlen(key); i; i >>= 1)
        if (i & 1)
            MD5Update(&ctx, (unsigned const char *)final+j, 1);
        else
            MD5Update(&ctx, (unsigned const char *)key+j, 1);

    memset(passwd, 0, 120);
    strncpy(passwd, sp, sl);
    strcat(passwd, "$");

    MD5Final(final,&ctx);

    for (i = 0; i < 1000; i++) {
        MD5Init(&ctx1);

        if (i & 1)
            MD5Update(&ctx1,(unsigned const char *)key,strlen(key));
        else
            MD5Update(&ctx1,(unsigned const char *)final,16);

        if (i % 3)
            MD5Update(&ctx1,(unsigned const char *)sp,sl);

        if (i % 7)
            MD5Update(&ctx1,(unsigned const char *)key,strlen(key));

        if (i & 1)
            MD5Update(&ctx1,(unsigned const char *)final,16);
        else
            MD5Update(&ctx1,(unsigned const char *)key,strlen(key));

        MD5Final(final,&ctx1);
    }

    p = passwd + strlen(passwd);

    l = (final[0] << 16) | (final[6] << 8) | final[12];
    to64(p, l, 4); p += 4;
    l = (final[1] << 16) | (final[7] << 8) | final[13];
    to64(p, l, 4); p += 4;
    l = (final[2] << 16) | (final[8] << 8) | final[14];
    to64(p, l, 4); p += 4;
    l = (final[3] << 16) | (final[9] << 8) | final[15];
    to64(p, l, 4); p += 4;
    l = (final[4] << 16) | (final[10] << 8) | final[5];
    to64(p, l, 4); p += 4;
    l = final[11];
    to64(p, l, 2); p += 2;
    *p = '\0';

    memset(final, 0, sizeof final);

    return passwd;
}

/* Register SMD5 mechanism */
void ircd_register_crypt_smd5(void)
{
    crypt_mech_t* crypt_mech;

    if ((crypt_mech = (crypt_mech_t*)MyMalloc(sizeof(crypt_mech_t))) == NULL)
        return;

    crypt_mech->mechname = "smd5";
    crypt_mech->shortname = "crypt_smd5";
    crypt_mech->description = "Salted MD5 password hash mechanism.";
    crypt_mech->crypt_function = &ircd_crypt_smd5;
    crypt_mech->crypt_token = "$SMD5$";
    crypt_mech->crypt_token_size = 6;

    ircd_crypt_register_mech(crypt_mech);
}

/* Inline ircd_crypt */
char* ircd_crypt(const char* key, const char* salt)
{
    char *hashed_pass = NULL;
    const char *temp_hashed_pass, *mysalt;
    crypt_mechs_t* crypt_mech;

    assert(NULL != key);
    assert(NULL != salt);

    crypt_mech = crypt_mechs_root->next;

    for (;crypt_mech;)
    {
        if (strlen(salt) < (size_t)crypt_mech->mech->crypt_token_size)
        {
            crypt_mech = crypt_mech->next;
            continue;
        }

        if(0 == ircd_strncmp(crypt_mech->mech->crypt_token, salt, crypt_mech->mech->crypt_token_size))
        {
            if(strlen(salt) < (size_t)crypt_mech->mech->crypt_token_size + 1)
                return NULL;

            mysalt = salt + crypt_mech->mech->crypt_token_size;

            if(NULL == (temp_hashed_pass = crypt_mech->mech->crypt_function(key, mysalt)))
                return NULL;

            if(NULL == (hashed_pass = (char *)MyMalloc(sizeof(char)*strlen(temp_hashed_pass) + crypt_mech->mech->crypt_token_size + 1)))
                return NULL;

            memset(hashed_pass, 0, sizeof(char)*strlen(temp_hashed_pass)
                +crypt_mech->mech->crypt_token_size + 1);
            ircd_strncpy(hashed_pass, crypt_mech->mech->crypt_token,
                crypt_mech->mech->crypt_token_size);
            ircd_strncpy(hashed_pass + crypt_mech->mech->crypt_token_size, temp_hashed_pass, strlen(temp_hashed_pass));
        } else {
            crypt_mech = crypt_mech->next;
            continue;
        }
        return hashed_pass;
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

/* Inline ircd_crypt_init */
void ircd_crypt_init(void)
{
    if((crypt_mechs_root = MyMalloc(sizeof(crypt_mechs_t))) == NULL)
        return;

    crypt_mechs_root->mech = NULL;
    crypt_mechs_root->next = crypt_mechs_root->prev = NULL;

    ircd_register_crypt_smd5();
    ircd_register_crypt_plain();
}

/* Inline oper_password_match */
int oper_password_match(const char* to_match, const char* passwd)
{
    char *crypted;
    int res;

    if (!to_match || !passwd)
        return 0;

    crypted = ircd_crypt(to_match, passwd);

    if (!crypted)
        return 0;
    res = strcmp(crypted, passwd);
    MyFree(crypted);
    return 0 == res;
}


/* ========== Test fixtures ========== */

static int setup_crypt(void **state)
{
    (void)state;
    ircd_crypt_init();
    return 0;
}

static int teardown_crypt(void **state)
{
    (void)state;
    /* Note: In production code we'd free all mechanisms, but for tests
     * we just leave them allocated - they're small and short-lived */
    return 0;
}


/* ========== ircd_crypt_plain tests ========== */

static void test_crypt_plain_returns_key(void **state)
{
    (void)state;
    const char *result;

    /* PLAIN mechanism just returns the key unchanged */
    result = ircd_crypt_plain("password", "salt");
    assert_string_equal("password", result);
}

static void test_crypt_plain_different_inputs(void **state)
{
    (void)state;
    const char *result;

    result = ircd_crypt_plain("secret123", "anysalt");
    assert_string_equal("secret123", result);

    result = ircd_crypt_plain("", "salt");
    assert_string_equal("", result);
}


/* ========== ircd_crypt_smd5 tests ========== */

static void test_crypt_smd5_produces_hash(void **state)
{
    (void)state;
    const char *result;

    result = ircd_crypt_smd5("password", "saltsalt");

    assert_non_null(result);
    assert_true(strlen(result) > 0);
}

static void test_crypt_smd5_deterministic(void **state)
{
    (void)state;
    const char *result1, *result2;
    char saved[128];

    /* Same password + salt should produce same hash */
    result1 = ircd_crypt_smd5("mypassword", "testsalt");
    strncpy(saved, result1, sizeof(saved) - 1);
    saved[sizeof(saved) - 1] = '\0';

    result2 = ircd_crypt_smd5("mypassword", "testsalt");
    assert_string_equal(saved, result2);
}

static void test_crypt_smd5_different_passwords(void **state)
{
    (void)state;
    const char *result1, *result2;
    char saved[128];

    result1 = ircd_crypt_smd5("password1", "salt1234");
    strncpy(saved, result1, sizeof(saved) - 1);
    saved[sizeof(saved) - 1] = '\0';

    result2 = ircd_crypt_smd5("password2", "salt1234");

    /* Different passwords should produce different hashes */
    assert_string_not_equal(saved, result2);
}

static void test_crypt_smd5_different_salts(void **state)
{
    (void)state;
    const char *result1, *result2;
    char saved[128];

    result1 = ircd_crypt_smd5("samepassword", "salt1111");
    strncpy(saved, result1, sizeof(saved) - 1);
    saved[sizeof(saved) - 1] = '\0';

    result2 = ircd_crypt_smd5("samepassword", "salt2222");

    /* Different salts should produce different hashes */
    assert_string_not_equal(saved, result2);
}


/* ========== ircd_crypt tests ========== */

static void test_ircd_crypt_plain_tagged(void **state)
{
    (void)state;
    char *result;

    /* Test PLAIN mechanism with tag */
    result = ircd_crypt("testpass", "$PLAIN$testpass");

    assert_non_null(result);
    assert_string_equal("$PLAIN$testpass", result);
    MyFree(result);
}

static void test_ircd_crypt_smd5_tagged(void **state)
{
    (void)state;
    char *result;

    /* Test SMD5 mechanism with tag */
    result = ircd_crypt("password", "$SMD5$saltsalt$somehash");

    assert_non_null(result);
    /* Should start with $SMD5$ tag */
    assert_true(strncmp(result, "$SMD5$", 6) == 0);
    MyFree(result);
}

static void test_ircd_crypt_unknown_tag(void **state)
{
    (void)state;
    char *result;

    /* Unknown tag should fall through to native crypt (which we stub as NULL) */
    result = ircd_crypt("password", "$UNKNOWN$salt");

    /* Our stub returns NULL for native crypt */
    assert_null(result);
}

static void test_ircd_crypt_short_salt(void **state)
{
    (void)state;
    char *result;

    /* Salt too short for any mechanism */
    result = ircd_crypt("password", "ab");

    /* Should return NULL */
    assert_null(result);
}


/* ========== oper_password_match tests ========== */

static void test_oper_password_match_plain_correct(void **state)
{
    (void)state;
    int result;

    /* Correct password should match */
    result = oper_password_match("secretpass", "$PLAIN$secretpass");
    assert_int_equal(1, result);
}

static void test_oper_password_match_plain_incorrect(void **state)
{
    (void)state;
    int result;

    /* Incorrect password should not match */
    result = oper_password_match("wrongpass", "$PLAIN$secretpass");
    assert_int_equal(0, result);
}

static void test_oper_password_match_null_inputs(void **state)
{
    (void)state;
    int result;

    /* NULL inputs should return 0 (no match) */
    result = oper_password_match(NULL, "$PLAIN$test");
    assert_int_equal(0, result);

    result = oper_password_match("test", NULL);
    assert_int_equal(0, result);

    result = oper_password_match(NULL, NULL);
    assert_int_equal(0, result);
}

static void test_oper_password_match_empty_password(void **state)
{
    (void)state;
    int result;

    /* $PLAIN$ without a password after the tag returns NULL from ircd_crypt
     * because the implementation requires at least one character after the token.
     * This is correct security behavior - reject malformed password entries. */
    result = oper_password_match("", "$PLAIN$");
    assert_int_equal(0, result);

    /* But $PLAIN$ with an actual empty string placeholder should work */
    /* Actually, the token check requires strlen > token_size, so even empty
     * string after token would fail. Let's verify single char works: */
    result = oper_password_match("x", "$PLAIN$x");
    assert_int_equal(1, result);
}

static void test_oper_password_match_smd5(void **state)
{
    (void)state;
    char *hashed;
    int result;

    /* First generate a hash for a known password */
    hashed = ircd_crypt("operpass", "$SMD5$saltsalt$");
    assert_non_null(hashed);

    /* Now verify the password matches */
    result = oper_password_match("operpass", hashed);
    assert_int_equal(1, result);

    /* Wrong password should not match */
    result = oper_password_match("wrongpass", hashed);
    assert_int_equal(0, result);

    MyFree(hashed);
}


/* ========== Mechanism registration tests ========== */

static void test_mechanism_registered(void **state)
{
    (void)state;
    crypt_mechs_t *mech;
    int found_plain = 0, found_smd5 = 0;

    /* Verify both mechanisms are registered */
    for (mech = crypt_mechs_root->next; mech; mech = mech->next)
    {
        if (strcmp(mech->mech->shortname, "crypt_plain") == 0)
            found_plain = 1;
        if (strcmp(mech->mech->shortname, "crypt_smd5") == 0)
            found_smd5 = 1;
    }

    assert_int_equal(1, found_plain);
    assert_int_equal(1, found_smd5);
}

static void test_mechanism_tokens(void **state)
{
    (void)state;
    crypt_mechs_t *mech;

    /* Verify token formats */
    for (mech = crypt_mechs_root->next; mech; mech = mech->next)
    {
        if (strcmp(mech->mech->shortname, "crypt_plain") == 0)
        {
            assert_string_equal("$PLAIN$", mech->mech->crypt_token);
            assert_int_equal(7, mech->mech->crypt_token_size);
        }
        if (strcmp(mech->mech->shortname, "crypt_smd5") == 0)
        {
            assert_string_equal("$SMD5$", mech->mech->crypt_token);
            assert_int_equal(6, mech->mech->crypt_token_size);
        }
    }
}


int main(void)
{
    const struct CMUnitTest tests[] = {
        /* ircd_crypt_plain */
        cmocka_unit_test_setup_teardown(test_crypt_plain_returns_key, setup_crypt, teardown_crypt),
        cmocka_unit_test_setup_teardown(test_crypt_plain_different_inputs, setup_crypt, teardown_crypt),

        /* ircd_crypt_smd5 */
        cmocka_unit_test_setup_teardown(test_crypt_smd5_produces_hash, setup_crypt, teardown_crypt),
        cmocka_unit_test_setup_teardown(test_crypt_smd5_deterministic, setup_crypt, teardown_crypt),
        cmocka_unit_test_setup_teardown(test_crypt_smd5_different_passwords, setup_crypt, teardown_crypt),
        cmocka_unit_test_setup_teardown(test_crypt_smd5_different_salts, setup_crypt, teardown_crypt),

        /* ircd_crypt */
        cmocka_unit_test_setup_teardown(test_ircd_crypt_plain_tagged, setup_crypt, teardown_crypt),
        cmocka_unit_test_setup_teardown(test_ircd_crypt_smd5_tagged, setup_crypt, teardown_crypt),
        cmocka_unit_test_setup_teardown(test_ircd_crypt_unknown_tag, setup_crypt, teardown_crypt),
        cmocka_unit_test_setup_teardown(test_ircd_crypt_short_salt, setup_crypt, teardown_crypt),

        /* oper_password_match */
        cmocka_unit_test_setup_teardown(test_oper_password_match_plain_correct, setup_crypt, teardown_crypt),
        cmocka_unit_test_setup_teardown(test_oper_password_match_plain_incorrect, setup_crypt, teardown_crypt),
        cmocka_unit_test_setup_teardown(test_oper_password_match_null_inputs, setup_crypt, teardown_crypt),
        cmocka_unit_test_setup_teardown(test_oper_password_match_empty_password, setup_crypt, teardown_crypt),
        cmocka_unit_test_setup_teardown(test_oper_password_match_smd5, setup_crypt, teardown_crypt),

        /* Mechanism registration */
        cmocka_unit_test_setup_teardown(test_mechanism_registered, setup_crypt, teardown_crypt),
        cmocka_unit_test_setup_teardown(test_mechanism_tokens, setup_crypt, teardown_crypt),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
