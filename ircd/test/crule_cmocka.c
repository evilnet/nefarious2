/* crule_cmocka.c - CMocka unit tests for connection rule parser
 *
 * Tests the connection rule grammar parser used for server link rules.
 * We inline the parser functions with CR_DEBUG and CR_CHKCONF defined
 * to avoid server dependencies, but prevent the built-in main().
 *
 * Grammar:
 *   rule:      orexpr END
 *   orexpr:    andexpr | andexpr || orexpr
 *   andexpr:   primary | primary && andexpr
 *   primary:   function | ! primary | ( orexpr )
 *   function:  word ( ) | word ( arglist )
 *   arglist:   word | word , arglist
 */

#include "config.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <cmocka.h>

/* Provide character classification macros */
#include "ircd_chattr.h"

/* Define CR_CHKCONF to get standalone parser mode (no server deps)
 * but unlike CR_DEBUG, it doesn't include main() */
#define CR_CHKCONF

/* Provide MyMalloc/MyFree stubs before including crule.c */
#define MyMalloc malloc
#define MyFree free

/* Provide ircd_strcmp - case-insensitive compare */
#define ircd_strcmp strcasecmp

/* Provide DupString macro */
#define DupString(x,y) \
    do { \
        x = (char*) malloc(strlen(y)+1); \
        strcpy(x,y); \
    } while(0)

/* === Inline the parser structures and functions from crule.c === */

#define CR_MAXARGLEN 80
#define CR_MAXARGS 3

enum crule_token {
    CR_UNKNOWN,
    CR_END,
    CR_AND,
    CR_OR,
    CR_NOT,
    CR_OPENPAREN,
    CR_CLOSEPAREN,
    CR_COMMA,
    CR_WORD
};

enum crule_errcode {
    CR_NOERR,
    CR_UNEXPCTTOK,
    CR_UNKNWTOK,
    CR_EXPCTAND,
    CR_EXPCTOR,
    CR_EXPCTPRIM,
    CR_EXPCTOPEN,
    CR_EXPCTCLOSE,
    CR_UNKNWFUNC,
    CR_ARGMISMAT
};

typedef int (*crule_funcptr)(int, void **);

struct CRuleNode {
    crule_funcptr funcptr;
    int numargs;
    void *arg[CR_MAXARGS];
};

typedef struct CRuleNode* CRuleNodePtr;

/* Rule function stubs - in CHKCONF mode these return 0 */
static int crule_connected(int numargs, void *crulearg[]) { return 0; }
static int crule_directcon(int numargs, void *crulearg[]) { return 0; }
static int crule_via(int numargs, void *crulearg[]) { return 0; }
static int crule_directop(int numargs, void *crulearg[]) { return 0; }

/* Forward declarations */
static int crule__andor(int, void *[]);
static int crule__not(int, void *[]);
void crule_free(struct CRuleNode** elem);
static int crule_gettoken(int* token, const char** str);
static void crule_getword(char*, int*, size_t, const char**);
static int crule_parseandexpr(CRuleNodePtr*, int *, const char**);
static int crule_parseorexpr(CRuleNodePtr*, int *, const char**);
static int crule_parseprimary(CRuleNodePtr*, int *, const char**);
static int crule_parsefunction(CRuleNodePtr*, int *, const char**);
static int crule_parsearglist(CRuleNodePtr, int *, const char**);

char *crule_errstr[] = {
    "Unknown error",
    "Unexpected token",
    "Unknown token",
    "And expr expected",
    "Or expr expected",
    "Primary expected",
    "( expected",
    ") expected",
    "Unknown function",
    "Argument mismatch"
};

struct crule_funclistent {
    char name[15];
    int reqnumargs;
    crule_funcptr funcptr;
};

struct crule_funclistent crule_funclist[] = {
    {"connected", 1, crule_connected},
    {"directcon", 1, crule_directcon},
    {"via", 2, crule_via},
    {"directop", 0, crule_directop},
    {"", 0, NULL}
};

/* crule_eval */
int crule_eval(struct CRuleNode* rule)
{
    return (rule->funcptr(rule->numargs, rule->arg));
}

/* crule__andor */
static int crule__andor(int numargs, void *crulearg[])
{
    int result1;
    result1 = crule_eval(crulearg[0]);
    if (crulearg[2])
        return (result1 || crule_eval(crulearg[1]));
    else
        return (result1 && crule_eval(crulearg[1]));
}

/* crule__not */
static int crule__not(int numargs, void *crulearg[])
{
    return (!crule_eval(crulearg[0]));
}

/* crule_gettoken */
static int crule_gettoken(int* next_tokp, const char** ruleptr)
{
    char pending = '\0';

    *next_tokp = CR_UNKNOWN;
    while (*next_tokp == CR_UNKNOWN)
        switch (*(*ruleptr)++)
        {
            case ' ':
            case '\t':
                break;
            case '&':
                if (pending == '\0')
                    pending = '&';
                else if (pending == '&')
                    *next_tokp = CR_AND;
                else
                    return (CR_UNKNWTOK);
                break;
            case '|':
                if (pending == '\0')
                    pending = '|';
                else if (pending == '|')
                    *next_tokp = CR_OR;
                else
                    return (CR_UNKNWTOK);
                break;
            case '!':
                *next_tokp = CR_NOT;
                break;
            case '(':
                *next_tokp = CR_OPENPAREN;
                break;
            case ')':
                *next_tokp = CR_CLOSEPAREN;
                break;
            case ',':
                *next_tokp = CR_COMMA;
                break;
            case '\0':
                (*ruleptr)--;
                *next_tokp = CR_END;
                break;
            case ':':
                *next_tokp = CR_END;
                break;
            default:
                if ((IsAlpha(*(--(*ruleptr)))) || (**ruleptr == '*') ||
                    (**ruleptr == '?') || (**ruleptr == '.') || (**ruleptr == '-'))
                    *next_tokp = CR_WORD;
                else
                    return (CR_UNKNWTOK);
                break;
        }
    return CR_NOERR;
}

/* crule_getword */
static void crule_getword(char* word, int* wordlenp, size_t maxlen, const char** ruleptr)
{
    char *word_ptr;

    word_ptr = word;
    while ((size_t)(word_ptr - word) < maxlen
        && (IsAlnum(**ruleptr)
        || **ruleptr == '*' || **ruleptr == '?'
        || **ruleptr == '.' || **ruleptr == '-'))
        *word_ptr++ = *(*ruleptr)++;
    *word_ptr = '\0';
    *wordlenp = word_ptr - word;
}

/* crule_parseorexpr */
static int crule_parseorexpr(CRuleNodePtr * orrootp, int *next_tokp, const char** ruleptr)
{
    int errcode = CR_NOERR;
    CRuleNodePtr andexpr;
    CRuleNodePtr orptr;

    *orrootp = NULL;
    while (errcode == CR_NOERR)
    {
        errcode = crule_parseandexpr(&andexpr, next_tokp, ruleptr);
        if ((errcode == CR_NOERR) && (*next_tokp == CR_OR))
        {
            orptr = (CRuleNodePtr) malloc(sizeof(struct CRuleNode));
            orptr->funcptr = crule__andor;
            orptr->numargs = 3;
            orptr->arg[2] = (void *)1;
            if (*orrootp != NULL)
            {
                (*orrootp)->arg[1] = andexpr;
                orptr->arg[0] = *orrootp;
            }
            else
                orptr->arg[0] = andexpr;
            *orrootp = orptr;
        }
        else
        {
            if (*orrootp != NULL)
            {
                if (andexpr != NULL)
                {
                    (*orrootp)->arg[1] = andexpr;
                    return (errcode);
                }
                else
                {
                    (*orrootp)->arg[1] = NULL;
                    return (CR_EXPCTAND);
                }
            }
            else
            {
                *orrootp = andexpr;
                return (errcode);
            }
        }
        if ((errcode = crule_gettoken(next_tokp, ruleptr)) != CR_NOERR)
            return (errcode);
    }
    return (errcode);
}

/* crule_parseandexpr */
static int crule_parseandexpr(CRuleNodePtr * androotp, int *next_tokp, const char** ruleptr)
{
    int errcode = CR_NOERR;
    CRuleNodePtr primary;
    CRuleNodePtr andptr;

    *androotp = NULL;
    while (errcode == CR_NOERR)
    {
        errcode = crule_parseprimary(&primary, next_tokp, ruleptr);
        if ((errcode == CR_NOERR) && (*next_tokp == CR_AND))
        {
            andptr = (CRuleNodePtr) malloc(sizeof(struct CRuleNode));
            andptr->funcptr = crule__andor;
            andptr->numargs = 3;
            andptr->arg[2] = (void *)0;
            if (*androotp != NULL)
            {
                (*androotp)->arg[1] = primary;
                andptr->arg[0] = *androotp;
            }
            else
                andptr->arg[0] = primary;
            *androotp = andptr;
        }
        else
        {
            if (*androotp != NULL)
            {
                if (primary != NULL)
                {
                    (*androotp)->arg[1] = primary;
                    return (errcode);
                }
                else
                {
                    (*androotp)->arg[1] = NULL;
                    return (CR_EXPCTPRIM);
                }
            }
            else
            {
                *androotp = primary;
                return (errcode);
            }
        }
        if ((errcode = crule_gettoken(next_tokp, ruleptr)) != CR_NOERR)
            return (errcode);
    }
    return (errcode);
}

/* crule_parseprimary */
static int crule_parseprimary(CRuleNodePtr* primrootp, int *next_tokp, const char** ruleptr)
{
    CRuleNodePtr *insertionp;
    int errcode = CR_NOERR;

    *primrootp = NULL;
    insertionp = primrootp;
    while (errcode == CR_NOERR)
    {
        switch (*next_tokp)
        {
            case CR_OPENPAREN:
                if ((errcode = crule_gettoken(next_tokp, ruleptr)) != CR_NOERR)
                    break;
                if ((errcode = crule_parseorexpr(insertionp, next_tokp, ruleptr)) != CR_NOERR)
                    break;
                if (*insertionp == NULL)
                {
                    errcode = CR_EXPCTAND;
                    break;
                }
                if (*next_tokp != CR_CLOSEPAREN)
                {
                    errcode = CR_EXPCTCLOSE;
                    break;
                }
                errcode = crule_gettoken(next_tokp, ruleptr);
                break;
            case CR_NOT:
                *insertionp = (CRuleNodePtr) malloc(sizeof(struct CRuleNode));
                (*insertionp)->funcptr = crule__not;
                (*insertionp)->numargs = 1;
                (*insertionp)->arg[0] = NULL;
                insertionp = (CRuleNodePtr *) & ((*insertionp)->arg[0]);
                if ((errcode = crule_gettoken(next_tokp, ruleptr)) != CR_NOERR)
                    break;
                continue;
            case CR_WORD:
                errcode = crule_parsefunction(insertionp, next_tokp, ruleptr);
                break;
            default:
                if (*primrootp == NULL)
                    errcode = CR_NOERR;
                else
                    errcode = CR_EXPCTPRIM;
                break;
        }
        return (errcode);
    }
    return (errcode);
}

/* crule_parsefunction */
static int crule_parsefunction(CRuleNodePtr* funcrootp, int* next_tokp, const char** ruleptr)
{
    int errcode = CR_NOERR;
    char funcname[CR_MAXARGLEN];
    int namelen;
    int funcnum;

    *funcrootp = NULL;
    crule_getword(funcname, &namelen, CR_MAXARGLEN - 1, ruleptr);
    if ((errcode = crule_gettoken(next_tokp, ruleptr)) != CR_NOERR)
        return (errcode);
    if (*next_tokp == CR_OPENPAREN)
    {
        for (funcnum = 0;; funcnum++)
        {
            if (0 == ircd_strcmp(crule_funclist[funcnum].name, funcname))
                break;
            if (crule_funclist[funcnum].name[0] == '\0')
                return (CR_UNKNWFUNC);
        }
        if ((errcode = crule_gettoken(next_tokp, ruleptr)) != CR_NOERR)
            return (errcode);
        *funcrootp = (CRuleNodePtr) malloc(sizeof(struct CRuleNode));
        (*funcrootp)->funcptr = NULL;
        if ((errcode = crule_parsearglist(*funcrootp, next_tokp, ruleptr)) != CR_NOERR)
            return (errcode);
        if (*next_tokp != CR_CLOSEPAREN)
            return (CR_EXPCTCLOSE);
        if ((crule_funclist[funcnum].reqnumargs != (*funcrootp)->numargs) &&
            (crule_funclist[funcnum].reqnumargs != -1))
            return (CR_ARGMISMAT);
        if ((errcode = crule_gettoken(next_tokp, ruleptr)) != CR_NOERR)
            return (errcode);
        (*funcrootp)->funcptr = crule_funclist[funcnum].funcptr;
        return (CR_NOERR);
    }
    else
        return (CR_EXPCTOPEN);
}

/* crule_parsearglist */
static int crule_parsearglist(CRuleNodePtr argrootp, int *next_tokp, const char** ruleptr)
{
    int errcode = CR_NOERR;
    char *argelemp = NULL;
    char currarg[CR_MAXARGLEN];
    int arglen = 0;
    char word[CR_MAXARGLEN];
    int wordlen = 0;

    argrootp->numargs = 0;
    currarg[0] = '\0';
    while (errcode == CR_NOERR)
    {
        switch (*next_tokp)
        {
            case CR_WORD:
                crule_getword(word, &wordlen, CR_MAXARGLEN - 1, ruleptr);
                if (currarg[0] != '\0')
                {
                    if ((arglen + wordlen) < (CR_MAXARGLEN - 1))
                    {
                        strcat(currarg, " ");
                        strcat(currarg, word);
                        arglen += wordlen + 1;
                    }
                }
                else
                {
                    strcpy(currarg, word);
                    arglen = wordlen;
                }
                errcode = crule_gettoken(next_tokp, ruleptr);
                break;
            default:
                /* In CR_CHKCONF mode, skip collapse() call */
                if (currarg[0] != '\0')
                {
                    DupString(argelemp, currarg);
                    argrootp->arg[argrootp->numargs++] = (void *)argelemp;
                }
                if (*next_tokp != CR_COMMA)
                    return (CR_NOERR);
                currarg[0] = '\0';
                errcode = crule_gettoken(next_tokp, ruleptr);
                break;
        }
    }
    return (errcode);
}

/* crule_parse */
struct CRuleNode* crule_parse(const char *rule)
{
    const char* ruleptr = rule;
    int next_tok;
    struct CRuleNode* ruleroot = 0;
    int errcode = CR_NOERR;

    if ((errcode = crule_gettoken(&next_tok, &ruleptr)) == CR_NOERR) {
        if ((errcode = crule_parseorexpr(&ruleroot, &next_tok, &ruleptr)) == CR_NOERR) {
            if (ruleroot != NULL) {
                if (next_tok == CR_END)
                    return (ruleroot);
                else
                    errcode = CR_UNEXPCTTOK;
            }
            else
                errcode = CR_EXPCTOR;
        }
    }
    if (ruleroot != NULL)
        crule_free(&ruleroot);
    fprintf(stderr, "%s in rule: %s\n", crule_errstr[errcode], rule);
    return 0;
}

/* crule_free */
void crule_free(struct CRuleNode** elem)
{
    int arg, numargs;

    if ((*(elem))->funcptr == crule__not)
    {
        if ((*(elem))->arg[0] != NULL)
            crule_free((struct CRuleNode**) &((*(elem))->arg[0]));
    }
    else if ((*(elem))->funcptr == crule__andor)
    {
        crule_free((struct CRuleNode**) &((*(elem))->arg[0]));
        if ((*(elem))->arg[1] != NULL)
            crule_free((struct CRuleNode**) &((*(elem))->arg[1]));
    }
    else
    {
        numargs = (*(elem))->numargs;
        for (arg = 0; arg < numargs; arg++)
            free((*(elem))->arg[arg]);
    }
    free(*elem);
    *elem = 0;
}

/* ========== Basic Parsing Tests ========== */

static void test_parse_empty_rule(void **state)
{
    (void)state;
    struct CRuleNode *rule;

    /* Empty string should fail to parse */
    rule = crule_parse("");
    assert_null(rule);
}

static void test_parse_simple_function_no_args(void **state)
{
    (void)state;
    struct CRuleNode *rule;

    /* directop() takes no arguments */
    rule = crule_parse("directop()");
    assert_non_null(rule);
    assert_ptr_equal(rule->funcptr, crule_directop);
    assert_int_equal(rule->numargs, 0);
    crule_free(&rule);
    assert_null(rule);
}

static void test_parse_simple_function_one_arg(void **state)
{
    (void)state;
    struct CRuleNode *rule;

    /* connected() takes one argument */
    rule = crule_parse("connected(*.example.com)");
    assert_non_null(rule);
    assert_ptr_equal(rule->funcptr, crule_connected);
    assert_int_equal(rule->numargs, 1);
    assert_string_equal((char*)rule->arg[0], "*.example.com");
    crule_free(&rule);
    assert_null(rule);
}

static void test_parse_simple_function_two_args(void **state)
{
    (void)state;
    struct CRuleNode *rule;

    /* via() takes two arguments */
    rule = crule_parse("via(hub.*, *.leaf.net)");
    assert_non_null(rule);
    assert_ptr_equal(rule->funcptr, crule_via);
    assert_int_equal(rule->numargs, 2);
    assert_string_equal((char*)rule->arg[0], "hub.*");
    assert_string_equal((char*)rule->arg[1], "*.leaf.net");
    crule_free(&rule);
    assert_null(rule);
}

static void test_parse_directcon(void **state)
{
    (void)state;
    struct CRuleNode *rule;

    rule = crule_parse("directcon(irc.example.*)");
    assert_non_null(rule);
    assert_ptr_equal(rule->funcptr, crule_directcon);
    assert_int_equal(rule->numargs, 1);
    assert_string_equal((char*)rule->arg[0], "irc.example.*");
    crule_free(&rule);
}

/* ========== NOT Operator Tests ========== */

static void test_parse_not_operator(void **state)
{
    (void)state;
    struct CRuleNode *rule;

    rule = crule_parse("!directop()");
    assert_non_null(rule);
    assert_ptr_equal(rule->funcptr, crule__not);
    assert_int_equal(rule->numargs, 1);
    struct CRuleNode *child = (struct CRuleNode*)rule->arg[0];
    assert_non_null(child);
    assert_ptr_equal(child->funcptr, crule_directop);
    crule_free(&rule);
}

static void test_parse_double_not(void **state)
{
    (void)state;
    struct CRuleNode *rule;

    rule = crule_parse("!!directop()");
    assert_non_null(rule);
    assert_ptr_equal(rule->funcptr, crule__not);
    struct CRuleNode *child = (struct CRuleNode*)rule->arg[0];
    assert_non_null(child);
    assert_ptr_equal(child->funcptr, crule__not);
    struct CRuleNode *grandchild = (struct CRuleNode*)child->arg[0];
    assert_non_null(grandchild);
    assert_ptr_equal(grandchild->funcptr, crule_directop);
    crule_free(&rule);
}

/* ========== AND Operator Tests ========== */

static void test_parse_and_operator(void **state)
{
    (void)state;
    struct CRuleNode *rule;

    rule = crule_parse("directop() && connected(*)");
    assert_non_null(rule);
    assert_ptr_equal(rule->funcptr, crule__andor);
    assert_int_equal(rule->numargs, 3);
    assert_null(rule->arg[2]); /* NULL means AND */

    struct CRuleNode *left = (struct CRuleNode*)rule->arg[0];
    struct CRuleNode *right = (struct CRuleNode*)rule->arg[1];
    assert_non_null(left);
    assert_non_null(right);
    assert_ptr_equal(left->funcptr, crule_directop);
    assert_ptr_equal(right->funcptr, crule_connected);
    crule_free(&rule);
}

static void test_parse_chained_and(void **state)
{
    (void)state;
    struct CRuleNode *rule;

    rule = crule_parse("directop() && connected(*) && directcon(hub.*)");
    assert_non_null(rule);
    assert_ptr_equal(rule->funcptr, crule__andor);
    crule_free(&rule);
}

/* ========== OR Operator Tests ========== */

static void test_parse_or_operator(void **state)
{
    (void)state;
    struct CRuleNode *rule;

    rule = crule_parse("directop() || connected(*)");
    assert_non_null(rule);
    assert_ptr_equal(rule->funcptr, crule__andor);
    assert_int_equal(rule->numargs, 3);
    assert_non_null(rule->arg[2]); /* non-NULL means OR */

    struct CRuleNode *left = (struct CRuleNode*)rule->arg[0];
    struct CRuleNode *right = (struct CRuleNode*)rule->arg[1];
    assert_non_null(left);
    assert_non_null(right);
    assert_ptr_equal(left->funcptr, crule_directop);
    assert_ptr_equal(right->funcptr, crule_connected);
    crule_free(&rule);
}

static void test_parse_chained_or(void **state)
{
    (void)state;
    struct CRuleNode *rule;

    rule = crule_parse("directop() || connected(*) || directcon(hub.*)");
    assert_non_null(rule);
    assert_ptr_equal(rule->funcptr, crule__andor);
    assert_non_null(rule->arg[2]); /* OR */
    crule_free(&rule);
}

/* ========== Precedence Tests ========== */

static void test_parse_and_or_precedence(void **state)
{
    (void)state;
    struct CRuleNode *rule;

    /* AND has higher precedence than OR */
    rule = crule_parse("directop() || connected(*) && directcon(hub.*)");
    assert_non_null(rule);
    assert_ptr_equal(rule->funcptr, crule__andor);
    assert_non_null(rule->arg[2]); /* OR at top level */
    crule_free(&rule);
}

static void test_parse_parentheses_override(void **state)
{
    (void)state;
    struct CRuleNode *rule;

    /* Parentheses override normal precedence */
    rule = crule_parse("(directop() || connected(*)) && directcon(hub.*)");
    assert_non_null(rule);
    assert_ptr_equal(rule->funcptr, crule__andor);
    assert_null(rule->arg[2]); /* AND at top level */

    struct CRuleNode *left = (struct CRuleNode*)rule->arg[0];
    assert_non_null(left);
    assert_ptr_equal(left->funcptr, crule__andor);
    assert_non_null(left->arg[2]); /* OR */
    crule_free(&rule);
}

static void test_parse_nested_parentheses(void **state)
{
    (void)state;
    struct CRuleNode *rule;

    rule = crule_parse("((directop()))");
    assert_non_null(rule);
    assert_ptr_equal(rule->funcptr, crule_directop);
    crule_free(&rule);
}

/* ========== Error Handling Tests ========== */

static void test_parse_unknown_function(void **state)
{
    (void)state;
    struct CRuleNode *rule;

    rule = crule_parse("unknownfunc()");
    assert_null(rule);
}

static void test_parse_wrong_arg_count(void **state)
{
    (void)state;
    struct CRuleNode *rule;

    /* directop takes 0 args */
    rule = crule_parse("directop(extra)");
    assert_null(rule);

    /* connected takes 1 arg */
    rule = crule_parse("connected()");
    assert_null(rule);

    /* via takes 2 args */
    rule = crule_parse("via(only.one)");
    assert_null(rule);
}

static void test_parse_unclosed_paren(void **state)
{
    (void)state;
    struct CRuleNode *rule;

    rule = crule_parse("(directop()");
    assert_null(rule);

    rule = crule_parse("directop(");
    assert_null(rule);
}

static void test_parse_unexpected_token(void **state)
{
    (void)state;
    struct CRuleNode *rule;

    rule = crule_parse("directop())");
    assert_null(rule);

    rule = crule_parse("directop() &&");
    assert_null(rule);

    rule = crule_parse("directop() ||");
    assert_null(rule);
}

static void test_parse_invalid_characters(void **state)
{
    (void)state;
    struct CRuleNode *rule;

    rule = crule_parse("@invalid");
    assert_null(rule);

    /* Single & is invalid */
    rule = crule_parse("directop() & connected(*)");
    assert_null(rule);

    /* Single | is invalid */
    rule = crule_parse("directop() | connected(*)");
    assert_null(rule);
}

/* ========== Whitespace Handling Tests ========== */

static void test_parse_extra_whitespace(void **state)
{
    (void)state;
    struct CRuleNode *rule;

    rule = crule_parse("  directop(  )  ");
    assert_non_null(rule);
    assert_ptr_equal(rule->funcptr, crule_directop);
    crule_free(&rule);

    rule = crule_parse("directop()  &&  connected(*)");
    assert_non_null(rule);
    assert_ptr_equal(rule->funcptr, crule__andor);
    crule_free(&rule);
}

static void test_parse_tabs(void **state)
{
    (void)state;
    struct CRuleNode *rule;

    rule = crule_parse("\tdirectop()\t&&\tconnected(*)\t");
    assert_non_null(rule);
    crule_free(&rule);
}

/* ========== Colon Terminator Tests ========== */

static void test_parse_colon_terminator(void **state)
{
    (void)state;
    struct CRuleNode *rule;

    rule = crule_parse("directop():extra stuff ignored");
    assert_non_null(rule);
    assert_ptr_equal(rule->funcptr, crule_directop);
    crule_free(&rule);
}

/* ========== Wildcard Pattern Tests ========== */

static void test_parse_wildcard_patterns(void **state)
{
    (void)state;
    struct CRuleNode *rule;

    rule = crule_parse("connected(*.net)");
    assert_non_null(rule);
    assert_string_equal((char*)rule->arg[0], "*.net");
    crule_free(&rule);

    rule = crule_parse("connected(irc?.example.com)");
    assert_non_null(rule);
    assert_string_equal((char*)rule->arg[0], "irc?.example.com");
    crule_free(&rule);

    /* Use separate string to avoid trigraph warning */
    rule = crule_parse("connected(irc*.example.net)");
    assert_non_null(rule);
    assert_string_equal((char*)rule->arg[0], "irc*.example.net");
    crule_free(&rule);
}

static void test_parse_hostname_patterns(void **state)
{
    (void)state;
    struct CRuleNode *rule;

    rule = crule_parse("connected(irc.server.example.com)");
    assert_non_null(rule);
    assert_string_equal((char*)rule->arg[0], "irc.server.example.com");
    crule_free(&rule);

    rule = crule_parse("connected(irc-server.example-net.com)");
    assert_non_null(rule);
    assert_string_equal((char*)rule->arg[0], "irc-server.example-net.com");
    crule_free(&rule);
}

/* ========== Evaluation Tests ========== */

static void test_eval_functions_return_zero(void **state)
{
    (void)state;
    struct CRuleNode *rule;
    int result;

    /* All rule functions return 0 in test mode */
    rule = crule_parse("directop()");
    assert_non_null(rule);
    result = crule_eval(rule);
    assert_int_equal(result, 0);
    crule_free(&rule);

    /* NOT of 0 is 1 */
    rule = crule_parse("!directop()");
    assert_non_null(rule);
    result = crule_eval(rule);
    assert_int_equal(result, 1);
    crule_free(&rule);

    /* 0 && 0 = 0 */
    rule = crule_parse("directop() && connected(*)");
    assert_non_null(rule);
    result = crule_eval(rule);
    assert_int_equal(result, 0);
    crule_free(&rule);

    /* 0 || 0 = 0 */
    rule = crule_parse("directop() || connected(*)");
    assert_non_null(rule);
    result = crule_eval(rule);
    assert_int_equal(result, 0);
    crule_free(&rule);

    /* !0 || 0 = 1 */
    rule = crule_parse("!directop() || connected(*)");
    assert_non_null(rule);
    result = crule_eval(rule);
    assert_int_equal(result, 1);
    crule_free(&rule);
}

/* ========== Complex Expression Tests ========== */

static void test_parse_complex_expression(void **state)
{
    (void)state;
    struct CRuleNode *rule;

    rule = crule_parse("!directop() || !connected(hub.*)");
    assert_non_null(rule);
    crule_free(&rule);

    rule = crule_parse("(directop() || connected(hub.*)) && !connected(leaf.*)");
    assert_non_null(rule);
    crule_free(&rule);
}

static void test_parse_via_with_wildcards(void **state)
{
    (void)state;
    struct CRuleNode *rule;

    rule = crule_parse("via(hub.*.net, *.leaf.*)");
    assert_non_null(rule);
    assert_ptr_equal(rule->funcptr, crule_via);
    assert_int_equal(rule->numargs, 2);
    assert_string_equal((char*)rule->arg[0], "hub.*.net");
    assert_string_equal((char*)rule->arg[1], "*.leaf.*");
    crule_free(&rule);
}

/* ========== Main ========== */

int main(void)
{
    const struct CMUnitTest tests[] = {
        /* Basic parsing */
        cmocka_unit_test(test_parse_empty_rule),
        cmocka_unit_test(test_parse_simple_function_no_args),
        cmocka_unit_test(test_parse_simple_function_one_arg),
        cmocka_unit_test(test_parse_simple_function_two_args),
        cmocka_unit_test(test_parse_directcon),

        /* NOT operator */
        cmocka_unit_test(test_parse_not_operator),
        cmocka_unit_test(test_parse_double_not),

        /* AND operator */
        cmocka_unit_test(test_parse_and_operator),
        cmocka_unit_test(test_parse_chained_and),

        /* OR operator */
        cmocka_unit_test(test_parse_or_operator),
        cmocka_unit_test(test_parse_chained_or),

        /* Precedence */
        cmocka_unit_test(test_parse_and_or_precedence),
        cmocka_unit_test(test_parse_parentheses_override),
        cmocka_unit_test(test_parse_nested_parentheses),

        /* Error handling */
        cmocka_unit_test(test_parse_unknown_function),
        cmocka_unit_test(test_parse_wrong_arg_count),
        cmocka_unit_test(test_parse_unclosed_paren),
        cmocka_unit_test(test_parse_unexpected_token),
        cmocka_unit_test(test_parse_invalid_characters),

        /* Whitespace */
        cmocka_unit_test(test_parse_extra_whitespace),
        cmocka_unit_test(test_parse_tabs),

        /* Colon terminator */
        cmocka_unit_test(test_parse_colon_terminator),

        /* Wildcards */
        cmocka_unit_test(test_parse_wildcard_patterns),
        cmocka_unit_test(test_parse_hostname_patterns),

        /* Evaluation */
        cmocka_unit_test(test_eval_functions_return_zero),

        /* Complex expressions */
        cmocka_unit_test(test_parse_complex_expression),
        cmocka_unit_test(test_parse_via_with_wildcards),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
