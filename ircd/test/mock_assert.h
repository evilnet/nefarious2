/* mock_assert.h - route assert() to CMocka's mock_assert().
 *
 * Force-included (-include) when a test compiles an ircd source file
 * whose asserts it wants to observe: a failed assert then fails the test
 * that hit it (or satisfies expect_assert_failure()), instead of aborting
 * the whole test program.  ircd_log.h only defines assert() when it is
 * not defined yet, so this one wins; a source that pulls in the system
 * <assert.h> afterwards would undo it, which the ipcheck test checks.
 */
#ifndef INCLUDED_mock_assert_h
#define INCLUDED_mock_assert_h

extern void mock_assert(const int result, const char* const expression,
                        const char * const file, const int line);

#undef assert
#define assert(expression) \
  mock_assert((int)(!!(expression)), #expression, __FILE__, __LINE__)

#endif /* INCLUDED_mock_assert_h */
