/* events_assert.h - assert() for the event core under ircd_events_cmocka.
 *
 * Force-included (-include) when ircd_events_cmocka compiles
 * ../ircd_events.c, as mock_assert.h is for IPcheck.c.  A failed assert
 * goes to the test's events_assert().  That fails the case through CMocka's
 * mock_assert(), so expect_assert_failure() sees it -- or, in a case that
 * runs the core as a release build would, counts the assert and returns, so
 * the code goes on past it as it does with assert() compiled out (NDEBUG).
 * ircd_log.h only defines assert() when it is not defined yet, so this one
 * wins.
 */
#ifndef INCLUDED_events_assert_h
#define INCLUDED_events_assert_h

extern void events_assert(int ok, const char *expression, const char *file,
                          int line);

#undef assert
#define assert(expression) \
  events_assert(!!(expression), #expression, __FILE__, __LINE__)

#endif /* INCLUDED_events_assert_h */
