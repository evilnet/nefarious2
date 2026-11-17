/*
 * redact_judge_stubs.c - what m_redact.o links against and redact_judge_cmocka
 * never reaches: the command handlers' sends, the channel lookups, the
 * features.  Kept apart from the test, out of reach of the headers that
 * declare them; each fails the case if called.
 */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>
#include <time.h>

time_t CurrentTime;
/* struct CapRouteContext (send.h): never read here; room enough for it. */
char cap_route_ctx[4096];

#define NEVER(name) \
  int name(void) { fail_msg(#name " called"); return 0; }
NEVER(feature_bool)
NEVER(feature_int)
NEVER(find_member_link)
NEVER(forward_history_write)
NEVER(generate_msgid)
NEVER(hSeekChannel)
NEVER(history_attach_context)
NEVER(history_event_time_ms)
NEVER(history_format_ms)
NEVER(history_forward_encode)
NEVER(history_owner_of)
NEVER(history_parse_ms)
NEVER(need_more_params)
NEVER(send_fail)
NEVER(sendcmdto_one_event)
NEVER(sendcmdto_serv_butone_v3)
NEVER(sendcmdto_set_client_event)
NEVER(sendcmdto_set_client_msgid)
NEVER(sendcmdto_set_s2s_tags)
NEVER(sendcmdto_want_s2s_tags)
NEVER(start_redact_fed_query)
