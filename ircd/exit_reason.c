/*
 * IRC - Internet Relay Chat, ircd/exit_reason.c
 *
 * Which realnames are dead_link()'s old clobber.  Pure: no ircd
 * dependencies, so the CMocka suite links it without the server.
 */
#include "exit_reason.h"

#include <string.h>

int exit_reason_is_clobbered_info(const char *info)
{
  /* dead_link() (send.c) wrote these three into cli_info until 2026-10;
   * "Write error: " carries strerror()/the OpenSSL reason after it. */
  static const char write_error[] = "Write error: ";

  if (!info || !*info)
    return 0;
  if (0 == strncmp(info, write_error, sizeof(write_error) - 1)
      && info[sizeof(write_error) - 1] != '\0')
    return 1;
  return 0 == strcmp(info, "Max sendQ exceeded")
         || 0 == strcmp(info, "Buffer allocation error");
}
