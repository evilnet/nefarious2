/*
 * IRC - Internet Relay Chat, ircd/m_mdbx.c
 * Copyright (C) 2026 Afternet Development
 *
 * MDBX database administration command for IRC operators.
 *
 * Usage: /MDBX <subcommand> [target]
 *
 * Subcommands:
 *   DEFRAG [history|metadata|all]  - Defragment databases (default: all)
 *   SYNC   [history|metadata|all]  - Force flush to disk (default: all)
 *   GC     [history|metadata]      - Garbage collection info
 *   INFO   [history|metadata]      - Detailed environment info
 *
 * Requires PRIV_REHASH privilege.
 */
#include "config.h"

#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "history.h"
#include "metadata.h"
#include "msg.h"
#include "numeric.h"
#include "s_debug.h"
#include "send.h"

#include <string.h>

/* Forward declarations for subcommand handlers */
static int mo_mdbx_defrag(struct Client *sptr, const char *target);
static int mo_mdbx_sync(struct Client *sptr, const char *target);
static int mo_mdbx_gc(struct Client *sptr, const char *target);
static int mo_mdbx_info(struct Client *sptr, const char *target);

/*
 * mo_mdbx - oper message handler
 *
 * parv[0] = sender prefix
 * parv[1] = subcommand (DEFRAG, SYNC, GC, INFO)
 * parv[2] = target (history, metadata, all) - optional, defaults to "all"
 */
int mo_mdbx(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  const char *subcmd;
  const char *target;

  if (!HasPriv(sptr, PRIV_REHASH))
    return send_reply(sptr, ERR_NOPRIVILEGES);

  if (parc < 2) {
    send_reply(sptr, SND_EXPLICIT | RPL_STATSDEBUG,
               "X :Usage: MDBX <DEFRAG|SYNC|GC|INFO> [history|metadata|all]");
    return 0;
  }

  subcmd = parv[1];
  target = (parc >= 3) ? parv[2] : "all";

  if (0 == ircd_strcmp(subcmd, "DEFRAG")) {
    return mo_mdbx_defrag(sptr, target);
  } else if (0 == ircd_strcmp(subcmd, "SYNC")) {
    return mo_mdbx_sync(sptr, target);
  } else if (0 == ircd_strcmp(subcmd, "GC")) {
    return mo_mdbx_gc(sptr, target);
  } else if (0 == ircd_strcmp(subcmd, "INFO")) {
    return mo_mdbx_info(sptr, target);
  } else {
    send_reply(sptr, SND_EXPLICIT | RPL_STATSDEBUG,
               "X :Unknown subcommand: %s", subcmd);
    send_reply(sptr, SND_EXPLICIT | RPL_STATSDEBUG,
               "X :Usage: MDBX <DEFRAG|SYNC|GC|INFO> [history|metadata|all]");
    return 0;
  }
}

/* ========== DEFRAG ========== */

static int
mo_mdbx_defrag(struct Client *sptr, const char *target)
{
  int do_history = (0 == ircd_strcmp(target, "all") || 0 == ircd_strcmp(target, "history"));
  int do_metadata = (0 == ircd_strcmp(target, "all") || 0 == ircd_strcmp(target, "metadata"));

  if (!do_history && !do_metadata) {
    send_reply(sptr, SND_EXPLICIT | RPL_STATSDEBUG,
               "X :DEFRAG: unknown target '%s' (use: history, metadata, all)", target);
    return 0;
  }

  send_reply(sptr, SND_EXPLICIT | RPL_STATSDEBUG,
             "X :MDBX DEFRAG starting (5s limit per db)...");

  sendto_opmask_butone(0, SNO_OLDSNO,
                        "%C is running MDBX DEFRAG on %s", sptr, target);

  if (do_history)
    history_report_defrag(sptr);
  if (do_metadata)
    metadata_report_defrag(sptr);

  send_reply(sptr, SND_EXPLICIT | RPL_STATSDEBUG,
             "X :MDBX DEFRAG complete");
  return 0;
}

/* ========== SYNC ========== */

static int
mo_mdbx_sync(struct Client *sptr, const char *target)
{
  int do_history = (0 == ircd_strcmp(target, "all") || 0 == ircd_strcmp(target, "history"));
  int do_metadata = (0 == ircd_strcmp(target, "all") || 0 == ircd_strcmp(target, "metadata"));
  int rc;

  if (!do_history && !do_metadata) {
    send_reply(sptr, SND_EXPLICIT | RPL_STATSDEBUG,
               "X :SYNC: unknown target '%s' (use: history, metadata, all)", target);
    return 0;
  }

  send_reply(sptr, SND_EXPLICIT | RPL_STATSDEBUG,
             "X :MDBX SYNC starting...");

  if (do_history) {
    rc = history_sync();
    send_reply(sptr, SND_EXPLICIT | RPL_STATSDEBUG,
               "X :  History: %s", rc == 0 ? "synced" : "failed or unavailable");
  }

  if (do_metadata) {
    rc = metadata_sync();
    send_reply(sptr, SND_EXPLICIT | RPL_STATSDEBUG,
               "X :  Metadata: %s", rc == 0 ? "synced" : "failed or unavailable");
  }

  send_reply(sptr, SND_EXPLICIT | RPL_STATSDEBUG,
             "X :MDBX SYNC complete");
  return 0;
}

/* ========== GC ========== */

static int
mo_mdbx_gc(struct Client *sptr, const char *target)
{
  int do_history = (0 == ircd_strcmp(target, "all") || 0 == ircd_strcmp(target, "history"));
  int do_metadata = (0 == ircd_strcmp(target, "all") || 0 == ircd_strcmp(target, "metadata"));

  if (!do_history && !do_metadata) {
    send_reply(sptr, SND_EXPLICIT | RPL_STATSDEBUG,
               "X :GC: unknown target '%s' (use: history, metadata, all)", target);
    return 0;
  }

  send_reply(sptr, SND_EXPLICIT | RPL_STATSDEBUG,
             "X :MDBX GC Information");

  if (do_history)
    history_report_gc(sptr);
  if (do_metadata)
    metadata_report_gc(sptr);

  return 0;
}

/* ========== INFO ========== */

static int
mo_mdbx_info(struct Client *sptr, const char *target)
{
  int do_history = (0 == ircd_strcmp(target, "all") || 0 == ircd_strcmp(target, "history"));
  int do_metadata = (0 == ircd_strcmp(target, "all") || 0 == ircd_strcmp(target, "metadata"));

  if (!do_history && !do_metadata) {
    send_reply(sptr, SND_EXPLICIT | RPL_STATSDEBUG,
               "X :INFO: unknown target '%s' (use: history, metadata, all)", target);
    return 0;
  }

  send_reply(sptr, SND_EXPLICIT | RPL_STATSDEBUG,
             "X :MDBX Environment Info");

  if (do_history)
    history_report_mdbx_info(sptr);
  if (do_metadata)
    metadata_report_mdbx_info(sptr);

  return 0;
}
