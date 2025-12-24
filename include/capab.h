#ifndef INCLUDED_capab_h
#define INCLUDED_capab_h
/*
 * IRC - Internet Relay Chat, include/capab.h
 * Copyright (C) 2004 Kevin L. Mitchell <klmitch@mit.edu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
/** @file
 * @brief Interface and public definitions for capabilities extension
 * @version $Id: capab.h 1349 2005-04-05 01:46:05Z entrope $
 */

/* Forward declaration for function prototype */
struct Client;

/** Number of bits in an unsigned long. */
#ifndef FLAGSET_NBITS
#define FLAGSET_NBITS (8 * sizeof(unsigned long))
#endif
/** Index for a flag in the bits array. */
#ifndef FLAGSET_INDEX
#define FLAGSET_INDEX(flag) ((flag) / FLAGSET_NBITS)
#endif
/** Element bit for flag. */
#ifndef FLAGSET_MASK
#define FLAGSET_MASK(flag) (1ul<<((flag) % FLAGSET_NBITS))
#endif
/** Declare a flagset structure of a particular size. */
#ifndef DECLARE_FLAGSET
#define DECLARE_FLAGSET(name,max) \
  struct name \
  { \
    unsigned long bits[((max + FLAGSET_NBITS - 1) / FLAGSET_NBITS)]; \
  }
#endif

/** Test whether a flag is set in a flagset. */
#ifndef FlagHas
#define FlagHas(set,flag) ((set)->bits[FLAGSET_INDEX(flag)] & FLAGSET_MASK(flag))
#endif
/** Set a flag in a flagset. */
#ifndef FlagSet
#define FlagSet(set,flag) ((set)->bits[FLAGSET_INDEX(flag)] |= FLAGSET_MASK(flag))
#endif
/** Clear a flag in a flagset. */
#ifndef FlagClr
#define FlagClr(set,flag) ((set)->bits[FLAGSET_INDEX(flag)] &= ~FLAGSET_MASK(flag))
#endif

#define CAPFL_HIDDEN	0x0001	/**< Do not advertize this capability */
#define CAPFL_PROHIBIT	0x0002	/**< Client may not set this capability */
#define CAPFL_PROTO	0x0004	/**< Cap must be acknowledged by client */
#define CAPFL_STICKY    0x0008  /**< Cap may not be cleared once set */

#define CAPLIST	\
	_CAP(USERPFX, 0, "undernet.org/userpfx")

/** Client capabilities */
enum Capab {
#define _CAP(cap, flags, name, feat)	CAP_ ## cap
  _CAP(NONE, CAPFL_HIDDEN|CAPFL_PROHIBIT, "none", 0),
  _CAP(NAMESX, 0, "multi-prefix", 0),
  _CAP(UHNAMES, 0, "userhost-in-names", 0),
  _CAP(EXTJOIN, 0, "extended-join", 0),
  _CAP(AWAYNOTIFY, 0, "away-notify", 0),
  _CAP(ACCNOTIFY, 0, "account-notify", 0),
  _CAP(SASL, 0, "sasl", 0),
  _CAP(CAPNOTIFY, 0, "cap-notify", 0),
  _CAP(SERVERTIME, 0, "server-time", 0),
  _CAP(ECHOMSG, 0, "echo-message", 0),
  _CAP(ACCOUNTTAG, 0, "account-tag", 0),
  _CAP(CHGHOST, 0, "chghost", 0),
  _CAP(INVITENOTIFY, 0, "invite-notify", 0),
  _CAP(LABELEDRESP, 0, "labeled-response", 0),
  _CAP(BATCH, 0, "batch", 0),
  _CAP(SETNAME, 0, "setname", 0),
  _CAP(STANDARDREPLIES, 0, "standard-replies", 0),
  _CAP(DRAFT_NOIMPLICITNAMES, 0, "draft/no-implicit-names", 0),
  _CAP(DRAFT_EXTISUPPORT, 0, "draft/extended-isupport", 0),
  _CAP(DRAFT_PREAWAY, 0, "draft/pre-away", 0),
  _CAP(DRAFT_MULTILINE, 0, "draft/multiline", 0),
  _CAP(DRAFT_CHATHISTORY, 0, "draft/chathistory", 0),
  _CAP(DRAFT_EVENTPLAYBACK, 0, "draft/event-playback", 0),
  _CAP(DRAFT_REDACT, 0, "draft/message-redaction", 0),
  _CAP(DRAFT_ACCOUNTREG, 0, "draft/account-registration", 0),
  _CAP(DRAFT_READMARKER, 0, "draft/read-marker", 0),
  _CAP(DRAFT_CHANRENAME, 0, "draft/channel-rename", 0),
  _CAP(DRAFT_METADATA2, 0, "draft/metadata-2", 0),
#ifdef USE_SSL
  _CAP(TLS, 0, "tls", 0),
#endif
/*  CAPLIST, */
#undef _CAP
  _CAP_LAST_CAP
};

DECLARE_FLAGSET(CapSet, _CAP_LAST_CAP);

#define CapHas(cs, cap)	FlagHas(cs, cap)
#define CapSet(cs, cap)	FlagSet(cs, cap)
#define CapClr(cs, cap)	FlagClr(cs, cap)

extern void client_check_caps(struct Client *client, struct Client *replyto);

#endif /* INCLUDED_capab_h */
