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
  _CAP(MSGTAGS, 0, "message-tags", 0),
  _CAP(NOIMPLICITNAMES, 0, "no-implicit-names", 0),
  _CAP(NOIMPLICITNAMES_LEGACY, 0, "draft/no-implicit-names", 0),
  _CAP(DRAFT_EXTISUPPORT, 0, "draft/extended-isupport", 0),
  _CAP(DRAFT_PREAWAY, 0, "draft/pre-away", 0),
  _CAP(DRAFT_MULTILINE, 0, "draft/multiline", 0),
  _CAP(DRAFT_CHATHISTORY, 0, "draft/chathistory", 0),
  _CAP(SOJU_SEARCH, 0, "soju.im/search", 0),
  _CAP(DRAFT_EVENTPLAYBACK, 0, "draft/event-playback", 0),
  _CAP(DRAFT_REDACT, 0, "draft/message-redaction", 0),
  _CAP(DRAFT_ACCOUNTREG, 0, "draft/account-registration", 0),
  _CAP(DRAFT_READMARKER, 0, "draft/read-marker", 0),
  _CAP(DRAFT_CHANRENAME, 0, "draft/channel-rename", 0),
  _CAP(EVILNET_RELOCATE, 0, "evilnet.github.io/channel-relocate", 0),
  _CAP(DRAFT_METADATA2, 0, "draft/metadata-2", 0),
  _CAP(DRAFT_WEBPUSH, 0, "draft/webpush", 0),
  _CAP(DRAFT_AUTHTOKEN, 0, "draft/authtoken", 0),
  _CAP(EVILNET_PERSISTENCE, 0, "evilnet.github.io/persistence", 0),
  _CAP(DRAFT_PERSISTENCE, 0, "draft/persistence", 0),
  _CAP(DRAFT_OPERTAG, 0, "draft/oper-tag", 0),
#ifdef USE_SSL
  _CAP(TLS, 0, "tls", 0),
  _CAP(STS, CAPFL_PROHIBIT, "sts", 0),
#endif
/*  CAPLIST, */
#undef _CAP
  _CAP_LAST_CAP
};

DECLARE_FLAGSET(CapSet, _CAP_LAST_CAP);

#define CapHas(cs, cap)	FlagHas(cs, cap)
#define CapSet(cs, cap)	FlagSet(cs, cap)
#define CapClr(cs, cap)	FlagClr(cs, cap)

/** Bitwise OR two CapSets: dst |= src. */
#define CapSetOR(dst, src) \
  do { \
    unsigned int _i; \
    for (_i = 0; _i < sizeof((dst)->bits)/sizeof((dst)->bits[0]); _i++) \
      (dst)->bits[_i] |= (src)->bits[_i]; \
  } while (0)

/** The CAP version from which a connection gets CAP 302's features: cap
 * values, cap-notify implied, SASL 3.2 (AUTHENTICATE after registration). */
#define CAP_VERSION_302 302

/** A connection's CAP version once it has sent "CAP LS [<version>]" with
 * \a arg as its version (NULL or "": none), when it was \a current: the
 * highest version it ever sent.  The capability-negotiation spec presumes a
 * client that sent CAP LS 302 supports 302's features for the life of the
 * connection, so a later CAP LS with no version, a lower one or one that is
 * not a positive number leaves it as it was.  The number is read as atoi()
 * reads it (an optional '+', then digits; what follows them is ignored),
 * and one past the field's range is its highest value, never one that
 * wrapped around. */
static inline unsigned short cap_version_after_ls(unsigned short current,
                                                  const char *arg)
{
  unsigned long v = 0;

  if (!arg)
    return current;
  if (*arg == '+')
    arg++;
  for (; *arg >= '0' && *arg <= '9'; arg++)
    if ((v = v * 10 + (unsigned long)(*arg - '0')) > 65535)
      v = 65535;
  return v > current ? (unsigned short)v : current;
}

/** Whether a connection at CAP \a version may not turn \a cap off: the
 * capability-negotiation spec enables cap-notify implicitly for a client
 * that sent CAP LS 302, and that client cannot disable it.  CAP REQ
 * :-cap-notify is refused (NAK), and CAP CLEAR leaves it, as for a sticky
 * capability. */
static inline int cap_kept_on(int cap, unsigned short version)
{
  return cap == CAP_CAPNOTIFY && version >= CAP_VERSION_302;
}

extern void client_check_caps(struct Client *client, struct Client *replyto);
extern int cap_lookup(const char **caplist_p, int *neg_p, int *cap_out, unsigned long *flags_out);

/* The sasl capability's current value (mechanism list), or NULL: what CAP
 * LS advertises, and what RPL_SASLMECHS (908) lists. */
extern const char *cap_sasl_mechanisms(void);

/* Whether CAP LS offers the sasl capability. */
extern int cap_sasl_offered(void);

/* IRCv3 cap-notify: send CAP NEW/DEL notifications to clients */
extern void send_cap_notify(const char *capname, int available, const char *value);

/* Overwrite a capability's advertised CAP 302 value at runtime (the value is
 * copied).  NULL/"" advertises the capability with no value. */
extern void cap_set_value(enum Capab cap, const char *value);

/* Feature-notify hook (ircd_features.c table): rebuilds the
 * draft/account-registration CAP value from FEAT_REGISTER_VERIFY_EMAIL.
 * Defined in m_register.c. */
extern void feature_notify_accountreg_capvalue(void);
extern void feature_notify_cap_accountreg(void);

/* Feature-notify hooks for evilnet.github.io/persistence, draft/persistence
 * and PERSISTENCE_DRAFT_EXTRAS: each keeps the caps' CAP 302 values in step
 * and tells cap-notify clients.  Defined in m_persistence.c. */
extern void feature_notify_cap_evilnet_persistence(void);
extern void feature_notify_cap_draft_persistence(void);
extern void feature_notify_persistence_draft_extras(void);

/* CAP notify batching for rehash - aggregates multiple CAP NEW/DEL into single messages */
extern void cap_notify_begin_batch(void);
extern void cap_notify_flush(void);

#endif /* INCLUDED_capab_h */
