/*
 * ircd_parser.y: A yacc/bison parser for ircd config files.
 * This is part of ircu, an Internet Relay Chat server.
 * The contents of this file are Copyright 2001 Diane Bruce,
 * Andrew Miller, the ircd-hybrid team and the ircu team.
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307,
 *  USA.
 * $Id: ircd_parser.y 1907 2009-02-09 04:11:04Z entrope $
 */
%{

#include "config.h"
#include "s_conf.h"
#include "class.h"
#include "client.h"
#include "crule.h"
#include "ircd_features.h"
#include "fileio.h"
#include "gline.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_chattr.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "list.h"
#include "listener.h"
#include "match.h"
#include "motd.h"
#include "numeric.h"
#include "numnicks.h"
#include "opercmds.h"
#include "parse.h"
#include "res.h"
#include "s_auth.h"
#include "s_bsd.h"
#include "s_conf.h"
#include "s_debug.h"
#include "dnsbl.h"
#include "s_misc.h"
#include "send.h"
#include "struct.h"
#include "sys.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#define MAX_STRINGS 80 /* Maximum number of feature params. */
#define USE_IPV4 (1 << 16)
#define USE_IPV6 (1 << 17)

extern int init_lexer_file(char* file);

  extern struct LocalConf   localConf;
  extern struct DenyConf*   denyConfList;
  extern struct CRuleConf*  cruleConfList;
  extern struct ServerConf* serverConfList;
  extern struct s_map*      GlobalServiceMapList;
  extern struct qline*      GlobalQuarantineList;
  extern struct WebIRCConf* webircConfList;
  extern struct SHostConf*  shostConfList;
  extern struct ExceptConf* exceptConfList;

  int yylex(void);
  /* Now all the globals we need :/... */
  unsigned int snomask;
  int fakelagmin;
  int fakelagfactor;
  int tping, tconn, maxlinks, sendq, recvq, port, invert, stringno, flags;
  int maxchans, redirport, hidehostcomps;
  char *name, *pass, *host, *from_host, *ip, *username, *origin, *hub_limit;
  char *spoofhost, *sslfp, *sslciphers, *description, *redirserver;
  char *country, *continent, *ajoinchan, *ajoinnotice, *swhois;
  struct SLink *hosts;
  char *stringlist[MAX_STRINGS];
  struct ListenerFlags listen_flags;
  struct ConnectionClass *c_class;
  struct DenyConf *dconf;
  struct s_map *smap;
  struct Privs privs;
  struct Privs privs_dirty;
  struct WebIRCFlags wflags;
  struct ClassRestrictFlags crestrict;
  /* DNSBL block parsing globals */
  char *dnsbl_domain, *dnsbl_index, *dnsbl_mark;
  unsigned int dnsbl_bitmask;
  int dnsbl_action, dnsbl_score;

static void parse_error(char *pattern,...) {
  static char error_buffer[1024];
  va_list vl;
  va_start(vl,pattern);
  ircd_vsnprintf(NULL, error_buffer, sizeof(error_buffer), pattern, vl);
  va_end(vl);
  yyerror(error_buffer);
}

static void free_slist(struct SLink **link) {
  struct SLink *next;
  while (*link != NULL) {
    next = (*link)->next;
    MyFree((*link)->value.cp);
    free_link(*link);
    *link = next;
  }
}

%}

%token <text> QSTRING
%token <num> NUMBER

%token GENERAL
%token ADMIN
%token LOCATION
%token CONTACT
%token CONNECT
%token CLASS
%token CHANNEL
%token PINGFREQ
%token CONNECTFREQ
%token MAXLINKS
%token MAXHOPS
%token SENDQ
%token RECVQ
%token NAME
%token HOST
%token FROM
%token IP
%token USERNAME
%token PASS
%token LOCAL
%token SECONDS
%token MINUTES
%token HOURS
%token DAYS
%token WEEKS
%token MONTHS
%token YEARS
%token DECADES
%token BYTES
%token KBYTES
%token MBYTES
%token GBYTES
%token TBYTES
%token SERVER
%token PORT
%token MASK
%token HUB
%token LEAF
%token UWORLD
%token YES
%token NO
%token OPER
%token VHOST
%token HIDDEN
%token MOTD
%token JUPE
%token NICK
%token NUMERIC
%token DESCRIPTION
%token CLIENT
%token KILL
%token CRULE
%token REAL
%token REASON
%token TFILE
%token RULE
%token ALL
%token FEATURES
%token QUARANTINE
%token PSEUDO
%token PREPEND
%token USERMODE
%token IAUTH
%token TIMEOUT
%token FAST
%token AUTOCONNECT
%token PROGRAM
%token TOK_IPV4 TOK_IPV6
%token DNS
%token FORWARDS
%token WEBIRC
%token DNSBL
%token BITMASK
%token SCORE
%token ACTION
%token BLOCK_ALL
%token BLOCK_ANON
%token WHITELIST
%token IDENT
%token USERIDENT
%token IGNOREIDENT
%token STRIPSSLFP
%token MAXCHANS
%token COUNTRY
%token CONTINENT
%token VERSION
%token SPOOFHOST
%token AUTOAPPLY
%token SNOMASK
%token EXCEPT
%token SHUN
%token KLINE
%token GLINE
%token ZLINE
%token RDNS
%token IPCHECK
%token TARGETLIMIT
%token LISTDELAY
%token NOIDENTTILDE
%token ISMASK
%token REDIRECT
%token HIDEHOSTCOMPONANTS
%token HIDEHOSTCOMPONENTS
%token AUTOJOINCHANNEL
%token AUTOJOINNOTICE
%token AUTHEXEMPT
%token MARK
%token RESTRICT_JOIN
%token RESTRICT_PRIVMSG
%token RESTRICT_UMODE
%token MATCHUSERNAME
%token FAKELAGMINIMUM
%token FAKELAGFACTOR
%token DEFAULTTEXT
%token SSLFP
%token SSLCIPHERS
%token INCLUDE
%token SSLTOK
%token SWHOIS
%token ENABLEOPTIONS
%token TRUSTACCOUNT
/* and now a lot of privileges... */
%token TPRIV_CHAN_LIMIT TPRIV_MODE_LCHAN TPRIV_DEOP_LCHAN TPRIV_WALK_LCHAN
%token TPRIV_LOCAL_KILL TPRIV_REHASH TPRIV_RESTART TPRIV_GITSYNC TPRIV_DIE
%token TPRIV_LOCAL_GLINE TPRIV_LOCAL_JUPE TPRIV_LOCAL_BADCHAN
%token TPRIV_LOCAL_OPMODE TPRIV_OPMODE TPRIV_SET TPRIV_WHOX TPRIV_BADCHAN
%token TPRIV_SEE_CHAN TPRIV_SHOW_INVIS TPRIV_SHOW_ALL_INVIS TPRIV_PROPAGATE
%token TPRIV_UNLIMIT_QUERY TPRIV_DISPLAY TPRIV_SEE_OPERS TPRIV_WIDE_GLINE
%token TPRIV_FORCE_OPMODE TPRIV_FORCE_LOCAL_OPMODE TPRIV_APASS_OPMODE
%token TPRIV_LIST_CHAN TPRIV_CHECK TPRIV_WHOIS_NOTICE TPRIV_HIDE_OPER
%token TPRIV_HIDE_CHANNELS TPRIV_HIDE_IDLE TPRIV_XTRAOP TPRIV_SERVICE
%token TPRIV_REMOTE TPRIV_LOCAL_SHUN TPRIV_WIDE_SHUN
%token TPRIV_FREEFORM TPRIV_REMOTEREHASH TPRIV_REMOVE TPRIV_LOCAL_ZLINE
%token TPRIV_WIDE_ZLINE TPRIV_TEMPSHUN
/* and some types... */
%type <num> sizespec
%type <num> timespec timefactor factoredtimes factoredtime
%type <num> expr yesorno privtype address_family
%left '+' '-'
%left '*' '/'

%union{
 char *text;
 int num;
}

%%
/* Blocks in the config file... */
blocks: blocks block | block;
block: adminblock | generalblock | classblock | connectblock |
       uworldblock | operblock | portblock | jupeblock | clientblock |
       killblock | cruleblock | motdblock | featuresblock | quarantineblock |
       pseudoblock | iauthblock | forwardsblock | webircblock | spoofhostblock |
       exceptblock | dnsblblock | include | error ';';

/* The timespec, sizespec and expr was ripped straight from
 * ircd-hybrid-7. */
timespec: expr | factoredtimes;

factoredtimes: factoredtimes factoredtime
{
  $$ = $1 + $2;
} | factoredtime;

factoredtime: expr timefactor
{
  $$ = $1 * $2;
};

timefactor: SECONDS { $$ = 1; }
| MINUTES { $$ = 60; }
| HOURS { $$ = 60 * 60; }
| DAYS { $$ = 60 * 60 * 24; }
| WEEKS { $$ = 60 * 60 * 24 * 7; }
| MONTHS { $$ = 60 * 60 * 24 * 7 * 4; }
| YEARS { $$ = 60 * 60 * 24 * 365; }
| DECADES { $$ = 60 * 60 * 24 * 365 * 10; };


sizespec:	expr	{
			$$ = $1;
		}
		| expr BYTES  { 
			$$ = $1;
		}
		| expr KBYTES {
			$$ = $1 * 1024;
		}
		| expr MBYTES {
			$$ = $1 * 1024 * 1024;
		}
		| expr GBYTES {
			$$ = $1 * 1024 * 1024 * 1024;
		}
		| expr TBYTES {
			$$ = $1 * 1024 * 1024 * 1024;
		}
		;

/* this is an arithmetic expression */
expr: NUMBER
		{ 
			$$ = $1;
		}
		| expr '+' expr { 
			$$ = $1 + $3;
		}
		| expr '-' expr { 
			$$ = $1 - $3;
		}
		| expr '*' expr { 
			$$ = $1 * $3;
		}
		| expr '/' expr { 
			$$ = $1 / $3;
		}
/* leave this out until we find why it makes BSD yacc dump core -larne
		| '-' expr  %prec NEG {
			$$ = -$2;
		} */
		| '(' expr ')' {
			$$ = $2;
		}
		;

jupeblock: JUPE '{' jupeitems '}' ';' ;
jupeitems: jupeitem jupeitems | jupeitem;
jupeitem: jupenick;
jupenick: NICK '=' QSTRING ';'
{
  addNickJupes($3);
  MyFree($3);
};

generalblock: GENERAL
{
    /* Zero out the vhost addresses, in case they were removed. */
    memset(&VirtualHost_v4.addr, 0, sizeof(VirtualHost_v4.addr));
    memset(&VirtualHost_v6.addr, 0, sizeof(VirtualHost_v6.addr));
} '{' generalitems '}' ';' {
  if (localConf.name == NULL)
    parse_error("Your General block must contain a name.");
  if (localConf.numeric == 0)
    parse_error("Your General block must contain a numeric (between 1 and 4095).");
};
generalitems: generalitem generalitems | generalitem;
generalitem: generalnumeric | generalname | generalvhost | generaldesc
  | generaldnsvhost | generaldnsserver;

generalnumeric: NUMERIC '=' NUMBER ';'
{
  if (localConf.numeric == 0)
    localConf.numeric = $3;
  else if (localConf.numeric != $3)
    parse_error("Redefinition of server numeric %i (%i)", $3,
    		localConf.numeric);
};

generalname: NAME '=' QSTRING ';'
{
  if (localConf.name == NULL)
    localConf.name = $3;
  else {
    if (strcmp(localConf.name, $3))
      parse_error("Redefinition of server name %s (%s)", $3,
                  localConf.name);
    MyFree($3);
  }
};

generaldesc: DESCRIPTION '=' QSTRING ';'
{
  MyFree(localConf.description);
  localConf.description = $3;
  ircd_strncpy(cli_info(&me), $3, REALLEN + 1);
};

generalvhost: VHOST '=' QSTRING ';'
{
  struct irc_in_addr addr;
  char *vhost = $3;

  if (!strcmp(vhost, "*")) {
    /* This traditionally meant bind to all interfaces and connect
     * from the default. */
  } else if (!ircd_aton(&addr, vhost))
    parse_error("Invalid virtual host '%s'.", vhost);
  else if (irc_in_addr_is_ipv4(&addr))
    memcpy(&VirtualHost_v4.addr, &addr, sizeof(addr));
  else
    memcpy(&VirtualHost_v6.addr, &addr, sizeof(addr));
  MyFree(vhost);
};

generaldnsvhost: DNS VHOST '=' address_family QSTRING ';'
{
  struct irc_in_addr addr;
  int families = $4;
  char *vhost = $5;

  if (!strcmp(vhost, "*")) {
    /* Let the operating system assign the default. */
  } else if (!ircd_aton(&addr, vhost))
    parse_error("Invalid DNS virtual host '%s'.", vhost);
  else
  {
    if ((families & USE_IPV4)
        || (!families && irc_in_addr_is_ipv4(&addr)))
      memcpy(&VirtualHost_dns_v4.addr, &addr, sizeof(addr));
    if ((families & USE_IPV6)
        || (!families && !irc_in_addr_is_ipv4(&addr)))
      memcpy(&VirtualHost_dns_v6.addr, &addr, sizeof(addr));
  }
  MyFree(vhost);
};

generaldnsserver: DNS SERVER '=' QSTRING ';'
{
  char *server = $4;

  add_nameserver(server);
  MyFree(server);
};

adminblock: ADMIN
{
  MyFree(localConf.location1);
  MyFree(localConf.location2);
  MyFree(localConf.contact);
  localConf.location1 = localConf.location2 = localConf.contact = NULL;
}
'{' adminitems '}' ';'
{
  if (localConf.location1 == NULL)
    DupString(localConf.location1, "");
  if (localConf.location2 == NULL)
    DupString(localConf.location2, "");
  if (localConf.contact == NULL)
    DupString(localConf.contact, "");
};
adminitems: adminitems adminitem | adminitem;
adminitem: adminlocation | admincontact;
adminlocation: LOCATION '=' QSTRING ';'
{
  if (localConf.location1 == NULL)
    localConf.location1 = $3;
  else if (localConf.location2 == NULL)
    localConf.location2 = $3;
  else /* Otherwise just drop it. -A1kmm */
    MyFree($3);
};
admincontact: CONTACT '=' QSTRING ';'
{
 MyFree(localConf.contact);
 localConf.contact = $3;
};

classblock: CLASS {
  tping = 90;
  snomask = 0;
  fakelagmin = -1;
  fakelagfactor = -1;
  memset(&crestrict, 0, sizeof(crestrict));
} '{' classitems '}' ';'
{
  if (name != NULL)
  {
    struct ConnectionClass *c_class;
    add_class(name, tping, tconn, maxlinks, sendq, recvq);
    c_class = find_class(name);
    MyFree(c_class->default_umode);
    c_class->default_umode = pass;
    MyFree(c_class->autojoinchan);
    c_class->autojoinchan = ajoinchan;
    MyFree(c_class->autojoinnotice);
    c_class->autojoinnotice = ajoinnotice;
    c_class->snomask = snomask;
    c_class->lag_min = fakelagmin;
    c_class->lag_factor = fakelagfactor;
    c_class->max_chans = maxchans;
    memcpy(&c_class->privs, &privs, sizeof(c_class->privs));
    memcpy(&c_class->privs_dirty, &privs_dirty, sizeof(c_class->privs_dirty));
    memcpy(&c_class->restrictflags, &crestrict, sizeof(c_class->restrictflags));
  }
  else {
   parse_error("Missing name in class block");
  }
  name = NULL;
  pass = NULL;
  ajoinchan = NULL;
  ajoinnotice = NULL;
  tconn = 0;
  maxlinks = 0;
  sendq = 0;
  recvq = 0;
  maxchans = 0;
  snomask = 0;
  memset(&privs, 0, sizeof(privs));
  memset(&privs_dirty, 0, sizeof(privs_dirty));
  memset(&crestrict, 0, sizeof(crestrict));
};
classitems: classitem classitems | classitem;
classitem: classname | classpingfreq | classconnfreq | classmaxlinks |
           classsendq | classrecvq | classusermode | classmaxchans | priv |
           classsnomask | classajoinchan | classajoinnotice | classrestrictjoin |
           classrestrictpm | classrestrictumode | classfakelagmin | classfakelagfactor;
classname: NAME '=' QSTRING ';'
{
  MyFree(name);
  name = $3;
};
classpingfreq: PINGFREQ '=' timespec ';'
{
  tping = $3;
};
classconnfreq: CONNECTFREQ '=' timespec ';'
{
  tconn = $3;
};
classmaxlinks: MAXLINKS '=' expr ';'
{
  maxlinks = $3;
};
classsendq: SENDQ '=' sizespec ';'
{
  sendq = $3;
};
classrecvq: RECVQ '=' sizespec ';'
{
  recvq = $3;
};
classusermode: USERMODE '=' QSTRING ';'
{
  MyFree(pass);
  pass = $3;
};
classmaxchans: MAXCHANS '=' expr ';'
{
  maxchans = $3;
};
classsnomask: SNOMASK '=' expr ';'
{
  snomask = $3;
};
classfakelagmin: FAKELAGMINIMUM '=' expr ';'
{
  fakelagmin = $3;
};
classfakelagfactor: FAKELAGFACTOR '=' expr ';'
{
  fakelagfactor = $3;
};
classajoinchan: AUTOJOINCHANNEL '=' QSTRING ';'
{
  MyFree(ajoinchan);
  ajoinchan = $3;
};
classajoinnotice: AUTOJOINNOTICE '=' QSTRING ';'
{
  MyFree(ajoinnotice);
  ajoinnotice = $3;
};
classrestrictjoin: RESTRICT_JOIN '=' YES ';'
{
  FlagSet(&crestrict, CRFLAG_JOIN);
} | RESTRICT_JOIN '=' NO ';'
{
  FlagClr(&crestrict, CRFLAG_JOIN);
};
classrestrictpm: RESTRICT_PRIVMSG '=' YES ';'
{
  FlagSet(&crestrict, CRFLAG_PRIVMSG);
} | RESTRICT_PRIVMSG '=' NO ';'
{
  FlagClr(&crestrict, CRFLAG_PRIVMSG);
};
classrestrictumode: RESTRICT_UMODE '=' YES ';'
{
  FlagSet(&crestrict, CRFLAG_UMODE);
} | RESTRICT_UMODE '=' NO ';'
{
  FlagClr(&crestrict, CRFLAG_UMODE);
};

connectblock: CONNECT
{
 flags = CONF_AUTOCONNECT;
} '{' connectitems '}' ';'
{
 struct ConfItem *aconf = NULL;
 if (name == NULL)
  parse_error("Missing name in connect block");
 else if (pass == NULL)
  parse_error("Missing password in connect block");
 else if (strlen(pass) > PASSWDLEN)
  parse_error("Password too long in connect block");
 else if (host == NULL)
  parse_error("Missing host in connect block");
 else if (strchr(host, '*') || strchr(host, '?'))
  parse_error("Invalid host '%s' in connect block (use 'from' field for wildcard patterns)", host);
 else if (c_class == NULL)
  parse_error("Missing or non-existent class in connect block");
 else {
   aconf = make_conf(CONF_SERVER);
   aconf->name = name;
   aconf->origin_name = origin;
   aconf->passwd = pass;
   aconf->sslfp = sslfp;
   aconf->sslciphers = sslciphers;
   aconf->conn_class = c_class;
   aconf->address.port = port;
   aconf->host = host;
   /* Set from_host for incoming connection validation.
    * If not specified, default to host value for backward compatibility.
    */
   if (from_host) {
     unsigned char addrbits;
     aconf->from_host = from_host;
     /* Try to parse as IP mask */
     if (ipmask_parse(from_host, &aconf->from_address, &addrbits)) {
       aconf->from_addrbits = addrbits;
     } else {
       aconf->from_addrbits = -1;
     }
   } else {
     /* Default: use host for both outbound and inbound */
     DupString(aconf->from_host, host);
     aconf->from_addrbits = -1;
   }
   /* If the user specified a hub allowance, but not maximum links,
    * allow an effectively unlimited number of hops.
    */
   aconf->maximum = (hub_limit != NULL && maxlinks == 0) ? 65535 : maxlinks;
   aconf->hub_limit = hub_limit;
   aconf->flags = flags;
   lookup_confhost(aconf);
 }
 if (!aconf) {
   MyFree(name);
   MyFree(pass);
   MyFree(sslfp);
   MyFree(sslciphers);
   MyFree(host);
   MyFree(from_host);
   MyFree(origin);
   MyFree(hub_limit);
 }
 name = pass = host = from_host = origin = hub_limit = NULL;
 c_class = NULL;
 sslfp = sslciphers = NULL;
 port = flags = maxlinks = 0;
};
connectitems: connectitem connectitems | connectitem;
connectitem: connectname | connectpass | connectclass | connecthost | connectfrom
              | connectport | connectvhost | connectleaf | connecthub
              | connecthublimit | connectmaxhops | connectauto | connectssl
              | connectsslfp | connectsslciphers;
connectname: NAME '=' QSTRING ';'
{
 MyFree(name);
 name = $3;
};
connectpass: PASS '=' QSTRING ';'
{
 MyFree(pass);
 pass = $3;
};
connectclass: CLASS '=' QSTRING ';'
{
 c_class = find_class($3);
 if (!c_class)
  parse_error("No such connection class '%s' for Connect block", $3);
 MyFree($3);
};
connecthost: HOST '=' QSTRING ';'
{
 MyFree(host);
 host = $3;
};
connectfrom: FROM '=' QSTRING ';'
{
 MyFree(from_host);
 from_host = $3;
};
connectport: PORT '=' NUMBER ';'
{
 port = $3;
};
connectvhost: VHOST '=' QSTRING ';'
{
 MyFree(origin);
 origin = $3;
};
connectleaf: LEAF ';'
{
 maxlinks = 0;
};
connecthub: HUB ';'
{
 MyFree(hub_limit);
 DupString(hub_limit, "*");
};
connecthublimit: HUB '=' QSTRING ';'
{
 MyFree(hub_limit);
 hub_limit = $3;
};
connectmaxhops: MAXHOPS '=' expr ';'
{
  maxlinks = $3;
};
connectauto: AUTOCONNECT '=' YES ';' { flags |= CONF_AUTOCONNECT; }
 | AUTOCONNECT '=' NO ';' { flags &= ~CONF_AUTOCONNECT; };
connectssl: SSLTOK '=' YES ';'
{
#ifdef USE_SSL
  flags |= CONF_SSL;
#else
  parse_error("Connect block has SSL enabled but I'm not built with SSL.  Check ./configure syntax/output.");
  flags &= ~CONF_SSL;
#endif /* USE_SSL */
} | SSLTOK '=' NO ';' { flags &= ~CONF_SSL; };
connectsslfp: SSLFP '=' QSTRING ';'
{
  MyFree(sslfp);
  sslfp = $3;
};
connectsslciphers: SSLCIPHERS '=' QSTRING ';'
{
  MyFree(sslciphers);
  sslciphers = $3;
};

uworldblock: UWORLD '{' uworlditems '}' ';';
uworlditems: uworlditem uworlditems | uworlditem;
uworlditem: uworldname;
uworldname: NAME '=' QSTRING ';'
{
  make_conf(CONF_UWORLD)->host = $3;
};

operblock: OPER
{
  snomask = 0;
} '{' operitems '}' ';'
{
  struct ConfItem *aconf = NULL;
  struct SLink *link;

  if (name == NULL)
    parse_error("Missing name in operator block");
  else if (pass == NULL)
    parse_error("Missing password in operator block");
  /* Do not check password length because it may be crypted. */
  else if (hosts == NULL)
    parse_error("Missing host(s) in operator block");
  else if (c_class == NULL)
    parse_error("Invalid or missing class in operator block");
  else if (!FlagHas(&privs_dirty, PRIV_PROPAGATE)
           && !FlagHas(&c_class->privs_dirty, PRIV_PROPAGATE))
    parse_error("Operator block for %s and class %s have no LOCAL setting", name, c_class->cc_name);
  else for (link = hosts; link != NULL; link = link->next) {
    aconf = make_conf(CONF_OPERATOR);
    DupString(aconf->name, name);
    DupString(aconf->passwd, pass);
    if (sslfp)
      DupString(aconf->sslfp, sslfp);
    if (ajoinchan)
      DupString(aconf->autojoinchan, ajoinchan);
    if (ajoinnotice)
      DupString(aconf->autojoinnotice, ajoinnotice);
    if (swhois)
      DupString(aconf->swhois, swhois);
    conf_parse_userhost(aconf, link->value.cp);
    aconf->conn_class = c_class;
    aconf->snomask = snomask;
    memcpy(&aconf->privs, &privs, sizeof(aconf->privs));
    memcpy(&aconf->privs_dirty, &privs_dirty, sizeof(aconf->privs_dirty));
  }
  MyFree(name);
  MyFree(pass);
  MyFree(sslfp);
  MyFree(ajoinchan);
  MyFree(ajoinnotice);
  MyFree(swhois);
  free_slist(&hosts);
  name = pass = NULL;
  c_class = NULL;
  memset(&privs, 0, sizeof(privs));
  memset(&privs_dirty, 0, sizeof(privs_dirty));
};
operitems: operitem | operitems operitem;
operitem: opername | operpass | operhost | operclass | opersslfp | opersnomask
           | operajoinchan | operajoinnotice | operswhois | priv;
opername: NAME '=' QSTRING ';'
{
  MyFree(name);
  name = $3;
};
operpass: PASS '=' QSTRING ';'
{
  MyFree(pass);
  pass = $3;
};
operhost: HOST '=' QSTRING ';'
{
 struct SLink *link;
 link = make_link();
 if (!strchr($3, '@'))
 {
   int uh_len;
   link->value.cp = (char*) MyMalloc((uh_len = strlen($3)+3));
   ircd_snprintf(0, link->value.cp, uh_len, "*@%s", $3);
 }
 else
   DupString(link->value.cp, $3);
 MyFree($3);
 link->next = hosts;
 hosts = link;
};
operclass: CLASS '=' QSTRING ';'
{
 c_class = find_class($3);
 if (!c_class)
  parse_error("No such connection class '%s' for Operator block", $3);
 MyFree($3);
};
opersslfp: SSLFP '=' QSTRING ';'
{
  MyFree(sslfp);
  sslfp = $3;
};
opersnomask: SNOMASK '=' expr ';'
{
  snomask = $3;
};
operajoinchan: AUTOJOINCHANNEL '=' QSTRING ';'
{
  MyFree(ajoinchan);
  ajoinchan = $3;
};
operajoinnotice: AUTOJOINNOTICE '=' QSTRING ';'
{
  MyFree(ajoinnotice);
  ajoinnotice = $3;
};
operswhois: SWHOIS '=' QSTRING ';'
{
  MyFree(swhois);
  swhois = $3;
};

priv: privtype '=' yesorno ';'
{
  FlagSet(&privs_dirty, $1);
  if (($3 == 1) ^ invert)
    FlagSet(&privs, $1);
  else
    FlagClr(&privs, $1);
  invert = 0;
};

privtype: TPRIV_CHAN_LIMIT { $$ = PRIV_CHAN_LIMIT; } |
          TPRIV_MODE_LCHAN { $$ = PRIV_MODE_LCHAN; } |
          TPRIV_DEOP_LCHAN { $$ = PRIV_DEOP_LCHAN; } |
          TPRIV_WALK_LCHAN { $$ = PRIV_WALK_LCHAN; } |
          KILL { $$ = PRIV_KILL; } |
          TPRIV_LOCAL_KILL { $$ = PRIV_LOCAL_KILL; } |
          TPRIV_REHASH { $$ = PRIV_REHASH; } |
          TPRIV_RESTART { $$ = PRIV_RESTART; } |
          TPRIV_GITSYNC { $$ = PRIV_GITSYNC; } |
          TPRIV_DIE { $$ = PRIV_DIE; } |
          GLINE { $$ = PRIV_GLINE; } |
          TPRIV_LOCAL_GLINE { $$ = PRIV_LOCAL_GLINE; } |
          JUPE { $$ = PRIV_JUPE; } |
          TPRIV_LOCAL_JUPE { $$ = PRIV_LOCAL_JUPE; } |
          TPRIV_LOCAL_OPMODE { $$ = PRIV_LOCAL_OPMODE; } |
          TPRIV_OPMODE { $$ = PRIV_OPMODE; }|
          TPRIV_SET { $$ = PRIV_SET; } |
          TPRIV_WHOX { $$ = PRIV_WHOX; } |
          TPRIV_BADCHAN { $$ = PRIV_BADCHAN; } |
          TPRIV_LOCAL_BADCHAN { $$ = PRIV_LOCAL_BADCHAN; } |
          TPRIV_SEE_CHAN { $$ = PRIV_SEE_CHAN; } |
          TPRIV_SHOW_INVIS { $$ = PRIV_SHOW_INVIS; } |
          TPRIV_SHOW_ALL_INVIS { $$ = PRIV_SHOW_ALL_INVIS; } |
          TPRIV_PROPAGATE { $$ = PRIV_PROPAGATE; } |
          TPRIV_UNLIMIT_QUERY { $$ = PRIV_UNLIMIT_QUERY; } |
          TPRIV_DISPLAY { $$ = PRIV_DISPLAY; } |
          TPRIV_SEE_OPERS { $$ = PRIV_SEE_OPERS; } |
          TPRIV_WIDE_GLINE { $$ = PRIV_WIDE_GLINE; } |
          TPRIV_LIST_CHAN { $$ = PRIV_LIST_CHAN; } |
          LOCAL { $$ = PRIV_PROPAGATE; invert = 1; } |
          TPRIV_FORCE_OPMODE { $$ = PRIV_FORCE_OPMODE; } |
          TPRIV_FORCE_LOCAL_OPMODE { $$ = PRIV_FORCE_LOCAL_OPMODE; } |
          TPRIV_APASS_OPMODE { $$ = PRIV_APASS_OPMODE; } |
          TPRIV_CHECK { $$ = PRIV_CHECK; } |
          TPRIV_WHOIS_NOTICE { $$ = PRIV_WHOIS_NOTICE; } |
          TPRIV_HIDE_OPER { $$ = PRIV_HIDE_OPER; } |
          TPRIV_HIDE_CHANNELS { $$ = PRIV_HIDE_CHANNELS; } |
          TPRIV_HIDE_IDLE { $$ = PRIV_HIDE_IDLE; } |
          ADMIN { $$ = PRIV_ADMIN; } |
          TPRIV_XTRAOP { $$ = PRIV_XTRAOP; } |
          TPRIV_SERVICE { $$ = PRIV_SERVICE; } |
          TPRIV_REMOTE { $$ = PRIV_REMOTE; } |
          SHUN { $$ = PRIV_SHUN; } |
          TPRIV_LOCAL_SHUN { $$ = PRIV_LOCAL_SHUN; } |
          TPRIV_WIDE_SHUN { $$ = PRIV_WIDE_SHUN; } |
          TPRIV_FREEFORM { $$ = PRIV_FREEFORM; } |
          TPRIV_REMOTEREHASH { $$ = PRIV_REMOTEREHASH; } |
          TPRIV_REMOVE { $$ = PRIV_REMOVE; } |
          ZLINE { $$ = PRIV_ZLINE; } |
          TPRIV_LOCAL_ZLINE { $$ = PRIV_LOCAL_ZLINE; } |
          TPRIV_WIDE_ZLINE { $$ = PRIV_WIDE_ZLINE; } |
          TPRIV_TEMPSHUN { $$ = PRIV_TEMPSHUN; };

yesorno: YES { $$ = 1; } | NO { $$ = 0; };

/* not a recursive definition because some pedant will just come along
 * and whine that the parser accepts "ipv4 ipv4 ipv4 ipv4"
 */
address_family:
               { $$ = 0; }
    | TOK_IPV4 { $$ = USE_IPV4; }
    | TOK_IPV6 { $$ = USE_IPV6; }
    | TOK_IPV4 TOK_IPV6 { $$ = USE_IPV4 | USE_IPV6; }
    | TOK_IPV6 TOK_IPV4 { $$ = USE_IPV6 | USE_IPV4; }
    ;

/* The port block... */
portblock: PORT '{' portitems '}' ';' {
  struct ListenerFlags flags_here;
  struct SLink *link;
  if (hosts == NULL) {
    struct SLink *link;
    link = make_link();
    DupString(link->value.cp, "*");
    link->flags = 0;
    link->next = hosts;
    hosts = link;
  }
  for (link = hosts; link != NULL; link = link->next) {
    memcpy(&flags_here, &listen_flags, sizeof(flags_here));
    switch (link->flags & (USE_IPV4 | USE_IPV6)) {
    case USE_IPV4:
      FlagSet(&flags_here, LISTEN_IPV4);
      break;
    case USE_IPV6:
      FlagSet(&flags_here, LISTEN_IPV6);
      break;
    default: /* 0 or USE_IPV4|USE_IPV6 */
      FlagSet(&flags_here, LISTEN_IPV4);
      FlagSet(&flags_here, LISTEN_IPV6);
      break;
    }
    if (link->flags & 65535)
      port = link->flags & 65535;
    add_listener(port, link->value.cp, pass, &flags_here);
  }
  free_slist(&hosts);
  MyFree(pass);
  memset(&listen_flags, 0, sizeof(listen_flags));
  pass = NULL;
  port = 0;
};
portitems: portitem portitems | portitem;
portitem: portnumber | portvhost | portvhostnumber | portmask | portserver | porthidden | portssl;
portnumber: PORT '=' address_family NUMBER ';'
{
  if ($4 < 1 || $4 > 65535) {
    parse_error("Port %d is out of range", port);
  } else {
    port = $3 | $4;
    if (hosts && (0 == (hosts->flags & 65535)))
      hosts->flags = (hosts->flags & ~65535) | port;
  }
};

portvhost: VHOST '=' address_family QSTRING ';'
{
  struct SLink *link;
  link = make_link();
  link->value.cp = $4;
  link->flags = $3 | port;
  link->next = hosts;
  hosts = link;
};

portvhostnumber: VHOST '=' address_family QSTRING NUMBER ';'
{
  if ($5 < 1 || $5 > 65535) {
    parse_error("Port %d is out of range", port);
  } else {
    struct SLink *link;
    link = make_link();
    link->value.cp = $4;
    link->flags = $3 | $5;
    link->next = hosts;
    hosts = link;
  }
};

portmask: MASK '=' QSTRING ';'
{
  MyFree(pass);
  pass = $3;
};

portserver: SERVER '=' YES ';'
{
  FlagSet(&listen_flags, LISTEN_SERVER);
} | SERVER '=' NO ';'
{
  FlagClr(&listen_flags, LISTEN_SERVER);
};

porthidden: HIDDEN '=' YES ';'
{
  FlagSet(&listen_flags, LISTEN_HIDDEN);
} | HIDDEN '=' NO ';'
{
  FlagClr(&listen_flags, LISTEN_HIDDEN);
};

portssl: SSLTOK '=' YES ';'
{
#ifdef USE_SSL
  FlagSet(&listen_flags, LISTEN_SSL);
#else
  parse_error("Port block has SSL enabled but I'm not built with SSL.  Check ./configure syntax/output.");
  FlagClr(&listen_flags, LISTEN_SSL);
#endif /* USE_SSL */
} | SSLTOK '=' NO ';'
{
  FlagClr(&listen_flags, LISTEN_SSL);
}

clientblock: CLIENT
{
  maxlinks = 65535;
  port = 0;
  flags = CONF_NOIDENTTILDE;
  redirport = 0;
  hidehostcomps = -1;
}
'{' clientitems '}' ';'
{
  struct ConfItem *aconf = 0;
  struct irc_in_addr addr;
  unsigned char addrbits = 0;

  if (!c_class)
    parse_error("Invalid or missing class in Client block");
  else if (pass && strlen(pass) > PASSWDLEN)
    parse_error("Password too long in connect block");
  else if (ip && !ipmask_parse(ip, &addr, &addrbits))
    parse_error("Invalid IP address %s in Client block", ip);
  else {
    aconf = make_conf(CONF_CLIENT);
    aconf->username = username;
    aconf->host = host;
    if (ip)
      memcpy(&aconf->address.addr, &addr, sizeof(aconf->address.addr));
    else
      memset(&aconf->address.addr, 0, sizeof(aconf->address.addr));
    aconf->address.port = port;
    aconf->addrbits = addrbits;
    aconf->name = ip;
    aconf->conn_class = c_class;
    aconf->maximum = maxlinks;
    aconf->passwd = pass;
    aconf->sslfp = sslfp;
    aconf->countrymask = country;
    aconf->continentmask = continent;
    aconf->redirserver = redirserver;
    aconf->redirport = redirport;
    aconf->flags = flags;
    aconf->hidehostcomps = hidehostcomps;
    aconf->autojoinchan = ajoinchan;
    aconf->autojoinnotice = ajoinnotice;
  }
  if (!aconf) {
    MyFree(username);
    MyFree(host);
    MyFree(ip);
    MyFree(pass);
    MyFree(country);
    MyFree(continent);
    MyFree(sslfp);
    MyFree(redirserver);
    MyFree(ajoinchan);
    MyFree(ajoinnotice);
  }
  host = NULL;
  username = NULL;
  c_class = NULL;
  maxlinks = 0;
  ip = NULL;
  pass = NULL;
  sslfp = NULL;
  port = 0;
  country = NULL;
  continent = NULL;
  redirport = 0;
  redirserver = NULL;
  hidehostcomps = 0;
  ajoinchan = NULL;
  ajoinnotice = NULL;
};
clientitems: clientitem clientitems | clientitem;
clientitem: clienthost | clientip | clientusername | clientclass | clientpass
            | clientmaxlinks | clientport | clientcountry | clientcontinent
            | clientsslfp | clientnoidenttilde | clientredir | clienthidehostcomps
            | clientajoinchan | clientajoinnotice;
clienthost: HOST '=' QSTRING ';'
{
  char *sep = strchr($3, '@');
  MyFree(host);
  if (sep) {
    *sep++ = '\0';
    MyFree(username);
    DupString(host, sep);
    username = $3;
  } else {
    host = $3;
  }
};
clientip: IP '=' QSTRING ';'
{
  char *sep;
  sep = strchr($3, '@');
  MyFree(ip);
  if (sep) {
    *sep++ = '\0';
    MyFree(username);
    DupString(ip, sep);
    username = $3;
  } else {
    ip = $3;
  }
};
clientusername: USERNAME '=' QSTRING ';'
{
  MyFree(username);
  username = $3;
};
clientclass: CLASS '=' QSTRING ';'
{
  c_class = find_class($3);
  if (!c_class)
    parse_error("No such connection class '%s' for Client block", $3);
  MyFree($3);
};
clientpass: PASS '=' QSTRING ';'
{
  MyFree(pass);
  pass = $3;
};
clientmaxlinks: MAXLINKS '=' expr ';'
{
  maxlinks = $3;
};
clientport: PORT '=' expr ';'
{
  port = $3;
};
clientcountry: COUNTRY '=' QSTRING ';'
{
  MyFree(country);
  country = $3;
};
clientcontinent: CONTINENT '=' QSTRING ';'
{
  MyFree(continent);
  continent = $3;
};
clientsslfp: SSLFP '=' QSTRING ';'
{
  MyFree(sslfp);
  sslfp = $3;
};
clientnoidenttilde: NOIDENTTILDE '=' YES ';'
{
  if (!username)
    DupString(username, "*");
  flags |= CONF_NOIDENTTILDE;
} | NOIDENTTILDE '=' NO ';'
{
  flags &= ~CONF_NOIDENTTILDE;
};
clientredir: REDIRECT '=' QSTRING expr ';'
{
  redirport = $4;
  MyFree(redirserver);
  redirserver = $3;
} | REDIRECT '=' QSTRING ';'
{
  redirport = 6667;
  MyFree(redirserver);
  redirserver = $3;
};
clienthidehostcomps: HIDEHOSTCOMPONANTS '=' expr ';'
{
  log_write(LS_CONFIG, L_WARNING, 0, "Field \"hidehostcomponants\" deprecated, "
            "use \"hosthidecomponents\"");
  hidehostcomps = $3;
} | HIDEHOSTCOMPONENTS '=' expr ';'
{
  hidehostcomps = $3;
};
clientajoinchan: AUTOJOINCHANNEL '=' QSTRING ';'
{
  MyFree(ajoinchan);
  ajoinchan = $3;
};
clientajoinnotice: AUTOJOINNOTICE '=' QSTRING ';'
{
  MyFree(ajoinnotice);
  ajoinnotice = $3;
};

killblock: KILL
{
  dconf = (struct DenyConf*) MyCalloc(1, sizeof(*dconf));
} '{' killitems '}' ';'
{
  if (dconf->usermask || dconf->hostmask || dconf->realmask ||
      dconf->countrymask || dconf->continentmask || dconf->version) {
    dconf->next = denyConfList;
    denyConfList = dconf;
  }
  else
  {
    MyFree(dconf->usermask);
    MyFree(dconf->hostmask);
    MyFree(dconf->realmask);
    MyFree(dconf->message);
    MyFree(dconf->countrymask);
    MyFree(dconf->continentmask);
    MyFree(dconf->version);
    MyFree(dconf->mark);
    MyFree(dconf);
    parse_error("Kill block must match on at least one of username, host, country, continent or realname");
  }
  dconf = NULL;
};
killitems: killitem killitems | killitem;
killitem: killuhost | killreal | killusername | killcountry | killcontinent | killreasonfile | killreason
                    | killversion | killauthexempt | killmark;
killuhost: HOST '=' QSTRING ';'
{
  char *h;
  MyFree(dconf->hostmask);
  MyFree(dconf->usermask);
  if ((h = strchr($3, '@')) == NULL)
  {
    DupString(dconf->usermask, "*");
    dconf->hostmask = $3;
  }
  else
  {
    *h++ = '\0';
    DupString(dconf->hostmask, h);
    dconf->usermask = $3;
  }
  ipmask_parse(dconf->hostmask, &dconf->address, &dconf->bits);
};

killusername: USERNAME '=' QSTRING ';'
{
  MyFree(dconf->usermask);
  dconf->usermask = $3;
};

killreal: REAL '=' QSTRING ';'
{
 MyFree(dconf->realmask);
 dconf->realmask = $3;
};

killcountry: COUNTRY '=' QSTRING ';'
{
  MyFree(dconf->countrymask);
  dconf->countrymask = $3;
};

killcontinent: CONTINENT '=' QSTRING ';'
{
  MyFree(dconf->continentmask);
  dconf->continentmask = $3;
};

killversion: VERSION '=' QSTRING ';'
{
  MyFree(dconf->version);
  dconf->version = $3;
};

killreason: REASON '=' QSTRING ';'
{
 dconf->flags &= ~DENY_FLAGS_FILE;
 MyFree(dconf->message);
 dconf->message = $3;
};

killreasonfile: TFILE '=' QSTRING ';'
{
 dconf->flags |= DENY_FLAGS_FILE;
 MyFree(dconf->message);
 dconf->message = $3;
};

killauthexempt: AUTHEXEMPT '=' YES ';'
{
  dconf->flags |= DENY_FLAGS_AUTHEX;
} | AUTHEXEMPT '=' NO ';'
{
  dconf->flags &= ~DENY_FLAGS_AUTHEX;
};

killmark: MARK '=' QSTRING ';'
{
 MyFree(dconf->mark);
 dconf->mark = $3;
};


cruleblock: CRULE
{
  tconn = CRULE_AUTO;
} '{' cruleitems '}' ';'
{
  struct CRuleNode *node = NULL;
  struct SLink *link;

  if (hosts == NULL)
    parse_error("Missing server(s) in crule block");
  else if (pass == NULL)
    parse_error("Missing rule in crule block");
  else if ((node = crule_parse(pass)) == NULL)
    parse_error("Invalid rule '%s' in crule block", pass);
  else for (link = hosts; link != NULL; link = link->next)
  {
    struct CRuleConf *p = (struct CRuleConf*) MyMalloc(sizeof(*p));
    if (node == NULL)
      node = crule_parse(pass);
    DupString(p->hostmask, link->value.cp);
    DupString(p->rule, pass);
    p->type = tconn;
    p->node = node;
    node = NULL;
    p->next = cruleConfList;
    cruleConfList = p;
  }
  free_slist(&hosts);
  MyFree(pass);
  pass = NULL;
  tconn = 0;
};

cruleitems: cruleitem cruleitems | cruleitem;
cruleitem: cruleserver | crulerule | cruleall;

cruleserver: SERVER '=' QSTRING ';'
{
  struct SLink *link;
  link = make_link();
  link->value.cp = $3;
  link->next = hosts;
  hosts = link;
};

crulerule: RULE '=' QSTRING ';'
{
 MyFree(pass);
 pass = $3;
};

cruleall: ALL '=' YES ';'
{
 tconn = CRULE_ALL;
} | ALL '=' NO ';'
{
 tconn = CRULE_AUTO;
};

motdblock: MOTD '{' motditems '}' ';'
{
  struct SLink *link;
  if (pass != NULL)
    for (link = hosts; link != NULL; link = link->next)
      motd_add(link->value.cp, pass, link->flags);
  free_slist(&hosts);
  MyFree(pass);
  pass = NULL;
};

motditems: motditem motditems | motditem;
motditem: motdhost | motdcountry | motdcontinent | motdfile;
motdhost: HOST '=' QSTRING ';'
{
  struct SLink *link;
  link = make_link();
  link->value.cp = $3;
  link->flags = 0;
  link->next = hosts;
  hosts = link;
};

motdcountry: COUNTRY '=' QSTRING ';'
{
  struct SLink *link;
  link = make_link();
  link->value.cp = $3;
  link->flags = MOTD_COUNTRY;
  link->next = hosts;
  hosts = link;
};

motdcontinent: CONTINENT '=' QSTRING ';'
{
  struct SLink *link;
  link = make_link();
  link->value.cp = $3;
  link->flags = MOTD_CONTINENT;
  link->next = hosts;
  hosts = link;
};

motdfile: TFILE '=' QSTRING ';'
{
  MyFree(pass);
  pass = $3;
};

featuresblock: FEATURES '{' featureitems '}' ';';
featureitems: featureitems featureitem | featureitem;

featureitem: QSTRING
{
  stringlist[0] = $1;
  stringno = 1;
} '=' stringlist ';' {
  unsigned int ii;
  feature_set(NULL, (const char * const *)stringlist, stringno);
  for (ii = 0; ii < stringno; ++ii)
    MyFree(stringlist[ii]);
};

stringlist: stringlist extrastring | extrastring;
extrastring: QSTRING
{
  if (stringno < MAX_STRINGS)
    stringlist[stringno++] = $1;
  else
    MyFree($1);
};

quarantineblock: QUARANTINE '{' quarantineitems '}' ';';
quarantineitems: quarantineitems quarantineitem | quarantineitem;
quarantineitem: QSTRING '=' QSTRING ';'
{
  struct qline *qconf = MyCalloc(1, sizeof(*qconf));
  qconf->chname = $1;
  qconf->reason = $3;
  qconf->next = GlobalQuarantineList;
  GlobalQuarantineList = qconf;
};

pseudoblock: PSEUDO QSTRING '{'
{
  smap = MyCalloc(1, sizeof(struct s_map));
  smap->command = $2;
}
pseudoitems '}' ';'
{
  int valid = 0;

  if (!smap->name)
    parse_error("Missing name in pseudo %s block", smap->command);
  else if (!smap->services)
    parse_error("Missing nick in pseudo %s block", smap->command);
  else if (!strIsIrcNk(smap->command))
    parse_error("Pseudo command %s invalid: must all be letters, numbers or any of {|}~[\\]^-_`", smap->command);
  else
    valid = 1;
  if (valid && register_mapping(smap))
  {
    smap->next = GlobalServiceMapList;
    GlobalServiceMapList = smap;
  }
  else
  {
    free_mapping(smap);
  }
  smap = NULL;
};

pseudoitems: pseudoitem pseudoitems | pseudoitem;
pseudoitem: pseudoname | pseudoprepend | pseudonick | pseudoflags
          | pseudodefault;
pseudoname: NAME '=' QSTRING ';'
{
  MyFree(smap->name);
  smap->name = $3;
};
pseudoprepend: PREPEND '=' QSTRING ';'
{
  MyFree(smap->prepend);
  smap->prepend = $3;
};
pseudodefault: DEFAULTTEXT '=' QSTRING ';'
{
  MyFree(smap->defaulttext);
  smap->defaulttext = $3;
};
pseudonick: NICK '=' QSTRING ';'
{
  char *sep = strchr($3, '@');

  if (sep != NULL) {
    size_t slen = strlen($3);
    struct nick_host *nh = MyMalloc(sizeof(*nh) + slen);
    memcpy(nh->nick, $3, slen + 1);
    nh->nicklen = sep - $3;
    nh->next = smap->services;
    smap->services = nh;
  }
  MyFree($3);
};
pseudoflags: FAST ';'
{
  smap->flags |= SMAP_FAST;
};

iauthblock: IAUTH '{' iauthitems '}' ';'
{
  auth_spawn(stringno, stringlist);
  while (stringno > 0)
  {
    --stringno;
    MyFree(stringlist[stringno]);
  }
};

iauthitems: iauthitem iauthitems | iauthitem;
iauthitem: iauthprogram;
iauthprogram: PROGRAM '='
{
  while (stringno > 0)
  {
    --stringno;
    MyFree(stringlist[stringno]);
  }
} stringlist ';';

forwardsblock: FORWARDS {
  unsigned int ii;
  for(ii = 0; ii < 256; ++ii) {
    MyFree(GlobalForwards[ii]);
  }
} '{' forwarditems '}' ';';
forwarditems: forwarditems forwarditem | forwarditem;
forwarditem: QSTRING '=' QSTRING ';'
{
  unsigned char ch = $1[0];
  MyFree(GlobalForwards[ch]);
  GlobalForwards[ch] = $3;
  MyFree($1);
};

webircblock: WEBIRC
{
  memset(&wflags, 0, sizeof(struct WebIRCFlags));
} '{' webircitems '}' ';'
{
  struct WebIRCConf *wconf;
  struct SLink *link;
  char *h;

  if (pass == NULL)
    parse_error("Missing password in webirc block");
  else for (link = hosts; link != NULL; link = link->next) {
    wconf = (struct WebIRCConf*) MyCalloc(1, sizeof(*wconf));
    if ((h = strchr(link->value.cp, '@')) == NULL) {
      DupString(wconf->usermask, "*");
      DupString(wconf->hostmask, link->value.cp);
    } else {
      *h++ = '\0';
      DupString(wconf->hostmask, h);
      DupString(wconf->usermask, link->value.cp);
    }
    ipmask_parse(wconf->hostmask, &wconf->address, &wconf->bits);

    memcpy(&wconf->flags, &wflags, sizeof(struct WebIRCFlags));
    DupString(wconf->passwd, pass);
    if (username != NULL)
      DupString(wconf->ident, username);
    if (description != NULL)
      DupString(wconf->description, description);

    wconf->next = webircConfList;
    webircConfList = wconf;
  }

  free_slist(&hosts);
  MyFree(pass);
  MyFree(username);
  MyFree(description);
  pass = username = description = NULL;
  memset(&wflags, 0, sizeof(struct WebIRCFlags));
  wconf = NULL;
};
webircitems: webircitem webircitems | webircitem;
webircitem: webircuhost | webircpass | webircident | webircuserident
          | webircignoreident | webircdescription | webircstripsslfp
          | webircenableoptions | webirctrustaccount;
webircuhost: HOST '=' QSTRING ';'
{
 struct SLink *link;
 link = make_link();
 if (!strchr($3, '@'))
 {
   int uh_len;
   link->value.cp = (char*) MyMalloc((uh_len = strlen($3)+3));
   ircd_snprintf(0, link->value.cp, uh_len, "*@%s", $3);
 }
 else
   DupString(link->value.cp, $3);
 MyFree($3);
 link->next = hosts;
 hosts = link;
};
webircpass: PASS '=' QSTRING ';'
{
  MyFree(pass);
  pass = $3;
};
webircident: IDENT '=' QSTRING ';'
{
  MyFree(username);
  username = $3;
};
webircuserident: USERIDENT '=' YES ';'
{
  FlagSet(&wflags, WFLAG_USERIDENT);
} | USERIDENT '=' NO ';'
{
  FlagClr(&wflags, WFLAG_USERIDENT);
};
webircignoreident: IGNOREIDENT '=' YES ';'
{
  FlagSet(&wflags, WFLAG_NOIDENT);
} | IGNOREIDENT '=' NO ';'
{
  FlagClr(&wflags, WFLAG_NOIDENT);
};
webircstripsslfp: STRIPSSLFP '=' YES ';'
{
  FlagSet(&wflags, WFLAG_STRIPSSLFP);
} | STRIPSSLFP '=' NO ';'
{
  FlagClr(&wflags, WFLAG_STRIPSSLFP);
};
webircenableoptions: ENABLEOPTIONS '=' YES ';'
{
  FlagSet(&wflags, WFLAG_USEOPTIONS);
} | ENABLEOPTIONS '=' NO ';'
{
  FlagClr(&wflags, WFLAG_USEOPTIONS);
};
webirctrustaccount: TRUSTACCOUNT '=' YES ';'
{
  FlagSet(&wflags, WFLAG_TRUSTACCOUNT);
} | TRUSTACCOUNT '=' NO ';'
{
  FlagClr(&wflags, WFLAG_TRUSTACCOUNT);
};
webircdescription: DESCRIPTION '=' QSTRING ';'
{
  MyFree(description);
  description = $3;
};

spoofhostblock : SPOOFHOST QSTRING
{
  flags = SHFLAG_NOPASS | SHFLAG_MATCHUSER;
  spoofhost = $2;
} '{' spoofhostitems '}' ';'
{
  struct SLink *link;
  struct SHostConf* sconf;
  char *h;

  if (flags & SHFLAG_ISMASK)
    flags &= ~SHFLAG_AUTOAPPLY;

  if (hosts == NULL)
    parse_error("Missing host(s) in spoofhost block");
  else if (spoofhost == NULL)
    parse_error("Missing spoofhost in spoofhost block");
  else for (link = hosts; link != NULL; link = link->next) {
    sconf = (struct SHostConf*) MyCalloc(1, sizeof(*sconf));
    if (!(flags & SHFLAG_NOPASS))
      DupString(sconf->passwd, pass);
    if ((h = strchr(link->value.cp, '@')) == NULL) {
      DupString(sconf->usermask, "*");
      DupString(sconf->hostmask, link->value.cp);
    } else {
      *h++ = '\0';
      DupString(sconf->hostmask, h);
      DupString(sconf->usermask, link->value.cp);
    }
    ipmask_parse(sconf->hostmask, &sconf->address, &sconf->bits);
    DupString(sconf->spoofhost, spoofhost);
    sconf->flags = flags;

    sconf->next = shostConfList;
    shostConfList = sconf;
  }
  MyFree(spoofhost);
  MyFree(pass);
  free_slist(&hosts);
  flags = 0;
}
spoofhostitems: spoofhostitem | spoofhostitems spoofhostitem;
spoofhostitem: spoofhosthost | spoofhostpass | spoofhostautoapply | spoofhostismask
             | spoofhostmatchuser;

spoofhosthost: HOST '=' QSTRING ';'
{
  struct SLink *link;
  link = make_link();
  if (!strchr($3, '@'))
  {
    int uh_len;
    link->value.cp = (char*) MyMalloc((uh_len = strlen($3)+3));
    ircd_snprintf(0, link->value.cp, uh_len, "*@%s", $3);
  }
  else
    DupString(link->value.cp, $3);
  MyFree($3);
  link->next = hosts;
  hosts = link;
};
spoofhostpass: PASS '=' QSTRING ';'
{
  MyFree(pass);
  pass = $3;
  flags &= ~SHFLAG_NOPASS;
};
spoofhostautoapply: AUTOAPPLY '=' YES ';'
{
  flags |= SHFLAG_AUTOAPPLY;
} | AUTOAPPLY '=' NO ';'
{
  flags &= ~SHFLAG_AUTOAPPLY;
};
spoofhostismask: ISMASK '=' YES ';'
{
  flags |= SHFLAG_ISMASK;
} | ISMASK '=' NO ';'
{
  flags &= ~SHFLAG_ISMASK;
};
spoofhostmatchuser: MATCHUSERNAME '=' YES ';'
{
  flags |= SHFLAG_MATCHUSER;
} | MATCHUSERNAME '=' NO ';'
{
  flags &= ~SHFLAG_MATCHUSER;
};

exceptblock: EXCEPT
{
  flags = 0;
} '{' exceptitems '}' ';'
{
  struct ExceptConf *econf;
  struct SLink *link;
  char *h;

  if (flags == 0)
    parse_error("Missing exemption type(s)");
  else for (link = hosts; link != NULL; link = link->next) {
    econf = (struct ExceptConf*) MyCalloc(1, sizeof(*econf));
    econf->flags = flags;

    if ((h = strchr(link->value.cp, '@')) == NULL) {
      econf->usermask = NULL;
      DupString(econf->hostmask, link->value.cp);
    } else {
      *h++ = '\0';
      DupString(econf->hostmask, h);
      DupString(econf->usermask, link->value.cp);
    }
    ipmask_parse(econf->hostmask, &econf->address, &econf->bits);

    econf->next = exceptConfList;
    exceptConfList = econf;
  }
  free_slist(&hosts);
  flags = 0;
};
exceptitems: exceptitem exceptitems | exceptitem;
exceptitem: exceptuhost | exceptshun | exceptkline | exceptgline
          | exceptzline | exceptident | exceptrdns | exceptipcheck
          | excepttarglimit | exceptlistdelay;
exceptuhost: HOST '=' QSTRING ';'
{
 struct SLink *link;
 link = make_link();
 if (!strchr($3, '@'))
 {
   int uh_len;
   link->value.cp = (char*) MyMalloc((uh_len = strlen($3)+3));
   ircd_snprintf(0, link->value.cp, uh_len, "*@%s", $3);
 }
 else
   DupString(link->value.cp, $3);
 MyFree($3);
 link->next = hosts;
 hosts = link;
};
exceptshun: SHUN '=' YES ';'
{
  flags |= EFLAG_SHUN;
} | SHUN '=' NO ';'
{
  flags &= ~EFLAG_SHUN;
};
exceptkline: KLINE '=' YES ';'
{
  flags |= EFLAG_KLINE;
} | KLINE '=' NO ';'
{
  flags &= ~EFLAG_KLINE;
};
exceptgline: GLINE '=' YES ';'
{
  flags |= EFLAG_GLINE;
} | GLINE '=' NO ';'
{
  flags &= ~EFLAG_GLINE;
};
exceptzline: ZLINE '=' YES ';'
{
  flags |= EFLAG_ZLINE;
} | ZLINE '=' NO ';'
{
  flags &= ~EFLAG_ZLINE;
};
exceptident: IDENT '=' YES ';'
{
  flags |= EFLAG_IDENT;
} | IDENT '=' NO ';'
{
  flags &= ~EFLAG_IDENT;
};
exceptrdns: RDNS '=' YES ';'
{
  flags |= EFLAG_RDNS;
} | RDNS '=' NO ';'
{
  flags &= ~EFLAG_RDNS;
};
exceptipcheck: IPCHECK '=' YES ';'
{
  flags |= EFLAG_IPCHECK;
} | IPCHECK '=' NO ';'
{
  flags &= ~EFLAG_IPCHECK;
};
excepttarglimit: TARGETLIMIT '=' YES ';'
{
  flags |= EFLAG_TARGLIMIT;
} | TARGETLIMIT '=' NO ';'
{
  flags &= ~EFLAG_TARGLIMIT;
};
exceptlistdelay: LISTDELAY '=' YES ';'
{
  flags |= EFLAG_LISTDELAY;
} | LISTDELAY '=' NO ';'
{
  flags &= ~EFLAG_LISTDELAY;
};

dnsblblock: DNSBL
{
  dnsbl_domain = dnsbl_index = dnsbl_mark = NULL;
  dnsbl_bitmask = 0;
  dnsbl_action = DNSBL_ACT_MARK;
  dnsbl_score = 0;
} '{' dnsblitems '}' ';'
{
  if (dnsbl_domain == NULL)
    parse_error("Missing name in DNSBL block");
  else {
    dnsbl_add_server(dnsbl_domain, dnsbl_index, dnsbl_bitmask,
                     dnsbl_action, dnsbl_mark, dnsbl_score);
  }
  MyFree(dnsbl_domain);
  MyFree(dnsbl_index);
  MyFree(dnsbl_mark);
  dnsbl_domain = dnsbl_index = dnsbl_mark = NULL;
  dnsbl_bitmask = 0;
  dnsbl_action = DNSBL_ACT_MARK;
  dnsbl_score = 0;
};
dnsblitems: dnsblitem dnsblitems | dnsblitem;
dnsblitem: dnsblname | dnsblindex | dnsblbitmask | dnsblaction | dnsblmark | dnsblscore;
dnsblname: NAME '=' QSTRING ';'
{
  MyFree(dnsbl_domain);
  dnsbl_domain = $3;
};
dnsblindex: HOST '=' QSTRING ';'
{
  /* HOST used as "index" for reply values, e.g., "2,3,5" */
  MyFree(dnsbl_index);
  dnsbl_index = $3;
};
dnsblbitmask: BITMASK '=' expr ';'
{
  dnsbl_bitmask = $3;
};
dnsblaction: ACTION '=' MARK ';'
{
  dnsbl_action = DNSBL_ACT_MARK;
} | ACTION '=' BLOCK_ALL ';'
{
  dnsbl_action = DNSBL_ACT_BLOCK_ALL;
} | ACTION '=' BLOCK_ANON ';'
{
  dnsbl_action = DNSBL_ACT_BLOCK_ANON;
} | ACTION '=' WHITELIST ';'
{
  dnsbl_action = DNSBL_ACT_WHITELIST;
};
dnsblmark: REASON '=' QSTRING ';'
{
  /* REASON is used as the mark string */
  MyFree(dnsbl_mark);
  dnsbl_mark = $3;
};
dnsblscore: SCORE '=' expr ';'
{
  dnsbl_score = $3;
};

include: INCLUDE QSTRING ';'
{
  init_lexer_file($2);
}
