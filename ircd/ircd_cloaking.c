/*
 * IRC - Internet Relay Chat, ircd/ircd_cloaking.c
 * Copyright (C) 1999 Thomas Helvey
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
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
 * @brief Implementation of IP and host cloaking functions..
 * @version $Id$
 */
#include "config.h"

#include "ircd_chattr.h"
#include "ircd_cloaking.h"
#include "ircd_defs.h"
#include "ircd_features.h"
#include "ircd_md5.h"
#include "ircd_snprintf.h"
#include "res.h"

#include <netinet/in.h>
#include <string.h>

#undef KEY1
#undef KEY2
#undef KEY3
#undef PREFIX
#define KEY1 feature_str(FEAT_HOST_HIDING_KEY1)
#define KEY2 feature_str(FEAT_HOST_HIDING_KEY2)
#define KEY3 feature_str(FEAT_HOST_HIDING_KEY3)
#define PREFIX feature_str(FEAT_HOST_HIDING_PREFIX)

static inline unsigned int downsample(unsigned char *i);

/** Downsamples a 128bit result to 32bits (md5 -> unsigned int) */
static inline unsigned int downsample(unsigned char *i)
{
unsigned char r[4];

        r[0] = i[0] ^ i[1] ^ i[2] ^ i[3];
        r[1] = i[4] ^ i[5] ^ i[6] ^ i[7];
        r[2] = i[8] ^ i[9] ^ i[10] ^ i[11];
        r[3] = i[12] ^ i[13] ^ i[14] ^ i[15];

        return ( ((unsigned int)r[0] << 24) +
                 ((unsigned int)r[1] << 16) +
                 ((unsigned int)r[2] << 8) +
                 (unsigned int)r[3]);
}

/** Downsamples a 128bit result to 24bits (md5 -> unsigned int) */
static inline unsigned int downsample24(unsigned char *i)
{
unsigned char r[4];

  r[0] = i[0] ^ i[1] ^ i[2] ^ i[3] ^ i[4];
  r[1] = i[5] ^ i[6] ^ i[7] ^ i[8] ^ i[9] ^ i[10];
  r[2] = i[11] ^ i[12] ^ i[13] ^ i[14] ^ i[15];

  return ( ((unsigned int)r[0] << 16) +
           ((unsigned int)r[1] << 8) +
           (unsigned int)r[2]);
}


char *hidehost_ipv4(struct irc_in_addr *ip)
{
unsigned int a, b, c, d;
static char buf[512], res[512], res2[512], result[128];
unsigned long n;
unsigned int alpha, beta, gamma, delta;
unsigned char *pch;

        /*
         * Output: ALPHA.BETA.GAMMA.DELTA.IP
         * ALPHA is unique for a.b.c.d
         * BETA  is unique for a.b.c.*
         * GAMMA is unique for a.b.*
         * We cloak like this:
         * ALPHA = downsample24(md5(md5("KEY2:A.B.C.D:KEY3")+"KEY1"));
         * BETA  = downsample24(md5(md5("KEY3:A.B.C:KEY1")+"KEY2"));
         * GAMMA = downsample24(md5(md5("KEY1:A.B:KEY2")+"KEY3"));
         * DELTA = downsample24(md5(md5("KEY2:A:KEY1:KEY3")+"KEY1"));
         */
        if (!irc_in_addr_is_ipv4(ip))
          return hidehost_ipv6(ip);

        pch = (unsigned char*)&ip->in6_16[6];
        a = *pch++;
        b = *pch;
        pch = (unsigned char*)&ip->in6_16[7];
        c = *pch++;
        d = *pch;

        /* ALPHA... */
        ircd_snprintf(0, buf, 512, "%s:%d.%d.%d.%d:%s", KEY2, a, b, c, d, KEY3);
        DoMD5((unsigned char *)&res, (unsigned char *)&buf, strlen(buf));
        strcpy(res+16, KEY1); /* first 16 bytes are filled, append our key.. */
        n = strlen(res+16) + 16;
        DoMD5((unsigned char *)&res2, (unsigned char *)&res, n);
        alpha = downsample24((unsigned char *)&res2);

        /* BETA... */
        ircd_snprintf(0, buf, 512, "%s:%d.%d.%d:%s", KEY3, a, b, c, KEY1);
        DoMD5((unsigned char *)&res, (unsigned char *)&buf, strlen(buf));
        strcpy(res+16, KEY2); /* first 16 bytes are filled, append our key.. */
        n = strlen(res+16) + 16;
        DoMD5((unsigned char *)&res2, (unsigned char *)&res, n);
        beta = downsample24((unsigned char *)&res2);

        /* GAMMA... */
        ircd_snprintf(0, buf, 512, "%s:%d.%d:%s", KEY1, a, b, KEY2);
        DoMD5((unsigned char *)&res, (unsigned char *)&buf, strlen(buf));
        strcpy(res+16, KEY3); /* first 16 bytes are filled, append our key.. */
        n = strlen(res+16) + 16;
        DoMD5((unsigned char *)&res2, (unsigned char *)&res, n);
        gamma = downsample24((unsigned char *)&res2);

        /* DELTA... */
        ircd_snprintf(0, buf, 512, "%s:%d:%s:%s", KEY2, a, KEY1, KEY3);
        DoMD5((unsigned char *)&res, (unsigned char *)&buf, strlen(buf));
        strcpy(res+16, KEY1); /* first 16 bytes are filled, append our key.. */
        n = strlen(res+16) + 16;
        DoMD5((unsigned char *)&res2, (unsigned char *)&res, n);
        delta = downsample24((unsigned char *)&res2);

        ircd_snprintf(0, result, HOSTLEN, "%X.%X.%X.%X.IP", alpha, beta, gamma, delta);
        return result;
}

char *hidehost_ipv6(struct irc_in_addr *ip)
{
unsigned int a, b, c, d, e, f, g, h;
static char buf[512], res[512], res2[512], result[128];
unsigned long n;
unsigned int alpha, beta, gamma, delta;

        /*
         * Output: ALPHA:BETA:GAMMA:IP
         * ALPHA is unique for a:b:c:d:e:f:g:h
         * BETA  is unique for a:b:c:d:e:f:g
         * GAMMA is unique for a:b:c:d
         * We cloak like this:
         * ALPHA = downsample24(md5(md5("KEY2:a:b:c:d:e:f:g:h:KEY3")+"KEY1"));
         * BETA  = downsample24(md5(md5("KEY3:a:b:c:d:e:f:g:KEY1")+"KEY2"));
         * GAMMA = downsample24(md5(md5("KEY1:a:b:c:d:KEY2")+"KEY3"));
         * DELTA = downsample24(md5(md5("KEY2:a:b:KEY1:KEY3")+"KEY1"));
         */

        if (irc_in_addr_is_ipv4(ip))
          return hidehost_ipv4(ip);

        a = ntohs(ip->in6_16[0]);
        b = ntohs(ip->in6_16[1]);
        c = ntohs(ip->in6_16[2]);
        d = ntohs(ip->in6_16[3]);
        e = ntohs(ip->in6_16[4]);
        f = ntohs(ip->in6_16[5]);
        g = ntohs(ip->in6_16[6]);
        h = ntohs(ip->in6_16[7]);

        /* ALPHA... */
        ircd_snprintf(0, buf, 512, "%s:%x:%x:%x:%x:%x:%x:%x:%x:%s", KEY2, a, b, c, d, e, f, g, h, KEY3);
        DoMD5((unsigned char *)&res, (unsigned char *)&buf, strlen(buf));
        strcpy(res+16, KEY1); /* first 16 bytes are filled, append our key.. */
        n = strlen(res+16) + 16;
        DoMD5((unsigned char *)&res2, (unsigned char *)&res, n);
        alpha = downsample24((unsigned char *)&res2);

        /* BETA... */
        ircd_snprintf(0, buf, 512, "%s:%x:%x:%x:%x:%x:%x:%x:%s", KEY3, a, b, c, d, e, f, g, KEY1);
        DoMD5((unsigned char *)&res, (unsigned char *)&buf, strlen(buf));
        strcpy(res+16, KEY2); /* first 16 bytes are filled, append our key.. */
        n = strlen(res+16) + 16;
        DoMD5((unsigned char *)&res2, (unsigned char *)&res, n);
        beta = downsample24((unsigned char *)&res2);

        /* GAMMA... */
        ircd_snprintf(0, buf, 512, "%s:%x:%x:%x:%x:%s", KEY1, a, b, c, d, KEY2);
        DoMD5((unsigned char *)&res, (unsigned char *)&buf, strlen(buf));
        strcpy(res+16, KEY3); /* first 16 bytes are filled, append our key.. */
        n = strlen(res+16) + 16;
        DoMD5((unsigned char *)&res2, (unsigned char *)&res, n);
        gamma = downsample24((unsigned char *)&res2);

        /* DELTA... */
        ircd_snprintf(0, buf, 512, "%s:%x:%x:%s:%s", KEY2, a, b, KEY1, KEY3);
        DoMD5((unsigned char *)&res, (unsigned char *)&buf, strlen(buf));
        strcpy(res+16, KEY1); /* first 16 bytes are filled, append our key.. */
        n = strlen(res+16) + 16;
        DoMD5((unsigned char *)&res2, (unsigned char *)&res, n);
        delta = downsample24((unsigned char *)&res2);

        ircd_snprintf(0, result, HOSTLEN, "%X:%X:%X:%X:IP", alpha, beta, gamma, delta);
        return result;
}

char *hidehost_normalhost(char *host, int componants)
{
char *p;
static char buf[512], res[512], res2[512], result[HOSTLEN+1];
unsigned int alpha, n;
int comps = 0;

        ircd_snprintf(0, buf, 512, "%s:%s:%s", KEY1, host, KEY2);
        DoMD5((unsigned char *)&res, (unsigned char *)&buf, strlen(buf));
        strcpy(res+16, KEY3); /* first 16 bytes are filled, append our key.. */
        n = strlen(res+16) + 16;
        DoMD5((unsigned char *)&res2, (unsigned char *)&res, n);
        alpha = downsample((unsigned char *)&res2);

        for (p = host; *p; p++) {
                if (*p == '.') {
                        comps++;
                        if ((comps >= componants) && IsAlpha(*(p + 1)))
                                break;
                }
        }

        if (*p)
        {
                unsigned int len;
                p++;

                ircd_snprintf(0, result, HOSTLEN, "%s-%X.", PREFIX, alpha);
                len = strlen(result) + strlen(p);
                if (len <= HOSTLEN)
                        strcat(result, p);
                else
                        strcat(result, p + (len - HOSTLEN));
        } else
                ircd_snprintf(0, result, HOSTLEN, "%s-%X", PREFIX, alpha);

        return result;
}

