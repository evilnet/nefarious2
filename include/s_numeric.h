/** @file s_numeric.h
 * @brief Send a numeric message to a client.
 * @version $Id: s_numeric.h 1231 2004-10-05 04:21:37Z entrope $
 */
#ifndef INCLUDED_s_numeric_h
#define INCLUDED_s_numeric_h

struct Client;

/*
 * Prototypes
 */

extern int do_numeric(int numeric, int nnn, struct Client *cptr, struct Client *sptr,
    int parc, char *parv[]);

#endif /* INCLUDED_s_numeric_h */
