/*
 * ml_route.h - does the way to a server carry multiline (ML) batches?
 *
 * The originating server of a multiline batch decides, once, whether a
 * recipient behind another server gets the batch as ML lines or as the
 * single-line fallback.  It decides by the whole way to that server, not
 * by its own next hop: every server a batch crosses forwards ML only to
 * links that announced ML, so one hop that does not take ML is where the
 * batch stops (a DM) or turns into the fallback (a channel, at the relay).
 */
#ifndef INCLUDED_ml_route_h
#define INCLUDED_ml_route_h

struct Client;

/** The most servers ml_route_carries_multiline() walks before it gives
 * up and answers no.  A P10 network is a tree far shallower than this;
 * the bound only keeps a corrupt up-chain from looping forever. */
#define ML_ROUTE_MAX_HOPS 64

extern int ml_route_carries_multiline(struct Client *server);

#endif /* INCLUDED_ml_route_h */
