/*
 * nick_route.h - does the way to a session primary's server carry a
 * device's nick request (BX W)?
 */
#ifndef INCLUDED_nick_route_h
#define INCLUDED_nick_route_h

struct Client;

extern int nick_writer_route(struct Client *home);

#endif /* INCLUDED_nick_route_h */
