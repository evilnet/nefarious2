/** @file send.h
 * @brief Send messages to certain targets.
 * @version $Id: send.h 1274 2004-12-16 03:28:52Z entrope $
 */
#ifndef INCLUDED_send_h
#define INCLUDED_send_h
#ifndef INCLUDED_stdarg_h
#include <stdarg.h>         /* va_list */
#define INCLUDED_stdarg_h 
#endif
#ifndef INCLUDED_time_h
#include <time.h>	/* time_t */
#define INCLUDED_time_h
#endif

struct Channel;
struct Client;
struct DBuf;
struct MsgBuf;

/*
 * Prototypes
 */
extern struct SLink *opsarray[];

extern void send_buffer(struct Client* to, struct MsgBuf* buf, int prio);

extern void kill_highest_sendq(int servers_too);
extern void flush_connections(struct Client* cptr);
extern void send_queued(struct Client *to);

/* Send a raw message to one client; USE ONLY IF YOU MUST SEND SOMETHING
 * WITHOUT A PREFIX!
 */
extern void sendrawto_one(struct Client *to, const char *pattern, ...);

/* Send a command to one client */
extern void sendcmdto_one(struct Client *from, const char *cmd,
			  const char *tok, struct Client *to,
			  const char *pattern, ...);

/* Same as above, but include message tags (label, time, account) */
extern void sendcmdto_one_tags(struct Client *from, const char *cmd,
			  const char *tok, struct Client *to,
			  const char *pattern, ...);

/* Send TAGMSG with client-only tags to a single client */
extern void sendcmdto_one_client_tags(struct Client *from, const char *cmd,
                               struct Client *to, const char *client_tags,
                               const char *pattern, ...);

/* Same as above, except it puts the message on the priority queue */
extern void sendcmdto_prio_one(struct Client *from, const char *cmd,
			       const char *tok, struct Client *to,
			       const char *pattern, ...);

/* Send command to servers by flags except one */
extern void sendcmdto_flag_serv_butone(struct Client *from, const char *cmd,
                                       const char *tok, struct Client *one,
                                       int require, int forbid,
                                       const char *pattern, ...);

/* Send command to all servers except one */
extern void sendcmdto_serv_butone(struct Client *from, const char *cmd,
				  const char *tok, struct Client *one,
				  const char *pattern, ...);

/* Send command to all channels user is on */
extern void sendcmdto_common_channels_butone(struct Client *from,
					     const char *cmd,
					     const char *tok,
					     struct Client *one,
					     const char *pattern, ...);

/* Send command to all channels user is on with or without a specified capability */
extern void sendcmdto_common_channels_capab_butone(struct Client *from,
                                             const char *cmd,
                                             const char *tok,
                                             struct Client *one,
                                             int withcap,
                                             int skipcap,
                                             const char *pattern, ...);

/* Send command to all channel users on this server */
extern void sendcmdto_channel_butserv_butone(struct Client *from,
					     const char *cmd,
					     const char *tok,
					     struct Channel *to,
					     struct Client *one,
                                             unsigned int skip,
					     const char *pattern, ...);

/* Send command to all channel users on this server with or without a specified capbility */
extern void sendcmdto_channel_capab_butserv_butone(struct Client *from,
                                            const char *cmd,
                                            const char *tok, struct Channel *to,
                                            struct Client *one,
                                            unsigned int skip,
                                            int withcap,
                                            int skipcap,
                                            const char *pattern, ...);

/* Send TAGMSG with client-only tags to channel members with message-tags capability */
extern void sendcmdto_channel_client_tags(struct Client *from, const char *cmd,
                                   struct Channel *to, struct Client *one,
                                   unsigned int skip, const char *client_tags,
                                   const char *pattern, ...);

/* Send command to all servers interested in a channel */
extern void sendcmdto_channel_servers_butone(struct Client *from,
                                             const char *cmd,
                                             const char *tok,
                                             struct Channel *to,
                                             struct Client *one,
                                             unsigned int skip,
                                             const char *pattern, ...);

/* Send command to all interested channel users */
extern void sendcmdto_channel_butone(struct Client *from, const char *cmd,
				     const char *tok, struct Channel *to,
				     struct Client *one, unsigned int skip,
				     unsigned char prefix, const char *pattern, ...);

#define SKIP_DEAF	0x01	/**< skip users that are +d */
#define SKIP_BURST	0x02	/**< skip users that are bursting */
#define SKIP_NONOPS	0x04	/**< skip users that aren't chanops */
#define SKIP_NONVOICES  0x08    /**< skip users that aren't voiced (includes
                                   chanops and halfops) */
#define SKIP_NONHOPS	0x10	/**< skip users that aren't halfopped (includes
                                   chanops) */
#define SKIP_CHGHOST	0x20	/**< skip users that have chghost capability */

/* Send command to all users having a particular flag set */
extern void sendwallto_group_butone(struct Client *from, int type, 
				    struct Client *one, const char *pattern,
				    ...);

#define WALL_DESYNCH	1       /**< send as a DESYNCH message */
#define WALL_WALLOPS	2       /**< send to all +w opers */
#define WALL_WALLUSERS	3       /**< send to all +w users */

/* Send command to all matching clients */
extern void sendcmdto_match_butone(struct Client *from, const char *cmd,
				   const char *tok, const char *to,
				   struct Client *one, unsigned int who,
				   const char *pattern, ...);

/* Send server notice to servers and opers but one--one can be NULL */
extern void sendto_opmask_butone_global(struct Client *one, unsigned int mask,
                           const char *pattern, ...);

/* Send server notice to opers but one--one can be NULL */
extern void sendto_opmask_butone(struct Client *one, unsigned int mask,
				 const char *pattern, ...);

/* Send server notice to opers from from but one--one can be NULL */
extern void sendto_opmask_butone_from(struct Client *from, struct Client *one,
                                      unsigned int mask, const char *pattern, ...);

/* Same as above, but rate limited */
extern void sendto_opmask_butone_ratelimited(struct Client *one,
					     unsigned int mask, time_t *rate,
					     const char *pattern, ...);

/* Same as above, but with variable argument list */
extern void vsendto_opmask_butone(struct Client *from, struct Client *one,
				  unsigned int mask, const char *pattern, va_list vl);

/* Send server notice to users with the supplied mode but one--one can be NULL */
extern void sendto_mode_butone(struct Client *one, struct Client *from, const char *mode,
                          const char *pattern, ...);

/* Same as above, but with variable argument list */
extern void vsendto_mode_butone(struct Client *one, struct Client *from, const char *mode,
                           const char *pattern, va_list vl);

/* Start a batch for a client (labeled-response integration) */
extern void send_batch_start(struct Client *to, const char *type);

/* End a batch for a client */
extern void send_batch_end(struct Client *to);

/* Check if a client has an active batch */
extern int has_active_batch(struct Client *cptr);

/* S2S batch functions for netjoin/netsplit coordination */
extern void send_s2s_batch_start(struct Client *sptr, const char *type,
                                 const char *server1, const char *server2);
extern void send_s2s_batch_end(struct Client *sptr, const char *batch_id);

/* Netjoin/netsplit batch functions for automatic batching */
extern void send_netjoin_batch_start(struct Client *server, struct Client *uplink);
extern void send_netjoin_batch_end(struct Client *server);
extern void send_netsplit_batch_start(struct Client *server, struct Client *uplink,
                                       char *batch_id_out, size_t batch_id_len);
extern void send_netsplit_batch_end(const char *batch_id);

/* Active network batch tracking for @batch tag inclusion in QUIT/JOIN messages */
extern void set_active_network_batch(const char *batch_id);
extern const char *get_active_network_batch(void);

/* IRCv3 standard-replies (FAIL/WARN/NOTE) */
extern void send_fail(struct Client *to, const char *command, const char *code,
                      const char *context, const char *description);
extern void send_warn(struct Client *to, const char *command, const char *code,
                      const char *context, const char *description);
extern void send_note(struct Client *to, const char *command, const char *code,
                      const char *context, const char *description);

#endif /* INCLUDED_send_h */
