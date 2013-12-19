/** @file ircd_geoip.h
 * @brief GeoIP routine definitions.
 * @version $Id$
 */
#ifndef INCLUDED_ircd_geoip_h
#define INCLUDED_ircd_geoip_h

#include "client.h"

extern void geoip_init(void);
extern void geoip_apply(struct Client* cptr);
extern void geoip_apply_mark(struct Client* cptr, char* country, char* continent);
extern void geoip_handle_enable(void);
extern void geoip_handle_file(void);
extern void geoip_handle_ipv6_file(void);

#endif /* INCLUDED_ircd_geoip_h */

