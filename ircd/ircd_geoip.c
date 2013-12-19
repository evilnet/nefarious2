/*
 * IRC - Internet Relay Chat, ircd/ircd.c
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
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
 * @brief GeoIP routines.
 * @version $Id$
 */

#include <sys/types.h>
#include <sys/stat.h>

#include "config.h"

#include "client.h"
#include "ircd_geoip.h"
#include "ircd_features.h"
#include "ircd_string.h"
#include "res.h"

#ifdef USE_GEOIP
#include <GeoIP.h>
#endif /* USE_GEOIP */

/** GeoIP structs. */
#ifdef USE_GEOIP
GeoIP *gi4 = NULL;
GeoIP *gi6 = NULL;
#endif /* USE_GEOIP */

const char geoip_continent_code[7][3] = {"--", "AF", "AS", "EU", "NA", "OC", "SA"};
const char *geoip_continent_name[7] = {"N/A", "Africa", "Asia", "Europe",
                                       "North America", "Oceania", "South America"};

/** Find continent name by 2 letter code.
 * @param[in] cc 2 letter continent code
 * @return Continent name
 */
const char* geoip_continent_name_by_code(const char* cc)
{
  int i = 0;

  for (i=0; i<7; i++) {
    if (strncasecmp(cc, (char *)&geoip_continent_code[i], 2) == 0)
      break;
  }

  return geoip_continent_name[i];
}

/** Initialize GeoIP global states.
 */
void geoip_init(void)
{
#ifdef USE_GEOIP
  if (gi4 != NULL)
    GeoIP_delete(gi4);
  if (gi6 != NULL)
    GeoIP_delete(gi6);
  gi4 = NULL;
  gi6 = NULL;
#endif /* USE_GEOIP */

  if (!feature_bool(FEAT_GEOIP_ENABLE))
    return;

#ifdef USE_GEOIP
  /* Load IPv4 GeoIP database */
  if (feature_str(FEAT_GEOIP_FILE)) {
    gi4 = GeoIP_open(feature_str(FEAT_GEOIP_FILE), GEOIP_STANDARD);
  }

  /* Try to load GeoIP.dat from lib/ if FEAT_GEOIP_FILE was not loaded. */
  if (gi4 == NULL)
    gi4 = GeoIP_open_type(GEOIP_COUNTRY_EDITION, GEOIP_STANDARD);

  /* Load IPv6 GeoIP database */
  if (feature_str(FEAT_GEOIP_IPV6_FILE)) {
    gi6 = GeoIP_open(feature_str(FEAT_GEOIP_IPV6_FILE), GEOIP_STANDARD);
  }

  /* Try to load GeoIPv6.dat from lib/ if FEAT_GEOIP_IPV6_FILE was not loaded. */
  if (gi6 == NULL)
    gi6 = GeoIP_open_type(GEOIP_COUNTRY_EDITION_V6, GEOIP_STANDARD);
#endif /* USE_GEOIP */
}

/** Apply GeoIP country data to a client.
 * @param[in] cptr Client to apply GeoIP country data to.
 */
void geoip_apply(struct Client* cptr)
{
#ifdef USE_GEOIP
  int gcid = 0;
#endif /* USE_GEOIP */
#ifdef USE_GEOIP_GL
  GeoIPLookup gl;
#endif /* USE_GEOIP_GL */

  if (!feature_bool(FEAT_GEOIP_ENABLE))
    return;

  if (!(cptr))
    return;

#ifdef USE_GEOIP
  if (irc_in_addr_is_ipv4(&cli_ip(cptr))) {
    /* User is IPv4 so use gi4. */
    if (gi4 != NULL)
#ifdef USE_GEOIP_GL
      gcid = GeoIP_id_by_addr_gl(gi4, cli_sock_ip(cptr), &gl);
#else
      gcid = GeoIP_id_by_addr(gi4, cli_sock_ip(cptr));
#endif /* USE_GEOIP_GL */
  } else {
    /* User is IPv6 so use gi6. */
    if (gi6 != NULL)
#ifdef USE_GEOIP_GL
      gcid = GeoIP_id_by_addr_v6_gl(gi6, cli_sock_ip(cptr), &gl);
#else
      gcid = GeoIP_id_by_addr_v6(gi6, cli_sock_ip(cptr));
#endif /* USE_GEOIP_GL */
  }
#endif /* USE_GEOIP */

#ifdef USE_GEOIP
  if (gcid == 0) {
#endif /* USE_GEOIP */
    ircd_strncpy((char *)&cli_countrycode(cptr), "--", 3);
    ircd_strncpy((char *)&cli_countryname(cptr), "Unknown", 8);
    ircd_strncpy((char *)&cli_continentcode(cptr), "--", 3);
    ircd_strncpy((char *)&cli_continentname(cptr), "Unknown", 8);
#ifdef USE_GEOIP
  } else {
    ircd_strncpy((char *)&cli_countrycode(cptr), GeoIP_code_by_id(gcid), 3);
    ircd_strncpy((char *)&cli_countryname(cptr), GeoIP_name_by_id(gcid), 256);
    ircd_strncpy((char *)&cli_continentcode(cptr), GeoIP_continent_by_id(gcid), 3);
    ircd_strncpy((char *)&cli_continentname(cptr), geoip_continent_name_by_code(GeoIP_continent_by_id(gcid)), 256);
  }
#endif /* USE_GEOIP */

  SetGeoIP(cptr);
}

/** Apply GeoIP country data to a client from a MARK.
 * @param[in] cptr Client to apply GeoIP country data to.
 * @param[in] country Country code from MARK.
 * @param[in] continent Continent code from MARK.
 */
void geoip_apply_mark(struct Client* cptr, char* country, char* continent)
{
  ircd_strncpy((char *)&cli_countrycode(cptr), (!country ? "--" : country), 3);
  ircd_strncpy((char *)&cli_continentcode(cptr), (!continent ? "--" : continent), 3);

#ifdef USE_GEOIP
  if (!country || !strcmp(country, "--"))
#endif /* USE_GEOIP */
    ircd_strncpy((char *)&cli_countryname(cptr), "Unknown", 8);
#ifdef USE_GEOIP
  else
    ircd_strncpy((char *)&cli_countryname(cptr), GeoIP_name_by_id(GeoIP_id_by_code(country)), 256);

  if (!continent || !strcmp(continent, "--"))
#endif /* USE_GEOIP */
    ircd_strncpy((char *)&cli_continentname(cptr), "Unknown", 8);
#ifdef USE_GEOIP
  else
    ircd_strncpy((char *)&cli_continentname(cptr), geoip_continent_name_by_code(continent), 256);
#endif /* USE_GEOIP */

  SetGeoIP(cptr);
}

/** Handle an update to FEAT_GEOIP_ENABLE. */
void geoip_handle_enable(void)
{
  geoip_init();
}

/** Handle an update to FEAT_GEOIP_FILE. */
void geoip_handle_file(void)
{
  if (!feature_bool(FEAT_GEOIP_ENABLE))
    return;

#ifdef USE_GEOIP
  if (gi4 != NULL)
    GeoIP_delete(gi4);
  gi4 = NULL;

  /* Load IPv4 GeoIP database */
  if (feature_str(FEAT_GEOIP_FILE)) {
    gi4 = GeoIP_open(feature_str(FEAT_GEOIP_FILE), GEOIP_STANDARD);
  }

  /* Try to load GeoIP.dat from lib/ if FEAT_GEOIP_FILE was not loaded. */
  if (gi4 == NULL)
    gi4 = GeoIP_open_type(GEOIP_COUNTRY_EDITION, GEOIP_STANDARD);
#endif /* USE_GEOIP */
}

/** Handle an update to FEAT_GEOIP_IPV6_FILE. */
void geoip_handle_ipv6_file(void)
{
  if (!feature_bool(FEAT_GEOIP_ENABLE))
    return;

#ifdef USE_GEOIP
  if (gi6 != NULL)
    GeoIP_delete(gi6);
  gi6 = NULL;

  /* Load IPv6 GeoIP database */
  if (feature_str(FEAT_GEOIP_IPV6_FILE)) {
    gi6 = GeoIP_open(feature_str(FEAT_GEOIP_IPV6_FILE), GEOIP_STANDARD);
  }

  /* Try to load GeoIPv6.dat from lib/ if FEAT_GEOIP_IPV6_FILE was not loaded. */
  if (gi6 == NULL)
    gi6 = GeoIP_open_type(GEOIP_COUNTRY_EDITION_V6, GEOIP_STANDARD);
#endif /* USE_GEOIP */
}

