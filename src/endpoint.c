/*
** Copyright (C) 2017 by Kevin L. Mitchell <klmitch@mit.edu>
**
** Licensed under the Apache License, Version 2.0 (the "License"); you
** may not use this file except in compliance with the License. You
** may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
** implied. See the License for the specific language governing
** permissions and limitations under the License.
*/

#include <config.h>

#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>
#include <syslog.h>
#include <sys/un.h>

#include "include/common.h"
#include "include/endpoint.h"
#include "include/yaml_util.h"

int
ep_addr_set_local(ep_addr_t *addr, const char *path,
		  yaml_ctx_t *ctx, yaml_node_t *value)
{
#ifdef AF_LOCAL
  int len, max_len;

  /* No warning necessary; it's already been given */
  if (addr->ea_flags & EA_INVALID)
    return 0;

  /* Look out for duplications */
  if (addr->ea_flags & (EA_LOCAL | EA_IPADDR | EA_PORT)) {
    yaml_ctx_report(ctx, &value->start_mark, LOG_WARNING,
		    "Address has already been set");
    addr->ea_flags |= EA_INVALID;
    return 0;
  }

  /* Check if the path is too long */
  max_len = (sizeof(addr->ea_addr.eau_local) -
	     SUN_LEN(&addr->ea_addr.eau_local) - 1);
  len = strlen(path);
  if (len > max_len) {
    yaml_ctx_report(ctx, &value->start_mark, LOG_WARNING,
		    "Local address \"%s\" is too long (%d > maximum of %d)",
		    path, len, max_len);
    addr->ea_flags |= EA_INVALID;
    return 0;
  }

  /* Make sure it's a valid path */
  if (*path != '/' || len <= 2 || path[len - 1] == '/') {
    yaml_ctx_report(ctx, &value->start_mark, LOG_WARNING,
		    "Local address \"%s\" is invalid", path);
    addr->ea_flags |= EA_INVALID;
    return 0;
  }

  /* Save the path */
  strcpy(addr->ea_addr.eau_local.sun_path, path);
  addr->ea_flags = EA_LOCAL;
  addr->ea_addrlen = SUN_LEN(&addr->ea_addr.eau_local);

  return 1;
#else
  yaml_ctx_report(ctx, &value->start_mark, LOG_WARNING,
                  "Local addresses not supported on this system");
  addr->ea_flags |= EA_INVALID;
  return 0;
#endif
}

int
ep_addr_set_ipaddr(ep_addr_t *addr, const char *pres,
		   yaml_ctx_t *ctx, yaml_node_t *value)
{
#ifndef AF_INET6
  static int inet6_warning = 0;
#endif
  uint16_t port = 0;

  /* No warning necessary; it's already been given */
  if (addr->ea_flags & EA_INVALID)
    return 0;

  /* Look out for duplications */
  if (addr->ea_flags & (EA_LOCAL | EA_IPADDR)) {
    yaml_ctx_report(ctx, &value->start_mark, LOG_WARNING,
		    "Address has already been set");
    addr->ea_flags |= EA_INVALID;
    return 0;
  }

  /* If the port has been set, let's save it */
  if (addr->ea_flags & EA_PORT)
    port = addr->ea_addr.eau_ip4.sin_port;

  /* Try converting it as IPv4 */
  if (inet_pton(AF_INET, pres, &addr->ea_addr.eau_ip4.sin_addr)) {
    addr->ea_flags |= EA_IPADDR;
    addr->ea_addr.eau_ip4.sin_family = AF_INET;
    if (addr->ea_flags & EA_PORT)
      addr->ea_addr.eau_ip4.sin_port = port;
    addr->ea_addrlen = sizeof(addr->ea_addr.eau_ip4);

    return 1;
  }

#ifdef AF_INET6
  /* Try converting it as IPv6 */
  if (inet_pton(AF_INET6, pres, &addr->ea_addr.eau_ip6.sin6_addr)) {
    addr->ea_flags |= EA_IPADDR;
    addr->ea_addr.eau_ip6.sin6_family = AF_INET6;
    if (addr->ea_flags & EA_PORT)
      addr->ea_addr.eau_ip6.sin6_port = port;
    addr->ea_addrlen = sizeof(addr->ea_addr.eau_ip6);

    return 1;
  }
#else
  /* Emit an IPv6 warning only once */
  if (!inet6_warning) {
    yaml_ctx_report(ctx, &value->start_mark, LOG_WARNING,
		    "IPv6 addresses are not supported by this system");
    inet6_warning = 1;
  }
#endif

  /* OK, it's an invalid address */
  yaml_ctx_report(ctx, &value->start_mark, LOG_WARNING,
		  "Invalid IP address \"%s\"", pres);
  addr->ea_flags |= EA_INVALID;

  return 0;
}

int
ep_addr_set_port(ep_addr_t *addr, int port,
		 yaml_ctx_t *ctx, yaml_node_t *value)
{
  /* No warning necessary; it's already been given */
  if (addr->ea_flags & EA_INVALID)
    return 0;

  /* Look out for duplications */
  if (addr->ea_flags & (EA_LOCAL | EA_PORT)) {
    yaml_ctx_report(ctx, &value->start_mark, LOG_WARNING,
		    "Port has already been set");
    addr->ea_flags |= EA_INVALID;
    return 0;
  }

  /* Bounds-check the port number */
  if (port <= 0 || port > 65535) {
    yaml_ctx_report(ctx, &value->start_mark, LOG_WARNING,
		    "Port %d out of range (0, 65535]", port);
    addr->ea_flags |= EA_INVALID;
    return 0;
  }

  /* Put the address in the correct place */
  if (!(addr->ea_flags & EA_IPADDR) ||
      addr->ea_addr.eau_addr.sa_family == AF_INET)
    addr->ea_addr.eau_ip4.sin_port = htons(port);
#ifdef AF_INET6
  else if (addr->ea_addr.eau_addr.sa_family == AF_INET6)
    addr->ea_addr.eau_ip6.sin6_port = htons(port);
#endif
  else
    /* We don't know the address family?!? */
    abort();

  addr->ea_flags |= EA_PORT;

  return 1;
}

void
ep_addr_default(ep_addr_t *dest, ep_addr_t *src)
{
  uint16_t port = 0;

  /* Do nothing if it's invalid */
  if (dest->ea_flags & EA_INVALID || src->ea_flags & EA_INVALID)
    return;

  /* Copy over the parts of the address that weren't set */
#ifdef AF_LOCAL
  if (!(dest->ea_flags & EA_LOCAL) && (src->ea_flags & EA_LOCAL)) {
    dest->ea_addr.eau_local.sun_family = AF_LOCAL;
    strcpy(dest->ea_addr.eau_local.sun_path, src->ea_addr.eau_local.sun_path);
    dest->ea_addrlen = src->ea_addrlen;
    dest->ea_flags |= EA_LOCAL;
  } else {
#endif
    if (!(dest->ea_flags & EA_IPADDR) && (src->ea_flags & EA_IPADDR)) {
      /* Save the port */
      if (dest->ea_flags & EA_PORT)
	port = dest->ea_addr.eau_ip4.sin_port;

      /* Copy over the address */
      if (src->ea_addr.eau_addr.sa_family == AF_INET) {
	dest->ea_addr.eau_ip4.sin_family = AF_INET;
	dest->ea_addr.eau_ip4.sin_addr = src->ea_addr.eau_ip4.sin_addr;
	if (dest->ea_flags & EA_PORT)
	  dest->ea_addr.eau_ip4.sin_port = port;
      }
#ifdef AF_INET6
      else if (src->ea_addr.eau_addr.sa_family == AF_INET6) {
	dest->ea_addr.eau_ip6.sin6_family = AF_INET6;
	dest->ea_addr.eau_ip6.sin6_addr = src->ea_addr.eau_ip6.sin6_addr;
	if (dest->ea_flags & EA_PORT)
	  dest->ea_addr.eau_ip6.sin6_port = port;
      }
#endif

      /* Update the address length */
      dest->ea_addrlen = src->ea_addrlen;

      /* Record that we have the IP address */
      dest->ea_flags |= EA_IPADDR;
    }

    if (!(dest->ea_flags & EA_PORT) && (src->ea_flags & EA_PORT)) {
      if (src->ea_addr.eau_addr.sa_family == AF_INET)
	dest->ea_addr.eau_ip4.sin_port = src->ea_addr.eau_ip4.sin_port;
#ifdef AF_INET6
      else if (src->ea_addr.eau_addr.sa_family == AF_INET6)
	dest->ea_addr.eau_ip6.sin6_port = src->ea_addr.eau_ip6.sin6_port;
#endif

      /* Record that we have the port */
      dest->ea_flags |= EA_PORT;
    }
#ifdef AF_LOCAL
  }
#endif
}

void
ep_ad_release(ep_ad_t *ad)
{
  /* Zero the advertisement */
  ep_ad_init(ad, 0);

  /* Zero the magic number */
  ad->epa_magic = 0;
}

void
ep_config_release(ep_config_t *endpoint)
{
  int i;

  /* Release memory associated with the endpoint advertisements */
  for (i = 0; i < flexlist_count(&endpoint->epc_ads); i++)
    ep_ad_release((ep_ad_t *)flexlist_item(&endpoint->epc_ads, i));

  /* Release the ad list */
  flexlist_release(&endpoint->epc_ads);

  /* Zero the config */
  ep_config_init(endpoint);

  /* Zero the magic number */
  endpoint->epc_magic = 0;
}

void
ep_network_release(ep_network_t *network)
{
  /* Zero the network */
  ep_network_init(network);

  /* Zero the magic number */
  network->epn_magic = 0;
}
