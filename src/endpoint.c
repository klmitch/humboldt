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
#include <errno.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <netinet/in.h>
#include <stdint.h>
#include <string.h>
#include <syslog.h>
#include <sys/un.h>
#include <unistd.h>

#ifdef WIN32
#include <inttypes.h>	/* Needed for PRIdPTR */
#endif

#include "include/alloc.h"
#include "include/common.h"
#include "include/configuration.h"
#include "include/connection.h"
#include "include/db.h"
#include "include/endpoint.h"
#include "include/interfaces.h"
#include "include/log.h"
#include "include/runtime.h"
#include "include/yaml_util.h"

static freelist_t advertisements = FREELIST_INIT(ep_ad_t, 0);
static freelist_t configs = FREELIST_INIT(ep_config_t, 0);
static freelist_t networks = FREELIST_INIT(ep_network_t, 0);
static freelist_t endpoints = FREELIST_INIT(endpoint_t, 0);

int
ep_addr_set_local(ep_addr_t *addr, const char *path, conf_ctx_t *ctx)
{
#ifdef AF_LOCAL
  int len, max_len;

  /* No warning necessary; it's already been given */
  if (addr->ea_flags & EA_INVALID)
    return 0;

  /* Look out for duplications */
  if (addr->ea_flags & (EA_LOCAL | EA_IPADDR | EA_PORT)) {
    config_report(ctx, LOG_WARNING, "Address has already been set");
    addr->ea_flags |= EA_INVALID;
    return 0;
  }

  /* Check if the path is too long */
  max_len = (sizeof(addr->ea_addr.eau_local) -
	     SUN_LEN(&addr->ea_addr.eau_local) - 1);
  len = strlen(path);
  if (len > max_len) {
    config_report(ctx, LOG_WARNING,
		  "Local address \"%s\" is too long (%d > maximum of %d)",
		  path, len, max_len);
    addr->ea_flags |= EA_INVALID;
    return 0;
  }

  /* Make sure it's a valid path */
  if (*path != '/' || len <= 2 || path[len - 1] == '/') {
    config_report(ctx, LOG_WARNING, "Local address \"%s\" is invalid", path);
    addr->ea_flags |= EA_INVALID;
    return 0;
  }

  /* Save the path */
  addr->ea_addr.eau_local.sun_family = AF_LOCAL;
  strcpy(addr->ea_addr.eau_local.sun_path, path);
  addr->ea_flags = EA_LOCAL;
  addr->ea_addrlen = SUN_LEN(&addr->ea_addr.eau_local);

  return 1;
#else
  config_report(ctx, LOG_WARNING,
		"Local addresses not supported on this system");
  addr->ea_flags |= EA_INVALID;
  return 0;
#endif
}

int
ep_addr_set_ipaddr(ep_addr_t *addr, const char *pres, conf_ctx_t *ctx)
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
    config_report(ctx, LOG_WARNING, "Address has already been set");
    addr->ea_flags |= EA_INVALID;
    return 0;
  }

  /* If the port has been set, let's save it */
  if (addr->ea_flags & EA_PORT)
    port = addr->ea_addr.eau_ip4.sin_port;

  /* Before anything else, clear the address structure */
  memset(&addr->ea_addr, 0, sizeof(addr->ea_addr));

  /* Try converting it as IPv4 */
  if (evutil_inet_pton(AF_INET, pres, &addr->ea_addr.eau_ip4.sin_addr)) {
    addr->ea_flags |= EA_IPADDR;
    addr->ea_addr.eau_ip4.sin_family = AF_INET;
    if (addr->ea_flags & EA_PORT)
      addr->ea_addr.eau_ip4.sin_port = port;
    addr->ea_addrlen = sizeof(addr->ea_addr.eau_ip4);

    return 1;
  }

#ifdef AF_INET6
  /* Try converting it as IPv6 */
  if (evutil_inet_pton(AF_INET6, pres, &addr->ea_addr.eau_ip6.sin6_addr)) {
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
    config_report(ctx, LOG_WARNING,
		  "IPv6 addresses are not supported by this system");
    inet6_warning = 1;
  }
#endif

  /* OK, it's an invalid address */
  config_report(ctx, LOG_WARNING, "Invalid IP address \"%s\"", pres);
  addr->ea_flags |= EA_INVALID;

  return 0;
}

int
ep_addr_set_port(ep_addr_t *addr, int port, conf_ctx_t *ctx)
{
  /* No warning necessary; it's already been given */
  if (addr->ea_flags & EA_INVALID)
    return 0;

  /* Look out for duplications */
  if (addr->ea_flags & (EA_LOCAL | EA_PORT)) {
    config_report(ctx, LOG_WARNING, "Port has already been set");
    addr->ea_flags |= EA_INVALID;
    return 0;
  }

  /* Bounds-check the port number */
  if (port <= 0 || port > 65535) {
    config_report(ctx, LOG_WARNING, "Port %d out of range (0, 65535]", port);
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
ep_addr_set_fromaddr(ep_addr_t *addr, struct sockaddr *sockaddr, int addrlen)
{
  /* Initialize the address */
  ep_addr_init(addr);

  /* Save the address length (the easy part) */
  addr->ea_addrlen = addrlen;

  /* Save the address itself (the hard part) */
#ifdef AF_LOCAL
  if (sockaddr->sa_family == AF_LOCAL) {
    memcpy(&addr->ea_addr.eau_addr, sockaddr, addrlen);
    addr->ea_flags |= EA_LOCAL;
    return;
  }
#endif
#ifdef AF_INET6
    if (sockaddr->sa_family == AF_INET6)
      addr->ea_addr.eau_ip6 = *((struct sockaddr_in6 *)sockaddr);
    else
#endif
      addr->ea_addr.eau_ip4 = *((struct sockaddr_in *)sockaddr);
    addr->ea_flags |= EA_IPADDR | EA_PORT;
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
      /* Load the port from the source */
#ifdef AF_INET6
      if (src->ea_addr.eau_addr.sa_family == AF_INET6)
	port = src->ea_addr.eau_ip6.sin6_port;
      else
#endif
	port = src->ea_addr.eau_ip4.sin_port;

      /* Save it to the destination */
#ifdef AF_INET6
      if (dest->ea_addr.eau_addr.sa_family == AF_INET6)
	dest->ea_addr.eau_ip6.sin6_port = port;
      else
#endif
	dest->ea_addr.eau_ip4.sin_port = port;

      /* Record that we have the port */
      dest->ea_flags |= EA_PORT;
    }
#ifdef AF_LOCAL
  }
#endif
}

const char *
ep_addr_describe(ep_addr_t *addr, char *buf, size_t buflen)
{
  const void *ipaddr;
  const char *br_open = "", *br_close = "";
  int port;
#ifdef INET6_ADDRSTRLEN
  char addr_buf[INET6_ADDRSTRLEN + 1];
#else
  char addr_buf[INET_ADDRSTRLEN + 1];
#endif

  if (addr->ea_flags & EA_INVALID)
    snprintf(buf, buflen, "Invalid address");
#ifdef AF_LOCAL
  else if (addr->ea_flags & EA_LOCAL)
    snprintf(buf, buflen, "[%s]", addr->ea_addr.eau_local.sun_path);
#endif
  else if (!(addr->ea_flags & EA_IPADDR))
    snprintf(buf, buflen, "[]:%d", (addr->ea_flags & EA_PORT) ?
	     ntohs(addr->ea_addr.eau_ip4.sin_port) : 0);
  else {
#ifdef AF_INET6
    if (addr->ea_addr.eau_addr.sa_family == AF_INET6) {
      br_open = "[";
      br_close = "]";
      ipaddr = (void *)&addr->ea_addr.eau_ip6.sin6_addr;
      port = addr->ea_addr.eau_ip6.sin6_port;
    } else {
#endif
      ipaddr = (void *)&addr->ea_addr.eau_ip4.sin_addr;
      port = addr->ea_addr.eau_ip4.sin_port;
#ifdef AF_INET6
    }
#endif

    snprintf(buf, buflen, "%s%s%s:%d", br_open,
	     evutil_inet_ntop(addr->ea_addr.eau_addr.sa_family, ipaddr,
			      addr_buf, sizeof(addr_buf)),
	     br_close, (addr->ea_flags & EA_PORT) ? ntohs(port) : 0);
  }

  return buf;
}

int
ep_addr_comp(const void *key1, const void *key2)
{
  int comp;
  const ep_addr_t *addr1 = key1, *addr2 = key2;

  /* Invalid addresses are indistinguishable and sort before others */
  if (addr1->ea_flags & EA_INVALID)
    return (addr2->ea_flags & EA_INVALID) ? 0 : -1;
  else if (addr2->ea_flags & EA_INVALID)
    return 1;

  /* Compare address families */
  if (addr1->ea_addr.eau_addr.sa_family != addr2->ea_addr.eau_addr.sa_family)
    return (addr1->ea_addr.eau_addr.sa_family -
	    addr2->ea_addr.eau_addr.sa_family);

  /* OK, same family; compare contents */
#ifdef AF_LOCAL
  if (addr1->ea_flags & EA_LOCAL)
    /* Just compare endpoint names */
    return strcmp(addr1->ea_addr.eau_local.sun_path,
		  addr2->ea_addr.eau_local.sun_path);
#endif

#ifdef AF_INET6
  /* Is it an IPv6 address? */
  if (addr1->ea_addr.eau_addr.sa_family == AF_INET6) {
    if ((comp = memcmp(&addr1->ea_addr.eau_ip6.sin6_addr,
		       &addr2->ea_addr.eau_ip6.sin6_addr,
		       sizeof(addr1->ea_addr.eau_ip6.sin6_addr))))
      return comp;

    /* Addresses are the same, so check ports */
    return (addr1->ea_addr.eau_ip6.sin6_port -
	    addr2->ea_addr.eau_ip6.sin6_port);
  }
#endif

  /* Compare the IPv4 addresses */
  if ((comp = memcmp(&addr1->ea_addr.eau_ip4.sin_addr,
		     &addr2->ea_addr.eau_ip4.sin_addr,
		     sizeof(addr1->ea_addr.eau_ip4.sin_addr))))
    return comp;

  /* Addresses are the same, so check ports */
  return addr1->ea_addr.eau_ip4.sin_port - addr2->ea_addr.eau_ip4.sin_port;
}

hash_t
ep_addr_hash(const void *key)
{
  hash_t hash = HASH_INIT;
  const ep_addr_t *addr = key;

  /* Invalid addresses are essentially zero length */
  if (addr->ea_flags & EA_INVALID)
    return hash;

  /* Hash the address family */
  hash = hash_fnv1a_update(hash, &addr->ea_addr.eau_addr.sa_family,
			   sizeof(addr->ea_addr.eau_addr.sa_family));

  /* Hash the address itself */
#ifdef AF_LOCAL
  if (addr->ea_flags & EA_LOCAL)
    /* For a local address, hash the path */
    return hash_fnv1a_update(hash, addr->ea_addr.eau_local.sun_path, -1);
#endif

#ifdef AF_INET6
  /* Is it an IPv6 address? */
  if (addr->ea_addr.eau_addr.sa_family == AF_INET6) {
    hash = hash_fnv1a_update(hash, &addr->ea_addr.eau_ip6.sin6_addr,
			     sizeof(addr->ea_addr.eau_ip6.sin6_addr));
    return hash_fnv1a_update(hash, &addr->ea_addr.eau_ip6.sin6_port,
			     sizeof(addr->ea_addr.eau_ip6.sin6_port));
  }
#endif

  /* Hash the IPv4 address and the port */
  hash = hash_fnv1a_update(hash, &addr->ea_addr.eau_ip4.sin_addr,
			   sizeof(addr->ea_addr.eau_ip4.sin_addr));
  return hash_fnv1a_update(hash, &addr->ea_addr.eau_ip4.sin_port,
			   sizeof(addr->ea_addr.eau_ip4.sin_port));
}

ep_ad_t *
ep_ad_create(ep_config_t *epconf)
{
  ep_ad_t *ad;

  common_verify(epconf, EP_CONFIG_MAGIC);

  /* Allocate an advertisement */
  if (!(ad = alloc(&advertisements)))
    return 0;

  /* Initialize it */
  ep_ad_init(ad, epconf);

  return ad;
}

int
ep_ad_finish(ep_ad_t *ad, config_t *conf, conf_ctx_t *ctx)
{
  /* Add the advertisement to the endpoint's linked list */
  link_append(&ad->epa_config->epc_ads, &ad->epa_link);

  return 1;
}

void
ep_ad_release(ep_ad_t *ad)
{
  /* Remove from the hash table and linked list */
  hash_remove(&ad->epa_hashent);
  link_pop(&ad->epa_link);

  /* Zero the advertisement */
  ep_ad_init(ad, 0);

  /* Release the advertisement */
  release(&advertisements, ad);
}

ep_config_t *
ep_config_create(void)
{
  ep_config_t *config;

  /* Allocate a config */
  if (!(config = alloc(&configs)))
    return 0;

  /* Initialize it */
  ep_config_init(config);

  return config;
}

static int
ep_config_telescope(ep_config_t *ep_conf, config_t *conf, conf_ctx_t *ctx,
		    int family)
{
  uint16_t port = 0;
  link_elem_t *if_elem, *ad_elem;
  interface_t *iface;
  ep_config_t *new_conf;
  ep_ad_t *ad, *new_ad;

  /* First, make sure we have the interfaces information */
  if (!conf->cf_interfaces && !(conf->cf_interfaces = interfaces_get())) {
    config_report(ctx, LOG_WARNING, "Unable to get system interfaces");
    return 0;
  } else if (!conf->cf_interfaces->ifs_interfaces.lh_count) {
    config_report(ctx, LOG_WARNING, "No local system interfaces");
    return 0;
  }

  /* Get the port, if set */
  if (ep_conf->epc_addr.ea_flags & EA_PORT) {
#ifdef AF_INET6
    if (ep_conf->epc_addr.ea_addr.eau_addr.sa_family == AF_INET6)
      port = ep_conf->epc_addr.ea_addr.eau_ip6.sin6_port;
    else
#endif
      port = ep_conf->epc_addr.ea_addr.eau_ip4.sin_port;
  }

  /* Iterate through the list by hand */
  for (if_elem = conf->cf_interfaces->ifs_interfaces.lh_first; if_elem;
       if_elem = if_elem->le_next) {
    /* Get the interface */
    iface = if_elem->le_obj;

    /* Skip interfaces that aren't in the desired family */
    if (family && iface->if_addr.ea_addr.eau_addr.sa_family != family)
      continue;

    /* Get a new configuration */
    if (!(new_conf = ep_config_create())) {
      config_report(ctx, LOG_WARNING, "Out of memory telescoping endpoint");
      continue;
    }

    /* Copy over important information */
    new_conf->epc_flags = ep_conf->epc_flags;
    new_conf->epc_type = ep_conf->epc_type;
    if (ep_conf->epc_username &&
	!(new_conf->epc_username = strdup(ep_conf->epc_username))) {
      config_report(ctx, LOG_WARNING, "Out of memory telescoping endpoint");
      ep_config_release(new_conf);
      continue;
    }

    /* OK, now we set up the address */
    ep_addr_default(&new_conf->epc_addr, &iface->if_addr);

    /* Copy over the port */
    if (ep_conf->epc_addr.ea_flags & EA_PORT) {
      if (new_conf->epc_addr.ea_addr.eau_addr.sa_family == AF_INET)
	new_conf->epc_addr.ea_addr.eau_ip4.sin_port = port;
#ifdef AF_INET6
      else if (new_conf->epc_addr.ea_addr.eau_addr.sa_family == AF_INET6)
	new_conf->epc_addr.ea_addr.eau_ip6.sin6_port = port;
#endif
      new_conf->epc_addr.ea_flags |= EA_PORT;
    }

    /* Copy the advertisements */
    for (ad_elem = ep_conf->epc_ads.lh_first; ad_elem;
	 ad_elem = ad_elem->le_next) {
      /* Get the advertisement */
      ad = ad_elem->le_obj;

      /* Create a new advertisement */
      if (!(new_ad = ep_ad_create(new_conf))) {
	config_report(ctx, LOG_WARNING, "Out of memory telescoping endpoint");
	continue;
      }

      /* Copy over important information */
      new_ad->epa_flags = ad->epa_flags;
      new_ad->epa_addr = ad->epa_addr;
      memcpy(&new_ad->epa_network, &ad->epa_network, sizeof(ad->epa_network));

      /* Finish the new advertisement */
      if (!ep_ad_finish(new_ad, conf, ctx))
	ep_ad_release(new_ad);
    }

    /* Finish the new endpoint */
    if (!ep_config_finish(new_conf, conf, ctx))
      ep_config_release(new_conf);
  }

  /* Release the original configuration that we've telescoped */
  ep_config_release(ep_conf);

  return 1;
}

static void
ep_config_release_ads(ep_ad_t *ad, void *extra)
{
  ep_ad_release(ad);
}

int
ep_config_finish(ep_config_t *ep_conf, config_t *conf, conf_ctx_t *ctx)
{
  ep_ad_t *ad;
  link_elem_t *elem;

  /* Check if we need to multiply our configs */
  if (!(ep_conf->epc_addr.ea_flags & (EA_LOCAL | EA_IPADDR)))
    return ep_config_telescope(ep_conf, conf, ctx, 0);
  else if (ep_conf->epc_addr.ea_flags & EA_IPADDR) {
    if (ep_conf->epc_addr.ea_addr.eau_addr.sa_family == AF_INET &&
	ep_conf->epc_addr.ea_addr.eau_ip4.sin_addr.s_addr == INADDR_ANY)
      return ep_config_telescope(ep_conf, conf, ctx, AF_INET);
#ifdef AF_INET6
    else if (ep_conf->epc_addr.ea_addr.eau_addr.sa_family == AF_INET6 &&
	     IN6_IS_ADDR_UNSPECIFIED(&ep_conf->epc_addr.ea_addr
				     .eau_ip6.sin6_addr))
      return ep_config_telescope(ep_conf, conf, ctx, AF_INET6);
#endif
  }

  /* Set the default port as needed */
  if (!(ep_conf->epc_addr.ea_flags & (EA_LOCAL | EA_PORT)))
    ep_addr_set_port(&ep_conf->epc_addr, DEFAULT_PORT, ctx);

  /* Add the endpoint to the configuration */
  switch (hash_add(&conf->cf_endpoints, &ep_conf->epc_hashent)) {
  case DBERR_NONE:
    break; /* add successful */

  case DBERR_DUPLICATE:
    config_report(ctx, LOG_WARNING, "Endpoint is a duplicate");
    return 0;
    break; /* not reached */

  case DBERR_NOMEMORY:
    config_report(ctx, LOG_WARNING, "Out of memory reading endpoints");
    return 0;
    break; /* not reached */
  }

  /* Set up the endpoint type */
  if (ep_conf->epc_addr.ea_flags & EA_LOCAL)
    ep_conf->epc_type = ENDPOINT_CLIENT;
  else if (ep_conf->epc_type == ENDPOINT_UNKNOWN)
    ep_conf->epc_type = ENDPOINT_PEER;

  /* Set up advertisements */
  if (ep_conf->epc_type == ENDPOINT_CLIENT) {
    ep_conf->epc_flags |= EP_CONFIG_UNADVERTISED;

    /* Clear any advertisements */
    link_iter(&ep_conf->epc_ads, (db_iter_t)ep_config_release_ads, 0);
  } else if (!ep_conf->epc_ads.lh_count) {
    if (!(ad = ep_ad_create(ep_conf)))
      config_report(ctx, LOG_WARNING,
		    "Out of memory creating default endpoint advertisement");
    else if (!ep_ad_finish(ad, conf, ctx))
      ep_ad_release(ad);
  }

  /* Polish the endpoint's advertisements */
  for (elem = ep_conf->epc_ads.lh_first; elem; elem = elem->le_next) {
    ad = elem->le_obj;

    /* Set up the advertisement's default addressing */
    ep_addr_default(&ad->epa_addr, &ep_conf->epc_addr);

    /* Add the advertisement to the configuration */
    switch (hash_add(&conf->cf_ads, &ad->epa_hashent)) {
    case DBERR_NONE:
      break; /* add successful */

    case DBERR_DUPLICATE:
      config_report(ctx, LOG_WARNING, "Endpoint advertisement is a duplicate");
      break;

    case DBERR_NOMEMORY:
      config_report(ctx, LOG_WARNING,
		    "Out of memory adding endpoint advertisements");
      break;
    }
  }

  return 1;
}

void
ep_config_release(ep_config_t *config)
{
  /* Release the username, if allocated */
  if (config->epc_username)
    free((void *)config->epc_username);

  /* Release the endpoint advertisements */
  link_iter(&config->epc_ads, (db_iter_t)ep_config_release_ads, 0);

  /* Zero the config */
  ep_config_init(config);

  /* Release the configuration */
  release(&configs, config);
}

ep_network_t *
ep_network_create(void)
{
  ep_network_t *network;

  /* Allocate a network */
  if (!(network = alloc(&networks)))
    return 0;

  /* Initialize it */
  ep_network_init(network);

  return network;
}

int
ep_network_finish(ep_network_t *network, config_t *conf, conf_ctx_t *ctx)
{
  /* Add the network to the configuration */
  switch (hash_add(&conf->cf_networks, &network->epn_hashent)) {
  case DBERR_NONE:
    break; /* add was successful */

  case DBERR_DUPLICATE:
    config_report(ctx, LOG_WARNING, "Network \"%s\" is a duplicate",
		  network->epn_name);
    ep_network_release(network);
    return 0;
    break; /* not reached */

  case DBERR_NOMEMORY:
    config_report(ctx, LOG_WARNING, "Out of memory reading networks");
    ep_network_release(network);
    return 0;
    break; /* not reached */
  }

  return 1;
}

void
ep_network_release(ep_network_t *network)
{
  /* Zero the network */
  ep_network_init(network);

  /* Release the network */
  release(&networks, network);
}

static void
_endpoint_listener(struct evconnlistener *listener, evutil_socket_t sock,
		   struct sockaddr *addr, int addrlen, endpoint_t *endpoint)
{
  char address[ADDR_DESCRIPTION];
  char ep_addr[ADDR_DESCRIPTION], conf_addr[ADDR_DESCRIPTION];
  char configured[ADDR_DESCRIPTION + sizeof(" (configured as )")] = "";
  const char *type;
  ep_addr_t cliaddr;

  /* Describe the endpoint and configuration addresses */
  ep_addr_describe(&endpoint->ep_addr, ep_addr, sizeof(ep_addr));
  if (memcmp(&endpoint->ep_addr, &endpoint->ep_config->epc_addr,
	     sizeof(ep_addr_t)))
    snprintf(configured, sizeof(configured), " (configured as %s)",
	     ep_addr_describe(&endpoint->ep_config->epc_addr, conf_addr,
			      sizeof(conf_addr)));
  type = (endpoint->ep_config->epc_type == ENDPOINT_CLIENT ? "client" :
	  (endpoint->ep_config->epc_type == ENDPOINT_PEER ? "peer" :
	   "unknown"));

  /* Construct the address of the client */
  ep_addr_set_fromaddr(&cliaddr, addr, addrlen);
  ep_addr_describe(&cliaddr, address, sizeof(address));

  log_emit(endpoint->ep_runtime->rt_config, LOG_INFO,
#ifdef WIN32
	   "Connection from %s at %s (id %" PRIdPTR ") on endpoint %s%s",
#else
	   "Connection from %s at %s (id %d) on endpoint %s%s",
#endif
	   type, address, sock, ep_addr, configured);

  /* Create the connection; responsibility for sock passes here */
  connection_create(endpoint->ep_runtime, endpoint, sock, &cliaddr);
}

static int
_endpoint_create(runtime_t *runtime, ep_config_t *config, ep_addr_t *addr)
{
  char address[ADDR_DESCRIPTION], conf_addr[ADDR_DESCRIPTION];
  char configured[ADDR_DESCRIPTION + sizeof(" (configured as )")] = "";
  endpoint_t *endpoint;

  ep_addr_describe(addr, address, sizeof(address));
  if (addr != &config->epc_addr)
    snprintf(configured, sizeof(configured), " (configured as %s)",
	     ep_addr_describe(&config->epc_addr, conf_addr,
			      sizeof(conf_addr)));

  log_emit(runtime->rt_config, LOG_INFO, "Creating endpoint for %s%s",
	   address, configured);

  /* Allocate an item */
  if (!(endpoint = alloc(&endpoints))) {
    log_emit(runtime->rt_config, LOG_WARNING,
	     "Out of memory creating endpoint %s%s", address, configured);
    return 0;
  }

  /* Initialize the endpoint */
  link_elem_init(&endpoint->ep_link, endpoint);
  endpoint->ep_addr = *addr;
  endpoint->ep_config = config;
  endpoint->ep_runtime = runtime;

#ifdef AF_LOCAL
  /* Make sure the local socket is unlinked */
  if (addr->ea_flags & EA_LOCAL)
    unlink(endpoint->ep_addr.ea_addr.eau_local.sun_path);
#endif

  /* Create the listening socket */
  if (!(endpoint->ep_listener = evconnlistener_new_bind(
	  runtime->rt_evbase, (evconnlistener_cb)_endpoint_listener, endpoint,
	  LEV_OPT_REUSEABLE, -1, &endpoint->ep_addr.ea_addr.eau_addr,
	  endpoint->ep_addr.ea_addrlen))) {
    log_emit(runtime->rt_config, LOG_WARNING,
	     "Failed to create a listening socket on %s%s: %s",
	     address, configured, strerror(errno));
    release(&endpoints, endpoint);
    return 0;
  }

  /* Set the magic number, now that it's valid */
  endpoint->ep_magic = ENDPOINT_MAGIC;

  /* Add it to the list of endpoints */
  link_append(&runtime->rt_endpoints, &endpoint->ep_link);

  return 1;
}

int
endpoint_create(runtime_t *runtime, ep_config_t *config)
{
  int cnt = 0;

  common_verify(config, EP_CONFIG_MAGIC);

  /* Is it an all-zeros interface? */
  if (!(config->epc_addr.ea_flags & (EA_IPADDR | EA_LOCAL))) {
    log_emit(runtime->rt_config, LOG_ERR,
	     "Don't know how to open the all-zeros endpoint yet");
    return cnt;

  /* Open the single port */
  } else if (_endpoint_create(runtime, config, &config->epc_addr))
    cnt++;

  return cnt;
}
