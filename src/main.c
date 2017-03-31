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

#include <event2/util.h>
#include <sys/un.h>

#include "include/alloc.h"
#include "include/endpoint.h"
#include "include/configuration.h"
#include "include/log.h"
#include "include/runtime.h"

static void
emit_addr(config_t *conf, ep_addr_t *addr, const char *pfx)
{
  const void *ipaddr;
  int version, port;
#ifdef INET6_ADDRSTRLEN
  char addr_buf[INET6_ADDRSTRLEN + 1];
#else
  char addr_buf[INET_ADDRSTRLEN + 1];
#endif

  if (addr->ea_flags & EA_INVALID)
    log_emit(conf, LOG_DEBUG, "%sAddress is invalid", pfx);
#ifdef AF_LOCAL
  else if (addr->ea_flags & EA_LOCAL)
    log_emit(conf, LOG_DEBUG, "%sLocal address %s", pfx,
	     addr->ea_addr.eau_local.sun_path);
#endif
  else {
#ifdef AF_INET6
    if (addr->ea_addr.eau_addr.sa_family == AF_INET6) {
      ipaddr = (void *)&addr->ea_addr.eau_ip6.sin6_addr;
      version = 6;
      port = addr->ea_addr.eau_ip6.sin6_port;
    } else {
#endif
      ipaddr = (void *)&addr->ea_addr.eau_ip4.sin_addr;
      version = 4;
      port = addr->ea_addr.eau_ip4.sin_port;
#ifdef AF_INET6
    }
#endif

    if (addr->ea_flags & EA_IPADDR)
      log_emit(conf, LOG_DEBUG, "%sIPv%d address: %s", pfx, version,
	       evutil_inet_ntop(addr->ea_addr.eau_addr.sa_family, ipaddr,
				addr_buf, sizeof(addr_buf)));
    if (addr->ea_flags & EA_PORT)
      log_emit(conf, LOG_DEBUG, "%sPort: %d", pfx, ntohs(port));
  }
}

int
main(int argc, char **argv)
{
  config_t conf = CONFIG_INIT();
  runtime_t runtime;

  initialize_config(&conf, argc, argv);

  /* Output information about the configuration */
  log_emit(&conf, LOG_DEBUG, "Configuration file: \"%s\"%s", conf.cf_config,
	   (conf.cf_flags & CONFIG_FILE_DEFAULT) ? " (default)" : "");
  log_emit(&conf, LOG_DEBUG, "State directory: \"%s\"%s%s", conf.cf_statedir,
	   (conf.cf_flags & CONFIG_STATEDIR_ALLOCATED) ? " [allocated]" : "",
	   (conf.cf_flags & CONFIG_STATEDIR_FIXED) ? " (no override)" : "");
  log_emit(&conf, LOG_DEBUG, "Debugging mode %s%s",
	   (conf.cf_flags & CONFIG_DEBUG) ? "ENABLED" : "DISABLED",
	   (conf.cf_flags & CONFIG_DEBUG_FIXED) ? " (no override)" : "");
  log_emit(&conf, LOG_DEBUG, "Log facility %d%s", conf.cf_facility >> 3,
	   (conf.cf_flags & CONFIG_FACILITY_FIXED) ? " (no override)" : "");

  /* How many endpoints have been defined? */
  log_emit(&conf, LOG_DEBUG, "Endpoints (%d):",
	   flexlist_count(&conf.cf_endpoints));
  for (int i = 0; i < flexlist_count(&conf.cf_endpoints); i++) {
    ep_config_t *endpoint = (ep_config_t *)flexlist_item(&conf.cf_endpoints,
							 i);

    log_emit(&conf, LOG_DEBUG, "  Endpoint %d: type %s (%s%s%s)", i,
	     (endpoint->epc_type == ENDPOINT_UNKNOWN ? "unknown" :
	      (endpoint->epc_type == ENDPOINT_CLIENT ? "client" :
	       (endpoint->epc_type == ENDPOINT_PEER ? "peer" : "other"))),
	     (endpoint->epc_flags == 0 ? "no flags" :
	      (endpoint->epc_flags & EP_CONFIG_INVALID ? "invalid" :
	       "unadvertised")),
	     (endpoint->epc_flags & EP_CONFIG_INVALID ?
	      ((endpoint->epc_flags & EP_CONFIG_UNADVERTISED) ? " " : "") :
	      ""),
	     (endpoint->epc_flags ==
	      (EP_CONFIG_INVALID | EP_CONFIG_UNADVERTISED) ? "unadvertised" :
	      ""));

    emit_addr(&conf, &endpoint->epc_addr, "    ");

    if (!(endpoint->epc_flags & EP_CONFIG_UNADVERTISED)) {
      log_emit(&conf, LOG_DEBUG, "    Advertisements (%d):",
	       flexlist_count(&endpoint->epc_ads));
      for (int j = 0; j < flexlist_count(&endpoint->epc_ads); j++) {
	ep_ad_t *ad = (ep_ad_t *)flexlist_item(&endpoint->epc_ads, j);

	log_emit(&conf, LOG_DEBUG, "      Advertisement %d:%s%s", j,
		 ad->epa_network[0] ? " Network " : "",
		 ad->epa_network[0] ? ad->epa_network : "");

	emit_addr(&conf, &ad->epa_addr, "        ");
      }
    }
  }

  /* How many networks have been defined? */
  log_emit(&conf, LOG_DEBUG, "Networks (%d):",
	   flexlist_count(&conf.cf_networks));
  for (int i = 0; i < flexlist_count(&conf.cf_networks); i++) {
    ep_network_t *network = (ep_network_t *)flexlist_item(&conf.cf_networks,
							  i);

    log_emit(&conf, LOG_DEBUG, "  Network %d: %s", i, network->epn_name ?
	     network->epn_name : "<Public>");

    emit_addr(&conf, &network->epn_addr, "    ");
  }

  /* Initialize the runtime */
  if (!initialize_runtime(&runtime, &conf)) {
    log_emit(&conf, LOG_ERR, "Failed to initialize runtime, exiting...");
    exit(EXIT_FAILURE);
  }

  return 0;
}
