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

int
main(int argc, char **argv)
{
  char addr_desc[ADDR_DESCRIPTION];
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

    log_emit(&conf, LOG_DEBUG, "  Endpoint %d: %s type %s (%s%s%s)", i,
	     ep_addr_describe(&endpoint->epc_addr, addr_desc,
			      sizeof(addr_desc)),
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

    if (!(endpoint->epc_flags & EP_CONFIG_UNADVERTISED)) {
      log_emit(&conf, LOG_DEBUG, "    Advertisements (%d):",
	       flexlist_count(&endpoint->epc_ads));
      for (int j = 0; j < flexlist_count(&endpoint->epc_ads); j++) {
	ep_ad_t *ad = (ep_ad_t *)flexlist_item(&endpoint->epc_ads, j);

	log_emit(&conf, LOG_DEBUG, "      Advertisement %d: %s%s%s", j,
		 ep_addr_describe(&ad->epa_addr, addr_desc, sizeof(addr_desc)),
		 ad->epa_network[0] ? " Network " : "",
		 ad->epa_network[0] ? ad->epa_network : "");
      }
    }
  }

  /* How many networks have been defined? */
  log_emit(&conf, LOG_DEBUG, "Networks (%d):",
	   flexlist_count(&conf.cf_networks));
  for (int i = 0; i < flexlist_count(&conf.cf_networks); i++) {
    ep_network_t *network = (ep_network_t *)flexlist_item(&conf.cf_networks,
							  i);

    log_emit(&conf, LOG_DEBUG, "  Network %d: %s Name %s", i,
	     ep_addr_describe(&network->epn_addr, addr_desc,
			      sizeof(addr_desc)),
	     network->epn_name ? network->epn_name : "<Public>");
  }

  /* Report the SSL configuration */
  if (!conf.cf_ssl)
    log_emit(&conf, LOG_DEBUG, "SSL not configured");
  else {
    log_emit(&conf, LOG_DEBUG, "SSL configured:");
    if (conf.cf_ssl->sc_cert_chain)
      log_emit(&conf, LOG_DEBUG, "  Certificate chain file: %s",
	       conf.cf_ssl->sc_cert_chain);
    if (conf.cf_ssl->sc_ciphers)
      log_emit(&conf, LOG_DEBUG, "  Configured SSL ciphers: %s",
	       conf.cf_ssl->sc_ciphers);
    if (conf.cf_ssl->sc_private_key)
      log_emit(&conf, LOG_DEBUG, "  Private key file: %s",
	       conf.cf_ssl->sc_private_key);
  }

  /* Initialize the runtime */
  if (!initialize_runtime(&runtime, &conf)) {
    log_emit(&conf, LOG_ERR, "Failed to initialize runtime, exiting...");
    exit(EXIT_FAILURE);
  }

  /* Run Humboldt */
  switch (run(&runtime)) {
  case -1:
    log_emit(&conf, LOG_ERR, "Unhandled error in Libevent, exiting...");
    exit(EXIT_FAILURE);
    break;

  default:
    log_emit(&conf, LOG_NOTICE, "Exiting event loop");
    break;
  }

  return 0;
}
