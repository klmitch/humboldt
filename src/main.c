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
#include "include/sasl_util.h"
#include "include/ssl.h"

static void
emit_advertisement(ep_ad_t *ad, config_t *conf)
{
  char addr_desc[ADDR_DESCRIPTION];

  log_emit(conf, LOG_DEBUG, "      Advertisement: %s%s%s",
	   ep_addr_describe(&ad->epa_addr, addr_desc, sizeof(addr_desc)),
	   ad->epa_network[0] ? " Network " : "",
	   ad->epa_network[0] ? ad->epa_network : "");
}

static void
emit_endpoint(ep_config_t *endpoint, config_t *conf)
{
  char addr_desc[ADDR_DESCRIPTION];

  log_emit(conf, LOG_DEBUG, "  Endpoint: %s type %s (%s%s%s)%s%s",
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
	    ""),
	   endpoint->epc_username ? " Username: " : "",
	   endpoint->epc_username ? endpoint->epc_username : "");

  if (!(endpoint->epc_flags & EP_CONFIG_UNADVERTISED)) {
    log_emit(conf, LOG_DEBUG, "    Advertisements (%d):",
	     endpoint->epc_ads.lh_count);
    link_iter(&endpoint->epc_ads, (db_iter_t)emit_advertisement, conf);
  }
}

static void
emit_network(ep_network_t *network, config_t *conf)
{
  char addr_desc[ADDR_DESCRIPTION];

  log_emit(conf, LOG_DEBUG, "  Network: %s Name %s",
	   ep_addr_describe(&network->epn_addr, addr_desc, sizeof(addr_desc)),
	   network->epn_name ? network->epn_name : "<Public>");
}

static void
emit_sasl_option(sasl_option_t *option, config_t *conf)
{
  log_emit(conf, LOG_DEBUG, "  Option %s: \"%s\" (%zu)",
	   option->sao_option, option->sao_value, option->sao_vallen);
}

int
main(int argc, char **argv)
{
  char uuid_buf[37];
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
  uuid_unparse(conf.cf_uuid, uuid_buf);
  log_emit(&conf, LOG_DEBUG, "Humboldt node UUID: %s", uuid_buf);

  /* How many endpoints have been defined? */
  log_emit(&conf, LOG_DEBUG, "Endpoints (%d):", conf.cf_endpoints.ht_count);
  hash_iter(&conf.cf_endpoints, (db_iter_t)emit_endpoint, &conf);

  /* How many networks have been defined? */
  log_emit(&conf, LOG_DEBUG, "Networks (%d):", conf.cf_networks.ht_count);
  hash_iter(&conf.cf_networks, (db_iter_t)emit_network, &conf);

  /* Report the SASL configuration */
  if (!conf.cf_sasl)
    log_emit(&conf, LOG_DEBUG, "SASL not configured");
  else {
    log_emit(&conf, LOG_DEBUG, "SASL configuration:");
    hash_iter(&conf.cf_sasl->sac_options, (db_iter_t)emit_sasl_option, &conf);
  }

  /* Report the SSL configuration */
  if (!conf.cf_ssl)
    log_emit(&conf, LOG_DEBUG, "SSL not configured");
  else {
    log_emit(&conf, LOG_DEBUG, "SSL configured:");
    if (conf.cf_ssl->sc_cafile)
      log_emit(&conf, LOG_DEBUG, "  Certificate CA file: %s",
	       conf.cf_ssl->sc_cafile);
    if (conf.cf_ssl->sc_capath)
      log_emit(&conf, LOG_DEBUG, "  Certificate CA path: %s",
	       conf.cf_ssl->sc_capath);
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
