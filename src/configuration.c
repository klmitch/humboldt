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

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <yaml.h>

#include "include/common.h"
#include "include/configuration.h"
#include "include/log.h"
#include "include/yaml_util.h"

/* Recognized short options */
static const char *opt_str = "c:dDf:hv";

/* Recognized long options */
static const struct option opts[] = {
  {"config", required_argument, 0, 'c'},
  {"debug", no_argument, 0, 'd'},
  {"no-debug", no_argument, 0, 'D'},
  {"facility", required_argument, 0, 'f'},
  {"help", no_argument, 0, 'h'},
  {"version", no_argument, 0, 'v'},
  {0, 0, 0, 0}
};

static void
usage(const char *prog, int exit_code)
{
  FILE *stream = exit_code == EXIT_SUCCESS ? stdout : stderr;

  /* Output a usage message */
  fprintf(stream, "Usage: %s [options]\n\n", prog);
  fprintf(stream, "Start the " PACKAGE_NAME ".\n\n");
  fprintf(stream, "Options:\n");
  fprintf(stream, "-c FILE, --config FILE  Location of the Humboldt "
	  "configuration file (default:\n");
  fprintf(stream, "                        " DEFAULT_CONFIG ")\n");
  fprintf(stream, "-d, --debug             Enable debugging output; "
	  "overrides configuration file.\n");
  fprintf(stream, "-D, --no-debug          Disable debugging output; "
	  "overrides configuration file.\n");
  fprintf(stream, "-f FACILITY, --facility FACILITY\n");
  fprintf(stream, "                        Log to the specified syslog "
	  "facility.\n");
  fprintf(stream, "-h, --help              Show this help message and "
	  "exit.\n");
  fprintf(stream, "-v, --version           Output version information.\n");

  exit(exit_code);
}

static void
parse_args(config_t *conf, int argc, char **argv)
{
  int c;

  common_verify(conf, CONFIG_MAGIC);

  while ((c = getopt_long(argc, argv, opt_str, opts, 0)) >= 0)
    switch (c) {
    case 'c':
      /* Has the configuration already been set? */
      if (!(conf->cf_flags & CONFIG_FILE_DEFAULT)) {
	fprintf(stderr, "%s: Configuration file has already been set to "
		"\"%s\"\n", conf->cf_prog, conf->cf_config);
	usage(conf->cf_prog, EXIT_FAILURE);
      }

      /* Save the configuration file */
      conf->cf_config = optarg;  /* can't be unallocated */
      conf->cf_flags &= ~CONFIG_FILE_DEFAULT;
      break;

    case 'd':
      /* -d and -D are mutually exclusive; can detect from
       * CONFIG_DEBUG_FIXED.
       */
      if ((conf->cf_flags & (CONFIG_DEBUG | CONFIG_DEBUG_FIXED)) ==
	  CONFIG_DEBUG_FIXED) {
	fprintf(stderr, "%s: The \"-d\" and \"-D\" options are "
		"mutually exclusive.\n", conf->cf_prog);
	usage(conf->cf_prog, EXIT_FAILURE);
      }

      /* Enable debugging, and prohibit override from the
       * configuration file.
       */
      conf->cf_flags |= CONFIG_DEBUG | CONFIG_DEBUG_FIXED;
      break;

    case 'D':
      /* -d and -D are mutually exclusive; can detect from
       * CONFIG_DEBUG_FIXED.
       */
      if ((conf->cf_flags & (CONFIG_DEBUG | CONFIG_DEBUG_FIXED)) ==
	  (CONFIG_DEBUG | CONFIG_DEBUG_FIXED)) {
	fprintf(stderr, "%s: The \"-d\" and \"-D\" options are "
		"mutually exclusive.\n", conf->cf_prog);
	usage(conf->cf_prog, EXIT_FAILURE);
      }

      /* Disable debugging, and prohibit override from the
       * configuration file.
       */
      conf->cf_flags |= CONFIG_DEBUG_FIXED;
      break;

    case 'f':
      /* Don't allow -f to be used multiple times */
      if (conf->cf_flags & CONFIG_FACILITY_FIXED) {
	fprintf(stderr, "%s: The facility has already been set\n",
		conf->cf_prog);
	usage(conf->cf_prog, EXIT_FAILURE);
      }

      /* Look up the facility */
      if ((conf->cf_facility = log_facility(optarg)) < 0) {
	fprintf(stderr, "%s: Unknown syslog facility \"%s\"\n",
		conf->cf_prog, optarg);
	exit(EXIT_FAILURE);
      }
      conf->cf_flags |= CONFIG_FACILITY_FIXED;
      break;

    case 'h':
      /* Emit the usage message */
      usage(conf->cf_prog, EXIT_SUCCESS);
      break;

    case 'v':
      /* Emit the description and version */
      printf("%s\n", PACKAGE_STRING);
      exit(EXIT_SUCCESS);
      break;

    case '?':
      usage(conf->cf_prog, EXIT_FAILURE);
      break;

    default:
      fprintf(stderr, "%s: Programming error: Unimplemented option -%c\n",
	      conf->cf_prog, c);
      abort();
      break;
    }

  /* Check for any unrecognized arguments */
  if (argv[optind]) {
    fprintf(stderr, "%s: Extraneous trailing arguments\n", conf->cf_prog);
    usage(conf->cf_prog, EXIT_FAILURE);
  }
}

static void
proc_debug(const char *key, config_t *conf, yaml_ctx_t *ctx,
	   yaml_node_t *value)
{
  int debug;

  common_verify(conf, CONFIG_MAGIC);

  /* Convert the value as boolean */
  if (yaml_get_bool(ctx, value, &debug) &&
      !(conf->cf_flags & CONFIG_DEBUG_FIXED))
    switch (debug) {
    case 1:
      conf->cf_flags |= CONFIG_DEBUG;
      break;

    case 0:
      conf->cf_flags &= ~CONFIG_DEBUG;
      break;

    default:
      break;
    }
}

static void
proc_endpoint_ad_ip(const char *key, ep_ad_t *ad,
		    yaml_ctx_t *ctx, yaml_node_t *value)
{
  const char *pres;

  common_verify(ad, EP_AD_MAGIC);

  /* Convert the IP as a string and set it */
  if (!yaml_get_str(ctx, value, &pres, 0) ||
      !ep_addr_set_ipaddr(&ad->epa_addr, pres, ctx, value))
    ad->epa_flags |= EP_AD_INVALID;
}

static void
proc_endpoint_ad_network(const char *key, ep_ad_t *ad,
			 yaml_ctx_t *ctx, yaml_node_t *value)
{
  const char *network;

  common_verify(ad, EP_AD_MAGIC);

  /* Convert the network name as a string */
  if (yaml_get_str(ctx, value, &network, 0)) {
    if (strlen(network) > NETWORK_LEN) {
      yaml_ctx_report(ctx, &value->start_mark, LOG_WARNING,
		      "Network name \"%s\" too long; maximum length: %d",
		      network, NETWORK_LEN);
      ad->epa_flags |= EP_AD_INVALID;
    } else
      strcpy(ad->epa_network, network);
  } else
    ad->epa_flags |= EP_AD_INVALID;
}

static void
proc_endpoint_ad_port(const char *key, ep_ad_t *ad,
		      yaml_ctx_t *ctx, yaml_node_t *value)
{
  long port;

  common_verify(ad, EP_AD_MAGIC);

  /* Convert the value as an integer and set the port */
  if (!yaml_get_int(ctx, value, &port) ||
      !ep_addr_set_port(&ad->epa_addr, port, ctx, value))
    ad->epa_flags |= EP_AD_INVALID;
}

static mapkeys_t ad_config[] = {
  MAPKEY("ip", proc_endpoint_ad_ip),
  MAPKEY("network", proc_endpoint_ad_network),
  MAPKEY("port", proc_endpoint_ad_port)
};

static void
proc_endpoint_ad(int idx, ep_config_t *endpoint, yaml_ctx_t *ctx,
		 yaml_node_t *value)
{
  ep_ad_t *ad;

  common_verify(endpoint, EP_CONFIG_MAGIC);

  /* Allocate an advertisement */
  if (!(ad = flexlist_append(&endpoint->epc_ads))) {
    yaml_ctx_report(ctx, &value->start_mark, LOG_WARNING,
		    "Out of memory reading endpoint advertisements");
    return;
  }

  /* Initialize the endpoint advertisement descriptor */
  ep_ad_init(ad, endpoint);

  /* Process the configuration */
  yaml_ctx_path_push_idx(ctx, idx);
  yaml_proc_mapping(ctx, value, ad_config, MAPKEYS_COUNT(ad_config),
		    (void *)ad);
  yaml_ctx_path_pop(ctx);

  /* Validate the advertisement */
  if (ad->epa_flags & EA_INVALID) {
    ep_ad_release(ad);
    flexlist_pop(&endpoint->epc_ads);
  } else
    ep_addr_default(&ad->epa_addr, &endpoint->epc_addr);
}

static void
proc_endpoint_advertise(const char *key, ep_config_t *endpoint,
			yaml_ctx_t *ctx, yaml_node_t *value)
{
  int advertise;

  common_verify(endpoint, EP_CONFIG_MAGIC);

  if (value->type == YAML_SEQUENCE_NODE) {
    /* Process all the elements in the sequence */
    yaml_ctx_path_push_key(ctx, key);
    yaml_proc_sequence(ctx, value, (itemproc_t)proc_endpoint_ad, endpoint);
    yaml_ctx_path_pop(ctx);
  } else if (yaml_get_bool(ctx, value, &advertise)) {
    if (!advertise)
      endpoint->epc_flags |= EP_CONFIG_UNADVERTISED;
  } else
    endpoint->epc_flags |= EP_CONFIG_INVALID;
}

static void
proc_endpoint_ip(const char *key, ep_config_t *endpoint,
		 yaml_ctx_t *ctx, yaml_node_t *value)
{
  const char *pres;

  common_verify(endpoint, EP_CONFIG_MAGIC);

  /* Convert the IP as a string and set it */
  if (!yaml_get_str(ctx, value, &pres, 0) ||
      !ep_addr_set_ipaddr(&endpoint->epc_addr, pres, ctx, value))
    endpoint->epc_flags |= EP_CONFIG_INVALID;
}

static void
proc_endpoint_local(const char *key, ep_config_t *endpoint,
		    yaml_ctx_t *ctx, yaml_node_t *value)
{
  const char *path;

  common_verify(endpoint, EP_CONFIG_MAGIC);

  /* Convert the value as a string and set it */
  if (!yaml_get_str(ctx, value, &path, 0) ||
      !ep_addr_set_local(&endpoint->epc_addr, path, ctx, value))
    endpoint->epc_flags |= EP_CONFIG_INVALID;
}

static void
proc_endpoint_port(const char *key, ep_config_t *endpoint,
		   yaml_ctx_t *ctx, yaml_node_t *value)
{
  long port;

  common_verify(endpoint, EP_CONFIG_MAGIC);

  /* Convert the value as an integer and set the port */
  if (!yaml_get_int(ctx, value, &port) ||
      !ep_addr_set_port(&endpoint->epc_addr, port, ctx, value))
    endpoint->epc_flags |= EP_CONFIG_INVALID;
}

static void
proc_endpoint_type(const char *key, ep_config_t *endpoint,
		   yaml_ctx_t *ctx, yaml_node_t *value)
{
  const char *type;

  common_verify(endpoint, EP_CONFIG_MAGIC);

  /* Convert the value as a string */
  if (yaml_get_str(ctx, value, &type, 0)) {
    if (!strcmp(type, "client"))
      endpoint->epc_type = ENDPOINT_CLIENT;
    else if (!strcmp(type, "peer"))
      endpoint->epc_type = ENDPOINT_PEER;
    else {
      yaml_ctx_report(ctx, &value->start_mark, LOG_WARNING,
		      "Invalid endpoint type \"%s\"; "
		      "use \"client\" or \"peer\"", type);
      endpoint->epc_flags |= EP_CONFIG_INVALID;
    }
  } else
    endpoint->epc_flags |= EP_CONFIG_INVALID;
}

static mapkeys_t endpoint_config[] = {
  MAPKEY("advertise", proc_endpoint_advertise),
  MAPKEY("ip", proc_endpoint_ip),
  MAPKEY("local", proc_endpoint_local),
  MAPKEY("port", proc_endpoint_port),
  MAPKEY("type", proc_endpoint_type)
};

static void
proc_endpoint(int idx, config_t *conf, yaml_ctx_t *ctx, yaml_node_t *value)
{
  int i;
  ep_config_t *endpoint;
  ep_ad_t *ad;

  common_verify(conf, CONFIG_MAGIC);

  /* Allocate an endpoint */
  if (!(endpoint = flexlist_append(&conf->cf_endpoints))) {
    yaml_ctx_report(ctx, &value->start_mark, LOG_WARNING,
		    "Out of memory reading endpoints");
    return;
  }

  /* Initialize the endpoint descriptor */
  ep_config_init(endpoint);

  /* Process the configuration */
  yaml_ctx_path_push_idx(ctx, idx);
  yaml_proc_mapping(ctx, value,
		    endpoint_config, MAPKEYS_COUNT(endpoint_config),
		    (void *)endpoint);
  yaml_ctx_path_pop(ctx);

  /* Must have an address */
  if (!(endpoint->epc_addr.ea_flags & (EA_LOCAL | EA_IPADDR))) {
    yaml_ctx_report(ctx, &value->start_mark, LOG_WARNING,
		    "No address provided for endpoint");
    endpoint->epc_flags |= EP_CONFIG_INVALID;
  }

  /* Set the default port as needed */
  if ((endpoint->epc_addr.ea_flags & (EA_IPADDR | EA_PORT)) == EA_IPADDR)
    ep_addr_set_port(&endpoint->epc_addr, DEFAULT_PORT, ctx, value);

  /* Validate the endpoint */
  if (endpoint->epc_flags & EP_CONFIG_INVALID) {
    ep_config_release(endpoint);
    flexlist_pop(&conf->cf_endpoints);
    return;
  }

  /* Set up the endpoint type */
  if (endpoint->epc_addr.ea_flags & EA_LOCAL)
    endpoint->epc_type = ENDPOINT_CLIENT;
  else if (endpoint->epc_type == ENDPOINT_UNKNOWN)
    endpoint->epc_type = ENDPOINT_PEER;

  /* Set up advertisements */
  if (endpoint->epc_type == ENDPOINT_CLIENT) {
    endpoint->epc_flags |= EP_CONFIG_UNADVERTISED;

    /* Clear any advertisements */
    if (flexlist_count(&endpoint->epc_ads)) {
      for (i = 0; i < flexlist_count(&endpoint->epc_ads); i++)
	ep_ad_release((ep_ad_t *)flexlist_item(&endpoint->epc_ads, i));

      /* Release the ad list */
      flexlist_release(&endpoint->epc_ads);
    }
  } else if (!flexlist_count(&endpoint->epc_ads)) {
    if (!(ad = flexlist_append(&endpoint->epc_ads))) {
      yaml_ctx_report(ctx, &value->start_mark, LOG_WARNING,
		      "Out of memory creating default endpoint advertisement");
      return;
    }

    /* Initialize the ad */
    ep_ad_init(ad, endpoint);

    ep_addr_default(&ad->epa_addr, &endpoint->epc_addr);
  }
}

static void
proc_endpoints(const char *key, config_t *conf, yaml_ctx_t *ctx,
	       yaml_node_t *value)
{
  common_verify(conf, CONFIG_MAGIC);

  /* Process all the elements in the sequence */
  yaml_ctx_path_push_key(ctx, key);
  yaml_proc_sequence(ctx, value, (itemproc_t)proc_endpoint, conf);
  yaml_ctx_path_pop(ctx);
}

static void
proc_facility(const char *key, config_t *conf, yaml_ctx_t *ctx,
              yaml_node_t *value)
{
  const char *name;
  int facility;

  common_verify(conf, CONFIG_MAGIC);

  /* Convert the value as a string */
  if (yaml_get_str(ctx, value, &name, 0)) {
    if ((facility = log_facility(name)) < 0)
      yaml_ctx_report(ctx, &value->start_mark, LOG_WARNING,
		      "Unrecognized facility name \"%s\"", name);
    else if (!(conf->cf_flags & CONFIG_FACILITY_FIXED))
      conf->cf_facility = facility;
  }
}

static void
proc_network_ip(const char *key, ep_network_t *network,
		yaml_ctx_t *ctx, yaml_node_t *value)
{
  const char *pres;

  common_verify(network, EP_NETWORK_MAGIC);

  /* Convert the IP as a string and set it */
  if (!yaml_get_str(ctx, value, &pres, 0) ||
      !ep_addr_set_ipaddr(&network->epn_addr, pres, ctx, value))
    network->epn_flags |= EP_NETWORK_INVALID;
}

static void
proc_network_network(const char *key, ep_network_t *network,
		     yaml_ctx_t *ctx, yaml_node_t *value)
{
  const char *name;

  common_verify(network, EP_NETWORK_MAGIC);

  /* Convert the network name as a string */
  if (yaml_get_str(ctx, value, &name, 0)) {
    if (strlen(name) > NETWORK_LEN) {
      yaml_ctx_report(ctx, &value->start_mark, LOG_WARNING,
		      "Network name \"%s\" too long; maximum length: %d",
		      name, NETWORK_LEN);
      network->epn_flags |= EP_NETWORK_INVALID;
    } else
      strcpy(network->epn_name, name);
  } else
    network->epn_flags |= EP_NETWORK_INVALID;
}

static void
proc_network_port(const char *key, ep_network_t *network,
		  yaml_ctx_t *ctx, yaml_node_t *value)
{
  long port;

  common_verify(network, EP_NETWORK_MAGIC);

  /* Convert the value as an integer and set the port */
  if (!yaml_get_int(ctx, value, &port) ||
      !ep_addr_set_port(&network->epn_addr, port, ctx, value))
    network->epn_flags |= EP_NETWORK_INVALID;
}

static mapkeys_t network_config[] = {
  MAPKEY("ip", proc_network_ip),
  MAPKEY("network", proc_network_network),
  MAPKEY("port", proc_network_port)
};

static void
proc_network(int idx, config_t *conf, yaml_ctx_t *ctx, yaml_node_t *value)
{
  ep_network_t *network;

  common_verify(conf, CONFIG_MAGIC);

  /* Allocate a network */
  if (!(network = flexlist_append(&conf->cf_networks))) {
    yaml_ctx_report(ctx, &value->start_mark, LOG_WARNING,
		    "Out of memory reading networks");
    return;
  }

  /* Initialize the network descriptor */
  ep_network_init(network);

  /* Process the configuration */
  yaml_ctx_path_push_idx(ctx, idx);
  yaml_proc_mapping(ctx, value, network_config, MAPKEYS_COUNT(network_config),
		    (void *)network);
  yaml_ctx_path_pop(ctx);

  /* Validate the network */
  if (network->epn_flags & EP_NETWORK_INVALID) {
    ep_network_release(network);
    flexlist_pop(&conf->cf_networks);
  }
}

static void
proc_networks(const char *key, config_t *conf, yaml_ctx_t *ctx,
	      yaml_node_t *value)
{
  common_verify(conf, CONFIG_MAGIC);

  /* Process all the elements in the sequence */
  yaml_ctx_path_push_key(ctx, key);
  yaml_proc_sequence(ctx, value, (itemproc_t)proc_network, conf);
  yaml_ctx_path_pop(ctx);
}

static mapkeys_t top_level[] = {
  MAPKEY("debug", proc_debug),
  MAPKEY("endpoints", proc_endpoints),
  MAPKEY("facility", proc_facility),
  MAPKEY("networks", proc_networks)
};

void
initialize_config(config_t *conf, int argc, char **argv)
{
  const char *tmp;

  common_verify(conf, CONFIG_MAGIC);

  /* Begin by filling in the program name */
  if ((tmp = strrchr(argv[0], '/')))
    conf->cf_prog = tmp + 1;
  else
    conf->cf_prog = argv[0];

  /* Next, parse command line arguments */
  parse_args(conf, argc, argv);

  /* Read the configuration file */
  yaml_file_mapping(conf, conf->cf_config, top_level, MAPKEYS_COUNT(top_level),
		    (void *)conf, 0, 0);
}
