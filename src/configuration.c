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

#include <errno.h>
#include <getopt.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <uuid.h>
#include <yaml.h>

#include "include/common.h"
#include "include/configuration.h"
#include "include/endpoint.h"
#include "include/interfaces.h"
#include "include/log.h"
#include "include/ssl.h"
#include "include/yaml_util.h"

/* Recognized short options */
static const char *opt_str = "c:dDf:hs:v";

/* Recognized long options */
static const struct option opts[] = {
  {"config", required_argument, 0, 'c'},
  {"debug", no_argument, 0, 'd'},
  {"no-debug", no_argument, 0, 'D'},
  {"facility", required_argument, 0, 'f'},
  {"help", no_argument, 0, 'h'},
  {"statedir", required_argument, 0, 's'},
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
	  "configuration file. (default:\n");
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
  fprintf(stream, "-s DIR, --statedir DIR  Set the state directory. This "
	  "directory will contain\n");
  fprintf(stream, "                        several state files. (default:\n");
  fprintf(stream, "                        " DEFAULT_STATEDIR ")\n");
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

    case 's':
      /* Don't allow -s to be used multiple times */
      if (conf->cf_flags & CONFIG_STATEDIR_FIXED) {
	fprintf(stderr, "%s: The state directory has already been set\n",
		conf->cf_prog);
	usage(conf->cf_prog, EXIT_FAILURE);
      }

      /* Save the state directory */
      conf->cf_statedir = optarg;
      conf->cf_flags |= CONFIG_STATEDIR_FIXED;
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

void
config_report(conf_ctx_t *conf_ctx, int priority, const char *fmt, ...)
{
  va_list ap;

  /* Initialize the va_list */
  va_start(ap, fmt);

  /* Log to the correct destination */
  switch (conf_ctx->cc_flavor) {
  case CTX_FLAVOR_CONF:
    log_vemit(conf_ctx->cc_data.ccd_conf, priority, fmt, ap);
    break;

  case CTX_FLAVOR_YAML:
    yaml_ctx_vreport(conf_ctx->cc_data.ccd_yaml.ccdy_ctx,
		     conf_ctx->cc_data.ccd_yaml.ccdy_loc,
		     priority, fmt, ap);
    break;
  }

  /* Clean up */
  va_end(ap);
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
  conf_ctx_t conf_ctx = CONF_CTX_YAML(ctx, value);
  const char *pres;

  common_verify(ad, EP_AD_MAGIC);

  /* Convert the IP as a string and set it */
  if (!yaml_get_str(ctx, value, &pres, 0, 0) ||
      !ep_addr_set_ipaddr(&ad->epa_addr, pres, &conf_ctx))
    ad->epa_flags |= EP_AD_INVALID;
}

static void
proc_endpoint_ad_network(const char *key, ep_ad_t *ad,
			 yaml_ctx_t *ctx, yaml_node_t *value)
{
  conf_ctx_t conf_ctx = CONF_CTX_YAML(ctx, value);
  const char *network;

  common_verify(ad, EP_AD_MAGIC);

  /* Convert the network name as a string */
  if (yaml_get_str(ctx, value, &network, 0, 0)) {
    if (strlen(network) > NETWORK_LEN) {
      config_report(&conf_ctx, LOG_WARNING,
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
  conf_ctx_t conf_ctx = CONF_CTX_YAML(ctx, value);
  long port;

  common_verify(ad, EP_AD_MAGIC);

  /* Convert the value as an integer and set the port */
  if (!yaml_get_int(ctx, value, &port) ||
      !ep_addr_set_port(&ad->epa_addr, port, &conf_ctx))
    ad->epa_flags |= EP_AD_INVALID;
}

static mapkeys_t ad_config[] = {
  MAPKEY("ip", proc_endpoint_ad_ip),
  MAPKEY("network", proc_endpoint_ad_network),
  MAPKEY("port", proc_endpoint_ad_port)
};

struct epconfig {
  ep_config_t  *endpoint;
  config_t     *config;
};

static void
proc_endpoint_ad(int idx, struct epconfig *epc, yaml_ctx_t *ctx,
		 yaml_node_t *value)
{
  conf_ctx_t conf_ctx = CONF_CTX_YAML(ctx, value);
  const char *network;
  size_t netlen;
  ep_ad_t *ad;

  common_verify(epc->endpoint, EP_CONFIG_MAGIC);

  /* Allocate an advertisement */
  if (!(ad = ep_ad_create(epc->endpoint))) {
    config_report(&conf_ctx, LOG_WARNING,
		  "Out of memory reading endpoint advertisements");
    return;
  }

  /* Process the configuration */
  if (value->type == YAML_MAPPING_NODE)
    yaml_proc_mapping(ctx, value, ad_config, list_count(ad_config),
		      (void *)ad);
  else if (yaml_get_str(ctx, value, &network, &netlen, ALLOW_NULL)) {
    if (network) {
      if (netlen > NETWORK_LEN) {
	config_report(&conf_ctx, LOG_WARNING,
		      "Network name \"%s\" too long; maximum length: %d",
		      network, NETWORK_LEN);
	ad->epa_flags |= EP_AD_INVALID;
      } else
	strcpy(ad->epa_network, network);
    }
  } else
    ad->epa_flags |= EA_INVALID;

  /* Validate the advertisement and finish setting it up */
  if ((ad->epa_flags & EA_INVALID) ||
      !ep_ad_finish(ad, epc->config, &conf_ctx))
    ep_ad_release(ad);
}

static void
proc_endpoint_advertise(const char *key, struct epconfig *epc,
			yaml_ctx_t *ctx, yaml_node_t *value)
{
  int advertise;

  common_verify(epc->endpoint, EP_CONFIG_MAGIC);

  if (value->type == YAML_SEQUENCE_NODE)
    /* Process all the elements in the sequence */
    yaml_proc_sequence(ctx, value, (itemproc_t)proc_endpoint_ad, epc);
  else if (yaml_get_bool(ctx, value, &advertise)) {
    if (!advertise)
      epc->endpoint->epc_flags |= EP_CONFIG_UNADVERTISED;
  } else
    epc->endpoint->epc_flags |= EP_CONFIG_INVALID;
}

static void
proc_endpoint_ip(const char *key, struct epconfig *epc,
		 yaml_ctx_t *ctx, yaml_node_t *value)
{
  conf_ctx_t conf_ctx = CONF_CTX_YAML(ctx, value);
  const char *pres;

  common_verify(epc->endpoint, EP_CONFIG_MAGIC);

  /* Convert the IP as a string and set it */
  if (!yaml_get_str(ctx, value, &pres, 0, 0) ||
      !ep_addr_set_ipaddr(&epc->endpoint->epc_addr, pres, &conf_ctx))
    epc->endpoint->epc_flags |= EP_CONFIG_INVALID;
}

static void
proc_endpoint_local(const char *key, struct epconfig *epc,
		    yaml_ctx_t *ctx, yaml_node_t *value)
{
  conf_ctx_t conf_ctx = CONF_CTX_YAML(ctx, value);
  const char *path;

  common_verify(epc->endpoint, EP_CONFIG_MAGIC);

  /* Convert the value as a string and set it */
  if (!yaml_get_str(ctx, value, &path, 0, 0) ||
      !ep_addr_set_local(&epc->endpoint->epc_addr, path, &conf_ctx))
    epc->endpoint->epc_flags |= EP_CONFIG_INVALID;
}

static void
proc_endpoint_port(const char *key, struct epconfig *epc,
		   yaml_ctx_t *ctx, yaml_node_t *value)
{
  conf_ctx_t conf_ctx = CONF_CTX_YAML(ctx, value);
  long port;

  common_verify(epc->endpoint, EP_CONFIG_MAGIC);

  /* Convert the value as an integer and set the port */
  if (!yaml_get_int(ctx, value, &port) ||
      !ep_addr_set_port(&epc->endpoint->epc_addr, port, &conf_ctx))
    epc->endpoint->epc_flags |= EP_CONFIG_INVALID;
}

static void
proc_endpoint_type(const char *key, struct epconfig *epc,
		   yaml_ctx_t *ctx, yaml_node_t *value)
{
  conf_ctx_t conf_ctx = CONF_CTX_YAML(ctx, value);
  const char *type;

  common_verify(epc->endpoint, EP_CONFIG_MAGIC);

  /* Convert the value as a string */
  if (yaml_get_str(ctx, value, &type, 0, 0)) {
    if (!strcmp(type, "client"))
      epc->endpoint->epc_type = ENDPOINT_CLIENT;
    else if (!strcmp(type, "peer"))
      epc->endpoint->epc_type = ENDPOINT_PEER;
    else {
      config_report(&conf_ctx, LOG_WARNING,
		    "Invalid endpoint type \"%s\"; "
		    "use \"client\" or \"peer\"", type);
      epc->endpoint->epc_flags |= EP_CONFIG_INVALID;
    }
  } else
    epc->endpoint->epc_flags |= EP_CONFIG_INVALID;
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
  conf_ctx_t conf_ctx = CONF_CTX_YAML(ctx, value);
  struct epconfig epc = {0, conf};

  common_verify(conf, CONFIG_MAGIC);

  /* Allocate an endpoint */
  if (!(epc.endpoint = ep_config_create())) {
    config_report(&conf_ctx, LOG_WARNING, "Out of memory reading endpoints");
    return;
  }

  /* Process the configuration */
  yaml_proc_mapping(ctx, value,
		    endpoint_config, list_count(endpoint_config),
		    (void *)&epc);

  /* Validate the endpoint */
  if ((epc.endpoint->epc_flags & EP_CONFIG_INVALID) ||
      !ep_config_finish(epc.endpoint, epc.config, &conf_ctx))
    ep_config_release(epc.endpoint);
}

static void
proc_endpoints(const char *key, config_t *conf, yaml_ctx_t *ctx,
	       yaml_node_t *value)
{
  common_verify(conf, CONFIG_MAGIC);

  /* Process all the elements in the sequence */
  yaml_proc_sequence(ctx, value, (itemproc_t)proc_endpoint, conf);
}

static void
proc_facility(const char *key, config_t *conf, yaml_ctx_t *ctx,
              yaml_node_t *value)
{
  conf_ctx_t conf_ctx = CONF_CTX_YAML(ctx, value);
  const char *name;
  int facility;

  common_verify(conf, CONFIG_MAGIC);

  /* Convert the value as a string */
  if (yaml_get_str(ctx, value, &name, 0, 0)) {
    if ((facility = log_facility(name)) < 0)
      config_report(&conf_ctx, LOG_WARNING,
		    "Unrecognized facility name \"%s\"", name);
    else if (!(conf->cf_flags & CONFIG_FACILITY_FIXED))
      conf->cf_facility = facility;
  }
}

static void
proc_network_ip(const char *key, ep_network_t *network,
		yaml_ctx_t *ctx, yaml_node_t *value)
{
  conf_ctx_t conf_ctx = CONF_CTX_YAML(ctx, value);
  const char *pres;

  common_verify(network, EP_NETWORK_MAGIC);

  /* Convert the IP as a string and set it */
  if (!yaml_get_str(ctx, value, &pres, 0, 0) ||
      !ep_addr_set_ipaddr(&network->epn_addr, pres, &conf_ctx))
    network->epn_flags |= EP_NETWORK_INVALID;
}

static void
proc_network_network(const char *key, ep_network_t *network,
		     yaml_ctx_t *ctx, yaml_node_t *value)
{
  conf_ctx_t conf_ctx = CONF_CTX_YAML(ctx, value);
  const char *name;

  common_verify(network, EP_NETWORK_MAGIC);

  /* Convert the network name as a string */
  if (yaml_get_str(ctx, value, &name, 0, 0)) {
    if (strlen(name) > NETWORK_LEN) {
      config_report(&conf_ctx, LOG_WARNING,
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
  conf_ctx_t conf_ctx = CONF_CTX_YAML(ctx, value);
  long port;

  common_verify(network, EP_NETWORK_MAGIC);

  /* Convert the value as an integer and set the port */
  if (!yaml_get_int(ctx, value, &port) ||
      !ep_addr_set_port(&network->epn_addr, port, &conf_ctx))
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
  conf_ctx_t conf_ctx = CONF_CTX_YAML(ctx, value);
  const char *name;
  ep_network_t *network;

  common_verify(conf, CONFIG_MAGIC);

  /* Allocate a network */
  if (!(network = ep_network_create())) {
    config_report(&conf_ctx, LOG_WARNING, "Out of memory reading networks");
    return;
  }

  /* Process the configuration */
  if (value->type == YAML_MAPPING_NODE)
    yaml_proc_mapping(ctx, value, network_config,
		      list_count(network_config), (void *)network);
  else if (yaml_get_str(ctx, value, &name, 0, ALLOW_NULL)) {
    if (name) {
      if (strlen(name) > NETWORK_LEN) {
	config_report(&conf_ctx, LOG_WARNING,
		      "Network name \"%s\" too long; maximum length: %d",
		      name, NETWORK_LEN);
	network->epn_flags |= EP_NETWORK_INVALID;
      } else
	strcpy(network->epn_name, name);
    }
  } else
    network->epn_flags |= EP_NETWORK_INVALID;

  /* Validate the network */
  if ((network->epn_flags & EP_NETWORK_INVALID) ||
      !ep_network_finish(network, conf, &conf_ctx))
    ep_network_release(network);
}

static void
proc_networks(const char *key, config_t *conf, yaml_ctx_t *ctx,
	      yaml_node_t *value)
{
  common_verify(conf, CONFIG_MAGIC);

  /* Process all the elements in the sequence */
  yaml_proc_sequence(ctx, value, (itemproc_t)proc_network, conf);
}

static void
proc_statedir(const char *key, config_t *conf, yaml_ctx_t *ctx,
	      yaml_node_t *value)
{
  conf_ctx_t conf_ctx = CONF_CTX_YAML(ctx, value);
  int len;
  const char *dirname;
  char *tmp;

  common_verify(conf, CONFIG_MAGIC);

  /* Convert the value as a string */
  if (!yaml_get_str(ctx, value, &dirname, 0, 0))
    return;

  /* Ensure it's a valid path */
  len = strlen(dirname);
  if (*dirname != '/' || len <= 2) {
    config_report(&conf_ctx, LOG_WARNING,
		  "Invalid state directory path \"%s\"", dirname);
    return;
  } else if (conf->cf_flags & CONFIG_STATEDIR_FIXED)
    /* It's fixed from the command line */
    return;

  /* Strip off trailing slashes */
  while (dirname[len - 1] == '/')
    len--;

  /* Allocate memory for the new value */
  if (!(tmp = (char *)malloc(len))) {
    config_report(&conf_ctx, LOG_WARNING,
		  "Out of memory setting state directory path");
    return;
  }

  /* Copy the path in */
  strncpy(tmp, dirname, len);
  tmp[len] = '\0';

  /* Release the existing value if needed */
  if (conf->cf_flags & CONFIG_STATEDIR_ALLOCATED)
    free((void *)conf->cf_statedir);

  conf->cf_statedir = tmp;
  conf->cf_flags |= CONFIG_STATEDIR_ALLOCATED;
}

static void
proc_uuid(const char *key, config_t *conf, yaml_ctx_t *ctx, yaml_node_t *value)
{
  conf_ctx_t conf_ctx = CONF_CTX_YAML(ctx, value);
  const char *uuid_text;

  common_verify(conf, CONFIG_MAGIC);

  /* Convert the value as a string */
  if (!yaml_get_str(ctx, value, &uuid_text, 0, 0))
    return;

  /* Parse the UUID */
  if (uuid_parse(uuid_text, conf->cf_uuid)) {
    config_report(&conf_ctx, LOG_WARNING, "Unable to parse UUID \"%s\"",
		  uuid_text);
    return;
  }

  /* UUID is set */
  conf->cf_flags |= CONFIG_UUID_SET;
}

static mapkeys_t top_level[] = {
  MAPKEY("debug", proc_debug),
  MAPKEY("endpoints", proc_endpoints),
  MAPKEY("facility", proc_facility),
  MAPKEY("networks", proc_networks),
  MAPKEY("ssl", ssl_conf_processor),
  MAPKEY("statedir", proc_statedir),
  MAPKEY("uuid", proc_uuid)
};

struct typecount {
  int		clients;
  int		peers;
};

static void
count_endpoints(ep_config_t *endpoint, struct typecount *counts)
{
  switch (endpoint->epc_type) {
  case ENDPOINT_CLIENT:
    counts->clients++;
    break;

  case ENDPOINT_PEER:
    counts->peers++;
    break;

  default:
    break;
  }
}

int
config_read(config_t *conf)
{
  conf_ctx_t conf_ctx = CONF_CTX_CONF(conf);
  FILE *stream;
  int len, valid;
  struct typecount counts = {0, 0};
  ep_config_t *endpoint;
  ep_network_t *network;
  char path_buf[1024]; /* more than enough for a socket path */

  /* Read the configuration file */
  if (!(stream = fopen(conf->cf_config, "r"))) {
    if (!(conf->cf_flags & CONFIG_FILE_DEFAULT) || errno != ENOENT) {
      config_report(&conf_ctx, LOG_WARNING,
		    "%s opening configuration file \"%s\"",
		    strerror(errno), conf->cf_config);
      return 0;
    }
  } else {
    valid = yaml_file_mapping(conf, conf->cf_config, stream, top_level,
			      list_count(top_level), (void *)conf, 0, 0);
    fclose(stream);

    if (!valid)
      return 0;
  }

  /* Ensure we have at least one of each type of endpoint */
  hash_iter(&conf->cf_endpoints, (db_iter_t)count_endpoints, &counts);

  /* Do we need to create a client endpoint? */
  if (!counts.clients) {
    if (!(endpoint = ep_config_create()))
      config_report(&conf_ctx, LOG_WARNING,
		    "Out of memory creating default client endpoint");
    else {
      /* Set the basic flags and endpoint type */
      endpoint->epc_flags = EP_CONFIG_UNADVERTISED;
      endpoint->epc_type = ENDPOINT_CLIENT;

#ifdef AF_LOCAL
      /* Begin by copying the statedir to the path_buf */
      len = strlen(conf->cf_statedir);
      strncpy(path_buf, conf->cf_statedir, sizeof(path_buf));

      /* Add a '/' and the socket file name */
      strncpy(&path_buf[len], "/" DEFAULT_CLIENT_SOCK,
	      sizeof(path_buf) - len > 0 ? sizeof(path_buf) - len : 0);

      /* Make sure it's terminated */
      path_buf[len + sizeof("/" DEFAULT_CLIENT_SOCK) > 1024 ?
	       1023 : len + sizeof("/" DEFAULT_CLIENT_SOCK)] = '\0';

      /* Set the local address */
      if (!ep_addr_set_local(&endpoint->epc_addr, path_buf, &conf_ctx)) {
	config_report(&conf_ctx, LOG_WARNING,
		      "Unable to set up client port at \"%s\"; trying "
		      "loopback", path_buf);
	/* Clear the local address so we can try again */
	ep_addr_init(&endpoint->epc_addr);
#endif

	/* Set to the loopback address */
	if (!ep_addr_set_ipaddr(&endpoint->epc_addr, "127.0.0.1", &conf_ctx) ||
	    !ep_addr_set_port(&endpoint->epc_addr, DEFAULT_PORT, &conf_ctx))
	  config_report(&conf_ctx, LOG_WARNING,
			"Unable to create a client port");
	else
	  ep_config_finish(endpoint, conf, &conf_ctx);

#ifdef AF_LOCAL
      } else
	ep_config_finish(endpoint, conf, &conf_ctx);
#endif
    }
  }

  /* Do we need to create a peer endpoint? */
  if (!counts.peers) {
    if (!(endpoint = ep_config_create()))
      config_report(&conf_ctx, LOG_WARNING,
		    "Out of memory creating default peer endpoint");
    else {
      /* Set the endpoint type */
      endpoint->epc_type = ENDPOINT_PEER;

      /* Set the default port */
      if (!ep_addr_set_port(&endpoint->epc_addr, DEFAULT_PORT, &conf_ctx))
	config_report(&conf_ctx, LOG_WARNING, "Unable to create a peer port");
      else if (!ep_config_finish(endpoint, conf, &conf_ctx))
	ep_config_release(endpoint);
    }
  }

  /* Ensure we have at least one network */
  if (!conf->cf_networks.ht_count) {
    if (!(network = ep_network_create()))
      config_report(&conf_ctx, LOG_WARNING,
		    "Out of memory creating default network");
    else if (!ep_network_finish(network, conf, &conf_ctx))
      ep_network_release(network);
  }

  /* Clean up cached interfaces information */
  if (conf->cf_interfaces) {
    interfaces_free(conf->cf_interfaces);
    conf->cf_interfaces = 0;
  }

  return 1;
}

void
initialize_config(config_t *conf, int argc, char **argv)
{
  const char *tmp;
  char uuid_buf[37];

  common_verify(conf, CONFIG_MAGIC);

  /* Begin by filling in the program name */
  if ((tmp = strrchr(argv[0], '/')))
    conf->cf_prog = tmp + 1;
  else
    conf->cf_prog = argv[0];

  /* Next, parse command line arguments */
  parse_args(conf, argc, argv);

  /* Read the configuration file */
  if (!config_read(conf)) {
    log_emit(conf, LOG_ERR, "Unable to read configuration, exiting...");
    exit(EXIT_FAILURE);
  }

  /* Make sure we have a UUID */
  if (!(conf->cf_flags & CONFIG_UUID_SET)) {
    uuid_generate(conf->cf_uuid);
    conf->cf_flags |= CONFIG_UUID_SET;
    uuid_unparse(conf->cf_uuid, uuid_buf);
    log_emit(conf, LOG_NOTICE, "UUID not set by configuration; using %s",
	     uuid_buf);
  }
}
