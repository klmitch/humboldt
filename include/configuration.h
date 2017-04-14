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

#ifndef _HUMBOLDT_CONFIGURATION_H
#define _HUMBOLDT_CONFIGURATION_H

#include <stdint.h>	/* for uint32_t */
#include <syslog.h>	/* for LOG_DAEMON */
#include <uuid.h>	/* for uuid_t */

#include "common.h"	/* for magic_t */

/** \brief Configuration.
 *
 * The Humboldt configuration.  This contains configuration drawn from
 * command line arguments, as well as from the named configuration
 * file.
 */
typedef struct _config_s config_t;

/** \brief Configuration context.
 *
 * Contains information required to report log messages pertaining to
 * the configuration.
 */
typedef struct _conf_ctx_s conf_ctx_t;

/** \brief Configuration context flavor.
 *
 * The possible flavors for the configuration context.  This
 * information is used by config_report() to pick the correct logging
 * function to write logs to.
 */
typedef enum _conf_ctx_flavor_e {
  CTX_FLAVOR_CONF,		/**< Context contains only configuration */
  CTX_FLAVOR_YAML		/**< Context contains YAML context */
} conf_ctx_flavor_t;

#include "db.h"		/* for hash_tab_t */
#include "endpoint.h"	/* for endpoint types; depends on config_t */
#include "ssl.h"	/* for ssl_conf_t; depends on config_t */
#include "yaml_util.h"	/* for yaml_ctx_t, yaml_mark_t */

/** \brief Configuration context structure.
 *
 * This structure contains the definition of the configuration
 * context.
 */
struct _conf_ctx_s {
  conf_ctx_flavor_t
		cc_flavor;	/**< Context flavor */
  union {
    config_t   *ccd_conf;	/**< The configuration object */
    struct {
      yaml_ctx_t
	       *ccdy_ctx;	/**< The YAML context */
      yaml_mark_t
	       *ccdy_loc;	/**< The YAML location */
    }		ccd_yaml;	/**< YAML context and location data */
  }		cc_data;	/**< The context data */
};

/** \brief Initialize a configuration context from configuration.
 *
 * Initialize a configuration context structure using just
 * configuration.  This will cause config_report() to use plain old
 * log_emit() to emit the log messages.  This is a static initializer.
 *
 * \param[in]		conf	The configuration structure.
 */
#define CONF_CTX_CONF(conf)			\
  {						\
    CTX_FLAVOR_CONF,				\
    {						\
      .ccd_conf = (conf)			\
    }						\
  }

/** \brief Initialize a configuration context from a YAML context.
 *
 * Initialize a configuration context structure using the specified
 * YAML context.  This will cause config_report() to use
 * yaml_ctx_report() to emit the log messages.  This is a static
 * initializer.
 *
 * \param[in]		ctx	The YAML context.
 * \param[in]		node	A YAML node.  Optional.  If provided,
 *				the node's \c start_mark will be
 *				passed to yaml_ctx_report().
 */
#define CONF_CTX_YAML(ctx, node)				\
  {								\
    CTX_FLAVOR_YAML,						\
    {								\
      .ccd_yaml.ccdy_ctx = (ctx),				\
      .ccd_yaml.ccdy_loc = (node) ? &(node)->start_mark : 0	\
    }								\
  }

/** \brief Configuration structure.
 *
 * This structure contains the definition of the configuration.
 */
struct _config_s {
  magic_t	cf_magic;	/**< Magic number */
  uint32_t	cf_flags;	/**< Configuration flags */
  const char   *cf_config;	/**< Name of the configuration file */
  const char   *cf_statedir;	/**< Name of the state directory */
  const char   *cf_prog;	/**< The program name */
  uuid_t	cf_uuid;	/**< UUID of Humboldt */
  int		cf_facility;	/**< Syslog facility to log to */
  hash_tab_t	cf_endpoints;	/**< Endpoints hash table */
  hash_tab_t	cf_ads;		/**< Endpoint advertisements hash table */
  hash_tab_t	cf_networks;	/**< Networks hash table */
  ssl_conf_t   *cf_ssl;		/**< SSL configuration */
};

/** \brief Configuration magic number.
 *
 * This is the magic number used for the configuration structure.  It
 * is used to guard against programming problems, such passing an
 * incorrect configuration.
 */
#define CONFIG_MAGIC 0xa059d600

/** \brief Default configuration file location.
 *
 * This is the default location of the configuration file.
 */
#define DEFAULT_CONFIG		SYSCONFDIR "/" PACKAGE_TARNAME "/config.yaml"

/** \brief Default state file location.
 *
 * This is the default location of the state directory.
 */
#define DEFAULT_STATEDIR	LOCALSTATEDIR "/" PACKAGE_TARNAME

/** \brief Default socket file name.
 *
 * This is the default name of the client socket.  If no client
 * endpoint is described in the configuration file, a socket with this
 * name will be created in the state directory.
 */
#define DEFAULT_CLIENT_SOCK	"socket"

/** \brief Initialize a configuration structure.
 *
 * Initialize the configuration structure.  This is a static
 * initializer that ensures that the configuration is properly
 * initialized.
 */
#define CONFIG_INIT()							\
  {									\
    CONFIG_MAGIC,							\
    CONFIG_FILE_DEFAULT,						\
    DEFAULT_CONFIG,							\
    DEFAULT_STATEDIR,							\
    0,									\
    {},									\
    LOG_DAEMON,								\
    HASH_TAB_INIT(ep_addr_hash, ep_addr_comp),				\
    HASH_TAB_INIT(ep_addr_hash, ep_addr_comp),				\
    HASH_TAB_INIT(db_str_hash, db_str_comp),				\
    0									\
  }

/** \brief Debugging enabled.
 *
 * A configuration flag indicating that debugging output should be
 * emitted.
 */
#define CONFIG_DEBUG			0x80000000

/** \brief Debugging fixed.
 *
 * A configuration flag indicating that \c CONFIG_DEBUG got its
 * setting from the command line and cannot be overridden by the
 * configuration file.
 */
#define CONFIG_DEBUG_FIXED		0x40000000

/** \brief Configuration file is at its default.
 *
 * This flag is used solely to detect the case of the user passing the
 * "--config" option multiple times; it is cleared after processing
 * the first "--config" or "-c" option.
 */
#define CONFIG_FILE_DEFAULT		0x20000000

/** \brief Logging has been initialized.
 *
 * This flag is used by the logging abstraction to detect if logging
 * has been initialized.  Until it has, log messages of \c LOG_INFO or
 * higher (or \c LOG_DEBUG or higher if debugging is enabled) will be
 * sent to standard output, with log messages of \c LOG_WARNING or
 * higher sent to standard error.
 */
#define CONFIG_LOG_INITIALIZED		0x10000000

/** \brief Facility fixed.
 *
 * A configuration flag indicating that the logging facility got its
 * setting from the command line and cannot be overridden by the
 * configuration file.
 */
#define CONFIG_FACILITY_FIXED		0x08000000

/** \brief State directory allocated.
 *
 * A configuration flag indicating that the state directory path is
 * stored in allocated memory.
 */
#define CONFIG_STATEDIR_ALLOCATED	0x04000000

/** \brief State directory fixed.
 *
 * A configuration flag indicating that the state directory path came
 * from the command line and cannot be overridden by the configuration
 * file.
 */
#define CONFIG_STATEDIR_FIXED		0x02000000

/** \brief UUID set.
 *
 * A configuration flag indicating that the UUID has been obtained
 * from the configuration file.
 */
#define CONFIG_UUID_SET			0x01000000

/** \brief Initialize configuration.
 *
 * Initialize the configuration.  This routine parses command line
 * arguments and reads in the configuration file, placing the results
 * into a configuration structure for use by the rest of Humboldt.
 *
 * \param[in,out]	conf	The configuration structure to
 *				initialize.
 * \param[in]		argc	The count of the number of command
 *				line arguments.
 * \param[in]		argv	The command line arguments.
 */
void initialize_config(config_t *conf, int argc, char **argv);

/** \brief Report a message about configuration.
 *
 * Given a #conf_ctx_t object, generates a log message utilizing the
 * appropriate logging backend for the configuration context.
 *
 * \param[in]		conf_ctx
 *				The configuration context.
 * \param[in]		priority
 * 				The log priority, one of the values
 * 				accepted by syslog().  This must not
 *				be combined with a facility code.
 * \param[in]		fmt	A format string for the log message.
 */
void config_report(conf_ctx_t *conf_ctx, int priority, const char *fmt, ...);

#endif /* _HUMBOLDT_CONFIGURATION_H */
