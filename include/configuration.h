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

#include <syslog.h>	/* for LOG_DAEMON */
#include <yaml.h>

#include "common.h"	/* for magic_t */


/** \brief Configuration.
 *
 * The Humboldt configuration.  This contains configuration drawn from
 * command line arguments, as well as from the named configuration
 * file.
 */
typedef struct _config_s config_t;

/** \brief Configuration file context.
 *
 * Represents the configuration file context, describing the file
 * being processed.
 */
typedef struct _config_ctx_s config_ctx_t;

/** \brief Mapping of YAML mapping keys to processors.
 *
 * This structure is used while parsing a YAML mapping.  Lists of
 * these structures map a given key in a YAML mapping to the routine
 * (a #mapproc_t) required to parse that key.
 */
typedef struct _mapkeys_s mapkeys_t;

/** \brief YAML mapping key processor.
 *
 * This function pointer describes a YAML mapping key processor.
 * These routines should process the \p value node and store the value
 * in an appropriate place in \p dest.
 *
 * \param[in]		key	The name of the key.
 * \param[in,out]	dest	A pointer to the object to contain the
 *				processed value.
 * \param[in]		ctx	The configuration processing context.
 * \param[in]		value	The YAML node containing the value.
 */
typedef void (*mapproc_t)(const char *key, void *dest,
			  config_ctx_t *ctx, yaml_node_t *value);

/** \brief YAML sequence item processor.
 *
 * This function pointer describes a YAML sequence item processor.
 * These routines should process the \p value node and store the value
 * in an appropriate place in \p dest.
 *
 * \param[in]		idx	The index to process.
 * \param[in,out]	dest	A pointer to the object to contain the
 *				processed value.
 * \param[in]		ctx	The configuration processing context.
 * \param[in]		value	The YAML node containing the value.
 */
typedef void (*itemproc_t)(int idx, void *dest,
			   config_ctx_t *ctx, yaml_node_t *value);

/** \brief Configuration structure.
 *
 * This structure contains the definition of the configuration.
 */
struct _config_s {
  magic_t	cf_magic;	/**< Magic number */
  uint32_t	cf_flags;	/**< Configuration flags */
  const char   *cf_config;	/**< Name of the configuration file */
  const char   *cf_prog;	/**< The program name */
  int		cf_facility;	/**< Syslog facility to log to */
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
#define DEFAULT_CONFIG SYSCONFDIR "/" PACKAGE_TARNAME "/config.yaml"

/** \brief Initialize a configuration structure.
 *
 * Initialize the configuration structure.  This is a static
 * initializer that ensures that the configuration is properly
 * initialized.
 */
#define CONFIG_INIT()							\
  {CONFIG_MAGIC, CONFIG_FILE_DEFAULT, DEFAULT_CONFIG, 0, LOG_DAEMON}

/** \brief Debugging enabled.
 *
 * A configuration flag indicating that debugging output should be
 * emitted.
 */
#define CONFIG_DEBUG		0x80000000

/** \brief Debugging fixed.
 *
 * A configuration flag indicating that \c CONFIG_DEBUG got its
 * setting from the command line and cannot be overridden by the
 * configuration file.
 */
#define CONFIG_DEBUG_FIXED	0x40000000

/** \brief Configuration file is at its default.
 *
 * This flag is used solely to detect the case of the user passing the
 * "--config" option multiple times; it is cleared after processing
 * the first "--config" or "-c" option.
 */
#define CONFIG_FILE_DEFAULT	0x20000000

/** \brief Logging has been initialized.
 *
 * This flag is used by the logging abstraction to detect if logging
 * has been initialized.  Until it has, log messages of \c LOG_INFO or
 * higher (or \c LOG_DEBUG or higher if debugging is enabled) will be
 * sent to standard output, with log messages of \c LOG_WARNING or
 * higher sent to standard error.
 */
#define CONFIG_LOG_INITIALIZED	0x10000000

/** \brief Facility fixed.
 *
 * A configuration flag indicating that the logging facility got its
 * setting from the command line and cannot be overridden by the
 * configuration file.
 */
#define CONFIG_FACILITY_FIXED	0x08000000

/** \brief Maximum size of the path buffer.
 *
 * This constant sets the size of the path buffer.
 */
#define PATH_BUF		1024

/** \brief Configuration file context structure.
 *
 * This structure contains the context of the configuration file
 * reading.  This is used to format comprehensible error messages.
 */
struct _config_ctx_s {
  config_t     *cc_conf;	/**< The configuration */
  const char   *cc_filename;	/**< Name of the file being processed */
  int		cc_docnum;	/**< Number of the document in the file */
  yaml_document_t
	       *cc_document;	/**< The document being processed */
  char		cc_path[PATH_BUF];
				/**< A buffer containing the document path */
  int		cc_pathlen;	/**< Length of the document path */
};

/** \brief Initialize a #config_ctx_t.
 *
 * Initializes a #config_ctx_t.  The path is initialized to empty.
 *
 * \param[in]		conf	The configuration.
 */
#define CONFIG_CTX_INIT(conf)	{(conf), 0, 1, 0, '', 0}

/** \brief YAML mapping keys structure.
 *
 * This structure contains a YAML mapping.
 */
struct _mapkeys_s {
  const char   *mk_key;		/**< Mapping key value */
  mapproc_t	mk_proc;	/**< Mapping value processor */
};

/** \brief Create an entry in a #mapkeys_t list.
 *
 * This helper macro declares a key in a #mapkeys_t list.
 *
 * \param[in]		key	The name of the key.
 * \param[in]		proc	The processor function.  Note that
 *				this is cast to #mapproc_t for
 *				convenience.
 */
#define MAPKEY(key, proc)	{(key), (mapproc_t)(proc)}

/** \brief Count entries in a #mapkeys_t list.
 *
 * This macro counts the number of entries in a #mapkeys_t list.
 */
#define MAPKEYS_COUNT(list)	(sizeof((list)) / sizeof(mapkeys_t))

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

/** \brief Push a path element.
 *
 * Updates the context to push a new path element, i.e., a mapping key
 * name.
 *
 * \param[in,out]	ctx	The configuration context.
 * \param[in]		path	The path element to push.
 */
void config_ctx_path_push_key(config_ctx_t *ctx, const char *path);

/** \brief Push an index element.
 *
 * Updates the context to push a new sequence index.
 *
 * \param[in,out]	ctx	The configuration context.
 * \param[in]		idx	The index to push.
 */
void config_ctx_path_push_idx(config_ctx_t *ctx, int idx);

/** \brief Pop a path element.
 *
 * Updates the context to pop off a path element, either a mapping key
 * name or a sequence index.
 *
 * \param[in,out]	ctx	The configuration context.
 */
void config_ctx_path_pop(config_ctx_t *ctx);

/** \brief Report something related to the configuration.
 *
 * This is a wrapper around log_emit() that includes the configuration
 * context and other location information, such as line number.
 *
 * \param[in]		ctx	The configuration context.
 * \param[in]		loc	The location of the YAML node.
 *				Optional; pass \c NULL if not
 *				available.
 * \param[in]		priority
 * 				The log priority, one of the values
 * 				accepted by syslog().  This must not
 *				be combined with a facility code.
 * \param[in]		fmt	A format string for the log message.
 */
void config_ctx_report(config_ctx_t *ctx, yaml_mark_t *loc, int priority,
		       const char *fmt, ...);

/** \brief Process a YAML sequence.
 *
 * Process all the nodes in a YAML sequence.
 *
 * \param[in]		ctx	The configuration context.
 * \param[in]		seq	A YAML sequence node.
 * \param[in]		proc	The processor routine for the items in
 *				the sequence.
 * \param[in,out]	dest	A pointer to the object to contain the
 *				processed value.
 */
void config_proc_sequence(config_ctx_t *ctx, yaml_node_t *seq,
			  itemproc_t proc, void *dest);

/** \brief Process a YAML mapping.
 *
 * Process all the keys and values in a YAML mapping.
 *
 * \param[in]		ctx	The configuration context.
 * \param[in]		seq	A YAML sequence node.
 * \param[in]		keys	A sorted list of #mapkeys_t values
 *				mapping keys to processors.
 * \param[in]		keycnt	The number of keys in \p keys.
 * \param[in,out]	dest	A pointer to the object to contain the
 *				processed value.
 */
void config_proc_mapping(config_ctx_t *ctx, yaml_node_t *map,
			 mapkeys_t *keys, size_t keycnt, void *dest);

/** \brief Get a boolean YAML node value.
 *
 * Determine the value of a boolean YAML node.
 *
 * \param[in]		ctx	The configuration context.
 * \param[in]		node	The YAML node.
 * \param[out]		dest	A pointer to an integer to fill in
 *				with the boolean value.
 *
 * \return	A false value if an error occurred, true otherwise.
 */
int config_get_bool(config_ctx_t *ctx, yaml_node_t *node, int *dest);

/** \brief Get an integer YAML node value.
 *
 * Determine the value of an integer YAML node.
 *
 * \param[in]		ctx	The configuration context.
 * \param[in]		node	The YAML node.
 * \param[out]		dest	A pointer to an integer to fill in
 *				with the integer value.
 *
 * \return	A false value if an error occurred, true otherwise.
 */
int config_get_int(config_ctx_t *ctx, yaml_node_t *node, long *dest);

/** \brief Get a string YAML node value.
 *
 * Determine the value of a string YAML node.
 *
 * \param[in]		ctx	The configuration context.
 * \param[in]		node	The YAML node.
 * \param[out]		dest	A pointer to a character pointer to
 *				fill in with the string value.
 * \param[in]		allow_null
 *				If true, a \c NULL value is allowed.
 *
 * \return	A false value if an error occurred, true otherwise.
 */
int config_get_str(config_ctx_t *ctx, yaml_node_t *node, const char **dest,
		   int allow_null);

#endif /* _HUMBOLDT_CONFIGURATION_H */
