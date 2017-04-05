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

#ifndef _HUMBOLDT_YAML_UTIL_H
#define _HUMBOLDT_YAML_UTIL_H

#include <stdint.h>		/* for uint32_t, intmax_t */
#include <stdlib.h>		/* for size_t */
#include <yaml.h>

/* Make sure we have the binary tag available */
#ifndef YAML_BINARY_TAG
# define YAML_BINARY_TAG	"tag:yaml.org,2002:binary"
#endif

#include "configuration.h"	/* for config_t */

/** \brief Scalar node types.
 *
 * This enumeration lists the types of scalar nodes that we know
 * and care about.
 */
typedef enum _node_tag_e {
  NODE_BINARY_TAG,		/**< A !!binary node */
  NODE_BOOL_TAG,		/**< A !!bool node */
  NODE_FLOAT_TAG,		/**< A !!float node */
  NODE_INT_TAG,			/**< A !!int node */
  NODE_NULL_TAG,		/**< A !!null node */
  NODE_STR_TAG,			/**< A !!str node */
  NODE_TIMESTAMP_TAG,		/**< A !!timestamp node */
  NODE_OTHER_TAG		/**< An unrecognized node */
} node_tag_t;

/** \brief YAML file context.
 *
 * Represents the YAML file context, which describes the file being
 * processed.
 */
typedef struct _yaml_ctx_s yaml_ctx_t;

/** \brief Mapping of YAML mapping keys to processors.
 *
 * This structure is used while parsing a YAML mapping.  Lists of
 * these structures map a given key in a YAML mapping to the routine
 * (a #mapproc_t) required to parse that key.
 */
typedef struct _mapkeys_s mapkeys_t;

/** \brief Scalar node information.
 *
 * This structure is used to express information about a scalar node,
 * including the actual underlying node type, the inferred node tag,
 * and its value.
 */
typedef struct _node_info_s node_info_t;

/** \brief YAML mapping key processor.
 *
 * This function pointer describes a YAML mapping key processor.
 * These routines should process the \p value node and store the value
 * in an appropriate place in \p dest.
 *
 * \param[in]		key	The name of the key.
 * \param[in,out]	dest	A pointer to the object to contain the
 *				processed value.
 * \param[in]		ctx	The YAML file context.
 * \param[in]		value	The YAML node containing the value.
 */
typedef void (*mapproc_t)(const char *key, void *dest,
			  yaml_ctx_t *ctx, yaml_node_t *value);

/** \brief YAML sequence item processor.
 *
 * This function pointer describes a YAML sequence item processor.
 * These routines should process the \p value node and store the value
 * in an appropriate place in \p dest.
 *
 * \param[in]		idx	The index to process.
 * \param[in,out]	dest	A pointer to the object to contain the
 *				processed value.
 * \param[in]		ctx	The YAML file context.
 * \param[in]		value	The YAML node containing the value.
 */
typedef void (*itemproc_t)(int idx, void *dest,
			   yaml_ctx_t *ctx, yaml_node_t *value);

/** \brief Next document callback.
 *
 * This function pointer describes a function to call if subsequent
 * documents are read from a YAML file.  The function should return a
 * new pointer for \c dest.
 *
 * \param[in]		ctx	The YAML file context.
 * \param[in]		orig	The original value of the \c dest
 *				parameter.
 *
 * \return	The new value for \c dest.
 */
typedef void *(*nextdoc_t)(yaml_ctx_t *ctx, void *orig);

/** \brief Maximum size of the path buffer.
 *
 * This constant sets the size of the path buffer.
 */
#define PATH_BUF		1024

/** \brief YAML file context structure.
 *
 * This structure contains the context of the YAML file being read.
 * This is used to format comprehensible error messages.
 */
struct _yaml_ctx_s {
  config_t     *yc_conf;	/**< The configuration */
  const char   *yc_filename;	/**< Name of the file being processed */
  int		yc_docnum;	/**< Number of the document in the file */
  int		yc_docvalid;	/**< Count of valid documents in the file */
  yaml_document_t
		yc_document;	/**< The document being processed */
  char		yc_path[PATH_BUF];
				/**< A buffer containing the document path */
  int		yc_pathlen;	/**< Length of the document path */
};

/** \brief YAML mapping keys structure.
 *
 * This structure maps a YAML mapping key to the processor for that
 * key.
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

/** \brief YAML scalar node information structure.
 *
 * This structure describes the information known about a YAML scalar
 * node.
 */
struct _node_info_s {
  node_tag_t		ni_type;	/**< Type of node */
  const char	       *ni_tag;		/**< Node's tag */
  union {
    intmax_t		nid_int;	/**< Integer value of node */
    struct {
      const char       *nids_value;	/**< String value of node */
      size_t		nids_length;	/**< Length of string data */
    }			nid_str;	/**< String value of node */
  }			ni_data;	/**< Node data */
};

/** \brief Push a path element.
 *
 * Updates the context to push a new path element, i.e., a mapping key
 * name.
 *
 * \param[in,out]	ctx	The YAML file context.
 * \param[in]		path	The path element to push.
 */
void yaml_ctx_path_push_key(yaml_ctx_t *ctx, const char *path);

/** \brief Push an index element.
 *
 * Updates the context to push a new sequence index.
 *
 * \param[in,out]	ctx	The YAML file context.
 * \param[in]		idx	The index to push.
 */
void yaml_ctx_path_push_idx(yaml_ctx_t *ctx, int idx);

/** \brief Pop a path element.
 *
 * Updates the context to pop off a path element, either a mapping key
 * name or a sequence index.
 *
 * \param[in,out]	ctx	The YAML file context.
 */
void yaml_ctx_path_pop(yaml_ctx_t *ctx);

/** \brief Report something related to the configuration.
 *
 * This is a wrapper around log_emit() that includes the YAML file
 * context and other location information, such as line number.
 *
 * \param[in]		ctx	The YAML file context.
 * \param[in]		loc	The location of the YAML node.
 *				Optional; pass \c NULL if not
 *				available.
 * \param[in]		priority
 * 				The log priority, one of the values
 * 				accepted by syslog().  This must not
 *				be combined with a facility code.
 * \param[in]		fmt	A format string for the log message.
 */
void yaml_ctx_report(yaml_ctx_t *ctx, yaml_mark_t *loc, int priority,
		     const char *fmt, ...);

/** \brief Process a YAML sequence.
 *
 * Process all the nodes in a YAML sequence.
 *
 * \param[in]		ctx	The YAML file context.
 * \param[in]		seq	A YAML sequence node.
 * \param[in]		proc	The processor routine for the items in
 *				the sequence.
 * \param[in,out]	dest	A pointer to the object to contain the
 *				processed value.
 */
void yaml_proc_sequence(yaml_ctx_t *ctx, yaml_node_t *seq,
			itemproc_t proc, void *dest);

/** \brief Process a YAML mapping.
 *
 * Process all the keys and values in a YAML mapping.
 *
 * \param[in]		ctx	The YAML file context.
 * \param[in]		seq	A YAML sequence node.
 * \param[in]		keys	A sorted list of #mapkeys_t values
 *				mapping keys to processors.
 * \param[in]		keycnt	The number of keys in \p keys.
 * \param[in,out]	dest	A pointer to the object to contain the
 *				processed value.
 */
void yaml_proc_mapping(yaml_ctx_t *ctx, yaml_node_t *map,
		       mapkeys_t *keys, size_t keycnt, void *dest);

/** \brief Get information from a scalar node.
 *
 * Examines a scalar node and assembles information on that node,
 * including its value.
 *
 * \param[in]		ctx	The YAML file context.
 * \param[in]		scalar	A YAML scalar node.
 * \param[in,out]	info	A pointer to an allocated node
 *				information structure to contain the
 *				node information.
 *
 * \return	A false value if an error occurred, true otherwise.
 */
int yaml_get_scalar(yaml_ctx_t *ctx, yaml_node_t *scalar, node_info_t *info);

/** \brief Get a boolean YAML node value.
 *
 * Determine the value of a boolean YAML node.
 *
 * \param[in]		ctx	The YAML file context.
 * \param[in]		node	The YAML node.
 * \param[out]		dest	A pointer to an integer to fill in
 *				with the boolean value.
 *
 * \return	A false value if an error occurred, true otherwise.
 */
int yaml_get_bool(yaml_ctx_t *ctx, yaml_node_t *node, int *dest);

/** \brief Get an integer YAML node value.
 *
 * Determine the value of an integer YAML node.
 *
 * \param[in]		ctx	The YAML file context.
 * \param[in]		node	The YAML node.
 * \param[out]		dest	A pointer to an integer to fill in
 *				with the integer value.
 *
 * \return	A false value if an error occurred, true otherwise.
 */
int yaml_get_int(yaml_ctx_t *ctx, yaml_node_t *node, long *dest);

/** \brief Get a string YAML node value.
 *
 * Determine the value of a string YAML node.
 *
 * \param[in]		ctx	The YAML file context.
 * \param[in]		node	The YAML node.
 * \param[out]		dest	A pointer to a character pointer to
 *				fill in with the string value.
 * \param[in,out]	len	A pointer to fill in the length of the
 *				string or binary data.  May be \c
 *				NULL.
 * \param[in]		flags	Flags controlling whether to accept
 *				other nodes than string, such as null
 *				(\c ALLOW_NULL) or binary (\c
 *				ALLOW_BINARY).
 *
 * \return	A false value if an error occurred, true otherwise.
 *		If the value is greater than 1, this indicates that
 *		the value placed in \p dest points to allocated
 *		memory.
 */
int yaml_get_str(yaml_ctx_t *ctx, yaml_node_t *node, const char **dest,
		 size_t *len, uint32_t flags);

/** \brief Allow converting null nodes.
 *
 * This flag, if passed in the \c flags parameter of yaml_get_str(),
 * indicates that the function may utilize null nodes.
 */
#define ALLOW_NULL		0x80000000

/** \brief Allow converting binary nodes.
 *
 * This flag, if passed in the \c flags parameter of yaml_get_str(),
 * indicates that the function may utilize binary nodes.
 */
#define ALLOW_BINARY		0x40000000

/** \brief Read a mapping from a named file.
 *
 * This function reads one or more mappings from a named file.
 *
 * \param[in]		conf	The configuration.
 * \param[in]		filename
 *				The name of the file to read.
 * \param[in]		stream	An open stdio stream for reading the
 *				file.
 * \param[in]		keys	A sorted list of #mapkeys_t values
 *				mapping keys to processors.
 * \param[in]		keycnt	The number of keys in \p keys.
 * \param[in,out]	dest	A pointer to the object to contain the
 *				processed value.
 * \param[in]		all_docs
 *				If true, all documents will be read
 *				from the file; otherwise, only the
 *				first document will be read.
 * \param[in]		nextdoc	A pointer to a function to call on
 *				second and subsequent documents; the
 *				function return value will be used as
 *				\p dest for those subsequent
 *				documents.  May be passed as \c NULL
 *				if \p dest does not need to be updated
 *				between documents.  Ignored if \p
 *				all_docs is false.
 *
 * \return	A false value if an error occurred, true otherwise.
 */
int yaml_file_mapping(config_t *conf, const char *filename, FILE *stream,
		      mapkeys_t *keys, size_t keycnt, void *dest,
		      int all_docs, nextdoc_t nextdoc);

#endif /* _HUMBOLDT_YAML_UTIL_H */
