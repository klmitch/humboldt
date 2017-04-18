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

#ifndef _HUMBOLDT_SASL_UTIL_H
#define _HUMBOLDT_SASL_UTIL_H

#include <sasl/sasl.h>		/* for sasl_conn_t */
#include <stdlib.h>		/* for size_t */

/** \brief SASL configuration.
 *
 * Configuration for SASL, drawn from the Humboldt configuration.
 * This contains a hash table of the SASL configuration options.
 */
typedef struct _sasl_conf_s sasl_conf_t;

/** \brief SASL option.
 *
 * A single option stored in Humboldt's SASL configuration structure.
 * This is the entry that gets added to the hash table in
 * #sasl_conf_t.
 */
typedef struct _sasl_option_s sasl_option_t;

/** \brief SASL connection context.
 *
 * Connection context specific to SASL.  This will contain the SASL
 * connection context for both server and client.  It will also
 * contain the libevent bufferevent for any security layer that has
 * been negotiated.
 */
typedef struct _sasl_connection_s sasl_connection_t;

#include "common.h"		/* for magic_t */
#include "configuration.h"	/* for config_t, conf_ctx_t */
#include "connection.h"		/* for connection_t */
#include "db.h"			/* for hash_tab_t, hash_ent_t */
#include "protocol.h"		/* for pbuf_result_t */
#include "yaml_util.h"		/* for yaml_ctx_t, yaml_node_t */

/** \brief SASL configuration structure.
 *
 * This structure contains the definition of the SASL configuration.
 */
struct _sasl_conf_s {
  magic_t	sac_magic;	/**< Magic number */
  hash_tab_t	sac_options;	/**< Hash table for options */
};

/** \brief Configuration magic number.
 *
 * This is the magic number used for the SASL configuration structure.
 * It is used to guard against programming problems, such passing an
 * uninitialized SASL configuration.
 */
#define SASL_CONF_MAGIC 0x4fd4ec6e

/** \brief SASL option structure.
 *
 * This structure contains the definition of the SASL option
 * structure.
 */
struct _sasl_option_s {
  magic_t	sao_magic;	/**< Magic number */
  hash_ent_t	sao_hashent;	/**< Hash table entry */
  char	       *sao_option;	/**< Option name */
  size_t	sao_vallen;	/**< Option value length */
  char		sao_value[1];	/**< Option value */
};

/** \brief SASL configuration option magic number.
 *
 * This is the magic number used for the SASL option structure.  It is
 * used to guard against programming problems, such passing an
 * uninitialized SASL option.
 */
#define SASL_OPTION_MAGIC 0x1b9b2ac9

/** \brief SASL connection context structure.
 *
 * This structure contains the definition of the SASL connection
 * context.
 */
struct _sasl_connection_s {
  magic_t	sac_magic;	/**< Magic number */
  sasl_conn_t  *sac_server;	/**< Server-side connection context */
  sasl_conn_t  *sac_client;	/**< Client-side connection context */
  struct bufferevent
	       *sac_bev;	/**< Libevent bufferevent for SASL */
};

/** \brief SASL connection context magic number.
 *
 * This is the magic number used for the SASL connection context
 * structure.  It is used to guard against programming problems, such
 * passing an uninitialized SASL connection context.
 */
#define SASL_CONNECTION_MAGIC 0xfa157908

/** \brief Default minimum security strength factor.
 *
 * This is the default minimum security strength factor required for
 * connections.  If a connection's current security strength factor is
 * less than this value, the SASL library will be configured to omit
 * plain-text mechanisms and to attempt to negotiate a security
 * layer.
 */
#define DEFAULT_MINIMUM_SSF	56

/** \brief Default security strength factor for local connections.
 *
 * This is the default security strength factor for local connections.
 * It must be greater than the default minimum required security
 * strength factor.
 */
#define DEFAULT_LOCAL_SSF	256

/** \brief Process SASL configuration.
 *
 * This is the configuration processor specific to SASL.  It conforms
 * to the #mapproc_t type, and is used to process "sasl" keys from the
 * configuration.
 *
 * \param[in]		key	The name of the key.
 * \param[in,out]	conf	A pointer to the top-level #config_t
 *				configuration structure.
 * \param[in]		ctx	The YAML file context.
 * \param[in]		value	The YAML node containing the value.
 */
void sasl_conf_processor(const char *key, config_t *conf,
			 yaml_ctx_t *ctx, yaml_node_t *value);

/** \brief Free SASL configuration.
 *
 * This function is used to free the memory consumed by a SASL
 * configuration structure.  The SASL configuration should not be
 * referenced after calling this function.
 *
 * \param[in]		conf	The SASL configuration.
 */
void sasl_conf_free(sasl_conf_t *conf);

/** \brief Initialize SASL library.
 *
 * This function is used to initialize the SASL library.  It sets up
 * the appropriate callbacks for such things as logging and
 * configuration settings.  (Note that the configuration settings
 * callback is not registered if no "sasl" section is found in the
 * configuration file.)
 *
 * \param[in]		conf	The Humboldt configuration.
 *
 * \return	A true value if initialization succeeded, false
 *		otherwise.
 */
int initialize_sasl(config_t *conf);

/** \brief Allocate and initialize connection context.
 *
 * This function is used to initialize the SASL connection context for
 * a connection.
 *
 * \param[in,out]	conn	The connection to initialize the
 *				context for.
 *
 * \return	A true value if initialization succeeded, false
 *		otherwise.  This sets the SASL connection context in
 *		the connection object on success.
 */
int sasl_connection_init(connection_t *conn);

/** \brief Set security strength factor.
 *
 * A connection has a security strength factor which indicates how
 * secure the connection is.  This function is used for setting that
 * strength factor; it notifies the SASL library to ensure that
 * authentication exchanges take an external strength factor into
 * account.
 *
 * \param[in]		conn	The connection.
 * \param[in]		ssf	The new security strength factor.
 *
 * \return	A true value if setting the security strength factor
 *		is successful, false otherwise.
 */
int sasl_set_ssf(connection_t *conn, unsigned int ssf);

/** \brief Set external authentication ID.
 *
 * This function notifies the SASL library that the authentication ID
 * has been set externally.  It is called by connection_set_username()
 * to communicate the username to the SASL library.
 *
 * \param[in]		conn	The connection.
 * \param[in]		username
 *				The externally-set authentication ID.
 *
 * \return	A true value if setting the external authentication ID
 *		is successful, false otherwise.
 */
int sasl_set_external(connection_t *conn, const char *username);

/** \brief Process received SASL messages.
 *
 * This is a protocol dispatch routine which is used to process
 * received SASL exchange protocol messages.
 *
 * \param[in]		msg	The received message to process.
 * \param[in,out]	conn	The connection the message came in
 *				on.
 *
 * \return	One of the #pbuf_result_t values.
 */
pbuf_result_t sasl_process(protocol_buf_t *msg, connection_t *conn);

/** \brief Release a connection context.
 *
 * This function releases a SASL connection context for a connection,
 * disposing of the SASL library connection information and shutting
 * down any negotiated security layer.  The SASL connection context
 * should not be referenced after this call.
 *
 * \param[in,out]	sasl_conn
 *				The SASL connection context to
 *				release.
 */
void sasl_connection_release(sasl_connection_t *sasl_conn);

#endif /* _HUMBOLDT_SASL_UTIL_H */
