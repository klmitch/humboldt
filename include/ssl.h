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

#ifndef _HUMBOLDT_SSL_H
#define _HUMBOLDT_SSL_H

/** \brief SSL configuration.
 *
 * The SSL configuration.  This contains configuration data specific
 * to SSL, and can only be set via the Humboldt configuration file.
 */
typedef struct _ssl_conf_s ssl_conf_t;

/** \brief SSL context.
 *
 * The SSL context.  The presence or absence of this pointer in the
 * runtime is responsible for controlling whether SSL is available.
 */
typedef void *ssl_ctx_t;

#include "common.h"		/* for magic_t */
#include "configuration.h"	/* for config_t */
#include "connection.h"		/* for connection_t */
#include "protocol.h"		/* for protocol_buf_t, pbuf_result_t */
#include "yaml_util.h"		/* for yaml_ctx_t, yaml_node_t */

/** \brief SSL configuration structure.
 *
 * This structure contains the definition of the SSL configuration.
 */
struct _ssl_conf_s {
  magic_t	sc_magic;	/**< Magic number */
  const char   *sc_cafile;	/**< File containing certs for verification */
  const char   *sc_capath;	/**< Dir containing certs for verification */
  const char   *sc_cert_chain;	/**< Certificate chain file */
  const char   *sc_ciphers;	/**< Configured SSL ciphers */
  const char   *sc_private_key;	/**< Private key file (PEM-encoded) */
};

/** \brief SSL configuration magic number.
 *
 * This is the magic number used for the configuration structure.  It
 * is used to guard against programming problems, such as passing an
 * incorrect configuration.
 */
#define SSL_CONF_MAGIC 0xa2601857

/** \brief Process SSL configuration.
 *
 * This is the configuration processor specific to SSL.  It conforms
 * to the #mapproc_t type, and is used to process "ssl" keys from the
 * configuration.
 *
 * \param[in]		key	The name of the key.
 * \param[in,out]	conf	A pointer to the top-level #config_t
 *				configuration structure.
 * \param[in]		ctx	The YAML file context.
 * \param[in]		value	The YAML node containing the value.
 */
void ssl_conf_processor(const char *key, config_t *conf,
			yaml_ctx_t *ctx, yaml_node_t *value);

/** \brief Free SSL configuration.
 *
 * This function is used to free the memory consumed by an SSL
 * configuration structure.  The SSL configuration should not be
 * referenced after calling this function.
 *
 * \param[in]		conf	The SSL configuration.
 */
void ssl_conf_free(ssl_conf_t *conf);

/** \brief Initialize SSL context.
 *
 * This function is called by initialize_runtime() to initialize the
 * SSL context.  It is also responsible for initializing the OpenSSL
 * library.  If SSL cannot be initialized--for instance, if OpenSSL
 * was not enabled, or if the SSL parameters are not set--then a \c
 * NULL pointer will be returned.
 *
 * \param[in]		conf	A pointer to the top-level #config_t
 *                              configuration structure.
 *
 * \return	A pointer to an SSL context, or \c NULL if SSL cannot
 *		be initialized.
 */
ssl_ctx_t ssl_ctx_init(config_t *conf);

/** \brief Process received STARTTLS message.
 *
 * This is a protocol dispatch routine which is used to process the
 * STARTTLS family of messages (protocol 2).
 *
 * \param[in]		msg	The received message to process.
 * \param[in,out]	conn	The connection the message came in
 *				on.
 *
 * \return	One of the #pbuf_result_t values.
 */
pbuf_result_t ssl_process(protocol_buf_t *msg, connection_t *conn);

#endif /* _HUMBOLDT_SSL_H */
