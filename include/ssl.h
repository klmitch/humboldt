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

/** \brief TLS configuration.
 *
 * The TLS configuration.  This contains configuration data specific
 * to TLS, and can only be set via the Humboldt configuration file.
 */
typedef struct _ssl_conf_s ssl_conf_t;

/** \brief TLS context.
 *
 * The TLS context.  The presence or absence of this pointer in the
 * runtime is responsible for controlling whether TLS is available.
 */
typedef void *ssl_ctx_t;

/** \brief Socket TLS.
 *
 * The TLS object for a socket.  This will be both the \c SSL object
 * from OpenSSL and the Libevent bufferevent filter implementing TLS
 * in Humboldt.
 */
typedef void *ssl_conn_t;

#include "common.h"		/* for magic_t */
#include "configuration.h"	/* for config_t */
#include "connection.h"		/* for connection_t */
#include "protocol.h"		/* for protocol_buf_t, pbuf_result_t */
#include "yaml_util.h"		/* for yaml_ctx_t, yaml_node_t */

/** \brief TLS configuration structure.
 *
 * This structure contains the definition of the TLS configuration.
 */
struct _ssl_conf_s {
  magic_t	sc_magic;	/**< Magic number */
  const char   *sc_cafile;	/**< File containing certs for verification */
  const char   *sc_capath;	/**< Dir containing certs for verification */
  const char   *sc_cert_chain;	/**< Certificate chain file */
  const char   *sc_ciphers;	/**< Configured TLS ciphers */
  const char   *sc_private_key;	/**< Private key file (PEM-encoded) */
};

/** \brief TLS configuration magic number.
 *
 * This is the magic number used for the configuration structure.  It
 * is used to guard against programming problems, such as passing an
 * incorrect configuration.
 */
#define SSL_CONF_MAGIC 0xa2601857

/** \brief Process TLS configuration.
 *
 * This is the configuration processor specific to TLS.  It conforms
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

/** \brief Free TLS configuration.
 *
 * This function is used to free the memory consumed by an TLS
 * configuration structure.  The TLS configuration should not be
 * referenced after calling this function.
 *
 * \param[in]		conf	The TLS configuration.
 */
void ssl_conf_free(ssl_conf_t *conf);

/** \brief Initialize TLS context.
 *
 * This function is called by initialize_runtime() to initialize the
 * TLS context.  It is also responsible for initializing the OpenSSL
 * library.  If TLS cannot be initialized--for instance, if OpenSSL
 * was not enabled, or if the TLS parameters are not set--then a \c
 * NULL pointer will be returned.
 *
 * \param[in]		conf	A pointer to the top-level #config_t
 *                              configuration structure.
 *
 * \return	A pointer to an TLS context, or \c NULL if TLS cannot
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

/** \brief Process TLS handshake events.
 *
 * This function is called from the connection event processing when a
 * connection has the #CONN_FLAG_TLS_HANDSHAKE flag set.  This allows
 * TLS-specific events to be processed and appropriate updates made to
 * the connection state.
 *
 * \param[in,out]	conn	The connection the event occurred on.
 * \param[in]		events	The events reported by Libevent.
 *
 * \return	A true value if the event was completely handled, or
 *		false if the standard processing should be performed.
 */
int ssl_event(connection_t *conn, short events);

/** \brief Initiate TLS shutdown.
 *
 * This function is called from connection_destroy() to shut down any
 * extant TLS connection.
 *
 * \param[in]		conn	The connection to shut down.
 */
void ssl_shutdown(connection_t *conn);

/** \brief Free TLS memory.
 *
 * This function is called to release TLS-specific memory associated
 * with the connection.  No references should be made to this data
 * after this call.
 *
 * \param[in,out]	scon	The SSL-specific memory.
 */
void ssl_free(ssl_conn_t scon);

#endif /* _HUMBOLDT_SSL_H */
