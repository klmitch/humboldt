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

#include "common.h"		/* for magic_t */
#include "configuration.h"	/* for config_t */
#include "yaml_util.h"		/* for yaml_ctx_t, yaml_node_t */

/** \brief SSL configuration structure.
 *
 * This structure contains the definition of the SSL configuration.
 */
struct _ssl_conf_s {
  magic_t	sc_magic;	/**< Magic number */
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

#endif /* _HUMBOLDT_SSL_H */
