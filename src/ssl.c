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

#include "include/common.h"
#include "include/configuration.h"
#include "include/ssl.h"
#include "include/yaml_util.h"

/*
  Notes:

  SSL_CTX_set_cipher_list - sets cipher list (duh)

  SSL_CTX_set_options - sets options; options of interest:
  * SSL_OP_NO_SSLv2
  * SSL_OP_NO_SSLv3

  SSL_CTX_set_session_cache_mode - use to enable the session cache
  * SSL_SESS_CACHE_BOTH - enable both client and server caching

  SSL_CTX_set_session_id_context - sets the context for session caching

  SSL_CTX_set_verify - control certificate verification
  * SSL_VERIFY_PEER - request peer certificate
  * SSL_VERIFY_FAIL_IF_NO_PEER_CERT - require peer certificate

  SSL_CTX_set_verify_depth - set certificate verification depth

  SSL_CTX_use_certificate_chain_file - set certificate chain file

  SSL_CTX_use_PrivateKey_file - set private key file

 */

#ifndef HAVE_OPENSSL

void
ssl_conf_processor(const char *key, config_t *conf, yaml_ctx_t *ctx,
		   yaml_node_t *value)
{
  static int ssl_warning = 0;

  common_verify(conf, CONFIG_MAGIC);

  /* Emit a warning about SSL being unavailable */
  if (!ssl_warning) {
    yaml_ctx_report(ctx, &value->start_mark, LOG_WARNING,
		    "SSL support is not enabled.");
    ssl_warning = 1;
  }
}

#else /* HAVE_OPENSSL */

#include <stdlib.h>
#include <string.h>

static void
proc_cert_chain(const char *key, ssl_conf_t *conf, yaml_ctx_t *ctx,
		yaml_node_t *value)
{
  const char *filename;

  common_verify(conf, SSL_CONF_MAGIC);

  /* Convert the value as a string */
  if (!yaml_get_str(ctx, value, &filename, 0, 0))
    return;

  /* Copy the filename into the configuration structure */
  if (!(conf->sc_cert_chain = strdup(filename)))
    yaml_ctx_report(ctx, &value->start_mark, LOG_WARNING,
		    "Out of memory reading string");
}

static void
proc_ciphers(const char *key, ssl_conf_t *conf, yaml_ctx_t *ctx,
	     yaml_node_t *value)
{
  const char *ciphers;

  common_verify(conf, SSL_CONF_MAGIC);

  /* Convert the value as a string */
  if (!yaml_get_str(ctx, value, &ciphers, 0, 0))
    return;

  /* Copy the filename into the configuration structure */
  if (!(conf->sc_ciphers = strdup(ciphers)))
    yaml_ctx_report(ctx, &value->start_mark, LOG_WARNING,
		    "Out of memory reading string");
}

static void
proc_private_key(const char *key, ssl_conf_t *conf, yaml_ctx_t *ctx,
		 yaml_node_t *value)
{
  const char *filename;

  common_verify(conf, SSL_CONF_MAGIC);

  /* Convert the value as a string */
  if (!yaml_get_str(ctx, value, &filename, 0, 0))
    return;

  /* Copy the filename into the configuration structure */
  if (!(conf->sc_private_key = strdup(filename)))
    yaml_ctx_report(ctx, &value->start_mark, LOG_WARNING,
		    "Out of memory reading string");
}

static mapkeys_t ssl_options[] = {
  MAPKEY("cert_chain", proc_cert_chain),
  MAPKEY("ciphers", proc_ciphers),
  MAPKEY("private_key", proc_private_key),
};

void
ssl_conf_processor(const char *key, config_t *conf, yaml_ctx_t *ctx,
		   yaml_node_t *value)
{
  ssl_conf_t *ssl_conf;

  common_verify(conf, CONFIG_MAGIC);

  /* Allocate a configuration structure */
  if (!(ssl_conf = malloc(sizeof(ssl_conf_t)))) {
    yaml_ctx_report(ctx, &value->start_mark, LOG_WARNING,
		    "Out of memory reading SSL configuration");
    return;
  }

  /* Initialize it */
  ssl_conf->sc_cert_chain = 0;
  ssl_conf->sc_ciphers = 0;
  ssl_conf->sc_private_key = 0;
  ssl_conf->sc_magic = SSL_CONF_MAGIC;

  /* Process the configuration */
  yaml_proc_mapping(ctx, value, ssl_options, list_count(ssl_options),
		    (void *)ssl_conf);

  /* Do we have what we need? */
  if (!ssl_conf->sc_cert_chain || !ssl_conf->sc_private_key) {
    yaml_ctx_report(ctx, &value->start_mark, LOG_WARNING,
		    "Not configuring SSL: missing configuration for %s%s%s",
		    ssl_conf->sc_cert_chain ? "" : "cert_chain",
		    !ssl_conf->sc_cert_chain && !ssl_conf->sc_private_key ?
		    " and " : "",
		    ssl_conf->sc_private_key ? "" : "private_key");
    ssl_conf_free(ssl_conf);
    return;
  }

  /* OK, save it in the configuration */
  conf->cf_ssl = ssl_conf;
}

void
ssl_conf_free(ssl_conf_t *conf)
{
  common_verify(conf, SSL_CONF_MAGIC);

  /* Release each of the allocated strings */
  if (conf->sc_cert_chain)
    free((void *)conf->sc_cert_chain);
  if (conf->sc_ciphers)
    free((void *)conf->sc_ciphers);
  if (conf->sc_private_key)
    free((void *)conf->sc_private_key);

  conf->sc_magic = 0;
  free(conf);
}

#endif /* HAVE_OPENSSL */
