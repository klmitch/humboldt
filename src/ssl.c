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

#include <inttypes.h>

#include "include/common.h"
#include "include/configuration.h"
#include "include/connection.h"
#include "include/endpoint.h"
#include "include/log.h"
#include "include/protocol.h"
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

ssl_ctx_t
ssl_ctx_init(config_t *conf)
{
  common_verify(conf, CONFIG_MAGIC);

  return 0; /* SSL not available */
}

pbuf_result_t
ssl_process(protocol_buf_t *msg, connection_t *conn)
{
  char address[ADDR_DESCRIPTION];
  protocol_buf_t pbuf = PROTOCOL_BUF_INIT(PROTOCOL_ERROR, 2);

  common_verify(msg, PROTOCOL_BUF_MAGIC);
  common_verify(conn, CONNECTION_MAGIC);

  /* For error messages, do nothing */
  if (msg->pb_flags & PROTOCOL_ERROR)
    return PBR_MSG_PROCESSED;

  /* If we got a reply, we have to close the connection, since we
   * don't actually know how to SSL.
   */
  else if (msg->pb_flags & PROTOCOL_REPLY)
    return PBR_CONNECTION_CLOSE;

  /* OK, it was a request for SSL; send back an error */
  if (!protocol_buf_send(&pbuf, conn)) {
    log_emit(conn->con_runtime->rt_config, LOG_WARNING,
	     "Out of memory constructing SSL error packet for %s (id %"
	     PRIdPTR ")",
	     ep_addr_describe(&conn->con_remote, address, sizeof(address)),
	     conn->con_socket);
    return PBR_CONNECTION_CLOSE;
  }

  /* Release the buffer memory */
  protocol_buf_free(&pbuf);

  return PBR_MSG_PROCESSED;
}

#else /* HAVE_OPENSSL */

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#define SESSION_CACHE_ID	"Humboldt"

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

static void
log_errors(config_t *conf, const char *fmt, ...)
{
  unsigned long errcode;
  char context_buf[256];
  const char *context = context_buf;
  va_list ap;

  /* Construct the context */
  va_start(ap, fmt);
  vsnprintf(context_buf, sizeof(context_buf), fmt, ap);
  va_end(ap);

  /* Log all errors in the queue */
  while ((errcode = ERR_get_error())) {
    log_emit(conf, LOG_WARNING, "OpenSSL error%s%s: %s", context ? " " : "",
	     context ? context : "", ERR_error_string(errcode, 0));
    context = 0;
  }

  /* If there were no errors, log something */
  if (context)
    log_emit(conf, LOG_WARNING, "OpenSSL error %s: Unknown error", context);
}

ssl_ctx_t
ssl_ctx_init(config_t *conf)
{
  static int lib_initialized = 0;
  SSL_CTX *ctx;

  common_verify(conf, CONFIG_MAGIC);

  /* Check if the SSL configuration is available */
  if (!conf->cf_ssl)
    return 0;

  common_verify(conf->cf_ssl, SSL_CONF_MAGIC);

  /* First step, initialize the library if needed */
  if (!lib_initialized) {
    SSL_load_error_strings();
    SSL_library_init();
    lib_initialized = 1;
  }

  /* Next, allocate a context */
  if (!(ctx = SSL_CTX_new(SSLv23_method())))
    return 0;

  /* Restrict the versions of SSL we'll allow */
  SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

  /* Enable the session cache */
  SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_BOTH);
  SSL_CTX_set_session_id_context(ctx, (unsigned char *)SESSION_CACHE_ID,
				 sizeof(SESSION_CACHE_ID));

  /* Request peer certificates */
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, 0);

  /* Set the cipher list */
  if (conf->cf_ssl->sc_ciphers &&
      !SSL_CTX_set_cipher_list(ctx, conf->cf_ssl->sc_ciphers)) {
    log_errors(conf, "while setting ciphers to \"%s\"",
	       conf->cf_ssl->sc_ciphers);
    log_emit(conf, LOG_WARNING, "Disabling SSL");
    SSL_CTX_free(ctx);
    return 0;
  }

  /* Configure the certificate chain file */
  if (SSL_CTX_use_certificate_chain_file(ctx, conf->cf_ssl->sc_cert_chain)
      != 1) {
    log_errors(conf, "while setting certificate chain file to \"%s\"",
	       conf->cf_ssl->sc_cert_chain);
    log_emit(conf, LOG_WARNING, "Disabling SSL");
    SSL_CTX_free(ctx);
    return 0;
  }

  /* Configure the private key file */
  if (SSL_CTX_use_PrivateKey_file(ctx, conf->cf_ssl->sc_private_key,
				  SSL_FILETYPE_PEM) != 1) {
    log_errors(conf, "while setting private key file to \"%s\"",
	       conf->cf_ssl->sc_private_key);
    log_emit(conf, LOG_WARNING, "Disabling SSL");
    SSL_CTX_free(ctx);
    return 0;
  }

  log_emit(conf, LOG_INFO, "SSL enabled");

  return (ssl_ctx_t)ctx;
}

pbuf_result_t
ssl_process(protocol_buf_t *msg, connection_t *conn)
{
  char address[ADDR_DESCRIPTION];
  protocol_buf_t pbuf = PROTOCOL_BUF_INIT(PROTOCOL_ERROR, 2);

  common_verify(msg, PROTOCOL_BUF_MAGIC);
  common_verify(conn, CONNECTION_MAGIC);

  /* For error messages, do nothing */
  if (msg->pb_flags & PROTOCOL_ERROR)
    return PBR_MSG_PROCESSED;

  /* If we got a reply, we have to close the connection, since we
   * don't actually know how to SSL.
   */
  else if (msg->pb_flags & PROTOCOL_REPLY)
    return PBR_CONNECTION_CLOSE;

  /* OK, it was a request for SSL; send back an error */
  if (!protocol_buf_send(&pbuf, conn)) {
    log_emit(conn->con_runtime->rt_config, LOG_WARNING,
	     "Out of memory constructing SSL error packet for %s (id %"
	     PRIdPTR ")",
	     ep_addr_describe(&conn->con_remote, address, sizeof(address)),
	     conn->con_socket);
    return PBR_CONNECTION_CLOSE;
  }

  /* Release the buffer memory */
  protocol_buf_free(&pbuf);

  return PBR_MSG_PROCESSED;
}

#endif /* HAVE_OPENSSL */

/* Defined regardless of whether OpenSSL is available, for
 * completeness.
 */
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
