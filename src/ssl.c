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

  /* Emit a warning about TLS being unavailable */
  if (!ssl_warning) {
    yaml_ctx_report(ctx, &value->start_mark, LOG_WARNING,
		    "TLS support is not enabled.");
    ssl_warning = 1;
  }
}

ssl_ctx_t
ssl_ctx_init(config_t *conf)
{
  common_verify(conf, CONFIG_MAGIC);

  return 0; /* TLS not available */
}

pbuf_result_t
ssl_process(protocol_buf_t *msg, connection_t *conn)
{
  char conn_desc[ADDR_DESCRIPTION];
  protocol_buf_t pbuf = PROTOCOL_BUF_INIT(PROTOCOL_ERROR, 2);

  common_verify(msg, PROTOCOL_BUF_MAGIC);
  common_verify(conn, CONNECTION_MAGIC);

  /* For error messages, do nothing */
  if (msg->pb_flags & PROTOCOL_ERROR)
    return PBR_MSG_PROCESSED;

  /* If we got a reply, we have to close the connection, since we
   * don't actually know how to TLS.
   */
  else if (msg->pb_flags & PROTOCOL_REPLY) {
    log_emit(conn->con_runtime->rt_config, LOG_WARNING,
	     "Received a Start TLS Reply from %s, but TLS is not available",
	     connection_describe(conn, conn_desc, sizeof(conn_desc)));
    return PBR_CONNECTION_CLOSE;
  }

  /* OK, it was a request for TLS; log the event... */
  log_emit(conn->con_runtime->rt_config, LOG_NOTICE,
	   "Received a Start TLS Request from %s, but TLS is not available",
	   connection_describe(conn, conn_desc, sizeof(conn_desc)));

  /* ...then send back an error */
  if (!protocol_buf_send(&pbuf, conn)) {
    log_emit(conn->con_runtime->rt_config, LOG_WARNING,
	     "Out of memory constructing TLS error packet for %s",
	     connection_describe(conn, conn_desc, sizeof(conn_desc)));
    return PBR_CONNECTION_CLOSE;
  }

  /* Release the buffer memory */
  protocol_buf_free(&pbuf);

  return PBR_MSG_PROCESSED;
}

int
ssl_event(connection_t *conn, short events)
{
  /* Shouldn't ever actually be called */
  return 0;
}

void
ssl_shutdown(connection_t *conn)
{
  /* Called unconditionally by connection_destroy() */
}

void
ssl_free(ssl_conn_t scon)
{
  /* Shouldn't ever actually be called */
}

#else /* HAVE_OPENSSL */

#include <event2/bufferevent_ssl.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "include/alloc.h"

#define SESSION_CACHE_ID	"Humboldt"

struct ssl_conn_s {
  magic_t	scon_magic;	/**< Magic number */
  SSL	       *scon_ssl;	/**< SSL object */
  struct bufferevent
	       *scon_bev;	/**< Libevent bufferevent for SSL */
};

#define SSL_CONN_MAGIC 0xa1100c24

#define ssl_conn_init(scon)			\
  do {						\
    struct ssl_conn_s *_scon = (scon);		\
    _scon->scon_ssl = 0;			\
    _scon->scon_bev = 0;			\
    _scon->scon_magic = SSL_CONN_MAGIC;		\
  } while (0)

static freelist_t sslobjs = FREELIST_INIT(struct ssl_conn_s, 0);

static void
proc_cafile(const char *key, ssl_conf_t *conf, yaml_ctx_t *ctx,
	    yaml_node_t *value)
{
  const char *filename;

  common_verify(conf, SSL_CONF_MAGIC);

  /* Convert the value as a string */
  if (!yaml_get_str(ctx, value, &filename, 0, 0))
    return;

  /* Copy the filename into the configuration structure */
  if (!(conf->sc_cafile = strdup(filename)))
    yaml_ctx_report(ctx, &value->start_mark, LOG_WARNING,
		    "Out of memory reading string");
}

static void
proc_capath(const char *key, ssl_conf_t *conf, yaml_ctx_t *ctx,
	    yaml_node_t *value)
{
  const char *dirname;

  common_verify(conf, SSL_CONF_MAGIC);

  /* Convert the value as a string */
  if (!yaml_get_str(ctx, value, &dirname, 0, 0))
    return;

  /* Copy the filename into the configuration structure */
  if (!(conf->sc_capath = strdup(dirname)))
    yaml_ctx_report(ctx, &value->start_mark, LOG_WARNING,
		    "Out of memory reading string");
}

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
  MAPKEY("cafile", proc_cafile),
  MAPKEY("capath", proc_capath),
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
		    "Out of memory reading TLS configuration");
    return;
  }

  /* Initialize it */
  ssl_conf->sc_cafile = 0;
  ssl_conf->sc_capath = 0;
  ssl_conf->sc_cert_chain = 0;
  ssl_conf->sc_ciphers = 0;
  ssl_conf->sc_private_key = 0;
  ssl_conf->sc_magic = SSL_CONF_MAGIC;

  /* Process the configuration */
  yaml_proc_mapping(ctx, value, 0, ssl_options, list_count(ssl_options),
		    (void *)ssl_conf);

  /* Do we have what we need? */
  if (!ssl_conf->sc_cert_chain || !ssl_conf->sc_private_key) {
    yaml_ctx_report(ctx, &value->start_mark, LOG_WARNING,
		    "Not configuring TLS: missing configuration for %s%s%s",
		    ssl_conf->sc_cert_chain ? "" : "cert_chain",
		    !ssl_conf->sc_cert_chain && !ssl_conf->sc_private_key ?
		    " and " : "",
		    ssl_conf->sc_private_key ? "" : "private_key");
    ssl_conf_free(ssl_conf);
    return;
  } else if (!ssl_conf->sc_cafile && !ssl_conf->sc_capath) {
    yaml_ctx_report(ctx, &value->start_mark, LOG_WARNING,
		    "Not configuring TLS: missing configuration for "
		    "peer certificate verification; provide either "
		    "cafile or capath (or both)");
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

  /* Check if the TLS configuration is available */
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

  /* Restrict the versions of TLS we'll allow */
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
    log_emit(conf, LOG_WARNING, "Disabling TLS");
    SSL_CTX_free(ctx);
    return 0;
  }

  /* Configure the certificate chain file */
  if (SSL_CTX_use_certificate_chain_file(ctx, conf->cf_ssl->sc_cert_chain)
      != 1) {
    log_errors(conf, "while setting certificate chain file to \"%s\"",
	       conf->cf_ssl->sc_cert_chain);
    log_emit(conf, LOG_WARNING, "Disabling TLS");
    SSL_CTX_free(ctx);
    return 0;
  }

  /* Configure the private key file */
  if (SSL_CTX_use_PrivateKey_file(ctx, conf->cf_ssl->sc_private_key,
				  SSL_FILETYPE_PEM) != 1) {
    log_errors(conf, "while setting private key file to \"%s\"",
	       conf->cf_ssl->sc_private_key);
    log_emit(conf, LOG_WARNING, "Disabling TLS");
    SSL_CTX_free(ctx);
    return 0;
  }

  /* Configure the verification certificates */
  if (SSL_CTX_load_verify_locations(ctx, conf->cf_ssl->sc_cafile,
				    conf->cf_ssl->sc_capath) != 1) {
    log_errors(conf, "while loading peer verification certificates from "
	       "\"%s%s%s\"",
	       conf->cf_ssl->sc_cafile ? conf->cf_ssl->sc_cafile : "",
	       conf->cf_ssl->sc_cafile && conf->cf_ssl->sc_capath ?
	       "\" and \"" : "",
	       conf->cf_ssl->sc_capath ? conf->cf_ssl->sc_capath : "");
    log_emit(conf, LOG_WARNING, "Disabling TLS");
    SSL_CTX_free(ctx);
    return 0;
  }

  log_emit(conf, LOG_INFO, "TLS enabled");

  return (ssl_ctx_t)ctx;
}

pbuf_result_t
ssl_process(protocol_buf_t *msg, connection_t *conn)
{
  struct ssl_conn_s *scon;
  char conn_desc[ADDR_DESCRIPTION];
  protocol_buf_t pbuf = PROTOCOL_BUF_INIT(PROTOCOL_ERROR, 2);

  common_verify(msg, PROTOCOL_BUF_MAGIC);
  common_verify(conn, CONNECTION_MAGIC);

  /* For error messages, do nothing */
  if (msg->pb_flags & PROTOCOL_ERROR)
    return PBR_MSG_PROCESSED;

  /* For now, respond to replies by closing the connection; in future,
   * when we are able to initiate connections, we'll need to do
   * something more intelligent here.
   */
  else if (msg->pb_flags & PROTOCOL_REPLY) {
    log_emit(conn->con_runtime->rt_config, LOG_WARNING,
	     "Received a Start TLS Reply from %s, but I never sent a "
	     "Start TLS Request",
	     connection_describe(conn, conn_desc, sizeof(conn_desc)));
    return PBR_CONNECTION_CLOSE;
  }

  /* OK, it was a request for TLS; can we enable it? */
  if (conn->con_runtime->rt_ssl &&
      !(conn->con_state.cst_flags & CONN_STATE_SEC)) {
    /* Allocate an ssl_conn_t */
    if (!(scon = alloc(&sslobjs))) {
      log_emit(conn->con_runtime->rt_config, LOG_WARNING,
	       "Out of memory constructing TLS object for %s",
	       connection_describe(conn, conn_desc, sizeof(conn_desc)));
      return PBR_CONNECTION_CLOSE;
    }

    /* Initialize the SSL connection information */
    ssl_conn_init(scon);

    /* Allocate the SSL object */
    if (!(scon->scon_ssl = SSL_new(conn->con_runtime->rt_ssl))) {
      log_errors(conn->con_runtime->rt_config,
		 "while allocating TLS object for %s",
		 connection_describe(conn, conn_desc, sizeof(conn_desc)));
      ssl_free(scon);
      return PBR_CONNECTION_CLOSE;
    }

    /* Set up the Libevent filter */
    if (!(scon->scon_bev = bufferevent_openssl_filter_new(
	    conn->con_runtime->rt_evbase, conn->con_bev, scon->scon_ssl,
	    BUFFEREVENT_SSL_ACCEPTING, 0))) {
      log_emit(conn->con_runtime->rt_config, LOG_WARNING,
	       "Out of memory creating TLS bufferevent for %s",
	       connection_describe(conn, conn_desc, sizeof(conn_desc)));
      ssl_free(scon);
      return PBR_CONNECTION_CLOSE;
    }

    /* Send the response */
    pbuf.pb_flags = PROTOCOL_REPLY;
    if (!protocol_buf_send(&pbuf, conn)) {
      log_emit(conn->con_runtime->rt_config, LOG_WARNING,
	       "Out of memory constructing TLS reply packet for %s",
	       connection_describe(conn, conn_desc, sizeof(conn_desc)));
      ssl_free(scon);
      return PBR_CONNECTION_CLOSE;
    }

    /* Install the new bufferevent on the connection */
    if (!connection_install(conn, scon->scon_bev)) {
      log_emit(conn->con_runtime->rt_config, LOG_WARNING,
	       "Unable to install SSL bufferevent for %s",
	       connection_describe(conn, conn_desc, sizeof(conn_desc)));
      ssl_free(scon);
      return PBR_CONNECTION_CLOSE;
    }

    /* Save the SSL object */
    conn->con_ssl = scon;

    /* Flag that we're handshaking... */
    conn->con_flags |= CONN_FLAG_TLS_HANDSHAKE;
  } else {
    /* Can't enable TLS on this connection */
    log_emit(conn->con_runtime->rt_config, LOG_NOTICE,
	     "Received a Start TLS Request from %s, but %s",
	     connection_describe(conn, conn_desc, sizeof(conn_desc)),
	     conn->con_runtime->rt_ssl ? "connection is already secure" :
	     "TLS is not configured");

    /* Send back an error */
    if (!protocol_buf_send(&pbuf, conn)) {
      log_emit(conn->con_runtime->rt_config, LOG_WARNING,
	       "Out of memory constructing TLS error packet for %s",
	       connection_describe(conn, conn_desc, sizeof(conn_desc)));
      return PBR_CONNECTION_CLOSE;
    }
  }

  return PBR_MSG_PROCESSED;
}

int
ssl_event(connection_t *conn, short events)
{
  char conn_desc[ADDR_DESCRIPTION];
  struct ssl_conn_s *scon = conn->con_ssl;
  unsigned long errcode;

  /* If we got an error, check if it was from OpenSSL */
  if (events & BEV_EVENT_ERROR) {
    char context_buf[256];
    const char *context = context_buf;

    if (!(errcode = bufferevent_get_openssl_error(scon->scon_bev)))
      return 0; /* Not an OpenSSL error */

    /* Formulate a context message */
    snprintf(context_buf, sizeof(context_buf),
	     "while handshaking with %s",
	     connection_describe(conn, conn_desc, sizeof(conn_desc)));

    /* Log the errors */
    do {
      log_emit(conn->con_runtime->rt_config, LOG_WARNING,
	       "OpenSSL error%s%s: %s", context ? " " : "",
	       context ? context : "", ERR_error_string(errcode, 0));
      context = 0;
    } while ((errcode = bufferevent_get_openssl_error(scon->scon_bev)));

    /* Destroy the connection */
    connection_destroy(conn, 1);
    return 1;
  } else if (events & BEV_EVENT_CONNECTED) {
    X509 *cert;
    X509_NAME *subject;
    int len;
    char *name;

    /* Log that the handshake is complete */
    log_emit(conn->con_runtime->rt_config, LOG_NOTICE,
	     "SSL handshake with %s complete",
	     connection_describe(conn, conn_desc, sizeof(conn_desc)));

    /* Clear the handshake flag */
    conn->con_flags &= ~CONN_FLAG_TLS_HANDSHAKE;

    /* Update the connection state */
    if (!connection_set_state(conn, CONN_STATE_SEC, 0, CONN_STATE_FLAGS_SET))
      connection_destroy(conn, 1);

    /* Now, let's see if we have a peer certificate */
    if (!(cert = SSL_get_peer_certificate(scon->scon_ssl)))
      return 1;

    /* Get the subject name */
    subject = X509_get_subject_name(cert);

    /* How much space do we need to allocate? */
    if ((len = X509_NAME_get_text_by_NID(subject, NID_commonName, 0, 0)) < 0) {
      X509_free(cert); /* release the certificate */
      return 1;
    }

    /* Allocate space for the common name */
    if (!(name = malloc(len + 1))) {
      X509_free(cert); /* release the certificate */
      return 1;
    }

    /* Now grab the subject's common name */
    if ((len = X509_NAME_get_text_by_NID(subject, NID_commonName,
					 name, len + 1)) >= 0)
      log_emit(conn->con_runtime->rt_config, LOG_INFO,
	       "SSL peer at %s is %s",
	       connection_describe(conn, conn_desc, sizeof(conn_desc)), name);

    /* Clean up after ourselves */
    free(name);
    X509_free(cert);

    return 1;
  }

  /* Not something we know about */
  return 0;
}

void
ssl_shutdown(connection_t *conn)
{
  struct ssl_conn_s *scon;

  common_verify(conn, CONNECTION_MAGIC);
  if (!conn->con_ssl || (conn->con_flags & CONN_FLAG_CLOSING))
    return;

  scon = (struct ssl_conn_s *)conn->con_ssl;

  common_verify(scon, SSL_CONN_MAGIC);

  /* Initiate the shutdown */
  SSL_shutdown(scon->scon_ssl);
}

void
ssl_free(ssl_conn_t scon)
{
  struct ssl_conn_s *conn = scon;

  common_verify(conn, SSL_CONN_MAGIC);

  /* Release the buffer event */
  if (conn->scon_bev)
    bufferevent_free(conn->scon_bev);

  /* Release the SSL object */
  if (conn->scon_ssl)
    SSL_free(conn->scon_ssl);

  /* Release the object itself */
  release(&sslobjs, conn);
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
