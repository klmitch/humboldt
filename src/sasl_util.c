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

#include <event2/bufferevent.h>
#include <event2/util.h>
#include <sasl/sasl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "include/alloc.h"
#include "include/configuration.h"
#include "include/connection.h"
#include "include/log.h"
#include "include/sasl_util.h"
#include "include/user.h"
#include "include/yaml_util.h"

#define HUMBOLDT_APPNAME	"Humboldt"
#define HUMBOLDT_SVCNAME	"humboldt"
#define MAX_SASL_CALLBACKS	3

static freelist_t connections = FREELIST_INIT(sasl_connection_t, 0);

static void
proc_sasl_conf(const char *key, sasl_conf_t *sasl_conf, yaml_ctx_t *ctx,
	       yaml_node_t *value)
{
  conf_ctx_t conf_ctx = CONF_CTX_YAML(ctx, value);
  node_info_t info;
  sasl_option_t *sasl_opt;
  char strbuf[100], *val_str;
  size_t key_len, val_len;

  common_verify(sasl_conf, SASL_CONF_MAGIC);

  /* Get the value information */
  if (!yaml_get_scalar(ctx, value, &info))
    return;

  /* Interpret the node's type */
  if (info.ni_type == NODE_NULL_TAG) {
    /* Interpret as a zero-length string */
    val_str = "";
    val_len = 0;
  } else if (info.ni_type == NODE_INT_TAG)
    /* Convert integer back into a string, but without YAML's extensions */
    val_len = snprintf(val_str = strbuf, sizeof(strbuf), "%jd",
		       info.ni_data.nid_int);
  else {
    /* Everything else, go back to the original string value */
    val_str = (char *)value->data.scalar.value;
    val_len = value->data.scalar.length;
  }

  /* Need the key's length too */
  key_len = strlen(key);

  /* Allocate an option structure */
  if (!(sasl_opt = malloc(sizeof(sasl_option_t) + val_len + key_len + 1))) {
    config_report(&conf_ctx, LOG_WARNING,
		  "Out of memory saving SASL configuration value \"%s\"", key);
    return;
  }

  /* Initialize the option structure values */
  sasl_opt->sao_vallen = val_len;
  memcpy(sasl_opt->sao_value, val_str, val_len);
  sasl_opt->sao_value[val_len] = '\0';
  sasl_opt->sao_option = &sasl_opt->sao_value[val_len + 1];
  memcpy(sasl_opt->sao_option, key, key_len);
  sasl_opt->sao_option[key_len] = '\0';

  /* Now we can initialize the hash entry */
  hash_ent_init(&sasl_opt->sao_hashent, sasl_opt, sasl_opt->sao_option);

  /* And set the magic number */
  sasl_opt->sao_magic = SASL_OPTION_MAGIC;

  /* Add it to the hash table */
  switch (hash_add(&sasl_conf->sac_options, &sasl_opt->sao_hashent)) {
  case DBERR_NONE:
    break; /* add successful */

  case DBERR_DUPLICATE:
    config_report(&conf_ctx, LOG_WARNING, "Duplicate SASL option \"%s\"", key);
    free(sasl_opt);
    break;

  case DBERR_NOMEMORY:
    config_report(&conf_ctx, LOG_WARNING,
		  "Out of memory saving SASL configuration value \"%s\"", key);
    free(sasl_opt);
    break;
  }
}

void
sasl_conf_processor(const char *key, config_t *conf,
		    yaml_ctx_t *ctx, yaml_node_t *value)
{
  conf_ctx_t conf_ctx = CONF_CTX_YAML(ctx, value);
  sasl_conf_t *sasl_conf;

  common_verify(conf, CONFIG_MAGIC);

  /* Construct a sasl_conf_t object */
  if (!(sasl_conf = malloc(sizeof(sasl_conf_t)))) {
    config_report(&conf_ctx, LOG_WARNING,
		  "Out of memory reading SASL configuration");
    return;
  }

  /* Initialize the object */
  hash_tab_init(&sasl_conf->sac_options, db_str_hash, db_str_comp);
  sasl_conf->sac_magic = SASL_CONF_MAGIC;

  /* Save it in the configuration */
  conf->cf_sasl = sasl_conf;

  /* Process all the items in the mapping */
  yaml_proc_mapping(ctx, value, (mapproc_t)proc_sasl_conf, 0, 0, sasl_conf);
}

static void
free_option(sasl_option_t *option, void *extra)
{
  common_verify(option, SASL_OPTION_MAGIC);

  /* First, remove it from the hash table */
  hash_remove(&option->sao_hashent);

  /* Release the option memory */
  free(option);
}

void
sasl_conf_free(sasl_conf_t *conf)
{
  common_verify(conf, SASL_CONF_MAGIC);

  /* Release all the entries first */
  hash_iter(&conf->sac_options, (db_iter_t)free_option, 0);

  /* Release the configuration memory */
  free(conf);
}

static int level_map[] = {
  -1,		/* SASL_LOG_NONE */
  LOG_ERR,	/* SASL_LOG_ERR */
  LOG_WARNING,	/* SASL_LOG_FAIL */
  LOG_WARNING,	/* SASL_LOG_WARN */
  LOG_NOTICE,	/* SASL_LOG_NOTE */
  LOG_DEBUG,	/* SASL_LOG_DEBUG */
  LOG_DEBUG,	/* SASL_LOG_TRACE */
  -1		/* SASL_LOG_PASS */
};

/* Map of libsasl level to prefix */
static const char *level_pfx[] = {
  0,
  "[ ERR ]",
  "[ FAIL]",
  "[ WARN]",
  "[ NOTE]",
  "[DEBUG]",
  "[TRACE]",
  0
};

static int
log_callback(config_t *conf, int level, const char *msg)
{
  /* If it's one of the levels we should not log, skip */
  if (level_map[level] < 0)
    return SASL_OK;

  /* Use our log_emit() */
  log_emit(conf, level_map[level], "libsasl2: %s %s", level_pfx[level], msg);

  return SASL_OK;
}

static int
getopt_callback(sasl_conf_t *sasl_conf, const char *plugin_name,
		const char *option, const char **result, unsigned int *len)
{
  sasl_option_t *opt;

  /* Look up the option */
  if ((opt = hash_find(&sasl_conf->sac_options, option))) {
    /* Set up the result, and length if requested */
    *result = opt->sao_value;
    if (len)
      *len = opt->sao_vallen;
  }

  return SASL_OK;
}

static int
checkpass_callback(sasl_conn_t *conn, userdb_t *userdb,
		   const char *username, const char *passwd,
		   unsigned int passlen, struct propctx *propctx)
{
  int i = 0, j = 0;
  uint8_t result = 0;
  user_t *user;

  /* First, look up the user record */
  if (!(user = user_lookup(userdb, username)))
    return SASL_NOUSER; /* other mechs will be queried */

  /* Now, check to see if it has a password */
  if (!user->u_passwd)
    return SASL_DISABLED; /* other mechs will be queried */

  /* OK, compare the passwords; avoid giving away information with timing */
  while (j < passlen) {
    result |= (uint8_t)user->u_passwd[i] ^ (uint8_t)passwd[j];

    /* Increment the indexes as appropriate */
    if (user->u_passwd[i])
      i++;
    j++;
  }

  /* Return the state of the comparison */
  return result ? SASL_BADAUTH : SASL_OK;
}

#define set_callback(cb_id, cb_proc, cb_context)	\
  do {							\
    callbacks[cb_idx].id = (cb_id);			\
    callbacks[cb_idx].proc = (int (*)(void))(cb_proc);	\
    callbacks[cb_idx].context = (cb_context);		\
    cb_idx++; /* Increment to the next callback */	\
  } while (0)

#define last_callback()				\
  do {						\
    callbacks[cb_idx].id = SASL_CB_LIST_END;	\
    callbacks[cb_idx].proc = 0;			\
    callbacks[cb_idx].context = 0;		\
  } while (0)

sasl_callback_t callbacks[MAX_SASL_CALLBACKS + 1];

int
initialize_sasl(config_t *conf)
{
  int cb_idx = 0, result;

  /* Set up the logging callback */
  set_callback(SASL_CB_LOG, log_callback, conf);

  /* If we have SASL options in the config, set up the getopt callback */
  if (conf->cf_sasl)
    set_callback(SASL_CB_GETOPT, getopt_callback, conf->cf_sasl);

  /* If we have passwords in the config, set up the checkpass callback */
  if (conf->cf_userdb && (conf->cf_userdb->udb_flags & USERDB_FLAG_PASSWORDS))
    set_callback(SASL_CB_SERVER_USERDB_CHECKPASS, checkpass_callback,
		 conf->cf_userdb);

  /* Done setting up the callbacks */
  last_callback();

  /* Initialize the SASL library */
  if ((result = sasl_client_init(callbacks)) != SASL_OK) {
    log_emit(conf, LOG_ERR, "Failed to initialize SASL (client side): %s",
	     sasl_errstring(result, 0, 0));
    return 0;
  } else if ((result = sasl_server_init(callbacks, HUMBOLDT_APPNAME)) !=
	     SASL_OK) {
    log_emit(conf, LOG_ERR, "Failed to initialize SASL (server side): %s",
	     sasl_errstring(result, 0, 0));
    sasl_client_done();
    return 0;
  }

  log_emit(conf, LOG_INFO, "SASL initialized");
  return 1;
}

int
sasl_connection_init(connection_t *conn)
{
  char conn_desc[ADDR_DESCRIPTION];
#ifdef INET6_ADDRSTRLEN
  char addrbuf[INET6_ADDRSTRLEN + 1];
#else
  char addrbuf[INET_ADDRSTRLEN + 1];
#endif
  char srvbuf[ADDR_DESCRIPTION], *srvaddr = srvbuf;
  char clibuf[ADDR_DESCRIPTION], *cliaddr = clibuf;
  const void *local_ipaddr, *remote_ipaddr;
  int local_port, remote_port, result;
  sasl_connection_t *sasl_conn;

  common_verify(conn, CONNECTION_MAGIC);

  /* Begin by allocating a connection object */
  if (!(sasl_conn = alloc(&connections))) {
    log_emit(conn->con_runtime->rt_config, LOG_WARNING,
	     "Out of memory allocating SASL connection information for %s",
	     connection_describe(conn, conn_desc, sizeof(conn_desc)));
    return 0;
  }

  /* Next, format the addresses */
  if (conn->con_endpoint->ep_addr.ea_flags & EA_LOCAL) {
    /* Local port.  Could use a local host address, but which one? */
    cliaddr = 0;
    srvaddr = 0;
  } else {
    /* Pick out the addresses and ports */
#ifdef AF_INET6
    if (conn->con_endpoint->ep_addr.ea_addr.eau_addr.sa_family == AF_INET6) {
      local_ipaddr = (void *)&conn->con_endpoint->ep_addr
	.ea_addr.eau_ip6.sin6_addr;
      local_port = conn->con_endpoint->ep_addr.ea_addr.eau_ip6.sin6_port;
      remote_ipaddr = (void *)&conn->con_remote.ea_addr.eau_ip6.sin6_addr;
      remote_port = conn->con_remote.ea_addr.eau_ip6.sin6_port;
    } else {
#endif
      local_ipaddr = (void *)&conn->con_endpoint->ep_addr
	.ea_addr.eau_ip4.sin_addr;
      local_port = conn->con_endpoint->ep_addr.ea_addr.eau_ip4.sin_port;
      remote_ipaddr = (void *)&conn->con_remote.ea_addr.eau_ip4.sin_addr;
      remote_port = conn->con_remote.ea_addr.eau_ip4.sin_port;
#ifdef AF_INET6
    }
#endif

    /* Format them for SASL */
    snprintf(srvbuf, sizeof(srvbuf), "%s;%d",
	     evutil_inet_ntop(conn->con_remote.ea_addr.eau_addr.sa_family,
			      local_ipaddr, addrbuf, sizeof(addrbuf)),
	     ntohs(local_port));
    snprintf(clibuf, sizeof(clibuf), "%s;%d",
	     evutil_inet_ntop(conn->con_remote.ea_addr.eau_addr.sa_family,
			      remote_ipaddr, addrbuf, sizeof(addrbuf)),
	     ntohs(remote_port));
  }

  /* Initialize the server side of SASL */
  if ((result = sasl_server_new(HUMBOLDT_SVCNAME, 0, 0, srvaddr, cliaddr,
				0, 0, &sasl_conn->sac_server)) != SASL_OK) {
    log_emit(conn->con_runtime->rt_config, LOG_NOTICE,
	     "Failed to initialize SASL connection (server side) for %s: %s",
	     connection_describe(conn, conn_desc, sizeof(conn_desc)),
	     sasl_errstring(result, 0, 0));
    release(&connections, sasl_conn);
    return 0;
  }

  /* Initialize the client side of SASL, if needed */
  if (conn->con_type == ENDPOINT_PEER) {
    if ((result = sasl_client_new(HUMBOLDT_SVCNAME, 0, srvaddr, cliaddr,
				  0, 0, &sasl_conn->sac_client)) != SASL_OK) {
      log_emit(conn->con_runtime->rt_config, LOG_NOTICE,
	       "Failed to initialize SASL connection (client side) for %s: %s",
	       connection_describe(conn, conn_desc, sizeof(conn_desc)),
	       sasl_errstring(result, 0, 0));
      sasl_dispose(&sasl_conn->sac_server);
      sasl_conn->sac_server = 0;
      release(&connections, sasl_conn);
      return 0;
    }
  } else
    sasl_conn->sac_client = 0;

  /* Finish initializing the connection information */
  sasl_conn->sac_bev = 0;
  sasl_conn->sac_magic = SASL_CONNECTION_MAGIC;

  /* Save it in the connection */
  conn->con_sasl = sasl_conn;

  /* Set the initial SSF */
  if (!sasl_set_ssf(conn, conn->con_endpoint->ep_config->epc_ssf)) {
    conn->con_sasl = 0;
    sasl_connection_release(sasl_conn);
    return 0;
  }

  /* Set the external authentication ID if it's available */
  if (conn->con_username && !sasl_set_external(conn, conn->con_username)) {
    conn->con_sasl = 0;
    sasl_connection_release(sasl_conn);
    return 0;
  }

  return 1;
}

int
sasl_set_ssf(connection_t *conn, unsigned int ssf)
{
  char conn_desc[ADDR_DESCRIPTION];
  sasl_security_properties_t sec_props;

  log_emit(conn->con_runtime->rt_config, LOG_DEBUG,
	   "Setting security strength factor of %s to %d",
	   connection_describe(conn, conn_desc, sizeof(conn_desc)), ssf);

  /* Begin by setting up the security properties */
  sec_props.security_flags = SASL_SEC_NOANONYMOUS;
  sec_props.property_names = 0;
  sec_props.property_values = 0;
  if (ssf >= conn->con_runtime->rt_config->cf_min_ssf) {
    sec_props.min_ssf = 0;
    sec_props.max_ssf = 0;
    sec_props.maxbufsize = 0;
  } else {
    /* Still in plain text mode */
    sec_props.security_flags |= SASL_SEC_NOPLAINTEXT;
    sec_props.min_ssf = conn->con_runtime->rt_config->cf_min_ssf;
    sec_props.max_ssf = 256; /* Just an arbitrary maximum */
    sec_props.maxbufsize = 0; /* Not supported yet */
  }

  /* First, set up the security strength factor for the server side */
  if (sasl_setprop(conn->con_sasl->sac_server, SASL_SSF_EXTERNAL, &ssf) !=
      SASL_OK) {
    log_emit(conn->con_runtime->rt_config, LOG_NOTICE,
	     "Failed to set security strength factor on SASL connection "
	     "(server side) for %s: %s",
	     connection_describe(conn, conn_desc, sizeof(conn_desc)),
	     sasl_errdetail(conn->con_sasl->sac_server));
    return 0;
  }

  /* Now try the security properties */
  if (sasl_setprop(conn->con_sasl->sac_server, SASL_SEC_PROPS, &sec_props) !=
      SASL_OK) {
    log_emit(conn->con_runtime->rt_config, LOG_NOTICE,
	     "Failed to set security properties on SASL connection "
	     "(server side) for %s: %s",
	     connection_describe(conn, conn_desc, sizeof(conn_desc)),
	     sasl_errdetail(conn->con_sasl->sac_server));
    return 0;
  }

  /* Now do the client side */
  if (conn->con_sasl->sac_client) {
    /* First, the security strength factor on the client side */
    if (sasl_setprop(conn->con_sasl->sac_client, SASL_SSF_EXTERNAL, &ssf) !=
	SASL_OK) {
      log_emit(conn->con_runtime->rt_config, LOG_NOTICE,
	       "Failed to set security strength factor on SASL connection "
	       "(client side) for %s: %s",
	       connection_describe(conn, conn_desc, sizeof(conn_desc)),
	       sasl_errdetail(conn->con_sasl->sac_client));
      return 0;
    }

    /* Now the security properties */
    if (sasl_setprop(conn->con_sasl->sac_client, SASL_SEC_PROPS, &sec_props) !=
	SASL_OK) {
      log_emit(conn->con_runtime->rt_config, LOG_NOTICE,
	       "Failed to set security properties on SASL connection "
	       "(client side) for %s: %s",
	       connection_describe(conn, conn_desc, sizeof(conn_desc)),
	       sasl_errdetail(conn->con_sasl->sac_client));
      return 0;
    }
  }

  return 1;
}

int
sasl_set_external(connection_t *conn, const char *username)
{
  char conn_desc[ADDR_DESCRIPTION];

  log_emit(conn->con_runtime->rt_config, LOG_DEBUG,
	   "Setting external authentication ID of %s to %s",
	   connection_describe(conn, conn_desc, sizeof(conn_desc)), username);

  /* Set the authentication ID */
  if (sasl_setprop(conn->con_sasl->sac_server, SASL_AUTH_EXTERNAL, username) !=
      SASL_OK) {
    log_emit(conn->con_runtime->rt_config, LOG_NOTICE,
	     "Failed to set external authentication ID to \"%s\" for %s: %s",
	     username, connection_describe(conn, conn_desc, sizeof(conn_desc)),
	     sasl_errdetail(conn->con_sasl->sac_server));
    return 0;
  }

  return 1;
}

pbuf_result_t
sasl_process(protocol_buf_t *msg, connection_t *conn)
{
  char conn_desc[ADDR_DESCRIPTION];
  protocol_buf_t pbuf = PROTOCOL_BUF_INIT(PROTOCOL_REPLY, PROTOCOL_SASL);
  char mechname[SASL_MECHNAMEMAX + 1] = "";
  uint8_t mechname_len = 0;
  pbuf_pos_t pos = PBUF_POS_INIT();
  const char *out_data, *username;
  unsigned int out_len, *ssf_p;
  int result;

  common_verify(msg, PROTOCOL_BUF_MAGIC);
  common_verify(conn, CONNECTION_MAGIC);

  /* Handle the message bits */
  if (msg->pb_flags & PROTOCOL_ERROR)
    /* Right now, we only operate server-side, so nothing to do */
    return PBR_MSG_PROCESSED;
  else if (msg->pb_flags & PROTOCOL_REPLY)
    /* IBID */
    return PBR_MSG_PROCESSED;

  /* Extract the mechanism name length */
  if (!protocol_buf_get_uint8(msg, &pos, &mechname_len) ||
      (mechname_len != 255 &&
       (mechname_len > SASL_MECHNAMEMAX ||
	mechname_len > pbp_remaining(&pos, msg)))) {
    connection_report_error(conn, CONN_ERR_MALFORMED_MSG, 3);
    return PBR_CONNECTION_CLOSE;
  }

  /* Is it asking for a list of mechanisms? */
  if (mechname_len == 255) {
    const char *mechlist;
    unsigned int mechlist_len;

    /* Get the list of mechanisms */
    if (sasl_listmech(conn->con_sasl->sac_server, 0, "", " ", "",
		      &mechlist, &mechlist_len, 0) != SASL_OK) {
      const char *detail = sasl_errdetail(conn->con_sasl->sac_server);
      log_emit(conn->con_runtime->rt_config, LOG_NOTICE,
	       "Unable to generate list of SASL mechanisms for %s: %s",
	       connection_describe(conn, conn_desc, sizeof(conn_desc)),
	       detail);
      pbuf.pb_flags = PROTOCOL_ERROR;
      protocol_buf_append(&pbuf, detail, -1);
      protocol_buf_send(&pbuf, conn);
      protocol_buf_free(&pbuf);
      return PBR_MSG_PROCESSED;
    }

    /* Send it */
    if (!protocol_buf_add_uint8(&pbuf, 255) ||
	!protocol_buf_append(&pbuf, mechlist, mechlist_len) ||
	!protocol_buf_send(&pbuf, conn)) {
      log_emit(conn->con_runtime->rt_config, LOG_NOTICE,
	       "Unable to send list of SASL mechanisms to %s",
	       connection_describe(conn, conn_desc, sizeof(conn_desc)));
      protocol_buf_free(&pbuf);
      return PBR_CONNECTION_CLOSE;
    }

    protocol_buf_free(&pbuf);
    return PBR_MSG_PROCESSED;
  } else if (mechname_len > 0)
    /* Copy out the mechanism name; can't fail */
    protocol_buf_extract(msg, &pos, (unsigned char *)mechname, mechname_len);

  /* Are we starting or continuing authentication? */
  if (conn->con_flags & CONN_FLAG_SASL_INPROGRESS) {
    log_emit(conn->con_runtime->rt_config, LOG_DEBUG,
	     "Starting %s SASL exchange with %s", mechname,
	     connection_describe(conn, conn_desc, sizeof(conn_desc)));
    result = sasl_server_step(conn->con_sasl->sac_server,
			      pbp_data(&pos, msg),
			      pbp_remaining(&pos, msg),
			      &out_data,
			      &out_len);
  } else {
    /* Starting it */
    conn->con_flags |= CONN_FLAG_SASL_INPROGRESS;
    result = sasl_server_start(conn->con_sasl->sac_server,
			       mechname,
			       pbp_data(&pos, msg),
			       pbp_remaining(&pos, msg),
			       &out_data,
			       &out_len);
  }

  switch (result) {
  case SASL_OK:
    /* Authentication complete! */
    conn->con_flags &= ~CONN_FLAG_SASL_INPROGRESS;

    /* Get the authenticated user name */
    if (sasl_getprop(conn->con_sasl->sac_server, SASL_USERNAME,
		     (const void **)&username) != SASL_OK) {
      log_emit(conn->con_runtime->rt_config, LOG_NOTICE,
	       "Unable to get authenticated username from SASL for %s: %s",
	       connection_describe(conn, conn_desc, sizeof(conn_desc)),
	       sasl_errdetail(conn->con_sasl->sac_server));
      return PBR_CONNECTION_CLOSE;
    }

    /* Check if it's different and save it */
    if (!conn->con_username || strcmp(conn->con_username, username))
      connection_set_username(conn, username, CONN_USERNAME_FROMSASL);

    /* Get the security strength factor */
    if (sasl_getprop(conn->con_sasl->sac_server, SASL_SSF,
		     (const void **)&ssf_p) != SASL_OK) {
      log_emit(conn->con_runtime->rt_config, LOG_NOTICE,
	       "Unable to get security strength factor from SASL for %s: %s",
	       connection_describe(conn, conn_desc, sizeof(conn_desc)),
	       sasl_errdetail(conn->con_sasl->sac_server));
      return PBR_CONNECTION_CLOSE;
    }

    /* Check if we need to install a security layer */
    if (*ssf_p > 0)
      log_emit(conn->con_runtime->rt_config, LOG_WARNING,
	       "Connection %s negotiated a security layer, but security "
	       "layers are not yet supported; ignoring...",
	       connection_describe(conn, conn_desc, sizeof(conn_desc)));

    log_emit(conn->con_runtime->rt_config, LOG_DEBUG,
	     "Completed SASL exchange with %s",
	     connection_describe(conn, conn_desc, sizeof(conn_desc)));
    if (!connection_set_state(conn, 0, conn->con_type == ENDPOINT_CLIENT ?
			      CONN_STAT_CLIENT : CONN_STAT_AUTH,
			      CONN_STATE_STATUS))
      return PBR_CONNECTION_CLOSE;
    break;

  case SASL_CONTINUE:
    /* More protocol exchanges needed */
    if (!protocol_buf_add_uint8(&pbuf, 0) ||
	!protocol_buf_append(&pbuf, out_data, out_len) ||
	!protocol_buf_send(&pbuf, conn)) {
      log_emit(conn->con_runtime->rt_config, LOG_NOTICE,
	       "Unable to continue SASL authentication exchange to %s",
	       connection_describe(conn, conn_desc, sizeof(conn_desc)));
      protocol_buf_free(&pbuf);
      return PBR_CONNECTION_CLOSE;
    }
    protocol_buf_free(&pbuf);
    break;

  default:
    /* An error occurred; repurpose out_data for error message */
    out_data = sasl_errdetail(conn->con_sasl->sac_server);
    log_emit(conn->con_runtime->rt_config, LOG_NOTICE,
	     "Authentication failed for %s: %s",
	     connection_describe(conn, conn_desc, sizeof(conn_desc)),
	     out_data);
    pbuf.pb_flags = PROTOCOL_ERROR;
    protocol_buf_append(&pbuf, out_data, -1);
    protocol_buf_send(&pbuf, conn);
    protocol_buf_free(&pbuf);
    return PBR_CONNECTION_CLOSE;
    break; /* not reached */
  }

  return PBR_MSG_PROCESSED;
}

void
sasl_connection_release(sasl_connection_t *sasl_conn)
{
  common_verify(sasl_conn, SASL_CONNECTION_MAGIC);

  /* Dispose of the server and client connection contexts */
  if (sasl_conn->sac_server)
    sasl_dispose(&sasl_conn->sac_server);
  if (sasl_conn->sac_client)
    sasl_dispose(&sasl_conn->sac_client);
  sasl_conn->sac_server = 0;
  sasl_conn->sac_client = 0;

  /* If a security layer was created, dispose of it as well */
  if (sasl_conn->sac_bev)
    bufferevent_free(sasl_conn->sac_bev);
  sasl_conn->sac_bev = 0;

  /* Release the memory */
  release(&connections, sasl_conn);
}
