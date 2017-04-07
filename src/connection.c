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

#include <errno.h>
#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/util.h>
#include <stdarg.h>
#include <string.h>
#include <uuid.h>

#include "include/alloc.h"
#include "include/common.h"
#include "include/connection.h"
#include "include/endpoint.h"
#include "include/log.h"
#include "include/protocol.h"

static freelist_t connections = FREELIST_INIT(connection_t, 0);

static void
_connection_read(struct bufferevent *bev, connection_t *conn)
{
  protocol_buf_t *msg;
  struct evbuffer *in = bufferevent_get_input(bev);
  char address[ADDR_DESCRIPTION];

  while (1) {
    /* Grab off a message */
    if (!protocol_buf_recv(in, &msg)) {
      log_emit(conn->con_runtime->rt_config, LOG_NOTICE,
	       "Error receiving message from %s: %s",
	       ep_addr_describe(&conn->con_remote, address, sizeof(address)),
	       strerror(errno));
      connection_destroy(conn);
      return;
    }

    /* Was there a message? */
    if (!msg)
      return;

    log_emit(conn->con_runtime->rt_config, LOG_DEBUG,
	     "Protocol %u message received from %s", msg->pb_protocol,
	     ep_addr_describe(&conn->con_remote, address, sizeof(address)));

    /* Process the message */
    if (protocol_buf_dispatch(msg, conn) == PBR_CONNECTION_CLOSE) {
      log_emit(conn->con_runtime->rt_config, LOG_INFO,
	       "Closing connection %s",
	       ep_addr_describe(&conn->con_remote, address, sizeof(address)));
      connection_destroy(conn);
      return;
    }
  }
}

static void
_connection_event(struct bufferevent *bev, short events, connection_t *conn)
{
  char address[ADDR_DESCRIPTION];

  if (events & (BEV_EVENT_ERROR | BEV_EVENT_EOF)) {
    if (events & BEV_EVENT_ERROR)
      log_emit(conn->con_runtime->rt_config, LOG_NOTICE,
	       "Error on connection to %s: %s",
	       ep_addr_describe(&conn->con_remote, address, sizeof(address)),
	       strerror(errno));
    else
      log_emit(conn->con_runtime->rt_config, LOG_INFO,
	       "Closing connection %s",
	       ep_addr_describe(&conn->con_remote, address, sizeof(address)));

    connection_destroy(conn);
  }
}

connection_t *
connection_create(runtime_t *runtime, endpoint_t *endpoint,
		  evutil_socket_t sock, ep_addr_t *addr)
{
  char address[ADDR_DESCRIPTION];
  connection_t *connection;

  /* Allocate an item */
  if (!(connection = alloc(&connections))) {
    log_emit(runtime->rt_config, LOG_WARNING,
	     "Out of memory creating connection for %s",
	     ep_addr_describe(addr, address, sizeof(address)));
    evutil_closesocket(sock);
    return 0;
  }

  /* Initialize the connection */
  link_elem_init(&connection->con_link, connection);
  connection->con_remote = *addr;
  connection->con_endpoint = endpoint;
  connection->con_type = endpoint->ep_config->epc_type;
  connection->con_runtime = runtime;

  /* Initialize the connection state */
  connection->con_state.cst_flags = 0;
  connection->con_state.cst_status = CONN_STAT_INITIAL;
  connection->con_state.cst_reserved = 0;

  /* Set the connection flags */
  if (connection->con_type == ENDPOINT_CLIENT)
    connection->con_state.cst_flags |= CONN_STATE_CLI;
  if (endpoint->ep_addr.ea_flags & EA_LOCAL)
    /* Local connections are considered secure */
    connection->con_state.cst_flags |= CONN_STATE_SEC;

  /* Create the bufferevent */
  if (!(connection->con_bev = bufferevent_socket_new(
	  runtime->rt_evbase, sock, BEV_OPT_CLOSE_ON_FREE))) {
    log_emit(runtime->rt_config, LOG_WARNING,
	     "Out of memory creating bufferevent for %s",
	     ep_addr_describe(addr, address, sizeof(address)));
    evutil_closesocket(sock);
    release(&connections, connection);
    return 0;
  }

  /* Set the bufferevent callbacks */
  bufferevent_setcb(connection->con_bev,
		    (bufferevent_data_cb)_connection_read, 0,
		    (bufferevent_event_cb)_connection_event, connection);

  /* Enable it for reading or writing */
  if (bufferevent_enable(connection->con_bev, EV_READ | EV_WRITE)) {
    log_emit(runtime->rt_config, LOG_WARNING,
	     "Unable to enable bufferevent for %s",
	     ep_addr_describe(addr, address, sizeof(address)));
    bufferevent_free(connection->con_bev); /* closes sock */
    release(&connections, connection);
    return 0;
  }

  /* Set the magic number, now that it's valid */
  connection->con_magic = CONNECTION_MAGIC;

  /* Add it to the list of connections */
  link_append(&runtime->rt_connections, &connection->con_link);

  /* Send the connection state */
  if (!connection_send_state(connection)) {
    connection_destroy(connection);
    return 0;
  }

  return connection;
}

int
connection_send_state(connection_t *conn)
{
  protocol_buf_t pbuf = PROTOCOL_BUF_INIT(PROTOCOL_REPLY, 0);

  /* Give a hint as to the packet size */
  if (!protocol_buf_hint(&pbuf, 20)) {
    log_emit(conn->con_runtime->rt_config, LOG_WARNING,
	     "Out of memory initializing protocol buffer");
    return 0;
  }

  /* Build the protocol packet */
  if (!protocol_buf_add_uint8(&pbuf, conn->con_state.cst_flags) ||
      !protocol_buf_add_uint8(&pbuf, conn->con_state.cst_status) ||
      !protocol_buf_add_uint16(&pbuf, conn->con_state.cst_reserved) ||
      !protocol_buf_append(&pbuf, conn->con_runtime->rt_config->cf_uuid,
			   sizeof(uuid_t))) {
    log_emit(conn->con_runtime->rt_config, LOG_WARNING,
	     "Out of memory constructing connection state packet");
    return 0;
  }

  /* Send it */
  if (!protocol_buf_send(&pbuf, conn)) {
    char address[ADDR_DESCRIPTION];

    log_emit(conn->con_runtime->rt_config, LOG_INFO,
	     "Unable to send connection state to %s: %s",
	     ep_addr_describe(&conn->con_remote, address, sizeof(address)),
	     strerror(errno));

    return 0;
  }

  /* Release the buffer memory */
  protocol_buf_free(&pbuf);

  return 1;
}

void
connection_report_error(connection_t *conn, conn_error_t error, ...)
{
  char address[ADDR_DESCRIPTION], errmsg[1024] = "";
  protocol_buf_t pbuf = PROTOCOL_BUF_INIT(PROTOCOL_ERROR, 0);
  va_list ap;

  common_verify(conn, CONNECTION_MAGIC);

  /* Set the error code on the error packet */
  protocol_buf_add_uint8(&pbuf, error);

  /* Process any additional arguments */
  va_start(ap, error);
  switch (error) {
  case CONN_ERR_NO_ERROR:
    /* No additional arguments */
    snprintf(errmsg, sizeof(errmsg), "No error");
    break;

  case CONN_ERR_UNKNOWN_PROTOCOL:
    {
      /* Add the protocol to the error packet */
      unsigned int proto = va_arg(ap, unsigned int);
      protocol_buf_add_uint8(&pbuf, proto);

      snprintf(errmsg, sizeof(errmsg), "Unrecognized protocol %d", proto);
    }
    break;
  }

  /* Make a best effort to send the message */
  protocol_buf_send(&pbuf, conn);

  /* Free the error message */
  protocol_buf_free(&pbuf);

  /* Log the error */
  log_emit(conn->con_runtime->rt_config, LOG_NOTICE,
	   "Error from %s: %s",
	   ep_addr_describe(&conn->con_remote, address, sizeof(address)),
	   errmsg);
}

pbuf_result_t
connection_process(protocol_buf_t *msg, connection_t *conn)
{
  common_verify(msg, PROTOCOL_BUF_MAGIC);
  common_verify(conn, CONNECTION_MAGIC);

  /* Handle the message bits */
  if (msg->pb_flags & PROTOCOL_ERROR) {
    /* Other side will be closing the connection */
    /* XXX We should log the error information */
    return PBR_CONNECTION_CLOSE;
  } else if (msg->pb_flags & PROTOCOL_REPLY)
    /* Should maintain state of the other end */
    return PBR_MSG_PROCESSED;

  /* For a request packet, just send the state */
  return connection_send_state(conn) ? PBR_MSG_PROCESSED :
    PBR_CONNECTION_CLOSE;
}

void
connection_destroy(connection_t *conn)
{
  common_verify(conn, CONNECTION_MAGIC);

  /* Remove from the linked list */
  link_pop(&conn->con_link);

  /* Free the bufferevent, which will close the socket */
  bufferevent_free(conn->con_bev);
  conn->con_bev = 0;

  /* Release it to the free list */
  release(&connections, conn);
}