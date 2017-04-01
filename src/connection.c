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
#include <string.h>

#include "include/alloc.h"
#include "include/common.h"
#include "include/connection.h"
#include "include/endpoint.h"
#include "include/log.h"

static freelist_t connections = FREELIST_INIT(connection_t, 0);

static void
_connection_read(struct bufferevent *bev, connection_t *conn)
{
  /* For now, just act like an echo server */
  struct evbuffer *in = bufferevent_get_input(bev);
  struct evbuffer *out = bufferevent_get_output(bev);
  evbuffer_add_buffer(out, in);
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

  return connection;
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
