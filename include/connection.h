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

#ifndef _HUMBOLDT_CONNECTION_H
#define _HUMBOLDT_CONNECTION_H

#include <event2/util.h>	/* for evutil_socket_t */

#include "common.h"		/* for magic_t */
#include "endpoint.h"		/* for endpoint types */
#include "runtime.h"		/* for runtime_t */

/** \brief Connection.
 *
 * Represents a connection to a client or to another peer.
 */
typedef struct _connection_s connection_t;

/** \brief Connection structure.
 *
 * This structure contains a description of the connection.
 */
struct _connection_s {
  magic_t	con_magic;	/**< Magic number */
  link_elem_t	con_link;	/**< Linked list element */
  ep_addr_t	con_remote;	/**< Remote address */
  endpoint_t   *con_endpoint;	/**< Endpoint connection came in on */
  ep_type_t	con_type;	/**< Type of connection: peer or client? */
  struct bufferevent
	       *con_bev;	/**< Libevent eventbuffer for connection */
  runtime_t    *con_runtime;	/**< Humboldt runtime */
};

/** \brief Connection magic number.
 *
 * This is the magic number used for the connection structure.  It is
 * used to guard against programming problems, such as failure to
 * initialize a connection.
 */
#define CONNECTION_MAGIC 0x12f955f3

/** \brief Allocate and initialize a connection.
 *
 * This function is called when a connection is accepted.  It creates
 * the connection object to represent the connection.
 *
 * \param[in,out]	runtime	The runtime.
 * \param[in]		endpoint
 *				The endpoint the connection arrived
 *				on.
 * \param[in]		sock	The socket for the connection.  The
 *				function takes responsibility for
 *				closing the socket in the event of an
 *				error.
 * \param[in]		addr	The address of the remote end of the
 *				endpoint.
 *
 * \return	The newly created connection, or \c NULL if an error
 *		occurs.
 */
connection_t *connection_create(runtime_t *runtime, endpoint_t *endpoint,
				evutil_socket_t sock, ep_addr_t *addr);

/** \brief Destroy connection.
 *
 * This function is called to destroy a connection.  The underlying
 * socket will be closed.
 *
 * \param[in,out]	conn	The connection to destroy.  No more
 *				references should be made to this
 *				object after this call.
 */
void connection_destroy(connection_t *conn);

#endif /* _HUMBOLDT_CONNECTION_H */
