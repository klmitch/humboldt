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

/** \brief Connection state.
 *
 * Represents a connection's state, including flags.  This information
 * is grouped together as any changes to it should result in a
 * protocol 0 message being sent.
 */
typedef struct _conn_state_s conn_state_t;

/** \brief Connection.
 *
 * Represents a connection to a client or to another peer.
 */
typedef struct _connection_s connection_t;

/** \brief Connection status.
 *
 * The status of the connection.
 */
typedef enum _conn_status_e {
  CONN_STAT_INITIAL = 0,	/**< Connection is in INITIAL status */
  CONN_STAT_ERROR = 255		/**< Connection is in ERROR status */
} conn_status_t;

/** \brief Connection state structure.
 *
 * This structure contains the connection state.
 */
struct _conn_state_s {
  uint8_t	cst_flags;	/**< Connection flags */
  conn_status_t	cst_status:8;	/**< Connection status (8 bits) */
  uint16_t	cst_reserved;	/**< Reserved; should be set to 0 */
};

/** \brief Client connection flag.
 *
 * This state flag is set if the connection is a client-type
 * connection.
 */
#define CONN_STATE_CLI		0x80

/** \brief Secure flag.
 *
 * This state flag is set if the connection is secure.  Note that this
 * implies confidentiality protection, e.g., encryption; simple
 * integrity protection does not constitute "secure".
 */
#define CONN_STATE_SEC		0x40

/** \brief TLS availability flag.
 *
 * This state flag is set if TLS protection is available for the
 * connection.  The presence of this flag in the protocol indicates
 * that a STARTTLS protocol frame may succeed.
 */
#define CONN_STATE_TLS		0x20

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
  conn_state_t	con_state;	/**< Connection state */
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

/** \brief Send connection state.
 *
 * Send the connection state to the connection.
 *
 * \param[in]		conn	The connection.
 *
 * \return	A true value if successful, false otherwise.  On
 *		failure, the connection will be destroyed.
 */
int connection_send_state(connection_t *conn);

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
