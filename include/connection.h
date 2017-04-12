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
#include <stdint.h>		/* for uint32_t */

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

/** \brief Connection errors.
 *
 * The possible error codes for connection errors.  These are used for
 * such tasks as reporting an unknown protocol.
 */
typedef enum _conn_error_e {
  CONN_ERR_NO_ERROR,		/**< No error has occurred */
  CONN_ERR_UNKNOWN_PROTOCOL	/**< Protocol is unknown */
} conn_error_t;

#include "common.h"		/* for magic_t */
#include "endpoint.h"		/* for endpoint types */
#include "runtime.h"		/* for runtime_t */
#include "protocol.h"		/* for protocol_buf_t */

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

/** \brief Flags update flag.
 *
 * When passed to connection_set_state(), this flag indicates that the
 * provided connection state flags should be set.
 */
#define CONN_STATE_FLAGS_SET	0x80000000

/** \brief Status update flag.
 *
 * When passed to connection_set_state(), this flag indicates that the
 * connection status value should be updated.
 */
#define CONN_STATE_STATUS	0x10000000

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
  uint32_t	con_flags;	/**< Miscellaneous non-state flags */
  struct bufferevent
	       *con_bev;	/**< Libevent bufferevent for connection */
  struct bufferevent
	       *con_root;	/**< Root bufferevent for socket */
  evutil_socket_t
		con_socket;	/**< Connection socket */
  runtime_t    *con_runtime;	/**< Humboldt runtime */
};

/** \brief Connection magic number.
 *
 * This is the magic number used for the connection structure.  It is
 * used to guard against programming problems, such as failure to
 * initialize a connection.
 */
#define CONNECTION_MAGIC 0x12f955f3

/** \brief Connection is closing.
 *
 * This non-state flag indicates that the connection is being closed.
 * This is usually sent in the event that there is data in the output
 * buffer for the connection.
 */
#define CONN_FLAG_CLOSING	0x80000000

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

/** \brief Install a bufferevent.
 *
 * This function is used to install a bufferevent on a connection.  It
 * is presumed that the bufferevent is already configured with its
 * underlying transport; this function just installs the callbacks and
 * ensures that it is enabled.
 *
 * \param[in,out]	conn	The connection.
 * \param[in,out]	bev	The bufferevent to install on the
 *				connection.
 *
 * \return	A true value if the bufferevent was successfully
 *		installed, false otherwise.
 */
int connection_install(connection_t *conn, struct bufferevent *bev);

/** \brief Send connection state.
 *
 * Send the connection state to the connection.
 *
 * \param[in]		conn	The connection.
 *
 * \return	A true value if successful, false otherwise.  On
 *		failure, the connection should be destroyed by the
 *		caller.
 */
int connection_send_state(connection_t *conn);

/** \brief Set connection state.
 *
 * Updates the connection state on the specified connection.  If
 * changes are made to the connection state, this will also call
 * connection_send_state() on the connection to alert the other end to
 * the state change.
 *
 * \param[in,out]	conn	The connection.
 * \param[in]		cst_flags
 *				Connection state flags to update.
 *				Ignored unless #CONN_STATE_FLAGS_SET
 *				is specified to \p flags.
 * \param[in]		cst_status
 *				Connection status to switch to.
 *				Ignored unless #CONN_STATE_STATUS is
 *				specified to \p flags.
 * \param[in]		flags	Flags to control which elements of the
 *				connection state are affected.
 *
 * \return	A true value if successful, false otherwise.  On
 *		failure, the connection should be destroyed by the
 *		caller.
 */
int connection_set_state(connection_t *conn, uint8_t cst_flags,
			 conn_status_t cst_status, uint32_t flags);

/** \brief Send an error report.
 *
 * If an error occurs, this function is responsible for reporting the
 * error to the remote side.  This function may take a third argument,
 * depending on the value of \p error.
 *
 * <TABLE>
 *   <TR>
 *     <TH>Error</TH>
 *     <TH>Arguments</TH>
 *   </TR>
 *   <TR>
 *     <TD>CONN_ERR_NO_ERROR</TD>
 *     <TD>No additional argument required.</TD>
 *   </TR>
 *   <TR>
 *     <TD>CONN_ERR_UNKNOWN_PROTOCOL</TD>
 *     <TD>Protocol number (uint8_t).</TD>
 *   </TR>
 * </TABLE>
 *
 * \param[in,out]	conn	The connection.  After making this
 *				call, the connection is destroyed; no
 *				further references to the connection
 *				should be made.
 * \param[in]		error	The error that occurred.
 */
void connection_report_error(connection_t *conn, conn_error_t error, ...);

/** \brief Process received connection state message.
 *
 * This is a protocol dispatch routine which is used to process
 * received connection state messages.
 *
 * \param[in]		msg	The received message to process.
 * \param[in,out]	conn	The connection the message came in
 *				on.
 *
 * \return	One of the #pbuf_result_t values.
 */
pbuf_result_t connection_process(protocol_buf_t *msg, connection_t *conn);

/** \brief Destroy connection.
 *
 * This function is called to destroy a connection.  The underlying
 * socket will be closed.
 *
 * \param[in,out]	conn	The connection to destroy.  No more
 *				references should be made to this
 *				object after this call.
 * \param[in]		immediate
 *				If set to a true value, indicates that
 *				the connection should be destroyed
 *				immediately, without waiting for any
 *				buffered data to be written.
 */
void connection_destroy(connection_t *conn, int immediate);

#endif /* _HUMBOLDT_CONNECTION_H */
