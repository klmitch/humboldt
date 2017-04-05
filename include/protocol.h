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

#ifndef _HUMBOLDT_PROTOCOL_H
#define _HUMBOLDT_PROTOCOL_H

#include <stdint.h>		/* for uint*_t */
#include <stdlib.h>		/* for size_t */

#include "common.h"		/* for magic_t */
#include "connection.h"		/* for connection_t */

/** \brief Protocol buffer.
 *
 * Represents a protocol message read or written to a connection.
 */
typedef struct _protocol_buf_s protocol_buf_t;

/** \brief Protocol buffer structure.
 *
 * This structure contains a description of a protocol message.
 */
struct _protocol_buf_s {
  magic_t	pb_magic;	/**< Magic number */
  uint8_t	pb_version:4;	/**< Carrier protocol version (0) */
  uint8_t	pb_flags:4;	/**< Carrier protocol flags */
  uint8_t	pb_protocol;	/**< Encapsulated protocol number */
  uint16_t	pb_count;	/**< Number of bytes in the buffer */
  uint16_t	pb_capacity;	/**< Total capacity of the buffer */
  uint8_t      *pb_contents;	/**< Contents of the buffer */
};

/** \brief Protocol buffer magic number.
 *
 * This is the magic number used for the protocol buffer structure.
 * It is used to guard against programming problems, such as failure
 * to initialize a protocol buffer.
 */
#define PROTOCOL_BUF_MAGIC 0x9011855c

/** \brief Initialize a protocol buffer.
 *
 * Initialize a protocol buffer.  This is a static initializer that
 * ensures that the protocol buffer is properly initialized.
 *
 * \param[in]		flags	The flags to set on the protocol
 *				message.
 * \param[in]		proto	The protocol number to specify.
 */
#define PROTOCOL_BUF_INIT(flags, proto)			\
  {PROTOCOL_BUF_MAGIC, 0, (flags), (proto), 0, 0, 0}

/** \brief Protocol message is a request.
 *
 * This flag indicates that the protocol message is a request.
 */
#define PROTOCOL_REQUEST	0x0

/** \brief Protocol message is a reply.
 *
 * This flag indicates that the protocol message is a reply.
 */
#define PROTOCOL_REPLY		0x8

/** \brief Protocol message is an error.
 *
 * This flag indicates that the protocol message indicates an error
 * condition.
 */
#define PROTOCOL_ERROR		0x4

/** \brief Append data to a buffer.
 *
 * Causes the specified data to be appended to the protocol buffer.
 *
 * \param[in,out]	pbuf	The protocol buffer.
 * \param[in]		data	The data to append.
 * \param[in]		datalen	The amount of data to append.
 *
 * \return	A true value if successful, false otherwise.
 */
int protocol_buf_append(protocol_buf_t *pbuf, unsigned char *data,
			size_t datalen);

/** \brief Append a byte to a buffer.
 *
 * Causes the specified byte to be appended to the protocol buffer.
 *
 * \param[in,out]	pbuf	The protocol buffer.
 * \param[in]		datum	The byte to be appended.
 *
 * \return	A true value if successful, false otherwise.
 */
int protocol_buf_add_uint8(protocol_buf_t *pbuf, uint8_t datum);

/** \brief Append a 2-byte integer to a buffer.
 *
 * Causes the specified integer to be appended to the protocol
 * buffer.  The integer will be appended in network byte order.
 *
 * \param[in,out]	pbuf	The protocol buffer.
 * \param[in]		datum	The integer to be appended.
 *
 * \return	A true value if successful, false otherwise.
 */
int protocol_buf_add_uint16(protocol_buf_t *pbuf, uint16_t datum);

/** \brief Append a 4-byte integer to a buffer.
 *
 * Causes the specified integer to be appended to the protocol
 * buffer.  The integer will be appended in network byte order.
 *
 * \param[in,out]	pbuf	The protocol buffer.
 * \param[in]		datum	The integer to be appended.
 *
 * \return	A true value if successful, false otherwise.
 */
int protocol_buf_add_uint32(protocol_buf_t *pbuf, uint32_t datum);

/** \brief Hint of the amount of data coming.
 *
 * This function allows the protocol buffer to be warned of how much
 * data is expected to be appended to the buffer (excluding the
 * carrier protocol header).  More data than this can be appended if
 * necessary, but the hint will allow the protocol buffer to be more
 * efficient with memory allocation.
 *
 * \param[in,out]	pbuf	The protocol buffer.
 * \param[in]		size_hint
 *				The expected amount of data, not
 *				including the carrier protocol
 *				header.
 *
 * \return	A true value if successful, false otherwise.
 */
int protocol_buf_hint(protocol_buf_t *pbuf, uint16_t size_hint);

/** \brief Send the protocol message.
 *
 * Send the protocol buffer message.  The buffer contents are NOT
 * freed after this call.
 *
 * \param[in,out]	pbuf	The protocol buffer.
 * \param[in]		conn	The connection to send the protocol
 *				message to.
 *
 * \return	A true value if successful, false otherwise.
 */
int protocol_buf_send(protocol_buf_t *pbuf, connection_t *conn);

/** \brief Release the protocol buffer.
 *
 * Releases memory allocated for the protocol buffer.  The buffer
 * contents may no longer be referenced after this call.
 *
 * \param[in,out]	pbuf	The protocol buffer.
 */
void protocol_buf_free(protocol_buf_t *pbuf);

#endif /* _HUMBOLDT_PROTOCOL_H */
