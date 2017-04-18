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

#include <event2/buffer.h>	/* for struct evbuffer */
#include <stdint.h>		/* for uint*_t */
#include <stdlib.h>		/* for size_t */

#include "common.h"		/* for magic_t */
#include "connection.h"		/* for connection_t */

/** \brief Protocol buffer.
 *
 * Represents a protocol message read or written to a connection.
 */
typedef struct _protocol_buf_s protocol_buf_t;

/** \brief Protocol buffer position.
 *
 * Represents an object used to track the position within a protocol
 * buffer.
 */
typedef struct _pbuf_pos_s pbuf_pos_t;

/** \brief Protocol dispatch function return codes.
 *
 * This enumeration contains all the valid return values from a
 * protocol message processor.  Most protocol message processors will
 * return \c PBR_MSG_PROCESSED, but some may need to close the
 * connection; those MUST return \c PBR_CONNECTION_CLOSED to ensure
 * that no more messages are processed from the connection.
 */
typedef enum _pbuf_result_e {
  PBR_MSG_PROCESSED,		/**< Message processed normally */
  PBR_CONNECTION_CLOSE		/**< Message processed, connection closed */
} pbuf_result_t;

/** \brief Protocol values.
 *
 * This enumeration contains all the protocol numbers that Humboldt
 * knows about.
 */
typedef enum _protocol_e {
  PROTOCOL_CONNSTATE,		/**< Connection state messages */
  PROTOCOL_PING,		/**< Ping messages */
  PROTOCOL_TLS			/**< StartTLS messages */
} protocol_t;

/** \brief Protocol dispatch function.
 *
 * Protocol processors are registered by listing a function possessing
 * the signature of this type in a list, indexed by protocol number,
 * in the <CODE>protocol.c</CODE> file.
 *
 * \param[in]		msg	The received message to process.
 * \param[in,out]	conn	The connection the message came in
 *				on.
 *
 * \return	One of the #pbuf_result_t values.
 */
typedef pbuf_result_t (*pbuf_dispatch_t)(protocol_buf_t *msg,
					 connection_t *conn);

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

/** \brief Protocol header size.
 *
 * This macro contains the size of the carrier protocol header.
 */
#define PROTOCOL_HEADER_SIZE	4

/** \brief Protocol buffer position structure.
 *
 * This structure contains a description of a protocol buffer
 * position.
 */
struct _pbuf_pos_s {
  int32_t	pbp_pos;	/**< Position within the buffer */
};

/** \brief Initialize a protocol buffer position.
 *
 * Initialize a protocol buffer position to point at the beginning of
 * the buffer (after the carrier protocol header).  This is a static
 * initializer; to seek back to the beginning, or to seek to another
 * location within the buffer, use pbp_seek().
 */
#define PBUF_POS_INIT()	{0}

/** \brief Seek to a location within the buffer.
 *
 * This macro updates a protocol buffer position to a new offset
 * within the protocol buffer.
 *
 * \param[in,out]	pbp	The protocol buffer position.
 * \param[in]		pbuf	The corresponding protocol buffer.
 * \param[in]		off	The offset to seek to.  If negative,
 *				this will be interpreted relative to
 *				the end of the protocol buffer.  Note
 *				that no bounds checking is performed
 *				here; the functions that utilize a
 *				protocol buffer position apply bounds
 *				checking themselves.
 */
#define pbp_seek(pbp, pbuf, off)			\
  do {							\
    pbuf_pos_t *_pbp = (pbp);				\
    protocol_buf_t *_pbuf = (pbuf);			\
    int32_t _off = (off);				\
    if (_off < 0)					\
      _off += _pbuf->pb_count - PROTOCOL_HEADER_SIZE;	\
    _pbp->pbp_pos = _off;				\
  } while (0)

/** \brief Increment a protocol buffer position.
 *
 * Increment a protocol buffer position by a specified delta.
 *
 * \param[in,out]	pbp	The protocol buffer position.
 * \param[in]		incr	The amount to increment (or decrement,
 *				for negative values) the protocol
 *				buffer position.  Note that no bounds
 *				checking is performed here; the
 *				functions that utilize a protocol
 *				buffer position apply bounds checking
 *				themselves.
 */
#define pbp_incr(pbp, incr)	((pbp)->pbp_pos += (incr))

#define pbp_remaining(pbp, pbuf)				\
  ((pbuf)->pb_count - (pbp)->pbp_pos + PROTOCOL_HEADER_SIZE)

/** \brief Determine if position is at end.
 *
 * Checks to see if the position is at or beyond the end of the
 * protocol buffer.
 *
 * \param[in]		pbp	The protocol buffer position.
 * \param[in]		pbuf	The protocol buffer.
 *
 * \return	A true value if the position is at or beyond the end
 *		of \p pbuf, false otherwise.
 */
#define pbp_atend(pbp, pbuf)					\
  ((pbp)->pbp_pos + PROTOCOL_HEADER_SIZE >= (pbuf)->pb_count)

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

/** \brief Extract data from a buffer.
 *
 * Extracts the specified amount of data from a protocol buffer,
 * starting at a specified position.  The position will be incremented
 * appropriately.
 *
 * \param[in]		pbuf	The protocol buffer.
 * \param[in,out]	pos	The position within the buffer.
 * \param[out]		data	A buffer to store the extracted data
 *				in.
 * \param[in]		datalen	The amount of data to extract.
 *
 * \return	A true value if successful, false otherwise.
 */
int protocol_buf_extract(protocol_buf_t *pbuf, pbuf_pos_t *pos,
			 unsigned char *data, size_t datalen);

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

/** \brief Extract a byte from a buffer.
 *
 * Extracts a single byte from a buffer, from the specified position.
 * The position will be incremented appropriately.
 *
 * \param[in]		pbuf	The protocol buffer.
 * \param[in,out]	pos	The position within the buffer.
 * \param[out]		datum	A pointer in which to store the value.
 *
 * \return	A true value if successful, false otherwise.
 */
int protocol_buf_get_uint8(protocol_buf_t *pbuf, pbuf_pos_t *pos,
			   uint8_t *datum);

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

/** \brief Extract a 2-byte integer from a buffer.
 *
 * Extracts a 2-byte integer from a buffer, from the specified
 * position.  The position will be incremented appropriately.
 *
 * \param[in]		pbuf	The protocol buffer.
 * \param[in,out]	pos	The position within the buffer.
 * \param[out]		datum	A pointer in which to store the value.
 *
 * \return	A true value if successful, false otherwise.
 */
int protocol_buf_get_uint16(protocol_buf_t *pbuf, pbuf_pos_t *pos,
			    uint16_t *datum);

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

/** \brief Extract a 4-byte integer from a buffer.
 *
 * Extracts a 4-byte integer from a buffer, from the specified
 * position.  The position will be incremented appropriately.
 *
 * \param[in]		pbuf	The protocol buffer.
 * \param[in,out]	pos	The position within the buffer.
 * \param[out]		datum	A pointer in which to store the value.
 *
 * \return	A true value if successful, false otherwise.
 */
int protocol_buf_get_uint32(protocol_buf_t *pbuf, pbuf_pos_t *pos,
			    uint32_t *datum);

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

/** \brief Receive a protocol message.
 *
 * Receive a single protocol message from the buffer.
 *
 * \param[in,out]	in	An event buffer potentially containing
 *				a message to be received.
 * \param[out]		pbuf_p	A pointer to a pointer to a protocol
 *				buffer.  The protocol buffer allocated
 *				to contain the message will be
 *				returned through this parameter.  If
 *				no full message was in the buffer,
 *				this will be a \c NULL pointer.
 *
 * \return	A true value if successful, including if no complete
 *		message was found in the buffer; false otherwise.
 */
int protocol_buf_recv(struct evbuffer *in, protocol_buf_t **pbuf_p);

/** \brief Release the protocol buffer contents.
 *
 * Releases memory allocated for the contents of the protocol buffer.
 * The buffer contents may no longer be referenced after this call.
 * This function should be called only on protocol buffers that have
 * been statically allocated.
 *
 * \param[in,out]	pbuf	The protocol buffer.
 */
void protocol_buf_free(protocol_buf_t *pbuf);

/** \brief Release the protocol buffer.
 *
 * Releases memory allocated for a protocol buffer, including its
 * contents.  The buffer may no longer be referenced after this call.
 * This function should be called only on protocol buffers that have
 * been dynamically allocated by protocol_buf_recv().
 *
 * \param[in]		pbuf	The protocol buffer.
 */
void protocol_buf_release(protocol_buf_t *pbuf);

/** \brief Dispatch a protocol message.
 *
 * Dispatch a protocol message to the appropriate processor for that
 * protocol message.  Protocol processors are registered by listing a
 * function possessing the signature of the #pbuf_dispatch_t in a
 * list, indexed by protocol number, in the <CODE>protocol.c</CODE>
 * file.
 *
 * \param[in]		msg	The received message to process.
 * \param[in,out]	conn	The connection the message came in
 *				on.
 *
 * \return	One of the #pbuf_result_t values.
 */
pbuf_result_t protocol_buf_dispatch(protocol_buf_t *msg, connection_t *conn);

#endif /* _HUMBOLDT_PROTOCOL_H */
