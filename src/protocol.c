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

#include <assert.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <stdlib.h>
#include <string.h>

#include "include/alloc.h"
#include "include/common.h"
#include "include/connection.h"
#include "include/log.h"
#include "include/protocol.h"
#include "include/ssl.h"

static pbuf_result_t ping_process(protocol_buf_t *msg, connection_t *conn);

static pbuf_dispatch_t processors[] = {
  connection_process,		/* Protocol 0: Connection state */
  ping_process,			/* Protocol 1: PING/PONG */
  ssl_process			/* Protocol 2: SSL */
};

static freelist_t messages = FREELIST_INIT(protocol_buf_t, 0);

#define BUFFER_CHUNK	32

#define bounds_check(pbuf, pbp, count)					\
  do {									\
    protocol_buf_t *_pbuf = (pbuf);					\
    pbuf_pos_t *_pbp = (pbp);						\
    common_verify(_pbuf, PROTOCOL_BUF_MAGIC);				\
    if (_pbp->pbp_pos < 0 ||						\
	_pbp->pbp_pos + (count) - PROTOCOL_HEADER_SIZE < _pbuf->pb_count) \
      return 0;								\
  } while (0)

#define pos_to_off(pbp)	((pos)->pbp_pos + PROTOCOL_HEADER_SIZE)

int
protocol_buf_append(protocol_buf_t *pbuf, unsigned char *data, size_t datalen)
{
  /* protocol_buf_hint() will validate pbuf, so no call to common_verify() */

  /* Make sure there's enough space */
  if (!protocol_buf_hint(pbuf, pbuf->pb_count + datalen))
    return 0;

  /* Append the data to the buffer */
  memcpy(pbuf->pb_contents + pbuf->pb_count, data, datalen);
  pbuf->pb_count += datalen;

  return 1;
}

int
protocol_buf_extract(protocol_buf_t *pbuf, pbuf_pos_t *pos,
		     unsigned char *data, size_t datalen)
{
  /* Check that we're valid and within bounds */
  bounds_check(pbuf, pos, datalen);

  /* Copy data out of the buffer */
  memcpy(data, pbuf->pb_contents + pos_to_off(pos), datalen);
  pbp_incr(pos, datalen);

  return 1;
}

int
protocol_buf_add_uint8(protocol_buf_t *pbuf, uint8_t datum)
{
  /* protocol_buf_hint() will validate pbuf, so no call to common_verify() */

  /* Make sure there's enough space */
  if (!protocol_buf_hint(pbuf, pbuf->pb_count + 1))
    return 0;

  /* Append the datum to the buffer */
  pbuf->pb_contents[pbuf->pb_count++] = datum;

  return 1;
}

int
protocol_buf_get_uint8(protocol_buf_t *pbuf, pbuf_pos_t *pos, uint8_t *datum)
{
  /* Check that we're valid and within bounds */
  bounds_check(pbuf, pos, 1);
  if (!datum)
    return 0;

  /* Copy data out of the buffer */
  *datum = *(pbuf->pb_contents + pos_to_off(pos));
  pbp_incr(pos, 1);

  return 1;
}

int
protocol_buf_add_uint16(protocol_buf_t *pbuf, uint16_t datum)
{
  /* protocol_buf_hint() will validate pbuf, so no call to common_verify() */

  /* Make sure there's enough space */
  if (!protocol_buf_hint(pbuf, pbuf->pb_count + 2))
    return 0;

  /* Append the datum to the buffer */
  pbuf->pb_contents[pbuf->pb_count++] = (datum >> 8) & 0xff;
  pbuf->pb_contents[pbuf->pb_count++] = (datum     ) & 0xff;

  return 1;
}

int
protocol_buf_get_uint16(protocol_buf_t *pbuf, pbuf_pos_t *pos, uint16_t *datum)
{
  /* Check that we're valid and within bounds */
  bounds_check(pbuf, pos, 2);
  if (!datum)
    return 0;

  /* Copy data out of the buffer */
  *datum =
    (*(pbuf->pb_contents + pos_to_off(pos)    ) << 8) |
    (*(pbuf->pb_contents + pos_to_off(pos) + 1)     );
  pbp_incr(pos, 2);

  return 1;
}

int
protocol_buf_add_uint32(protocol_buf_t *pbuf, uint32_t datum)
{
  /* protocol_buf_hint() will validate pbuf, so no call to common_verify() */

  /* Make sure there's enough space */
  if (!protocol_buf_hint(pbuf, pbuf->pb_count + PROTOCOL_HEADER_SIZE))
    return 0;

  /* Append the datum to the buffer */
  pbuf->pb_contents[pbuf->pb_count++] = (datum >> 24) & 0xff;
  pbuf->pb_contents[pbuf->pb_count++] = (datum >> 16) & 0xff;
  pbuf->pb_contents[pbuf->pb_count++] = (datum >>  8) & 0xff;
  pbuf->pb_contents[pbuf->pb_count++] = (datum      ) & 0xff;

  return 1;
}

int
protocol_buf_get_uint32(protocol_buf_t *pbuf, pbuf_pos_t *pos, uint32_t *datum)
{
  /* Check that we're valid and within bounds */
  bounds_check(pbuf, pos, 4);
  if (!datum)
    return 0;

  /* Copy data out of the buffer */
  *datum =
    (*(pbuf->pb_contents + pos_to_off(pos)    ) << 24) |
    (*(pbuf->pb_contents + pos_to_off(pos) + 1) << 16) |
    (*(pbuf->pb_contents + pos_to_off(pos) + 2) <<  8) |
    (*(pbuf->pb_contents + pos_to_off(pos) + 3)      );
  pbp_incr(pos, 4);

  return 1;
}

int
protocol_buf_hint(protocol_buf_t *pbuf, uint16_t size_hint)
{
  uint8_t *tmp;

  common_verify(pbuf, PROTOCOL_BUF_MAGIC);

  /* Add the carrier protocol header */
  size_hint += PROTOCOL_HEADER_SIZE;

  /* If we'd be shrinking the buffer, nothing to do */
  if (size_hint < pbuf->pb_capacity)
    return 1;

  /* OK, we need to grow; figure out what to grow _to_ */
  size_hint += size_hint % BUFFER_CHUNK;
  if (!(tmp = realloc(pbuf->pb_contents, size_hint)))
    return 0; /* out of memory, it would seem */

  /* Update the buffer */
  if (!pbuf->pb_count) /* buffer was completely empty before */
    pbuf->pb_count = PROTOCOL_HEADER_SIZE;
  pbuf->pb_contents = tmp;
  pbuf->pb_capacity = size_hint;

  return 1;
}

int
protocol_buf_send(protocol_buf_t *pbuf, connection_t *conn)
{
  uint8_t tmp_hdr[PROTOCOL_HEADER_SIZE], *data;
  uint16_t count = PROTOCOL_HEADER_SIZE;

  common_verify(pbuf, PROTOCOL_BUF_MAGIC);
  common_verify(conn, CONNECTION_MAGIC);

  /* Make sure there's data to send */
  if (!pbuf->pb_count)
    data = tmp_hdr;
  else {
    data = pbuf->pb_contents;
    count = pbuf->pb_count;
  }

  /* Format the header */
  data[0] = ((pbuf->pb_version & 0xf) << 4) | (pbuf->pb_flags & 0xf);
  data[1] = pbuf->pb_protocol & 0xff;
  data[2] = (count >> 8) & 0xff;
  data[3] = (count     ) & 0xff;

  /* Write the data to the connection and return */
  return bufferevent_write(conn->con_bev, data, count) ? 0 : 1;
}

int
protocol_buf_recv(struct evbuffer *in, protocol_buf_t **pbuf_p)
{
  protocol_buf_t *pbuf;
  uint8_t carrier[PROTOCOL_HEADER_SIZE];
  ev_ssize_t readcnt;
  uint8_t version;
  uint16_t count;

  assert(pbuf_p);

  /* Copy out the packet size */
  if ((readcnt = evbuffer_copyout(in, &carrier, sizeof(carrier))) <
      sizeof(carrier)) {
    *pbuf_p = 0;
    return 1;
  }

  /* Convert the carrier protocol version */
  version = (carrier[0] & 0xf0) >> 4;

  /* If we don't know it, panic now */
  if (version != 0)
    return 0;

  /* Convert the packet size */
  count = (carrier[2] << 8) | carrier[3];

  /* Do we have that much in the buffer? */
  if (count > evbuffer_get_length(in)) {
    *pbuf_p = 0;
    return 1;
  }

  /* Allocate a protocol buffer */
  if (!(pbuf = alloc(&messages)))
    return 0;

  /* Initialize the protocol buffer memory-related data */
  pbuf->pb_magic = PROTOCOL_BUF_MAGIC;
  pbuf->pb_count = 0;
  pbuf->pb_capacity = 0;
  pbuf->pb_contents = 0;

  /* Allocate space in the protocol buffer for the message */
  if (!protocol_buf_hint(pbuf, count - PROTOCOL_HEADER_SIZE)) {
    release(&messages, pbuf);
    return 0;
  }

  /* Remove the message from the receive buffer into the protocol buffer */
  if ((readcnt = evbuffer_remove(in, pbuf->pb_contents, count)) < count) {
    protocol_buf_free(pbuf);
    release(&messages, pbuf);
    return 0;
  }

  /* Extract the rest of the message information */
  pbuf->pb_version = version;
  pbuf->pb_flags = carrier[0] & 0x0f;
  pbuf->pb_protocol = carrier[1];
  pbuf->pb_count = count;

  /* Pass it back to the caller */
  *pbuf_p = pbuf;
  return 1;
}

void
protocol_buf_free(protocol_buf_t *pbuf)
{
  common_verify(pbuf, PROTOCOL_BUF_MAGIC);

  /* Release allocated memory */
  if (pbuf->pb_contents)
    free(pbuf->pb_contents);

  /* Zero all the tracking data */
  pbuf->pb_count = 0;
  pbuf->pb_capacity = 0;
  pbuf->pb_contents = 0;
}

void
protocol_buf_release(protocol_buf_t *pbuf)
{
  /* First, release the contents; protocol_buf_free() will validate for us */
  protocol_buf_free(pbuf);

  /* Now, release it back to the system */
  release(&messages, pbuf);
}

pbuf_result_t
protocol_buf_dispatch(protocol_buf_t *msg, connection_t *conn)
{
  common_verify(msg, PROTOCOL_BUF_MAGIC);
  common_verify(conn, CONNECTION_MAGIC);

  /* Check if we have a matching protocol */
  if (msg->pb_protocol < list_count(processors) &&
      processors[msg->pb_protocol])
    /* Process the message */
    return processors[msg->pb_protocol](msg, conn);

  /* Unrecognized protocol message... */
  connection_report_error(conn, CONN_ERR_UNKNOWN_PROTOCOL, msg->pb_protocol);

  return PBR_CONNECTION_CLOSE;
}

static pbuf_result_t
ping_process(protocol_buf_t *msg, connection_t *conn)
{
  char conn_desc[ADDR_DESCRIPTION];

  common_verify(msg, PROTOCOL_BUF_MAGIC);
  common_verify(conn, CONNECTION_MAGIC);

  /* Handle the message bits */
  if (msg->pb_flags & PROTOCOL_ERROR)
    return PBR_MSG_PROCESSED; /* Unused */
  else if (msg->pb_flags & PROTOCOL_REPLY)
    return PBR_MSG_PROCESSED; /* In future, we'll need to store the RTT */

  /* OK, it's a request; set the reply flag and send it back */
  msg->pb_flags |= PROTOCOL_REPLY;
  if (!protocol_buf_send(msg, conn)) {
    log_emit(conn->con_runtime->rt_config, LOG_NOTICE,
	     "Failed to send ping response packet for %s",
	     connection_describe(conn, conn_desc, sizeof(conn_desc)));
    return PBR_CONNECTION_CLOSE;
  }

  return PBR_MSG_PROCESSED;
}
