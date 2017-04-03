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
#include <stdlib.h>
#include <string.h>

#include "include/common.h"
#include "include/connection.h"
#include "include/protocol.h"

#define BUFFER_CHUNK	32

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
protocol_buf_add_uint32(protocol_buf_t *pbuf, uint32_t datum)
{
  /* protocol_buf_hint() will validate pbuf, so no call to common_verify() */

  /* Make sure there's enough space */
  if (!protocol_buf_hint(pbuf, pbuf->pb_count + 4))
    return 0;

  /* Append the datum to the buffer */
  pbuf->pb_contents[pbuf->pb_count++] = (datum >> 24) & 0xff;
  pbuf->pb_contents[pbuf->pb_count++] = (datum >> 16) & 0xff;
  pbuf->pb_contents[pbuf->pb_count++] = (datum >>  8) & 0xff;
  pbuf->pb_contents[pbuf->pb_count++] = (datum      ) & 0xff;

  return 1;
}

int
protocol_buf_hint(protocol_buf_t *pbuf, uint16_t size_hint)
{
  uint8_t *tmp;

  common_verify(pbuf, PROTOCOL_BUF_MAGIC);

  /* Add 4 for the carrier protocol header */
  size_hint += 4;

  /* If we'd be shrinking the buffer, nothing to do */
  if (size_hint < pbuf->pb_capacity)
    return 1;

  /* OK, we need to grow; figure out what to grow _to_ */
  size_hint += size_hint % BUFFER_CHUNK;
  if (!(tmp = realloc(pbuf->pb_contents, size_hint)))
    return 0; /* out of memory, it would seem */

  /* Update the buffer */
  if (!pbuf->pb_count) /* buffer was completely empty before */
    pbuf->pb_count = 4;
  pbuf->pb_contents = tmp;
  pbuf->pb_capacity = size_hint;

  return 1;
}

int
protocol_buf_send(protocol_buf_t *pbuf, connection_t *conn)
{
  uint8_t tmp_hdr[4], *data;
  uint16_t count = 4;

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
