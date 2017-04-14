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
#include <event2/util.h>
#include <signal.h>
#include <string.h>
#include <uuid.h>

#include "include/alloc.h"
#include "include/endpoint.h"
#include "include/configuration.h"
#include "include/log.h"
#include "include/runtime.h"

static void
handle_sigint(evutil_socket_t signum, short event, runtime_t *runtime)
{
  log_emit(runtime->rt_config, LOG_NOTICE, "Received SIGINT; terminating");
  event_base_loopexit(runtime->rt_evbase, 0);
}

struct epcreator {
  runtime_t    *runtime;
  int		clients;
  int		peers;
  int		total;
};

static void
create_endpoint(ep_config_t *epconf, struct epcreator *counts)
{
  int tmp;

  /* Create the endpoint */
  tmp = endpoint_create(counts->runtime, epconf);

  /* Increment the correct counts */
  counts->total += tmp;
  switch (epconf->epc_type) {
  case ENDPOINT_CLIENT:
    counts->clients += tmp;
    break;

  case ENDPOINT_PEER:
    counts->peers += tmp;
    break;

  default:
    break;
  }
}

int
initialize_runtime(runtime_t *runtime, config_t *conf)
{
  struct epcreator creator = {runtime, 0, 0, 0};

  /* Initialize event logging */
  log_libevent_init(conf);

  /* Initialize the runtime */
  runtime->rt_config = conf;
  if (!(runtime->rt_evbase = event_base_new())) {
    log_emit(conf, LOG_ERR, "Failed to initialize Libevent: %s",
	     strerror(errno));
    return 0;
  } else
    log_emit(conf, LOG_INFO, "Libevent initialized with method %s",
	     event_base_get_method(runtime->rt_evbase));

  /* Initialize SSL */
  runtime->rt_ssl = ssl_ctx_init(conf);

  /* Initialize the endpoints and connections lists */
  link_head_init(&runtime->rt_endpoints);
  link_head_init(&runtime->rt_connections);

  /* Open all the endpoints */
  hash_iter(&conf->cf_endpoints, (db_iter_t)create_endpoint, &creator);

  log_emit(conf, LOG_INFO, "Opened %d client and %d peer endpoints (%d total)",
	   creator.clients, creator.peers, creator.total);

  /* Set up the SIGINT handler */
  if (!(runtime->rt_inthandle = evsignal_new(runtime->rt_evbase, SIGINT,
					     (event_callback_fn)handle_sigint,
					     runtime)))
    log_emit(conf, LOG_WARNING, "Failed to initialize SIGINT handler");
  else if (evsignal_add(runtime->rt_inthandle, 0))
    log_emit(conf, LOG_WARNING, "Failed to add SIGINT handler");

  /* Set the magic number last */
  runtime->rt_magic = RUNTIME_MAGIC;
  return 1;
}

int
run(runtime_t *runtime)
{
  char uuid_buf[37];

  uuid_unparse(runtime->rt_config->cf_uuid, uuid_buf);
  log_emit(runtime->rt_config, LOG_NOTICE,
	   "Starting humboldt with UUID %s", uuid_buf);

  return event_base_loop(runtime->rt_evbase, 0);
}
