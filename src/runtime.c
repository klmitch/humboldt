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

int
initialize_runtime(runtime_t *runtime, config_t *conf)
{
  int i, tmp;
  int clients = 0, peers = 0, total = 0;

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

  /* Initialize the endpoints list */
  flexlist_init(&runtime->rt_endpoints, endpoint_t);

  /* Open all the endpoints */
  for (i = 0; i < flexlist_count(&conf->cf_endpoints); i++) {
    ep_config_t *epconf = (ep_config_t *)flexlist_item(&conf->cf_endpoints, i);

    tmp = endpoint_create(runtime, epconf);
    total += tmp;

    /* Increment the correct count */
    if (epconf->epc_type == ENDPOINT_CLIENT)
      peers += tmp;
    else if (epconf->epc_type == ENDPOINT_PEER)
      clients += tmp;
  }

  log_emit(conf, LOG_INFO, "Opened %d client and %d peer endpoints (%d total)",
	   clients, peers, total);

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
  return event_base_loop(runtime->rt_evbase, 0);
}
