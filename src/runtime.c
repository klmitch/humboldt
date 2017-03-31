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
#include <string.h>

#include "include/configuration.h"
#include "include/log.h"
#include "include/runtime.h"

int
initialize_runtime(runtime_t *runtime, config_t *conf)
{
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

  /* Set the magic number last */
  runtime->rt_magic = RUNTIME_MAGIC;
  return 1;
}
