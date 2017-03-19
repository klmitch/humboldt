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

#include "include/configuration.h"
#include "include/log.h"

int
main(int argc, char **argv)
{
  config_t conf = CONFIG_INIT();

  initialize_config(&conf, argc, argv);

  /* Output information about the configuration */
  log_emit(&conf, LOG_DEBUG, "Configuration file: \"%s\"%s\n", conf.cf_config,
	   (conf.cf_flags & CONFIG_FILE_DEFAULT) ? " (default)" : "");
  log_emit(&conf, LOG_DEBUG, "Debugging mode %s%s\n",
	   (conf.cf_flags & CONFIG_DEBUG) ? "ENABLED" : "DISABLED",
	   (conf.cf_flags & CONFIG_DEBUG_FIXED) ? " (no override)" : "");
  log_emit(&conf, LOG_DEBUG, "Log facility %d%s\n", conf.cf_facility >> 3,
	   (conf.cf_flags & CONFIG_FACILITY_FIXED) ? " (no override)" : "");

  return 0;
}
