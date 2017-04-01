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

#ifndef _HUMBOLDT_RUNTIME_H
#define _HUMBOLDT_RUNTIME_H

#include "alloc.h"		/* for flexlist_t */
#include "common.h"		/* for magic_t */
#include "configuration.h"	/* for config_t */

/** \brief Runtime data.
 *
 * The Humboldt runtime.  This structure contains such things as the
 * routing table, active ports, etc.; basically, everything needed for
 * running Humboldt.
 */
typedef struct _runtime_s runtime_t;

/** \brief Runtime structure.
 *
 * This structure contains the definition of the runtime.
 */
struct _runtime_s {
  magic_t		rt_magic;	/**< Magic number */
  config_t	       *rt_config;	/**< Configuration */
  struct event_base    *rt_evbase;	/**< Libevent event loop */
  flexlist_t		rt_endpoints;	/**< Open endpoints */
  struct event	       *rt_inthandle;	/**< SIGINT handler */
};

/** \brief Runtime magic number.
 *
 * This is the magic number used for the runtime structure.  It is
 * used to guard against programming problems, such as passing an
 * incorrect runtime.
 */
#define RUNTIME_MAGIC 0xb18935f8

/** \brief Initialize the runtime.
 *
 * This function initializes a passed-in runtime structure in
 * preparation for starting Humboldt.  This functionality will include
 * such things as daemonizing the process and initializing logging, as
 * well as creating a Libevent <CODE>struct event_base</CODE> object.
 * The function does not enter Libevent's loop.
 *
 * \param[in,out]	runtime	The runtime to initialize.
 * \param[in]		conf	The configuration.
 *
 * \return	A false value if an error occurred, true otherwise.
 */
int initialize_runtime(runtime_t *runtime, config_t *conf);

#endif /* _HUMBOLDT_RUNTIME_H */
