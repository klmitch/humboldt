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

#ifndef _HUMBOLDT_CONFIGURATION_H
#define _HUMBOLDT_CONFIGURATION_H

#include "common.h"	/* for magic_t */

/** \brief Configuration.
 *
 * The Humboldt configuration.  This contains configuration drawn from
 * command line arguments, as well as from the named configuration
 * file.
 */
typedef struct _config_s config_t;

/** \brief Configuration structure.
 *
 * This structure contains the definition of the configuration.
 */
struct _config_s {
  magic_t	cf_magic;	/**< Magic number */
  uint32_t	cf_flags;	/**< Configuration flags */
  const char   *cf_config;	/**< Name of the configuration file */
};

/** \brief Configuration magic number.
 *
 * This is the magic number used for the configuration structure.  It
 * is used to guard against programming problems, such passing an
 * incorrect configuration.
 */
#define CONFIG_MAGIC 0xa059d600

/** \brief Default configuration file location.
 *
 * This is the default location of the configuration file.
 */
#define DEFAULT_CONFIG SYSCONFDIR "/" PACKAGE_TARNAME "/config.yaml"

/** \brief Initialize a configuration structure.
 *
 * Initialize the configuration structure.  This is a static
 * initializer that ensures that the configuration is properly
 * initialized.
 */
#define CONFIG_INIT()							\
  {CONFIG_MAGIC, CONFIG_FILE_DEFAULT, DEFAULT_CONFIG}

/** \brief Debugging enabled.
 *
 * A configuration flag indicating that debugging output should be
 * emitted.
 */
#define CONFIG_DEBUG		0x80000000

/** \brief Debugging fixed.
 *
 * A configuration flag indicating that \c CONFIG_DEBUG got its
 * setting from the command line and cannot be overridden by the
 * configuration file.
 */
#define CONFIG_DEBUG_FIXED	0x40000000

/** \brief Configuration file is at its default.
 *
 * This flag is used solely to detect the case of the user passing the
 * "--config" option multiple times; it is cleared after processing
 * the first "--config" or "-c" option.
 */
#define CONFIG_FILE_DEFAULT	0x20000000

#endif /* _HUMBOLDT_CONFIGURATION_H */
