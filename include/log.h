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

#ifndef _HUMBOLDT_LOG_H
#define _HUMBOLDT_LOG_H

#include <stdarg.h>		/* for va_list */

#include "configuration.h"	/* for config_t */

/** \brief Message buffer size.
 *
 * This macro provides a recommended buffer size for formatting log
 * messages.
 */
#define LOGMSG_BUF		4096

/** \brief Look up a facility name.
 *
 * Given the name of a syslog facility, this looks up and returns the
 * appropriate facility code to use with openlog().
 *
 * \param[in]		name	The facility name.
 *
 * \return	The integer for that facility, or \c -1 if no facility
 *              with that name exists.
 */
int log_facility(const char *name);

/** \brief Initialize logging.
 *
 * Initialize logging.  This initializes syslog() with the appropriate
 * program name and facility code defined in the configuration.
 *
 * \param[in]		conf	The configuration.
 */
void log_init(config_t *conf);

/** \brief Emit a log message.
 *
 * This emits a log message.  If log_init() has not been called, the
 * message will be emitted to standard output, or standard error if \p
 * priority is of level \c LOG_WARNING or higher.  Messages of \c
 * LOG_DEBUG will not be emitted in this case unless debugging is
 * enabled in the configuration.  If log_init() has been called, the
 * messages are unconditionally passed to syslog().
 *
 * \param[in]		conf	The configuration.
 * \param[in]		priority
 * 				The log priority, one of the values
 * 				accepted by syslog().  This must not
 *				be combined with a facility code.
 * \param[in]		fmt	A format string for the log message.
 */
void log_emit(config_t *conf, int priority, const char *fmt, ...);

/** \brief Emit a log message.
 *
 * This is a \c stdarg version of log_emit().
 *
 * \param[in]		conf	The configuration.
 * \param[in]		priority
 * 				The log priority, one of the values
 * 				accepted by syslog().  This must not
 *				be combined with a facility code.
 * \param[in]		fmt	A format string for the log message.
 * \param[in,out]	ap	The variable arguments pointer.
 */
void log_vemit(config_t *conf, int priority, const char *fmt, va_list ap);

/** \brief Reinitialize logging.
 *
 * Reinitialize logging.  This closes and re-opens syslog(), typically
 * as a result of the configured facility code being changed.
 *
 * \param[in]		conf	The configuration.
 */
void log_reinit(config_t *conf);

/** \brief Close logging.
 *
 * This closes syslog().  After this call, the only valid calls that
 * may be made are log_init() and log_emit(), which will now output
 * log messages to standard output or standard error as appropriate.
 *
 * \param[in]		conf	The configuration.
 */
void log_close(config_t *conf);

#endif /* _HUMBOLDT_LOG_H */
