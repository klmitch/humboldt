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
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>

#include "include/configuration.h"
#include "include/log.h"

/* Mapping of facility name to facility value */
struct facility_s {
  const char *f_name;
  int f_val;
};
#define CODE_SIZE(list)		(sizeof((list)) / sizeof(struct facility_s))

/* Note: this list must be in the same collation as used by strcmp(),
 * as it will be searched using a binary search.
 */
static struct facility_s facilities[] = {
#ifdef LOG_AUTH
  {"auth", LOG_AUTH},
#endif
#ifdef LOG_AUTHPRIV
  {"authpriv", LOG_AUTHPRIV},
#endif
#ifdef LOG_CRON
  {"cron", LOG_CRON},
#endif
#ifdef LOG_DAEMON
  {"daemon", LOG_DAEMON},
#endif
#ifdef LOG_FTP
  {"ftp", LOG_FTP},
#endif
#ifdef LOG_KERN
  {"kern", LOG_KERN},
#endif
#ifdef LOG_LOCAL0
  {"local0", LOG_LOCAL0},
#endif
#ifdef LOG_LOCAL1
  {"local1", LOG_LOCAL1},
#endif
#ifdef LOG_LOCAL2
  {"local2", LOG_LOCAL2},
#endif
#ifdef LOG_LOCAL3
  {"local3", LOG_LOCAL3},
#endif
#ifdef LOG_LOCAL4
  {"local4", LOG_LOCAL4},
#endif
#ifdef LOG_LOCAL5
  {"local5", LOG_LOCAL5},
#endif
#ifdef LOG_LOCAL6
  {"local6", LOG_LOCAL6},
#endif
#ifdef LOG_LOCAL7
  {"local7", LOG_LOCAL7},
#endif
#ifdef LOG_LPR
  {"lpr", LOG_LPR},
#endif
#ifdef LOG_MAIL
  {"mail", LOG_MAIL},
#endif
#ifdef LOG_NEWS
  {"news", LOG_NEWS},
#endif
#ifdef LOG_SYSLOG
  {"syslog", LOG_SYSLOG},
#endif
#ifdef LOG_USER
  {"user", LOG_USER},
#endif
#ifdef LOG_UUCP
  {"uucp", LOG_UUCP}
#endif
};

int
log_facility(const char *name)
{
  int lo = 0, hi = CODE_SIZE(facilities), mid, result;

  /* Implement a binary search */
  for (mid = hi / 2; lo < hi; mid = lo + (hi - lo) / 2) {
    /* Found a match! */
    if ((result = strcmp(name, facilities[mid].f_name)) == 0)
      return facilities[mid].f_val;

    /* Is it to the left or right? */
    if (result < 0)
      hi = mid;
    else
      lo = mid + 1;
  }

  return -1;
}

void
log_init(config_t *conf)
{
  assert(!(conf->cf_flags & CONFIG_LOG_INITIALIZED));

  /* Call openlog */
  openlog(conf->cf_prog, LOG_PID, conf->cf_facility);

  /* Record that the log is open */
  conf->cf_flags |= CONFIG_LOG_INITIALIZED;
}

void
log_vemit(config_t *conf, int priority, const char *fmt, va_list ap)
{
  FILE *stream;

  /* Has the log been initialized? */
  if (conf->cf_flags & CONFIG_LOG_INITIALIZED) {
#if HAVE_VSYSLOG
    vsyslog(priority, fmt, ap);
#else
    /* No vsyslog() function, so render to a temporary buffer */
    char msg_buf[LOGMSG_BUF];

    vsnprintf(msg_buf, sizeof(msg_buf), fmt, ap);
    msg_buf[sizeof(msg_buf) - 1] = '\0';
    syslog(priority, "%s", msg_buf);
#endif

    return;
  }

  /* Are we to output this message? */
  if (!(conf->cf_flags & CONFIG_DEBUG) && priority > LOG_INFO)
    return;

  /* Select the correct output stream */
  stream = priority <= LOG_WARNING ? stderr : stdout;

  /* Emit the log message */
  vfprintf(stream, fmt, ap);
  fputc('\n', stream);
  fflush(stream);
}

void log_emit(config_t *conf, int priority, const char *fmt, ...)
{
  va_list ap;

  /* Call log_vemit() */
  va_start(ap, fmt);
  log_vemit(conf, priority, fmt, ap);
  va_end(ap);
}

void
log_reinit(config_t *conf)
{
  assert(conf->cf_flags & CONFIG_LOG_INITIALIZED);

  /* Close the syslog */
  closelog();

  /* Re-open it */
  openlog(conf->cf_prog, LOG_PID, conf->cf_facility);
}

void
log_close(config_t *conf)
{
  assert(conf->cf_flags & CONFIG_LOG_INITIALIZED);

  /* Close the syslog */
  closelog();

  /* Reset the initialization state. */
  conf->cf_flags &= ~CONFIG_LOG_INITIALIZED;
}
