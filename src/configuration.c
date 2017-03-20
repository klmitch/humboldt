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

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <yaml.h>

#include "include/configuration.h"
#include "include/log.h"
#include "include/yaml_util.h"

/* Recognized short options */
static const char *opt_str = "c:dDf:hv";

/* Recognized long options */
static const struct option opts[] = {
  {"config", required_argument, 0, 'c'},
  {"debug", no_argument, 0, 'd'},
  {"no-debug", no_argument, 0, 'D'},
  {"facility", required_argument, 0, 'f'},
  {"help", no_argument, 0, 'h'},
  {"version", no_argument, 0, 'v'},
  {0, 0, 0, 0}
};

static void
usage(const char *prog, int exit_code)
{
  FILE *stream = exit_code == EXIT_SUCCESS ? stdout : stderr;

  /* Output a usage message */
  fprintf(stream, "Usage: %s [options]\n\n", prog);
  fprintf(stream, "Start the " PACKAGE_NAME ".\n\n");
  fprintf(stream, "Options:\n");
  fprintf(stream, "-c FILE, --config FILE  Location of the Humboldt "
	  "configuration file (default:\n");
  fprintf(stream, "                        " DEFAULT_CONFIG ")\n");
  fprintf(stream, "-d, --debug             Enable debugging output; "
	  "overrides configuration file.\n");
  fprintf(stream, "-D, --no-debug          Disable debugging output; "
	  "overrides configuration file.\n");
  fprintf(stream, "-f FACILITY, --facility FACILITY\n");
  fprintf(stream, "                        Log to the specified syslog "
	  "facility.\n");
  fprintf(stream, "-h, --help              Show this help message and "
	  "exit.\n");
  fprintf(stream, "-v, --version           Output version information.\n");

  exit(exit_code);
}

static void
parse_args(config_t *conf, int argc, char **argv)
{
  int c;

  while ((c = getopt_long(argc, argv, opt_str, opts, 0)) >= 0)
    switch (c) {
    case 'c':
      /* Has the configuration already been set? */
      if (!(conf->cf_flags & CONFIG_FILE_DEFAULT)) {
	fprintf(stderr, "%s: Configuration file has already been set to "
		"\"%s\"\n", conf->cf_prog, conf->cf_config);
	usage(conf->cf_prog, EXIT_FAILURE);
      }

      /* Save the configuration file */
      conf->cf_config = optarg;  /* can't be unallocated */
      conf->cf_flags &= ~CONFIG_FILE_DEFAULT;
      break;

    case 'd':
      /* -d and -D are mutually exclusive; can detect from
       * CONFIG_DEBUG_FIXED.
       */
      if ((conf->cf_flags & (CONFIG_DEBUG | CONFIG_DEBUG_FIXED)) ==
	  CONFIG_DEBUG_FIXED) {
	fprintf(stderr, "%s: The \"-d\" and \"-D\" options are "
		"mutually exclusive.\n", conf->cf_prog);
	usage(conf->cf_prog, EXIT_FAILURE);
      }

      /* Enable debugging, and prohibit override from the
       * configuration file.
       */
      conf->cf_flags |= CONFIG_DEBUG | CONFIG_DEBUG_FIXED;
      break;

    case 'D':
      /* -d and -D are mutually exclusive; can detect from
       * CONFIG_DEBUG_FIXED.
       */
      if ((conf->cf_flags & (CONFIG_DEBUG | CONFIG_DEBUG_FIXED)) ==
	  (CONFIG_DEBUG | CONFIG_DEBUG_FIXED)) {
	fprintf(stderr, "%s: The \"-d\" and \"-D\" options are "
		"mutually exclusive.\n", conf->cf_prog);
	usage(conf->cf_prog, EXIT_FAILURE);
      }

      /* Disable debugging, and prohibit override from the
       * configuration file.
       */
      conf->cf_flags |= CONFIG_DEBUG_FIXED;
      break;

    case 'f':
      /* Don't allow -f to be used multiple times */
      if (conf->cf_flags & CONFIG_FACILITY_FIXED) {
	fprintf(stderr, "%s: The facility has already been set\n",
		conf->cf_prog);
	usage(conf->cf_prog, EXIT_FAILURE);
      }

      /* Look up the facility */
      if ((conf->cf_facility = log_facility(optarg)) < 0) {
	fprintf(stderr, "%s: Unknown syslog facility \"%s\"\n",
		conf->cf_prog, optarg);
	exit(EXIT_FAILURE);
      }
      conf->cf_flags |= CONFIG_FACILITY_FIXED;
      break;

    case 'h':
      /* Emit the usage message */
      usage(conf->cf_prog, EXIT_SUCCESS);
      break;

    case 'v':
      /* Emit the description and version */
      printf("%s\n", PACKAGE_STRING);
      exit(EXIT_SUCCESS);
      break;

    case '?':
      usage(conf->cf_prog, EXIT_FAILURE);
      break;

    default:
      fprintf(stderr, "%s: Programming error: Unimplemented option -%c\n",
	      conf->cf_prog, c);
      abort();
      break;
    }

  /* Check for any unrecognized arguments */
  if (argv[optind]) {
    fprintf(stderr, "%s: Extraneous trailing arguments\n", conf->cf_prog);
    usage(conf->cf_prog, EXIT_FAILURE);
  }
}

static void
proc_debug(const char *key, config_t *conf, yaml_ctx_t *ctx,
	   yaml_node_t *value)
{
  int debug;

  /* Convert the value as boolean */
  if (yaml_get_bool(ctx, value, &debug) &&
      !(conf->cf_flags & CONFIG_DEBUG_FIXED))
    switch (debug) {
    case 1:
      conf->cf_flags |= CONFIG_DEBUG;
      break;

    case 0:
      conf->cf_flags &= ~CONFIG_DEBUG;
      break;

    default:
      break;
    }
}

static void
proc_facility(const char *key, config_t *conf, yaml_ctx_t *ctx,
              yaml_node_t *value)
{
  const char *name;
  int facility;

  /* Convert the value as a string */
  if (yaml_get_str(ctx, value, &name, 0)) {
    if ((facility = log_facility(name)) < 0)
      yaml_ctx_report(ctx, &value->start_mark, LOG_WARNING,
			"Unrecognized facility name \"%s\"", name);
    else if (!(conf->cf_flags & CONFIG_FACILITY_FIXED))
      conf->cf_facility = facility;
  }
}

static mapkeys_t top_level[] = {
  MAPKEY("debug", proc_debug),
  MAPKEY("facility", proc_facility)
};

void
initialize_config(config_t *conf, int argc, char **argv)
{
  const char *tmp;

  /* Begin by filling in the program name */
  if ((tmp = strrchr(argv[0], '/')))
    conf->cf_prog = tmp + 1;
  else
    conf->cf_prog = argv[0];

  /* Next, parse command line arguments */
  parse_args(conf, argc, argv);
}
