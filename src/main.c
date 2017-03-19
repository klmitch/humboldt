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

#include "include/configuration.h"

/* Recognized short options */
static const char *opt_str = "c:dDhv";

/* Recognized long options */
static const struct option opts[] = {
  {"config", required_argument, 0, 'c'},
  {"debug", no_argument, 0, 'd'},
  {"no-debug", no_argument, 0, 'D'},
  {"help", no_argument, 0, 'h'},
  {"version", no_argument, 0, 'v'},
  {0, 0, 0, 0}
};

static void
usage(const char *prog, int exit_code)
{
  const char *tmp;
  FILE *stream = exit_code == EXIT_SUCCESS ? stdout : stderr;

  /* Find the program name */
  if ((tmp = strrchr(prog, '/')))
    prog = tmp + 1;

  /* Output a usage message */
  fprintf(stream, "Usage: %s [options]\n\n", prog);
  fprintf(stream, "Start the " PACKAGE_NAME ".\n\n");
  fprintf(stream, "Options:\n");
  fprintf(stream, "-h, --help              Show this help message and "
	  "exit.\n");
  fprintf(stream, "-c FILE, --config FILE  Location of the Humboldt "
	  "configuration file (default:\n");
  fprintf(stream, "                        " DEFAULT_CONFIG ")\n");
  fprintf(stream, "-d, --debug             Enable debugging output; "
	  "overrides configuration file.\n");
  fprintf(stream, "-D, --no-debug          Disable debugging output; "
	  "overrides configuration file.\n");
  fprintf(stream, "-v, --version           Output version information.\n");

  exit(exit_code);
}

static void
parse_args(int argc, char **argv, config_t *conf)
{
  int c;

  while ((c = getopt_long(argc, argv, opt_str, opts, 0)) >= 0)
    switch (c) {
    case 'c':
      /* Has the configuration already been set? */
      if (!(conf->cf_flags & CONFIG_FILE_DEFAULT)) {
	fprintf(stderr, "Configuration file has already been set to \"%s\"\n",
		conf->cf_config);
	usage(argv[0], EXIT_FAILURE);
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
	fprintf(stderr, "The \"-d\" and \"-D\" options are "
		"mutually exclusive.\n");
	usage(argv[0], EXIT_FAILURE);
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
	fprintf(stderr, "The \"-d\" and \"-D\" options are "
		"mutually exclusive.\n");
	usage(argv[0], EXIT_FAILURE);
      }

      /* Disable debugging, and prohibit override from the
       * configuration file.
       */
      conf->cf_flags |= CONFIG_DEBUG_FIXED;
      break;

    case 'h':
      /* Emit the usage message */
      usage(argv[0], EXIT_SUCCESS);
      break;

    case 'v':
      /* Emit the description and version */
      printf("%s\n", PACKAGE_STRING);
      exit(EXIT_SUCCESS);
      break;

    case '?':
      fprintf(stderr, "Bad option; usage:\n");
      usage(argv[0], EXIT_FAILURE);
      break;

    default:
      fprintf(stderr, "Unimplemented option -%c\n", c);
      break;
    }

  /* Check for any unrecognized arguments */
  if (argv[optind]) {
    fprintf(stderr, "Extraneous trailing arguments; usage:\n");
    usage(argv[0], EXIT_FAILURE);
  }
}

int
main(int argc, char **argv)
{
  config_t conf = CONFIG_INIT();

  parse_args(argc, argv, &conf);

  /* Output information about the configuration */
  printf("Configuration file: \"%s\"%s\n", conf.cf_config,
	 (conf.cf_flags & CONFIG_FILE_DEFAULT) ? " (default)" : "");
  printf("Debugging mode %s%s\n",
	 (conf.cf_flags & CONFIG_DEBUG) ? "ENABLED" : "DISABLED",
	 (conf.cf_flags & CONFIG_DEBUG_FIXED) ? " (no override)" : "");

  return 0;
}
