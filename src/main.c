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

/* Recognized short options */
static const char *opt_str = "c:d";

/* Recognized long options */
static const struct option opts[] = {
  {"config", required_argument, 0, 'c'},
  {"debug", no_argument, 0, 'd'},
  {0, 0, 0, 0}
};

static void
parse_args(int argc, char **argv)
{
  int c;

  while ((c = getopt_long(argc, argv, opt_str, opts, 0)) >= 0)
    switch (c) {
    case 'c':
      printf("Option -%c: Use configuration file \"%s\"\n", c, optarg);
      break;

    case 'd':
      printf("Option -%c: Debugging enabled\n", c);
      break;

    case '?':
      fprintf(stderr, "Bad option; usage:\n");
      exit(EXIT_FAILURE);
      break;

    default:
      fprintf(stderr, "Unimplemented option -%c\n", c);
      break;
    }

  /* Check for any unrecognized arguments */
  if (argv[optind]) {
    fprintf(stderr, "Extraneous trailing arguments; usage:\n");
    exit(EXIT_FAILURE);
  }
}

int
main(int argc, char **argv)
{
  printf("Hello, world!\n");

  parse_args(argc, argv);

  return 0;
}
