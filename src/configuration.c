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
#include <getopt.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <yaml.h>

#include "include/configuration.h"
#include "include/log.h"

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

void
config_ctx_path_push_key(config_ctx_t *ctx, const char *path)
{
  int n;

  if (ctx->cc_pathlen >= PATH_BUF)
    return; /* Can't add it to the buffer */

  /* Add the path element */
  if ((n = snprintf(ctx->cc_path + ctx->cc_pathlen, PATH_BUF - ctx->cc_pathlen,
		    "/%s", path)) > PATH_BUF - ctx->cc_pathlen) {
    ctx->cc_pathlen = PATH_BUF;
    ctx->cc_path[PATH_BUF - 1] = '\0';
  } else
    ctx->cc_pathlen += n;
}

void
config_ctx_path_push_idx(config_ctx_t *ctx, int idx)
{
  int n;

  if (ctx->cc_pathlen >= PATH_BUF)
    return; /* Can't add it to the buffer */

  /* Add the sequence index */
  if ((n = snprintf(ctx->cc_path + ctx->cc_pathlen, PATH_BUF - ctx->cc_pathlen,
		    "/[%d]", idx)) > PATH_BUF - ctx->cc_pathlen) {
    ctx->cc_pathlen = PATH_BUF;
    ctx->cc_path[PATH_BUF - 1] = '\0';
  } else
    ctx->cc_pathlen += n;
}

void
config_ctx_path_pop(config_ctx_t *ctx)
{
  /* Count back until we get to the beginning or to a '/' */
  while (ctx->cc_pathlen > 0 && ctx->cc_path[ctx->cc_pathlen] != '/')
    ctx->cc_pathlen--;

  /* Terminate the string */
  ctx->cc_path[ctx->cc_pathlen] = '\0';
}

void
config_ctx_report(config_ctx_t *ctx, yaml_mark_t *loc, int priority,
		  const char *fmt, ...)
{
  va_list ap;
  char msgbuf[LOGMSG_BUF];
  int n;

  /* Begin by formatting the context */
  n = snprintf(msgbuf, sizeof(msgbuf), "%s[%d]:%s", ctx->cc_filename,
	       ctx->cc_docnum, ctx->cc_path);

  /* Add the location, if one was provided */
  if (loc && n < sizeof(msgbuf))
    n += snprintf(msgbuf + n, sizeof(msgbuf) - n, " (line %d)",
		  (int)loc->line);

  /* Format the message */
  if (n < sizeof(msgbuf))
    msgbuf[n++] = ':';
  if (n < sizeof(msgbuf))
    msgbuf[n++] = ' ';
  if (n < sizeof(msgbuf)) {
    va_start(ap, fmt);
    n += vsnprintf(msgbuf + n, sizeof(msgbuf) - n, fmt, ap);
    va_end(ap);
  }

  /* Make sure the buffer is terminated */
  if (n >= sizeof(msgbuf))
    msgbuf[sizeof(msgbuf) - 1] = '\0';

  log_emit(ctx->cc_conf, priority, "%s", msgbuf);
}

static void
process_mapping_key(mapkeys_t *keys, size_t keycnt,
		    const char *key, void *dest,
		    config_ctx_t *ctx, yaml_node_t *value,
		    yaml_mark_t *key_mark)
{
  int lo = 0, hi = keycnt, mid, result;

  /* Implement a binary search */
  for (mid = hi / 2; lo < hi; mid = lo + (hi - lo) / 2) {
    /* Have we found a match? */
    if ((result = strcmp(key, keys[mid].mk_key)) == 0) {
      keys[mid].mk_proc(key, dest, ctx, value);
      return;
    }

    /* Is it to the left or right? */
    if (result < 0)
      hi = mid;
    else
      lo = mid + 1;
  }

  config_ctx_report(ctx, key_mark, LOG_WARNING,
		    "Ignoring unknown key \"%s\"", key);
}

static const char *_node_types[] = {
  "empty",
  "scalar",
  "sequence",
  "mapping"
};

static const char *
node_type(yaml_node_t *node)
{
  if (node->type <= YAML_MAPPING_NODE)
    return _node_types[node->type];

  return "unknown";
}

void
config_proc_sequence(config_ctx_t *ctx, yaml_node_t *seq,
		     itemproc_t proc, void *dest)
{
  yaml_node_t *item;
  yaml_node_item_t *cursor;

  /* Make sure it's what we expect */
  if (seq->type != YAML_SEQUENCE_NODE) {
    config_ctx_report(ctx, &seq->start_mark, LOG_WARNING,
		      "Expected sequence node, found %s node", node_type(seq));
    return;
  } else if (strcmp((const char *)seq->tag, YAML_SEQ_TAG)) {
    config_ctx_report(ctx, &seq->start_mark, LOG_WARNING,
		      "Expected node with tag \"" YAML_SEQ_TAG
		      "\", got tag \"%s\"", seq->tag);
    return;
  }

  /* Walk the items and call proc */
  for (cursor = seq->data.sequence.items.start;
       cursor <= seq->data.sequence.items.top; cursor++) {
    item = yaml_document_get_node(ctx->cc_document, *cursor);
    proc(cursor - seq->data.sequence.items.start, dest, ctx, item);
  }
}

void
config_proc_mapping(config_ctx_t *ctx, yaml_node_t *map,
		    mapkeys_t *keys, size_t keycnt, void *dest)
{
  yaml_node_t *key, *value;
  yaml_node_pair_t *cursor;

  /* Make sure it's what we expect */
  if (map->type != YAML_MAPPING_NODE) {
    config_ctx_report(ctx, &map->start_mark, LOG_WARNING,
		      "Expected mapping node, found %s node", node_type(map));
    return;
  } else if (strcmp((const char *)map->tag, YAML_MAP_TAG)) {
    config_ctx_report(ctx, &map->start_mark, LOG_WARNING,
		      "Expected node with tag \"" YAML_MAP_TAG
		      "\", got tag \"%s\"", map->tag);
    return;
  }

  /* Walk the pairs and call the appropriate proc */
  for (cursor = map->data.mapping.pairs.start;
       cursor <= map->data.mapping.pairs.top; cursor++) {
    /* Get the key node and make sure it makes sense */
    key = yaml_document_get_node(ctx->cc_document, cursor->key);
    if (key->type != YAML_SCALAR_NODE) {
      config_ctx_report(ctx, &key->start_mark, LOG_WARNING,
			"Expected scalar key node, found %s node",
			node_type(key));
      continue;
    } else if (strcmp((const char *)key->tag, YAML_STR_TAG)) {
      config_ctx_report(ctx, &key->start_mark, LOG_WARNING,
			"Expected key node with tag \"" YAML_STR_TAG
			"\", got tag \"%s\"", key->tag);
      continue;
    }

    /* Now get the value node */
    value = yaml_document_get_node(ctx->cc_document, cursor->value);

    /* Look up and invoke the processor */
    process_mapping_key(keys, keycnt, (const char *)key->data.scalar.value,
			dest, ctx, value, &key->start_mark);
  }
}

struct boolean_s {
  const char *text;
  int value;
};
#define BOOLEAN_SIZE(list)	(sizeof((list)) / sizeof(struct boolean_s))

static struct boolean_s booleans[] = {
  {"false", 0},
  {"n", 0},
  {"no", 0},
  {"off", 0},
  {"on", 1},
  {"true", 1},
  {"y", 1},
  {"yes", 1}
};

int
config_get_bool(config_ctx_t *ctx, yaml_node_t *node, int *dest)
{
  int lo = 0, hi = BOOLEAN_SIZE(booleans), mid, result;

  /* Sanity-check the node */
  if (node->type != YAML_SCALAR_NODE) {
    config_ctx_report(ctx, &node->start_mark, LOG_WARNING,
		      "Expected scalar node, found %s node", node_type(node));
    return 0;
  } else if (strcmp((const char *)node->tag, YAML_BOOL_TAG)) {
    config_ctx_report(ctx, &node->start_mark, LOG_WARNING,
		      "Expected node with tag \"" YAML_BOOL_TAG
		      "\", got tag \"%s\"", node->tag);
    return 0;
  }

  for (mid = hi / 2; lo < hi; mid = lo + (hi - lo) / 2) {
    /* Have we found a match? */
    if ((result = strcasecmp((const char *)node->data.scalar.value,
			     booleans[mid].text))) {
      *dest = booleans[mid].value;
      return 1;
    }

    /* Is it to the left or right? */
    if (result < 0)
      hi = mid;
    else
      lo = mid + 1;
  }

  /* Incomprehensible value */
  config_ctx_report(ctx, &node->start_mark, LOG_WARNING,
		    "Invalid boolean value \"%s\"", node->data.scalar.value);
  return 0;
}

int
config_get_int(config_ctx_t *ctx, yaml_node_t *node, long *dest)
{
  long tmp;
  char *end;

  /* Sanity-check the node */
  if (node->type != YAML_SCALAR_NODE) {
    config_ctx_report(ctx, &node->start_mark, LOG_WARNING,
		      "Expected scalar node, found %s node", node_type(node));
    return 0;
  } else if (strcmp((const char *)node->tag, YAML_INT_TAG)) {
    config_ctx_report(ctx, &node->start_mark, LOG_WARNING,
		      "Expected node with tag \"" YAML_INT_TAG
		      "\", got tag \"%s\"", node->tag);
    return 0;
  }

  errno = 0; /* reset errno value */
  tmp = strtol((const char *)node->data.scalar.value, &end, 0);

  if (*end != '\0') {
    config_ctx_report(ctx, &node->start_mark, LOG_WARNING,
		      "Invalid integer \"%s\"", node->data.scalar.value);
    return 0;
  } else if ((tmp == LONG_MIN || tmp == LONG_MAX) && errno == ERANGE) {
    config_ctx_report(ctx, &node->start_mark, LOG_WARNING,
		      "Integer %sflow", tmp < 0 ? "under" : "over");
    return 0;
  }

  *dest = tmp;
  return 1;
}

int
config_get_str(config_ctx_t *ctx, yaml_node_t *node, const char **dest,
	       int allow_null)
{
  /* Sanity-check the node */
  if (node->type != YAML_SCALAR_NODE) {
    config_ctx_report(ctx, &node->start_mark, LOG_WARNING,
		      "Expected scalar node, found %s node", node_type(node));
    return 0;
  } else if (allow_null && !strcmp((const char *)node->tag, YAML_NULL_TAG)) {
    *dest = 0;
    return 1;
  } else if (strcmp((const char *)node->tag, YAML_STR_TAG)) {
    config_ctx_report(ctx, &node->start_mark, LOG_WARNING,
		      "Expected node with tag \"" YAML_STR_TAG
		      "\", got tag \"%s\"", node->tag);
    return 0;
  }

  *dest = (const char *)node->data.scalar.value;
  return 1;
}

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
