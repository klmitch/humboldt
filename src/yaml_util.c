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
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <yaml.h>

#include "include/common.h"
#include "include/configuration.h"
#include "include/log.h"
#include "include/yaml_util.h"

void
yaml_ctx_path_push_key(yaml_ctx_t *ctx, const char *path)
{
  int n;

  if (ctx->yc_pathlen >= PATH_BUF)
    return; /* Can't add it to the buffer */

  /* Add the path element */
  if ((n = snprintf(ctx->yc_path + ctx->yc_pathlen, PATH_BUF - ctx->yc_pathlen,
		    "/%s", path)) > PATH_BUF - ctx->yc_pathlen) {
    ctx->yc_pathlen = PATH_BUF;
    ctx->yc_path[PATH_BUF - 1] = '\0';
  } else
    ctx->yc_pathlen += n;
}

void
yaml_ctx_path_push_idx(yaml_ctx_t *ctx, int idx)
{
  int n;

  if (ctx->yc_pathlen >= PATH_BUF)
    return; /* Can't add it to the buffer */

  /* Add the sequence index */
  if ((n = snprintf(ctx->yc_path + ctx->yc_pathlen, PATH_BUF - ctx->yc_pathlen,
		    "/[%d]", idx)) > PATH_BUF - ctx->yc_pathlen) {
    ctx->yc_pathlen = PATH_BUF;
    ctx->yc_path[PATH_BUF - 1] = '\0';
  } else
    ctx->yc_pathlen += n;
}

void
yaml_ctx_path_pop(yaml_ctx_t *ctx)
{
  /* Count back until we get to the beginning or to a '/' */
  while (ctx->yc_pathlen > 0 && ctx->yc_path[ctx->yc_pathlen] != '/')
    ctx->yc_pathlen--;

  /* Terminate the string */
  ctx->yc_path[ctx->yc_pathlen] = '\0';
}

void
yaml_ctx_report(yaml_ctx_t *ctx, yaml_mark_t *loc, int priority,
		const char *fmt, ...)
{
  va_list ap;
  char msgbuf[LOGMSG_BUF];
  int n;

  /* Begin by formatting the context */
  n = snprintf(msgbuf, sizeof(msgbuf), "%s[%d]:%s", ctx->yc_filename,
	       ctx->yc_docnum, ctx->yc_path);

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

  log_emit(ctx->yc_conf, priority, "%s", msgbuf);
}

static void
process_mapping_key(mapkeys_t *keys, size_t keycnt,
		    const char *key, void *dest,
		    yaml_ctx_t *ctx, yaml_node_t *value,
		    yaml_mark_t *key_mark)
{
  int lo = 0, hi = keycnt, mid, result;

  /* Implement a binary search */
  for (mid = hi / 2; lo < hi; mid = lo + (hi - lo) / 2) {
    /* Have we found a match? */
    if (!(result = strcmp(key, keys[mid].mk_key))) {
      keys[mid].mk_proc(key, dest, ctx, value);
      return;
    }

    /* Is it to the left or right? */
    if (result < 0)
      hi = mid;
    else
      lo = mid + 1;
  }

  yaml_ctx_report(ctx, key_mark, LOG_WARNING,
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
yaml_proc_sequence(yaml_ctx_t *ctx, yaml_node_t *seq,
		   itemproc_t proc, void *dest)
{
  yaml_node_t *item;
  yaml_node_item_t *cursor;

  /* Make sure it's what we expect */
  if (seq->type != YAML_SEQUENCE_NODE) {
    yaml_ctx_report(ctx, &seq->start_mark, LOG_WARNING,
		    "Expected sequence node, found %s node", node_type(seq));
    return;
  } else if (strcmp((const char *)seq->tag, YAML_SEQ_TAG)) {
    yaml_ctx_report(ctx, &seq->start_mark, LOG_WARNING,
		    "Expected node with tag \"" YAML_SEQ_TAG
		    "\", got tag \"%s\"", seq->tag);
    return;
  }

  /* Walk the items and call proc */
  for (cursor = seq->data.sequence.items.start;
       cursor < seq->data.sequence.items.top; cursor++) {
    item = yaml_document_get_node(&ctx->yc_document, *cursor);
    proc(cursor - seq->data.sequence.items.start, dest, ctx, item);
  }
}

void
yaml_proc_mapping(yaml_ctx_t *ctx, yaml_node_t *map,
		    mapkeys_t *keys, size_t keycnt, void *dest)
{
  yaml_node_t *key, *value;
  yaml_node_pair_t *cursor;

  /* Make sure it's what we expect */
  if (map->type != YAML_MAPPING_NODE) {
    yaml_ctx_report(ctx, &map->start_mark, LOG_WARNING,
		    "Expected mapping node, found %s node", node_type(map));
    return;
  } else if (strcmp((const char *)map->tag, YAML_MAP_TAG)) {
    yaml_ctx_report(ctx, &map->start_mark, LOG_WARNING,
		    "Expected node with tag \"" YAML_MAP_TAG
		    "\", got tag \"%s\"", map->tag);
    return;
  }

  /* Walk the pairs and call the appropriate proc */
  for (cursor = map->data.mapping.pairs.start;
       cursor < map->data.mapping.pairs.top; cursor++) {
    /* Get the key node and make sure it makes sense */
    key = yaml_document_get_node(&ctx->yc_document, cursor->key);
    if (key->type != YAML_SCALAR_NODE) {
      yaml_ctx_report(ctx, &key->start_mark, LOG_WARNING,
		      "Expected scalar key node, found %s node",
		      node_type(key));
      continue;
    } else if (strcmp((const char *)key->tag, YAML_STR_TAG)) {
      yaml_ctx_report(ctx, &key->start_mark, LOG_WARNING,
		      "Expected key node with tag \"" YAML_STR_TAG
		      "\", got tag \"%s\"", key->tag);
      continue;
    }

    /* Now get the value node */
    value = yaml_document_get_node(&ctx->yc_document, cursor->value);

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
  {"FALSE", 0},
  {"False", 0},
  {"N", 0},
  {"NO", 0},
  {"No", 0},
  {"OFF", 0},
  {"ON", 1},
  {"Off", 0},
  {"On", 1},
  {"TRUE", 1},
  {"True", 1},
  {"Y", 1},
  {"YES", 1},
  {"Yes", 1},
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
yaml_get_bool(yaml_ctx_t *ctx, yaml_node_t *node, int *dest)
{
  int lo = 0, hi = BOOLEAN_SIZE(booleans), mid, result;

  /* Sanity-check the node */
  if (node->type != YAML_SCALAR_NODE) {
    yaml_ctx_report(ctx, &node->start_mark, LOG_WARNING,
		    "Expected scalar node, found %s node", node_type(node));
    return 0;

  /* The libyaml parser doesn't handle implicit tags, so if a boolean
   * node is not explicitly tagged as boolean, we provisionally allow
   * str tags with a plain style to be substituted.
   */
  } else if (strcmp((const char *)node->tag, YAML_BOOL_TAG) &&
	     (strcmp((const char *)node->tag, YAML_STR_TAG) ||
	      node->data.scalar.style != YAML_PLAIN_SCALAR_STYLE)) {
    yaml_ctx_report(ctx, &node->start_mark, LOG_WARNING,
		    "Expected node with tag \"" YAML_BOOL_TAG
		    "\", got tag \"%s\"", node->tag);
    return 0;
  }

  for (mid = hi / 2; lo < hi; mid = lo + (hi - lo) / 2) {
    /* Have we found a match? */
    if (!(result = strcmp((const char *)node->data.scalar.value,
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
  yaml_ctx_report(ctx, &node->start_mark, LOG_WARNING,
		  "Invalid boolean value \"%s\"", node->data.scalar.value);
  return 0;
}

int
yaml_get_int(yaml_ctx_t *ctx, yaml_node_t *node, long *dest)
{
  long tmp;
  char *end;

  /* Sanity-check the node */
  if (node->type != YAML_SCALAR_NODE) {
    yaml_ctx_report(ctx, &node->start_mark, LOG_WARNING,
		    "Expected scalar node, found %s node", node_type(node));
    return 0;

  /* The libyaml parser doesn't handle implicit tags, so if an integer
   * node is not explicitly tagged as integer, we provisionally allow
   * str tags with a plain style to be substituted.
   */
  } else if (strcmp((const char *)node->tag, YAML_INT_TAG) &&
	     (strcmp((const char *)node->tag, YAML_STR_TAG) ||
	      node->data.scalar.style != YAML_PLAIN_SCALAR_STYLE)) {
    yaml_ctx_report(ctx, &node->start_mark, LOG_WARNING,
		    "Expected node with tag \"" YAML_INT_TAG
		    "\", got tag \"%s\"", node->tag);
    return 0;
  }

  errno = 0; /* reset errno value */
  tmp = strtol((const char *)node->data.scalar.value, &end, 0);

  if (*end != '\0') {
    yaml_ctx_report(ctx, &node->start_mark, LOG_WARNING,
		    "Invalid integer \"%s\"", node->data.scalar.value);
    return 0;
  } else if ((tmp == LONG_MIN || tmp == LONG_MAX) && errno == ERANGE) {
    yaml_ctx_report(ctx, &node->start_mark, LOG_WARNING,
		    "Integer %sflow", tmp < 0 ? "under" : "over");
    return 0;
  }

  *dest = tmp;
  return 1;
}

/* Determine if a string is a YAML "null" value */
#define IS_NULL(str)	(!strcmp(str, "") || !strcmp(str, "~") ||	\
			 !strcmp(str, "null") || !strcmp(str, "Null") || \
			 !strcmp(str, "NULL"))

int
yaml_get_str(yaml_ctx_t *ctx, yaml_node_t *node, const char **dest,
	       int allow_null)
{
  /* Sanity-check the node */
  if (node->type != YAML_SCALAR_NODE) {
    yaml_ctx_report(ctx, &node->start_mark, LOG_WARNING,
		    "Expected scalar node, found %s node", node_type(node));
    return 0;

  /* The libyaml parser doesn't handle implicit tags, so if a null
   * node is not explicitly tagged as null, we check if it's a str tag
   * with a plain style and having one of the accepted "null" values.
   */
  } else if (allow_null &&
	     (!strcmp((const char *)node->tag, YAML_NULL_TAG) ||
	      (!strcmp((const char *)node->tag, YAML_STR_TAG) &&
	       node->data.scalar.style == YAML_PLAIN_SCALAR_STYLE &&
	       IS_NULL((const char *)node->data.scalar.value)))) {
    *dest = 0;
    return 1;
  } else if (strcmp((const char *)node->tag, YAML_STR_TAG)) {
    yaml_ctx_report(ctx, &node->start_mark, LOG_WARNING,
		    "Expected node with tag \"" YAML_STR_TAG
		    "\", got tag \"%s\"", node->tag);
    return 0;
  }

  *dest = (const char *)node->data.scalar.value;
  return 1;
}

static const char *_error_types[] = {
  "No",
  "Memory",
  "Reader",
  "Scanner",
  "Parser",
  "Composer",
  "Writer",
  "Emitter"
};

static const char *
error_type(yaml_error_type_t error)
{
  if (error <= YAML_EMITTER_ERROR)
    return _error_types[error];

  return "Unknown";
}

static void
report_parser_error(yaml_ctx_t *ctx, yaml_parser_t *parser)
{
  yaml_ctx_report(ctx, &parser->problem_mark, LOG_WARNING,
		  "%s error parsing file: %s", error_type(parser->error),
		  parser->problem);
}

void
yaml_file_mapping(config_t *conf, const char *filename,
		  mapkeys_t *keys, size_t keycnt, void *dest,
		  int all_docs, nextdoc_t nextdoc)
{
  yaml_parser_t parser;
  yaml_ctx_t ctx;
  yaml_node_t *root;
  FILE *fp;

  common_verify(conf, CONFIG_MAGIC);

  /* Open the YAML file */
  if (!(fp = fopen(filename, "r")))
    return;

  /* Initialize the context */
  ctx.yc_conf = conf;
  ctx.yc_filename = filename;
  ctx.yc_docnum = 0;
  ctx.yc_path[0] = '\0';
  ctx.yc_pathlen = 0;

  /* Initialize the parser */
  if (!yaml_parser_initialize(&parser)) {
    report_parser_error(&ctx, &parser);
    fclose(fp);
    return;
  }

  /* Set it to read from our stream */
  yaml_parser_set_input_file(&parser, fp);

  /* Read documents from the stream */
  do {
    /* Increment the document count */
    ctx.yc_docnum++;

    /* Load a document from the stream */
    if (!yaml_parser_load(&parser, &ctx.yc_document)) {
      report_parser_error(&ctx, &parser);
      break;
    }

    /* Get the document's root node */
    if (!(root = yaml_document_get_root_node(&ctx.yc_document))) {
      report_parser_error(&ctx, &parser);
      yaml_document_delete(&ctx.yc_document);
      break;
    }

    /* Update dest if necessary */
    if (nextdoc && ctx.yc_docnum > 1)
      dest = nextdoc(&ctx, dest);

    /* Process the node as a mapping */
    yaml_proc_mapping(&ctx, root, keys, keycnt, dest);

    /* Clean up the document */
    yaml_document_delete(&ctx.yc_document);
  } while (all_docs);

  /* Clean up after ourselves */
  yaml_parser_delete(&parser);
  fclose(fp);
}
