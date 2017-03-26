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

  /* Add the sequence index; we make it 1-indexed for convenience */
  if ((n = snprintf(ctx->yc_path + ctx->yc_pathlen, PATH_BUF - ctx->yc_pathlen,
		    "/[%d]", idx + 1)) > PATH_BUF - ctx->yc_pathlen) {
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

  /* Add the location, if one was provided; use 1-indexed line numbers */
  if (loc && n < sizeof(msgbuf))
    n += snprintf(msgbuf + n, sizeof(msgbuf) - n, " (line %d)",
		  (int)(loc->line + 1));

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

static int
mapping_key_compare(const char *key, const mapkeys_t *member)
{
  return strcmp(key, member->mk_key);
}

static void
process_mapping_key(mapkeys_t *keys, size_t keycnt,
		    const char *key, void *dest,
		    yaml_ctx_t *ctx, yaml_node_t *value,
		    yaml_mark_t *key_mark)
{
  mapkeys_t *result;

  if (!(result = (mapkeys_t *)bsearch((const void *)key, (const void *)keys,
				      keycnt, sizeof(mapkeys_t),
				      (compare_t)mapping_key_compare))) {
    yaml_ctx_report(ctx, key_mark, LOG_WARNING,
		    "Ignoring unknown key \"%s\"", key);
    return;
  }

  yaml_ctx_path_push_key(ctx, key);
  result->mk_proc(key, dest, ctx, value);
  yaml_ctx_path_pop(ctx);
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
  int idx;
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
    idx = cursor - seq->data.sequence.items.start;
    yaml_ctx_path_push_idx(ctx, idx);
    proc(idx, dest, ctx, item);
    yaml_ctx_path_pop(ctx);
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

/* Processor for scalar nodes */
typedef int (*scalar_proc_t)(yaml_ctx_t *ctx, yaml_node_t *scalar,
			     node_tag_t type, uint32_t possible_types,
			     node_info_t *info);

/* Converts a node type into a bit mask */
#define possible(type)	(1 << (type))

/* Simple conversion */
static int simple_proc(yaml_ctx_t *ctx, yaml_node_t *scalar, node_tag_t type,
		       uint32_t possible_types, node_info_t *info);

/* Handle possible implicit nodes */
static int implicit_proc(yaml_ctx_t *ctx, yaml_node_t *scalar, node_tag_t type,
			 uint32_t possible_types, node_info_t *info);

struct node_tags {
  const char *tag;
  node_tag_t type;
  uint32_t possible_types;
  scalar_proc_t proc;
};

static struct node_tags tag_list[] = {
  {YAML_BINARY_TAG, NODE_BINARY_TAG, possible(NODE_BINARY_TAG), simple_proc},
  {YAML_BOOL_TAG, NODE_BOOL_TAG, possible(NODE_BOOL_TAG), implicit_proc},
  {YAML_FLOAT_TAG, NODE_FLOAT_TAG, possible(NODE_FLOAT_TAG), implicit_proc},
  {YAML_INT_TAG, NODE_INT_TAG, possible(NODE_INT_TAG), implicit_proc},
  {YAML_NULL_TAG, NODE_NULL_TAG, possible(NODE_NULL_TAG), implicit_proc},
  {YAML_STR_TAG, NODE_STR_TAG, (possible(NODE_BOOL_TAG) |
				possible(NODE_FLOAT_TAG) |
				possible(NODE_INT_TAG) |
				possible(NODE_NULL_TAG) |
				possible(NODE_STR_TAG) |
				possible(NODE_TIMESTAMP_TAG)), implicit_proc},
  {YAML_TIMESTAMP_TAG, NODE_TIMESTAMP_TAG, possible(NODE_TIMESTAMP_TAG),
   implicit_proc}
};
#define TAG_COUNT	(sizeof(tag_list) / sizeof(struct node_tags))

static int
tag_compare(const char *tag, const struct node_tags *member)
{
  return strcmp(tag, member->tag);
}

static int
simple_proc(yaml_ctx_t *ctx, yaml_node_t *scalar, node_tag_t type,
	    uint32_t possible_types, node_info_t *info)
{
  info->ni_type = type;
  info->ni_tag = type == NODE_OTHER_TAG ? (const char *)scalar->tag :
    tag_list[type].tag;
  info->ni_data.nid_str.nids_value = (const char *)scalar->data.scalar.value;
  info->ni_data.nid_str.nids_length = scalar->data.scalar.length;

  return 1;
}

int
yaml_get_scalar(yaml_ctx_t *ctx, yaml_node_t *scalar, node_info_t *info)
{
  struct node_tags *result;

  /* Make sure it's what we expect */
  if (scalar->type != YAML_SCALAR_NODE) {
    yaml_ctx_report(ctx, &scalar->start_mark, LOG_WARNING,
		    "Expected scalar node, found %s node", node_type(scalar));
    return 0;
  }

  /* Look up the tag in the array */
  if ((result = (struct node_tags *)bsearch((const void *)scalar->tag,
					    (const void *)tag_list,
					    TAG_COUNT,
					    sizeof(struct node_tags),
					    (compare_t)tag_compare)))
    return result->proc(ctx, scalar, result->type, result->possible_types,
			info);

  return implicit_proc(ctx, scalar, NODE_OTHER_TAG, 0, info);
}

int
yaml_get_bool(yaml_ctx_t *ctx, yaml_node_t *node, int *dest)
{
  node_info_t info;

  /* Get the node information */
  if (!yaml_get_scalar(ctx, node, &info))
    return 0;

  /* Is it a boolean node? */
  if (info.ni_type != NODE_BOOL_TAG) {
    yaml_ctx_report(ctx, &node->start_mark, LOG_WARNING,
		    "Expected node with tag \"" YAML_BOOL_TAG
		    "\", got tag \"%s\"", info.ni_tag);
    return 0;
  }

  *dest = info.ni_data.nid_int;
  return 1;
}

int
yaml_get_int(yaml_ctx_t *ctx, yaml_node_t *node, long *dest)
{
  node_info_t info;

  /* Get the node information */
  if (!yaml_get_scalar(ctx, node, &info))
    return 0;

  /* Is it an integer node? */
  if (info.ni_type != NODE_INT_TAG) {
    yaml_ctx_report(ctx, &node->start_mark, LOG_WARNING,
		    "Expected node with tag \"" YAML_INT_TAG
		    "\", got tag \"%s\"", info.ni_tag);
    return 0;
  }

  *dest = info.ni_data.nid_int;
  return 1;
}

int
yaml_get_str(yaml_ctx_t *ctx, yaml_node_t *node, const char **dest,
	     size_t *len, uint32_t flags)
{
  node_info_t info;

  /* Get the node information */
  if (!yaml_get_scalar(ctx, node, &info))
    return 0;

  /* Is it the right kind of node? */
  if (info.ni_type != NODE_STR_TAG &&
      (!(flags & ALLOW_NULL) || info.ni_type != NODE_NULL_TAG) &&
      (!(flags & ALLOW_BINARY) || info.ni_type != NODE_BINARY_TAG)) {
    yaml_ctx_report(ctx, &node->start_mark, LOG_WARNING,
		    "Expected node with tag \"" YAML_STR_TAG
		    "\", got tag \"%s\"", info.ni_tag);
    return 0;
  }

  /* Binary nodes need to be decoded */
  if (info.ni_type == NODE_BINARY_TAG) {
    yaml_ctx_report(ctx, &node->start_mark, LOG_ERR,
		    "Binary node support not yet implemented");
    return 0;
  }

  *dest = info.ni_data.nid_str.nids_value;
  if (len)
    *len = info.ni_data.nid_str.nids_length;

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

int
yaml_file_mapping(config_t *conf, const char *filename, FILE *stream,
		  mapkeys_t *keys, size_t keycnt, void *dest,
		  int all_docs, nextdoc_t nextdoc)
{
  yaml_parser_t parser;
  yaml_ctx_t ctx;
  yaml_node_t *root;

  common_verify(conf, CONFIG_MAGIC);

  /* Initialize the context */
  ctx.yc_conf = conf;
  ctx.yc_filename = filename;
  ctx.yc_docnum = 0;
  ctx.yc_docvalid = 0;
  ctx.yc_path[0] = '\0';
  ctx.yc_pathlen = 0;

  /* Initialize the parser */
  if (!yaml_parser_initialize(&parser)) {
    report_parser_error(&ctx, &parser);
    return 0;
  }

  /* Set it to read from our stream */
  yaml_parser_set_input_file(&parser, stream);

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

    /* Increment the count of valid documents */
    ctx.yc_docvalid++;
  } while (all_docs);

  /* Clean up after ourselves */
  yaml_parser_delete(&parser);

  return ctx.yc_docnum == ctx.yc_docvalid;
}

/* Note: What follows is a rather compact bit of logic that processes
 * the contents of scalar nodes to handle implicit conversions
 * (STR(1234) -> INT(1234)).  This is in essence a hand-constructed
 * regular expression parser that constructs some values on the fly.
 * I say "some" because Humboldt is not interested in float or
 * timestamp values, so although we have to recognize them (to warn
 * about them as errors in the configuration), we don't need to
 * convert the values from them.
 */

/* Contains a bitmap allowing us to identify which characters are
 * expected and which unexpected.  If we encounter something
 * unexpected, then it can't be a string node.
 */
typedef struct {
  uint32_t		bitmap[8];
} next_t;

/* Clear the bitmap */
#define next_clear(obj)				\
  do {						\
    next_t *_obj = (obj);			\
    _obj->bitmap[0] = 0;			\
    _obj->bitmap[1] = 0;			\
    _obj->bitmap[2] = 0;			\
    _obj->bitmap[3] = 0;			\
    _obj->bitmap[4] = 0;			\
    _obj->bitmap[5] = 0;			\
    _obj->bitmap[6] = 0;			\
    _obj->bitmap[7] = 0;			\
  } while (0)

/* Array index into the bitmap */
#define _next_idx(c)		((c) >> 5)

/* Bit within the bitmap */
#define _next_bit(c)		(1 << ((c) & 31))

/* Set the bit associated with a single character */
#define next_setc(obj, c)	((obj)->bitmap[_next_idx(c)] |= _next_bit(c))

/* Set the bits associated with the characters of a string */
#define next_sets(obj, str)			\
  do {						\
    next_t *_obj = (obj);			\
    const char *_str = (str);			\
    for (; *_str; _str++)			\
      next_setc(_obj, *_str);			\
  } while (0)

/* Test if a character bit is set */
#define next_isset(obj, c)	((obj)->bitmap[_next_idx(c)] & _next_bit(c))

/* Accepted sequences of digits for integers of various bases */
#define DECIMAL_DIGITS		"0123456789_"
#define BINARY_DIGITS		"01_"
#define OCTAL_DIGITS		"01234567_"
#define HEX_DIGITS		"0123456789ABCDEFabcdef_"
#define SEX_DIGITS1		"012345"
#define SEX_DIGITS2		"0123456789"
#define TIMESTAMP_DIGITS	"0123456789"

/* Various flags used during processing */
#define CONSUMED_DOT		0x80000000	/* . was consumed */
#define CONSUMED_E		0x40000000	/* e was consumed */
#define OVERFLOW		0x20000000	/* integer overflow */
#define NEGATIVE		0x10000000	/* integer is negative */
#define TIME_REQUIRED		0x08000000	/* time is required */

/* Enumeration to keep track of which part of a timestamp we're
 * looking at.
 */
typedef enum {
  DATE_YEAR,
  DATE_MONTH,
  DATE_DAY,
  DATE_HOUR,
  DATE_MINUTE,
  DATE_SECOND,
  DATE_FRACTION,
  DATE_TZ_HOUR,
  DATE_TZ_MINUTE
} date_parts_t;

/* An end_allowed flag to always allow ending here */
#define END_ALLOWED		0xffffffff

/* Keep track of characteristics of the parts of a timestamp we're
 * recognizing.
 */
static struct {
  int		min_run;
  int		expected_run;
  uint32_t	min_flags;
  const char   *next_chars;
  uint32_t	end_allowed;
} date_parts[] = {
  {4, 4, 0, "-", 0},					/* year */
  {1, 2, TIME_REQUIRED, "-", 0},			/* month */
  {1, 2, TIME_REQUIRED, "\t Tt", TIME_REQUIRED},	/* day */
  {1, 2, 0, ":", 0},					/* hour */
  {2, 2, 0, ":", 0},					/* minute */
  {2, 2, 0, "\t -+.Z", END_ALLOWED},			/* second */
  {0, 0, 0, "\t -+Z", END_ALLOWED},			/* fraction */
  {1, 2, 0, ":", END_ALLOWED},				/* tz_hour */
  {2, 2, 0, "", END_ALLOWED},				/* tz_minute */
};

/* Accumulate a digit to the integer value */
#define accum(c)				\
  do {						\
    int _c = (c);				\
    if (!(flags & OVERFLOW) && base > 0) {	\
      if (_c >= '0' && _c <= '9')		\
	_c -= '0';				\
      else if (_c >= 'a' && _c <= 'f')		\
	_c = _c - 'a' + 10;			\
      else if (_c >= 'A' && _c <= 'F')		\
	_c = _c - 'A' + 10;			\
      if (base == 60)				\
	sex_group = sex_group * 10 + _c;	\
      else {					\
	tmp = val;				\
	val = val * base + _c;			\
	if (val < tmp)				\
	  flags |= OVERFLOW;			\
      }						\
    }						\
  } while (0)

static int
implicit_proc(yaml_ctx_t *ctx, yaml_node_t *scalar, node_tag_t type,
	      uint32_t possible_types, node_info_t *info)
{
  const char *digits = DECIMAL_DIGITS; /* accepted set of digits */
  /* Current character being processed */
  const char *c = (const char *)scalar->data.scalar.value;
  /* Final character to consider */
  const char *end = (const char *)(scalar->data.scalar.value +
				   scalar->data.scalar.length);
  uint32_t flags = 0; /* various state flags */
  int last = 0; /* last character processed */
  int base = 0; /* integer conversion base: 0, 2, 8, 10, 16, 60 */
  int run = 0; /* number of decimal digits in a row */
  next_t next; /* bitmap of next expected character */
  intmax_t val = 0, tmp = 0; /* integer value and tmp for overflow */
  int sex_group = 0; /* up to 2-digit group following ':' */
  date_parts_t date = DATE_YEAR; /* start by collecting year */

  /* Start off with something simple: if it's str and not plain style,
   * fall back to simple_proc()
   */
  if (type == NODE_STR_TAG &&
      scalar->data.scalar.style != YAML_PLAIN_SCALAR_STYLE)
    return simple_proc(ctx, scalar, type, possible_types, info);

  /* Initialize the next expected character */
  next_clear(&next);
  next_sets(&next, "+-.0123456789FfNnOoTtYy~");
  next_setc(&next, '\0');

  /* Loop through the text, including trailing \0 */
  for (; c <= end; last = *c, c++) {
    /* Break out if the character isn't expected */
    if (!next_isset(&next, *c)) {
      possible_types &= possible(NODE_STR_TAG); /* can't be anything else */
      break;
    }

    next_clear(&next);

    if (*c >= '0' && *c <= '9')
      run++;

    /* Switch based on the character */
    switch (*c) {
    case '\0':
      if (possible_types & possible(NODE_BOOL_TAG) &&
	  (last == 'y' || last == 'Y' || last == 'n' || last == 'N'))
	possible_types &= possible(NODE_BOOL_TAG);
      else if (possible_types & possible(NODE_NULL_TAG))
	possible_types &= possible(NODE_NULL_TAG);
      else if ((possible_types & possible(NODE_TIMESTAMP_TAG)) &&
	       date == DATE_DAY &&
	       date_parts[date].expected_run &&
	       run < date_parts[date].expected_run)
	possible_types &= ~possible(NODE_TIMESTAMP_TAG);
      break;

    case '\t':
    case ' ':
      possible_types &= possible(NODE_STR_TAG) | possible(NODE_TIMESTAMP_TAG);
      if (date == DATE_DAY || date == DATE_HOUR) {
	if (date_parts[date].expected_run &&
	    run < date_parts[date].expected_run)
	  flags |= date_parts[date].min_flags;
	date = DATE_HOUR;
	next_sets(&next, digits);
	next_sets(&next, "\t ");
      } else if (date == DATE_SECOND || date == DATE_FRACTION) {
	date = DATE_FRACTION;
	next_sets(&next, date_parts[date].next_chars);
	if (date_parts[date].end_allowed & ~flags)
	  next_setc(&next, '\0');
      }
      break;

    case '+':
      if (last == 'e' || last == 'E') {
	possible_types &= possible(NODE_STR_TAG) | possible(NODE_FLOAT_TAG);
	next_sets(&next, DECIMAL_DIGITS);
      } else if (last == 0) {
	possible_types &= possible(NODE_STR_TAG) | possible(NODE_INT_TAG) |
	  possible(NODE_FLOAT_TAG);
	next_sets(&next, "0123456789.");
      } else {
	possible_types &= possible(NODE_STR_TAG) |
	  possible(NODE_TIMESTAMP_TAG);
	digits = TIMESTAMP_DIGITS;
	next_sets(&next, digits);
	date = DATE_TZ_HOUR;
      }
      break;

    case '-':
      if (last == 'e' || last == 'E') {
	possible_types &= possible(NODE_STR_TAG) | possible(NODE_FLOAT_TAG);
	next_sets(&next, DECIMAL_DIGITS);
      } else if (last == 0) {
	possible_types &= possible(NODE_STR_TAG) | possible(NODE_INT_TAG) |
	  possible(NODE_FLOAT_TAG);
	next_sets(&next, "0123456789.");
	flags |= NEGATIVE;
      } else {
	possible_types &= possible(NODE_STR_TAG) |
	  possible(NODE_TIMESTAMP_TAG);
	digits = TIMESTAMP_DIGITS;
	next_sets(&next, digits);
	if (date_parts[date].expected_run &&
	    run < date_parts[date].expected_run)
	  flags |= date_parts[date].min_flags;
	if (date < DATE_DAY)
	  date++; /* advance to next field */
	else
	  date = DATE_TZ_HOUR;
      }
      break;

    case '.':
      if (possible_types & possible(NODE_FLOAT_TAG)) {
	possible_types &= possible(NODE_STR_TAG) | possible(NODE_FLOAT_TAG);
	flags |= CONSUMED_DOT;
	if (base == 60)
	  flags |= CONSUMED_E;
	base = 10;
	digits = DECIMAL_DIGITS;
	next_sets(&next, digits);
	if (last == 0 || last == '-' || last == '+')
	  next_sets(&next, "iI");
	if (last == 0)
	  next_sets(&next, "nN");
	if (last >= '0' && last <= '9') {
	  if (!(flags & CONSUMED_E))
	    next_sets(&next, "eE");
	  next_setc(&next, '\0');
	}
      } else {
	possible_types &= possible(NODE_STR_TAG) |
	  possible(NODE_TIMESTAMP_TAG);
	date = DATE_FRACTION;
	next_sets(&next, digits);
	next_sets(&next, date_parts[date].next_chars);
	if (date_parts[date].end_allowed & ~flags)
	  next_setc(&next, '\0');
      }
      break;

    case '0':
      if (possible_types & possible(NODE_TIMESTAMP_TAG)) {
	if (date_parts[date].expected_run &&
	    run > date_parts[date].expected_run)
	  possible_types &= ~possible(NODE_TIMESTAMP_TAG);
	else if (run >= date_parts[date].min_run) {
	  next_sets(&next, date_parts[date].next_chars);
	  if (date_parts[date].end_allowed & ~flags)
	    next_setc(&next, '\0');
	}
      }
      possible_types &= possible(NODE_STR_TAG) | possible(NODE_TIMESTAMP_TAG) |
	possible(NODE_INT_TAG) | possible(NODE_FLOAT_TAG);
      if (possible_types & possible(NODE_FLOAT_TAG)) {
	if (!(flags & CONSUMED_DOT))
	  next_setc(&next, '.');
	if (!(flags & CONSUMED_E))
	  next_sets(&next, "eE");
      }
      if (possible_types & (possible(NODE_INT_TAG) |
			    possible(NODE_FLOAT_TAG))) {
	if (last == 0)
	  next_sets(&next, "bx:");
	else if (base == 10 || base == 60)
	  next_setc(&next, ':');
	next_setc(&next, '\0');
	next_sets(&next, digits);
	accum(*c);
      } else
	next_sets(&next, digits);
      break;

    case '1':
    case '2':
    case '3':
    case '4':
    case '5':
      if (possible_types & possible(NODE_TIMESTAMP_TAG)) {
	if (date_parts[date].expected_run &&
	    run > date_parts[date].expected_run)
	  possible_types &= ~possible(NODE_TIMESTAMP_TAG);
	else if (run >= date_parts[date].min_run) {
	  next_sets(&next, date_parts[date].next_chars);
	  if (date_parts[date].end_allowed & ~flags)
	    next_setc(&next, '\0');
	}
      }
      possible_types &= possible(NODE_STR_TAG) | possible(NODE_TIMESTAMP_TAG) |
	possible(NODE_INT_TAG) | possible(NODE_FLOAT_TAG);
      if (possible_types & possible(NODE_FLOAT_TAG)) {
	if (!(flags & CONSUMED_DOT))
	  next_setc(&next, '.');
	if (!(flags & CONSUMED_E))
	  next_sets(&next, "eE");
      }
      if (possible_types & (possible(NODE_INT_TAG) |
			    possible(NODE_FLOAT_TAG))) {
	if (base == 0) {
	  if (last == '0') {
	    base = 8;
	    digits = OCTAL_DIGITS;
	  } else {
	    base = 10;
	    digits = DECIMAL_DIGITS;
	  }
	  next_setc(&next, ':');
	} else if (base == 10 || base == 60)
	  next_setc(&next, ':');
	next_setc(&next, '\0');
	next_sets(&next, digits);
	accum(*c);
      } else
	next_sets(&next, digits);
      break;

    case '6':
    case '7':
      if (possible_types & possible(NODE_TIMESTAMP_TAG)) {
	if (date_parts[date].expected_run &&
	    run > date_parts[date].expected_run)
	  possible_types &= ~possible(NODE_TIMESTAMP_TAG);
	else if (run >= date_parts[date].min_run) {
	  next_sets(&next, date_parts[date].next_chars);
	  if (date_parts[date].end_allowed & ~flags)
	    next_setc(&next, '\0');
	}
      }
      possible_types &= possible(NODE_STR_TAG) | possible(NODE_TIMESTAMP_TAG) |
	possible(NODE_INT_TAG) | possible(NODE_FLOAT_TAG);
      if (possible_types & possible(NODE_FLOAT_TAG)) {
	if (!(flags & CONSUMED_DOT))
	  next_setc(&next, '.');
	if (!(flags & CONSUMED_E))
	  next_sets(&next, "eE");
      }
      if (possible_types & (possible(NODE_INT_TAG) |
			    possible(NODE_FLOAT_TAG))) {
	if (base == 0) {
	  if (last == '0') {
	    base = 8;
	    digits = OCTAL_DIGITS;
	  } else {
	    base = 10;
	    digits = DECIMAL_DIGITS;
	  }
	  next_setc(&next, ':');
	} else if (base == 10 || base == 60)
	  next_setc(&next, ':');
	if (base != 60) /* No other digits can follow */
	  next_sets(&next, digits);
	next_setc(&next, '\0');
	accum(*c);
      } else
	next_sets(&next, digits);
      break;

    case '8':
    case '9':
      if (possible_types & possible(NODE_TIMESTAMP_TAG)) {
	if (date_parts[date].expected_run &&
	    run > date_parts[date].expected_run)
	  possible_types &= ~possible(NODE_TIMESTAMP_TAG);
	else if (run >= date_parts[date].min_run) {
	  next_sets(&next, date_parts[date].next_chars);
	  if (date_parts[date].end_allowed & ~flags)
	    next_setc(&next, '\0');
	}
      }
      if (possible_types & (possible(NODE_INT_TAG) |
			    possible(NODE_FLOAT_TAG))) {
	if (base == 0) {
	  base = 10;
	  digits = DECIMAL_DIGITS;

	  if (last == '0')
	    possible_types &= possible(NODE_STR_TAG) |
	      possible(NODE_TIMESTAMP_TAG) | possible(NODE_FLOAT_TAG);
	  else
	    possible_types &= possible(NODE_STR_TAG) |
	      possible(NODE_TIMESTAMP_TAG) | possible(NODE_INT_TAG) |
	      possible(NODE_FLOAT_TAG);

	  next_setc(&next, ':');
	} else if (base == 10 || base == 60)
	  next_setc(&next, ':');
	if (possible_types & possible(NODE_FLOAT_TAG)) {
	  if (!(flags & CONSUMED_DOT))
	    next_setc(&next, '.');
	  if (!(flags & CONSUMED_E))
	    next_sets(&next, "eE");
	}
	if (base != 60) /* No other digits can follow */
	  next_sets(&next, digits);
	next_setc(&next, '\0');
	accum(*c);
      } else
	next_sets(&next, digits);
      break;

    case ':':
      if (possible_types & possible(NODE_TIMESTAMP_TAG)) {
	possible_types &= possible(NODE_STR_TAG) |
	  possible(NODE_TIMESTAMP_TAG);
	date++;
	next_sets(&next, digits);
      } else {
	if (base == 0 && last == '0')
	  possible_types &= possible(NODE_STR_TAG) | possible(NODE_FLOAT_TAG);
	else
	  possible_types &= possible(NODE_STR_TAG) | possible(NODE_INT_TAG) |
	    possible(NODE_FLOAT_TAG);
	if (!(flags & OVERFLOW) && base == 60) {
	  tmp = val;
	  val += sex_group;
	  if (val < tmp)
	    flags |= OVERFLOW;
	}
	if (!(flags & OVERFLOW)) {
	  tmp = val;
	  val *= 60;
	  if (val < tmp)
	    flags |= OVERFLOW;
	}
	base = 60;
	digits = SEX_DIGITS2;
	sex_group = 0;
	next_sets(&next, digits);
      }
      break;

    case '_':
      possible_types &= possible(NODE_STR_TAG) | possible(NODE_INT_TAG) |
	possible(NODE_FLOAT_TAG);
      next_sets(&next, digits);
      if ((possible_types & possible(NODE_FLOAT_TAG)) &&
	  !(flags & CONSUMED_DOT))
	next_setc(&next, '.');
      break;

    case 'A':
      if (possible_types & possible(NODE_FLOAT_TAG)) {
	possible_types &= possible(NODE_STR_TAG) | possible(NODE_FLOAT_TAG);
	next_setc(&next, last);
      } else if (possible_types & possible(NODE_BOOL_TAG)) {
	possible_types &= possible(NODE_STR_TAG) | possible(NODE_BOOL_TAG);
	next_setc(&next, 'L');
      } else if (possible_types & possible(NODE_INT_TAG) && base == 16) {
	possible_types &= possible(NODE_STR_TAG) | possible(NODE_INT_TAG);
	next_sets(&next, digits);
	next_setc(&next, '\0');
	accum(*c);
      }
      break;

    case 'a':
      if (possible_types & possible(NODE_FLOAT_TAG)) {
	possible_types &= possible(NODE_STR_TAG) | possible(NODE_FLOAT_TAG);
	next_setc(&next, last);
      } else if (possible_types & possible(NODE_BOOL_TAG)) {
	possible_types &= possible(NODE_STR_TAG) | possible(NODE_BOOL_TAG);
	next_setc(&next, 'l');
      } else if (possible_types & possible(NODE_INT_TAG) && base == 16) {
	possible_types &= possible(NODE_STR_TAG) | possible(NODE_INT_TAG);
	next_sets(&next, digits);
	next_setc(&next, '\0');
	accum(*c);
      }
      break;

    case 'b':
      possible_types &= possible(NODE_STR_TAG) | possible(NODE_INT_TAG);
      if (base == 0) {
	base = 2;
	digits = BINARY_DIGITS;
	next_sets(&next, digits);
      } else if (base == 16) {
	next_sets(&next, digits);
	next_setc(&next, '\0');
	accum(*c);
      }
      break;

    case 'B':
    case 'C':
    case 'c':
    case 'D':
    case 'd':
      possible_types &= possible(NODE_STR_TAG) | possible(NODE_INT_TAG);
      next_sets(&next, digits);
      next_setc(&next, '\0');
      accum(*c);
      break;

    case 'E':
      if (possible_types & possible(NODE_BOOL_TAG)) {
	possible_types &= possible(NODE_STR_TAG) | possible(NODE_BOOL_TAG);
	if (last == 'Y')
	  next_setc(&next, 'S');
	else
	  next_setc(&next, '\0');
      } else if (possible_types & possible(NODE_FLOAT_TAG)) {
	possible_types &= possible(NODE_STR_TAG) | possible(NODE_FLOAT_TAG);
	flags |= CONSUMED_E;
	next_sets(&next, "-+");
      } else if (possible_types & possible(NODE_INT_TAG)) {
	possible_types &= possible(NODE_STR_TAG) | possible(NODE_INT_TAG);
	next_sets(&next, digits);
	next_setc(&next, '\0');
	accum(*c);
      }
      break;

    case 'e':
      if (possible_types & possible(NODE_BOOL_TAG)) {
	possible_types &= possible(NODE_STR_TAG) | possible(NODE_BOOL_TAG);
	if (last == 'y' || last == 'Y')
	  next_setc(&next, 's');
	else
	  next_setc(&next, '\0');
      } else if (possible_types & possible(NODE_FLOAT_TAG)) {
	possible_types &= possible(NODE_STR_TAG) | possible(NODE_FLOAT_TAG);
	flags |= CONSUMED_E;
	next_sets(&next, "-+");
      } else if (possible_types & possible(NODE_INT_TAG)) {
	possible_types &= possible(NODE_STR_TAG) | possible(NODE_INT_TAG);
	next_sets(&next, digits);
	next_setc(&next, '\0');
	accum(*c);
      }
      break;

    case 'F':
      if (possible_types & possible(NODE_BOOL_TAG)) {
	possible_types &= possible(NODE_STR_TAG) | possible(NODE_BOOL_TAG);
	if (last == 0) {
	  next_sets(&next, "aA");
	  val = 0;
	} else if (last == 'F')
	  next_setc(&next, '\0');
	else {
	  next_setc(&next, 'F');
	  val = 0;
	}
      } else if (possible_types & possible(NODE_FLOAT_TAG)) {
	possible_types &= possible(NODE_STR_TAG) | possible(NODE_FLOAT_TAG);
	next_setc(&next, '\0');
      } else if (possible_types & possible(NODE_INT_TAG)) {
	possible_types &= possible(NODE_STR_TAG) | possible(NODE_INT_TAG);
	next_sets(&next, digits);
	next_setc(&next, '\0');
	accum(*c);
      }
      break;

    case 'f':
      if (possible_types & possible(NODE_BOOL_TAG)) {
	possible_types &= possible(NODE_STR_TAG) | possible(NODE_BOOL_TAG);
	if (last == 0) {
	  next_setc(&next, 'a');
	  val = 0;
	} else if (last == 'f')
	  next_setc(&next, '\0');
	else {
	  next_setc(&next, 'f');
	  val = 0;
	}
      } else if (possible_types & possible(NODE_FLOAT_TAG)) {
	possible_types &= possible(NODE_STR_TAG) | possible(NODE_FLOAT_TAG);
	next_setc(&next, '\0');
      } else if (possible_types & possible(NODE_INT_TAG)) {
	possible_types &= possible(NODE_STR_TAG) | possible(NODE_INT_TAG);
	next_sets(&next, digits);
	next_setc(&next, '\0');
	accum(*c);
      }
      break;

    case 'I':
      possible_types &= possible(NODE_STR_TAG) | possible(NODE_FLOAT_TAG);
      next_sets(&next, "nN");
      break;

    case 'i':
      possible_types &= possible(NODE_STR_TAG) | possible(NODE_FLOAT_TAG);
      next_setc(&next, 'n');
      break;

    case 'L':
      if (possible_types & possible(NODE_BOOL_TAG)) {
	possible_types &= possible(NODE_STR_TAG) | possible(NODE_BOOL_TAG);
	next_setc(&next, 'S');
      } else if (possible_types & possible(NODE_NULL_TAG)) {
	possible_types &= possible(NODE_STR_TAG) | possible(NODE_NULL_TAG);
	if (last == 'L')
	  next_setc(&next, '\0');
	else
	  next_setc(&next, 'L');
      }
      break;

    case 'l':
      if (possible_types & possible(NODE_BOOL_TAG)) {
	possible_types &= possible(NODE_STR_TAG) | possible(NODE_BOOL_TAG);
	next_setc(&next, 's');
      } else if (possible_types & possible(NODE_NULL_TAG)) {
	possible_types &= possible(NODE_STR_TAG) | possible(NODE_NULL_TAG);
	if (last == 'l')
	  next_setc(&next, '\0');
	else
	  next_setc(&next, 'l');
      }
      break;

    case 'N':
      if (possible_types & (possible(NODE_BOOL_TAG) |
			    possible(NODE_NULL_TAG))) {
	possible_types &= possible(NODE_STR_TAG) | possible(NODE_BOOL_TAG) |
	  possible(NODE_NULL_TAG);
	if (last == 0) {
	  next_sets(&next, "uUoO");
	  val = 0;
	} else
	  val = 1;
	next_setc(&next, '\0');
      } else if (possible_types & possible(NODE_FLOAT_TAG)) {
	if (last == '.')
	  next_sets(&next, "aA");
	else if (last == 'A' || last == 'a')
	  next_setc(&next, '\0');
	else
	  next_setc(&next, 'F');
      }
      break;

    case 'n':
      if (possible_types & (possible(NODE_BOOL_TAG) |
			    possible(NODE_NULL_TAG))) {
	possible_types &= possible(NODE_STR_TAG) | possible(NODE_BOOL_TAG) |
	  possible(NODE_NULL_TAG);
	if (last == 0) {
	  next_sets(&next, "uo");
	  val = 0;
	} else
	  val = 1;
	next_setc(&next, '\0');
      } else if (possible_types & possible(NODE_FLOAT_TAG)) {
	if (last == '.')
	  next_setc(&next, 'a');
	else if (last == 'a')
	  next_setc(&next, '\0');
	else
	  next_setc(&next, 'f');
      }
      break;

    case 'O':
      possible_types &= possible(NODE_STR_TAG) | possible(NODE_BOOL_TAG);
      if (last == 0)
	next_sets(&next, "nNfF");
      else
	next_setc(&next, '\0');
      break;

    case 'o':
      possible_types &= possible(NODE_STR_TAG) | possible(NODE_BOOL_TAG);
      if (last == 0)
	next_sets(&next, "nf");
      else
	next_setc(&next, '\0');
      break;

    case 'R':
      possible_types &= possible(NODE_STR_TAG) | possible(NODE_BOOL_TAG);
      next_setc(&next, 'U');
      break;

    case 'r':
      possible_types &= possible(NODE_STR_TAG) | possible(NODE_BOOL_TAG);
      next_setc(&next, 'u');
      break;

    case 'S':
      possible_types &= possible(NODE_STR_TAG) | possible(NODE_BOOL_TAG);
      if (last == 'E')
	next_setc(&next, '\0');
      else
	next_setc(&next, 'E');
      break;

    case 's':
      possible_types &= possible(NODE_STR_TAG) | possible(NODE_BOOL_TAG);
      if (last == 'e')
	next_setc(&next, '\0');
      else
	next_setc(&next, 'e');
      break;

    case 'T':
      if ((possible_types & possible(NODE_TIMESTAMP_TAG)) && last != 0) {
	possible_types &= possible(NODE_STR_TAG) |
	  possible(NODE_TIMESTAMP_TAG);
	if (date_parts[date].expected_run &&
	    run < date_parts[date].expected_run)
	  flags |= date_parts[date].min_flags;
	date++;
	next_sets(&next, digits);
      } else {
	possible_types &= possible(NODE_STR_TAG) | possible(NODE_BOOL_TAG);
	next_sets(&next, "rR");
	val = 1;
      }
      break;

    case 't':
      if ((possible_types & possible(NODE_TIMESTAMP_TAG)) && last != 0) {
	possible_types &= possible(NODE_STR_TAG) |
	  possible(NODE_TIMESTAMP_TAG);
	if (date_parts[date].expected_run &&
	    run < date_parts[date].expected_run)
	  flags |= date_parts[date].min_flags;
	date++;
	next_sets(&next, digits);
      } else {
	possible_types &= possible(NODE_STR_TAG) | possible(NODE_BOOL_TAG);
	next_setc(&next, 'r');
	val = 1;
      }
      break;

    case 'U':
      if (possible_types & possible(NODE_NULL_TAG)) {
	possible_types &= possible(NODE_STR_TAG) | possible(NODE_NULL_TAG);
	next_setc(&next, 'L');
      } else if (possible_types & possible(NODE_BOOL_TAG)) {
	possible_types &= possible(NODE_STR_TAG) | possible(NODE_BOOL_TAG);
	next_setc(&next, 'E');
      }
      break;

    case 'u':
      if (possible_types & possible(NODE_NULL_TAG)) {
	possible_types &= possible(NODE_STR_TAG) | possible(NODE_NULL_TAG);
	next_setc(&next, 'l');
      } else if (possible_types & possible(NODE_BOOL_TAG)) {
	possible_types &= possible(NODE_STR_TAG) | possible(NODE_BOOL_TAG);
	next_setc(&next, 'e');
      }
      break;

    case 'x':
      possible_types &= possible(NODE_STR_TAG) | possible(NODE_INT_TAG);
      base = 16;
      digits = HEX_DIGITS;
      next_sets(&next, digits);
      break;

    case 'Y':
      possible_types &= possible(NODE_STR_TAG) | possible(NODE_BOOL_TAG);
      next_sets(&next, "eE");
      next_setc(&next, '\0');
      val = 1;
      break;

    case 'y':
      possible_types &= possible(NODE_STR_TAG) | possible(NODE_BOOL_TAG);
      next_setc(&next, 'e');
      next_setc(&next, '\0');
      val = 1;
      break;

    case 'Z':
      possible_types &= possible(NODE_STR_TAG) | possible(NODE_TIMESTAMP_TAG);
      next_setc(&next, '\0');
      break;

    case '~':
      possible_types &= possible(NODE_STR_TAG) | possible(NODE_NULL_TAG);
      next_setc(&next, '\0');
      break;
    }

    if (*c < '0' || *c > '9')
      run = 0;

    /* Break out if we're reduced to just unknown or string */
    if (!possible_types || possible_types == possible(NODE_STR_TAG))
      break;
  }

  /* Floats must consume a dot */
  if (!(flags & CONSUMED_DOT))
    possible_types &= ~possible(NODE_FLOAT_TAG);

  /* Set the info to return */
  if (possible_types == possible(NODE_STR_TAG)) {
    info->ni_type = NODE_STR_TAG;
    info->ni_tag = tag_list[NODE_STR_TAG].tag;
    info->ni_data.nid_str.nids_value = (const char *)scalar->data.scalar.value;
    info->ni_data.nid_str.nids_length = scalar->data.scalar.length;
    return 1;
  } else if (possible_types & possible(NODE_INT_TAG)) {
    /* Sexigesimal; need to accumulate the last sex_group */
    if (base == 60 && !(flags & OVERFLOW)) {
      tmp = val;
      val += sex_group;
      if (val < tmp)
	flags |= OVERFLOW;
    }

    info->ni_type = NODE_INT_TAG;
    info->ni_tag = tag_list[NODE_INT_TAG].tag;

    /* Handle overflow and the appropriate sign */
    if (flags & OVERFLOW) {
      yaml_ctx_report(ctx, &scalar->start_mark, LOG_WARNING,
		      "Integer overflow converting string \"%s\"",
		      scalar->data.scalar.value);
      info->ni_data.nid_int = (flags & NEGATIVE) ? INTMAX_MIN : INTMAX_MAX;
    } else if (flags & NEGATIVE)
      info->ni_data.nid_int = -val;
    else
      info->ni_data.nid_int = val;

    return 1;
  } else if (possible_types & possible(NODE_FLOAT_TAG)) {
    info->ni_type = NODE_FLOAT_TAG;
    info->ni_tag = tag_list[NODE_FLOAT_TAG].tag;
    info->ni_data.nid_str.nids_value = (const char *)scalar->data.scalar.value;
    info->ni_data.nid_str.nids_length = scalar->data.scalar.length;
    return 1;
  } else if (possible_types & possible(NODE_BOOL_TAG)) {
    info->ni_type = NODE_BOOL_TAG;
    info->ni_tag = tag_list[NODE_BOOL_TAG].tag;
    info->ni_data.nid_int = val;
    return 1;
  } else if (possible_types & possible(NODE_NULL_TAG)) {
    info->ni_type = NODE_NULL_TAG;
    info->ni_tag = tag_list[NODE_NULL_TAG].tag;
    info->ni_data.nid_str.nids_value = 0;
    info->ni_data.nid_str.nids_length = 0;
    return 1;
  } else if (possible_types & possible(NODE_TIMESTAMP_TAG)) {
    info->ni_type = NODE_TIMESTAMP_TAG;
    info->ni_tag = tag_list[NODE_TIMESTAMP_TAG].tag;
    info->ni_data.nid_str.nids_value = (const char *)scalar->data.scalar.value;
    info->ni_data.nid_str.nids_length = scalar->data.scalar.length;
    return 1;
  }

  /* Invalid value, I guess */
  yaml_ctx_report(ctx, &scalar->start_mark, LOG_WARNING,
		  "Invalid value \"%s\" for node with tag \"%s\"",
		  scalar->data.scalar.value, scalar->tag);
  return 0;
}
