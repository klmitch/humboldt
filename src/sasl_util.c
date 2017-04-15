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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "include/configuration.h"
#include "include/sasl_util.h"
#include "include/yaml_util.h"

static void
proc_sasl_conf(const char *key, sasl_conf_t *sasl_conf, yaml_ctx_t *ctx,
	       yaml_node_t *value)
{
  conf_ctx_t conf_ctx = CONF_CTX_YAML(ctx, value);
  node_info_t info;
  sasl_option_t *sasl_opt;
  char strbuf[100], *val_str;
  size_t key_len, val_len;

  common_verify(sasl_conf, SASL_CONF_MAGIC);

  /* Get the value information */
  if (!yaml_get_scalar(ctx, value, &info))
    return;

  /* Interpret the node's type */
  if (info.ni_type == NODE_NULL_TAG) {
    /* Interpret as a zero-length string */
    val_str = "";
    val_len = 0;
  } else if (info.ni_type == NODE_INT_TAG)
    /* Convert integer back into a string, but without YAML's extensions */
    val_len = snprintf(val_str = strbuf, sizeof(strbuf), "%jd",
		       info.ni_data.nid_int);
  else {
    /* Everything else, go back to the original string value */
    val_str = (char *)value->data.scalar.value;
    val_len = value->data.scalar.length;
  }

  /* Need the key's length too */
  key_len = strlen(key);

  /* Allocate an option structure */
  if (!(sasl_opt = malloc(sizeof(sasl_option_t) + val_len + key_len + 1))) {
    config_report(&conf_ctx, LOG_WARNING,
		  "Out of memory saving SASL configuration value \"%s\"", key);
    return;
  }

  /* Initialize the option structure values */
  sasl_opt->sao_vallen = val_len;
  memcpy(sasl_opt->sao_value, val_str, val_len);
  sasl_opt->sao_value[val_len] = '\0';
  sasl_opt->sao_option = &sasl_opt->sao_value[val_len + 1];
  memcpy(sasl_opt->sao_option, key, key_len);
  sasl_opt->sao_option[key_len] = '\0';

  /* Now we can initialize the hash entry */
  hash_ent_init(&sasl_opt->sao_hashent, sasl_opt, sasl_opt->sao_option);

  /* And set the magic number */
  sasl_opt->sao_magic = SASL_OPTION_MAGIC;

  /* Add it to the hash table */
  switch (hash_add(&sasl_conf->sac_options, &sasl_opt->sao_hashent)) {
  case DBERR_NONE:
    break; /* add successful */

  case DBERR_DUPLICATE:
    config_report(&conf_ctx, LOG_WARNING, "Duplicate SASL option \"%s\"", key);
    free(sasl_opt);
    break;

  case DBERR_NOMEMORY:
    config_report(&conf_ctx, LOG_WARNING,
		  "Out of memory saving SASL configuration value \"%s\"", key);
    free(sasl_opt);
    break;
  }
}

void
sasl_conf_processor(const char *key, config_t *conf,
		    yaml_ctx_t *ctx, yaml_node_t *value)
{
  conf_ctx_t conf_ctx = CONF_CTX_YAML(ctx, value);
  sasl_conf_t *sasl_conf;

  common_verify(conf, CONFIG_MAGIC);

  /* Construct a sasl_conf_t object */
  if (!(sasl_conf = malloc(sizeof(sasl_conf_t)))) {
    config_report(&conf_ctx, LOG_WARNING,
		  "Out of memory reading SASL configuration");
    return;
  }

  /* Initialize the object */
  hash_tab_init(&sasl_conf->sac_options, db_str_hash, db_str_comp);
  sasl_conf->sac_magic = SASL_CONF_MAGIC;

  /* Save it in the configuration */
  conf->cf_sasl = sasl_conf;

  /* Process all the items in the mapping */
  yaml_proc_mapping(ctx, value, (mapproc_t)proc_sasl_conf, 0, 0, sasl_conf);
}

static void
free_option(sasl_option_t *option, void *extra)
{
  common_verify(option, SASL_OPTION_MAGIC);

  /* First, remove it from the hash table */
  hash_remove(&option->sao_hashent);

  /* Release the option memory */
  free(option);
}

void
sasl_conf_free(sasl_conf_t *conf)
{
  common_verify(conf, SASL_CONF_MAGIC);

  /* Release all the entries first */
  hash_iter(&conf->sac_options, (db_iter_t)free_option, 0);

  /* Release the configuration memory */
  free(conf);
}
