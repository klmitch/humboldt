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

#include <regex.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "include/alloc.h"
#include "include/configuration.h"
#include "include/db.h"
#include "include/user.h"
#include "include/yaml_util.h"

static freelist_t users = FREELIST_INIT(user_t, 0);

static void
user_free(user_t *user, void *extra)
{
  /* Remove from the hash table and linked lists, as needed */
  if (hash_ent_linked(&user->u_hashent))
    hash_remove(&user->u_hashent);
  if (linked(&user->u_linkelem))
    link_pop(&user->u_linkelem);

  /* Free the username, if present */
  if (user->u_name)
    free((void *)user->u_name);

  /* Ditto for the password */
  if (user->u_passwd)
    free((void *)user->u_passwd);

  /* Free the regular expression */
  if (user->u_type == USER_TYPE_BYREGEX)
    regfree(&user->u_regex);

  /* Reinitialize the user */
  user_init(user);

  /* And release it back to the freelist */
  release(&users, user);
}

struct authz_map {
  const char *name;
  uint32_t flag;
};

struct authz_map authz_values[] = {
  {"admin", USER_AUTHZ_CLIENT | USER_AUTHZ_ADMIN},
  {"client", USER_AUTHZ_CLIENT},
  {"peer", USER_AUTHZ_PEER},
};

static int
authz_compare(const char *name, const struct authz_map *member)
{
  return strcmp(name, member->name);
}

static uint32_t
authz_lookup(const char *name)
{
  struct authz_map *result;

  if (!(result = (struct authz_map *)bsearch(name, authz_values,
					     list_count(authz_values),
					     sizeof(struct authz_map),
					     (compare_t)authz_compare)))
    return 0;

  return result->flag;
}

static void
proc_user_authz_all(int idx, user_t *user, yaml_ctx_t *ctx, yaml_node_t *value)
{
  conf_ctx_t conf_ctx = CONF_CTX_YAML(ctx, value);
  const char *authz;
  uint32_t authz_flag;

  common_verify(user, USER_MAGIC);

  /* Look up the authorization value */
  if (yaml_get_str(ctx, value, &authz, 0, 0)) {
    /* Look it up */
    if (!(authz_flag = authz_lookup(authz)))
      /* Note: Just log a warning, don't mark user invalid */
      config_report(&conf_ctx, LOG_WARNING,
		    "Unrecognized authorization value \"%s\"", authz);
    else
      user->u_flags |= authz_flag;
  } else
    user->u_flags |= USER_INVALID;
}

static void
proc_user_authz(const char *key, user_t *user, yaml_ctx_t *ctx,
		yaml_node_t *value)
{
  conf_ctx_t conf_ctx = CONF_CTX_YAML(ctx, value);
  const char *authz;
  uint32_t authz_flag;

  common_verify(user, USER_MAGIC);

  if (value->type == YAML_SEQUENCE_NODE)
    /* Process all the elements in the sequence */
    yaml_proc_sequence(ctx, value, (itemproc_t)proc_user_authz_all, user);
  else if (yaml_get_str(ctx, value, &authz, 0, 0)) {
    /* Single string */
    if (!(authz_flag = authz_lookup(authz)))
      /* Note: Just log a warning, don't mark user invalid */
      config_report(&conf_ctx, LOG_WARNING,
		    "Unrecognized authorization value \"%s\"", authz);
    else
      user->u_flags |= authz_flag;
  } else
    user->u_flags |= USER_INVALID;
}

static void
proc_user_name(const char *key, user_t *user, yaml_ctx_t *ctx,
	       yaml_node_t *value)
{
  conf_ctx_t conf_ctx = CONF_CTX_YAML(ctx, value);
  const char *name;

  common_verify(user, USER_MAGIC);

  /* Only one of name or name_regex may be specified */
  if (user->u_name) {
    config_report(&conf_ctx, LOG_WARNING,
		  "Only one of \"name\" or \"name_regex\" may be specified "
		  "for a user");
    user->u_flags |= USER_INVALID;
    return;
  }

  /* Grab the name */
  if (!yaml_get_str(ctx, value, &name, 0, 0)) {
    user->u_flags |= USER_INVALID;
    return;
  }

  /* Copy it into the entry */
  if (!(user->u_name = strdup(name))) {
    config_report(&conf_ctx, LOG_WARNING,
		  "Out of memory reading user database");
    user->u_flags |= USER_INVALID;
    return;
  }

  /* Set the entry type */
  user->u_type = USER_TYPE_BYNAME;
}

static void
proc_user_name_regex(const char *key, user_t *user, yaml_ctx_t *ctx,
		     yaml_node_t *value)
{
  conf_ctx_t conf_ctx = CONF_CTX_YAML(ctx, value);
  const char *name;
  int errcode;

  common_verify(user, USER_MAGIC);

  /* Only one of name or name_regex may be specified */
  if (user->u_name) {
    config_report(&conf_ctx, LOG_WARNING,
		  "Only one of \"name\" or \"name_regex\" may be specified "
		  "for a user");
    user->u_flags |= USER_INVALID;
    return;
  }

  /* Grab the name */
  if (!yaml_get_str(ctx, value, &name, 0, 0)) {
    user->u_flags |= USER_INVALID;
    return;
  }

  /* Copy it into the entry */
  if (!(user->u_name = strdup(name))) {
    config_report(&conf_ctx, LOG_WARNING,
		  "Out of memory reading user database");
    user->u_flags |= USER_INVALID;
    return;
  }

  /* Compile the regular expression */
  if ((errcode = regcomp(&user->u_regex, user->u_name, REG_EXTENDED))) {
    if (errcode == REG_ESPACE)
      config_report(&conf_ctx, LOG_WARNING,
		    "Out of memory reading user database");
    else {
      char errbuf[256];
      regerror(errcode, &user->u_regex, errbuf, sizeof(errbuf));
      config_report(&conf_ctx, LOG_WARNING,
		    "Failed to compile regular expression: %s", errbuf);
    }

    /* Free the regular expression buffer */
    regfree(&user->u_regex);

    user->u_flags |= USER_INVALID;
    return;
  }

  /* Set the entry type */
  user->u_type = USER_TYPE_BYREGEX;
}

static void
proc_user_password(const char *key, user_t *user, yaml_ctx_t *ctx,
		   yaml_node_t *value)
{
  conf_ctx_t conf_ctx = CONF_CTX_YAML(ctx, value);
  const char *passwd;

  common_verify(user, USER_MAGIC);

  /* Don't allow the password to be specified multiple times */
  if (user->u_passwd) {
    config_report(&conf_ctx, LOG_WARNING,
		  "The password may be specified at most once");
    user->u_flags |= USER_INVALID;
    return;
  }

  /* Grab the password */
  if (!yaml_get_str(ctx, value, &passwd, 0, 0)) {
    user->u_flags |= USER_INVALID;
    return;
  }

  /* Copy it into the entry */
  if (!(user->u_passwd = strdup(passwd))) {
    config_report(&conf_ctx, LOG_WARNING,
		  "Out of memory reading user database");
    user->u_flags |= USER_INVALID;
    return;
  }
}

static mapkeys_t user_config[] = {
  MAPKEY("authz", proc_user_authz),
  MAPKEY("name", proc_user_name),
  MAPKEY("name_regex", proc_user_name_regex),
  MAPKEY("password", proc_user_password)
};

static void
proc_user(int idx, userdb_t *userdb, yaml_ctx_t *ctx, yaml_node_t *value)
{
  conf_ctx_t conf_ctx = CONF_CTX_YAML(ctx, value);
  user_t *user;

  common_verify(userdb, USERDB_MAGIC);

  /* Allocate a user entry */
  if (!(user = alloc(&users))) {
    config_report(&conf_ctx, LOG_WARNING,
		  "Out of memory reading user database");
    return;
  }

  /* Initialize it */
  user_init(user);

  /* Process the user database entry */
  yaml_proc_mapping(ctx, value, 0, user_config, list_count(user_config), user);

  /* Validate the user entry */
  if (user->u_flags & USER_INVALID)
    user_free(user, 0);
  else
    switch (user->u_type) {
    case USER_TYPE_UNKNOWN:
      config_report(&conf_ctx, LOG_WARNING, "No user name or regex specified");
      user_free(user, 0);
      break;

    case USER_TYPE_BYNAME:
      /* Add user to the by-name hash table */
      hash_ent_setkey(&user->u_hashent, user->u_name);
      switch (hash_add(&userdb->udb_users, &user->u_hashent)) {
      case DBERR_NONE:
	break; /* add successful */

      case DBERR_DUPLICATE:
	config_report(&conf_ctx, LOG_WARNING, "User is a duplicate");
	user_free(user, 0);
	break;

      case DBERR_NOMEMORY:
	config_report(&conf_ctx, LOG_WARNING,
		      "Out of memory reading user database");
	user_free(user, 0);
	break;
      }
      break;

    case USER_TYPE_BYREGEX:
      /* Add user to the by-regex linked list */
      link_append(&userdb->udb_regex, &user->u_linkelem);
      break;
    }

  /* If the entry has a password, indicate that for the whole userdb */
  if (user->u_passwd)
    userdb->udb_flags |= USERDB_FLAG_PASSWORDS;
}

void
user_conf_processor(const char *key, config_t *conf, yaml_ctx_t *ctx,
		    yaml_node_t *value)
{
  conf_ctx_t conf_ctx = CONF_CTX_YAML(ctx, value);
  userdb_t *userdb;

  common_verify(conf, CONFIG_MAGIC);

  /* Construct a userdb_t object */
  if (!(userdb = malloc(sizeof(userdb_t)))) {
    config_report(&conf_ctx, LOG_WARNING,
		  "Out of memory reading user database");
    return;
  }

  /* Initialize the object */
  userdb_init(userdb);

  /* Save it to the configuration */
  conf->cf_userdb = userdb;

  /* Process all the elements in the sequence */
  yaml_proc_sequence(ctx, value, (itemproc_t)proc_user, userdb);
}

void
user_conf_free(userdb_t *userdb)
{
  /* Release all the users in the hash table */
  hash_iter(&userdb->udb_users, (db_iter_t)user_free, 0);
  hash_free(&userdb->udb_users);

  /* Ditto for the linked list */
  link_iter(&userdb->udb_regex, (db_iter_t)user_free, 0);

  /* Reinitialize the userdb */
  userdb_init(userdb);

  /* Clear the magic number */
  userdb->udb_magic = 0;

  /* Release back to the system */
  free(userdb);
}

user_t *
user_lookup(userdb_t *userdb, const char *username)
{
  link_elem_t *elem;
  user_t *user;
  regmatch_t matches[1];
  int namelen;

  /* If there's no database or username, do nothing */
  if (!userdb || !username)
    return 0;

  common_verify(userdb, USERDB_MAGIC);

  /* Try the hash table first */
  if ((user = hash_find(&userdb->udb_users, username)))
    return user;

  /* Will need the username length */
  namelen = strlen(username);

  /* OK, have to iterate through the linked list */
  for (elem = userdb->udb_regex.lh_first; elem; elem = elem->le_next) {
    user = elem->le_obj;

    /* See if it matches the regular expression */
    if (!regexec(&user->u_regex, username, 1, matches, 0) &&
	matches[0].rm_so == 0 && matches[0].rm_eo == namelen)
      return user;
  }

  /* No matching entries */
  return 0;
}
