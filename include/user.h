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

#ifndef _HUMBOLDT_USER_H
#define _HUMBOLDT_USER_H

#include <regex.h>		/* for regex_t */
#include <sys/types.h>

/** \brief User database.
 *
 * The user database.  This contains a hash table of configured users
 * drawn from the configuration file, along with a linked list of user
 * entries that match by regular expression.
 */
typedef struct _userdb_s userdb_t;

/** \brief User database entry.
 *
 * A user in the user database.  This describes a single user,
 * including the configured password (if any) and what the user is
 * authorized to do.
 */
typedef struct _user_s user_t;

/** \brief User entry type.
 *
 * The possible flavors for a user entry.  User entries may be either
 * a fixed name (#USER_TYPE_BYNAME) or a POSIX extended regular
 * expression (#USER_TYPE_BYREGEX).
 */
typedef enum _user_type_e {
  USER_TYPE_UNKNOWN,		/**< User type is as-yet unknown */
  USER_TYPE_BYNAME,		/**< User type is by-name */
  USER_TYPE_BYREGEX		/**< User type is by-regex */
} user_type_t;

#include "common.h"		/* for magic_t */
#include "configuration.h"	/* for config_t, conf_ctx_t */
#include "db.h"			/* for hash_tab_t, etc. */
#include "yaml_util.h"		/* for yaml_ctx_t, yaml_node_t */

/** \brief User database structure.
 *
 * This structure contains the definition of the user database.
 */
struct _userdb_s {
  magic_t	udb_magic;	/**< Magic number */
  uint32_t	udb_flags;	/**< Flags */
  hash_tab_t	udb_users;	/**< User entries by name */
  link_head_t	udb_regex;	/**< User entries by regex */
};

/** \brief User database magic number.
 *
 * This is the magic number used for the user database structure.  It
 * is used to guard against programming problems, such as passing an
 * incorrect user database.
 */
#define USERDB_MAGIC 0xe3ca0a6d

/** \brief Initialize a user database.
 *
 * Initializes a user database object.
 *
 * \param[in,out]	obj	A pointer to the user database to
 *				initialize.
 */
#define userdb_init(obj)					\
  do {								\
    userdb_t *_udb = (obj);					\
    _udb->udb_flags = 0;					\
    hash_tab_init(&_udb->udb_users, db_str_hash, db_str_comp);	\
    link_head_init(&_udb->udb_regex);				\
    _udb->udb_magic = USERDB_MAGIC;				\
  } while (0)

/** \brief User database contains passwords.
 *
 * Used to indicate that the user database contains at least one
 * password.  This is used by the SASL module to set a password
 * verification callback that uses passwords from the user database.
 */
#define USERDB_FLAG_PASSWORDS	0x80000000

/** \brief User database entry structure.
 *
 * This structure contains the definition of entries in the user
 * database.
 */
struct _user_s {
  magic_t	u_magic;	/**< Magic number */
  hash_ent_t	u_hashent;	/**< Entry in the by-name hash table */
  link_elem_t	u_linkelem;	/**< Entry in the by-regex linked list */
  uint32_t	u_flags;	/**< Flags affecting the user entry */
  user_type_t	u_type;		/**< Type of user database entry */
  const char   *u_name;		/**< User name or name regex */
  const char   *u_passwd;	/**< User password (optional) */
  regex_t	u_regex;	/**< Compiled username regex */
};

/** \brief User database magic number.
 *
 * This is the magic number used for the user database entry
 * structure.  It is used to guard against programming problems, such
 * as passing an incorrect user database entry.
 */
#define USER_MAGIC 0x9da7b0c4

/** \brief Initialize a user database entry.
 *
 * Initializes a user database entry object.  Note that this DOES NOT
 * set the key for the hash table entry; that will need to be set
 * later with hash_ent_setkey().  This is because the entry key is the
 * user name, which is only relevant for #USER_TYPE_BYNAME entries,
 * and which is not available at the time the entry is initialized.
 *
 * \param[in,out]	obj	A pointer to the user database entry
 *				to initialize.
 */
#define user_init(obj)				\
  do {						\
    user_t *_u = (obj);				\
    hash_ent_init(&_u->u_hashent, _u, 0);	\
    link_elem_init(&_u->u_linkelem, _u);	\
    _u->u_flags = 0;				\
    _u->u_type = USER_TYPE_UNKNOWN;		\
    _u->u_name = 0;				\
    _u->u_passwd = 0;				\
    memset(&_u->u_regex, 0, sizeof(regex_t));	\
    _u->u_magic = USER_MAGIC;			\
  } while (0)

/** \brief User entry is invalid.
 *
 * Used to indicate that a user entry is invalid.  This allows the
 * configuration processing routines to later discard a user entry,
 * after reporting all problems that were encountered while attempting
 * to read it.
 */
#define USER_INVALID		0x80000000

/** \brief User authorized to be a peer.
 *
 * Used to indicate that a user entry is authorized to act as a peer.
 */
#define USER_AUTHZ_PEER		0x40000000

/** \brief User authorized to be a client.
 *
 * Used to indicate that a user entry is authorized to act as a
 * client.
 */
#define USER_AUTHZ_CLIENT	0x20000000

/** \brief User authorized to be an admin.
 *
 * Used to indicate that a user entry is authorized to act as an
 * admin.  This implies #USER_AUTHZ_CLIENT.
 */
#define USER_AUTHZ_ADMIN	0x10000000

/** \brief Process user database.
 *
 * This is the configuration processor specific to the user database.
 * It conforms to the #mapproc_t type, and is used to process the
 * "users" key from the configuration.
 *
 * \param[in]		key	The name of the key.
 * \param[in,out]	conf	A pointer to the top-level #config_t
 *				configuration structure.
 * \param[in]		ctx	The YAML file context.
 * \param[in]		value	The YAML node containing the value.
 */
void user_conf_processor(const char *key, config_t *conf,
			 yaml_ctx_t *ctx, yaml_node_t *value);

/** \brief Free user database.
 *
 * Used to free the memory consumed by the user database.  The user
 * database should not be referenced after calling this function.
 *
 * \param[in]		userdb	The user database.
 */
void user_conf_free(userdb_t *userdb);

/** \brief Look up user entry.
 *
 * Used to look up a matching user entry from the user database.
 * Exact matches are returned, but if no exact match is available,
 * regular expression entries will be explored in the order defined in
 * the configuration; the first matching entry will be returned.
 *
 * \param[in]		userdb	The user database.
 * \param[in]		username
 *				The username to look up in the user
 *				database.
 *
 * \return	A pointer to a matching user entry, or \c NULL if
 *		there are no matches.
 */
user_t *user_lookup(userdb_t *userdb, const char *username);

#endif /* _HUMBOLDT_USER_H */
