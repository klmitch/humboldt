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

#ifndef _HUMBOLDT_DB_H
#define _HUMBOLDT_DB_H

#include <event2/util.h>	/* for ev_ssize_t */
#include <stdint.h>		/* for uint32_t */

#include "common.h"		/* for magic_t */

/** \brief Linked list head.
 *
 * Represents the head of a linked list.  This will keep track of the
 * number of elements, as well as the first and last element of the
 * list.
 */
typedef struct _link_head_s link_head_t;

/** \brief Linked list element.
 *
 * Represents an element on a linked list.  This keeps track of the
 * actual object associated with the element.
 */
typedef struct _link_elem_s link_elem_t;

/** \brief Hash table.
 *
 * Represents a hash table.
 */
typedef struct _hash_tab_s hash_tab_t;

/** \brief Hash table entry.
 *
 * Represents a hash table entry.
 */
typedef struct _hash_ent_s hash_ent_t;

/** \brief Hash value.
 *
 * Represents the hash value of a key for a hash table.
 */
typedef uint32_t hash_t;

/** \brief Database errors.
 *
 * The possible error codes for database functions.
 */
typedef enum _db_error_e {
  DBERR_NONE,		/**< No error */
  DBERR_DUPLICATE,	/**< Duplicate entry */
  DBERR_NOMEMORY	/**< Out of memory */
} db_error_t;

/** \brief Database key comparison callback.
 *
 * A callback that compares database keys.  The keys must be treated
 * consistently; that is, they must be treated as if they were of the
 * same type.
 *
 * \param[in]		key1	The first key to compare.
 * \param[in]		key2	The second key to compare.
 *
 * \return	A value less than, equal to, or greater than 0
 *		depending on whether \p key1 is less than, equal to,
 *		or greater than \p key2.
 */
typedef int (*db_comp_t)(const void *key1, const void *key2);

/** \brief Iteration callback.
 *
 * A callback that is called by one of the iteration functions, such
 * as link_iter() or hash_iter().  This callback will be invoked with
 * each object in turn.
 *
 * \param[in]		obj	The object.
 * \param[in]		extra	Extra data passed to the iteration
 *				function.
 */
typedef void (*db_iter_t)(void *obj, void *extra);

/** \brief Hash callback.
 *
 * A callback function that generates a hash of a key.  The hash is
 * expected to utilize the full range of a 32-bit unsigned integer.
 * It is suggested to utilize hash_fnv1a_update() to compute this
 * hash.
 *
 * \param[in]		key	The key object to generate a hash
 *				for.
 *
 * \return	The hash of the key.
 */
typedef hash_t (*hash_func_t)(const void *key);

/** \brief Linked list head structure.
 *
 * This structure describes the head of a linked list.
 */
struct _link_head_s {
  magic_t	lh_magic;	/**< Magic number */
  uint32_t	lh_count;	/**< Number of entries in the list */
  link_elem_t  *lh_first;	/**< First entry in the list */
  link_elem_t  *lh_last;	/**< Last entry in the list */
};

/** \brief Linked list head magic number.
 *
 * This is the magic number used for the linked list head.  It is used
 * to guard against programming problems, such as failure to
 * initialize a linked list head.
 */
#define LINK_HEAD_MAGIC 0x4c6155d7

/** \brief Initialize a linked list head.
 *
 * Initialize a linked list head.  This is a static initializer that
 * ensures that the linked list head is properly initialized.
 */
#define LINK_HEAD_INIT()	{LINK_HEAD_MAGIC, 0, 0, 0}

/** \brief Initialize a linked list head.
 *
 * Initialize a linked list head.  This is a dynamic initializer that
 * ensures that the linked list head is properly initialized.
 *
 * \param[in,out]	obj	A pointer to the linked list head.
 */
#define link_head_init(obj)			\
  do {						\
    link_head_t *_lh = (obj);			\
    _lh->lh_count = 0;				\
    _lh->lh_first = 0;				\
    _lh->lh_last = 0;				\
    _lh->lh_magic = LINK_HEAD_MAGIC;		\
  } while (0)

/** \brief Linked list element structure.
 *
 * This structure describes an element of a linked list.
 */
struct _link_elem_s {
  magic_t	le_magic;	/**< Magic number */
  link_elem_t  *le_next;	/**< Next element in the list */
  link_elem_t  *le_prev;	/**< Previous element in the list */
  void	       *le_obj;		/**< Object associated with this element */
  link_head_t  *le_head;	/**< Head of the linked list */
};

/** \brief Linked list element magic number.
 *
 * This is the magic number used for the linked list element.  It is
 * used to guard against programming problems, such as failure to
 * initialize a linked list element.
 */
#define LINK_ELEM_MAGIC 0x97cdf72a

/** \brief Initialize a linked list element.
 *
 * Initialize a linked list element.  This is a static initializer
 * that ensures that the linked list element is properly initialized.
 *
 * \param[in]		obj	The object the element references.
 */
#define LINK_ELEM_INIT(obj)	{LINK_ELEM_MAGIC, 0, 0, (obj), 0}

/** \brief Initialize a linked list element.
 *
 * Initialize a linked list element.  This is a dynamic initializer
 * that ensures that the linked list element is properly initialized.
 *
 * \param[in,out]	elem	A pointer to the linked list element.
 * \param[in]		obj	The object the element references.
 */
#define link_elem_init(elem, obj)		\
  do {						\
    link_elem_t *_le = (elem);			\
    _le->le_next = 0;				\
    _le->le_prev = 0;				\
    _le->le_obj = (obj);			\
    _le->le_head = 0;				\
    _le->le_magic = LINK_ELEM_MAGIC;		\
  } while (0)

/** \brief Append an element to a linked list.
 *
 * Append a given element to a linked list.
 *
 * \param[in,out]	list	The linked list to append the element
 *				to.
 * \param[in,out]	elem	The element to append to the linked
 *				list.
 */
#define link_append(list, elem)			\
  do {						\
    link_head_t *_lh = (list);			\
    link_elem_t *_le = (elem);			\
    common_verify(_lh, LINK_HEAD_MAGIC);	\
    common_verify(_le, LINK_ELEM_MAGIC);	\
    if (!_lh->lh_first) {			\
      _lh->lh_first = _le;			\
      _lh->lh_last = _le;			\
      _le->le_next = 0;				\
      _le->le_prev = 0;				\
    } else {					\
      _le->le_next = 0;				\
      _le->le_prev = _lh->lh_last;		\
      _lh->lh_last->le_next = _le;		\
      _lh->lh_last = _le;			\
    }						\
    _lh->lh_count++;				\
    _le->le_head = _lh;				\
  } while (0)

/** \brief Pop an element off a linked list.
 *
 * Remove a given element from the linked list it's attached to, if
 * any.
 *
 * \param[in,out]	elem	The element to pop off the linked
 *				list.
 */
#define link_pop(elem)					\
  do {							\
    link_elem_t *_le = (elem);				\
    common_verify(_le, LINK_ELEM_MAGIC);		\
    if (_le->le_prev)					\
      _le->le_prev->le_next = _le->le_next;		\
    else if (_le->le_head)				\
      _le->le_head->lh_first = _le->le_next;		\
    if (_le->le_next)					\
      _le->le_next->le_prev = _le->le_prev;		\
    else if (_le->le_head)				\
      _le->le_head->lh_last = _le->le_prev;		\
    if (_le->le_head)					\
      _le->le_head->lh_count--;				\
    _le->le_head = 0;					\
  } while (0)

/** \brief Determine if an element is linked.
 *
 * Tests to see whether a linked list element is linked to a linked
 * list.
 *
 * \param[in]		elem	The element to check.
 *
 * \return	A true value if the element is linked, false
 *		otherwise.
 */
#define linked(elem)	((elem)->le_head)

/** \brief Iterate over a linked list.
 *
 * Iterates over every element in a linked list.  It is safe for
 * entries to be removed during the iteration.
 *
 * \param[in]		list	The list to iterate over.
 * \param[in]		func	The iteration function to call.
 * \param[in]		extra	Extra data to be passed to \p func.
 */
#define link_iter(list, func, extra)			\
  do {							\
    link_head_t *_lh = (list);				\
    db_iter_t _func = (func);				\
    void *_extra = (extra);				\
    link_elem_t *_elem, *_next;				\
    for (_elem = _lh->lh_first; _elem; _elem = _next) {	\
      _next = _elem->le_next;				\
      _func(_elem->le_obj, _extra);			\
    }							\
  } while (0)

/** \brief Hash table structure.
 *
 * This structure describes a hash table.
 */
struct _hash_tab_s {
  magic_t	ht_magic;	/**< Magic number */
  uint32_t	ht_flags;	/**< Table flags */
  uint32_t	ht_modulus;	/**< Modulus of the table (prime) */
  uint32_t	ht_pending;	/**< Pending new modulus of the table */
  uint32_t	ht_count;	/**< Number of elements in the table */
  uint32_t	ht_rollover;	/**< Size at which to grow */
  uint32_t	ht_rollunder;	/**< Size at which to shrink */
  link_head_t  *ht_table;	/**< Hash table entries */
  hash_func_t	ht_func;	/**< Function to compute entry hash */
  db_comp_t	ht_comp;	/**< Function to compare entries */
};

/** \brief Hash table magic number.
 *
 * This is the magic number used for the hash table.  It is used to
 * guard against programming problems, such as failure to initialize a
 * hash table.
 */
#define HASH_TAB_MAGIC 0xe0aa785a

/** \brief Initialize a hash table.
 *
 * Initialize a hash table.  This is a static initializer that ensures
 * that the hash table is properly initialized.
 *
 * \param[in]		func	The function to compute an entry hash.
 * \param[in]		comp	The function to compare entry keys.
 */
#define HASH_TAB_INIT(func, comp)			\
  {HASH_TAB_MAGIC, 0, 0, 0, 0, 0, 0, 0, (func), (comp)}

/** \brief Initialize a hash table.
 *
 * Initialize a hash table.  This is a dynamic initializer that
 * ensures that the hash table is properly initialized.
 *
 * \param[in,out]	obj	A pointer to the hash table.
 * \param[in]		func	The function to compute an entry hash.
 * \param[in]		comp	The function to compare entry keys.
 */
#define hash_tab_init(obj, func, comp)		\
  do {						\
    hash_tab_t *_ht = (obj);			\
    _ht->ht_flags = 0;				\
    _ht->ht_modulus = 0;			\
    _ht->ht_pending = 0;			\
    _ht->ht_count = 0;				\
    _ht->ht_rollover = 0;			\
    _ht->ht_rollunder = 0;			\
    _ht->ht_table = 0;				\
    _ht->ht_func = (func);			\
    _ht->ht_comp = (comp);			\
    _ht->ht_magic = HASH_TAB_MAGIC;		\
  } while (0)

/** \brief Hash table frozen flag.
 *
 * This flag is set by the hash_iter() function to communicate to the
 * rest of the hash table functions that iteration is in progress.
 * This allows entries to be removed from a hash table during
 * iteration without causing the table to be reordered.
 */
#define HASH_FLAG_FROZEN	0x80000000

/** \brief Hash table resize pending flag.
 *
 * This flag is set internally during iteration by hash_iter() to
 * indicate that the hash table needs to be resized once iteration is
 * complete.
 */
#define HASH_FLAG_PENDING	0x40000000

/** \brief Hash table entry structure.
 *
 * This structure describes an entry in a hash table.
 */
struct _hash_ent_s {
  magic_t	he_magic;	/**< Magic number */
  link_elem_t	he_elem;	/**< Linked list element */
  void	       *he_obj;		/**< Object associated with this entry */
  const void   *he_key;		/**< Object key for this entry */
  hash_t	he_hash;	/**< Entry absolute hash */
  hash_tab_t   *he_table;	/**< Hash table entry is in */
};

/** \brief Hash table entry magic number.
 *
 * This is the magic number used for hash table entries.  It is used
 * to guard against programming problems, such as failure to
 * initialize a hash table entry.
 */
#define HASH_ENT_MAGIC 0x7bda1e68

/** \brief Initialize a hash table entry.
 *
 * Initialize a hash table entry.  This is a dynamic initializer that
 * ensures that the hash table entry is properly initialized.
 *
 * \param[in,out]	ent	A pointer to the hash table entry.
 * \param[in]		obj	The object the entry references.
 * \param[in]		key	The object acting as a key for the
 *				entry.
 */
#define hash_ent_init(ent, obj, key)		\
  do {						\
    hash_ent_t *_he = (ent);			\
    link_elem_init(&_he->he_elem, _he);		\
    _he->he_obj = (obj);			\
    _he->he_key = (key);			\
    _he->he_table = 0;				\
    _he->he_hash = 0;				\
    _he->he_magic = HASH_ENT_MAGIC;		\
  } while (0)

/** \brief Set a hash table entry key.
 *
 * Some hash table entries are allocated before the key on the entry
 * can be set.  This macro allows the key of a dynamically allocated
 * hash table entry to be set after the entry has been initialized.
 *
 * \param[in,out]	ent	A pointer to the hash table entry.
 * \param[in]		key	The object acting as a key for the
 *				entry.
 */
#define hash_ent_setkey(ent, key)	((ent)->he_key = (key))

/** \brief Determine if an entry is linked.
 *
 * Tests to see whether a hash table entry is linked to a hash table.
 *
 * \param[in]		ent	The hash table entry.
 *
 * \return	A true value if the entry is linked, false otherwise.
 */
#define hash_ent_linked(ent)	((ent)->he_table)

/** \brief Implementation of FNV-1a.
 *
 * This is an implementation of the FNV-1a hash (documented at
 * http://www.isthe.com/chongo/tech/comp/fnv/).  This is meant for use
 * by routines implementing the #hash_func_t callback.  Given an
 * initial hash value (use #HASH_INIT to initialize prior to the first
 * call), it adds additional \p data to the hash value and returns the
 * result.
 *
 * \param[in]		partial	The hash value so far accumulated.
 *				For the first call, initialize to
 *				#HASH_INIT.
 * \param[in]		data	The data to accumulate to the hash.
 * \param[in]		len	The size of the data to accumulate.
 *				If negative, the data will be
 *				accumulated up to, but not including,
 *				a NUL value; this allows strings to be
 *				used as well as binary data.
 *
 * \return	The resulting hash value, which may be passed to a
 *		subsequent invocation of hash_fnv1a_update() or
 *		returned by a #hash_func_t function.
 */
hash_t hash_fnv1a_update(hash_t partial, const void *data, ev_ssize_t len);

/** \brief Compare strings.
 *
 * This is a #db_comp_t compatible function for comparing two
 * strings.  It is provided for convenience for when the keys are
 * standard C strings.
 *
 * \param[in]		key1	The first string to compare.
 * \param[in]		key2	The second string to compare.
 *
 * \return	A value less than, equal to, or greater than 0
 *		depending on whether \p key1 is less than, equal to,
 *		or greater than \p key2.
 */
int db_str_comp(const void *key1, const void *key2);

/** \brief Hash a string.
 *
 * This is a #hash_func_t compatible function for hashing a string.
 * It is provided for convenience for when the keys are standard C
 * strings.
 *
 * \param[in]		key	The string to generate a hash for.
 *
 * \return	The hash of the string.
 */
hash_t db_str_hash(const void *key);

/** \brief Initial hash value.
 *
 * This is the value that should be passed to the first invocation of
 * the hash_fnv1a_update() function.
 */
#define HASH_INIT	2166136261UL

/** \brief Add an entry to a hash table.
 *
 * Adds an entry to a hash table.  The entry is assumed to not already
 * be in a table.
 *
 * \param[in,out]	table	The table to add the entry to.
 * \param[in,out]	entry	The entry to add.
 *
 * \retval DBERR_NONE		The addition was successful.
 * \retval DBERR_DUPLICATE	An entry with an identical key already
 *				exists in the table.
 * \retval DBERR_NOMEMORY	No memory could be allocated.
 */
db_error_t hash_add(hash_tab_t *table, hash_ent_t *entry);

/** \brief Remove an entry from a hash table.
 *
 * Removes a hash table entry from a hash table.
 *
 * \param[in,out]	entry	The entry to remove.
 */
void hash_remove(hash_ent_t *entry);

/** \brief Find an entry in a hash table.
 *
 * Find an entry in the table with the given \p key.
 *
 * \param[in]		table	The hash table to search.
 * \param[in]		key	The key to search for.
 *
 * \return	The desired entry, or \c NULL if no matching entry
 *		exists in the table.
 */
void *hash_find(hash_tab_t *table, const void *key);

/** \brief Iterate over a hash table.
 *
 * Iterates over every element in a hash table.  It is safe for
 * entries to be removed during the iteration.
 *
 * \param[in]		table	The table to iterate over.
 * \param[in]		func	The iteration function to call.
 * \param[in]		extra	Extra data to be passed to \p func.
 */
void hash_iter(hash_tab_t *table, db_iter_t func, void *extra);

/** \brief Release hash table memory.
 *
 * Releases memory allocated for a hash table.  Note that this will
 * not attempt to release any of the hash table entries; to prevent
 * memory leaks, it is necessary to use hash_iter() to release the
 * entries before calling this function.
 *
 * \param[in,out]	table	The table to release.
 */
void hash_free(hash_tab_t *table);

#endif /* _HUMBOLDT_DB_H */
