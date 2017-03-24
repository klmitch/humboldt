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

#ifndef _HUMBOLDT_ALLOC_H
#define _HUMBOLDT_ALLOC_H

#include <stdlib.h>	/* for size_t */

#include "common.h"	/* for magic_t */

/** \brief Generic free list.
 *
 * Generic free list head.  For every object to be allocated with the
 * benefit of a free list, one of these structures must be allocated
 * and initialized with #FREELIST_INIT.
 */
typedef struct _freelist_s freelist_t;

/** \brief Free list item.
 *
 * Represent a single item in a free list.
 */
typedef struct _freeitem_s _freeitem_t;

/** \brief Flexible list.
 *
 * Represent a flexible list that grows dynamically.
 */
typedef struct _flexlist_s flexlist_t;

/** \brief Free list structure.
 *
 * This structure contains the definition of the free list head.
 */
struct _freelist_s {
  magic_t	fl_magic;	/**< Magic number */
  size_t	fl_size;	/**< Size of structures to allocate */
  unsigned int	fl_max;		/**< Maximum size of the free list */
  unsigned int	fl_alloc;	/**< Number of items allocated */
  unsigned int	fl_count;	/**< Number of items on the free list */
  _freeitem_t  *fl_freelist;	/**< The free list */
};

/** \brief Free list magic number.
 *
 * This is the magic number used for the free list structure.  It is
 * used to guard against programming problems, such as failure to
 * initialize a free list.
 */
#define FREELIST_MAGIC 0x7e5c2320

/** \brief Initialize a free list head.
 *
 * Initialize the head of a free list.  This is a static initializer
 * that ensures that the free list head is properly initialized.
 *
 * \param[in]		type	The type the free list tracks.
 * \param[in]		max	The maximum number of items to keep in
 *				the free list.  Use \c 0 to indicate
 *				an arbitrary number of items.
 */
#define FREELIST_INIT(type, max) {FREELIST_MAGIC, sizeof(type), max, 0, 0, 0}

/** \brief Determine memory allocation.
 *
 * Determine how much memory has been allocated for objects of this
 * type.  This is a total allocation, including not only elements on
 * the free list, but also objects currently in use.
 *
 * \param[in]		obj	A pointer to the free list head.
 *
 * \return	The total amount of memory allocated.
 */
#define freelist_allocated(obj)	((obj)->fl_size * (obj)->fl_alloc)

/** \brief Determine memory on the free list.
 *
 * Determine how much memory has been allocated for objects of this
 * type that are currently on the free list and not in use.
 *
 * \param[in]		obj	A pointer to the free list head.
 *
 * \return	The total amount of memory on the free list.
 */
#define freelist_extra(obj)	((obj)->fl_size * (obj)->fl_count)

/** \brief Free item structure.
 *
 * This structure contains the definition of a free list item.  This
 * is a convenience structure for threading the free list.
 */
struct _freeitem_s {
  _freeitem_t  *fi_next;	/**< Next element on the freelist */
};

/** \brief Flexible list structure.
 *
 * This structure contains the definition of a flexible list.  The
 * flexible list is initialized with the size of a type, and elements
 * may be queried from it.
 */
struct _flexlist_s {
  magic_t	fx_magic;	/**< Magic number */
  int		fx_count;	/**< Number of items in the list */
  int		fx_capacity;	/**< Total capacity of the list */
  size_t	fx_size;	/**< Size of an item */
  char	       *fx_contents;	/**< Contents of the list */
};

/** \brief Flexible list magic number.
 *
 * This is the magic number used for the flexible list structure.  It
 * is used to guard against programming problems, such as failure to
 * initialize a flexible list.
 */
#define FLEXLIST_MAGIC 0x775f243e

/** \brief Initialize a flexible list.
 *
 * Initialize a flexible list.  This is a static initializer that
 * ensures that the flexible list is properly initialized.
 *
 * \param[in]		type	The type the flexible list contains.
 */
#define FLEXLIST_INIT(type)	{FLEXLIST_MAGIC, 0, 0, sizeof(type), 0}

/** \brief Initialize a flexible list.
 *
 * Initialize a flexible list.  This differs from FLEXLIST_INIT() in
 * that this macro is designed for initializing dynamically allocated
 * memory.
 *
 * \param[in,out]	obj	A pointer to the flexible list.
 * \param[in]		type	The type the flexible list contains.
 */
#define flexlist_init(obj, type)		\
  do {						\
    flexlist_t *_fx = (obj);			\
    _fx->fx_count = 0;				\
    _fx->fx_capacity = 0;			\
    _fx->fx_size = sizeof(type);		\
    _fx->fx_contents = 0;			\
    _fx->fx_magic = FLEXLIST_MAGIC;		\
  } while (0)

/** \brief Determine the number of items in the list.
 *
 * Returns the number of items contained in the flexible list.
 *
 * \param[in]		obj	A pointer to the flexible list.
 *
 * \return	The number of items in the flexible list.
 */
#define flexlist_count(obj)	((obj)->fx_count)

/** \brief Pop an item off the end of a flexible list.
 *
 * This macro decrements the number of items contained in the flexible
 * list, essentially popping the last element off the list.
 *
 * \param[in,out]	obj	A pointer to the flexible list.
 */
#define flexlist_pop(obj)	((obj)->fx_count--)

/** \brief Determine memory consumed by the flexible list.
 *
 * Returns the amount of memory in use for representing the flexible
 * list.
 *
 * \param[in]		obj	A pointer to the flexible list.
 *
 * \return	The total amount of memory consumed by the flexible
 *		list.
 */
#define flexlist_allocated(obj)	((obj)->fx_capacity * (obj)->fx_size)

/** \brief Retrieve an item from a flexible list.
 *
 * Retrieve a specified item from the flexible list.  Note that this
 * macro performs no bounds checking.
 *
 * \param[in]		obj	A pointer to the flexible list.
 * \param[in]		i	The index of the item to retrieve.
 *
 * \return	A pointer to \c void containing the retrieved item.
 *		Note that this will need to be cast to the appropriate
 *		type.
 */
#define flexlist_item(obj, i)	((void *)((obj)->fx_contents +		\
					  (obj)->fx_size * (i)))

/** \brief Allocate an item.
 *
 * Allocate an item based on the definition of the free list head.
 *
 * \param[in,out]	freelist
 *				A pointer to the free list head.
 *
 * \return	An uninitialized item of the appropriate size, either
 *		allocate off the free list or obtained from the
 *		system.  If no memory is available, \c NULL is
 *		returned.
 */
void *alloc(freelist_t *freelist);

/** \brief Release an item.
 *
 * Release an item based on the definition of the free list head.  The
 * item may be either placed on the free list or released back to the
 * system; in either case, it should not be referenced after a call to
 * this function.
 *
 * \param[in,out]	freelist
 * 				A pointer to the free list head.
 * \param[in]		item	The item to be released.
 */
void release(freelist_t *freelist, void *item);

/** \brief Wipe the free list.
 *
 * Wipe out the free list.  This releases all items on the free list
 * back to the system.
 *
 * \param[in,out]	freelist
 * 				A pointer to the free list head.
 */
void wipe(freelist_t *freelist);

/** \brief Append an item to a flexible list.
 *
 * Extends the flexible list by one item.
 *
 * \param[in,out]	fx	A pointer to the flexible list.
 *
 * \return	A pointer to \c void containing the uninitialized item
 *		added to the flexible list.  Note that this will need
 *		to be cast to the appropriate type.  May return \c
 *		NULL if no more memory can be allocated.
 */
void *flexlist_append(flexlist_t *fx);

/** \brief Release a flexible list.
 *
 * Release all memory consumed by a flexible list.  After being
 * called, the flexible list will be empty.
 *
 * \param[in,out]	fx	A pointer to the flexible list.
 */
void flexlist_release(flexlist_t *fx);

#endif /* _HUMBOLDT_ALLOC_H */
