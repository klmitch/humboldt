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
    if (_le->le_next)					\
      _le->le_next->le_prev = _le->le_prev;		\
    if (_le->le_head && !--_le->le_head->lh_count) {	\
      _le->le_head->lh_first = 0;			\
      _le->le_head->lh_last = 0;			\
    }							\
    _le->le_head = 0;					\
  } while (0)

/** \brief Determine if an element is linked.
 *
 * Tests to see whether a linked list element is linked to a linked
 * list.
 *
 * \param[in]		elem	The element to check.
 *
 * \returns	A true value if the element is linked, false
 *		otherwise.
 */
#define linked(elem)	((elem)->le_head)

#endif /* _HUMBOLDT_DB_H */
