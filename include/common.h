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

#ifndef _HUMBOLDT_COMMON_H
#define _HUMBOLDT_COMMON_H

#include <stdint.h>

/** \brief Magic number type.
 *
 * Magic numbers are used throughout the code to guard against
 * programming problems, such as failure to initialize a free list, or
 * referencing an item after it is released.  This is a type to use
 * for magic numbers.
 */
typedef uint32_t magic_t;

/** \brief Type for common structure.
 *
 * Alias for objects having magic numbers.  This is used for
 * verification of objects.
 */
typedef struct _common_s _common_t;

/** \brief Common structure.
 *
 * This structure contains a field for a magic number as its first
 * element.  This is a convenience structure for verification of
 * objects.
 */
struct _common_s {
  magic_t	c_magic;	/**< Magic number */
};

/** \brief Type for comparison functions.
 *
 * This type is a convenience type for comparison functions for use
 * with the standard library bsearch() function.
 *
 * \param[in]		key	The key to search an array for.
 * \param[in]		member	A member of the array being searched.
 *
 * \return	A zero value if the key matches the member; otherwise,
 *		a value less than or greater than 0 if the \p key is
 *		less than or greater than \p member.
 */
typedef int (*compare_t)(const void *key, const void *member);

#endif /* _HUMBOLDT_COMMON_H */

#include <assert.h>	/* pick up current NDEBUG definition */

/** \brief Verify objects.
 *
 * Performs verification of objects by checking the object's magic
 * number against the one that is expected.  Verification uses
 * <CODE>assert()</CODE> to verify that the object is not \c NULL and
 * has the expected magic number; as such, this macro generates no
 * code if the macro \c NDEBUG was defined at the moment this header
 * was last included.
 *
 * \param[in]		obj	A pointer to the object to verify.
 * \param[in]		magic	The expected magic number.
 */
#undef common_verify
#ifdef NDEBUG
# define common_verify(obj, magic)	((void)0)
#else
# define common_verify(obj, magic)		\
  do {						\
    _common_t *_obj = (_common_t *)(obj);	\
    assert(_obj && _obj->c_magic == (magic));	\
  } while (0)
#endif
