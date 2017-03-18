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
