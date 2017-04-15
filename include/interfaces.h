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

#ifndef _HUMBOLDT_INTERFACES_H
#define _HUMBOLDT_INTERFACES_H

/** \brief List of system interfaces.
 *
 * Contains a linked list of the available system interface addresses.
 */
typedef struct _interfaces_s interfaces_t;

/** \brief System interface address.
 *
 * Contains one interface address.
 */
typedef struct _interface_s interface_t;

#include "common.h"
#include "db.h"
#include "endpoint.h"

/** \brief System interfaces structure.
 *
 * This structure contains the definition of the system interfaces
 * list.
 */
struct _interfaces_s {
  magic_t	ifs_magic;	/**< Magic number */
  link_head_t	ifs_interfaces;	/**< Interface addresses */
};

/** \brief Interfaces list magic number.
 *
 * This is the magic number used for the interfaces list structure.
 * It is used to guard against programming problems, such passing an
 * incorrect configuration.
 */
#define INTERFACES_MAGIC 0x2c2de4b7

/** \brief System interface structure.
 *
 * This structure contains the definition of a single system
 * interface.
 */
struct _interface_s {
  magic_t	if_magic;	/**< Magic number */
  link_elem_t	if_link;	/**< Linked list element */
  ep_addr_t	if_addr;	/**< Interface address */
};

/** \brief System interface magic number.
 *
 * This is the magic number used for the system interfaces structure.
 * It is used to guard against programming problems, such passing an
 * incorrect configuration.
 */
#define INTERFACE_MAGIC 0x5c2ce179

/** \brief Get the interfaces.
 *
 * Called to fill in a system interfaces list.
 *
 * \param[in,out]	ifs	The system interfaces list.
 *
 * \return	A true value for success, false otherwise.
 */
interfaces_t *interfaces_get(void);

/** \brief Release system interfaces memory.
 *
 * Releases the memory consumed by the list of system interfaces.
 *
 * \param[in,out]	ifs	The system interfaces list.
 */
void interfaces_free(interfaces_t *ifs);

#endif /* _HUMBOLDT_INTERFACES_H */
