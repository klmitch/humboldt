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

#include <net/if.h> /* On some systems, must be included before ifaddrs.h */
#include <ifaddrs.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "include/alloc.h"
#include "include/common.h"
#include "include/db.h"
#include "include/endpoint.h"
#include "include/interfaces.h"

static void
add_iface(interfaces_t *ifs, struct sockaddr *sockaddr, int addrlen)
{
  interface_t *iface;

  /* Look out for special addresses */
  if (sockaddr->sa_family == AF_INET) {
    struct in_addr *addr = &((struct sockaddr_in *)sockaddr)->sin_addr;

    if (addr->s_addr == INADDR_ANY ||
	addr->s_addr == INADDR_BROADCAST ||
	addr->s_addr == INADDR_NONE ||
	IN_MULTICAST(addr->s_addr) ||
	IN_EXPERIMENTAL(addr->s_addr) ||
	IN_BADCLASS(addr->s_addr) ||
	/* Anything in the loopback network */
	((addr->s_addr & IN_CLASSA_NET) >> IN_CLASSA_NSHIFT) == IN_LOOPBACKNET)
      return;
  }
#ifdef AF_INET6
  else if (sockaddr->sa_family == AF_INET6) {
    struct in6_addr *addr = &((struct sockaddr_in6 *)sockaddr)->sin6_addr;

    if (IN6_IS_ADDR_UNSPECIFIED(addr) ||
	IN6_IS_ADDR_LOOPBACK(addr) ||
	IN6_IS_ADDR_LINKLOCAL(addr) ||
	IN6_IS_ADDR_SITELOCAL(addr) ||
	IN6_IS_ADDR_MULTICAST(addr))
      return;
  }
#endif

  /* Allocate an interface */
  if (!(iface = malloc(sizeof(interface_t))))
    return;

  /* Initialize the link */
  link_elem_init(&iface->if_link, iface);

  /* Initialize the address from the sockaddr */
  ep_addr_set_fromaddr(&iface->if_addr, sockaddr, addrlen);
  iface->if_addr.ea_flags &= ~EA_PORT; /* Haven't set the port */

  /* Set the magic number */
  iface->if_magic = INTERFACE_MAGIC;

  /* Add it to the list of interfaces */
  link_append(&ifs->ifs_interfaces, &iface->if_link);
}

static void
release_iface(interface_t *iface, void *extra)
{
  common_verify(iface, INTERFACE_MAGIC);

  /* Pop it off the list of interfaces */
  link_pop(&iface->if_link);

  /* Release the memory */
  free(iface);
}

void
interfaces_free(interfaces_t *ifs)
{
  common_verify(ifs, INTERFACES_MAGIC);

  /* Release all the interfaces */
  link_iter(&ifs->ifs_interfaces, (db_iter_t)release_iface, 0);

  /* Release the list, too */
  free(ifs);
}

interfaces_t *
interfaces_get(void)
{
  interfaces_t *ifs;
  struct ifaddrs *head, *iface;

  /* Allocate the list */
  if (!(ifs = malloc(sizeof(interfaces_t))))
    return 0;

  /* Initialize it */
  link_head_init(&ifs->ifs_interfaces);
  ifs->ifs_magic = INTERFACES_MAGIC;

  /* Get the interface addresses */
  if (getifaddrs(&head)) {
    free(ifs);
    return 0;
  }

  /* Step through the returned list of addresses */
  for (iface = head; iface; iface = iface->ifa_next) {
    /* Skip interfaces that are not up or that loop back */
    if ((iface->ifa_flags & (IFF_UP | IFF_LOOPBACK)) != IFF_UP)
      continue;

    /* Check if it's one of the address families we're interested in */
    switch (iface->ifa_addr->sa_family) {
    case AF_INET:
      add_iface(ifs, iface->ifa_addr, sizeof(struct sockaddr_in));
      break;

#ifdef AF_INET6
    case AF_INET6:
      add_iface(ifs, iface->ifa_addr, sizeof(struct sockaddr_in6));
      break;
#endif
    }
  }

  /* Release the memory allocated by getifaddrs() */
  freeifaddrs(head);

  return ifs;
}
