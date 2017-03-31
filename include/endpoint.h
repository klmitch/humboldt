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

#ifndef _HUMBOLDT_ENDPOINT_H
#define _HUMBOLDT_ENDPOINT_H

#include <netinet/in.h>		/* for sockaddr_in, sockaddr_in6 */
#include <stdint.h>		/* for uint32_t */
#include <string.h>		/* for memset() */
#include <sys/socket.h>		/* for AF_UNSPEC */
#include <sys/un.h>		/* for sockaddr_un */
#include <yaml.h>		/* for yaml_node_t */

#include "alloc.h"		/* for flexlist_t */
#include "common.h"		/* for magic_t */

/* Ensure we have AF_LOCAL if possible */
#if !defined(AF_LOCAL) && defined(AF_UNIX)
# define AF_LOCAL		AF_UNIX
#endif

/** \brief Endpoint address.
 *
 * Represents the endpoint address, which is characterized by an
 * address family and either a path name (local addresses), or an IPv4
 * or IPv6 address and a port number.  This is used as a member of the
 * other endpoint structures, including the #ep_network_t structure.
 */
typedef struct _ep_addr_s ep_addr_t;

/** \brief Endpoint advertisement.
 *
 * Endpoints must be advertised to the network for Humboldt to be able
 * to connect to them.  This structure represents an advertisement,
 * which may not be the same as the endpoint address (in the case of,
 * e.g., NAT gateways or interfaces only available on specific
 * networks).
 */
typedef struct _ep_ad_s ep_ad_t;

/** \brief Endpoint configuration.
 *
 * Represent the configuration of an endpoint.  This includes not only
 * the host IP and port to bind to, but also other data such as the
 * endpoint type.
 */
typedef struct _ep_config_s ep_config_t;

/** \brief Endpoint network.
 *
 * Some endpoints may be advertised as belonging to specific
 * networks.  This structure represents a given network, including an
 * optional local address to bind when attempting to connect to an
 * endpoint on the same network.
 */
typedef struct _ep_network_s ep_network_t;

/** \brief Endpoint type.
 *
 * Endpoints come in two flavors: client endpoints, which only
 * Humboldt clients connect to; and peer endpoints, which only other
 * instances of Humboldt connect to.  Note that local endpoints are
 * required to be client endpoints, and that non-local endpoints
 * default to be peer endpoints.
 */
typedef enum _ep_type_e {
  ENDPOINT_UNKNOWN,		/**< Endpoint type is not known */
  ENDPOINT_CLIENT,		/**< Endpoint is a client endpoint */
  ENDPOINT_PEER			/**< Endpoint is a peer endpoint */
} ep_type_t;

/** \brief Endpoint address structure.
 *
 * This structure contains the endpoint address.
 */
struct _ep_addr_s {
  uint32_t	ea_flags;		/**< Validity flags */
  union _ep_addr_u {
    struct sockaddr	eau_addr;	/**< Generic address */
    struct sockaddr_in	eau_ip4;	/**< IPv4 address */
#ifdef AF_INET6
    struct sockaddr_in6	eau_ip6;	/**< IPv6 address */
#endif
#ifdef AF_LOCAL
    struct sockaddr_un	eau_local;	/**< Local address */
#endif
  }		ea_addr;		/**< Endpoint address */
  int		ea_addrlen;		/**< Size of address */
};

/** \brief Indicates that the address is invalid.
 *
 * This flag is used to indicate that at least one of the components
 * that were used to fill in the address was invalid.
 */
#define EA_INVALID		0x80000000

/** \brief Indicates that a local address was given.
 *
 * This flag indicates that an \c AF_LOCAL address was provided.
 */
#define EA_LOCAL		0x40000000

/** \brief Indicates that an IP address was given.
 *
 * This flag indicates that an IP address was given.
 */
#define EA_IPADDR		0x20000000

/** \brief Indicates that an IP port was given.
 *
 * This flag indicates that an IP port was given.  If the address
 * family was not set at the time the IP port was set, the port will
 * be tentatively stored in the \c eau_ip4 member; care should be
 * taken to not overwrite it.
 */
#define EA_PORT			0x10000000

/** \brief Initialize endpoint address.
 *
 * Initialize an endpoint address structure.  This sets the address to
 * all zeros.
 *
 * \param[in,out]	obj	A pointer to the endpoint address.
 */
#define ep_addr_init(obj)					\
  do {								\
    ep_addr_t *_ea = (obj);					\
    _ea->ea_flags = 0;						\
    memset((void *)&_ea->ea_addr, 0, sizeof(_ea->ea_addr));	\
    _ea->ea_addrlen = 0;					\
  } while (0)

#define NETWORK_LEN	16

/** \brief Endpoint advertisement structure.
 *
 * This structure contains the representation of an endpoint
 * advertisement.
 */
struct _ep_ad_s {
  magic_t	epa_magic;	/**< Magic number */
  uint32_t	epa_flags;	/**< Advertisement flags */
  ep_addr_t	epa_addr;	/**< Address to advertise */
  char		epa_network[NETWORK_LEN + 1];
				/**< Optional name of endpoint network */
  ep_config_t  *epa_config;	/**< Corresponding configuration */
};

/** \brief Endpoint advertisement magic number.
 *
 * This is the magic number used for the endpoint advertisement
 * structure.  It is used to guard against programming problems, such
 * as failure to initialize an endpoint advertisement.
 */
#define EP_AD_MAGIC 0xb68d9a45

/** \brief Indicates endpoint advertisement is invalid.
 *
 * This flag is used to indicate that at least one of the components
 * that were used to fill in the endpoint advertisement was invalid.
 */
#define EP_AD_INVALID		0x80000000

/** \brief Initialize endpoint advertisement.
 *
 * Initialize an endpoint advertisement structure.  This initializes
 * the address and points the advertisement to the appropriate
 * endpoint configuration.
 *
 * \param[in,out]	obj	A pointer to the endpoint
 *				advertisement.
 * \param[in]		epconf	A pointer to the endpoint
 *				configuration which corresponds to the
 *				advertisement.
 */
#define ep_ad_init(obj, epconf)			\
  do {						\
    ep_ad_t *_epa = (obj);			\
    _epa->epa_flags = 0;			\
    ep_addr_init(&_epa->epa_addr);		\
    _epa->epa_network[0] = '\0';		\
    _epa->epa_config = (epconf);		\
    _epa->epa_magic = EP_AD_MAGIC;		\
  } while (0)

/** \brief Endpoint configuration structure.
 *
 * This structure contains the representation of an endpoint
 * configuration.
 */
struct _ep_config_s {
  magic_t	epc_magic;	/**< Magic number */
  uint32_t	epc_flags;	/**< Endpoint flags */
  ep_addr_t	epc_addr;	/**< Address to listen on */
  ep_type_t	epc_type;	/**< Address type: client or peer */
  flexlist_t	epc_ads;	/**< List of advertisements */
};

/** \brief Endpoint configuration magic number.
 *
 * This is the magic number used for the endpoint configuration
 * structure.  It is used to guard against programming problems, such
 * as failure to initialize an endpoint configuration.
 */
#define EP_CONFIG_MAGIC 0x8d88bb1d

/** \brief Indicates endpoint is invalid.
 *
 * This flag is used to indicate that at least one of the components
 * that were used to fill in the endpoint configuration was invalid.
 */
#define EP_CONFIG_INVALID	0x80000000

/** \brief Do not advertise endpoint.
 *
 * An endpoint configuration flag that indicates that the endpoint
 * should not be advertised.
 */
#define EP_CONFIG_UNADVERTISED	0x40000000

/** \brief Initialize endpoint configuration.
 *
 * Initialize an endpoint configuration structure.  This initializes
 * the address and the list of advertisements, clears flags, and sets
 * the endpoint type to #ENDPOINT_UNKNOWN.
 *
 * \param[in,out]	obj	A pointer to the endpoint
 *				configuration.
 */
#define ep_config_init(obj)			\
  do {						\
    ep_config_t *_epc = (obj);			\
    _epc->epc_flags = 0;			\
    ep_addr_init(&_epc->epc_addr);		\
    _epc->epc_type = ENDPOINT_UNKNOWN;		\
    flexlist_init(&_epc->epc_ads, ep_ad_t);	\
    _epc->epc_magic = EP_CONFIG_MAGIC;		\
  } while (0)

/** \brief Endpoint network structure.
 *
 * This structure contains the representation of an endpoint network.
 */
struct _ep_network_s {
  magic_t	epn_magic;	/**< Magic number */
  uint32_t	epn_flags;	/**< Network flags */
  char		epn_name[NETWORK_LEN + 1];
				/**< Network name */
  ep_addr_t	epn_addr;	/**< Local address to use for outgoing
				     connections on this network */
};

/** \brief Endpoint network magic number.
 *
 * This is the magic number used for the endpoint network structure.
 * It is used to guard against programming problems, such as failure
 * to initialize an endpoint network.
 */
#define EP_NETWORK_MAGIC 0xfe39257

/** \brief Indicates network is invalid.
 *
 * This flag is used to indicate that at least one of the components
 * that were used to fill in the network was invalid.
 */
#define EP_NETWORK_INVALID	0x80000000

/** \brief Initialize endpoint network.
 *
 * Initialize an endpoint network structure.  This initializes the
 * address and sets the network name to \c NULL.
 */
#define ep_network_init(obj)			\
  do {						\
    ep_network_t *_epn = (obj);			\
    _epn->epn_flags = 0;			\
    _epn->epn_name[0] = '\0';			\
    ep_addr_init(&_epn->epn_addr);		\
    _epn->epn_magic = EP_NETWORK_MAGIC;		\
  } while (0)

/* Note: included from configuration.h so try to avoid include loop */

#include "yaml_util.h"

/** \brief Set a local address.
 *
 * Sets an address (an #ep_addr_t) to be a "local" address.
 *
 * \param[in,out]	addr	The address structure to be updated.
 * \param[in]		path	The local address path.  May not be \c
 *				NULL.
 * \param[in]		ctx	The YAML file context.
 * \param[in]		value	The YAML node being processed.
 *
 * \return	A false value if an error occurred, true otherwise.
 */
int ep_addr_set_local(ep_addr_t *addr, const char *path,
		      yaml_ctx_t *ctx, yaml_node_t *value);

/** \brief Set an IP address.
 *
 * Sets an address (an #ep_addr_t) to be an IP address.  Both IPv4 and
 * (if the system supports it) IPv6 can be used.
 *
 * \param[in,out]	addr	The address structure to be updated.
 * \param[in]		pres	The presentation form of the IP
 *				address.
 * \param[in]		ctx	The YAML file context.
 * \param[in]		value	The YAML node being processed.
 *
 * \return	A false value if an error occurred, true otherwise.
 */
int ep_addr_set_ipaddr(ep_addr_t *addr, const char *pres,
		       yaml_ctx_t *ctx, yaml_node_t *value);

/** \brief Set an IP port.
 *
 * Sets an address (an #ep_addr_t) to include an IP port number.
 *
 * \param[in,out]	addr	The address structure to be updated.
 * \param[in]		port	The port number.
 * \param[in]		ctx	The YAML file context.
 * \param[in]		value	The YAML node being processed.
 *
 * \return	A false value if an error occurred, true otherwise.
 */
int ep_addr_set_port(ep_addr_t *addr, int port,
		     yaml_ctx_t *ctx, yaml_node_t *value);

/** \brief Copy address default.
 *
 * Fill in the unprovided portions of \p dest from \p src.
 *
 * \param[in,out]	dest	The address to fill in.
 * \param[in]		src	The address to fill in from.
 */
void ep_addr_default(ep_addr_t *dest, ep_addr_t *src);

/** \brief Describe an address.
 *
 * Fills a buffer with a description of the socket.  For local
 * addresses, this will be the socket path enclosed in square brackets
 * ("[]").  For plain ports with no address, this will be of the form
 * "[]:1234", with the port number following the colon ("1234" in the
 * example).  For IPv4 addresses, this will be of the form
 * "127.0.0.1:1234", and for IPv6 addresses, this will be of the form
 * "[::1]:1234", again with the port number following the last colon.
 * If the port number is unspecified, it will be 0.
 *
 * \param[in]		addr	The address to describe.
 * \param[in,out]	buf	The buffer to place the address into.
 * \param[in]		buflen	The size of the buffer.
 *
 * \return	A pointer to \p addr, for convenience.
 */
const char *ep_addr_describe(ep_addr_t *addr, char *buf, size_t buflen);

/** \brief Address description buffer size.
 *
 * This is a suggested amount of memory to set aside for an address
 * description.
 */
#define ADDR_DESCRIPTION	256

/** \brief Release endpoint advertisement.
 *
 * This function ensures that all memory allocated to represent a
 * given endpoint advertisement is released.
 *
 * \param[in,out]	ad	The endpoint advertisement to
 *				release.
 */
void ep_ad_release(ep_ad_t *ad);

/** \brief Release endpoint configuration.
 *
 * This function ensures that all memory allocated to represent a
 * given endpoint configuration is released.
 *
 * \param[in,out]	endpoint
 *				The endpoint configuration to
 *				release.
 */
void ep_config_release(ep_config_t *endpoint);

/** \brief Release endpoint network.
 *
 * This function ensures that all memory allocated to represent a
 * given endpoint network is released.
 *
 * \param[in,out]	network	The endpoint network to release.
 */
void ep_network_release(ep_network_t *network);

#endif /* _HUMBOLDT_ENDPOINT_H */
