#ifndef _HUMBOLDT_NODE_H
#define _HUMBOLDT_NODE_H

#include <uuid.h>

#include "common.h"

typedef struct _node_s node_t;

typedef struct _link_s link_t;

typedef struct _route_s route_t;

struct _route_s {
  magic_t	r_magic;	/**< Magic number */
  route_t      *r_parent;	/**< Parent node in the priority queue */
  route_t      *r_left;		/**< Left child in the priority queue */
  route_t      *r_right;	/**< Right child in the priority queue */
  node_t       *r_target;	/**< Target of this route */
  unsigned int	r_cost;		/**< Cost of using this route */
  node_t       *r_next;		/**< Next hop in the route */
};

#define ROUTE_MAGIC 0xe7cd4f16

struct _node_s {
  magic_t	n_magic;	/**< Magic number */
  node_color_t	n_color;	/**< Node color, for red-black tree */
  node_t       *n_parent;	/**< Parent node in red-black tree */
  node_t       *n_left;		/**< Left child in red-black tree */
  node_t       *n_right;	/**< Right child in red-black tree */
  uuid_t	n_id;		/**< Node ID */
  unsigned int	n_link_count;	/**< Number of links */
  link_t       *n_link_table;	/**< Link table */
  route_t      *n_primary;	/**< Primary route for reaching node */
  route_t      *n_secondary;	/**< Secondary route for reaching node */
  route_t	n_storage[2];	/**< Storage for primary and secondary */
};

#define NODE_MAGIC 0xb8de12c

#endif /* _HUMBOLDT_NODE_H */
