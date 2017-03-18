#include "alloc.h"
#include "node.h"

static freelist_t free_nodes = FREELIST_INIT(node_t, 0);
