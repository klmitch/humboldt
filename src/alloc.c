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

#include <stdlib.h>

#include "include/alloc.h"
#include "include/common.h"

void *
alloc(freelist_t *freelist)
{
  void *result;

  common_verify(freelist, FREELIST_MAGIC);

  /* Check to see if there's something on the free list */
  if ((result = freelist->fl_freelist)) {
    /* Pop it off the list */
    freelist->fl_freelist = ((_freeitem_t *)result)->fi_next;
    freelist->fl_count--;
  } else {
    /* Try to allocate a new one */
    result = malloc(freelist->fl_size);
    if (result)
      /* Keep a count of what we've allocated */
      freelist->fl_alloc++;
  }

  return result;
}

void
release(freelist_t *freelist, void *item)
{
  _freeitem_t *freeitem = (_freeitem_t *)item;

  common_verify(freelist, FREELIST_MAGIC);

  /* Check to see which flavor of release we need */
  if (freelist->fl_max && freelist->fl_count >= freelist->fl_max) {
    /* Free item and update allocated count */
    free(item);
    freelist->fl_alloc--;
  } else {
    /* Add it to the free list */
    freeitem->fi_next = freelist->fl_freelist;
    freelist->fl_freelist = freeitem;
    freelist->fl_count++;
  }
}

void
wipe(freelist_t *freelist)
{
  _freeitem_t *item, *next;

  common_verify(freelist, FREELIST_MAGIC);

  /* Walk the free list and free each item */
  for (item = freelist->fl_freelist, next = freelist->fl_freelist->fi_next;
       item; item = next, next = next->fi_next)
    free(item);

  /* Update the counts and zero the freelist */
  freelist->fl_alloc -= freelist->fl_count;
  freelist->fl_count = 0;
  freelist->fl_freelist = 0;
}
