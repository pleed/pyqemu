/**

  @file
  
  @brief Implementation of a very simple single linked list.
    
  Part of Georgios Portokalidis' Aho Corasick algorithm.
  
  ----
  
  Fairly Fast Packet Filter
  http://ffpf.sourceforge.net/

  Copyright (c), 2003 - 2004 Georgios Portokalidis, Herbert Bos & Willem de Bruijn
  contact info : wdebruij_AT_users.sourceforge.net

  ----
  
  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

*/

#include "xalloc.h"

#ifdef __KERNEL__
#include <linux/string.h>
#else
#include <string.h>
#endif


#include "slist.h"

/** \brief Append data to list
	\param list a pointer to a list
	\param data the data to place in the list
	\return 0 on success, or -1 on failure
*/
int
slist_append(slist_t *list,void *data)
{
	slist_node_t *node;

	if ( (node = xalloc(sizeof(slist_node_t))) == NULL )
			return -1;

	node->data = data;
	node->next = NULL;

	if ( slist_head(list) == NULL )
		slist_head(list) = node;
	else
		slist_next(slist_tail(list)) = node;

	slist_tail(list) = node;
	++slist_size(list);

	return 0;
}

/** \brief Prepend data to list
	\param list a pointer to list
	\param data the data to place in the list
	\return 0 on success, or -1 on failure
*/
int
slist_prepend(slist_t *list,void *data)
{
	slist_node_t *node;

	if ( (node = xalloc(sizeof(slist_node_t))) == NULL )
			return -1;
	
	slist_data(node) = data;
	slist_next(node) = slist_head(list);

	slist_head(list) = node;
	if ( slist_tail(list) == NULL )
		slist_tail(list) = node;
	++slist_size(list);

	return 0;
}

/** \brief Pop the first element in the list
	\param list a pointer to a list
	\return a pointer to the element, or NULL if the list is empty
*/
void *
slist_pop_first(slist_t *list)
{
	void *d;
	slist_node_t *node;

	if ( slist_head(list) == NULL )
		return NULL;

	d = slist_data((node = slist_head(list)));
	slist_head(list) = slist_next(node);
	xfree(node);
	if ( --slist_size(list) == 0 )
		slist_tail(list) = NULL;
	return d;
}

/** \ brief Initialize a single linked list
	\param list the list to initialize
*/
void
slist_init(slist_t *list)
{
	slist_head(list) = slist_tail(list) = NULL;
	slist_size(list) = 0;
}

/** \brief Destroy and de-allocate the memory hold by a list
	\param list a pointer to an existing list
	\param dealloc flag that indicates whether stored data should also be de-allocated
*/
void
slist_destroy(slist_t *list,slist_destroy_t dealloc)
{
	slist_node_t *node;

	while( ((node = slist_head(list)) != NULL) )
	{
		slist_head(list) = slist_next(node);
		if ( dealloc == SLIST_FREE_DATA )
			xfree(slist_data(node));
		xfree(node);
	}
	slist_tail(list) = NULL;
	slist_size(list) = 0;
}
