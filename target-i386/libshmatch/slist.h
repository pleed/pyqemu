/**

  @file
  
  @brief Implementation of a very simple single linked list.
    
  Part of Georgios Portokalidis' Aho Corasick algorithm.
  
  FIXME: the same functionality is delivered by support/list.h
  remove this file and all references to it.
  
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

#ifndef SLIST_H
#define SLIST_H

//! The definition of a single linked list node
struct slist_node
{
	void *data; //!< Pointer to data of this node
	struct slist_node *next; //!< Pointer to next node on list
};

//! Single linked list node type
typedef struct slist_node slist_node_t;

//! The definition of a single linked list
struct slist
{
	slist_node_t *head; //!< Pointer to head of list
	slist_node_t *tail; //!< Pointer to tail of list
	unsigned int size; //!< The number of elements in the list
};

//! Single linked list type
typedef struct slist slist_t;

//! Macro to get the head node of a list l
#define slist_head(l) l->head
//! Macro to get the tail node of a list l
#define slist_tail(l) l->tail
//! Macro to get the size of a list l
#define slist_size(l) l->size
//! Macro to get the next node of l
#define slist_next(n) n->next
//! Macro to get the data of node l
#define slist_data(n) n->data

//! Specifies whether slist_destroy should deallocate or not stored elements
typedef enum { SLIST_LEAVE_DATA = 0, SLIST_FREE_DATA } slist_destroy_t;

void slist_init(slist_t *);
void slist_destroy(slist_t *,slist_destroy_t);
void *slist_pop_first(slist_t *);
int slist_append(slist_t *,void *);
int slist_prepend(slist_t *,void *);

#endif
