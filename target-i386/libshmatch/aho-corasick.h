/**

  Modified by Felix Matenaar 2010

  @file
  
  @brief implementation of the Aho-Corasick pattern matching algorithm.
    
  most of this code was taken from another module by Georgios Portokalidis
  with his permission. Since I don't really know how he has implemented the code
  I haven't tried to document it. 
  
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

#include <unistd.h>

#include "slist.h"
#include "shmatch.h"

#ifndef AHO_CORASICK_H
#define AHO_CORASICK_H

typedef unsigned int aho_corasick_int_t;

#define AHO_CORASICK_CHARACTERS 256



/* A transition table has two possible implemementations:

   1.  A "dense" array.  Constant-time access, but expensive in terms of memory.

   2.  A "sparse" linked list.  Linear time acces, but not too expensive in
       terms of memory.
 */

/* Defines the two types of transition table implementations we might want to
   use. */
typedef enum { AHO_CORASICK_DENSE_TRANSITIONS = 0, 
	       AHO_CORASICK_SPARSE_TRANSITIONS } aho_corasick_transition_t;

struct aho_corasick_transition_table {
	aho_corasick_transition_t type;
	union {
		/* array is a pointer to an array of states. */
		struct aho_corasick_state ** array;
		slist_t* slist;
	} data;
};
typedef struct aho_corasick_transition_table aho_corasick_transition_table_t;


/* Represents a single labeled edge. */
struct aho_corasick_labeled_edge {
	unsigned char label;
	struct aho_corasick_state *state;
};
typedef struct aho_corasick_labeled_edge aho_corasick_labeled_edge_t;



struct aho_corasick_state
{
	aho_corasick_int_t id;
	aho_corasick_int_t depth;
	size_t output;
	struct aho_corasick_state * fail;
	aho_corasick_transition_table_t _transitions;
	struct pattern* pattern;
};
typedef struct aho_corasick_state aho_corasick_state_t;




struct aho_corasick
{
	aho_corasick_int_t newstate;
	aho_corasick_state_t *zerostate;
};

typedef struct aho_corasick aho_corasick_t;


/* Initializes the tree.  Returns 0 on success, -1 on failure. */
int aho_corasick_init(aho_corasick_t *);

/* Adds a new string to the tree, given that the string is of length n. */
int aho_corasick_addstring(aho_corasick_t *,unsigned char *, size_t, struct pattern*);

/* Finalizes construction by setting up the failrue transitions, as
   well as the goto transitions of the zerostate. */
int aho_corasick_maketree(aho_corasick_t *);


/* Set a transition arrow from this from_state, via a symbol, to a
   to_state. */
void aho_corasick_goto_set(aho_corasick_state_t *from_state,
			   unsigned char symbol,
			   aho_corasick_state_t *to_state);

/* Returns the transition state.  If no such state exists, returns NULL. */
aho_corasick_state_t* aho_corasick_goto_get(aho_corasick_state_t *state,
					    unsigned char symbol);



/* Helper functions to search for matches in a aho corasick tree. */
aho_corasick_int_t ahocorasick_KeywordTree_search_helper(aho_corasick_state_t *,unsigned char *,size_t, size_t, size_t *, size_t *, aho_corasick_state_t **);
aho_corasick_int_t ahocorasick_KeywordTree_search_long_helper(aho_corasick_state_t *,unsigned char *,size_t, size_t, size_t *, size_t *, aho_corasick_state_t **);

/* type of any function that helps with search. */
typedef aho_corasick_int_t (*ahocorasick_KeywordTree_search_helper_t)
  (aho_corasick_state_t*, unsigned char *, size_t, size_t, 
   size_t*, size_t*, aho_corasick_state_t**);


/* Destroys a tree, deallocating memory. */
void aho_corasick_destroy(aho_corasick_t *);


#endif
