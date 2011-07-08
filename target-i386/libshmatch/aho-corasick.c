/**
  Modified by Felix Matenaar 2010

  @file
  
  @brief implementation of the Aho-Corasick pattern matching algorithm.
    
  most of this code was taken from another module by Georgios Portokalidis
  with his permission. 

  2005/03/20: I [Danny Yoo (dyoo@hkn.eecs.berkeley.edu)] munged this code a
  bit to make it more useful for my Python wrapper.  I modified the output
  state to maintain the lengths of keyword matches, refactored out some of the
  initialization code, and dropped support for the optional global tree M.
  I'll leave the notices about FFPF in here, of course, but be aware that this
  code has been mutated quite at bit.  *grin*
  
  
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


/* dyoo: the xalloc.h header must come first now, since it includes Python.h,
   and Python.h sets the posix C source defines.  Having it anywhere
   afterwards may cause compiler conflicts.*/
#include "xalloc.h"

#ifdef __KERNEL__
#include <linux/string.h>
#else
#include <string.h>
#endif

#include "aho-corasick.h"
#include "shmatch.h"

#include "slist.h"

#include <stdio.h>


#ifdef DEBUG
#define debug(x) x
#else
#define debug(x)
#endif

#define FAIL NULL
#define aho_corasick_fail(x) x->fail
#define aho_corasick_output(x) x->output


/* dyoo: Every state whose depth is less than the
   TRANSITION_SWITCHING_THRESHOLD gets a dense transition table definition.
   Otherwise, use the sparse slist representation.

   The number I've selected below is completely arbitrary.  Changing it will
   affect memory and performance.  I dunno, three seemed like a good odd
   number.  *grin*
 */
#define TRANSITION_SWITCHING_THRESHOLD 3


/**********************************************************************/
/* dyoo: I want to abstract away the direct use of the state
   transition list, to see if I can use a simple linked list
   representation instead. */
/**********************************************************************/

void aho_corasick_goto_set(aho_corasick_state_t *from_state,
			   unsigned char symbol,
			   aho_corasick_state_t *to_state) {
	aho_corasick_labeled_edge_t *edge;
	switch (from_state->_transitions.type) {
	case AHO_CORASICK_DENSE_TRANSITIONS:
		from_state->_transitions.data.array[symbol] = to_state;
		return;
	case AHO_CORASICK_SPARSE_TRANSITIONS:
		edge = xalloc(sizeof(aho_corasick_labeled_edge_t));
		if (edge == NULL) {
			/* fixme: check memory allocation! */
		}
		edge->label = symbol;
		edge->state = to_state;
		
		if (slist_prepend(from_state->_transitions.data.slist, edge) < 0) {
			/* fixme: check memory allocation! */
		}
		return;
	}

}


/* Follows the transition arrow from the state, along the edge labeled by the
   symbol.  If no such transition exists, returns FAIL. */
aho_corasick_state_t* aho_corasick_goto_get(aho_corasick_state_t *state,
					    unsigned char symbol) {
	slist_node_t *node;
	switch (state->_transitions.type) {
	case AHO_CORASICK_DENSE_TRANSITIONS:
		return state->_transitions.data.array[symbol];
	case AHO_CORASICK_SPARSE_TRANSITIONS:
		node = slist_head(state->_transitions.data.slist);
		while (node != NULL) {
			if (((aho_corasick_labeled_edge_t *) node->data)
			    ->label == symbol) {
				return ((aho_corasick_labeled_edge_t *)
					node->data)->state;
			}
			node = node->next;
		}
		return FAIL;
	}

	/* FIXME: We should never get here. */
	return FAIL;
}


/* Initializes all of the transition arrows to FAIL.  representation_type must
   be either DENSE_TRANSITIONS or SPARSE_TRANSITIONS.  If everything is ok,
   returns 0.  If bad things happen, returns -1. */
static int aho_corasick_goto_initialize(aho_corasick_state_t *state) {
	aho_corasick_transition_t rep_type = AHO_CORASICK_DENSE_TRANSITIONS;
	if (state->depth >= TRANSITION_SWITCHING_THRESHOLD) {
		rep_type = AHO_CORASICK_SPARSE_TRANSITIONS;
	}
	switch (rep_type) {
	case AHO_CORASICK_DENSE_TRANSITIONS:
		state->_transitions.type = AHO_CORASICK_DENSE_TRANSITIONS;
		state->_transitions.data.array =
			xalloc(AHO_CORASICK_CHARACTERS *
			       sizeof(aho_corasick_state_t *));
		if (state->_transitions.data.array == NULL)
			return -1;
		memset(state->_transitions.data.array,
		       (long) FAIL,
		       AHO_CORASICK_CHARACTERS*sizeof(aho_corasick_state_t *));
		return 0;
	case AHO_CORASICK_SPARSE_TRANSITIONS:
		state->_transitions.type = AHO_CORASICK_SPARSE_TRANSITIONS;
		state->_transitions.data.slist =
			xalloc(sizeof(slist_t));
		if (state->_transitions.data.slist == NULL)
			return -1;
		slist_init(state->_transitions.data.slist);
		return 0;
	}
	return 0;
}


/* Deallocates the transition table.  Do nothing for now. */
static void aho_corasick_goto_destroy(aho_corasick_state_t *state) {
	switch (state->_transitions.type) {
	case AHO_CORASICK_DENSE_TRANSITIONS:
		xfree(state->_transitions.data.array);
		return;
	case AHO_CORASICK_SPARSE_TRANSITIONS:
		slist_destroy(state->_transitions.data.slist, SLIST_FREE_DATA);
		xfree(state->_transitions.data.slist);
	}
}




/* Anything below this should access state transitions only through the API
   methods here.  They should not touch the structure directly, because the
   implementation of state->transitions will be munged! */



/**********************************************************************/



/* Does an aho-corasick search, given a 'string' of length 'n'.  If
   we're able to find a match, returns a positive integer.  Also
   outputs the start-end indices of the match as well as the last
   matching state with out parameters.
 */
aho_corasick_int_t
ahocorasick_KeywordTree_search_helper(aho_corasick_state_t *state,
				      unsigned char *string,
				      size_t n,
				      size_t startpos,
				      size_t *out_start,
				      size_t *out_end,
				      aho_corasick_state_t **out_last_state)
{
	size_t j;
	for(j = startpos; j < n ; j++)
	{
		while( aho_corasick_goto_get(state,*(string+j)) == FAIL ) 
		{
			state = aho_corasick_fail(state);
		}
		state = aho_corasick_goto_get(state,*(string+j));
		if ( aho_corasick_output(state) != 0 ) 
		{
			*out_start = j - aho_corasick_output(state) + 1;
			*out_end = j+1;
			*out_last_state = state;
			return state->id;
		}
	}
	*out_start = -1;
	*out_end = -1;
	return 0;
}



/* Similar to the first helper function, but tries to return the longest
   match. */
aho_corasick_int_t
ahocorasick_KeywordTree_search_long_helper(aho_corasick_state_t *state,
					   unsigned char *string,
					   size_t n,
					   size_t startpos,
					   size_t *out_start,
					   size_t *out_end,
					   aho_corasick_state_t **out_last_state)
{
	size_t j;

	*out_start = -1;
	*out_end = -1;
	for(j = startpos ; j < n ; j++)
	{

		if (aho_corasick_goto_get(state, *(string+j)) == FAIL &&
		    *out_end != -1) 
		{
			*out_last_state = state;
			return state->id;
		}
		while( aho_corasick_goto_get(state,*(string+j)) == FAIL )
		{
			state = aho_corasick_fail(state);
		}
		state = aho_corasick_goto_get(state,*(string+j));
		if ( aho_corasick_output(state) != 0) 
		{
			*out_start = j - aho_corasick_output(state) + 1;
			*out_end = j+1;
		}
	}

	/* If we reach the end of the string, we still have to double check if
	   we had a longest match queued up. */
	if (*out_end != -1) {
		*out_last_state = state;
		return state->id;
	}
	return 0;
}





/* Initializes the zerostate.  If initialization is successful,
   returns 0.  If bad things happen, returns -1. */
static int
initialize_zero_state(aho_corasick_t *in) {
	if ( in->zerostate == NULL )
	{
		if ( (in->zerostate = xalloc(sizeof(aho_corasick_state_t))) == NULL )
		{
			xfree(in);
			return -1;
		}
		in->newstate = 1;
		in->zerostate->id = 0;
		in->zerostate->depth = 0;
		aho_corasick_output(in->zerostate) = 0;
		aho_corasick_fail(in->zerostate) = NULL;
		/* FIXME: check the error return value of
		   aho_corasick_goto_initialize. */
		aho_corasick_goto_initialize(in->zerostate);
	}
	return 0;
}


int
aho_corasick_init(aho_corasick_t *g)
{
	if (!g)
	{
		return -1;
	}
	else
	{
		g->zerostate = NULL;
		g->newstate = 0;
		return initialize_zero_state(g);
	}

}


/* Really do the memory deallocation of a state. */
static void aho_corasick_state_dealloc(aho_corasick_state_t *state) {
	/* Warning: order dependent code ahead: */
	aho_corasick_goto_destroy(state);
	xfree(state);
}



/* Helper function for aho_corasick_destroy.  Recursively frees up each state,
   doing this essentially depth-first. */
static void
aho_corasick_free(aho_corasick_state_t *state)
{
	int i;

	for(i = 0; i < AHO_CORASICK_CHARACTERS ;i++)
		if ( aho_corasick_goto_get(state,i) != FAIL ) 
			aho_corasick_free(aho_corasick_goto_get(state,i));
	
	/* Actually do the memory deallocation here. */
	aho_corasick_state_dealloc(state);
}




void
aho_corasick_destroy(aho_corasick_t *in)
{
	int i;

	if (in->zerostate != NULL) 
	{
		for(i = 0; i < AHO_CORASICK_CHARACTERS ;i++)
			if ( aho_corasick_goto_get(in->zerostate,i) != FAIL && 
			     aho_corasick_goto_get(in->zerostate,i)->id > 0 )
				aho_corasick_free(aho_corasick_goto_get
						  (in->zerostate,i));
		
		/* dyoo: added to free the last node. */
		aho_corasick_state_dealloc(in->zerostate);
		
		in->zerostate = NULL;
	}
}

int
aho_corasick_maketree(aho_corasick_t *in)
{
	slist_t queue;
	aho_corasick_state_t *state,*s,*r;
	aho_corasick_t *g = in;
	int i;

	slist_init(&queue);

	// Set all FAIL transition of 0 state to point to itself
	for(i = 0; i < AHO_CORASICK_CHARACTERS ;i++)
	{
		if ( aho_corasick_goto_get(g->zerostate,i) == FAIL )
			aho_corasick_goto_set(g->zerostate, i, g->zerostate);
		// Construct fail()
		else
		{
			if ( slist_append(&queue,aho_corasick_goto_get(g->zerostate,i)) < 0 )
				goto fail;
			aho_corasick_fail(aho_corasick_goto_get(g->zerostate,i)) = g->zerostate;
		}
	}

	// Set fail() for depth > 0
	while( (r = slist_pop_first(&queue)) != NULL )
	{
		for(i = 0; i < AHO_CORASICK_CHARACTERS ;i++)
		{
			if ( (s = aho_corasick_goto_get(r,i)) == FAIL )
				continue;
			if ( slist_append(&queue,s) < 0 )
				goto fail;
			state = aho_corasick_fail(r);
			while( aho_corasick_goto_get(state,i) == FAIL )
				state = aho_corasick_fail(state);
			aho_corasick_fail(s) = aho_corasick_goto_get(state,i);
			debug(printf("Setting f(%u) == %u\n",s->id,
				     aho_corasick_goto_get(state,i)->id));
			// Join outputs missing
		}
	}

	slist_destroy(&queue,SLIST_LEAVE_DATA);
	return 0;

fail:
	slist_destroy(&queue,SLIST_LEAVE_DATA);
	return -1;
}




int
aho_corasick_addstring(aho_corasick_t *in, unsigned char *string, size_t n, struct pattern* p)
{
	aho_corasick_t* g = in;
	aho_corasick_state_t *state,*s = NULL;
	int j = 0;

	state = g->zerostate;

	// As long as we have transitions follow them
	while( j != n &&
	       (s = aho_corasick_goto_get(state,*(string+j))) != FAIL )
	{
		state = s;
		++j;
	}

	if ( j == n ) {
		/* dyoo: added so that if a keyword ends up in a prefix
		   of another, we still mark that as a match.*/
		aho_corasick_output(s) = j;
		return 0;
	}

	while( j != n )
	{
		// Create new state
		if ( (s = xalloc(sizeof(aho_corasick_state_t))) == NULL )
			return -1;
		s->id = g->newstate++;
 		debug(printf("allocating state %d\n", s->id)); /* debug */ 
		s->depth = state->depth + 1;
		s->pattern = p;

		/* FIXME: check the error return value of
		   aho_corasick_goto_initialize. */
		aho_corasick_goto_initialize(s);

		// Create transition
		aho_corasick_goto_set(state,*(string+j), s);
		debug(printf("%u -> %c -> %u\n",state->id,*(string+j),s->id));
		state = s;
		aho_corasick_output(s) = 0;
		aho_corasick_fail(s) = NULL;
		++j;
	}

	aho_corasick_output(s) = n;

	return 0;
}
