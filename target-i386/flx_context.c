#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>
#include <avl.h>

#include "flx_context.h"

/*
 * Heuristic modules need to have process context information
 * in order to deal with more than one instrumented process at
 * a time in future design changes.
 * This module manages a process tree and defines an API to access
 * the current process associated data structures
 */

flx_context* current_context;
avl_tree_t *context_tree;


static int                avl_context_cmp(const flx_context* a, const flx_context* b);
static void               avl_context_free(flx_context* c);

static int
avl_context_cmp(const flx_context* a, const flx_context* b){
	if(a->pid > b->pid)
		return 1;
	else if(a->pid < b->pid)
		return -1;
	else if(a->tid > b->tid)
		return 1;
	else if(a->tid < b->tid)
		return -1;
	else
		return 0;
}

static void
avl_context_free(flx_context* c){
	free(c);
}

void flx_context_init(void){
	context_tree = avl_alloc_tree((avl_compare_t)avl_context_cmp, (avl_freeitem_t)avl_context_free);
	current_context = NULL;
}

static flx_context*
flx_context_alloc(uint16_t pid, uint16_t tid, const char* procname){
	flx_context* context = malloc(sizeof(*context));
	memset(context, 0, sizeof(*context));
	context->pid = pid;
	context->tid = tid;
	context->procname = strdup(procname);
	return context;
}

void flx_context_set(int32_t p, int32_t t, const char* procname){
	if(p == -1 && t == -1){
		current_context = NULL;
		return;
	}
	uint16_t pid = p;
	uint16_t tid = t;
	flx_context* context = flx_context_alloc(pid, tid, procname);
	avl_node_t* node = avl_search(context_tree, (void*)context);
	if(node){
		current_context = node->item;
		free(context);
	}
	else{
		avl_insert(context_tree, context);
		current_context = context;
	}
}

flx_context*
flx_context_current(void){
	return current_context;
}
