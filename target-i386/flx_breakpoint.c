#include <avl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>

#include "exec-all.h"
#include "cpu.h"
#include "flx_instrument.h"
#include "flx_breakpoint.h"

/*
 * Breakpoints are important for hooking and the initial
 * entrypoint execution detection. This module manages
 * breakpoints in cascaded AVL-trees.
 *
 * The upper tree includes the running processes while each
 * tree node again holds a tree managing the breakpoint addresses
 *
 * cr3 is used as the process identifier.
 */

avl_tree_t *bps;

static void flx_breakpoint_free(flx_breakpoint* bp){
	if(bp->processes)
		avl_free_tree(bp->processes);
	free(bp);
}

static void avl_breakpoint_free(flx_breakpoint *bp){
	flx_breakpoint_free(bp);
}

static void avl_process_free(void *item){
	free(item);
}

static int avl_process_cmp(const uint32_t *a, const uint32_t *b){
	if(*a==*b)
		return 0;
	else if(*a<*b)
		return -1;
	else
		return 1;
}


static int avl_breakpoint_cmp(const flx_breakpoint *a, const flx_breakpoint *b){
	if(a->addr == b->addr)
		return 0;
	else if(a->addr < b->addr)
		return -1;
	return 1;
}

static flx_breakpoint* flx_breakpoint_alloc(uint32_t addr){
	flx_breakpoint* bp = malloc(sizeof(flx_breakpoint));
	if(!bp){
		printf("out of memory!\n");
		exit(1);
	}
	bp->addr = addr;
	bp->processes = NULL;
	return bp;
}

void flx_breakpoint_init(void){
	bps = avl_alloc_tree((avl_compare_t)avl_breakpoint_cmp, (avl_freeitem_t)avl_breakpoint_free);
}

/*static void flx_breakpoint_destroy(void){
	avl_free_tree(bps);
}*/

void flx_breakpoint_insert(uint32_t addr, uint32_t cr3){
	flx_breakpoint *bp = flx_breakpoint_alloc(addr);
	avl_node_t *node = avl_search(bps, bp);
	avl_tree_t *processes;
	if(!node){
		avl_insert(bps, bp);
		bp->processes = avl_alloc_tree((avl_compare_t)avl_process_cmp, (avl_freeitem_t)avl_process_free);
		processes = bp->processes;
		
	}
	else{
		avl_breakpoint_free(bp);
		flx_breakpoint *tmp = node->item;
		processes = tmp->processes;
	}
	if(!avl_search(processes, &cr3)){
		uint32_t *item = malloc(sizeof(cr3));
		memcpy(item, &cr3, sizeof(cr3));
		avl_insert(processes, item);
		breakpoint_invalidate(current_environment, addr);
	}
}

int flx_breakpoint_search(uint32_t addr, uint32_t cr3){
	flx_breakpoint *bp = flx_breakpoint_alloc(addr);
	avl_node_t *node = avl_search(bps, bp);
	int found = 0;

	if(node){
		flx_breakpoint *tmp = node->item;
		avl_tree_t *tree = tmp->processes;
		if(avl_search(tree, &cr3))
			found = 1;
	}

	flx_breakpoint_free(bp);
	return found;
}

int flx_breakpoint_delete(uint32_t addr, uint32_t cr3){
	flx_breakpoint *bp = flx_breakpoint_alloc(addr);
	avl_node_t *found  = avl_search(bps, bp);
	if(!found){
		flx_breakpoint_free(bp);
		return 0;
	}
	else{
		flx_breakpoint *tmp = found->item;
		avl_tree_t *processes = tmp->processes;
		avl_delete(processes, &cr3);
		if(avl_count(processes) == 0)
			avl_delete(bps, bp);
		flx_breakpoint_free(bp);
		breakpoint_invalidate(current_environment, addr);
		return 1;
	}
}

int flx_breakpoint_search_addr(uint32_t addr, uint32_t *next){
	flx_breakpoint *bp = flx_breakpoint_alloc(addr);
	avl_node_t *node;
	int closest;
	int found = 1;

	closest = avl_search_closest(bps, &addr, &node);
	flx_breakpoint_free(bp);

	/* tree is empty */
	if(!node){
		return 0;
	}
	else if(closest < 0){
		if(node->next){
			bp = node->next->item;
			*next = bp->addr;
		}
		else
			*next = 0xffffffff;
	}
	else if(closest >=0){
		bp = node->item;
		*next = bp->addr;
	}

	return found;
}

/*
int main(int argc, char *argv[]){
	flx_breakpoint_init();
	int i;
	int j;
	for(i=0; i<100; ++i)
		for(j=0; j<100; ++j)
			flx_breakpoint_insert(i,j);
	if(i!=avl_count(bps))
		printf("COUNT FAILED\n");
	for(i=0; i<100; ++i)
		for(j=0; j<100; ++j)
			if(!flx_breakpoint_search(i,j))
				printf("FAILED! search\n");
	for(i=0; i<100; ++i){
		for(j=0; j<99; ++j)
			flx_breakpoint_delete(i,j);
		if(!flx_breakpoint_search_addr(i))
			printf("search failed 1\n");
		flx_breakpoint_delete(i,99);
		if(flx_breakpoint_search_addr(i))
			printf("search failed 2\n");
		
	}
	flx_breakpoint_destroy();
	printf("success\n");
}
*/
