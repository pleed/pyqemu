#include <avl.h>
#include <stdlib.h>
#include <string.h>

#include "flx_breakpoint.h"

avl_tree_t *bps;

void flx_breakpoint_free(flx_breakpoint* bp){
	free(bp);
}

static void avl_breakpoint_free(flx_breakpoint *bp){
	flx_breakpoint_free(bp);
}

static int avl_breakpoint_cmp(const flx_breakpoint *a, const flx_breakpoint *b){
	if(a->cr3 == b->cr3){
		if(a->addr == b->addr)
			return 0;
		else if(a->addr < b->addr)
			return -1;
		return 1;
	}
	else if(a->cr3 < b->cr3)
		return -1;
	else
		return 1;
}

flx_breakpoint* flx_breakpoint_alloc(uint32_t addr, uint32_t cr3){
	flx_breakpoint* bp = malloc(sizeof(flx_breakpoint));
	bp->addr = addr;
	bp->cr3  = cr3;
	return bp;
}

void flx_breakpoint_init(void){
	bps = avl_alloc_tree((avl_compare_t)avl_breakpoint_cmp, (avl_freeitem_t)avl_breakpoint_free);
}

void flx_breakpoint_destroy(void){
	avl_free_tree(bps);
}

void flx_breakpoint_insert(uint32_t addr, uint32_t cr3){
	flx_breakpoint *bp = flx_breakpoint_alloc(addr, cr3);
	avl_insert(bps, bp);
}

int flx_breakpoint_search(uint32_t addr, uint32_t cr3){
	flx_breakpoint *bp = flx_breakpoint_alloc(addr, cr3);
	avl_node_t *node = avl_search(bps, bp);
	flx_breakpoint_free(bp);
	return (node!=NULL);
}

int flx_breakpoint_delete(uint32_t addr, uint32_t cr3){
	flx_breakpoint *bp = flx_breakpoint_alloc(addr, cr3);
	avl_node_t *found  = avl_search(bps, bp);
	if(!found){
		flx_breakpoint_free(bp);
		return 0;
	}
	else{
		avl_delete(bps, bp);
		flx_breakpoint_free(bp);
		return 1;
	}
}
