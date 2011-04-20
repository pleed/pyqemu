#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>
#include <avl.h>

#include "flx_bbl.h"

static inline uint8_t     flx_bbl_cache_index(uint32_t address);
static inline flx_bbl*    flx_bbl_cache_hit(uint32_t address);
static inline void        flx_bbl_cache_update(flx_bbl* bbl);
static inline avl_tree_t* flx_bbl_addrtotree(uint32_t addr);
static int                avl_bbl_cmp(const flx_bbl* a, const flx_bbl* b);
static void               avl_bbl_free(void* item);

avl_tree_t* bbl_trees[NUM_BBL_TREES];

bbl_cache flx_bbl_cache;

static inline uint8_t
flx_bbl_cache_index(uint32_t address){
	return address&(NUM_BBL_TREES-1);
}

static inline flx_bbl*
flx_bbl_cache_hit(uint32_t address){
	uint8_t index = flx_bbl_cache_index(address);
	if(flx_bbl_cache.valid[index] && \
	   address == flx_bbl_cache.bbls[index]->addr){
		return flx_bbl_cache.bbls[index];
	}
	return NULL;
}

static inline void
flx_bbl_cache_update(flx_bbl* bbl){
	uint8_t index = flx_bbl_cache_index(bbl->addr);
	flx_bbl_cache.valid[index] = 1;
	flx_bbl_cache.bbls[index] = bbl;
}

static inline void
flx_bbl_cache_invalidate(void){
	uint16_t i;
	for(i=0; i<BBL_CACHE_SIZE; ++i){
		flx_bbl_cache.valid[i] = 0;
	}
}

int avl_bbl_cmp(const flx_bbl* a, const flx_bbl* b){
	if(a->addr > b->addr)
		return 1;
	else if(a->addr < b->addr)
		return -1;
	return 0;
}

void avl_bbl_free(void* item){
	free(item);
}

static inline avl_tree_t*
flx_bbl_addrtotree(uint32_t addr){
	return bbl_trees[addr&(NUM_BBL_TREES-1)];
}

void flx_bbl_add(flx_bbl* bbl){
	flx_bbl_cache_update(bbl);
	avl_tree_t* tree = flx_bbl_addrtotree(bbl->addr);
	flx_bbl* new_bbl = malloc(sizeof(*bbl));
	memcpy(new_bbl, bbl, sizeof(*bbl));
	avl_insert(tree, new_bbl);
}

void flx_bbl_flush(void){
	uint16_t i;
	for(i=0; i<NUM_BBL_TREES; ++i){
		avl_free_nodes(bbl_trees[i]);
	}
	flx_bbl_cache_invalidate();
}

void flx_bbl_init(void){
	uint16_t i;
	for(i=0; i<NUM_BBL_TREES; ++i){
		bbl_trees[i] = avl_alloc_tree((avl_compare_t)avl_bbl_cmp, (avl_freeitem_t)avl_bbl_free);
	}
	memset(&flx_bbl_cache, 0, sizeof(flx_bbl_cache));
}

void flx_bbl_destroy(void){
	uint16_t i;
	for(i=0; i<NUM_BBL_TREES; ++i){
		avl_free_tree(bbl_trees[i]);
	}
}

flx_bbl*
flx_bbl_search(uint32_t address){
	flx_bbl* bbl = flx_bbl_cache_hit(address);
	if(bbl){
		return bbl;
	}
	
	avl_tree_t* tree = flx_bbl_addrtotree(address);
	if(!tree){
		return NULL;
	}

	bbl = malloc(sizeof(*bbl));
	bbl->addr = address;
	avl_node_t *node = avl_search(tree, (void*)bbl);
	free(bbl);
	if(node){
		flx_bbl_cache_update(node->item);
		return node->item;
	}
	return NULL;
}

