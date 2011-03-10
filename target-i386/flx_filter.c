#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <avl.h>

#include "flx_filter.h"

#define NUM_FILTER_TREES 256

uint8_t flx_filter_enabled;
avl_tree_t* page_trees[NUM_FILTER_TREES];

flx_filter_cache flx_filter_search_cache;

static inline uint32_t
flx_filter_addrtopage(uint32_t addr){
	return (addr & 0xfffff000);
}

static inline uint8_t
flx_filter_cache_index(uint32_t address){
	return (address>>16) & 0x3f;
}

static inline int
flx_filter_cache_hit(uint32_t address){
	uint8_t index = flx_filter_cache_index(address);
	if(flx_filter_search_cache.valid[index] && \
	   flx_filter_addrtopage(address) == flx_filter_search_cache.pages[index]){
		return 1;
	}
	return 0;
}

static inline int
flx_filter_cache_update(uint32_t address){
	uint8_t index = flx_filter_cache_index(address);
	flx_filter_search_cache.valid[index] = 1;
	flx_filter_search_cache.pages[index] = flx_filter_addrtopage(address);
}

static inline void
flx_filter_cache_invalidate(address){
	flx_filter_search_cache.valid[flx_filter_cache_index(address)] = 0;
}

int avl_page_cmp(const uint16_t* a, const uint16_t* b){
	if(*a > *b)
		return 1;
	else if(*a < *b)
		return -1;
	return 0;
}

void avl_page_free(void* item){
	free(item);
}

static inline avl_tree_t*
flx_filter_addrtotree(uint32_t addr){
	return page_trees[(addr>>16)&0xff];
}

static uint16_t
flx_filter_addrtovalue(uint32_t addr){
	addr = addr >> 12;
	addr = (addr & 0xf) | ((addr >> 8) &0xfff0);
	return addr;
}

void flx_filter_init(void){
	memset(page_trees, 0, sizeof(page_trees));
	flx_filter_cache_invalidate();
}

void flx_filter_destroy(void){
	uint16_t i;
	for(i=0; i<NUM_FILTER_TREES; ++i){
		page_trees[i];
	}
}

void flx_filter_enable(void){
	flx_filter_enabled = 1;
}
void flx_filter_disable(void){
	flx_filter_enabled = 0;
}

int flx_filter_search_by_addr(uint32_t address){
	if(flx_filter_cache_hit(address))
		return 1;

	uint8_t hash = (address>>16)&0xff;
	avl_tree_t* tree = flx_filter_addrtotree(address);
	if(!tree){
		return 0;
	}
	uint16_t* value = malloc(sizeof(*value));
	*value = flx_filter_addrtovalue(address);
	avl_node_t *node = avl_search(tree, value);
	free(value);
	if(node){
		flx_filter_cache_update(address);
		return 1;
	}
	return 0;
}

int flx_filter_del_by_addr(uint32_t address){
	if(!flx_filter_search_by_addr(address))
		return 0;
	uint16_t value = flx_filter_addrtovalue(address);
	uint16_t* item = avl_delete(flx_filter_addrtotree(address), &value);
	if(item){
		if(flx_filter_cache_hit(address))
			flx_filter_cache_invalidate(address);
	}
	return 0;
}

int flx_filter_del_by_range(uint32_t start, uint32_t end){
	if(start > end)
		return -1;
	else{
		start = flx_filter_addrtopage(start);
		end   = flx_filter_addrtopage(end);
		for(; start<end; start+=0x00001000){
			flx_filter_del_by_addr(start);
		}
	}
	return 0;
}

int flx_filter_search_by_range(uint32_t start, uint32_t end){
	if(start > end)
		return -1;
	else{
		start = flx_filter_addrtopage(start);
		end   = flx_filter_addrtopage(end);
		for(; start<end; start+=0x00001000){
			if(flx_filter_search_by_addr(start))
				return 1;
		}
	}
	return 0;
}

int flx_filter_add_by_addr(uint32_t address){
	uint8_t hash = (address>>16) & 0xff;
	uint16_t* value = malloc(sizeof(*value));

	if(flx_filter_search_by_addr(address))
		return 1;

	if(!page_trees[hash]){
		page_trees[hash] = avl_alloc_tree((avl_compare_t)avl_page_cmp, (avl_freeitem_t)avl_page_free);
	}

	*value = flx_filter_addrtovalue(address);
	avl_insert(page_trees[hash], value);
	return 0;
}


int flx_filter_add_by_range(uint32_t start, uint32_t end){
	if(start > end)
		return -1;
	else{
		start = flx_filter_addrtopage(start);
		end   = flx_filter_addrtopage(end);

		for(; start<end; start+=0x00001000){
			flx_filter_add_by_addr(start);
		}
	}
	return 0;
}

int flx_filter_filtered(uint32_t address){
	avl_tree_t* tree = flx_filter_addrtotree(address);
	
}

#ifdef FLX_FILTER_UNITTEST

#include <stdlib.h>
#include <time.h>
#include <stdio.h>

#define VALUES 1024*1024

int main(int argc, char* argv[]){
	srand(time(NULL));
	uint32_t addresses[VALUES];
	uint32_t foovalues[VALUES];
	int i;
	for(i=0; i<VALUES; ++i){
		addresses[i] = i;
		foovalues[i] = VALUES+i;
	}
	flx_filter_init();
	for(i=0; i<VALUES; ++i){
		flx_filter_add_by_addr(addresses[i]);
	}
	for(i=0; i<VALUES; ++i){
		if(!flx_filter_search_by_addr(addresses[i]))
			printf("ALARM!\n");
		if(flx_filter_search_by_addr(foovalues[i]))
			printf("FALSE POSITIVE!\n");
	}
	for(i=0; i<VALUES; ++i){
		flx_filter_del_by_addr(addresses[i]);
	}
	for(i=0; i<256; ++i){
		if(page_trees[i])
			if(avl_count(page_trees[i]) != 0)
				printf("ALARM\n");
	}
	for(i=0; i<VALUES; ++i){
		flx_filter_add_by_addr(addresses[i]);
	}
	flx_filter_del_by_range(0,0xffffffff);
	for(i=0; i<256; ++i){
		if(page_trees[i])
			if(avl_count(page_trees[i]) != 0)
				printf("ALARM!!!!\n");
	}
	flx_filter_destroy();
}

#endif
