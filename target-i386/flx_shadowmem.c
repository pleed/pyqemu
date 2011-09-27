#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>
#include <avl.h>
#include <math.h>

#include "flx_shadowmem.h"

/*
 * When doing pattern matching, PyQemu relies on
 * the advantages of dynamic analysis to reduce
 * the search space and thus also the false positive
 * rate. Therefore we need a shadow memory which stores
 * only memory regions that were acessed before.
 * This module implements the shadow memory and supports
 * iteration over subsequent pages.
 */

static int
shadowmem_page_cmp(const shadow_page* p1, const shadow_page* p2){
	if(p1->addr < p2->addr)
		return -1;
	else if(p1->addr > p2->addr)
		return 1;
	return 0;
}

static void
shadowmem_page_free(shadow_page* page){
	if(page->mem)
		free(page->mem);
	free(page);
}

static shadow_page*
flx_shadowmem_find_page(shadowmem* mem, uint32_t addr){
	shadow_page* page = malloc(sizeof(*page));
	page->addr = addr&(~0xfff);
	avl_node_t* node = avl_search(mem, page);
	if(!node){
		page->mem = malloc(FLX_PAGE_SIZE);
		page->eip = malloc(FLX_PAGE_SIZE*sizeof(uint32_t));
		memset(page->mem, 0, FLX_PAGE_SIZE);
		node = avl_insert(mem, page);
	}
	else
		free(page);
	return node->item;
}

shadowmem*
flx_shadowmem_new(void){
	return avl_alloc_tree((avl_compare_t)shadowmem_page_cmp, (avl_freeitem_t)shadowmem_page_free);
}

void
flx_shadowmem_delete(shadowmem* mem){
	avl_free_tree(mem);
}

void
flx_shadowmem_store(shadowmem* mem, uint32_t address, uint8_t value, uint32_t eip){
	shadow_page* page = flx_shadowmem_find_page(mem, address);
	assert(page);
	address &= 0xfff;
	page->mem[address] = value;
	page->eip[address] = eip;
}

uint8_t
flx_shadowmem_load(shadowmem* mem, uint32_t address, uint8_t *value){
	shadow_page* page = flx_shadowmem_find_page(mem, address);
	assert(page);
	address &= 0xfff;
	*value = page->mem[address];
	return 1;
}

shadowmem_iterator*
flx_shadowmem_iterator_new(shadowmem* mem){
	shadowmem_iterator* iter = malloc(sizeof(*iter));
	iter->current = avl_at(mem, 0);
	iter->addr = 0;
	return iter;
}

void
flx_shadowmem_iterator_delete(shadowmem_iterator* iter){
	free(iter);
}

void
flx_shadowmem_block_dealloc(mem_block* block){
	free(block->mem);
	free(block->eips);
	free(block);
}

static mem_block*
flx_shadowmem_block_alloc(uint32_t num_pages){
	mem_block* block = malloc(sizeof(*block));
	block->eips = malloc(num_pages*FLX_PAGE_SIZE*sizeof(*(block->eips)));
	block->mem = malloc(num_pages*FLX_PAGE_SIZE);
	block->len = num_pages*FLX_PAGE_SIZE;
	return block;
}

static mem_block*
flx_shadowmem_block_realloc(mem_block* block, uint32_t num_pages){
	block->eips = realloc(block->eips, num_pages*FLX_PAGE_SIZE*sizeof(uint32_t));
	block->mem  = realloc(block->mem, num_pages*FLX_PAGE_SIZE);
	block->len = num_pages*FLX_PAGE_SIZE;
	return block;
}

mem_block*
flx_shadowmem_iterate(shadowmem_iterator* iter){
	if(!iter->current)
		return NULL;

	uint32_t num_pages = 1;
	uint32_t last_page_addr;

	shadow_page* page = iter->current->item;
	last_page_addr = page->addr;
	mem_block* block = flx_shadowmem_block_alloc(num_pages);
	memcpy(block->mem, page->mem, FLX_PAGE_SIZE);
	memcpy(block->eips, page->eip, FLX_PAGE_SIZE*sizeof(uint32_t));
	iter->current = iter->current->next;

	while(iter->current){
		page = iter->current->item;
		if(page->addr == (last_page_addr+FLX_PAGE_SIZE)){
			block = flx_shadowmem_block_realloc(block, ++num_pages);
			memcpy(&block->mem[(num_pages-1)*FLX_PAGE_SIZE],  page->mem, FLX_PAGE_SIZE);
			memcpy(&block->eips[(num_pages-1)*FLX_PAGE_SIZE], page->eip, FLX_PAGE_SIZE*sizeof(uint32_t));
		}
		else{
			break;
		}
		iter->current = iter->current->next;
	}
	return block;
}

