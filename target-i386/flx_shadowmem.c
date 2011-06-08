#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <avl.h>
#include <math.h>

#include "flx_shadowmem.h"

#define shadowmem_inuse(page, address) ((page->used[(address&0xfff)/32] >> (address%32)) & 0x01)
#define shadowmem_setuse(page, address) do { page->used[(address&0xfff)/32] |= (1 << (address%32));} while(0)

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
		memset(page->used, 0 , sizeof(page->used));
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
	shadowmem_setuse(page, address);
}

uint8_t
flx_shadowmem_load(shadowmem* mem, uint32_t address, uint8_t *value){
	shadow_page* page = flx_shadowmem_find_page(mem, address);
	assert(page);
	address &= 0xfff;
	if(!shadowmem_inuse(page, address))
		return 0;
	*value = page->mem[address];
	return 1;
}

shadowmem_iterator*
flx_shadowmem_iterator_new(shadowmem* mem){
	shadowmem_iterator* iter = malloc(sizeof(*iter));
	iter->current = avl_at(mem, 0);
	if(iter->current){
		shadow_page* page = iter->current->item;
		iter->addr = page->addr;
	}
	else{
		iter->addr = 0;
	}
	return iter;
}

void
flx_shadowmem_iterator_delete(shadowmem_iterator* iter){
	free(iter);
}

void
flx_shadowmem_block_dealloc(mem_block* block){
	free(block->mem);
	free(block);
}

/*
static mem_block*
flx_shadowmem_block_alloc(uint32_t size){
	mem_block* block = malloc(sizeof(*block));
	block->mem = malloc(size);
	block->len = size;
	return block;
}*/

static uint8_t
flx_shadowmem_get_next_blockstart(shadowmem_iterator* iter){
	while(iter->current){
		shadow_page* page = iter->current->item;
		uint32_t page_offset = iter->addr&0xfff;
		while(page_offset < FLX_PAGE_SIZE && !shadowmem_inuse(page, page_offset)){
			++page_offset;
		}
		iter->addr = (iter->addr&(~0xfff)) + page_offset;
		if(page_offset < FLX_PAGE_SIZE)
			break;
		iter->current = iter->current->next;
	}
	return iter->current != NULL;
}

static uint8_t
flx_shadowmem_get_next_blockbyte(shadowmem_iterator* iter, uint8_t *byte, uint32_t *eip){
	uint8_t found = 0;
	while(iter->current){
		shadow_page* page = iter->current->item;
		if(iter->addr >= page->addr+FLX_PAGE_SIZE){
			iter->current = iter->current->next;
			continue;
		}
		else{
			uint32_t page_offset = iter->addr&0xfff;
			if(shadowmem_inuse(page, page_offset)){
				*byte = page->mem[page_offset];
				*eip  = page->eip[page_offset];
				found = 1;
				++iter->addr;
			}
			break;
		}
	}
	return found;
}

mem_block*
flx_shadowmem_iterate(shadowmem_iterator* iter, uint32_t** arg_eips){
	if(!flx_shadowmem_get_next_blockstart(iter))
		return NULL;

	uint32_t byte_counter = 0;
	uint8_t* buf = malloc(128);
	uint32_t* eips = malloc(128*sizeof(uint32_t));
	uint8_t value;
	uint32_t cur_eip;
	while(flx_shadowmem_get_next_blockbyte(iter, &value, &cur_eip)){
		buf[byte_counter] = value;
		eips[byte_counter] = cur_eip;

		byte_counter++;
		if((byte_counter % 128) == 0){
			buf = realloc(buf, byte_counter+128);
			eips = realloc(eips, (byte_counter+128)*sizeof(uint32_t));
		}
	}
	if(!byte_counter){
		free(buf);
		free(eips);
		return NULL;
	}
	*arg_eips = eips;
	mem_block* new_block = malloc(sizeof(*new_block));
	new_block->mem = buf;
	new_block->len = byte_counter;
	return new_block;
}


#ifdef FLX_SHADOWMEM_DEBUG

uint8_t is_used(shadowmem* mem, uint32_t address){

	shadow_page* page = flx_shadowmem_find_page(mem, address);
	if(!page){
		return 0;
	}
	else{
		address &= 0xfff;
		return shadowmem_inuse(page, address);
	}
}

int main(void){
	shadowmem* mem = flx_shadowmem_new();
	uint32_t i;
	for(i=4090; i<4090+0x100; i+=1){
		flx_shadowmem_store(mem, i, 0x41);
	}
	uint8_t value;
	for(i=4090; i<4090+0x100; i+=1){
		if(!flx_shadowmem_load(mem, i, &value))
			printf("FAIL 1\n");
		if(value != 0x41)
			printf("FAIL 2\n");
	}
	for(i=4090; i<4090+0x100; i+=1){
		if(!is_used(mem, i))
			printf("used fail\n");
	}
	for(i=0; i<4090; i+=2){
		if(is_used(mem, i))
			printf("unused fail\n");
	}
	printf("storing %d pages\n", avl_count(mem));
	mem_block* block;
	shadowmem_iterator* iter = flx_shadowmem_iterator_new(mem);
	while((block = flx_shadowmem_iterate(iter))){
		uint32_t a;
		for(a=0; a<block->len; ++a){
			if(block->mem[a] != 0x41)
				printf("FAIL!!!\n");
		}
		printf("block len: %d\n",block->len);
		flx_shadowmem_block_dealloc(block);
	}
	flx_shadowmem_iterator_delete(iter);
	flx_shadowmem_delete(mem);
	return 0;
}
#endif
