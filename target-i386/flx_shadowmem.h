#ifndef FLX_SHADOWMEM
#define FLX_SHADOWMEM

#include <avl.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>

#define FLX_PAGE_SIZE 4096

typedef avl_tree_t shadowmem;

typedef struct {
	uint32_t addr;
	avl_node_t* current;
} shadowmem_iterator;

typedef struct {
	uint32_t addr;
	uint8_t* mem;
	uint32_t used[(FLX_PAGE_SIZE)/(sizeof(uint32_t)*8)];
} shadow_page;

typedef struct{
	uint8_t *mem;
	uint32_t len;
} mem_block;

shadowmem* flx_shadowmem_new(void);
void       flx_shadowmem_delete(shadowmem* mem);
void       flx_shadowmem_store(shadowmem* mem, uint32_t address, uint8_t value);
uint8_t    flx_shadowmem_load(shadowmem* mem, uint32_t address, uint8_t *value);

shadowmem_iterator* flx_shadowmem_iterator_new(shadowmem* mem);
void                flx_shadowmem_iterator_delete(shadowmem_iterator* iter);
mem_block*          flx_shadowmem_iterate(shadowmem_iterator* iter);
void                flx_shadowmem_block_dealloc(mem_block* block);

#endif
