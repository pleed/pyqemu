#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <avl.h>
#include <math.h>
#include <shmatch.h>

#include "flx_instrument.h"
#include "flx_shadowmem.h"
#include "flx_constsearch.h"
#include "flx_memtrack.h"
#include "flx_context.h"


float constsearch_threshold = 0;
constsearch_handler flx_constsearch_handler = NULL;
struct shmatcher* mem_block_matcher = NULL;

void flx_constsearch_init(constsearch_handler handler){
	flx_constsearch_handler = handler;
}

void flx_constsearch_enable(void){
	flx_memtrace_register_handler(flx_constsearch_memaccess);
	flx_memtrace_enable();

	mem_block_matcher = shmatch_new(shmatch_stub_encode);
	flx_state.constsearch_active = 1;
}

void flx_constsearch_disable(void){
	flx_memtrace_unregister_handler(flx_constsearch_memaccess);

	shmatch_destroy(mem_block_matcher);
	mem_block_matcher = NULL;
	flx_state.constsearch_active = 0;
}

static int
flx_constsearch_destructor(flx_context* c){
	flx_shadowmem_delete(c->constsearch);	
	return 0;
}

static shadowmem*
flx_constsearch_current_memory(void){
	flx_context* current = flx_context_current();
	assert(current != NULL);
	if(!current->constsearch){
		current->constsearch = flx_shadowmem_new() ;
		current->constsearch_destructor = (context_destructor)flx_constsearch_destructor;
	}
	return current->constsearch;
}

int flx_constsearch_memaccess(uint32_t address, uint32_t value, uint8_t size, uint8_t iswrite){
	if(!iswrite){
		shadowmem* mem = flx_constsearch_current_memory();
		size = size/8;
		address += size-1;
		while(size){
			size-=1;
			uint8_t byte = (value >> (size*8)) & 0xff;
			flx_shadowmem_store(mem, address, byte, current_environment->eip);
			address -= 1;
		}
	}
	return 0;
}

void flx_constsearch_search(void){
	static struct string tmp_string = {0,NULL};

	mem_block* block = NULL;
	shadowmem* mem = flx_constsearch_current_memory();

	shadowmem_iterator* iter = flx_shadowmem_iterator_new(mem);
	uint32_t* eips = NULL;
	while((block = flx_shadowmem_iterate(iter, &eips))){
		tmp_string.data = (char*)&block->mem[0];
		tmp_string.len  = block->len;
		assert(tmp_string.data != NULL && tmp_string.len > 0);
		struct match* p = shmatch_search(mem_block_matcher, &tmp_string);
		while(p){
			struct pattern* needle = p->needle;
			flxinstrument_constsearch_event(eips[p->startpos], (uint8_t*)needle->data->data, needle->data->len);
			p = shmatch_search(mem_block_matcher, NULL);
		}
		flx_shadowmem_block_dealloc(block);
		free(eips);
	}
	flx_shadowmem_iterator_delete(iter);

	block=(mem_block*)mem++;
}

void flx_constsearch_pattern(uint8_t* pattern, uint32_t len){
	struct string* new_pattern = shmatch_string_new(len);
	memcpy(new_pattern->data, pattern, len);
	if(!mem_block_matcher)
		flx_constsearch_enable();
	if(shmatch_add_pattern(mem_block_matcher, new_pattern) == -1){
		printf("Unable to add pattern into automaton!\n");
		exit(-1);
	}
}

