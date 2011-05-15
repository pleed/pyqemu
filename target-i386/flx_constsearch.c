#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <avl.h>
#include <math.h>

#include "flx_instrument.h"
#include "flx_shadowmem.h"
#include "flx_constsearch.h"
#include "flx_memtrack.h"
#include "flx_context.h"


float constsearch_threshold = 0;
constsearch_handler flx_constsearch_handler = NULL;

void flx_constsearch_init(constsearch_handler handler){
	flx_constsearch_handler = handler;
}

void flx_constsearch_enable(void){
	flx_memtrace_register_handler(flx_constsearch_memaccess);
	flx_memtrace_enable();

	flx_state.constsearch_active = 1;
}

void flx_constsearch_disable(void){
	flx_memtrace_unregister_handler(flx_constsearch_memaccess);
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
			flx_shadowmem_store(mem, address, byte);
			address -= 1;
		}
	}
	return 0;
}

