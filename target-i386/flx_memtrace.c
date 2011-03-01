#include <inttypes.h>

#include "exec-all.h"
#include "cpu.h"

#include "flx_instrument.h"
#include "flx_memtrace.h"

uint8_t memtrace_enabled = 0;
mem_access_handler flx_access_handler = NULL;

void flx_memtrace_init(mem_access_handler handler){
	flx_access_handler = handler;
}

void flx_memtrace_start(void){
	tb_invalidate_phys_page_range(0, 0xffffffff, 0);
	memtrace_enabled = 1;
}
void flx_memtrace_stop(void){
	tb_invalidate_phys_page_range(0, 0xffffffff, 0);
	memtrace_enabled = 0;
}

void flx_memtrace_event(uint32_t address, uint32_t value, uint8_t size, uint8_t iswrite){
	if(likely(flx_access_handler)){
		if(!(current_environment->eip &0x80000000) && !(address& 0x80000000))
			flx_access_handler(address, value, size, iswrite);
	}
	else{
		printf("failed to initialize flx_memtrace handler!\n");
	}
}
