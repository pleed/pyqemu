#include <inttypes.h>

#include "exec-all.h"
#include "cpu.h"

#include "flx_instrument.h"
#include "flx_memtrace.h"

mem_access_handler flx_access_handler = NULL;

void flx_memtrace_init(mem_access_handler handler){
	flx_access_handler = handler;
}

void flx_memtrace_start(void){
	tb_flush(current_environment);
	flx_state.memtrace_active = 1;
}
void flx_memtrace_stop(void){
	tb_flush(current_environment);
	flx_state.memtrace_active = 0;
}

void flx_memtrace_event(uint32_t address, uint32_t value, uint8_t size, uint8_t iswrite){
	flx_access_handler(address, value, size, iswrite);
}
