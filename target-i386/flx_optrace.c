#include <inttypes.h>
#include <stdint.h>
#include <sys/types.h>
#include <stdio.h>

#include "exec-all.h"
#include "cpu.h"

#include "flx_instrument.h"
#include "flx_optrace.h"

optrace_handler flx_optrace_handler = 0;

void flx_optrace_init(optrace_handler handler){
	flx_optrace_handler = handler;
}

void flx_optrace_enable(void){
	tb_flush(current_environment);
	flx_state.optrace_active = 1;
}

void flx_optrace_disable(void){
	tb_flush(current_environment);
	flx_state.optrace_active = 0;
}

void flx_optrace_event(uint32_t eip, uint32_t opcode){
	if(likely(flx_optrace_handler))
		flx_optrace_handler(eip, opcode);
	else
		printf("failed to initialize flx_optrace handler!\n");
}

int flx_optrace_status(void){
	return flx_state.optrace_active;
}
