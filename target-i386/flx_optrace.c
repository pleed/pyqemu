#include <inttypes.h>
#include <stdint.h>
#include <sys/types.h>
#include <stdio.h>

#include "exec-all.h"
#include "cpu.h"

#include "flx_optrace.h"

uint8_t optrace_enabled = 0;
optrace_handler flx_optrace_handler = 0;

void flx_optrace_init(optrace_handler handler){
	flx_optrace_handler = handler;
}

void flx_optrace_enable(void){
	tb_invalidate_phys_page_range(0, 0xffffffff, 0);
	optrace_enabled = 1;
}

void flx_optrace_disable(void){
	tb_invalidate_phys_page_range(0, 0xffffffff, 0);
	optrace_enabled = 0;
}

void flx_optrace_event(uint32_t eip, uint32_t opcode){
	if(likely(flx_optrace_handler))
		flx_optrace_handler(eip, opcode);
	else
		printf("failed to initialize flx_optrace handler!\n");
}
