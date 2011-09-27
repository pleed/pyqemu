#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>

#include "flx_instrument.h"
#include "flx_calltrace.h"
#include "flx_functiontrace.h"

/*
 * This module provides high level event generation
 * for the python interface to build shadow callstacks
 * in the python layer.
 */

functiontrace_handler flx_functiontrace_handler = NULL;

void flx_functiontrace_init(functiontrace_handler handler){
	flx_functiontrace_handler = handler;
}

void flx_functiontrace_enable(void){
	flx_calltrace_enable();
	flx_calltrace_register_handler(flx_functiontrace_event);
	flx_state.functiontrace_active = 1;
}

void flx_functiontrace_disable(void){
	flx_calltrace_unregister_handler(flx_functiontrace_event);
	flx_state.functiontrace_active = 0;
}

int flx_functiontrace_event(uint32_t old_eip, uint32_t new_eip, uint32_t next_eip, uint32_t esp, flx_call_type type){
	flx_functiontrace_handler(new_eip, type);
	return 0;
}

