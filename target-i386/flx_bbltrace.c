#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <avl.h>

#include "flx_instrument.h"
#include "flx_bbltrace.h"

bbltrace_handler flx_bbltrace_handler = NULL;

void flx_bbltrace_init(bbltrace_handler handler){
	flx_bbltrace_handler = handler;
}

void flx_bbltrace_enable(void){
	flx_state.bbltrace_active = 1;
}

void flx_bbltrace_disable(void){
	flx_state.bbltrace_active = 0;
}

void flx_bbltrace_event(uint32_t eip, uint32_t esp){
	flx_bbltrace_handler(eip, esp);
}
