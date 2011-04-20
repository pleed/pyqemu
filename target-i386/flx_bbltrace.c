#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <avl.h>

#include "flx_instrument.h"
#include "flx_bbltrace.h"

bbltrace_handler[MAX_BBLTRACE_HANDLERS] flx_bbltrace_handlers;

void flx_bbltrace_init(bbltrace_handler handler){
	memset(flx_bbltrace_handlers, 0, sizeof(flx_bbltrace_handlers));
	flx_bbltrace_handlers[0] = handler;
}

void flx_bbltrace_enable(void){
	flx_state.bbltrace_active = 1;
}

void flx_bbltrace_disable(void){
	flx_state.bbltrace_active = 0;
}

void flx_bbltrace_event(uint32_t eip, uint32_t esp){
	uint8_t i;
	for(i=0; i<MAX_BBLTRACE_HANDLERS; ++i){
		if(!flx_bbltrace_handlers[i])
			break;
		flx_bbltrace_handlers[i](eip, esp)
	}
}

void flx_bbltrace_register_handler(bbltrace_handler handler){
	uint8_t i;
	for(i=0; i<MAX_BBLTRACE_HANDLERS; ++i){
		if(!flx_bbltrace_handlers[i]){
			flx_bbltrace_handlers[i] = handler
			return
		}
	}
	printf("WARNING, MAX_BBLTRACE_HANDLERS reached!!!\n");
	exit(-1);
	return;
}

void flx_bbltrace_unregister_handler(bbltrace_handler handler){
	uint8_t i;
	uint8_t handler_index;
	uint8_t last_handler_index;
	for(i=0; i<MAX_BBLTRACE_HANDLERS; ++i){
		if(flx_bbltrace_handlers[i]){
			last_handler_index = i;
			if(flx_bbltrace_handlers[i] == handler){
				handler_index = i;
			}
		}
	}
	flx_bbltrace_handlers[handler_index] = flx_bbltrace_handlers[last_handler_index];
	flx_bbltrace_handlers[last_handler_index] = NULL;
}
