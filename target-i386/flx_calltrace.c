#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <avl.h>
#include <stdio.h>

#include "flx_instrument.h"
#include "flx_bbltrace.h"
#include "flx_calltrace.h"

calltrace_handler flx_calltrace_handlers[MAX_CALLTRACE_HANDLERS];

#define FLX_CALLTRACE_STACKFRAMES_STEPS 1000
typedef struct {
	uint32_t eip;
	uint32_t esp;
} flx_frame;

typedef struct {
	flx_frame* frames;
	uint32_t  max_element;
	uint32_t  cur_element;
} flx_stackframes;

flx_stackframes stackframes;
uint8_t flx_calltrace_last_call = 0;

static void flx_calltrace_stackframes_push(uint32_t esp, uint32_t eip);
static inline uint32_t flx_calltrace_stackframes_left(uint32_t esp);
static uint8_t flx_calltrace_stackframes_pop(uint32_t* esp, uint32_t* eip);
static void flx_calltrace_stackframes_realloc(void);

static inline uint32_t
flx_calltrace_stackframes_left(uint32_t esp){
	uint32_t stackframes_left = 0;
	uint32_t i = stackframes.cur_element;
	while(i>0 && esp > stackframes.frames[i].esp){
		++stackframes_left;
		--i;
	}
	return stackframes_left;
}

static void
flx_calltrace_stackframes_push(uint32_t esp, uint32_t eip){
	if(stackframes.cur_element >= stackframes.max_element)
		flx_calltrace_stackframes_realloc();
	stackframes.frames[stackframes.cur_element].esp = esp;
	stackframes.frames[stackframes.cur_element].eip = eip;
	++stackframes.cur_element;
}

static uint8_t
flx_calltrace_stackframes_pop(uint32_t* esp, uint32_t* eip){
	if(stackframes.cur_element == 0)
		return 0;

	--stackframes.cur_element;
	*esp = stackframes.frames[stackframes.cur_element].esp;
	*eip = stackframes.frames[stackframes.cur_element].eip;
	return 1;
}

static void 
flx_calltrace_stackframes_realloc(void){
	uint32_t new_size = (stackframes.max_element+FLX_CALLTRACE_STACKFRAMES_STEPS)*sizeof(*(stackframes.frames));
	stackframes.max_element += FLX_CALLTRACE_STACKFRAMES_STEPS;
	stackframes.frames = realloc(stackframes.frames, new_size);
}


void flx_calltrace_init(void){
	return;
}

void flx_calltrace_enable(void){
	memset(flx_calltrace_handlers, 0, sizeof(flx_calltrace_handlers));
	memset(&stackframes, 0, sizeof(stackframes));
	stackframes.frames = malloc(sizeof(*(stackframes.frames))*FLX_CALLTRACE_STACKFRAMES_STEPS);
	stackframes.max_element = FLX_CALLTRACE_STACKFRAMES_STEPS;

	flx_state.bbltrace_active = 1;
	flx_bbltrace_register_handler(flx_calltrace_bblexec);
	flx_state.calltrace_active = 1;

}

void flx_calltrace_disable(void){
	flx_state.calltrace_active = 0;
	flx_bbltrace_unregister_handler(flx_calltrace_bblexec);
	free(stackframes.frames);
}

int flx_calltrace_bblexec(uint32_t eip, uint32_t esp){
	if(flx_calltrace_last_call){
		flx_calltrace_last_call = 0;
		return 0;
	}

	uint32_t cur_esp = 0;
	uint32_t cur_eip = 0;
	uint32_t frames_left = flx_calltrace_stackframes_left(esp);
	while(frames_left > 1){
		flx_calltrace_stackframes_pop(&cur_esp,&cur_eip);
		uint8_t i;
		for(i=0; i<MAX_CALLTRACE_HANDLERS; ++i){
			if(!flx_calltrace_handlers[i])
				break;
			flx_calltrace_handlers[i](0, cur_eip, 0, cur_esp, FLX_CALLTRACE_MISSED_RET);
		}
		frames_left--;
	}
	if(frames_left==1){
		flx_calltrace_stackframes_pop(&cur_esp, &cur_eip);
		uint8_t i;
		for(i=0; i<MAX_CALLTRACE_HANDLERS; ++i){
			if(!flx_calltrace_handlers[i])
				break;
			flx_calltrace_handlers[i](0, cur_eip, 0, cur_esp, FLX_CALLTRACE_RET);
		}
	}
	return 0;
}

void flx_calltrace_event(uint32_t old_eip, uint32_t new_eip, uint32_t next_eip, uint32_t esp){
	flx_calltrace_last_call = 1;
	flx_calltrace_stackframes_push(esp, next_eip);

	uint8_t i;
	for(i=0; i<MAX_CALLTRACE_HANDLERS; ++i){
		if(!flx_calltrace_handlers[i])
			break;
		flx_calltrace_handlers[i](old_eip, new_eip, next_eip, esp, FLX_CALLTRACE_CALL);
	}
}

void flx_calltrace_register_handler(calltrace_handler handler){
	uint8_t i;
	for(i=0; i<MAX_CALLTRACE_HANDLERS; ++i){
		if(!flx_calltrace_handlers[i]){
			flx_calltrace_handlers[i] = handler;
			return;
		}
	}
	printf("WARNING, MAX_CALLTRACE_HANDLERS reached!!!\n");
	exit(-1);
	return;
}

void flx_calltrace_unregister_handler(calltrace_handler handler){
	uint8_t i;
	uint8_t handler_index = 0;
	uint8_t last_handler_index = 0;
	for(i=0; i<MAX_CALLTRACE_HANDLERS; ++i){
		if(flx_calltrace_handlers[i]){
			last_handler_index = i;
			if(flx_calltrace_handlers[i] == handler){
				handler_index = i;
			}
		}
	}
	flx_calltrace_handlers[handler_index] = flx_calltrace_handlers[last_handler_index];
	flx_calltrace_handlers[last_handler_index] = NULL;
}

