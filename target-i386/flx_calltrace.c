#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <avl.h>
#include <stdio.h>

#include "flx_instrument.h"
#include "flx_bbltrace.h"
#include "flx_calltrace.h"
#include "flx_context.h"

calltrace_handler flx_calltrace_handlers[MAX_CALLTRACE_HANDLERS];

static void flx_calltrace_stackframes_push(flx_stackframes* stackframes, uint32_t esp, uint32_t eip);
static inline uint32_t flx_calltrace_stackframes_left(flx_stackframes* stackframes, uint32_t esp);
static uint8_t flx_calltrace_stackframes_pop(flx_stackframes* stackframes, uint32_t* esp, uint32_t* eip);
static void flx_calltrace_stackframes_realloc(flx_stackframes* stackframes);
static flx_stackframes* flx_calltrace_current_stackframes(void);
static flx_stackframes*  flx_calltrace_stackframes_alloc(void);
static int               flx_calltrace_stackframes_destroy(flx_context*);

static int
flx_calltrace_stackframes_destroy(flx_context* context){
	flx_stackframes* stackframes = context->calltrace;
	free(stackframes->frames);
	free(stackframes);
	return 0;
}

static inline uint32_t
flx_calltrace_stackframes_left(flx_stackframes* stackframes, uint32_t esp){
	uint32_t stackframes_left = 0;
	uint32_t i = stackframes->cur_element;
	while(i>0 && esp > stackframes->frames[i-1].esp){
		++stackframes_left;
		--i;
	}
	return stackframes_left;
}

static void
flx_calltrace_stackframes_push(flx_stackframes* stackframes, uint32_t esp, uint32_t eip){
	if(stackframes->cur_element >= stackframes->max_element)
		flx_calltrace_stackframes_realloc(stackframes);
	stackframes->frames[stackframes->cur_element].esp = esp;
	stackframes->frames[stackframes->cur_element].eip = eip;
	stackframes->cur_element += 1;
}

static uint8_t
flx_calltrace_stackframes_pop(flx_stackframes* stackframes, uint32_t* esp, uint32_t* eip){
	if(stackframes->cur_element == 0)
		return 0;

	stackframes->cur_element -= 1;
	*esp = stackframes->frames[stackframes->cur_element].esp;
	*eip = stackframes->frames[stackframes->cur_element].eip;
	return 1;
}

static void 
flx_calltrace_stackframes_realloc(flx_stackframes* stackframes){
	uint32_t new_size = (stackframes->max_element+FLX_CALLTRACE_STACKFRAMES_STEPS)*sizeof(*(stackframes->frames));
	stackframes->max_element += FLX_CALLTRACE_STACKFRAMES_STEPS;
	stackframes->frames = realloc(stackframes->frames, new_size);
}


void flx_calltrace_init(void){
	memset(flx_calltrace_handlers, 0, sizeof(flx_calltrace_handlers));
	return;
}

static flx_stackframes*
flx_calltrace_stackframes_alloc(void){
	flx_stackframes* stackframes = malloc(sizeof(*stackframes));
	memset(stackframes, 0, sizeof(*stackframes));
	stackframes->frames = malloc(sizeof(*(stackframes->frames))*FLX_CALLTRACE_STACKFRAMES_STEPS);
	stackframes->max_element = FLX_CALLTRACE_STACKFRAMES_STEPS;
	stackframes->cur_element = 0;
	return stackframes;
}

void flx_calltrace_enable(void){
	flx_state.bbltrace_active = 1;
	flx_bbltrace_register_handler(flx_calltrace_bblexec);
	flx_state.calltrace_active = 1;
}

void flx_calltrace_disable(void){
	flx_state.calltrace_active = 0;
	flx_bbltrace_unregister_handler(flx_calltrace_bblexec);
}

static flx_stackframes*
flx_calltrace_current_stackframes(void){
	flx_context* context = flx_context_current();
	if(!context){
		exit(-1);
	}
	if(!context->calltrace){
		context->calltrace = flx_calltrace_stackframes_alloc();
		context->calltrace_destructor = (context_destructor)flx_calltrace_stackframes_destroy;
	}
	return context->calltrace;
}

int flx_calltrace_bblexec(uint32_t eip, uint32_t esp){
	uint32_t cur_esp = 0;
	uint32_t cur_eip = 0;
	uint32_t frames_left = 0; 
	flx_stackframes* stackframes = flx_calltrace_current_stackframes();

	if(stackframes->cur_element == 0){
		return 0;
	}

	else if(eip == stackframes->frames[stackframes->cur_element-1].eip){
		flx_calltrace_stackframes_pop(stackframes, &cur_esp, &cur_eip);
		uint8_t i;
		for(i=0; i<MAX_CALLTRACE_HANDLERS; ++i){
			if(!flx_calltrace_handlers[i])
				break;
			flx_calltrace_handlers[i](0, cur_eip, 0, cur_esp, FLX_CALLTRACE_RET);
		}
	}
	else if((frames_left = flx_calltrace_stackframes_left(stackframes, esp)) > 0){
		while(frames_left > 1){
			flx_calltrace_stackframes_pop(stackframes, &cur_esp,&cur_eip);
			uint8_t i;
			for(i=0; i<MAX_CALLTRACE_HANDLERS; ++i){
				if(!flx_calltrace_handlers[i])
					break;
				flx_calltrace_handlers[i](0, cur_eip, 0, cur_esp, FLX_CALLTRACE_MISSED_RET);
			}
			frames_left--;
		}
		flx_calltrace_stackframes_pop(stackframes, &cur_esp, &cur_eip);
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
	flx_stackframes* stackframes = flx_calltrace_current_stackframes();
	flx_calltrace_stackframes_push(stackframes, esp, next_eip);

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

