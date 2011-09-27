#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <avl.h>
#include <math.h>

#include "flx_instrument.h"
#include "flx_functionentropy.h"
#include "flx_calltrace.h"
#include "flx_memtrack.h"
#include "flx_context.h"

/*
 * NOT USED
 * Constructed for entropy measurements
 * which have been moved to the a-posteriori
 * analys for performance reasons.
 */

typedef struct function_stack function_stack;
struct function_stack {
	memtracker* before;
	memtracker* after;
	uint32_t eip;
	float diff;
	uint32_t depth;
	function_stack* next;
};

float functionentropy_threshold = 0;
functionentropy_handler flx_functionentropy_handler = NULL;

void flx_functionentropy_init(functionentropy_handler handler){
	flx_functionentropy_handler = handler;
}

void flx_functionentropy_enable(float threshold){
	functionentropy_threshold = threshold;

	flx_calltrace_register_handler(flx_functionentropy_functionevent);
	flx_calltrace_enable();
	flx_memtrace_register_handler(flx_functionentropy_memaccess);
	flx_memtrace_enable();

	flx_state.functionentropy_active = 1;
}

void flx_functionentropy_disable(void){
	flx_calltrace_unregister_handler(flx_functionentropy_functionevent);
	flx_memtrace_unregister_handler(flx_functionentropy_memaccess);

	flx_state.functionentropy_active = 0;
}

static int
flx_functionentropy_stackframe_destroy(flx_context* context){
	function_stack* stack = (function_stack*)context->memtrace;
	function_stack* next;
	while(stack){
		flx_memtrack_delete(stack->before);
		flx_memtrack_delete(stack->after);
		next = stack->next;
		free(stack);
		stack = next;
	}
	return 0;
}

static function_stack*
flx_functionentropy_stackframe_alloc(void){
	function_stack* frame = malloc(sizeof(*frame));
	memset(frame, 0, sizeof(*frame));
	frame->before = flx_memtrack_new();
	frame->after  = flx_memtrack_new();
	frame->depth  = 1;
	return frame;
}

static void
flx_functionentropy_stackframe_dealloc(function_stack* frame){
	flx_memtrack_delete(frame->before);	
	flx_memtrack_delete(frame->after);	
	free(frame);
}

static function_stack**
flx_functionentropy_current_stackframe(void){
	flx_context* context = flx_context_current();
	if(!context){
		exit(-1);
	}
	if(!context->memtrace){
		context->memtrace_destructor = (context_destructor)flx_functionentropy_stackframe_destroy;
	}
	return (function_stack**)&context->memtrace;
}

static float
flx_functionentropy_calculate_entropy(memtracker* tracker, uint32_t *bytes){
	return 0.0;
	memtrack_iterator iter = flx_memtrack_iterator();
	memory_byte* current;

	uint32_t byte_counter = 0;
	uint32_t values[256];
	memset(values, 0, sizeof(values));

	//printf("values: ");
	while((current = flx_memtrack_iterate(tracker, &iter))){
		uint8_t current_value = current->value;
		values[current_value] += 1;
		byte_counter += 1;
		//printf(" %d ",current_value);
	}
	//printf("\n");
	*bytes = byte_counter;
	if(byte_counter == 0)
		return 0;

	/* calculate scaled entropy */
	float e_sum = 0;
	uint16_t i;
	for(i=0; i<256; ++i){
		if(values[i] > 0){
			float tmp_1 = ((float)values[i])/byte_counter;
			float tmp_2 = (log(((float)values[i])/byte_counter)/log(2));
			e_sum += tmp_1*tmp_2;
		}
		//e_sum += ((float)values[i])/byte_counter*(log(((float)values[i])/byte_counter)/log(2));
	}
	float scaled_entropy = (e_sum*-1)/(log((byte_counter < 256)?byte_counter:256)/log(2));
	return scaled_entropy;
}

static void
flx_functionentropy_functionevent_call(uint32_t new_eip){
	function_stack** frame = flx_functionentropy_current_stackframe();
	function_stack* new = flx_functionentropy_stackframe_alloc();
	new->next = *frame;
	*frame = new;
	new->eip = new_eip;
}

static function_stack*
flx_functionentropy_functionevent_ret(void){
	function_stack** frame = flx_functionentropy_current_stackframe();
	function_stack* current = *frame;
	if(current->depth + 1 > current->next->depth)
		current->next->depth = current->depth + 1;
	if(current->depth <= 3){
		uint32_t bytes_touched = 0;
		//printf("after\n");
		float after  = flx_functionentropy_calculate_entropy(current->after, &bytes_touched);
		//printf("entropy: %f\n", after);
		//printf("before\n");
		float before = flx_functionentropy_calculate_entropy(current->before, &bytes_touched);
		//printf("entropy: %f\n", before);
		float diff;
		if(before == 0 || after == 0 || bytes_touched < 20)
			diff = 0;
		else{
			diff = after - before;
			if(diff < 0)
				diff *= -1;
		}
		current->diff = diff;
		flx_memtrack_merge(current->next->before, current->before, 0);
		flx_memtrack_merge(current->next->after, current->after, 1);
	}
	else{
		current->diff = 0;
	}
	*frame = current->next;
	return current;
}

int flx_functionentropy_functionevent(uint32_t old_eip, uint32_t new_eip, uint32_t next_eip, uint32_t esp, flx_call_type type){
	function_stack* frame = NULL;
	switch(type){
	case FLX_CALLTRACE_CALL:
					flx_functionentropy_functionevent_call(new_eip);
					break;
	case FLX_CALLTRACE_RET:
	case FLX_CALLTRACE_MISSED_RET:
					frame = flx_functionentropy_functionevent_ret();
					if(frame){
						if(frame->diff > functionentropy_threshold){
							//printf("entropy handling, diff: %f, eip: 0x%x\n",frame->diff, frame->eip);
							flx_functionentropy_handler(frame->diff, frame->eip);
						}
						flx_functionentropy_stackframe_dealloc(frame);
					}
					break;
	default:
		printf("ERROR: unknown FLX_CALLTRACE TYPE: %d\n",type);
	}
	return 0;
}

int flx_functionentropy_memaccess(uint32_t address, uint32_t value, uint8_t size, uint8_t iswrite){
	function_stack** frame = flx_functionentropy_current_stackframe();
	if(!*frame){
		*frame = flx_functionentropy_stackframe_alloc();
	}
	function_stack* current = *frame;
	size = size/8;
	address += size-1;
	while(size){
		size-=1;
		uint8_t byte = (value >> (size*8)) & 0xff;
		if(iswrite){
			flx_memtrack_store(current->after, address, byte, 1);
		}
		else{
			flx_memtrack_store(current->after, address, byte, 0);
			flx_memtrack_store(current->before, address, byte, 0);
		}
		address -= 1;
	}
	return 0;
}

