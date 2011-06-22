#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <avl.h>
#include <math.h>

#include "flx_instrument.h"
#include "flx_taintgraph.h"
#include "flx_functiontaint.h"
#include "flx_calltrace.h"
#include "flx_context.h"

#define FLX_CYCLE_READ 0
#define FLX_CYCLE_WRITE 1

typedef struct taint_stack taint_stack;
struct taint_stack {
	flx_graph* graph;
	uint8_t cycle_state;
	uint32_t eip;
	float quotient;
	uint32_t depth;
	uint32_t* read_buf;
	uint32_t num_read;
	uint32_t* write_buf;
	uint32_t num_write;
	uint32_t buf_size;
	taint_stack* next;
};

float functiontaint_threshold = 0;
functiontaint_handler flx_functiontaint_handler = NULL;

void flx_functiontaint_init(functiontaint_handler handler){
	flx_functiontaint_handler = handler;
}

void flx_functiontaint_enable(float threshold){
	functiontaint_threshold = threshold;

	flx_calltrace_register_handler(flx_functiontaint_functionevent);
	flx_calltrace_enable();
	flx_memtrace_register_handler(flx_functiontaint_memaccess);
	flx_memtrace_enable();

	flx_state.functiontaint_active = 1;
}

void flx_functiontaint_disable(void){
	flx_calltrace_unregister_handler(flx_functiontaint_functionevent);
	flx_memtrace_unregister_handler(flx_functiontaint_memaccess);

	flx_state.functiontaint_active = 0;
}

static int
flx_functiontaint_stackframe_destroy(flx_context* context){
	taint_stack* stack = (taint_stack*)context->memtrace;
	taint_stack* next;
	while(stack){
		flx_graph_dealloc(stack->graph);
		next = stack->next;
		free(stack);
		stack = next;
	}
	return 0;
}

static taint_stack*
flx_functiontaint_stackframe_alloc(void){
	taint_stack* frame = malloc(sizeof(*frame));
	memset(frame, 0, sizeof(*frame));
	frame->graph  = flx_graph_alloc();
	frame->depth  = 1;
	return frame;
}

static void
flx_functiontaint_stackframe_dealloc(taint_stack* frame){
	flx_graph_dealloc(frame->graph);
	free(frame->write_buf);
	free(frame->read_buf);
	free(frame);
}

static taint_stack**
flx_functiontaint_current_stackframe(void){
	flx_context* context = flx_context_current();
	if(!context){
		exit(-1);
	}
	if(!context->taintstack){
		context->taintgraph_destructor = (context_destructor)flx_functiontaint_stackframe_destroy;
	}
	return (taint_stack**)&context->taintstack;
}

static float
flx_functiontaint_calculate_taint(flx_graph* g){
	return flx_taint_quotient(g);
}

static void
flx_functiontaint_functionevent_call(uint32_t new_eip){
	taint_stack** frame = flx_functiontaint_current_stackframe();
	taint_stack* new = flx_functiontaint_stackframe_alloc();
	new->next = *frame;
	*frame = new;
	new->eip = new_eip;
}

static taint_stack*
flx_functiontaint_functionevent_ret(void){
	taint_stack** frame = flx_functiontaint_current_stackframe();
	taint_stack* current = *frame;
	if(current->depth + 1 > current->next->depth)
		current->next->depth = current->depth + 1;
	if(current->depth <= 3){
		current->quotient = flx_functiontaint_calculate_taint(current->graph);
	}
	else{
		current->quotient = 0;
	}
	*frame = current->next;
	return current;
}

int flx_functiontaint_functionevent(uint32_t old_eip, uint32_t new_eip, uint32_t next_eip, uint32_t esp, flx_call_type type){
	taint_stack* frame = NULL;
	switch(type){
	case FLX_CALLTRACE_CALL:
					flx_functiontaint_functionevent_call(new_eip);
					break;
	case FLX_CALLTRACE_RET:
	case FLX_CALLTRACE_MISSED_RET:
					frame = flx_functiontaint_functionevent_ret();
					if(frame){
						if(frame->quotient > functiontaint_threshold){
							flx_functiontaint_handler(frame->quotient, frame->eip);
						}
						flx_functiontaint_stackframe_dealloc(frame);
					}
					break;
	default:
		printf("ERROR: unknown FLX_CALLTRACE TYPE: %d\n",type);
	}
	return 0;
}

static void
flx_functiontaint_fill_graph(taint_stack* frame, uint32_t address, uint8_t iswrite){
	if(frame->buf_size <= frame->num_read || frame->buf_size <= frame->num_write){
		frame->buf_size += 128;
		frame->write_buf = realloc(frame->write_buf, frame->buf_size*sizeof(uint32_t));
		frame->read_buf  = realloc(frame->read_buf,  frame->buf_size*sizeof(uint32_t));
	}
	if(frame->cycle_state == FLX_CYCLE_WRITE && iswrite == FLX_CYCLE_READ){
		uint32_t i,j;
		for(i=0; i<frame->num_write; ++i){
			for(j=0; j<frame->num_read; ++j)
				flx_graph_add_edge(frame->graph, frame->read_buf[j], frame->write_buf[i]);
		}
		frame->num_read = 0;
		frame->num_write = 0;
	}

	frame->cycle_state = iswrite;
	if(iswrite)
		frame->write_buf[frame->num_write++] = address;
	else
		frame->read_buf[frame->num_read++] = address;
}

int flx_functiontaint_memaccess(uint32_t address, uint32_t value, uint8_t size, uint8_t iswrite){
	taint_stack** frame = flx_functiontaint_current_stackframe();
	if(!*frame){
		*frame = flx_functiontaint_stackframe_alloc();
	}
	taint_stack* current = *frame;
	size = size/8;
	address += size-1;
	while(size){
		size-=1;
		flx_functiontaint_fill_graph(current, address, iswrite);
		address -= 1;
	}
	int* x = malloc(100);
	free(x);
	return 0;
}

