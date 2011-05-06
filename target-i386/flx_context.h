#ifndef FLX_CONTEXT
#define FLX_CONTEXT

#include <avl.h>

#include "flx_instrument.h"

typedef int (*context_destructor)(void*);

typedef struct {
	uint16_t pid;
	uint16_t tid;
	void *calltrace;
	void *memtrace;
	context_destructor calltrace_destructor;
	context_destructor memtrace_destructor;
} flx_context;

void         flx_context_init(void);
void         flx_context_set(int32_t, int32_t);
flx_context* flx_context_current(void);

#endif
