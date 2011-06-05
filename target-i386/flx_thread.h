#ifndef FLX_CONTEXT
#define FLX_CONTEXT

#include <avl.h>

#include "flx_instrument.h"

typedef struct {
	uint16_t tid;
} flx_thread;

flx_thread* flx_thread_new(uint16_t);
void        flx_thread_delete(flx_thread*);
int         flx_thread_

#endif
