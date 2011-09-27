#ifndef FLX_PROCESS
#define FLX_PROCESS

#include <avl.h>

/*
 * NOT USED
 */

#include "flx_instrument.h"

typedef struct {
	uint16_t pid;
} flx_process;

void
flx_process* flx_process_new(uint16_t);
void         flx_process_delete(flx_process*);
flx_thread*  flx_process_get(uint16_t);
flx_thread*  flx_process_current(void);

#endif
