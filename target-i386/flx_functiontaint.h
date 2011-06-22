#ifndef FLX_FUNCTION_TAINT
#define FLX_FUNCTION_TAINT

#include <avl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>

#include "flx_instrument.h"
#include "flx_memtrace.h"
#include "flx_calltrace.h"

typedef int(*functiontaint_handler)(float, uint32_t);

void flx_functiontaint_init(functiontaint_handler handler);
void flx_functiontaint_enable(float);
void flx_functiontaint_disable(void);
int  flx_functiontaint_memaccess(uint32_t, uint32_t, uint8_t, uint8_t);
int  flx_functiontaint_functionevent(uint32_t old_eip, uint32_t new_eip, uint32_t next_eip, uint32_t esp, flx_call_type type);

#endif
