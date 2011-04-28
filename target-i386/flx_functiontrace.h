#ifndef FLX_FUNCTIONTRACE
#define FLX_FUNCTIONTRACE

#include <avl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>

#include "flx_instrument.h"
#include "flx_calltrace.h"

typedef int(*functiontrace_handler)(uint32_t new_eip, flx_call_type type);

extern functiontrace_handler flx_functiontrace_handler;

void flx_functiontrace_init(functiontrace_handler handler);
void flx_functiontrace_enable(void);
void flx_functiontrace_disable(void);
int flx_functiontrace_event(uint32_t, uint32_t, uint32_t, uint32_t, flx_call_type);

#endif
