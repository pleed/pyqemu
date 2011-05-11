#ifndef FLX_FUNCTION_ENTROPY
#define FLX_FUNCTION_ENTROPY

#include <avl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>

#include "flx_instrument.h"
#include "flx_memtrace.h"
#include "flx_calltrace.h"

typedef int(*functionentropy_handler)(float, uint32_t);

void flx_functionentropy_init(functionentropy_handler handler);
void flx_functionentropy_enable(float);
void flx_functionentropy_disable(void);
int  flx_functionentropy_memaccess(uint32_t, uint32_t, uint8_t, uint8_t);
int  flx_functionentropy_functionevent(uint32_t old_eip, uint32_t new_eip, uint32_t next_eip, uint32_t esp, flx_call_type type);

#endif
