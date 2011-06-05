#ifndef FLX_ENTROPY
#define FLX_ENTROPY

#include <avl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>

#include "flx_instrument.h"

typedef int(*entropy_handler)(float, float);

extern entropy_handler flx_entropy_handler;

void flx_entropy_init(entropy_handler handler);
void flx_entropy_enable(float);
void flx_entropy_disable(void);
int flx_entropy_callevent(uint32_t, uint32_t, uint32_t, uint32_t flx_call_type);
int flx_entropy_memaccess(uint32_t, uint32_t, uint8_t, uint8_t);

#endif
