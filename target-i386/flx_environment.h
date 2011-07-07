#ifndef FLX_ENVIRONMENT
#define FLX_ENVIRONMENT

#include "cpu.h"
#include "flx_hashmap.h"
#include "flx_instrument.h"

void flx_environment_init(void);
void flx_environment_destroy(void);
void flx_environment_save_state(CPUState*);
CPUState* flx_environment_get_state(uint32_t);

#endif
