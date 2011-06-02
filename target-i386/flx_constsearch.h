#ifndef FLX_CONSTSEARCH
#define FLX_CONSTSEARCH

#include <avl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>

#include "flx_instrument.h"
#include "flx_memtrace.h"
#include "flx_calltrace.h"

typedef int(*constsearch_handler)(uint32_t, uint32_t);

void flx_constsearch_init(constsearch_handler handler);
void flx_constsearch_enable(void);
void flx_constsearch_disable(void);
void flx_constsearch_search(void);
int  flx_constsearch_memaccess(uint32_t, uint32_t, uint8_t, uint8_t);
void flx_constsearch_pattern(uint8_t* , uint32_t);

#endif
