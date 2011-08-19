#ifndef FLX_CODESEARCH
#define FLX_CODESEARCH

#include <avl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>

#include "flx_instrument.h"
#include "flx_memtrace.h"
#include "flx_calltrace.h"

#define FLX_INSN_CHAIN_RESIZE 1024

typedef struct insn_chain insn_chain;
struct insn_chain {
	uint32_t* data;
	uint32_t* eips;
	uint32_t len;
	uint32_t size;
	insn_chain* next;
};

typedef int(*codesearch_handler)(uint32_t, uint8_t*, uint32_t);

void flx_codesearch_init(codesearch_handler handler);
void flx_codesearch_enable(void);
void flx_codesearch_disable(void);
void flx_codesearch_search(void);
int  flx_codesearch_bbl(uint32_t, uint32_t);
int  flx_codesearch_calltrace(uint32_t, uint32_t, uint32_t, uint32_t, flx_call_type);
void flx_codesearch_pattern(uint8_t* , uint32_t);

#endif
