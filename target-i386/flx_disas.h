#ifndef FLX_DISAS
#define FLX_DISAS

#include <avl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>

typedef struct {
	uint8_t* s;
	uint32_t size;
} flx_disassembly;

flx_disassembly*
flx_disas_bbl(uint32_t addr);

#endif
