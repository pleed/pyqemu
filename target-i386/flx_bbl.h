#ifndef FLX_FILTER
#define FLX_FILTER

#include <avl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>

#define NUM_FILTER_TREES 256

extern avl_tree_t* bbl_trees[NUM_FILTER_TREES];

typedef struct {
	uint32_t eip;
	uint32_t icount;
	uint32_t arithcount;
} flx_bbl;

void flx_bbltrace_init(void);
void flx_bbltrace_enable(void);
void flx_bbltrace_disable(void);

void flx_bbltrace_arith(void);
void flx_bbltrace_next(uint32_t eip);
flx_bbl* flx_bbltrace_cur(void);

#endif
