#ifndef FLX_BBL
#define FLX_BBL

#include <avl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>

#define NUM_BBL_TREES 256
#define BBL_CACHE_SIZE 4096

extern avl_tree_t* bbl_trees[NUM_BBL_TREES];

typedef struct {
	uint32_t addr;
	uint32_t icount;
	uint32_t arithcount;
} flx_bbl;

typedef struct {
	flx_bbl* bbls[BBL_CACHE_SIZE];
	uint8_t valid[BBL_CACHE_SIZE];
} bbl_cache;

void flx_bbl_init(void);
void flx_bbl_destroy(void);
void flx_bbl_add(flx_bbl* bbl);
void flx_bbl_flush(void);
flx_bbl* flx_bbl_search(uint32_t addr);

#endif
