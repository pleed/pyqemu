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
	uint32_t num_mov;
	uint32_t num_ins;
	uint32_t num_arith;
} flx_bbl;

void flx_bbl_init(void);
void flx_bbl_destroy(void);
int flx_bbl_search_by_addr(uint32_t address);
int flx_bbl_del_by_addr(uint32_t address);
int flx_bbl_add_by_addr(uint32_t address);
int flx_bbl_add_by_range(uint32_t start, uint32_t end);

int flx_bbl_new_current(uint32_t address);
int flx_bbl_get_current(void);
int flx_bbl_del_current(
#endif
