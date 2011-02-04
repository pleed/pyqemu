#ifndef _FLX_BREAKPOINT_H
#define _FLX_BREAKPOINT_H

#include <avl.h>
#include <sys/types.h>
#include <inttypes.h>

extern avl_tree_t *bps;

typedef struct {
	uint32_t addr;
	avl_tree_t *processes;
} flx_breakpoint;

void flx_breakpoint_init(void);
void flx_breakpoint_insert(uint32_t addr, uint32_t cr3);
int flx_breakpoint_delete(uint32_t addr, uint32_t cr3);
int flx_breakpoint_search(uint32_t addr, uint32_t cr3);
int flx_breakpoint_search_addr(uint32_t addr, uint32_t *next);


#endif
