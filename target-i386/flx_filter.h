#ifndef FLX_FILTER
#define FLX_FILTER

#include <avl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>

#define MAX_NUM_PAGES 1<<20

void flx_filter_init(void);
void flx_filter_destroy(void);
void flx_filter_enable(void);
void flx_filter_disable(void);
int flx_filter_search_by_addr(uint32_t address);
int flx_filter_del_by_addr(uint32_t address);
int flx_filter_del_by_range(uint32_t start, uint32_t end);
int flx_filter_search_by_range(uint32_t start, uint32_t end);
int flx_filter_add_by_addr(uint32_t address);
int flx_filter_add_by_range(uint32_t start, uint32_t end);

#endif
