#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <avl.h>

#include "flx_instrument.h"
#include "flx_filter.h"

/*
 * To make analysis faster, instrumentation can
 * be reduced to a subset of the process code space.
 * This module stores pages to decide
 * which BBLs should be instrumented in the binary translation.
 */

uint8_t flx_filter_map[MAX_NUM_PAGES];

void flx_filter_init(void){
	memset(flx_filter_map, 0, sizeof(flx_filter_map));
}

void flx_filter_destroy(void){
	return;
}

void flx_filter_enable(void){
	flx_state.filter_active= 1;
}
void flx_filter_disable(void){
	flx_state.filter_active= 0;
}

static inline uint32_t
flx_filter_page_offset(uint32_t address){
	return address>>12;
}

int flx_filter_search_by_addr(uint32_t address){
	return flx_filter_map[flx_filter_page_offset(address)];
}

int flx_filter_del_by_addr(uint32_t address){
	flx_filter_map[flx_filter_page_offset(address)] = 0;
	return 0;
}

int flx_filter_del_by_range(uint32_t start, uint32_t end){
	if(start > end)
		return -1;
	else{
		for(; start<end; start+=0x00001000){
			flx_filter_del_by_addr(start);
		}
	}
	return 0;
}

int flx_filter_search_by_range(uint32_t start, uint32_t end){
	if(start > end)
		return -1;
	else{
		for(; start<end; start+=0x00001000){
			if(flx_filter_search_by_addr(start))
				return 1;
		}
	}
	return 0;
}

int flx_filter_add_by_addr(uint32_t address){
	flx_filter_map[flx_filter_page_offset(address)] = 1;
	return 0;
}


int flx_filter_add_by_range(uint32_t start, uint32_t end){
	if(start > end)
		return -1;
	else{
		for(; start<end; start+=0x00001000){
			flx_filter_add_by_addr(start);
		}
	}
	return 0;
}

