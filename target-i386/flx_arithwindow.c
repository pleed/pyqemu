#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <avl.h>

#include "flx_instrument.h"
#include "flx_arithwindow.h"
#include "flx_bbltranslate.h"
#include "flx_bbltrace.h"

arithwindow_handler flx_arithwindow_handler = NULL;

uint16_t arithwindow_cache[65536];

typedef struct {
	flx_bbl** bbls;
	uint32_t window_size;
	uint32_t start_index;
	uint32_t end_index;
	uint32_t instructions;
	uint32_t arith_instructions;
	float    arith_percentage;
} bbl_window;

bbl_window flx_bbl_window;

static inline void flx_arithwindow_cache_init(void);
static inline int flx_arithwindow_cache_search(uint32_t);
static inline void flx_arithwindow_cache_del(uint32_t);
static inline void flx_arithwindow_cache_add(uint32_t);

static inline void flx_arithwindow_cache_init(void){
	memset(arithwindow_cache, 0, sizeof(arithwindow_cache));
}

static inline int flx_arithwindow_cache_search(uint32_t addr){
	if(arithwindow_cache[addr&0xffff] == addr>>16)
		return 1;
	return 0;
}
static inline void flx_arithwindow_cache_add(uint32_t addr){
	arithwindow_cache[addr&0xffff] = addr>>16;
}

static inline void flx_arithwindow_cache_del(uint32_t addr){
	arithwindow_cache[addr&0xffff] = 0;
}

void flx_arithwindow_init(arithwindow_handler handler){
	memset(&flx_bbl_window, 0, sizeof(flx_bbl_window));

	flx_arithwindow_handler = handler;

	flx_bbltrace_enable();
	flx_bbltranslate_enable();
}

void flx_arithwindow_destroy(void){
	flx_arithwindow_disable();
	free(flx_bbl_window.bbls);
}

void flx_arithwindow_enable(uint32_t window_size, float arith_percentage){
	flx_arithwindow_cache_init();
	flx_bbl_window.bbls = malloc(sizeof(flx_bbl*) * window_size);
	flx_bbl_window.window_size = window_size;
	flx_bbl_window.arith_percentage = arith_percentage;

	flx_bbltrace_register_handler(flx_arithwindow_bblexec);
	flx_bbltranslate_register_handler(flx_arithwindow_bbltranslate);
	flx_state.arithwindow_active = 1;

	uint32_t i;
	for(i=0; i<window_size; ++i){
		flx_bbl_window.bbls[i] = malloc(sizeof(flx_bbl));
	}
}

void flx_arithwindow_disable(void){
	flx_bbltrace_unregister_handler(flx_arithwindow_bblexec);
	flx_bbltranslate_unregister_handler(flx_arithwindow_bbltranslate);
	flx_state.arithwindow_active = 0;
	uint32_t i;
	for(i=0; i<flx_bbl_window.window_size; ++i){
		free(flx_bbl_window.bbls[i]);
	}
	free(flx_bbl_window.bbls);
}

int flx_arithwindow_bblexec(uint32_t eip, uint32_t esp){
	flx_bbl* bbl = flx_bbl_search(eip);
	memcpy(flx_bbl_window.bbls[flx_bbl_window.end_index], bbl, sizeof(*bbl));

	flx_bbl_window.instructions       += bbl->icount;
	flx_bbl_window.arith_instructions += bbl->arithcount;

	flx_bbl_window.end_index += 1;
	flx_bbl_window.end_index %= flx_bbl_window.window_size;

	if(flx_bbl_window.instructions > flx_bbl_window.window_size){
		if((float)flx_bbl_window.arith_instructions / (float)flx_bbl_window.instructions >= flx_bbl_window.arith_percentage &&
		    !flx_arithwindow_cache_search(flx_bbl_window.bbls[flx_bbl_window.start_index]->addr)){
			flx_arithwindow_handler(flx_bbl_window.bbls[flx_bbl_window.start_index]->addr);
			flx_arithwindow_cache_add(flx_bbl_window.bbls[flx_bbl_window.start_index]->addr);
		}
		flx_bbl_window.instructions       -= flx_bbl_window.bbls[flx_bbl_window.start_index]->icount;
		flx_bbl_window.arith_instructions -= flx_bbl_window.bbls[flx_bbl_window.start_index]->arithcount;

		flx_bbl_window.start_index += 1;
		flx_bbl_window.start_index %= flx_bbl_window.window_size;
	}
	return 0;
}

int flx_arithwindow_bbltranslate(flx_bbl* bbl){
	flx_bbl* new_bbl = malloc(sizeof(*bbl));
	memcpy(new_bbl, bbl, sizeof(*new_bbl));
	flx_bbl_add(new_bbl);

	if(flx_arithwindow_cache_search(bbl->addr))
		flx_arithwindow_cache_del(bbl->addr);
	return 0;
}
