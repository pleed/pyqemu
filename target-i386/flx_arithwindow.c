#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <avl.h>

#include "flx_instrument.h"
#include "flx_arithwindow.h"
#include "flx_bbltranslate.h"

arithwindow_handler flx_arithwindow_handler = NULL;

typedef {
	flx_bbl** bbls;
	uint32_t window_size;
	uint32_t start_index;
	uint32_t end_index;
	uint32_t instructions;
	uint32_t arith_instructions;
	float    arith_percentage;
} bbl_window;

bbl_window flx_bbl_window;

void flx_arithwindow_init(arithwindow_handler handler, uint32_t window_size, float arith_percentage){
	memset(&flx_bbl_window, 0, sizeof(flx_bbl_window));
	flx_bbl_window.bbls = malloc(sizeof(flx_bbl*) * window_size);
	flx_bbl_window.window_size = window_size;

	flx_arithwindow_handler = handler;

	flx_bbltrace_register_handler(flx_arithwindow_bblexec);
	flx_bbltrace_enable();

	flx_bbltranslate_register_handler(flx_arithwindow_bbltranslate);
	flx_bbltranslate_enable();
}

void flx_arithwindow_destroy(void){
	free(flx_bbl_window.bbls);
}

void flx_arithwindow_enable(void){
	flx_state.arithwindow_active = 1;
}

void flx_arithwindow_disable(void){
	flx_state.arithwindow_active = 0;
}

int flx_arithwindow_bblexec(uint32_t eip, uint32_t esp){
	flx_bbl* bbl = flx_bbl_search(eip);

	flx_bbl_window.instructions       += bbl->num_insn;
	flx_bbl_window.arith_instructions += bbl->num_arith;

	flx_bbl_window.end_index += 1
	flx_bbl_window.end_index %= flx_bbl_window.window_size;

	if(flx_bbl_window.instructions > flx_bbl_window.window_size){
		if((float)flx_bbl_window.arith_instructions / (float)flx_bbl_window.instructions >= flx_bbl_window.arith_percentage)
			flx_arithwindow_handler(flx_bbl_window.bbls[flx_bbl_window.start_index]->addr);
		flx_bbl_window.instructions       -= flx_bbl_window.bbls[flx_bbl_window.start_index]->num_insn;
		flx_bbl_window.arith_instructions -= flx_bbl_window.bbls[flx_bbl_window.start_index]->num_arith;

		flx_bbl_window.start_index += 1
		flx_bbl_window.start_index %= flx_bbl_window.window_size;
	}
	return 0;
}

int flx_arithwindow_bbltranslate(flx_bbl* bbl){
	flx_bbl* new_bbl = malloc(sizeof(*bbl));
	memcpy(new_bbl, bbl, sizeof(*new_bbl));
	flx_bbl_add(new_bbl);
}
