#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <avl.h>

#include "flx_instrument.h"
#include "flx_wang.h"

flx_bbl* current_bbl = NULL;
wang_handler flx_wang_handler = NULL;

void flx_wang_init(wang_handler handler){
	flx_wang_handler = handler;
}

void flx_wang_enable(void){
	flx_state.wang_active = 1;
}

void flx_wang_disable(void){
	flx_state.wang_active = 0;
	if(current_bbl){
		free(current_bbl);
		current_bbl = NULL;
	}
}

void flx_wang_bbl_new(uint32_t eip){
	if(current_bbl){
		flx_wang_handler(current_bbl->eip, current_bbl->icount, current_bbl->arithcount);
		free(current_bbl);
	}
	current_bbl = malloc(sizeof(*current_bbl));
	current_bbl->eip = eip;
	current_bbl->icount = 0;
	current_bbl->arithcount = 0;
}

void flx_wang_arith(void){
	current_bbl->arithcount++;
}

void flx_wang_insn(void){
	current_bbl->icount++;
}

