#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <avl.h>

#include "flx_instrument.h"
#include "flx_caballero.h"

flx_bbl* current_bbl = NULL;
caballero_handler flx_caballero_handler = NULL;
caballero_config* flx_caballero_config = NULL;

void flx_caballero_init(caballero_handler handler){
	flx_caballero_handler = handler;
}

void flx_caballero_enable(uint32_t min_icount, float min_arith_percentage){
	flx_state.caballero_active = 1;
	flx_caballero_config = malloc(sizeof(*flx_caballero_config));
	flx_caballero_config->min_bbl_icount = min_icount;
	flx_caballero_config->min_arith_percentage = min_arith_percentage;
}

void flx_caballero_disable(void){
	flx_state.caballero_active = 0;
	if(current_bbl){
		free(current_bbl);
		current_bbl = NULL;
	}
	if(flx_caballero_config)
		free(flx_caballero_config);
}

void flx_caballero_bbl_new(uint32_t eip){
	current_bbl = malloc(sizeof(*current_bbl));
	current_bbl->eip = eip;
	current_bbl->icount = 0;
	current_bbl->arithcount = 0;
}

void flx_caballero_bbl_end(void){
	if(current_bbl){
		if(current_bbl->icount >= flx_caballero_config->min_bbl_icount &&
		   ((float)current_bbl->arithcount/(float)current_bbl->icount) >= flx_caballero_config->min_arith_percentage){
			flx_caballero_handler(current_bbl->eip, current_bbl->icount, current_bbl->arithcount);
		}
		free(current_bbl);
	}
}

void flx_caballero_arith(void){
	current_bbl->arithcount++;
}

void flx_caballero_insn(void){
	current_bbl->icount++;
}

