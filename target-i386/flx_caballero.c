#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <avl.h>

#include "flx_instrument.h"
#include "flx_caballero.h"
#include "flx_bbltranslate.h"

caballero_handler flx_caballero_handler = NULL;
caballero_config* flx_caballero_config = NULL;

void flx_caballero_init(caballero_handler handler){
	flx_caballero_handler = handler;
}

void flx_caballero_enable(uint32_t min_icount, float min_arith_percentage){
	flx_state.caballero_active = 1;
	flx_state.bbltranslate_active = 1;

	flx_caballero_config = malloc(sizeof(*flx_caballero_config));
	flx_caballero_config->min_bbl_icount = min_icount;
	flx_caballero_config->min_arith_percentage = min_arith_percentage;
	flx_bbltranslate_register_handler(flx_caballero_event);
}

void flx_caballero_disable(void){
	flx_bbltranslate_unregister_handler(flx_caballero_event);
	flx_state.caballero_active = 0;
	if(flx_caballero_config)
		free(flx_caballero_config);
}

int flx_caballero_event(flx_bbl* bbl){
	if(bbl->icount >= flx_caballero_config->min_bbl_icount &&
	   ((float)bbl->arithcount/(float)bbl->icount) >= flx_caballero_config->min_arith_percentage){
		flx_caballero_handler(bbl->addr, bbl->icount, bbl->arithcount);
	}
	return 0;
}

