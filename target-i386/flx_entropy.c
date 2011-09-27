#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <avl.h>

#include "flx_instrument.h"
#include "flx_entropy.h"
#include "flx_bbltranslate.h"

/*
 * Not used
 * Constructed to calculate entropy information
 * which is now done in the a-posteriori analysis
 */

entropy_handler flx_entropy_handler = NULL;
entropy_config* flx_entropy_config = NULL;

void flx_entropy_init(entropy_handler handler){
	flx_entropy_handler = handler;
}

void flx_entropy_enable(uint32_t min_icount, float min_arith_percentage){
	flx_state.entropy_active = 1;
	flx_state.bbltranslate_active = 1;

	flx_entropy_config = malloc(sizeof(*flx_entropy_config));
	flx_entropy_config->min_bbl_icount = min_icount;
	flx_entropy_config->min_arith_percentage = min_arith_percentage;
	flx_bbltranslate_register_handler(flx_entropy_event);
}

void flx_entropy_disable(void){
	flx_bbltranslate_unregister_handler(flx_entropy_event);
	flx_state.entropy_active = 0;
	if(flx_entropy_config)
		free(flx_entropy_config);
}

static void flx_entropy_start(void){
	
}

static void flx_entropy_stop(void){
	
}

int flx_entropy_memaccess(uint32_t address, uint32_t value, uint8_t size, uint8_t iswrite){

}

int flx_entropy_callevent(uint32_t old_eip, uint32_t new_eip, uint32_t next_eip, uint32_t esp, flx_call_type type){
		
}
