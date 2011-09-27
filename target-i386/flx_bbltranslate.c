#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <avl.h>

#include "flx_bbl.h"
#include "flx_instrument.h"
#include "flx_bbltranslate.h"

/*
 * Often it is useful to get notified when new basic blocks
 * are translated by Qemu. This module can manage callbacks
 * via the register_handler API to dispatch block translation
 * events to further analysis. It automatically adds new blocks
 * to the basic block management (flx_bbl)
 */

bbltranslate_handler flx_bbltranslate_handlers[MAX_BBLTRANSLATE_HANDLERS];
flx_bbl flx_current_bbl;

void flx_bbltranslate_init(void){
	memset(flx_bbltranslate_handlers, 0, sizeof(flx_bbltranslate_handlers));
	memset(&flx_current_bbl, 0, sizeof(flx_bbl));
}

void flx_bbltranslate_enable(void){
	flx_state.bbltranslate_active = 1;
}

void flx_bbltranslate_disable(void){
	flx_state.bbltranslate_active = 0;
}

inline uint32_t flx_bbltranslate_bbl_addr(void){
	return flx_current_bbl.addr;
}

void flx_bbltranslate_bbl_new(uint32_t addr){
	flx_current_bbl.addr = addr;
	flx_current_bbl.icount = 0;
	flx_current_bbl.arithcount = 0;
	flx_current_bbl.movcount = 0;
	flx_current_bbl.listcount = 0;
	if(flx_current_bbl.insn_list){
		flx_current_bbl.insn_list = NULL;
	}
}

static void
flx_bbltranslate_append(enum insn_type insn){
	if(!flx_current_bbl.insn_list){
		flx_current_bbl.insn_list = malloc(sizeof(insn_list));
		flx_current_bbl.insn_list->insn_type = insn;
		flx_current_bbl.insn_list->next = NULL;
	}
	else{
		insn_list* new_element = malloc(sizeof(insn_list));
		new_element->insn_type = insn;
		new_element->next = flx_current_bbl.insn_list;
		flx_current_bbl.insn_list = new_element;
	}
}

void flx_bbltranslate_insn(enum insn_type insn){
	switch(insn){
		case INSN_COUNTER:
			++flx_current_bbl.icount;
			break;
		case INSN_MOV:
			++flx_current_bbl.movcount;
			break;
		case INSN_XOR ... INSN_ADD:
			flx_bbltranslate_append(insn);
			++flx_current_bbl.listcount;
		default:
			++flx_current_bbl.arithcount;
	}
}

void flx_bbltranslate_bbl_size(uint32_t size){
	flx_current_bbl.size = size;
}

void flx_bbltranslate_bbl_end(void){
	flx_bbl* new_bbl = malloc(sizeof(*new_bbl));
	memcpy(new_bbl, &flx_current_bbl, sizeof(flx_current_bbl));
	flx_bbl_add(new_bbl);

	uint8_t i;
	for(i=0; i<MAX_BBLTRANSLATE_HANDLERS; ++i){
		if(!flx_bbltranslate_handlers[i])
			break;
		flx_bbltranslate_handlers[i](new_bbl);
	}
}

void flx_bbltranslate_register_handler(bbltranslate_handler handler){
	uint8_t i;
	for(i=0; i<MAX_BBLTRANSLATE_HANDLERS; ++i){
		if(!flx_bbltranslate_handlers[i]){
			flx_bbltranslate_handlers[i] = handler;
			return;
		}
	}
	printf("WARNING, MAX_BBLTRANSLATE_HANDLERS reached!!!\n");
	exit(-1);
	return;
}

void flx_bbltranslate_unregister_handler(bbltranslate_handler handler){
	uint8_t i;
	uint8_t handler_index = 0;
	uint8_t last_handler_index = 0;
	for(i=0; i<MAX_BBLTRANSLATE_HANDLERS; ++i){
		if(flx_bbltranslate_handlers[i]){
			last_handler_index = i;
			if(flx_bbltranslate_handlers[i] == handler){
				handler_index = i;
			}
		}
	}
	flx_bbltranslate_handlers[handler_index] = flx_bbltranslate_handlers[last_handler_index];
	flx_bbltranslate_handlers[last_handler_index] = NULL;
}
