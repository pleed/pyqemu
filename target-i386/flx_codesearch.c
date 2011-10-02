#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <avl.h>
#include <math.h>
#include <shmatch.h>

#include "flx_instrument.h"
#include "flx_bbl.h"
#include "flx_bbltranslate.h"
#include "flx_shadowmem.h"
#include "flx_codesearch.h"
#include "flx_memtrack.h"
#include "flx_context.h"
#include "flx_bbltrace.h"

/*
 * This module enables instruction class based pattern matching
 * on executed code. It exposes the register_handler API
 */

codesearch_handler flx_codesearch_handler = NULL;
struct shmatcher* insn_matcher = NULL;

void flx_codesearch_init(codesearch_handler handler){
	flx_codesearch_handler = handler;
}

void flx_codesearch_enable(void){
	flx_bbltrace_register_handler(flx_codesearch_bbl);
	flx_bbltrace_enable();
	flx_calltrace_register_handler(flx_codesearch_calltrace);
	flx_calltrace_enable();

	insn_matcher = shmatch_new(shmatch_stub_encode);
	flx_state.codesearch_active = 1;
}

void flx_codesearch_disable(void){
	flx_bbltrace_unregister_handler(flx_codesearch_bbl);
	flx_calltrace_unregister_handler(flx_codesearch_calltrace);

	shmatch_destroy(insn_matcher);
	insn_matcher = NULL;
	flx_state.codesearch_active = 0;
}

static void
flx_insnchain_dealloc(insn_chain* chain){
	free(chain->data);
	free(chain->eips);
	free(chain);
}

static int
flx_insnchain_delete(flx_context* context){
	insn_chain* chain = (insn_chain*)context->insnchain;
	insn_chain* next;
	while(chain){
		next = chain->next;
		flx_insnchain_dealloc(chain);
		chain = next;
	}

	return 0;
}

static void
flx_insnchain_expand(insn_chain* chain, uint32_t len){
	if(len == 0){
		chain->data = realloc(chain->data, sizeof(uint32_t)*(chain->size+FLX_INSN_CHAIN_RESIZE));
		chain->eips = realloc(chain->eips, sizeof(uint32_t)*(chain->size+FLX_INSN_CHAIN_RESIZE));
		chain->size += FLX_INSN_CHAIN_RESIZE;
	}
	else{
		chain->data = realloc(chain->data, sizeof(uint32_t)*(chain->size+len));
		chain->eips = realloc(chain->eips, sizeof(uint32_t)*(chain->size+len));
		chain->size += len;
	}
}

static insn_chain*
flx_insnchain_alloc(void){
	insn_chain* chain = malloc(sizeof(*chain));
	memset(chain, 0, sizeof(*chain));
	flx_insnchain_expand(chain, 0);
	return chain;
}


static int
flx_codesearch_destructor(flx_context* c){
	flx_insnchain_delete(c);	
	return 0;
}

static insn_chain**
flx_codesearch_current_insnchain(void){
	flx_context* current = flx_context_current();
	assert(current != NULL);
	if(!current->insnchain){
		current->insnchain = flx_insnchain_alloc() ;
		current->codesearch_destructor = (context_destructor)flx_codesearch_destructor;
	}
	return (insn_chain**)&current->insnchain;
}

int flx_codesearch_calltrace(uint32_t old_eip, uint32_t new_eip, uint32_t next_eip, uint32_t esp, flx_call_type type){
	static struct string tmp_string = {0, NULL};
	insn_chain** pchain = flx_codesearch_current_insnchain();
	insn_chain* chain = *pchain;

	if(type == FLX_CALLTRACE_RET || type == FLX_CALLTRACE_MISSED_RET){
		tmp_string.data = (char*)chain->data;
		tmp_string.len  = sizeof(uint32_t)*chain->len;
		if(!tmp_string.data || !tmp_string.len){
			return 0;
		}

		struct match* p = shmatch_search(insn_matcher, &tmp_string);
		for(; p; p = shmatch_search(insn_matcher, NULL)){
			struct pattern* needle = p->needle;
			flx_codesearch_handler(chain->eips[p->startpos/sizeof(uint32_t)], (uint8_t*)needle->data->data, needle->data->len);
			shmatch_match_destroy(p);
		}
		*pchain = chain->next;
		flx_insnchain_dealloc(chain);
	}
	else {
		insn_chain* chain = flx_insnchain_alloc();
		chain->next = *pchain;
		*pchain = chain;
	}
	return 0;
}
int flx_codesearch_bbl(uint32_t eip, uint32_t esp){
	insn_chain** pchain = flx_codesearch_current_insnchain();
	insn_chain* chain = *pchain;
	flx_bbl* bbl = flx_bbl_search(eip);
	assert(bbl != NULL);
	insn_list* insns = bbl->insn_list;

	if(bbl->listcount == 0)
		return 0;

	if(bbl->listcount >= (chain->size-chain->len)){
		flx_insnchain_expand(chain, (bbl->listcount>FLX_INSN_CHAIN_RESIZE)?bbl->listcount:0);
	}

	uint32_t index = chain->len + bbl->listcount - 1;
	uint32_t assert_counter = 0;
	uint8_t debug = 0;
	while(insns){
		assert(index < chain->size);
		assert_counter++;
		chain->data[index] = insns->insn_type;
		chain->eips[index] = eip;
		insns = insns->next;
		assert(index > 0 || ! insns);
		--index;
	}
	assert(assert_counter == bbl->listcount);
	chain->len += bbl->listcount;
	return 0;
}

void flx_codesearch_pattern(uint8_t* pattern, uint32_t len){
	struct string* new_pattern = shmatch_string_new(len);
	memcpy(new_pattern->data, pattern, len);
	if(!insn_matcher)
		flx_codesearch_enable();
	if(shmatch_add_pattern(insn_matcher, new_pattern) == -1){
		printf("Unable to add pattern into automaton!\n");
		exit(-1);
	}
}

