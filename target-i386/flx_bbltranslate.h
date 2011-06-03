#ifndef FLX_BBLTRANSLATE
#define FLX_BBLTRANSLATE

#include <avl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>

#include "flx_instrument.h"
#include "flx_bbl.h"

#define MAX_BBLTRANSLATE_HANDLERS 16

#define FLX_BBLTRANSLATE_HOOK(function) do{if(flx_state.global_active && flx_state.bbltranslate_active && (flx_state.filter_active && flx_filter_search_by_addr(pc_ptr))) function;}while(0)

typedef int(*bbltranslate_handler)(flx_bbl*);

void flx_bbltranslate_init(void);
void flx_bbltranslate_enable(void);
void flx_bbltranslate_disable(void);

void flx_bbltranslate_bbl_new(uint32_t);
void flx_bbltranslate_bbl_end(void);
void flx_bbltranslate_arith(void);
void flx_bbltranslate_insn(void);
void flx_bbltranslate_bbl_size(uint32_t);

void flx_bbltranslate_register_handler(bbltranslate_handler);
void flx_bbltranslate_unregister_handler(bbltranslate_handler);

#endif
