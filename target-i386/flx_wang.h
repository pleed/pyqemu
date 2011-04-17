#ifndef FLX_WANG
#define FLX_WANG

#include <avl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>

#include "flx_instrument.h"

#define FLX_WANG_HOOK(function) do{if(flx_state.global_active && flx_state.wang_active && (flx_state.filter_active && flx_filter_search_by_addr(pc_ptr))) function;}while(0)
//#define FLX_WANG_NOTIFY do{if(flx_state.global_active && flx_state.wang_active && (flx_state.filter_active && flx_filter_search_by_addr(pc_ptr))) flx_wang_arith();}while(0)
/*
Arithmetic/Binary/logic/bit/shift instructions that will trigger hooks

['cmps', 'rol', '!sqrtsd!', '!hsubps!', 'imul', '!sqrtss!', '!pand!', 'ror', '!hsubpd!', '!fisub!', 'fchs', '!divps!', 'scasw', 'scasq', '!divpd!', '!maxss!', '!add!', '!fdivrp!', 'adc', '!fadd!', 'scasd', 'scasb', '!fmulp!', '!fdivp!', '!fdivr!', 'not', 'shr', '!mulps!', '!rsqrtss!', '!divsd!', '!pmuludq!', 'div', '!mulpd!', 'shl', '!cmp!', '!rcpps!', '!psubd!', '!psubb!', 'bts', 'btr', '!addsubps!', '!psubw!', '!pandn!', 'btc', '!addsubpd!', '!shlalias!', '!fsubrp!', 'cmpsq', 'xor', 'sub', 'fxtract', 'xadd', '!sqrtpd!', '!pxor!', 'mul', '!pmaddwd!', '!paddusw!', '!addpd!', 'bt', '!fidiv!', '!paddusb!', '!addps!', 'sbb', '!maxsd!', '!minss!', '!xorpd!', '!xorps!', '!minsd!', 'or', 'shrd', 'fsub', '!psubusb!', '!fidivr!', '!por!', 'fdiv', 'fmul', '!psubusw!', '!fsqrt!', 'rcl', '!subsd!', '!pmullw!', '!faddp!', 'rcr', 'cmpxchg8b', '!subss!', '!sqrtps!', '!haddpd!', '!rsqrtps!', 'cmpxchg16b', '!rcpss!', '!haddps!', 'cmpxchg', 'shld', 'fprem1', '!paddsw!', '!fisubr!', 'frndint', '!andnpd!', '!pmulhw!', '!paddsb!', 'fsubp', 'fsubr', '!andnps!', 'dec', 'and', '!addsd!', '!psubsw!', '!maxpd!', '!psubq!', '!sal!', '!andpd!', '!addss!', '!psubsb!', 'sar', 'scas', '!andps!', 'inc', '!mulss!', '!minps!', '!paddb!', 'fabs', 'cmpsw', 'idiv', '!paddw!', 'cmpsb', '!minpd!', 'mulsd', '!paddq!', 'test', '!fiadd!', 'fprem', '!orpd!', '!paddd!', 'bsr', '!orps!', 'bsf', '!subpd!', '!maxps!', '!fimul!', 'fscale', '!subps!', 'neg', '!divss!']
*/

typedef struct {
	uint32_t eip;
	uint32_t icount;
	uint32_t arithcount;
} flx_bbl;

typedef int(*wang_handler)(uint32_t, uint32_t, uint32_t);

extern wang_handler flx_wang_handler;

void flx_wang_init(wang_handler handler);
void flx_wang_enable(void);
void flx_wang_disable(void);
void flx_wang_bbl_new(uint32_t eip);
void flx_wang_bbl_end(void);
void flx_wang_arith(void);
void flx_wang_insn(void);

#endif
