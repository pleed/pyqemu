#ifndef FLX_CABALLERO
#define FLX_CABALLERO

#include <avl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>

#include "flx_instrument.h"
#include "flx_bbltranslate.h"

/*
Arithmetic/Binary/logic/bit/shift instructions that will trigger hooks

['cmps', 'rol', '!sqrtsd!', '!hsubps!', 'imul', '!sqrtss!', '!pand!', 'ror', '!hsubpd!', '!fisub!', 'fchs', '!divps!', 'scasw', 'scasq', '!divpd!', '!maxss!', '!add!', '!fdivrp!', 'adc', '!fadd!', 'scasd', 'scasb', '!fmulp!', '!fdivp!', '!fdivr!', 'not', 'shr', '!mulps!', '!rsqrtss!', '!divsd!', '!pmuludq!', 'div', '!mulpd!', 'shl', '!cmp!', '!rcpps!', '!psubd!', '!psubb!', 'bts', 'btr', '!addsubps!', '!psubw!', '!pandn!', 'btc', '!addsubpd!', '!shlalias!', '!fsubrp!', 'cmpsq', 'xor', 'sub', 'fxtract', 'xadd', '!sqrtpd!', '!pxor!', 'mul', '!pmaddwd!', '!paddusw!', '!addpd!', 'bt', '!fidiv!', '!paddusb!', '!addps!', 'sbb', '!maxsd!', '!minss!', '!xorpd!', '!xorps!', '!minsd!', 'or', 'shrd', 'fsub', '!psubusb!', '!fidivr!', '!por!', 'fdiv', 'fmul', '!psubusw!', '!fsqrt!', 'rcl', '!subsd!', '!pmullw!', '!faddp!', 'rcr', 'cmpxchg8b', '!subss!', '!sqrtps!', '!haddpd!', '!rsqrtps!', 'cmpxchg16b', '!rcpss!', '!haddps!', 'cmpxchg', 'shld', 'fprem1', '!paddsw!', '!fisubr!', 'frndint', '!andnpd!', '!pmulhw!', '!paddsb!', 'fsubp', 'fsubr', '!andnps!', 'dec', 'and', '!addsd!', '!psubsw!', '!maxpd!', '!psubq!', '!sal!', '!andpd!', '!addss!', '!psubsb!', 'sar', 'scas', '!andps!', 'inc', '!mulss!', '!minps!', '!paddb!', 'fabs', 'cmpsw', 'idiv', '!paddw!', 'cmpsb', '!minpd!', 'mulsd', '!paddq!', 'test', '!fiadd!', 'fprem', '!orpd!', '!paddd!', 'bsr', '!orps!', 'bsf', '!subpd!', '!maxps!', '!fimul!', 'fscale', '!subps!', 'neg', '!divss!']
*/

typedef struct {
	uint32_t min_bbl_icount;
	float    min_arith_percentage;
} caballero_config;

typedef int(*caballero_handler)(uint32_t, uint32_t, uint32_t);

extern caballero_handler flx_caballero_handler;

void flx_caballero_init(caballero_handler handler);
void flx_caballero_enable(uint32_t, float);
void flx_caballero_disable(void);
int flx_caballero_event(flx_bbl* bbl);

#endif
