#ifndef FLX_ARITHWINDOW
#define FLX_ARITHWINDOW

#include <avl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>

#include "flx_instrument.h"
#include "flx_bbltranslate.h"

typedef int(*arithwindow_handler)(uint32_t);

void flx_arithwindow_init(arithwindow_handler);
void flx_arithwindow_enable(uint32_t, float);
void flx_arithwindow_disable(void);
void flx_arithwindow_destroy(void);
int flx_arithwindow_bblexec(uint32_t, uint32_t);
int flx_arithwindow_bbltranslate(flx_bbl* bbl);

#endif
