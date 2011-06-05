#ifndef FLX_BBLWINDOW
#define FLX_BBLWINDOW

#include <avl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>

#include "flx_instrument.h"
#include "flx_bbltranslate.h"

void flx_bblwindow_init(void);
void flx_bblwindow_enable(uint32_t);
void flx_bblwindow_disable(void);
int flx_bblwindow_bblexec(uint32_t, uint32_t);
int flx_bblwindow_get(uint32_t, uint32_t*);

#endif
