#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <avl.h>

#include "flx_instrument.h"
#include "flx_bblwindow.h"
#include "flx_bbltranslate.h"
#include "flx_bbltrace.h"

struct {
	uint32_t size;
	uint32_t*buf;
	uint32_t cur;
} bbl_window;

void flx_bblwindow_init(void){
	flx_bbltrace_enable();
	flx_bbltranslate_enable();
}

void flx_bblwindow_enable(uint32_t window_size){
	bbl_window.buf = malloc(window_size*sizeof(uint32_t));
	memset(bbl_window.buf, 0, window_size);
	bbl_window.size = window_size;
	bbl_window.cur = 0;

	flx_bbltrace_register_handler(flx_bblwindow_bblexec);
}

void flx_bblwindow_disable(void){
	flx_bbltrace_unregister_handler(flx_bblwindow_bblexec);
	free(bbl_window.buf);
}

int flx_bblwindow_get(uint32_t index, uint32_t* eip){
	if(index >= bbl_window.size)
		return -1;
	else{
		*eip = bbl_window.buf[(index<= bbl_window.cur)?\
		                      bbl_window.cur-index : \
		                      bbl_window.size+(bbl_window.cur-index)];
	}
	if(!*eip)
		return -1;
	return 0;
}

int flx_bblwindow_bblexec(uint32_t eip, uint32_t esp){
	bbl_window.cur++;
	bbl_window.cur %= bbl_window.size;
	bbl_window.buf[bbl_window.cur] = eip;
	return 0;
}

