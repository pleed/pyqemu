#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>
#include <avl.h>

#include "flx_instrument.h"
#include "disas.h"
#include "flx_bbl.h"
#include "flx_disas.h"

static uint32_t
flx_disas_bbl_size(uint32_t addr){
	flx_bbl* bbl = flx_bbl_search(addr);
	if(!bbl){
		printf("FATA: flx_disas_bbl could not find basic block\n");
		return 0;
	}
	return bbl->size;
}

static flx_disassembly*
flx_disas_alloc(uint8_t* buf, uint32_t size){
	flx_disassembly* disas = malloc(sizeof(flx_disassembly));
	disas->s = buf;
	disas->size = size;
	return disas;
}


flx_disassembly*
flx_disas_bbl(uint32_t addr){
	uint32_t size = flx_disas_bbl_size(addr);
	if(!size)
		return NULL;

	uint8_t* buf = malloc(size);
	if(cpu_memory_rw_debug(current_environment, addr, buf, size, 0) != 0){
		free(buf);
		return NULL;
	}

	int fds[2];
	if(pipe(fds)){
		free(buf);
		return NULL;
	}
	FILE* disas_read  = fdopen(fds[0],"r");
	FILE* disas_write = fdopen(fds[1],"w");

	disas_relative(disas_write, buf, size, addr);
	fclose(disas_write);
	free(buf);

	const uint8_t buf_size = 128;
	uint32_t tmp_size = buf_size;
	uint8_t* tmp_buf = malloc(tmp_size);
	uint32_t disas_size = 0;
	while(fread(&tmp_buf[disas_size], 1, 1, disas_read)){
		disas_size++;
		if(disas_size >= tmp_size){
			tmp_size += buf_size;
			tmp_buf = realloc(tmp_buf, tmp_size);
		}
	}
	if(ferror(disas_read)){
		free(tmp_buf);
		return NULL;
	}

	fclose(disas_read);
	return flx_disas_alloc(tmp_buf, disas_size);
}

