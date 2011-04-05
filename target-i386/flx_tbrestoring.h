#ifndef _FLX_TBRESTORE_H
#define _FLX_TBRESTORE_H

#include <avl.h>
#include <sys/types.h>
#include <inttypes.h>

typedef struct {
	int i;
	int j;
} flx_tb_cache;

typedef struct {
	uint32_t cr3;
	flx_tb_cache* cache;
} flx_process_tb;

void flx_tbrestore_init(void);
void flx_tbrestore_new(uint32_t cr3);
void flx_tbrestore_delete(uint32_t cr3);
int flx_tbrestore_save(uint32_t cr3);
int flx_tbrestore_restore(uint32_t cr3);

#endif
