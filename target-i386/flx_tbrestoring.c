#include <avl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>

#include "exec-all.h"
#include "cpu.h"
#include "flx_instrument.h"
#include "flx_breakpoint.h"

#include "flx_tbrestoring.h"

avl_tree_t *tbs;
int cachecache = 0;

static void avl_process_tb_free(flx_process_tb* tb){
	if(tb->cache)
		free(tb->cache);
	free(tb);
}

static int avl_process_tb_cmp(const flx_process_tb *a, const flx_process_tb *b){
	if(a->cr3 == b->cr3)
		return 0;
	else if(a->cr3 < b->cr3)
		return -1;
	return 1;
}

static flx_process_tb*
flx_process_tb_alloc(uint32_t cr3){
	flx_process_tb* tb = malloc(sizeof(*tb));
	tb->cr3 = cr3;
	tb->cache = malloc(sizeof(*(tb->cache)));
	return tb;
}

static void
flx_process_tb_free(flx_process_tb* tb){
	if(tb->cache)
		free(tb->cache);
	free(tb);
}

void flx_tbrestore_init(void){
	tbs = avl_alloc_tree((avl_compare_t)avl_process_tb_cmp, (avl_freeitem_t)avl_process_tb_free);
}

void flx_tbrestore_new(uint32_t cr3){
	flx_process_tb* tb = flx_process_tb_alloc(cr3);
	avl_node_t *node = avl_search(tbs, tb);
	if(!node){
		avl_insert(tbs, tb);
	}
}
void flx_tbrestore_delete(uint32_t cr3){
	flx_process_tb* tb = flx_process_tb_alloc(cr3);
	avl_delete(tbs, tb);
	flx_process_tb_free(tb);
}

int flx_tbrestore_save(uint32_t cr3){
	flx_process_tb* tb = flx_process_tb_alloc(cr3);
	avl_node_t *node = avl_search(tbs, tb);
	if(!node){
		flx_process_tb_free(tb);
		return -1;
	}
	else{
		flx_process_tb_free(tb);
		((flx_process_tb*)(node->item))->cache->i = cachecache;
		return 0;
	}
}
int flx_tbrestore_restore(uint32_t cr3){
	flx_process_tb* tb = flx_process_tb_alloc(cr3);
	avl_node_t *node = avl_search(tbs, tb);
	if(!node){
		flx_process_tb_free(tb);
		return -1;
	}
	else{
		flx_process_tb_free(tb);
		cachecache = ((flx_process_tb*)(node->item))->cache->i;
		return 0;
	}
}

/*
#include <stdio.h>
int main(int argc, char* argv[]){
	flx_tbrestore_init();
	
	uint32_t i;
	for(i=0; i<10000; ++i)
		flx_tbrestore_new(i);
	for(i=0; i<10000; ++i){
		cachecache = i;
		if(flx_tbrestore_save(i))
			printf("SAVE ALARM!\n");
	}
	for(i=0; i<10000; ++i){
		if(flx_tbrestore_restore(i))
			printf("RESTORE ALARM!\n");
		if(cachecache != i)
			printf("ALARM!\n");
	}
	for(i=0; i<10000; ++i)
		flx_tbrestore_delete(i);
	for(i=10000;i<20000;++i)
		if(!flx_tbrestore_restore(i))
			printf("RESTORE ALARM!\n");
	return 0;
}
*/
