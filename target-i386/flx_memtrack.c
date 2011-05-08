#include <inttypes.h>
#include <stdlib.h>

#include "exec-all.h"
#include "cpu.h"

#include "flx_instrument.h"
#include "flx_memtrack.h"

static int
memory_byte_cmp(const memory_byte* b1, const memory_byte* b2){
	if(b1->addr < b2->addr)
		return -1;
	else if(b1->addr > b2->addr)
		return 1;
	return 0;
}

static void
memory_byte_free(memory_byte* byte){
	free(byte);
}

memtracker* flx_memtrack_new(void){
	return avl_alloc_tree((avl_compare_t)memory_byte_cmp, (avl_freeitem_t)memory_byte_free);
}

void
flx_memtrack_delete(memtracker* tracker){
	avl_free_tree(tracker);
}

void
flx_memtrack_store(memtracker* tracker, uint32_t address, uint8_t value, uint8_t overwrite){
	memory_byte* byte = malloc(sizeof(*byte));
	byte->addr = address;
	byte->value = value;
	avl_node_t * node = avl_search(tracker, byte);
	if(node){
		if(overwrite)
			((memory_byte*)(node->item))->value = value;
		free(byte);
	}
	else{
		avl_insert(tracker, byte);
	}
}

uint8_t
flx_memtrack_load(memtracker* tracker, uint32_t address, uint8_t* value){
	memory_byte* byte = malloc(sizeof(*byte));
	byte->addr = address;
	avl_node_t* node = avl_search(tracker, byte);
	if(!node){
		free(byte);
		return 0;
	}
	else{
		uint8_t x = ((memory_byte*)(node->item))->value;
		*value = x;
		free(byte);
		return 1;
	}
}
void
flx_memtrack_merge(memtracker* dst, memtracker* src, uint8_t overwrite){
	memtrack_iterator iter = flx_memtrack_iterator();
	memory_byte* current;
	while(current = flx_memtrack_iterate(src, &iter)){
		flx_memtrack_store(dst, current->addr, current->value, overwrite);
	}
}

memtrack_iterator
flx_memtrack_iterator(void){
	return 0;
}

memory_byte*
flx_memtrack_iterate(memtracker* tracker, memtrack_iterator* iter){
	avl_node_t* node = avl_at(tracker, *iter);
	if(!node)
		return NULL;
	else{
		++(*iter);
		return node->item;
	}
}

/*
#include <stdio.h>
int main(void){
	memory_byte bytes[] = {{0,0},{1,1},{2,2},{3,4},{10,10}};
	memtracker* tracker = flx_memtrack_new();
	uint8_t i = 0;
	while(i<5){
		flx_memtrack_store(tracker, bytes[i].addr, bytes[i].value, 0);
		i+=1;
	}
	memtrack_iterator iter = flx_memtrack_iterator();
	memory_byte* current = NULL;
	while(current = flx_memtrack_iterate(tracker, &iter)){
		printf("address: %d, value: %d\n",current->addr,current->value);
	}
	printf("---\n");

	uint8_t value = 0;
	if(!flx_memtrack_load(tracker, 3, &value))
		printf("load fail\n");
	if(value != 4)
		printf("value load fail: %d\n",value);
	memory_byte t = {0,13};
	flx_memtrack_store(tracker, t.addr, t.value, 0);
	if(!flx_memtrack_load(tracker, t.addr, &value))
		printf("load fail 2\n");
	if(value != 0)
		printf("value load fail 2\n");
	flx_memtrack_store(tracker, t.addr, t.value, 1);
	if(!flx_memtrack_load(tracker, t.addr, &value))
		printf("load fail 2\n");
	if(value != 13)
		printf("value load fail 2\n");

	memtracker* dst = flx_memtrack_new();
	flx_memtrack_merge(dst, tracker, 0);
	iter = flx_memtrack_iterator();
	memtrack_iterator iter2 = flx_memtrack_iterator();

	memory_byte* current2 = NULL;
	while(current = flx_memtrack_iterate(tracker, &iter)){
 		current2 = flx_memtrack_iterate(dst, &iter2);
		if(current->addr == current2->addr && current->value == current2->value)
			printf("address %d, value %d\n", current2->addr, current2->value);
	}
	flx_memtrack_store(tracker, 10, 14, 1);
	flx_memtrack_merge(dst, tracker, 1);
	if(!flx_memtrack_load(dst, 10, &value))
		printf("fail3\n");
	if(value != 14)
		printf("fail5\n");

	flx_memtrack_delete(dst);
	flx_memtrack_delete(tracker);
}

*/
