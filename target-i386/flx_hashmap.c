#include <avl.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>

#include "hashmap.h"
#include "flx_hashmap.h"

static hmap*
flx_hashmap_alloc(void){
	return malloc(sizeof(hmap));
}

static void
flx_hashmap_dealloc(hmap* h){
	free(h);
}

static uint8_t
flx_hashmap_destructor_callback(void* key, void* value, void* context){
	hmap* map = context;
	map->item_destructor(value);
	map->key_destructor(key);
	return 1;
}

hmap* flx_hashmap_new(hashmap_hash hash, hashmap_equals equ, hashmap_destructor key_destruct, hashmap_destructor item_destruct){
	hmap* h = flx_hashmap_alloc();
	h->map = hashmapCreate(FLX_HASHMAP_INITIAL_SIZE, hash, equ);
	h->key_destructor = key_destruct;
	h->item_destructor = item_destruct;
	return h;
}

hmap* flx_hashmap_delete(hmap* h){
	hashmapForEach(h->map, flx_hashmap_destructor_callback, h);
	hashmapFree(h->map);
	flx_hashmap_dealloc(h);
	return NULL;
}
void*
flx_hashmap_put(hmap* h, void* key, void* value){
	return hashmapPut(h->map, key, value);
}
void*
flx_hashmap_get(hmap* h, void* key){
	return hashmapGet(h->map, key);
}

