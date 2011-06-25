#ifndef FLX_HASHMAP
#define FLX_HASHMAP

#include <avl.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>

#include "hashmap.h"

#define FLX_HASHMAP_INITIAL_SIZE 1<<20

typedef int(*hashmap_hash)(void*);
typedef uint8_t(*hashmap_equals)(void*, void*);
typedef void(*hashmap_destructor)(void*);

typedef struct{
	Hashmap* map;
	hashmap_destructor item_destructor;
	hashmap_destructor key_destructor;
} hmap;

hmap* flx_hashmap_new(hashmap_hash hash, hashmap_equals equ, hashmap_destructor key_destruct, hashmap_destructor item_destruct);
hmap* flx_hashmap_delete(hmap* h);
void*    flx_hashmap_put(hmap* h, void* key, void* value);
void*    flx_hashmap_get(hmap* h, void* key);

#endif
