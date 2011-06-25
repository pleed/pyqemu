#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <inttypes.h>

#ifndef HASHMAP
#define HASHMAP

typedef struct Entry Entry;
struct Entry {
	void* key;
	int hash;
	void* value;
	Entry* next;
};

typedef struct {
	Entry** buckets;
	size_t bucketCount;
	int (*hash)(void* key);
	uint8_t (*equals)(void* keyA, void* keyB);
	size_t size;
} Hashmap;

Hashmap* hashmapCreate(size_t initialCapacity, int (*hash)(void* key), uint8_t (*equals)(void* keyA, void* keyB));
size_t hashmapSize(Hashmap* map);
void hashmapFree(Hashmap* map);
int hashmapHash(void* key, size_t keySize);
void* hashmapPut(Hashmap* map, void* key, void* value);
void* hashmapGet(Hashmap* map, void* key);
uint8_t hashmapContainsKey(Hashmap* map, void* key);
void* hashmapMemoize(Hashmap* map, void* key, void* (*initialValue)(void* key, void* context), void* context);
void* hashmapRemove(Hashmap* map, void* key);
void hashmapForEach(Hashmap* map, uint8_t (*callback)(void* key, void* value, void* context), void* context);
size_t hashmapCurrentCapacity(Hashmap* map);
size_t hashmapCountCollisions(Hashmap* map);
int hashmapIntHash(void* key);
uint8_t hashmapIntEquals(void* keyA, void* keyB);

#endif
