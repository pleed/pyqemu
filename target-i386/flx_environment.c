#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <avl.h>
#include <math.h>
#include <shmatch.h>

#include "flx_instrument.h"
#include "flx_context.h"
#include "flx_memtrace.h"
#include "flx_calltrace.h"

#include "flx_environment.h"

hmap* env_map = NULL;

static int
flx_environment_hash(uint32_t* item){
	return *item;
}

static uint8_t
flx_environment_equals(uint32_t* a, uint32_t* b){
	return *a==*b;
}

static void
flx_environment_destructor(void* i){
	free(i);
}

void
flx_environment_init(void){
	env_map = flx_hashmap_new((hashmap_hash)flx_environment_hash, (hashmap_equals)flx_environment_equals, (hashmap_destructor)flx_environment_destructor, (hashmap_destructor)flx_environment_destructor);
}

void
flx_environment_destroy(void){
	flx_hashmap_delete(env_map);
}

void
flx_environment_save_state(CPUState* state){
	CPUState* s = malloc(sizeof(*s));
	uint32_t* key = malloc(sizeof(uint32_t));

	memcpy(s, state, sizeof(*s));
	*key = state->cr[3];
	flx_hashmap_put(env_map, key, s);
}

CPUState*
flx_environment_get_state(uint32_t cr3){
	return flx_hashmap_get(env_map, &cr3);
}
