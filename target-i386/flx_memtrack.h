#ifndef FLX_MEMTRACK
#define FLX_MEMTRACK

#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <avl.h>

typedef avl_tree_t memtracker;
typedef uint32_t memtrack_iterator;

typedef struct {
	uint32_t addr;
	uint8_t value;
} memory_byte;

memtracker* flx_memtrack_new(void);
void        flx_memtrack_delete(memtracker* tracker);
void        flx_memtrack_store(memtracker* tracker, uint32_t address, uint8_t value, uint8_t overwrite);
uint8_t     flx_memtrack_load(memtracker* tracker, uint32_t address, uint8_t* value);
void        flx_memtrack_merge(memtracker* dst, memtracker* src, uint8_t overwrite);

memtrack_iterator flx_memtrack_iterator(void);
memory_byte*      flx_memtrack_iterate(memtracker* tracker, memtrack_iterator* iter);

#endif
