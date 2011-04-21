#ifndef FLX_MEMTRACE
#define FLX_MEMTRACE

#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>

#define MAX_MEMTRACE_HANDLERS 16

typedef int(*memtrace_handler)(uint32_t, uint32_t, uint8_t, uint8_t);

void flx_memtrace_init(void);
void flx_memtrace_enable(void);
void flx_memtrace_disable(void);
void flx_memtrace_event(uint32_t address, uint32_t value, uint8_t size, uint8_t iswrite);
void flx_memtrace_register_handler(memtrace_handler);
void flx_memtrace_unregister_handler(memtrace_handler);

#endif
