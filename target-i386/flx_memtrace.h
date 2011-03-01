#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>

typedef int(*mem_access_handler)(uint32_t, uint32_t, uint8_t, uint8_t);


extern uint8_t memtrace_enabled;
extern mem_access_handler flx_access_handler;


void flx_memtrace_init(mem_access_handler handler);
void flx_memtrace_start(void);
void flx_memtrace_stop(void);
void flx_memtrace_event(uint32_t address, uint32_t value, uint8_t size, uint8_t iswrite);
