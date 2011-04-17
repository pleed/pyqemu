#ifndef _FLX_INSTRUMENT_
#define _FLX_INSTRUMENT_

#include "cpu-all.h"

#include <inttypes.h>


#define FLX_BLACKLIST_SIZE 256*256*256

#define userspace(x) (!(x&0x80000000))
#define kernelspace(x) (x&0x80000000)

#define FLX_SLOT_EMPTY  0
#define FLX_SLOT_ISCALL 1
#define FLX_SLOT_ISJMP  2

extern CPUState *current_environment;

typedef struct {
	// global flags
	uint8_t global_active;
	uint8_t python_active;

	// feature flags
	uint8_t optrace_active;
	uint8_t memtrace_active;
	uint8_t filter_active;

	// specific opcode flags
	uint8_t syscall_active;
	uint8_t jmp_active;
	uint8_t call_active;
	uint8_t ret_active;

	// heuristics
	uint8_t wang_active;
	uint8_t caballero_active;
} FLX_STATE;

extern FLX_STATE flx_state;

typedef struct {
	char set;
	char msb;
	uint32_t cr3;
} blacklist_slot;

typedef struct {
	blacklist_slot slots[FLX_BLACKLIST_SIZE];
} blacklist;

void flxinstrument_init(void);
int flxinstrument_update_cr3(uint32_t old_cr3, uint32_t new_cr3);
int flxinstrument_call_event(uint32_t call_origin, uint32_t call_destination, uint32_t next_eip);
int flxinstrument_jmp_event(uint32_t jmp_source, uint32_t jmp_destination);
int flxinstrument_syscall_event(uint32_t eax);
int flxinstrument_ret_event(uint32_t eip, uint32_t new_eip);
int flxinstrument_breakpoint_event(uint32_t eip);
int flxinstrument_memtrace_event(uint32_t address, uint32_t value, uint8_t size, uint8_t iswrite);
int flxinstrument_optrace_event(uint32_t eip, uint32_t opcode);
int flxinstrument_bblstart_event(uint32_t eip, uint32_t ins_count);
int flxinstrument_wang_event(uint32_t eip, uint32_t icount, uint32_t arithcount);
int flxinstrument_bblwang_event(uint32_t eip);

int flxinstrument_shutdown_event(void);

void flxinstrument_blacklist_alloc(void);
int flxinstrument_is_blacklisted(uint32_t addr, uint32_t type);
void flxinstrument_blacklist(uint32_t addr, uint32_t type);
void flxinstrument_blacklist_cleanup(void);

#endif
