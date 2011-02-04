#ifndef _FLX_INSTRUMENT_
#define _FLX_INSTRUMENT_

#include <inttypes.h>

#define FLX_BLACKLIST_SIZE 256*256*256

#define FLX_SLOT_EMPTY  0
#define FLX_SLOT_ISCALL 1
#define FLX_SLOT_ISJMP  2

extern CPUState *current_environment;

extern int instrumentation_active;
extern int instrumentation_call_active;
extern int instrumentation_syscall_active;
extern int python_active;

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
int flxinstrument_jmp_event(uint32_t jmp_destination);
int flxinstrument_syscall_event(uint32_t eax);
int flxinstrument_ret_event(uint32_t new_eip);
int flxinstrument_breakpoint_event(uint32_t eip);

void flxinstrument_blacklist_alloc(void);
int flxinstrument_is_blacklisted(uint32_t addr, uint32_t type);
void flxinstrument_blacklist(uint32_t addr, uint32_t type);
void flxinstrument_blacklist_cleanup(void);

#endif
