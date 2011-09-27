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
	uint8_t bbltranslate_active;
	uint8_t bbltrace_active;
	uint8_t memtrace_active;
	uint8_t filter_active;
	uint8_t calltrace_active;
	uint8_t functiontrace_active;
	uint8_t dump_active;

	// specific opcode flags
	uint8_t syscall_active;
	uint8_t jmp_active;
	uint8_t call_active;
	uint8_t ret_active;

	// heuristics
	uint8_t caballero_active;
	uint8_t arithwindow_active;
	uint8_t functionentropy_active;
	uint8_t constsearch_active;
	uint8_t functiontaint_active;
	uint8_t codesearch_active;
} FLX_STATE;

extern FLX_STATE flx_state;

/**
 * Initializes instrumentation and activates submodules
 */
void flxinstrument_init(void);

/**
 * Handles a scheduling event (cr3 modification)
 */
int flxinstrument_update_cr3(uint32_t old_cr3, uint32_t new_cr3);

/**
 * Handles high level function call events
 */
int flxinstrument_call_event(uint32_t call_origin, uint32_t call_destination, uint32_t next_eip, uint32_t esp);

/**
 * Handles Jump events 
 */
int flxinstrument_jmp_event(uint32_t jmp_source, uint32_t jmp_destination);

/**
 * Handles Syscall / Sysenter / int 80 / int 2e
 */
int flxinstrument_syscall_event(uint32_t eax);

/**
 * Handles function call return events 
 */
int flxinstrument_ret_event(uint32_t eip, uint32_t new_eip);

/**
 * Handles breakpoint triggering events 
 */
int flxinstrument_breakpoint_event(uint32_t eip);

/**
 * Handles memory access events
 */
int flxinstrument_memtrace_event(uint32_t address, uint32_t value, uint8_t size, uint8_t iswrite);

/**
 * Called before the execution of a BBL
 */
int flxinstrument_bbltrace_event(uint32_t eip, uint32_t esp);

/**
 * Handles Caballero detection events
 */
int flxinstrument_caballero_event(uint32_t eip, uint32_t icount, uint32_t arithcount);

/**
 * Handles Arithwindow detection events
 */
int flxinstrument_arithwindow_event(uint32_t eip);

/**
 * Handles function call/ret events
 */
int flxinstrument_functiontrace_event(uint32_t eip, uint8_t type);

/**
 * Handles entropy heuristic events 
 */
int flxinstrument_functionentropy_event(float entropychange, uint32_t eip);

/**
 * Handles taintgraph events 
 */
int flxinstrument_functiontaint_event(float quotient, uint32_t eip);

/**
 * Called when pattern in memory found
 */
int flxinstrument_constsearch_event(uint32_t eip, uint8_t* pattern, uint32_t len);

/**
 * Called when pattern in code found 
 */
int flxinstrument_codesearch_event(uint32_t eip, uint8_t* pattern, uint32_t len);

/**
 * Called when Qemu is forced to shut down (Strg+C)
 */
int flxinstrument_shutdown_event(void);

#endif
