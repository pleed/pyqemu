#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <avl.h>
#include <unistd.h>

#include "flx_instrument.h"
#include "flx_syscall.h"

/*
 * This module distributes syscall events via
 * the register_handler API
 */

#define NUM_SYSCALLS 0x117

syscall_handler flx_syscall_handler = NULL;
uint8_t syscall_hook_table[NUM_SYSCALLS];

void flx_syscall_init(syscall_handler handler){
	memset(syscall_hook_table, 0, sizeof(syscall_hook_table));
	flx_syscall_handler = handler;
}

void flx_syscall_destroy(void){
	memset(syscall_hook_table, 0, sizeof(syscall_hook_table));
	return;
}

void flx_syscall_enable(void){
	flx_state.syscall_active = 1;
}

void flx_syscall_disable(void){
	flx_state.syscall_active = 0;
}

void flx_syscall_hook(uint32_t syscall){
	if(syscall < NUM_SYSCALLS)
		syscall_hook_table[syscall] = 1;
}

void flx_syscall_event(uint32_t syscall){
	if(syscall < NUM_SYSCALLS && syscall_hook_table[syscall] && flx_state.syscall_active)
		flx_syscall_handler(syscall);
}

