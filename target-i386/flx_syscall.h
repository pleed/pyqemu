#ifndef FLX_SYSCALL
#define FLX_SYSCALL

#include <avl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>

#include "flx_instrument.h"
#include "flx_bbltranslate.h"

typedef int(*syscall_handler)(uint32_t);

void flx_syscall_init(syscall_handler);
void flx_syscall_enable(void);
void flx_syscall_disable(void);
void flx_syscall_destroy(void);
void flx_syscall_event(uint32_t);
void flx_syscall_hook(uint32_t);

#endif
