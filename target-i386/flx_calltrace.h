#ifndef FLX_CALLTRACE
#define FLX_CALLTRACE

#include <avl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>

#include "flx_instrument.h"

#define MAX_CALLTRACE_HANDLERS 16
#define FLX_CALLTRACE_STACKFRAMES_STEPS 1000

typedef uint8_t flx_call_type;

enum {
	FLX_CALLTRACE_CALL = 0,
	FLX_CALLTRACE_RET  = 1,
	FLX_CALLTRACE_MISSED_RET = 2,
};

typedef struct {
	uint32_t eip;
	uint32_t esp;
} flx_frame;

typedef struct {
	flx_frame* frames;
	uint32_t  max_element;
	uint32_t  cur_element;
} flx_stackframes;

typedef int(*calltrace_handler)(uint32_t old_eip, uint32_t new_eip, uint32_t next_eip, uint32_t esp, flx_call_type type);

void flx_calltrace_init(void);
void flx_calltrace_register_handler(calltrace_handler handler);
void flx_calltrace_unregister_handler(calltrace_handler handler);
void flx_calltrace_enable(void);
void flx_calltrace_disable(void);
void flx_calltrace_event(uint32_t, uint32_t, uint32_t, uint32_t);
int flx_calltrace_bblexec(uint32_t, uint32_t);
uint32_t flx_lookup_current_function(void);

#endif
