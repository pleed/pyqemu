#ifndef _FLX_INSTRUMENT_
#define _FLX_INSTRUMENT_

#include <inttypes.h>

void flxinstrument_init(void);
int flxinstrument_update_cr3(uint32_t old_cr3, uint32_t new_cr3);
int flxinstrument_call_event(uint32_t call_origin, uint32_t call_destination);
int flxinstrument_syscall_event(uint32_t eax);
int flxinstrument_ret_event(uint32_t ret_origin);

extern CPUState *current_environment;

extern int instrumentation_active;
extern int instrumentation_call_active;
extern int instrumentation_syscall_active;
extern int instrumentation_ret_active;
extern int python_active;

#endif
