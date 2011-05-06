#ifndef FLX_HOOKING
#define FLX_HOOKING

#include "flx_instrument.h"

#define FLX_ON_USERSPACE      0x00000001
#define FLX_ON_MEMTRACE       0x00000004
#define FLX_ON_FILTERED       0x00000008
#define FLX_ON_GLOBAL_ACTIVE  0x00000010
#define FLX_ON_CALL_ACTIVE    0x00000020
#define FLX_ON_RET_ACTIVE     0x00000040
#define FLX_ON_JMP_ACTIVE     0x00000080
#define FLX_ON_SYSCALL_ACTIVE 0x00000100
#define FLX_ON_CABALLERO      0x00000200
#define FLX_ON_BBLTRACE       0x00000400

/* use this hook to catch events happening *anywhere* in the process */
#define flx_global_hook(conditions, context, hook, ...) do{ \
											FLX_TEST_CONDITIONS( FLX_ON_USERSPACE | conditions );\
											do{\
											gen_jmp_im(pc_ptr - context->cs_base);\
											hook(__VA_ARGS__);\
											}while(0);\
										  }while(0)

/* use this hook to catch events happening *only* in the main process image */
#define flx_hook(conditions, context, hook, ...) do{ \
											FLX_TEST_CONDITIONS( FLX_ON_GLOBAL_ACTIVE | FLX_ON_USERSPACE | conditions );\
											do{\
											gen_jmp_im(pc_ptr - context->cs_base);\
											hook(__VA_ARGS__);\
											}while(0);\
										  }while(0)

#define FLX_TEST_CONDITION(conditions, code, condition) ((((conditions) & condition) && !(code))?0:1)

#define FLX_TEST_CONDITION_FILTERED(conditions)       FLX_TEST_CONDITION(conditions, ((flx_state.filter_active) && (flx_filter_search_by_addr(pc_ptr))), FLX_ON_FILTERED)
#define FLX_TEST_CONDITION_USERSPACE(conditions)      FLX_TEST_CONDITION(conditions, userspace(pc_ptr), FLX_ON_USERSPACE)
#define FLX_TEST_CONDITION_BBLTRACE(conditions)       FLX_TEST_CONDITION(conditions, flx_state.bbltrace_active, FLX_ON_BBLTRACE)
#define FLX_TEST_CONDITION_MEMTRACE(conditions)       FLX_TEST_CONDITION(conditions, flx_state.memtrace_active, FLX_ON_MEMTRACE)
#define FLX_TEST_CONDITION_GLOBAL_ACTIVE(conditions)  FLX_TEST_CONDITION(conditions, flx_state.global_active, FLX_ON_GLOBAL_ACTIVE)
#define FLX_TEST_CONDITION_JMP_ACTIVE(conditions)     FLX_TEST_CONDITION(conditions, flx_state.jmp_active,    FLX_ON_JMP_ACTIVE)
#define FLX_TEST_CONDITION_RET_ACTIVE(conditions)     FLX_TEST_CONDITION(conditions, flx_state.ret_active,    FLX_ON_RET_ACTIVE)
#define FLX_TEST_CONDITION_CALL_ACTIVE(conditions)    FLX_TEST_CONDITION(conditions, flx_state.call_active,   FLX_ON_CALL_ACTIVE)
#define FLX_TEST_CONDITION_SYSCALL_ACTIVE(conditions) FLX_TEST_CONDITION(conditions, flx_state.syscall_active,   FLX_ON_SYSCALL_ACTIVE)
#define FLX_TEST_CONDITION_CABALLERO(conditions)           FLX_TEST_CONDITION(conditions, flx_state.caballero_active, FLX_ON_CABALLERO)


#define FLX_TEST_CONDITIONS(conditions) if(!FLX_TEST_CONDITION_GLOBAL_ACTIVE(conditions) || \
					!FLX_TEST_CONDITION_USERSPACE(conditions)     ||\
					!FLX_TEST_CONDITION_FILTERED(conditions)      ||\
					!FLX_TEST_CONDITION_CALL_ACTIVE(conditions)   ||\
					!FLX_TEST_CONDITION_JMP_ACTIVE(conditions)    ||\
					!FLX_TEST_CONDITION_RET_ACTIVE(conditions)    ||\
					!FLX_TEST_CONDITION_SYSCALL_ACTIVE(conditions)    ||\
					!FLX_TEST_CONDITION_BBLTRACE(conditions)       ||\
					!FLX_TEST_CONDITION_CABALLERO(conditions) ||\
					!FLX_TEST_CONDITION_MEMTRACE(conditions)){\
						break;\
					}

#endif

