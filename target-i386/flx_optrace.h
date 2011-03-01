#include <inttypes.h>
#include <stdint.h>
#include <sys/types.h>

enum {
	FLX_OP_OR,
	FLX_OP_AND,
	FLX_OP_XOR,
	FLX_OP_ROL,
	FLX_OP_ROR,
	FLX_OP_RCL,
	FLX_OP_SHL,
	FLX_OP_SHR,
	FLX_OP_SHL1,
	FLX_OP_SAR,
};

typedef int(*optrace_handler)(uint32_t, uint32_t);

extern uint8_t optrace_enabled;
extern optrace_handler flx_optrace_handler;

void flx_optrace_init(optrace_handler handler);
void flx_optrace_enable(void);
void flx_optrace_disable(void);
void flx_optrace_event(uint32_t eip, uint32_t opcode);
