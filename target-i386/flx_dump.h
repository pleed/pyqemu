#ifndef FLX_DUMP
#define FLX_DUMP

enum flx_events {
	MEM_ACCESS,
	FUNCTION,
	BBLEXEC,
	BBLTRANSLATE,
};

typedef struct __attribute__((__packed__)){
	uint8_t event_type;
	uint32_t eip;
	uint8_t type;
} flx_dump_functionevent;

typedef struct __attribute__((__packed__)){
	uint8_t event_type;
	uint32_t address;
	uint32_t value;
	uint8_t options;
} flx_dump_memaccess;

typedef struct __attribute__((__packed__)){
	uint8_t event_type;
	uint32_t addr;
} flx_dump_exec;

typedef struct __attribute__((__packed__)){
	uint8_t event_type;
	uint32_t icount;
	uint32_t total_count;
	uint32_t movcount;
	uint32_t addr;
	uint32_t insn[];
} flx_dump_translate;



void flx_dump_init(void);
void flx_dump_destroy(void);
void flx_dump_enable(const char* dumpfile);
void flx_dump_disable(void);

#endif
