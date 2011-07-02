#ifndef FLX_DUMP
#define FLX_DUMP

enum flx_events {
	MEM_ACCESS,
	FUNCTION,
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
	uint16_t pid;
	uint16_t tid;
} flx_dump_context;


void flx_dump_init(const char* dumpfile);
void flx_dump_destroy(void);
void flx_dump_enable(void);
void flx_dump_disable(void);

#endif
