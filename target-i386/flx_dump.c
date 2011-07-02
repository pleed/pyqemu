#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <avl.h>
#include <math.h>
#include <shmatch.h>

#include "flx_instrument.h"
#include "flx_context.h"
#include "flx_memtrace.h"
#include "flx_calltrace.h"

#include "flx_dump.h"

char* flx_dump_path = NULL;

void
flx_dump_init(const char* path){
	flx_dump_path = strdup(path);
}

void
flx_dump_destroy(void){
	free(flx_dump_path);
}

static uint32_t
flx_strncat(char* dest, const char* src, uint32_t size){
	uint32_t src_len = strlen(src);
	strncat(dest, src, size);
	if(src_len > size)
		return 0;
	else
		return size-src_len;
}

static inline char*
flx_dump_generate_filename(flx_context* context){
	time_t now;
	time(&now);
	char* time_str = strdup(ctime(&now));
	uint32_t procname_len = strlen(context->procname);
	uint32_t flx_dump_path_len = strlen(flx_dump_path);
	uint32_t tmp_len = procname_len + strlen(time_str) + flx_dump_path_len + 32 + strlen(" dump");
	uint32_t bytes_left = tmp_len;
	char* tmp = malloc(tmp_len);
	char* id_str = malloc(64);
	snprintf(id_str, 32, " %u %u", context->pid, context->tid);

	tmp[0] = '\0';
	bytes_left = flx_strncat(tmp, flx_dump_path, bytes_left);
	bytes_left = flx_strncat(tmp, context->procname, bytes_left);
	bytes_left = flx_strncat(tmp, id_str, bytes_left);
	bytes_left = flx_strncat(tmp, " ", bytes_left);
	bytes_left = flx_strncat(tmp, time_str, bytes_left);
	tmp[tmp_len-bytes_left-1] = '\0';
	bytes_left = flx_strncat(tmp, ".dump", bytes_left);

	free(id_str);
	free(time_str);
	return tmp;
}


static inline FILE*
flx_dump_current_fp(void){
	flx_context* context = flx_context_current();
	if(!context){
		exit(-1);
	}
	if(!context->dump){
		context->dump_destructor = (context_destructor)fclose;
		context->dump = fopen(flx_dump_generate_filename(context), "w");
		assert(context->dump);
	}
	return context->dump;
}

static void
flx_dump_event(uint8_t* buf, uint32_t size){
	uint32_t written = fwrite(buf, size, 1, flx_dump_current_fp());
	if(written < 1)
		printf("WARNING - Dumpfile is corrupted!\n");
}

static int
flx_dump_mem(uint32_t address, uint32_t value, uint8_t size, uint8_t iswrite){
	flx_dump_memaccess event = {MEM_ACCESS, address, value, size<<1|iswrite};
	flx_dump_event((uint8_t*)&event, sizeof(event));
	return 0;
}

static int
flx_dump_function(uint32_t old_eip, uint32_t new_eip, uint32_t next_eip, uint32_t esp, uint8_t type){
	flx_dump_functionevent event = {FUNCTION, new_eip, type};
	flx_dump_event((uint8_t*)&event, sizeof(event));
	return 0;
}

void
flx_dump_enable(void){
	flx_memtrace_register_handler(flx_dump_mem);
	flx_memtrace_enable();
	flx_calltrace_register_handler(flx_dump_function);
	flx_calltrace_enable();
	flx_state.dump_active = 1;
}

void
flx_dump_disable(void){
	flx_memtrace_unregister_handler(flx_dump_mem);
	flx_calltrace_unregister_handler(flx_dump_function);
	flx_state.dump_active = 0;
}

