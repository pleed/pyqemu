#include <inttypes.h>

#include "exec-all.h"
#include "cpu.h"

#include "flx_instrument.h"
#include "flx_memtrace.h"

memtrace_handler flx_memtrace_handlers[MAX_MEMTRACE_HANDLERS];

void flx_memtrace_init(void){
	memset(flx_memtrace_handlers, 0, sizeof(flx_memtrace_handlers));
}

void flx_memtrace_enable(void){
	flx_state.memtrace_active = 1;
}
void flx_memtrace_disable(void){
	flx_state.memtrace_active = 0;
}

void flx_memtrace_event(uint32_t address, uint32_t value, uint8_t size, uint8_t iswrite){
	static struct timeval before_tv = {0,0};	
	static struct timeval after_tv = {0,0};
	static struct timeval sum_tv = {0,0};
	static uint32_t timr = 0;
	static FILE* f = NULL;

	gettimeofday(&before_tv, NULL);

	if(!f){
		f = fopen("/tmp/bla","a");
	}
	fwrite(&address, 4, 1, f);
	fwrite(&value, 4, 1, f);
	fwrite(&size, 1, 1, f);
	fwrite(&iswrite, 1, 1, f);


	uint8_t i;
	for(i=0; i<MAX_MEMTRACE_HANDLERS; ++i){
		if(!flx_memtrace_handlers[i])
			break;
		flx_memtrace_handlers[i](address, value, size, iswrite);
	}

	gettimeofday(&after_tv, NULL);
	sum_tv.tv_sec += after_tv.tv_sec - before_tv.tv_sec;
	suseconds_t tmp = sum_tv.tv_usec + after_tv.tv_usec;
	if(tmp < sum_tv.tv_usec){
		sum_tv.tv_sec +=1;
	}
	sum_tv.tv_usec = tmp;
	if(sum_tv.tv_sec > timr){
		printf("Seconds: %lu\n",sum_tv.tv_sec);
		printf("Microseconds: %lu\n",sum_tv.tv_usec);
		timr = sum_tv.tv_sec;
	}
}

void flx_memtrace_register_handler(memtrace_handler handler){
	uint8_t i;
	for(i=0; i<MAX_MEMTRACE_HANDLERS; ++i){
		if(!flx_memtrace_handlers[i]){
			flx_memtrace_handlers[i] = handler;
			return;
		}
	}
	printf("WARNING, MAX_MEMTRACE_HANDLERS reached!!!\n");
	exit(-1);
	return;
}

void flx_memtrace_unregister_handler(memtrace_handler handler){
	uint8_t i;
	uint8_t handler_index = 0;
	uint8_t last_handler_index = 0;
	for(i=0; i<MAX_MEMTRACE_HANDLERS; ++i){
		if(flx_memtrace_handlers[i]){
			last_handler_index = i;
			if(flx_memtrace_handlers[i] == handler){
				handler_index = i;
			}
		}
	}
	flx_memtrace_handlers[handler_index] = flx_memtrace_handlers[last_handler_index];
	flx_memtrace_handlers[last_handler_index] = NULL;
}
