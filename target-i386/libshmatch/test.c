#include <time.h>
#include <stdlib.h>
#include <signal.h>

#include "shmatch.h"

/*
 * Felix Matenaar 2010
 */

struct {
	int runcount;
	int starttime;
	int endtime;
} stats;

void showstats(int sig){
	printf("--------------------------\n");
	printf("Started at %i\n", stats.starttime);
	printf("Successed %i counts\n", stats.runcount);
	printf("--------------------------\n");
}

size_t
myrand(size_t min, size_t max){
	int r = abs(rand());
	return (r%(max+1-min))+min;
}

struct string*
generate_string(int len){
	struct string* s = shmatch_string_new(len);
	size_t i;
	for(i=0; i<len; ++i){
		s->data[i] = myrand(0,256);
	}
	return s;
}

struct string**
generate_needles(int num){
	struct string** needles = malloc(sizeof(struct string*)*num);
	size_t i;
	for(i=0; i<num; ++i){
		needles[i] = generate_string(myrand(2,20));
	}
	return needles;
}

void
destroy_needles(struct string** needles, int num){
	size_t i;
	for(i=0; i<num; ++i){
		free(needles[i]->data);
		free(needles[i]);
	}
	free(needles);
}

struct string*
generate_haystack(struct string** needles, int num){
	size_t needed_len = 0;
	size_t i;
	for(i=0; i<num; ++i){
		needed_len += needles[i]->len;
	}
	needed_len *= myrand(2,4);
	struct string* haystack = generate_string(needed_len);

	size_t offset = 0;
	for(i=0; i<num; ++i){
		offset += myrand(0, needles[i]->len*1);		
		memcpy(haystack->data+offset, needles[i]->data, needles[i]->len);
		offset += needles[i]->len;
	}
	for(i=0; i<num; ++i){
		if(!memmem(haystack->data,haystack->len, needles[i]->data, needles[i]->len)){
			printf("Copying failed!\n");
			exit(-1);
		}
	}
	return haystack;
}

void
destroy_haystack(struct string* haystack){
	shmatch_string_destroy(haystack);
}

int
aho_find_all(struct shmatcher* m, struct string* haystack){
	int found = 0;
	struct match* p = shmatch_search(m, haystack);
	while(p){
		found++;
		shmatch_match_destroy(p);
		p = shmatch_search(m, NULL);
	}
	return found;
}

int
mem_find_all(struct string* haystack, struct string** patterns, int num){
	int found = 0;
	size_t i;
	for(i=0; i<num; ++i){
		if(memmem(haystack->data, haystack->len, patterns[i]->data, patterns[i]->len))
			found++;
	}
	return found;
}

void
bin_dump(char* desc, char* data, int len){
	printf("%s",desc);
	size_t i;
	for(i=0; i<len; ++i){
		printf("\\x%02x",(unsigned char)data[i]);
	}
	printf("\n");
}

void
dump_all(struct string* haystack, struct string** needles, int pattern_num, struct shmatcher* m){
	bin_dump("Haystack: ",haystack->data, haystack->len);
	size_t i;
	for(i=0; i<pattern_num; ++i){
		bin_dump("Pattern: ",needles[i]->data, needles[i]->len);
	}

	struct string* encoded = shmatch_xor_encode(haystack);
	bin_dump("Encoded Haystack: ", encoded->data, encoded->len);
	shmatch_string_destroy(encoded);
	struct list* patterns = m->patterns;
	while(patterns){
		struct pattern* p = patterns->data;
		bin_dump("Encoded Pattern: ", p->encoded_data->data, p->encoded_data->len);
		patterns = patterns->next;
	}
}

int
run_random_test(){
	int err = 0;
	int pattern_num = myrand(1,50);
	struct shmatcher* m = shmatch_new(shmatch_xor_encode);
	struct string** needles = generate_needles(pattern_num);
	struct string*  haystack= generate_haystack(needles, pattern_num);

	size_t i;
	for(i=0; i<pattern_num; ++i){
		if(shmatch_add_pattern(m, needles[i]) == -1)
			return -1;
	}

	int aho_found = aho_find_all(m, haystack);
	int mem_found = 0;
	if(aho_found < pattern_num){
		mem_found = mem_find_all(haystack, needles, pattern_num);	
		if(aho_found < mem_found){
			dump_all(haystack, needles, pattern_num, m);
			printf("aho_found: %i, mem_found: %i\n", aho_found, mem_found);
			printf("haystack len: %i\n", haystack->len);
			printf("pattern num: %i\n", pattern_num);
			return -1;
		}
		printf("num: %i\n",pattern_num);
		printf("found: %i\n",aho_found);
	}

	destroy_needles(needles, pattern_num);
	shmatch_string_destroy(haystack);
	shmatch_destroy(m);
	return err;
}

void
random_test(int duration, int count){
	srand(time(NULL));
	memset(&stats, 0, sizeof(stats));
	signal(SIGINT, showstats);
	stats.starttime = time(NULL);
	stats.endtime   = stats.starttime+duration;
	while(count--){
		int err = run_random_test();
		if(err != 0){
			printf("Fail. Errorcode: %i\n",err);
			showstats(0);
			return;
		}
		stats.runcount++;
		if(stats.endtime < time(NULL)){
			showstats(0);
			return;
		}
	}
}

int main(int argc, char *argv[]){
	if(argc != 3){
		printf("usage: %s %s %s",argv[0],"<max test time>", "<max test count");
		exit(0);
	}
	// argv[1] = maximum test time in seconds
	// argv[2] = maximum test count in run_test() calls
	random_test(atoi(argv[1]), atoi(argv[2]));
	return 0;
}
/*

	struct shmatcher* m = shmatch_new(shmatch_xor_encode);

	struct string haystack = {12,"\x6d\x72\xaa\x42\xaa\x42\x8a\x8a\x3d\x9c\x2a\x53"};
	struct string  needles[] ={
	                          {3,"\xaa\x42\xaa"},
	                          {3,"\x3d\x9c\x2a"},
                              {0,NULL}
	                         };
	size_t i=0;
	while(needles[i].data){
		if(shmatch_add_pattern(m, &needles[i]) == -1)
			printf("Failed to add pattern!\n");
		++i;
	}
	size_t found = 0;
	struct pattern* p = shmatch_search(m, &haystack);
	while(p){
		found++;
		//shmatch_print_pattern(p);
		p = shmatch_search(m, NULL);
	}
	shmatch_destroy(m);
	printf("Got %i matches!\n", found);
	return 0;
}
*/
