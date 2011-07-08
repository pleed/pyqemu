#include <unistd.h>

#include "shmatch.h"
#include "acwrap.h"

/*
 * Felix Matenaar 2010
 */

#ifdef DEBUG
/*
 * debug functions
 */
void
shmatch_print_pattern(struct pattern* p){
	struct string *s = p->data;
	printf("data->len: %i\n",s->len);
	printf("data->data: ");
	int i;
	for(i=0; i< s->len; ++i){
		printf("%c",s->data[i]);
	}
	printf("\n");

	s=p->encoded_data;
	printf("encoded->len: %i\n",s->len);
	printf("encoded->data: ");
	for(i=0; i< s->len; ++i){
		printf("0x%x ",s->data[i]);
	}
	printf("\n");
}
#endif

struct match*
shmatch_match_new(struct pattern* needle, struct pattern* haystack, int startpos, int endpos){
	struct match* match = malloc(sizeof(struct match));
	match->startpos = startpos;
	match->endpos   = endpos;
	match->haystack = shmatch_pattern_dup(haystack);
	match->needle   = shmatch_pattern_dup(needle);
	return match;
}

void
shmatch_match_destroy(struct match* match){
	if(match){
		shmatch_pattern_destroy(match->haystack);
		shmatch_pattern_destroy(match->needle);
	}
	free(match);
}

struct pattern*
shmatch_pattern_new(struct string* s, shmatch_encoder_t encoder){
	struct pattern *p = malloc(sizeof(struct pattern));
	p->data = shmatch_string_new(s->len);
	memcpy(p->data->data, s->data, s->len);
	p->encoded_data = encoder(s);
	return p;
}

struct pattern*
shmatch_pattern_dup(struct pattern* old){
	struct pattern* new = malloc(sizeof(struct pattern));
	new->data = shmatch_string_new(old->data->len);
	new->encoded_data = shmatch_string_new(old->encoded_data->len);
	memcpy(new->data->data, old->data->data, old->data->len);
	memcpy(new->encoded_data->data, old->encoded_data->data, old->encoded_data->len);
	return new;
}

void
shmatch_pattern_destroy(struct pattern* p){
	shmatch_string_destroy(p->data);
	shmatch_string_destroy(p->encoded_data);
	free(p);
}

struct string*
shmatch_string_new(size_t n){
	if(n <= 0)
		return NULL;

	struct string *s = malloc(sizeof(struct string));
	s->data = malloc(n);
	s->len  = n;
	return s;
}

void
shmatch_string_destroy(struct string* s){
	if(s->len > 0)
		free(s->data);
	free(s);
}

/*
struct string*
shmatch_rot_encode(struct string* old){
	struct string* new = shmatch_string_new(old->len-1);
	size_t i;
	for(i=0; i<(old->len-1); ++i){
		new->data[i] = old->data[i] - old->data[i+1];
	}
	return new;
}

struct string*
shmatch_xor_encode(struct string* old){
	struct string* new = shmatch_string_new(old->len-1);
	size_t i;
	for(i=0; i<(old->len-1); ++i){
		new->data[i] = old->data[i] ^ old->data[i+1];
	}
	return new;
}*/

struct string*
shmatch_stub_encode(struct string* old){
	struct string* new = shmatch_string_new(old->len);
	memcpy(new->data, old->data, new->len);
	return new;
}

struct string*
shmatch_xor_encode(struct string* old){
	struct string* new = shmatch_string_new(old->len-ENCODER_KEYLEN);
	long* to     = (long*)new->data;
	long* from   = (long*)old->data;
	long* from_x = (long*)(old->data+ENCODER_KEYLEN);
	size_t num   = (old->len-ENCODER_KEYLEN)/sizeof(long);

	size_t i;
	for(i=0; i<num; ++i){
		*to = *from ^ *from_x;
		to++;
		from++;
		from_x++;
	}

	size_t index = (char*)to - new->data;
	num = (old->len-ENCODER_KEYLEN)%sizeof(long);
	for(i=0; i<num; ++i, ++index){
		new->data[index] = old->data[index] ^ old->data[index+ENCODER_KEYLEN];
	}
	return new;
}

struct string*
shmatch_rot_encode(struct string* old){
	struct string* new = shmatch_string_new(old->len-ENCODER_KEYLEN);
	long* to     = (long*)new->data;
	long* from   = (long*)old->data;
	long* from_x = (long*)(old->data+ENCODER_KEYLEN);
	size_t num   = (old->len-ENCODER_KEYLEN)/sizeof(long);

	size_t i;
	for(i=0; i<num; ++i){
		*to = *from ^ *from_x;
		to++;
		from++;
		from_x++;
	}

	size_t index = (char*)to - new->data;
	num = (old->len-ENCODER_KEYLEN)%sizeof(long);
	for(i=0; i<num; ++i, ++index){
		new->data[index] = old->data[index] ^ old->data[index+ENCODER_KEYLEN];
	}
	return new;
}


struct shmatcher*
shmatch_new(shmatch_encoder_t encoder){
	struct shmatcher* m = malloc(sizeof(struct shmatcher));
	m->searcher = ahocorasick_search_alloc();
	m->tree     = ahocorasick_KeywordTree_alloc();
	m->encoder  = encoder;
	m->patterns = NULL;
	m->haystack = NULL;
	m->pos      = 0;
	if(!m->searcher ||
	   ! m->tree  ||
	   ! m->encoder){
		shmatch_destroy(m);
		return NULL;
	}
	return m;
}

void
shmatch_destroy(struct shmatcher* matcher){
	ahocorasick_search_dealloc(matcher->searcher);
	ahocorasick_KeywordTree_dealloc(matcher->tree);
	struct list* l = matcher->patterns;
	struct list* tmp;
	while(l){
		shmatch_pattern_destroy(l->data);
		tmp = l;
		l = l->next;
		free(tmp);
	}
	free(matcher);
}

int
shmatch_add_pattern(struct shmatcher* matcher, struct string* pattern){
	struct pattern* p = shmatch_pattern_new(pattern, matcher->encoder);

	if(ahocorasick_KeywordTree_add(matcher->tree, (unsigned char*)p->encoded_data->data, p->encoded_data->len, p) == -1)
		return -1;

	struct list* l = malloc(sizeof(struct list));
	l->data = p;
	l->next = matcher->patterns;
	matcher->patterns = l;
	return 0;
}

struct match*
shmatch_search(struct shmatcher* matcher, struct string* data){
	if(!matcher->tree->made)
		ahocorasick_KeywordTree_make(matcher->tree);

	if(data){
		if(matcher->haystack)
			shmatch_pattern_destroy(matcher->haystack);
		matcher->haystack = shmatch_pattern_new(data, matcher->encoder);
		memset(matcher->searcher, 0, sizeof(aho_corasick_search));
		matcher->pos = 0;
	}

	matcher->searcher = ahocorasick_KeywordTree_search(matcher->tree, matcher->haystack->encoded_data->data,
	                                                 matcher->haystack->encoded_data->len, matcher->pos, matcher->searcher);
	if(matcher->searcher->start < 0){
		if(matcher->haystack){
			shmatch_pattern_destroy(matcher->haystack);
			matcher->haystack = NULL;
		}
		return NULL;
	}	
	matcher->pos = matcher->searcher->end+1;
	return shmatch_match_new(matcher->searcher->search_state->pattern,
	                         matcher->haystack,
	                         matcher->searcher->start,
	                         matcher->searcher->end);
	//return shmatch_pattern_dup(matcher->searcher->search_state->pattern);
}
