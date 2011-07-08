#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "aho-corasick.h"
#include "shmatch.h"

/* written by Felix Matenaar 2010 */

/*
 * Allocate new KeywordTree
 */
ahocorasick_KeywordTree*
ahocorasick_KeywordTree_alloc(void){
	ahocorasick_KeywordTree* matcher = malloc(sizeof(ahocorasick_KeywordTree));
	matcher->count = 0;
	matcher->made  = 0;
	matcher->tree  = malloc(sizeof(aho_corasick_t));	
	if(aho_corasick_init(matcher->tree) == -1)
		return NULL;
	return matcher;
}

void
ahocorasick_KeywordTree_dealloc(ahocorasick_KeywordTree* matcher){
	aho_corasick_destroy(matcher->tree);
	free(matcher->tree);
	free(matcher);
}

int
ahocorasick_KeywordTree_add(ahocorasick_KeywordTree* matcher, unsigned char* needle, size_t len, struct pattern* p){
	if(aho_corasick_addstring(matcher->tree, needle, len, p) == -1)
		return -1;
	matcher->count++;
	return 0;
}

int
ahocorasick_KeywordTree_make(ahocorasick_KeywordTree* matcher){
	if(!matcher->made){
		if(matcher->count == 0){
			return -1;
		}
		aho_corasick_maketree(matcher->tree);
		matcher->made = 1;
	}
	return 0;
}

aho_corasick_search*
ahocorasick_KeywordTree_basesearch(ahocorasick_KeywordTree* matcher, char* haystack, size_t len, size_t s, ahocorasick_KeywordTree_search_helper_t helper, aho_corasick_search* searcher){
	unsigned char *queryString = (unsigned char*)haystack;
	int startpos = s;
	aho_corasick_state_t *last_state;
	aho_corasick_state_t *initial_state = searcher->search_state;
	size_t n = len;
	size_t start, end;

	if(startpos < 0)
		return NULL;	
	if(!matcher->made)
		return NULL;
	if(!initial_state){
#ifdef DEBUG
		printf("doing init state\n");
#endif
		initial_state = matcher->tree->zerostate;
	}

	if((*helper)(initial_state,
				 queryString, n,
				 startpos,
				 &start, &end, &last_state)){
	}
	searcher->start = start;
	searcher->end   = end;
	searcher->search_state = last_state;
	return searcher;
}

aho_corasick_search*
ahocorasick_search_alloc(){
	aho_corasick_search* s = malloc(sizeof(aho_corasick_search));
	memset(s, 0, sizeof(aho_corasick_search));
	return s;
}

void
ahocorasick_search_dealloc(aho_corasick_search* s){
	free(s);
}

aho_corasick_search*
ahocorasick_KeywordTree_search(ahocorasick_KeywordTree* matcher, char* haystack, size_t len, size_t startpos, aho_corasick_search* searcher){
	return ahocorasick_KeywordTree_basesearch(matcher, haystack, len, startpos, ahocorasick_KeywordTree_search_long_helper, searcher);
}
