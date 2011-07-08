#ifndef ACWRAP_H
#define ACWRAP_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "aho-corasick.h"
#include "shmatch.h"

/* written by Felix Matenaar 2010 */

typedef struct {
	int count;
	int made;
	aho_corasick_t* tree;
} ahocorasick_KeywordTree;

typedef struct {
	int start;
	int end;
	aho_corasick_state_t *search_state;
} aho_corasick_search;

/*
 * Allocate new KeywordTree
 */
ahocorasick_KeywordTree*             ahocorasick_KeywordTree_alloc(void);
void                                 ahocorasick_KeywordTree_dealloc(ahocorasick_KeywordTree* matcher);
int                                  ahocorasick_KeywordTree_add(ahocorasick_KeywordTree* matcher, unsigned char* needle, size_t len, struct pattern* p);
int                                  ahocorasick_KeywordTree_make(ahocorasick_KeywordTree* matcher);
aho_corasick_search*                 ahocorasick_KeywordTree_basesearch(ahocorasick_KeywordTree* matcher, 
                                                                        char* haystack, size_t len, size_t s,
                                                                        ahocorasick_KeywordTree_search_helper_t helper,
                                                                        aho_corasick_search* searcher);
aho_corasick_search*                 ahocorasick_search_alloc();
void                                 ahocorasick_search_dealloc(aho_corasick_search* s);
aho_corasick_search*                 ahocorasick_KeywordTree_search(ahocorasick_KeywordTree* matcher, char* haystack, size_t len, size_t startpos,
                                                                    aho_corasick_search* searcher);

#endif
