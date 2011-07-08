#ifndef SHMATCH_H
#define SHMATCH_H

#include <string.h>
#include "acwrap.h"

/*
 * Felix Matenaar 2010
 */

#define ENCODER_KEYLEN 1

typedef struct string* (*shmatch_encoder_t)(struct string*);

struct string {
	size_t len;
	char *data;
};

struct pattern {
	struct string *data;
	struct string *encoded_data;
	size_t score;
};

struct list {
	void* data;
	struct list *next;	
};

struct shmatcher {
	aho_corasick_search* searcher;
	ahocorasick_KeywordTree* tree;
	shmatch_encoder_t encoder;	
	struct list *patterns;

	struct pattern* haystack;
	size_t pos;
};

struct match {
	struct pattern* needle;
	struct pattern* haystack;
	int startpos;
	int endpos;
};

/*
 * Creates a new matcher.
 * Choose between XOR and ROT encoding.
 */
struct shmatcher*      shmatch_new(shmatch_encoder_t);

/*
 * Deallocates matcher
 */
void                   shmatch_destroy(struct shmatcher*);

/*
 * Add new pattern to matcher
 */
int	                   shmatch_add_pattern(struct shmatcher*, struct string*);

/*
 * Search for matches in data.
 * Call with NULL for second to last matches.
 */
struct match*          shmatch_search(struct shmatcher*, struct string*);

/*
 * XOR Encoder
 */
struct string*         shmatch_xor_encode(struct string*);

/*
 * ROT Encoder
 */
struct string*         shmatch_rot_encode(struct string*);

/*
 * STUB Encoder
 */
struct string*         shmatch_stub_encode(struct string*);


/*
 * Struct creation/destroy functions
 */
void                   shmatch_string_destroy(struct string* s);
struct string*         shmatch_string_new(size_t n);

void                   shmatch_pattern_destroy(struct pattern* p);
struct pattern*        shmatch_pattern_new(struct string* s, shmatch_encoder_t encoder);
struct pattern*        shmatch_pattern_dup(struct pattern* old);

struct match*          shmatch_match_new(struct pattern* p, struct pattern* searchstring, int startpos, int endpos);
void                   shmatch_match_destroy(struct match* match);

#ifdef DEBUG
void                   shmatch_print_pattern(struct pattern* p);
#endif

#endif

