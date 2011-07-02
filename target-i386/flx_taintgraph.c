#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <avl.h>
#include <sys/time.h>

#include "flx_graph.h"

static void
flx_vertex_destroy(vertex* v){
	if(v->edges)
		avl_free_tree(v->edges);
	free(v);
}

static int
avl_vertex_compare(const vertex* v1, const vertex* v2){
	if(v1->v < v2->v)
		return -1;
	else if(v1->v > v2->v)
		return 1;
	else
		return 0;
}

static void
avl_vertex_free(vertex* v){
	flx_vertex_destroy(v);
}

static void
avl_edge_free(vertex* v){
	return;
}

flx_graph*
flx_graph_alloc(void){
	return avl_alloc_tree((avl_compare_t)avl_vertex_compare, (avl_freeitem_t)avl_vertex_free);
}

void
flx_graph_dealloc(flx_graph* graph){
	avl_free_tree(graph);
}

vertex*
flx_graph_add_vertex(flx_graph* graph, uint32_t value){
	vertex* v = malloc(sizeof(*v));
	v->v = value;
	avl_node_t* node = avl_insert(graph, v);
	if(!node){
		node = avl_search(graph, v);
		free(v);
		return node->item;
	}
	else{
		v->edges = avl_alloc_tree((avl_compare_t)avl_vertex_compare, (avl_freeitem_t)avl_edge_free);
		return v;
	}
}

void
flx_graph_add_edge(flx_graph* graph, uint32_t value1, uint32_t value2){
	vertex* v = flx_graph_add_vertex(graph, value1);
	vertex* u = flx_graph_add_vertex(graph, value2);
	avl_insert(v->edges, u);
}

vertex_iterator
flx_graph_iterator_new(void){
	return 0;
}

vertex*
flx_graph_iterate(flx_graph* g, vertex_iterator* i){
	avl_node_t* node = avl_at(g, *i);
	if(!node)
		return NULL;
	
	vertex* v = node->item;
	++(*i);
	return v;
}

edge_iterator
flx_edge_iterator_new(void){
	return 0;
}

vertex*
flx_edge_iterate(vertex* v, edge_iterator* i){
	avl_node_t* node = avl_at(v->edges, *i);
	if(!node)
		return NULL;
	vertex* u = node->item;
	++(*i);
	return u;
}

static vertex_block*
flx_taint_next_block(flx_graph* g, vertex_iterator* iter){
	uint32_t last_num = 0;
	uint32_t allocated_num = 128;
	vertex_block* block = malloc(sizeof(*block));

	memset(block, 0, sizeof(*block));
	block->vertices = malloc(sizeof(vertex*)*allocated_num);

	vertex* tmp = flx_graph_iterate(g, iter);
	if(!tmp){
		free(block->vertices);
		free(block);
		return NULL;
	}

	block->vertices[block->num++] = tmp;
	last_num = tmp->v;

	while((tmp = flx_graph_iterate(g, iter))){
		if(block->num >= allocated_num){
			allocated_num += 128;
			block->vertices = realloc(block->vertices, sizeof(vertex*)*allocated_num);
		}

		if(tmp->v == last_num+1){
			block->vertices[block->num++] = tmp;
			last_num+=1;
		}
		else{
			--(*iter);
			break;
		}
	}
	return block;
}

static float
flx_taint_calc_quotient(vertex_block* block){
	return 0.0;
	if(block->num < 8){
		return 0;
	}

	uint32_t i;
	uint32_t j;
	uint32_t vertices = block->num;
	uint32_t edges = block->num;

	for(i=0; i<block->num; ++i){
		for(j=0; j<block->num; ++j){
			if(i==j)
				continue;
			else{
				if(avl_search(block->vertices[i]->edges, block->vertices[j]))
					++edges;
			}
		}
	}
	return (float)edges/(float)vertices;
}

float
flx_taint_quotient(flx_graph* g){
	vertex_iterator iter = flx_graph_iterator_new();
	vertex_block* block;
	float max_quotient = 0.0;
	while((block = flx_taint_next_block(g, &iter))){
		float tmp = flx_taint_calc_quotient(block);
		max_quotient = (max_quotient > tmp) ? max_quotient : tmp;
		free(block->vertices);
		free(block);
	}
	return max_quotient;
}

/*
int main(int argc, char* argv[]){
	flx_graph* g = flx_graph_alloc();

	int i;
	int j;
	for(i=0; i<100; ++i){
		for(j=0; j<100; ++j)
			flx_graph_add_edge(g,i,j);
	}
	printf("%f\n",flx_taint_quotient(g));

	flx_graph_dealloc(g);
	return 0;
}
*/
