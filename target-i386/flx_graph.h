#include <stdio.h>
#include <avl.h>

typedef avl_tree_t flx_graph;
typedef uint32_t vertex_iterator;
typedef uint32_t edge_iterator;

typedef struct {
	avl_tree_t* edges;
	uint32_t v;
} vertex;

typedef struct {
	vertex** vertices;
	uint32_t num;
} vertex_block;

flx_graph* flx_graph_alloc(void);
void       flx_graph_dealloc(flx_graph* graph);
vertex*    flx_graph_add_vertex(flx_graph* graph, uint32_t v);
void       flx_graph_add_edge(flx_graph* graph, uint32_t u, uint32_t v);

vertex_iterator flx_graph_iterator_new(void);
vertex*         flx_graph_iterate(flx_graph* graph, vertex_iterator* i);
edge_iterator   flx_edge_iterator_new(void);
vertex*         flx_edge_iterate(vertex* v, edge_iterator* i);

float flx_taint_quotient(flx_graph* g);

