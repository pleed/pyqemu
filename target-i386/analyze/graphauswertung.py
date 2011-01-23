#!/usr/bin/env python

class MyFasterGraph:
	def __init__(self, graph = None):
		self.edges = {}
		self.nodes  = {}
		if graph is not None:
			for node in graph.nodes():
				node = str(node)
				self.add_node(int(node))
			for edge in graph.edges():
				edge = map(int, edge)
				self.add_edge(edge[0],edge[1])
				

	def add_node(self, node):
		self.nodes[node] = node
		self.edges[node] = {}

	def add_edge(self, src, dst):
		if not src == dst:
			if not self.nodes.has_key(src):
				self.add_node(src)
			if not self.nodes.has_key(dst):
				self.add_node(dst)
			self.edges[src][dst] = dst

	def get_nodes(self):
		return self.nodes.keys()

	def get_node_count(self):
		return len(self.nodes)

	def get_edge_count(self):
		count = 0
		for key,value in self.edges.items():
			count += len(value)
		return count

	def subgraph(self, nodes):
		g = MyFasterGraph()
		nodes.sort()
		for node in nodes:
			g.add_node(node)
			for key in self.edges[node]:
				g.add_edge(node, key)
		return g

	def __str__(self):
		#edgelist = []
		#for node in self.nodes:
		#	for key in self.edges[node]:
		#		edgelist.append((node,key))
		#return "Nodes: "+str(self.nodes.keys())+"\nEdges: "+str(edgelist)
		return str(self.nodes)+"\n\n\n"+str(self.edges)+"\n\n\n"

	def del_edge(self, src, dst):
		del(self.edges[src][dst])

	def del_node(self, node):
		del(self.edges[node])
		for key in self.edges:
			if self.edges[key].has_key(node):
				del(self.edges[key][node])
		del(self.nodes[node])

def block_quotient(l):
	return float(len(l))/float(l[-1]-l[0]+1)

def is_block(l, treshold=1):
	return block_quotient(l)>=treshold

def max_clique(graph): #NP!
	nodes = graph.get_nodes()
	nodes.sort()
	blocks = create_blocks(nodes)
	quotient = None
	g = None
	for block in blocks:
		subgraph = graph.subgraph(block)
		if quotient is None:
			quotient = clique_quotient(subgraph)
			q = quotient
			g = subgraph
		else:
			q = clique_quotient(subgraph)
			if q > quotient:
				g = subgraph
				quotient = q
	return quotient,g

def create_blocks(l):
	blocklist = []
	cur_block = []
	for item in l:
		if len(cur_block)==0: 
			cur_block.append(item)
		elif abs(int(item)-int(last)) == 1:
			cur_block.append(item)
		else:
			blocklist.append(cur_block)
			cur_block = [item]
		last = item
	if len(cur_block) > 0:
		blocklist.append(cur_block)
	return blocklist

def clique_quotient(graph):
	nodes = graph.get_node_count()
	edges = graph.get_edge_count()
	q = float(edges)/float(nodes)
	return q

def get_graph(count):
	g = MyFasterGraph()
	for i in range(count):
		g.add_node(i)
	#g.add_node(1)
	#g.add_node(2)
	#g.add_node(3)
	#g.add_node(4)
	for node1 in g.get_nodes():
		for node2 in g.get_nodes():
			g.add_edge(node1,node2)
	
	#g.add_node(7)
	#g.add_node(8)
	#g.add_node(9)
	#g.add_node(10)
	#g.add_node(11)
	#for node1 in g.get_nodes():
#		for node2 in g.get_nodes():
#			if node1 in range(7,12) and node2 in range(7,12):
#				g.add_edge(node1,node2)
#	g.del_edge(7,8)
#	g.del_edge(7,9)
#	g.del_edge(8,10)
#	g.del_edge(8,11)
	print "get_graph done"
	return g

#g = get_graph(1000)
#q,g = max_clique(g)
#print "Quotient: "+str(q)

import sys
import glob
import json
import os
import pygraphviz as pgv

class FlxFunctionAnalysis(dict):
	def __init__(self, name):
		self.name = name
		dict.__init__(self)

	def putAnalysis(self, analysis):
		for key,value in analysis.items():
			if not self.has_key(key):
				self[key] = [value]
			else:
				self[key].append(value)

	def putGraph(self, graph):
		#quotient = float(len(graph.edges()))/float(len(graph.nodes()))
		analyzer = GraphAnalyzer(graph)
		quotient = analyzer.getAnalysis()
		#quotient,graph = max_clique(MyFasterGraph(graph))
		if self.name == "0x4015b0":
			print graph
		if not self.has_key("graph_quotient"):
			self["graph_quotient"] = [quotient]
		else:
			self["graph_quotient"].append(quotient)
		#if not self.has_key("graph_property"):
		#	self["graph_property"] = [len(graph.get_nodes())]
		#else:
	#		self["graph_property"].append(len(graph.get_nodes()))

	def analyzeWriteStats(self, stats):
		return 0.0

	def avg(self):
		for key,list in self.items():
			accumulator = 0.0
			if key == "write_stats":
				self[key] = self.analyzeWriteStats(list)
			else:
				for value in list:
					accumulator += float(value)
				accumulator = float(accumulator) / float(len(list))
				self[key] = accumulator
		return self

	def getName(self):
		return self.name

	def __getitem__(self, key):
		if not self.has_key(key):
			return None
		return dict.__getitem__(self, key)

	def show(self, keys = None):
		s = ""
		if keys is None or len(keys) == 0:
			for key,value in self.items():
				s+="\t%s:%s"%(key,value)
		else:
			for key in keys:
				s+="\t%s:%s"%(key,self[key])
		return s

class Analyzer:
	pass

class GraphAnalyzer:
	def __init__(self, graph):
		self.graph = MyFasterGraph(graph)

	def getAnalysis(self):
		self._deleteNodesNoEdges()
		edgecount = self.graph.get_edge_count()
		nodecount = self.graph.get_node_count()
		if nodecount == 0:
			return 0
		return float(edgecount)/float(nodecount)
			

	def _deleteNodesNoEdges(self):
		for node in self.graph.get_nodes():
			delete = True
			if len(self.graph.edges[node]) == 0:
				for fromnode in self.graph.get_nodes():
					if node in self.graph.edges[fromnode].values():
						delete = False
			else:
				delete = False
						
			if delete:
				self.graph.del_node(node)
		

class FlxLogAnalyzer:
	def __init__(self):
		self.analyzed_functions = {}

	def read(self, directory):
		self.directory = directory
		logdirs = glob.glob(self.directory+"/*")
		for logdir in logdirs:
			function_name = os.path.basename(logdir)
			self.analyzed_functions[function_name] = FlxFunctionAnalysis(function_name)
			self.readJson(self.analyzed_functions[function_name], logdir)
			self.readDotfile(self.analyzed_functions[function_name], logdir)

	def readDotfile(self, analyzed_function, logdir):
		for dotfile in glob.glob(logdir+"/*.dot"):
			if os.path.getsize(dotfile) == 0:
				continue
			graph = pgv.AGraph(file=dotfile)
			analyzed_function.putGraph(graph)

	def readJson(self, analyzed_function, logdir):
		for jsonfile in glob.glob(logdir+"/*.json"):
			f = open(jsonfile,"r")
			analysis = json.load(f)
			f.close()
			analyzed_function.putAnalysis(analysis)

	def show(self, key, presenter = None):
		analyzed = map(lambda x: x.avg(), self.analyzed_functions.values())
		analyzed.sort(cmp=lambda x,y: cmp_analysis(x,y,key))
		print "------------------------------"
		for analysis in analyzed:
			print "%s: %s"%(analysis.getName(), analysis.show([key]))
		print "------------------------------"

	def sortby(self, d, k):
		l = lambda x: key_projection(x,k)
		return sorted(d,key=l)

def key_projection(dictionary, key):
	if not dictionary.has_key(key):
		dictionary[key] = None
	return dictionary

def cmp_analysis(x,y,key):
	if x[key]<y[key]:
		return -1
	elif x[key]==y[key]:
		return 0
	return 1

def analyze(directory):
	for logdir in glob.glob(directory+"/*"):
		analyze_logdir

def usage():
	print "%s directory key"%sys.argv[0]

if __name__ == "__main__":
	if len(sys.argv) < 3:
		usage()
	else:
		analyzer = FlxLogAnalyzer()
		analyzer.read(sys.argv[1])
		analyzer.show(sys.argv[2])
