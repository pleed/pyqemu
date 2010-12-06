#!/usr/bin/env python

import pickle
import sys
import event
from event import *
import pygraphviz as pgv
import copy

G = pgv.AGraph()
def default_object_handler(obj):
	global G

class PyQemuDumpAnalyzer:
	def __init__(self, filename):
		self.dumpfile = open(filename,"rb")

	def run(self):
		while 1:
			try:
				obj = pickle.load(self.dumpfile)
				self.process_event(obj)
			except EOFError:
				break
		self.finish()

	def finish(self):
		raise Exception("implement in inherited class")

	def process_event(self, obj):
		raise Exception("implement in inherited class")

class CallGraphBuilder(PyQemuDumpAnalyzer):
	def __init__(self, filename, graphfile):
		PyQemuDumpAnalyzer.__init__(self, filename)
		self.G = pgv.AGraph()
		self.graphfile = graphfile
		self.callstack = []
		self.id = 0

	def finish(self):
		self.G.draw(self.graphfile ,prog='circo')

	def process_event(self, obj):
		self.id += 1
		if isinstance(obj, CallEvent):
			node = (obj.dll+"::"+obj.name)
			self.callstack.append(node)
			self.G.add_node(node+"() - "+str(self.id))
			try:
				self.G.add_edge(self.callstack[-2], self.callstack[-1])
			except:
				pass
		elif isinstance(obj, RetEvent):
			try:
				retobj = obj.dll+"::"+obj.name
				i = 0
				for element in self.callstack:
					if element == retobj:
						break
					i+=1
				j = i
				while i < len(self.callstack):
					self.G.add_edge(self.callstack[i], self.callstack[i-1])
					i+=1
				del(self.callstack[j:])
			except:
				pass

if __name__ == "__main__":
	analyzer = CallGraphBuilder(sys.argv[1], sys.argv[2])
	analyzer.run()
