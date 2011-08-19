#!/usr/bin/env python

from heuristic import PyQemuHeuristic
import struct

constsearch_trigger_api_calls = [
	"ExitProcess",
	"ExitThread",
]

class MutablePattern(str):
	pass

def uint32_array(x, little_endian = True):
	return pattern_padder(x, 4, little_endian)

def uint16_array(x, little_endian = True):
	return pattern_padder(x, 2, little_endian)

def pattern_padder(x, itemsize = 4, little_endian = True):
	if little_endian:
		padder = lambda item: item+"\x00"*(itemsize-1)
	else:
		padder = lambda item: "\x00"*(itemsize-1)+item
	return "".join(map(padder, x))

class PatternManager:
	patternlist = {
		# Patterns optained from kerckhoffr

	}

	def __init__(self, heuristic):
		self.heuristic = heuristic
		for key,value in self.patternlist.items():
			if isinstance(key, MutablePattern):
				for mutation in self.mutate(key):
					self.patternlist[mutation] = value

	def mutate(self, pattern):
		mutators = [uint32_array, uint16_array]
		mutations = []
		for mutator in mutators:
			mutations.append(mutator(pattern))
		return mutations

	def __call__(self):
		self.heuristic.process.hardware.instrumentation.constsearch_enable()
		for pattern,index in map(lambda x,y: (x,y), self.patternlist.keys(), range(len(self.patternlist))):
			self.heuristic.process.hardware.instrumentation.constsearch_pattern(pattern)

class CodeSearchHeuristic(PyQemuHeuristic):
	PREFIX = "CodePattern"
	def setupCallbacks(self):
		self.patterns = PatternManager(self)
		self.process.onInstrumentationInit(self.patterns)
		self.process.onInstrumentationInit(lambda: self.registerApiHooks(self.process))
		self.attach("codesearch", self.onPatternFound)

	def onPatternFound(self, process, event):
		self.log("%s %s,0x%x"%(self.PREFIX, self.patterns.patternlist[event.pattern], event.eip))

heuristic = ConstSearchHeuristic
