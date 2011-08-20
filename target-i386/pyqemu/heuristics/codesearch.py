#!/usr/bin/env python

from heuristic import PyQemuHeuristic
import struct

MOV = 0
XOR = 1
SHX = 2
AND = 3
OR  = 4
ROX = 5
MUL = 6
DIV = 7
BIT = 8
ADD = 9
OTHER = 10

class PatternManager:
	patternlist = {
		(XOR,SHX,SHX,XOR):"testpattern"
	}

	def __init__(self, heuristic):
		self.heuristic = heuristic
		for key,value in self.patternlist.items():
			pattern = ""
			for insn in key:
				pattern += struct.pack("<I",insn)
			self.patternlist[key] = value

	def __call__(self):
		self.heuristic.process.hardware.instrumentation.codesearch_enable()
		for pattern in self.patternlist:
			self.heuristic.process.hardware.instrumentation.codesearch_pattern(pattern)

class CodeSearchHeuristic(PyQemuHeuristic):
	PREFIX = "CodePattern"
	def setupCallbacks(self):
		self.patterns = PatternManager(self)
		self.process.onInstrumentationInit(self.patterns)
		self.process.onInstrumentationInit(lambda: self.registerApiHooks(self.process))
		self.attach("codesearch", self.onPatternFound)

	def onPatternFound(self, process, event):
		self.log("%s %s,0x%x"%(self.PREFIX, self.patterns.patternlist[event.pattern], event.eip))

heuristic = CodeSearchHeuristic
