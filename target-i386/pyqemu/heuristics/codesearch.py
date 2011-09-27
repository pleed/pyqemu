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
	""" Instruction class pattern management """
	patternlist = {
		#(SHX,SHX,XOR,SHX,XOR,XOR):"testpattern",
		(SHX,AND,SHX,XOR,XOR,AND,SHX,XOR):"cygcrypto aes",
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
			s = "".join(map(lambda x: struct.pack("<I",x), pattern))
			self.heuristic.process.hardware.instrumentation.codesearch_pattern(s)

class CodeSearchHeuristic(PyQemuHeuristic):
	""" Code search heuristic logging """
	PREFIX = "CodePattern"
	def setupCallbacks(self):
		self.patterns = PatternManager(self)
		self.process.onInstrumentationInit(self.patterns)
		self.attach("codesearch", self.onPatternFound)

	def onPatternFound(self, process, event):
		pattern = tuple(struct.unpack("<"+"I"*(len(event.pattern)/4), event.pattern))
		self.log("%s %s,0x%x"%(self.PREFIX, self.patterns.patternlist[pattern], event.eip))

heuristic = CodeSearchHeuristic
