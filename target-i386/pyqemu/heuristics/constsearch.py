#!/usr/bin/env python

from heuristic import PyQemuHeuristic

constsearch_trigger_api_calls = [
	"ExitProcess",
	"ExitThread",
	"LoadLibrary",
	"CreateProcess",
	"CreateThread",
	"CreateRemoteThread",
]

class PatternManager:
	patternlist = []
	def __init__(self, heuristic):
		self.heuristic = heuristic
	def __call__(self):
		for pattern,index in map(lambda x,y: (x,y), self.patternlist, range(len(self.patternlist))):
			self.heuristic.process.hardware.instrumentation.constsearch_pattern(index, pattern)
		self.heuristic.process.hardware.instrumentation.constsearch_enable()

class ConstSearchHeuristic(PyQemuHeuristic):
	PREFIX = "Memory constant search"
	def setupCallbacks(self):
		self.patterns = PatternManager(self)
		self.process.onInstrumentationInit(self.patterns)
		self.process.onInstrumentationInit(lambda: self.registerApiHooks(self.process))
		self.attach("constsearch", self.onPatternFound)

	def onPatternFound(self, process, event):
		pattern = self.patterns.patternlist[event.index]
		self.log("Pattern(0x%x, '%s'"%(event.eip, pattern))

	def registerApiHooks(self, process):
		for function in constsearch_trigger_api_calls:
			process.installHookByName(self.onApiCallEvent, function)

	def onApiCallEvent(self, process, dll, function, addr):
		process.hardware.instrumentation.constsearch_search()

heuristic = ConstSearchHeuristic
