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
	patternlist = [
		"A"*64,
	]
	def __init__(self, heuristic):
		self.heuristic = heuristic
	def __call__(self):
		self.heuristic.process.hardware.instrumentation.constsearch_enable()
		for pattern,index in map(lambda x,y: (x,y), self.patternlist, range(len(self.patternlist))):
			self.heuristic.process.hardware.instrumentation.constsearch_pattern(pattern)

class ConstSearchHeuristic(PyQemuHeuristic):
	PREFIX = "Memory constant search"
	def setupCallbacks(self):
		self.patterns = PatternManager(self)
		self.process.onInstrumentationInit(self.patterns)
		self.process.onInstrumentationInit(lambda: self.registerApiHooks(self.process))
		self.attach("constsearch", self.onPatternFound)

	def onPatternFound(self, process, event):
		self.log("Pattern(0x%x, '%s'"%(event.eip, event.pattern))

	def registerApiHooks(self, process):
		for function in constsearch_trigger_api_calls:
			process.installHookByName(self.onApiCallEvent, function)

	def onApiCallEvent(self, process, dll, function, addr):
		process.hardware.instrumentation.constsearch_search()

heuristic = ConstSearchHeuristic
