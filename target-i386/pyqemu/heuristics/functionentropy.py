#!/usr/bin/env python

from heuristic import PyQemuHeuristic

class FunctionEntropyHeuristic(PyQemuHeuristic):
	""" Logging class for the entropy heuristic """
	PREFIX = "Function Entropy Trace"

	def setupCallbacks(self):
		self.process.onInstrumentationInit(lambda: self.process.hardware.instrumentation.functionentropy_enable(self.options["threshold"]))
		self.attach("functionentropy",    self.onFunctionEntropyEvent)

	def onFunctionEntropyEvent(self, process, event):
		self.log("Function(0x%x, 0x%x, %f)"%(self.current_function, event.start, event.entropychange))

heuristic = FunctionEntropyHeuristic
