#!/usr/bin/env python

from heuristic import PyQemuHeuristic

class FunctionTaintHeuristic(PyQemuHeuristic):
	""" Logging class for the taint heuristic """
	PREFIX = "Function Taint Trace"

	def setupCallbacks(self):
		self.process.onInstrumentationInit(lambda: self.process.hardware.instrumentation.functiontaint_enable(self.options["threshold"]))
		self.attach("functiontaint",    self.onFunctionTaintEvent)

	def onFunctionTaintEvent(self, process, event):
		self.log("Taint(0x%x, 0x%x, %f)"%(self.current_function, event.start, event.quotient))

heuristic = FunctionTaintHeuristic
