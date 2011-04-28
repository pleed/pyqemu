#!/usr/bin/env python

from heuristic import PyQemuHeuristic

class FunctionTraceHeuristic(PyQemuHeuristic):
	PREFIX = "Functiontrace"
	def setupCallbacks(self):
		self.process.onInstrumentationInit(lambda: self.process.hardware.instrumentation.functiontrace_enable())
		self.attach("functiontrace",    self.onFunctionTraceEvent)

	def onFunctionTraceEvent(self, process, event):
		if event.isCall():
			self.log("Call(0x%x"%(event.eip))
		elif event.isRet():
			self.log("Ret(0x%x"%(event.eip))
		elif event.isLateRet():
			self.log("LateRet(0x%x"%(event.eip))
		else:
			raise Exception("Unknown Function trace event type")

heuristic = FunctionTraceHeuristic
