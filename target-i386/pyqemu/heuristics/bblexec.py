#!/usr/bin/env python

from heuristic import PyQemuHeuristic

class BBLExecHeuristic(PyQemuHeuristic):
	""" Basic Block execution Logging """
	PREFIX = "BBLExec"
	def setupCallbacks(self):
		self.process.onInstrumentationInit(lambda: self.process.hardware.instrumentation.bbltrace_enable())
		self.attach("bbl",    self.onBBLExec)

	def onBBLExec(self, process, event):
		self.log("%s(0x%x,0x%x)"%(self.PREFIX, event.eip, event.esp))

heuristic = BBLExecHeuristic
