#!/usr/bin/env python

from heuristic import PyQemuHeuristic

class ArithwindowHeuristic(PyQemuHeuristic):
	""" Logging class for the arithwindow c implementation """
	PREFIX = "Arithwindow"
	def setupCallbacks(self):
		self.process.onInstrumentationInit(lambda: self.process.hardware.instrumentation.arithwindow_enable(self.options["window_size"], self.options["threshold"]))
		self.attach("arithwindow",    self.onArithwindowEvent)

	def onArithwindowEvent(self, process, event):
		self.log("%s,0x%x"%(self.PREFIX, event.eip))

heuristic = ArithwindowHeuristic
