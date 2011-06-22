#!/usr/bin/env python

from heuristic import PyQemuHeuristic

class ArithwindowHeuristic(PyQemuHeuristic):
	PREFIX = "Arithwindow"
	def setupCallbacks(self):
		self.process.onInstrumentationInit(lambda: self.process.hardware.instrumentation.arithwindow_enable(self.options["window_size"], self.options["threshold"]))
		self.attach("arithwindow",    self.onCaballeroBBLTranslate)

	def onCaballeroBBLTranslate(self, process, event):
		self.log("%s(0x%x, 0x%x)"%(self.PREFIX, self.current_function, event.eip))

heuristic = ArithwindowHeuristic
