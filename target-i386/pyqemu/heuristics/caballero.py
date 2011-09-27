#!/usr/bin/env python

from heuristic import PyQemuHeuristic

class CaballeroHeuristic(PyQemuHeuristic):
	""" Logging class for the caballero heuristic """
	PREFIX = "Caballero"
	def setupCallbacks(self):
		self.process.onInstrumentationInit(lambda: self.process.hardware.instrumentation.caballero_enable(self.options["min_icount"], self.options["threshold"]))
		self.attach("caballero",    self.onCaballeroBBLTranslate)

	def onCaballeroBBLTranslate(self, process, event):
		self.log("%s %f,0x%x"%(self.PREFIX, float(event.arith)/float(event.icount), event.eip))

heuristic = CaballeroHeuristic
