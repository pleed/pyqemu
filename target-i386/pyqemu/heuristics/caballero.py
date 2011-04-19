#!/usr/bin/env python

from heuristic import PyQemuHeuristic

class CaballeroHeuristic(PyQemuHeuristic):
	PREFIX = "Caballero"
	def setupCallbacks(self):
		self.process.onInstrumentationInit(lambda: self.process.hardware.instrumentation.caballero_enable(self.options["min_icount"], self.options["threshold"]))
		self.attach("caballero",    self.onCaballeroBBLTranslate)

	def onCaballeroBBLTranslate(self, process, event):
		self.log("%s(0x%x,%f,%d)"%(self.PREFIX, event.eip, float(event.arith)/float(event.icount), event.icount))

heuristic = CaballeroHeuristic
