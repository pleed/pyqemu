#!/usr/bin/env python

from heuristic import PyQemuHeuristic

class CaballeroHeuristic(PyQemuHeuristic):
	PREFIX = "Caballero"
	def setupCallbacks(self):
		self.attach("wang",    self.onBBLTranslate)

	def onBBLTranslate(self, event):
		if event.icount >= self.options["min_icount"]:
			percentage = float(event.arith)/float(event.icount)
			if percentage >= self.options["threshold"]:
				self.log("%s(0x%x,%f,%d)"%(self.PREFIX, event.eip, percentage, event.icount))

heuristic = CaballeroHeuristic
