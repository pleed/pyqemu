#!/usr/bin/env python

class ArithBasicBlock:
	def __init__(self, icount, eip):
		self.arithcount = 0
		self.icount = icount
		self.eip = eip

	def addArithOpcode(self):
		self.arithcount += 1

class ArithHeuristic(Heuristic):
	def __init__(self, logger, thread):
		self.logger = logger
		self.thread = thread

		self.hooks = {
			"optrace":self.onArithOpcode
			"bbl":self.onNewBasicBlock
		}

		self.bbls = []
		self.current_bbl = None

	def onArithOpcode(self, event):
		if self.current_bbl is not None:
			self.current_bbl.addArithOpcode()

	def onNewBasicBlock(self, event):
		if self.current_bbl is not None:
			self.bbls.append(self.current_bbl)
		self.current_bbl = ArithBasicBlock(event.icount, event.eip)
