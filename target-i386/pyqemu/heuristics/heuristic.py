#!/usr/bin/env python

class PyQemuHeuristic:
	def __init__(self, process, options):
		self.process = process
		self.options = options
		self.setupCallbacks()

	def setupCallbacks(self):
		raise Exception("Implement in inherited class")

	def attach(self, event_type, function):
		self.process.eventHandlers[event_type].attach(self.PREFIX, function)

	def detach(self, event_type):
		self.process.eventHandlers[event_type].detach(self.PREFIX)
