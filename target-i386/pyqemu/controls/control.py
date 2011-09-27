#!/usr/bin/env python

class ProcessControl:
	""" Process Controlling API for customization """
	def __init__(self, process, options):
		self.process = process
		self.options = options
		self.setupCallbacks()

	def setupCallbacks(self):
		""" Called on instrumentation init for each process """
		raise Exception("Implement in inherited class")

	def attach(self, event_type, function):
		""" Hook into event handling """
		self.process.eventHandlers[event_type].attach(self.PREFIX, function)

	def detach(self, event_type):
		""" Remove hook from event handling """
		self.process.eventHandlers[event_type].detach(self.PREFIX)

	def log(self, msg):
		self.process.log(msg)

	def getCurrentFunction(self):
		return self.process.hardware.instrumentation.function_lookup()
	current_function = property(getCurrentFunction)

control = None
