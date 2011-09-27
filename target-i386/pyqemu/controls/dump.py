#!/usr/bin/env python

from control import ProcessControl

class DumpControl(ProcessControl):
	""" Sets dump configuration option in process instance """
	def setupCallbacks(self):
		self.process.onInstrumentationInit(lambda: self.process.hardware.instrumentation.dump_enable(self.options["dump"]))

control = DumpControl
