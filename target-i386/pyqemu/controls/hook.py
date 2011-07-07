#!/usr/bin/env python

from control import ProcessControl

api_calls = [
	"CreateThread",
	"CreateRemoteThread",
	"GetModuleHandle",
	"GetProcAddress",
]

class ApiControl(ProcessControl):
	PREFIX = "Api"

	def setupCallbacks(self):
		self.process.onInstrumentationInit(lambda: self.registerApiHooks(self.process))
		self.process.onInstrumentationInit(lambda: self.process.hardware.instrumentation.bblwindow_enable(100))

	def registerApiHooks(self, process):
		for function in api_calls:
			process.installHookByName(self.onApiCallEvent, function)

	def onApiCallEvent(self, process, dll, function, addr):
		last_bbl = process.hardware.instrumentation.bblwindow_get(0)
		self.log("%s %s %s,0x%x"%(self.PREFIX, dll, function, last_bbl))

control = ApiControl
