#!/usr/bin/env python

from control import ProcessControl
from pyqemu.Structures import *
import struct

api_calls = [
	"CreateThread",
	"CreateRemoteThread",
	"GetModuleHandle",
	"GetProcAddress",
	"LoadLibrary",
	"LoadLibraryEx",
	"LoadLibraryW",
	"LoadLibraryA",
]

class LibraryUpdateHook:
	def __init__(self, return_to_address, libname, process):
		self.return_to = return_to_address
		self.libname = libname
		self.process = process

	def __call__(self, addr):
		if self.process.updateLibrary(self.libname) == False:
			print "LOADING LIBRARY FAILED!"
		self.process.delBreakpoint(self.return_to, self)

def LoadLibraryHandler(process):
	esp = process.hardware.cpu.esp
	mem = process.readmem(esp+1*4, 4)
	return_to = struct.unpack("I",process.readmem(esp, 4))[0]
	filename_ptr = struct.unpack("I", mem)[0]
	try:
		library_name = STR(process.backend, filename_ptr)
		print "LoadLibrary(%s)"%library_name
		process.installHookByAddr(return_to, LibraryUpdateHook(return_to, str(library_name), process))
	except PageFaultException:
		pass

def LoadLibraryHandlerW(process):
	esp = process.hardware.cpu.esp
	mem = process.readmem(esp+1*4, 4)
	return_to = struct.unpack("I",process.readmem(esp, 4))[0]
	filename_ptr = struct.unpack("I", mem)[0]
	try:
		library_name = WSTR(process.backend, filename_ptr)
		print "LoadLibrary(%s)"%library_name
		process.installHookByAddr(return_to, LibraryUpdateHook(return_to, str(library_name), process))
	except PageFaultException:
		pass


api_handlers = {
	"LoadLibrary":LoadLibraryHandler,
	"LoadLibraryEx":LoadLibraryHandler,
	"LoadLibraryExA":LoadLibraryHandler,
	"LoadLibraryExW":LoadLibraryHandlerW,
	"LoadLibraryW":LoadLibraryHandlerW,
	"LoadLibraryA":LoadLibraryHandler,
}

class ApiControl(ProcessControl):
	""" Example for hooking API calls """
	PREFIX = "Api"

	def setupCallbacks(self):
		self.process.onInstrumentationInit(lambda: self.registerApiHooks(self.process))
		self.process.onInstrumentationInit(lambda: self.process.hardware.instrumentation.bblwindow_enable(100))

	def registerApiHooks(self, process):
		for function in api_calls:
			process.installHookByName(self.onApiCallEvent, function)

	def onApiCallEvent(self, process, dll, function, addr):
		last_bbl = process.hardware.instrumentation.bblwindow_get(0)
		if api_handlers.has_key(function):
			api_handlers[function](process)
		self.log("%s %s %s,0x%x"%(self.PREFIX, dll, function, last_bbl))

control = ApiControl
