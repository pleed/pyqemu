#!/usr/include/python

import traceback
import sys
import os
import pefile
import glob

import PyFlxInstrument
import processinfo
from Structures import *

DEBUG = True

R_EAX = 0
R_ECX = 1
R_EDX = 2
R_EBX = 3
R_ESP = 4
R_EBP = 5
R_ESI = 6
R_EDI = 7

R_ES = 0
R_CS = 1
R_SS = 2
R_DS = 3
R_FS = 4
R_GS = 5


KNOWN_Processes = {}

# Helper functions
def get_current_process():
	regs = PyFlxInstrument.registers()
	cr3 = regs["cr3"]
	process = KNOWN_Processes[cr3]
	return process

def dump_memory(process, address, len, filename):
	delimeter = "\x90"*23
	file = open(filename,"a")
	buf = process.backend.read(address, len)+delimeter
	file.write(buf)
	file.close()

def debug(msg):
	global DEBUG
	if DEBUG:
		print msg

def event_update_cr3(old_cr3, new_cr3):
	global KNOWN_Processes	

	kpcr_addr = PyFlxInstrument.creg(R_FS)
	if KNOWN_Processes.has_key(new_cr3):
		process = KNOWN_Processes[new_cr3]		
		if not process.watched:
			PyFlxInstrument.set_instrumentation_active(0)
			return 1
		
		is_new = False

		if not process.valid:
			process.update()

		if process.valid:
			if not isinstance(process, TracedProcess):
				process.watched = False
				PyFlxInstrument.set_instrumentation_active(0)
				return 1

			if isinstance(process, TracedProcess):
				PyFlxInstrument.set_instrumentation_active(1)

		return 1
	elif kpcr_addr > 0xf0000000: #otherwise something breaks :(			   
		backend = VMemBackend( 0, 0x100000000)				
		filename = ""
		try:
			kpcr = KPCR( backend, kpcr_addr ) #problem: here
			filename = kpcr.PrcbData.CurrentThread.deref().ApcState.Process.deref().ImageFileName
		except:
			return -1
				
		filename = filename.replace("\x00", "")
		if (len(filename) > 0):
			if filename.lower() in map(lambda x: x.lower(), proc_event_callbacks.keys()):
				print "New TracedProcess %s"%filename
				p = TracedProcess(proc_event_callbacks)
			else:
				print "New UntracedProcess %s"%filename
				p = UntracedProcess()
			KNOWN_Processes[new_cr3] = p
			p.watched = True
	
	return 0

class TracedProcess(processinfo.Process):
	""" A traced process with functionality to register callbacks for vm call handling. """

	def __init__(self, callbacklist):
		self.callbacklist = callbacklist
		self.callbacklist_loaded = False
		self.callonfunction = {}
		processinfo.Process.__init__(self)

	def handle_syscall(self, eax):
		print "syscall :), eax is %i"%eax

	def handle_call(self, *args):
		""" Call Opcode handler. """
		if not self.callbacklist_loaded:
			self.loadCallbacks(self.callbacklist)
		self._handle_call_run(*args)

	def addrInExe(self, addr):
		""" Returns true if address is in main executable mapping. """
		image = self.get_image_by_address(addr)
		if image is not None:
			return image.get_basedllname() == self.get_imagefilename().strip("\x00")
		else:
			return False

	def _handle_call_run(self, fromaddr, toaddr):
		""" Resolve interesting call and trigger callbacks. """
		from_image = self.get_image_by_address(fromaddr)
		to_image   = self.get_image_by_address(toaddr)
		if from_image is None or to_image is None:
			self.update_images()
		if from_image is not None and to_image is not None and  \
		   self.addrInExe(fromaddr) and not self.addrInExe(toaddr):
			try:
				self.runCallbacks(to_image.get_basedllname(), self.symbols[toaddr][2])
			except:
				to_image.update()

	def runCallbacks(self, dllname, funcname):
		""" Run registered Callbacks for (dll, function) tuple. """
		dllname = dllname.lower()
		debug("Call on %s::%s()"%(dllname,funcname))
		if self.callonfunction.has_key(dllname+funcname):
			for callback in self.callonfunction[dllname+funcname]:
				callback()

	def registerFunctionHandler(self, dllname, function, callback):
		""" Registers a function that will be called when vm process calls dllname::funcname(). """
		dllname = dllname.lower()
		if self.callonfunction.has_key(dllname+function):
			self.callonfunction[dllname+function].append(callback)
		else:
			self.callonfunction[dllname+function] = [callback]
		return None

	def loadCallbacks(self, callbacklist):
		""" Callbacks are stored in a dictionary with dll+fname as key, containing lists. """
		debug("loadCallbacks %s"%self.get_imagefilename().strip("\x00").lower())
		if callbacklist.has_key(self.get_imagefilename().strip("\x00").lower()):
			for callback in callbacklist[self.get_imagefilename().strip("\x00").lower()]:
				self.registerFunctionHandler(*callback)
		self.callbacklist_loaded = True

class UntracedProcess(processinfo.Process):
	def handle_call(self, *args):
		pass
	def handle_syscall(self, *args):
		pass

def init(sval):	
	print "Python instrument started"
	return 1

# Exceptions are not properly handled in flx_instrument.c wrapper helps detecting them
def error_dummy(func, *args):
	try:
		ret =  func(*args)
		if ret is None:
			return 0
		return ret
	except:
		traceback.print_exception(*sys.exc_info())
		import code
		code.interact("DBG",local = locals())
		sys.exit(-1)

def ensure_error_handling_helper(func):
	return lambda *args: error_dummy(func,*args)

# Implement Process event Callbacks here

def notepad_msvcrt_exit():
	print "NOTEPAD CALLED EXIT!"

def notepad_user32_getmessagew():
	print "NOTEPAD CALLED GETMESSAGEW"

# Register Process event Callbacks
proc_event_callbacks = {
	"notepad.exe": [
					("msvcrt.dll","exit", notepad_msvcrt_exit),
					("USER32.dll","GetMessageW",notepad_user32_getmessagew)
				   ]
}

# Register FLX Callbacks 
ev_syscall    = ensure_error_handling_helper(lambda *args: get_current_process().handle_syscall(*args))
ev_call       = ensure_error_handling_helper(lambda *args: get_current_process().handle_call(*args))
ev_update_cr3 = ensure_error_handling_helper(event_update_cr3)


