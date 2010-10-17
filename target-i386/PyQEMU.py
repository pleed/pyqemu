#!/usr/include/python

import traceback
import sys
import os
import glob
import struct

import PyFlxInstrument
import processinfo
from Structures import *
from windecl import *

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
	delimeter = "\x90"*42
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
	global R_FS

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

class CalledFunction:
	def __init__(self, dll, name, process):
		self.dll  = dll
		self.name = name
		self.regsnapshot = PyFlxInstrument.registers()
		self.process = process

	def top(self):
		""" Stack frame starts at stored EIP! In this definition, arguments belong to predecessor """
		return self.regsnapshot["esp"]

	def __str__(self):
		return str(self.dll)+"::"+str(self.name)+"()"

	def __eq__(self, other):
		return self.dll == other.dll and self.name == other.name and self.top == other.top

	def __ne__(self, other):
		return not self.__eq__(other)

	def isActive(self):
		return self == self.process.activeFunction()

	def _checkActive(self):
		if not self.isActive():
			raise Exception("Function: %s , member would return invalid values since function is inactive!"%self)

	def getIntArg(self, num):
		self._checkActive()
		return struct.unpack("I", self.getFunctionArg(num))

	def getBufFromPtr(self, num, size):
		self._checkActive()
		address = self.getIntArg(num)
		return struct.unpack(str(num)+"c", self.process.readmem(address, size))

	def getFunctionArg(self, num):
		self._checkActive()
		global R_ESP
		esp = self.genreg(R_ESP)
		return self.process.readmem(esp+num*4, 4)

class TracedProcess(processinfo.Process):
	""" A traced process with functionality to register callbacks for vm call handling. """

	def __init__(self, callbacklist):
		self.callbacklist        = callbacklist
		self.callbacklist_loaded = False
		self.callonfunction      = {}
		self.callhistory         = []
		self.callstack           = []
		self.heapallocated       = {}
		processinfo.Process.__init__(self)

#		self._loadInternalCallbacks()

	def readmem(self, address, length):
		return self.backend.read(address, length)

	def creg(self, register):
		return PyFlxInstrument.creg(register)

	def eip(self):
		return PyFlxInstrument.eip()

	def genreg(self, index):
		return PyFlxInstrument.genreg(index)

	def activeFunction(self):
		if not len(self.callstack) == 0:
			return self.callstack[-1]
		else:
			raise Exception("Not active Function")

	def _handle_function_send(self, me, function):
		pass

	def _loadInternalCallbacks(self):
		internal_callbacks = [
								("ws2_32.dll","send", self._handle_function_send),
								("kernel32.dll","HeapAlloc",_self.handle_function_send),
							 ]

	def handle_syscall(self, eax):
		print "syscall :), eax is %i"%eax

	def handle_call(self, *args):
		""" Call Opcode handler. """
		if not self.callbacklist_loaded:
			self.loadCallbacks(self.callbacklist)
		self._handle_call_filter(*args)

	def addrInExe(self, addr):
		""" Returns true if address is in main executable mapping. """
		image = self.get_image_by_address(addr)
		if image is not None:
			return image.get_basedllname().lower() == self.imagefilename()
		else:
			return False

	def _handle_call_filter(self, fromaddr, toaddr, nextaddr):
		""" Resolve interesting call and trigger callbacks. """
		from_image = self.get_image_by_address(fromaddr)
		to_image   = self.get_image_by_address(toaddr)
		if from_image is None or to_image is None:
			self.update_images()
		if from_image is not None and to_image is not None and self.addrInExe(fromaddr):
			if not self.symbols.has_key(toaddr):
				to_image.update()
			try:
				print "Call %x -> %x, nextaddr is %x" % (fromaddr, toaddr, nextaddr)
				# We got a valid call
				self._handle_interesting_call(to_image.get_basedllname(), self.symbols[toaddr][2], resolved = True)
			except KeyError:
				self._handle_interesting_call(to_image.get_basedllname(), hex(toaddr))

	def _handle_interesting_call(self, dllname, function, resolved = False):
		dllname = dllname.lower()
		f = CalledFunction(dllname, function, self)
		self.callhistory.append(f)
		if not resolved:
			self._handle_unresolved_call(f)
		else:
			self.runCallbacks(f)
		regs = PyFlxInstrument.registers()
		eip = regs["eip"]
		dump_memory(self, eip, 10, "/tmp/dumptest")
		try:
			debug("call to -> %s"%self.callhistory[-1])
		except:
			pass

	def _handle_unresolved_call(self, function):
		pass

	def runCallbacks(self, function):
		""" Run registered Callbacks for (dll, function) tuple. """
		if self.callonfunction.has_key(function.dll+function.name):
			for callback in self.callonfunction[function.dll+function.name]:
				callback(self, self.callhistory[-1])

	def imagefilename(self):
		return self.get_imagefilename().strip("\x00").lower()

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
		debug("loadCallbacks %s"%self.imagefilename())
		if callbacklist.has_key(self.imagefilename()):
			for callback in callbacklist[self.imagefilename()]:
				self.registerFunctionHandler(*callback)
		self.callbacklist_loaded = True

class UntracedProcess(processinfo.Process):
	def handle_call(self, *args):
		pass
	def handle_syscall(self, *args):
		pass
	def handle_ret(self, *args):
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
def print_params(process, function):
	print str(function)
	return

# Register Process event Callbacks
proc_event_callbacks = {
	"notepad.exe": [
					("msvcrt.dll","exit", print_params),
					("USER32.dll","GetMessageW", print_params),
					("kernel32.dll","lstrcpynW",print_params),
					#("user32.dll","LoadStringW",notepad_user32_LoadStringW),
					#("user32.dll","CharNextW",notepad_user32_CharNextW),
				   ]
}

# Register FLX Callbacks 
ev_syscall    = ensure_error_handling_helper(lambda *args: get_current_process().handle_syscall(*args))
ev_call       = ensure_error_handling_helper(lambda *args: get_current_process().handle_call(*args))
ev_update_cr3 = ensure_error_handling_helper(event_update_cr3)
