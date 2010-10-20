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
			if filename.lower() in trace_processes:
				print "New TracedProcess %s"%filename
				p = TracedProcess()
			else:
				print "New UntracedProcess %s"%filename
				p = UntracedProcess()
			KNOWN_Processes[new_cr3] = p
			p.watched = True
	
	return 0

class Stack(list):
	def __init__(self, *args):
		list.__init__(self, *args)
		self.push = self.append

	def top(self):
		return self[-1]

class CalledFunction:
	def __init__(self, fromaddr, toaddr, nextaddr, process):
		self.fromaddr = fromaddr
		self.toaddr   = toaddr
		self.nextaddr = nextaddr
		self.process = process

		self.entrystate = PyFlxInstrument.registers()
		self.exitstate = None

	def isReturning(self, nextaddr):
		self.exitstate = PyFlxInstrument.registers()
		return (nextaddr == self.nextaddr and self.exitstate["esp"] == self.entrystate["esp"]) or (self.exitstate["esp"] > self.entrystate["esp"])

	def retval(self):
		self.exitstate = PyFlxInstrument.registers()
		return self.exitstate["eax"]

	def resolveToName(self):
		dll, addr = self.resolve()
		if dll is None:
			return "Unknown","Unknown"
		try:
			return dll.get_basedllname(), self.process.symbols[addr][2]
		except KeyError:
			return dll.get_basedllname(), hex(addr)

	def resolve(self):
		image = self.process.get_image_by_address(self.toaddr)
		return image, self.toaddr

	def top(self):
		""" Stack frame starts at stored EIP! In this definition, arguments belong to predecessor """
		return self.entrystate["esp"]

	def __str__(self):
		return "%s::%s()"%(self.resolveToName())

	def __eq__(self, other):
		return self.toaddr== other.toaddr and self.top() == other.top()

	def __ne__(self, other):
		return not self.__eq__(other)

	def isActive(self):
		return self == self.process.activeFunction()

	def _checkActive(self):
		if not self.isActive():
			raise Exception("Function: %s , member would return invalid values since function is inactive!"%self)

	def getIntArg(self, num):
		self._checkActive()
		return struct.unpack("I", self.getFunctionArg(num))[0]

	def getBufFromPtr(self, num, size):
		self._checkActive()
		address = self.getIntArg(num)
		return struct.unpack(str(num)+"c", self.process.readmem(address, size))

	def getFunctionArg(self, num):
		self._checkActive()
		global R_ESP
		esp = self.process.genreg(R_ESP)
		return self.process.readmem(esp+num*4, 4)

class TracedProcess(processinfo.Process):
	""" A traced process with functionality to register callbacks for vm call handling. """

	def __init__(self):
		self.callonfunction      = {}
		self.callhistory         = []
		self.callstack           = Stack()
		self.heapallocated       = {}
		processinfo.Process.__init__(self)

		self._loadInternalCallbacks()

	def register(self, register):
		regs = PyFlxInstrument.registers()
		return regs[register]

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

	def handle_function_heap_allocated(self, function, event):
		print "heap allocate!"
		if event == "leave":
			addr = function.retval()
			size = function.getIntArg(1)
			self.heapallocated[addr] = size
			print "allocated %d bytes on addr: 0x%x"%(size,addr)

	def handle_function_heap_freed(self, function, event):
		print "heap free!"
		if event == "enter":
			addr = function.getIntArg(1)
			if self.heapallocated.has_key(addr):
				del(self.heapallocated[addr])
			print "freed mem on addr: 0x%x"%addr

	def handle_function_recv(self, function, event):
		print "recv!"
		if event == "enter":
			addr = function.getIntArg(2)
			if self.heapallocated.has_key(addr):
				print "Previously allocated buffer has been filled"
			else:
				print "receiving to unknown buffer 0x%x"%addr

	def handle_function_send(self, function, event):
		print "send!"
		if event == "enter":
			addr = function.getIntArg(2)
			if self.heapallocated.has_key(addr):
				print "Previously allocated buffer has been sent"
			else:
				print "sending unknown buffer 0x%x"%addr

	def _loadInternalCallbacks(self):
		internal_callbacks = [
								("msvcrt.dll",  "malloc",  self.handle_function_heap_allocated),
								("msvcrt.dll",  "free",    self.handle_function_heap_freed),
								("wsock32.dll", "recv",    self.handle_function_recv),
								("ws2_32.dll",  "WSARecv", self.handle_function_recv),
								("wsock32.dll", "send",    self.handle_function_send),
								("ws2_32.dll",  "send",    self.handle_function_send),
						 	 ]
		self.loadCallbacks(internal_callbacks)

	def handle_ret(self, toaddr):
		try:
			function = self.callstack.top()
		except IndexError:
			return
		#if function.isReturning(toaddr):
		if self.addrInExe(toaddr):
			print "Returning from %s"%function
			self.runCallbacks(function,"leave")
			self.callstack.pop()

	def handle_syscall(self, eax):
		print "syscall :), eax is %i"%eax

	def handle_call(self, *args):
		""" Call Opcode handler. """
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
		if fromaddr == 0 and nextaddr == 0:
			return self._handle_interesting_call(fromaddr, toaddr, nextaddr)
		from_image = self.get_image_by_address(fromaddr)
		to_image   = self.get_image_by_address(toaddr)
		if from_image is None or to_image is None:
			self.update_images()
		if from_image is not None and to_image is not None and self.addrInExe(fromaddr):
			if not self.symbols.has_key(toaddr):
				to_image.update()
			self._handle_interesting_call(fromaddr, toaddr, nextaddr)

	def _handle_interesting_call(self, fromaddr, toaddr, nextaddr):
		if fromaddr == 0 and nextaddr == 0:
			if self.symbols.has_key(toaddr):
				try:
					last = self.callstack.pop()
				except IndexError:
					return
				fromaddr = last.fromaddr
				nextaddr = last.nextaddr
		function = CalledFunction(fromaddr, toaddr, nextaddr, self)
		self.callstack.push(function)
		print "Called %s"%function
		self.runCallbacks(function,"enter")

	def runCallbacks(self, function, *args):
		""" Run registered Callbacks for (dll, function) tuple. """
		dll,name = function.resolveToName()
		if self.callonfunction.has_key(dll+name):
			for callback in self.callonfunction[dll+name]:
				callback(self.callstack.top(), *args)

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
		for callback in callbacklist:
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

# Register Processes to trace
trace_processes = [
	"telnet.exe",
	"notepad.exe",
	"wget.exe"
]

# Register FLX Callbacks 
ev_syscall    = ensure_error_handling_helper(lambda *args: get_current_process().handle_syscall(*args))
ev_call       = ensure_error_handling_helper(lambda *args: get_current_process().handle_call(*args))
ev_ret       = ensure_error_handling_helper(lambda *args: get_current_process().handle_ret(*args))
ev_update_cr3 = ensure_error_handling_helper(event_update_cr3)
