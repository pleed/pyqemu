#!/usr/include/python

import traceback
import json
import sys
import glob
import struct
import pickle
import avl
import gc
import copy
import Queue
import random
import time

from dll import *

import PyFlxInstrument
import processinfo
import syscalls
from Structures import *
from event import *
from fhandle import *
from config import *
from msg import *
from memory import *

class Breakpoint:
	def __init__(self, addr, callback):
		PyFlxInstrument.breakpoint_insert(addr)
		self.addr = addr
		self.callback = callback

	def trigger(self):
		self.callback(self.addr)

class Thread:
	def __init__(self, process, heap = None, stack = None, data = None, unknown = None, callstack = None):
		if callstack is None:
			self.callstack = Stack()
		else:
			self.callstack = callstack
		self.memory  = MemoryManager(process, heap, stack, data, unknown)
		self.previous_call = None
		self.process = process

	def __del__(self):
		self.terminate()

	def terminate(self):
		while len(self.callstack) > 0:
			call_event = self.callstack.pop()
			self.process.log("Ret(0x%x)"%call_event[0])

class EventHandler:
	def __init__(self, process):
		self.observers = {}
		self.process   = process

	def __call__(self, event):
		for observer,function in self.observers.items():
			function(self.process, event)

	def attach(self, name, function):
		self.observers[name] = function

	def detach(self, name):
		del(self.observers[name])

class TracedProcess(processinfo.Process):
	""" A traced process with functionality to register callbacks for vm inspection """

	def __init__(self, options, os, logger, imagefilename, hardware):
		self.os = os
		self.hardware = hardware
		self.detected_dlls       = 0
		self.threadcount         = 0
		self.threads             = {}
		self.logger              = logger
		self.dllhandler          = PEHandler(options["dlldir"])
		# stores registerd callbacks
		self.callonfunction      = {}
		self.breakpoints         = {}
		self.options             = options
		self.initialized         = False
		self.instrumentation_initializers = []

		processinfo.Process.__init__(self)
		self.loadCallbacks([])
		self.setupEventHandlers()
		self.pe_image = PEFile("%s/%s"%(options["exedir"], imagefilename), 0)
		self.addBreakpoint(self.pe_image.calculateEntryPoint(), self.entryPointReached)

	def onInstrumentationInit(self, function):
		self.instrumentation_initializers.append(function)

	def entryPointReached(self, addr):
		""" Instrumentation starts here after entry point has been reached """
		self.logger.info("------------------------------------")
		self.logger.info("Instrumentation starting for %s at address 0x%x"%(self.imagefilename(),addr))
		self.logger.info("------------------------------------")
		self.update_images()
		for image in self.images.values():
			if image.BaseDllName.lower() in map(lambda x: x.lower(), self.options["instrument"]):
				self.hardware.instrumentation.filter_add(image.DllBase, image.DllBase+image.SizeOfImage)
				self.logger.info("Instrumenting %s"%image.FullDllName)
			else:
				self.logger.info("Not Instrumenting %s"%image.FullDllName)
		self.hardware.instrumentation.filter_enable()
		for initializer in self.instrumentation_initializers:
			initializer()

		#self.hardware.instrumentation.memtrace_enable()
		self.hardware.instrumentation.retranslate()

		self.callstack.push((addr, self.hardware.cpu.esp))
		#self.log("Call(0x%x)"%addr)
		self.logger.info("Instrumentation initialized!!!")

	def setupEventHandlers(self):
		self.eventHandlers = {
			"call":EventHandler(self),
			"jmp":EventHandler(self),
			"ret":EventHandler(self),
			"syscall":EventHandler(self),
			#"breakpoint":EventHandler(self),
			"breakpoint":self.handle_breakpoint,
			"memtrace":EventHandler(self),
			"bbl":EventHandler(self),
			"bblcaballero":EventHandler(self),
			"caballero":EventHandler(self),
			"arithwindow":EventHandler(self),
		}

	def handleEvent(self, event):
		self.eventHandlers[event.event_type](event)

	def addBreakpoint(self, addr, callback):
		self.hardware.instrumentation.retranslate()
		if not self.breakpoints.has_key(addr):
			self.breakpoints[addr] = Breakpoint(addr, callback)

	def delBreakpoint(self, addr):
		self.breakpoints[addr].delete()
		del(self.breakpoints[addr])

	def isRegisteredThread(self):
		try:
			t = self.thread
			return True
		except KeyError:
			return False

	def createNewThread(self):
		if self.threadcount == 0:
			self.threadcount += 1
			self.threads[self.cur_tid] = Thread(self)
		else:
			anythread = self.threads.values()[0]
			self.threads[self.cur_tid] = Thread(self, anythread.memory.heap, \
													  None, \
			                                          anythread.memory.data, \
													  anythread.memory.unknown,\
													  None)
		self.threads[self.cur_tid].callstack.push((self.hardware.cpu.eip, 0xffffffff))
		self.logger.info("Thread %d registered"%self.cur_tid)

	def getThread(self):
		try:
			return self.threads[self.cur_tid]
		except KeyError:
			self.createNewThread()
	thread = property(getThread)

	def getCallstack(self):
		return self.thread.callstack
	callstack = property(getCallstack)

	def getMemory(self):
		return self.thread.memory
	memory = property(getMemory)

	def getstackframe(self, address):
		""" Returns the corresponding function which owns the stack frame the address belongs to """
		esp = self.register("esp")
		stack_top = self.callstack.bottom().top()
		if esp <= address <= stack_top:
			frameid = len(self.callstack)-1
			while frameid >= 0 and self.callstack[frameid].top() < address:
				frameid -= 1
			if frameid >= 0:
				return self.callstack[frameid]
			else:
				raise Exception("Address not on stack!")
		else:
			raise Exception("Address not on stack!")

	def log(self, obj):
		""" Log event """
		self.logger.handleProcessEvent(obj, self)

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

	def addPendingReturn(self, function):
		""" Used by FunctionHandlers to hook corresponding return of a called function """
		self.callstack.top().addReturnCallback(function)

	def loadCallbacks(self,handlers):
		""" Load FunctionHandlers from dict """
		for dll,fname,handlerclass in handlers:
			self.registerFunctionHandler(dll, fname, handlerclass(self))

	def handle_breakpoint(self, bp):
		try:
			breakpoint = self.breakpoints[bp.addr]
		except KeyError:
			raise Exception("Unregistered breakpoint has been triggered!")
		breakpoint.trigger()

	def handle_call(self, event):
		self.log("Call(0x%x)"%event.toaddr)
		self.callstack.push((event.toaddr,event.esp))

	def handle_ret(self, event):
		raise Exception("should not be called!")
		""" Will be called on ret opcode - updates callstack and triggers handlers """
		# keep callstack up to date
		if self.hardware.instrumentation.filter_filtered(event.fromaddr):
			try:
				if self.callstack.top().isReturning(event.toaddr):
					f = self.callstack.pop()
					self.log(RetEvent(f))
					f.doReturn()
				else:
					esp = self.register("esp")
					f = self.callstack.top()
					lateRet = True
					while f.top() < esp:
						if lateRet:
							self.log(LateRetEvent(f))
							lateRet = False
						del(f)
						f = self.callstack.pop()
			except IndexError:
				pass
			self.memory.stack.update()

	def handle_syscall(self, syscall):
		# NtCreateThread
		syscall_name = syscalls.getSyscallByNumber(syscall.number)
		if syscall_name is not None:
			if syscall_name == "NtTerminateProcess":
				self.os.terminating_processes.append((self,PyFlxInstrument.registers()["cr3"]))
				self.log(syscall_name)
				self.thread.terminate()
				self.logger.shutdown(self)
			if syscall_name == "NtCreateThread":
				self.logger.info("Creating Thread")
				self.log(syscall_name)
			if syscall_name == "NtTerminateThread":
				self.logger.info("Thread %d terminated"%self.cur_tid)
				self.log(syscall_name)
				self.thread.terminate()
			if syscall_name == "NtCreateProcess" or syscall_name == "NtCreateProcessEx":
				self.logger.info("New Process has been created by %s"%self.name)
				self.log(syscall_name)

	def handle_memtrace(self, event):
		eip = PyFlxInstrument.registers()["eip"]
		if event.writes:
			self.log("Write: 0x%x , Addr: 0x%x, BBL: 0x%x"%(event.value,event.addr,eip))
		else:
			self.log("Read:  0x%x , Addr: 0x%x, BBL: 0x%x"%(event.value,event.addr,eip))

	def handle_bbl(self, event):
		self.log("BBL(0x%x,%d)"%(event.eip,event.instructions))

	def handle_caballero_bbl(self, event):
		while event.esp > self.callstack[-1][1]:
			call_event = self.callstack.pop()
			self.log("Ret(0x%x)"%call_event[0])

		self.log("CaballeroCall(0x%x)"%(event.eip))

	def handle_call(self, event):
		if self.hardware.instrumentation.filter_filtered(event.toaddr):
			self.log("Call(0x%x)"%event.toaddr)
			self.callstack.push((event.toaddr,event.esp))

	def handle_caballero(self, event):
		self.log("CaballeroBlock(0x%x,%d,%d)"%(event.eip, event.icount, event.arith))

	def handle_jmp(self, event):
		pass

	def addrInExe(self, addr):
		""" check if address is located in main executable image """
		image = self.get_image_by_address(addr)
		if image is not None:
			return image.get_basedllname().lower() == self.imagefilename()
		else:
			return False

	def callFromExe(self):
		try:
			dll,name = self.callstack.top().resolveToName()
			return dll == self.imagefilename()
		except IndexError:
			return True

	def getSymbol(self, addr):
		if self.symbols.has_key(addr):
			return self.symbols[addr][2]
		else:
			if self.detected_dlls < len(self.images):
				for image in self.images:
					base = image
					image = self.get_image_by_address(image)
					self.dllhandler.loadPE(image.get_basedllname(), base)
				self.detected_dlls = len(self.images)
			lib = self.dllhandler.getLib(addr)
			if lib is not None and lib.has_key(addr):
				return str(lib[addr][2])
		return str(hex(addr))

	def hasSymbol(self, addr):
		if self.symbols.has_key(addr):
			return True
		else:
			lib = self.dllhandler.getLib(addr)
			if lib is not None and lib.has_key(addr):
				return True
		return False

	def log_call(self, function, prefix = ""):
		try:
			self.log(CallEvent(function, self.callstack[-1]))
		except IndexError:
			self.log(CallEvent(function))

	def runCallbacks(self, function, event_type):
		""" Run registered Callbacks for (dll, function) tuple. """
		dll,name = function.resolveToName()	
		if dll is None or name is None:
			print "dll: "+str(type(dll))
			print "name: "+str(type(name))
		if self.callonfunction.has_key(dll+name):
			for callback in self.callonfunction[dll+name]:
				if event_type == "enter":
					callback.onEnter(function)
				elif event_type == "leave":
					callback.onLeave(function)
				else:
					raise Exception("unknown event type!")

	def imagefilename(self):
		return self.get_imagefilename().strip("\x00").lower()
	name = property(imagefilename)

	def registerFunctionHandler(self, dllname, function, callback):
		""" Registers a function that will be called when vm process calls dllname::funcname(). """
		dllname = dllname.lower()
		if self.callonfunction.has_key(dllname+function):
			self.callonfunction[dllname+function].append(callback)
		else:
			self.callonfunction[dllname+function] = [callback]
		return None

	def __del__(self):
		self.terminate()

	def terminate(self):
		self.log.info("Terminating process: %s"%self.imagefilename())
		try:
			for tid,thread in self.threads.items():
				del(thread)
			self.logger.close()
			del(self.logger)
			del(self.dllhandler)
			del(self.callonfunction)
		except:
			pass

class UntracedProcess(processinfo.Process):
	def __init__(self, callhandler):
		processinfo.Process.__init__(self)

	def handle_call(self, *args):
		print "UNTRACED PROCESS CALL! %s"%str(args)
	def handle_syscall(self, *args):
		print "UNTRACED PROCESS SYSCALL! %s"%str(args)
	def handle_ret(self, *args):
		print "UNTRACED PROCESS RET! %s"%str(args)
	def handle_jmp(self, *args):
		print "UNTRACED PROCESS JMP! %s"%str(args)
	def handle_memtrace(self, *args):
		print "UNTRACED PROCESS MEMTRACE! %s"%str(args)
	def handle_bblstart(self, *args):
		print "UNTRACED PROCESS BBLSTART! %s"%str(args)
	def handleEvent(self, *args):
		print "UNTRACED PROCESS HANDLE EVENT! %s"%str(args)
