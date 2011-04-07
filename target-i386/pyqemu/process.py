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

		processinfo.Process.__init__(self)
		self.loadCallbacks([])

		self.pe_image = PEFile("%s/%s"%(options["exedir"], imagefilename), 0)
		self.addBreakpoint(self.pe_image.calculateEntryPoint(), self.entryPointReached)
		self.optrace = False

	def entryPointReached(self, addr):
		image = self.get_image_by_address(addr)
		if image is None:
			print "MAIN IMAGE IS NONE!!!"
			return
		self.imagestart = image.DllBase
		self.imagestop  = self.imagestart + image.SizeOfImage
		self.hardware.instrumentation.filter_add(self.imagestart,self.imagestop)
		self.hardware.instrumentation.filter_enable()
		self.hardware.instrumentation.optrace_enable()
		self.hardware.instrumentation.memtrace_enable()
		self.hardware.instrumentation.retranslate()
		print "INITIALIZING FILTER DONE!!!"

	def handleEvent(self, event):
		if isinstance(event, QemuCallEvent):
			self.handle_call(event)
		elif isinstance(event, QemuJmpEvent):
			self.handle_jmp(event)
		elif isinstance(event, QemuRetEvent):
			self.handle_ret(event)
		elif isinstance(event, QemuSyscallEvent):
			self.handle_syscall(event)
		elif isinstance(event, QemuBreakpointEvent):
			self.handle_breakpoint(event)
		elif isinstance(event, QemuMemtraceEvent):
			self.handle_memtrace(event)
		elif isinstance(event, QemuOptraceEvent):
			self.handle_optrace(event)
		elif isinstance(event, QemuBBLEvent):
			self.handle_bbl(event)

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
		print "Thread %d registered"%self.cur_tid

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
		print "BREAKPOINT TRIGGERED!!!!!!!!"
		try:
			breakpoint = self.breakpoints[bp.addr]
		except KeyError:
			raise Exception("Unregistered breakpoint has been triggered!")
		breakpoint.trigger()

	def handle_ret(self, ret):
		""" Will be called on ret opcode - updates callstack and triggers handlers """
		# keep callstack up to date
		try:
			if self.callstack.top().isReturning(ret.toaddr):
				f = self.callstack.pop()
				self.log(RetEvent(f))
				f.doReturn()
			else:
				esp = self.register("esp")
				f = self.callstack.top()
				while f.top() < esp:
					self.log(LateRetEvent(f))
					del(f)
					f = self.callstack.pop()
		except IndexError:
			pass
		self.memory.stack.update()

	def handle_syscall(self, syscall):
		# NtCreateThread
		syscall_name = syscalls.getSyscallByNumber(syscall.number)
		if syscall_name is not None:
			self.log(SyscallEvent(syscall_name))
			if syscall_name == "NtTerminateProcess":
				global cleanup_processes
				self.os.terminating_processes.append((self,PyFlxInstrument.registers()["cr3"]))
				self.log(SyscallEvent(syscall_name))
			if syscall_name == "NtCreateThread":
				print "New Thread has been created by %s"%self.name
				self.log(SyscallEvent(syscall_name))
			if syscall_name == "NtTerminateThread":
				print "Thread %d terminated"%self.cur_tid
				self.log(SyscallEvent(syscall_name))
			if syscall_name == "NtCreateProcess" or syscall_name == "NtCreateProcessEx":
				print "New Process has been created by %s"%self.name
				self.log(SyscallEvent(syscall_name))

	def handle_call(self, event):
		""" Call Opcode handler. """
		self._handle_call_filter(event.fromaddr, event.toaddr, event.nextaddr)

	def handle_memtrace(self, event):
		eip = PyFlxInstrument.registers()["eip"]
		if event.writes:
			self.log("Write: 0x%x , Addr: 0x%x, BBL: 0x%x"%(event.value,event.addr,eip))
		else:
			self.log("Read:  0x%x , Addr: 0x%x, BBL: 0x%x"%(event.value,event.addr,eip))

	def handle_bbl(self, event):
		self.log("BBL start at 0x%x, containing %d instructions"%(event.eip,event.instructions))

	def handle_optrace(self, event):
		if self.imagestart > event.eip or self.imagestop < event.eip:
			print "EIP NOT IN RANGE!!!"
		print "Executed opcode 0x%x at eip 0x%x"%(event.opcode, event.eip)

	def handle_jmp(self, event):
		#self.logger.handle_event("JMP: "+hex(toaddr))
		if not self._is_jmp_pad(event.toaddr):
			pass
			#self.logger.handle_event("Blacklisting: "+str(toaddr))
		else:
			try:
				f = self.callstack.top()
				# did we push the previous call onto the callstack?
				if (f.fromaddr, f.toaddr, f.nextaddr) == self.thread.previous_call:
					f = self.callstack.pop()
					del(f)
			except IndexError:
				return
			if self.callFromExe():
				self.log("Resolved through jump pad:")
				self._handle_interesting_call(self.thread.previous_call[0], event.toaddr, self.thread.previous_call[2], False)
			else:
				PyFlxInstrument.blacklist(event.fromaddr, PyFlxInstrument.SLOT_JMP)
			self.thread.previous_call = None


	def addrInExe(self, addr):
		""" check if address is located in main executable image """
		image = self.get_image_by_address(addr)
		if image is not None:
			return image.get_basedllname().lower() == self.imagefilename()
		else:
			return False

	def _handle_call_filter(self, fromaddr, toaddr, nextaddr):
		""" test for interesting calls/jmps and trigger next stage handlers """
		if self.hasSymbol(toaddr):
			# Call comes from exe and so is interesting for us
			if self.callFromExe():
				#self.log("Resolved early:")
				self._handle_interesting_call(fromaddr, toaddr, nextaddr, True)
			# Call in library is not interesting, log it for debugging
			else:
				#self.log_call(CalledFunction(fromaddr, toaddr, nextaddr, self), "Not interesting:")
				PyFlxInstrument.blacklist(fromaddr, PyFlxInstrument.SLOT_CALL)
				#self.logger.handle_event("Blacklisting: "+str(toaddr))
				pass
		else:
			# try to resolve call
			from_image = self.get_image_by_address(fromaddr)
			to_image   = self.get_image_by_address(toaddr)
			if from_image is None or to_image is None:
				try:
					self.update_images()
				except PageFaultException:
					return
			if from_image is not None and to_image is not None:
				if self.callFromExe():
					self.thread.previous_call = (fromaddr, toaddr, nextaddr)
					if not self.hasSymbol(toaddr):
						to_image.update()
					# log it in all cases
					#self.log("Resolved late:")
					self._handle_interesting_call(fromaddr, toaddr, nextaddr, True)
				else:
					# blacklist call target
					PyFlxInstrument.blacklist(fromaddr, PyFlxInstrument.SLOT_CALL)
					pass
					#self.logger.handle_event("Blacklisting: "+str(hex(toaddr)))

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

	def _is_jmp_pad(self, toaddr):
		# if target is a known function, check if address pushed by previous call is still on $esp
		if self.thread.previous_call is None:
			return False
		if self.hasSymbol(toaddr) and \
		struct.unpack("I",self.backend.read(self.register("esp"),4))[0] == self.thread.previous_call[2]:
			return True
		return False

	def _is_jmp(self, fromaddr, toaddr, nextaddr):
		#jumps will set fromaddr/nextaddr to 0, calls *should* not
		return (fromaddr == 0) and (nextaddr == 0)

	def log_call(self, function, prefix = ""):
		if prefix != "":
			self.log(prefix)
		try:
			self.log(CallEvent(function, self.callstack[-1]))
		except IndexError:
			self.log(CallEvent(function))

	def _handle_interesting_call(self, fromaddr, toaddr, nextaddr, iscall):
		""" if call/jmp could generate interesting event, this function will handle it """
		global emulate_functions
		function = CalledFunction(fromaddr, toaddr, nextaddr, self)
		self.log_call(function)
		self.callstack.push(function)
		self.runCallbacks(function,"enter")

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
		self.optrace = False

	def handle_call(self, *args):
		print "UNTRACED PROCESS CALL! %s"%str(args)
	def handle_syscall(self, *args):
		print "UNTRACED PROCESS SYSCALL! %s"%str(args)
	def handle_ret(self, *args):
		print "UNTRACED PROCESS RET! %s"%str(args)
	def handle_jmp(self, *args):
		print "UNTRACED PROCESS JMP! %s"%str(args)
	def handle_optrace(self, *args):
		print "UNTRACED PROCESS OPTRACE! %s"%str(args)
	def handle_memtrace(self, *args):
		print "UNTRACED PROCESS MEMTRACE! %s"%str(args)
	def handle_bblstart(self, *args):
		print "UNTRACED PROCESS BBLSTART! %s"%str(args)
	def handleEvent(self, *args):
		print "UNTRACED PROCESS HANDLE EVENT! %s"%str(args)
