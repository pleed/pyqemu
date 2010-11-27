#!/usr/include/python

import traceback
import sys
import os
import glob
import struct
import cPickle
import pickle
import avl
import gc
import copy
import guppy

from event import *
import PyFlxInstrument
import processinfo
from Structures import *
from dllhandling import *
import syscalls

DEBUG = True
NULL = 0

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
cleanup_processes = []

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

	if len(cleanup_processes) > 0:
		print "Deleting process"
		p,cr3 = cleanup_processes.pop()
		KNOWN_Processes[cr3] = UntracedProcess([])
		del(p)

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
			if filename.lower() in trace_processes.keys():
				print "New TracedProcess %s"%filename
				p = TracedProcess(trace_processes[filename.lower()])
			else:
				print "New UntracedProcess %s"%filename
				p = UntracedProcess([])
			KNOWN_Processes[new_cr3] = p
			p.watched = True
	
	return 0

class Stack(list):
	def __init__(self, *args):
		list.__init__(self, *args)
		self.push = self.append

	def top(self):
		return self[-1]

	def bottom(self):
		return self[0]

	def empty(self):
		return len(self) == 0

	def __str__(self):
		s = ""
		for item in self:
			s+="%s\n"%item
		return s

class CalledFunction:
	""" Function that was called before, encapsulates entry/exit states """
	def __init__(self, fromaddr, toaddr, nextaddr, process):
		self.fromaddr = fromaddr
		self.toaddr   = toaddr
		self.nextaddr = nextaddr
		self.process = process

		self.entrystate = PyFlxInstrument.registers()
		self.exitstate = None

	def isReturning(self, nextaddr):
		if nextaddr == self.nextaddr:
			self.exitstate = PyFlxInstrument.registers()
			return self.entrystate["esp"] == self.exitstate["esp"]
		return False

	def retval(self):
		self.exitstate = PyFlxInstrument.registers()
		return self.exitstate["eax"]

	def resolveToName(self):
		dll, addr = self.resolve()
		if dll is None:
			return "Unknown","Unknown"
		try:
			return dll.get_basedllname().lower(), self.process.getSymbol(addr)
		except KeyError:
			return dll.get_basedllname(), hex(addr)

	def resolve(self):
		image = self.process.get_image_by_address(self.toaddr)
		return image, self.toaddr

	def top(self):
		""" Stack frame starts at stored EIP! In this definition, arguments belong to predecessor """
		return self.entrystate["esp"]

	def __deepcopy__(self, memo):
		new_object = CalledFunction(self.fromaddr, self.toaddr, self.nextaddr, self.process)
		new_object.entrystate = copy.deepcopy(self.entrystate, memo)
		new_object.exitstate = copy.deepcopy(self.exitstate, memo)
		return new_object

	def __str__(self):
		return "%s::%s()"%(self.resolveToName())

	def __eq__(self, other):
		return self.toaddr== other.toaddr and self.top() == other.top()

	def __ne__(self, other):
		return not self.__eq__(other)

	def getIntArg(self, num):
		return struct.unpack("I", self.getFunctionArg(num))[0]

	def getBufFromPtr(self, num, size):
		address = self.getIntArg(num)
		return struct.unpack(str(num)+"c", self.process.readmem(address, size))

	def getFunctionArg(self, num):
		global R_ESP
		esp = self.process.genreg(R_ESP)
		return self.process.readmem(esp+num*4, 4)

class EventLogger:
	""" Object serialization logger """
	def __init__(self, dumpfile):
		self.dumpfile = dumpfile
		self.dumper   = pickle

	def handle_event(self, obj):
		if obj is None:
			print "obj is None"
		if self.dumpfile is None:
			print "file is None"
		print "type obj: "+str(type(obj))
		print "type file:"+str(type(self.dumpfile))
		self.dumper.dump(obj, self.dumpfile)
		self.dumpfile.flush()

	def close(self):
		self.dumpfile.close()

class StdoutEventLogger(EventLogger):
	""" Event logger for debugging """
	def handle_event(self, obj):
		self.dumpfile.write("Process: %d, Thread: %d, %s\n"%(get_current_process().pid,get_current_process().cur_tid,str(obj)))
		self.dumpfile.flush()

class Buffer:
	identifier = 0
	""" Represents allocated memory """
	def __init__(self, startaddr, size, origin = None, segment = None):
		self.startaddr = startaddr
		self.size      = size
		self.endaddr   = startaddr+size-1
		self.origin    = origin
		self.segment   = segment
		self.backend   = get_current_process().backend

		# Assign unique ID, several buffers could be mapped to the same address after freeing the previous
		Buffer.identifier+= 1
		self.id        = Buffer.identifier

	def read(self, len = None):
		if len is None:
			return self.backend.read(self.startaddr, self.size)
		else:
			return self.backend.read(self.startaddr, len)

	def includes(self, address):
		return self.startaddr <= address <= self.endaddr

	def __eq__(self, other):
		other = int(other)
		return self.startaddr == other

	def __lt__(self, other):
		other = int(other)
		return self.startaddr < other

	def __le__(self, other):
		other = int(other)
		return self.startaddr <= other

	def __ne__(self, other):
		other = int(other)
		return self.startaddr != other

	def __ge__(self, other):
		other = int(other)
		return self.startaddr >= other

	def __gt__(self, other):
		other = int(other)
		return self.startaddr > other

	def __int__(self):
		return self.startaddr

	def __str__(self):
		s = "[id=%d:0x%x[%s]"%(self.id, self.startaddr, str(self.size))
		if self.origin is not None:
			s += "[%s]"%self.origin
		if self.segment is not None:
			s += "[%s]"%self.segment
		s+="]"
		return s

	def __len__(self):
		return self.size

class HeapMemoryTracer:
	""" Traces memory located on heap """
	def __init__(self, process):
		self.tree = avl.new()
		self.process = process

	def allocate(self, address, size):
		global heap_allocation_functions
		try:
			allocating_function = None
			for	f in self.process.callstack:
				dll,name = f.resolveToName()
				if not (dll, name) in heap_allocation_functions:
					allocating_function = f
		except IndexError:
			allocating_function = None
		b = Buffer(address, size, allocating_function, "HEAP")
		self.tree.insert(b)
		return b

	def getBuffer(self, address):
		try:
			buffer = self.tree.at_most(address)
		except ValueError:
			return None
		if buffer.includes(address):
			return buffer
		return None

	def deallocate(self, address):
		if self.allocated(address):
			obj = self.tree.at_most(address)
			self.tree.remove(obj)
		else:
			debug("double free detected by HeapMemoryTracer!")

	def free(self, address):
		self.deallocate(address)

	def allocated(self, address):
		return self.getBuffer(address) is not None

class StackMemoryTracer:
	""" Traces memory located on stack """
	def __init__(self, process):
		self.process = process
		self.buffers = {}

	def allocated(self, address):
		esp = self.process.register("esp")
		stack_top = self.process.callstack.bottom().top()
		if esp <= address <= stack_top:
			function = self.process.getstackframe(address)
			maxlen = function.top()-address-4
			self.buffers[address] = Buffer(address, maxlen, function, "STACK")
			return True
		else:
			return False

	def update(self):
		esp = self.process.register("esp")
		keys = self.buffers.keys()
		for key in keys:
			if self.buffers[key].startaddr < esp:
				self.process.log(DeallocateEvent(self.buffers[key]))
				del(self.buffers[key])

	def getBuffer(self, address):
		return self.buffers[address]

	def __deepcopy__(self, memo):
		new_object = StackMemoryTracer(self.process)
		new_object.buffers = copy.deepcopy(self.buffers, memo)
		return new_object

class DataMemoryTracer:
	""" Traces memory globally allocated in image """
	def __init__(self, process):
		self.process = process
		self.tree = avl.new()

	def allocate(self, address):
		b = Buffer(address, 0, None, "DATA")
		self.tree.insert(b)
		return b

	def inData(self, address):
		return self.process.get_image_by_address(address) is not None

	def allocated(self, address):
		if self.inData(address):
			try:
				buffer = self.tree.at_most(address)
				if not buffer.includes(address):
					return False
			except ValueError:
				self.allocate(address)
			return True
		return False

	def getBuffer(self, address):
		if self.allocated(address):
			return self.tree.at_most(address)
		else:
			if self.inData(address):
				return self.allocate(address)
			else:
				return None

class UnknownMemoryTracer:
	""" Traces memory from unknown origins """
	def __init__(self, process):
		self.process = process
		self.tree = avl.new()

	def allocate(self, address):
		b = Buffer(address, 0, None, "UNKNOWN")
		self.tree.insert(b)
		return b

	def allocated(self, address):
		try:
			buffer = self.tree.at_most(address)
		except ValueError:
			return False
		if buffer.includes(address):
			return True
		return False

	def getBuffer(self, address):
		# Should never return None
		try:
			buffer = self.tree.at_most(address)
			if not buffer.includes(address):
				buffer = self.allocate(address)
		except ValueError:
			buffer = self.allocate(address)
		return buffer

		

class MemoryManager:
	""" main memory manager, encapsulates as much of the underlying memory classes as possible """
	def __init__(self, process, heap = None, stack = None, data = None, unknown = None):
		if heap is None:
			self.heap = HeapMemoryTracer(process)
		else:
			self.heap = heap
		if stack is None:
			self.stack = StackMemoryTracer(process)
		else:
			self.stack = stack
		if data is None:
			self.data = DataMemoryTracer(process)
		else:
			self.data = data
		if unknown is None:
			self.unknown = UnknownMemoryTracer(process)
		else:
			self.unknown = unknown

	def onStack(self, addr):
		return self.stack.allocated(addr)

	def onData(self, addr):
		return self.data.allocated(addr)

	def onHeap(self, addr):
		return self.heap.allocated(addr)

	def getMemoryTracer(self, addr):
		if self.onStack(addr):
			return self.stack
		elif self.onHeap(addr):
			return self.heap
		elif self.onData(addr):
			return self.data
		else:
			return self.unknown

	def getBuffer(self, addr):
		tracer = self.getMemoryTracer(addr)
		return tracer.getBuffer(addr)

class FunctionHandler:
	""" base class for function handlers """
	def __init__(self, process):
		self.process = process

	def onEnter(self, function):
		self.addPendingReturn(function)

	def onLeave(self, function):
		raise Exception("Implement in inherited class!")

	def addPendingReturn(self, function):
		self.process.add_pending_return(function)

class HeapAllocationFunctionHandler(FunctionHandler):
	def onLeave(self, function):
		addr = function.retval()
		size = function.getIntArg(1)
		buffer = self.process.memory.heap.allocate(addr, size)
		self.process.log(AllocateEvent(buffer))

class CallocFunctionHandler(FunctionHandler):
	def onLeave(self, function):
		addr = function.retval()
		if addr != NULL:
			num  = function.getIntArg(1)
			size = function.getIntArg(2)
			buffer = self.process.memory.heap.allocate(addr, num*size)
			self.process.log(AllocateEvent(buffer))

class HeapFreeFunctionHandler(FunctionHandler):
	def onEnter(self, function):
		addr = function.getIntArg(1)
		if self.process.memory.heap.allocated(addr):
			buffer = self.process.memory.heap.getBuffer(addr)
			self.process.log(DeallocateEvent(buffer))
			self.process.memory.heap.deallocate(addr)
		else:
			self.process.log(DeallocateEvent("unknown: 0x%x"%addr))
		# isnt that a nice place to do garbage collection?
		#gc.collect()

class WSARecvFunctionHandler(FunctionHandler):
	def onEnter(self, function):
		self.addPendingReturn(function)
		self.addr  = function.getIntArg(2)
		self.count = function.getIntArg(3)
		self.call  = function.getIntArg(7)
		self.socket,self.buffers,self.count,self.recvd,self.flags,self.overlapped,self.callback = function.getIntArg(1),function.getIntArg(2),function.getIntArg(3),function.getIntArg(4),function.getIntArg(5),function.getIntArg(6),function.getIntArg(7),

	def onLeave(self, function):
		eax = function.retval()
		if eax == 0:
			bytesreceived = struct.unpack("I", self.process.readmem(function.getIntArg(4), 4))[0]
			total_received = bytesreceived
			i = 0
			while i<self.count and bytesreceived > 0:
				len,ptr = struct.unpack("II", self.process.readmem(self.addr+i*8, 8))
				self.buffer = self.process.memory.getBuffer(ptr)
				self.buffer.size = max(self.buffer.size, len)
				bytesinbuffer = min(bytesreceived, len)
				bytesreceived -= bytesinbuffer
				self.process.log(RecvEvent(self.buffer, ptr, bytesinbuffer))
				i += 1

class SendFunctionHandler(FunctionHandler):
	def onEnter(self, function):
		self.addPendingReturn(function)
		self.addr = function.getIntArg(2)
		self.len  = function.getIntArg(3)


	def onLeave(self, function):
		bytes_sent = function.retval()
		if bytes_sent > 0:
			buffer = self.process.memory.getBuffer(self.addr)
			self.process.log(SendEvent(buffer, self.addr, self.len, bytes_sent))
		else:
			pass
			#error occured

class ReallocFunctionHandler(FunctionHandler):
	""" Handles realloc like functions, relies on other handlers producing events (e.g. malloc) """
	def onEnter(self, function):
		self.addPendingReturn(function)
		self.old_ptr  = function.getIntArg(1)
		self.new_size = function.getIntArg(2)

	def onLeave(self, function):
		new_ptr = function.retval()
		if self.old_ptr == NULL:
			# will call malloc - nothing to do
			return

		elif self.new_size == 0:
			# behaves like free
			addr = self.old_ptr
			if self.process.memory.heap.allocated(addr):
				buffer = self.process.memory.heap.getBuffer(addr)
				self.process.log(DeallocateEvent(buffer))
				self.process.memory.heap.deallocate(addr)
			else:
				self.process.log(DeallocateEvent("unknown: 0x%x"%addr))
		elif new_ptr != NULL:
			# reallocation, probably
			if self.old_ptr == new_ptr:
				buffer = self.process.memory.getBuffer(self.old_ptr)
				buffer.size = self.new_size
			else:
				old_buffer = self.process.memory.getBuffer(self.old_ptr)
				new_buffer = self.process.memory.heap.allocate(new_ptr, self.new_size)
				self.process.log(AllocateEvent(new_buffer))
				self.process.log(CopyEvent(new_buffer, old_buffer, old_buffer.size))
				self.process.log(DeallocateEvent(old_buffer))
				self.process.memory.heap.deallocate(old_buffer)

class CpyFunctionHandler(FunctionHandler):
	""" Handles copying functions without a length argument """
	def onEnter(self, function, len = -1):
		dst = function.getIntArg(1)
		src = function.getIntArg(2)
		src_buffer = self.process.memory.getBuffer(src)
		dst_buffer = self.process.memory.getBuffer(dst)
		self.process.log(CopyEvent(dst_buffer, src_buffer, len, dst, src))

class StrCpyFunctionHandler(CpyFunctionHandler):
	def onEnter(self, function):
		src = function.getIntArg(2)
		CpyFunctionHandler.onEnter(self, function, len=len(STR(self.process.backend, src)))

class NCpyFunctionHandler(CpyFunctionHandler):
	""" Handles copying functions with a length argument """
	def onEnter(self, function):
		len = function.getIntArg(3)
		CpyFunctionHandler.onEnter(self, function, len)

class StrDupFunctionHandler(FunctionHandler):
	""" Handles strdup like functions """
	def onEnter(self, function):
		self.addPendingReturn(function)
		self.src = function.getIntArg(1)

	def onLeave(self, function):
		self.dst = function.retval()
		if self.dst != NULL:
			src_buffer = self.process.memory.getBuffer(self.src)
			dst_buffer = self.process.memory.getBuffer(self.dst)
			self.process.log(CopyEvent(dst_buffer, src_buffer, dst_buffer.size))


class RaiseFunctionHandler(FunctionHandler):
	""" we have to notice exceptions later to keep callstack up to date """
	def onEnter(self, function):
		raise Exception("Program raised Exception via %s"%function)

class RegisteredCallback:
	def __init__(self, func):
		self.func = func

	def __call__(self, *args):
		process = get_current_process()
		if not process.isRegisteredThread():
			process.createNewThread()
		return self.func(process,*args)

class Thread:
	def __init__(self, *args):
		self.callstack = Stack()
		self.wait_for_return = {}
		self.memory  = MemoryManager(*args)
		self.previous_call = None

class TracedProcess(processinfo.Process):
	""" A traced process with functionality to register callbacks for vm inspection """

	def __init__(self, callhandler = []):
		self.detected_dlls       = 0
		self.threadcount         = 0
		self.threads             = {}
		# log events
		self.logger              = StdoutEventLogger(open("/tmp/flx_dump_events","w"))
		self.dllhandler          = DLLHandler("/media/shared/")
		# stores registerd callbacks
		self.callonfunction      = {}

		self.create_thread_list  = []

		processinfo.Process.__init__(self)
		self.loadCallbacks(callhandler)

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
			if len(self.create_thread_list) > 1:
				raise Exception("Race condition creating new threads!, FIX IT!")
			creating_thread_id = self.create_thread_list.pop()
			self.threads[self.cur_tid] = Thread(self, self.threads[creating_thread_id].memory.heap, \
			                                          copy.deepcopy(self.threads[creating_thread_id].memory.stack),\
			                                          self.threads[creating_thread_id].memory.data, \
													  self.threads[creating_thread_id].memory.unknown)
		print "Thread %d registered"%self.cur_tid

	def registerCreateThreadCall(self):
		self.create_thread_list.append(self.cur_tid)

	def getThread(self):
		try:
			return self.threads[self.cur_tid]
		except KeyError:
			self.createNewThread()
	thread = property(getThread)

	def getCallstack(self):
		return self.thread.callstack
	callstack = property(getCallstack)

	def getWaitForReturn(self):
		return self.thread.wait_for_return
	wait_for_return = property(getWaitForReturn)

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
			if frameid > 0:
				return self.callstack[frameid]
			else:
				return None
		else:
			return None

	def log(self, obj):
		""" Log event """
		self.logger.handle_event(obj)

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

	def add_pending_return(self, function):
		""" Used by FunctionHandlers to hook corresponding return of a called function """
		self.wait_for_return[hash((function.nextaddr,function.top()))] = function

	def loadCallbacks(self,handlers):
		""" Load FunctionHandlers from dict """
		for dll,fname,handlerclass in handlers:
			self.registerFunctionHandler(dll, fname, handlerclass(self))

	@RegisteredCallback
	def handle_ret(self, toaddr):
		""" Will be called on ret opcode - updates callstack and triggers handlers """
		esp = self.register("esp")
		index = hash((toaddr,esp))

		# keep callstack up to date
		try:
			if self.callstack.top().isReturning(toaddr):
				f = self.callstack.pop()
				self.log(RetEvent(f))
				del(f)
			else:
				f = self.callstack.top()
				while f.top() < esp:
					self.log(LateRetEvent(f))
					del(f)
					f = self.callstack.pop()
		except IndexError:
			pass
		self.memory.stack.update()

		# check for pending return callback
		if self.wait_for_return.has_key(index):
			function = self.wait_for_return[index]
			if not function.isReturning(toaddr):
				raise Exception("FUNCTION NOT RETURNING!!!")
			self.runCallbacks(function,"leave")
			del(self.wait_for_return[index])

		#garbage collection
		if len(self.wait_for_return) > 500:
			for index,function in self.wait_for_return:
				if function.top() < esp:
					del(self.wait_for_return[hash(toaddr,function.top())])
			print "wait_for_return size is now: %d"%len(self.wait_for_return)

	@RegisteredCallback
	def handle_syscall(self, eax):
		# NtCreateThread
		syscall_name = syscalls.getSyscallByNumber(eax)
		if syscall_name is not None:
			self.log(SyscallEvent(syscall_name))
			if syscall_name == "NtTerminateProcess":
				global cleanup_processes
				cleanup_processes.append((self,PyFlxInstrument.registers()["cr3"]))
				
		else:
			self.log(SyscallEvent(eax))
		if eax == 0x35:
			self.registerCreateThreadCall()

	@RegisteredCallback
	def handle_call(self, *args):
		""" Call Opcode handler. """
		self._handle_call_filter(*args)

	def addrInExe(self, addr):
		""" check if address is located in main executable image """
		image = self.get_image_by_address(addr)
		if image is not None:
			return image.get_basedllname().lower() == self.imagefilename()
		else:
			return False

	def _handle_call_filter(self, fromaddr, toaddr, nextaddr):
		""" test for interesting calls/jmps and trigger next stage handlers """
		# handle jumps that could be jump pads
		if self._is_jmp(fromaddr, toaddr, nextaddr):
			if self._is_jmp_pad(fromaddr, toaddr, nextaddr):
				try:
					f = self.callstack.top()
					# did we push the previous call onto the callstack?
					if (f.fromaddr, f.toaddr, f.nextaddr) == self.thread.previous_call:
						f = self.callstack.pop()
						del(f)
				except IndexError:
					pass
				self._handle_interesting_call(self.thread.previous_call[0], toaddr, self.thread.previous_call[2], False)
				self.thread.previous_call = None
			else:
				return
		# handle normal calls
		else:
			self.thread.previous_call = (fromaddr, toaddr, nextaddr)
			from_image = self.get_image_by_address(fromaddr)
			to_image   = self.get_image_by_address(toaddr)
			if from_image is None or to_image is None:
				self.update_images()
			if from_image is not None and to_image is not None:
				if (self.addrInExe(toaddr) or self.addrInExe(fromaddr)) and not self.hasSymbol(toaddr):
					to_image.update()
				# just known functions or call from/to main exe are interesting right now
				if self.addrInExe(toaddr) or self.addrInExe(fromaddr) or self.hasSymbol(toaddr):
					self._handle_interesting_call(fromaddr, toaddr, nextaddr, True)

	def getSymbol(self, addr):
		if self.symbols.has_key(addr):
			return self.symbols[addr][2]
		else:
			if self.detected_dlls < len(self.images):
				for image in self.images:
					base = image
					image = self.get_image_by_address(image)
					self.dllhandler.loadDLL(image.get_basedllname(), base)
				self.detected_dlls = len(self.images)
			lib = self.dllhandler.getLib(addr)
			if lib is not None and lib.has_key(addr):
				return lib[addr][2]
		return str(hex(addr))

	def hasSymbol(self, addr):
		if self.symbols.has_key(addr):
			return True
		else:
			lib = self.dllhandler.getLib(addr)
			if lib is not None and lib.has_key(addr):
				return True
		return False

	def _is_jmp_pad(self, fromaddr, toaddr, nextaddr):
		# if target is a known function, check if address pushed by previous call is still on $esp
		if self.hasSymbol(toaddr) and \
		struct.unpack("I",self.backend.read(self.register("esp"),4))[0] == self.thread.previous_call[2]:
			return True
		return False

	def _is_jmp(self, fromaddr, toaddr, nextaddr):
		#jumps will set fromaddr/nextaddr to 0, calls *should* not
		return (fromaddr == 0) and (nextaddr == 0)

	def _handle_interesting_call(self, fromaddr, toaddr, nextaddr, iscall):
		""" if call/jmp could generate interesting event, this function will handle it """
		function = CalledFunction(fromaddr, toaddr, nextaddr, self)
		self.callstack.push(function)
		self.runCallbacks(function,"enter")
		self.log(CallEvent(function))

	def runCallbacks(self, function, event_type):
		""" Run registered Callbacks for (dll, function) tuple. """
		dll,name = function.resolveToName()	
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

	def registerFunctionHandler(self, dllname, function, callback):
		""" Registers a function that will be called when vm process calls dllname::funcname(). """
		dllname = dllname.lower()
		if self.callonfunction.has_key(dllname+function):
			self.callonfunction[dllname+function].append(callback)
		else:
			self.callonfunction[dllname+function] = [callback]
		return None

	def __del__(self):
		for tid,thread in self.threads.items():
			del(thread)
		self.logger.close()
		del(self.logger)
		del(self.dllhandler)
		del(self.callonfunction)

class UntracedProcess(processinfo.Process):
	def __init__(self, callhandler):
		processinfo.Process.__init__(self)

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

# Heap allocation functions to get real origin
# O(n) :(
heap_allocation_functions = [
				("msvcrt.dll",  "malloc"),
				("kernel32.dll", "HeapAlloc"),
				("ole32.dll", "CoTaskMemAlloc"),
				("msvcrt.dll", "realloc"),
				("msvcrt.dll", "_strdup"),
				("msvcrt.dll", "calloc"),
							]
# Register Processes to trace
trace_processes = {
	"telnet.exe":[],
	"notepad.exe":[],
	"wget.exe":[
				("msvcrt.dll",  "malloc",  HeapAllocationFunctionHandler),
				("msvcrt.dll",  "free",    HeapFreeFunctionHandler),
				("wsock32.dll", "recv",    WSARecvFunctionHandler),
				("wsock32.dll", "send",    SendFunctionHandler),
				("ws2_32.dll",  "WSARecv", WSARecvFunctionHandler),
				("ws2_32.dll",  "send",    SendFunctionHandler),
				("msvcrt.dll",  "strcpy",  StrCpyFunctionHandler),
				("msvcrt.dll",  "strncpy", NCpyFunctionHandler),
				("msvcrt.dll",  "memcpy",  NCpyFunctionHandler),
				("msvcrt.dll",  "wcscpy",  CpyFunctionHandler),
				("kernel32.dll", "RaiseException", RaiseFunctionHandler),
				("kernel32.dll", "HeapAlloc" , HeapAllocationFunctionHandler),
				("ole32.dll", "CoTaskMemAlloc", HeapAllocationFunctionHandler),
				("msvcrt.dll", "realloc",  ReallocFunctionHandler),
				("msvcrt.dll", "_strdup",  StrDupFunctionHandler),
				("msvcrt.dll", "calloc",   CallocFunctionHandler),
			   ],
	"asam.exe":[
				("msvcrt.dll",  "malloc",  HeapAllocationFunctionHandler),
				("msvcrt.dll",  "free",    HeapFreeFunctionHandler),
				("wsock32.dll", "recv",    WSARecvFunctionHandler),
				("wsock32.dll", "send",    SendFunctionHandler),
				("ws2_32.dll",  "WSARecv", WSARecvFunctionHandler),
				("ws2_32.dll",  "send",    SendFunctionHandler),
				("msvcrt.dll",  "strcpy",  StrCpyFunctionHandler),
				("msvcrt.dll",  "strncpy", NCpyFunctionHandler),
				("msvcrt.dll",  "memcpy",  NCpyFunctionHandler),
				("msvcrt.dll",  "wcscpy",  CpyFunctionHandler),
				("kernel32.dll", "RaiseException", RaiseFunctionHandler),
				("kernel32.dll", "HeapAlloc" , HeapAllocationFunctionHandler),
				("ole32.dll", "CoTaskMemAlloc", HeapAllocationFunctionHandler),
				("msvcrt.dll", "realloc",  ReallocFunctionHandler),
				("msvcrt.dll", "_strdup",  StrDupFunctionHandler),
				("msvcrt.dll", "calloc",   CallocFunctionHandler),
				],
	"virus.exe":[
				("msvcrt.dll",  "malloc",  HeapAllocationFunctionHandler),
				("msvcrt.dll",  "free",    HeapFreeFunctionHandler),
				("wsock32.dll", "recv",    WSARecvFunctionHandler),
				("wsock32.dll", "send",    SendFunctionHandler),
				("ws2_32.dll",  "WSARecv", WSARecvFunctionHandler),
				("ws2_32.dll",  "send",    SendFunctionHandler),
				("msvcrt.dll",  "strcpy",  StrCpyFunctionHandler),
				("msvcrt.dll",  "strncpy", NCpyFunctionHandler),
				("msvcrt.dll",  "memcpy",  NCpyFunctionHandler),
				("msvcrt.dll",  "wcscpy",  CpyFunctionHandler),
				("kernel32.dll", "RaiseException", RaiseFunctionHandler),
				("kernel32.dll", "HeapAlloc" , HeapAllocationFunctionHandler),
				("ole32.dll", "CoTaskMemAlloc", HeapAllocationFunctionHandler),
				("msvcrt.dll", "realloc",  ReallocFunctionHandler),
				("msvcrt.dll", "_strdup",  StrDupFunctionHandler),
				("msvcrt.dll", "calloc",   CallocFunctionHandler),
				],
}

# Register FLX Callbacks 
ev_syscall    = ensure_error_handling_helper(lambda *args: get_current_process().handle_syscall(*args))
ev_call       = ensure_error_handling_helper(lambda *args: get_current_process().handle_call(*args))
ev_ret        = ensure_error_handling_helper(lambda *args: get_current_process().handle_ret(*args))
ev_update_cr3 = ensure_error_handling_helper(event_update_cr3)
