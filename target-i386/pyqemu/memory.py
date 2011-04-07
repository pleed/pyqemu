#!/usr/bin/env python

import avl
from Structures import VMemBackend
import PyFlxInstrument

class QemuMemory(VMemBackend):
	pass

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

	def __deepcopy__(self, memo):
		new_object = Stack()
		for item in self:
			new_object.append(copy.deepcopy(item))
		return new_object

class CalledFunction:
	""" Function that was called before, encapsulates entry/exit states """
	def __init__(self, fromaddr, toaddr, nextaddr, process):
		self.fromaddr = fromaddr
		self.toaddr   = toaddr
		self.nextaddr = nextaddr
		self.process = process

		self.entrystate = PyFlxInstrument.registers()
		self.exitstate = None
		self.return_callbacks = []

		self.dllname = None
		self.name = None

	def isReturning(self, nextaddr):
		if nextaddr == self.nextaddr:
			return True
		return False

	def doReturn(self):
		self.exitstate = PyFlxInstrument.registers()
		for callback in self.return_callbacks:
			callback(self)

	def addReturnCallback(self, callback):
		self.return_callbacks.append(callback)

	def retval(self):
		self.exitstate = PyFlxInstrument.registers()
		return self.exitstate["eax"]

	def resolveToName(self):
		if self.name is None and self.dllname is None:
			dll, addr = self.resolve()
			if dll is None:
				return "Unknown","Unknown"
			try:
				self.dllname, self.name =  dll.get_basedllname().lower(), self.process.getSymbol(addr)
				return self.dllname, self.name
			except KeyError:
				return dll.get_basedllname(), hex(addr)
		else:
			return self.dllname, self.name

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

	def __hash__(self):
		return hash(self.resolveToName())

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

	def sizeHint(self, len):
		self.size = max(len, self.size)

	def update(self):
		self.read()

	def read(self, len = None):
		try:
			if len is None:
				return self.backend.read(self.startaddr, self.size)
			else:
				return self.backend.read(self.startaddr, len)
		except PageFaultException:
			return ""

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
		if self.process.callstack.empty():
			return False
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
	""" Traces memory globally allocated in memory data segment """
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

