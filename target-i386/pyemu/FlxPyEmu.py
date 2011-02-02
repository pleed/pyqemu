#!/usr/bin/env python

import os, sys
import math
import pygraphviz as pgv
import pydasm

sys.path.append("./lib")

import pefile
from PyEmu import *

class ExecutionError(Exception):
	def __init__(self):
		Exception.__init__(self, "Executing failed")

class PyQEMU_Interface:
	def getRegister(self, register):
		pass
	def getMemory(self, startaddr, len):
		return "\x90"*len

class TestPyQEMU_Interface:
	def getRegister(self, register):
		raise Exception("can not return register")

	def getMemory(self, startaddr, length):
		if startaddr == 0:
			code = "\xbb\x00\x20\x00\x00\xb9\x04\x00\x00\x00\x8b\x03\x81\xc3\x04\x00\x00\x00\x89\x03\x85\xc9\x74\x06\x49\xe9\xec\xff\xff\xff\xc3"
			code += "\x90"*(length-len(code))
			return code
		else:
			return "\x01"*length

	def getPage(self, page, memory):
		return self.getMemory(page, memory.PAGESIZE)

class FlowGraph:
	def __init__(self):
		self.mode = "reading"
		self.read = []
		self.written = []
		self.graph = pgv.AGraph(directed=True)

	def update(self, address, operation):
		self.graph.add_node(address)
		if operation == "read":
			self.recordRead(address)
		else:
			self.recordWrite(address)

	def resetRecord(self):
		self.read  = []
		self.written = []

	def recordRead(self, address):
		if self.mode == "writing":
			for s in self.read:
				for d in self.written:
					self.graph.add_edge(s,d)

			self.resetRecord()
			self.mode = "reading"
		self.read.append(address)

	def recordWrite(self, address):
		if self.mode == "reading":
			self.mode = "writing"
		self.written.append(address)

	def dump(self):
		return self.graph.string()

class DataflowRecorder:
	def __init__(self):
		self.instruction_counter = 0
		self.eip_hash = {}
		self.binary_operations = 0
		self.memory_write_operations = 0
		self.memory_write_hash = {}
		self.memory_read_operations = 0
		self.memory_read_hash = {}
		self.flowgraph = FlowGraph()
		self.influencing_memory = []
		self.memory_write_count = {}

	def memAccess(self, emu, address, value, size, operation):
		if operation == "write":
			for offset in range(size):
				self.memory_write_hash[address+offset] = (value,size)
			self.memory_write_operations += 1
			for addr in range(address, address+size):
				if not self.memory_write_count.has_key(addr):
					self.memory_write_count[addr] = 0
				self.memory_write_count[addr] +=1
		elif operation == "read":
			if address == emu.get_register("EIP"):
				return
			for offset in range(size):
				self.memory_read_hash[address+offset]  = (value,size)
			self.memory_read_operations += 1
		else:
			raise Exception("unknown operation: %s"%operation)

		for addr in range(address, address+size):
			self.flowgraph.update(addr, operation)

		#print "Address: %s, Value: %s, Size: %s, Operation: %s"%(str(address), str(value), str(size), str(operation))

	def regAccess(self, emu, register, value, operation):
		pass
		#print "Register: %s, Value: %s, Operation: %s"%(str(register), str(value), str(operation))

	def recordEIP(self, eip):
		if not self.eip_hash.has_key(eip):
			self.eip_hash[eip] = 1
		self.instruction_counter += 1

	def recordInstruction(self, emu, EIP):
		if emu.cpu.executed_instructions[EIP].mnemonic in ["xor","neg","or","and","shl","shr","sal","sar"]:
			self.binary_operations += 1

	def getStats(self):
		stats = {}
		dotfile = self.flowgraph.dump()

		write_addresses = self.memory_write_hash.keys()
		write_addresses.sort()
		read_addresses = self.memory_read_hash.keys()
		read_addresses.sort()
		stats["loop"]  = (float(self.instruction_counter)/float(len(self.eip_hash)))
		stats["binop"] = (float(self.binary_operations)/float(self.instruction_counter))
		if len(self.memory_write_hash) > 0:
			stats["write"] = (float(self.memory_write_operations)/float(len(self.memory_write_hash)))
		if len(self.memory_read_hash) > 0:
			stats["read"]  = (float(self.memory_read_operations)/float(len(self.memory_read_hash)))
		stats["write_count"] = len(write_addresses)
		stats["read_count"]  = len(read_addresses)

		read_data = ""
		for key,value in self.memory_read_hash.items():
			v = value[0]
			s = value[1]
			read_data += hex(v)[s*2*-1:]
		
		stats["entropy_read"] = float(self.entropy(read_data))

		write_data = ""
		for key,value in self.memory_write_hash.items():
			v = value[0]
			s = value[1]
			write_data += hex(v)[s*2*-1:]
		stats["entropy_write"] = float(self.entropy(write_data))
		stats["write_stats"] = self.memory_write_count
		return dotfile, stats

	def entropy(self, data):
		if not data:
			return 0
		entropy = 0
		for x in range(256):
			p_x = float(data.count(chr(x)))/len(data)
			if p_x > 0:
				entropy += - p_x*math.log(p_x, 2)
		return entropy



class FunctionEmulator(PEPyEmu):
	def __init__(self, qemu_interface, flow_rec, debug_level = 0):
		self.qemu_interface = qemu_interface
		self.flow_rec = flow_rec
		PEPyEmu.__init__(self, membackend = qemu_interface)
		self.configure()
		self.debug(debug_level)

	def configure(self):
		self.set_mnemonic_handler("ret",  self.handleEndOfFunction)
		self.set_mnemonic_handler("call", self.handleBeginOfFunction)
		self.set_memory_access_handler(self.flow_rec.memAccess)
		self.stack_depth = 0
		self.done = False
		self.pf = False
		self.register_safe = {}

	def run(self, registers = {}, function_name = "unknown"):
		for key,value in registers.items():
			self.set_register(key,value)
			self.set_register_handler(key, self.flow_rec.regAccess)

		while not self.done:
			error = False
			eip = self.get_register("EIP")
			#print "EIP: 0x%x"%eip
			self.flow_rec.recordEIP(eip)
			if not self.execute():
				print "COULD NOT EXECUTE!"
				error = True
			#print "Executing: %s"%self.get_disasm()
			if error:
				return None,None
			self.flow_rec.recordInstruction(self, eip)
			#print "-------------------------------------------"
		return self.flow_rec.getStats()

	def handleBeginOfFunction(self, emu, mnemonic, eip, *operands):
		self.stack_depth += 1

	def handleEndOfFunction(self, emu, mnemonic, eip, *operands):
		if self.stack_depth == 0:
			self.done = True
		else:
			self.stack_depth -=1

	def pageBase(self, address):
		return address&(0xfffff000)


if __name__ == "__main__":
	regs = {
		"EAX":0,
		"EBX":0,
		"ECX":0,
		"EDX":0,
		"ESI":0,
		"EDI":0,
		"EIP":0,
		"ESP":0,
		"EBP":0,
		"IOPL":0,
		"CS":0,
		"SS":0,
		"DS":0,
		"ES":0,
		"FS":0,
		"GS":0,
		"IOPL":0,
		"NT":0,
		"VM":0,
		"AC":0,
		"VIF":0,
		"VIP":0,
		"ID":0,
	}
	femu = FunctionEmulator(TestPyQEMU_Interface(), DataflowRecorder())
	dotfile,stats = femu.run(regs)
	print dotfile
	print stats

