#!/usr/bin/env python

import os, sys

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

class DataflowRecorder:
	def __init__(self):
		self.instruction_counter = 0
		self.eip_hash = {}
		self.binary_operations = 0
		self.memory_write_operations = 0
		self.memory_write_hash = {}
		self.memory_read_operations = 0
		self.memory_read_hash = {}

	def memAccess(self, emu, address, value, size, operation):
		if operation == "write":
			for offset in range(size):
				self.memory_write_hash[address+offset] = 1
			self.memory_write_operations += 1
		elif operation == "read":
			for offset in range(size):
				self.memory_read_hash[address+offset] = 1
			self.memory_read_operations += 1
		else:
			raise Exception("unknown operation: %s"%operation)
		print "Address: %s, Value: %s, Size: %s, Operation: %s"%(str(address), str(value), str(size), str(operation))

	def regAccess(self, emu, register, value, operation):
		print "Register: %s, Value: %s, Operation: %s"%(str(register), str(value), str(operation))

	def recordEIP(self, eip):
		if not self.eip_hash.has_key(eip):
			self.eip_hash[eip] = 1
		self.instruction_counter += 1

	def recordInstruction(self, emu, EIP):
		if emu.cpu.executed_instructions[EIP].mnemonic in ["xor","neg","or","and","shl","shr"]:
			self.binary_operations += 1

	def showStats(self):
		write_addresses = self.memory_write_hash.keys()
		write_addresses.sort()
		read_addresses = self.memory_read_hash.keys()
		read_addresses.sort()
		print "----------------- STATISTICS ----------------"
		print "Different EIPs seen: %d"%len(self.eip_hash)
		print "Opcodes Executed: %d"%self.instruction_counter
		print "Loop quotient: %f"%(float(self.instruction_counter)/float(len(self.eip_hash)))
		print "---------------------------------------------"
		print "Binary Operations done: %d"%self.binary_operations
		print "BinOp quotient: %f"%(float(self.binary_operations)/float(self.instruction_counter))
		print "---------------------------------------------"
		print "Memory Write Operations done: %d"%self.memory_write_operations
		print "MemWrite quotient: %f"%(float(self.memory_write_operations)/float(len(self.memory_write_hash)))
		print "---------------------------------------------"
		print "Memory Read Operations done: %d"%self.memory_read_operations
		print "MemRead quotient: %f"%(float(self.memory_read_operations)/float(len(self.memory_read_hash)))
		print "---------------------------------------------"
		print "Written to locations: %s"%write_addresses
		print "---------------------------------------------"
		print "Read from locations: %s"%read_addresses
		print "---------------------------------------------"



class FunctionEmulator(PEPyEmu):
	def __init__(self, qemu_interface, flow_rec):
		self.qemu_interface = qemu_interface
		self.flow_rec = flow_rec
		PEPyEmu.__init__(self, membackend = qemu_interface)
		self.configure()

	def configure(self):
		self.set_mnemonic_handler("ret",  self.handleEndOfFunction)
		self.set_mnemonic_handler("call", self.handleBeginOfFunction)
		self.set_memory_access_handler(self.flow_rec.memAccess)
		self.stack_depth = 0
		self.done = False
		self.pf = False
		self.register_safe = {}

	def run(self, registers = {}):
		for key,value in registers.items():
			self.set_register(key,value)
			self.set_register_handler(key, self.flow_rec.regAccess)

		while not self.done:
			eip = self.get_register("EIP")
			self.flow_rec.recordEIP(eip)
			if not self.execute():
				raise Exception("failed to execute")
			self.flow_rec.recordInstruction(self, eip)
			print "-------------------------------------------"
		self.dump_regs()
		self.flow_rec.showStats()
		return True

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
	femu.run(regs)

