#!/usr/bin/env python

from PyFlxInstrument import registers,genreg,creg

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

class QemuCPU:

	@classmethod
	def getReg(cls, register):
		regs = registers()
		return registers()[register]

	@classmethod
	def genReg(cls, register):
		return genreg(register)

	def cReg(cls, register):
		return creg(register)

	eax = property(lambda self: self.genReg(R_EAX))
	ebx = property(lambda self: self.genReg(R_EBX))
	ecx = property(lambda self: self.genReg(R_ECX))
	edx = property(lambda self: self.genReg(R_EDX))
	ebp = property(lambda self: self.genReg(R_EBP))
	esp = property(lambda self: self.genReg(R_ESP))
	edi = property(lambda self: self.genReg(R_EDI))
	esi = property(lambda self: self.genReg(R_ESI))

	es  = property(lambda self: self.cReg(R_ES))
	cs  = property(lambda self: self.cReg(R_CS))
	ss  = property(lambda self: self.cReg(R_SS))
	ds  = property(lambda self: self.cReg(R_DS))
	fs  = property(lambda self: self.cReg(R_FS))
	gs  = property(lambda self: self.cReg(R_GS))

	eflags = property(lambda self: self.getReg("eflags"))

	cr0 = property(lambda self: self.getReg("cr0"))
	cr2 = property(lambda self: self.getReg("cr2"))
	cr3 = property(lambda self: self.getReg("cr3"))
	cr4 = property(lambda self: self.getReg("cr4"))

	eip = property(lambda self: self.getReg("eip"))

