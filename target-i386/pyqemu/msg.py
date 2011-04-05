#!/usr/bin/env python

class QemuEvent:
	def __init__(self, *args):
		self.args = args

class QemuBranchEvent(QemuEvent):
	def getFrom(self):
		return self.args[0]
	def getTo(self):
		return self.args[1]
	fromaddr = property(getFrom)
	toaddr   = property(getTo)

class QemuCallEvent(QemuBranchEvent):
	def getNext(self):
		return self.args[2]
	nextaddr = property(getNext)

class QemuJmpEvent(QemuBranchEvent):
	pass

class QemuSyscallEvent(QemuEvent):
	def getNumber(self):
		return self.args[0]
	number = property(getNumber)

class QemuRetEvent(QemuBranchEvent):
	pass
	
class QemuBreakpointEvent(QemuEvent):
	def getAddr(self):
		return self.args[0]
	addr = property(getAddr)

class QemuMemtraceEvent(QemuEvent):
	def getAddr(self):
		return self.args[0]
	def getValue(self):
		return self.args[1]
	def getSize(self):
		return self.args[2]
	def isWrite(self):
		return self.args[3]==1

	addr    = property(getAddr)
	value   = property(getValue)
	size    = property(getSize)
	writes  = property(isWrite)
class QemuBBLEvent(QemuEvent):
	def getEIP(self):
		return self.args[0]
	def getInstructionCount(self):
		return self.args[1]
	eip = property(getEIP)
	instructions = property(getInstructionCount)

class QemuOptraceEvent(QemuEvent):
	def getEIP(self):
		return self.args[0]
	def getOpcode(self):
		return self.args[1]

	eip = property(getEIP)
	opcode = property(getOpcode)

class QemuScheduleEvent(QemuEvent):
	def getPrevious(self):
		return self.args[0]
	def getCurrent(self):
		return self.args[1]
	prev = property(getPrevious)
	cur  = property(getCurrent)

QemuEventTypes = {
	"call":QemuCallEvent,
	"jmp":QemuJmpEvent,
	"ret":QemuRetEvent,
	"syscall":QemuSyscallEvent,
	"breakpoint":QemuBreakpointEvent,
	"memtrace":QemuMemtraceEvent,
	"optrace":QemuOptraceEvent,
	"schedule":QemuScheduleEvent,
	"bbl":QemuBBLEvent,
}



def createEventObject(ev, *args):
	try:
		return QemuEventTypes[ev](*args)
	except KeyError:
		raise Exception("Unknown event type: %s"%ev)
