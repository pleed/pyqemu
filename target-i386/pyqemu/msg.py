#!/usr/bin/env python

class QemuEvent:
	def __init__(self, event_type, *args):
		self.event_type = event_type
		self.args = args

class QemuArithwindowEvent(QemuEvent):
	def getEIP(self):
		return self.args[0]
	eip = property(getEIP)

class QemuCaballeroEvent(QemuEvent):
	def getEIP(self):
		return self.args[0]
	def getICount(self):
		return self.args[1]
	def getArithCount(self):
		return self.args[2]
	eip    = property(getEIP)
	icount = property(getICount)
	arith  = property(getArithCount)

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
	def getESP(self):
		return self.args[3]
	nextaddr = property(getNext)
	esp      = property(getESP)

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
	def getESP(self):
		return self.args[1]
	eip = property(getEIP)
	esp = property(getESP)

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
	"schedule":QemuScheduleEvent,
	"bbl":QemuBBLEvent,
	"caballero":QemuCaballeroEvent,
	"arithwindow":QemuArithwindowEvent
}



def createEventObject(ev, *args):
	try:
		return QemuEventTypes[ev](ev, *args)
	except KeyError:
		raise Exception("Unknown event type: %s"%ev)
