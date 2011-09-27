#!/usr/include/python

import string
from copy import deepcopy
import syscalls

# NOT USED ANYMORE ! ! !

def string_from_buf(buffer, len = None, omit = 0):
	if len is None:
		not_printable = buffer.read(None)
		not_printable = not_printable[omit:]
	else:
		not_printable = buffer.read(len+omit)
		not_printable = not_printable[omit:omit+len]
	s = ""
	for letter in not_printable:
		if letter in string.printable and not letter in "\t\n\r":
			s += letter
		else:
			s += "\\"+hex(ord(letter))
	return s
	

class Event:
	""" Event base class """
	pass

class SyscallEvent(Event):
	def __init__(self, syscall):
		self.syscall = syscall

	def __str__(self):
		return "Syscall: (%s)"%self.syscall

class CopyEvent(Event):
	""" Memory was copied from src to dst """
	def __init__(self, dst_buffer, src_buffer, len, dst_addr = 0, src_addr = 0):
		self.src_buffer_id = src_buffer.id
		self.dst_buffer_id = dst_buffer.id
		self.src_segment   = src_buffer.segment
		self.dst_segment   = src_buffer.segment
		self.copy_length = len
		if dst_addr == 0:
			self.dst_buffer_offset = 0
		else:
			self.dst_buffer_offset = dst_addr - dst_buffer.startaddr
		if src_addr == 0:
			self.src_buffer_offset = 0
		else:
			self.src_buffer_offset = src_addr - src_buffer.startaddr
		self.src_content = src_buffer.read()[self.src_buffer_offset:]
		self.dst_content = dst_buffer.read()[self.dst_buffer_offset:]

	def __str__(self):
		return "Copy: (%d, %d, %s) <-- (%d, %d, %s)"%(self.dst_buffer_id, self.dst_buffer_offset, self.dst_segment, self.src_buffer_id, self.src_buffer_offset, self.src_segment)

class SendEvent(Event):
	def __init__(self, buffer, addr, requested_len, sent_len):
		self.num_sent     = sent_len
		self.send_offset  = addr-buffer.startaddr
		self.content      = buffer.read()[self.send_offset:]
		self.buffer_id    = buffer.id
		self.buffer_segment = buffer.segment

	def __str__(self):
		return "Send: (%d, %d, %s)"%(self.buffer_id, self.send_offset, self.buffer_segment)

class RecvEvent(Event):
	def __init__(self, buffer, startptr, bytes_received):
		self.num_received = bytes_received
		self.recv_offset  = startptr-buffer.startaddr
		self.content      = buffer.read()[self.recv_offset:]
		self.buffer_id    = buffer.id
		self.buffer_segment = buffer.segment

	def __str__(self):
		return "Recv: (%d, %d, %d, %s)"%(self.buffer_id, self.recv_offset, self.num_received, self.buffer_segment)

class AllocateEvent(Event):
	""" Memory allocated """
	def __init__(self, buffer):
		self.buffer_id = buffer.id
		self.buffer_size = buffer.size
		self.buffer_segment = buffer.segment

	def __str__(self):
		return "Alloc: (%d, %d, %s)"%(self.buffer_id, self.buffer_size, self.buffer_segment)

class DeallocateEvent(Event):
	""" Memory deallocated """
	def __init__(self, buffer):
		self.buffer_id = buffer.id
		self.buffer_size = buffer.size
		self.buffer_segment = buffer.segment

	def __str__(self):
		return "Free: (%d, %d, %s)"%(self.buffer_id, self.buffer_size, self.buffer_segment)

class CallEvent(Event):
	""" Function called """
	def __init__(self, function, fromfunction = None):
		self.dll, self.name = function.resolveToName()
		if fromfunction is None:
			self.fromdll = ""
			self.fromname = "main()"
		else:
			self.fromdll, self.fromname = fromfunction.resolveToName()

	def __str__(self):
		return "Call: (%s, %s) -------> (%s, %s)"%(self.fromdll, self.fromname, self.dll, self.name)

class RetEvent(Event):
	""" Function returned """
	def __init__(self, function):
		self.dll, self.name = function.resolveToName()

	def __str__(self):
		return "Ret: (%s, %s)"%(self.dll, self.name)

class LateRetEvent(Event):
	""" Sometimes functions do not return properly, this event will show that, but later """
	def __init__(self, function):
		self.dll, self.name = function.resolveToName()

	def __str__(self):
		return "LateRet: (%s, %s)"%(self.dll, self.name)

