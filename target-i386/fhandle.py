#!/usr/include/python

import traceback
import sys
import os
import glob
import struct
import pickle
import avl
import gc
import copy
import guppy
import cProfile
import threading
import Queue

import event
from event import *
import PyFlxInstrument
import processinfo
from Structures import *
import Structures
from dllhandling import *
import dllhandling
import syscalls
from fhandle import *

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

class RecvFunctionHandler(FunctionHandler):
	def onEnter(self, function):
		self.addPendingReturn(function)
		self.addr = function.getIntArg(2)

	def onLeave(self, function):
		self.sent = function.retval()
		self.buffer = self.process.memory.getBuffer(self.addr)
		if self.sent > 0:
			self.process.log(RecvEvent(self.buffer, self.addr, self.sent))
			pass


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

class LoadLibraryFunctionHandler(FunctionHandler):
	def onEnter(self, function):
		filename = function.getIntArg(1)		
		try:
			print "LoadLibrary(%s)"%STR(self.process.backend, filename)
		except PageFaultException:
			pass

class LoadLibraryAFunctionHandler(FunctionHandler):
	def onEnter(self, function):
		filename = function.getIntArg(1)		
		try:
			print "LoadLibraryA(%s)"%STR(self.process.backend, filename)
		except PageFaultException:
			pass

class LoadLibraryWFunctionHandler(FunctionHandler):
	def onEnter(self, function):
		filename = function.getIntArg(1)		
		try:
			print "LoadLibraryW(%s)"%WSTR(self.process.backend, filename)
		except PageFaultException:
			pass

class LoadLibraryExAFunctionHandler(LoadLibraryAFunctionHandler):
	def onEnter(self, function):
		LoadLibraryAFunctionHandler.onEnter(self,function)

class LoadLibraryExWFunctionHandler(LoadLibraryWFunctionHandler):
	def onEnter(self, function):
		LoadLibraryWFunctionHandler.onEnter(self,function)


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
				self.buffer.sizeHint(len)
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
		buffer = self.process.memory.getBuffer(self.addr)
		buffer.sizeHint(self.len)
		buffer.update()
		if bytes_sent > 0:
			buffer = self.process.memory.getBuffer(self.addr)
			self.process.log(SendEvent(buffer, self.addr, self.len, bytes_sent))
		else:
			pass
			#error occured

class ConnectFunctionHandler(FunctionHandler):
	def onEnter(self, function):
		self.addPendingReturn(function)
		self.socket   = function.getIntArg(1)
		self.sockaddr = function.getIntArg(2)
		self.len      = function.getIntArg(3)

	def onLeave(self, function):
		ret = function.retval()
		ip = ".".join(map(str,map(ord, self.process.readmem(self.sockaddr+4, 4))))
		port = struct.unpack(">H", self.process.readmem(self.sockaddr+2, 2))
		print "Connection to ip: %s"%ip
		print "Connection to port: %d"%port
		print "length was: %d"%self.len
		if ret == 0:
			print "connection established"
		else:
			print "connection failed"

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
		src_buffer.sizeHint(len)
		dst_buffer.sizeHint(len)
		self.process.log(CopyEvent(dst_buffer, src_buffer, len, dst, src))

class StrCpyFunctionHandler(CpyFunctionHandler):
	def onEnter(self, function, stringtype = STR):
		src = function.getIntArg(2)
		CpyFunctionHandler.onEnter(self, function, len=len(stringtype(self.process.backend, src)))

class StrCatFunctionHandler(FunctionHandler):
	def onEnter(self, function, stringtype = STR):
		dst = function.getIntArg(1)
		src = function.getIntArg(2)
		src_buffer = self.process.memory.getBuffer(src)
		dst_buffer = self.process.memory.getBuffer(dst)
		srclen = len(stringtype(self.process.backend, src))
		dstlen = len(stringtype(self.process.backend, dst))
		src_buffer.sizeHint(srclen)
		dst_buffer.sizeHint(dstlen+srclen)
		self.process.log(CopyEvent(dst_buffer, src_buffer, srclen, dst+srclen, src))

class WcsCatFunctionHandler(StrCatFunctionHandler):
	def onEnter(self, function):
		StrCatFunctionHandler.onEnter(self, function, WSTR)

class WcsCpyFunctionHandler(StrCpyFunctionHandler):
	def onEnter(self, function):
		StrCpyFunctionHandler.onEnter(self, function, WSTR)

class StrLenFunctionHandler(FunctionHandler):
	def onEnter(self, function):
		self.addPendingReturn(function)
		self.addr = function.getIntArg(1)

	def onLeave(self, function):
		len = function.retval()
		buffer = self.process.memory.getBuffer(self.addr)
		buffer.sizeHint(len)

class WcsLenFunctionHandler(FunctionHandler):
	def onEnter(self, function):
		self.addPendingReturn(function)
		self.addr = function.getIntArg(1)

	def onLeave(self, function):
		len = function.retval()
		len = len*2
		buffer = self.process.memory.getBuffer(self.addr)
		buffer.sizeHint(len)

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

class CreateThreadFunctionHandler(FunctionHandler):
	""" Handles strdup like functions """
	def onEnter(self, function):
		self.addPendingReturn(function)
		self.process.registerCreateThreadCall()

	def onLeave(self, function):
		self.threadhandle = function.retval()
		if self.threadhandle == NULL:
			self.process.unregisterCreateThreadCall()

class RaiseFunctionHandler(FunctionHandler):
	""" we have to notice exceptions later to keep callstack up to date """
	def onEnter(self, function):
		raise Exception("Program raised Exception via %s"%function)
