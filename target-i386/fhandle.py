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
		function.addReturnCallback(self.onLeave)

class WinExecFunctionHandler(FunctionHandler):
	def onEnter(self, function):
		self.cmdline = STR(self.process.backend, function.getIntArg(1))
		self.cmdshow = function.getIntArg(1)
		self.addPendingReturn(function)

	def onLeave(self, function):
		retval = function.retval()
		if retval > 31:
			print "WinExec('%s')"%self.cmdline
		else:
			print "WinExec returned Error!"

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
	def onEnter(self, function):
		self.addPendingReturn(function)
		self.size = function.getIntArg(1)
	
	def onLeave(self, function):
		addr = function.retval()
		if addr != NULL:
			buffer = self.process.memory.heap.allocate(addr, self.size)
			self.process.log(AllocateEvent(buffer))

class RtlAllocateHeapFunctionHandler(FunctionHandler):
	def onEnter(self, function):
		self.addPendingReturn(function)
		self.size = function.getIntArg(3)
	
	def onLeave(self, function):
		addr = function.retval()
		buffer = self.process.memory.heap.allocate(addr, self.size)
		self.process.log(AllocateEvent(buffer))
		self.process.log("Alloc 0x%x"%addr)

class LocalAllocFunctionHandler(FunctionHandler):
	def onEnter(self, function):
		self.addPendingReturn(function)
		self.size = function.getIntArg(2)

	def onLeave(self, function):
		addr = function.retval()
		if addr != NULL:
			buffer = self.process.memory.heap.allocate(addr, self.size)
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
			#self.process.log(DeallocateEvent("unknown: 0x%x"%addr))
			self.process.log("Freeing unknown: 0x%x"%addr)

class RtlFreeHeapFunctionHandler(FunctionHandler):
	def onEnter(self, function):
		self.addPendingReturn(function)
		self.addr = function.getIntArg(3)
		self.flags= function.getIntArg(2)

	def onLeave(self, function):
		retval = function.retval()
		if retval != 0:
			if self.process.memory.heap.allocated(self.addr):
				buffer = self.process.memory.heap.getBuffer(self.addr)
				self.process.log(DeallocateEvent(buffer))
				self.process.memory.heap.deallocate(self.addr)
			elif self.addr != NULL:
				print "Free of unknown Buffer 0x%x"%self.addr


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
			print "return value: %d"%ret

class WSAGetLastErrorFunctionHandler(FunctionHandler):
	def onLeave(self, function):
		ret = function.retval()
		print "WSAGetLastError() returned: %d"%ret

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
		dst_buffer.sizeHint(len)
		self.process.log(CopyEvent(dst_buffer, src_buffer, min(src_buffer.size, len ), dst, src))

class StrCpyFunctionHandler(CpyFunctionHandler):
	def onEnter(self, function, stringtype = STR):
		src = function.getIntArg(2)
		CpyFunctionHandler.onEnter(self, function, len=len(stringtype(self.process.backend, src)))

class StrNCpyFunctionHandler(CpyFunctionHandler):
	def onEnter(self, function, stringtype = STR, maxlen = -1):
		src = function.getIntArg(2)
		CpyFunctionHandler.onEnter(self, function, len=min(maxlen, len(stringtype(self.process.backend, src))))

class lstrcpyWFunctionHandler(StrCpyFunctionHandler):
	def onEnter(self, function, stringtype = WSTR):
		StrCpyFunctionHandler.onEnter(self, function, stringtype)

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

class WcsNCpyFunctionHandler(StrNCpyFunctionHandler):
	def onEnter(self, function):
		len = function.getIntArg(3)
		StrNCpyFunctionHandler.onEnter(self, function, WSTR, len)

class StrLenFunctionHandler(FunctionHandler):
	def onEnter(self, function):
		self.addPendingReturn(function)
		self.addr = function.getIntArg(1)

	def onLeave(self, function):
		len = function.retval()
		buffer = self.process.memory.getBuffer(self.addr)
		buffer.sizeHint(len)

class lstrlenWFunctionHandler(StrLenFunctionHandler):
	def onEnter(self, function):
		StrLenFunctionHandler.onEnter(self, function)

	def onLeave(self, function):
		len = function.retval()*2 # unicode
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

# Heap allocation functions to get real origin on buffer allocation
# O(n) :(
heap_allocation_functions = [
				("msvcrt.dll",  "malloc"),
				("kernel32.dll", "HeapAlloc"),
				("ole32.dll", "CoTaskMemAlloc"),
				("msvcrt.dll", "realloc"),
				("msvcrt.dll", "_strdup"),
				("msvcrt.dll", "calloc"),
							]

HOOKS = [
				("msvcrt.dll",  "malloc",  HeapAllocationFunctionHandler),
				("msvcrt.dll",  "free",    HeapFreeFunctionHandler),
				("wsock32.dll", "recv",    WSARecvFunctionHandler),
				("wsock32.dll", "send",    SendFunctionHandler),
				("ws2_32.dll",  "WSARecv", WSARecvFunctionHandler),
				("ws2_32.dll",  "send",    SendFunctionHandler),
				("ws2_32.dll",  "recv",    RecvFunctionHandler),
				("ws2_32.dll",  "connect", ConnectFunctionHandler),
				("msvcrt.dll",  "strcpy",  StrCpyFunctionHandler),
				("kernel32.dll", "lsrcpyA",  StrCpyFunctionHandler),
				("msvcrt.dll",  "strncpy", NCpyFunctionHandler),
				("msvcrt.dll",  "memcpy",  NCpyFunctionHandler),
				("kernel32.dll", "RaiseException", RaiseFunctionHandler),
				("kernel32.dll", "HeapAlloc" , HeapAllocationFunctionHandler),
				("ole32.dll", "CoTaskMemAlloc", HeapAllocationFunctionHandler),
				("msvcrt.dll", "realloc",  ReallocFunctionHandler),
				("msvcrt.dll", "_strdup",  StrDupFunctionHandler),
				("msvcrt.dll", "calloc",   CallocFunctionHandler),
				("ntdll.dll",  "memmove",  NCpyFunctionHandler),
				("msvcrt.dll", "wcscat",   WcsCatFunctionHandler),
				("msvcrt.dll", "wcscpy",  WcsCpyFunctionHandler),
				("msvcrt.dll", "wcslen",   WcsLenFunctionHandler),
				("ntdll.dll",  "wcscpy",   WcsCpyFunctionHandler),
				("ntdll.dll",  "wcslen",   WcsLenFunctionHandler),
				("msvcrt.dll", "strlen",   StrLenFunctionHandler),
				("msvcrt.dll", "strcat",   StrCatFunctionHandler),
				("kernel32.dll",  "LoadLibrary", LoadLibraryFunctionHandler),
				("kernel32.dll",  "LoadLibraryA", LoadLibraryAFunctionHandler),
				("kernel32.dll",  "LoadLibraryW", LoadLibraryWFunctionHandler),
				("kernel32.dll",  "LoadLibraryExA", LoadLibraryExAFunctionHandler),
				("kernel32.dll",  "LoadLibraryExW", LoadLibraryExWFunctionHandler),
				#("kernel32.dll",  "CreateThread", CreateThreadFunctionHandler),
				("kernel32.dll",  "lstrcpyA", StrCpyFunctionHandler),
				("kernel32.dll",  "lstrcpyW", lstrcpyWFunctionHandler),
				("kernel32.dll",  "lstrlenA", StrLenFunctionHandler),
				("kernel32.dll",  "lstrlenW", lstrlenWFunctionHandler),
				("kernel32.dll",  "LocalAlloc", LocalAllocFunctionHandler),
				("kernel32.dll",  "LocalFree", HeapFreeFunctionHandler),
				("kernel32.dll",  "GlobalAlloc", LocalAllocFunctionHandler),
				("kernel32.dll",  "GlobalFree", HeapFreeFunctionHandler),
				("msvcrt.dll",   "wcsncpy",   WcsNCpyFunctionHandler),
				("ntdll.dll",    "wcsncpy",    WcsNCpyFunctionHandler),
				("ntdll.dll",  "RtlFreeHeap", RtlFreeHeapFunctionHandler),
				("ntdll.dll",  "RtlAllocateHeap", RtlAllocateHeapFunctionHandler),
				("ntdll.dll",  "FreeHeap"       , HeapFreeFunctionHandler),
				("ntdll.dll",  "AllocateHeap"   , HeapAllocationFunctionHandler),
				("ole32.dll",  "CoTaskMemAlloc" , HeapAllocationFunctionHandler),
				("ole32.dll",  "CoTaskMemFree"  , HeapFreeFunctionHandler),
				("ws2_32.dll", "WSAGetLastError", WSAGetLastErrorFunctionHandler),
				("kernel32.dll", "WinExec", WinExecFunctionHandler),
]
