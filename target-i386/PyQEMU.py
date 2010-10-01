#!/usr/include/python

import traceback
import sys
import os
import pefile
import glob

import PyFlxInstrument
import processinfo
from Structures import *

MONITOR_ACTIVE = True
DEBUG = True

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


MONITOR_NAME = "notepad.exe"

def get_current_process():
	regs = PyFlxInstrument.registers()
	cr3 = regs["cr3"]
	process = KNOWN_Processes[cr3]
	return process

def dump_memory(process, address, len, filename):
	file = open(filename,"a")
	buf = process.backend.read(address, len)+"\x90"*23
	file.write(buf)
	file.close()

def debug(msg):
	global DEBUG
	if DEBUG:
		print msg

def event_update_cr3(old_cr3, new_cr3):
	global KNOWN_Processes	
	#print "type(new_cr3) = "+str(type(new_cr3))
	#print "new_cr3 = "+str(new_cr3)

	#return 1

	kpcr_addr = PyFlxInstrument.creg(R_FS)
	if KNOWN_Processes.has_key(new_cr3):
		#print "Task switch: %08x: " % new_cr3, KNOWN_Processes[new_cr3]
		
		process = KNOWN_Processes[new_cr3]		
		if not process.watched:
			PyFlxInstrument.set_instrumentation_active(0)
			return 1
		
		is_new = False

		if not process.valid:
			#print process.valid
			process.update()

		if process.valid:
			active = process.get_imagefilename().strip("\x00")

			if active.lower() != MONITOR_NAME:
				process.watched = False
				PyFlxInstrument.set_instrumentation_active(0)
				return 1

			try:
				#print "%x -%s-" % (process.get_cur_tid(), active)
				pass				
			except:
				# ignore if we can't get the thread id
				return 1

				#start interactive python shell
				import traceback
				traceback.print_exc()

				import code
				import sys
				#code.interact("Welcome to PyQEMU shell", local=locals())


			if active == MONITOR_NAME and MONITOR_ACTIVE == True:
				PyFlxInstrument.set_instrumentation_active(1)
			#elif last == MONITOR_NAME:
			#	print "inactive"
				

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
			#print "New process: 0x%08x => %s" % (new_cr3, filename)
			if filename == MONITOR_NAME:
				print "New TracedProcess %s"%filename
				p = TracedProcess(proc_event_callbacks)
			else:
				print "New DummyProcess %s"%filename
				p = DummyProcess()
			#print p.get_pid()
				
			#print map(hex, map(ord, filename))
			KNOWN_Processes[new_cr3] = p
			p.watched = True
	
	return 0

class TracedProcess(processinfo.Process):
	""" A traced process with functionality to register callbacks for vm call handling. """
	PROCSTATE_PRERUN = 0
	PROCSTATE_RUN = 1
	CALL_CACHE_SIZE = 100

	def __init__(self, callbacklist):
		self.last_image_num = 0
		self.callbacklist = callbacklist
		self.callbacklist_loaded = False
		self.callcache = []
		self.callonfunction = {}
		self.execution_state = self.PROCSTATE_PRERUN
		self.callcounter = 0
		self.dllhandler = DLLHandler()
		processinfo.Process.__init__(self)

	def handle_syscall(self, eax):
		print "syscall :), eax is %i"%eax

	def handle_call(self, *args):
		if not self.callbacklist_loaded:
			self.loadCallbacks(self.callbacklist)
		if self.execution_state == self.PROCSTATE_PRERUN:
			self._handle_call_prerun(*args)
		elif self.execution_state == self.PROCSTATE_RUN:
			self._handle_call_run(*args)
		else:
			raise Exception("Unknown process execution state")

	def _handle_call_prerun(self, fromaddr, toaddr):
		""" Will be called for every 'call' opcode executed by the vm process. """
		self.callcache.append((fromaddr, toaddr))
		self.callcounter += 1
		if self.callcounter%self.CALL_CACHE_SIZE == 0:
			self.update()
			functioncalls = []
			for src,dst in self.callcache:
				if self.addrInExe(src) and not self.addrInExe(dst):
					image, function = self.dllhandler.getFunctionName(toaddr)
					if image is None or function is None:
						continue
					self.runCallbacks(image.FileName, function)
					self.execution_state = self.PROCSTATE_RUN
			self.callcache = []

	def addrInExe(self, addr):
		image = self.get_image_by_address(addr)
		if image is not None:
			return image.get_basedllname() == self.get_imagefilename().strip("\x00")
		else:
			return False

	def _handle_call_run(self, fromaddr, toaddr):
		if self.execution_state != self.PROCSTATE_RUN:
			raise Exception("called _handle_call_run but process is not ready yet.")
		if self.addrInExe(fromaddr) and not self.addrInExe(toaddr):
			image, function = self.dllhandler.getFunctionName(toaddr)
			if image is None or function is None:
				self.update()
				image, function = self.dllhandler.getFunctionName(toaddr)
			if image is not None and function is not None:
				self.runCallbacks(image.FileName, function)

	def runCallbacks(self, dllname, funcname):
		debug("Call on %s::%s()"%(dllname,funcname))
		if self.callonfunction.has_key(dllname+funcname):
			for callback in self.callonfunction[dllname+funcname]:
				callback()

	def registerFunctionHandler(self, dllname, function, callback):
		""" Registers a function that will be called when vm process calls dllname::funcname(). """
		if self.callonfunction.has_key(dllname+function):
			self.callonfunction[dllname+function].append(callback)
		else:
			self.callonfunction[dllname+function] = [callback]
		return None

	def loadCallbacks(self, callbacklist):
		debug("loadCallbacks %s"%self.get_imagefilename().strip("\x00").lower())
		if callbacklist.has_key(self.get_imagefilename().strip("\x00").lower()):
			for callback in callbacklist[self.get_imagefilename().strip("\x00").lower()]:
				self.registerFunctionHandler(*callback)
		self.callbacklist_loaded = True

	def update(self):
		self._ensure_run(lambda: processinfo.Process.update(self))

	def update_images(self):
		self._ensure_run(lambda: processinfo.Process.update_images(self))
		if len(self.images) > self.last_image_num:
			for image in self.images.values():
				self.dllhandler.newDLL(image)
		self.last_image_um = len(self.images)

	def _ensure_run(self, function):
		try:
			debug("updating process: %s"%self.get_imagefilename().strip("\x00").lower())
		except:
			pass
		counter = 0
		finished = False
		function()

class DummyProcess(processinfo.Process):
	def handle_call(self, *args):
		pass
	def handle_syscall(self, *args):
		pass

class DLLHandler(dict):
	def __init__(self):
		print "initializing DLLHandler"
		self.dlldir = "/mnt/shared/dlls"
		dict.__init__(self)

	def newDLL(self, image):
		try:
			if not self.has_key(image.BaseDllName):
				self[image.BaseDllName] = DLLFile(self.dlldir+"/"+image.BaseDllName.lower(), image.DllBase)
				if self[image.BaseDllName].SizeOfImage != image.SizeOfImage:
					Exception("Local and Guest DLL %s differ!!!!!"%(image.BaseDllName))
		except:
			print "Could not load %s"%image.BaseDllName.strip("\x00").lower()

	def getFunctionName(self, addr):
		for dllname,dll in self.items():
			if dll.ImageBase <= addr and addr <= dll.ImageBase+dll.SizeOfImage:
				if dll.has_key(addr):
					f = dll[addr]
				else:
					f = None
				return dll, f
				if dll is None or f is None:
					print "Could not resolve 0x%x"%addr
		return None, None

class DLLFile(dict):
	def __init__(self, FileName, ImageBase):
		print "initializing DLLFile %s"%FileName
		dict.__init__(self)
		self.filename = os.path.basename(FileName)
		self.FileName = self.filename
		self.ImageBase = ImageBase
		lib = pefile.PE(FileName)
		self.SizeOfImage = lib.OPTIONAL_HEADER.SizeOfImage
		for function in lib.DIRECTORY_ENTRY_EXPORT.symbols:
			self[ImageBase+function.address] = function.name
		del(lib)

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

# Implement Process event Callbacks here

def notepad_msvcrt_exit():
	print "NOTEPAD CALLED EXIT!"

def notepad_user32_getmessagew():
	print "NOTEPAD CALLED GETMESSAGEW"

# Register Process event Callbacks
proc_event_callbacks = {
	"notepad.exe": [
					("msvcrt.dll","exit", notepad_msvcrt_exit),
					("user32.dll","GetMessageW",notepad_user32_getmessagew)
				   ]
}

def call_info(origin_eip, dest_eip):
	p = get_current_process()
	return p.handle_call(origin_eip, dest_eip)

# Register FLX Callbacks 
ev_syscall = ensure_error_handling_helper(lambda *args: get_current_process().handle_syscall(*args))
ev_call = ensure_error_handling_helper(lambda *args: get_current_process().handle_call(*args))
ev_update_cr3 = ensure_error_handling_helper(event_update_cr3)


