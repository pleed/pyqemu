#!/usr/include/python

import traceback
import sys
import os
import dislib
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
	CALL_CACHE_SIZE = 10000

	def __init__(self, callbacklist):
		self.callbacklist = callbacklist
		self.callbacklist_loaded = False
		self.callcache = []
		self.callonfunction = {}
		self.execution_state = self.PROCSTATE_PRERUN
		self.callcounter = 0
		self.dllhandler = None
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
				from_image = self.get_image_by_address(src)
				to_image   = self.get_image_by_address(dst)
				if from_image is not None and to_image is not None:
					from_image_name = from_image.get_basedllname()
					to_image_name   = to_image.get_basedllname()
					pname = self.get_imagefilename().strip("\x00")
					if from_image_name == pname and to_image_name != pname:
						if self.symbols.has_key(toaddr):
							functioncalls.append((to_image, self.symbols[toaddr][2]))
			self.callcache = []
			if not len(functioncalls) == 0:
				for image,func in functioncalls:
					self.runCallbacks(image.get_basedllname(), func)
				self.execution_state = self.PROCSTATE_RUN

	def _handle_call_run(self, fromaddr, toaddr):
		if self.execution_state != self.PROCSTATE_RUN:
			raise Exception("called _handle_call_run but process is not ready yet.")
		from_image = self.get_image_by_address(fromaddr)
		to_image   = self.get_image_by_address(toaddr)
		if from_image is not None and to_image is not None:
			from_image_name = from_image.get_basedllname()
			to_image_name   = to_image.get_basedllname()
			pname = self.get_imagefilename().strip("\x00")
			if from_image_name == pname and to_image_name != pname:
				if not self.symbols.has_key(toaddr):
					self.update_images()
				try:
					self.runCallbacks(to_image.get_basedllname(), self.symbols[toaddr][2])
				except:
					pass
					
	def runCallbacks(self, dllname, funcname):
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

	def _ensure_run(self, function):
		try:
			debug("updating process: %s"%self.get_imagefilename().strip("\x00").lower())
		except:
			pass
		counter = 0
		finished = False
		while not finished and counter < 5:
			try:
				function()
				finished = True
			except:
				continue

class DummyProcess(processinfo.Process):
	def handle_call(self, *args):
		pass
	def handle_syscall(self, *args):
		pass

class DLLHandler(dict):
	def __init__(self, dlldir, images):
		print "initializing DLLHandler"
		self.symbols = {}
		dict.__init__(self)
		self._loadDllFiles(dlldir, images)

	def _loadDllFiles(self,dlldir, images):
		files = glob.glob(dlldir+"/*.dll")
		for image in images:
			try:
				self[image.BaseDllName] = DLLFile(dlldir+"/"+image.BaseDllName, image.DllBase)
				debug("%s loaded"%image.BaseDllName)
			except:
				pass

class DLLFile(dislib.PEFile, dict):
	def __init__(self, FileName, NewImageBase=None):
		print "initializing DLLFile"
		print "filename "+FileName
		dict.__init__(self)
		dislib.PEFile.__init__(self, FileName, NewImageBase)
		self._loadSymbols()
		self.filename = os.path.basename(FileName)

	def _loadSymbols(self):
		for function in self.Exports:
			self[function.VA+function.Ordinal] = function.Name

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
					("USER32.dll","GetMessageW",notepad_user32_getmessagew)
				   ]
}

def call_info(origin_eip, dest_eip):
	p = get_current_process()
	return p.handle_call(origin_eip, dest_eip)

# Register FLX Callbacks 
ev_syscall = ensure_error_handling_helper(lambda *args: get_current_process().handle_syscall(*args))
ev_call = ensure_error_handling_helper(lambda *args: get_current_process().handle_call(*args))
ev_update_cr3 = ensure_error_handling_helper(event_update_cr3)


