#!/usr/include/python

import traceback
import sys

import PyFlxInstrument
import processinfo
from Structures import *

MONITOR_ACTIVE = True

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
			p = processinfo.Process()
			#print p.get_pid()
				
			#print map(hex, map(ord, filename))
			KNOWN_Processes[new_cr3] = p
			p.watched = True
	
	return 0

def update_workaround(process):
	print "updating"
	try:
		process.update()
	except:
		pass

call_list = []
call_counter = 1
def call_info_prerun(fromaddr, toaddr, process):
	"""returns image,function on calls from main executable into dll/itself"""
	global call_list
	global call_counter
	call_list.append((fromaddr,toaddr))
	if call_counter%10000 != 0:
		call_counter += 1
	else:
		call_counter += 1
		functioncalls = []
		update_workaround(process)
		for fromaddr,toaddr in call_list:
			from_image = process.get_image_by_address(fromaddr)
			to_image   = process.get_image_by_address(toaddr)
			if from_image is not None and to_image is not None:
				from_image_name = from_image.get_basedllname()
				to_image_name = to_image.get_basedllname()
				procname = process.get_imagefilename().strip("\x00")
				if from_image_name == procname and to_image_name != procname:
					functioncalls.append((to_image, process.symbols[toaddr][2]))
		if not len(functioncalls) == 0:
			return functioncalls
	return None

def call_info_run(fromaddr, toaddr, process):
	from_image = process.get_image_by_address(fromaddr)
	to_image   = process.get_image_by_address(toaddr)
	if from_image is not None and to_image is not None:
		from_image_name = from_image.get_basedllname()
		to_image_name = to_image.get_basedllname()
		procname = process.get_imagefilename().strip("\x00")
		if from_image_name == procname and to_image_name != procname:
			try:
				return [(to_image, process.symbols[toaddr][2])]
			except:
				return [(to_image, None)]
	return None

call_info = call_info_prerun
def call_event_callback(origin_eip, dest_eip):
	global call_info
	process = get_current_process()
	functioncalls = call_info(origin_eip, dest_eip, process)
	if functioncalls is not None:
		call_info = call_info_run
		for image,function in functioncalls:
			if function is None:
				function = "unknown function"
			print "Process: %s\t\t%s::%s()"%(process.get_imagefilename().strip("\x00"), image.get_basedllname(), function)
	return 0

#	if userspace(origin_eip) and userspace(dest_eip):
#		image,function = call_info(origin_eip, dest_eip, process)
#		if image is not None:
#			if function is None:
#				function = "Unknown"
#			print "Call into Image: %s\nFunction: %s\nPID: %s\n"%(image.getbasedllname(), function, process.pid)
#	return 0

#last_tid = 0
#def call_event_callback(origin_eip, dest_eip):
#	global last_tid
#	if dest_eip < 0x80000000 and origin_eip < 0x70000000:
#		print "PyCall: %08x -> %08x" % (origin_eip, dest_eip)
#		regs = PyFlxInstrument.registers()
#		cr3 = regs["cr3"]
#		if KNOWN_Processes.has_key(cr3):
#			process = KNOWN_Processes[cr3]
#			dllimage = call_into_image(dest_eip, origin_eip, process)
#			if dllimage is not None:
#				print "call into %s in process: "%(dllimage.getbasedllname(), process.get_imagefilename().strip("\x00").lower())
#			new_tid = process.get_cur_tid()
#			if new_tid > 0 and new_tid != last_tid:				
#				print "Thread switch: %x -> %x" % (last_tid, new_tid)
#				last_tid = new_tid
#
#	return 0

#def call_event_callback(src_eip, dst_eip):
#	print "call: %x -> %x"%(src_eip,dst_eip)


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

ev_call = ensure_error_handling_helper(call_event_callback)
ev_update_cr3 = ensure_error_handling_helper(event_update_cr3)
