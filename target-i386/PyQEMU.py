#!/usr/include/python

import traceback
import json
import sys
import io
import os as pyos
import glob
import struct
import pickle
import avl
import gc
import copy
import Queue
import random
import time

import PyFlxInstrument
import pyqemu.processinfo
import pyqemu.syscalls
from pyqemu.Structures import *
from pyqemu.dll import *
from pyqemu.event import *
from pyqemu.fhandle import *
from pyqemu.config import *
from pyqemu.cpu import QemuCPU
from pyqemu.msg import *
from pyqemu.memory import QemuMemory
from pyqemu.instrumentation import QemuInstrumentation
from pyqemu.operatingsystem import OperatingSystem

class QemuFlxLogger:
	BUFFERSIZE = 1000
	def __init__(self, config):
		self.config = config
		self.logfiles = {}
		self.starttimes = {}

	def error(self, message):
		print "ERROR: %s"%message
	def warning(self, warning):
		print "WARNING: %s"%message
	def info(self, message):
		print "INFO: %s"%message
	def debug(self, message):
		if self.config["debug"] == 1:
			print "DEBUG: %s"%message

	def buildLogfile(self, process):
		if not self.starttimes.has_key(process.pid):
			self.starttimes[process.pid] = time.asctime()
		timestamp = self.starttimes[process.pid]
		logfile = "%s-%s-%s.log"%(process.imagefilename(),process.cur_tid,timestamp)
		logfile = self.config["logger"]["logdir"]+"/"+logfile
		return logfile
		

	def getLogfile(self, process):
		index = hash((process.imagefilename(), process.cur_tid))
		if not self.logfiles.has_key(index):
			logfile = self.buildLogfile(process)
			self.logfiles[index] = io.open(logfile,"w")
		return self.logfiles[index]

	def shutdown(self, process = None):
		if not process:
			print "SHUTTING DOWN!!!"
			self.closeAll()
		else:
			self.getLogfile(process).flush()
			self.getLogfile(process).close()

	def handleProcessEvent(self, obj, process):
		self.getLogfile(process).write(u"%s\n"%obj)

	def closeAll(self):
		for key,value in self.logfiles.items():
			try:
				value.flush()
				value.close()
				del(self.logfiles[key])
			except ValueError:
				continue

	def __del__(self):
		self.closeAll()

class Qemu:
	def __init__(self):
		self.cpu = QemuCPU()
		self.memory = QemuMemory()
		self.instrumentation = QemuInstrumentation()

class VirtualMachine:
	def __init__(self, configfile):
		self.loadConfiguration(configfile)

		self.logger = QemuFlxLogger(self.config)
		self.qemu   = Qemu()
		self.os     = OperatingSystem(self.config, self.qemu, self.logger)

	def loadConfiguration(self, configfile):
		print "Loading configuration from: %s"%configfile
		self.config = ConfigLoaderFactory.create("json", configfile, QemuFlxConfig)

	def handleQemuEvent(self, ev, *args):
		if ev == "shutdown":
			self.logger.shutdown()
		else:
			event = createEventObject(ev, *args)
			self.os.handleEvent(event)

vm = None
def init(sval):	
	global vm
	try:
		print "Python instrument started"
		if pyos.getenv("PYQEMU_DISABLE") is None:
			print "Initializing Python Virtual Machine"
			vm = VirtualMachine("/etc/qemuflx/flx.json")
			return 0
	except:
		traceback.print_exception(*sys.exc_info())
		import code
		code.interact("DBG",local = locals())
		sys.exit(-1)
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

def getVirtualMachine():
	return vm

# Register FLX Callbacks 
ev_syscall    = ensure_error_handling_helper(lambda *args: getVirtualMachine().handleQemuEvent("syscall",*args))
ev_call       = ensure_error_handling_helper(lambda *args: getVirtualMachine().handleQemuEvent("call",*args))
ev_jmp        = ensure_error_handling_helper(lambda *args: getVirtualMachine().handleQemuEvent("jmp",*args))
ev_ret        = ensure_error_handling_helper(lambda *args: getVirtualMachine().handleQemuEvent("ret",*args))
ev_bp         = ensure_error_handling_helper(lambda *args: getVirtualMachine().handleQemuEvent("breakpoint",*args))
ev_memtrace   = ensure_error_handling_helper(lambda *args: getVirtualMachine().handleQemuEvent("memtrace",*args))
ev_optrace    = ensure_error_handling_helper(lambda *args: getVirtualMachine().handleQemuEvent("optrace",*args))
ev_bblstart   = ensure_error_handling_helper(lambda *args: getVirtualMachine().handleQemuEvent("bbl",*args))

ev_update_cr3 = ensure_error_handling_helper(lambda *args: getVirtualMachine().handleQemuEvent("schedule",*args))
ev_shutdown = ensure_error_handling_helper(lambda *args: getVirtualMachine().handleQemuEvent("shutdown",*args))
ev_arithwindow = ensure_error_handling_helper(lambda *args: getVirtualMachine().handleQemuEvent("arithwindow",*args))

ev_caballero = ensure_error_handling_helper(lambda *args: getVirtualMachine().handleQemuEvent("caballero",*args))
ev_functiontrace = ensure_error_handling_helper(lambda *args: getVirtualMachine().handleQemuEvent("functiontrace",*args))
