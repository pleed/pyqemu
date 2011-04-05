#!/usr/include/python

import traceback
import json
import sys
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
from pyqemu.dllhandling import *
from pyqemu.event import *
from pyqemu.fhandle import *
from pyqemu.config import *
from pyqemu.cpu import QemuCPU
from pyqemu.msg import *
from pyqemu.memory import QemuMemory
from pyqemu.instrumentation import QemuInstrumentation
from pyqemu.os import OperatingSystem

class QemuFlxLogger:
	def __init__(self, config):
		self.config = config

	def error(self, message):
		print "ERROR: %s"
	def warning(self, warning):
		print "WARNING: %s"
	def info(self, message):
		print "INFO: %s"
	def debug(self, message):
		if self.config["debug"] == 1:
			print "DEBUG: %s"%message

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
