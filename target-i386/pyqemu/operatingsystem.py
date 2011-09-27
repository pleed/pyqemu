#!/usr/bin/env python

from msg import *
from process import *
import heuristics
from heuristics import *
import controls
from controls import *

class OperatingSystem:
	""" Represents the guest operating system state and configuration """
	def __init__(self, config, hardware, logger):
		self.config = config
		self.hardware = hardware

		self.active_process = None
		self.terminating_processes = []
		self.processes = {}
		self.logger = logger

	def shutdown(self):
		for process in self.processes.values():
			if isinstance(process, UntracedProcess):
				continue
			process.shutdown()

	def handleEvent(self, event):
		if event.event_type == "schedule":
			self.schedule(event)
			try:
				if not self.active_process.isRegisteredThread():
					self.active_process.createNewThread()
			except:
				pass
		else:
			if not self.active_process.isRegisteredThread():
				self.active_process.createNewThread()
			self.active_process.handleEvent(event)

	def schedule(self, event):
		self.exitPendingProcesses()
		try:
			self.active_process = self.processes[event.cur]
		except KeyError:
			return self.createProcess(event.cur)
		if not self.active_process.watched:
			self.hardware.instrumentation.deactivate()
			return 0

		if not self.active_process.valid:
			self.active_process.update()
		else:
			if isinstance(self.active_process, UntracedProcess):
				self.active_process.watched = False
				self.hardware.instrumentation.deactivate()
			else:
				try:
					self.hardware.instrumentation.activate(self.active_process.pid, self.active_process.cur_tid, "instrumented")
				except:
					self.hardware.instrumentation.activate(-1, -1, "instrumented")

	def createProcess(self, cr3):
		kpcr_addr = self.hardware.cpu.fs
		if kpcr_addr > 0xf0000000:
			backend = VMemBackend(0, 0x100000000)
			filename = ""
			try:
				kpcr = KPCR(backend, kpcr_addr)
				filename = kpcr.PrcbData.CurrentThread.deref().ApcState.Process.deref().ImageFileName
			except:
				return -1
			filename = filename.replace("\x00", "")
			if len(filename) > 0:
				if filename.lower() in map(lambda x: x.lower(), self.config["os"]["processes"].keys()):
					self.logger.info("New Traced Process: %s"%filename)
					
					self.active_process = TracedProcess(self.config["os"]["processes"][filename], self, self.logger, filename, self.hardware)
					self.setupControls(self.active_process)
					self.setupHeuristics(self.active_process)
					self.hardware.instrumentation.retranslate()
					self.hardware.instrumentation.activate(-1,-1, "instrumented")

				else:
					self.logger.info("New Process: %s"%filename)
					self.active_process = UntracedProcess([])
					self.hardware.instrumentation.deactivate()
				self.processes[cr3] = self.active_process
				self.active_process.watched = True
		return 0

	def setupHeuristics(self, process):
		for heuristic,options in self.config["os"]["heuristics"].items():
			module = __import__("pyqemu")
			module = getattr(module, "heuristics")
			module = getattr(module, heuristic)
			heuristic_class = getattr(module,"heuristic")
			self.logger.info("Activating heuristic: %s"%heuristic)
			heuristic_class(process, self.config["os"]["heuristics"][heuristic])

	def setupControls(self, process):
		module  = __import__("pyqemu")
		module  = getattr(module, "controls")
		modules = getattr(module, "__all__")
		for mod in modules:
			control = getattr(module, mod)
			control_class = getattr(control, "control")
			if control_class is not None:
				self.logger.info("Activating control: %s"%mod)
				control_class(process, self.config["os"])

	def exitPendingProcesses(self):
		for process,cr3 in self.terminating_processes:
			self.processes[cr3] = UntracedProcess([])	
			del(process)
