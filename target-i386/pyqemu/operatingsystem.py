#!/usr/bin/env python

from msg import *
from process import *
import heuristics

class OperatingSystem:
	def __init__(self, config, hardware, logger):
		self.config = config
		self.hardware = hardware

		self.active_process = None
		self.terminating_processes = []
		self.processes = {}
		self.logger = logger

	def handleEvent(self, event):
		if event.event_type == "schedule":
			self.schedule(event)
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
				return 0
			else:
				self.hardware.instrumentation.activate()

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
					self.setupHeuristics(self.active_process)
					self.hardware.instrumentation.retranslate()
					self.hardware.instrumentation.activate()

				else:
					self.logger.info("New Process: %s"%filename)
					self.active_process = UntracedProcess([])
					self.hardware.instrumentation.deactivate()
				self.processes[cr3] = self.active_process
				self.active_process.watched = True
		return 0

	def setupHeuristics(self, process):
		for heuristic,options in self.config["os"]["heuristics"].values():
			module = __import__("heuristics."+heuristic)
			heuristicmodule = getattr(module,heuristic)
			heuristic_class = getattr(heuristicmodule,"heuristic")
			heuristic_class(process, self.config["os"]["heuristics"][heuristic])

	def exitPendingProcesses(self):
		for process,cr3 in self.terminating_processes:
			self.processes[cr3] = UntracedProcess([])	
			del(process)
