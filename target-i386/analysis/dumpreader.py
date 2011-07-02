#!/usr/bin/env python

import glob
import struct

class Dumpfile:
	MEM_ACCESS = 0
	FUNCTION   = 1

	def __init__(self, filename):
		self.name, self.pid, self.tid = filename.split(" ")[:3]
		self.filename = filename
		self.dumpfile = open(filename,"r")

	def get_bytes(self, count):
		bytes = self.dumpfile.read(count)
		if len(bytes) < count:
			raise Exception("READ ERROR in file: %s"%self.filename)

	def next(self):
		event_type = self.get_bytes(1)

	def read_function_event(self):
	def read_memory_event(self):
		
		
		

class Dumpreader(list):
	def __init__(self, path):
		list.__init__(self)
		dumpfiles = glob.glob(path+"/*.dump")
		for dumpfile in dumpfiles:
			self.append(Dumpfile(dumpfile))
