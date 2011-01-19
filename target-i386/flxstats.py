#!/usr/bin/env python
import re
import sys

class Function:
	def __init__(self, name):
		self.name = name
		self.calls_made_outside = []
		self.calls_made_inside = []
		self.called = 0
		self.marked = False

class FlxLogParser:
	p_regex = re.compile("Process: ([0-9]+)")
	t_regex = re.compile("Thread: ([0-9]+)")
	e_regex = re.compile(" ([a-zA-Z]+): \\(")
	from_regex = re.compile("\\((.*)\\) --")
	to_regex   = re.compile("-> \\((.*)\\)")

	def __init__(self, logfile, imagename):
		self.logfile = logfile
		self.imagename = imagename
		self.functions = {}

	def parse(self):
		current_line = None
		for lookahead in self.logfile:
			if current_line is None:
				current_line = lookahead
				continue
			else:
				if not "Resolved" in lookahead:
					self.parseLine(current_line)
			current_line = lookahead
		self.parseLine(lookahead)

	def getPid(self, line):
		return self.p_regex.search(line).group(1)
	def getTid(self, line):
		return self.t_regex.search(line).group(1)
	def getEvent(self, line):
		return self.e_regex.search(line).group(1)
	def getFrom(self, line):
		return self.from_regex.search(line).group(1)
	def getTo(self, line):
		return self.to_regex.search(line).group(1)


	def parseLine(self, line):
		if "Resolved" in line:
			return
		else:
			if self.getEvent(line).lower() != "call":
				return
			call_from = self.getFrom(line)
			call_to   = self.getTo(line)
			if not self.functions.has_key(call_from):
				self.functions[call_from] = Function(call_from)
			if call_to.startswith(self.imagename) and not self.functions.has_key(call_to):
				self.functions[call_to] = Function(call_to)

			if call_to.startswith(self.imagename):
				self.functions[call_from].calls_made_inside.append(call_to)
				self.functions[call_to].called += 1
			else:
				self.functions[call_from].calls_made_outside.append(call_to)

	def printStats(self):
		print "DLL | NAME | CALLS INSIDE | CALLS OUTSIDE | CALLED"
		for key,value in self.functions.items():
			print "%s ,\t%d,\t%d,\t%d"%(value.name, len(value.calls_made_inside), len(value.calls_made_outside), value.called)

	def printNonOutsideCalling(self):
		for key,value in self.functions.items():
			if len(value.calls_made_outside) == 0:
				print value.name

	def printNonCalling(self):
		for key,value in self.functions.items():
			if len(value.calls_made_outside) == 0 and len(value.calls_made_inside) == 0:
				print value.name

	def printNonTransitiveOutsideCalling(self):
		for key,value in self.functions.items():
			if len(value.calls_made_outside) > 0:
				self.functions[key].marked = True

		change_happened = True
		while change_happened:
			change_happened = False
			for key,value in self.functions.items():
				if value.marked == True:
					continue
				else:
					for k,v in self.functions.items():
						if v.name in value.calls_made_inside:
							value.marked = True
							change_happened = True
		for key, value in self.functions.items():
			if value.marked == False:
				print "Name: "+value.name+" Called: %d"%value.called
				

def usage():
	print "%s <logfile> <image name>"%sys.argv[0]

if __name__ == "__main__":
	if len(sys.argv) < 3:
		usage()
	else:
		p = FlxLogParser(open(sys.argv[1],"r"), sys.argv[2])
		p.parse()
		#p.printNonOutsideCalling()
		#p.printNonCalling()
		p.printNonTransitiveOutsideCalling()
