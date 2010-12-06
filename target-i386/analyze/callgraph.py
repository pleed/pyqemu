#!/usr/bin/env python

import pygraphviz as pgv
import sys

class CallGraphAnalyzer:
	def __init__(self, dumpfile):
		self.dumpfile = dumpfile
		self.threads = {}

	def parseLine(self, line):
		line = line.strip()
		if not ", Call:" in line and not ", Ret:" in line:
			return None
		p,t,e = line.split(",")
		print str(p)
		print str(t)
		print str(e)
		p = p.split(":")[1][1:]
		t = t.split(":")[1][1:]
		e,a = map(lambda x: x.strip(), e.split(": "))
		return p,t,e,a

	def run(self):
		callstack = []
		readfile = open(self.dumpfile,"r")
		for line in readfile:
			tmp = self.parseLine(line)
			if tmp is None:
				continue
			pid,tid,event,arg = tmp

def usage():
	print "%s <dumpfile>"%sys.argv[0]

if __name__ == "__main__":
	if len(sys.argv) < 2:
		print usage()
		sys.exit(0)
	else:
		analyzer = CallGraphAnalyzer(sys.argv[1])
		analyzer.run()
