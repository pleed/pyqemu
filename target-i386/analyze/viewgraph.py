#!/usr/bin/env python
import pygraphviz as pgv
import sys
import random
import time
import os

if __name__ == "__main__":
	for name in sys.argv[1:]:
		random.seed(time.time())
		filename = str(random.random())[2:]
		graph = pgv.AGraph(file=name)
		graph.layout()
		filename = "/tmp/"+filename+".png"
		graph.draw(filename)
		os.system("evince "+filename)
