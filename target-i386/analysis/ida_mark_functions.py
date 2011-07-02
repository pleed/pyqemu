#!/usr/bin/env python
addressfile = open("pyqemu_functions", "r")
entries = []
for line in addressfile:
    line = line.strip()
    desc, addr = line.split(",")
    entries.append((desc, int(addr,16)))
unique_found = set(entries)
mark_objects = {}
functions = {}

for desc, addr in unique_found:
	fname = GetFunctionName(addr)
	if functions.has_key(fname):
		descs, addr, color = functions[fname]
		descs.append(desc)
		functions[fname] = (descs, addr, color)
	else:
		functions[fname] = ([desc], addr, 0xaaaaaa)

for descs, addr, color in functions.values():
	descs.sort()
	description = "\n".join(descs)
	SetFunctionCmt(addr, description, 1)
	SetColor(addr, CIC_FUNC, color)

addressfile.close()

print "Marked all functions - respawn function window to workaround IDA displaying bug"
