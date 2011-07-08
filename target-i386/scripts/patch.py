#!/usr/bin/env python

from idautils import *
from idaapi import *
from idc import *

page_directory = "X:\\pages\\"
segments = []
for seg in Segments():
	segments.append((seg, GetSegmentAttr(seg, SEGATTR_END)))

for seg in segments:
	start,end = seg
	print "Patching Segment: 0x%x - 0x%x"%(start,end)
	while start < end:
		f = open(page_directory+hex(start), "rb")
		mem = f.read()
		f.close()
		for offset in range(4096):
			PatchByte(start+offset, ord(mem[offset]))
		for offset in range(4096):
			auto_make_code(start+offset)
		start += 4096
	analyze_area(start,end)
analyze_area(0, 0xffffffff)
