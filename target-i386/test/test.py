#!/usr/bin/env python

from windecl import *

headerfile = WindowsHeader(["test.h"])
decl = headerfile.declFromFunction("bla")
print str(decl)
decl = headerfile.declFromStruct("foo")
print str(decl)
decl = headerfile.declFromVar("glob_arg")
print str(decl)
