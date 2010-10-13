#!/usr/bin/env python

from windecl import *
import pygccxml

#headerfile = WindowsHeader(["/mnt/shared/headers/Include/windows-sp2.h"], define_symbols = ["RC_INVOKED","NOWINRES","_WIN32","_CRTBLD","_X86","NT_INCLUDED","_WINBASE_","_WINUSER_","_WINREG_","_WINDEF_"])
#headerfile = WindowsHeader(["/mnt/shared/headers/Include/windows-sp2.h"], define_symbols = ["RC_INVOKED","NOWINRES","_WIN32","_CRTBLD","_X86"])
#headerfile = WindowsHeader(["/mnt/shared/all.h"])
headerfile = WindowsHeader(["test.h"])

prefix = ""

#import code
#code.interact("DBG",local=locals())

# typen: pointer

class Pointer:
	def __init__(self, obj):
		self.obj = obj

	def __str__(self):
		global prefix
		s = prefix+"Pointer -> \n"
		prefix += "\t"
		s += str(self.obj)
		prefix = "\t"*(len(prefix)-1)
		return s


class Struct:
	def __init__(self, members):
		self.members = members

	def __str__(self):
		global prefix
		s = prefix+"Struct {\n"
		prefix += "\t"
		for member in self.members:
			s += str(member)
		prefix = "\t"*(len(prefix)-1)
		s += prefix+"};\n"
		return s

def buildobject(obj, address):
	# Pointer?
	if isinstance(obj, pygccxml.declarations.cpptypes.pointer_t):
		return Pointer(buildobject(obj.base))
	elif hasattr(obj, "type") and type(obj.type) == pygccxml.declarations.cpptypes.pointer_t:
		return Pointer(buildobject(obj.type.base))
	# Struct?
	elif isinstance(obj, pygccxml.declarations.cpptypes.declarated_t) and\
	hasattr(obj, "declaration") and isinstance(obj.declaration, pygccxml.declarations.class_declaration.class_t):
	# Standard Type !
		memberlist = []
		for member in obj.declaration.vars().to_list():
			memberlist.append(buildobject(member))
		return Struct(memberlist)
	else:
		return CType(obj)
	raise Exception("FOO!")

#try:
for arg in headerfile.declFromFunction("lstrcpy").required_args:
	print "Argument:"
	print arg
	#print buildobject(arg.type)

#except:
#	import code
#	code.interact("foo",local=locals())

	# p.base - pointer type
	# struct.declaration -> decl (declaration class)
	#	 decl.vars().to_list()


#decl = headerfile.declFromFunction("bla")
#print str(decl)
#decl = headerfile.declFromStruct("foo")
#print str(decl)
#decl = headerfile.declFromVar("glob_arg")
#print str(decl)
#decl = headerfile.declFromStruct("barfoo")
#print str(decl)
