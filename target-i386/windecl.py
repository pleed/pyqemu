#!/usr/bin/env python

import os
import sys

from pygccxml import parser
from pygccxml import declarations

if __name__ == "__main__":
	print "this module cannot be executed standalone"

class WindowsHeader:
	def __init__(self, headerfiles = [], define_symbols = None, undefine_symbols = None, header_paths = ["/mnt/shared/headers/Include"], namespace = "win_sp2", gccxml_version = 'v09'):
		this_module_dir_path = os.path.abspath ( os.path.dirname( sys.modules[__name__].__file__) )
		gccxml_09_path = os.path.join( this_module_dir_path, '..', '..', '..', 'gccxml_bin', gccxml_version, sys.platform, 'bin' )
		config = parser.config_t( gccxml_path=gccxml_09_path, include_paths=header_paths, define_symbols = define_symbols, undefine_symbols = undefine_symbols)
		self.decls = parser.parse( headerfiles, config)

		self.global_namespace = declarations.get_global_namespace( self.decls )
		self.namespace = namespace

	def _getNamespace(self, namespace):
		if namespace is None:
			namespace = self.namespace
		return self.global_namespace.namespace(name=namespace)

	def declFromFunction(self, fname, namespace = None):
		ns = self._getNamespace(namespace)
		flist = ns.free_functions(name=fname).to_list()
		if len(flist) > 1:
			raise Exception("function name not unique!")
		return flist[0]

	def declFromStruct(self, structname, namespace = None):
		ns = self._getNamespace(namespace)
		return ns.class_(structname)

	def declFromVar(self, variable, namespace = None):
		ns = self._getNamespace(namespace)
		return ns.vars(name=variable)

class WinAPIFunction:
	def __init__(self, dllname, fname, *arguments):
		self.dllname = dllname
		self.fname   = fname
		self.args = []
		for arg in arguments:
			self.args.append(arg)

