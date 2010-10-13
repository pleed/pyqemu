#!/usr/bin/env python

import pygccxml
from pygccxml.declarations.cpptypes import *
from ctypes import *

type_converter = {
	bool_t:c_bool
	array_t:c_buffer
	char_t:c_char
	double_t:
	float_t
	int_t
	long_double_t
	long_int_t
	long_long_int_t
	long_long_unsigned_int_t
	long_unsigned_int_t
	pointer_t
	short_int_t
	short_unsigned_int_t
	signed_char_t
	unsigned_char_t
	unsigned_int_t
	void_t
	wchar_t
}

def newStruct(name, fields):
	return type(name, (Structure,), {"_fields_":fields})

def newCType(name

class Argument:
	def __init__(self, declaration, address, conditions = None):
		self.declaration = declaration
		self.address = address
		self.conditions = conditions
		self._buildObjTree()

	def _buildObjTree(self):
		
