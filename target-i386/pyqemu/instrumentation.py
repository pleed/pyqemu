#!/usr/bin/env python

import PyFlxInstrument

class QemuInstrumentation:
	def __init__(self):
		pass
	def activate(self):
		PyFlxInstrument.set_instrumentation_active(1)

	def deactivate(self):
		PyFlxInstrument.set_instrumentation_active(0)

	def optrace_enable(self):
		PyFlxInstrument.optrace_enable()

	def optrace_disable(self):
		PyFlxInstrument.optrace_disable()

	def memtrace_enable(self):
		PyFlxInstrument.memtrace_enable()

	def memtrace_disable(self):
		PyFlxInstrument.memtrace_disable()

	def retranslate(self):
		PyFlxInstrument.retranslate()

	def filter_enable(self):
		PyFlxInstrument.filter_enable()

	def filter_disable(self):
		PyFlxInstrument.filter_disable()

	def filter_add(self, start, stop):
		PyFlxInstrument.filter_add(start, stop)

	def filter_del(self, start, end):
		PyFlxInstrument.filter_del(start, stop)

	def filter_filtered(self, addr):
		return PyFlxInstrument.filtered(addr)

	def wang_enable(self):
		PyFlxInstrument.wang_enable()
	def wang_disable(self):
		PyFlxInstrument.wang_disable()
