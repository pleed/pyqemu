#!/usr/bin/env python

import PyFlxInstrument
import Helpers

class QemuInstrumentation:
	def __init__(self):
		pass
	def activate(self, pid, tid, procname):
		PyFlxInstrument.set_instrumentation_active(1)
		PyFlxInstrument.set_context(pid,tid, str(procname))

	def deactivate(self):
		PyFlxInstrument.set_instrumentation_active(0)

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

	def bbltrace_enable(self):
		PyFlxInstrument.bbltrace_enable()

	def bbltrace_disable(self):
		PyFlxInstrument.bbltrace_disable()

	def caballero_enable(self, min_icount, threshold):
		PyFlxInstrument.caballero_enable(min_icount, threshold)

	def caballero_disable(self):
		PyFlxInstrument.caballero_disable()

	def arithwindow_enable(self, window_size, threshold):
		PyFlxInstrument.arithwindow_enable(window_size, threshold)
		
	def arithwindow_disable(self):
		PyFlxInstrument.arithwindow_disable()

	def functiontrace_enable(self):
		PyFlxInstrument.functiontrace_enable()

	def functiontrace_disable(self):
		PyFlxInstrument.functiontrace_disable()

	def set_context(self, pid, tid):
		PyFlxInstrument.set_context(pid, tid)

	def functionentropy_enable(self, threshold):
		PyFlxInstrument.functionentropy_enable(threshold)

	def functionentropy_disable(self):
		PyFlxInstrument.functionentropy_disable()

	def constsearch_pattern(self, pattern):
		PyFlxInstrument.constsearch_pattern(pattern)

	def constsearch_enable(self):
		PyFlxInstrument.constsearch_enable()

	def constsearch_disable(self):
		PyFlxInstrument.constsearch_disable()

	def constsearch_search(self):
		PyFlxInstrument.constsearch_search()

	def breakpoint_insert(self, addr):
		PyFlxInstrument.breakpoint_insert(addr)

	def breakpoint_delete(self, addr):
		PyFlxInstrument.breakpoint_delete(addr)

	def bblwindow_enable(self, window_size):
		PyFlxInstrument.bblwindow_enable(window_size)

	def bblwindow_disable(self):
		PyFlxInstrument.bblwindow_disable()

	def bblwindow_get(self, index):
		return PyFlxInstrument.bblwindow_get(index)

	def disas_bbl(self, addr):
		return PyFlxInstrument.disas_bbl(addr)

	def functiontaint_enable(self, threshold):
		return PyFlxInstrument.functiontaint_enable(threshold)

	def functiontaint_disable(self, threshold):
		return PyFlxInstrument.functiontaint_disable(threshold)

	def function_lookup(self):
		return PyFlxInstrument.function_lookup()

	def syscall_enable(self):
		PyFlxInstrument.syscall_enable()

	def syscall_disable(self):
		PyFlxInstrument.syscall_disable()

	def syscall_hook(self, number):
		PyFlxInstrument.syscall_hook(number)

	def dump_enable(self, path):
		PyFlxInstrument.dump_enable(path)

	def dump_disable(self):
		PyFlxInstrument.dump_disable()

	def vmem_read(self, n):
		return PyFlxInstrument.vmem_read(n, 4096)

	def read_process(self, process, address, len):
		try:
			return PyFlxInstrument.vmem_read_process(process.cr3, address, len)
		except RuntimeError:
			return None

	def read_process_page(self, process, address):
		return self.read_process(process, address&0xfffff000, 4096)
