#!/usr/bin/env python

#syscall table from metasploit


syscall_table = {
	0x2f:"NtCreateProcess",
	0x39:"NtCreateProcessEx",
	0x35:"NtCreateThread",
	0x101:"NtTerminateProcess",
	0x102:"NtTerminateThread",
}

def getSyscallByNumber(number):
	global syscall_table
	if syscall_table.has_key(number):
		return syscall_table[number]
	return None
