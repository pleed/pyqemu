
import PyFlxInstrument
from Structures import *

PAGESIZE = 4096
USER_KERNEL_SPLIT = 0x80000000
current_process = None

DUMP_UNSPECIFIED = 0
DUMP_IMAGE = 1
DUMP_PARTIAL = 2
DUMP_FULL = 4
DUMP_INITIAL = 8

IMAGE_TYPE_UNKNOWN = 0
IMAGE_TYPE_DLL = 1
IMAGE_TYPE_EXE = 2

def kernelspace(addr):
	return not userspace(addr)

def userspace(addr):
	if addr & 0x80000000:
		return False
	return True

class PageFaultException( Exception):
    def __init__( self, value):
        self.value = value

    def __str__( self):
        return "Page Fault at address 0x%08x, pdb 0x%08x" % self.value


