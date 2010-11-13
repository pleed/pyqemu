import pefile
import os
import avl

class DLLHandler:
	def __init__(self, dlldir):
		self.dlldir = dlldir
		self.tree = avl.new()

	def loadDLL(self, filename, imagebase):
		lib = DLLFile(self.dlldir+"/"+filename, imagebase)
		self.tree.insert(lib)

	def _getLib(self, address):
		try:
			lib = self.tree.at_most(address)
		except ValueError:
			return None
		if lib.includes(address):
			return lib
		else:
			return None

	def resolveToName(self, addr):
		dll = self._getLib(addr)
		if dll is None:
			return None, None
		try:
			return str(dll), dll[addr]
		except KeyError:
			return str(dll), None

class DLLFile(dict):
	def __init__(self, filename, imagebase):
		self.imagebase = imagebase
		self.filename = os.path.basename(filename)

		dict.__init__(self)

		# Load functions
		lib = pefile.PE(filename)
		self.size = lib.OPTIONAL_HEADER.SizeOfImage
		for function in lib.DIRECTORY_ENTRY_EXPORT.symbols:
			self[imagebase+function.address] = function.name
		del(lib)

	def includes(self, address):
		return self.imagebase <= address < self.imagebase+self.size
	def __len__(self):
		return self.size
	def __int__(self):
		return self.imagebase
	def __str__(self):
		return self.filename
	def __eq__(self, other):
		other = int(other)
		return self.imagebase == other
	def __lt__(self, other):
		other = int(other)
		return self.imagebase < other
	def __le__(self, other):
		other = int(other)
		return self.imagebase <= other
	def __ne__(self, other):
		other = int(other)
		return self.imagebase != other
	def __ge__(self, other):
		other = int(other)
		return self.imagebase >= other
	def __gt__(self, other):
		other = int(other)
		return self.imagebase > other
