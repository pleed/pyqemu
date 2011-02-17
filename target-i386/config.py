#!/usr/bin/env

import json

class ConfigException(Exception):
	pass

class _ConfigLoader(dict):
	def __init__(self, filename):
		self.file = open(filename,"r")

	def load(self, file):
		raise ConfigException("Implement in inherited class")

	def close(self):
		self.file.close()
		self.file = None

	def __del__(self):
		if self.file is not None:
			self.close()

class _JsonConfigLoader(_ConfigLoader):
	def load(self):
		return json.load(self.file)

class ConfigLoaderFactory:
	@classmethod
	def create(cls, configtype, configfile):
		if configtype == "json":
			return _JsonConfigLoader(configfile)
		raise ConfigException("Unknown type of configuration file - file: %s, type: %s"%(configfile, configtype))

class ProgramAnalyzerConfig(dict):
	def __init__(self, *args):
		dict.__init__(self, *args)
		if not self.isValid():
			raise Exception("Invalid config file!")

	def isValid(self):
		return True 
