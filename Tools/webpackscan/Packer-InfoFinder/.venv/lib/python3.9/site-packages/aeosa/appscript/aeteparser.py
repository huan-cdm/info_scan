""" aeteparser -- Basic aete parser to construct name-code terminology tables from an application's class, enumerator, property, element and command definitions. 

The tables returned by this module are an intermediate format, suitable for exporting to Python modules via terminology.dump. The terminology module will convert these intermediate tables into the final format used in AppData objects. """

from struct import pack, unpack
import string

from aem import ae, kae
from .reservedkeywords import kReservedKeywords


######################################################################
# PRIVATE
######################################################################

class Parser:
	_keywordcache = {}
	_reservedwords = set(kReservedKeywords)
	_specialconversions = {
			' ': '_',
			'-': '_',
			'&': 'and',
			'/': '_',
	}
	_legalchars = string.ascii_letters + '_'
	_alphanum = _legalchars + string.digits
		
	def __init__(self):
		# terminology tables; order is significant where synonym definitions occur
		self.commands = {}
		self.properties = []
		self.elements = []
		self.classes = []
		self.enumerators = []
		# use sets to record previously found definitions, and avoid adding duplicates to lists
		# (i.e. 'name+code not in <set>' is quicker than using 'name+code not in <list>')
		self._foundproperties = set()
		self._foundelements = set()
		self._foundclasses = set()
		self._foundenumerators = set()
		# ideally, aetes should define both singular and plural names for each class, but
		# some define only one or the other so we need to fill in any missing ones afterwards
		self._spareclassnames = {}
		self._foundclasscodes = set()
		self._foundelementcodes = set()
		
	def integer(self):
		"""Read a 2-byte integer."""
		self._ptr += 2
		return unpack("H", self._data[self._ptr - 2:self._ptr])[0]
	
	def word(self):
		"""Read a 4-byte OSType."""
		self._ptr += 4
		return self._data[self._ptr - 4:self._ptr] # big-endian
	
	def name(self):
		"""Read a MacRoman-encoded Pascal keyword string."""
		count = self._data[self._ptr]
		self._ptr += 1 + count
		s = self._data[self._ptr - count:self._ptr].decode('macroman')
		if s not in self._keywordcache:
			legal = self._legalchars
			res = ''
			for c in s:
				if c in legal:
					res += c
				elif c in self._specialconversions:
					res += self._specialconversions[c]
				else:
					if res == '':
						res = '_' # avoid creating an invalid identifier
					res += '0x{:X}'.format(ord(c))
				legal = self._alphanum
			if res in self._reservedwords or res.startswith('_') or res.startswith('AS_'):
				res += '_'
			self._keywordcache[s] = str(res)
		return self._keywordcache[s]

	
	##
	
	def parsecommand(self):
		name = self.name()
		self._ptr += 1 + self._data[self._ptr] # description string
		self._ptr += self._ptr & 1 # align
		code = self.word() + self.word() # event class + event id
		# skip result
		self._ptr += 4 # datatype word
		self._ptr += 1 + self._data[self._ptr] # description string
		self._ptr += self._ptr & 1 # align
		self._ptr += 2 # flags integer
		# skip direct parameter
		self._ptr += 4 # datatype word
		self._ptr += 1 + self._data[self._ptr] # description string
		self._ptr += self._ptr & 1 # align
		self._ptr += 2 # flags integer
		#
		params = []
		# Note: overlapping command definitions (e.g. InDesign) should be processed as follows:
		# - If their names and codes are the same, only the last definition is used; other definitions are ignored and will not compile.
		# - If their names are the same but their codes are different, only the first definition is used; other definitions are ignored and will not compile.
		# - If a dictionary-defined command has the same name but different code to a built-in definition, escape its name so it doesn't conflict with the default built-in definition.
		if name not in self.commands or self.commands[name][1] == code:
			self.commands[name] = (name, code, params)
		# add labelled parameters
		for _ in range(self.integer()):
			name = self.name()
			self._ptr += self._ptr & 1 # align
			code = self.word()
			self._ptr += 4 # datatype word
			self._ptr += 1 + self._data[self._ptr] # description string
			self._ptr += self._ptr & 1 # align
			self._ptr += 2 # flags integer
			params.append((name, code))
	
	
	def parseclass(self):
		name = self.name()
		self._ptr += self._ptr & 1 # align
		code = self.word()
		self._ptr += 1 + self._data[self._ptr] # description string
		self._ptr += self._ptr & 1 # align
		isplural = False
		for _ in range(self.integer()): # properties
			propname = self.name()
			self._ptr += self._ptr & 1 # align
			propcode = self.word()
			self._ptr += 4 # datatype word
			self._ptr += 1 + self._data[self._ptr] # description string
			self._ptr += self._ptr & 1 # align
			flags = self.integer()
			if propcode != kae.pInherits: # not a superclass definition (see kAEInheritedProperties)
				if flags & 1: # indicates class name is plural (see kAESpecialClassProperties)
					isplural = True
				elif ((propname, propcode)) not in self._foundproperties:
					self.properties.append((propname, propcode)) # preserve ordering
					self._foundproperties.add((propname, propcode))
		for _ in range(self.integer()): # skip elements
			self._ptr += 4 # code word
			count = self.integer()
			self._ptr += 4 * count # reference forms
		if isplural:
			if ((name, code)) not in self._foundelements:
				self.elements.append((name, code))
				self._foundelements.add((name, code))
				self._foundelementcodes.add(code)
		else:
			if ((name, code)) not in self._foundclasses:
				self.classes.append((name, code))
				self._foundclasses.add((name, code))
				self._foundclasscodes.add(code)
		self._spareclassnames[code] = name
	
	
	def parsecomparison(self): # comparison info isn't used
		self._ptr += 1 + self._data[self._ptr] # name string
		self._ptr += self._ptr & 1 # align
		self._ptr += 4 # code word
		self._ptr += 1 + self._data[self._ptr] # description string
		self._ptr += self._ptr & 1 # align
	
	
	def parseenumeration(self): 
		self._ptr += 4 # code word
		for _ in range(self.integer()): # enumerators
			name = self.name()
			self._ptr += self._ptr & 1 # align
			code = self.word()
			self._ptr += 1 + self._data[self._ptr] # description string
			self._ptr += self._ptr & 1 # align
			if ((name, code)) not in self._foundenumerators:
				self.enumerators.append((name, code))
				self._foundenumerators.add((name, code))

	
	def parsesuite(self):
		self._ptr += 1 + self._data[self._ptr] # name string
		self._ptr += 1 + self._data[self._ptr] # description string
		self._ptr += self._ptr & 1 # align
		self._ptr += 4 # code word
		self._ptr += 4 # level, version integers
		for fn in [self.parsecommand, self.parseclass, self.parsecomparison, self.parseenumeration]:
			for _ in range(self.integer()):
				fn()
	
	#######
	# Public
	
	def parse(self, aetes):
		for aete in aetes:
			if isinstance(aete, ae.AEDesc) and aete.type in [kae.typeAETE, kae.typeAEUT] and aete.data:
				self._data = aete.data
				self._ptr = 6 # version, language, script integers
				for _ in range(self.integer()):
					self.parsesuite()
		# singular names are normally used in the classes table and plural names in the elements table. However, if an aete defines a singular name but not a plural name then the missing plural name is substituted with the singular name; and vice-versa if there's no singular equivalent for a plural name.
		missingelements = self._foundclasscodes - self._foundelementcodes
		missingclasses = self._foundelementcodes - self._foundclasscodes
		for code in missingelements:
			self.elements.append((self._spareclassnames[code], code))
		for code in missingclasses:
			self.classes.append((self._spareclassnames[code], code))
		return (self.classes, self.enumerators, self.properties, self.elements, list(self.commands.values()))


class LittleEndianParser(Parser):

	def word(self):
		"""Read a 4-byte string (really a long, but represented as an 4-character 8-bit string for readability)."""
		self._ptr += 4
		return self._data[self._ptr - 1:self._ptr - 5:-1] # little-endian


######################################################################
# PUBLIC
######################################################################

def buildtablesforaetes(aetes):
	"""
		aetes : list of aem.ae.AEDesc
	"""
	if pack("H", 1) == b'\x00\x01': # is it big-endian?
		return Parser().parse(aetes)
	else:
		return LittleEndianParser().parse(aetes)


