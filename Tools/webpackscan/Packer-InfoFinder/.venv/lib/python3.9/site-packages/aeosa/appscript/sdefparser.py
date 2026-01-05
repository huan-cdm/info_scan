""" sdefparser -- Basic SDEF parser to construct name-code terminology tables from an application's class, enumerator, property, element and command definitions. 

The tables returned by this module are an intermediate format, suitable for exporting to Python modules via terminology.dump. The terminology module will convert these intermediate tables into the final format used in AppData objects. 

"""

import string, struct

from lxml import etree

from aem import ae, kae
from .reservedkeywords import kReservedKeywords


######################################################################
# PRIVATE
######################################################################


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

def toidentifier(s):
	if s not in _keywordcache:
		legal = _legalchars
		res = ''
		for c in s:
			if c in legal:
				res += c
			elif c in _specialconversions:
				res += _specialconversions[c]
			else:
				if res == '':
					res = '_' # avoid creating an invalid identifier
				res += '0x{:X}'.format(ord(c))
			legal = _alphanum
		if res in _reservedwords or res.startswith('_') or res.startswith('AS_'):
			res += '_'
		_keywordcache[s] = str(res)
	return _keywordcache[s]

def tocode(s):
	if len(s) == 10 and s.startswith('0x'):
		return bytes((int(s[i:i+2], 16) for i in range(2, 10, 2)))
	elif len(s) == 4:
		return s.encode('macroman')
	else:
		return b'\x00\x00\x00\x00' # TO DO: throw and let caller catch and discard this malformed item?

def toeventcode(s):
	if len(s) == 18 and s.startswith('0x'):
		return bytes((int(s[i:i+2], 16) for i in range(2, 18, 2)))
	elif len(s) == 8:
		return s.encode('macroman')
	else:
		return b'\x00\x00\x00\x00\x00\x00\x00\x00' # TO DO: throw and let caller catch and discard this malformed item?


#######

# TO DO: if etree is too slow to process InDesign's sdef, use SAX to parse the top-level XML, dropping into etree to process the includes only

class Parser:
	""" Uses lxml.etree for its XInclude support (SAX would be faster but would have to do its own include handling) """
		
	def __init__(self):
		# terminology tables; order is significant where synonym definitions occur
		self.commands = {}
		self.properties = []
		self.elements = []
		self.classes = []
		self.enumerators = []
		# use sets to record previously found definitions, and avoid adding duplicates to lists
		self._foundproperties = set()
		self._foundelements = set()
		self._foundclasses = set()
		self._foundenumerators = set()
	
	
	#######
	
		'''
	     synonym      Defines an alternate term or code for the main element.

                  ATTRIBUTES
                  name    The alternate name, which follows the rules for
                          terminology element names.
                  code    The alternate code.
                  hidden  As above.
                  plural  As for class.  This is meaningful only for synonyms of
                          classes.

                  At least one of ‘name’ or ‘code’ is required.  Depending on
                  which attributes are present, the element will have different
                  effects:

                      Name only
                      Use these to define an alternate term that may be used at
                      compile time.  It will decompile as the main term.  For
                      example, AppleScript uses “app” as a name-only synonym for
                      “application”.  Cocoa scriptTerminology files do not
                      support these; generate an ‘aete’ resource for your
                      application as well.

                      Code only /// could probably ignore this, as only place it might be used is in string representations of Reference and Keyword, and only then if the app's implementation hasn't been fully updated to return new codes
                      Use these when migrating from one code to another.
                      (Typically, this happens when correcting an older version
                      of the dictionary which used a non-standard code.)
                      Compiled scripts that use the synonym code will decompile
                      using the main term.  Code-only synonyms are implicitly
                      hidden.  Because of how Cocoa scriptSuite files work, they
                      must contain a cocoa element with a ‘method’ or ‘key’
                      attribute in order to generate a correct scriptSuite file.

                      Name and Code
                      Use these to define an alternate term that is preserved
                      across compilation.  Effectively, this is a separate term
                      that happens to act the same as the main one.  As with
                      code-only synonyms, they must contain a cocoa element to
                      generate a correct scriptSuite file.
'''
	
	def parsesynonym(self, node, results, found, ocode):
		sname = node.get('name')
		if sname: # ignore code-only synonyms, as those are only used when decompiling AS bytecode that uses obsolete codes, translating them to current keywords
			sname = toidentifier(sname)
			scode = node.get('code')
			scode = tocode(scode) if scode else ocode
			if (sname, scode) not in found:
				found.add((sname, scode))
				results.append((sname, scode))
	
	def parsepluralsynonym(self, node, results, found, ocode):
		splural = node.get('plural') 
		if not splural:
			splural = node.get('name')
			if splural: splural += 's'
		if splural: # ignore code-only synonyms
			splural = toidentifier(splural)
			scode = node.get('code')
			scode = tocode(scode) if scode else ocode
			if (splural, scode) not in self._foundelements:
				found.add((splural, scode))
				results.append((splural, scode))
	
	def parsecommandsynonym(self, node, ocode, params):
		sname = node.get('name')
		if sname: # ignore code-only synonyms, as those are only used when decompiling AS bytecode that uses obsolete codes, translating them to current keywords
			sname = toidentifier(sname)
			scode = node.get('code')
			scode = toeventcode(scode) if scode else ocode
			if sname not in self.commands or self.commands[sname][1] == scode:
				self.commands[sname] = (sname, scode, params)

	
	def parsenamevalue(self, node, results, found):
		name = toidentifier(node.get('name'))
		code = tocode(node.get('code'))
		if (name, code) not in found:
			found.add((name, code))
			results.append((name, code))
		for subnode in node.findall('synonym'):
			self.parsesynonym(subnode, results, found, code)
	
	def parseclass(self, node):
		if node.tag != 'class-extension':
			name = node.get('name')
			plural = toidentifier(node.get('plural') or name+'s') # yes, this looks stupid if singular name already ends in 's', but that's how macOS does it
			name = toidentifier(name)
			code = tocode(node.get('code'))
			if (name, code) not in self._foundclasses: # type names
				self._foundclasses.add((name, code))
				self.classes.append((name, code))
			if (plural, code) not in self._foundelements: # elements
				self._foundelements.add((plural, code))
				self.elements.append((plural, code))
		else:
			name = code = plural = None # not quite right, but TBH anyone defining synonyms in class-extension needs a good smack
		for subnode in node:
			if subnode.tag == 'property':
				self.parsenamevalue(subnode, self.properties, self._foundproperties)
			elif subnode.tag == 'synonym':
				self.parsesynonym(subnode, self.classes, self._foundclasses, code) # type names
				self.parsepluralsynonym(subnode, self.elements, self._foundelements, code) # elements

	
	def parsecommand(self, node):
		name = toidentifier(node.get('name'))
		code = toeventcode(node.get('code'))
		params = []
		found = set()
		# Note: overlapping command definitions (e.g. InDesign) should be processed as follows:
		# - If their names and codes are the same, only the last definition is used; other definitions are ignored and will not compile.
		# - If their names are the same but their codes are different, only the first definition is used; other definitions are ignored and will not compile.
		# - If a dictionary-defined command has the same name but different code to a built-in definition, escape its name so it doesn't conflict with the default built-in definition.
		if name not in self.commands or self.commands[name][1] == code:
			self.commands[name] = (name, code, params)
		for subnode in node:
			if subnode.tag == 'parameter':
				self.parsenamevalue(subnode, params, found)
			elif subnode.tag == 'synonym':
				self.parsecommandsynonym(subnode, code, params)
	
	#######
	# Public
	
	def parse(self, sdef):
		dictionary = etree.XML(sdef)
		etree.ElementTree(dictionary).xinclude() # resolve any XIncludes, which makes generating glue tables from SDEFs far more complicated and slower than it ought to be as otherwise we could've done it with a simple single-pass SAX parser; no need to build and walk a large DOM; alas the history of AppleScript is full of well-intentioned bad decisions that come back to bite foreverafter
		for suite in dictionary.findall("suite"):
			for node in suite:
				if node.tag == 'class' or node.tag == 'class-extension' or node.tag == 'record-type':
					self.parseclass(node)
				elif node.tag == 'command' or node.tag == 'event':
					self.parsecommand(node)
				elif node.tag == 'enumeration':
					for subnode in node:
						if subnode.tag == 'enumerator':
							self.parsenamevalue(subnode, self.enumerators, self._foundenumerators)
				elif node.tag == 'value-type':
					self.parsenamevalue(node, self.classes, self._foundclasses)
		return (self.classes, self.enumerators, self.properties, self.elements, list(self.commands.values()))



######################################################################
# PUBLIC
######################################################################

def buildtablesforsdef(sdef):
	"""
		sdef : bytes
	"""
	return Parser().parse(sdef)

