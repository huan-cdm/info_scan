"""terminology -- Obtains an application's aete resource(s) using a 'ascrgdte' event and converts them into lookup tables for use in AppData objects. """

from aem import Application, AEType, AEEnum, EventError, findapp, ae, kae
from . import defaultterminology

from .aeteparser import buildtablesforaetes
from .sdefparser import buildtablesforsdef
from .keywordwrapper import Keyword

__all__ = ['tablesforapp', 'tablesformodule', 'tablesforaetes', 'tablesforsdef',
		'kProperty', 'kElement', 'kCommand', 
		'defaulttables', 'aetesforapp', 'dump']


######################################################################
# PUBLIC
######################################################################
# Constants

kProperty = b'p'
kElement = b'e'
kCommand = b'c'

######################################################################
# PRIVATE
######################################################################
# Cache

_terminologycache = {} # cache parsed terminology

######################################################################
# Default terminology tables for converting between human-readable identifiers and Apple event codes; used by all apps.
# Includes default entries for Required Suite, get/set and miscellaneous other commands; application may override some or all of these definitions.

# Type tables; used to translate constants
# e.g. k.document <-> AEType(b'docu')
# e.g. k.ask <-> AEEnum(b'ask ')

_defaulttypebyname = {} # used to encode class and enumerator keywords
_defaulttypebycode = {} # used to decode class (typeType) and enumerator (typeEnum) descriptors
_defaulttypecodebyname = {} # used to check for name collisions

for _, enumerators in defaultterminology.enumerations:
	for name, code in enumerators:
		_defaulttypebyname[name] = AEEnum(code)
		_defaulttypebycode[code] = Keyword(name)
		_defaulttypecodebyname[name] = code
for defs in [defaultterminology.types, defaultterminology.properties]:
	for name, code in defs:
		_defaulttypebyname[name] = AEType(code)
		_defaulttypebycode[code] = Keyword(name)
		_defaulttypecodebyname[name] = code

# Reference tables; used to translate references and commands
# e.g. app(...).documents.text <-> app.elements(b'docu').property(b'ctxt')
# e.g. app(...).quit(saving=k.ask) <-> Application(...).event(b'aevtquit', {b'savo': AEEnum(b'ask ')})

_defaultreferencebycode = {} # used to decode property and element specifiers
_defaultreferencebyname = {} # used to encode property and element specifiers and Apple events
_defaultcommandcodebyname = {} # used to check for name collisions


for name, code in defaultterminology.properties:
	_defaultreferencebycode[kProperty + code] = (kProperty, name)
	_defaultreferencebyname[name] = (kProperty, code)

for name, code in defaultterminology.elements:
	_defaultreferencebycode[kElement + code] = (kElement, name)
	_defaultreferencebyname[name] = (kElement, code)

for name, code, params in defaultterminology.commands:
	_defaultreferencebyname[name] = (kCommand, (code, dict(params)))
	_defaultcommandcodebyname[name] = code


######################################################################
# Translation table parsers

def _maketypetable(classes, enums, properties):
	# Used for constructing k.keywords
	# Each argument is of format [[name, code], ...]
	typebycode = _defaulttypebycode.copy()
	typebyname = _defaulttypebyname.copy()
	# note: testing indicates that where name+code clashes occur, classes have highest priority, followed by properties, with enums last (prior to 0.19.0 this code gave higher priority to enums):
	for klass, table in [(AEEnum, enums), (AEType, properties), (AEType, classes)]: # note: packing properties as AEProp causes problems when the same name is used for both a class and a property, and the property's definition masks the class's one (e.g. Finder's 'file'); if an AEProp is passed where an AEType is expected, it can cause an error as it's not what the receiving app expects. (Whereas they may be more tolerant of an AEType being passed where an AEProp is expected.) Also, note that AppleScript always seems to pack property names as typeType, so we should be ok following its lead here.
		for i, (name, code) in enumerate(table):
			# If an application-defined name overlaps an existing type name but has a different code, append '_' to avoid collision:
			if _defaulttypecodebyname.get(name, code) != code:
				name += '_'
			typebycode[code] = Keyword(name) # to handle synonyms, if same code appears more than once then use name from last definition in list
			name, code = table[-i - 1]
			if _defaulttypecodebyname.get(name, code) != code:
				name += '_'
			typebyname[name] = klass(code) # to handle synonyms, if same name appears more than once then use code from first definition in list
	return typebycode, typebyname


def _makereferencetable(properties, elements, commands):
	# Used for constructing references and commands
	# First two parameters are of format [[name, code], ...]
	# Last parameter is of format [name, code, direct arg type, [[arg code, arg name], ...]]
	referencebycode = _defaultreferencebycode.copy()
	referencebyname = _defaultreferencebyname.copy()
	for kind, table in [(kElement, elements), (kProperty, properties)]:
		# note: if property and element names are same (e.g. 'file' in BBEdit), will pack as property specifier unless it's a special case (i.e. see 'text' below). Note that there is currently no way to override this, i.e. to force appscript to pack it as an all-elements specifier instead (in AS, this would be done by prepending the 'every' keyword), so clients would need to use aem for that (but could add an 'all' method to Reference class if there was demand for a built-in workaround)
		for i, (name, code) in enumerate(table):
			# If an application-defined name overlaps an existing type name but has a different code, append '_' to avoid collision:
			if _defaulttypecodebyname.get(name, code) != code:
				name += '_'
			referencebycode[kind+code] = (kind, name) # to handle synonyms, if same code appears more than once then use name from last definition in list
			name, code = table[-i - 1]
			if _defaulttypecodebyname.get(name, code) != code:
				name += '_'
			referencebyname[name] = (kind, code) # to handle synonyms, if same name appears more than once then use code from first definition in list
	if 'text' in referencebyname: # special case: AppleScript always packs 'text of...' as all-elements specifier
		referencebyname['text'] = (kElement, referencebyname['text'][1])
	for name, code, args in commands[::-1]: # to handle synonyms, if two commands have same name but different codes, only the first definition should be used (iterating over the commands list in reverse ensures this)
		# Avoid collisions between default commands and application-defined commands with same name but different code (e.g. 'get' and 'set' in InDesign CS2):
		if code != _defaultcommandcodebyname.get(name, code):
			name += '_'
		referencebyname[name] = (kCommand, (code, dict(args)))
	return referencebycode, referencebyname


######################################################################
# PUBLIC
######################################################################


defaulttables = _maketypetable([], [], []) + _makereferencetable([], [], []) # (typebycode, typebyname, referencebycode, referencebyname)

# SDEF

def urlforapp(aemapp):
	""" Get file: or eppc: URL for application. """
	if aemapp.AEM_identity[0] == 'url':
		return aemapp.AEM_identity[1]
	else:
		path = ae.addressdesctopath(aemapp.AEM_packself(None)) # this will throw if typeMachPort; TO DO: what if current application?
		return ae.convertpathtourl(path, 0)


def sdefforurl(url):
	""" Get application's SDEF given a file: or eppc: URL. """
	try:
		return ae.scriptingdefinitionfromurl(url)
	except Exception as e:
		raise RuntimeError("Can't get terminology for application ({!r}): {}".format(url, e)) from e


def sdefforapp(aemapp):
	""" Get SDEF from local/remote app; result is XML as bytes. """
	return sdefforurl(urlforapp(aemapp))


def tablesforsdef(sdef):
	"""Build terminology tables from an SDEF XML.
		Result : tuple of dict -- (typebycode, typebyname, referencebycode, referencebyname)
	"""
	classes, enums, properties, elements, commands = buildtablesforsdef(sdef)
	return _maketypetable(classes, enums, properties) + _makereferencetable(properties, elements, commands)


# AETE

def aetesforapp(aemapp):
	"""Get aetes from local/remote app via an ascrgdte event; result is a list of byte strings."""
	try:
		aetes = aemapp.event(b'ascrgdte', {b'----':0}).send(120 * 60)
	except Exception as e: # (e.g.application not running)
		if isinstance(e, EventError) and e.errornumber == -192:
			aetes = []
		else:
			raise RuntimeError("Can't get terminology for application ({!r}): {}".format(aemapp, e)) from e
	if not isinstance(aetes, list):
		aetes = [aetes]
	return [aete for aete in aetes if isinstance(aete, ae.AEDesc) and aete.type == kae.typeAETE and aete.data]


def tablesforaetes(aetes):
	"""Build terminology tables from a list of unpacked aete byte strings.
		Result : tuple of dict -- (typebycode, typebyname, referencebycode, referencebyname)
	"""
	classes, enums, properties, elements, commands = buildtablesforaetes(aetes)
	return _maketypetable(classes, enums, properties) + _makereferencetable(properties, elements, commands)


def tablesformodule(terms):
	"""Build terminology tables from a dumped terminology module.
		Result : tuple of dict -- (typebycode, typebyname, referencebycode, referencebyname)
	"""
	return _maketypetable(terms.classes, terms.enums, terms.properties) \
			+ _makereferencetable(terms.properties, terms.elements, terms.commands)


def tablesforapp(aemapp, usesdef=False):
	"""Build terminology tables for an application.
		aemapp : aem.Application
		Result : tuple of dict -- (typebycode, typebyname, referencebycode, referencebyname)
	"""
	identity = aemapp.AEM_identity + (usesdef,)
	if identity not in _terminologycache:
		if usesdef:
			_terminologycache[identity] = tablesforsdef(sdefforapp(aemapp))
		else:
			_terminologycache[identity] = tablesforaetes(aetesforapp(aemapp))
	return _terminologycache[identity]


def dumptables(tables, sourcepath, modulepath):
	"""Dump terminology data to Python module.
		tables : tuple of list -- five-item tuple: (classes, enums, properties, elements, commands)
		sourcepath : str -- path to source application/scripting addition
		modulepath : str -- path to generated module
	"""
	from pprint import pprint
	atts = zip(('classes', 'enums', 'properties', 'elements', 'commands'), tables)
	with open(modulepath, 'w', encoding='utf-8') as f:
		f.write('version = 1.1\n')
		f.write('path = {!r}\n'.format(sourcepath))
		for key, value in atts:
			if key[0] != '_':
				f.write('\n{} = \\\n'.format(key))
				pprint(value, f)


######################################################################
# PUBLIC
######################################################################


def dump(apppath, modulepath, usesdef=False):
	"""Dump application terminology data to Python module.
		apppath : str -- name or path of application
		modulepath : str -- path to generated module
		usesdef : bool -- if True, use SDEF
		
	Generates a Python module containing an application's basic terminology 
	(names and codes) as used by appscript.
	
	Call the dump() function to dump faulty aetes to Python module, e.g.:
	
		dump('MyApp', '/path/to/site-packages/myappglue.py')
	
	Patch any errors by hand, then import the patched module into your script 
	and pass it to appscript's app() constructor via its 'terms' argument, e.g.:
	
		from appscript import *
		import myappglue
		
		myapp = app('MyApp', terms=myappglue)

	Note that dumped terminologies aren't used by appscript's built-in help system.
	"""
	apppath = findapp.byname(apppath)
	app = Application(apppath)
	if usesdef:
		tables = buildtablesforsdef(sdefforapp(app))
	else:
		tables = buildtablesforaetes(aetesforapp(app))
	dumptables(tables, apppath, modulepath)
