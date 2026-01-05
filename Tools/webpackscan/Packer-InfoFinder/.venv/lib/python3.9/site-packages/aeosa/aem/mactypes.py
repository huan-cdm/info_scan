"""mactypes -- Defines user-friendly wrapper classes for Mac OS datatypes that don't have a suitable Python equivalent.

- File objects encompass AEDescs of typeFSRef/typeFSSpec/typeFileURL to save user from having to deal with them directly. File objects refer to filesystem locations which may or may not already exist.

- Alias objects wrap AEDescs of typeAlias. Aliases refer to filesystem objects and can track them as they're moved around the disk or renamed.

Both classes provide a variety of constructors and read-only properties for getting raw objects in and out. Objects are comparable and nominally hashable.

- Units objects represent units of measurement. Default unit types are defined in aem; clients can add additional definitions to aem Codecs/appscript AppData objects as needed.

"""

from os.path import abspath

from .ae import newdesc, convertpathtourl, converturltopath, MacOSError
from . import kae

kCFURLPOSIXPathStyle = 0
kCFURLHFSPathStyle = 1
kCFURLWindowsPathStyle = 2

__all__ = ['Alias', 'File', 'Units']


######################################################################
# PRIVATE
######################################################################
# Constants

class _kNoPath: pass

class _Base:
	def __eq__(self, val):
		return self is val or (self.__class__ == val.__class__ and self.url == val.url)
	
	def __ne__(self, val):
		return not self == val
	
	def __hash__(self):
		return hash(self.__class__)


######################################################################
# PUBLIC
######################################################################

class Alias(_Base):
	"""A persistent reference to a filesystem object."""
	
	# Constructors
	
	def __init__(self, path):
		"""Make Alias object from POSIX path."""
		if path is _kNoPath:
			self._desc = None
		else:
			urldesc = newdesc(kae.typeFileURL, 
					convertpathtourl(abspath(path), kCFURLPOSIXPathStyle).encode('utf8'))
			try:
				self._desc = urldesc.coerce(kae.typeAlias)
			except MacOSError as err:
				if err.args[0] == -1700:
					raise ValueError("Can't make mactypes.Alias as file doesn't exist: {!r}".format(path)) from err
				else:
					raise
		
	def makewithhfspath(klass, path):
		return klass.makewithurl(convertpathtourl(path, kCFURLHFSPathStyle))
	makewithhfspath = classmethod(makewithhfspath)
	
	def makewithurl(klass, url):
		"""Make File object from file URL."""
		obj = klass(_kNoPath)
		obj._desc = newdesc(kae.typeFileURL, url.encode('utf8')).coerce(kae.typeAlias)
		return obj
	makewithurl = classmethod(makewithurl)
	
	def makewithdesc(klass, desc):
		"""Make Alias object from aem.ae.AEDesc of typeAlias (typeFSS/typeFSRef/typeFileURL are also allowed).
		"""
		if desc.type != kae.typeAlias:
			desc = desc.coerce(kae.typeAlias)
		obj = klass(_kNoPath)
		obj._desc = desc
		return obj
	makewithdesc = classmethod(makewithdesc)
	
	# Instance methods
	
	def __repr__(self):
		return 'mactypes.Alias({!r})'.format(self.path)
	
	# Properties
	
	path = property(lambda self: converturltopath(self.url, kCFURLPOSIXPathStyle), doc="Get as POSIX path.")
	
	hfspath = property(lambda self: converturltopath(self.url, kCFURLHFSPathStyle), doc="Get as HFS path.")
	
	url = property(lambda self: self._desc.coerce(kae.typeFileURL).data.decode('utf8'), doc="Get as file URL.")
	
	file = property(lambda self: File.makewithdesc(self._desc), doc="Get as mactypes.File.")
	
	alias = property(lambda self: self, doc="Get as mactypes.Alias (i.e. itself).")
	
	desc = property(lambda self: self._desc, doc="Get as aem.ae.AEDesc.")



class File(_Base):
	"""A reference to a filesystem location."""
	
	# Constructors
	
	def __init__(self, path):
		"""Make File object from POSIX path."""
		if path is not _kNoPath:
			if not isinstance(path, str):
				path = str(path)
			self._path = abspath(path)
			self._url = convertpathtourl(self._path, kCFURLPOSIXPathStyle)
			self._desc = newdesc(kae.typeFileURL, self._url.encode('utf8'))
	
	def makewithhfspath(klass, path):
		return klass.makewithurl(convertpathtourl(path, kCFURLHFSPathStyle))
	makewithhfspath = classmethod(makewithhfspath)
	
	def makewithurl(klass, url):
		"""Make File object from file URL."""
		obj = klass(_kNoPath)
		obj._desc = newdesc(kae.typeFileURL, url.encode('utf8'))
		obj._url = url
		obj._path = converturltopath(url, kCFURLPOSIXPathStyle)
		return obj
	makewithurl = classmethod(makewithurl)
		
	def makewithdesc(klass, desc):
		"""Make File object from aem.ae.AEDesc of typeFSS/typeFSRef/typeFileURL.
			Note: behaviour for other descriptor types is undefined: typeAlias will cause problems, others will probably fail.
		"""
		obj = klass(_kNoPath)
		obj._path = None
		obj._url = None
		if desc.type in [kae.typeFSS, kae.typeFSRef, kae.typeFileURL]:
			obj._desc = desc
		else:
			obj._desc = desc.coerce(kae.typeFileURL)
		return obj
	makewithdesc = classmethod(makewithdesc)
	
	# Instance methods
	
	def __repr__(self):
		return 'mactypes.File({!r})'.format(self.path)
	
	# Properties
	
	def path(self):
		if self._path is None:
			self._path = converturltopath(self.url, kCFURLPOSIXPathStyle)
		return self._path
	path = property(path, doc="Get as POSIX path.")
	
	hfspath = property(lambda self: converturltopath(self.url, kCFURLHFSPathStyle), doc="Get as HFS path.")
	
	def url(self):
		if self._url is None:
			if self._desc.type == kae.typeFileURL:
				self._url = self._desc.data.decode('utf8')
			else:
				self._url = self._desc.coerce(kae.typeFileURL).data.decode('utf8')
		return self._url
	url = property(url, doc="Get as file URL.")
	
	file = property(lambda self: File(self.path), doc="Get as mactypes.File.")
	
	alias = property(lambda self: Alias.makewithdesc(self.desc), doc="Get as mactypes.Alias.")
	
	def desc(self):
		if self._desc is None:
			self._desc = newdesc(kae.typeFileURL, self.url.encode('utf8'))
		return self._desc
	desc = property(desc, doc="Get as aem.ae.AEDesc.")



#######

class Units:
	"""Represents a measurement; e.g. 3 inches, 98.5 degrees Fahrenheit.
	
	The AEM defines a standard set of unit types; some applications may define additional types for their own use. This wrapper stores the raw unit type and value data; aem/appscript Codecs objects will convert this to/from an AEDesc, or raise an error if the unit type is unrecognised.
	"""
	
	def __init__(self, value, type):
		"""
			value : int | float -- the unit value, e.g. 3
			type : str -- the unit type name, e.g. 'inches'
		"""
		self._value = value
		self._type = type
	
	value = property(lambda self: self._value, doc="Get unit value, e.g. 3")
	type = property(lambda self: self._type, doc="Get unit type, e.g. 'inches'")
	
	def __eq__(self, val):
		return self is val or (self.__class__ == val.__class__ 
				and self._value == val.value and self._type == val.type)
	
	def __ne__(self, val):
		return not self == val
	
	def __hash__(self):
		return hash((self.value, self.type))
	
	def __repr__(self):
		return 'mactypes.Units({!r}, {!r})'.format(self.value, self.type)
	
	def __str__(self):
		return '{!r} {}'.format(self.value, self.type.replace('_', ' '))
	
	def __int__(self):
		return int(self.value)
	
	def __float__(self):
		return float(self.value)


