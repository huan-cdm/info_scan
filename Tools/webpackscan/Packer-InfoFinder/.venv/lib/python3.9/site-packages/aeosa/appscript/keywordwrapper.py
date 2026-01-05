"""keywordwrapper -- generic wrapper for application-specific type and enum names. """

# The Keyword class provides a generic wrapper for class, enum, property and type names.
# Users don't instantiate this class directly; instead, the syntactic sugar layer allows keywords
# to be created by referring to the exported 'k' variable; e.g. k.document, k.ask, k.name, k.String.

class Keyword:
	"""A class/property/enumerator/type name."""
	
	def __init__(self, name): 
		self.AS_name = name
	
	def __repr__(self): 
		return 'k.{}'.format(self.AS_name)
	
	def __hash__(self): 
		return hash(self.AS_name)
	
	def __eq__(self, val):
		return val.__class__ == self.__class__ and val.AS_name == self.AS_name
	
	def __ne__(self, val):
		return not self.__eq__(val)
	
	def __bool__(self):
		return self.AS_name != 'missing_value'
	
	name = property(lambda self:self.AS_name)


class _KeywordShim(object):
	""" Infinite namespace 'containing' all possible class/property/enumerator/type names. """
	
	def __getattr__(self, name): 
		if name.startswith('__') and name.endswith('__'):
			return object.__getattr__(self, name)
		else:
			return Keyword(name)
	
	def __repr__(self):
		return 'k'	


k = _KeywordShim()

