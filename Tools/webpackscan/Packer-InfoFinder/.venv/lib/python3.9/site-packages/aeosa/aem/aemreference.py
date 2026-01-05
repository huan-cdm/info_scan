"""aemreference -- An object-oriented API for constructing object specifiers. """

import struct
from . import ae, kae

######################################################################
# SUPPORT FUNCTIONS
######################################################################

###################################
# packing support

if struct.pack("h", 1) == b'\x00\x01': # host is big-endian

	def packtype(code):
		return ae.newdesc(kae.typeType, code)
	
	def packabsoluteordinal(code): 
		return ae.newdesc(kae.typeAbsoluteOrdinal, code)
	
	def packenum(code):
		return ae.newdesc(kae.typeEnumeration, code)

else: # host is small-endian

	def packtype(code):
		return ae.newdesc(kae.typeType, code[::-1])
	
	def packabsoluteordinal(code): 
		return ae.newdesc(kae.typeAbsoluteOrdinal, code[::-1])
	
	def packenum(code):
		return ae.newdesc(kae.typeEnumeration, code[::-1])


def packlistas(type, lst):
	desc = ae.newrecord().coerce(type)
	for key, value in lst:
		desc.setparam(key, value)
	return desc


###################################
# comparison support

class _CollectComparable:
	def __init__(self):
		self.result = []
	
	def __getattr__(self, name):
		self.result.append(name)
		return self
	
	def __call__(self, *args):
		self.result.append(args)
		return self


######################################################################
# BASE CLASS
######################################################################

class Query(object):
	"""Base class for all specifier and testclause classes."""
	
	def __hash__(self):
		"""References are immutable, so may be used as dictionary keys."""
		return hash(repr(self))
	
	def __ne__(self, v):
		"""References may be compared for equality."""
		return not (self == v)
	
	def __eq__(self, v):
		"""References may be compared for equality."""
		return self is v or (
				self.__class__ == v.__class__ and 
				self.AEM_comparable() == v.AEM_comparable())
	
	def AEM_comparable(self):
		collector = _CollectComparable()
		self.AEM_resolve(collector)
		val = collector.result
		self.AEM_comparable = lambda: val
		return val


######################################################################
# BASE CLASS FOR ALL REFERENCE FORMS
######################################################################

class Specifier(Query):
	"""Base class for all object specifier classes."""
	
	def __init__(self, container, key):
		self._container = container
		self._key = key
		
	def AEM_root(self):
		# Get reference's root node. Used by range and filter specifiers when determining type of reference
		# passed as argument(s): range specifiers take absolute (app-based) and container (con-based)
		# references; filter specifiers require an item (its-based) reference.
		return self._container.AEM_root()
	
	def AEM_trueself(self):
		# Called by specifier classes when creating a reference to sub-element(s) of the current reference.
		# - An AllElements specifier (which contains 'want', 'form', 'seld' and 'from' values) will return an UnkeyedElements object (which contains 'want' and 'from' data only). The new specifier object  (ElementByIndex, ElementsByRange, etc.) wraps itself around this stub and supply its own choice of 'form' and 'seld' values.
		# - All other specifiers simply return themselves. 
		#
		#This sleight-of-hand allows foo.elements('bar ') to produce a legal reference to all elements, so users don't need to write foo.elements('bar ').all to achieve the same goal. This isn't a huge deal for aem, but makes a significant difference to the usability of user-friendly wrappers like appscript.
		return self
	
	def AEM_packself(self, codecs):
		# Pack this Specifier; called by codecs.
		desc = self._packself(codecs)
		self.AEM_packself = lambda codecs: desc # once packed, reuse this AEDesc for efficiency
		return desc


######################################################################
# INSERTION POINT REFERENCE FORM
######################################################################

class InsertionSpecifier(Specifier):
	"""Form: allelementsref.beginning/end, elementsref.before/after
		A reference to an element insertion point.
	"""
	def __init__(self, container, key, keyname):
		Specifier.__init__(self, container, key)
		self._keyname = keyname
	
	def __repr__(self):
		return '{!r}.{}'.format(self._container, self._keyname)
	
	def _packself(self, codecs):
		return packlistas(kae.typeInsertionLoc, [
				(kae.keyAEObject, self._container.AEM_packself(codecs)), 
				(kae.keyAEPosition, self._key),
				])
	
	def AEM_resolve(self, obj):
		return getattr(self._container.AEM_resolve(obj), self._keyname)


######################################################################
# BASE CLASS FOR ALL OBJECT REFERENCE FORMS
######################################################################

class _PositionSpecifier(Specifier):
	"""All property and element reference forms inherit from this class.
	
	Note that comparison and logic 'operator' methods are implemented on this class - these are only for use in constructing its-based references and shouldn't be used on app- and con-based references. Aem doesn't enforce this rule itself so as to minimise runtime overhead (the target application will raise an error if the user does something foolish).
	"""
	
	_kBeginning = packenum(kae.kAEBeginning)
	_kEnd = packenum(kae.kAEEnd)
	_kBefore = packenum(kae.kAEBefore)
	_kAfter = packenum(kae.kAEAfter)
	_kPrevious = packenum(kae.kAEPrevious)
	_kNext = packenum(kae.kAENext)
	
	def __init__(self, wantcode, container, key):
		self.AEM_want = wantcode
		Specifier.__init__(self, container, key)
	
	def __repr__(self):
		return '{!r}.{}({!r})'.format(self._container, self._kBy, self._key)
	
	def _packself(self, codecs):
		return packlistas(kae.typeObjectSpecifier, [
				(kae.keyAEDesiredClass, packtype(self.AEM_want)),
				(kae.keyAEKeyForm, self._kKeyForm),
				(kae.keyAEKeyData, self._packkey(codecs)),
				(kae.keyAEContainer, self._container.AEM_packself(codecs)),
				])
	
	# Comparison tests; these should only be used on its-based references:
	
	def gt(self, val):
		"""gt(anything) --> is greater than test"""
		return GreaterThan(self, val)
		
	def ge(self, val):
		"""ge(anything) --> is greater than or equals test"""
		return GreaterOrEquals(self, val)
	
	def eq(self, val):
		"""eq(anything) --> equals test"""
		return Equals(self, val)
	
	def ne(self, val):
		"""ne(anything) --> does not equal test"""
		return NotEquals(self, val)
	
	def lt(self, val):
		"""lt(anything) --> is less than test"""
		return LessThan(self, val)
	
	def le(self, val):
		"""le(anything) --> is less than or equals test"""
		return LessOrEquals(self, val)
	
	def beginswith(self, val):
		"""beginswith(anything) --> begins with test"""
		return BeginsWith(self, val)
	
	def endswith(self, val):
		"""endswith(anything) --> ends with test"""
		return EndsWith(self, val)
	
	def contains(self, val):
		"""contains(anything) --> contains test"""
		return Contains(self, val)
	
	def isin(self, val):
		"""isin(anything) --> isin test"""
		return IsIn(self, val)
	
	# Insertion references can be used on any kind of element reference, and also on property references where the property represents a one-to-one relationship, e.g. textedit.documents[1].text.end is valid:
		
	beginning = property(lambda self: InsertionSpecifier(self, self._kBeginning, 'beginning'), doc="beginning --> insertion location")
	end = property(lambda self: InsertionSpecifier(self, self._kEnd, 'end'), doc="end --> insertion location")
	before = property(lambda self: InsertionSpecifier(self, self._kBefore, 'before'), doc="before --> insertion location")
	after = property(lambda self: InsertionSpecifier(self, self._kAfter, 'after'), doc="after --> insertion location")
	
	# Property and element references can be used on any type of object reference:
	
	def property(self, propertycode):
		"""property(propertycode) --> property"""
		return Property(kae.cProperty, self, propertycode)
	
	def userproperty(self, name):
		"""property(name) --> property"""
		return UserProperty(kae.cProperty, self, name)
	
	def elements(self, elementcode):
		"""elements(elementcode) --> all elements"""
		return AllElements(elementcode, self)
	
	# Relative position references are unlikely to work on one-to-one relationships - but what the hey, it simplifies the class structure a bit.
	
	def previous(self, elementcode):
		"""previous(elementcode) --> element"""
		return ElementByRelativePosition(elementcode, self, self._kPrevious, 'previous')
	
	def next(self, elementcode):
		"""next(elementcode) --> element"""
		return ElementByRelativePosition(elementcode, self, self._kNext, 'next')


######################################################################
# PROPERTY REFERENCE FORMS
######################################################################

class Property(_PositionSpecifier):
	"""Form: ref.property(code)
		A reference to an application-defined property, where code is the code identifying the property.
	"""
	_kBy = 'property'
	_kKeyForm = packenum(kae.formPropertyID)
	
	def _packkey(self, codecs):
		return packtype(self._key)
	
	def AEM_resolve(self, obj):
		return self._container.AEM_resolve(obj).property(self._key)


class UserProperty(_PositionSpecifier):
	"""Form: ref.userproperty(name)
		A reference to a user-defined property, where name is a string representing the property's name. 
		
		Scriptable applications shouldn't use this reference form, but OSA script applets can.
		Note that OSA languages may have additional rules regarding case sensitivity/conversion.
	"""
	_kBy = 'userproperty'
	_kKeyForm = packenum(kae.formUserPropertyID)
	
	def _packkey(self, codecs):
		return codecs.pack(self._key).coerce(kae.typeChar)
	
	def AEM_resolve(self, obj):
		return self._container.AEM_resolve(obj).userproperty(self._key)


######################################################################
# ELEMENT REFERENCE FORMS
######################################################################

###################################
# Single elements

class _SingleElement(_PositionSpecifier):
	"""Base class for all single element specifiers."""
	
	def __init__(self, wantcode, container, key):
		# Notes: when byindex, byname, byid, first, middle, last or any is called on an AllElements object, we want to 'strip' the AllElements object away and use the underlying UnkeyedElements object as our 'container' instead. AEM_trueself returns the UnkeyedElements object when called on an AllElements object; in all other cases it returns the same object it was called on.
		_PositionSpecifier.__init__(self, wantcode, container.AEM_trueself(), key)
	
	def _packkey(self, codecs):
		return codecs.pack(self._key)
	
	def AEM_resolve(self, obj):
		return getattr(self._container.AEM_resolve(obj), self._kBy)(self._key)


#######

class ElementByName(_SingleElement):
	"""Form: elementsref.byname(text)
		A reference to a single element by its name, where text is string or unicode.
	"""
	_kBy = 'byname'
	_kKeyForm = packenum(kae.formName)


class ElementByIndex(_SingleElement):
	"""Form: elementsref.byindex(i)
		A reference to a single element by its index, where i is a non-zero whole number.
	"""
	_kBy = 'byindex'
	_kKeyForm = packenum(kae.formAbsolutePosition)


class ElementByID(_SingleElement):
	"""Form: elementsref.byid(anything)
		A reference to a single element by its id.
	"""
	_kBy = 'byid'
	_kKeyForm = packenum(kae.formUniqueID)

##

class ElementByOrdinal(_SingleElement):
	"""Form: elementsref.first/middle/last/any
		A reference to first/middle/last/any element.
	"""
	_kKeyForm = packenum(kae.formAbsolutePosition)
	
	def __init__(self, wantcode, container, key, keyname):
		self._keyname = keyname
		_SingleElement.__init__(self, wantcode, container, key)
	
	def __repr__(self):
		return '{!r}.{}'.format(self._container, self._keyname)
	
	def AEM_resolve(self, obj):
		return getattr(self._container.AEM_resolve(obj), self._keyname)


class ElementByRelativePosition(_SingleElement):
	"""Form: elementsref.previous/next(code)
		A relative reference to previous/next element, where code
		is the class code of element to get.
	"""
	_kKeyForm = packenum(kae.formRelativePosition)
	
	def __init__(self, wantcode, container, key, keyname):
		# Note: this method overrides _SingleElement.__init__() since we want to keep any AllElements container references as-is, not sub-select them.
		self._keyname = keyname
		_PositionSpecifier.__init__(self, wantcode, container, key)
	
	def __repr__(self):
		return '{!r}.{}({!r})'.format(self._container, self._keyname, self.AEM_want)
	
	def AEM_resolve(self, obj):
		return getattr(self._container.AEM_resolve(obj), self._keyname)(self.AEM_want)


###################################
# Multiple elements

class _MultipleElements(_PositionSpecifier):
	"""Base class for all multiple element specifiers."""
	
	_kFirst = packabsoluteordinal(kae.kAEFirst)
	_kMiddle = packabsoluteordinal(kae.kAEMiddle)
	_kLast = packabsoluteordinal(kae.kAELast)
	_kAny = packabsoluteordinal(kae.kAEAny)
	
	first = property(lambda self: ElementByOrdinal(self.AEM_want, self, self._kFirst, 'first'), doc="first --> element")
	middle = property(lambda self: ElementByOrdinal(self.AEM_want, self, self._kMiddle, 'middle'), doc="middle --> element")
	last = property(lambda self: ElementByOrdinal(self.AEM_want, self, self._kLast, 'last'), doc="last --> element")
	any = property(lambda self: ElementByOrdinal(self.AEM_want, self, self._kAny, 'any'), doc="any --> element")
	
	def byname(self, name):
		"""byname(name) --> element"""
		return ElementByName(self.AEM_want, self, name)
	
	def byindex(self, index):
		"""byindex(index) --> element"""
		return ElementByIndex(self.AEM_want, self, index)
	
	def byid(self, id):
		"""byid(id) --> element"""
		return ElementByID(self.AEM_want, self, id)
	
	def byrange(self, start, stop):
		"""byrange(start, stop) --> elements"""
		return ElementsByRange(self.AEM_want, self, (start, stop))
	
	def byfilter(self, expression):
		"""byfilter(expression) --> elements"""
		return ElementsByFilter(self.AEM_want, self, expression)


#######

class ElementsByRange(_MultipleElements):
	"""Form: elementsref.range(start, stop)
		A reference to a range of elements, where start and stop are relative references 
		to the first and last elements in range (see also 'con').
	"""
	_kKeyForm = packenum(kae.formRange)
	
	def __init__(self, wantcode, container, key):
		_MultipleElements.__init__(self, wantcode, container.AEM_trueself(), key)
	
	def __repr__(self):
		return '{!r}.byrange({!r}, {!r})'.format(self._container, *self._key)

	def _packkey(self, codecs):
		rangeselectors = []
		for key, selector in [(kae.keyAERangeStart, self._key[0]), (kae.keyAERangeStop, self._key[1])]:
			if isinstance(selector, Specifier):
				rangeselectors.append([key, codecs.pack(selector)])
			elif isinstance(selector, str):
				rangeselectors.append([key, codecs.pack(con.elements(self.AEM_want).byname(selector))])
			else:
				rangeselectors.append([key, codecs.pack(con.elements(self.AEM_want).byindex(selector))])
		return packlistas(kae.typeRangeDescriptor, rangeselectors)
	
	def AEM_resolve(self, obj):
		return self._container.AEM_resolve(obj).byrange(*self._key)


class ElementsByFilter(_MultipleElements):
	"""Form: elementsref.filter(expr)
		A reference to all elements that match a condition, where expr 
		is a relative reference to the object being tested (see also 'its').
	"""
	_kKeyForm = packenum(kae.formTest)
	
	def __init__(self, wantcode, container, key):
		if not isinstance(key, Test):
			raise TypeError('Not a test specifier: {!r}'.format(key))
		_MultipleElements.__init__(self, wantcode, container.AEM_trueself(), key)
	
	def __repr__(self):
		return '{!r}.byfilter({!r})'.format(self._container, self._key)

	def _packkey(self, codecs):
		return codecs.pack(self._key)
	
	def AEM_resolve(self, obj):
		return self._container.AEM_resolve(obj).byfilter(self._key)


class AllElements(_MultipleElements):
	"""Form: ref.elements(code)
		A reference to all elements of container, where code is elements' class code.
	"""
	_kKeyForm = packenum(kae.formAbsolutePosition)
	_kAll = packabsoluteordinal(kae.kAEAll)
	
	def __init__(self, wantcode, container):
		# An AllElements object is a wrapper around an UnkeyedElements object; when selecting one or more of these elements, the AllElements wrapper is skipped and the UnkeyedElements object is used as the 'container' for the new specifier.
		_PositionSpecifier.__init__(self, wantcode, UnkeyedElements(wantcode, container), self._kAll)
	
	def __repr__(self):
		return repr(self._container)
	
	def _packkey(self, codecs):
		return self._kAll
	
	def AEM_trueself(self): # override default implementation to return the UnkeyedElements object stored inside of this AllElements instance
		return self._container
	
	def AEM_resolve(self, obj):
		return self._container.AEM_resolve(obj) # forward to UnkeyedElements


######################################################################
# SHIMS
######################################################################

###################################
# Multiple element shim

class UnkeyedElements(Specifier):
	"""
		A partial elements reference, containing element code but no keyform/keydata. A shim.
		User is never exposed to this class directly. 
		
		The goal here is simple: to allow users to write 'x.elements(code)' to refer to all elements, 
		instead of the clumsier 'x.elements(code).all', as well as stuff like x.elements.first,
		x.elements.byindex(i), x.elements(code).elements(code), x.elements(code).byfilter(f).first, 
		and so on.
		
		Here's how it behaves:
		
		- Calling a reference's element() method initially returns an UnkeyedElements instance
		wrapped inside an AllElements instance, e.g. app.elements(b'docu'). 
		
		- Calling an element selection method on the AllElements instance, 
		e.g. app.elements(b'docu').byindex(1), strips away the AllElements instance to obtain the
		UnkeyedElements instance which is then used as the foundation for this new specifier.
		
		(There is one exception: ElementByRelativePosition. This keeps the AllElements reference
		intact, since it identifies a sibling of the currently specified elements.)
		
		- Calling property() and element() methods on any reference does no stripping, nor does calling
		element selection methods on other multi-item specifiers (ElementsByRange, ElementsByFilter).
		In both cases, we're stepping down a level in the object model so want the AllElements reference
		to objects at this level intact.
		
		This extra work also makes the higher-level appscript wrapper simpler to implement, since
		the behaviour here is the same as there. While one could implement separate allelements,
		firstelement, elementbyindex, elementbyrange, etc. methods in the aem layer and then do the 
		shimming in the appscript layer, this way is more consistent.
	"""
	
	def __init__(self, wantcode, container):
		self.AEM_want = wantcode
		self._container = container
	
	def __repr__(self):
		return '{!r}.elements({!r})'.format(self._container, self.AEM_want)
	
	def AEM_packself(self, codecs):
		return self._container.AEM_packself(codecs) # forward to container specifier
	
	def AEM_resolve(self, obj):
		return self._container.AEM_resolve(obj).elements(self.AEM_want)


###################################
# Unresolved reference

class DeferredSpecifier(Query):	
	"""Deferred specifier; used to represent unresolved container references that may need to be resolved later. A performance optimisation.
	
	When unpacking specifier AEDescs of typeObjectSpecifier, if the topmost AEDesc is of formPropertyID, formAbsolutePosition, formName and formUniqueID (the simplest and most commonly used forms), its container AEDesc isn't unpacked immediately; instead, it's placed in a DeferredSpecifier instance and is only unpacked if actually needed (e.g. when __repr__ or AEM_resolve is called). 
	
	This makes the implementation a little more complex, but gives an approximately 2x speed up when unpacking references. Repacking these references is also faster as the original AEDesc is retained instead of being repacked from scratch.
	"""

	def __init__(self, desc, codecs):
		self._desc = desc
		self._codecs = codecs
	
	def _realref(self):
		ref = self._codecs.unpack(self._desc) or self._codecs.app
		if not isinstance(ref, Query):
			if ref is None:
				ref = self._codecs.app
			else:
				ref = customroot(ref)
		self._realref = lambda:ref
		return ref
	
	def AEM_trueself(self):
		return self
		
	def __repr__(self):
		return repr(self._realref())
	
	def __eq__(self, v):
		return self._realref() == v
	
	def __hash__(self):
		return hash(self._realref())
	
	def AEM_root(self):
		return self._realref().AEM_root()
	
	def AEM_resolve(self, obj):
		return self._realref().AEM_resolve(obj)
		

######################################################################
# TEST CLAUSES
######################################################################

###################################
# Base class

class Test(Query):
	"""Base class for all comparison and logic test classes (Equals, NotEquals, AND, OR, etc.)."""

	# Logical tests.
	def AND(self, operand2, *operands):
		"""AND(test,...) --> logical AND test"""
		return AND((self, operand2) + operands)
		
	def OR(self, operand2, * operands):
		"""OR(test,...) --> logical OR test"""
		return OR((self, operand2) + operands)
	
	NOT = property(lambda self: NOT((self,)), doc="NOT --> logical NOT test")


###################################
# Comparison tests

class _ComparisonTest(Test):
	"""Subclassed by comparison test classes."""
	def __init__(self, operand1, operand2):
		self._operand1 = operand1
		self._operand2 = operand2
	
	def __repr__(self):
		return '{!r}.{}({!r})'.format(self._operand1, self._name, self._operand2)

	def AEM_resolve(self, obj):
		return getattr(self._operand1.AEM_resolve(obj), self._name)(self._operand2)

	def AEM_packself(self, codecs):
		return packlistas(kae.typeCompDescriptor, [
				(kae.keyAEObject1, codecs.pack(self._operand1)), 
				(kae.keyAECompOperator, self._operator), 
				(kae.keyAEObject2, codecs.pack(self._operand2))
				])

##

class GreaterThan(_ComparisonTest):
	_name = 'gt'
	_operator = packenum(kae.kAEGreaterThan)

class GreaterOrEquals(_ComparisonTest):
	_name = 'ge'
	_operator = packenum(kae.kAEGreaterThanEquals)

class Equals(_ComparisonTest):
	_name = 'eq'
	_operator = packenum(kae.kAEEquals)

class NotEquals(Equals):
	_name = 'ne'
	_operatorNOT = packenum(kae.kAENOT)
	
	def AEM_packself(self, codecs):
		return self._operand1.eq(self._operand2).NOT.AEM_packself(codecs)

class LessThan(_ComparisonTest):
	_name = 'lt'
	_operator = packenum(kae.kAELessThan)

class LessOrEquals(_ComparisonTest):
	_name = 'le'
	_operator = packenum(kae.kAELessThanEquals)

class BeginsWith(_ComparisonTest):
	_name = 'beginswith'
	_operator = packenum(kae.kAEBeginsWith)

class EndsWith(_ComparisonTest):
	_name = 'endswith'
	_operator = packenum(kae.kAEEndsWith)

class Contains(_ComparisonTest):
	_name = 'contains'
	_operator = packenum(kae.kAEContains)

class IsIn(Contains):
	_name = 'isin'

	def AEM_packself(self, codecs):
		return packlistas(kae.typeCompDescriptor, [
				(kae.keyAEObject1, codecs.pack(self._operand2)), 
				(kae.keyAECompOperator, self._operator), 
				(kae.keyAEObject2, codecs.pack(self._operand1))
				])


###################################
# Logical tests

class _LogicalTest(Test):
	"""Subclassed by logical test classes."""
	def __init__(self, operands):
		self._operands = operands
		
	def __repr__(self):
		return '{!r}.{}({})'.format(self._operands[0], self._name, repr(list(self._operands[1:]))[1:-1])
	
	def AEM_resolve(self, obj):
		return getattr(self._operands[0].AEM_resolve(obj), self._name)(*self._operands[1:])
	
	def AEM_packself(self, codecs):
		return packlistas(kae.typeLogicalDescriptor, [
				(kae.keyAELogicalOperator, self._operator), 
				(kae.keyAELogicalTerms, codecs.pack(self._operands)),
				])

##

class AND(_LogicalTest):
	_operator = packenum(kae.kAEAND)
	_name = 'AND'


class OR(_LogicalTest):
	_operator = packenum(kae.kAEOR)
	_name = 'OR'


class NOT(_LogicalTest):
	_operator = packenum(kae.kAENOT)
	_name = 'NOT'
		
	def __repr__(self):
		return '{!r}.NOT'.format(self._operands[0])
	
	def AEM_resolve(self, obj):
		return self._operands[0].AEM_resolve(obj).NOT


######################################################################
# REFERENCE ROOTS
######################################################################

###################################
# Base class


class ReferenceRoot(_PositionSpecifier):
	def __init__(self):
		pass
	
	def __repr__(self):
		return self._kName
	
	def _packself(self, codecs):
		return self._kType
	
	def AEM_root(self):
		return self
	
	def AEM_resolve(self, obj):
		return getattr(obj, self._kName)


###################################
# Concrete classes

class ApplicationRoot(ReferenceRoot):
	"""Form: app
		Reference base; represents an application's application object. Used to construct full references.
	"""
	_kName = 'app'
	_kType = ae.newdesc(kae.typeNull, b'')


class CurrentContainer(ReferenceRoot):
	"""Form: con
		Reference base; represents elements' container object. Used to construct by-range references.
	"""
	_kName = 'con'
	_kType = ae.newdesc(kae.typeCurrentContainer, b'')


class ObjectBeingExamined(ReferenceRoot):
	"""Form: its
		Reference base; represents an element to be tested. Used to construct by-filter references.
	"""
	_kName = 'its'
	_kType = ae.newdesc(kae.typeObjectBeingExamined, b'')


class CustomRoot(ReferenceRoot):
	"""Form: customroot(obj)
		Reference base; represents an arbitrary root object, e.g. an AEAddressDesc in a fully qualified reference.
	"""

	def __init__(self, rootObj):
		ReferenceRoot.__init__(self)
		self._rootObj = rootObj
	
	def __repr__(self):
		return 'customroot({!r})'.format(self._rootObj)
	
	def _packself(self, codecs):
		return codecs.pack(self._rootObj)
	
	def AEM_resolve(self, obj):
		return obj.customroot(self._rootObj)


###################################
# Reference root objects; use these constants to construct new specifiers, e.g. app.property(b'pnam')

app = ApplicationRoot()
con = CurrentContainer()
its = ObjectBeingExamined()
customroot = CustomRoot

