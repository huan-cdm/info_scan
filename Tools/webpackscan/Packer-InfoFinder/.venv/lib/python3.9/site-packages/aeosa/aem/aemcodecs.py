"""codecs -- Convert from Python to Apple Event Manager types and vice-versa. """

import struct, datetime, time
from codecs import BOM_UTF16_LE, BOM_UTF16_BE

from .ae import AEDesc, newdesc, newlist, newrecord
from .typewrappers import AEType, AEEnum, AEProp, AEKey
from . import aemreference, mactypes, kae


######################################################################
# PRIVATE
######################################################################

if struct.pack("h", 1) == b'\x00\x01': # host is big-endian
	fourcharcode = lambda code: code
	nativeutf16encoding = 'UTF-16BE'
else: # host is small-endian
	fourcharcode = lambda code: code[::-1]
	nativeutf16encoding = 'UTF-16LE'


class _Ordinal:
	def __init__(self, code):
		self.code = code

class _Range:
	def __init__(self, range):
		self.range = range


######################################################################
# PUBLIC
######################################################################


class UnitTypeCodecs:
	"""Provides pack and unpack methods for converting between mactypes.Units instances and AE unit types. Each Codecs instance is allocated its own UnitTypeCodecs instance.
	"""
	
	_defaultunittypes = [
		('centimeters', b'cmtr'),
		('meters', b'metr'),
		('kilometers', b'kmtr'),
		('inches', b'inch'),
		('feet', b'feet'),
		('yards', b'yard'),
		('miles', b'mile'),
		
		('square_meters', b'sqrm'),
		('square_kilometers', b'sqkm'),
		('square_feet', b'sqft'),
		('square_yards', b'sqyd'),
		('square_miles', b'sqmi'),
		
		('cubic_centimeters', b'ccmt'),
		('cubic_meters', b'cmet'),
		('cubic_inches', b'cuin'),
		('cubic_feet', b'cfet'),
		('cubic_yards', b'cyrd'),
		
		('liters', b'litr'),
		('quarts', b'qrts'),
		('gallons', b'galn'),
		
		('grams', b'gram'),
		('kilograms', b'kgrm'),
		('ounces', b'ozs '),
		('pounds', b'lbs '),
		
		('degrees_Celsius', b'degc'),
		('degrees_Fahrenheit', b'degf'),
		('degrees_Kelvin', b'degk'),
	]
	
	##
	
	def _defaultpacker(self, units, code): 
		return newdesc(code, struct.pack('d', units.value))
	
	def _defaultunpacker(self, desc, name):
		return mactypes.Units(struct.unpack('d', desc.data)[0], name)
	
	##
	
	def __init__(self):
		self._typebyname = {}
		self._typebycode = {}
		self.addtypes(self._defaultunittypes)
	
	def addtypes(self, typedefs):
		""" Add application-specific unit type definitions to this UnitTypeCodecs instance.
		
			typedefs is a list of tuples, where each tuple is of form:
				(typename, typecode, packer, unpacker)
			or:
				(typename, typecode)
			
			If optional packer and unpacker functions are omitted, default pack/unpack functions
			are used instead; these pack/unpack AEDesc data as a double precision float.
		"""
		for item in typedefs:
			if len(item) == 2:
				item = item + (self._defaultpacker, self._defaultunpacker)
			name, code, packer, unpacker = item
			self._typebyname[name] = (code, packer)
			self._typebycode[code] = (name, unpacker)
	
	def pack(self, val):
		if isinstance(val, mactypes.Units):
			try:
				code, packer = self._typebyname[val.type]
			except KeyError as e:
				raise TypeError('Unknown unit type: {!r}'.format(val)) from e
			else:
				return True, packer(val, code)
		else:
			return False, val
	
	def unpack(self, desc):
		if desc.type in self._typebycode:
			name, unpacker = self._typebycode[desc.type]
			return True, unpacker(desc, name)
		else:
			return False, desc



######################################################################


class Codecs:
	"""Convert between Python and Apple event data types.
	Clients may add additional encoders/decoders and/or subclass to suit their needs.
	"""
	
	# Constants
	
	kNullDesc = newdesc(kae.typeNull, '')
	kMacEpoch = datetime.datetime(1904, 1, 1) # used in packing datetime objects as AEDesc typeLongDateTime
	kMacEpochT = time.mktime(kMacEpoch.timetuple())
	kShortMacEpoch = kMacEpoch.date() # used in packing date objects as AEDesc typeLongDateTime

	kTrueDesc = newdesc(kae.typeTrue, '')
	kFalseDesc = newdesc(kae.typeFalse, '')
	
	#######
	# tables to map AE codes to aem method names
	
	kInsertionLocSelectors = {
			fourcharcode(kae.kAEBefore): 'before', 
			fourcharcode(kae.kAEAfter): 'after', 
			fourcharcode(kae.kAEBeginning): 'beginning', 
			fourcharcode(kae.kAEEnd): 'end'
	}
	
	kTypeCompDescriptorOperators = {
			fourcharcode(kae.kAEGreaterThan): 'gt',
			fourcharcode(kae.kAEGreaterThanEquals): 'ge',
			fourcharcode(kae.kAEEquals): 'eq',
			fourcharcode(kae.kAELessThan): 'lt',
			fourcharcode(kae.kAELessThanEquals): 'le',
			fourcharcode(kae.kAEBeginsWith): 'beginswith',
			fourcharcode(kae.kAEEndsWith): 'endswith',
			fourcharcode(kae.kAEContains): 'contains'
	}
	
	kTypeLogicalDescriptorOperators = {
			fourcharcode(kae.kAEAND): 'AND',
			fourcharcode(kae.kAEOR): 'OR',
			fourcharcode(kae.kAENOT): 'NOT'
	}
	
	
	###################################
	
	
	def __init__(self):
		# Clients may add/remove/replace encoder and decoder items:
		self.encoders = {
				AEDesc: self.packdesc,
				type(None): self.packnone,
				bool: self.packbool,
				int: self.packint,
				float: self.packfloat,
				
				bytes: self.packbytes,
				str: self.packstr,
				
				list: self.packlist,
				tuple: self.packlist,
				dict: self.packdict,
				datetime.date: self.packdate,
				datetime.datetime: self.packdatetime,
				datetime.time: self.packtime,
				time.struct_time: self.packstructtime,
				
				mactypes.Alias: self.packalias,
				mactypes.File: self.packfile,
				
				AEType: self.packtype,
				AEEnum: self.packenum,
				AEProp: self.packprop,
				AEKey: self.packkey,
		}
		
		self. decoders = {
				kae.typeNull: self.unpacknull,
				kae.typeBoolean: self.unpackboolean,
				kae.typeFalse: self.unpackfalse,
				kae.typeTrue: self.unpacktrue,
				kae.typeSInt16: self.unpacksint16,
				kae.typeUInt16: self.unpackuint16,
				kae.typeSInt32: self.unpacksint32,
				kae.typeUInt32: self.unpackuint32,
				kae.typeSInt64: self.unpacksint64,
				kae.typeUInt64: self.unpackuint64,
				kae.typeIEEE32BitFloatingPoint: self.unpackfloat32,
				kae.typeIEEE64BitFloatingPoint: self.unpackfloat64,
				kae.type128BitFloatingPoint: self.unpackfloat128,
				
				kae.typeData: self.unpackdata,
				
				kae.typeChar: self.unpackchar,
				kae.typeIntlText: self.unpackintltext,
				kae.typeUTF8Text: self.unpackutf8text,
				kae.typeUTF16ExternalRepresentation: self.unpackutf16externalrepresentation,
				kae.typeStyledText: self.unpackstyledtext,
				kae.typeUnicodeText: self.unpackunicodetext,
				
				kae.typeLongDateTime: self.unpacklongdatetime,
				kae.typeAEList: self.unpackaelist,
				kae.typeAERecord: self.unpackaerecord,
				kae.typeVersion: self.unpackversion,
				
				kae.typeAlias: self.unpackalias,
				kae.typeFSS: self.unpackfss,
				kae.typeFSRef: self.unpackfsref,
				kae.typeFileURL: self.unpackfileurl,
				
				kae.typeQDPoint: self.unpackqdpoint,
				kae.typeQDRectangle: self.unpackqdrect, 
				kae.typeRGBColor: self.unpackrgbcolor,
				
				kae.typeType: self.unpacktype,
				kae.typeEnumeration: self.unpackenumeration,
				kae.typeProperty: self.unpackproperty,
				kae.typeKeyword: self.unpackkeyword,
				
				kae.typeInsertionLoc: self.unpackinsertionloc,
				kae.typeObjectSpecifier: self.unpackobjectspecifier,
				kae.typeAbsoluteOrdinal: self.unpackabsoluteordinal,
				kae.typeCompDescriptor: self.unpackcompdescriptor,
				kae.typeLogicalDescriptor: self.unpacklogicaldescriptor,
				kae.typeRangeDescriptor: self.unpackrangedescriptor,
				
				kae.typeCurrentContainer: lambda desc: self.con,
				kae.typeObjectBeingExamined: lambda desc: self.its,
		}

		self._unittypecodecs = UnitTypeCodecs()
		self._packtextastype = kae.typeUnicodeText
	
	
	###################################
	
	def addunittypes(self, typedefs):
		"""Register custom unit type definitions with this Codecs instance
			e.g. Adobe apps define additional unit types (ciceros, pixels, etc.)
		"""
		self._unittypecodecs.addtypes(typedefs)
	
	def dontcacheunpackedspecifiers(self):
		""" When unpacking object specifiers, unlike AppleScript, appscript caches
			the original AEDesc for efficiency, allowing the resulting reference to
			be re-packed much more quickly. Occasionally this causes compatibility
			problems with applications that returned subtly malformed specifiers.
			To force a Codecs object to fully unpack and repack object specifiers,
			call its dontcacheunpackedspecifiers method.
		"""
		self.unpackobjectspecifier = self.fullyunpackobjectspecifier
	
	def packstringsastype(self, code):
		""" Specify the AE type for packing str objects. Default is kae.typeUnicodeText, but 
			some older non-Unicode-aware Carbon may require kae.typeChar or kae.typeIntlText. 
		"""
		if not (isinstance(code, bytes) and len(code) == 4):
			raise TypeError('Code must be a four-byte value: {!r}'.format(code))
		self._packtextastype = code
	
	
	###################################
	
	def packunknown(self, data):
		"""Clients may override this to provide additional packers."""
		raise TypeError("Can't pack data into an AEDesc (unsupported type): {!r}".format(data))
	
	def unpackunknown(self, desc):
		"""Clients may override this to provide additional unpackers."""
		if desc.isrecord():
			rec = desc.coerce(b'reco')
			rec.setparam(b'pcls', self.pack(AEType(desc.type)))
			decoder = self.decoders.get(b'reco')
			if decoder:
				return decoder(rec)
			else:
				return rec
		else:
			return desc
	
	##
	
	def pack(self, data):
		"""Pack Python data.
			data : anything -- a Python value
			Result : aem.ae.AEDesc -- an Apple event descriptor, or error if no encoder exists for this type of data
		"""
		if isinstance(data, aemreference.Query):
			return data.AEM_packself(self)
		else:
			try:
				return self.encoders[data.__class__](data) # quick lookup by type/class
			except (KeyError, AttributeError):
				for type, encoder in self.encoders.items(): # slower but more thorough lookup that can handle subtypes/subclasses
					if isinstance(data, type):
						return encoder(data)
				didpack, desc = self._unittypecodecs.pack(data)
				if didpack:
					return desc
				else:
					self.packunknown(data)
	
	def unpack(self, desc):
		"""Unpack an Apple event descriptor.
			desc : aem.ae.AEDesc -- an Apple event descriptor
			Result : anything -- a Python value, or the AEDesc object if no decoder is found
		"""
		decoder = self.decoders.get(desc.type)
		if decoder:
			return decoder(desc)
		else:
			didunpack, val = self._unittypecodecs.unpack(desc)
			if didunpack:
				return val
			else:
				return self.unpackunknown(desc)
	
	
	###################################
	
	def packdesc(self, val):
		return val
	
	def packnone(self, val):
		return self.kNullDesc
	
	def packbool(self, val):
		return val and self.kTrueDesc or self.kFalseDesc
	
	def packint(self, val): # note: Python int = C long, so may need to pack as typeSInt64 on 64-bit
		if (-2**31) <= val < (2**31): # pack as typeSInt32 if possible (non-lossy)
			return newdesc(kae.typeSInt32, struct.pack('i', val))
		elif (-2**63) <= val < (2**63): # else pack as typeSInt64 if possible (non-lossy)
			return newdesc(kae.typeSInt64, struct.pack('q', val))
		else: # else pack as typeFloat (lossy)
			return self.pack(float(val))
		
	def packfloat(self, val):
		return newdesc(kae.typeFloat, struct.pack('d', val))
	
	##
	
	def packbytes(self, val):
		return newdesc(kae.typeData, val)
	
	def packstr(self, val):
		# Note: optional BOM is omitted as this causes problems with stupid apps like iTunes 7 that don't
		# handle BOMs correctly; note: while typeUnicodeText is not recommended as of OS 10.4, it's still
		# being used rather than typeUTF8Text or typeUTF16ExternalRepresentation to provide compatibility
		#with not-so-well-designed applications that may have problems with these newer types.
		data = val.encode(nativeutf16encoding)
		if data.startswith(BOM_UTF16_LE) or data.startswith(BOM_UTF16_BE):
			data = data[2:]
		desc = newdesc(kae.typeUnicodeText, data)
		if self._packtextastype == kae.typeUnicodeText:
			return desc
		else:
			return desc.coerce(self._packtextastype)

	##
	
	def packdate(self, val):
		delta = val - self.kShortMacEpoch
		sec = delta.days * 3600 * 24 + delta.seconds
		return newdesc(kae.typeLongDateTime, struct.pack('q', sec))
	
	def packdatetime(self, val):
		delta = val - self.kMacEpoch
		sec = delta.days * 3600 * 24 + delta.seconds
		return newdesc(kae.typeLongDateTime, struct.pack('q', sec))
	
	def packtime(self, val):
		return self.packdatetime(datetime.datetime.combine(datetime.date.today(), val))
	
	def packstructtime(self, val):
		sec = int(time.mktime(val) - self.kMacEpochT)
		return newdesc(kae.typeLongDateTime, struct.pack('q', sec))
	
	def packalias(self, val):
		return val.desc
	packfile = packalias
	
	##
	
	def packlist(self, val):
		lst = newlist()
		for item in val:
			lst.setitem(0, self.pack(item))
		return lst
	
	def packdict(self, val):
		record = newrecord()
		usrf = None
		for key, value in val.items():
			if isinstance(key, (AEType, AEProp)):
				if key.code == b'pcls': # AS packs records that contain a 'class' property by coercing the packed record to that type at the end
					try:
						record = record.coerce(value.code)
					except:
						record.setparam(key.code, self.pack(value))
				else:
					record.setparam(key.code, self.pack(value))
			else:
				if not usrf:
					usrf = newlist()
				usrf.setitem(0, self.pack(key))
				usrf.setitem(0, self.pack(value))
		if usrf:
			record.setparam(b'usrf', usrf)
		return record
	
	##
	
	def packtype(self, val):
		return newdesc(kae.typeType, fourcharcode(val.code))
	
	def packenum(self, val): 
		return newdesc(kae.typeEnumeration, fourcharcode(val.code))
	
	def packprop(self, val): 
		return newdesc(kae.typeProperty, fourcharcode(val.code))
	
	def packkey(self, val): 
		return newdesc(kae.typeKeyword, fourcharcode(val.code))

	
	###################################
	# unpack
	
	def unpacknull(self, desc):
		return None
	
	def unpackboolean(self, desc):
		return bool(desc.data[0])
	
	def unpacktrue(self, desc):
		return True
	
	def unpackfalse(self, desc):
		return False
	
	def unpacksint16(self, desc):
		return struct.unpack('h', desc.data)[0]
	
	def unpackuint16(self, desc):
		return struct.unpack('H', desc.data)[0]
	
	def unpacksint32(self, desc):
		return struct.unpack('i', desc.data)[0]
	
	def unpackuint32(self, desc):
		return struct.unpack('I', desc.data)[0]
	
	def unpacksint64(self, desc):
		return struct.unpack('q', desc.data)[0]
	
	def unpackuint64(self, desc):
		return struct.unpack('Q', desc.data)[0]
	
	def unpackfloat32(self, desc):
		return struct.unpack('f', desc.data)[0]
	
	def unpackfloat64(self, desc):
		return struct.unpack('d', desc.data)[0]
	
	def unpackfloat128(self, desc):
		return struct.unpack('d', desc.coerce(kae.typeIEEE64BitFloatingPoint).data)[0]

	##
	
	def unpackdata(self, desc):
		return desc.data
	
	##
	
	def unpackchar(self, desc):
		return self.unpackunicodetext(desc.coerce(kae.typeUnicodeText))
	
	def unpackintltext(self, desc):
		return self.unpackunicodetext(desc.coerce(kae.typeUnicodeText))
	
	def unpackutf8text(self, desc):
		return desc.data.decode('utf8')
	
	def unpackstyledtext(self, desc):
		return self.unpackunicodetext(desc.coerce(kae.typeUnicodeText))
	
	def unpackunicodetext(self, desc):
		# typeUnicodeText = native endian UTF16 with optional BOM
		data = desc.data
		if data.startswith(BOM_UTF16_BE):
			return data.decode('UTF-16BE')
		elif data.startswith(BOM_UTF16_LE):
			return data.decode('UTF-16LE')
		else:
			return data.decode(nativeutf16encoding)
	
	def unpackutf16externalrepresentation(self, desc): 
		# type UTF16ExternalRepresentation = big-endian UTF16 with optional byte-order-mark 
		# OR little-endian UTF16 with required byte-order-mark
		if desc.data.startswith(BOM_UTF16_LE):
			return desc.data.decode('UTF-16LE')
		else:
			return desc.data.decode('UTF-16BE')
	
	##
	
	def unpacklongdatetime(self, desc):
		return self.kMacEpoch + datetime.timedelta(seconds=struct.unpack('q', desc.data)[0])
	
	def unpackqdpoint(self, desc): 
		x, y = struct.unpack('hh', desc.data)
		return (y, x)
	
	def unpackqdrect(self, desc):
		x1, y1, x2, y2 = struct.unpack('hhhh', desc.data)
		return (y1, x1, y2, x2)
	
	def unpackrgbcolor(self, desc):
		return struct.unpack('HHH', desc.data)
	
	def unpackversion(self, desc):
		# Cocoa apps use unicode strings for version numbers, so return as string for consistency
		try:
			return self.unpack(desc.coerce(kae.typeUnicodeText)) # supported in 10.4+
		except:
			return '{}.{}.{}'.format(desc.data[0], *divmod(desc.data[1], 16)) # note: always big-endian
	
	##
	
	def unpackalias(self, desc):
		return mactypes.Alias.makewithdesc(desc)
		
	def unpackfileurl(self, desc):
		return mactypes.File.makewithdesc(desc)
	unpackfsref = unpackfss = unpackfileurl
	
	##
	
	def unpackaelist(self, desc):
		# Unpack list and its values.
		return [self.unpack(desc.getitem(i + 1, kae.typeWildCard)[1]) for i in range(desc.count())]
	
	def unpackaerecord(self, desc):
		# Unpack record to dict, converting keys from 4-letter codes to AEType instances and unpacking values.
		dct = {}
		for i in range(desc.count()):
			key, value = desc.getitem(i + 1, kae.typeWildCard)
			if key == b'usrf':
				lst = self.unpackaelist(value)
				for i in range(0, len(lst), 2):
					dct[lst[i]] = lst[i+1]
			else:
				dct[AEType(key)] = self.unpack(value)
		return dct

	##
	
	def unpacktype(self, desc):
		return AEType(fourcharcode(desc.data))
	
	def unpackenumeration(self, desc):
		return AEEnum(fourcharcode(desc.data))
	
	def unpackproperty(self, desc):
		return AEProp(fourcharcode(desc.data))
	
	def unpackkeyword(self, desc):
		return AEKey(fourcharcode(desc.data))
					
	##
	
	def fullyunpackobjectspecifier(self, desc):
		# This function performs a full recursive unpacking of object specifiers, reconstructing an 'app'/'con'/'its' based aem reference from the ground up.
		want = self.unpack(desc.getparam(kae.keyAEDesiredClass, kae.typeType)).code # 4-letter code indicating element class
		keyform = self.unpack(desc.getparam(kae.keyAEKeyForm, kae.typeEnumeration)).code # 4-letter code indicating Specifier type
		key = self.unpack(desc.getparam(kae.keyAEKeyData, kae.typeWildCard)) # value indicating which object(s) to select
		ref = self.unpack(desc.getparam(kae.keyAEContainer, kae.typeWildCard)) # recursively unpack container structure
		if not isinstance(ref, aemreference.Query):
			if ref is None:
				ref = self.app
			else:
				ref = self.customroot(ref)
		# print(want, keyform, key, ref) # DEBUG
		if keyform == kae.formPropertyID: # property specifier
			return ref.property(key.code)
		elif keyform == b'usrp': # user-defined property specifier
			return ref.userproperty(key)
		elif keyform == kae.formRelativePosition: # relative element specifier
			if key.code == kae.kAEPrevious:
				return ref.previous(want)
			elif key.code == kae.kAENext:
				return ref.next(want)
			else:
				raise ValueError("Bad relative position selector: {!r}".format(want))
		else: # other element(s) specifier
			ref = ref.elements(want)
			if keyform == kae.formName:
				return ref.byname(key)
			elif keyform == kae.formAbsolutePosition:
				if isinstance(key, _Ordinal):
					if key.code == kae.kAEAll:
						return ref
					else:
						return getattr(ref, {kae.kAEFirst: 'first', kae.kAELast: 'last', kae.kAEMiddle: 'middle', kae.kAEAny: 'any'}[key.code])
				else:
					return ref.byindex(key)
			elif keyform == kae.formUniqueID:
				return ref.byid(key)
			elif keyform == kae.formRange:
				return ref.byrange(*key.range)
			elif keyform == kae.formTest:
				return ref.byfilter(key)
		raise TypeError
	
	
	def unpackobjectspecifier(self, desc):
		# This function performance-optimises the unpacking of some object specifiers by only doing a shallow unpack where only the topmost descriptor is unpacked.
		# The container AEDesc is retained as-is, allowing a full recursive unpack to be performed later on only if needed (e.g. if the __repr__ method is called).
		# For simplicity, only the commonly encountered forms are optimised this way; forms that are rarely returned by applications (e.g. typeRange) are always fully unpacked.
		keyform = self.unpack(desc.getparam(kae.keyAEKeyForm, kae.typeEnumeration)).code
		if keyform in [kae.formPropertyID, kae.formAbsolutePosition, kae.formName, kae.formUniqueID]:
			want = self.unpack(desc.getparam(kae.keyAEDesiredClass, kae.typeType)).code # 4-letter code indicating element class
			key = self.unpack(desc.getparam(kae.keyAEKeyData, kae.typeWildCard)) # value indicating which object(s) to select
			container = aemreference.DeferredSpecifier(desc.getparam(kae.keyAEContainer, kae.typeWildCard), self)
			if keyform == kae.formPropertyID:
				ref = aemreference.Property(want, container, key.code)
			elif keyform == kae.formAbsolutePosition:
				if isinstance(key, _Ordinal):
					if key.code == kae.kAEAll:
						ref = aemreference.AllElements(want, container)
					else:
						keyname = {kae.kAEFirst: 'first', kae.kAELast: 'last', kae.kAEMiddle: 'middle', kae.kAEAny: 'any'}[key.code]
						ref = aemreference.ElementByOrdinal(want, aemreference.UnkeyedElements(want, container), key, keyname)
				else:
					ref = aemreference.ElementByIndex(want, aemreference.UnkeyedElements(want, container), key)
			elif keyform == kae.formName:
				ref = aemreference.ElementByName(want, aemreference.UnkeyedElements(want, container), key)
			elif keyform == kae.formUniqueID:
				ref = aemreference.ElementByID(want, aemreference.UnkeyedElements(want, container), key)
			ref.AEM_packself = lambda codecs:desc
			return ref
		else: # do full unpack of more complex, rarely returned reference forms
			return self.fullyunpackobjectspecifier(desc)
	
	
	def unpackinsertionloc(self, desc):
		return getattr(self.fullyunpackobjectspecifier(desc.getparam(kae.keyAEObject, kae.typeWildCard)), 
				self.kInsertionLocSelectors[desc.getparam(kae.keyAEPosition, kae.typeEnumeration).data])
	
	
	def unpackcompdescriptor(self, desc):
		operator = self.kTypeCompDescriptorOperators[desc.getparam(kae.keyAECompOperator, kae.typeEnumeration).data]
		op1 = self.unpack(desc.getparam(kae.keyAEObject1, kae.typeWildCard))
		op2 = self.unpack(desc.getparam(kae.keyAEObject2, kae.typeWildCard))
		if operator == 'contains':
			if isinstance(op1, aemreference.Query) and op1.AEM_root() == aemreference.its:
				return op1.contains(op2)
			else:
				return op2.isin(op1)
		return getattr(op1, operator)(op2)
	
	
	def unpacklogicaldescriptor(self, desc):
		operator = self.kTypeLogicalDescriptorOperators[desc.getparam(kae.keyAELogicalOperator, kae.typeEnumeration).data]
		operands = self.unpack(desc.getparam(kae.keyAELogicalTerms, kae.typeAEList))
		return operator == 'NOT' and operands[0].NOT or getattr(operands[0], operator)(*operands[1:])
	
	def unpackrangedescriptor(self, desc):
		return _Range([self.unpack(desc.getparam(kae.keyAERangeStart, kae.typeWildCard)), 
				self.unpack(desc.getparam(kae.keyAERangeStop, kae.typeWildCard))])
	
	
	def unpackabsoluteordinal(self, desc):
		return _Ordinal(fourcharcode(desc.data))
	
	##
	
	app = aemreference.app
	con = aemreference.con
	its = aemreference.its
	customroot = aemreference.customroot
	

