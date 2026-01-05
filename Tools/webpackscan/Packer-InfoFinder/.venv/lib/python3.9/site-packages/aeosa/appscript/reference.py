"""reference -- High-level, terminology-driven wrapper for aem. 

Lots of syntactic sugar allows users to construct query-based references using familiar OO-like syntax.
"""

import struct, sys
from time import sleep

import aem, mactypes
from aem import kae
from aem.ae import newlist, newrecord, newdesc, MacOSError
from aem.aemreference import InsertionSpecifier, Test

from .genericreference import GenericReference
from . import terminology
from .terminology import kProperty, kElement
from .referencerenderer import renderreference
from .keywordwrapper import Keyword


######################################################################
# PRIVATE
######################################################################
# Codecs

_lowlevelcodecs = aem.Codecs()


###################################
# Application-specific data/codecs

class AppData(aem.Codecs):
	"""Provides application-specific:
		- aem.Application instance
		- name-code terminology translation tables
		- pack/unpack methods
		- help system
	"""
	
	#######
	# constants, etc.
	
	keyAECompOperator = aem.AEType(kae.keyAECompOperator)
	keyAEObject1 = aem.AEType(kae.keyAEObject1)
	keyAEObject2 = aem.AEType(kae.keyAEObject2)

	kAppscriptTypeCompDescriptorOperators = {
			kae. kAEGreaterThan: 'AS__gt__',
			kae.kAEGreaterThanEquals: 'AS__ge__',
			kae.kAEEquals: 'AS__eq__',
			kae.kAELessThan: 'AS__lt__',
			kae.kAELessThanEquals: 'AS__le__',
			kae.kAEBeginsWith: 'beginswith',
			kae.kAEEndsWith: 'endswith',
			kae.kAEContains: 'contains'
	}
	
	kClassKeyword = Keyword('class_')
	kClassType = aem.AEType(b'pcls')
	
	kHelpAgentBundleID = 'net.sourceforge.appscript.asdictionary'
	
	
	#######
	# initialiser
	
	def __init__(self, aemapplicationclass, constructor, identifier, terms, aemconstructoroptions={}):
		"""
			aemapplicationclass : class -- aem.Application or equivalent
			constructor : str -- indicates how to construct the aem.Application instance ('path', 'pid', 'url', 'aemapp', 'current')
			identifier : any -- value identifying the target application (its type is dependent on constructor parameter)
			terms : bool | module | tuple -- if True, retrieve terminology from target application dynamically; 
					if false, use only default terminology; if static glue module or tuple, use terminology from that
			aemconstructoroptions -- any additional keyword arguments to pass to aemapplicationclass constructor
					(e.g. newinstance, hide)
		"""
		# initialise codecs
		aem.Codecs.__init__(self)
		self.decoders.update({
				kae.typeType: self.unpackkeyword,
				kae.typeEnumerated: self.unpackkeyword,
				kae.typeProperty: self.unpackkeyword,
				kae.typeObjectSpecifier: self.unpackreference,
				kae.typeInsertionLoc: self.unpackreference,
				# AEAddressDesc types
				kae.typeApplicationBundleID: self.unpackapplicationbyid,
				kae.typeApplicationURL: self.unpackapplicationbyurl,
#				kae.typeApplSignature: self.unpackapplicationbysignature, # OSType; very deprecated # TO DO: can this address desc be coerced to typeApplicationBundleID?
				kae.typeKernelProcessID: self.unpackapplicationbypid,
				kae.typeMachPort: self.unpackapplicationbydesc,
				kae.typeProcessSerialNumber: self.unpackapplicationbydesc,
		})
		# store parameters for later use
		self._aemapplicationclass = aemapplicationclass
		self.constructor, self.identifier = constructor, identifier
		self.aemconstructoroptions = aemconstructoroptions
		self._relaunchmode = 'limited'
		self._terms = terms
		self._helpagent = None
		self._isconnected = False
	
	
	#######
	
	# Terminology-aware pack/unpack functions.
	# These replace the default aem pack/unpack functions, which don't understand appscript Keyword and Reference objects.
	
	def packdict(self, val):
		# Pack dictionary whose keys are strings (e.g. 'foo'), Keywords (e.g. k.name) or AETypes (e.g. AEType(b'pnam').
		record = newrecord()
		if self.kClassKeyword in val or self.kClassType in val:
			# if hash contains a 'class' property containing a class name, coerce the AEDesc to that class
			newval = val.copy()
			if self.kClassKeyword in newval:
				value = newval.pop(self.kClassKeyword)
			else:
				value = newval.pop(self.kClassType)
			if isinstance(value, Keyword): # get the corresponding AEType (assuming there is one)
				value = self.typebyname().get(value.name, value)
			if isinstance(value, aem.AEType): # coerce the record to the desired type
				record = record.coerce(value.code)
				val = newval
		usrf = None
		for key, value in val.items():
			if isinstance(key, Keyword):
				try:
					keyCode = self.typebyname()[key.AS_name].code
				except KeyError as err:
					raise ValueError("Unknown Keyword: k.{}".format(key.AS_name)) from err
				record.setparam(keyCode, self.pack(value))
			elif isinstance(key, aem.AETypeBase): # AEType/AEProp (AEType is normally used in practice)
				record.setparam(key.code, self.pack(value))
			else: # user-defined key (normally a string)
				if not usrf:
					usrf = newlist()
				usrf.setitem(0, self.pack(key))
				usrf.setitem(0, self.pack(value))
		if usrf:
			record.setparam(b'usrf', usrf)
		return record
	
	
	def unpackaerecord(self, desc):
		# Unpack typeAERecord,  converting record keys to Keyword objects (not AETypes) where possible.
		dct = {}
		for i in range(desc.count()):
			key, value = desc.getitem(i + 1, kae.typeWildCard)
			if key == b'usrf':
				lst = self.unpack(value)
				for i in range(0, len(lst), 2):
					dct[lst[i]] = lst[i+1]
			elif key in self.typebycode():
				dct[self.typebycode()[key]] = self.unpack(value)
			else:
				dct[aem.AEType(key)] = self.unpack(value)
		return dct

	##
	
	def unpackkeyword(self, desc):
		# Unpack typeType, typeEnum, typeProperty; replaces default aem decoders to convert types, enums, etc.
		# to Keyword objects instead of AETypes, AEEnums, etc.
		aemValue = _lowlevelcodecs.unpack(desc)
		return self.typebycode().get(aemValue.code, aemValue)
	
	
	def unpackreference(self, desc):
		return Reference(self, _lowlevelcodecs.unpack(desc))
	
	
	def unpackcompdescriptor(self, desc):
		# need to do some typechecking when unpacking 'contains' comparisons, so have to override the low-level unpacker
		rec = self.unpack(desc.coerce(kae.typeAERecord))
		operator = self.kAppscriptTypeCompDescriptorOperators[rec[self.keyAECompOperator].code]
		op1 = rec[self.keyAEObject1]
		op2 = rec[self.keyAEObject2]
		if operator == 'contains':
			if isinstance(op1, Reference) and op1.AS_aemreference.AEM_root() == aem.its:
				return op1.contains(op2)
			elif isinstance(op2, Reference) and op2.AS_aemreference.AEM_root() == aem.its:
				return op2.isin(op1)
			else:
				return _lowlevelcodecs.unpack(desc)
		else:
			return getattr(op1, operator)(op2)
	
	##
	
	def unpackapplicationbyid(self, desc):
		return app(id=desc.data)
	
	def unpackapplicationbyurl(self, desc):
		if desc.data.startswith(b'file'): # workaround for converting AEAddressDescs containing file:// URLs to application paths, since AEAddressDescs containing file URLs don't seem to work correctly
			return app(mactypes.File.makewithurl(desc.data.decode('utf8')).path)
		else: # presumably contains an eppc:// URL
			return app(url=desc.data)
	
	def unpackapplicationbypid(self, desc):
		return app(pid=struct.unpack('I', desc.data)[0])
	
	def unpackapplicationbydesc(self, desc):
		return app(aemapp=aem.Application(desc=desc))

	#######
	
	isconnected = property(lambda self: self._isconnected)
	
	def connect(self):
		"""Initialises application target and terminology lookup tables.
		
		Called automatically the first time clients retrieve target, typebycode, typebyname,
		referencebycode, referencebyname; clients should not need to call it themselves.
		"""
		# initialise target (by default an aem.Application instance)
		if self.constructor == 'aemapp':
			t = self._target = self.identifier
		elif self.constructor == 'current':
			t = self._target = self._aemapplicationclass()
		else:
			kargs = {self.constructor: self.identifier}
			kargs.update(self.aemconstructoroptions)
			t = self._target = self._aemapplicationclass(**kargs)
		# initialise translation tables
		if self._terms in ['aete', 'sdef', True]: # obtain terminology from application
			self._terms = terminology.tablesforapp(t, usesdef=(self._terms == 'sdef'))
		elif self._terms in ['default', False]: # use built-in terminology only (e.g. targeting an AppleScript applet)
			self._terms = terminology.defaulttables
		elif not isinstance(self._terms, tuple): # use user-supplied terminology module
			self._terms = terminology.tablesformodule(self._terms)
		d1, d2, d3, d4 = self._typebycode, self._typebyname, \
				self._referencebycode, self._referencebyname = self._terms
		self.target = lambda: t
		self.typebycode = lambda: d1
		self.typebyname = lambda: d2
		self.referencebycode = lambda: d3
		self.referencebyname = lambda: d4
		self._isconnected = True
	
	def target(self):
		self.connect()
		return self._target
	
	def typebycode(self):
		self.connect()
		return self._typebycode
	
	def typebyname(self):
		self.connect()
		return self._typebyname
	
	def referencebycode(self):
		self.connect()
		return self._referencebycode
	
	def referencebyname(self):
		self.connect()
		return self._referencebyname
		
	_kYes = Keyword('yes')
	_kNo = Keyword('no')
	_kAsk = Keyword('ask')
	
	def permissiontoautomate(self, code=kae.typeWildCard*2):
		try:
			self.target().permissiontoautomate(code[:4], code[4:], True)
		except MacOSError as e:
			if e.args[0] == -1744: # errAEEventWouldRequireUserConsent
				return self._kAsk # unknown (i.e. user has yet to allow/forbid access)
			elif e.args[0] == -1743: # errAEEventNotPermitted (broken in 10.14.x; see <rdar://44049802>)
				return self._kNo
			else: # e.g. -600 (process not found)
				raise
		except NotImplementedError: # always True if OS version < 10.14
			pass
		return self._kYes
	
	##
	
	def pack(self, data):
		if isinstance(data, GenericReference):
			data = data.AS_resolve(Reference, self)
		if isinstance(data, Reference):
			data = data.AS_aemreference
		elif isinstance(data, Keyword):
			try:
				data = self.typebyname()[data.AS_name]
			except KeyError as err:
				raise ValueError("Unknown Keyword: k.{}".format(data.AS_name)) from err
		return aem.Codecs.pack(self, data)
	
	# Relaunch mode
	
	def _setrelaunchmode(self, mode):
		if mode not in ['never', 'limited', 'always']:
			raise ValueError('Unknown relaunch mode: {!r}'.format(mode))
		self._relaunchmode = mode
	relaunchmode = property(lambda self: self._relaunchmode, _setrelaunchmode)
	
	# Help system
	
	def _write(self, s):
		print(s, file=sys.stderr)
	
	def _inithelpagent(self):
		try:
			apppath = aem.findapp.byid(self.kHelpAgentBundleID)
			self._helpagent = aem.Application(apppath, hide=True)
			return True
		except aem.findapp.ApplicationNotFoundError:
			self._write("No help available: ASDictionary application not found.")
		except aem.CantLaunchApplicationError:
			self._write("No help available: can't launch ASDictionary application.")
		return False
	
	def _displayhelp(self, flags, ref):
		if isinstance(ref, Command):
			commandname = ref.AS_name
			ref = ref.AS_aemreference
		else:
			commandname = ''
		try:
			self._write(self._helpagent.event(b'AppSHelp', {
					b'Cons': self.constructor,
					b'Iden': self.identifier,
					b'Styl': 'py-appscript',
					b'Flag': flags,
					b'aRef': self.pack(ref),
					b'CNam': commandname
					}).send())
			return None
		except aem.EventError as e:
			return e
	
	def help(self, flags, ref):
		try:
			if not self._helpagent: # initialise help system upon first use
				if not self._inithelpagent():
					return ref # if ASDictionary is unavailable then do nothing
			e = self._displayhelp(flags, ref)
			if e and e.errornumber in [-600, -609]: # ASDictionary is no longer running, so reconnect
				if not self._inithelpagent():
					return ref # if ASDictionary is unavailable then do nothing
				e = self._displayhelp(flags, ref)
			if e:
				self._write("No help available: ASDictionary raised an error: {}".format(e))
		except Exception as err:
			self._write("No help available: unknown error: {}".format(err))
			from traceback import print_exc
			print_exc()
		return ref


######################################################################
# Considering/ignoring constants

def _packuint32(n): # used to pack csig attributes
	return newdesc(kae.typeUInt32, struct.pack('I', n))

# 'csig' attribute flags (see ASRegistry.h; note: there's no option for 'numeric strings' in 10.4)

_ignoreenums = [
	(Keyword('case'), kae.kAECaseConsiderMask, kae.kAECaseIgnoreMask),
	(Keyword('diacriticals'), kae.kAEDiacriticConsiderMask, kae.kAEDiacriticIgnoreMask),
	(Keyword('whitespace'), kae.kAEWhiteSpaceConsiderMask, kae.kAEWhiteSpaceIgnoreMask),
	(Keyword('hyphens'), kae.kAEHyphensConsiderMask, kae.kAEHyphensIgnoreMask),
	(Keyword('expansion'), kae.kAEExpansionConsiderMask, kae.kAEExpansionIgnoreMask),
	(Keyword('punctuation'), kae.kAEPunctuationConsiderMask, kae.kAEPunctuationIgnoreMask),
	]

# default cons, csig attributes

_defaultconsiderations =  _lowlevelcodecs.pack([aem.AEEnum(kae.kAECase)])
_defaultconsidsandignores = _packuint32(kae.kAECaseIgnoreMask)


######################################################################
# Base class for references and commands

class _Base:
	# Base class for Command and Reference objects.
	def __init__(self, appdata):
		self.AS_appdata = appdata
		
	# Help system
	
	def help(self, flags='-t'): # add a help() method to all concrete app, reference and command objects
		"""Print help. Use help('-h') for more info."""
		return self.AS_appdata.help(flags, self)


######################################################################
# PUBLIC
######################################################################
# The Reference and Command classes are used to construct references and commands applying to those references

class Command(_Base):
	
	def __init__(self, parentref, name, code, arginfo):
		_Base.__init__(self, parentref.AS_appdata)
		self.AS_aemreference = parentref.AS_aemreference
		self.AS_name = name
		self._parentref = parentref
		self._code = code
		self._labelledargterms = arginfo
	
	def __repr__(self):
		return '{!r}.{}'.format(self._parentref, self.AS_name)
	
	def __call__(self, *args, **kargs):
		keywordargs = kargs.copy()
		if len(args) > 1:
			raise TypeError("Command received more than one direct parameter {!r}.".format(args))
		# get user-specified timeout, if any
		timeout = int(keywordargs.pop('timeout', 60)) # appscript's default is 60 sec
		if timeout <= 0:
			timeout = kae.kNoTimeOut
		else:
			timeout *= 60 # convert to ticks
		# ignore application's reply?
		sendflags = keywordargs.pop('waitreply', True) and kae.kAEWaitReply or kae.kAENoReply
		# allow macOS 10.14+ to prompt user for access to target app, if needed, before sending it this event (if False, throws CommandError -1744 if user hasn't yet granted permission)
		canaskforconsent = bool(keywordargs.pop('canaskforconsent', True))
		if not canaskforconsent:
			sendflags |= kAEDoNotPromptForUserConsent
		atts, params = {b'subj':None}, {}
		# add considering/ignoring attributes (note: most apps currently ignore these)
		ignoreoptions = keywordargs.pop('ignore', None)
		if ignoreoptions is None:
			atts[b'cons'] = _defaultconsiderations # 'csig' obsoletes 'cons', but latter is retained for compatibility
			atts[b'csig'] = _defaultconsidsandignores
		else:
			atts[b'cons'] = ignoreoptions
			csig = 0
			for option, considermask, ignoremask in _ignoreenums:
				csig += option in ignoreoptions and ignoremask or considermask
			atts[b'csig'] = _packuint32(csig)
		# optionally have application supply return value as specified type
		if 'resulttype' in keywordargs:
			params[b'rtyp'] = keywordargs.pop('resulttype')
		# add direct parameter, if any
		if args:
			params[b'----'] = args[0]
		# extract Apple event's labelled parameters, if any
		try:
			for name, value in keywordargs.items():
				params[self._labelledargterms[name]] = value
		except KeyError as err:
			raise TypeError('Unknown keyword argument {!r}.'.format(name)) from err
		# apply special cases for certain commands (make, set, any command that takes target object specifier as its direct parameter); appscript provides these as a convenience to users, making its syntax more concise, OO-like and nicer to use
		if self.AS_aemreference is not aem.app:
			if self._code == b'coresetd':
				# Special case: if ref.set(...) contains no 'to' argument, use direct argument for 'to' parameter and target reference for direct parameter
				if b'----' in params and b'data' not in params:
					params[b'data'] = params[b'----']
					params[b'----'] = self.AS_aemreference
				elif b'----' not in params:
					params[b'----'] = self.AS_aemreference
				else:
					atts[b'subj'] = self.AS_aemreference
			elif self._code == b'corecrel':
				# this next bit is a bit tricky: 
				# - While it should be possible to pack the target reference as a subject attribute, when the target is of typeInsertionLoc, CocoaScripting stupidly tries to coerce it to typeObjectSpecifier, which causes a coercion error.
				# - While it should be possible to pack the target reference as the 'at' parameter, some less-well-designed applications won't accept this and require it to be supplied as a subject attribute (i.e. how AppleScript supplies it).
				# One option is to follow the AppleScript approach and force users to always supply subject attributes as target references and 'at' parameters as 'at' parameters, but the syntax for the latter is clumsy and not backwards-compatible with a lot of existing appscript code (since earlier versions allowed the 'at' parameter to be given as the target reference). So for now we split the difference when deciding what to do with a target reference: if it's an insertion location then pack it as the 'at' parameter (where possible), otherwise pack it as the subject attribute (and if the application doesn't like that then it's up to the client to pack it as an 'at' parameter themselves).
				#
				# if ref.make(...) contains no 'at' argument and target is an insertion reference, use target reference for 'at' parameter...
				if isinstance(self.AS_aemreference, InsertionSpecifier) and b'insh' not in params:
					params[b'insh'] = self.AS_aemreference
				else: # ...otherwise pack the target reference as the subject attribute
					atts[b'subj'] = self.AS_aemreference
			elif b'----' in params:
				# if user has already supplied a direct parameter, pack that reference as the subject attribute
				atts[b'subj'] = self.AS_aemreference
			else:
				# pack that reference as the direct parameter
				params[b'----'] = self.AS_aemreference
		# build and send the Apple event, returning its result, if any
		try:
			return self.AS_appdata.target().event(self._code, params, atts, codecs=self.AS_appdata).send(timeout, sendflags)
		except aem.EventError as e:
			if e.errornumber == -1708 and self._code == b'ascrnoop':
				return # 'launch' events always return 'not handled' errors; just ignore these
			elif e.errornumber in [-600, -609] and self.AS_appdata.constructor == 'path':
				#
				# Event was sent to a local app for which we no longer have a valid address
				# (i.e. the application has quit since this aem.Application object was made).
				#
				# - If application is running under a new process id, we just update the 
				#   aem.Application object and resend the event.
				#
				# - If application isn't running, then we see if the event being sent is one of 
				#   those allowed to relaunch the application (i.e. 'run' or 'launch'). If it is, the
				#   application is relaunched, the process id updated and the event resent;
				#   if not, the error is rethrown.
				#
				if not self.AS_appdata.target().processexistsforpath(self.AS_appdata.identifier):
					if self.AS_appdata.relaunchmode == 'never':
						raise CommandError(self, (args, kargs), e, self.AS_appdata) from e
					elif self.AS_appdata.relaunchmode == 'limited':
						if self._code == b'ascrnoop':
							aem.Application.launch(self.AS_appdata.identifier) # relaunch app in background
						elif self._code != b'aevtoapp': # only 'launch' and 'run' are allowed to restart a local application that's been quit
							raise CommandError(self, (args, kargs), e, self.AS_appdata) from e
					# else always relaunch
				# update AEMApplication object's AEAddressDesc
				self.AS_appdata.target().reconnect()
				# re-send command
				try:
					return self.AS_appdata.target().event(self._code, params, atts, 
							codecs=self.AS_appdata).send(timeout, sendflags)
				except aem.EventError as e:
					if e.errornumber == -1708 and self._code == 'ascrnoop':
						return
					raise CommandError(self, (args, kargs), e, self.AS_appdata) from e
			raise CommandError(self, (args, kargs), e, self.AS_appdata) from e
	
	def AS_formatcommand(self, args):
		return '{!r}({})'.format(self, ', '.join(['{!r}'.format(v) for v in args[0]] + ['{}={!r}'.format(k, v) for (k, v) in args[1].items()]))
	
	permissiontoautomate = property(lambda self: self.AS_appdata.permissiontoautomate(self._code))
		

######################################################################

class Reference(_Base):
	# A general-purpose class used to construct all real appscript references. 
	# It's a simple wrapper around an aem reference that provides syntactic sugar 
	# and terminology->AE code conversion. Calling a reference-building method 
	# returns a new Reference object containing the new reference, except where 
	# it would create a structurally invalid reference (e.g. ref.items[1]['foo']), in which 
	# case the aem reference will raise an AttributeError.
	
	def __init__(self, appdata, aemreference):
		_Base.__init__(self, appdata)
		self.AS_aemreference = aemreference # an aem app-/con-/its-based reference
	
	def _resolverangeboundary(self, selector, valueifnone): # used by __getitem__() below
		if selector is None: # e.g. documents[2:]
			selector = valueifnone 
		if isinstance(selector, GenericReference):
			return selector.AS_resolve(Reference, self.AS_appdata).AS_aemreference
		elif isinstance(selector, Reference):
			return selector.AS_aemreference
		else:
			return selector
	
	# Full references are hashable and comparable for equality. (Generic references aren't, 
	# however, as __eq__() is overridden for other purposes, but the user shouldn't be 
	# troubled by this given how generic refs are normally used.)
	
	def __eq__(self, val):
		return self.__class__ == val.__class__ and \
				self.AS_appdata.target() == val.AS_appdata.target() and \
				self.AS_aemreference == val.AS_aemreference
	
	def __ne__(self, val):
		return not self == val
	
	def __hash__(self):
		val = hash((self.AS_aemreference, self.AS_appdata.target()))
		self.__hash__ = lambda: val
		return val
	
	def __iter__(self): # dummy-proof
		raise RuntimeError("Can't iterate an application reference; use ref.get() to return a list of references first.")
	
	def __repr__(self): # references display as themselves
		val = renderreference(self.AS_appdata, self.AS_aemreference)
		self.__repr__ = lambda: val
		return val
		
	# miscellaneous
	
	def isrunning(self):
		constructor = self.AS_appdata.constructor
		identifier = self.AS_appdata.identifier
		if constructor == 'path':
			return aem.Application.processexistsforpath(identifier)
		elif constructor == 'pid':
			return aem.Application.processexistsforpid(identifier)
		elif constructor == 'url':
			return aem.Application.processexistsforurl(identifier)
		elif constructor == 'aemapp':
			return aem.Application.processexistsforpath(identifier.addressdesc)
		else: # constructor == 'current'
			return True
	
	def _setrelaunchmode(self, mode): # mode = 'never', 'limited' or 'always'
		self.AS_appdata.relaunchmode = mode
	relaunchmode = property(lambda self: self.AS_appdata.relaunchmode, _setrelaunchmode)
	
	# Public properties and methods; these are called by end-user and other clients (e.g. generic references)
	
	def __getattr__(self, name):
		try:
			selectortype, code = self.AS_appdata.referencebyname()[name]
		except KeyError as e:
			raise AttributeError("Unknown property, element or command: {!r}".format(name)) from e
		if selectortype == kProperty:
			return Reference(self.AS_appdata, self.AS_aemreference.property(code))
		elif selectortype == kElement:
			return Reference(self.AS_appdata, self.AS_aemreference.elements(code))
		else: # kCommand (note: 'code' variable here actually contains a (code, args) struct)
			return Command(self, name, code[0], code[1])
	
	def __getitem__(self, selector):
		if isinstance(selector, str): # by-name
			return Reference(self.AS_appdata, self.AS_aemreference.byname(selector))
		elif isinstance(selector, (GenericReference, Reference, Test)): # by-test
			if isinstance(selector, GenericReference):
				testclause = selector.AS_resolve(Reference, self.AS_appdata)
				try:
					testclause = testclause.AS_aemreference
				except AttributeError as e:
					raise ValueError('Not a valid its-based test: {!r}'.format(selector)) from e
			elif isinstance(selector, Reference):
				testclause = selector.AS_aemreference
			else:
				testclause = selector
			if not isinstance(testclause, Test):
				raise TypeError('Not an its-based test: {!r}'.format(selector))
			return Reference(self.AS_appdata, self.AS_aemreference.byfilter(testclause))
		elif isinstance(selector, slice): # by-range
			return Reference(self.AS_appdata, self.AS_aemreference.byrange(
					self._resolverangeboundary(selector.start, 1),
					self._resolverangeboundary(selector.stop, -1)))
		else: # by-index
			return Reference(self.AS_appdata, self.AS_aemreference.byindex(selector))
	
	first = property(lambda self: Reference(self.AS_appdata, self.AS_aemreference.first))
	middle = property(lambda self: Reference(self.AS_appdata, self.AS_aemreference.middle))
	last = property(lambda self: Reference(self.AS_appdata, self.AS_aemreference.last))
	any = property(lambda self: Reference(self.AS_appdata, self.AS_aemreference.any))
	beginning = property(lambda self: Reference(self.AS_appdata, self.AS_aemreference.beginning))
	end = property(lambda self: Reference(self.AS_appdata, self.AS_aemreference.end))
	before = property(lambda self: Reference(self.AS_appdata, self.AS_aemreference.before))
	after = property(lambda self: Reference(self.AS_appdata, self.AS_aemreference.after))
	
	def previous(self, klass):
		try:
			aemtype = self.AS_appdata.typebyname()[klass.AS_name]
		except AttributeError as e: # can't get klass.AS_name
			raise TypeError("Not a keyword: {!r}".format(name)) from e
		except KeyError as e: # can't get typebyname[<name>]
			raise ValueError("Unknown class: {!r}".format(name)) from e
		return Reference(self.AS_appdata, self.AS_aemreference.previous(aemtype.code))
	
	def next(self, klass):
		try:
			aemtype = self.AS_appdata.typebyname()[klass.AS_name]
		except AttributeError as e: # can't get klass.AS_name
			raise TypeError("Not a keyword: {!r}".format(name)) from e
		except KeyError as e: # can't get typebyname[<name>]
			raise ValueError("Unknown class: {!r}".format(name)) from e
		return Reference(self.AS_appdata, self.AS_aemreference.next(aemtype.code))
	
	def ID(self, id):
		return Reference(self.AS_appdata, self.AS_aemreference.byid(id))
	
	def __call__(self, *args, **kargs):
		return self.get(*args, **kargs)
	
	# Following methods will be called by its-based generic references when resolving themselves into real references; end-users and other clients shouldn't call them directly.
	
	def AS__gt__(self, operand):
		return Reference(self.AS_appdata, self.AS_aemreference.gt(operand))
	
	def AS__ge__(self, operand):
		return Reference(self.AS_appdata, self.AS_aemreference.ge(operand))
	
	def AS__eq__(self, operand):
		return Reference(self.AS_appdata, self.AS_aemreference.eq(operand))
	
	def AS__ne__(self, operand):
		return Reference(self.AS_appdata, self.AS_aemreference.ne(operand))
	
	def AS__lt__(self, operand):
		return Reference(self.AS_appdata, self.AS_aemreference.lt(operand))
	
	def AS__le__(self, operand):
		return Reference(self.AS_appdata, self.AS_aemreference.le(operand))
	
	def beginswith(self, operand):
		return Reference(self.AS_appdata, self.AS_aemreference.beginswith(operand))
	
	def endswith(self, operand):
		return Reference(self.AS_appdata, self.AS_aemreference.endswith(operand))
	
	def contains(self, operand):
		return Reference(self.AS_appdata, self.AS_aemreference.contains(operand))
	
	def isin(self, operand):
		return Reference(self.AS_appdata, self.AS_aemreference.isin(operand))
	
	def doesnotbeginwith(self, operand):
		return self.beginswith(operand).NOT
	
	def doesnotendwith(self, operand):
		return self.endswith(operand).NOT
	
	def doesnotcontain(self, operand):
		return self.contains(operand).NOT
	
	def isnotin(self, operand):
		return self.isin(operand).NOT
	
	def AND(self, *operands):
		return Reference(self.AS_appdata, self.AS_aemreference.AND(*operands))
		
	def OR(self, *operands):
		return Reference(self.AS_appdata, self.AS_aemreference.OR(*operands))
	
	NOT = property(lambda self: Reference(self.AS_appdata, self.AS_aemreference.NOT))


######################################################################
# The Application class is not directly instantiated by the user; instead, they call 
# the GenericApp instance and this returns the real Application instance. This allows 
# users to write generic app-based references, e.g. app.documents.end, as well as 
# real ones, e.g. app('TextEdit').documents.end

class Application(Reference):
	"""Creates objects for communicating with scriptable applications."""
	
	# overridable hook; appscript.Application subclasses can modify creating
	# and/or sending Apple events by using custom aem.Application and
	# aem.Event classes # Note: subclassing this class is now a bit trickier 
	# due to introduction of generic 'app'; clients need to import this class 
	# directly, subclass it, and then create their own GenericApp instance to 
	# use in place of the standard version.
	_Application = aem.Application
	
	def __init__(self, name=None, id=None, pid=None, url=None, aemapp=None, 
			terms='aete', newinstance=False, hide=False):
		"""
			app(name=None, id=None, pid=None, url=None, terms=True)
				name : str -- name or path of application, e.g. 'TextEdit', 'TextEdit.app', '/System/Applications/Textedit.app'
				id : str -- bundle id of application, e.g. 'com.apple.textedit'
				pid : int -- Unix process id, e.g. 955
				url : str -- eppc:// URL, e.g. eppc://G4.local/TextEdit'
				aemapp : aem.Application
				terms : module | 'default' | 'aete' | 'sdef' -- if a module, get terminology from it; 
						if 'aete' or 'sdef', get terminology from target application; 
						if 'default', use built-in terminology only
						(legacy support also accepts bool: True = 'aete', False = 'sdef')
				newinstance : bool -- launch a new application instance?
				hide : bool -- hide after launch?
			
			Notes: 
			
			- The newinstance and hide options only apply when specifying application by name, or id.
		"""
		if len([i for i in [name, id, pid, url, aemapp] if i]) > 1:
			raise TypeError('app() received more than one of the following arguments: name, id, pid, url, aemapp')
		if name:
			constructor, identifier = 'path', aem.findapp.byname(name)
		elif id:
			constructor, identifier = 'path',  aem.findapp.byid(id)
		elif pid:
			constructor, identifier = 'pid', pid
		elif url:
			constructor, identifier = 'url', url
		elif aemapp:
			constructor, identifier = 'aemapp', aemapp
		else:
			constructor, identifier = 'current', None
		# Defer initialisation of AppData until it's needed. This allows user to call launch() on a non-running application without the application being launched by aem.Application, which automatically launches local applications in order to construct an AEAddressDesc of typeProcessSerialNumber.
		# launch()'s usefulness is somewhat limited, since constructing a real app-based reference will also launch the application normally in order to get its terminology. So to actually launch an application, you have to use launch() before constructing any real references to its objects; i.e.:
		#     te = app('TextEdit'); te.launch(); d = app.documents
		# will launch TE without it creating any new documents (i.e. app receives 'ascrnoop' as its first event), but:
		#     te = app('TextEdit'); d = app.documents; te.launch()
		# will launch TE normally (i.e. app receives 'aevtoapp' as its first event), causing it to open a new, empty window.
		Reference.__init__(self, 
				AppData(self._Application, constructor, identifier, terms, {'newinstance': newinstance, 'hide': hide}), 
				aem.app)
	
	def AS_newreference(self, ref):
		"""Create a new appscript reference from an aem reference."""
		if isinstance(ref, GenericReference):
			return ref.AS_resolve(Reference, self.AS_appdata)
		elif isinstance(ref, aem.Query):
			return Reference(self.AS_appdata, ref)
		elif ref is None:
			return Reference(self.AS_appdata, aem.app)
		else:
			return Reference(self.AS_appdata, aem.customroot(ref))

	def begintransaction(self, session=None):
		self.AS_appdata.target().begintransaction(session)
	
	def aborttransaction(self):
		self.AS_appdata.target().aborttransaction()
	
	def endtransaction(self):
		self.AS_appdata.target().endtransaction()
	
	def launch(self):
		"""Launch a non-running application in the background and send it a 'launch' event. 
			Note: this will only launch non-running apps that are specified by name/path/
			bundle id. Apps specified by other means will be still sent a 
			launch event if already running, but an error will occur if they're not.
		"""
		if not self.isrunning() and self.AS_appdata.constructor == 'path' \
				and self.AS_appdata.relaunchmode != 'never':
			aem.Application.launch(self.AS_appdata.identifier)
			self.AS_appdata.target().reconnect() # make sure aem.Application object's AEAddressDesc is up to date
		else: # send launch event to app (will error if not already running)
			Command(self, 'launch', b'ascrnoop', {})()
	
	permissiontoautomate = property(lambda self: self.AS_appdata.permissiontoautomate())


#######

class GenericApp(GenericReference):
	def __init__(self, appclass):
		self._appclass = appclass
		GenericReference.__init__(self, ['app'])
		
	def __call__(self, *args, **kargs):
		return self._appclass(*args, **kargs)


app = GenericApp(Application) # app-based references are generic references unless you specify an application by calling app, e.g. app.home is generic, app('Finder').home is real


######################################################################
# The CommandError class is exposed for use in try...except... blocks

class CommandError(Exception):
	"""An error raised when sending a command (e.g. aem.EventError). Contains
		the original exception object and the command on which the error was raised.
	"""
	
	def __init__(self, command, parameters, realerror, codecs):
		"""
			command : Command -- command reference
			parameters : tuple -- two-item tuple containing tuple of positional args and dict of keyword args
			realerror : Exception -- the original error raised
			codecs : AppData -- used to unpack error data as needed
		"""
		self.command, self. parameters, self.realerror = command, parameters, realerror
		self._codecs = codecs
		Exception.__init__(self, command, parameters, realerror)
		
	def __int__(self):
		if isinstance(self.realerror, aem.EventError):
			return int(self.realerror)
		elif isinstance(self.realerror, MacOSError):
			return self.realerror.args[0]
		else:
			return -2700
	
	def __repr__(self):
		return 'appscript.CommandError({!r}, {!r}, {!r})'.format(self.command, self. parameters, self.realerror)
	
	def __str__(self):
		if isinstance(self.realerror, aem.EventError):
			err = "Command failed:\n\t\tOSERROR: {}".format(self.errornumber)
			msg = self.errormessage
			if msg:
				err += "\n\t\tMESSAGE: {}".format(msg)
			for label, key in [
					["OFFENDING OBJECT", kae.kOSAErrorOffendingObject], 
					["EXPECTED TYPE", kae.kOSAErrorExpectedType],
					["PARTIAL RESULT", kae.kOSAErrorPartialResult]]:
				if key in self.realerror.raw:
					err += "\n\t\t{}: {!r}".format(label, self._codecs.unpack(self.realerror.raw[key]))
		else:
			err = self.realerror
		return "{}\n\t\tCOMMAND: {}".format(err, self.command.AS_formatcommand(self.parameters))
	
	# basic error info (an error number is always given by AEM/application;
	# message is either supplied by application or generated by aem.EventError)
	
	errornumber = property(lambda self: int(self), doc="int -- Mac OS error number")
	
	errormessage = property(lambda self: 
			self.realerror.errormessage if isinstance(self.realerror, aem.EventError) else '', 
			doc="str -- application-supplied/generic error description")

	# extended error info (some apps may return some or all additional error info, though most don't)
	
	def _errorinfo(self, key):
		if isinstance(self.realerror, aem.EventError):
			desc = self.realerror.raw.get(key)
			if desc:
				return self._codecs.unpack(desc)
		return None
	
	offendingobject = property(lambda self: self._errorinfo(kae.kOSAErrorOffendingObject),
			doc="anything | None -- object that caused the error, if given by application")
	expectedtype = property(lambda self: self._errorinfo(kae.kOSAErrorExpectedType),
			doc="anything | None -- object that caused a coercion error, if given by application")
	partialresult = property(lambda self: self._errorinfo(kae.kOSAErrorPartialResult),
			doc="anything | None -- part of return value constructed before error occurred, if given by application")


