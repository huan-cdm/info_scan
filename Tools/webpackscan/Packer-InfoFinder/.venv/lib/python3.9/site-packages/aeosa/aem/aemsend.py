"""send -- Construct and send Apple events. """

from .ae import newappleevent, stringsforosstatus, MacOSError
from . import kae

from .aemcodecs import Codecs

__all__ = ['Event', 'EventError']

######################################################################
# PRIVATE
######################################################################

_defaultcodecs = Codecs()

def sendappleevent(evt, flags, timeout):
	""" Default function for sending Apple events.
		evt : aem.ae.AEDesc -- the AppleEvent to send
		flags : int -- send mode flags
		timeout : int -- timeout delay
		Result : aem.ae.AEDesc -- the reply AppleEvent
	"""
	return evt.send(flags, timeout)

######################################################################
# PUBLIC
######################################################################


class Event:
	"""Represents an Apple event (serialised message)."""
	
	def __init__(self, address, event, params={}, atts={},
			transaction=kae.kAnyTransactionID, returnid= kae.kAutoGenerateReturnID, 
			codecs=_defaultcodecs, createproc=newappleevent, sendproc=sendappleevent):
		"""Called by aem.Application.event(); users shouldn't instantiate this class themselves.
			address : AEAddressDesc -- the target application
			event : bytes -- 8-letter code indicating event's class and id, e.g. b'coregetd'
			params : dict -- a dict of form {AE_code:anything,...} containing zero or more event parameters (message arguments)
			atts : dict -- a dict of form {AE_code:anything,...} containing zero or more event attributes (event info)
			transaction : int -- transaction number (default = kAnyTransactionID)
			returnid : int  -- reply event's ID (default = kAutoGenerateReturnID)
			codecs : Codecs -- user can provide custom parameter & result encoder/decoder (default = standard codecs); supplied by Application class
			createproc : function -- function to create a new AppleEvent descriptor
			sendproc : function -- function to send an AppleEvent descriptor
		"""
		self._eventcode = event
		self._codecs = codecs
		self._sendproc = sendproc
		self.AEM_event = createproc(event[:4], event[4:], address, returnid, transaction)
		for key, value in atts.items():
			self.AEM_event.setattr(key, codecs.pack(value))
		for key, value in params.items():
			self.AEM_event.setparam(key, codecs.pack(value))
	
	# Public
	
	def send(self, timeout= kae.kAEDefaultTimeout, flags= kae.kAECanSwitchLayer + kae.kAEWaitReply):
		"""Send this Apple event (may be called any number of times).
			timeout : int | aem.k.DefaultTimeout | aem.k.NoTimeout -- number of ticks to wait for target process
					to reply before raising timeout error (default=DefaultTimeout)
			flags : int -- bitwise flags [1] indicating how target process should handle event (default=WaitReply)
			Result : anything -- value returned by application, if any
			
			[1] aem.k provides the following constants for convenience:
			
				[ aem.k.NoReply | aem.k.QueueReply | aem.k.WaitReply ]
				[ aem.k.DontReconnect ]
				[ aem.k.WantReceipt ]
				[ aem.k.NeverInteract | aem.k.CanInteract | aem.k.AlwaysInteract ]
				[ aem.k.CanSwitchLayer ]
		"""
		try:
			replyevent = self._sendproc(self.AEM_event, flags, timeout)
		except MacOSError as err: # an OS-level error occurred
			if not (self._eventcode == b'aevtquit' and err.args[0] == -609): # Ignore invalid connection error (-609) when quitting
				raise EventError(err.args[0]) from err
		else: # decode application's reply, if any
			if replyevent.type != kae.typeNull:
				eventresult = dict([replyevent.getitem(i + 1, kae.typeWildCard) 
						for i in range(replyevent.count())])
				# note: while Apple docs say that both keyErrorNumber and keyErrorString should be
				# tested for when determining if an error has occurred, AppleScript tests for keyErrorNumber
				# only, so do the same here for compatibility
				if kae.keyErrorNumber in eventresult: # an application-level error occurred
					# note: uses standard codecs to unpack error info to ensure consistent conversion
					errornum = _defaultcodecs.unpack(eventresult[kae.keyErrorNumber])
					if errornum != 0: # Stupid Finder returns non-error error number and message for successful move/duplicate command, so just ignore it
						errormsg = eventresult.get(kae.keyErrorString)
						if errormsg:
							errormsg = _defaultcodecs.unpack(errormsg)
						raise EventError(errornum, errormsg, eventresult)
				if kae.keyAEResult in eventresult: # application has returned a value
					# note: unpack result with [optionally] user-specified codecs, allowing clients to customise unpacking (e.g. appscript)
					return self._codecs.unpack(eventresult[kae.keyAEResult])



######################################################################


class EventError(MacOSError):
	""" Raised by aem.Event.send() when sending an event fails; contains error information 
		provided by Apple Event Manager or target application.
		
		Notes:
			
			- the 'raw' attribute contains either a dict containing the reply event's 
				raw parameters, or an empty dict if the error occurred while sending 
				the outgoing event; used by appscript.CommandError; third-parties 
				should avoid using it directly
	"""
	
	_carbonerrors = { # Following error descriptions are mostly cribbed from AppleScript Language Guide.
		# OS errors
		-34: "Disk is full.",
		-35: "Disk wasn't found.",
		-37: "Bad name for file.",
		-38: "File wasn't open.",
		-39: "End of file error.",
		-42: "Too many files open.",
		-43: "File wasn't found.",
		-44: "Disk is write protected.",
		-45: "File is locked.",
		-46: "Disk is locked.",
		-47: "File is busy.",
		-48: "Duplicate file name.",
		-49: "File is already open.",
		-50: "Parameter error.",
		-51: "File reference number error.",
		-61: "File not open with write permission.",
		-108: "Out of memory.",
		-120: "Folder wasn't found.",
		-124: "Disk is disconnected.",
		-128: "User canceled.",
		-192: "A resource wasn't found.",
		-600: "Application isn't running.",
		-601: "Not enough room to launch application with special requirements.",
		-602: "Application is not 32-bit clean.",
		-605: "More memory is needed than is specified in the size resource.",
		-606: "Application is background-only.",
		-607: "Buffer is too small.",
		-608: "No outstanding high-level event.",
		-609: "Connection is invalid.",
		-904: "Not enough system memory to connect to remote application.",
		-905: "Remote access is not allowed.",
		-906: "Application isn't running or program linking isn't enabled.",
		-915: "Can't find remote machine.",
		-30720: "Invalid date and time.",
		# AE errors
		-1700: "Can't make some data into the expected type.",
		-1701: "Some parameter is missing for command.",
		-1702: "Some data could not be read.",
		-1703: "Some data was the wrong type.",
		-1704: "Some parameter was invalid.",
		-1705: "Operation involving a list item failed.",
		-1706: "Need a newer version of the Apple Event Manager.",
		-1707: "Event isn't an Apple event.",
		-1708: "Application could not handle this command.",
		-1709: "AEResetTimer was passed an invalid reply.",
		-1710: "Invalid sending mode was passed.",
		-1711: "User canceled out of wait loop for reply or receipt.",
		-1712: "Apple event timed out.",
		-1713: "No user interaction allowed.",
		-1714: "Wrong keyword for a special function.",
		-1715: "Some parameter wasn't understood.",
		-1716: "Unknown Apple event address type.",
		-1717: "The handler is not defined.",
		-1718: "Reply has not yet arrived.",
		-1719: "Can't get reference. Invalid index.",
		-1720: "Invalid range.",
		-1721: "Wrong number of parameters for command.",
		-1723: "Can't get reference. Access not allowed.",
		-1725: "Illegal logical operator called.",
		-1726: "Illegal comparison or logical.",
		-1727: "Expected a reference.",
		-1728: "Can't get reference.",
		-1729: "Object counting procedure returned a negative count.",
		-1730: "Container specified was an empty list.",
		-1731: "Unknown object type.",
		-1739: "Attempting to perform an invalid operation on a null descriptor.",
		-1743: "The user has declined permission.",
		-1744: "User consent is required, but the user has not yet been prompted for it.",
		# Application scripting errors
		-10000: "Apple event handler failed.",
		-10001: "Type error.",
		-10002: "Invalid key form.",
		-10003: "Can't set reference to given value. Access not allowed.",
		-10004: "A privilege violation occurred.",
		-10005: "The read operation wasn't allowed.",
		-10006: "Can't set reference to given value.",
		-10007: "The index of the event is too large to be valid.",
		-10008: "The specified object is a property, not an element.",
		-10009: "Can't supply the requested descriptor type for the data.",
		-10010: "The Apple event handler can't handle objects of this class.",
		-10011: "Couldn't handle this command because it wasn't part of the current transaction.",
		-10012: "The transaction to which this command belonged isn't a valid transaction.",
		-10013: "There is no user selection.",
		-10014: "Handler only handles single objects.",
		-10015: "Can't undo the previous Apple event or user action.",
		-10023: "Enumerated value is not allowed for this property.",
		-10024: "Class can't be an element of container.",
		-10025: "Illegal combination of properties settings.",
	}
	
	# Following Cocoa Scripting error descriptions taken from:
	# http://developer.apple.com/documentation/Cocoa/Reference/Foundation/ObjC_classic/Classes/NSScriptCommand.html
	# http://developer.apple.com/documentation/Cocoa/Reference/Foundation/ObjC_classic/Classes/NSScriptObjectSpecifier.html

	_cocoaerrors = (
		('NSReceiverEvaluationScriptError', 'The object or objects specified by the direct parameter to a command could not be found.'),
		('NSKeySpecifierEvaluationScriptError', 'The object or objects specified by a key (for commands that support key specifiers) could not be found.'),
		('NSArgumentEvaluationScriptError', 'The object specified by an argument could not be found.'),
		('NSReceiversCantHandleCommandScriptError', "The receivers don't support the command sent to them."),
		('NSRequiredArgumentsMissingScriptError', 'An argument (or more than one argument) is missing.'),
		('NSArgumentsWrongScriptError', 'An argument (or more than one argument) is of the wrong type or is otherwise invalid.'),
		('NSUnknownKeyScriptError', 'An unidentified error occurred; indicates an error in the scripting support of your application.'),
		('NSInternalScriptError', 'An unidentified internal error occurred; indicates an error in the scripting support of your application.'),
		('NSOperationNotSupportedForKeyScriptError', 'The implementation of a scripting command signaled an error.'),
		('NSCannotCreateScriptCommandError', 'Could not create the script command; an invalid or unrecognized Apple event was received.'),
		('NSNoSpecifierError', 'No error encountered.'),
		('NSNoTopLevelContainersSpecifierError', 'Someone called evaluate with nil.'),
		('NSContainerSpecifierError', 'Error evaluating container specifier.'),
		('NSUnknownKeySpecifierError', 'Receivers do not understand the key.'),
		('NSInvalidIndexSpecifierError', 'Index out of bounds.'),
		('NSInternalSpecifierError', 'Other internal error.'),
		('NSOperationNotSupportedForKeySpecifierError', 'Attempt made to perform an unsupported operation on some key.'),
	)
	
	def __init__(self, number, message=None, raw=None):
		MacOSError.__init__(self, number)
		self._number, self._message, self._raw = number, str(message or ''), raw
	
	raw = property(lambda self: self._raw or {}, 
			doc="dict -- raw error data from reply event, if any (note: clients should not need to use this directly)")
	
	def __repr__(self):
		return "aem.EventError({!r}, {!r}, {!r})".format(self._number, self._message, self._raw)
		
	def __int__(self):
		return self._number
	
	def __str__(self):
		return "Command failed: {} ({})".format(self.errormessage, self.errornumber)
	
	# basic error info (an error number is always given by AEM/application;
	# message is either supplied by application or generated here)	
	errornumber = property(lambda self: self._number, doc="int -- Mac OS error number")
	
	def errormessage(self):
		message = self._message
		if self._number > 0 and message:
			for name, description in self._cocoaerrors:
				if message.startswith(name):
					message = '{} ({})'.format(message, description)
					break
		elif not message:
			message = self._carbonerrors.get(self._number)
			if not message:
				message = stringsforosstatus(self._number)[1] or 'OS error'
		return message
	errormessage = property(errormessage, 
			doc="str -- application-supplied/generic error description")
	
	# extended error info (some apps may return additional error info, though most don't)

	def _errorinfo(self, key):
		if self._raw:
			desc = self._raw.get(key)
			if desc:
				return _defaultcodecs.unpack(desc)
		return None
	
	offendingobject = property(lambda self: self._errorinfo(kae.kOSAErrorOffendingObject),
			doc="anything | None -- object that caused the error, if given by application")
	expectedtype = property(lambda self: self._errorinfo(kae.kOSAErrorExpectedType),
			doc="anything | None -- object that caused a coercion error, if given by application")
	partialresult = property(lambda self: self._errorinfo(kae.kOSAErrorPartialResult),
			doc="anything | None -- part of return value constructed before error occurred, if given by application")

