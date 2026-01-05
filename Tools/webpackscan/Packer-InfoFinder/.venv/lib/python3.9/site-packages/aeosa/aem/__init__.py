"""aem -- Mid-level wrapper for building and sending Apple events. """

import struct

from . import ae, kae, findapp, mactypes, aemconnect
from .aemconnect import CantLaunchApplicationError
from .aemsend import Event, EventError, newappleevent, sendappleevent
from .aemcodecs import Codecs
from .aemreference import app, con, its, customroot, Query
from .typewrappers import AETypeBase, AEType, AEEnum, AEProp, AEKey


__all__ = [
	'ae', 'kae',
	'findapp', 'mactypes',
	'Application',
	'Event', 'EventError',
	'CantLaunchApplicationError',
	'Codecs', 
	'app', 'con', 'its', 'customroot', 'Query',
	'AETypeBase', 'AEType', 'AEEnum', 'AEProp', 'AEKey',
]


######################################################################
# PRIVATE
######################################################################

_defaultcodecs = Codecs()

######################################################################
# PUBLIC
######################################################################

class Application(Query):
	"""Target application for Apple events."""
	
	# aem.Application subclasses can override these attributes to modify the creation
	# and sending of AppleEvent descriptors
	_createproc = staticmethod(newappleevent)
	_sendproc = staticmethod(sendappleevent)
	
	# aem.Application subclasses can override this attribute (typically with a subclass 
	# of the standard aemsend.Event class) to have the event() method return a different
	# class instance; simpler than overriding the event() method
	_Event = Event

	# need to keep a local copy of this constant to avoid upsetting Application.__del__() 
	# at cleanup time, otherwise it may be disposed of before __del__() can use it
	_transaction = _kAnyTransactionID = kae.kAnyTransactionID
	
	def __init__(self, path=None, pid=None, url=None, desc=None, 
			codecs= _defaultcodecs, newinstance=False, hide=False):
		"""
			path : str | None -- full path to local application
			pid : int | None -- Unix process id for local process
			url : str | None -- url for remote process
			desc : AEAddressDesc | None -- AEAddressDesc for application
			codecs : Codecs -- used to convert Python values to AEDescs and vice-versa
			newinstance : bool -- launch a new application instance?
			hide : bool -- hide after launch?
			
			Notes: 
			
				- If no path, pid, url or aedesc is given, target will be 'current application'.
				
				- If path is given, application will be launched automatically; if pid, url or 
					desc is given, user is responsible for ensuring application is running 
					before sending it any events.
				
				- The newinstance and hide options only apply when specifying application
					by path.
		"""
		self._path, self._codecs, self._newinstance, self._hide = path, codecs, newinstance, hide
		if path:
			self._address = aemconnect.localapp(path, newinstance, hide)
			self.AEM_identity = ('path', path)
		elif pid:
			self._address = aemconnect.localappbypid(pid)
			self.AEM_identity = ('pid', pid)
		elif url:
			self._address = aemconnect.remoteapp(url)
			self.AEM_identity = ('url', url)
		elif desc:
			self._address = desc
			self.AEM_identity = ('desc', (desc.type, desc.data))
		else:
			self._address = aemconnect.currentapp
			self.AEM_identity = ('current', None)
	
	def __repr__(self):
		args = []
		if self.AEM_identity[0] == 'desc':
			args.append('desc={!r}'.format(self._address))
		elif self.AEM_identity[0] == 'path':
			args.append(repr(self.AEM_identity[1]))
		elif self.AEM_identity[0] != 'current':
			args.append('{}={!r}'.format(*self.AEM_identity))
		if self._codecs != _defaultcodecs:
			args.append('codecs={!r}'.format(self._codecs))
		if self._newinstance:
			args.append('newinstance={!r}'.format(struct.unpack('II', self._address.data)))
		if self._hide:
			args.append('hide=True')
		modulename = '{}.'.format(self.__class__.__module__)
		if modulename == 'aem.send.':
			modulename = 'aem.'
		elif modulename == '__main__.':
			modulename = ''
		return '{}{}({})'.format(modulename, self.__class__.__name__, ', '.join(args))
			
	__str__ = __repr__
	
	def __eq__(self, val):
		return self is val or (
				self.__class__ == val.__class__ and 
				self.AEM_identity == val.AEM_identity)
	
	def __ne__(self, val):
		return not self == val
	
	def __hash__(self):
		return hash(self.AEM_identity)
	
	def AEM_comparable(self):
		return ['AEMApplication', self.AEM_identity]
	
	def AEM_packself(self, codecs):
		return self._address
	
	def __del__(self):
		# If user forgot to close a transaction before throwing away the Application object 
		# that opened it, try to close it for them. Otherwise application will be left in 
		# mid-transaction, preventing anyone else from using it.
		if self._transaction != self._kAnyTransactionID:
			self.endtransaction()
	
	#######
	# Utility functions; placed here for convenience
	
	# Launch a local application without sending it the usual 'run' event (aevtoapp):
	launch = staticmethod(aemconnect.launchapp)
	
	# Check if an application specified by path/pid/URL/AEAddressDesc is running:
	processexistsforpath = staticmethod(aemconnect.processexistsforpath)
	processexistsforpid = staticmethod(aemconnect.processexistsforpid)
	processexistsforurl = staticmethod(aemconnect.processexistsforurl)
	processexistsfordesc = staticmethod(aemconnect.processexistsfordesc)
	
	#######
	
	addressdesc = property(lambda self: self._address)
	
	def reconnect(self):
		"""If application has quit since this Application object was created, its 
			AEAddressDesc is no longer valid so this Application object 
			will not work even when application is restarted. reconnect() will 
			update this Application object's AEAddressDesc so it's valid again.
		
			Notes:
			
			- This only works for Application objects specified by path, not by
				URL or AEDesc. Also, any Event objects created prior to calling 
				reconnect() will still be invalid.
			
			- If the Application object was created with newinstance=True, calling
				reconnect() will launch a new application instance and connect 
				to that each time it is called. Otherwise it will reconnect to the
				first existing application instance it finds, and only launches a new
				instance if none are found.
		"""
		if self._path:
			self._address = aemconnect.localapp(self._path, self._newinstance, self._hide)
	
	def permissiontoautomate(self, eventclass=kae.typeWildCard, eventid=kae.typeWildCard, askuserifneeded=False):
		"""Throws if current process is not authorized to send an Apple event to the target application.
		
			Errors include:
	
			- errAEEventNotPermitted (-1743): the user has declined permission.
		
			- errAEEventWouldRequireUserConsent (-1744): user consent is required for this, but the user has not yet been prompted for it. You need to pass False for askUserIfNeeded to get this.
		
			- procNotFound (-600): the specified app is not currently running.
			
			Throws NotImplementedError on 10.13 and earlier. (Permission is always available.)
			
			## Known Issues ##
			
			AEDeterminePermissionToAutomateTarget() is buggy on 10.14. See rdar://44049802 (fixed in 10.14.3)
		"""
		self._address.permissiontoautomate(eventclass, eventid, askuserifneeded)
	
	##
	
	def event(self, event, params={}, atts={}, returnid=kae.kAutoGenerateReturnID, codecs=None):
		"""Construct an Apple event.
			event  : str -- 8-letter code indicating event's class, e.g. 'coregetd'
			params : dict -- a dict of form {AE_code:anything,...} containing zero or more 
					event parameters (message arguments)
			atts : dict -- a dict of form {AE_code:anything,...} containing zero or more 
					event attributes (event info)
			returnid : int  -- reply event's ID (default = kAutoGenerateReturnID)
			codecs : Codecs | None -- custom codecs to use when packing/unpacking this
					event; if None, codecs supplied in Application constructor are used
		"""
		return self._Event(self._address, event, params, atts, self._transaction, returnid, 
				codecs or self._codecs, self._createproc, self._sendproc)
	
	def begintransaction(self, session=None):
		"""Begin a transaction."""
		if self._transaction != self._kAnyTransactionID:
			raise RuntimeError("Transaction is already active.")
		self._transaction = self._Event(self._address, b'miscbegi', 
				session is not None and {b'----':session} or {}, codecs=_defaultcodecs).send()
	
	def aborttransaction(self):
		"""Abort the current transaction."""
		if self._transaction == self._kAnyTransactionID:
			raise RuntimeError("No transaction is active.")
		self._Event(self._address, b'miscttrm', transaction=self._transaction).send()
		self._transaction = self._kAnyTransactionID
	
	def endtransaction(self):
		"""End the current transaction."""
		if self._transaction == self._kAnyTransactionID:
			raise RuntimeError("No transaction is active.")
		self._Event(self._address, b'miscendt', transaction=self._transaction).send()
		self._transaction = self._kAnyTransactionID

