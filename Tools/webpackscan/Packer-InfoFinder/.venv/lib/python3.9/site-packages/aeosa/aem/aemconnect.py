"""connect - Creates Apple event descriptor records of typeProcessSerialNumber and typeApplicationURL, used to specify the target application in send.Event() constructor. """
import struct
from time import sleep

from . import ae, kae

from .aemsend import Event

__all__ = ['launchapp', 'processexistsforpath', 'processexistsforpid', 'processexistsforurl', 
		'processexistsfordesc', 'currentapp', 'localapp', 'remoteapp', 'CantLaunchApplicationError']

######################################################################
# PRIVATE
######################################################################

kLSLaunchDefaults = 0x00000001
kLSLaunchAndPrint = 0x00000002
kLSLaunchReserved2 = 0x00000004
kLSLaunchReserved3 = 0x00000008
kLSLaunchReserved4 = 0x00000010
kLSLaunchReserved5 = 0x00000020
kLSLaunchAndDisplayErrors = 0x00000040
kLSLaunchInhibitBGOnly = 0x00000080
kLSLaunchDontAddToRecents = 0x00000100
kLSLaunchDontSwitch = 0x00000200
kLSLaunchNoParams = 0x00000800
kLSLaunchAsync = 0x00010000
kLSLaunchStartClassic = 0x00020000
kLSLaunchInClassic = 0x00040000
kLSLaunchNewInstance = 0x00080000
kLSLaunchAndHide = 0x00100000
kLSLaunchAndHideOthers = 0x00200000
kLSLaunchHasUntrustedContents = 0x00400000


_kNoProcess = 0
_kCurrentProcess = 2

_nulladdressdesc = ae.newdesc(kae.typeProcessSerialNumber, struct.pack('II', 0, _kNoProcess)) # ae.newappleevent complains if you pass None as address, so we give it one to throw away

_launchevent = Event(_nulladdressdesc, b'ascrnoop').AEM_event
_runevent = Event(_nulladdressdesc, b'aevtoapp').AEM_event

#######

def _launchapplication(path, event, newinstance=False, hide=False):
	flags = kLSLaunchNoParams | kLSLaunchStartClassic | kLSLaunchDontSwitch
	if newinstance:
		flags |= kLSLaunchNewInstance
	if hide:
		flags |= kLSLaunchAndHide
	try:
		return ae.launchapplication(path, event, flags)
	except ae.MacOSError as err:
		raise CantLaunchApplicationError(err.args[0], path) from err


######################################################################
# PUBLIC
######################################################################


class CantLaunchApplicationError(Exception):
	
	_lserrors = {
		# following taken from <http://developer.apple.com/documentation/Carbon/Reference/LaunchServicesReference>:
		-10660: "The application cannot be run because it is inside a Trash folder.",
		-10810: "An unknown error has occurred.",
		-10811: "The item to be registered is not an application.",
		-10813: "Data of the desired type is not available (for example, there is no kind string).",
		-10814: "No application in the Launch Services database matches the input criteria.",
		-10817: "Data is structured improperly (for example, an item's information property list is malformed).",
		-10818: "A launch of the application is already in progress.",
		-10822: "There is a problem communicating with the server process that maintains the Launch Services database.",
		-10823: "The filename extension to be hidden cannot be hidden.",
		-10825: "The application to be launched cannot run on the current Mac OS version.",
		-10826: "The user does not have permission to launch the application (on a managed network).",
		-10827: "The executable file is missing or has an unusable format.",
		-10828: "The Classic emulation environment was required but is not available.",
		-10829: "The application to be launched cannot run simultaneously in two different user sessions.",
	}

	def __init__(self, errornumber, apppath):
		self._number = errornumber
		self._apppath = apppath
		Exception.__init__(self, errornumber, apppath)
	
	errornumber = property(lambda self: self._number, doc="int -- Mac OS error number")
	
	apppath = property(lambda self: self._apppath, doc="str -- application path")
	
	def __int__(self):
		return self._number
	
	def __str__(self):
		return "Can't launch application at {!r}: {} ({})".format(self._apppath, self._lserrors.get(self._number, 'OS error'), self._number)


def launchapp(path, newinstance=False, hide=False):
	"""Send a 'launch' event to an application. If application is not already running, it will be launched in background first.
		path : string -- full path to application, e.g. '/System/Applications/TextEdit.app'
		newinstance : bool -- launch a new application instance?
		hide : bool -- hide after launch?
		Result : AEAddressDesc
	"""
	if newinstance:
		desc = _launchapplication(path, _launchevent, newinstance, hide)
	else:
		try:
			# If app is already running, calling ae.launchapplication will send a 'reopen' event, so need to check for this first:
			desc = ae.psnforapplicationpath(path)
		except ae.MacOSError as err:
			if err.args[0] == -600: # Application isn't running, so launch it and send it a 'launch' event:
				sleep(1)
				desc = _launchapplication(path, _launchevent, newinstance, hide)
			else:
				raise
		else: # App is already running, so send it a 'launch' event:
			ae.newappleevent(b'ascr', b'noop', desc, kae.kAutoGenerateReturnID, 
					kae.kAnyTransactionID).send(kae.kAEWaitReply, kae.kAEDefaultTimeout)
	return desc

##

def processexistsforpath(path):
	"""Does a local process launched from the specified application file exist?
		Note: if path is invalid, a MacOSError is raised.
	"""
	try:
		ae.psnforapplicationpath(path)
		return True
	except ae.MacOSError as err:
		if err.args[0] == -600: 
			return False
		else:
			raise

def processexistsforpid(pid):
	"""Is there a local application process with the given unix process id?"""
	return bool(ae.isvalidpid(pid))

def processexistsforurl(url):
	"""Does an application process specified by the given eppc:// URL exist?
		Note: this will send a 'launch' Apple event to the target application.
	"""
	if ':' not in url: # workaround: process will crash if no colon in URL (OS bug)
		raise ValueError("Invalid url: {!r}".format(url))
	return processexistsfordesc(ae.newdesc(kae.typeApplicationURL, url))

def processexistsfordesc(desc):
	"""Does an application process specified by the given AEAddressDesc exist?
		Returns false if process doesn't exist OR remote Apple events aren't allowed.
		Note: this will send a 'launch' Apple event to the target application.
	"""
	try:
		# This will usually raise error -1708 if process is running, and various errors
		# if the process doesn't exist/can't be reached. If app is running but busy,
		# AESendMessage() may return a timeout error (this should be -1712, but
		# -609 is often returned instead for some reason).
		Event(desc, b'ascrnoop').send()
	except ae.MacOSError as err:
		return err.args[0] not in [-600, -905] # -600 = no process; -905 = no network access
	return True


#######

currentapp = ae.newdesc(kae.typeProcessSerialNumber, struct.pack('II', 0, _kCurrentProcess))


def localapp(path, newinstance=False, hide=False):
	"""Make an AEAddressDesc identifying a local application. (Application will be launched if not already running.)
		path : string -- full path to application, e.g. '/System/Applications/TextEdit.app'
		newinstance : bool -- launch a new application instance?
		hide : bool -- hide after launch?
		Result : AEAddressDesc
	"""
	# Always create AEAddressDesc by process serial number; that way there's no confusion if multiple versions of the same app are running
	if newinstance:
		desc = _launchapplication(path, _runevent, newinstance, hide)
	else:
		try:
			desc = ae.psnforapplicationpath(path)
		except ae.MacOSError as err:
			if err.args[0] == -600: # Application isn't running, so launch it in background and send it a standard 'run' event.
				sleep(1)
				desc = _launchapplication(path, _runevent, newinstance, hide)
			else:
				raise
	return desc


def localappbypid(pid):
	"""Make an AEAddressDesc identifying a local process.
		pid : integer -- Unix process id
		Result : AEAddressDesc
	"""
	return ae.newdesc(kae.typeKernelProcessID, struct.pack('i', pid))


def remoteapp(url):
	"""Make an AEAddressDesc identifying a running application on another machine.
		url : string -- URL for remote application, e.g. 'eppc://user:password@192.168.2.1/TextEdit'
		Result : AEAddressDesc
	"""
	if ':' not in url: # workaround: process will crash if no colon in URL (OS bug)
		raise ValueError("Invalid url: {!r}".format(url))
	return ae.newdesc(kae.typeApplicationURL, url)

