"""osax.py -- Allows scripting additions (a.k.a. OSAXen) to be called from Python. """


from appscript import *
from appscript import reference, terminology
import aem


__all__ = ['OSAX', 'ApplicationNotFoundError', 'CommandError', 'k', 'mactypes']


######################################################################
# PRIVATE
######################################################################


_osaxpath = '/System/Library/ScriptingAdditions/StandardAdditions.osax'

_terms = None


######################################################################
# PUBLIC
######################################################################

def scriptingadditions():
	return ['StandardAdditions']


class OSAX(reference.Application):

	def __init__(self, *, name=None, id=None, pid=None, url=None, aemapp=None):
		global _terms
		if not _terms:
			_terms = terminology.tablesforsdef(terminology.sdefforurl(aem.ae.convertpathtourl(_osaxpath, 0)))
		reference.Application.__init__(self, name, id, pid, url, aemapp, _terms)
		try:
			self.AS_appdata.target().event(b'ascrgdut').send(300) # make sure target application has loaded event handlers for all installed OSAXen
		except aem.EventError as e:
			if e.errornumber != -1708: # ignore 'event not handled' error
				raise
		def _help(*args):
			raise NotImplementedError("Built-in help isn't available for scripting additions.")
		self.AS_appdata.help = _help
		
	def __str__(self):
		if self.AS_appdata.constructor == 'current':
			return 'OSAX()'.format()
		else:
			return 'OSAX({}={!r})'.format(self.AS_appdata.constructor, self.AS_appdata.identifier)
			
	def __getattr__(self, name):
		command = reference.Application.__getattr__(self, name)
		if isinstance(command, reference.Command):
			def osaxcommand(*args, **kargs):
				try:
					return command(*args, **kargs)
				except CommandError as e:
					if int(e) == -1713: # 'No user interaction allowed' error (e.g. user tried to send a 'display dialog' command to a non-GUI python process), so convert the target process to a full GUI process and try again
						aem.ae.transformprocesstoforegroundapplication()
						self.activate()
						return command(*args, **kargs)
					raise
			return osaxcommand
		else:
			return command
		
	__repr__ = __str__

