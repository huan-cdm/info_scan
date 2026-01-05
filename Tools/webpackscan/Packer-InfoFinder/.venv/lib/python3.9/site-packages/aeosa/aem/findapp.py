"""findapp -- Support module for obtaining the full path to a local application given its file name or bundle id. If application isn't found, an ApplicationNotFoundError exception is raised. """

from os.path import exists

from .ae import findapplicationforinfo, MacOSError

__all__ = ['byname', 'byid']

######################################################################
# PRIVATE
######################################################################

def _findapp(name=None, id=None):
	try:
		return findapplicationforinfo(b'????', id, name)
	except MacOSError as err:
		if err.args[0] == -10814:
			raise ApplicationNotFoundError(name or id) from err
		else:
			raise


######################################################################
# PUBLIC
######################################################################

class ApplicationNotFoundError(Exception):
	def __init__(self, name):
		self.name = name
		Exception.__init__(self, name)
	
	def __str__(self):
		return 'Local application {!r} not found.'.format(self.name)


def byname(name):
	"""Find the application with the given name and return its full path. 
	
	Absolute paths are also accepted. An '.app' suffix is optional.
	
	Examples: 
		byname('TextEdit')
		byname('Finder.app')
	"""
	if not name.startswith('/'): # application name only, not its full path
		try:
			name = _findapp(name)
		except ApplicationNotFoundError:
			if name.lower().endswith('.app'):
				raise
			name = _findapp(name + '.app')
	if not exists(name) and not name.lower().endswith('.app') and exists(name + '.app'):
		name += '.app'
	if not exists(name):
		raise ApplicationNotFoundError(name)
	return name

		
def byid(id):
	"""Find the application with the given bundle id and return its full path.
	
	Examples:
		byid('com.apple.textedit')
	"""
	return _findapp(id=id)




