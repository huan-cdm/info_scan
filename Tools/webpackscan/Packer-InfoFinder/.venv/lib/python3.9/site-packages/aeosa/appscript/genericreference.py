"""genericreference -- allows user to construct relative (con- and its- based) references without immediate access to application terminology. """

import aem

######################################################################
# PUBLIC
######################################################################

class GenericReference(object):
	def __init__(self, call):
		self._call = call # list of recorded call information (inital value is ['app'], ['con'] or ['its'])
	
	def __getattr__(self, i):
		return GenericReference(self._call + [('__getattr__', i, '.{}')])
	
	def __getitem__(self, i):
		return GenericReference(self._call + [('__getitem__', i, '[{!r}]')])
	
	def __call__(self, *args, **kargs):
		return GenericReference(self._call + [('__call__', (args, kargs), None)])
	
	def __gt__(self, i):
		return GenericReference(self._call + [('AS__gt__', i, ' > {!r}')])
	
	def __ge__(self, i):
		return GenericReference(self._call + [('AS__ge__', i, ' >= {!r}')])
	
	def __eq__(self, i):
		return GenericReference(self._call + [('AS__eq__', i, ' == {!r}')])
	
	def __ne__(self, i):
		return GenericReference(self._call + [('AS__ne__', i, ' != {!r}')])
	
	def __lt__(self, i):
		return GenericReference(self._call + [('AS__lt__', i, ' < {!r}')])
	
	def __le__(self, i):
		return GenericReference(self._call + [('AS__le__', i, ' <= {!r}')])
	
	def __hash__(self):
		return hash(self._call)
		
	def __repr__(self):
		s = self._call[0]
		for method, args, repstr in self._call[1:]:
			if method == '__call__':
				s += '({})'.format(', '.join(['{!r}'.format(i) for i in args[0]] + ['{}={!r}'.format(i) for i in args[1].items()]))
			elif method == '__getitem__' and isinstance(args, slice):
				s+= '[{!r}:{!r}]'.format(args.start, args.stop)
			elif method == '__getattr__' and args in ['AND', 'OR', 'NOT']:
				s = '({}).{}'.format(s, args)
			else:
				s += repstr.format(args)
		return s
	
	def AS_resolve(self, Reference, appdata):
		# (Note: reference.Reference class is passed as argument simply to avoid circular import between that module and this)
		ref = Reference(appdata, {'app':aem.app, 'con':aem.con, 'its':aem.its}[self._call[0]])
		for method, args, repstr in self._call[1:]:
			if method == '__getattr__':
				ref = getattr(ref, args)
			elif method == '__call__':
				ref = ref(*args[0], **args[1])
			else:
				ref = getattr(ref, method)(args)
		return ref

##

con = GenericReference(['con'])
its = GenericReference(['its'])
# 'app' is defined in reference module

