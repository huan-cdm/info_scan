"""defaultterminology -- translation tables between appscript-style typenames and corresponding AE codes """

types = [
		# Human-readable names for commonly used AE types.
		# Most of these names are equivalent to AS names, though
		# a few are adjusted to be more 'programmer friendly', 
		# e.g. 'float' instead of 'real', and a few have no AS equivalent,
		# e.g. 'utf8_text'
		('anything', b'****'),
		
		('boolean', b'bool'),
		
		('short_integer', b'shor'),
		('integer', b'long'),
		('unsigned_integer', b'magn'),
		('double_integer', b'comp'),
		
		('fixed', b'fixd'),
		('long_fixed', b'lfxd'),
		('decimal_struct', b'decm'),
		
		('short_float', b'sing'),
		('float', b'doub'),
		('extended_float', b'exte'),
		('float_128bit', b'ldbl'),
		
		('string', b'TEXT'),
		('styled_text', b'STXT'),
		('text_style_info', b'tsty'),
		('styled_clipboard_text', b'styl'),
		('encoded_string', b'encs'),
		('writing_code', b'psct'),
		('international_writing_code', b'intl'),
		('international_text', b'itxt'),
		('unicode_text', b'utxt'),
  		('utf8_text', b'utf8'), # typeUTF8Text
		('utf16_text', b'ut16'), # typeUTF16ExternalRepresentation
		
		('version', b'vers'),
		('date', b'ldt '),
		('list', b'list'),
		('record', b'reco'),
		('data', b'tdta'),
		('script', b'scpt'),
		
		('location_reference', b'insl'),
		('reference', b'obj '),
		
		('alias', b'alis'),
		('file_ref', b'fsrf'),
		('file_specification', b'fss '),
		('file_url', b'furl'),
		
		('point', b'QDpt'),
		('bounding_rectangle', b'qdrt'),
		('fixed_point', b'fpnt'),
		('fixed_rectangle', b'frct'),
		('long_point', b'lpnt'),
		('long_rectangle', b'lrct'),
		('long_fixed_point', b'lfpt'),
		('long_fixed_rectangle', b'lfrc'),
		
		('EPS_picture', b'EPS '),
		('GIF_picture', b'GIFf'),
		('JPEG_picture', b'JPEG'),
		('PICT_picture', b'PICT'),
		('TIFF_picture', b'TIFF'),
		('RGB_color', b'cRGB'),
		('RGB16_color', b'tr16'),
		('RGB96_color', b'tr96'),
		('graphic_text', b'cgtx'),
		('color_table', b'clrt'),
		('pixel_map_record', b'tpmm'),
		
		('best', b'best'),
		('type_class', b'type'),
		('enumerator', b'enum'),
		('property', b'prop'),
		
		# AEAddressDesc types
		
		('mach_port', b'port'),
		('kernel_process_id', b'kpid'),
		('application_bundle_id', b'bund'),
		('process_serial_number', b'psn '),
		('application_signature', b'sign'),
		('application_url', b'aprl'),
		
		# misc.
		
		('missing_value', b'msng'),
		
		('null', b'null'),
		
		('machine_location', b'mLoc'),
		('machine', b'mach'),
		
		('dash_style', b'tdas'),
		('rotation', b'trot'),
		
		('suite_info', b'suin'),
		('class_info', b'gcli'),
		('property_info', b'pinf'),
		('element_info', b'elin'),
		('event_info', b'evin'),
		('parameter_info', b'pmin'),
		
		('item', b'cobj'), # Apple have removed the 'item' class definition from skeleton.sdef
		
		# unit types
		
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
		
		# month and weekday
		
		('January', b'jan '),
		('February', b'feb '),
		('March', b'mar '),
		('April', b'apr '),
		('May', b'may '),
		('June', b'jun '),
		('July', b'jul '),
		('August', b'aug '),
		('September', b'sep '),
		('October', b'oct '),
		('November', b'nov '),
		('December', b'dec '),
		
		('Sunday', b'sun '),
		('Monday', b'mon '),
		('Tuesday', b'tue '),
		('Wednesday', b'wed '),
		('Thursday', b'thu '),
		('Friday', b'fri '),
		('Saturday', b'sat '),
]


pseudotypes = [ # non-concrete types that are only used for documentation purposes; use to remap typesbycode
		('file', b'file'), # typically FileURL, but could be other file types as well
		('number', b'nmbr'), # any numerical type: Integer, Float, Long
		# ('text', b'ctxt'), # Word X, Excel X uses 'ctxt' instead of 'TEXT' or 'utxt' (TO CHECK: is this Excel's stupidity, or is it acceptable?)
]


properties = [
		('class_', b'pcls'), # used as a key in AERecord structures that have a custom class; also, Apple have removed the 'item' class definition from skeleton.sdef
		('properties', b'pALL'), # Apple have removed the 'item' class definition from skeleton.sdef
		('id', b'ID  '), # some apps (e.g. iTunes) may omit 'id' property from terminology despite using it
]


elements = [
		('items', b'cobj'), # Apple have removed the 'item' class definition from skeleton.sdef
]


enumerations = [
		('savo', [
				('yes', b'yes '), 
				('no', b'no  '), 
				('ask', b'ask '),
		]),
		# constants used in commands' 'ignore' argument (note: most apps currently ignore these):
		('cons', [
			('case', b'case'),
			('diacriticals', b'diac'),
			('expansion', b'expa'),
			('punctuation', b'punc'),
			('hyphens', b'hyph'),
			('whitespace', b'whit'),
			('numeric_strings', b'nume'),
			('application_responses', b'rmte'),
		]),
]


commands = [
	# required suite
	('run', b'aevtoapp', []),
	('open', b'aevtodoc', []),
	('print_', b'aevtpdoc', []),
	('quit', b'aevtquit', [('saving', b'savo')]),
	# 'reopen' and 'activate' aren't listed in required suite, but should be
	('reopen', b'aevtrapp', []),
	('activate', b'miscactv', []),
	# 'launch' is a special case not listed in the required suite and implementation is provided by
	# the Apple event bridge (not the target applications), which uses the Process Manager/
	# LaunchServices to launch an application without sending it the usual run/open event.
	('launch', b'ascrnoop', []),
	# 'get' and 'set' commands are often omitted from applications' core suites, even when used
	('get', b'coregetd', []),
	('set', b'coresetd', [('to', b'data')]),
	# some apps (e.g. Safari) which support GetURL events may omit it from their terminology; 
	# 'open location' is the name Standard Additions defines for this event, so use it here
	('open_location', b'GURLGURL', [('window', b'WIND')]), 
]


