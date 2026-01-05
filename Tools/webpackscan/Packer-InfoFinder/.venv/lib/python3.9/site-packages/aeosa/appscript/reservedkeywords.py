"""reservedkeywords """

import keyword

# Important: the following must be reserved:
#
# - names of properties and methods used in reference.Application and reference.Reference classes
# - names of built-in keyword arguments in reference.Command.__call__

kReservedKeywords = [
	"ID",
	"beginning",
	"end",
	"before",
	"after",
	"previous",
	"next",
	"first",
	"middle",
	"last",
	"any",
	"beginswith",
	"endswith",
	"contains",
	"isin",
	"doesnotbeginwith",
	"doesnotendwith",
	"doesnotcontain",
	"isnotin",
	"AND",
	"NOT",
	"OR",
	"begintransaction",
	"aborttransaction",
	"endtransaction",
	"isrunning",
	"permissiontoautomate", # 10.14+
	"resulttype",
	"canaskforconsent", # 10.14+
	"ignore",
	"timeout",
	"waitreply",
	"help",
	"relaunchmode",
	"as",
	"with",
	"True",
	"False",
	"None",
	 ] + keyword.kwlist