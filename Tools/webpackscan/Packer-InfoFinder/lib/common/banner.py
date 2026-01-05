# !/usr/bin/env python3
# -*- encoding: utf-8 -*-

import random
from lib.common.utils import Utils
from lib.common.cmdline import CommandLines


Version = 'Packer InfoFinder v1.5'
red = '\033[25;31m'
green = '\033[25;32m'
yellow = '\033[25;33m'
blue = '\033[25;34m'
Fuchsia = '\033[25;35m'
cyan = '\033[25;36m'
end = '\033[0m'
colors = [red,green,yellow,blue,Fuchsia,cyan]

Banner = '''{}
 _____________________
< Packer-InfoFinder >
 _____________________
    \\
     \\
                                   .::!!!!!!!:.
  .!!!!!:.                        .:!!!!!!!!!!!!
  ~~~~!!!!!!.                 .:!!!!!!!!!UWWW$$$
      :$$NWX!!:           .:!!!!!!XUWW$$$$$$$$$P
      $$$$$##WX!:      .<!!!!UW$$$$"  $$$$$$$$#
      $$$$$  $$$UX   :!!UW$$$$$$$$$   4$$$$$*
      ^$$$B  $$$$\\     $$$$$$$$$$$$   d$$R"
        "*$bd$$$$      '*$$$$$$$$$$$o+#"
             """"          """""""
             {}
             
                          风岚sec-TFour、eonun
{}
'''.format(random.choice(colors),Version,end)



def RandomBanner():
    # BannerList = [Banner1,Banner2,Banner3,Banner7]
    if CommandLines().cmd().silent == None:
        print(Banner)
