'''
Description:[cdn识别模块]
Author:[huan666]
Date:[2023/11/17]
'''

import os

def cdnscan(domain):
    try:
        result = os.popen('bash ./finger.sh CDN_scan'+' '+domain).read()
    except:
        pass
    return result