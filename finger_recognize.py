'''
Description:[指纹识别模块]
Author:[huan666]
Date:[2023/11/11]
'''
import httpx_status
import os

def finger_scan(ip1):

    result = httpx_status.status_scan(ip1)

    finger_list = []
    for i in result:
        result = os.popen('bash ./finger.sh finger'+''+' '+i).read()
        finger_list.append(result)
    
    return finger_list