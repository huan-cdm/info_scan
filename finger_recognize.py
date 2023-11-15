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
        result1 = result.replace("[1;31m","")
        result2 = result1.replace("[0m","")
        result3 = result2.replace("[1;32m","")
        result4 = result3.replace("|",",")
        result5 = result4.replace("Banner: ","")
        finger_list.append(result5)
    
    #清空列表为空的数据
    while '' in finger_list:
        finger_list.remove('')
    #列表为空返回None
    if len(finger_list) == 0:
        finger_list.append("None")
    
    return finger_list