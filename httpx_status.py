'''
Description:[状态码模块]
Author:[huan666]
Date:[2023/11/10]
'''

import domain_lib
import subprocess

def status_scan(ip1):

    domain_list = domain_lib.domain_scan(ip1)
    f = open(file='./domain.txt', mode='w')
    for k in domain_list:
        f.write(str(k)+"\n")
    f.close()

    #判断状态码为200的url
    output = subprocess.check_output(["sh", "./httpxstatus.sh"], stderr=subprocess.STDOUT)
    output_list = output.decode().splitlines()
    
    #提取带http关键字的字符串
    status_code_list = []
    for ii in output_list:
        if "http" in ii:
            status_code_list.append(ii)

    return status_code_list