'''
Description:[ip属性查询]
Author:[huan666]
Date:[2023/11/19]
'''
import subprocess
from config import cloudserver
from config import exitaddress
from config import hotspot
from config import datacenter

def ipstatus_scan(ip):

    try:
        output = subprocess.check_output(["sh", "./finger.sh","location1",ip], stderr=subprocess.STDOUT)
        output_list = output.decode().splitlines()
        
        ip_list = []
        for ii in output_list:
            if "数据二" in ii:
                ip_list.append(ii)
        ip_list_status = ip_list[0]
        ip_status_list_result = []
       
        #云主机判断
        for a1 in cloudserver:
            if a1 in ip_list_status:
                ip_status_list_result.append("云服务器")
        
        #出口地址判断
        for a2 in exitaddress:
            if a2 in ip_list_status:
                ip_status_list_result.append("企业专线或家庭宽带")

        #手机热点
        for a3 in hotspot:
            if a3 in ip_list_status:
                ip_status_list_result.append("手机热点")

        #数据中心
        for a4 in datacenter:
            if a4 in ip_list_status:
                ip_status_list_result.append("数据中心")

        return ip_status_list_result[0]
    
    except:
        pass