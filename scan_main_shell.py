'''
Description:[命令行查询入口文件]
Author:[huan666]
Date:[2023/11/15]
'''
from config import switch
import httpx_status
import finger_recognize
import icp
import basic
import ip138
import sys
import json
import subprocess

def single_scan():
    ip = sys.argv[1]
     #状态码为200的url
    data1=httpx_status.status_scan(ip)

    #状态码为200的url指纹信息
    data3 = finger_recognize.finger_scan(ip)

    #icp备案信息
    data4 = icp.icp_scan(ip)

    #ip归属地
    output = subprocess.check_output(["sh", "./location.sh"], stderr=subprocess.STDOUT)
    output_list = output.decode().splitlines()
    #定义列表
    location_list = []
    for ii in output_list:
        if "地址" in ii:
            location_list.append(ii)
    localtion_list_1 = location_list[0].replace("地址","")
    localtion_list_result = localtion_list_1.replace(":","")

    #端口信息
    port = basic.shodan_api(ip)

    #ip138域名
    ip138_domain = ip138.ip138_scan(ip)

    dict_data = {
        "ip":ip,
        "port":port,
        "location":localtion_list_result,
        "company":data4,
        "history_domain":ip138_domain,
        "survival_domain":data1,
        "fingerprint":data3
    }
    json_data = json.dumps(dict_data,indent=4,ensure_ascii=False)
    with open('./output.json', 'w') as f:
        json.dump(dict_data,f,indent=4,ensure_ascii=False)
    print(json_data)


def batch_scan():

    print("批量扫描")


if __name__ == '__main__':
    if int(switch) == 0:
        single_scan()

    elif int(switch) ==1:
        batch_scan()

    else:
        print("配置文件switch字段只允许0/1")