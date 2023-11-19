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
import os
import re
import cdn_lib
import title_lib
import subdomain_lib
import ipstatus_lib

def single_scan():
    ip = sys.argv[1]
     #状态码为200的url
    data1=httpx_status.status_scan(ip)

    #状态码为200的url指纹信息
    data3 = finger_recognize.finger_scan(ip)

    #icp备案信息
    data4 = icp.icp_scan(ip)

    #ip归属地
    output = subprocess.check_output(["sh", "./finger.sh","location",ip], stderr=subprocess.STDOUT)
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

    #操作系统识别
    os_type = os.popen('bash ./finger.sh osscan'+' '+ip).read()

    #去掉https://或者http://
    urls_list_1 = [re.sub(r'http://|https://', '', url) for url in data1]
    urls_list = []
    for aa in urls_list_1:
        if "cn" in aa or "com" in aa:
            urls_list.append(aa)
    #定义存放cdn结果列表
    cdn_list_1 = []
     #定义存放子域名的列表
    subdomain_list_1 = []
    for bb in urls_list:
        cdn_result = cdn_lib.cdnscan(bb)
        cdn_list_1.append(cdn_result)

        #子域名存放列表
        subdomain_result = subdomain_lib.subdomain_scan(bb)
        subdomain_list_1.append(subdomain_result)
    try:
        flattened_list = [item for sublist in subdomain_list_1 for item in sublist]
    except:
        pass
    
    #CDN列表去重
    cdn_list = list(set(cdn_list_1))
    if len(cdn_list) == 0:
        cdn_list.append("None")

    #子域名列表去重
    subdomain_list = list(set(flattened_list))
    if len(subdomain_list) ==0:
        subdomain_list.append("None")

    #网站标题
    site_title_list = []
    for sa in data1:
        site_title = title_lib.title_scan(sa)
        site_title_list.append(site_title)
    site_title_list_result = list(set(site_title_list))
    if len(site_title_list_result) == 0:
        site_title_list_result.append("None")

    #IP属性判断
    try:
        ipstatus = ipstatus_lib.ipstatus_scan(ip)
    except:
        pass

    dict_data = {
        "ip":ip,
        "ipstatus":ipstatus,
        "system":os_type,
        "port":port,
        "location":localtion_list_result,
        "company":data4,
        "history_domain":ip138_domain,
        "survival_domain":data1,
        "site_title":site_title_list_result,
        "cdn_info":cdn_list,
        "fingerprint":data3,
        "sudomain":subdomain_list
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