'''
Description:[IP开放端口信息]
Author:[huan666]
Date:[2023/11/12]
'''
import shodan
from config import shodankey
import re

# 调用shodan接口查询ip基础信息
def shodan_api(ip):
    apis = shodan.Shodan(shodankey)
    try:
        result = apis.host(ip)
    except:
        pass
    try:
        port = result['ports']
        port_list = []
        for ii in port:
            port_list.append(ii)
        if len(port_list) == 0:
            port_list.append("NULL")
        return port_list
    except:
        pass


# 从目标url中提取ip地址并存到列表
def url_convert_ip():
    url_list = []
    file = open("/TIP/batch_scan_domain/url.txt",encoding='utf-8')
    for line in file.readlines():
        url_list.append(line.strip())
    
    # 正则表达式匹配IPv4地址  
    ip_pattern = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')  
  
    # 提取IP地址  
    ip_addresses = []  
    for url in url_list:  
        # 使用findall方法找到所有的匹配项  
        matches = ip_pattern.findall(url)  
        for match in matches:  
            # 添加到结果列表中（这里我们假设每个URL只有一个IP地址）  
            ip_addresses.append(match) 
    return ip_addresses


# 遍历ip列表存入文件中用于nmap批量扫描

def ip_convert_file():
    ip_list = url_convert_ip()
    #列表中数据存入文件中
    f = open(file='/TIP/info_scan/result/nmap_ip.txt',mode='w')
    for line in ip_list:
        f.write(str(line)+"\n")
    f.close()