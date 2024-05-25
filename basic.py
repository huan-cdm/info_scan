'''
Description:[IP开放端口信息]
Author:[huan666]
Date:[2023/11/12]
'''
import shodan
from config import shodankey
import re
import queue
import subprocess 

# icp备案查询
import httpx_status
import requests
from bs4 import BeautifulSoup
from fake_useragent import UserAgent
import random

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



# 目标url文件存入列表并返回
def url_file_ip_list():
    url_list = []
    file = open("/TIP/batch_scan_domain/url.txt",encoding='utf-8')
    for line in file.readlines():
        url_list.append(line.strip())
    return url_list


# 列表存入到队列中用于nmap扫描
def ip_queue_nmap():
    # 创建一个空队列
    q = queue.Queue()
    ip_list = url_convert_ip()
    for item in ip_list:
        q.put(item)
    # 取出并打印队列中的所有元素（先进先出）  
    while not q.empty():  
        ip_queue = q.get()
        result = subprocess.run(["sh", "./finger.sh","nmap_port",ip_queue], stdout=subprocess.PIPE) 

 
 # 生成一个随机的IPv4地址  
def generate_random_ip():  
    return '.'.join(str(random.randint(0, 255)) for _ in range(4)) 


# ICP备案信息查询
def icp_info(ip):
    UA = UserAgent()
    url = "https://icp.chinaz.com/" 
    hearder = {
        'Cookie':'cz_statistics_visitor=47200924-88b7-cc6f-e817-6e3d3d76af1c; pinghost=pay.it.10086.cn; Hm_lvt_ca96c3507ee04e182fb6d097cb2a1a4c=1707096410,1707902350; _clck=5gzbp1%7C2%7Cfj9%7C0%7C1496; qHistory=Ly9taWNwLmNoaW5hei5jb20vX+e9keermeWkh+ahiOafpeivol/np7vliqh8Ly9pY3AuY2hpbmF6LmNvbS9f572R56uZ5aSH5qGI5p+l6K+i; JSESSIONID=B525D76194927A260AC9E9C0B72B44D2; Hm_lpvt_ca96c3507ee04e182fb6d097cb2a1a4c=1707902454; _clsk=1hj5on3%7C1707902455070%7C6%7C0%7Cw.clarity.ms%2Fcollect',
        'Accept-Language':'zh-CN,zh;q=0.9,en;q=0.8',
        'User-Agent':UA.random,
        'Host':'icp.chinaz.com',
        'X-Forwarded-For': generate_random_ip()
        }
    #状态码为200并带http或者https的列表
    domain_value = httpx_status.status_scan(ip)
    
    # 提取带cn或者com的列表
    domain_list = []
    for ii in domain_value:
        if 'cn' in ii or 'com' in ii:
            domain_list.append(ii)

    # 列表去重
    try:
        domain_list_uniq = list(set(domain_list))
        domain_list_uniq_value = domain_list_uniq[0]
    except:
        pass

    
    if len(domain_list_uniq) == 0:
        icp_name = "None"
    else:
        try:
            res = requests.get(url+str(ii),headers=hearder,allow_redirects=False)
            res.encoding = 'utf-8'
            soup=BeautifulSoup(res.text,'html.parser')
            soup_td = soup.find_all('td')
            icp_name = soup_td[25].text
        except:
            icp_name = "接口异常"
    return icp_name


# 网站标题
def title_scan(url_list):
    hearder={
        'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)'
    }

    url_title_list = []
    if len(url_list) == 0:
        url_title_list.append("None")
    else:
        for url in url_list:
            try:
                res = requests.get(url,headers=hearder,allow_redirects=False)
                res.encoding='utf-8'
                title_1 = re.findall("<title>.*</title>",res.text)
                title_11 = title_1[0]
                title_2 = title_11.replace("<title>","")
                titleinfo = title_2.replace("</title>","")
                url_title_list.append(titleinfo)
            except:
                pass 
    url_title_list_uniq = list(set(url_title_list)) 
    return url_title_list_uniq