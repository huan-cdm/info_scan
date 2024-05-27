'''
Description:[系统调用第三方接口模块]
Author:[huan666]
Date:[2024/05/25]
'''
# shodan查询模块
import shodan
from config import shodankey
import queue
import subprocess 

# icp备案查询
import httpx_status
from fake_useragent import UserAgent
import random


# 高德地图
from config import gaodekey


# 通用模块
import re
import json
import os
import base64
import requests
from bs4 import BeautifulSoup


# IP属性判断
from config import cloudserver
from config import exitaddress
from config import hotspot
from config import datacenter


# fofa 通过ip查询域名
from config import fofaemail
from config import fofakey
from config import fofanum



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

 
 # 生成一个随机的IPv4地址防止封禁IP  
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
    #历史URL列表
    domain_value = domain_scan(ip)
    
    # 提取带域名后缀以cn或者com的列表，过滤掉IP的URL
    domain_list = []
    for ii in domain_value:
        if 'cn' in ii or 'com' in ii:
            domain_list.append(ii)
    
    # 列表去重
    try:
        domain_list_uniq = list(set(domain_list))
    except:
        pass

    icp_name_list = []
    if len(domain_list_uniq) == 0:
        icp_name_list.append("None")
    else:
        try:
            for jii in domain_list_uniq:
                res = requests.get(url+str(jii),headers=hearder,allow_redirects=False)
                res.encoding = 'utf-8'
                soup=BeautifulSoup(res.text,'html.parser')
                soup_td = soup.find_all('td')
                icp_name = soup_td[25].text
                icp_name_list.append(icp_name)
        except:
            icp_name_list.append("None")
    icp_name_list_uniq = list(set(icp_name_list))
    return icp_name_list_uniq


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
            except:
                url_title_list.append("请求出错")
            try:
                res.encoding='utf-8'
                title_1 = re.findall("<title>.*</title>",res.text)
                title_11 = title_1[0]
                title_2 = title_11.replace("<title>","")
                titleinfo = title_2.replace("</title>","")
                url_title_list.append(titleinfo)
            except:
                pass
    return url_title_list
            



# 调用高德地图接口查询公司位置信息
def amapscan(company_list_list):
   
    hearder={
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)'
        }
    company_location_list = []
    if len(company_list_list) == 0:
        company_location_list.append("None")
    else:
        try:
            for company in company_list_list:
                url = "https://restapi.amap.com/v3/place/text?keywords="+company+"&offset=20&page=1&key="+gaodekey+"&extensions=all"
                res = requests.get(url,headers=hearder,allow_redirects=False)
                res.encoding='utf-8'
                restext = res.text
                resdic=json.loads(restext)
                companylocation = resdic['pois'][0]['address']
                company_location_list.append(companylocation)
        except:
            company_location_list.append("None")
    company_location_list_uniq = list(set(company_location_list))
    return company_location_list_uniq
      
    

# 基于证书查询子域名
def subdomain_scan(domain):
    url = "https://crt.sh/?q="
    hearder={
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)'
    }
    try:
        res = requests.get(url+domain,headers=hearder,allow_redirects=False)
        res.encoding='utf-8'
        restext = res.text
        domain  = re.findall("<TD>.*</TD",restext)
        subdomain_list = []
        for ii in domain:
            if "com" in ii or "cn" in ii:
                subdomain_list.append(ii)
        subdomain_list_result = list(set(subdomain_list))
        subdomain_list_result_1 = []
        for jj in subdomain_list_result:
            if "<BR>" not in jj:
                jj1 = jj.replace("<TD>","")
                jj2 = jj1.replace("</TD","")
                subdomain_list_result_1.append(jj2)
        subdomain_list_result_11 = []
        for kk in subdomain_list_result_1:
            if "<A" not in kk:
                subdomain_list_result_11.append(kk)

        return subdomain_list_result_11
       
    except:
        pass



# 指纹识别接口
def finger_scan(ip1):
    result = httpx_status.status_scan(ip1)
    finger_list = []
    for i in result:
        result = os.popen('bash ./finger.sh finger'+''+' '+i).read()
        #页面显示优化
        pattern = re.compile(r'\x1b\[[0-9;]*m')
        clean_text = pattern.sub('', result)
        clean_text_1 = clean_text.replace("|","")
        finger_list.append(clean_text_1)
    
    #清空列表为空的数据
    while '' in finger_list:
        finger_list.remove('')
    #列表为空返回None
    if len(finger_list) == 0:
        finger_list.append("None")
    
    return finger_list



# IP属性判断
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


# fofa查询模块通过IP反查域名
def domain_scan(ip):

    fofa_first_argv= 'ip=' + ip + ''
    fofa_first_argv_utf8 = fofa_first_argv.encode('utf-8')
    fofa_first_argv_base64=base64.b64encode(fofa_first_argv_utf8)
    fofa_argv_str=str(fofa_first_argv_base64,'utf-8')
    url = "https://fofa.info/api/v1/search/all?email="+fofaemail+"&key="+fofakey+"&size="+fofanum+"&qbase64="
    hearder={
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)'
    }

    try:
        
        res = requests.get(url+fofa_argv_str,headers=hearder,allow_redirects=False)
        res.encoding='utf-8'
        restext = res.text
        resdic=json.loads(restext)
        resdicresult=resdic['results']
      
        fofa_list = []
        for i in resdicresult:
            matches1 = re.findall(r"(http(s)?://\S+)", i[0])
            for match in matches1:

                fofa_list.append(match)
        
        fofa_list_result = []
        for j in fofa_list:
            fofa_list_result.append(j[0])
        
        fofa_list_result_uniq = list(set(fofa_list_result))
        
        return fofa_list_result_uniq
    
    except:
        pass



# cdn识别
def cdnscan(domain):
    try:
        result = os.popen('bash ./finger.sh CDN_scan'+' '+domain).read()
    except:
        pass
    return result

# icp_info()