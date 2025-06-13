#!/usr/bin/python3
# shodan查询模块
import shodan
import queue
import subprocess 
# icp备案查询
from fake_useragent import UserAgent
import random
# 通用模块
import re
import json
import os
import base64
import mmh3
import requests
from bs4 import BeautifulSoup
import time
# IP属性判断
from config import cloudserver
from config import exitaddress
from config import hotspot
from config import datacenter
# fofa 通过ip查询域名
from config import fofanum

# 提取根域名
import tldextract  
# 指纹自定义列表
from config import finger_list
# MySQL操作模块
import pymysql
from config import dict
from config  import rule_options
# 根据规则分别存入不同的文件
from config import Shiro_rule
from config import SpringBoot_rule
from config import weblogic_rule
from config import struts2_rule
# 磁盘读写
import psutil
import sys
# 线程
import threading
from config import history_switch

import datetime

# yaml格式文件处理模块
import yaml
from config import device_pass_dir
from config import antiv_software_dir

# 过滤内网
import ipaddress

# dns日志
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import TimeoutException

import uuid




# IP基础信息端口查询通过fofa+shodan
def shodan_api(ip):
    
    shodankeyvalue = select_session_time_lib(3)
    apis = shodan.Shodan(shodankeyvalue)
    fofa_conf = select_fofakey_lib(2)
    fofa_email = fofa_conf[0]
    fofa_key = fofa_conf[1]
    key = {"email":str(fofa_email),"key":str(fofa_key)}
    # fofa接口
    fofa_first_argv= 'ip=' + ip + ''
    fofa_first_argv_utf8 = fofa_first_argv.encode('utf-8')
    fofa_first_argv_base64=base64.b64encode(fofa_first_argv_utf8)
    fofa_argv_str=str(fofa_first_argv_base64,'utf-8')
    url = "https://fofa.info/api/v1/search/all?email="+key["email"]+"&key="+key["key"]+"&size="+fofanum+"&qbase64="
    hearder={
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)'
    }

    try:
        result = apis.host(ip)
    except:
        pass
    try:
        # shodan接口
        port = result['ports']
        port_list = []
        for ii in port:
            port_list.append(ii)
        if len(port_list) == 0:
            port_list.append("NULL")

        # fofa接口
        res = requests.get(url+fofa_argv_str,headers=hearder,allow_redirects=False)
        res.encoding='utf-8'
        restext = res.text
        resdic=json.loads(restext)
        resdicresult=resdic['results']
        fofa_port_list = []
        for ki in resdicresult:
            fofa_port_list.append(ki[2])
        
        fofa_port_list_uniq = list(set(fofa_port_list))
        if len(fofa_port_list_uniq) == 0:
            fofa_port_list_uniq.append("NULL")
        
        # 列表元素转int型
        fofa_port_list_uniq_int = []
        for inti in fofa_port_list_uniq:
            fofa_port_list_uniq_int.append(int(inti))
        # fofa+shodan列表组合并去重
        total_list = list(set(fofa_port_list_uniq_int+port_list))
        return total_list
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

# 资产备份文件转列表
def url_back_file_ip_list():
    os.popen('cp /TIP/batch_scan_domain/url_back.txt /TIP/batch_scan_domain/url.txt')
    url_back_list = []
    file = open("/TIP/batch_scan_domain/url_back.txt",encoding='utf-8')
    for line in file.readlines():
        url_back_list.append(line.strip())
    return url_back_list

# 列表存入到队列中用于nmap扫描
def ip_queue_nmap(ip_queue_nmap):
    # 创建一个空队列
    q = queue.Queue()
    ip_list = url_convert_ip()
    for item in ip_list:
        q.put(item)
    # 取出并打印队列中的所有元素（先进先出）  
    while not q.empty():  
        ip_queue = q.get()
        result = subprocess.run(["sh", "./finger.sh","nmap_port",ip_queue,ip_queue_nmap], stdout=subprocess.PIPE) 

 
 # 生成一个随机的IPv4地址防止封禁IP  
def generate_random_ip():  
    return '.'.join(str(random.randint(0, 255)) for _ in range(4)) 


# ICP备案查询返回列表
def icp_info(ip):
    try:
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
                    print(jii)
                    res = requests.get(url+str(jii),headers=hearder,allow_redirects=False)
                    res.encoding = 'utf-8'
                    soup=BeautifulSoup(res.text,'html.parser')
                    soup_td = soup.find_all('td')
                    icp_name = soup_td[25].text
                    icp_name_list.append(icp_name)
            except:
                icp_name_list.append("ICP备案接口正在更新维护中")
        icp_name_list_uniq = list(set(icp_name_list))
        print(type(icp_name_list_uniq))
        success_third_party_port_addone(4)
    except:
        icp_name_list_uniq = ["None"]
        fail_third_party_port_addone(4)
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
                # 忽略 SSL 验证，可以使用 Session 对象来避免重复设置 verify=False
                session = requests.Session()  
                session.verify = False
                res = session.get(url,headers=hearder,allow_redirects=False)
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
    key = select_session_time_lib(4)
    hearder={
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)'
        }
    company_location_list = []
    if len(company_list_list) == 0:
        company_location_list.append("None")
    else:
        try:
            for company in company_list_list:
                # 判断公司名为空时公司位置直接返回空
                if company == "None":
                    company_location_list.append("None")
                else:
                    url = "https://restapi.amap.com/v3/place/text?keywords="+company+"&offset=20&page=1&key="+key+"&extensions=all"
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
    try:
        result = status_scan(ip1)
        finger_list = []
        for i in result:
            result = os.popen('bash /TIP/info_scan/finger.sh finger'+''+' '+i).read()
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
    except:
        finger_list = ["None"]
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
    fofa_conf = select_fofakey_lib(2)
    fofa_email = fofa_conf[0]
    fofa_key = fofa_conf[1]
    key = {"email":str(fofa_email),"key":str(fofa_key)}
    fofa_first_argv= 'ip=' + ip + ''
    fofa_first_argv_utf8 = fofa_first_argv.encode('utf-8')
    fofa_first_argv_base64=base64.b64encode(fofa_first_argv_utf8)
    fofa_argv_str=str(fofa_first_argv_base64,'utf-8')
    url = "https://fofa.info/api/v1/search/all?email="+key["email"]+"&key="+key["key"]+"&size="+fofanum+"&qbase64="
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
    except:
        fofa_list_result_uniq = ["None"]
    return fofa_list_result_uniq
    
    



# cdn识别
def cdnscan(domain):
    try:
        result = os.popen('bash /TIP/info_scan/finger.sh CDN_scan'+' '+domain).read()
    except:
        pass
    return result


# 根域名提取
def root_domain_scan(domain_list):
    try:
        root_domains = []  
        for url in domain_list:  
            extract = tldextract.extract(url)  
            root_domain = f"{extract.domain}.{extract.suffix}"
            root_domains.append(root_domain)
        return root_domains
    except:
        pass


# 提取状态码为200的url
def status_scan(ip1):
    try:
        domain_list = domain_scan(ip1)
        f = open(file='./result/domain.txt', mode='w')
        for k in domain_list:
            f.write(str(k)+"\n")
        f.close()
    
        #判断状态码为200的url
        try:
            output = subprocess.check_output(["sh", "./finger.sh","httpxfilterstatus"], stderr=subprocess.STDOUT)
            output_list = output.decode().splitlines()
        except Exception as e:
            print("捕获到异常:", e)
    
        
        #提取带http关键字的字符串
        status_code_list = []
        for ii in output_list:
            if "http" in ii:
                status_code_list.append(ii)
        
        if len(status_code_list) == 0:
            status_code_list.append("None")
    
        # 删除特殊字符
        status_code_list_result = []
        for jj in status_code_list:
            if "version" not in jj:
                status_code_list_result.append(jj)
    except:
        status_code_list_result = ["None"]
    return status_code_list_result


# fscan批量扫描
def batch_fscan_interface(part,part1):
    ip_list = url_convert_ip()
    
    f = open(file='/TIP/info_scan/fscan_tool/ip.txt', mode='w')
    for k in ip_list:
        f.write(str(k)+"\n")
    f.close()

    # 禁止Web漏洞扫描
    if int(part1) == 1:
        try:
            os.popen('bash /TIP/info_scan/finger.sh startfscanprocessmoren'+' '+part)
        except Exception as e:
            print("捕获到异常:", e)
    # 启用Web漏洞扫描
    elif int(part1) == 2:
        try:
            os.popen('bash /TIP/info_scan/finger.sh startfscanprocessmorenall'+' '+part)
        except Exception as e:
            print("捕获到异常:", e)
    else:
        print("只允许参数0和1")



# shiro漏洞扫描
def shiro_scan():
    # 清空上一次扫描结果
    os.popen('rm -rf /TIP/info_scan/result/shiro_vuln.txt')
    # 遍历url列表
    url_list = url_file_ip_list()
    try:
        for i in url_list:
            os.popen('bash /TIP/info_scan/finger.sh shiro_scan'+' '+str(i)+'')
    except Exception as e:
        print("捕获到异常:", e)



# 重点系统关键字列表，在config.py配置，用于过滤重点目标，并进行针对性扫描
# 2024.6.12优化
def key_point_tiqu():
    # 提取通过自定义列表过滤出的目标，并提取这些目标的关键字作为字典，存入列表中
    filter_list_result = []
   
    # 配置文件或者MySQL数据库
    if int(rule_options) == 1:
        key_rule_list = str(finger_list)
    elif int(rule_options) == 2:
        key_rule_list = select_rule()
    else:
        key_rule_list = ['参数只能为0/1']

    try:
        for i in key_rule_list:
            result = os.popen('bash /TIP/info_scan/finger.sh finger_filter_shell'+' '+i).read()
            filter_list_result.append(result)
    
    except Exception as e:
        print("捕获到异常:", e)

    try:
        f2 = open(file='/TIP/info_scan/result/finger_filter_text.txt', mode='w')
        for j in filter_list_result:
            j1 = j.replace("[","")
            j2 = j1.replace("]","")
            j3 = j2.replace("|","")
            f2.write(str(j3))
        f2.close()
    except Exception as e:
        print("捕获到异常:", e)
    
    try:
        filter_list_result_final = []
        f3 = open("/TIP/info_scan/result/finger_filter_text.txt",encoding='utf-8')
        for k in f3.readlines():
            #页面显示优化
            pattern = re.compile(r'\x1b\[[0-9;]*m')
            clean_text = pattern.sub('', k)
            clean_text_1 = clean_text.replace("\x1b38;2;237;64;35m ","")
            clean_text_2 = clean_text_1.replace(" \x1b0m","")
            filter_list_result_final.append(clean_text_2.strip())
            
    except Exception as e:
        print("捕获到异常:", e)

    finger_url_list_final = []
    for item in filter_list_result_final:
        url = item.split()[0]
        finger_url_list_final.append(url)
        finger_url_list_final_uniq = list(set(finger_url_list_final))
    return finger_url_list_final_uniq



# 重点资产数量
def key_point_assets_num(assets_finger_list):
    # 提取通过自定义列表过滤出的目标，并提取这些目标的关键字作为字典，存入列表中
    filter_list_result = []
    try:
        for i in assets_finger_list:
            result = os.popen('bash /TIP/info_scan/finger.sh finger_filter_shell'+' '+i).read()
            filter_list_result.append(result)
    except Exception as e:
        print("捕获到异常:", e)

    try:
        f2 = open(file='/TIP/info_scan/result/finger_filter_text.txt', mode='w')
        for j in filter_list_result:
            j1 = j.replace("[","")
            j2 = j1.replace("]","")
            j3 = j2.replace("|","")
            f2.write(str(j3))
        f2.close()
    except Exception as e:
        print("捕获到异常:", e)
    
    try:
        filter_list_result_final = []
        f3 = open("/TIP/info_scan/result/finger_filter_text.txt",encoding='utf-8')
        for k in f3.readlines():
            #页面显示优化
            pattern = re.compile(r'\x1b\[[0-9;]*m')
            clean_text = pattern.sub('', k)
            clean_text_1 = clean_text.replace("\x1b38;2;237;64;35m ","")
            clean_text_2 = clean_text_1.replace(" \x1b0m","")
            filter_list_result_final.append(clean_text_2.strip())
            
    except Exception as e:
        print("捕获到异常:", e)

    try:
        finger_url_list_final = []
        for item in filter_list_result_final:
            url = item.split()[0]
            finger_url_list_final.append(url)
    except:
        pass
    
    if len(finger_url_list_final) == 0:
        assets_len = 0
    else:
        finger_url_list_final_uniq = list(set(finger_url_list_final))
        assets_len = len(finger_url_list_final_uniq)
    
    return assets_len




# 识别重点资产存入文件
def key_point_assets_file(assets_finger_list):
    # 提取通过自定义列表过滤出的目标，并提取这些目标的关键字作为字典，存入列表中
    filter_list_result = []
    try:
        for i in assets_finger_list:
            result = os.popen('bash /TIP/info_scan/finger.sh finger_filter_shell'+' '+i).read()
            filter_list_result.append(result)
    except Exception as e:
        print("捕获到异常:", e)

    try:
        f2 = open(file='/TIP/info_scan/result/finger_filter_text.txt', mode='w')
        for j in filter_list_result:
            j1 = j.replace("[","")
            j2 = j1.replace("]","")
            j3 = j2.replace("|","")
            f2.write(str(j3))
        f2.close()
    except Exception as e:
        print("捕获到异常:", e)
    
    try:
        filter_list_result_final = []
        f3 = open("/TIP/info_scan/result/finger_filter_text.txt",encoding='utf-8')
        for k in f3.readlines():
            #页面显示优化
            pattern = re.compile(r'\x1b\[[0-9;]*m')
            clean_text = pattern.sub('', k)
            clean_text_1 = clean_text.replace("\x1b38;2;237;64;35m ","")
            clean_text_2 = clean_text_1.replace(" \x1b0m","")
            filter_list_result_final.append(clean_text_2.strip())
            
    except Exception as e:
        print("捕获到异常:", e)

    try:
        finger_url_list_final = []
        for item in filter_list_result_final:
            url = item.split()[0]
            finger_url_list_final.append(url)
    except:
        pass
    finger_url_list_final_uniq = list(set(finger_url_list_final))
    return finger_url_list_final_uniq



# fofa资产发现，查询数量通过前端传入
def fofa_search_assets_service_lib(parameter,num_fofa):
    fofa_conf = select_fofakey_lib(2)
    fofa_email = fofa_conf[0]
    fofa_key = fofa_conf[1]
    key = {"email":str(fofa_email),"key":str(fofa_key)}
    
    
    fofa_first_argv_utf8 = parameter.encode('utf-8')
    fofa_first_argv_base64=base64.b64encode(fofa_first_argv_utf8)
    fofa_argv_str=str(fofa_first_argv_base64,'utf-8')

    url = "https://fofa.info/api/v1/search/all?email="+key["email"]+"&key="+key["key"]+"&size="+num_fofa+"&qbase64="
    hearder={
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)'
    }

    try:
        
        res = requests.get(url+fofa_argv_str,headers=hearder,allow_redirects=False)
        res.encoding='utf-8'
        restext = res.text
        resdic=json.loads(restext)
        resdicresult=resdic['results']

        # fofa查询接口优化后，t去掉之间的只保留以协议开头的资产
        fofa_list = []
        for i in resdicresult:
            fofa_list.append(i[0])
        fofa_list_result_uniq = list(set(fofa_list))



        
        # 遍历列表存入目标资产
        f = open(file='/TIP/batch_scan_domain/url.txt', mode='w')
        for k in fofa_list_result_uniq:
            f.write(str(k)+"\n")
        f.close()

        # 存入资产项目管理目录,前端通过下拉列表查看资产,以当前时间戳命名文件名
        # 获取当前时间
        now = datetime.datetime.now()
        # 获取年月日时分秒，并确保月份和日期有两位数字
        year = str(now.year)
        month = now.month if now.month > 9 else f"0{now.month}"
        day = now.day if now.day > 9 else f"0{now.day}"
        hour = now.hour if now.hour > 9 else f"0{now.hour}"
        minute = now.minute if now.minute > 9 else f"0{now.minute}"
        second = now.second if now.second > 9 else f"0{now.second}"
        
        # 构建文件名
        file_name = f"{year}/{month}/{day}{hour}:{minute}:{second}.txt"
        
        file_name_result = f"/TIP/info_scan/result/assetmanager/{file_name}"
        insert_fofa_log_lib(parameter,file_name_result)
        # 确保目录存在
        os.makedirs(os.path.dirname(file_name_result), exist_ok=True)
        
        # 打开文件并写入数据
        with open(file=file_name_result, mode='w') as f21:
            for line21 in fofa_list_result_uniq:
                f21.write(str(line21) + "\n")
        
        # 资产备份
        os.popen('cp /TIP/batch_scan_domain/url.txt /TIP/batch_scan_domain/url_back.txt')
    except:
        # fofa接口异常无数据长度返回0
        fofa_list_result_uniq = [""]
        fofa_list_result_uniq.clear()
    return len(fofa_list_result_uniq)
    
    


# 启动hydra弱口令扫描库文件
def start_hydra_lib(part):
    if int(part) == 1:
        try:
            os.popen('bash /TIP/info_scan/finger.sh mysql_weak_password')
        except Exception as e:
            print("捕获到异常:", e)
    elif int(part) == 2:
        try:
            os.popen('bash /TIP/info_scan/finger.sh ssh_weak_password')
        except Exception as e:
            print("捕获到异常:", e)
    elif int(part) == 3:
        try:
            os.popen('bash /TIP/info_scan/finger.sh ftp_weak_password')
        except Exception as e:
            print("捕获到异常:", e)
    elif int(part) == 4:
        try:
            os.popen('bash /TIP/info_scan/finger.sh redis_weak_password')
        except Exception as e:
            print("捕获到异常:", e)

    elif int(part) == 5:
        try:
            os.popen('bash /TIP/info_scan/finger.sh mssql_weak_password')
        except Exception as e:
            print("捕获到异常:", e)
    else:
        print("接收的参数为1-5")



# 重点资产中筛选规则查询
def select_rule():
    try:
        db= pymysql.connect(host=dict['ip'],user=dict['username'],  
        password=dict['password'],db=dict['dbname'],port=dict['portnum']) 
        cur = db.cursor()
        sql="select rule FROM rule_table"
        cur.execute(sql)
        data = cur.fetchall()
        list_data = list(data)
        list_result = []
        for i in list_data:
            list_result.append(i[0])
    except:
        list_result = ['MySQL连接失败']

    return list_result


# 筛选后资产状态查询
def assets_status_show():
    try:
        db= pymysql.connect(host=dict['ip'],user=dict['username'],  
        password=dict['password'],db=dict['dbname'],port=dict['portnum']) 
        cur = db.cursor()
        sql="SELECT status_value FROM status_table where id = 1"
        cur.execute(sql)
        data = cur.fetchall()
        list_data = list(data)
        status_value = []
        for i in list_data:
            status_value.append(i[0])
        status_value_result = status_value[0]
    except:
        status_value_result = "MySQL连接失败"
    return status_value_result


# 筛选后资产状态更新
def assets_status_update(part):
    try:
        db= pymysql.connect(host=dict['ip'],user=dict['username'],  
        password=dict['password'],db=dict['dbname'],port=dict['portnum']) 
        cur = db.cursor()
        sql="UPDATE status_table SET status_value = '%s' WHERE id = 1"%(part)
        cur.execute(sql)
        db.commit()
        
    except Exception as e:
        print("捕获到异常:", e)
        db.rollback()



# 扫描器时间线查询
def vuln_scan_status_show():
    try:
        db= pymysql.connect(host=dict['ip'],user=dict['username'],  
        password=dict['password'],db=dict['dbname'],port=dict['portnum']) 
        cur = db.cursor()
        sql="SELECT status_value FROM status_table where id = 2"
        cur.execute(sql)
        data = cur.fetchall()
        list_data = list(data)
        status_value = []
        for i in list_data:
            status_value.append(i[0])
        vuln_status_value_result = status_value[0]
    except:
        vuln_status_value_result = "MySQL连接失败"
    return vuln_status_value_result



# 扫描器时间线更新
def vuln_scan_status_update(part):
    try:
        db= pymysql.connect(host=dict['ip'],user=dict['username'],  
        password=dict['password'],db=dict['dbname'],port=dict['portnum']) 
        cur = db.cursor()
        sql="UPDATE status_table SET status_value = '%s' WHERE id = 2"%(part)
        cur.execute(sql)
        db.commit()
             
    except Exception as e:
        print("捕获到异常:", e)
        db.rollback()



# 从资产文件url.txt中根据规则分别提取出springboot、weblogic、struts2、shiro资产并写入对应的文件
def asset_by_rule_handle():

    # shiro
    try:
        shiro_file_list = key_point_assets_file(Shiro_rule)
        f_shiro = open(file='/TIP/info_scan/result/keyasset/shiro_file.txt',mode='w')
        for shiro_line in shiro_file_list:
            f_shiro.write(str(shiro_line)+"\n")
        f_shiro.close()
    except Exception as e:
        print("捕获到异常:", e)

    # springboot
    try:
        springboot_file_list = key_point_assets_file(SpringBoot_rule)
        f_springboot = open(file='/TIP/info_scan/result/keyasset/springboot_file.txt',mode='w')
        for springboot_line in springboot_file_list:
            f_springboot.write(str(springboot_line)+"\n")
        f_springboot.close()
    except Exception as e:
        print("捕获到异常:", e)

    # struts2
    try:
        struts2_file_list = key_point_assets_file(struts2_rule)
        f_struts2 = open(file='/TIP/info_scan/result/keyasset/struts2_file.txt',mode='w')
        for struts2_line in struts2_file_list:
            f_struts2.write(str(struts2_line)+"\n")
        f_struts2.close()
    except Exception as e:
        print("捕获到异常:", e)

    # weblogic
    try:
        weblogic_file_list = key_point_assets_file(weblogic_rule)
        f_weblogic = open(file='/TIP/info_scan/result/keyasset/weblogic_file.txt',mode='w')
        for weblogic_line in weblogic_file_list:
            f_weblogic.write(str(weblogic_line)+"\n")
        f_weblogic.close()
    except Exception as e:
        print("捕获到异常:", e)



# 磁盘读写状态查询
def disk_read_write():
    try:
        # 获取当前的读取和写入字节数
        io_counters_start = psutil.disk_io_counters()
        read_bytes_start = io_counters_start.read_bytes
        write_bytes_start = io_counters_start.write_bytes
    
        # 等待一段时间（例如1秒）
        time.sleep(1)
    
        # 再次获取读取和写入字节数
        io_counters_end = psutil.disk_io_counters()
        read_bytes_end = io_counters_end.read_bytes
        write_bytes_end = io_counters_end.write_bytes
    
        # 计算读取和写入速度（单位：字节/秒）
        read_speed_bytes_per_sec = read_bytes_end - read_bytes_start
        write_speed_bytes_per_sec = write_bytes_end - write_bytes_start
    
        # 将字节转换为MB（1MB = 1024 * 1024 字节）
        read_speed_mb_per_sec = read_speed_bytes_per_sec / (1024 * 1024)
        write_speed_mb_per_sec = write_speed_bytes_per_sec / (1024 * 1024)
    
        
    except Exception as e:
        print("捕获到异常:", e)
    tuple_list = [read_speed_mb_per_sec,write_speed_mb_per_sec]
    return tuple_list


# thinkphp漏洞扫描
def thinkphp_scan():
    # 清空上一次扫描结果
    os.popen('rm -rf /TIP/info_scan/result/thinkphp_vuln.txt')
    # 遍历url列表
    url_list = url_file_ip_list()
    try:
        for i in url_list:
            os.popen('bash /TIP/info_scan/finger.sh thinkphp_vuln_scan'+' '+str(i)+'')
    except Exception as e:
        print("捕获到异常:", e)


# 利用otx网站查询域名绑定url
def otx_domain_url_lib():
    UA = UserAgent()
    try:
        # url.txt转换为列表
        url_list = url_file_ip_list()
        # 提取根域名
        root_domain_list = root_domain_scan(url_list)
        # 根域名去重
        root_domain_list_uniq = list(set(root_domain_list))
        domain_list_uniq_result = []
        for i in root_domain_list_uniq:
            if "cn" in i or "com" in i or "net" in i:
                domain_list_uniq_result.append(i)
    except Exception as e:
        print("捕获到异常:", e)

    
    for domain in domain_list_uniq_result:
        print("\n\n")
        print("[+]"+domain)
        time.sleep(2)
        try:
            success_third_party_port_addone(6)
            url = "https://otx.alienvault.com/api/v1/indicators/domain/" + domain + "/url_list?limit=500&page=1"  
            headers={
            'Cookie':'Hm_lvt_ecdd6f3afaa488ece3938bcdbb89e8da=1615729527; Hm_lvt_d39191a0b09bb1eb023933edaa468cd5=1617883004,1617934903,1618052897,1618228943; Hm_lpvt_d39191a0b09bb1eb023933edaa468cd5=1618567746',
            'Host':'otx.alienvault.com',
            'User-Agent':UA.random
            }
            res = requests.get(url, headers=headers, allow_redirects=False)  
            res.raise_for_status() 
            res_json = res.json()
        
            data = res_json.get('url_list', [])

            # 打印结果 
            for item in data:
                url_text = item.get('url','')
                print(url_text)
        except Exception as e:
            fail_third_party_port_addone(6)
            # 出现异常继续下一下
            print("捕获到异常:", e)
            continue


# 基于证书查询子域名
def crt_subdomain_lib():
    try:
        # url.txt转换为列表
        url_list = url_file_ip_list()
        # 提取根域名
        root_domain_list = root_domain_scan(url_list)
        # 根域名去重
        root_domain_list_uniq = list(set(root_domain_list))
        # domain_list_uniq_result = []
        for i in root_domain_list_uniq:
            if "cn" in i or "com" in i or "net" in i:
                print("\n")
                print("[+]"+i)
                print("\n")
                try:
                    subdomain_list = []
                    time.sleep(1)
                    subdomain = subdomain_scan(i)
                    success_third_party_port_addone(3)
                    subdomain_list.append(subdomain)
                    subdomain_list_all = []
                    for item in subdomain_list:
                        subdomain_list_all.extend(item)
                    for kk in subdomain_list_all:
                        print(kk)
                except Exception as e:
                    print("捕获到异常:", e)
    except Exception as e:
        fail_third_party_port_addone(3)
        print("捕获到异常:", e)



# 信息收集工具集合上一次扫描时间查询
def last_time_lib(part):
    try:
        db= pymysql.connect(host=dict['ip'],user=dict['username'],  
        password=dict['password'],db=dict['dbname'],port=dict['portnum']) 
        cur = db.cursor()
        sql="SELECT time_diff from info_time_diff where id = '%s'"%(part)
        cur.execute(sql)
        data = cur.fetchall()
        list_data = list(data)
        last_time_list = []
        for i in list_data:
            last_time_list.append(i[0])
        last_time_list_result = last_time_list[0]
    except:
        last_time_list_result = "MySQL连接失败"
    return last_time_list_result



# 信息收集集合更新为当前时间
def last_time_update_lib(part1,part2):
    try:
        db= pymysql.connect(host=dict['ip'],user=dict['username'],  
        password=dict['password'],db=dict['dbname'],port=dict['portnum']) 
        cur = db.cursor()
        sql="UPDATE info_time_diff SET time_diff = '%s' WHERE id = '%s'"%(part1,part2)
        cur.execute(sql)
        db.commit()
        
    except Exception as e:
        print("捕获到异常:", e)
        db.rollback()


# 信息收集类扫描器计算时间差
def info_time_shijian_cha(part):
    # 判断2次时间差是否大于2分钟,防止恶意重复提交
    # 获取系统当前时间
    current_time = time.time()
    # 存入数据库的上一次时间,传入参数part代表不同的扫描器
    last_time_str = last_time_lib(part)
    last_time = float(last_time_str)
    diff_time = current_time - last_time
    # 将时间差转换为分钟
    diff_time_minutes = diff_time / 60
    return diff_time_minutes
        
    



# 漏洞扫描工具集合上一次扫描时间查询
def vuln_last_time_lib(part):
    try:
        db= pymysql.connect(host=dict['ip'],user=dict['username'],  
        password=dict['password'],db=dict['dbname'],port=dict['portnum']) 
        cur = db.cursor()
        sql="SELECT time_diff from vuln_time_diff where id = '%s'"%(part)
        cur.execute(sql)
        data = cur.fetchall()
        list_data = list(data)
        last_time_list = []
        for i in list_data:
            last_time_list.append(i[0])
        vuln_last_time_list_result = last_time_list[0]
    except:
        vuln_last_time_list_result = "MySQL连接失败"
    return vuln_last_time_list_result



# 漏洞扫描集合更新为当前时间
def vuln_last_time_update_lib(part1,part2):
    try:
        db= pymysql.connect(host=dict['ip'],user=dict['username'],  
        password=dict['password'],db=dict['dbname'],port=dict['portnum']) 
        cur = db.cursor()
        sql="UPDATE vuln_time_diff SET time_diff = '%s' WHERE id = '%s'"%(part1,part2)
        cur.execute(sql)
        db.commit()
        
    except Exception as e:
        print("捕获到异常:", e)
        db.rollback()



# 漏洞扫描类扫描器计算时间差
def vuln_time_shijian_cha(part):
    # 判断2次时间差是否大于2分钟,防止恶意重复提交
    # 获取系统当前时间
    current_time = time.time()
    # 存入数据库的上一次时间,传入参数part代表不同的扫描器
    last_time_str = vuln_last_time_lib(part)
    last_time = float(last_time_str)
    diff_time = current_time - last_time
    # 将时间差转换为分钟
    diff_time_minutes = diff_time / 60
    return diff_time_minutes



# 关闭漏洞扫描程序
def stopstruts2_lib():
    struts2status = os.popen('bash /TIP/info_scan/finger.sh struts2_status').read()
    os.popen('bash /TIP/info_scan/finger.sh killstruts2process')
    if "stop" in struts2status:
        kill_struts2_result = "已关闭struts2漏洞扫描程序"
    else:
        kill_struts2_result = "正在关闭中......"
    return kill_struts2_result


# 关闭jndi服务
def stopjndi_lib():
    jndi_status = os.popen('bash /TIP/info_scan/finger.sh jndi_server_status').read()
    os.popen('bash /TIP/info_scan/finger.sh stop_jndi_python')
    if "stop" in jndi_status:
        killjndi_result = "已关闭JNDI服务程序"
    else:
        killjndi_result = "正在关闭中......"
    return killjndi_result



def stopweblogic_lib():
    weblogicstatus = os.popen('bash /TIP/info_scan/finger.sh weblogic_status').read()
    os.popen('bash /TIP/info_scan/finger.sh killweblogicprocess')
    if "stop" in weblogicstatus:
        kill_weblogic_result = "已关闭weblogic漏洞扫描程序"
    else:
        kill_weblogic_result = "正在关闭中......"

    return kill_weblogic_result


def stopshiro_lib():
    shirostatus = os.popen('bash /TIP/info_scan/finger.sh shiro_status').read()
    os.popen('bash /TIP/info_scan/finger.sh killshirovulnscanprocess')
    if "stop" in shirostatus:
        kill_shiro_result = "已关闭shiro漏洞扫描程序"
    else:
        kill_shiro_result = "正在关闭中......"
    return kill_shiro_result

def stopspringboot_lib():
    springbootstatus = os.popen('bash /TIP/info_scan/finger.sh springboot_scan_status').read()
    os.popen('bash /TIP/info_scan/finger.sh killspringbootvulnscanprocess')
    if "stop" in springbootstatus:
        kill_springboot_result = "已关闭springboot漏洞扫描程序"
    else:
        kill_springboot_result = "正在关闭中......"
    return kill_springboot_result


def stoptpscan_lib():
    tpscanstatus = os.popen('bash /TIP/info_scan/finger.sh TPscan_status').read()
    os.popen('bash /TIP/info_scan/finger.sh killthinkphpprocess')
    if "stop" in tpscanstatus:
        kill_thinkphp_result = "已关闭thinkphp漏洞扫描程序"
    else:
        kill_thinkphp_result = "正在关闭中......"
    return kill_thinkphp_result


def stopafrog_lib():
    afrogscanstatus = os.popen('bash /TIP/info_scan/finger.sh afrogscan_status').read()
    os.popen('bash /TIP/info_scan/finger.sh killafrog')
    if "stop" in afrogscanstatus:
        kill_afrog_result = "已关闭afrog扫描程序"
    else:
        kill_afrog_result = "正在关闭中......"

    return kill_afrog_result


def stopfscan_lib():
    fscanstatus = os.popen('bash /TIP/info_scan/finger.sh fscan_status').read()
    os.popen('bash /TIP/info_scan/finger.sh killfscan')
    if "stop" in fscanstatus:
        kill_fscan_result = "已关闭fscan扫描程序"
    else:
        kill_fscan_result = "正在关闭中......"

    return kill_fscan_result


def stophydra_lib():
    os.popen('bash /TIP/info_scan/finger.sh killhydra')
    hydra_scan_status = os.popen('bash /TIP/info_scan/finger.sh hydra_status').read()
    if "stop" in hydra_scan_status:
        kill_hydra_result = "已关闭弱口令扫描程序"
    else:
        kill_hydra_result = "正在关闭中......"

    return kill_hydra_result


def stopurlfinder_lib():
    os.popen('bash /TIP/info_scan/finger.sh killurlfinder')
    urlfinderstatus = os.popen('bash /TIP/info_scan/finger.sh urlfinder_status').read()
    if "stop" in urlfinderstatus:
        kill_urlfinder_result = "已关闭api接口扫描程序"
    else:
        kill_urlfinder_result = "正在关闭中......"
    return kill_urlfinder_result


def stopvulmap_lib():
    vulmapscanstatus = os.popen('bash /TIP/info_scan/finger.sh vulmapscan_status').read()
    os.popen('bash /TIP/info_scan/finger.sh killvulmap')
    if "stop" in vulmapscanstatus:
        kill_vulmap_result = "已关闭vulmap扫描程序"
    else:
        kill_vulmap_result = "正在关闭中......"
    return kill_vulmap_result



def stopnuclei_lib():
    nucleistatus =os.popen('bash /TIP/info_scan/finger.sh nucleistatus').read()
    os.popen('bash /TIP/info_scan/finger.sh killnuclei')
    if "stop" in nucleistatus:
        kill_nuclei_result = "已关闭nuclei扫描程序"
    else:
        kill_nuclei_result = "正在关闭中......"
    return kill_nuclei_result



def stopweaver_lib():
    weaver_status = os.popen('bash /TIP/info_scan/finger.sh weaver_status').read()
    os.popen('bash /TIP/info_scan/finger.sh kill_weaver_scan')
    if "stop" in weaver_status:
        kill_weaver_result = "已关闭历史URL查询接口"
    else:
        kill_weaver_result = "正在关闭中......"
    return kill_weaver_result

def stopesscan_lib():
    es_status = os.popen('bash /TIP/info_scan/finger.sh es_unauthorized_status').read()
    os.popen('bash /TIP/info_scan/finger.sh stopes_unauthorized')
    if "stop" in es_status:
        kill_es_result = "已关闭ES未授权扫描程序"
    else:
        kill_es_result = "正在关闭中......"
    return kill_es_result


def stopnacosscan_lib():
    nacos_status = os.popen('bash /TIP/info_scan/finger.sh nacos_vuln_scan_status').read()
    os.popen('bash /TIP/info_scan/finger.sh stop_nacos_scan')
    if "stop" in nacos_status:
        kill_nacos_result = "已关闭nacos漏洞扫描程序"
    else:
        kill_nacos_result = "正在关闭中......"
    return kill_nacos_result

def stoptomcatscan_lib():
    tomcat_status = os.popen('bash /TIP/info_scan/finger.sh tomcat_vuln_scan_status').read()
    os.popen('bash /TIP/info_scan/finger.sh stop_tomcat_scan')
    if "stop" in tomcat_status:
        kill_tomcat_result = "已关闭tomcat漏洞扫描程序"
    else:
        kill_tomcat_result = "正在关闭中......"
    return kill_tomcat_result

def stopfastjson_lib():
    fastjson_status = os.popen('bash /TIP/info_scan/finger.sh fastjson_scan_status').read()
    os.popen('bash /TIP/info_scan/finger.sh stop_fastjson_scan')
    if "stop" in fastjson_status:
        kill_fastjson_result = "已关闭fastjson漏洞扫描程序"
    else:
        kill_fastjson_result = "正在关闭中......"
    return kill_fastjson_result



# 关闭信息收集工具
def stopotx_lib():
    otx_domain_url_shell_status = os.popen('bash /TIP/info_scan/finger.sh otx_domain_url_shell_status').read()
    os.popen('bash /TIP/info_scan/finger.sh kill_otx_domain_url_shell')
    if "stop" in otx_domain_url_shell_status:
        kill_otx_url_result = "已关闭历史URL查询接口"
    else:
        kill_otx_url_result = "正在关闭中......"
    return kill_otx_url_result

def stopbbscan_lib():
    bbscanstatus = os.popen('bash /TIP/info_scan/finger.sh bbscan_status').read()
    os.popen('bash /TIP/info_scan/finger.sh killbbscan')
    if "stop" in bbscanstatus:
        kill_bbscan_result = "已关闭bbscan扫描程序"
    else:
        kill_bbscan_result = "正在关闭中......"
    return kill_bbscan_result

def stopehole_lib():
    os.popen('bash /TIP/info_scan/finger.sh killEHole')
    EHolestatus = os.popen('bash /TIP/info_scan/finger.sh ehole_status').read()
    if "stop" in EHolestatus:
        kill_EHole_result = "已关闭指纹识别程序"
    else:
        kill_EHole_result = "正在关闭中......"
    return kill_EHole_result

def stopcrtsubdomain_lib():
    crt_subdomain_shell_status = os.popen('bash /TIP/info_scan/finger.sh crt_subdomain_shell_status').read()
    os.popen('bash /TIP/info_scan/finger.sh kill_crt_subdomain_shell')
    if "stop" in crt_subdomain_shell_status:
        kill_crt_subdomain_result = "已关闭历史URL查询接口"
    else:
        kill_crt_subdomain_result = "正在关闭中......"
    return kill_crt_subdomain_result

def stopnmap_lib():
    nmapstatus =os.popen('bash /TIP/info_scan/finger.sh nmapstatus').read()
    os.popen('bash /TIP/info_scan/finger.sh killnmap')
    if "stop" in nmapstatus:
        kill_nmap_result = "已关闭nmap扫描程序"
    else:
        kill_nmap_result = "正在关闭中......"
    return kill_nmap_result






# 开启漏洞扫描程序
def startstruts2_lib():
    struts2status = os.popen('bash /TIP/info_scan/finger.sh struts2_status').read()
    if "running" in struts2status:
        struts2status_result = "struts2扫描程序正在运行中请勿重复提交"
    else:
        # 执行poc扫描
        os.popen('bash /TIP/info_scan/finger.sh struts2_poc_scan')
        struts2status_result = "struts2扫描程序已开启稍后查看结果"
    return struts2status_result


def startweblogic_lib():
    weblogic_status = os.popen('bash /TIP/info_scan/finger.sh weblogic_status').read()
    if "running" in weblogic_status:
        weblogic_status_result = "weblogic扫描程序正在运行中请勿重复提交"
    else:
        # 遍历目标文件存入列表
        url_list = []
        url_file = open('/TIP/batch_scan_domain/url.txt',encoding='utf-8')
        for i in url_file.readlines():
            url_list.append(i.strip())
        
        # url中匹配出域名
        domain_list = []
        for url in url_list:
            pattern = r"https?://([^/]+)"
            urls_re_1 = re.search(pattern,url)
            urls_re = urls_re_1.group(1)
            domain_list.append(urls_re)
        
        # 域名写入到weblogic_poc目标
        weblogic_file = open(file='/TIP/info_scan/weblogin_scan/target.txt', mode='w')
        for j in domain_list:
            weblogic_file.write(str(j)+"\n")
        weblogic_file.close()

        # weblogic_poc开始扫描
        os.popen('bash /TIP/info_scan/finger.sh weblogic_poc_scan')
        if "running" in weblogic_status:
            weblogic_status_result = "weblogic扫描程序已开启稍后查看结果"
        else:
            weblogic_status_result = "weblogic扫描程序正在后台启动中......"

    return weblogic_status_result


def startshiro_lib():
    shiro_status = os.popen('bash /TIP/info_scan/finger.sh shiro_status').read()
    if "running" in shiro_status:
        shiro_status_result = "shiro扫描程序正在运行中请勿重复提交"
    else:
        try:
            shiro_scan()
            shiro_status_result = "shiro扫描程序已开启稍后查看结果"
        except Exception as e:
            print("捕获到异常:", e)
    return shiro_status_result


def startspringboot_lib():
    springboot_scan_status = os.popen('bash /TIP/info_scan/finger.sh springboot_scan_status').read()
    if "running" in springboot_scan_status:
        springboot_scan_status_result = "springboot扫描程序正在运行中请勿重复提交"
    else:
        try:
            os.popen('bash /TIP/info_scan/finger.sh start_springboot')
            if "running" in springboot_scan_status:
                springboot_scan_status_result = "springboot扫描程序已开启稍后查看结果"
            else:
                springboot_scan_status_result = "springboot扫描程序正在后台启动中......"
        except Exception as e:
            print("捕获到异常:", e)
    return springboot_scan_status_result



def startthinkphp_lib():
    tpscan_status = os.popen('bash /TIP/info_scan/finger.sh TPscan_status').read()
    if "running" in tpscan_status:
        thinkphp_status_result = "thinkphp扫描程序正在运行中请勿重复提交"
    else:
        try:
            thinkphp_scan()
            if "running" in tpscan_status:
                thinkphp_status_result = "thinkphp扫描程序已开启稍后查看结果"
            else:
                thinkphp_status_result = "thinkphp扫描程序正在后台启动中......"

        except Exception as e:
            print("捕获到异常:", e)
    return thinkphp_status_result


def startafrog_lib():
    afrogscanstatus = os.popen('bash /TIP/info_scan/finger.sh afrogscan_status').read()
    if "running" in afrogscanstatus:
        start_afrog_result = "afrog正在运行中请勿重复提交"
    else:
        try:
            os.popen('bash /TIP/info_scan/finger.sh startafrogprocess')
            if "running" in afrogscanstatus:
                start_afrog_result = "afrog已开启稍后查看结果"
            else:
                start_afrog_result = "afrog正在后台启动中......"
        except Exception as e:
            print("捕获到异常:", e)
    return start_afrog_result



def startfscan_lib(fscanpartname,part1):
    # 删除历史fscan扫描数据
    os.popen('rm -rf /TIP/info_scan/fscan_tool/result.txt')

    fscanstatus = os.popen('bash /TIP/info_scan/finger.sh fscan_status').read()
    if "running" in fscanstatus:
        fscan_status_result = "fscan扫描程序正在运行中请勿重复提交"
    else:
        try:
            batch_fscan_interface(fscanpartname,part1)
            
            if "running" in fscanstatus:
                fscan_status_result = "fscan扫描程序已启动稍后查看扫描结果"
            else:
                fscan_status_result = "fscan正在后台启动中......"
        except Exception as e:
            print("捕获到异常:", e)

    return fscan_status_result


def starthydra_lib(hydrapart):
    # 调用url转ip函数写入文件
    ip_list = url_convert_ip()
    f = open(file='/TIP/info_scan/result/hydra_ip.txt',mode='w')
    for line in ip_list:
        f.write(str(line)+"\n")
    # 开启扫描
    hydra_scan_status = os.popen('bash /TIP/info_scan/finger.sh hydra_status').read()
    if "running" in hydra_scan_status:
        hydra_scan_result = "弱口令扫描程序正在运行中请勿重复提交"
    else:
        start_hydra_lib(hydrapart)
        hydra_scan_result = "弱口令扫描程序已开启稍后查看扫描结果"
    return hydra_scan_result



def starturlfinder_lib():
    urlfinder_status = os.popen('bash /TIP/info_scan/finger.sh urlfinder_status').read()
    if "running" in urlfinder_status:
        urlfinder_status_result = "api接口扫描程序正在运行中请勿重复提交"
    else:
        try:
            os.popen('bash /TIP/info_scan/finger.sh urlfinder_start')
            urlfinder_status = os.popen('bash /TIP/info_scan/finger.sh urlfinder_status').read()
            if "running" in urlfinder_status:
                urlfinder_status_result = "api接口扫描程序已开启稍后查看结果"
            else:
                urlfinder_status_result = "api接口扫描程序正在后台启动中......"
        except Exception as e:
            print("捕获到异常:", e)
    return urlfinder_status_result



def startvulmap_lib(vulnname):
    vulmapscanstatus = os.popen('bash /TIP/info_scan/finger.sh vulmapscan_status').read()
    if "running" in vulmapscanstatus:
        vummap_scan_result = "vulmap扫描程序正在运行中请勿重复提交"
    else:
        try:
            os.popen('bash /TIP/info_scan/finger.sh vulmapscan_shell'+' '+vulnname)
            if "running" in vulmapscanstatus:
                vummap_scan_result = "vulmap扫描程序已启动稍后查看扫描结果"
            else:
                vummap_scan_result = "vulmap正在后台启动中......"
        except Exception as e:
            print("捕获到异常:", e)
    return vummap_scan_result



def startnuclei_lib(poc_dir):
    nucleitatus = os.popen('bash /TIP/info_scan/finger.sh nucleistatus').read()
    if "running" in nucleitatus:
        nuclei_status_result = "nuclei扫描程序正在运行中请勿重复提交"
    else:
        if int(history_switch) == 0:
            os.popen('bash /TIP/info_scan/finger.sh startnuclei_url'+' '+poc_dir)
            nuclei_status_result = "nuclei扫描程序已开启稍后查看结果"
        elif int(history_switch) ==1:
            os.popen('bash /TIP/info_scan/finger.sh startnuclei_result')
        else:
            print("配置文件history_switch字段只允许0/1")
    return nuclei_status_result



def startweaver_lib():
    weaver_status = os.popen('bash /TIP/info_scan/finger.sh weaver_status').read()
    if "running" in weaver_status:
        weaver_status_result = "泛微OA漏洞扫描程序正在运行中请勿重复提交"
    else:
        try:
            os.popen('bash /TIP/info_scan/finger.sh weaver_exp_scan')
            weaver_status = os.popen('bash /TIP/info_scan/finger.sh weaver_status').read()
            if "running" in weaver_status:
                weaver_status_result = "泛微OA漏洞扫描程序已开启稍后查看结果"
            else:
                weaver_status_result = "泛微OA漏洞扫描程序正在后台启动中......"
        except Exception as e:
            print("捕获到异常:", e)
    return weaver_status_result


# 开启jndi服务
def startjndi_lib():
    jndi_status = os.popen('bash /TIP/info_scan/finger.sh jndi_server_status').read()
    jndi_python_status = os.popen('bash /TIP/info_scan/finger.sh jndi_python_server_status').read()
    if "running" in jndi_status and "running" in jndi_python_status:
        jndi_status_result = "JNDI服务正在运行中请勿重复提交"
    else:
        try:

            os.popen('bash /TIP/info_scan/finger.sh start_jndi > /TIP/info_scan/result/jndi_result.txt')
            
            os.popen('bash /TIP/info_scan/finger.sh start_jndi_python')

            if "running" in jndi_status and "running" in jndi_python_status:
                jndi_status_result = "JNDI服务已开启稍后查看结果"
            else:
                jndi_status_result = "JNDI服务正在后台启动中......"
        except Exception as e:
            print("捕获到异常:", e)
    return jndi_status_result


# 开启信息收集扫描程序
def startbbscan_lib():
    bbscan_status1 = os.popen('bash /TIP/info_scan/finger.sh bbscan_status').read()

    if "running" in bbscan_status1:
        bbscan_status_result = "敏感信息扫描程序正在运行中请勿重复提交"
    else:
        os.popen('rm -rf /TIP/info_scan/BBScan/report/*')
        # 执行敏感信息扫描
        os.popen('bash /TIP/info_scan/finger.sh bbscan_shell')
        if "running" in bbscan_status1:
            bbscan_status_result = "信息泄露扫描程序已启动稍后查看扫描结果"
        else:
            bbscan_status_result = "信息泄露扫描程序正在后台启动中......"
    return bbscan_status_result


# 指纹识别
def startechole_lib():
    finger_status = os.popen('bash /TIP/info_scan/finger.sh ehole_status').read()
    if "running" in finger_status:
        finger_status_result = "EHole程序正在运行中请勿重复提交"
    else:
        # 根据代理服务判断
        proxystatus = os.popen('bash /TIP/info_scan/finger.sh systemproxystatus').read().strip()
        if "已开启" == proxystatus:
            # 开启代理指纹识别
            os.popen('bash /TIP/info_scan/finger.sh ehole_finger_scan_proxy')
            if "running" in finger_status:
                finger_status_result = "指纹识别程序已启动稍后查看扫描结果(已开启代理)"
            else:
                finger_status_result = "指纹识别程序正在后台启动中(已开启代理)......"
        else:
            # 未开启代理指纹识别
            os.popen('bash /TIP/info_scan/finger.sh ehole_finger_scan')
            if "running" in finger_status:
                finger_status_result = "指纹识别程序已启动稍后查看扫描结果(未开启代理)"
            else:
                finger_status_result = "指纹识别程序正在后台启动中(未开启代理)......"
    return finger_status_result



def otxhistorydomain_lib():
    # 每次启动前清空上次扫描结果
    os.popen('rm -rf /TIP/info_scan/result/otxhistoryurl.txt')
    os.popen('touch /TIP/info_scan/result/otxhistoryurl.txt')
    otx_domain_url_shell_status = os.popen('bash /TIP/info_scan/finger.sh otx_domain_url_shell_status').read()
    if "running" in otx_domain_url_shell_status:
        otx_status_result = "历史URL查询接口正在运行中请勿重复提交"
    else:
        try:
            os.popen('bash /TIP/info_scan/finger.sh otx_domain_url_shell')
            if "running" in otx_domain_url_shell_status:
                otx_status_result = "历史URL查询接口已开启稍后查看结果"
            else:
                otx_status_result = "历史URL查询接口正在后台启动中......"
        except Exception as e:
            print("捕获到异常:", e)
    return otx_status_result


def crtdomain_lib():
    # 每次启动前清空上次扫描结果
    os.popen('rm -rf /TIP/info_scan/result/subdomain.txt')
    os.popen('touch /TIP/info_scan/result/subdomain.txt')
    crt_subdomain_shell_status = os.popen('bash /TIP/info_scan/finger.sh crt_subdomain_shell_status').read()
    if "running" in crt_subdomain_shell_status:
        crt_status_result = "基于证书查询子域名接口正在运行中请勿重复提交"
    else:
        try:
            os.popen('bash /TIP/info_scan/finger.sh crt_subdomain_shell')
            
            if "running" in crt_subdomain_shell_status:
                crt_status_result = "基于证书查询子域名接口已开启稍后查看结果"
            else:
                crt_status_result = "基于证书查询子域名接口正在后台启动中......"
        except Exception as e:
            print("捕获到异常:", e)
    return crt_status_result



def startnmap_lib(portscan_part):
    namptatus = os.popen('bash /TIP/info_scan/finger.sh nmapstatus').read()
    if "running" in namptatus:
        nmap_status_result = "端口扫描程序正在运行中请勿重复提交"
    
    else:
        # 创建一个新的线程启动端口扫描程序
        def run_portscan_process():
            print("已开启一个新的线程用于端口扫描")
            try:
                ip_queue_nmap(portscan_part)
            except Exception as e:
                print("捕获到异常:", e)
        threading.Thread(target=run_portscan_process).start()
        if "running" in namptatus:
            nmap_status_result = "端口扫描程序已开启稍后查看结果"
        else:
            nmap_status_result = "端口扫描程序正在后台启动中......"
    
    return nmap_status_result



# 开启存活检测
def httpsurvival_lib():
    httpx_status = os.popen('bash /TIP/info_scan/finger.sh httpx_status').read()
    if "running" in httpx_status:
        httpx_status_result = "httpx存活检测程序正在运行中请勿重复提交"
    else:
        try:
            os.popen('bash /TIP/info_scan/finger.sh survivaldetection')
            if "running" in httpx_status:
                httpx_status_result = "httpx存活检测程序已开启稍后查看结果"
            else:
                httpx_status_result = "httpx存活检测程序正在后台启动中......"
        except Exception as e:
            print("捕获到异常:", e)
    return httpx_status_result

# 关闭存活检测
def stop_httpsurvival_lib():
    httpx_status = os.popen('bash /TIP/info_scan/finger.sh httpx_status').read()
    os.popen('bash /TIP/info_scan/finger.sh kill_httpx_process')
    if "stop" in httpx_status:
        kill_httpx_result = "已关闭httpx存活检测程序"
    else:
        kill_httpx_result = "正在关闭中......"
    return kill_httpx_result


# 关闭资产扩展
def stop_assets_extend_lib():
    httpx_status = os.popen('bash /TIP/info_scan/finger.sh httpx_status').read()
    subfinder_status = os.popen('bash /TIP/info_scan/finger.sh subfinder_status').read()
    os.popen('bash /TIP/info_scan/finger.sh kill_httpx_process')
    os.popen('bash /TIP/info_scan/finger.sh kill_subfinder_process')
    if "stop" in httpx_status and "stop" in subfinder_status:
        kill_assetextend_result = "已关闭资产扩展程序"
    else:
        kill_assetextend_result = "正在关闭中......"
    return kill_assetextend_result



# 启动es未授权漏洞扫描
def startunes_lib():
    es_status = os.popen('bash /TIP/info_scan/finger.sh es_unauthorized_status').read()
    if "running" in es_status:
        es_status_result = "ES未授权检测程序正在运行中请勿重复提交"
    else:
        try:
            os.popen('bash /TIP/info_scan/finger.sh start_es_shell')
            if "running" in es_status:
                es_status_result = "ES未授权检测程序已开启稍后查看结果"
            else:
                es_status_result = "ES未授权检测程序正在后台启动中......"
        except Exception as e:
            print("捕获到异常:", e)
    return es_status_result


# 开启nacos漏洞扫描
def startnacosscan_lib():
    nacos_status = os.popen('bash /TIP/info_scan/finger.sh nacos_vuln_scan_status').read()
    if "running" in nacos_status:
        nacos_status_result = "nacos漏洞扫描程序正在运行中请勿重复提交"
    else:
        try:
            os.popen('bash /TIP/info_scan/finger.sh start_nacos_scan_shell')
            if "running" in nacos_status:
                nacos_status_result = "nacos漏洞扫描程序已开启稍后查看结果"
            else:
                nacos_status_result = "nacos漏洞扫描程序正在后台启动中......"
        except Exception as e:
            print("捕获到异常:", e)
    return nacos_status_result

# 开启tomcat漏洞扫描
def starttomcatscan_lib():
    tomcat_status = os.popen('bash /TIP/info_scan/finger.sh tomcat_vuln_scan_status').read()
    if "running" in tomcat_status:
        tomcat_status_result = "tomcat漏洞扫描程序正在运行中请勿重复提交"
    else:
        try:
            os.popen('bash /TIP/info_scan/finger.sh start_tomcat_scan_shell')
            if "running" in tomcat_status:
                tomcat_status_result = "tomcat漏洞扫描程序已开启稍后查看结果"
            else:
                tomcat_status_result = "tomcat漏洞扫描程序正在后台启动中......"
        except Exception as e:
            print("捕获到异常:", e)
    return tomcat_status_result

# 开启致远OA漏洞扫描
def startseeyonscan_lib():
    seeyon_status = os.popen('bash /TIP/info_scan/finger.sh seeyon_vuln_scan_status').read()
    if "running" in seeyon_status:
        seeyon_status_result = "致远OA漏洞扫描程序正在运行中请勿重复提交"
    else:
        try:
            os.popen('bash /TIP/info_scan/finger.sh start_seeyon_scan_shell')
            if "running" in seeyon_status:
                seeyon_status_result = "致远OA漏洞扫描程序已开启稍后查看结果"
            else:
                seeyon_status_result = "致远OA漏洞扫描程序正在后台启动中......"
        except Exception as e:
            print("捕获到异常:", e)
    return seeyon_status_result


# 关闭致远OA漏洞扫描程序
def stopseeyonvuln_lib():
    seeyon_status = os.popen('bash /TIP/info_scan/finger.sh seeyon_vuln_scan_status').read()
    os.popen('bash /TIP/info_scan/finger.sh stop_seeyon_scan')
    if "stop" in seeyon_status:
        kill_seeyon_result = "已关闭致远OA漏洞扫描程序"
    else:
        kill_seeyon_result = "正在关闭中......"
    return kill_seeyon_result



# 开启用友OA漏洞扫描
def startyonsuitescan_lib():
    yonsuite_status = os.popen('bash /TIP/info_scan/finger.sh yonsuite_vuln_scan_status').read()
    if "running" in yonsuite_status:
        yonsuite_status_result = "用友OA漏洞扫描程序正在运行中请勿重复提交"
    else:
        try:
            os.popen('bash /TIP/info_scan/finger.sh start_yonsuite_scan_shell')
            if "running" in yonsuite_status:
                yonsuite_status_result = "用友OA漏洞扫描程序已开启稍后查看结果"
            else:
                yonsuite_status_result = "用友OA漏洞扫描程序正在后台启动中......"
        except Exception as e:
            print("捕获到异常:", e)
    return yonsuite_status_result


# 关闭用友OA漏洞扫描程序
def stopyonsuitevuln_lib():
    yonsuite_status = os.popen('bash /TIP/info_scan/finger.sh yonsuite_vuln_scan_status').read()
    os.popen('bash /TIP/info_scan/finger.sh stop_yonsuite_scan')
    if "stop" in yonsuite_status:
        kill_yonsuite_result = "已关闭用友OA漏洞扫描程序"
    else:
        kill_yonsuite_result = "正在关闭中......"
    return kill_yonsuite_result


# 开启金蝶OA漏洞扫描
def startkingdeescan_lib():
    kingdee_status = os.popen('bash /TIP/info_scan/finger.sh kingdee_vuln_scan_status').read()
    if "running" in kingdee_status:
        kingdee_status_result = "金蝶OA漏洞扫描程序正在运行中请勿重复提交"
    else:
        try:
            os.popen('bash /TIP/info_scan/finger.sh start_kingdee_scan_shell')
            if "running" in kingdee_status:
                kingdee_status_result = "金蝶OA漏洞扫描程序已开启稍后查看结果"
            else:
                kingdee_status_result = "金蝶OA漏洞扫描程序正在后台启动中......"
        except Exception as e:
            print("捕获到异常:", e)
    return kingdee_status_result



# 关闭金蝶OA漏洞扫描程序
def stopkingdeevuln_lib():
    kingdee_status = os.popen('bash /TIP/info_scan/finger.sh kingdee_vuln_scan_status').read()
    os.popen('bash /TIP/info_scan/finger.sh stop_kingdee_scan')
    if "stop" in kingdee_status:
        kill_kingdee_result = "已关闭金蝶OA漏洞扫描程序"
    else:
        kill_kingdee_result = "正在关闭中......"
    return kill_kingdee_result



# 开启万户OA漏洞扫描
def startwanhuscan_lib():
    wanhu_status = os.popen('bash /TIP/info_scan/finger.sh wanhu_vuln_scan_status').read()
    if "running" in wanhu_status:
        wanhu_status_result = "万户OA漏洞扫描程序正在运行中请勿重复提交"
    else:
        try:
            os.popen('bash /TIP/info_scan/finger.sh start_wanhu_scan_shell')
            if "running" in wanhu_status:
                wanhu_status_result = "万户OA漏洞扫描程序已开启稍后查看结果"
            else:
                wanhu_status_result = "万户OA漏洞扫描程序正在后台启动中......"
        except Exception as e:
            print("捕获到异常:", e)
    return wanhu_status_result



# 关闭万户OA漏洞扫描程序
def stopwanhuvuln_lib():
    wanhu_status = os.popen('bash /TIP/info_scan/finger.sh wanhu_vuln_scan_status').read()
    os.popen('bash /TIP/info_scan/finger.sh stop_wanhu_scan')
    if "stop" in wanhu_status:
        kill_wanhu_result = "已关闭万户OA漏洞扫描程序"
    else:
        kill_wanhu_result = "正在关闭中......"
    return kill_wanhu_result


# 开启redis未授权漏洞扫描
def startunredisscan_lib():
    redis_status = os.popen('bash /TIP/info_scan/finger.sh redis_vuln_scan_status').read()
    if "running" in redis_status:
        redis_status_result = "redis未授权漏洞扫描程序正在运行中请勿重复提交"
    else:
        try:
            os.popen('bash /TIP/info_scan/finger.sh start_redis_scan_shell')
            if "running" in redis_status:
                redis_status_result = "redis未授权漏洞扫描程序已开启稍后查看结果"
            else:
                redis_status_result = "redis未授权漏洞扫描程序正在后台启动中......"
        except Exception as e:
            print("捕获到异常:", e)
    return redis_status_result


# 关闭redis漏洞扫描程序
def stopunredisvuln_lib():
    redis_status = os.popen('bash /TIP/info_scan/finger.sh redis_vuln_scan_status').read()
    os.popen('bash /TIP/info_scan/finger.sh stop_redis_scan')
    if "stop" in redis_status:
        kill_unredis_result = "已关闭redis未授权漏洞扫描程序"
    else:
        kill_unredis_result = "正在关闭中......"
    return kill_unredis_result


# 开启mongodb未授权漏洞扫描
def startunrmongodbscan_lib():
    mongodb_status = os.popen('bash /TIP/info_scan/finger.sh mongodb_vuln_scan_status').read()
    if "running" in mongodb_status:
        mongodb_status_result = "mongodb未授权漏洞扫描程序正在运行中请勿重复提交"
    else:
        try:
            os.popen('bash /TIP/info_scan/finger.sh start_mongodb_scan_shell')
            if "running" in mongodb_status:
                mongodb_status_result = "mongodb未授权漏洞扫描程序已开启稍后查看结果"
            else:
                mongodb_status_result = "mongodb未授权漏洞扫描程序正在后台启动中......"
        except Exception as e:
            print("捕获到异常:", e)
    return mongodb_status_result


# 关闭mongodb漏洞扫描程序
def stopunmongodbvuln_lib():
    mongodb_status = os.popen('bash /TIP/info_scan/finger.sh mongodb_vuln_scan_status').read()
    os.popen('bash /TIP/info_scan/finger.sh stop_mongodb_scan')
    if "stop" in mongodb_status:
        kill_unmongodb_result = "已关闭mongodb未授权漏洞扫描程序"
    else:
        kill_unmongodb_result = "正在关闭中......"
    return kill_unmongodb_result



# 开启memcached未授权漏洞扫描
def startunmemcachedscan_lib():
    memcached_status = os.popen('bash /TIP/info_scan/finger.sh memcached_vuln_scan_status').read()
    if "running" in memcached_status:
        memcached_status_result = "memcached未授权漏洞扫描程序正在运行中请勿重复提交"
    else:
        try:
            os.popen('bash /TIP/info_scan/finger.sh start_memcached_scan_shell')
            if "running" in memcached_status:
                memcached_status_result = "memcached未授权漏洞扫描程序已开启稍后查看结果"
            else:
                memcached_status_result = "memcached未授权漏洞扫描程序正在后台启动中......"
        except Exception as e:
            print("捕获到异常:", e)
    return memcached_status_result



# 关闭memcached漏洞扫描程序
def stopunmemcachedvuln_lib():
    memcached_status = os.popen('bash /TIP/info_scan/finger.sh memcached_vuln_scan_status').read()
    os.popen('bash /TIP/info_scan/finger.sh stop_memcached_scan')
    if "stop" in memcached_status:
        kill_unmemcached_result = "已关闭memcached未授权漏洞扫描程序"
    else:
        kill_unmemcached_result = "正在关闭中......"
    return kill_unmemcached_result


# 开启zookeeper未授权漏洞扫描
def startunzookeeperscan_lib():
    zookeeper_status = os.popen('bash /TIP/info_scan/finger.sh zookeeper_vuln_scan_status').read()
    if "running" in zookeeper_status:
        zookeeper_status_result = "zookeeper未授权漏洞扫描程序正在运行中请勿重复提交"
    else:
        try:
            os.popen('bash /TIP/info_scan/finger.sh start_zookeeper_scan_shell')
            if "running" in zookeeper_status:
                zookeeper_status_result = "zookeeper未授权漏洞扫描程序已开启稍后查看结果"
            else:
                zookeeper_status_result = "zookeeper未授权漏洞扫描程序正在后台启动中......"
        except Exception as e:
            print("捕获到异常:", e)
    return zookeeper_status_result


# 关闭zookeeper漏洞扫描程序
def stopunzookeepervuln_lib():
    zookeeper_status = os.popen('bash /TIP/info_scan/finger.sh zookeeper_vuln_scan_status').read()
    os.popen('bash /TIP/info_scan/finger.sh stop_zookeeper_scan')
    if "stop" in zookeeper_status:
        kill_zookeeper_result = "已关闭zookeeper未授权漏洞扫描程序"
    else:
        kill_zookeeper_result = "正在关闭中......"
    return kill_zookeeper_result


# 开启ftp未授权漏洞扫描
def startunftpscan_lib():
    ftp_status = os.popen('bash /TIP/info_scan/finger.sh ftp_vuln_scan_status').read()
    if "running" in ftp_status:
        ftp_status_result = "ftp未授权漏洞扫描程序正在运行中请勿重复提交"
    else:
        try:
            os.popen('bash /TIP/info_scan/finger.sh start_ftp_scan_shell')
            if "running" in ftp_status:
                ftp_status_result = "ftp未授权漏洞扫描程序已开启稍后查看结果"
            else:
                ftp_status_result = "ftp未授权漏洞扫描程序正在后台启动中......"
        except Exception as e:
            print("捕获到异常:", e)
    return ftp_status_result


# 关闭ftp漏洞扫描程序
def stopunftpvuln_lib():
    ftp_status = os.popen('bash /TIP/info_scan/finger.sh ftp_vuln_scan_status').read()
    os.popen('bash /TIP/info_scan/finger.sh stop_ftp_scan')
    if "stop" in ftp_status:
        kill_ftp_result = "已关闭ftp未授权漏洞扫描程序"
    else:
        kill_ftp_result = "正在关闭中......"
    return kill_ftp_result



# 开启couchdb未授权漏洞扫描
def startuncouchdbscan_lib():
    couchdb_status = os.popen('bash /TIP/info_scan/finger.sh couchdb_vuln_scan_status').read()
    if "running" in couchdb_status:
        couchdb_status_result = "couchdb未授权漏洞扫描程序正在运行中请勿重复提交"
    else:
        try:
            os.popen('bash /TIP/info_scan/finger.sh start_couchdb_scan_shell')
            if "running" in couchdb_status:
                couchdb_status_result = "couchdb未授权漏洞扫描程序已开启稍后查看结果"
            else:
                couchdb_status_result = "couchdb未授权漏洞扫描程序正在后台启动中......"
        except Exception as e:
            print("捕获到异常:", e)
    return couchdb_status_result


# 关闭couchdb漏洞扫描程序
def stopuncouchdbvuln_lib():
    couchdb_status = os.popen('bash /TIP/info_scan/finger.sh couchdb_vuln_scan_status').read()
    os.popen('bash /TIP/info_scan/finger.sh stop_couchdb_scan')
    if "stop" in couchdb_status:
        kill_couchdb_result = "已关闭couchdb未授权漏洞扫描程序"
    else:
        kill_couchdb_result = "正在关闭中......"
    return kill_couchdb_result



# 开启docker未授权漏洞扫描
def startundockerscan_lib():
    docker_status = os.popen('bash /TIP/info_scan/finger.sh docker_vuln_scan_status').read()
    if "running" in docker_status:
        docker_status_result = "docker未授权漏洞扫描程序正在运行中请勿重复提交"
    else:
        try:
            os.popen('bash /TIP/info_scan/finger.sh start_docker_scan_shell')
            if "running" in docker_status:
                docker_status_result = "docker未授权漏洞扫描程序已开启稍后查看结果"
            else:
                docker_status_result = "docker未授权漏洞扫描程序正在后台启动中......"
        except Exception as e:
            print("捕获到异常:", e)
    return docker_status_result


# 关闭docker漏洞扫描程序
def stopundockervuln_lib():
    docker_status = os.popen('bash /TIP/info_scan/finger.sh docker_vuln_scan_status').read()
    os.popen('bash /TIP/info_scan/finger.sh stop_docker_scan')
    if "stop" in docker_status:
        kill_docker_result = "已关闭docker未授权漏洞扫描程序"
    else:
        kill_docker_result = "正在关闭中......"
    return kill_docker_result


# 开启hadoop未授权漏洞扫描
def startunhadoopscan_lib():
    hadoop_status = os.popen('bash /TIP/info_scan/finger.sh hadoop_vuln_scan_status').read()
    if "running" in hadoop_status:
        hadoop_status_result = "hadoop未授权漏洞扫描程序正在运行中请勿重复提交"
    else:
        try:
            os.popen('bash /TIP/info_scan/finger.sh start_hadoop_scan_shell')
            if "running" in hadoop_status:
                hadoop_status_result = "hadoop未授权漏洞扫描程序已开启稍后查看结果"
            else:
                hadoop_status_result = "hadoop未授权漏洞扫描程序正在后台启动中......"
        except Exception as e:
            print("捕获到异常:", e)
    return hadoop_status_result


# 关闭hadoop漏洞扫描程序
def stopunhadoopvuln_lib():
    hadoop_status = os.popen('bash /TIP/info_scan/finger.sh hadoop_vuln_scan_status').read()
    os.popen('bash /TIP/info_scan/finger.sh stop_hadoop_scan')
    if "stop" in hadoop_status:
        kill_hadoop_result = "已关闭hadoop未授权漏洞扫描程序"
    else:
        kill_hadoop_result = "正在关闭中......"
    return kill_hadoop_result



# 开启nfs未授权漏洞扫描
def startunnfsscan_lib():
    nfs_status = os.popen('bash /TIP/info_scan/finger.sh nfs_vuln_scan_status').read()
    if "running" in nfs_status:
        nfs_status_result = "NFS未授权漏洞扫描程序正在运行中请勿重复提交"
    else:
        try:
            os.popen('bash /TIP/info_scan/finger.sh start_nfs_scan_shell')
            if "running" in nfs_status:
                nfs_status_result = "NFS未授权漏洞扫描程序已开启稍后查看结果"
            else:
                nfs_status_result = "NFS未授权漏洞扫描程序正在后台启动中......"
        except Exception as e:
            print("捕获到异常:", e)
    return nfs_status_result


# 关闭NFS漏洞扫描程序
def stopunnfsvuln_lib():
    nfs_status = os.popen('bash /TIP/info_scan/finger.sh nfs_vuln_scan_status').read()
    os.popen('bash /TIP/info_scan/finger.sh stop_nfs_scan')
    if "stop" in nfs_status:
        kill_nfs_result = "已关闭NFS未授权漏洞扫描程序"
    else:
        kill_nfs_result = "正在关闭中......"
    return kill_nfs_result



# 开启rsync未授权漏洞扫描
def startunrsyncscan_lib():
    rsync_status = os.popen('bash /TIP/info_scan/finger.sh rsync_vuln_scan_status').read()
    if "running" in rsync_status:
        rsync_status_result = "rsync未授权漏洞扫描程序正在运行中请勿重复提交"
    else:
        try:
            os.popen('bash /TIP/info_scan/finger.sh start_rsync_scan_shell')
            if "running" in rsync_status:
                rsync_status_result = "rsync未授权漏洞扫描程序已开启稍后查看结果"
            else:
                rsync_status_result = "rsync未授权漏洞扫描程序正在后台启动中......"
        except Exception as e:
            print("捕获到异常:", e)
    return rsync_status_result


# 关闭rsync漏洞扫描程序
def stopunrsyncvuln_lib():
    rsync_status = os.popen('bash /TIP/info_scan/finger.sh rsync_vuln_scan_status').read()
    os.popen('bash /TIP/info_scan/finger.sh stop_rsync_scan')
    if "stop" in rsync_status:
        kill_rsync_result = "已关闭rsync未授权漏洞扫描程序"
    else:
        kill_rsync_result = "正在关闭中......"
    return kill_rsync_result


# 开启Elasticsearch未授权扫描专项
def startunesscan_lib():
    es_status = os.popen('bash /TIP/info_scan/finger.sh elasticsearch_vuln_scan_status').read()
    if "running" in es_status:
        es_status_result = "Elasticsearch未授权漏洞扫描程序正在运行中请勿重复提交"
    else:
        try:
            os.popen('bash /TIP/info_scan/finger.sh start_elasticsearch_scan_shell')
            if "running" in es_status:
                es_status_result = "Elasticsearch未授权漏洞扫描程序已开启稍后查看结果"
            else:
                es_status_result = "Elasticsearch未授权漏洞扫描程序正在后台启动中......"
        except Exception as e:
            print("捕获到异常:", e)
    return es_status_result


# 关闭Elasticsearch未授权扫描专项程序
def stopunesvuln_lib():
    es_status = os.popen('bash /TIP/info_scan/finger.sh elasticsearch_vuln_scan_status').read()
    os.popen('bash /TIP/info_scan/finger.sh stop_elasticsearch_scan')
    if "stop" in es_status:
        kill_elasticsearch_result = "已关闭Elasticsearch未授权漏洞扫描程序"
    else:
        kill_elasticsearch_result = "正在关闭中......"
    return kill_elasticsearch_result

# -------------------------------------------------未授权专项扫描结尾-------------------------------------------------

# bcrypt加盐类解密
# 开启bcrypt
def startbcryptscan_lib():
    bcrypt_status = os.popen('bash /TIP/info_scan/finger.sh bcrypt_scan_status').read()
    if "running" in bcrypt_status:
        bcrypt_status_result = "bcrypt解密程序正在运行中请勿重复提交"
    else:
        try:
            os.popen('bash /TIP/info_scan/finger.sh start_bcrypt')
            if "running" in bcrypt_status:
                bcrypt_status_result = "bcrypt解密程序已开启稍后查看结果"
            else:
                bcrypt_status_result = "bcrypt解密程序程序正在后台启动中......"
        except Exception as e:
            print("捕获到异常:", e)
    return bcrypt_status_result

# 关闭bcrypt
def stopbcrypt_lib():
    bcrypt_status = os.popen('bash /TIP/info_scan/finger.sh bcrypt_scan_status').read()
    os.popen('bash /TIP/info_scan/finger.sh stop_bcrypt_scan')
    if "stop" in bcrypt_status:
        kill_bcrypt_result = "已关闭bcrypt解密程序"
    else:
        kill_bcrypt_result = "正在关闭中......"
    return kill_bcrypt_result

# 开启fastjson漏洞扫描
def startfastjson_lib():
    fastjson_scan_status = os.popen('bash /TIP/info_scan/finger.sh tomcat_vuln_scan_status').read()
    if "running" in fastjson_scan_status:
        fastjson_status_result = "fastjson漏洞扫描程序正在运行中请勿重复提交"
    else:
        try:
            # jndi服务开启允许开启fastjson扫描，否则禁止开启fastjson扫描
            jndi_status = os.popen('bash /TIP/info_scan/finger.sh jndi_server_status').read()
            jndi_python_status = os.popen('bash /TIP/info_scan/finger.sh jndi_python_server_status').read()
            if "running" in jndi_status and "running" in jndi_python_status:
                os.popen('bash /TIP/info_scan/finger.sh start_fastjson_shell')
                if "running" in fastjson_scan_status:
                    fastjson_status_result = "fastjson漏洞扫描程序已开启稍后查看结果"
                else:
                    fastjson_status_result = "fastjson漏洞扫描程序正在后台启动中......"
            else:
                fastjson_status_result = "jndi服务未开启,无法开启fastjson漏洞扫描程序"
        except Exception as e:
            print("捕获到异常:", e)
    return fastjson_status_result


# 开启WAF检测过滤掉存在WAF的资产
def startwafrecognize_lib():
    waf_scan_status = os.popen('bash /TIP/info_scan/finger.sh waf_scan_status').read()
    if "running" in waf_scan_status:
        waf_status_result = "WAF扫描程序正在运行中请勿重复提交"
    else:
        try:
            os.popen('bash /TIP/info_scan/finger.sh start_scan_waf')
            if "running" in waf_scan_status:
                waf_status_result = "WAF扫描程序已开启稍后查看结果"
            else:
                waf_status_result = "WAF扫描程序正在后台启动中......"
        except Exception as e:
            print("捕获到异常:", e)
    return waf_status_result


# 关闭WAF漏洞扫描程序
def stopwafrecognize_lib():
    waf_scan_status = os.popen('bash /TIP/info_scan/finger.sh waf_scan_status').read()
    os.popen('bash /TIP/info_scan/finger.sh kill_waf_scan')
    if "stop" in waf_scan_status:
        kill_waf_result = "已关闭WAF漏洞扫描程序"
    else:
        kill_waf_result = "正在关闭中......"
    return kill_waf_result




# 开启40xbypass fuzz工具
def start40xbypass_lib():
    bypass_scan_status = os.popen('bash /TIP/info_scan/finger.sh bypassstatus').read()
    url_list = url_file_ip_list()
    if "running" in bypass_scan_status:
        bypassx_status_result = "FUZZ扫描程序正在运行中请勿重复提交"
    else:
        try:
            for url in url_list:
                os.popen('bash /TIP/info_scan/finger.sh startbypass'+' '+url)
            if "running" in bypass_scan_status:
                bypassx_status_result = "FUZZ扫描程序已开启稍后查看结果"
            else:
                bypassx_status_result = "FUZZ扫描程序正在后台启动中......"
        except Exception as e:
            print("捕获到异常:", e)
    return bypassx_status_result


# 关闭40xbypass fuzz工具
def stopbypass_lib():
    bypass_scan_status = os.popen('bash /TIP/info_scan/finger.sh bypassstatus').read()
    os.popen('bash /TIP/info_scan/finger.sh stopbypass')
    if "stop" in bypass_scan_status:
        kill_bypass_result = "已关闭网站FUZZ扫描程序"
    else:
        kill_bypass_result = "正在关闭中......"
    return kill_bypass_result



# crawlergo爬虫结果文件处理
def crawlergo_file_lib():
    crawlergo_file = open('/TIP/info_scan/result/crawlergo_result.txt',encoding='utf-8')
    crawlergo_file_new = open(file='/TIP/info_scan/result/crawlergo_result_tmp.txt', mode='w')
    try:
        for line in crawlergo_file.readlines():
            line1 = line.replace("GET","")
            line2 = line1.replace("POST","")
            line3 = line2.replace("HTTP/1.1","")
            crawlergo_file_new.write(str(line3)+"\n".strip())
        os.popen('mv /TIP/info_scan/result/crawlergo_result_tmp.txt /TIP/info_scan/result/crawlergo_result.txt')
        
    except Exception as e:
        print("捕获到异常:", e)


# 开启crawlergo爬虫程序
def start_crawlergo_lib(pachongselectpart):
    # 每次扫描前清空上一次扫描结果
    os.popen('rm -rf /TIP/info_scan/result/crawlergo_result.txt')
    os.popen('rm -rf /TIP/info_scan/result/crawlergo_tmp_result.txt')
    
    # pachongselectpart 值为1不转发流量，值为2转发流量
    # poxry_ip_port 转发的流量和端口
   
    crawlergo_status = os.popen('bash /TIP/info_scan/finger.sh crawlergo_status').read()
    xray_status = os.popen('bash /TIP/info_scan/finger.sh xraystatus').read()
    if "running" in crawlergo_status:
        crawlergostatus_result = "爬虫程序正在运行中请勿重复提交"
    else:
        try:
            if int(pachongselectpart) == 1:
                os.popen('bash /TIP/info_scan/finger.sh start_crawlergo_shell')
                if "running" in crawlergo_status:
                    crawlergostatus_result = "爬虫程序已开启稍后查看结果"
                else:
                    crawlergostatus_result = "爬虫程序正在后台启动中......"
            elif int(pachongselectpart) == 2:
                print("传入值为2")
                # 判断xray是否开启监听，未开启监听不允许提交爬虫转发的流量
                if "running" in xray_status:
                    os.popen('bash /TIP/info_scan/finger.sh start_crawlergo_proxy_shell')
                    if "running" in crawlergo_status:
                        crawlergostatus_result = "爬虫程序已开启稍后查看结果"
                    else:
                        crawlergostatus_result = "爬虫程序正在后台启动中......"
                else:
                    crawlergostatus_result = "xray未开启被动监听无法开启爬虫流量转发"
            else:
                print("参数只为0/1")

        except Exception as e:
            print("捕获到异常:", e)
    return crawlergostatus_result


# 爬虫不开启流量转发
def start_crawlergo_scan_lib():
    try:
        # url.txt转换为列表
        url_list = url_file_ip_list()
        for url in url_list:
            result = os.popen('bash /TIP/info_scan/finger.sh start_crawlergo'+' '+url).read()
            print(result)
    except Exception as e:
        print("捕获到异常:", e)


# 爬虫开启流量转发
def start_crawlergo_scan_proxy_lib():
    try:
        # url.txt转换为列表
        url_list = url_file_ip_list()
        for url in url_list:
            result = os.popen('bash /TIP/info_scan/finger.sh start_crawlergo_proxy'+' '+url).read()
            print(result)
    except Exception as e:
        print("捕获到异常:", e)


# 关闭爬虫程序
def stop_crawlergo_lib():
    crawlergo_status = os.popen('bash /TIP/info_scan/finger.sh crawlergo_status').read()
    os.popen('bash /TIP/info_scan/finger.sh stop_crawlergo')
    if "stop" in crawlergo_status:
        kill_crawlergo_result = "已关闭爬虫扫描程序"
    else:
        kill_crawlergo_result = "正在关闭中......"
    return kill_crawlergo_result


# 开启xray
def startxray_lib():
    xraystatus = os.popen('bash /TIP/info_scan/finger.sh xraystatus').read()
    if "running" in xraystatus:
        xraystatus_result = "xray漏洞扫描程序正在运行中请勿重复提交"
    else:
        # 执行poc扫描
        result = os.popen('bash /TIP/info_scan/finger.sh startxray_scan').read()
        print(result)
        if "running" in xraystatus:
            xraystatus_result = "xray扫描程序已开启稍后查看结果"
        else:
            xraystatus_result = "xray扫描程序正在后台启动中......"
        xraystatus_result = "xray扫描程序已开启稍后查看结果"
    return xraystatus_result



# 关闭xray程序
def stop_xray_lib():
    xray_status = os.popen('bash /TIP/info_scan/finger.sh xraystatus').read()
    os.popen('bash /TIP/info_scan/finger.sh stopxrayscan')
    if "stop" in xray_status:
        kill_xray_result = "已关闭xray监听程序"
    else:
        kill_xray_result = "正在关闭中......"
    return kill_xray_result


# 资产管理遍历目录下的所有文件(绝对路径)
def list_files_in_directory():
    assset_file_list = []
    root_dir = '/TIP/info_scan/result/assetmanager'
    for root, dirs, files in os.walk(root_dir):
        for file in files:
            file_path = os.path.join(root, file)
            assset_file_list.append(file_path)
    return assset_file_list


# 扫描前是否进行指纹识别判断
# 已进行指纹识别返回：1
# 未进行指纹识别返回：2
def assets_finger_compare():
    # 资产列表
    url_list = url_file_ip_list()
    # 指纹识别结果列表
    finger_list_1 = []
    file = open("/TIP/info_scan/result/ehole_finger.txt",encoding='utf-8')
    for line in file.readlines():
        if 'http' in line:
            finger_list_1.append(line.strip())
    # 存在重点资产情况，去重列表
    finger_list = list(set(finger_list_1))
    
    conut_list = []
    for a in finger_list:
        for b in url_list:
            if b in a:
                conut_list.append('存在')
    if len(conut_list) > 0 and len(finger_list) >= len(conut_list):
        conut_result = 1
    else:
        conut_result = 2
    return conut_result
    

# 第三方接口成功次数,每查询一次数据库增加1次
def success_third_party_port_addone(id):
    try:
        db= pymysql.connect(host=dict['ip'],user=dict['username'],  
        password=dict['password'],db=dict['dbname'],port=dict['portnum']) 
        cur = db.cursor()
        sql="UPDATE interfacenum_table SET successnum = successnum + 1 where interid = '%s' "%(id)
        cur.execute(sql)
        db.commit()
        
    except Exception as e:
        print("捕获到异常:", e)
        db.rollback()

# 第三方接口失败次数,每查询一次数据库增加1次
def fail_third_party_port_addone(id):
    try:
        db= pymysql.connect(host=dict['ip'],user=dict['username'],  
        password=dict['password'],db=dict['dbname'],port=dict['portnum']) 
        cur = db.cursor()
        sql="UPDATE interfacenum_table SET failnum = failnum + 1 where interid = '%s' "%(id)
        cur.execute(sql)
        db.commit()
        
    except Exception as e:
        print("捕获到异常:", e)
        db.rollback()


# 统计第三方接口成功次数
def total_port_success_num(id):
    try:
        db= pymysql.connect(host=dict['ip'],user=dict['username'],  
        password=dict['password'],db=dict['dbname'],port=dict['portnum']) 
        cur = db.cursor()
        sql="select successnum from interfacenum_table where interid = '%s' "%(id)
        cur.execute(sql)
        data = cur.fetchall()
        list_data = list(data)
        list_result = []
        for i in list_data:
            list_result.append(i[0])
    except:
        list_result = ['MySQL连接失败']

    return list_result[0]


# 统计第三方接口失败次数
def total_port_fail_num(id):
    try:
        db= pymysql.connect(host=dict['ip'],user=dict['username'],  
        password=dict['password'],db=dict['dbname'],port=dict['portnum']) 
        cur = db.cursor()
        sql="select failnum from interfacenum_table where interid = '%s' "%(id)
        cur.execute(sql)
        data = cur.fetchall()
        list_data = list(data)
        list_result = []
        for i in list_data:
            list_result.append(i[0])
    except:
        list_result = ['MySQL连接失败']

    return list_result[0]


# 扫描器用时情况统计
# 获取扫描器开始时间戳存入数据库,并清空当前的扫描器结束时间
def scan_total_time_start_time(partid):
    try:
        current_time = time.time()
        db= pymysql.connect(host=dict['ip'],user=dict['username'],  
        password=dict['password'],db=dict['dbname'],port=dict['portnum']) 
        cur = db.cursor()
        sql="UPDATE scan_total_time_table SET starttime = '%s' WHERE typeid = '%s'"%(current_time,partid)
        cur.execute(sql)
        # 清空当前扫描器结束时间
        sql1="UPDATE scan_total_time_table SET endtime = '' WHERE typeid = '%s'"%(partid)
        cur.execute(sql1)
        db.commit()
        
    except Exception as e:
        print("捕获到异常:", e)
        db.rollback()


# 获取扫描器结束时间戳存入数据库
def scan_total_time_end_time(partid):
    try:
        current_time = time.time()
        db= pymysql.connect(host=dict['ip'],user=dict['username'],  
        password=dict['password'],db=dict['dbname'],port=dict['portnum']) 
        cur = db.cursor()
        sql="UPDATE scan_total_time_table SET endtime = '%s' WHERE typeid = '%s'"%(current_time,partid)
        cur.execute(sql)
        db.commit()
        
    except Exception as e:
        print("捕获到异常:", e)
        db.rollback()


# 判断扫描器结束时间是否为空,为空返回0,不为空返回1
def scan_total_time_endtimeisnull(partid):
    db= pymysql.connect(host=dict['ip'],user=dict['username'],  
    password=dict['password'],db=dict['dbname'],port=dict['portnum']) 
    cur = db.cursor()
    sql="select endtime from scan_total_time_table where typeid = '%s' "%(partid)
    cur.execute(sql)
    data = cur.fetchall()
    list_data = list(data)
    list_result = []
    for i in list_data:
        list_result.append(i[0])
    # 使用列表推导移除空数据
    filtered_list = [item for item in list_result if item]
    if len(filtered_list) ==0:
        resultvalue = 0
    else:
        resultvalue = 1
    return resultvalue


# 扫描器开始时间和结束时间做差
def scan_end_start_time(partid):
    try:
        db= pymysql.connect(host=dict['ip'],user=dict['username'],  
        password=dict['password'],db=dict['dbname'],port=dict['portnum']) 
        cur = db.cursor()
        sql="select starttime,endtime from scan_total_time_table where typeid = '%s' "%(partid)
        cur.execute(sql)
        data = cur.fetchall()
        list_data = list(data)
        starttime = []
        endtime = []
        for i in list_data:
            starttime.append(i[0])
            endtime.append(i[1])
        diff_time = float(endtime[0]) - float(starttime[0])
        diff_time_result = str(int(diff_time))
    except:
        diff_time_result = "初始状态："
    return diff_time_result
    
    

# 扫描器结束时间,当扫描器关闭状态and扫描器截止时间为空为真时,更新扫描器截止时间
def scan_total_time_final_end_time(typepart):
    if int(typepart) == 1:
        print("获取端口扫描最终截止时间")
        nmapstatus =os.popen('bash /TIP/info_scan/finger.sh nmapstatus').read()
        nmapisnull = scan_total_time_endtimeisnull(1)
        if "stop" in nmapstatus and nmapisnull == 0:
            scan_total_time_end_time(1)
        else:
            print("端口扫描程序运行时间正在计算中...")
    elif int(typepart) == 2:
        print("获取指纹识别扫描最终截止时间")
        finger_status = os.popen('bash /TIP/info_scan/finger.sh ehole_status').read()
        fingerisnull = scan_total_time_endtimeisnull(2)
        if "stop" in finger_status and fingerisnull == 0:
            scan_total_time_end_time(2)
        else:
            print("指纹识别程序运行时间正在计算中...")
    elif int(typepart) == 3:
        print("获取敏感信息扫描最终截止时间")
        bbscanstatus = os.popen('bash /TIP/info_scan/finger.sh bbscan_status').read()
        bbscanisnull = scan_total_time_endtimeisnull(3)
        if "stop" in bbscanstatus and bbscanisnull == 0:
            scan_total_time_end_time(3)
        else:
            print("敏感信息扫描程序运行时间正在计算中...")
    elif int(typepart) == 4:
        print("域名绑定URL扫描最终截止时间")
        otx_domain_url_shell_status = os.popen('bash /TIP/info_scan/finger.sh otx_domain_url_shell_status').read()
        otxisnull = scan_total_time_endtimeisnull(4)
        if "stop" in otx_domain_url_shell_status and otxisnull == 0:
            scan_total_time_end_time(4)
        else:
            print("域名绑定URL扫描程序运行时间正在计算中...")
    elif int(typepart) == 5:
        print("子域名扫描最终截止时间")
        crt_subdomain_shell_status = os.popen('bash /TIP/info_scan/finger.sh crt_subdomain_shell_status').read()
        crtisnull = scan_total_time_endtimeisnull(5)
        if "stop" in crt_subdomain_shell_status and crtisnull == 0:
            scan_total_time_end_time(5)
        else:
            print("子域名扫描程序运行时间正在计算中...")
    elif int(typepart) == 6:
        print("WAF识别扫描最终截止时间")
        waf_scan_status = os.popen('bash /TIP/info_scan/finger.sh waf_scan_status').read()
        wafisnull = scan_total_time_endtimeisnull(6)
        if "stop" in waf_scan_status and wafisnull == 0:
            scan_total_time_end_time(6)
        else:
            print("WAF识别扫描程序运行时间正在计算中...")
    elif int(typepart) == 7:
        print("网站FUZZ扫描最终截止时间")
        bypass_scan_status = os.popen('bash /TIP/info_scan/finger.sh bypassstatus').read()
        fuzzisnull = scan_total_time_endtimeisnull(7)
        if "stop" in bypass_scan_status and fuzzisnull == 0:
            scan_total_time_end_time(7)
        else:
            print("网站FUZZ扫描程序运行时间正在计算中...")
    elif int(typepart) == 8:
        print("爬虫扫描程序最终截止时间")
        crawlergo_status = os.popen('bash /TIP/info_scan/finger.sh crawlergo_status').read()
        crawlergoisnull = scan_total_time_endtimeisnull(8)
        if "stop" in crawlergo_status and crawlergoisnull == 0:
            scan_total_time_end_time(8)
        else:
            print("爬虫扫描程序运行时间正在计算中...")
    elif int(typepart) == 9:
        print("struts2扫描程序最终截止时间")
        struts2status = os.popen('bash /TIP/info_scan/finger.sh struts2_status').read()
        struts2scanisnull = scan_total_time_endtimeisnull(9)
        if "stop" in struts2status and struts2scanisnull == 0:
            scan_total_time_end_time(9)
        else:
            print("struts2扫描程序运行时间正在计算中...")
    elif int(typepart) == 10:
        print("weblogic扫描程序最终截止时间")
        weblogicstatus = os.popen('bash /TIP/info_scan/finger.sh weblogic_status').read()
        weblogicscanisnull = scan_total_time_endtimeisnull(10)
        if "stop" in weblogicstatus and weblogicscanisnull == 0:
            scan_total_time_end_time(10)
        else:
            print("weblogic扫描程序运行时间正在计算中...")
    elif int(typepart) == 11:
        print("shiro扫描程序最终截止时间")
        shirostatus = os.popen('bash /TIP/info_scan/finger.sh shiro_status').read()
        shiroscanisnull = scan_total_time_endtimeisnull(11)
        if "stop" in shirostatus and shiroscanisnull == 0:
            scan_total_time_end_time(11)
        else:
            print("shiro扫描程序运行时间正在计算中...")
    elif int(typepart) == 12:
        print("springboot扫描程序最终截止时间")
        springbootstatus = os.popen('bash /TIP/info_scan/finger.sh springboot_scan_status').read()
        springbootscanisnull = scan_total_time_endtimeisnull(12)
        if "stop" in springbootstatus and springbootscanisnull == 0:
            scan_total_time_end_time(12)
        else:
            print("springboot扫描程序运行时间正在计算中...")
    elif int(typepart) == 13:
        print("thinkphp扫描程序最终截止时间")
        tpscanstatus = os.popen('bash /TIP/info_scan/finger.sh TPscan_status').read()
        thinkphpscanisnull = scan_total_time_endtimeisnull(13)
        if "stop" in tpscanstatus and thinkphpscanisnull == 0:
            scan_total_time_end_time(13)
        else:
            print("springboot扫描程序运行时间正在计算中...")
    elif int(typepart) == 14:
        print("elasticsearch扫描程序最终截止时间")
        es_unauthorized_status = os.popen('bash /TIP/info_scan/finger.sh es_unauthorized_status').read()
        esscanisnull = scan_total_time_endtimeisnull(14)
        if "stop" in es_unauthorized_status and esscanisnull == 0:
            scan_total_time_end_time(14)
        else:
            print("es扫描程序运行时间正在计算中...")
    elif int(typepart) == 15:
        print("nacos扫描程序最终截止时间")
        nacos_status = os.popen('bash /TIP/info_scan/finger.sh nacos_vuln_scan_status').read()
        nacosscanisnull = scan_total_time_endtimeisnull(15)
        if "stop" in nacos_status and nacosscanisnull == 0:
            scan_total_time_end_time(15)
        else:
            print("nacos扫描程序运行时间正在计算中...")
    elif int(typepart) == 16:
        print("tomcat扫描程序最终截止时间")
        tomcat_status = os.popen('bash /TIP/info_scan/finger.sh tomcat_vuln_scan_status').read()
        tomcatscanisnull = scan_total_time_endtimeisnull(16)
        if "stop" in tomcat_status and tomcatscanisnull == 0:
            scan_total_time_end_time(16)
        else:
            print("tomcat扫描程序运行时间正在计算中...")
    elif int(typepart) == 17:
        print("fastjson扫描程序最终截止时间")
        fastjson_status = os.popen('bash /TIP/info_scan/finger.sh fastjson_scan_status').read()
        fastjsonscanisnull = scan_total_time_endtimeisnull(17)
        if "stop" in fastjson_status and fastjsonscanisnull == 0:
            scan_total_time_end_time(17)
        else:
            print("fastjson扫描程序运行时间正在计算中...")
    elif int(typepart) == 18:
        print("afrog扫描程序最终截止时间")
        afrogscanstatus = os.popen('bash /TIP/info_scan/finger.sh afrogscan_status').read()
        afrogscanisnull = scan_total_time_endtimeisnull(18)
        if "stop" in afrogscanstatus and afrogscanisnull == 0:
            scan_total_time_end_time(18)
        else:
            print("afrog扫描程序运行时间正在计算中...")
    elif int(typepart) == 19:
        print("fscan扫描程序最终截止时间")
        fscanstatus = os.popen('bash /TIP/info_scan/finger.sh fscan_status').read()
        fscanscanisnull = scan_total_time_endtimeisnull(19)
        if "stop" in fscanstatus and fscanscanisnull == 0:
            scan_total_time_end_time(19)
        else:
            print("fscan扫描程序运行时间正在计算中...")
    elif int(typepart) == 20:
        print("弱口令扫描程序最终截止时间")
        hydra_scan_status = os.popen('bash /TIP/info_scan/finger.sh hydra_status').read()
        hydrascanisnull = scan_total_time_endtimeisnull(20)
        if "stop" in hydra_scan_status and hydrascanisnull == 0:
            scan_total_time_end_time(20)
        else:
            print("弱口令扫描程序运行时间正在计算中...")
    elif int(typepart) == 21:
        print("api接口扫描程序最终截止时间")
        urlfinderstatus = os.popen('bash /TIP/info_scan/finger.sh urlfinder_status').read()
        urlfinderscanisnull = scan_total_time_endtimeisnull(21)
        if "stop" in urlfinderstatus and urlfinderscanisnull == 0:
            scan_total_time_end_time(21)
        else:
            print("弱口令扫描程序运行时间正在计算中...")
    elif int(typepart) == 22:
        print("vulmap扫描程序最终截止时间")
        vulmapscanstatus = os.popen('bash /TIP/info_scan/finger.sh vulmapscan_status').read()
        vulmapscanisnull = scan_total_time_endtimeisnull(22)
        if "stop" in vulmapscanstatus and vulmapscanisnull == 0:
            scan_total_time_end_time(22)
        else:
            print("vulmap扫描程序运行时间正在计算中...")
    elif int(typepart) == 23:
        print("nuclei扫描程序最终截止时间")
        nucleistatus =os.popen('bash /TIP/info_scan/finger.sh nucleistatus').read()
        nucleiscanisnull = scan_total_time_endtimeisnull(23)
        if "stop" in nucleistatus and nucleiscanisnull == 0:
            scan_total_time_end_time(23)
        else:
            print("nuclei扫描程序运行时间正在计算中...")
    elif int(typepart) == 24:
        print("泛微OA扫描程序最终截止时间")
        weaver_status = os.popen('bash /TIP/info_scan/finger.sh weaver_status').read()
        weaveroascanisnull = scan_total_time_endtimeisnull(24)
        if "stop" in weaver_status and weaveroascanisnull == 0:
            scan_total_time_end_time(24)
        else:
            print("泛微OA扫描程序运行时间正在计算中...")

    elif int(typepart) == 25:
        print("存活检测程序最终截止时间")
        httpx_status = os.popen('bash /TIP/info_scan/finger.sh httpx_status').read()
        httpxscanisnull = scan_total_time_endtimeisnull(25)
        if "stop" in httpx_status and httpxscanisnull == 0:
            scan_total_time_end_time(25)
        else:
            print("存活检测程序运行时间正在计算中...")
    elif int(typepart) == 26:
        print("xray被动扫描程序最终截止时间")
        xray_status = os.popen('bash /TIP/info_scan/finger.sh xraystatus').read()
        xrayscanisnull = scan_total_time_endtimeisnull(26)
        if "stop" in xray_status and xrayscanisnull == 0:
            scan_total_time_end_time(26)
        else:
            print("xray被动扫描程序运行时间正在计算中...")
    elif int(typepart) == 27:
        print("致远OA扫描程序最终截止时间")
        seeyon_status = os.popen('bash /TIP/info_scan/finger.sh seeyon_vuln_scan_status').read()
        seeyonscanisnull = scan_total_time_endtimeisnull(27)
        if "stop" in seeyon_status and seeyonscanisnull == 0:
            scan_total_time_end_time(27)
        else:
            print("致远OA漏洞扫描程序运行时间正在计算中...")
    elif int(typepart) == 28:
        print("用友OA扫描程序最终截止时间")
        yonsuite_status = os.popen('bash /TIP/info_scan/finger.sh yonsuite_vuln_scan_status').read()
        yonsuitescanisnull = scan_total_time_endtimeisnull(28)
        if "stop" in yonsuite_status and yonsuitescanisnull == 0:
            scan_total_time_end_time(28)
        else:
            print("用友OA漏洞扫描程序运行时间正在计算中...")
    elif int(typepart) == 29:
        print("金蝶OA扫描程序最终截止时间")
        kingdee_status = os.popen('bash /TIP/info_scan/finger.sh kingdee_vuln_scan_status').read()
        kingdeescanisnull = scan_total_time_endtimeisnull(29)
        if "stop" in kingdee_status and kingdeescanisnull == 0:
            scan_total_time_end_time(29)
        else:
            print("金蝶OA漏洞扫描程序运行时间正在计算中...")
    elif int(typepart) == 30:
        print("万户OA扫描程序最终截止时间")
        wanhu_status = os.popen('bash /TIP/info_scan/finger.sh wanhu_vuln_scan_status').read()
        wanhuscanisnull = scan_total_time_endtimeisnull(30)
        if "stop" in wanhu_status and wanhuscanisnull == 0:
            scan_total_time_end_time(30)
        else:
            print("万户OA漏洞扫描程序运行时间正在计算中...")
    elif int(typepart) == 31:
        print("subfinder扫描程序最终截止时间")
        subfinder_status = os.popen('bash /TIP/info_scan/finger.sh subfinder_status').read()
        subfinderscanisnull = scan_total_time_endtimeisnull(31)
        if "stop" in subfinder_status and subfinderscanisnull == 0:
            scan_total_time_end_time(31)
        else:
            print("subfinder扫描程序运行时间正在计算中...")
    elif int(typepart) == 32:
        print("redis扫描程序最终截止时间")
        redis_status = os.popen('bash /TIP/info_scan/finger.sh redis_vuln_scan_status').read()
        redisscanisnull = scan_total_time_endtimeisnull(32)
        if "stop" in redis_status and redisscanisnull == 0:
            scan_total_time_end_time(32)
        else:
            print("redis未授权扫描程序运行时间正在计算中...")
    elif int(typepart) == 33:
        print("mongodb扫描程序最终截止时间")
        mongodb_status = os.popen('bash /TIP/info_scan/finger.sh mongodb_vuln_scan_status').read()
        mongodbscanisnull = scan_total_time_endtimeisnull(33)
        if "stop" in mongodb_status and mongodbscanisnull == 0:
            scan_total_time_end_time(33)
        else:
            print("mongodb未授权扫描程序运行时间正在计算中...")
    elif int(typepart) == 34:
        print("memcached扫描程序最终截止时间")
        memcached_status = os.popen('bash /TIP/info_scan/finger.sh memcached_vuln_scan_status').read()
        memcachedscanisnull = scan_total_time_endtimeisnull(34)
        if "stop" in memcached_status and memcachedscanisnull == 0:
            scan_total_time_end_time(34)
        else:
            print("memcached未授权扫描程序运行时间正在计算中...")
    elif int(typepart) == 35:
        print("zookeeper扫描程序最终截止时间")
        zookeeper_status = os.popen('bash /TIP/info_scan/finger.sh zookeeper_vuln_scan_status').read()
        zookeeperscanisnull = scan_total_time_endtimeisnull(35)
        if "stop" in zookeeper_status and zookeeperscanisnull == 0:
            scan_total_time_end_time(35)
        else:
            print("zookeeper未授权扫描程序运行时间正在计算中...")
    elif int(typepart) == 36:
        print("ftp扫描程序最终截止时间")
        ftp_status = os.popen('bash /TIP/info_scan/finger.sh ftp_vuln_scan_status').read()
        ftpscanisnull = scan_total_time_endtimeisnull(36)
        if "stop" in ftp_status and ftpscanisnull == 0:
            scan_total_time_end_time(36)
        else:
            print("ftp未授权扫描程序运行时间正在计算中...")
    elif int(typepart) == 37:
        print("couchdb扫描程序最终截止时间")
        couchdb_status = os.popen('bash /TIP/info_scan/finger.sh couchdb_vuln_scan_status').read()
        couchdbscanisnull = scan_total_time_endtimeisnull(37)
        if "stop" in couchdb_status and couchdbscanisnull == 0:
            scan_total_time_end_time(37)
        else:
            print("couchdb未授权扫描程序运行时间正在计算中...")
    elif int(typepart) == 38:
        print("docker扫描程序最终截止时间")
        docker_status = os.popen('bash /TIP/info_scan/finger.sh docker_vuln_scan_status').read()
        dockerscanisnull = scan_total_time_endtimeisnull(38)
        if "stop" in docker_status and dockerscanisnull == 0:
            scan_total_time_end_time(38)
        else:
            print("docker未授权扫描程序运行时间正在计算中...")
    elif int(typepart) == 39:
        print("hadoop扫描程序最终截止时间")
        hadoop_status = os.popen('bash /TIP/info_scan/finger.sh hadoop_vuln_scan_status').read()
        hadoopscanisnull = scan_total_time_endtimeisnull(39)
        if "stop" in hadoop_status and hadoopscanisnull == 0:
            scan_total_time_end_time(39)
        else:
            print("hadoop未授权扫描程序运行时间正在计算中...")
    elif int(typepart) == 40:
        print("NFS扫描程序最终截止时间")
        nfs_status = os.popen('bash /TIP/info_scan/finger.sh nfs_vuln_scan_status').read()
        nfsscanisnull = scan_total_time_endtimeisnull(40)
        if "stop" in nfs_status and nfsscanisnull == 0:
            scan_total_time_end_time(40)
        else:
            print("NFS未授权扫描程序运行时间正在计算中...")
    elif int(typepart) == 41:
        print("rsync扫描程序最终截止时间")
        rsync_status = os.popen('bash /TIP/info_scan/finger.sh rsync_vuln_scan_status').read()
        rsyncscanisnull = scan_total_time_endtimeisnull(41)
        if "stop" in rsync_status and rsyncscanisnull == 0:
            scan_total_time_end_time(41)
        else:
            print("rsync未授权扫描程序运行时间正在计算中...")
    elif int(typepart) == 42:
        print("Elasticsearch扫描程序最终截止时间")
        es_status = os.popen('bash /TIP/info_scan/finger.sh elasticsearch_vuln_scan_status').read()
        esscanisnull = scan_total_time_endtimeisnull(42)
        if "stop" in es_status and esscanisnull == 0:
            scan_total_time_end_time(42)
        else:
            print("Elasticsearch未授权扫描程序运行时间正在计算中...")
    elif int(typepart) == 43:
        print("bcrypt解密程序最终截止时间")
        bcrypt_status = os.popen('bash /TIP/info_scan/finger.sh bcrypt_scan_status').read()
        bcryptscanisnull = scan_total_time_endtimeisnull(43)
        if "stop" in bcrypt_status and bcryptscanisnull == 0:
            scan_total_time_end_time(43)
        else:
            print("bcrypt解密程序运行时间正在计算中...")
    else:
        print("开发中...")


# 路由状态表更新
def route_status_update_lib(part1,part2):
    try:
        db= pymysql.connect(host=dict['ip'],user=dict['username'],  
        password=dict['password'],db=dict['dbname'],port=dict['portnum']) 
        cur = db.cursor()
        sql="UPDATE route_status SET typevalue = '%s' WHERE id = '%s'"%(part1,part2)
        cur.execute(sql)
        db.commit()
        
    except Exception as e:
        print("捕获到异常:", e)
        db.rollback()

# 路由状态表查询
def route_status_show_lib(id):
    try:
        db= pymysql.connect(host=dict['ip'],user=dict['username'],  
        password=dict['password'],db=dict['dbname'],port=dict['portnum']) 
        cur = db.cursor()
        sql="select typevalue from route_status where id = '%s' "%(id)
        cur.execute(sql)
        data = cur.fetchall()
        list_data = list(data)
        list_result = []
        for i in list_data:
            list_result.append(i[0])
    except:
        list_result = ['MySQL连接失败']

    return list_result[0]


# fofa查询日志文件绝对路径和fofa语法名称存库
def insert_fofa_log_lib(fofa_name,file_dir):
    
    db= pymysql.connect(host=dict['ip'],user=dict['username'],  
    password=dict['password'],db=dict['dbname'],port=dict['portnum']) 
    cur = db.cursor()
    
    sql_insert = "INSERT INTO fofa_log (fofa_grammar, file_path) VALUES ('%s', '%s')" % (fofa_name, file_dir)
    
    try:
        cur.execute(sql_insert)
        db.commit()
    except Exception as e:
        print("执行SQL语句时发生错误：", e)
        db.rollback() 


def restart_infoscan_lib():
    try:
        os.popen('bash /TIP/info_scan/finger.sh restartinfoscan')
    except Exception as e:
        print("执行重启语句时发生错误：", e)


# 系统配置更新
def update_session_time_lib(part1,part2):
    db= pymysql.connect(host=dict['ip'],user=dict['username'],  
    password=dict['password'],db=dict['dbname'],port=dict['portnum']) 
    cur = db.cursor()
    sql="UPDATE sys_conf SET info_session_time = '%s' WHERE id = '%s'"%(part1,part2)
    try:
        cur.execute(sql)
        db.commit()
    except Exception as e:
        print("执行SQL语句时发生错误：", e)
        db.rollback()
    
    # 配置生效需重启服务
    try:
        os.popen('bash /TIP/info_scan/finger.sh restartinfoscan')
    except Exception as e:
        print("执行重启语句时发生错误：", e)
    sess_time_1 = select_session_time_lib(1)
    shodan_key = select_session_time_lib(3)
    amap_key = select_session_time_lib(4)
    ceye_key = select_session_time_lib(5)
    if int(part1) == int(sess_time_1):
        return_result = "已更改会话过期时间"
    elif str(part1) == str(shodan_key):
        return_result = "已更改shodan配置"
    elif str(part1) == str(amap_key):
        return_result = "已更改amap配置"
    elif str(part1) == str(ceye_key):
        return_result = "已更改ceye配置"
    else:
        return_result = "其他配置"
    return return_result


# 更新DNS日志
def update_dnslog_lib(part1,part2):
    db= pymysql.connect(host=dict['ip'],user=dict['username'],  
    password=dict['password'],db=dict['dbname'],port=dict['portnum']) 
    cur = db.cursor()
    sql="UPDATE sys_conf SET info_session_time = '%s' WHERE id = '%s'"%(part1,part2)
    try:
        cur.execute(sql)
        db.commit()
    except Exception as e:
        print("执行SQL语句时发生错误：", e)
        db.rollback()
    
    dnslog_key = select_session_time_lib(6)
    if str(part1) == str(dnslog_key):
        return_result ="当前域名"+ part1+"已更改"
    else:
        return_result = "其他配置"
    return return_result
        


# 系统配置数据查询
def select_session_time_lib(id):
    try:
        db= pymysql.connect(host=dict['ip'],user=dict['username'],  
        password=dict['password'],db=dict['dbname'],port=dict['portnum']) 
        cur = db.cursor()
        sql="select info_session_time from sys_conf where id = '%s' "%(id)
        cur.execute(sql)
        data = cur.fetchall()
        list_data = list(data)
        list_result = []
        for i in list_data:
            list_result.append(i[0])
    except:
        list_result = ['MySQL连接失败']

    return list_result[0]


# fofa邮箱和key前端配置相关
# 更新配置
def update_fofakey_lib(part1,part2,part3):
    db= pymysql.connect(host=dict['ip'],user=dict['username'],  
    password=dict['password'],db=dict['dbname'],port=dict['portnum']) 
    cur = db.cursor()
    sql="UPDATE sys_conf SET fofa_email = '%s' , fofa_key = '%s' WHERE id = '%s'"%(part1,part2,part3)
    try:
        cur.execute(sql)
        db.commit()
    except Exception as e:
        print("执行SQL语句时发生错误：", e)
        db.rollback()
    # 配置生效需重启服务
    try:
        os.popen('bash /TIP/info_scan/finger.sh restartinfoscan')
    except Exception as e:
        print("执行重启语句时发生错误：", e)

    # 判断是否更新成功
    fofa_conf = select_fofakey_lib(2)
    fofa_email = fofa_conf[0]
    fofa_key = fofa_conf[1]
    
    if str(part1) == str(fofa_email) and str(part2) == str(fofa_key):
        return_result = "fofa配置已更新"
    return return_result


def select_fofakey_lib(id):
    try:
        db= pymysql.connect(host=dict['ip'],user=dict['username'],  
        password=dict['password'],db=dict['dbname'],port=dict['portnum']) 
        cur = db.cursor()
        sql="select fofa_email,fofa_key from sys_conf where id = '%s' "%(id)
        cur.execute(sql)
        data = cur.fetchall()
        list_data = list(data)
        list_result_1 = []
        list_result_2 = []
        for i in list_data:
            list_result_1.append(i[0])
        for j in list_data:
            list_result_2.append(i[1])
        list_result = list_result_1+list_result_2
        
    except:
        list_result = ['MySQL连接失败']

    return list_result


# 涉敏数据脱敏函数
def mask_data(data, visible_length=4):
    """
    数据脱敏处理，保留前4位和后4位明文，中间用*替换
    
    参数:
        data: 要脱敏的原始数据(字符串)
        visible_length: 头尾保留的明文长度(默认为4)
    
    返回:
        脱敏后的字符串
    """
    if len(data) <= visible_length * 2:
        # 如果数据长度不足，直接返回原始数据（或全星号）
        return data[:visible_length] + '*' * max(0, len(data) - visible_length)
    
    # 保留前N位和后N位，中间用星号填充
    head = data[:visible_length]
    tail = data[-visible_length:]
    return f"{head}{'*' * (len(data) - visible_length * 2)}{tail}"

    

# fofa日志搜索语法查询（去重）
def fofa_grammar_lib():
    try:
        db= pymysql.connect(host=dict['ip'],user=dict['username'],  
        password=dict['password'],db=dict['dbname'],port=dict['portnum']) 
        cur = db.cursor()
        sql="SELECT DISTINCT fofa_grammar FROM fofa_log"
        cur.execute(sql)
        data = cur.fetchall()
        list_data = list(data)
        list_result = []
        for i in list_data:
            list_result.append(i[0])
    except:
        list_result = ['MySQL连接失败']
    return list_result

# fofa日志查询根据语法查询路径
def fofa_grammar_by_dir_lib(grame):
    try:
        db= pymysql.connect(host=dict['ip'],user=dict['username'],  
        password=dict['password'],db=dict['dbname'],port=dict['portnum']) 
        cur = db.cursor()
        sql="SELECT file_path FROM fofa_log WHERE fofa_grammar = '%s' LIMIT 0,1"%(grame)
        cur.execute(sql)
        data = cur.fetchall()
        list_data = list(data)
        list_result = []
        for i in list_data:
            list_result.append(i[0])
        list_result1 = list_result[0]
       
    except:
        list_result1 = "MySQL连接失败"
    return list_result1
    

# 删除fofa查询日志表
def deletefofalog_lib():
    db= pymysql.connect(host=dict['ip'],user=dict['username'],  
    password=dict['password'],db=dict['dbname'],port=dict['portnum']) 
    cur = db.cursor()
    sql="DELETE FROM fofa_log"
    try:
        cur.execute(sql)
        db.commit()
    except Exception as e:
        print("执行SQL语句时发生错误：", e)
        db.rollback()

# 扩大资产范围
def expand_range_asset_lib():
    # url.txt转换为列表
    url_list = url_file_ip_list()
    # 提取根域名
    root_domain_list = root_domain_scan(url_list)
    # 根域名去重
    root_domain_list_uniq = list(set(root_domain_list))

    f = open(file='/TIP/info_scan/result/subfinder_target.txt', mode='w')
    # 定义域名常用后缀，用于过滤掉IP资产，IP不存在子域名信息
    domain_suffix = ['com','net','org','info','xyz','top','gov','edu','mil','pub','cn']
    for k in root_domain_list_uniq:
        for j in domain_suffix:
            if j in k:
                f.write(str(k)+"\n")
    f.close()

    # 调用subfinder获取子域名
    try:
        subprocess.run(['bash', '/TIP/info_scan/finger.sh', 'startsubfinder'], check=True)
    except Exception as e:
        print("错误信息：", e)

    # 把子域名和资产备份中的IP合成一个列表存入文件，得到最终的资产
    ip_list = []
    file = open("/TIP/batch_scan_domain/url_back.txt",encoding='utf-8')
    for line in file.readlines():
        ip_list.append(line.strip())

    subfinder_result_list = []
    file1 = open("/TIP/info_scan/result/subfinder_result.txt",encoding='utf-8')
    for line1 in file1.readlines():
        subfinder_result_list.append(line1.strip())
    domainiplist = ip_list + subfinder_result_list
    file3 = open(file='/TIP/info_scan/result/subfinder_result.txt',mode='w')
    for line2 in domainiplist:
        file3.write(str(line2)+"\n")
    file3.close()
    
    # 调用httpx把子域名中存活的提取出来并带协议
    try:
        subprocess.run(['bash', '/TIP/info_scan/finger.sh', 'subfinder_httpx'], check=True)
    except Exception as e:
        print("错误信息：", e)



# ICP查询
def icp_info_new(ip):
    try:
        #历史URL列表
        domain_value = domain_scan(ip)
        
        # 提取带域名后缀以cn或者com的列表，过滤掉IP的URL
        domain_list = []
        for ii in domain_value:
            if 'cn' in ii or 'com' in ii:
                domain_list.append(ii)
        
        # 列表去重
        try:
            domain_list_uniq1 = []
            domain_list_uniq = list(set(domain_list))
            for ji in domain_list_uniq:
                ji1 = ji.replace("https://","")
                ji2 = ji1.replace("http://","")
                ji3 = ji2.replace("www.","")
                domain_list_uniq1.append(ji3)
            
            domain_list_uniq2 = list(set(domain_list_uniq1))
        except:
            pass
    
        icp_name_list = []
        if len(domain_list_uniq2) == 0:
            icp_name_list.append("None")
        else:
            
            try:
                for jii in domain_list_uniq2:
                    icpname = os.popen('python3 /TIP/info_scan/selenium_run.py'+' '+jii).read()
                    icp_name_list.append(icpname)
            except:
                icp_name_list.append("ICP备案接口正在更新维护中")
        icp_name_list_uniq = list(set(icp_name_list))
        
        success_third_party_port_addone(4)
    except:
        icp_name_list_uniq = ["None"]
        fail_third_party_port_addone(4)
    return icp_name_list_uniq


# CDN检测
def cdn_detection_lib():
    print("CDN检测")
     # url.txt转换为列表
    url_list = url_file_ip_list()
    # 提取根域名
    domain_list = root_domain_scan(url_list)
    # 定义域名常用后缀，用于过滤掉IP资产，IP不存在子域名信息
    domain_suffix = ['com','net','org','info','xyz','top','gov','edu','mil','pub','cn']
    # 提取域名用于判断CDN
    # 域名列表
    domain_list_noip = []
    for k in domain_list:
        for j in domain_suffix:
            if j in k:
                domain_list_noip.append(k)
    # 纯域名无IP列表去重
    domain_list_noip_uniq = list(set(domain_list_noip))
    # 遍历列表判断是否存在CDN

    # 定义存在CDN和不存在CDN字典
    cdn_dict_list = []
    no_cdn_dict_list = []

    for domain in domain_list_noip_uniq:
        cdn_result = os.popen('bash /TIP/info_scan/finger.sh batch_cdn_scan'+' '+domain).read().strip() 
        if str(cdn_result) == "有CDN":
            cdn_dict_list.append(domain)
        else:
            no_cdn_dict_list.append(domain)
    
    # 无CDN+IP（不进行识别CDN）是最终的无CDN列表
    ip_list = url_convert_ip()
    ip_list_uniq = list(set(ip_list))
    total_list_uniq = no_cdn_dict_list+ip_list_uniq
    total_list_uniq_result = []
    for total_line in total_list_uniq:
        nocdnresult = os.popen('bash /TIP/info_scan/finger.sh recognize_no_cdn'+' '+total_line).read().strip()
        total_list_uniq_result.append(nocdnresult)
    total_list_uniq_result_uniq = list(set(total_list_uniq_result))

    #列表写入到url.txt
    f = open(file='/TIP/batch_scan_domain/url.txt',mode='w')
    for fileline in total_list_uniq_result_uniq:
        f.write(str(fileline)+"\n")
    f.close()

# 关闭CDN检测
def stop_cdnsurvival_lib():
    cdn_status = os.popen('bash /TIP/info_scan/finger.sh cdn_status').read()
    os.popen('bash /TIP/info_scan/finger.sh stop_cdn')
    if "stop" in cdn_status:
        kill_cdn_result = "已关闭CDN检测程序"
    else:
        kill_cdn_result = "正在关闭中......"
    return kill_cdn_result


# 图标文件hash计算
def compute_icon_hash_lib(url):
    try:
        print("hash计算")
        r=requests.get(url)
        r1=r.content
        r2=base64.encodebytes(r1)
        r3=mmh3.hash(r2)
    except Exception as e:
        print("捕获到异常:", e)
    return str(r3)


# 关闭字典生成程序
def stopgendict_lib():
    dict_status = os.popen('bash /TIP/info_scan/finger.sh gendict_status').read()
    os.popen('bash /TIP/info_scan/finger.sh stopgendict')
    if "stop" in dict_status:
        kill_dict_result = "已关闭字典生成程序"
    else:
        kill_dict_result = "正在关闭中......"
    return kill_dict_result


# 密码字典文件存入列表
def dict_file_list():
    dict_list = []
    file = open("/TIP/info_scan/result/workerdictionary.txt",encoding='utf-8')
    for line in file.readlines():
        dict_list.append(line.strip())
    return dict_list


# 通过shodan接口获取资产
def assets_college_shodan_lib():
    keyword = sys.argv[2]
    startnum = sys.argv[3]
    endnum = sys.argv[4]
    key1 = 'http.title:"{}"'
    key1 = key1.replace("{}", keyword)
    shodankeyvalue = select_session_time_lib(3)
    apis = shodan.Shodan(shodankeyvalue)
    
    try:
        # 开始页数
        page = int(startnum)
        # 最大页数
        max_pages = int(endnum)
        # 存入url列表
        url_list = []
        for p in range(1, max_pages + 1):
            results = apis.search(key1, page=p)
            
            for result in results['matches']:
                print(str(result['ip_str']))
                url_list.append(str(result['ip_str'])+str(":")+str(result['port']))
        f = open(file='/TIP/batch_scan_domain/url.txt', mode='w')
        for k in url_list:
            if ":443" in k:
                f.write("https://"+str(k)+"\n")
            elif ":80" in k:
                f.write("http://"+str(k)+"\n")
            else:
                f.write(str(k)+"\n")
        f.close()
    except:
        pass

# 常见设备口令查看（yaml文件）
def device_password_show():
    
    with open(device_pass_dir, 'r', encoding='utf-8') as file:
       
        data = yaml.safe_load(file)
        # 解析每一行并转换为字典
    result_list = []
    for item in data:
        # 拆分每一行，假设格式为 "公司`用户名`密码"
        parts = item.split("`")
        if len(parts) == 3:
            company, username, password = parts
            result_list.append({
                "company": company.strip(),
                "username": username.strip(),
                "password": password.strip()
            })
        else:
            print(f"解析错误：{item}")
    return result_list


# 常见杀软查询（yaml文件）
def antivirus_soft_show():
    with open(antiv_software_dir, 'r', encoding='utf-8') as file:
       
        data = yaml.safe_load(file)
        # 解析每一行并转换为字典
    result_list = []
    for item in data:
        # 拆分每一行，假设格式为 "杀软进程名`进程描述"
        parts = item.split("`")
        if len(parts) == 2:
            antivirus_name, antivirus_decrib = parts
            result_list.append({
                "antivirus_name": antivirus_name.strip(),
                "antivirus_decrib": antivirus_decrib.strip()
            })
        else:
            print(f"解析错误：{item}")
    return result_list



# 过滤内网IP
def filter_private_ip_lib():
    # 全部资产列表
    assets_list = url_file_ip_list()  
    private_ip_list = []
    public_ip_list = []
    
    for asset in assets_list:
        try:
            ip = ipaddress.ip_address(asset)
            if ip.version == 4:
                # 关键修复：将条件判断结果用于过滤
                if (ip.is_private or 
                    ip.is_loopback or 
                    ip.is_link_local or 
                    ip.is_unspecified or
                    (ip >= ipaddress.IPv4Address('100.64.0.0') and 
                     ip <= ipaddress.IPv4Address('100.127.255.255'))):
                    private_ip_list.append(asset)                    
                else:
                    public_ip_list.append(asset)                    
            elif ip.version == 6:
                if (ip.is_private or 
                    ip.is_loopback or 
                    ip.is_link_local or 
                    ip.is_unspecified):
                    private_ip_list.append(asset)                    
                else:
                    public_ip_list.append(asset)                    
        except ValueError:
            # 非IP地址（可能是URL或其他格式）
            public_ip_list.append(asset)
    # 判断是否执行成功
    total_assets_len = len(assets_list)
    sum_assets_len = len(private_ip_list) + len(public_ip_list)
    if total_assets_len == sum_assets_len:
        # 遍历列表存入目标资产
        f = open(file='/TIP/batch_scan_domain/url.txt', mode='w')
        for k in public_ip_list:
            f.write(str(k)+"\n")
        f.close()
        result = ["过滤内网地址成功",len(private_ip_list)]
    else:
        result = ["过滤内网地址失败",len(private_ip_list)]
    return result
    


# 提取IP地址
def withdrawiplocation_lib():
    # 全部资产列表
    assets_list = url_file_ip_list()  
    ip_list = []
    for asset in assets_list:
        try:
            ip = ipaddress.ip_address(asset)
            if ip.version == 4:
                ip_list.append(asset)                                      
            elif ip.version == 6:
                ip_list.append(asset)                    
        except:
            pass
    if len(ip_list) <= len(assets_list):
         # 遍历列表存入目标资产
        f = open(file='/TIP/batch_scan_domain/url.txt', mode='w')
        for k in ip_list:
            f.write(str(k)+"\n")
        f.close()
        ip_list_result = "提取IP地址成功"
    else:
        ip_list_result = "提取IP地址失败"
    return  ip_list_result

# 网络速率
def get_network_speed():
    # 获取当前的网络接口的字节数
    net_io_start = psutil.net_io_counters()
    bytes_sent_start = net_io_start.bytes_sent
    bytes_recv_start = net_io_start.bytes_recv

    # 等待1秒
    time.sleep(1)

    # 再次获取网络接口的字节数
    net_io_end = psutil.net_io_counters()
    bytes_sent_end = net_io_end.bytes_sent
    bytes_recv_end = net_io_end.bytes_recv

    # 计算1秒内的发送和接收字节数
    bytes_sent = bytes_sent_end - bytes_sent_start
    bytes_recv = bytes_recv_end - bytes_recv_start

    # 转换为KB/s
    net_out_rate = bytes_sent / 1024  # 转换为KB
    net_in_rate = bytes_recv / 1024  # 转换为KB

    # 格式化输出，保留最多三位有效数字
    def format_rate(rate):
        if rate < 10:
            return f"{rate:.3f}"  # 保留三位小数
        elif rate < 100:
            return f"{rate:.2f}"  # 保留两位小数
        else:
            return f"{rate:.1f}"  # 保留一位小数

    # 格式化接收速率和发送速率
    formatted_net_in_rate = "接收 "+format_rate(net_in_rate)+" KB/s"
    formatted_net_out_rate = "发送 "+format_rate(net_out_rate)+" KB/s"
    return formatted_net_in_rate, formatted_net_out_rate


# 用于态势感知大屏提取主机资产和网站资产
# 提取主机资产
def extract_host_assets_lib():
    # 全部资产列表
    assets_list = url_file_ip_list()  
    ip_list = []
    for asset in assets_list:
        try:
            ip = ipaddress.ip_address(asset)
            if ip.version == 4:
                ip_list.append(asset)                                      
            elif ip.version == 6:
                ip_list.append(asset)                    
        except:
            pass
    return str(len(ip_list))

# 提取网站资产
def extract_site_assets_lib():
    # 全部资产列表
    assets_list = url_file_ip_list()
    # 网站资产列表
    site_list = []
    try:
        for urlline in assets_list:
            if "http" in urlline:
                site_list.append(urlline)
    except:
        site_list.append("")
    return str(len(site_list))


# 自定义接口额度总量查询
def customize_interface_totalnum(partid):
    if partid >= 7:
        customize_result = "只能查询6条数据"
    else:
        db= pymysql.connect(host=dict['ip'],user=dict['username'],  
        password=dict['password'],db=dict['dbname'],port=dict['portnum']) 
        cur = db.cursor()
        sql="select totalnum from interfacenum_table where id = '%s' "%(partid)
        cur.execute(sql)
        data = cur.fetchall()
        list_data = list(data)
        for i in list_data:
            customize_result = i[0]
    return customize_result

# 自定义接口额度修改
def update_customize_interface_totalnum(part1,part2):
    try:
        db= pymysql.connect(host=dict['ip'],user=dict['username'],  
        password=dict['password'],db=dict['dbname'],port=dict['portnum']) 
        cur = db.cursor()
        sql="UPDATE interfacenum_table SET totalnum = '%s' WHERE id = '%s'"%(part1,part2)
        cur.execute(sql)
        db.commit()
        # 验证是否更新成功
        check_sql = "SELECT totalnum FROM interfacenum_table WHERE id = %s"
        cur.execute(check_sql, (part2))
        result = cur.fetchone()
        # 判断是哪个平台
        if int(part2) == 1:
            platform = "fofa"
        elif int(part2) == 2:
            platform = "shodan"
        elif int(part2) == 3:
            platform = "crt证书"
        elif int(part2) == 4:
            platform = "icp备案" 
        elif int(part2) == 5:
            platform = "高德地图"
        elif int(part2) == 6:
            platform = "otx威胁情报"
        else:
            print("其他参数")
        if int(result[0]) == int(part1):
            update_result = platform+"接口额度更新成功"
        else:
            update_result = platform+"接口额度更新失败"
    except Exception as e:
        print("捕获到异常:", e)
        db.rollback()
    # 配置生效需重启服务
    try:
        os.popen('bash /TIP/info_scan/finger.sh restartinfoscan')
    except Exception as e:
        print("执行重启语句时发生错误：", e)
    return update_result
    

# 资产校验开关查询
def verification_table_lib(partid):
    if partid >= 3:
        customize_result = "只能查询2条数据"
    else:
        db= pymysql.connect(host=dict['ip'],user=dict['username'],  
        password=dict['password'],db=dict['dbname'],port=dict['portnum']) 
        cur = db.cursor()
        sql="select logopart from verification_table where id = '%s' "%(partid)
        cur.execute(sql)
        data = cur.fetchall()
        list_data = list(data)
        for i in list_data:
            customize_result = i[0]
            if int(customize_result) == 1:
                customize_result_part = "已开启校验"
            else:
                customize_result_part = "未开启校验"
    return customize_result_part


# 修改校验开关
def update_verification_table_lib(part1,part2):
    try:
        db= pymysql.connect(host=dict['ip'],user=dict['username'],  
        password=dict['password'],db=dict['dbname'],port=dict['portnum']) 
        cur = db.cursor()
        sql="UPDATE verification_table SET logopart = '%s' WHERE id = '%s'"%(part1,part2)
        cur.execute(sql)
        db.commit()
        # 验证是否更新成功
        check_sql = "SELECT logopart FROM verification_table WHERE id = %s"
        cur.execute(check_sql, (part2))
        result = cur.fetchone()
        if int(part1) == 1:
            if int(result[0]) == int(part1):
                update_result = "已开启校验"
            else:
                update_result = "资产校验开启出错"
        elif int(part1) == 2:
            if int(result[0]) == int(part1):
                update_result = "未开启校验"
            else:
                update_result = "资产校验关闭出错"
        else:
            print("不允许配置其他参数")
        
    except Exception as e:
        print("捕获到异常:", e)
        db.rollback()
    # 配置生效需重启服务
    try:
        os.popen('bash /TIP/info_scan/finger.sh restartinfoscan')
    except Exception as e:
        print("执行重启语句时发生错误：", e)
    return update_result


# DNSLog Platform平台相关
# 获取随机子域名
def get_random_subdomain_lib():
    # 设置 Chrome 选项
    chrome_options = Options()
    chrome_options.add_argument("--no-sandbox")  # 允许 Chrome 在没有沙箱环境的情况下运行
    chrome_options.add_argument("--disable-dev-shm-usage")  # 避免使用 /dev/shm
    chrome_options.add_argument("--disable-gpu")  # 禁用 GPU 硬件加速
    chrome_options.add_argument("--headless")  # 无头模式
    chrome_options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
    driver = None
    try:
        # 初始化浏览器
        driver = webdriver.Chrome(options=chrome_options)
        # 打开目标网站
        driver.get("http://www.dnslog.cn/")

        # 设置显式等待
        wait = WebDriverWait(driver, 3)  # 等待最长20秒

        # 等待按钮出现并点击
        try:
            button = wait.until(EC.element_to_be_clickable((By.XPATH, '//*[@id="content"]/button[1]')))
            button.click()
        except TimeoutException:
            print("按钮未找到或页面加载超时")
            return
        # 添加3秒延时，等待数据加载
        time.sleep(3)
        # 等待页面加载完成后的 <div> 元素出现
        try:
            # 使用绝对路径定位内容
            result_xpath = "/html/body/div[2]/div"
            result_element = wait.until(EC.presence_of_element_located((By.XPATH, result_xpath)))
            result_text = result_element.text
        except TimeoutException:
            print("内容未找到或页面加载超时")
    except Exception as e:
        print("发生错误:", str(e))
    finally:
        # 关闭浏览器
        if driver:
            driver.quit()
    return result_text


# 刷新DNSLog记录
def refresh_random_subdomain_lib():
    # 设置 Chrome 选项
    chrome_options = Options()
    chrome_options.add_argument("--no-sandbox")  # 允许 Chrome 在没有沙箱环境的情况下运行
    chrome_options.add_argument("--disable-dev-shm-usage")  # 避免使用 /dev/shm
    chrome_options.add_argument("--disable-gpu")  # 禁用 GPU 硬件加速
    chrome_options.add_argument("--headless")  # 无头模式
    chrome_options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
    driver = None
    try:
        # 初始化浏览器
        driver = webdriver.Chrome(options=chrome_options)
        # 打开目标网站
        driver.get("http://www.dnslog.cn/")
        # 设置显式等待
        wait = WebDriverWait(driver, 20)  # 等待最长20秒

        # 等待按钮出现并点击
        try:
            button = wait.until(EC.element_to_be_clickable((By.XPATH, '//*[@id="content"]/button[2]')))
            button.click()
        except TimeoutException:
            print("按钮未找到或页面加载超时")
            return
        # 添加3秒延时，等待数据加载
        time.sleep(3)
        # 等待页面加载完成后的 <div> 元素出现
        try:
            # 使用绝对路径定位内容
            result_xpath = "/html/body/div[2]/center/table/tbody"
            result_element = wait.until(EC.presence_of_element_located((By.XPATH, result_xpath)))
            result_text = result_element.text
            print(result_text)
        except TimeoutException:
            print("内容未找到或页面加载超时")
    except Exception as e:
        print("发生错误:", str(e))
    finally:
        # 关闭浏览器
        if driver:
            driver.quit()

# 全局白名单查询
def global_white_conf_lib():
    whiteconf_list = []
    file = open("/TIP/info_scan/result/globalwhiteconfig.txt",encoding='utf-8')
    for line in file.readlines():
        whiteconf_list.append(line.strip())
    return whiteconf_list


# 随机抽取文件名
def random_file(directory):
    """
    从指定目录中随机选取一个文件
    :param directory: 指定的目录路径
    :return: 随机选取的文件的完整路径
    """
    # 获取目录中的所有文件和文件夹
    files_and_dirs = os.listdir(directory)
    
    # 过滤出文件（排除文件夹）
    files = [f for f in files_and_dirs if os.path.isfile(os.path.join(directory, f))]
    
    if not files:
        raise FileNotFoundError("指定目录中没有文件")
    
    # 随机选取一个文件
    random_file_name = random.choice(files)
    
    # 返回文件的完整路径
    return os.path.join(directory, random_file_name)


# 获取代理后ip地理位置
def get_ip_proxy_location_yh_lib(part):
    ip_location_list = []
    if int(part) == 0:
        proxyaddresslocat1 = subprocess.check_output(["bash", "/TIP/info_scan/finger.sh","proxyaddressyouhua"], stderr=subprocess.DEVNULL)
    elif int(part) == 1:
        proxyaddresslocat1 = subprocess.check_output(["bash", "/TIP/info_scan/finger.sh","addressyouhua"], stderr=subprocess.DEVNULL)
    # 将字节串解码为字符串
    output_str = proxyaddresslocat1.decode('utf-8')
    
    # 去除空行并分割成列表
    output_lines = [line.strip() for line in output_str.splitlines() if line.strip()]
    
    # 打印处理后的结果
    for line in output_lines:
        ip_location_list.append(line)
    return ip_location_list

# 文件UUID重命名
def filerename_lib():
    directory = "/usr/local/etc/v2ray"
    for root, dirs, files in os.walk(directory):
        for file in files:
            # 文件的完整路径
            file_path = os.path.join(root, file)
            # 分离文件名和扩展名
            name, ext = os.path.splitext(file)
            
            # 生成新的 UUID 文件名（保留原扩展名）
            new_name = str(uuid.uuid4()) + ext
            new_path = os.path.join(root, new_name)
           
            # 重命名文件
            os.rename(file_path, new_path)
            print("重命名成功")






if __name__ == "__main__":
    if len(sys.argv) > 1:
        func_name = sys.argv[1]
        if func_name == 'otx_domain_url_lib':
            otx_domain_url_lib()
        elif func_name == 'crt_subdomain_lib':
            crt_subdomain_lib()
        elif func_name == 'crawlergo_file_lib':
            crawlergo_file_lib()
        elif func_name == 'start_crawlergo_scan_lib':
            start_crawlergo_scan_lib()
        elif func_name == 'start_crawlergo_scan_proxy_lib':
            start_crawlergo_scan_proxy_lib()
        elif func_name == 'cdn_detection_lib':
            cdn_detection_lib()
        elif func_name == 'assets_college_shodan_lib':
            assets_college_shodan_lib()
        elif func_name == 'withdrawiplocation_lib':
            withdrawiplocation_lib()

        elif func_name == 'filerename_lib':
            filerename_lib()
        else:
            print("Invalid function number")
    else:
        print("No function number provided")