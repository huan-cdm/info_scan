'''
Description:[fofa|shodan api调用]
Author:[huan666]
Date:[2023/11/03]
'''
#自定义模块
from config import switch
from config import shodankey
from config import fofaemail
from config import fofakey
from config import fofanum

#系统模块
import sys
import shodan
import base64
import requests
import json
import re
import pandas as pd
import openpyxl
import numpy as np
import json
from bs4 import BeautifulSoup


def shodan_fofa_api(ip):

    try:
        apis = shodan.Shodan(shodankey)
        result = apis.host(ip)
    except:
        pass
    try:
        #端口
        port_1 = result['ports']
        port_11 = str(port_1).replace("[","")
        port = port_11.replace("]","")
    except:
        pass
    
    try:
        #主机名
        hostname0 = result['hostnames']
        hostname1 = str(hostname0).replace("['","")
        hostname = str(hostname1).replace("']","")
    except:
        pass


    #fofa_api
    try:
        fofa_first_argv= 'ip=' + ip + ''
        fofa_first_argv_utf8 = fofa_first_argv.encode('utf-8')
        fofa_first_argv_base64=base64.b64encode(fofa_first_argv_utf8)
        fofa_argv_str=str(fofa_first_argv_base64,'utf-8')

        url = "https://fofa.info/api/v1/search/all?email="+fofaemail+"&key="+fofakey+"&size="+fofanum+"&qbase64="
        hearder={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)'
        }
        
        res = requests.get(url+fofa_argv_str,headers=hearder,allow_redirects=False)
        res.encoding='utf-8'
        restext = res.text
        resdic=json.loads(restext)
        resdicresult=resdic['results']

        #定义fofa查询端口列表
        result_list = []
        for line in resdicresult:
            result_list.append(line[2])
        fofa_port_list = list(set(result_list))
        fofa_port_list_1 = set(fofa_port_list)

        #定义fofa查询域名列表
        fofa_domain_list = []
        #元组转列表
        fofa_domain_list_uniq_result = []

        for linee in resdicresult:
             matches1 = re.findall(r"(http(s)?://\S+)", linee[0])
             for match1 in matches1:
                 fofa_domain_list.append(match1)
        fofa_domain_uniq_list = list(set(fofa_domain_list))
        for ii in fofa_domain_uniq_list:
            fofa_domain_list_uniq_result.append(ii[0])
    except:
        pass
    


    #shodan列表去重、字符串转列表
    try:
        port_list = []
        str_list = port.split(", ")
        for item in str_list:
            port_list.append(item)
    except:
        pass

    try:
        shodan_port_list = port_list
        shodan_port_list_1 = set(shodan_port_list)
    except:
        pass
    

    try:
        #列表合并去重
        fofa_shodan_list = fofa_port_list_1.union(shodan_port_list_1)
        fofa_shodan_list_uniq = list(set(fofa_shodan_list))
        
        #清空列表为空的数据
        fofa_shodan_list_result = []
        for j in fofa_shodan_list_uniq:
            if j != ' ' or j != '':
                fofa_shodan_list_result.append(j)
    except:
        pass
    
    #ICP备案查询
    icp_list = []
    icp_uniq_list = []
    for a in fofa_domain_list_uniq_result:
        matches = re.findall(r"(?:https?:\/\/)?(?:\w+\.)?(?:com|cn)", a)
        icp_list.append(matches)
    
    for b in icp_list:
        try:
            icp_uniq_list.append(b[0])
        except:
            pass
    #列表去重
    icp_uniq_list_result = list(set(icp_uniq_list))
    icp_uniq_new_list = []
    if len(icp_uniq_list_result) == 0:
        try:
            icp_uniq_new_list.append(hostname)
        except:
            pass
    else:
        icp_uniq_new_list = icp_uniq_list_result
    
    #域名归属公司查询
    url = "https://icp.chinaz.com/"
    hearder = {
        'Cookie':'qHistory=Ly9pY3AuY2hpbmF6LmNvbS9qZC5jb21f572R56uZ5aSH5qGI5p+l6K+i; cz_statistics_visitor=68f8740c-7d0c-2be1-809e-b02636111b44; Hm_lvt_ca96c3507ee04e182fb6d097cb2a1a4c=1678588537; Hm_lpvt_ca96c3507ee04e182fb6d097cb2a1a4c=1678588537',
        'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.72 Safari/537.36',
        'Accept-Language':'zh-CN,zh;q=0.9,en;q=0.8'
        }
    try:
        res = requests.get(url+str(icp_uniq_new_list[0]),headers=hearder,allow_redirects=False)
    except:
        pass
    res.encoding = 'utf-8'
    soup=BeautifulSoup(res.text,'html.parser')
    soup_p = soup.find_all('p')
    try:
        company_name = soup_p[12].text
    except:
        pass

    
    try:
        #定义字典存数据
        data = {
            "ip":ip,
            "port":fofa_shodan_list_result,
            "hostname":hostname,
            "domain":fofa_domain_list_uniq_result,
            "company":company_name
            
        }
        return data
    except:
        pass