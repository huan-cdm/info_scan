'''
Description:[icp备案查询]
Author:[huan666]
Date:[2023/11/12]
'''
import httpx_status
import requests
from bs4 import BeautifulSoup
from fake_useragent import UserAgent
import random

def generate_random_ip():  
    # 生成一个随机的IPv4地址  
    return '.'.join(str(random.randint(0, 255)) for _ in range(4))  

def icp_scan(ip):
    UA = UserAgent()
    #状态码为200并带http或者https的列表
    domain_value = httpx_status.status_scan(ip)

    #提取带cn或者com的列表
    domain_list = []
    for ii in domain_value:
        if 'cn' in ii or 'com' in ii:
            domain_list.append(ii)
    url = "https://icp.chinaz.com/"
    hearder = {
        'Cookie':'cz_statistics_visitor=47200924-88b7-cc6f-e817-6e3d3d76af1c; pinghost=pay.it.10086.cn; Hm_lvt_ca96c3507ee04e182fb6d097cb2a1a4c=1707096410,1707902350; _clck=5gzbp1%7C2%7Cfj9%7C0%7C1496; qHistory=Ly9taWNwLmNoaW5hei5jb20vX+e9keermeWkh+ahiOafpeivol/np7vliqh8Ly9pY3AuY2hpbmF6LmNvbS9f572R56uZ5aSH5qGI5p+l6K+i; JSESSIONID=B525D76194927A260AC9E9C0B72B44D2; Hm_lpvt_ca96c3507ee04e182fb6d097cb2a1a4c=1707902454; _clsk=1hj5on3%7C1707902455070%7C6%7C0%7Cw.clarity.ms%2Fcollect',
        'Accept-Language':'zh-CN,zh;q=0.9,en;q=0.8',
        'User-Agent':UA.random,
        'Host':'icp.chinaz.com',
        'X-Forwarded-For': generate_random_ip()
       
        }
    print(generate_random_ip())
    try:
        icp_list = []
        if len(domain_list) == 0:
            icp_list.append("None")
        else:
            for ii in domain_list:
                res = requests.get(url+str(ii),headers=hearder,allow_redirects=False)
                res.encoding = 'utf-8'
                soup=BeautifulSoup(res.text,'html.parser')
                soup_p = soup.find_all('p')
                company_name = soup_p[7].text
                icp_list.append(company_name)
        icp_uniq_list = list(set(icp_list))
        icp_uniq_str = icp_uniq_list[0]
        
        return icp_uniq_str
    except:
        pass
    