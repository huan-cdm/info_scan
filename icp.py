'''
Description:[icp备案查询]
Author:[huan666]
Date:[2023/11/12]
'''
import httpx_status
import requests
from bs4 import BeautifulSoup

def icp_scan(ip):

    #状态码为200并带http或者https的列表
    domain_value = httpx_status.status_scan(ip)

    #提取带cn或者com的列表
    domain_list = []
    for ii in domain_value:
        if 'cn' in ii or 'com' in ii:
            domain_list.append(ii)
    url = "https://icp.chinaz.com/"
    hearder = {
        'Cookie':'qHistory=Ly9pY3AuY2hpbmF6LmNvbS9qZC5jb21f572R56uZ5aSH5qGI5p+l6K+i; cz_statistics_visitor=68f8740c-7d0c-2be1-809e-b02636111b44; Hm_lvt_ca96c3507ee04e182fb6d097cb2a1a4c=1678588537; Hm_lpvt_ca96c3507ee04e182fb6d097cb2a1a4c=1678588537',
        'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.72 Safari/537.36',
        'Accept-Language':'zh-CN,zh;q=0.9,en;q=0.8'
        }
    icp_list = []
    if len(domain_list) == 0:
        icp_list.append("None")
    else:
        for ii in domain_list:
            res = requests.get(url+str(ii),headers=hearder,allow_redirects=False)
            res.encoding = 'utf-8'
            soup=BeautifulSoup(res.text,'html.parser')
            soup_p = soup.find_all('p')
            company_name = soup_p[12].text
            icp_list.append(company_name)
    icp_uniq_list = list(set(icp_list))
    icp_uniq_str = icp_uniq_list[0]
    
    return icp_uniq_str
