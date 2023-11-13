'''
Description:[ip138信息查询]
Author:[huan666]
Date:[2023/11/12]
'''
import requests
from bs4 import BeautifulSoup

def ip138_scan(ip):
    url="https://site.ip138.com/"
    headers={
        'Cookie':'Hm_lvt_ecdd6f3afaa488ece3938bcdbb89e8da=1615729527; Hm_lvt_d39191a0b09bb1eb023933edaa468cd5=1617883004,1617934903,1618052897,1618228943; Hm_lpvt_d39191a0b09bb1eb023933edaa468cd5=1618567746',
        'Host':'site.ip138.com',
        'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36'
    }
    res=requests.get(url+ip,headers=headers,allow_redirects=False)
    res.encoding='utf-8'
    soup=BeautifulSoup(res.text,'html.parser')
    tag2=soup.find('ul',id="list")
    tag2_a = tag2.find_all('a')
    ip138_domain_list = []
   
    for j in tag2_a:
        ip138_domain_list.append(j.text)
    
    if len(ip138_domain_list) == 0:
        ip138_domain_list.append("None")
    
    return ip138_domain_list
