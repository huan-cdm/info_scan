'''
Description:[通过域名提取历史url接口]
Author:[huan666]
Date:[2024/01/03]
'''
import requests
import json


def historyurl(domain_list):
    headers={
        'Cookie':'Hm_lvt_ecdd6f3afaa488ece3938bcdbb89e8da=1615729527; Hm_lvt_d39191a0b09bb1eb023933edaa468cd5=1617883004,1617934903,1618052897,1618228943; Hm_lpvt_d39191a0b09bb1eb023933edaa468cd5=1618567746',
        'Host':'otx.alienvault.com',
        'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36'
    }
    
    for domain in domain_list:
        url = "https://otx.alienvault.com/api/v1/indicators/domain/"+domain+"/url_list?limit=500&page=1"
        res = requests.get(url,headers=headers,allow_redirects=False)
        res.encoding='utf-8'
        restext = res.text
        resdic=json.loads(restext)
        data = resdic['url_list']
        result = []
        for item in data:
            result.append(item['url'])
        
        return result