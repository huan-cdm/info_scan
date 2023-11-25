'''
Description:[高德地图API模块]
Author:[huan666]
Date:[2023/11/25]
'''
import requests
import json
from config import gaodekey

def gaodescan(keyvalue):

    
    url = "https://restapi.amap.com/v3/place/text?keywords="+keyvalue+"&offset=20&page=1&key="+gaodekey+"&extensions=all"
    hearder={
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)'
        }
    try:
        res = requests.get(url,headers=hearder,allow_redirects=False)
        res.encoding='utf-8'
        restext = res.text
        resdic=json.loads(restext)
        return resdic['pois'][0]['address']
    except:
        pass