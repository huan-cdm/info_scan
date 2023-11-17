'''
Description:[网站标题查询]
Author:[huan666]
Date:[2023/11/17]
'''
import requests
import re

def title_scan(url):
    
    hearder={
        'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)'
    }

    try:
        
        res = requests.get(url,headers=hearder,allow_redirects=False)
        res.encoding='utf-8'
        title_1 = re.findall("<title>.*</title>",res.text)
        title_11 = title_1[0]
        title_2 = title_11.replace("<title>","")
        titleinfo = title_2.replace("</title>","")
        return titleinfo
    except:
        pass
