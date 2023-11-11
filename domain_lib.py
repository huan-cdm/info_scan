'''
Description:[域名扫描模块]
Author:[huan666]
Date:[2023/11/10]
'''
from config import fofaemail
from config import fofakey
from config import fofanum
import base64
import requests
import json
import re
import os
import sys
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
