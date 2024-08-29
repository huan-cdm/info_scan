'''
Description:[自定义漏洞扫描函数]
Author:[huan666]
Date:[2024/8/28]
update:[2024/8/28]
'''
import requests
import basic
import sys
from datetime import datetime

# es未授权访问漏洞批量检测
def es_unauthorized():

    hearder={
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)'
    }

    # 资产文件存入列表
    url_list = basic.url_file_ip_list()

    # 提取es资产存入列表
    try:
        es_url_list = []
        for i in url_list:
            if ':9200' in i:
                es_url_list.append(i)
    except Exception as e:
        print("捕获到异常:", e)
    
    # 循环es资产列表判断是否存在未授权访问漏洞
    for url in es_url_list:
        # 获取当前时间
        now = datetime.now()

        # 格式化时间，只保留时、分、秒
        formatted_time = now.strftime("%H:%M:%S")

        try:
            # 忽略ssl证书验证
            res = requests.get(url,headers=hearder,allow_redirects=False,timeout=2,verify=False)
            res.encoding='utf-8'
            restext = res.text
            if 'cluster_name' and 'cluster_uuid' and 'version' in restext:
                print("[+]"+" "+formatted_time+" "+"目标："+" "+url+" "+"存在未授权访问漏洞")
            else:
                print("[-]"+" "+formatted_time+" "+"目标："+" "+url+" "+"不存在未授权访问漏洞")
        except:
            print("[-]"+" "+formatted_time+" "+"目标："+" "+url+" "+"网络不可达无法确认是否存在未授权访问漏洞")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        func_name = sys.argv[1]
        if func_name == 'es_unauthorized':
            es_unauthorized()
        else:
            print("Invalid function number")
    else:
        print("No function number provided")