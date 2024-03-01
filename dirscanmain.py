#!/usr/bin/env python3
"""
Pragram Name:[flask_cnvd]
Description:[信息收集系统]
Author:[huan666]
Date:[2021/08/01 12:08]
"""
#----------------------------------------------------------------------------------------#
from operator import imod
from flask import Flask
from flask import  render_template
from flask import request
from flask import session
from flask import redirect
from flask import send_from_directory
from flask import make_response
from flask import jsonify
import pymysql
import time
from flask_bootstrap import Bootstrap
import os
import requests
from bs4 import BeautifulSoup
import re
import base64
import json
import subprocess
from config import dict

app = Flask(__name__,template_folder='./templates')
app.secret_key = "DragonFire"
bootstrap = Bootstrap(app)


#跳转到目录扫描页面
@app.route("/dirscanpage/")
def dirscanpage():
    dirsearch_list = [] #回显给前端的处理后数据，不带http状态码(2023.05.29修改data)。
    dir_list_status_code = [] #回显给前端的原始数据，带http状态码。
    dir_no_swa_list = []
    
    #无后缀的URL列表
    dir_no_swa_list_1 = []
    global dir_no_swa_list_1_1
    dir_no_swa_list_1_1 = dir_no_swa_list_1
    dirsearch_file = open('/TIP/info_scan/dirsearch/finalreport/dirsearchreport.txt',encoding='utf-8')
    for line in dirsearch_file.readlines():
        dir_list_status_code.append(line)
        #捕获异常，报错直接PASS
        try:
            dirsearch_re = re.findall("http://.*|https://.*",line)
            dirsearch_list.append(dirsearch_re[0])
        except:
            pass
    #遍历不带状态码的URL列表,利用正则匹配出http://www.baidu.com/
    for b in dirsearch_list:
        no_swa = re.findall("http://.*?/|https://.*?/",b)
        dir_no_swa_list.append(no_swa)
    for c in dir_no_swa_list:
        dir_no_swa_list_1.append(c[0])
    
    #文件清洗服务运行状态
    file_clean_status = os.popen('bash ./finger.sh fileclean').read()
    #单条数据回显给前端
    try:
        db= pymysql.connect(host=dict['ip'],user=dict['username'],  
        password=dict['password'],db=dict['dbname'],port=dict['portnum']) 
        cur = db.cursor()
        sql="select url,id from scan_table order by id desc"
        cur.execute(sql)
        dirdata = cur.fetchall()
    except:
        pass
    #回显给前端的目标文件行数
    num = os.popen('bash ./finger.sh dirsearchtargetnum').read()
    
    num_1 = "URL数量: "+" "+str(num)
    
    #回显给前端的目录扫描数量
    dirsearch_count_tmp = os.popen('bash ./finger.sh dirsearchscancount').read()
    if int(dirsearch_count_tmp) == -2:
        dirsearch_count = "目录数量（过滤前）："+"目前暂无漏洞"
    else:
        dirsearch_count = "目录数量（过滤前）："+str(dirsearch_count_tmp)
   
    
     #目录扫描同步后的数量
    dirsearch_sync_value = os.popen('bash ./finger.sh dirsearchsyncresult').read()
    dirsearch_sync_value_result = "目录数量（过滤后）："+str(dirsearch_sync_value)

    return render_template('dirsearchscan.html',data=dirsearch_list,data6=dirdata,data7=num_1,
    data09=dir_list_status_code,data13=dirsearch_count,data20=file_clean_status,
    data18=dirsearch_sync_value_result)




#目录扫描后黑名单查询
@app.route("/QueryingBlacklist/",methods=['GET'])
def QueryingBlacklist():
    try:
        db= pymysql.connect(host=dict['ip'],user=dict['username'],  
        password=dict['password'],db=dict['dbname'],port=dict['portnum']) 
        cur = db.cursor()
        sql="select name from blacklist_table order by id desc"
        cur.execute(sql)
        data = cur.fetchall()
        list_data = list(data)
        message_json = {
            "query_black_list":list_data
        }
        return jsonify(message_json)
    except:
        pass



#目录扫描前黑名单查询
@app.route("/queryingbeforeblacklist/",methods=['GET'])
def queryingbeforeblacklist():
    
    #数据库连接部分
    db= pymysql.connect(host=dict['ip'],user=dict['username'],  
    password=dict['password'],db=dict['dbname'],port=dict['portnum']) 
    cur = db.cursor()
    
    #sql语句扫描前黑名单查询部分
    sql="SELECT vulnurl from vuln_url_table order by id desc"
    cur.execute(sql)
    data = cur.fetchall()
    list_data1 = list(data)
    global query_before_black_list
    query_before_black_list = list_data1
    #sql语句扫描后黑名单查询部分
    sql_after = "select * from blacklist_table order by id desc"
    cur.execute(sql_after)
    data_after =  cur.fetchall()
    list_data_after = list(data_after)
    message_json = {
    "query_before_black_list":query_before_black_list,
    "query_before_black_list_len":"扫描前黑名单数量: "+str(len(query_before_black_list)),
    "query_after_black_list_len":"扫描后黑名单数量: "+str(len(list_data_after))
    }
    return jsonify(message_json)



#目录扫描白名单查看
@app.route("/QueryingWhitelist/",methods=['GET'])
def QueryingWhitelist():
    try:
        db= pymysql.connect(host=dict['ip'],user=dict['username'],  
        password=dict['password'],db=dict['dbname'],port=dict['portnum']) 
        cur = db.cursor()
        sql="select name from whitelist_table order by id desc"
        cur.execute(sql)
        data1 = cur.fetchall()
        list_data1 = list(data1)
        message_json = {
            "query_white_list":list_data1
        }
        return jsonify(message_json)
       
    except:
        pass


#目录扫描启动
@app.route("/dirsearchscanfun/",methods=['post'])
def dirsearchscanfun():
    
    filename = request.form['filename']
    thread = request.form['thread']
    statuscode = request.form['statuscode']
    level = request.form['level']
    dict = request.form['dict']

    os.popen('bash ./finger.sh dirsearchscan'+''+' '+filename+''+' '+level+''+' '+statuscode+''+' '+dict+''+' '+thread+'')
    return render_template('dirsearchscan.html')
   

#目录扫描原始数据同步
@app.route("/dirsearchcopyfile/")
def dirsearchcopyfile():
    os.popen('cp /TIP/info_scan/dirsearch/reports/*/* /TIP/info_scan/dirsearch/finalreport/dirsearchreport.txt')
    return render_template('dirsearchscan.html')



#目录扫描列表删除
@app.route("/cleardirvulmaptarget/")
def cleardirvulmaptarget():
    os.popen('rm -rf /TIP/info_scan/dirsearch/finalreport/dirsearchreport.txt')
    os.popen('touch /TIP/info_scan/dirsearch/finalreport/dirsearchreport.txt')
    return render_template('dirsearchscan.html')


#目录扫描原始数据删除
@app.route("/origindataclearinterface/")
def origindataclearinterface():
    os.popen('rm -rf /TIP/info_scan/dirsearch/reports/*')
    return render_template('dirsearchscan.html')

    
   

if __name__ == '__main__':  
    app.run(host="127.0.0.1",port=8088)