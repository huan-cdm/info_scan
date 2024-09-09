#!/usr/bin/env python3
"""
Pragram Name:[dirscan]
Description:[目录扫描子系统]
Author:[huan666]
Date:[2024/07/12]
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
from config import sub_username
from config import sub_password

app = Flask(__name__,template_folder='./templates')
app.secret_key = "DragonFire"
bootstrap = Bootstrap(app)


#跳转到目录扫描页面
@app.route("/dirscanpage/")
def dirscanpage():
    user1 = session.get('username1')
    if str(user1) == sub_username:
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
        

        
        #回显给前端的目录扫描数量
        dirsearch_count_tmp = os.popen('bash /TIP/info_scan/finger.sh dirsearchscancount').read()
        if int(dirsearch_count_tmp) == -2:
            dirsearch_count = "筛选前："+"暂无数据"
        else:
            dirsearch_count = "筛选前："+str(dirsearch_count_tmp)
       
        
        #目录扫描同步后的数量
        dirsearch_sync_value = os.popen('bash /TIP/info_scan/finger.sh dirsearchsyncresult').read()
        if int(dirsearch_sync_value) == -2:
            dirsearch_sync_value_result = "筛选后："+"暂无数据"
        else:
            dirsearch_sync_value_result = "筛选后："+str(dirsearch_sync_value)
    
        return render_template('dirsearchscan.html',data=dirsearch_list,
        data09=dir_list_status_code,data13=dirsearch_count,data18=dirsearch_sync_value_result)
    
    else:
        return render_template('sublogin.html')
    
#目录扫描后黑名单查询
@app.route("/QueryingBlacklist/",methods=['GET'])
def QueryingBlacklist():
    user1 = session.get('username1')
    if str(user1) == sub_username:
        try:
            db= pymysql.connect(host=dict['ip'],user=dict['username'],  
            password=dict['password'],db=dict['dbname'],port=dict['portnum']) 
            cur = db.cursor()
            sql="select name from scan_after_black order by id desc"
            cur.execute(sql)
            data = cur.fetchall()
            list_data = list(data)
            message_json = {
                "query_black_list":list_data
            }
            return jsonify(message_json)
        except:
            pass
    else:
        return render_template('sublogin.html')


#目录扫描前黑名单查询
@app.route("/queryingbeforeblacklist/",methods=['GET'])
def queryingbeforeblacklist():
    user1 = session.get('username1')
    if str(user1) == sub_username:
        #数据库连接部分
        db= pymysql.connect(host=dict['ip'],user=dict['username'],  
        password=dict['password'],db=dict['dbname'],port=dict['portnum']) 
        cur = db.cursor()
        
        #sql语句扫描前黑名单查询部分
        sql="SELECT vulnurl from scan_before_black order by id desc"
        cur.execute(sql)
        data = cur.fetchall()
        list_data1 = list(data)
        global query_before_black_list
        query_before_black_list = list_data1
        #sql语句扫描后黑名单查询部分
        sql_after = "select * from scan_after_black order by id desc"
        cur.execute(sql_after)
        data_after =  cur.fetchall()
        list_data_after = list(data_after)
        message_json = {
        "query_before_black_list":query_before_black_list,
        "query_before_black_list_len":"扫描前黑名单数量: "+str(len(query_before_black_list)),
        "query_after_black_list_len":"扫描后黑名单数量: "+str(len(list_data_after))
        }
        return jsonify(message_json)
    else:
        return render_template('sublogin.html')


#目录扫描白名单查看
@app.route("/QueryingWhitelist/",methods=['GET'])
def QueryingWhitelist():
    user1 = session.get('username1')
    if str(user1) == sub_username:
        try:
            db= pymysql.connect(host=dict['ip'],user=dict['username'],  
            password=dict['password'],db=dict['dbname'],port=dict['portnum']) 
            cur = db.cursor()
            sql="select name from scan_after_white order by id desc"
            cur.execute(sql)
            data1 = cur.fetchall()
            list_data1 = list(data1)
            message_json = {
                "query_white_list":list_data1
            }
            return jsonify(message_json)
           
        except:
            pass
    else:
        return render_template('sublogin.html')
    

#目录扫描启动
@app.route("/dirsearchscanfun/",methods=['post'])
def dirsearchscanfun():
    user1 = session.get('username1')
    if str(user1) == sub_username:
        filename = request.form['filename']
        thread = request.form['thread']
        statuscode = request.form['statuscode']
        level = request.form['level']
        dict = request.form['dict']
        dirsearchstatus_result = os.popen('bash /TIP/info_scan/finger.sh dirsearchstatus').read()
        if "running" in dirsearchstatus_result:

            dirsearch_status_result = "目录扫描程序正在运行中稍后再开启扫描"
        else:
            os.popen('bash /TIP/info_scan/finger.sh dirsearchscan'+''+' '+filename+''+' '+level+''+' '+statuscode+''+' '+dict+''+' '+thread+'')
            dirsearch_status_result = "目录扫描程序已开启稍后查看结果"
        
        message_json = {
            "dirsearch_status_result":dirsearch_status_result
        }

        return jsonify(message_json)
        
    else:
        return render_template('sublogin.html')
   

#目录扫描原始数据同步
@app.route("/dirsearchcopyfile/")
def dirsearchcopyfile():
    user1 = session.get('username1')
    if str(user1) == sub_username:
        os.popen('cp /TIP/info_scan/dirsearch/reports/*/* /TIP/info_scan/dirsearch/finalreport/dirsearchreport.txt')
        return render_template('dirsearchscan.html')
    else:
        return render_template('sublogin.html')


#目录扫描列表删除
@app.route("/cleardirvulmaptarget/")
def cleardirvulmaptarget():
    user1 = session.get('username1')
    if str(user1) == sub_username:
        os.popen('rm -rf /TIP/info_scan/dirsearch/finalreport/dirsearchreport.txt')
        os.popen('touch /TIP/info_scan/dirsearch/finalreport/dirsearchreport.txt')
        return render_template('dirsearchscan.html')
    else:
        return render_template('sublogin.html')


#目录扫描原始数据删除
@app.route("/origindataclearinterface/")
def origindataclearinterface():
    user1 = session.get('username1')
    if str(user1) == sub_username:
        os.popen('rm -rf /TIP/info_scan/dirsearch/reports/*')
        return render_template('dirsearchscan.html')
    else:
        return render_template('sublogin.html')



#后台结束目录扫描进程
@app.route("/killdirsearch/",methods=['post'])
def killdirsearch():
    user1 = session.get('username1')
    if str(user1) == sub_username:
        try:
            os.popen('bash /TIP/info_scan/finger.sh killdirsearch')
        except:
            pass
        dirsearchstatus_result = os.popen('bash /TIP/info_scan/finger.sh dirsearchstatus').read()
        if "stop" in dirsearchstatus_result:
            kill_dirsearch_result = "已关闭目录扫描程序"
        else:
            kill_dirsearch_result = "正在关闭中......"

        message_json = {
            "kill_dirsearch_result":kill_dirsearch_result
        
        }
        return jsonify(message_json)   
        
    else:
        return render_template('sublogin.html')




#报告阈值设置
@app.route("/filterthresholdvalue/",methods=['get'])
def filterthresholdvalue():
    user1 = session.get('username1')
    if str(user1) == sub_username:
        thresholdname = request.args['thresholdname']
        #重复数大于4的列表元素
        dir_no_swa_list_2 = []
        #无后缀的URL列表,原始数据。
        global dir_no_swa_list_1_1
        #遍历新列表dir_no_swa_list_1，利用count函数判断出现的次数，大于4次的，追加到新的列表中，用于去重使用。
        for d in dir_no_swa_list_1_1:
            #列表元素出现的次数
            num_m = dir_no_swa_list_1_1.count(d)
            #列表中次数大于等于5的存到列表dir_no_swa_list_2
            if num_m >= int(thresholdname):
                dir_no_swa_list_2.append(d)
        #利用集合set去重列表，存到列表dir_no_swa_list_2_removal中
        dir_no_swa_list_2_removal = list(set(dir_no_swa_list_2))
        
        #将全局的列表写入到文件中，屏蔽阈值使用。
        f = open(file='/TIP/info_scan/result/thresholdvalue.txt', mode='w')
        for ii in dir_no_swa_list_2_removal:
            f.write(str(ii)+"\n")
    
        #调用shell脚本进行屏蔽操作
        os.popen('bash /TIP/info_scan/finger.sh thresholdvaluefilter')
        return render_template('dirsearchscan.html')
    else:
        return render_template('sublogin.html')

#批量添加扫描前黑名单
@app.route("/scanbeforeinsertinterface/",methods=['POST'])
def scanbeforeinsertinterface():
    user1 = session.get('username1')
    if str(user1) == sub_username:
        db= pymysql.connect(host=dict['ip'],user=dict['username'],  
        password=dict['password'],db=dict['dbname'],port=dict['portnum'])
        cur = db.cursor()
        urls = request.get_json()
        urls_re_list = []
        for url in urls:
            #从http://www.xx.com/1.html中匹配出www.xx.com
            pattern = r"https?://([^/]+)"
            urls_re_1 = re.search(pattern,url)
            urls_re = urls_re_1.group(1)
            urls_re_list.append(urls_re)
        #存取入库结果文件
        insert_data_list = []
        for j in urls_re_list:
            #检查是否存在相同数据
            sql_select = "select * from scan_before_black where vulnurl = '%s' "%(j)
            cur.execute(sql_select)
            result = cur.fetchone()
            if result:
                url_value_result_11 = list(result)[1]
                #如果存在相同数据，返回当前查询到的一条数据回显给前端
                vuln_url_message1 = url_value_result_11+" "+"已存在，请不要重复进行入库操作"
                insert_data_list.append(vuln_url_message1)
                
            else:
                sql_insert = "insert into scan_before_black(vulnurl) values('%s')"%(j)
                cur.execute(sql_insert)
                db.commit()
                vuln_url_message2 = "扫描前黑名单"+url_value_result_11+"已入库成功"
                insert_data_list.append(vuln_url_message2)
        
        #逻辑判断 2023.11.01
        for jj in insert_data_list:
            if "已入库成功" in jj:
                insert_data_list_11 = "正在入库中......"
            else:
                insert_data_list_11 = "已入库完成!"
        global insert_data_list_result
        insert_data_list_result = insert_data_list_11
        return render_template('dirsearchscan.html')
    else:
        return render_template('sublogin.html')
    


@app.route("/scanbeforeinsertinterfacebyajax/",methods=['GET'])
def scanbeforeinsertinterfacebyajax():
    user1 = session.get('username1')
    if str(user1) == sub_username:
        global insert_data_list_result
    
        message_json = {
        "insert_data_list_result":insert_data_list_result
        }
        return jsonify(message_json)
    else:
        return render_template('sublogin.html')

#扫描前黑名单删除
@app.route("/deletedirsearcscanbeforehblackbyname/",methods=['POST'])
def deletedirsearcscanbeforehblackbyname():
    user1 = session.get('username1')
    if str(user1) == sub_username:
        db= pymysql.connect(host=dict['ip'],user=dict['username'],  
        password=dict['password'],db=dict['dbname'],port=dict['portnum']) 
        cur = db.cursor()
        vulnurl = request.form['vulnurl']
       
        sql="DELETE from scan_before_black WHERE vulnurl = '%s' " %(vulnurl)
        cur.execute(sql)
        db.commit()
        db.rollback()
        return render_template('dirsearchscan.html')
    else:
        return render_template('sublogin.html')


#扫描后黑名单删除
@app.route("/deletedirsearchblackbyname/",methods=['POST'])
def deletedirsearchblackbyname():
    user1 = session.get('username1')
    if str(user1) == sub_username:
        db= pymysql.connect(host=dict['ip'],user=dict['username'],  
        password=dict['password'],db=dict['dbname'],port=dict['portnum']) 
        cur = db.cursor()
        blackname = request.form['blackname']
       
        sql="DELETE from scan_after_black WHERE name = '%s' " %(blackname)
        cur.execute(sql)
        db.commit()
        db.rollback()
        return render_template('dirsearchscan.html')
    else:
        return render_template('sublogin.html')



#批量添加扫描后黑名单
@app.route("/scanafterinsertinterface/",methods=['POST'])
def scanafterinsertinterface():
    user1 = session.get('username1')
    if str(user1) == sub_username:
        #数据库连接信息
        db= pymysql.connect(host=dict['ip'],user=dict['username'],  
        password=dict['password'],db=dict['dbname'],port=dict['portnum'])
        cur = db.cursor()
        #接收前端传入的json数据
        urls = request.get_json()
        urls_re_list = []
        for url in urls:
            #从http://www.xx.com/1.html中匹配出www.xx.com
            pattern = r"https?://([^/]+)"
            urls_re_1 = re.search(pattern,url)
            urls_re = urls_re_1.group(1)
            urls_re_list.append(urls_re)
    
        #存取入库结果文件
        insert_data_list = []
        for p in urls_re_list:
            #检查是否存在相同数据
            sql_select = "select * from scan_after_black where name = '%s' "%(p)
            cur.execute(sql_select)
            result = cur.fetchone()
            if result:
                url_value_result_11 = list(result)[1]
                #如果存在相同数据，返回当前查询到的一条数据回显给前端
                vuln_url_message1 = url_value_result_11+" "+"已存在，请不要重复进行入库操作"
                insert_data_list.append(vuln_url_message1)
                
            else:
                sql_insert = "insert into scan_after_black(name) values('%s')"%(p)
                cur.execute(sql_insert)
                db.commit()
                vuln_url_message2 = "扫描后黑名单"+url_value_result_11+"已入库成功"
                insert_data_list.append(vuln_url_message2)
    
        #逻辑判断 2023.11.01
        for jj in insert_data_list:
            if "已入库成功" in jj:
                insert_data_list_22 = "正在入库中......"
            else:
                insert_data_list_22 = "已入库完成!"
    
        #定义全局变量用于前端在展示
        global insert_after_data_list_result
        insert_after_data_list_result = insert_data_list_22
    
        #生成文件用于过滤扫描结果
        sql1 = "select name from scan_after_black order by id desc"
        cur.execute(sql1)
        data1 = cur.fetchall()
        f = open(file='/TIP/info_scan/result/filterdirsearchblack.txt', mode='w')
        for ii in list(data1):
            for jj in ii:
                f.write(str(jj)+"\n")
    
        return render_template('dirsearchscan.html')
    
    else:
        return render_template('sublogin.html')


@app.route("/scanafterinsertinterfacebyajax/",methods=['GET'])
def scanafterinsertinterfacebyajax():
    user1 = session.get('username1')
    if str(user1) == sub_username:
        global insert_after_data_list_result
    
        message_json = {
        "insert_after_data_list_result":insert_after_data_list_result
        }
        return jsonify(message_json)
    else:
        return render_template('sublogin.html')

#报告过滤黑名单同步
@app.route("/blacklistsync/",methods=['get'])
def blacklistsync():
    user1 = session.get('username1')
    if str(user1) == sub_username:
        os.popen('bash /TIP/info_scan/finger.sh blacklistsyncshell')
        return render_template('dirsearchscan.html')
    else:
        return render_template('sublogin.html')


#目录扫描原始日志信息
@app.route("/queryorigindatainterface/",methods=['post'])
def queryorigindatainterface():
    user1 = session.get('username1')
    if str(user1) == sub_username:
        url_data = request.form['url_data']
        try:
            list_result = []
            global global_item_origin_data
            file_result = open('/TIP/info_scan/dirsearch/finalreport/dirsearchreport.txt',encoding='utf-8')
            #将文件存到列表中用于检索
            for line in file_result.readlines():
                list_result.append(line)
            #前端传入的字符在列表中查找，查找到显示完整的字符串
            for item in list_result:
                if url_data in item:
                    global_item_origin_data_1 = item
            
            global_item_origin_data = "原始数据："+global_item_origin_data_1
            global global_item_origin_data_12
            global_item_origin_data_12 = global_item_origin_data
            return render_template('dirsearchscan.html')
    
        except Exception as e:
            print("捕获到异常:", e)
    else:
        return render_template('sublogin.html')

@app.route("/queryorigindatainterfacebyajax/",methods=['GET'])
def queryorigindatainterfacebyajax():
    user1 = session.get('username1')
    if str(user1) == sub_username:
        global global_item_origin_data_12
    
        message_json = {
        "global_item_origin_data":global_item_origin_data_12
       
        }
        return jsonify(message_json)
    else:
        return render_template('sublogin.html')


#跳转登录页
@app.route("/subloginpage/")
def subloginpage():
    return render_template('sublogin.html')



# @app.route('/sublogininterface/',methods=['post'])
# def sublogininterface():
#     username = request.form['username']
#     password = request.form['password']
#     if str(username) == str(sub_username) and str(password) == str(sub_password):
#         session['username1'] = username
#         return redirect("/dirscanpage/")
#     else:
#         return render_template('sublogin.html',data1="账号或者密码错误")
    




#登录实现
@app.route('/sublogininterface/',methods=['post'])
def sublogininterface():
    username = request.form['username']
    password = request.form['password']
    
    # 登录判断
    if str(username) == str(sub_username) and str(password) == str(sub_password):
        session['username1'] = username
        login_status = "账号密码正确确认登录系统吗？"
        redirecturl = '/dirscanpage/'

    elif str(username) == str(sub_username) and str(password) != str(sub_password):
        login_status = "密码错误"
        redirecturl = '/subloginpage/'
    elif str(username) != str(sub_username) and str(password) == str(sub_password):
        login_status = "账号不存在"
        redirecturl = '/subloginpage/'
    else:
        login_status = "登录失败"
        redirecturl = '/subloginpage/'

    message_json = {
        'subloginstatus':login_status,
        'subredirect_url':redirecturl,
        'subnologin':'/subloginpage/'
    }    
       
    return jsonify(message_json)



    


#注销系统
@app.route('/subsignout/',methods=['get'])
def subsignout():
    try:
         session['username1'].clear()
    except Exception as e:
        print("捕获到异常:",e)
    message_json = {
        'subzhuxiaostatus':'确认退出系统吗？',
        'subzhuxiaoredirect_url':'/subloginpage/'
    }    
       
    return jsonify(message_json)


if __name__ == '__main__':  
    app.run(host="127.0.0.1",port=8088)
