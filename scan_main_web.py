#!/usr/bin/python3
from flask import Flask, render_template,request
from flask import session
from flask import redirect
from flask_bootstrap import Bootstrap
from flask import send_file
import basic
import subprocess
import os
import re
from flask import jsonify
import report_total
import pandas as pd
from basic import root_domain_scan
#主系统账号密码配置导入
from config import main_username
from config import main_password
# 高危资产数量规则
from config import Shiro_rule
from config import SpringBoot_rule
from config import weblogic_rule
from config import baota_rule
from config import ruoyi_rule
from config import struts2_rule
from config import WordPress_rule
from config import jboss_rule
from config import phpMyAdmin_rule
from config import ThinkPHP_rule
from config import nacos_rule
from config import fanwei_rule
from config import tomcat_rule
from config import finger_list
from config  import rule_options
from config import dict
from basic import select_rule
import psutil
import pymysql


# 导入时间模块
import time
import datetime

# 扫面时间差控制
from config import info_time_controls
from config import vuln_time_controls

# 弱口令扫描字典
from config import mysql_dict_user_dir
from config import mysql_dict_pass_dir
from config import ssh_dict_user_dir
from config import ssh_dict_pass_dir
from config import ftp_dict_user_dir
from config import ftp_dict_pass_dir
from config import redis_dict_pass_dir
from config import mssql_dict_user_dir
from config import mssql_dict_pass_dir
from config import tomcat_user_dir
from config import tomcat_pass_dir
from config import nacos_user_dir
from config import nacos_pass_dir
from config import bcrypt_dict
from config import bcrypt_passwd

# 统计列表元素出现次数
from collections import Counter

# 统计第三方接口查询次数
fofa_max_num = basic.customize_interface_totalnum(1)
shodan_max_num = basic.customize_interface_totalnum(2)
crt_max_num =  basic.customize_interface_totalnum(3)
icp_max_num = basic.customize_interface_totalnum(4)
amap_max_num = basic.customize_interface_totalnum(5)
otx_max_num = basic.customize_interface_totalnum(6)

# 多线程操作模块
import threading

# 删除漏洞扫描报告二次验证
from config import recheck_username
from config import recheck_password

from config_session import PERMANENT_SESSION_LIFETIME

# 资产格式校验
assetverification = basic.verification_table_lib(1)
import json

# 校验是否先进行指纹识别
from config import verification_fingerprint_recognition

import shodan

from vuln_lib import get_time_period_lib

app = Flask(__name__,template_folder='./templates') 
app.config.from_pyfile('config_session.py')
app.secret_key = "DragonFire"
bootstrap = Bootstrap(app)


# 执行任何请求之前先执行此函数
@app.before_request
def before_request():
    # 在每个请求之前调用，更新session的过期时间
    session.permanent = True
    app.permanent_session_lifetime = PERMANENT_SESSION_LIFETIME

#IP基础信息查询
@app.route("/ipscaninterface/",methods=['post'])
def ipscaninterface():
    user = session.get('username')
    if str(user) == main_username:
        ip = request.form['ip']
        
        #状态码为200的url
        try:
            data1=basic.status_scan(ip)
        except:
            pass
    
        #状态码为200的url指纹信息
        try:
            data3 = basic.finger_scan(ip)
        except:
            pass
    
        #icp备案信息-列表返回
        try:
            # data4 = basic.icp_info(ip)
            data4_1 = basic.icp_info_new(ip)
            if data4_1 == ['']:
                data4 = basic.icp_info(ip)
            else:
                data4 = data4_1
            # print(len(data4))
            # print(data4)
        except:
            pass
    
        #公司位置信息
        gd_inter_num_success = basic.total_port_success_num(5)
        gd_inter_num_fail = basic.total_port_fail_num(5)
        amap_total = int(gd_inter_num_success) + int(gd_inter_num_fail)
        if amap_total > int(amap_max_num):
            companylocation = ["高德地图接口次数已超过额度"+str(amap_max_num)+"次,无法继续查询,请后台修改额度继续查询"]
        else:
            try:
               
                # 判断传递过来的公司名称是否有效
                company_name = data4[0]
                if company_name == "ICP备案接口正在更新维护中":
                    companylocation = ["未获取到公司名称,无法查询地理位置信息"]
                else:
                    companylocation = basic.amapscan(data4)
                basic.success_third_party_port_addone(5)
            except:
                companylocation = "接口异常"
                basic.fail_third_party_port_addone(5)
        
        #ip归属地
        try:
            output = subprocess.check_output(["sh", "./finger.sh","location",ip], stderr=subprocess.STDOUT)

            output_list = output.decode().splitlines()
            #定义列表
            location_list = []
            for ii in output_list:
                if "地址" in ii:
                    location_list.append(ii)
            localtion_list_1 = location_list[0].replace("地址","")
            localtion_list_result = localtion_list_1.replace(":","")
        except:
            localtion_list_result = "接口异常"
        
        #端口信息
        try:
            port = basic.shodan_api(ip)
            basic.success_third_party_port_addone(1)
            basic.success_third_party_port_addone(2)
        except:
            basic.fail_third_party_port_addone(1)
            basic.fail_third_party_port_addone(2)
    
        #历史域名
        try:
            history_domain = basic.domain_scan(ip)
        except:
            history_domain=["接口异常"]
    
        #操作系统识别
        try:
            os_type = os.popen('bash /TIP/info_scan/finger.sh osscan'+' '+ip).read()
        except:
            pass
        
        try:
            #去掉https://或者http://
            urls_list_1 = [re.sub(r'http://|https://', '', url) for url in data1]
        except:
            pass
       
        # 存活域名列表
        try:
            urls_list = []
            for aa in urls_list_1:
                if "cn" in aa or "com" in aa or "xyz" in aa or "top" in aa:
                    urls_list.append(aa)
        except:
            pass


        #定义存放cdn结果列表
        cdn_list = []
        #定义存放子域名的列表
        subdomain_list_1 = []
        
        urls_list_root = root_domain_scan(urls_list)
        for bb in urls_list:
            #cdn存放结果
            cdn_result = basic.cdnscan(bb)
            cdn_list.append(cdn_result)

        for ab in urls_list_root:
            #子域名存放列表
            subdomain_result = basic.subdomain_scan(ab)
            subdomain_list_1.append(subdomain_result)
        try:
            flattened_list = [item for sublist in subdomain_list_1 for item in sublist]
            
        except:
            pass
       
        #CDN列表为空判断
        if len(cdn_list) == 0:
            cdn_list.append("None")
        
    
        #子域名列表去重
        subdomain_list = list(set(flattened_list))
        if len(subdomain_list) ==0:
            subdomain_list.append("None")
        
    
        #网站标题
        try:
            site_title_list_result = basic.title_scan(data1)
        except:
            pass
    
        
        #IP属性判断
        try:
            ipstatus = basic.ipstatus_scan(ip)
        except:
            pass
        
        period_time = get_time_period_lib()
    
        return render_template('index.html',data1=data1,data2=ip,data3=data3,data4=data4
        ,data5=localtion_list_result,data6=port,data7=history_domain,data8=os_type,data9=cdn_list
        ,data10=site_title_list_result,data11=subdomain_list,data12=ipstatus,data13=companylocation,data20=str(user),data30 = str(period_time))
    else:
        return render_template('login.html')

#跳转首页
@app.route("/index/")
def index():
    user = session.get('username')
    if str(user) == main_username:

        asset_file_list = basic.fofa_grammar_lib()
        period_time = get_time_period_lib()
        # 判断是否开启JNDI
        jndi_status = os.popen('bash /TIP/info_scan/finger.sh jndi_server_status').read()
        jndi_python_status = os.popen('bash /TIP/info_scan/finger.sh jndi_python_server_status').read()
        if "running" in jndi_status and "running" in jndi_python_status:
            jndi_status_result = "1. JNDI监控服务已启动。"
        else:
            jndi_status_result = "1. JNDI监控服务未启动，一些检测功能将会受到限制。"

        # 判断时候开启MySQL
        mysql_status = os.popen('bash /TIP/info_scan/finger.sh mysql_server_status').read()
        if "running" in mysql_status:
            mysql_status_result = "2. MySQL服务已启动。"
        else:
            mysql_status_result = "2. MySQL服务未启动，系统部分功能将会受到限制。"
        
        # 判断是否开启资产格式校验
        verification_status = basic.verification_table_lib(1)
        if "已开启校验" == verification_status:
            assets_status_result = "3. 资产校验已启动，只允许输入URL格式资产。"
        else:
            assets_status_result = "3. 资产校验未启动，允许输入任意格式资产。"
        return render_template('index.html',data20=str(user),data21=asset_file_list,data30 = str(period_time),data31=str(jndi_status_result),data32=str(mysql_status_result),data33=str(assets_status_result))
    else:
        return render_template('login.html')



#主系统登录实现
@app.route('/logininterface/',methods=['post'])
def logininterface():
    username = request.form['username']
    password = request.form['password']
    
    # 登录判断
    if str(username) == str(main_username) and str(password) == str(main_password):

        session['username'] = username
        # session.permanent = True  # 确保会话是永久的
        login_status = "账号密码正确确认登录系统吗？"
        redirecturl = '/index/'

    elif str(username) == str(main_username) and str(password) != str(main_password):
        login_status = "密码错误"
        redirecturl = '/loginpage/'
    elif str(username) != str(main_username) and str(password) == str(main_password):
        login_status = "账号不存在"
        redirecturl = '/loginpage/'
    else:
        login_status = "登录失败"
        redirecturl = '/loginpage/'

    message_json = {
        'loginstatus':login_status,
        'redirect_url':redirecturl,
        'nologin':'/loginpage/'
    }    
       
    return jsonify(message_json)
    



#历史URL预览
@app.route("/previewhistoryurl/")
def previewhistoryurl():
    user = session.get('username')
    if str(user) == main_username:
        otx_his_num = os.popen('bash /TIP/info_scan/finger.sh otx_history_url_num').read()
        otx_domain_url_shell_status = os.popen('bash /TIP/info_scan/finger.sh otx_domain_url_shell_status').read()
        if "running" in otx_domain_url_shell_status:
            lines = ["正在扫描中......"]
        else:
            if int(otx_his_num) == 0:
                lines = ["未发现漏洞"]
            else:
                lines = []
                with open('/TIP/info_scan/result/otxhistoryurl.txt', 'r') as f:
                    for line in f:
                        lines.append(line.strip())
        return '<br>'.join(lines)
    else:
        return render_template('login.html')
    
    


#nmap接口预览
@app.route("/nmapresultshow/")
def nmapresultshow():
    user = session.get('username')
    if str(user) == main_username:
        nmap_num = os.popen('bash /TIP/info_scan/finger.sh nmap_scan_num').read()
        nmapstatus =os.popen('bash /TIP/info_scan/finger.sh nmapstatus').read()
        if "running" in nmapstatus:
            lines = ["正在扫描中......"]
        else:
            if int(nmap_num) == 0:
                lines = ["未发现漏洞"]
            else:
                lines = []
                with open('./result/nmap.txt', 'r') as f:
                    for line in f:
                        lines.append(line.strip())
        return '<br>'.join(lines)
    else:
        return render_template('login.html')


#nuclei结果预览
@app.route("/nucleiresultshow/")
def nucleiresultshow():
    user = session.get('username')
    if str(user) == main_username:
        nuclei_num = os.popen('bash /TIP/info_scan/finger.sh nuclei_scan_num').read()
        nucleistatus =os.popen('bash /TIP/info_scan/finger.sh nucleistatus').read()
        if "running" in nucleistatus:
            liness = ["正在扫描中......"]
        else:
            if int(nuclei_num) == 0:
                liness = ["未发现漏洞"]
            else:
                lines = []
                with open('./result/nucleiresult.txt', 'r') as f:
                    for line in f:
                        lines.append(line.strip())
                 #文件结果优化展示
                liness = []
                for line1 in lines:
                    
                    #页面显示优化
                    pattern = re.compile(r'\x1b\[[0-9;]*m')
                    clean_text = pattern.sub('', line1)
                    liness.append(clean_text)
            
        return '<br>'.join(liness)
    else:
        return render_template('login.html')


#前端文本框添加URL后端接口
@app.route('/submit_data/', methods=['POST'])  
def submit_data():
    user = session.get('username')
    if str(user) == main_username: 
        # 筛选后资产时间线更新
        basic.assets_status_update('手工录入资产完成')
        data = request.json.get('lines', [])

        if '' in  data:
            result_rule = "输入参数不能为空"

        if ' ' in data:
            result_rule = "输入参数不能包含空格"

        if 'alert' in data or 'select' in data or '<' in data or '>' in data or 'union' in data:
            result_rule = "请勿进行安全测试！"

        else:
            
            result_rule = ""
            if assetverification == "已开启校验":
                for ii in data:
                    if "http://"  not in ii and "https://" not in ii:
                        result_rule = "请勿输入非URL资产！！！"
                        break
            if not result_rule:
                # 列表中数据存入文件中
                f = open(file='/TIP/batch_scan_domain/url.txt',mode='w')
                for line in data:
                    f.write(str(line)+"\n")
                f.close()
                # 存入资产项目管理目录,前端通过下拉列表查看资产,以当前时间戳命名文件名
                # 获取当前时间
                now = datetime.datetime.now()
                # 获取年月日时分秒，并确保月份和日期有两位数字
                year = str(now.year)
                month = now.month if now.month > 9 else f"0{now.month}"
                day = now.day if now.day > 9 else f"0{now.day}"
                hour = now.hour if now.hour > 9 else f"0{now.hour}"
                minute = now.minute if now.minute > 9 else f"0{now.minute}"
                second = now.second if now.second > 9 else f"0{now.second}"
                
                # 构建文件名
                file_name = f"{year}/{month}/{day}{hour}:{minute}:{second}.txt"
                file_name_result = f"/TIP/info_scan/result/assetmanager/{file_name}"
                # 确保目录存在
                os.makedirs(os.path.dirname(file_name_result), exist_ok=True)
                
                # 打开文件并写入数据
                with open(file=file_name_result, mode='w') as f21:
                    for line21 in data:
                        f21.write(str(line21) + "\n")

                file_line = os.popen('bash /TIP/info_scan/finger.sh textarea_url_num').read()
                result_rule = "已成功添加"+str(file_line)+"条资产"
                #资产备份
                os.popen('cp /TIP/batch_scan_domain/url.txt /TIP/batch_scan_domain/url_back.txt')
            
        message_json = {
            "file_line":result_rule
        }
        return jsonify(message_json)
    else:
        return render_template('login.html')
   


# 实时查询路由运行状态
@app.route("/inter_route_status/")
def inter_route_status():
    user = session.get('username')
    if str(user) == main_username:
        fofa_status = basic.route_status_show_lib(1)
        if int(fofa_status) == 0:
            fofa_status_result1 = "资产正在收集中"
            fofa_status_result2 = ""
        elif int(fofa_status) == 1:
            fofa_status_result1 = ""
            fofa_status_result2 = "资产已收集完"
        message_json = {
            "fofa_status1":fofa_status_result1,
            "fofa_status2":fofa_status_result2
        }
        return jsonify(message_json)
    else:
        return render_template('login.html')



# 开启存活检测
@app.route("/filterstatuscodebyhttpx/",methods=['GET'])
def filterstatuscodebyhttpx():
    user = session.get('username')
    if str(user) == main_username:
        # 筛选后资产时间线更新
        basic.assets_status_update('存活检测已完成')
        # 存活检测程序用时统计相关
        basic.scan_total_time_start_time(25)
        httpx_status_result = basic.httpsurvival_lib()
        # 在后台单独启动1个线程实时判断扫描器停止时间
        def httxscanendtime():
            while True:
                time.sleep(1)
                basic.scan_total_time_final_end_time(25)
        threading.Thread(target=httxscanendtime).start()

        message_json = {
            "httpx_status_result":httpx_status_result
        }
        return jsonify(message_json)
    else:
        return render_template('login.html')
    

# 关闭存活检测
@app.route("/stopfilterstatuscodebyhttpx/",methods=['GET'])
def stopfilterstatuscodebyhttpx():
    user = session.get('username')
    if str(user) == main_username:
        
        stop_httpx_status_result = basic.stop_httpsurvival_lib()

        message_json = {
            "stop_httpx_status_result":stop_httpx_status_result
        }
        return jsonify(message_json)
    else:
        return render_template('login.html')
    

# 关闭资产扩展
@app.route("/stopassetextendinterface/",methods=['GET'])
def stopassetextendinterface():
    user = session.get('username')
    if str(user) == main_username:
        
        stop_extend_status_result = basic.stop_assets_extend_lib()

        message_json = {
            "stop_extend_status_result":stop_extend_status_result
        }
        return jsonify(message_json)
    else:
        return render_template('login.html')


#跳转登录页
@app.route("/loginpage/")
def loginpage():
    return render_template('login.html')

#注销系统
@app.route('/signout/',methods=['get'])
def signout():
    try:
        session.clear()
    except Exception as e:
        print("捕获到异常:",e)
    message_json = {
        'zhuxiaostatus':'确认退出系统吗？',
        'zhuxiaoredirect_url':'/index/'
    }    
       
    return jsonify(message_json)


# 开启CDN检测
@app.route('/cdn_service_recogize/',methods=['get'])
def cdn_service_recogize():
    user = session.get('username')
    if str(user) == main_username:
        # 筛选后资产时间线更新
        basic.assets_status_update('CDN检测已完成')
        cdn_status = os.popen('bash /TIP/info_scan/finger.sh cdn_status').read()
        if "running" in cdn_status:
            cdn_status_result = "CDN检测程序正在运行中请勿重复提交"
        else:
            os.popen('bash /TIP/info_scan/finger.sh start_cdn')
            cdn_status_result = "CDN检测程序已开启成功"
        message_json = {
            "cdn_status_result":cdn_status_result
        }
        return jsonify(message_json)
    else:
        return render_template('login.html')


# 关闭CDN检测
@app.route("/stopcdndetection/",methods=['GET'])
def stopcdndetection():
    user = session.get('username')
    if str(user) == main_username:
        
        stop_cdn_status_result = basic.stop_cdnsurvival_lib()

        message_json = {
            "stop_cdn_status_result":stop_cdn_status_result
        }
        return jsonify(message_json)
    else:
        return render_template('login.html')


#资产回退
@app.route("/assetsbackspaceinterface/")
def assetsbackspaceinterface():
    user = session.get('username')
    if str(user) == main_username:
        # 筛选后资产时间线更新
        basic.assets_status_update('资产回退已完成')
        url_list = basic.url_file_ip_list()
        url_back_list = basic.url_back_file_ip_list()
        # 比较资产列表长度判断是否回退成功
        if len(url_list) == len(url_back_list):
            returnresult = "资产已回退到初始版本"
        else:
            returnresult = "资产已回退到初始版本"
        message_json = {
            "returnresult":returnresult
        }
        return jsonify(message_json)
    else:
        return render_template('login.html')
    
    

#weblogic_poc扫描结果预览
@app.route("/weblogic_poc_report/")
def weblogic_poc_report():
    user = session.get('username')
    if str(user) == main_username:
        weblogic_num = os.popen('bash /TIP/info_scan/finger.sh weblogic_scan_num').read()
        weblogicstatus = os.popen('bash /TIP/info_scan/finger.sh weblogic_status').read()
        if "running" in weblogicstatus:
            lines = ["正在扫描中......"]
        else:
            if int(weblogic_num) ==0:
                lines = ["未发现漏洞"]
            else:
                lines = []
                with open('./result/weblogic_poc.txt', 'r') as f:
                    for line in f:
                        lines.append(line.strip())
        return '<br>'.join(lines)
    else:
        return render_template('login.html')



#struts2漏洞扫描结果预览
@app.route("/struts2_poc_report/")
def struts2_poc_report():
    user = session.get('username')
    if str(user) == main_username:
        struts2_num = os.popen('bash /TIP/info_scan/finger.sh struts2_scan_num').read()
        struts2status = os.popen('bash /TIP/info_scan/finger.sh struts2_status').read()
        if "running" in struts2status:
            lines = ["正在扫描中......"]
        else:
            if int(struts2_num) ==0:
                lines = ["未发现漏洞"]
            else:
                lines = []
                with open('./result/struts2_poc.txt', 'r') as f:
                    for line in f:
                        lines.append(line.strip())
        return '<br>'.join(lines)
    else:
        return render_template('login.html')
    



# 报告整合
@app.route("/report_total_interface/")
def report_total_interface():
    user = session.get('username')
    if str(user) == main_username:
        total_report_status = os.popen('bash /TIP/info_scan/finger.sh totalreport_num').read()
        if int(total_report_status) == 1:
            total_report_status_result = "报告正在整合中不要重复点击"
        else:
            # 创建一个新线程来执行报告整合脚本
            def run_report():
                # 执行报告整合脚本
                report_total.report_xlsx()
            threading.Thread(target=run_report).start()
            if int(total_report_status) == 2:
                total_report_status_result = "报告已整合完成"
            elif int(total_report_status) == 1:
                total_report_status_result = "报告正在整合中"
        message_json = {
            "total_result":total_report_status_result
        }

        return jsonify(message_json)
    else:
        return render_template('login.html')

    

#ehole_finger扫描结果预览
@app.route("/ehole_finger_report/")
def ehole_finger_report():
    user = session.get('username')
    if str(user) == main_username:
        ehole_num = os.popen('bash /TIP/info_scan/finger.sh ehole_finger_num').read()
        EHolestatus = os.popen('bash /TIP/info_scan/finger.sh ehole_status').read()
        if "running" in EHolestatus:
            lines = ["正在扫描中......"]
        else:
            if int(ehole_num) == 0:
                lines = ["未发现漏洞"]
            else:
                lines = []
                with open('./result/ehole_finger.txt', 'r') as f:
                    for line in f:
                        
                        #显示优化去掉颜色字符
                        pattern = re.compile(r'\x1b\[[0-9;]*m')
                        clean_text = pattern.sub('', line)
                        lines.append(clean_text)
    
        return '<br>'.join(lines)
    else:
        return render_template('login.html')
    
    


#bbscan扫描预览报告
@app.route("/showbbscanreport/")
def showbbscanreport():
    user = session.get('username')
    if str(user) == main_username:
        bbscan_num = os.popen('bash /TIP/info_scan/finger.sh bbscan_scan_num').read()
        bbscanstatus = os.popen('bash /TIP/info_scan/finger.sh bbscan_status').read()
        if "running" in bbscanstatus:
            lines = ["正在扫描中......"]
        else:
            if int(bbscan_num) == 0:
                lines = ["未发现漏洞"]
            else:
                lines = []
                with open('/TIP/info_scan/result/bbscan_info.txt', 'r') as f:
                    for line in f:
                        lines.append(line.strip())
        return '<br>'.join(lines)
    else:
        return render_template('login.html')
    

    

#子域名预览报告
@app.route("/showsubdomainreport/")
def showsubdomainreport():
    user = session.get('username')
    if str(user) == main_username:
        subdomain_num = os.popen('bash /TIP/info_scan/finger.sh subdomain_scan_num').read()
        crt_subdomain_shell_status = os.popen('bash /TIP/info_scan/finger.sh crt_subdomain_shell_status').read()
        if "running" in crt_subdomain_shell_status:
            lines = ["正在扫描中......"]
        else:
            if int(subdomain_num) == 0:
                lines = ["未发现漏洞"]
            else:
                lines = []
                with open('/TIP/info_scan/result/subdomain.txt', 'r') as f:
                    for line in f:
                        lines.append(line.strip())
        return '<br>'.join(lines)
    else:
        return render_template('login.html')



#vulmap漏扫预览报告
@app.route("/vulmapscanreport/")
def vulmapscanreport():
    user = session.get('username')
    if str(user) == main_username:
        vulmap_num = os.popen('bash /TIP/info_scan/finger.sh vulmap_scan_num').read()
        vulmapscanstatus = os.popen('bash /TIP/info_scan/finger.sh vulmapscan_status').read()
        if "running" in vulmapscanstatus:
            liness = ["正在扫描中......"]
        else:
            if int(vulmap_num) == 0:
                liness = ["未发现漏洞"]
            else:
                lines = []
                with open('/TIP/info_scan/result/vulmapscan_info.txt', 'r') as f:
                    for line in f:
                        lines.append(line.strip())
                 #文件结果优化展示
                liness = []
                for line1 in lines:
                    
                    #页面显示优化
                    pattern = re.compile(r'\x1b\[[0-9;]*m')
                    clean_text = pattern.sub('', line1)
                    liness.append(clean_text)
        return '<br>'.join(liness)
    else:
        return render_template('login.html')

    


#目标url文件存入列表回显给前端
@app.route("/url_list_textarea_show/")
def url_list_textarea_show():
    user = session.get('username')
    if str(user) == main_username:
        textvalue = basic.url_file_ip_list()
        message_json = {
            "textvalue":textvalue,
            "lentextvalue":"共"+str(len(textvalue))+"行"
        }
        return jsonify(message_json)
    else:
        return render_template('login.html')


#ceye_dns记录
@app.route("/ceye_dns_record/")
def ceye_dns_record():
    user = session.get('username')
    if str(user) == main_username:
        ceye_key = basic.select_session_time_lib(5)
        result = os.popen('bash /TIP/info_scan/finger.sh ceye_dns'+' '+ceye_key).read()
        result_dict = json.loads(result)
       
        message_json = {
            "resultdict":result_dict['data']
        }
        return jsonify(message_json)
    else:
        return render_template('login.html')





#关闭bbscan程序
@app.route("/killbbscanprocess/")
def killbbscanprocess():
    user = session.get('username')
    if str(user) == main_username:
        kill_bbscan_result = basic.stopbbscan_lib()
        message_json = {
            "kill_bbscan_result":kill_bbscan_result
        }

        return jsonify(message_json)
    else:
        return render_template('login.html')
    


#fscan报告预览
@app.route("/fscanreportyulan/")
def fscanreportyulan():
    user = session.get('username')
    if str(user) == main_username:
        fscan_num = os.popen('bash /TIP/info_scan/finger.sh fscan_scan_num').read()
        fscanstatus = os.popen('bash /TIP/info_scan/finger.sh fscan_status').read()
        if "running" in fscanstatus:
            lines = ["正在扫描中......"]
        else:
            if int(fscan_num) ==0:
                lines = ["未发现漏洞"]
            else:
                lines = []
                with open('/TIP/info_scan/result/fscan_vuln.txt', 'r') as f:
                    for line in f:
                        lines.append(line.strip())
        return '<br>'.join(lines)
    else:
        return render_template('login.html')
    

#致远OA报告预览
@app.route("/seeyonreportyulan/")
def seeyonreportyulan():
    user = session.get('username')
    if str(user) == main_username:
        seeyon_status = os.popen('bash /TIP/info_scan/finger.sh seeyon_vuln_scan_status').read()
        if "running" in seeyon_status:
            lines = ["正在扫描中......"]
        else:
            seeyon_num = os.popen('bash /TIP/info_scan/finger.sh seeyon_vuln_num').read()
            if int(seeyon_num) ==0:
                lines = ["未发现漏洞"]
            else:
                lines = []
                with open('/TIP/info_scan/result/seeyon_vuln.txt', 'r') as f:
                    for line in f:
                        lines.append(line.strip())
        return '<br>'.join(lines)
    else:
        return render_template('login.html')

#用友OA报告预览
@app.route("/yonsuitereportyulan/")
def yonsuitereportyulan():
    user = session.get('username')
    if str(user) == main_username:
        yonsuite_status = os.popen('bash /TIP/info_scan/finger.sh yonsuite_vuln_scan_status').read()
        if "running" in yonsuite_status:
            lines = ["正在扫描中......"]
        else:
            yonsuite_num = os.popen('bash /TIP/info_scan/finger.sh yonsuite_vuln_num').read()
            if int(yonsuite_num) ==0:
                lines = ["未发现漏洞"]
            else:
                lines = []
                with open('/TIP/info_scan/result/yonsuite_vuln.txt', 'r') as f:
                    for line in f:
                        lines.append(line.strip())
        return '<br>'.join(lines)
    else:
        return render_template('login.html')
    

#金蝶OA报告预览
@app.route("/kingdeereportyulan/")
def kingdeereportyulan():
    user = session.get('username')
    if str(user) == main_username:
        kingdee_status = os.popen('bash /TIP/info_scan/finger.sh kingdee_vuln_scan_status').read()
        if "running" in kingdee_status:
            lines = ["正在扫描中......"]
        else:
            kingdee_num = os.popen('bash /TIP/info_scan/finger.sh kingdee_vuln_num').read()
            if int(kingdee_num) ==0:
                lines = ["未发现漏洞"]
            else:
                lines = []
                with open('/TIP/info_scan/result/kingdee_vuln.txt', 'r') as f:
                    for line in f:
                        lines.append(line.strip())
        return '<br>'.join(lines)
    else:
        return render_template('login.html')


#万户OA报告预览
@app.route("/wanhureportyulan/")
def wanhureportyulan():
    user = session.get('username')
    if str(user) == main_username:
        wanhu_status = os.popen('bash /TIP/info_scan/finger.sh wanhu_vuln_scan_status').read()
        if "running" in wanhu_status:
            lines = ["正在扫描中......"]
        else:
            wanhu_num = os.popen('bash /TIP/info_scan/finger.sh wanhu_vuln_num').read()
            if int(wanhu_num) ==0:
                lines = ["未发现漏洞"]
            else:
                lines = []
                with open('/TIP/info_scan/result/wanhu_vuln.txt', 'r') as f:
                    for line in f:
                        lines.append(line.strip())
        return '<br>'.join(lines)
    else:
        return render_template('login.html')


#redis未授权报告预览
@app.route("/unredisreportyulan/")
def unredisreportyulan():
    user = session.get('username')
    if str(user) == main_username:
        redis_status = os.popen('bash /TIP/info_scan/finger.sh redis_vuln_scan_status').read()
        if "running" in redis_status:
            lines = ["正在扫描中......"]
        else:
            redis_num = os.popen('bash /TIP/info_scan/finger.sh redis_vuln_num').read()
            if int(redis_num) ==0:
                lines = ["未发现漏洞"]
            else:
                lines = []
                with open('/TIP/info_scan/result/redis_unauthorized.txt', 'r') as f:
                    for line in f:
                        lines.append(line.strip())
        return '<br>'.join(lines)
    else:
        return render_template('login.html')



#mongodb未授权报告预览
@app.route("/unmongodbreportyulan/")
def unmongodbreportyulan():
    user = session.get('username')
    if str(user) == main_username:
        mongodb_status = os.popen('bash /TIP/info_scan/finger.sh mongodb_vuln_scan_status').read()
        if "running" in mongodb_status:
            lines = ["正在扫描中......"]
        else:
            mongodb_num = os.popen('bash /TIP/info_scan/finger.sh mongodb_vuln_num').read()
            if int(mongodb_num) ==0:
                lines = ["未发现漏洞"]
            else:
                lines = []
                with open('/TIP/info_scan/result/mongodb_unauthorized.txt', 'r') as f:
                    for line in f:
                        lines.append(line.strip())
        return '<br>'.join(lines)
    else:
        return render_template('login.html')



#memcached未授权报告预览
@app.route("/unmemcachedreportyulan/")
def unmemcachedreportyulan():
    user = session.get('username')
    if str(user) == main_username:
        memcached_status = os.popen('bash /TIP/info_scan/finger.sh memcached_vuln_scan_status').read()
        if "running" in memcached_status:
            lines = ["正在扫描中......"]
        else:
            memcached_num = os.popen('bash /TIP/info_scan/finger.sh memcached_vuln_num').read()
            if int(memcached_num) ==0:
                lines = ["未发现漏洞"]
            else:
                lines = []
                with open('/TIP/info_scan/result/memcached_unauthorized.txt', 'r') as f:
                    for line in f:
                        lines.append(line.strip())
        return '<br>'.join(lines)
    else:
        return render_template('login.html')
    

#zookeeper未授权报告预览
@app.route("/unzookeeperreportyulan/")
def unzookeeperreportyulan():
    user = session.get('username')
    if str(user) == main_username:
        zookeeper_status = os.popen('bash /TIP/info_scan/finger.sh zookeeper_vuln_scan_status').read()
        if "running" in zookeeper_status:
            lines = ["正在扫描中......"]
        else:
            zookeeper_num = os.popen('bash /TIP/info_scan/finger.sh zookeeper_vuln_num').read()
            if int(zookeeper_num) ==0:
                lines = ["未发现漏洞"]
            else:
                lines = []
                with open('/TIP/info_scan/result/zookeeper_unauthorized.txt', 'r') as f:
                    for line in f:
                        lines.append(line.strip())
        return '<br>'.join(lines)
    else:
        return render_template('login.html')


#ftp未授权报告预览
@app.route("/unftpreportyulan/")
def unftpreportyulan():
    user = session.get('username')
    if str(user) == main_username:
        ftp_status = os.popen('bash /TIP/info_scan/finger.sh ftp_vuln_scan_status').read()
        if "running" in ftp_status:
            lines = ["正在扫描中......"]
        else:
            ftp_num = os.popen('bash /TIP/info_scan/finger.sh ftp_vuln_num').read()
            if int(ftp_num) ==0:
                lines = ["未发现漏洞"]
            else:
                lines = []
                with open('/TIP/info_scan/result/ftp_unauthorized.txt', 'r') as f:
                    for line in f:
                        lines.append(line.strip())
        return '<br>'.join(lines)
    else:
        return render_template('login.html')
    

#couchdb未授权报告预览
@app.route("/uncouchdbreportyulan/")
def uncouchdbreportyulan():
    user = session.get('username')
    if str(user) == main_username:
        couchdb_status = os.popen('bash /TIP/info_scan/finger.sh couchdb_vuln_scan_status').read()
        if "running" in couchdb_status:
            lines = ["正在扫描中......"]
        else:
            couchdb_num = os.popen('bash /TIP/info_scan/finger.sh couchdb_vuln_num').read()
            if int(couchdb_num) ==0:
                lines = ["未发现漏洞"]
            else:
                lines = []
                with open('/TIP/info_scan/result/couchdb_unauthorized.txt', 'r') as f:
                    for line in f:
                        lines.append(line.strip())
        return '<br>'.join(lines)
    else:
        return render_template('login.html')
    

#docker未授权报告预览
@app.route("/undockerreportyulan/")
def undockerreportyulan():
    user = session.get('username')
    if str(user) == main_username:
        docker_status = os.popen('bash /TIP/info_scan/finger.sh docker_vuln_scan_status').read()
        if "running" in docker_status:
            lines = ["正在扫描中......"]
        else:
            docker_num = os.popen('bash /TIP/info_scan/finger.sh docker_vuln_num').read()
            if int(docker_num) ==0:
                lines = ["未发现漏洞"]
            else:
                lines = []
                with open('/TIP/info_scan/result/docker_unauthorized.txt', 'r') as f:
                    for line in f:
                        lines.append(line.strip())
        return '<br>'.join(lines)
    else:
        return render_template('login.html')



#hadoop未授权报告预览
@app.route("/unhadoopreportyulan/")
def unhadoopreportyulan():
    user = session.get('username')
    if str(user) == main_username:
        hadoop_status = os.popen('bash /TIP/info_scan/finger.sh hadoop_vuln_scan_status').read()
        if "running" in hadoop_status:
            lines = ["正在扫描中......"]
        else:
            hadoop_num = os.popen('bash /TIP/info_scan/finger.sh hadoop_vuln_num').read()
            if int(hadoop_num) ==0:
                lines = ["未发现漏洞"]
            else:
                lines = []
                with open('/TIP/info_scan/result/hadoop_unauthorized.txt', 'r') as f:
                    for line in f:
                        lines.append(line.strip())
        return '<br>'.join(lines)
    else:
        return render_template('login.html')
    

#NFS未授权报告预览
@app.route("/unnfsreportyulan/")
def unnfsreportyulan():
    user = session.get('username')
    if str(user) == main_username:
        nfs_status = os.popen('bash /TIP/info_scan/finger.sh nfs_vuln_scan_status').read()
        if "running" in nfs_status:
            lines = ["正在扫描中......"]
        else:
            nfs_num = os.popen('bash /TIP/info_scan/finger.sh nfs_vuln_num').read()
            if int(nfs_num) ==0:
                lines = ["未发现漏洞"]
            else:
                lines = []
                with open('/TIP/info_scan/result/nfs_unauthorized.txt', 'r') as f:
                    for line in f:
                        lines.append(line.strip())
        return '<br>'.join(lines)
    else:
        return render_template('login.html')



#rsync未授权报告预览
@app.route("/unrsyncreportyulan/")
def unrsyncreportyulan():
    user = session.get('username')
    if str(user) == main_username:
        rsync_status = os.popen('bash /TIP/info_scan/finger.sh rsync_vuln_scan_status').read()
        if "running" in rsync_status:
            lines = ["正在扫描中......"]
        else:
            rsync_num = os.popen('bash /TIP/info_scan/finger.sh rsync_vuln_num').read()
            if int(rsync_num) ==0:
                lines = ["未发现漏洞"]
            else:
                lines = []
                with open('/TIP/info_scan/result/rsync_unauthorized.txt', 'r') as f:
                    for line in f:
                        lines.append(line.strip())
        return '<br>'.join(lines)
    else:
        return render_template('login.html')


#Elasticsearch未授权报告预览
@app.route("/unelasticsearchreportyulan/")
def unelasticsearchreportyulan():
    user = session.get('username')
    if str(user) == main_username:
        es_status = os.popen('bash /TIP/info_scan/finger.sh elasticsearch_vuln_scan_status').read()
        if "running" in es_status:
            lines = ["正在扫描中......"]
        else:
            es1_num = os.popen('bash /TIP/info_scan/finger.sh elasticsearch_vuln_num').read()
            if int(es1_num) ==0:
                lines = ["未发现漏洞"]
            else:
                lines = []
                with open('/TIP/info_scan/result/elasticsearch_unauthorized.txt', 'r') as f:
                    for line in f:
                        lines.append(line.strip())
        return '<br>'.join(lines)
    else:
        return render_template('login.html')


#decrypt报告预览
@app.route("/decryptreportyulan/")
def decryptreportyulan():
    user = session.get('username')
    if str(user) == main_username:
        decrypt_status = os.popen('bash /TIP/info_scan/finger.sh bcrypt_scan_status').read()
        if "running" in decrypt_status:
            lines = ["正在扫描中......"]
        else:
            bcrypt_num = os.popen('bash /TIP/info_scan/finger.sh bcrypt_num').read()
            if int(bcrypt_num) ==0:
                lines = ["未解密成功"]
            else:
                lines = []
                with open('/TIP/info_scan/result/bcrypt_result.txt', 'r') as f:
                    for line in f:
                        lines.append(line.strip())
        return '<br>'.join(lines)
    else:
        return render_template('login.html')


#shiro报告预览
@app.route("/shiro_report_show/")
def shiro_report_show():
    user = session.get('username')
    if str(user) == main_username:
        shiro_num = os.popen('bash /TIP/info_scan/finger.sh shiro_scan_num').read()
        shirostatus = os.popen('bash /TIP/info_scan/finger.sh shiro_status').read()
        if "running" in shirostatus:
            filtered_list_new = ["正在扫描中......"]
        else:
            if int(shiro_num) ==0:
                filtered_list_new = ["未发现漏洞"]
            else:
                lines = []
                with open('/TIP/info_scan/result/shiro_vuln.txt', 'r') as f:
                    for line in f:
                        lines.append(line.strip())
        
                 #文件结果优化展示
                liness = []
                for line1 in lines:
                    #页面显示优化
                    pattern = re.compile(r'\x1b\[[0-9;]*m')
                    clean_text = pattern.sub('', line1)
                    liness.append(clean_text)
                # 使用列表推导式创建一个新列表，其中不包含以'Checking :'开头的元素  
                filtered_list = [item for item in liness if not item.startswith('Checking :')]
                filtered_list_new = []
                for fi in filtered_list:
                    result = fi.replace("","")
                    filtered_list_new.append(result)
        return '<br>'.join(filtered_list_new)
    else:
        return render_template('login.html')

    
    

#识别高危资产
@app.route("/key_assets_withdraw/")
def key_assets_withdraw():
    user = session.get('username')
    if str(user) == main_username:

        
        eholestatus = os.popen('bash /TIP/info_scan/finger.sh ehole_status').read()
        if "running" in eholestatus:
            key_assets_result = "指纹识别接口正在运行中请稍后再进行识别高危资产"
        else:

            # 根据config.py中finger_list配置进行识别，可在finger_list列表中配置多个，最终写入到全局资产文件url.txt中
            try:
                key_url_list = basic.key_point_tiqu()
               
                f = open(file='/TIP/batch_scan_domain/url.txt',mode='w')
                for line in key_url_list:
                    f.write(str(line)+"\n")
                f.close()
            except Exception as e:
                print("捕获到异常:", e)

            # 根据config.py中*_rule配置进行识别，只能配置一个关键字
            # 从资产文件url.txt中根据规则分别提取出springboot、weblogic、struts2、shiro资产并写入对应的文件
            basic.asset_by_rule_handle()

            key_assets_result = "已成功识别出高危资产"
            # 筛选后资产时间线更新
            basic.assets_status_update('识别高危资产已完成')
        
        message_json = {
            "key_assets_result":key_assets_result
        }
        return jsonify(message_json)
        
    else:
        return render_template('login.html')



#nuclei poc查询
@app.route("/nuclei_poc_show/",methods=['POST'])
def nuclei_poc_show():
    
    
    user = session.get('username')
    if str(user) == main_username:
        
        poc_dir = request.form['poc_dir']
    
        try:
            result = os.popen('bash /TIP/info_scan/finger.sh templatenuclei'+''+' '+poc_dir).read()
            nuclei_poc_list = []
            for i in result.splitlines():
                nuclei_poc_list.append(i)
            
        except Exception as e:
            print("捕获到异常:", e)

        message_json = {
            "nuclei_poc_list_global":nuclei_poc_list,
            "nuclei_poc_list_len":"总共查询到"+" "+str(len(nuclei_poc_list))+" "+"条yaml规则",
        }
        return jsonify(message_json)
    
    else:
        return render_template('login.html')

    

#springboot报告预览
@app.route("/springboot_report_show/")
def springboot_report_show():
    user = session.get('username')
    if str(user) == main_username:
        os.popen('rm -rf /TIP/info_scan/result.txt')
        springboot_num = os.popen('bash /TIP/info_scan/finger.sh springboot_scan_num').read()
        springbootstatus = os.popen('bash /TIP/info_scan/finger.sh springboot_scan_status').read()
        if "running" in springbootstatus:
            lines = ["正在扫描中......"]
        else:
            if int(springboot_num) == 0:
                lines = ["未发现漏洞"]
            else:
                lines = []
                with open('./result/springboot_result.txt', 'r') as f:
                    for line in f:
                        lines.append(line.strip())
        return '<br>'.join(lines)
    else:
        return render_template('login.html')




# 通过fofa发现资产
@app.route("/fofa_search_assets_service/",methods=['POST'])
def fofa_search_assets_service():
    user = session.get('username')
    if str(user) == main_username:
        # 筛选后资产时间线更新
        basic.assets_status_update('通过fofa平台获取资产完成')
        basic.route_status_update_lib(0,1)
        part = request.form['part']
        num_fofa = request.form['num_fofa']
        if '' in  part:
            asset_len_list = "输入参数不能为空"

        if ' ' in part:
            asset_len_list = "输入参数不能包含空格"

        if 'alert' in part or 'select' in part or '<' in part or '>' in part or 'union' in part:
            asset_len_list = "请勿进行安全测试！"
        else:
            # 第三方接口限额配置
            fofa_inter_num_success = basic.total_port_success_num(1)
            fofa_inter_num_fail = basic.total_port_fail_num(1)
            fofa_total = int(fofa_inter_num_success) + int(fofa_inter_num_fail)
            if fofa_total > int(fofa_max_num):
                asset_len_list = "fofa接口次数已超过额度"+str(fofa_max_num)+"次,无法继续查询,请后台修改额度继续查询"
            else:
                try:
                    asset_len_list_1 = basic.fofa_search_assets_service_lib(part,num_fofa)
                    basic.success_third_party_port_addone(1)
                    basic.route_status_update_lib(1,1)
                    asset_len_list = "总共发现"+" "+str(asset_len_list_1)+" "+"条资产已存入扫描目标中"
                except:
                    basic.fail_third_party_port_addone(1)
        message_json = {
            "asset_len_list":asset_len_list
        }
        return jsonify(message_json)
    else:
        return render_template('login.html')
    

#hydra报告预览
@app.route("/hydra_report_show/")
def hydra_report_show():
    user = session.get('username')
    if str(user) == main_username:
        hydra_num = os.popen('bash /TIP/info_scan/finger.sh hydra_scan_num').read()
        hydra_scan_status = os.popen('bash /TIP/info_scan/finger.sh hydra_status').read()
        if "running" in hydra_scan_status:
            lines = ["正在扫描中......"]
        else:
            if int(hydra_num) == 0:
                lines = ["未发现漏洞"]
            else:
                lines = []
                with open('./result/hydra_result.txt', 'r') as f:
                    for line in f:
                        lines.append(line.strip())
        return '<br>'.join(lines)
    else:
        return render_template('login.html')

    

# 报告预览
@app.route('/totalreportyulan/')
def totalreportyulan():
    user = session.get('username')
    if str(user) == main_username:
        file_path = '/TIP/info_scan/result/vuln_report.xlsx'
        file_path_warn = '/TIP/info_scan/result/vuln_report_warn.xlsx'
        if os.path.exists(file_path) and os.path.isfile(file_path):
            # 读取Excel文件的所有sheets
            xls = pd.ExcelFile(file_path)
            result_data = {sheet_name: pd.read_excel(file_path, sheet_name=sheet_name).to_dict(orient='records') 
                           for sheet_name in xls.sheet_names}
        else:
            text_list = ["{\"status\":\"failed\",\"errorcode\":500,\"describe\":\"正在进行报告整合...\"}"]
            df_a = pd.DataFrame(text_list, columns=['警告信息'])
            with pd.ExcelWriter('/TIP/info_scan/result/vuln_report_warn.xlsx', engine='openpyxl') as writer:
            # 将 DataFrame 写入不同的工作表  
                df_a.to_excel(writer, sheet_name='正在整合中...', index=False)
            # 读取Excel文件的所有sheets
            xls = pd.ExcelFile(file_path_warn)
            result_data = {sheet_name: pd.read_excel(file_path_warn, sheet_name=sheet_name).to_dict(orient='records') 
                           for sheet_name in xls.sheet_names}
        # 使用模板渲染HTML表格
        return render_template('preview.html', data=result_data)
    else:
        return render_template('login.html')




# 报告下载
@app.route("/report_download_interface/",methods=['get'])
def report_download_interface():
    user = session.get('username')
    if str(user) == main_username:
        # 判断vuln_report.xlsx是否存在
        file_path = '/TIP/info_scan/result/vuln_report.xlsx'
        if os.path.exists(file_path) and os.path.isfile(file_path):
            return send_file(file_path, as_attachment=True, download_name='vuln_report.xlsx')
        else:
            text_list = ["{\"status\":\"failed\",\"errorcode\":500,\"describe\":\"正在进行报告整合...\"}"]
            df_a = pd.DataFrame(text_list, columns=['警告信息'])
            with pd.ExcelWriter('/TIP/info_scan/result/vuln_report_warn.xlsx', engine='openpyxl') as writer:
            # 将 DataFrame 写入不同的工作表  
                df_a.to_excel(writer, sheet_name='sheet1', index=False)
            file_path1 = '/TIP/info_scan/result/vuln_report_warn.xlsx'
            return send_file(file_path1, as_attachment=True, download_name='vuln_report_warn.xlsx')
    
    else:
        return render_template('login.html')


# 重启系统
@app.route("/restartsystemserviceinterface/")
def restartsystemserviceinterface():
    user = session.get('username')
    if str(user) == main_username:
        basic.restart_infoscan_lib()
        return render_template('index.html')
        # infoscanstatus = os.popen('bash /TIP/info_scan/finger.sh infoscanstatus').read()
        # if "running" in infoscanstatus:
        #     infoscanstatus = "服务已启动"
        # else:
        #     infoscanstatus = "正在重启中..."
        # message_json = {
        #     "infoscanstatus":""
        # }

        # return jsonify(message_json)
    
    else:
        return render_template('login.html')


@app.route("/restartsystemservice/")
def restartsystemservice():
    user = session.get('username')
    if str(user) == main_username:
        
        infoscanstatus = os.popen('bash /TIP/info_scan/finger.sh infoscanstatus').read()
        if "running" in infoscanstatus:
            infoscanstatus = "服务已启动"
        else:
            infoscanstatus = "正在重启中..."
        message_json = {
            "infoscanstatus":infoscanstatus
        }

        return jsonify(message_json)
    
    else:
        return render_template('login.html')



# 高危资产识别根据筛选规则名称删除
@app.route("/delete_point_rule_interface/",methods=['post'])
def delete_point_rule_interface():
    user = session.get('username')

    if str(user) == main_username:
        rule = request.form['rule']
        key = request.form['key']
        if '' in  rule:
            result_rule = "输入参数不能为空"

        if ' ' in rule:
            result_rule = "输入参数不能包含空格"

        if 'alert' in rule or 'select' in rule or '<' in rule or '>' in rule or 'union' in rule:
            result_rule = "请勿进行安全测试！"

        else:
            db= pymysql.connect(host=dict['ip'],user=dict['username'],  
            password=dict['password'],db=dict['dbname'],port=dict['portnum']) 
            cur = db.cursor()

            if int(key) == 1:
                # 判断是否删除成功
                sql1 = "select * from rule_table where rule = '%s' " %(rule)
                cur.execute(sql1)
                result = cur.fetchone()
                if result == None:
                    result_rule = rule+" "+"删除成功"

                else:

                    # 前端传递过来1为根据规则名称删除
                    sql="DELETE from rule_table WHERE rule = '%s' " %(rule)
                    cur.execute(sql)
                    db.commit()
                    db.rollback()

                    # 二次判断是否删除成功
                    sql1 = "select * from rule_table where rule = '%s' " %(rule)
                    cur.execute(sql1)
                    result = cur.fetchone()
                    if result == None:
                        result_rule = rule+" "+"删除完成,不要重复操作"

            elif int(key) ==2:
                

                # 判断是否删除成功
                sql1 = "select * from rule_table"
                cur.execute(sql1)
                result = cur.fetchone()
                if result == None:
                    result_rule = "规则已清空,不要重复操作"
                else:
                    # 前端传递过来2为清空筛选规则表
                    sql2="DELETE from rule_table"
                    cur.execute(sql2)
                    db.commit()
                    db.rollback()
                    
                    # 二次判断是否删除成功
                    sql1 = "select * from rule_table"
                    cur.execute(sql1)
                    result = cur.fetchone()
                    if result == None:
                        result_rule = "已清空所有规则"

            else:
                print("参数值只允许1/2")
            
            
        message_json = {
            "delete_rule":result_rule
        }

        return jsonify(message_json)
    
    else:
        return render_template('login.html')
    


#thinkphp_poc扫描结果预览
@app.route("/thinkphp_poc_report/")
def thinkphp_poc_report():
    user = session.get('username')
    if str(user) == main_username:
        thinkphp_num = os.popen('bash /TIP/info_scan/finger.sh thinkphp_scan_num').read()
        tpscanstatus = os.popen('bash /TIP/info_scan/finger.sh TPscan_status').read()
        if "running" in tpscanstatus:
            lines = ["正在扫描中......"]
        else:
            if int(thinkphp_num) == 0:
                lines = ["未发现漏洞"]
            else:
                lines = []
                with open('/TIP/info_scan/result/thinkphp_vuln.txt', 'r') as f:
                    for line in f:
                        lines.append(line.strip())
        return '<br>'.join(lines)
    else:
        return render_template('login.html')
    



#泛微扫描结果预览
@app.route("/weaverresultshow/")
def weaverresultshow():
    user = session.get('username')
    if str(user) == main_username:
        os.popen('rm -rf /TIP/info_scan/weaver_exp/*.zip')
        weaver_scan_num = os.popen('bash /TIP/info_scan/finger.sh weaver_scan_num').read()
        weaver_status = os.popen('bash /TIP/info_scan/finger.sh weaver_status').read()
        if "running" in weaver_status:
            liness = ["正在扫描中......"]
        else:
            if int(weaver_scan_num) == 0:
                liness = ["未发现漏洞"]
            else:
                lines = []
                with open('./result/weaver_vuln.txt', 'r') as f:
                    for line in f:
                        lines.append(line.strip())
                 #文件结果优化展示
                liness = []
                for line1 in lines:
                    
                    #页面显示优化
                    pattern = re.compile(r'\x1b\[[0-9;]*m')
                    clean_text = pattern.sub('', line1)
                    liness.append(clean_text)
            
        return '<br>'.join(liness)
    else:
        return render_template('login.html')



# 前端复选框批量开启信息收集工具接口
@app.route("/infoscan_check_back/",methods=['post'])
def infoscan_check_back():
    user = session.get('username')
    if str(user) == main_username:
        # 漏洞扫描器时间线更新
        basic.vuln_scan_status_update('已完成开启批量信息收集')
        data = request.get_json()  # 使用 get_json 解析 JSON 请求体
        info_front_list = data['info_front_list']
        portscan_part = data['portscan_part']
        pachongselectpart = data['pachongselectpart']
        
        # 接收前端传入的值转为int型
        info_value_list = []
        for i in info_front_list:
            info_value_list.append(int(i))

        # 遍历列表判断调用哪个扫描器
        for j in info_value_list:
            if '1' in str(j):
                if int(verification_fingerprint_recognition) == 0:
                    # 获取系统当前时间
                    current_time = time.time()
                    # 当前时间和数据库中的作时间差
                    diff_time_minutes = basic.info_time_shijian_cha(1)
                    
                    if int(diff_time_minutes) > info_time_controls:
                        # 超过单位时间更新数据库中的时间
                        basic.last_time_update_lib(current_time,1)
                        # 指纹识别程序用时统计相关
                        basic.scan_total_time_start_time(3)

                        # 提交扫描任务
                        bbscan_status_result = basic.startbbscan_lib()

                        # 在后台单独启动1个线程实时判断扫描器停止时间
                        def bbscanscanendtime():
                            while True:
                                time.sleep(1)
                                basic.scan_total_time_final_end_time(3)
                        threading.Thread(target=bbscanscanendtime).start()
                    else:
                        bbscan_status_result = "信息泄露扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
                elif int(verification_fingerprint_recognition) == 1:
                    # 判断是否已进行指纹识别
                    finger_part = basic.assets_finger_compare()
                    if finger_part == 2:
                        bbscan_status_result = "未进行指纹识别无法开启bbscan扫描"
                    else:
                        # 获取系统当前时间
                        current_time = time.time()
                        # 当前时间和数据库中的作时间差
                        diff_time_minutes = basic.info_time_shijian_cha(1)
                        
                        if int(diff_time_minutes) > info_time_controls:
                            # 超过单位时间更新数据库中的时间
                            basic.last_time_update_lib(current_time,1)
                            # 指纹识别程序用时统计相关
                            basic.scan_total_time_start_time(3)
    
                            # 提交扫描任务
                            bbscan_status_result = basic.startbbscan_lib()
    
                            # 在后台单独启动1个线程实时判断扫描器停止时间
                            def bbscanscanendtime():
                                while True:
                                    time.sleep(1)
                                    basic.scan_total_time_final_end_time(3)
                            threading.Thread(target=bbscanscanendtime).start()
                        else:
                            bbscan_status_result = "信息泄露扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
                
            elif '2' in str(j):
                # 获取系统当前时间
                current_time2 = time.time()
                # 当前时间和数据库中的作时间差
                diff_time_minutes2 = basic.info_time_shijian_cha(2)
                if int(diff_time_minutes2) > info_time_controls:
                    # 超过单位时间更新数据库中的时间
                    basic.last_time_update_lib(current_time2,2)

                    # 指纹识别程序用时统计相关
                    basic.scan_total_time_start_time(2)

                    # 提交扫描任务
                    finger_status_result = basic.startechole_lib()

                    # 在后台单独启动1个线程实时判断扫描器停止时间
                    def fingerscanendtime():
                        while True:
                            time.sleep(1)
                            basic.scan_total_time_final_end_time(2)
                    threading.Thread(target=fingerscanendtime).start()
                else:
                    finger_status_result = "指纹识别程序"+str(info_time_controls)+"分钟内不允许重复扫描"
            elif '3' in str(j):
                if int(verification_fingerprint_recognition) == 0:
                    # 限定第三方接口otx额度
                    otx_inter_num_success = basic.total_port_success_num(6)
                    otx_inter_num_fail = basic.total_port_fail_num(6)
                    otx_total = int(otx_inter_num_success) + int(otx_inter_num_fail)
                    if int(otx_total) > int(otx_max_num):
                        otx_status_result = "otx接口次数已超过额度"+str(otx_max_num)+"次,无法继续查询,请后台修改额度继续查询"
                    else:
                        # 获取系统当前时间
                        current_time3 = time.time()
                        # 当前时间和数据库中的作时间差
                        diff_time_minutes3 = basic.info_time_shijian_cha(3)
                        if int(diff_time_minutes3) > info_time_controls:
                            # 超过单位时间更新数据库中的时间
                            basic.last_time_update_lib(current_time3,3)

                            # 指纹识别程序用时统计相关
                            basic.scan_total_time_start_time(4)
                            # 提交扫描任务
                            otx_status_result = basic.otxhistorydomain_lib()

                            # 在后台单独启动1个线程实时判断扫描器停止时间
                            def otxscanendtime():
                                while True:
                                    time.sleep(1)
                                    basic.scan_total_time_final_end_time(4)
                            threading.Thread(target=otxscanendtime).start()

                        else:
                            otx_status_result = "历史URL查询接口"+str(info_time_controls)+"分钟内不允许重复扫描"
                elif int(verification_fingerprint_recognition) == 1:
                    # 判断是否已进行指纹识别
                    finger_part = basic.assets_finger_compare()
                    if finger_part == 2:
                        otx_status_result = "未进行指纹识别无法开启历史URL查询"
                    else:
                        # 限定第三方接口otx额度
                        otx_inter_num_success = basic.total_port_success_num(6)
                        otx_inter_num_fail = basic.total_port_fail_num(6)
                        otx_total = int(otx_inter_num_success) + int(otx_inter_num_fail)
                        if int(otx_total) > int(otx_max_num):
                            otx_status_result = "otx接口次数已超过额度"+str(otx_max_num)+"次,无法继续查询,请后台修改额度继续查询"
                        else:
                            # 获取系统当前时间
                            current_time3 = time.time()
                            # 当前时间和数据库中的作时间差
                            diff_time_minutes3 = basic.info_time_shijian_cha(3)
                            if int(diff_time_minutes3) > info_time_controls:
                                # 超过单位时间更新数据库中的时间
                                basic.last_time_update_lib(current_time3,3)
    
                                # 指纹识别程序用时统计相关
                                basic.scan_total_time_start_time(4)
                                # 提交扫描任务
                                otx_status_result = basic.otxhistorydomain_lib()
    
                                # 在后台单独启动1个线程实时判断扫描器停止时间
                                def otxscanendtime():
                                    while True:
                                        time.sleep(1)
                                        basic.scan_total_time_final_end_time(4)
                                threading.Thread(target=otxscanendtime).start()
    
                            else:
                                otx_status_result = "历史URL查询接口"+str(info_time_controls)+"分钟内不允许重复扫描"
            elif '4' in str(j):
                if int(verification_fingerprint_recognition) == 0:
                    crt_inter_num_success = basic.total_port_success_num(3)
                    crt_inter_num_fail = basic.total_port_fail_num(3)
                    crt_total = int(crt_inter_num_success) + int(crt_inter_num_fail)
                    if crt_total > int(crt_max_num):
                        crt_status_result = "子域名查询接口次数已超过额度"+str(crt_max_num)+"次,无法继续查询,请后台修改额度继续查询"
                    else:
                        # 获取系统当前时间
                        current_time4 = time.time()
                        # 当前时间和数据库中的作时间差
                        diff_time_minutes4 = basic.info_time_shijian_cha(4)
                        if int(diff_time_minutes4) > info_time_controls:
                            # 超过单位时间更新数据库中的时间
                            basic.last_time_update_lib(current_time4,4)
                            # 指纹识别程序用时统计相关
                            basic.scan_total_time_start_time(5)

                            # 提交扫描任务
                            crt_status_result = basic.crtdomain_lib()

                            # 在后台单独启动1个线程实时判断扫描器停止时间
                            def crtscanendtime():
                                while True:
                                    time.sleep(1)
                                    basic.scan_total_time_final_end_time(5)
                            threading.Thread(target=crtscanendtime).start()

                        else:
                            crt_status_result = "基于证书查询子域名接口"+str(info_time_controls)+"分钟内不允许重复扫描"
                elif int(verification_fingerprint_recognition) == 1:
                    # 判断是否已进行指纹识别
                    finger_part = basic.assets_finger_compare()
                    if finger_part == 2:
                        crt_status_result = "未进行指纹识别无法开启查询子域名"
                    else:
                        crt_inter_num_success = basic.total_port_success_num(3)
                        crt_inter_num_fail = basic.total_port_fail_num(3)
                        crt_total = int(crt_inter_num_success) + int(crt_inter_num_fail)
                        if crt_total > int(crt_max_num):
                            crt_status_result = "子域名查询接口次数已超过额度"+str(crt_max_num)+"次,无法继续查询,请后台修改额度继续查询"
                        else:
                            # 获取系统当前时间
                            current_time4 = time.time()
                            # 当前时间和数据库中的作时间差
                            diff_time_minutes4 = basic.info_time_shijian_cha(4)
                            if int(diff_time_minutes4) > info_time_controls:
                                # 超过单位时间更新数据库中的时间
                                basic.last_time_update_lib(current_time4,4)
                                # 指纹识别程序用时统计相关
                                basic.scan_total_time_start_time(5)
    
                                # 提交扫描任务
                                crt_status_result = basic.crtdomain_lib()
    
                                # 在后台单独启动1个线程实时判断扫描器停止时间
                                def crtscanendtime():
                                    while True:
                                        time.sleep(1)
                                        basic.scan_total_time_final_end_time(5)
                                threading.Thread(target=crtscanendtime).start()
    
                            else:
                                crt_status_result = "基于证书查询子域名接口"+str(info_time_controls)+"分钟内不允许重复扫描"
            elif '5' in str(j):
                if int(verification_fingerprint_recognition) == 0:
                    # 获取系统当前时间
                    current_time5 = time.time()
                    # 当前时间和数据库中的作时间差
                    diff_time_minutes5 = basic.info_time_shijian_cha(5)
                    if int(diff_time_minutes5) > info_time_controls:
                        # 超过单位时间更新数据库中的时间
                        basic.last_time_update_lib(current_time5,5)
                        # 端口扫描程序用时统计相关
                        basic.scan_total_time_start_time(1)
                        # 提交扫描任务
                        # 每次启动前清空上次扫描结果
                        nmap_status_result = basic.startnmap_lib(portscan_part)
                        # 在后台单独启动1个线程实时判断扫描器停止时间
                        def portscanendtime():
                            while True:
                                time.sleep(1)
                                basic.scan_total_time_final_end_time(1)
                        threading.Thread(target=portscanendtime).start()

                    else:
                        nmap_status_result = "nmap端口扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
                elif int(verification_fingerprint_recognition) == 1:
                    # 判断是否已进行指纹识别
                    finger_part = basic.assets_finger_compare()
                    if finger_part == 2:
                        nmap_status_result = "未进行指纹识别无法开启nmap扫描"
                    else:
                        # 获取系统当前时间
                        current_time5 = time.time()
                        # 当前时间和数据库中的作时间差
                        diff_time_minutes5 = basic.info_time_shijian_cha(5)
                        if int(diff_time_minutes5) > info_time_controls:
                            # 超过单位时间更新数据库中的时间
                            basic.last_time_update_lib(current_time5,5)
                            # 端口扫描程序用时统计相关
                            basic.scan_total_time_start_time(1)
                            # 提交扫描任务
                            # 每次启动前清空上次扫描结果
                            nmap_status_result = basic.startnmap_lib(portscan_part)
                            # 在后台单独启动1个线程实时判断扫描器停止时间
                            def portscanendtime():
                                while True:
                                    time.sleep(1)
                                    basic.scan_total_time_final_end_time(1)
                            threading.Thread(target=portscanendtime).start()
    
                        else:
                            nmap_status_result = "nmap端口扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"

            elif '6' in str(j):
                if int(verification_fingerprint_recognition) == 0:
                    # 获取系统当前时间
                    current_time6 = time.time()
                    # 当前时间和数据库中的作时间差
                    diff_time_minutes6 = basic.info_time_shijian_cha(6)
                    if int(diff_time_minutes6) > info_time_controls:
                        # 超过单位时间更新数据库中的时间
                        basic.last_time_update_lib(current_time6,6)
                        # waf扫描程序用时统计相关
                        basic.scan_total_time_start_time(6)
                        # 提交扫描任务
                        # 每次启动前清空上次扫描结果
                        waf_status_result = basic.startwafrecognize_lib()

                        # 在后台单独启动1个线程实时判断扫描器停止时间
                        def wafscanendtime():
                            while True:
                                time.sleep(1)
                                basic.scan_total_time_final_end_time(6)
                        threading.Thread(target=wafscanendtime).start()

                    else:
                        waf_status_result = "WAF扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
                elif int(verification_fingerprint_recognition) == 1:
                    # 判断是否已进行指纹识别
                    finger_part = basic.assets_finger_compare()
                    if finger_part == 2:
                        waf_status_result = "未进行指纹识别无法开启WAF扫描程序"
                    else:
                        # 获取系统当前时间
                        current_time6 = time.time()
                        # 当前时间和数据库中的作时间差
                        diff_time_minutes6 = basic.info_time_shijian_cha(6)
                        if int(diff_time_minutes6) > info_time_controls:
                            # 超过单位时间更新数据库中的时间
                            basic.last_time_update_lib(current_time6,6)
                            # waf扫描程序用时统计相关
                            basic.scan_total_time_start_time(6)
                            # 提交扫描任务
                            # 每次启动前清空上次扫描结果
                            waf_status_result = basic.startwafrecognize_lib()
    
                            # 在后台单独启动1个线程实时判断扫描器停止时间
                            def wafscanendtime():
                                while True:
                                    time.sleep(1)
                                    basic.scan_total_time_final_end_time(6)
                            threading.Thread(target=wafscanendtime).start()
    
                        else:
                            waf_status_result = "WAF扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
            elif '7' in str(j):
                if int(verification_fingerprint_recognition) == 0:
                    # 获取系统当前时间
                    current_time7 = time.time()
                    # 当前时间和数据库中的作时间差
                    diff_time_minutes7 = basic.info_time_shijian_cha(7)
                    if int(diff_time_minutes7) > info_time_controls:
                        # 超过单位时间更新数据库中的时间
                        basic.last_time_update_lib(current_time7,7)
                        # fuzz扫描程序用时统计相关
                        basic.scan_total_time_start_time(7)
                        # 提交扫描任务
                        # 每次启动前清空上次扫描结果
                        bypass_status_result = basic.start40xbypass_lib()

                        # 在后台单独启动1个线程实时判断扫描器停止时间
                        def fuzzscanendtime():
                            while True:
                                time.sleep(1)
                                basic.scan_total_time_final_end_time(7)
                        threading.Thread(target=fuzzscanendtime).start()

                    else:
                        bypass_status_result = "FUZZ扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
                elif int(verification_fingerprint_recognition) == 1:
                    # 判断是否已进行指纹识别
                    finger_part = basic.assets_finger_compare()
                    if finger_part == 2:
                        bypass_status_result = "未进行指纹识别无法开启FUZZ扫描程序"
                    else:
                        # 获取系统当前时间
                        current_time7 = time.time()
                        # 当前时间和数据库中的作时间差
                        diff_time_minutes7 = basic.info_time_shijian_cha(7)
                        if int(diff_time_minutes7) > info_time_controls:
                            # 超过单位时间更新数据库中的时间
                            basic.last_time_update_lib(current_time7,7)
                            # fuzz扫描程序用时统计相关
                            basic.scan_total_time_start_time(7)
                            # 提交扫描任务
                            # 每次启动前清空上次扫描结果
                            bypass_status_result = basic.start40xbypass_lib()
    
                            # 在后台单独启动1个线程实时判断扫描器停止时间
                            def fuzzscanendtime():
                                while True:
                                    time.sleep(1)
                                    basic.scan_total_time_final_end_time(7)
                            threading.Thread(target=fuzzscanendtime).start()
    
                        else:
                            bypass_status_result = "FUZZ扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
            elif '8' in str(j):
                if int(verification_fingerprint_recognition) == 0:
                    xray_status = os.popen('bash /TIP/info_scan/finger.sh xraystatus').read()
                    if "running" in xray_status:
                         # 获取系统当前时间
                         current_time8 = time.time()
                         # 当前时间和数据库中的作时间差
                         diff_time_minutes8 = basic.info_time_shijian_cha(8)
                         if int(diff_time_minutes8) > info_time_controls:
                            # 超过单位时间更新数据库中的时间
                            basic.last_time_update_lib(current_time8,8)
                            
                            # 爬虫扫描程序用时统计相关
                            basic.scan_total_time_start_time(8)
                             # 提交扫描任务
                             # 每次启动前清空上次扫描结果
                            crawlergo_status_result = basic.start_crawlergo_lib(pachongselectpart)
                            # 在后台单独启动1个线程实时判断扫描器停止时间
                            def crawlergoscanendtime():
                                while True:
                                    time.sleep(1)
                                    basic.scan_total_time_final_end_time(8)
                            threading.Thread(target=crawlergoscanendtime).start()
                         else:
                             crawlergo_status_result = "爬虫程序"+str(info_time_controls)+"分钟内不允许重复扫描"
                    else:
                        crawlergo_status_result = basic.start_crawlergo_lib(pachongselectpart)
                elif int(verification_fingerprint_recognition) == 1:
                    # 判断是否已进行指纹识别
                    finger_part = basic.assets_finger_compare()
                    if finger_part == 2:
                        crawlergo_status_result = "未进行指纹识别无法开启爬虫程序"
                    else:
                        xray_status = os.popen('bash /TIP/info_scan/finger.sh xraystatus').read()
                        if "running" in xray_status:
                             # 获取系统当前时间
                             current_time8 = time.time()
                             # 当前时间和数据库中的作时间差
                             diff_time_minutes8 = basic.info_time_shijian_cha(8)
                             if int(diff_time_minutes8) > info_time_controls:
                                # 超过单位时间更新数据库中的时间
                                basic.last_time_update_lib(current_time8,8)
                                
                                # 爬虫扫描程序用时统计相关
                                basic.scan_total_time_start_time(8)
                                 # 提交扫描任务
                                 # 每次启动前清空上次扫描结果
                                crawlergo_status_result = basic.start_crawlergo_lib(pachongselectpart)
                                # 在后台单独启动1个线程实时判断扫描器停止时间
                                def crawlergoscanendtime():
                                    while True:
                                        time.sleep(1)
                                        basic.scan_total_time_final_end_time(8)
                                threading.Thread(target=crawlergoscanendtime).start()
                             else:
                                 crawlergo_status_result = "爬虫程序"+str(info_time_controls)+"分钟内不允许重复扫描"
                        else:
                            crawlergo_status_result = basic.start_crawlergo_lib(pachongselectpart)
            else:
                print("参数正在完善中...")

        try:
            bbscan_status_result1 = bbscan_status_result
        except:
            bbscan_status_result1 = ""
        try:
            finger_status_result1 = finger_status_result
        except:
            finger_status_result1 = ""
        try:
            otx_status_result1 = otx_status_result
        except:
            otx_status_result1 = ""
        try:
            crt_status_result1 = crt_status_result
        except:
            crt_status_result1 = ""
        try:
            nmap_status_result1 = nmap_status_result
        except:
            nmap_status_result1 = ""
        try:
            waf_status_result1 = waf_status_result
        except:
            waf_status_result1 = ""
        try:
            bypass_status_result1 = bypass_status_result
        except:
            bypass_status_result1 = ""
        try:
            crawlergo_status_result1 = crawlergo_status_result
        except:
            crawlergo_status_result1 = ""
        
        eholestatus = os.popen('bash /TIP/info_scan/finger.sh ehole_status').read()
        bbscanstatus = os.popen('bash /TIP/info_scan/finger.sh bbscan_status').read()
        otx_status = os.popen('bash /TIP/info_scan/finger.sh otx_domain_url_shell_status').read()
        crt_status = os.popen('bash /TIP/info_scan/finger.sh crt_subdomain_shell_status').read()
        nmapstatus =os.popen('bash /TIP/info_scan/finger.sh nmapstatus').read()
        waf_status = os.popen('bash /TIP/info_scan/finger.sh waf_scan_status').read()
        bypass_status = os.popen('bash /TIP/info_scan/finger.sh bypassstatus').read()
        crawlergo_status = os.popen('bash /TIP/info_scan/finger.sh crawlergo_status').read()
        
        dict = {
            "key1":bbscan_status_result1,
            "key2":finger_status_result1,
            "key3":otx_status_result1,
            "key4":crt_status_result1,
            "key5":nmap_status_result1,
            "key6":waf_status_result1,
            "key7":bypass_status_result1,
            "key8":crawlergo_status_result1,
            "key9":eholestatus,
            "key10":bbscanstatus,
            "key11":otx_status,
            "key12":crt_status,
            "key13":nmapstatus,
            "key14":waf_status,
            "key15":bypass_status,
            "key16":crawlergo_status
        }
        message_json = {
            "dictkey1":dict['key1'],
            "dictkey2":dict['key2'],
            "dictkey3":dict['key3'],
            "dictkey4":dict['key4'],
            "dictkey5":dict['key5'],
            "dictkey6":dict['key6'],
            "dictkey7":dict['key7'],
            "dictkey8":dict['key8'],
            "dictkey9":dict['key9'],
            "dictkey10":dict['key10'],
            "dictkey11":dict['key11'],
            "dictkey12":dict['key12'],
            "dictkey13":dict['key13'],
            "dictkey14":dict['key14'],
            "dictkey15":dict['key15'],
            "dictkey16":dict['key16']
        }

        return jsonify(message_json)
    
    else:
        return render_template('login.html')


# 前端复选框批量开启漏洞扫描工具接口
@app.route("/vulnscan_check_back/",methods=['post'])
def vulnscan_check_back():
    user = session.get('username')
    if str(user) == main_username:
        # 漏洞扫描器时间线更新
        basic.vuln_scan_status_update('已完成开启批量漏洞扫描')
        # 使用 get_json 解析 JSON 请求体,接收前端传递过来的json
        data = request.get_json()  
        vuln_front_list = data['vuln_front_list']
        fscanpartname = str(data['fscanpartname'])
        fscanpartname1 = int(data['fscanpartname1'])
        hydrapart = int(data['hydrapart'])
        vulnname = data['vulnname']
        poc_dir = data['poc_dir']
        
        # 遍历列表判断调用哪个扫描器
        for k in vuln_front_list:
            if '1' in str(k):
                print("struts2")
                # 指纹识别开关
                if int(verification_fingerprint_recognition) == 0:
                    # 获取系统当前时间
                    current_time1 = time.time()
                    # 当前时间和数据库中的作时间差
                    diff_time_minutes1 = basic.vuln_time_shijian_cha(1)
                    if int(diff_time_minutes1) > vuln_time_controls:
                        # 超过单位时间更新数据库中的时间
                        basic.vuln_last_time_update_lib(current_time1,1)
                        # struts2扫描程序用时统计相关
                        basic.scan_total_time_start_time(9)
                        # 提交扫描任务
                        struts2status_result = basic.startstruts2_lib()
                        # 在后台单独启动1个线程实时判断扫描器停止时间
                        def struts2scanendtime():
                            while True:
                                time.sleep(1)
                                basic.scan_total_time_final_end_time(9)
                        threading.Thread(target=struts2scanendtime).start()

                    else:
                        struts2status_result = "struts2扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
                elif int(verification_fingerprint_recognition) == 1:
                    # 判断是否已进行指纹识别
                    finger_part = basic.assets_finger_compare()
                    if finger_part == 2:
                        struts2status_result = "未进行指纹识别无法开启struts2扫描"
                    else:
                        # 获取系统当前时间
                        current_time1 = time.time()
                        # 当前时间和数据库中的作时间差
                        diff_time_minutes1 = basic.vuln_time_shijian_cha(1)
                        if int(diff_time_minutes1) > vuln_time_controls:
                            # 超过单位时间更新数据库中的时间
                            basic.vuln_last_time_update_lib(current_time1,1)
                            # struts2扫描程序用时统计相关
                            basic.scan_total_time_start_time(9)
                            # 提交扫描任务
                            struts2status_result = basic.startstruts2_lib()
                            # 在后台单独启动1个线程实时判断扫描器停止时间
                            def struts2scanendtime():
                                while True:
                                    time.sleep(1)
                                    basic.scan_total_time_final_end_time(9)
                            threading.Thread(target=struts2scanendtime).start()
    
                        else:
                            struts2status_result = "struts2扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"

            elif '2' in str(k):
                print("weblogic")
                if int(verification_fingerprint_recognition) == 0:
                    # 获取系统当前时间
                    current_time2 = time.time()
                    # 当前时间和数据库中的作时间差
                    diff_time_minutes2 = basic.vuln_time_shijian_cha(2)
                    if int(diff_time_minutes2) > vuln_time_controls:
                        # 超过单位时间更新数据库中的时间
                        basic.vuln_last_time_update_lib(current_time2,2)
                        # struts2扫描程序用时统计相关
                        basic.scan_total_time_start_time(10)
                        # 提交扫描任务
                        weblogic_status_result = basic.startweblogic_lib()
                        # 在后台单独启动1个线程实时判断扫描器停止时间
                        def weblogicscanendtime():
                            while True:
                                time.sleep(1)
                                basic.scan_total_time_final_end_time(10)
                        threading.Thread(target=weblogicscanendtime).start()
                    else:
                        weblogic_status_result = "weblogic扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
                elif int(verification_fingerprint_recognition) == 1:
                    # 判断是否已进行指纹识别
                    finger_part = basic.assets_finger_compare()
                    if finger_part == 2:
                        weblogic_status_result = "未进行指纹识别无法开启weblogic扫描"
                    else:
                        # 获取系统当前时间
                        current_time2 = time.time()
                        # 当前时间和数据库中的作时间差
                        diff_time_minutes2 = basic.vuln_time_shijian_cha(2)
                        if int(diff_time_minutes2) > vuln_time_controls:
                            # 超过单位时间更新数据库中的时间
                            basic.vuln_last_time_update_lib(current_time2,2)
                            # struts2扫描程序用时统计相关
                            basic.scan_total_time_start_time(10)
                            # 提交扫描任务
                            weblogic_status_result = basic.startweblogic_lib()
                            # 在后台单独启动1个线程实时判断扫描器停止时间
                            def weblogicscanendtime():
                                while True:
                                    time.sleep(1)
                                    basic.scan_total_time_final_end_time(10)
                            threading.Thread(target=weblogicscanendtime).start()
                        else:
                            weblogic_status_result = "weblogic扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"

            elif '3' in str(k):
                print("shiro")
                if int(verification_fingerprint_recognition) == 0:
                    # 获取系统当前时间
                    current_time3 = time.time()
                    # 当前时间和数据库中的作时间差
                    diff_time_minutes3 = basic.vuln_time_shijian_cha(3)
                    if int(diff_time_minutes3) > vuln_time_controls:
                        # 超过单位时间更新数据库中的时间
                        basic.vuln_last_time_update_lib(current_time3,3)
                        # shiro扫描程序用时统计相关
                        basic.scan_total_time_start_time(11)
                        # 提交扫描任务
                        shiro_status_result = basic.startshiro_lib()
                        # 在后台单独启动1个线程实时判断扫描器停止时间
                        def shiroscanendtime():
                            while True:
                                time.sleep(1)
                                basic.scan_total_time_final_end_time(11)
                        threading.Thread(target=shiroscanendtime).start()
                        
                    else:
                        shiro_status_result = "shiro扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
                elif int(verification_fingerprint_recognition) == 1:
                    # 判断是否已进行指纹识别
                    finger_part = basic.assets_finger_compare()
                    if finger_part == 2:
                        shiro_status_result = "未进行指纹识别无法开启shiro扫描"
                    else:
                        # 获取系统当前时间
                        current_time3 = time.time()
                        # 当前时间和数据库中的作时间差
                        diff_time_minutes3 = basic.vuln_time_shijian_cha(3)
                        if int(diff_time_minutes3) > vuln_time_controls:
                            # 超过单位时间更新数据库中的时间
                            basic.vuln_last_time_update_lib(current_time3,3)
                            # shiro扫描程序用时统计相关
                            basic.scan_total_time_start_time(11)
                            # 提交扫描任务
                            shiro_status_result = basic.startshiro_lib()
                            # 在后台单独启动1个线程实时判断扫描器停止时间
                            def shiroscanendtime():
                                while True:
                                    time.sleep(1)
                                    basic.scan_total_time_final_end_time(11)
                            threading.Thread(target=shiroscanendtime).start()
                            
                        else:
                            shiro_status_result = "shiro扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"

            elif '4' in str(k):
                print("springboot")
                if int(verification_fingerprint_recognition) == 0:
                    # 获取系统当前时间
                    current_time4 = time.time()
                    # 当前时间和数据库中的作时间差
                    diff_time_minutes4 = basic.vuln_time_shijian_cha(4)
                    if int(diff_time_minutes4) > vuln_time_controls:
                        # 超过单位时间更新数据库中的时间
                        basic.vuln_last_time_update_lib(current_time4,4)
                        # springboot扫描程序用时统计相关
                        basic.scan_total_time_start_time(12)
                        # 提交扫描任务
                        springboot_scan_status_result = basic.startspringboot_lib()
                        # 在后台单独启动1个线程实时判断扫描器停止时间
                        def springbootscanendtime():
                            while True:
                                time.sleep(1)
                                basic.scan_total_time_final_end_time(12)
                        threading.Thread(target=springbootscanendtime).start()
                                    
                    else:
                        springboot_scan_status_result = "springboot扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
                elif int(verification_fingerprint_recognition) == 1:
                    # 判断是否已进行指纹识别
                    finger_part = basic.assets_finger_compare()
                    if finger_part == 2:
                        springboot_scan_status_result = "未进行指纹识别无法开启springboot扫描"
                    else:
                        # 获取系统当前时间
                        current_time4 = time.time()
                        # 当前时间和数据库中的作时间差
                        diff_time_minutes4 = basic.vuln_time_shijian_cha(4)
                        if int(diff_time_minutes4) > vuln_time_controls:
                            # 超过单位时间更新数据库中的时间
                            basic.vuln_last_time_update_lib(current_time4,4)
                            # springboot扫描程序用时统计相关
                            basic.scan_total_time_start_time(12)
                            # 提交扫描任务
                            springboot_scan_status_result = basic.startspringboot_lib()
                            # 在后台单独启动1个线程实时判断扫描器停止时间
                            def springbootscanendtime():
                                while True:
                                    time.sleep(1)
                                    basic.scan_total_time_final_end_time(12)
                            threading.Thread(target=springbootscanendtime).start()
                                        
                        else:
                            springboot_scan_status_result = "springboot扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
            elif '5' in str(k):
                print("thinkphp")
                if int(verification_fingerprint_recognition) == 0:
                    # 获取系统当前时间
                    current_time5 = time.time()
                    # 当前时间和数据库中的作时间差
                    diff_time_minutes5 = basic.vuln_time_shijian_cha(5)
                    if int(diff_time_minutes5) > vuln_time_controls:
                        # 超过单位时间更新数据库中的时间
                        basic.vuln_last_time_update_lib(current_time5,5)
                        # thinkphp扫描程序用时统计相关
                        basic.scan_total_time_start_time(13)
                        # 提交扫描任务
                        thinkphp_status_result = basic.startthinkphp_lib()
                        # 在后台单独启动1个线程实时判断扫描器停止时间
                        def thinkphpscanendtime():
                            while True:
                                time.sleep(1)
                                basic.scan_total_time_final_end_time(13)
                        threading.Thread(target=thinkphpscanendtime).start()
                                    
                    else:
                        thinkphp_status_result = "thinkphp扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
                elif int(verification_fingerprint_recognition) == 1:
                    # 判断是否已进行指纹识别
                    finger_part = basic.assets_finger_compare()
                    if finger_part == 2:
                        thinkphp_status_result = "未进行指纹识别无法开启thinkphp扫描"
                    else:
                        # 获取系统当前时间
                        current_time5 = time.time()
                        # 当前时间和数据库中的作时间差
                        diff_time_minutes5 = basic.vuln_time_shijian_cha(5)
                        if int(diff_time_minutes5) > vuln_time_controls:
                            # 超过单位时间更新数据库中的时间
                            basic.vuln_last_time_update_lib(current_time5,5)
                            # thinkphp扫描程序用时统计相关
                            basic.scan_total_time_start_time(13)
                            # 提交扫描任务
                            thinkphp_status_result = basic.startthinkphp_lib()
                            # 在后台单独启动1个线程实时判断扫描器停止时间
                            def thinkphpscanendtime():
                                while True:
                                    time.sleep(1)
                                    basic.scan_total_time_final_end_time(13)
                            threading.Thread(target=thinkphpscanendtime).start()
                                        
                        else:
                            thinkphp_status_result = "thinkphp扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
            elif '6' in str(k):
                print("afrog")
                if int(verification_fingerprint_recognition) == 0:
                    # 获取系统当前时间
                    current_time6 = time.time()
                    # 当前时间和数据库中的作时间差
                    diff_time_minutes6 = basic.vuln_time_shijian_cha(6)
                    if int(diff_time_minutes6) > vuln_time_controls:
                        # 超过单位时间更新数据库中的时间
                        basic.vuln_last_time_update_lib(current_time6,6)
                        # afrog扫描程序用时统计相关
                        basic.scan_total_time_start_time(18)
                        # 提交扫描任务
                        start_afrog_result = basic.startafrog_lib()
                        # 在后台单独启动1个线程实时判断扫描器停止时间
                        def afrogscanendtime():
                            while True:
                                time.sleep(1)
                                basic.scan_total_time_final_end_time(18)
                        threading.Thread(target=afrogscanendtime).start()
                                    
                    else:
                        start_afrog_result = "afrog扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
                elif int(verification_fingerprint_recognition) == 1:
                    # 判断是否已进行指纹识别
                    finger_part = basic.assets_finger_compare()
                    if finger_part == 2:
                        start_afrog_result = "未进行指纹识别无法开启afrog扫描"
                    else:
                        # 获取系统当前时间
                        current_time6 = time.time()
                        # 当前时间和数据库中的作时间差
                        diff_time_minutes6 = basic.vuln_time_shijian_cha(6)
                        if int(diff_time_minutes6) > vuln_time_controls:
                            # 超过单位时间更新数据库中的时间
                            basic.vuln_last_time_update_lib(current_time6,6)
                            # afrog扫描程序用时统计相关
                            basic.scan_total_time_start_time(18)
                            # 提交扫描任务
                            start_afrog_result = basic.startafrog_lib()
                            # 在后台单独启动1个线程实时判断扫描器停止时间
                            def afrogscanendtime():
                                while True:
                                    time.sleep(1)
                                    basic.scan_total_time_final_end_time(18)
                            threading.Thread(target=afrogscanendtime).start()
                                        
                        else:
                            start_afrog_result = "afrog扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
            elif '7' in str(k):
                print("fscan")
                if int(verification_fingerprint_recognition) == 0:
                    # 获取系统当前时间
                    current_time7 = time.time()
                    # 当前时间和数据库中的作时间差
                    diff_time_minutes7 = basic.vuln_time_shijian_cha(7)
                    if int(diff_time_minutes7) > vuln_time_controls:
                        # 超过单位时间更新数据库中的时间
                        basic.vuln_last_time_update_lib(current_time7,7)
                        # fscan扫描程序用时统计相关
                        basic.scan_total_time_start_time(19)
                        # 提交扫描任务
                        fscan_status_result = basic.startfscan_lib(fscanpartname,fscanpartname1)
                        # 在后台单独启动1个线程实时判断扫描器停止时间
                        def fscanscanendtime():
                            while True:
                                time.sleep(1)
                                basic.scan_total_time_final_end_time(19)
                        threading.Thread(target=fscanscanendtime).start()
                                    
                    else:
                        fscan_status_result = "fscan扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
                elif int(verification_fingerprint_recognition) == 1:
                    # 判断是否已进行指纹识别
                    finger_part = basic.assets_finger_compare()
                    if finger_part == 2:
                        fscan_status_result = "未进行指纹识别无法开启fscan扫描"
                    else:
                        # 获取系统当前时间
                        current_time7 = time.time()
                        # 当前时间和数据库中的作时间差
                        diff_time_minutes7 = basic.vuln_time_shijian_cha(7)
                        if int(diff_time_minutes7) > vuln_time_controls:
                            # 超过单位时间更新数据库中的时间
                            basic.vuln_last_time_update_lib(current_time7,7)
                            # fscan扫描程序用时统计相关
                            basic.scan_total_time_start_time(19)
                            # 提交扫描任务
                            fscan_status_result = basic.startfscan_lib(fscanpartname,fscanpartname1)
                            # 在后台单独启动1个线程实时判断扫描器停止时间
                            def fscanscanendtime():
                                while True:
                                    time.sleep(1)
                                    basic.scan_total_time_final_end_time(19)
                            threading.Thread(target=fscanscanendtime).start()
                                        
                        else:
                            fscan_status_result = "fscan扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
            elif '8' in str(k):
                print("弱口令")
                if int(verification_fingerprint_recognition) == 0:
                    # 获取系统当前时间
                    current_time8 = time.time()
                    # 当前时间和数据库中的作时间差
                    diff_time_minutes8 = basic.vuln_time_shijian_cha(8)
                    if int(diff_time_minutes8) > vuln_time_controls:
                        # 超过单位时间更新数据库中的时间
                        basic.vuln_last_time_update_lib(current_time8,8)
                        # 弱口令扫描程序用时统计相关
                        basic.scan_total_time_start_time(20)
                        # 提交扫描任务
                        hydra_scan_result = basic.starthydra_lib(hydrapart)
                        # 在后台单独启动1个线程实时判断扫描器停止时间
                        def weakpassscanendtime():
                            while True:
                                time.sleep(1)
                                basic.scan_total_time_final_end_time(20)
                        threading.Thread(target=weakpassscanendtime).start()
                                                
                    else:
                        hydra_scan_result = "弱口令扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
                elif int(verification_fingerprint_recognition) == 1:
                    # 判断是否已进行指纹识别
                    finger_part = basic.assets_finger_compare()
                    if finger_part == 2:
                        hydra_scan_result = "未进行指纹识别无法开启弱口令扫描"
                    else:
                        # 获取系统当前时间
                        current_time8 = time.time()
                        # 当前时间和数据库中的作时间差
                        diff_time_minutes8 = basic.vuln_time_shijian_cha(8)
                        if int(diff_time_minutes8) > vuln_time_controls:
                            # 超过单位时间更新数据库中的时间
                            basic.vuln_last_time_update_lib(current_time8,8)
                            # 弱口令扫描程序用时统计相关
                            basic.scan_total_time_start_time(20)
                            # 提交扫描任务
                            hydra_scan_result = basic.starthydra_lib(hydrapart)
                            # 在后台单独启动1个线程实时判断扫描器停止时间
                            def weakpassscanendtime():
                                while True:
                                    time.sleep(1)
                                    basic.scan_total_time_final_end_time(20)
                            threading.Thread(target=weakpassscanendtime).start()
                                                    
                        else:
                            hydra_scan_result = "弱口令扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
            elif '9' in str(k):
                print("api接口")
                if int(verification_fingerprint_recognition) == 0:
                    # 获取系统当前时间
                    current_time9 = time.time()
                    # 当前时间和数据库中的作时间差
                    diff_time_minutes9 = basic.vuln_time_shijian_cha(9)
                    if int(diff_time_minutes9) > vuln_time_controls:
                        # 超过单位时间更新数据库中的时间
                        basic.vuln_last_time_update_lib(current_time9,9)
                        # api接口扫描程序用时统计相关
                        basic.scan_total_time_start_time(21)
                        # 提交扫描任务
                        urlfinder_status_result = basic.starturlfinder_lib()
                        # 在后台单独启动1个线程实时判断扫描器停止时间
                        def apiinterfacescanendtime():
                            while True:
                                time.sleep(1)
                                basic.scan_total_time_final_end_time(21)
                        threading.Thread(target=apiinterfacescanendtime).start()
                                                
                    else:
                        urlfinder_status_result = "api接口扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
                elif int(verification_fingerprint_recognition) == 1:
                    # 判断是否已进行指纹识别
                    finger_part = basic.assets_finger_compare()
                    if finger_part == 2:
                        urlfinder_status_result = "未进行指纹识别无法开启api接口扫描"
                    else:
                        # 获取系统当前时间
                        current_time9 = time.time()
                        # 当前时间和数据库中的作时间差
                        diff_time_minutes9 = basic.vuln_time_shijian_cha(9)
                        if int(diff_time_minutes9) > vuln_time_controls:
                            # 超过单位时间更新数据库中的时间
                            basic.vuln_last_time_update_lib(current_time9,9)
                            # api接口扫描程序用时统计相关
                            basic.scan_total_time_start_time(21)
                            # 提交扫描任务
                            urlfinder_status_result = basic.starturlfinder_lib()
                            # 在后台单独启动1个线程实时判断扫描器停止时间
                            def apiinterfacescanendtime():
                                while True:
                                    time.sleep(1)
                                    basic.scan_total_time_final_end_time(21)
                            threading.Thread(target=apiinterfacescanendtime).start()
                                                    
                        else:
                            urlfinder_status_result = "api接口扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
            elif 'a' in str(k):
                print("vulmap")
                if int(verification_fingerprint_recognition) == 0:
                    # 获取系统当前时间
                    current_time10 = time.time()
                    # 当前时间和数据库中的作时间差
                    diff_time_minutes10 = basic.vuln_time_shijian_cha(10)
                    if int(diff_time_minutes10) > vuln_time_controls:
                        # 超过单位时间更新数据库中的时间
                        basic.vuln_last_time_update_lib(current_time10,10)
                        # vulmap扫描程序用时统计相关
                        basic.scan_total_time_start_time(22)
                        # 提交扫描任务
                        vummap_scan_result = basic.startvulmap_lib(vulnname)
                        # 在后台单独启动1个线程实时判断扫描器停止时间
                        def vulmapscanendtime():
                            while True:
                                time.sleep(1)
                                basic.scan_total_time_final_end_time(22)
                        threading.Thread(target=vulmapscanendtime).start()
                                                
                    else:
                        vummap_scan_result = "vulmap扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
                elif int(verification_fingerprint_recognition) == 1:
                    # 判断是否已进行指纹识别
                    finger_part = basic.assets_finger_compare()
                    if finger_part == 2:
                        vummap_scan_result = "未进行指纹识别无法开启vulmap扫描"
                    else:
                        # 获取系统当前时间
                        current_time10 = time.time()
                        # 当前时间和数据库中的作时间差
                        diff_time_minutes10 = basic.vuln_time_shijian_cha(10)
                        if int(diff_time_minutes10) > vuln_time_controls:
                            # 超过单位时间更新数据库中的时间
                            basic.vuln_last_time_update_lib(current_time10,10)
                            # vulmap扫描程序用时统计相关
                            basic.scan_total_time_start_time(22)
                            # 提交扫描任务
                            vummap_scan_result = basic.startvulmap_lib(vulnname)
                            # 在后台单独启动1个线程实时判断扫描器停止时间
                            def vulmapscanendtime():
                                while True:
                                    time.sleep(1)
                                    basic.scan_total_time_final_end_time(22)
                            threading.Thread(target=vulmapscanendtime).start()
                                                    
                        else:
                            vummap_scan_result = "vulmap扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
            elif 'b' in str(k):
                print("nuclei")
                if int(verification_fingerprint_recognition) == 0:
                    # 获取系统当前时间
                    current_time11 = time.time()
                    # 当前时间和数据库中的作时间差
                    diff_time_minutes11 = basic.vuln_time_shijian_cha(11)
                    if int(diff_time_minutes11) > vuln_time_controls:
                        # 超过单位时间更新数据库中的时间
                        basic.vuln_last_time_update_lib(current_time11,11)
                        # nuclei扫描程序用时统计相关
                        basic.scan_total_time_start_time(23)
                        # 提交扫描任务
                        nuclei_status_result = basic.startnuclei_lib(poc_dir)
                        # 在后台单独启动1个线程实时判断扫描器停止时间
                        def nucleiscanendtime():
                            while True:
                                time.sleep(1)
                                basic.scan_total_time_final_end_time(23)
                        threading.Thread(target=nucleiscanendtime).start()
                                                
                    else:
                        nuclei_status_result = "nuclei扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
                elif int(verification_fingerprint_recognition) == 1:
                    # 判断是否已进行指纹识别
                    finger_part = basic.assets_finger_compare()
                    if finger_part == 2:
                        nuclei_status_result = "未进行指纹识别无法开启nuclei扫描"
                    else:
                        # 获取系统当前时间
                        current_time11 = time.time()
                        # 当前时间和数据库中的作时间差
                        diff_time_minutes11 = basic.vuln_time_shijian_cha(11)
                        if int(diff_time_minutes11) > vuln_time_controls:
                            # 超过单位时间更新数据库中的时间
                            basic.vuln_last_time_update_lib(current_time11,11)
                            # nuclei扫描程序用时统计相关
                            basic.scan_total_time_start_time(23)
                            # 提交扫描任务
                            nuclei_status_result = basic.startnuclei_lib(poc_dir)
                            # 在后台单独启动1个线程实时判断扫描器停止时间
                            def nucleiscanendtime():
                                while True:
                                    time.sleep(1)
                                    basic.scan_total_time_final_end_time(23)
                            threading.Thread(target=nucleiscanendtime).start()
                                                    
                        else:
                            nuclei_status_result = "nuclei扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
            elif 'c' in str(k):
                print("泛微OA")
                if int(verification_fingerprint_recognition) == 0:
                    # 获取系统当前时间
                    current_time12 = time.time()
                    # 当前时间和数据库中的作时间差
                    diff_time_minutes12 = basic.vuln_time_shijian_cha(12)
                    if int(diff_time_minutes12) > vuln_time_controls:
                        # 超过单位时间更新数据库中的时间
                        basic.vuln_last_time_update_lib(current_time12,12)
                        # 泛微OA扫描程序用时统计相关
                        basic.scan_total_time_start_time(24)
                        # 提交扫描任务
                        weaver_status_result = basic.startweaver_lib()
                        # 在后台单独启动1个线程实时判断扫描器停止时间
                        def fanweioascanendtime():
                            while True:
                                time.sleep(1)
                                basic.scan_total_time_final_end_time(24)
                        threading.Thread(target=fanweioascanendtime).start()
                                                
                    else:
                        weaver_status_result = "泛微OA扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
                elif int(verification_fingerprint_recognition) == 1:
                    # 判断是否已进行指纹识别
                    finger_part = basic.assets_finger_compare()
                    if finger_part == 2:
                        weaver_status_result = "未进行指纹识别无法开启泛微OA扫描"
                    else:
                        # 获取系统当前时间
                        current_time12 = time.time()
                        # 当前时间和数据库中的作时间差
                        diff_time_minutes12 = basic.vuln_time_shijian_cha(12)
                        if int(diff_time_minutes12) > vuln_time_controls:
                            # 超过单位时间更新数据库中的时间
                            basic.vuln_last_time_update_lib(current_time12,12)
                            # 泛微OA扫描程序用时统计相关
                            basic.scan_total_time_start_time(24)
                            # 提交扫描任务
                            weaver_status_result = basic.startweaver_lib()
                            # 在后台单独启动1个线程实时判断扫描器停止时间
                            def fanweioascanendtime():
                                while True:
                                    time.sleep(1)
                                    basic.scan_total_time_final_end_time(24)
                            threading.Thread(target=fanweioascanendtime).start()
                                                    
                        else:
                            weaver_status_result = "泛微OA扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
            
            elif 'e' in str(k):
                print("ES未授权访问")
                if int(verification_fingerprint_recognition) == 0:
                    # 获取系统当前时间
                    current_time14 = time.time()
                    # 当前时间和数据库中的作时间差
                    diff_time_minutes14 = basic.vuln_time_shijian_cha(14)
                    if int(diff_time_minutes14) > vuln_time_controls:
                        # 超过单位时间更新数据库中的时间
                        basic.vuln_last_time_update_lib(current_time14,14)
                        # es扫描程序用时统计相关
                        basic.scan_total_time_start_time(14)
                        # 提交扫描任务
                        es_status_result = basic.startunes_lib()
                        # 在后台单独启动1个线程实时判断扫描器停止时间
                        def esscanendtime():
                            while True:
                                time.sleep(1)
                                basic.scan_total_time_final_end_time(14)
                        threading.Thread(target=esscanendtime).start()
                                 
                    else:
                        es_status_result = "Elasticsearch未授权访问扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
                elif int(verification_fingerprint_recognition) == 1:
                    # 判断是否已进行指纹识别
                    finger_part = basic.assets_finger_compare()
                    if finger_part == 2:
                        es_status_result = "未进行指纹识别无法开启ES相关漏洞扫描"
                    else:
                        # 获取系统当前时间
                        current_time14 = time.time()
                        # 当前时间和数据库中的作时间差
                        diff_time_minutes14 = basic.vuln_time_shijian_cha(14)
                        if int(diff_time_minutes14) > vuln_time_controls:
                            # 超过单位时间更新数据库中的时间
                            basic.vuln_last_time_update_lib(current_time14,14)
                            # es扫描程序用时统计相关
                            basic.scan_total_time_start_time(14)
                            # 提交扫描任务
                            es_status_result = basic.startunes_lib()
                            # 在后台单独启动1个线程实时判断扫描器停止时间
                            def esscanendtime():
                                while True:
                                    time.sleep(1)
                                    basic.scan_total_time_final_end_time(14)
                            threading.Thread(target=esscanendtime).start()
                                     
                        else:
                            es_status_result = "Elasticsearch未授权访问扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
                    
            elif 'f' in str(k):
                print("nacos漏洞扫描")
                if int(verification_fingerprint_recognition) == 0:
                    # 获取系统当前时间
                    current_time15 = time.time()
                    # 当前时间和数据库中的作时间差
                    diff_time_minutes15 = basic.vuln_time_shijian_cha(15)
                    if int(diff_time_minutes15) > vuln_time_controls:
                        # 超过单位时间更新数据库中的时间
                        basic.vuln_last_time_update_lib(current_time15,15)
                        # Nacos扫描程序用时统计相关
                        basic.scan_total_time_start_time(15)
                        # 提交扫描任务
                        nacos_status_result = basic.startnacosscan_lib()
                        # 在后台单独启动1个线程实时判断扫描器停止时间
                        def nacosscanendtime():
                            while True:
                                time.sleep(1)
                                basic.scan_total_time_final_end_time(15)
                        threading.Thread(target=nacosscanendtime).start()
                                     
                    else:
                        nacos_status_result = "nacos漏洞扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
                elif int(verification_fingerprint_recognition) == 1:
                    # 判断是否已进行指纹识别
                    finger_part = basic.assets_finger_compare()
                    if finger_part == 2:
                        nacos_status_result = "未进行指纹识别无法开启nacos漏洞扫描"
                    else:
                        # 获取系统当前时间
                        current_time15 = time.time()
                        # 当前时间和数据库中的作时间差
                        diff_time_minutes15 = basic.vuln_time_shijian_cha(15)
                        if int(diff_time_minutes15) > vuln_time_controls:
                            # 超过单位时间更新数据库中的时间
                            basic.vuln_last_time_update_lib(current_time15,15)
                            # Nacos扫描程序用时统计相关
                            basic.scan_total_time_start_time(15)
                            # 提交扫描任务
                            nacos_status_result = basic.startnacosscan_lib()
                            # 在后台单独启动1个线程实时判断扫描器停止时间
                            def nacosscanendtime():
                                while True:
                                    time.sleep(1)
                                    basic.scan_total_time_final_end_time(15)
                            threading.Thread(target=nacosscanendtime).start()
                                         
                        else:
                            nacos_status_result = "nacos漏洞扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
            
            elif 'g' in str(k):
                print("tomcat漏洞扫描")
                if int(verification_fingerprint_recognition) == 0:
                    # 获取系统当前时间
                    current_time16 = time.time()
                    # 当前时间和数据库中的作时间差
                    diff_time_minutes16 = basic.vuln_time_shijian_cha(16)
                    if int(diff_time_minutes16) > vuln_time_controls:
                        # 超过单位时间更新数据库中的时间
                        basic.vuln_last_time_update_lib(current_time16,16)
                        # tomcat扫描程序用时统计相关
                        basic.scan_total_time_start_time(16)
                        # 提交扫描任务
                        tomcat_status_result = basic.starttomcatscan_lib()
                        # 在后台单独启动1个线程实时判断扫描器停止时间
                        def tomcatscanendtime():
                            while True:
                                time.sleep(1)
                                basic.scan_total_time_final_end_time(16)
                        threading.Thread(target=tomcatscanendtime).start()
                                     
                    else:
                        tomcat_status_result = "tomcat漏洞扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
                elif int(verification_fingerprint_recognition) == 1:
                    # 判断是否已进行指纹识别
                    finger_part = basic.assets_finger_compare()
                    if finger_part == 2:
                        tomcat_status_result = "未进行指纹识别无法开启tomcat漏洞扫描"
                    else:
                        # 获取系统当前时间
                        current_time16 = time.time()
                        # 当前时间和数据库中的作时间差
                        diff_time_minutes16 = basic.vuln_time_shijian_cha(16)
                        if int(diff_time_minutes16) > vuln_time_controls:
                            # 超过单位时间更新数据库中的时间
                            basic.vuln_last_time_update_lib(current_time16,16)
                            # tomcat扫描程序用时统计相关
                            basic.scan_total_time_start_time(16)
                            # 提交扫描任务
                            tomcat_status_result = basic.starttomcatscan_lib()
                            # 在后台单独启动1个线程实时判断扫描器停止时间
                            def tomcatscanendtime():
                                while True:
                                    time.sleep(1)
                                    basic.scan_total_time_final_end_time(16)
                            threading.Thread(target=tomcatscanendtime).start()
                                         
                        else:
                            tomcat_status_result = "tomcat漏洞扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
            elif 'h' in str(k):
                
                # 这段代码不起作用，迁移到系统配置功能
                print("开启jndi服务")
                # 获取系统当前时间
                current_time17 = time.time()
                # 当前时间和数据库中的作时间差
                diff_time_minutes17 = basic.vuln_time_shijian_cha(17)
                if int(diff_time_minutes17) > vuln_time_controls:
                    # 超过单位时间更新数据库中的时间
                    basic.vuln_last_time_update_lib(current_time17,17)
                    # 提交扫描任务
                    jndi_status_result = basic.startjndi_lib()
                                 
                else:
                    jndi_status_result = "JNDI服务程序"+str(info_time_controls)+"分钟内不允许重复扫描"
            elif 'i' in str(k):
                print("开启fastjson漏洞扫描")
                if int(verification_fingerprint_recognition) == 0:
                    jndi_status = os.popen('bash /TIP/info_scan/finger.sh jndi_server_status').read()
                    jndi_python_status = os.popen('bash /TIP/info_scan/finger.sh jndi_python_server_status').read()
                    if "running" in jndi_status and "running" in jndi_python_status:
                        print("2")
                        # 获取系统当前时间
                        current_time18 = time.time()
                        # 当前时间和数据库中的作时间差
                        diff_time_minutes18 = basic.vuln_time_shijian_cha(18)
                        if int(diff_time_minutes18) > vuln_time_controls:
                            # 超过单位时间更新数据库中的时间
                            basic.vuln_last_time_update_lib(current_time18,18)
                            # fastjson扫描程序用时统计相关
                            basic.scan_total_time_start_time(17)
                            # 提交扫描任务
                            fastjson_status_result = basic.startfastjson_lib()
                            # 在后台单独启动1个线程实时判断扫描器停止时间
                            def fastjsonscanendtime():
                                while True:
                                    time.sleep(1)
                                    basic.scan_total_time_final_end_time(17)
                            threading.Thread(target=fastjsonscanendtime).start()
                                         
                        else:
                            fastjson_status_result = "fastjson漏洞扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
                    else:
                        fastjson_status_result = basic.startfastjson_lib()
                elif int(verification_fingerprint_recognition) == 1:
                    # 判断是否已进行指纹识别
                    finger_part = basic.assets_finger_compare()
                    if finger_part == 2:
                        fastjson_status_result = "未进行指纹识别无法开启fastjson漏洞扫描"
                    else:
                        jndi_status = os.popen('bash /TIP/info_scan/finger.sh jndi_server_status').read()
                        jndi_python_status = os.popen('bash /TIP/info_scan/finger.sh jndi_python_server_status').read()
                        if "running" in jndi_status and "running" in jndi_python_status:
                            print("2")
                            # 获取系统当前时间
                            current_time18 = time.time()
                            # 当前时间和数据库中的作时间差
                            diff_time_minutes18 = basic.vuln_time_shijian_cha(18)
                            if int(diff_time_minutes18) > vuln_time_controls:
                                # 超过单位时间更新数据库中的时间
                                basic.vuln_last_time_update_lib(current_time18,18)
                                # fastjson扫描程序用时统计相关
                                basic.scan_total_time_start_time(17)
                                # 提交扫描任务
                                fastjson_status_result = basic.startfastjson_lib()
                                # 在后台单独启动1个线程实时判断扫描器停止时间
                                def fastjsonscanendtime():
                                    while True:
                                        time.sleep(1)
                                        basic.scan_total_time_final_end_time(17)
                                threading.Thread(target=fastjsonscanendtime).start()
                                             
                            else:
                                fastjson_status_result = "fastjson漏洞扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
                        else:
                            fastjson_status_result = basic.startfastjson_lib()
                    
            elif 'j' in str(k):
                print("开启xray被动监听")
                # xray_status_result = basic.startxray_lib()
                # 获取系统当前时间
                current_time19 = time.time()
                # 当前时间和数据库中的作时间差
                diff_time_minutes19 = basic.vuln_time_shijian_cha(19)
                if int(diff_time_minutes19) > vuln_time_controls:
                    # 超过单位时间更新数据库中的时间
                    basic.vuln_last_time_update_lib(current_time19,19)
                    # xray扫描程序用时统计相关
                    basic.scan_total_time_start_time(26)
                    # 提交扫描任务
                    xray_status_result = basic.startxray_lib()
                    # 在后台单独启动1个线程实时判断扫描器停止时间
                    def xrayscanendtime():
                        while True:
                            time.sleep(1)
                            basic.scan_total_time_final_end_time(26)
                    threading.Thread(target=xrayscanendtime).start()
                                 
                else:
                    xray_status_result = "xray漏洞扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
            elif 'k' in str(k):
                print("开启致远OA漏洞扫描")
                if int(verification_fingerprint_recognition) == 0:
                    # 获取系统当前时间
                    current_time20 = time.time()
                    # 当前时间和数据库中的作时间差
                    diff_time_minutes20 = basic.vuln_time_shijian_cha(20)
                    if int(diff_time_minutes20) > vuln_time_controls:
                        # 超过单位时间更新数据库中的时间
                        basic.vuln_last_time_update_lib(current_time20,20)
                        # 致远OA扫描程序用时统计相关
                        basic.scan_total_time_start_time(27)
                        # 提交扫描任务
                        seeyon_status_result = basic.startseeyonscan_lib()
                        # 在后台单独启动1个线程实时判断扫描器停止时间
                        def seeyonscanendtime():
                            while True:
                                time.sleep(1)
                                basic.scan_total_time_final_end_time(27)
                        threading.Thread(target=seeyonscanendtime).start()
                                                
                    else:
                        seeyon_status_result = "致远OA扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
                elif int(verification_fingerprint_recognition) == 1:
                    # 判断是否已进行指纹识别
                    finger_part = basic.assets_finger_compare()
                    if finger_part == 2:
                        seeyon_status_result = "未进行指纹识别无法开启致远OA扫描"
                    else:
                        # 获取系统当前时间
                        current_time20 = time.time()
                        # 当前时间和数据库中的作时间差
                        diff_time_minutes20 = basic.vuln_time_shijian_cha(20)
                        if int(diff_time_minutes20) > vuln_time_controls:
                            # 超过单位时间更新数据库中的时间
                            basic.vuln_last_time_update_lib(current_time20,20)
                            # 致远OA扫描程序用时统计相关
                            basic.scan_total_time_start_time(27)
                            # 提交扫描任务
                            seeyon_status_result = basic.startseeyonscan_lib()
                            # 在后台单独启动1个线程实时判断扫描器停止时间
                            def seeyonscanendtime():
                                while True:
                                    time.sleep(1)
                                    basic.scan_total_time_final_end_time(27)
                            threading.Thread(target=seeyonscanendtime).start()
                                                    
                        else:
                            seeyon_status_result = "致远OA扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
            elif 'l' in str(k):
                print("开启用友OA漏洞扫描")
                if int(verification_fingerprint_recognition) == 0:
                    # 获取系统当前时间
                    current_time21 = time.time()
                    # 当前时间和数据库中的作时间差
                    diff_time_minutes21 = basic.vuln_time_shijian_cha(21)
                    if int(diff_time_minutes21) > vuln_time_controls:
                        # 超过单位时间更新数据库中的时间
                        basic.vuln_last_time_update_lib(current_time21,21)
                        # 用友OA扫描程序用时统计相关
                        basic.scan_total_time_start_time(28)
                        # 提交扫描任务
                        yonsuite_status_result = basic.startyonsuitescan_lib()
                        # 在后台单独启动1个线程实时判断扫描器停止时间
                        def yonsuitescanendtime():
                            while True:
                                time.sleep(1)
                                basic.scan_total_time_final_end_time(28)
                        threading.Thread(target=yonsuitescanendtime).start()
                                                
                    else:
                        yonsuite_status_result = "用友OA扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
                elif int(verification_fingerprint_recognition) == 1:
                    # 判断是否已进行指纹识别
                    finger_part = basic.assets_finger_compare()
                    if finger_part == 2:
                        yonsuite_status_result = "未进行指纹识别无法开启用友OA扫描"
                    else:
                        # 获取系统当前时间
                        current_time21 = time.time()
                        # 当前时间和数据库中的作时间差
                        diff_time_minutes21 = basic.vuln_time_shijian_cha(21)
                        if int(diff_time_minutes21) > vuln_time_controls:
                            # 超过单位时间更新数据库中的时间
                            basic.vuln_last_time_update_lib(current_time21,21)
                            # 用友OA扫描程序用时统计相关
                            basic.scan_total_time_start_time(28)
                            # 提交扫描任务
                            yonsuite_status_result = basic.startyonsuitescan_lib()
                            # 在后台单独启动1个线程实时判断扫描器停止时间
                            def yonsuitescanendtime():
                                while True:
                                    time.sleep(1)
                                    basic.scan_total_time_final_end_time(28)
                            threading.Thread(target=yonsuitescanendtime).start()
                                                    
                        else:
                            yonsuite_status_result = "用友OA扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
            elif 'm' in str(k):
                print("开启金蝶OA漏洞扫描")
                if int(verification_fingerprint_recognition) == 0:
                    # 获取系统当前时间
                    current_time22 = time.time()
                    # 当前时间和数据库中的作时间差
                    diff_time_minutes22 = basic.vuln_time_shijian_cha(22)
                    if int(diff_time_minutes22) > vuln_time_controls:
                        # 超过单位时间更新数据库中的时间
                        basic.vuln_last_time_update_lib(current_time22,22)
                        # 金蝶OA扫描程序用时统计相关
                        basic.scan_total_time_start_time(29)
                        # 提交扫描任务
                        kingdee_status_result = basic.startkingdeescan_lib()
                        # 在后台单独启动1个线程实时判断扫描器停止时间
                        def kingdeescanendtime():
                            while True:
                                time.sleep(1)
                                basic.scan_total_time_final_end_time(29)
                        threading.Thread(target=kingdeescanendtime).start()
                                                
                    else:
                        kingdee_status_result = "金蝶OA扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
                elif int(verification_fingerprint_recognition) == 1:
                    # 判断是否已进行指纹识别
                    finger_part = basic.assets_finger_compare()
                    if finger_part == 2:
                        kingdee_status_result = "未进行指纹识别无法开启金蝶OA扫描"
                    else:
                        # 获取系统当前时间
                        current_time22 = time.time()
                        # 当前时间和数据库中的作时间差
                        diff_time_minutes22 = basic.vuln_time_shijian_cha(22)
                        if int(diff_time_minutes22) > vuln_time_controls:
                            # 超过单位时间更新数据库中的时间
                            basic.vuln_last_time_update_lib(current_time22,22)
                            # 金蝶OA扫描程序用时统计相关
                            basic.scan_total_time_start_time(29)
                            # 提交扫描任务
                            kingdee_status_result = basic.startkingdeescan_lib()
                            # 在后台单独启动1个线程实时判断扫描器停止时间
                            def kingdeescanendtime():
                                while True:
                                    time.sleep(1)
                                    basic.scan_total_time_final_end_time(29)
                            threading.Thread(target=kingdeescanendtime).start()
                                                    
                        else:
                            kingdee_status_result = "金蝶OA扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
            elif 'n' in str(k):
                print("开启万户OA漏洞扫描")
                if int(verification_fingerprint_recognition) == 0:
                    # 获取系统当前时间
                    current_time23 = time.time()
                    # 当前时间和数据库中的作时间差
                    diff_time_minutes23 = basic.vuln_time_shijian_cha(23)
                    if int(diff_time_minutes23) > vuln_time_controls:
                        # 超过单位时间更新数据库中的时间
                        basic.vuln_last_time_update_lib(current_time23,23)
                        # 金蝶OA扫描程序用时统计相关
                        basic.scan_total_time_start_time(30)
                        # 提交扫描任务
                        wanhu_status_result = basic.startwanhuscan_lib()
                        # 在后台单独启动1个线程实时判断扫描器停止时间
                        def wanhuscanendtime():
                            while True:
                                time.sleep(1)
                                basic.scan_total_time_final_end_time(30)
                        threading.Thread(target=wanhuscanendtime).start()
                                                
                    else:
                        wanhu_status_result = "万户OA扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
                elif int(verification_fingerprint_recognition) == 1:
                    # 判断是否已进行指纹识别
                    finger_part = basic.assets_finger_compare()
                    if finger_part == 2:
                        wanhu_status_result = "未进行指纹识别无法开启万户OA扫描"
                    else:
                        # 获取系统当前时间
                        current_time23 = time.time()
                        # 当前时间和数据库中的作时间差
                        diff_time_minutes23 = basic.vuln_time_shijian_cha(23)
                        if int(diff_time_minutes23) > vuln_time_controls:
                            # 超过单位时间更新数据库中的时间
                            basic.vuln_last_time_update_lib(current_time23,23)
                            # 金蝶OA扫描程序用时统计相关
                            basic.scan_total_time_start_time(30)
                            # 提交扫描任务
                            wanhu_status_result = basic.startwanhuscan_lib()
                            # 在后台单独启动1个线程实时判断扫描器停止时间
                            def wanhuscanendtime():
                                while True:
                                    time.sleep(1)
                                    basic.scan_total_time_final_end_time(30)
                            threading.Thread(target=wanhuscanendtime).start()
                                                    
                        else:
                            wanhu_status_result = "万户OA扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
            
            elif 'o' in str(k):
                # 未授权专项不做指纹识别判断
                print("开启redis未授权漏洞扫描")
                # 获取系统当前时间
                current_time24 = time.time()
                # 当前时间和数据库中的作时间差
                diff_time_minutes24 = basic.vuln_time_shijian_cha(24)
                if int(diff_time_minutes24) > vuln_time_controls:
                    # 超过单位时间更新数据库中的时间
                    basic.vuln_last_time_update_lib(current_time24,24)
                    # 金蝶OA扫描程序用时统计相关
                    basic.scan_total_time_start_time(32)
                    # 提交扫描任务
                    redis_status_result = basic.startunredisscan_lib()
                    # 在后台单独启动1个线程实时判断扫描器停止时间
                    def redisscanendtime():
                        while True:
                            time.sleep(1)
                            basic.scan_total_time_final_end_time(32)
                    threading.Thread(target=redisscanendtime).start()
                                            
                else:
                    redis_status_result = "redis未授权扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
                    
            elif 'p' in str(k):
                # 未授权专项不做指纹识别判断
                print("开启mongodb未授权漏洞扫描")
                # 获取系统当前时间
                current_time25 = time.time()
                # 当前时间和数据库中的作时间差
                diff_time_minutes25 = basic.vuln_time_shijian_cha(25)
                if int(diff_time_minutes25) > vuln_time_controls:
                    # 超过单位时间更新数据库中的时间
                    basic.vuln_last_time_update_lib(current_time25,25)
                    # 金蝶OA扫描程序用时统计相关
                    basic.scan_total_time_start_time(33)
                    # 提交扫描任务
                    mongodb_status_result = basic.startunrmongodbscan_lib()
                    # 在后台单独启动1个线程实时判断扫描器停止时间
                    def mongodbscanendtime():
                        while True:
                            time.sleep(1)
                            basic.scan_total_time_final_end_time(33)
                    threading.Thread(target=mongodbscanendtime).start()
                                            
                else:
                    mongodb_status_result = "mongodb未授权扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
            
            elif 'q' in str(k):
                # 未授权专项不做指纹识别判断
                print("开启memcached未授权漏洞扫描")
                # 获取系统当前时间
                current_time26 = time.time()
                # 当前时间和数据库中的作时间差
                diff_time_minutes26 = basic.vuln_time_shijian_cha(26)
                if int(diff_time_minutes26) > vuln_time_controls:
                    # 超过单位时间更新数据库中的时间
                    basic.vuln_last_time_update_lib(current_time26,26)
                    # memcached扫描程序用时统计相关
                    basic.scan_total_time_start_time(34)
                    # 提交扫描任务
                    memcached_status_result = basic.startunmemcachedscan_lib()
                    # 在后台单独启动1个线程实时判断扫描器停止时间
                    def memcachedscanendtime():
                        while True:
                            time.sleep(1)
                            basic.scan_total_time_final_end_time(34)
                    threading.Thread(target=memcachedscanendtime).start()
                                            
                else:
                    memcached_status_result = "memcached未授权扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
            
            elif 'r' in str(k):
                # 未授权专项不做指纹识别判断
                print("开启zookeeper未授权漏洞扫描")
                # 获取系统当前时间
                current_time27 = time.time()
                # 当前时间和数据库中的作时间差
                diff_time_minutes27 = basic.vuln_time_shijian_cha(27)
                if int(diff_time_minutes27) > vuln_time_controls:
                    # 超过单位时间更新数据库中的时间
                    basic.vuln_last_time_update_lib(current_time27,27)
                    # zookeeper扫描程序用时统计相关
                    basic.scan_total_time_start_time(35)
                    # 提交扫描任务
                    zookeeper_status_result = basic.startunzookeeperscan_lib()
                    # 在后台单独启动1个线程实时判断扫描器停止时间
                    def zookeeperscanendtime():
                        while True:
                            time.sleep(1)
                            basic.scan_total_time_final_end_time(35)
                    threading.Thread(target=zookeeperscanendtime).start()
                                            
                else:
                    zookeeper_status_result = "zookeeper未授权扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"

            elif 's' in str(k):
                # 未授权专项不做指纹识别判断
                print("开启ftp未授权漏洞扫描")
                # 获取系统当前时间
                current_time28 = time.time()
                # 当前时间和数据库中的作时间差
                diff_time_minutes28 = basic.vuln_time_shijian_cha(28)
                if int(diff_time_minutes28) > vuln_time_controls:
                    # 超过单位时间更新数据库中的时间
                    basic.vuln_last_time_update_lib(current_time28,28)
                    # ftp扫描程序用时统计相关
                    basic.scan_total_time_start_time(36)
                    # 提交扫描任务
                    ftp_status_result = basic.startunftpscan_lib()
                    # 在后台单独启动1个线程实时判断扫描器停止时间
                    def ftpscanendtime():
                        while True:
                            time.sleep(1)
                            basic.scan_total_time_final_end_time(36)
                    threading.Thread(target=ftpscanendtime).start()
                                            
                else:
                    ftp_status_result = "ftp未授权扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
            
            elif 't' in str(k):
                # 未授权专项不做指纹识别判断
                print("开启couchdb未授权漏洞扫描")
                # 获取系统当前时间
                current_time29 = time.time()
                # 当前时间和数据库中的作时间差
                diff_time_minutes29 = basic.vuln_time_shijian_cha(29)
                if int(diff_time_minutes29) > vuln_time_controls:
                    # 超过单位时间更新数据库中的时间
                    basic.vuln_last_time_update_lib(current_time29,29)
                    # couchdb扫描程序用时统计相关
                    basic.scan_total_time_start_time(37)
                    # 提交扫描任务
                    couchdb_status_result = basic.startuncouchdbscan_lib()
                    # 在后台单独启动1个线程实时判断扫描器停止时间
                    def couchdbscanendtime():
                        while True:
                            time.sleep(1)
                            basic.scan_total_time_final_end_time(37)
                    threading.Thread(target=couchdbscanendtime).start()
                                            
                else:
                    couchdb_status_result = "couchdb未授权扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
            
            elif 'u' in str(k):
                # 未授权专项不做指纹识别判断
                print("开启docker未授权漏洞扫描")
                # 获取系统当前时间
                current_time30 = time.time()
                # 当前时间和数据库中的作时间差
                diff_time_minutes30 = basic.vuln_time_shijian_cha(30)
                if int(diff_time_minutes30) > vuln_time_controls:
                    # 超过单位时间更新数据库中的时间
                    basic.vuln_last_time_update_lib(current_time30,30)
                    # docker扫描程序用时统计相关
                    basic.scan_total_time_start_time(38)
                    # 提交扫描任务
                    docker_status_result = basic.startundockerscan_lib()
                    # 在后台单独启动1个线程实时判断扫描器停止时间
                    def dockerscanendtime():
                        while True:
                            time.sleep(1)
                            basic.scan_total_time_final_end_time(38)
                    threading.Thread(target=dockerscanendtime).start()
                                            
                else:
                    docker_status_result = "docker未授权扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
            
            elif 'v' in str(k):
                # 未授权专项不做指纹识别判断
                print("开启hadoop未授权漏洞扫描")
                # 获取系统当前时间
                current_time31 = time.time()
                # 当前时间和数据库中的作时间差
                diff_time_minutes31 = basic.vuln_time_shijian_cha(31)
                if int(diff_time_minutes31) > vuln_time_controls:
                    # 超过单位时间更新数据库中的时间
                    basic.vuln_last_time_update_lib(current_time31,31)
                    # hadoop扫描程序用时统计相关
                    basic.scan_total_time_start_time(39)
                    # 提交扫描任务
                    hadoop_status_result = basic.startunhadoopscan_lib()
                    # 在后台单独启动1个线程实时判断扫描器停止时间
                    def hadoopscanendtime():
                        while True:
                            time.sleep(1)
                            basic.scan_total_time_final_end_time(39)
                    threading.Thread(target=hadoopscanendtime).start()
                                            
                else:
                    hadoop_status_result = "hadoop未授权扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"

            elif 'w' in str(k):
                # 未授权专项不做指纹识别判断
                print("开启NFS未授权漏洞扫描")
                # 获取系统当前时间
                current_time32 = time.time()
                # 当前时间和数据库中的作时间差
                diff_time_minutes32 = basic.vuln_time_shijian_cha(32)
                if int(diff_time_minutes32) > vuln_time_controls:
                    # 超过单位时间更新数据库中的时间
                    basic.vuln_last_time_update_lib(current_time32,32)
                    # NFS扫描程序用时统计相关
                    basic.scan_total_time_start_time(40)
                    # 提交扫描任务
                    nfs_status_result = basic.startunnfsscan_lib()
                    # 在后台单独启动1个线程实时判断扫描器停止时间
                    def nfsscanendtime():
                        while True:
                            time.sleep(1)
                            basic.scan_total_time_final_end_time(40)
                    threading.Thread(target=nfsscanendtime).start()
                                            
                else:
                    nfs_status_result = "NFS未授权扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
            elif 'x' in str(k):
                # 未授权专项不做指纹识别判断
                print("开启rsync未授权漏洞扫描")
                # 获取系统当前时间
                current_time33 = time.time()
                # 当前时间和数据库中的作时间差
                diff_time_minutes33 = basic.vuln_time_shijian_cha(33)
                if int(diff_time_minutes33) > vuln_time_controls:
                    # 超过单位时间更新数据库中的时间
                    basic.vuln_last_time_update_lib(current_time33,33)
                    # rsync扫描程序用时统计相关
                    basic.scan_total_time_start_time(41)
                    # 提交扫描任务
                    rsync_status_result = basic.startunrsyncscan_lib()
                    # 在后台单独启动1个线程实时判断扫描器停止时间
                    def rsyncscanendtime():
                        while True:
                            time.sleep(1)
                            basic.scan_total_time_final_end_time(41)
                    threading.Thread(target=rsyncscanendtime).start()
                                            
                else:
                    rsync_status_result = "rsync未授权扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
            
            elif 'y' in str(k):
                # 未授权专项不做指纹识别判断
                print("开启es未授权漏洞扫描")
                # 获取系统当前时间
                current_time34 = time.time()
                # 当前时间和数据库中的作时间差
                diff_time_minutes34 = basic.vuln_time_shijian_cha(34)
                if int(diff_time_minutes34) > vuln_time_controls:
                    # 超过单位时间更新数据库中的时间
                    basic.vuln_last_time_update_lib(current_time34,34)
                    # es扫描程序用时统计相关
                    basic.scan_total_time_start_time(42)
                    # 提交扫描任务
                    unes_status_result = basic.startunesscan_lib()
                    # 在后台单独启动1个线程实时判断扫描器停止时间
                    def unesscanendtime():
                        while True:
                            time.sleep(1)
                            basic.scan_total_time_final_end_time(42)
                    threading.Thread(target=unesscanendtime).start()
                                            
                else:
                    unes_status_result = "Elasticsearch未授权扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"

            elif 'z' in str(k):
                print("bcrypt解密")
                # 获取系统当前时间
                current_time35 = time.time()
                # 当前时间和数据库中的作时间差
                diff_time_minutes35 = basic.vuln_time_shijian_cha(35)
                if int(diff_time_minutes35) > vuln_time_controls:
                    # 超过单位时间更新数据库中的时间
                    basic.vuln_last_time_update_lib(current_time35,35)
                    # bcrypt程序用时统计相关
                    basic.scan_total_time_start_time(43)
                    # 提交扫描任务
                    bcrypt_status_result = basic.startbcryptscan_lib()
                    # 在后台单独启动1个线程实时判断扫描器停止时间
                    def bcryptscanendtime():
                        while True:
                            time.sleep(1)
                            basic.scan_total_time_final_end_time(43)
                    threading.Thread(target=bcryptscanendtime).start()
                                            
                else:
                    bcrypt_status_result = "bcrypt解密程序"+str(info_time_controls)+"分钟内不允许重复扫描"
                
            else:
                print("其他扫描器正在完善中......")
        try:
            struts2status_result1 = struts2status_result
        except:
            struts2status_result1 = ""
        try:
            weblogic_status_result1 = weblogic_status_result
        except:
            weblogic_status_result1 = ""
        try:
            shiro_status_result1 = shiro_status_result
        except:
            shiro_status_result1 = ""
        try:
            springboot_scan_status_result1 = springboot_scan_status_result
        except:
            springboot_scan_status_result1 = ""
        try:
            thinkphp_status_result1 = thinkphp_status_result
        except:
            thinkphp_status_result1 = ""
        try:
            start_afrog_result1 = start_afrog_result
        except:
            start_afrog_result1 = ""
        try:
            fscan_status_result1 = fscan_status_result
        except:
            fscan_status_result1 = ""
        try:
            hydra_scan_result1 = hydra_scan_result
        except:
            hydra_scan_result1 = ""        
        try:
            seeyon_status_result1 = seeyon_status_result
        except:
            seeyon_status_result1 = ""        
        try:
            yonsuite_status_result1 = yonsuite_status_result
        except:
            yonsuite_status_result1 = ""
        try:
            kingdee_status_result1 = kingdee_status_result
        except:
            kingdee_status_result1 = ""
        try:
            wanhu_status_result1 = wanhu_status_result
        except:
            wanhu_status_result1 = ""
        try:
            redis_status_result1 = redis_status_result
        except:
            redis_status_result1 = ""
        try:
            mongodb_status_result1 = mongodb_status_result
        except:
            mongodb_status_result1 = ""
        try:
            memcached_status_result1 = memcached_status_result
        except:
            memcached_status_result1 = ""        
        try:
            zookeeper_status_result1 = zookeeper_status_result
        except:
            zookeeper_status_result1 = ""        
        try:
            ftp_status_result1 = ftp_status_result
        except:
            ftp_status_result1 = ""        
        try:
            couchdb_status_result1 = couchdb_status_result
        except:
            couchdb_status_result1 = ""
        try:
            docker_status_result1 = docker_status_result
        except:
            docker_status_result1 = ""        
        try:
            hadoop_status_result1 = hadoop_status_result
        except:
            hadoop_status_result1 = ""        
        try:
            nfs_status_result1 = nfs_status_result
        except:
            nfs_status_result1 = ""        
        try:
            rsync_status_result1 = rsync_status_result
        except:
            rsync_status_result1 = ""        
        try:
            unes_status_result1 = unes_status_result
        except:
            unes_status_result1 = ""        
        try:
            urlfinder_status_result1 = urlfinder_status_result
        except:
            urlfinder_status_result1 = ""
        try:
            vummap_scan_result1 = vummap_scan_result
        except:
            vummap_scan_result1 = ""
        try:
            nuclei_status_result1 = nuclei_status_result
        except:
            nuclei_status_result1 = ""
        try:
            weaver_status_result1 = weaver_status_result
        except:
            weaver_status_result1 = ""        
        try:
            es_status_result1 = es_status_result
        except:
            es_status_result1 = ""
        try:
            nacos_status_result1 = nacos_status_result
        except:
            nacos_status_result1 = ""        
        try:
            tomcat_status_result1 = tomcat_status_result
        except:
            tomcat_status_result1 = ""
        try:
            jndi_status_result1 = jndi_status_result
        except:
            jndi_status_result1 = ""
        try:
            fastjson_status_result1 = fastjson_status_result
        except:
            fastjson_status_result1 = ""
        try:
            xray_status_result1 = xray_status_result
        except:
            xray_status_result1 = ""
        try:
            bcrypt_status_result1 = bcrypt_status_result
        except:
            bcrypt_status_result1 = ""
        
        bcrypt_status = os.popen('bash /TIP/info_scan/finger.sh bcrypt_scan_status').read()
        struts2status = os.popen('bash /TIP/info_scan/finger.sh struts2_status').read()
        weblogicstatus = os.popen('bash /TIP/info_scan/finger.sh weblogic_status').read()
        shirostatus = os.popen('bash /TIP/info_scan/finger.sh shiro_status').read()
        springbootstatus = os.popen('bash /TIP/info_scan/finger.sh springboot_scan_status').read()
        thinkphpstatus = os.popen('bash /TIP/info_scan/finger.sh TPscan_status').read()
        afrogscanstatus = os.popen('bash /TIP/info_scan/finger.sh afrogscan_status').read()
        fscanstatus = os.popen('bash /TIP/info_scan/finger.sh fscan_status').read()
        hydrastatus = os.popen('bash /TIP/info_scan/finger.sh hydra_status').read()
        urlfinderstatus = os.popen('bash /TIP/info_scan/finger.sh urlfinder_status').read()
        vulmapscanstatus = os.popen('bash /TIP/info_scan/finger.sh vulmapscan_status').read()
        nucleistatus =os.popen('bash /TIP/info_scan/finger.sh nucleistatus').read()
        weaver_status = os.popen('bash /TIP/info_scan/finger.sh weaver_status').read()
        es_status = os.popen('bash /TIP/info_scan/finger.sh elasticsearch_vuln_scan_status').read()
        nacos_status = os.popen('bash /TIP/info_scan/finger.sh nacos_vuln_scan_status').read()
        tomcat_status = os.popen('bash /TIP/info_scan/finger.sh tomcat_vuln_scan_status').read()
        jndi_status = os.popen('bash /TIP/info_scan/finger.sh jndi_server_status').read()
        fastjson_status = os.popen('bash /TIP/info_scan/finger.sh fastjson_scan_status').read()
        xray_status = os.popen('bash /TIP/info_scan/finger.sh xraystatus').read()
        seeyonstatus = os.popen('bash /TIP/info_scan/finger.sh seeyon_vuln_scan_status').read()
        yonsuite_status = os.popen('bash /TIP/info_scan/finger.sh yonsuite_vuln_scan_status').read()
        kingdee_status = os.popen('bash /TIP/info_scan/finger.sh kingdee_vuln_scan_status').read()
        wanhu_status = os.popen('bash /TIP/info_scan/finger.sh wanhu_vuln_scan_status').read()
        redis_status = os.popen('bash /TIP/info_scan/finger.sh redis_vuln_scan_status').read()
        mongodb_status = os.popen('bash /TIP/info_scan/finger.sh mongodb_vuln_scan_status').read()
        memcached_status = os.popen('bash /TIP/info_scan/finger.sh memcached_vuln_scan_status').read()
        zookeeper_status = os.popen('bash /TIP/info_scan/finger.sh zookeeper_vuln_scan_status').read()
        ftp_status = os.popen('bash /TIP/info_scan/finger.sh ftp_vuln_scan_status').read()
        couchdb_status = os.popen('bash /TIP/info_scan/finger.sh couchdb_vuln_scan_status').read()
        docker_status = os.popen('bash /TIP/info_scan/finger.sh docker_vuln_scan_status').read()
        hadoop_status = os.popen('bash /TIP/info_scan/finger.sh hadoop_vuln_scan_status').read()
        nfs_status = os.popen('bash /TIP/info_scan/finger.sh nfs_vuln_scan_status').read()
        rsync_status = os.popen('bash /TIP/info_scan/finger.sh rsync_vuln_scan_status').read()
        unes1_status = os.popen('bash /TIP/info_scan/finger.sh elasticsearch_vuln_scan_status').read()

        message_json = {
            "struts2status_result":struts2status_result1,
            "struts2status":struts2status,
            "weblogic_status_result":weblogic_status_result1,
            "weblogicstatus":weblogicstatus,
            "shiro_status_result":shiro_status_result1,
            "shirostatus":shirostatus,
            "springboot_scan_status_result":springboot_scan_status_result1,
            "springbootstatus":springbootstatus,
            "thinkphp_status_result":thinkphp_status_result1,
            "thinkphpstatus":thinkphpstatus,
            "start_afrog_result":start_afrog_result1,
            "afrogscanstatus":afrogscanstatus,
            "fscan_status_result":fscan_status_result1,
            "fscanstatus":fscanstatus,
            "hydra_scan_result":hydra_scan_result1,
            "hydrastatus":hydrastatus,
            "urlfinder_status_result":urlfinder_status_result1,
            "urlfinderstatus":urlfinderstatus,
            "vummap_scan_result":vummap_scan_result1,
            "vulmapscanstatus":vulmapscanstatus,
            "nuclei_status_result":nuclei_status_result1,
            "nucleistatus":nucleistatus,
            "weaver_status_result":weaver_status_result1,
            "weaver_status":weaver_status,
            "es_status_result":es_status_result1,
            "es_status":es_status,
            "nacos_status_result":nacos_status_result1,
            "nacos_status":nacos_status,
            "tomcat_status_result":tomcat_status_result1,
            "tomcat_status":tomcat_status,
            "jndi_status_result":jndi_status_result1,
            "jndi_status":jndi_status,
            "fastjson_status_result":fastjson_status_result1,
            "fastjson_status":fastjson_status,
            "xray_status_result":xray_status_result1,
            "xray_status":xray_status,
            "seeyon_status_result":seeyon_status_result1,
            "seeyonstatus":seeyonstatus,
            "yonsuite_status_result":yonsuite_status_result1,
            "yonsuite_status":yonsuite_status,
            "kingdee_status_result":kingdee_status_result1,
            "kingdee_status":kingdee_status,
            "wanhu_status_result":wanhu_status_result1,
            "wanhu_status":wanhu_status,
            "redis_status_result":redis_status_result1,
            "redis_status":redis_status,
            "mongodb_status_result":mongodb_status_result1,
            "mongodb_status":mongodb_status,
            "memcached_status_result":memcached_status_result1,
            "memcached_status":memcached_status,
            "zookeeper_status_result":zookeeper_status_result1,
            "zookeeper_status":zookeeper_status,
            "ftp_status_result":ftp_status_result1,
            "ftp_status":ftp_status,
            "couchdb_status_result":couchdb_status_result1,
            "couchdb_status":couchdb_status,
            "docker_status_result":docker_status_result1,
            "docker_status":docker_status,
            "hadoop_status":hadoop_status,
            "hadoop_status_result":hadoop_status_result1,
            "nfs_status_result":nfs_status_result1,
            "nfs_status":nfs_status,
            "rsync_status_result":rsync_status_result1,
            "rsync_status":rsync_status,
            "unes_status_result":unes_status_result1,
            "unes1_status":unes1_status,
            "bcrypt_status_result":bcrypt_status_result1,
            "bcrypt_status":bcrypt_status
        }
        return jsonify(message_json)
    else:
        return render_template('login.html')



# 前端复选框批量关闭信息收集工具接口
@app.route("/stop_infoscan_back/",methods=['post'])
def stop_infoscan_back():
    user = session.get('username')
    if str(user) == main_username:
        # 漏洞扫描器时间线更新
        basic.vuln_scan_status_update('已完成关闭批量信息收集')
        data = request.get_json()  # 使用 get_json 解析 JSON 请求体
        info_front_list = data['info_front_list']
        # 接收前端传入的值转为int型
        info_value_list = []
        for i in info_front_list:
            info_value_list.append(int(i))

        # 遍历列表判断关闭哪个扫描器
        for j in info_value_list:
            if '1' in str(j):
                kill_bbscan_result = basic.stopbbscan_lib()
            elif '2' in str(j):
                kill_EHole_result = basic.stopehole_lib()
            elif '3' in str(j):
                kill_otx_url_result = basic.stopotx_lib()
            elif '4' in str(j):
                kill_crt_subdomain_result = basic.stopcrtsubdomain_lib()
            elif '5' in str(j):
                kill_nmap_result = basic.stopnmap_lib()
            elif '6' in str(j):
                kill_waf_result = basic.stopwafrecognize_lib()
            elif '7' in str(j):
                kill_bypass_result = basic.stopbypass_lib()
            elif '8' in str(j):
                kill_crawlergo_result = basic.stop_crawlergo_lib()
            else:
                print("参数正在完善中...")
        # 捕获异常
        try:
            kill_bbscan_result1 = kill_bbscan_result
        except:
            kill_bbscan_result1 = ""
        try:
            kill_EHole_result1 = kill_EHole_result
        except:
            kill_EHole_result1 = ""

        try:
            kill_otx_url_result1 = kill_otx_url_result
        except:
            kill_otx_url_result1 = ""
        try:
            kill_crt_subdomain_result1 = kill_crt_subdomain_result
        except:
            kill_crt_subdomain_result1 = ""
        try:
            kill_nmap_result1 = kill_nmap_result
        except:
            kill_nmap_result1 = ""
        try:
            kill_waf_result1 = kill_waf_result
        except:
            kill_waf_result1 = ""
        try:
            kill_bypass_result1 = kill_bypass_result
        except:
            kill_bypass_result1 = ""
        try:
            kill_crawlergo_result1 = kill_crawlergo_result
        except:
            kill_crawlergo_result1 = ""
        
        dict = {
            "key11":kill_bbscan_result1,
            "key21":kill_EHole_result1,
            "key31":kill_otx_url_result1,
            "key41":kill_crt_subdomain_result1,
            "key51":kill_nmap_result1,
            "key61":kill_waf_result1,
            "key71":kill_bypass_result1,
            "key81":kill_crawlergo_result1
        }
        message_json = {
            "dictkey11":dict['key11'],
            "dictkey21":dict['key21'],
            "dictkey31":dict['key31'],
            "dictkey41":dict['key41'],
            "dictkey51":dict['key51'],
            "dictkey61":dict['key61'],
            "dictkey71":dict['key71'],
            "dictkey81":dict['key81']
        }

        return jsonify(message_json)
    
    else:
        return render_template('login.html')



# 前端复选框批量关闭漏洞扫描接口
@app.route("/stop_vulnscan_back/",methods=['post'])
def stop_vulnscan_back():
    user = session.get('username')
    if str(user) == main_username:
        # 漏洞扫描器时间线更新
        basic.vuln_scan_status_update('已完成批量关闭漏洞扫描')
        # 使用 get_json 解析 JSON 请求体
        data = request.get_json()  
        vuln_front_list = data['vuln_front_list']
        
        # 遍历列表判断关闭哪个扫描器
        for j in vuln_front_list:
            if '1' in str(j):
                kill_struts2_result = basic.stopstruts2_lib()
            elif '2' in str(j):
                kill_weblogic_result = basic.stopweblogic_lib()
            elif '3' in str(j):
                kill_shiro_result = basic.stopshiro_lib()
            elif '4' in str(j):
                kill_springboot_result = basic.stopspringboot_lib()
            elif '5' in str(j):               
                kill_thinkphp_result = basic.stoptpscan_lib()               
            elif '6' in str(j):               
                kill_afrog_result = basic.stopafrog_lib()               
            elif '7' in str(j):               
                kill_fscan_result = basic.stopfscan_lib()                
            elif '8' in str(j):               
                kill_hydra_result = basic.stophydra_lib()
            elif '9' in str(j):                
                kill_urlfinder_result = basic.stopurlfinder_lib()                
            elif 'a' in str(j):                
                kill_vulmap_result = basic.stopvulmap_lib()                
            elif 'b' in str(j):                
                kill_nuclei_result = basic.stopnuclei_lib()  
            elif 'c' in str(j):                
                kill_weaver_result = basic.stopweaver_lib()
            elif 'e' in str(j):                
                kill_es_result = basic.stopesscan_lib()    
            elif 'f' in str(j):                
                kill_nacos_result = basic.stopnacosscan_lib()      
            elif 'g' in str(j):                
                kill_tomcat_result = basic.stoptomcatscan_lib()
            elif 'h' in str(j):                
                kill_jndi_result = basic.stopjndi_lib()
            elif 'i' in str(j):                
                kill_fastjson_result = basic.stopfastjson_lib()
            elif 'j' in str(j):                
                kill_fastjson_result = basic.stop_xray_lib()
            elif 'k' in str(j):                
                kill_seeyon_result = basic.stopseeyonvuln_lib()
            elif 'l' in str(j):                
                kill_yonsuite_result = basic.stopyonsuitevuln_lib()
            elif 'm' in str(j):                
                kill_kingdee_result = basic.stopkingdeevuln_lib()
            elif 'n' in str(j):                
                kill_wanhu_result = basic.stopwanhuvuln_lib()
            elif 'o' in str(j):                
                kill_redis_result = basic.stopunredisvuln_lib()
            elif 'p' in str(j):                
                kill_mongodb_result = basic.stopunmongodbvuln_lib()
            elif 'q' in str(j):                
                kill_memcached_result = basic.stopunmemcachedvuln_lib()
            elif 'r' in str(j):                
                kill_zookeeper_result = basic.stopunzookeepervuln_lib()
            elif 's' in str(j):                
                kill_ftp_result = basic.stopunftpvuln_lib()
            elif 't' in str(j):                
                kill_couchdb_result = basic.stopuncouchdbvuln_lib()
            elif 'u' in str(j):                
                kill_docker_result = basic.stopundockervuln_lib()
            elif 'v' in str(j):                
                kill_hadoop_result = basic.stopunhadoopvuln_lib()
            elif 'w' in str(j):                
                kill_nfs_result = basic.stopunnfsvuln_lib()
            elif 'x' in str(j):                
                kill_rsync_result = basic.stopunrsyncvuln_lib()
            elif 'y' in str(j):                
                kill_es1_result = basic.stopunesvuln_lib()
            elif 'z' in str(j):                
                kill_bcrypt_result = basic.stopbcrypt_lib()
                  
        try:
            kill_struts2_result1 = kill_struts2_result
        except:
            kill_struts2_result1 = ""

        try:
            kill_weblogic_result1 = kill_weblogic_result
        except:
            kill_weblogic_result1 = ""

        try:
            kill_shiro_result1 = kill_shiro_result
        except:
            kill_shiro_result1 = ""
        try:
            kill_seeyon_result1 = kill_seeyon_result
        except:
            kill_seeyon_result1 = ""

        try:
            kill_yonsuite_result1 = kill_yonsuite_result
        except:
            kill_yonsuite_result1 = ""

        try:
            kill_kingdee_result1 = kill_kingdee_result
        except:
            kill_kingdee_result1 = ""

        try:
            kill_wanhu_result1 = kill_wanhu_result
        except:
            kill_wanhu_result1 = ""
        try:
            kill_redis_result1 = kill_redis_result
        except:
            kill_redis_result1 = ""
        
        try:
            kill_mongodb_result1 = kill_mongodb_result
        except:
            kill_mongodb_result1 = ""

        try:
            kill_memcached_result1 = kill_memcached_result
        except:
            kill_memcached_result1 = ""
        
        try:
            kill_zookeeper_result1 = kill_zookeeper_result
        except:
            kill_zookeeper_result1 = ""
        
        try:
            kill_ftp_result1 = kill_ftp_result
        except:
            kill_ftp_result1 = ""
        
        try:
            kill_couchdb_result1 = kill_couchdb_result
        except:
            kill_couchdb_result1 = ""

        try:
            kill_docker_result1 = kill_docker_result
        except:
            kill_docker_result1 = ""
        
        try:
            kill_hadoop_result1 = kill_hadoop_result
        except:
            kill_hadoop_result1 = ""

        
        try:
            kill_nfs_result1 = kill_nfs_result
        except:
            kill_nfs_result1 = ""

        try:
            kill_rsync_result1 = kill_rsync_result
        except:
            kill_rsync_result1 = ""
        
        try:
            kill_es1_result1 = kill_es1_result
        except:
            kill_es1_result1 = ""
        try:
            kill_bcrypt_result1 = kill_bcrypt_result
        except:
            kill_bcrypt_result1 = ""
        try:
            kill_springboot_result1 = kill_springboot_result
        except:
            kill_springboot_result1 = ""

        try:
            kill_thinkphp_result1 = kill_thinkphp_result
        except:
            kill_thinkphp_result1 = ""

        try:
            kill_afrog_result1 = kill_afrog_result
        except:
            kill_afrog_result1 = ""

        try:
            kill_fscan_result1 = kill_fscan_result
        except:
            kill_fscan_result1 = ""

        try:
            kill_hydra_result1 = kill_hydra_result
        except:
            kill_hydra_result1 = ""

        try:
            kill_urlfinder_result1 = kill_urlfinder_result
        except:
            kill_urlfinder_result1 = ""
        
        try:
            kill_urlfinder_result1 = kill_urlfinder_result
        except:
            kill_urlfinder_result1 = ""

        try:
            kill_vulmap_result1 = kill_vulmap_result
        except:
            kill_vulmap_result1 = ""

        try:
            kill_nuclei_result1 = kill_nuclei_result
        except:
            kill_nuclei_result1 = ""

        try:
            kill_weaver_result1 = kill_weaver_result
        except:
            kill_weaver_result1 = ""
        try:
            kill_es_result1 = kill_es_result
        except:
            kill_es_result1 = ""
        try:
            kill_nacos_result1 = kill_nacos_result
        except:
            kill_nacos_result1 = ""
        try:
            kill_tomcat_result1 = kill_tomcat_result
        except:
            kill_tomcat_result1 = ""
        
        try:
            kill_jndi_result1 = kill_jndi_result
        except:
            kill_jndi_result1 = ""
        try:
            kill_fastjson_result1 = kill_fastjson_result
        except:
            kill_fastjson_result1 = ""

        message_json = {
           "kill_struts2_result":kill_struts2_result1,
           "kill_weblogic_result":kill_weblogic_result1,
           "kill_shiro_result":kill_shiro_result1,
           "kill_springboot_result":kill_springboot_result1,
           "kill_thinkphp_result":kill_thinkphp_result1,
           "kill_afrog_result":kill_afrog_result1,
           "kill_fscan_result":kill_fscan_result1,
           "kill_hydra_result":kill_hydra_result1,
           "kill_urlfinder_result":kill_urlfinder_result1,
           "kill_vulmap_result":kill_vulmap_result1,
           "kill_nuclei_result":kill_nuclei_result1,
           "kill_weaver_result":kill_weaver_result1,
           "kill_es_result":kill_es_result1,
           "kill_nacos_result":kill_nacos_result1,
           "kill_tomcat_result":kill_tomcat_result1,
           "kill_jndi_result":kill_jndi_result1,
           "kill_fastjson_result":kill_fastjson_result1,
           "kill_seeyon_result":kill_seeyon_result1,
           "kill_yonsuite_result":kill_yonsuite_result1,
           "kill_kingdee_result":kill_kingdee_result1,
           "kill_wanhu_result":kill_wanhu_result1,
           "kill_redis_result":kill_redis_result1,
           "kill_mongodb_result":kill_mongodb_result1,
           "kill_memcached_result":kill_memcached_result1,
           "kill_zookeeper_result":kill_zookeeper_result1,
           "kill_ftp_result":kill_ftp_result1,
           "kill_couchdb_result":kill_couchdb_result1,
           "kill_docker_result":kill_docker_result1,
           "kill_hadoop_result":kill_hadoop_result1,
           "kill_nfs_result":kill_nfs_result1,
           "kill_rsync_result":kill_rsync_result1,
           "kill_es1_result":kill_es1_result1,
           "kill_bcrypt_result":kill_bcrypt_result1
        }

        return jsonify(message_json)
    
    else:
        return render_template('login.html')



#es未授权访问漏洞报告预览
@app.route("/es_unauthorized_report/")
def es_unauthorized_report():
    user = session.get('username')
    if str(user) == main_username:
        es_num = os.popen('bash /TIP/info_scan/finger.sh es_unautorized_num').read()
        es_unauthorized_status = os.popen('bash /TIP/info_scan/finger.sh es_unauthorized_status').read()
        if "running" in es_unauthorized_status:
            lines = ["正在扫描中......"]
        else:
            if int(es_num) == 0:
                lines = ["未发现漏洞"]
            else:
                lines = []
                with open('/TIP/info_scan/result/esunauthorized.txt', 'r') as f:
                    for line in f:
                        lines.append(line.strip())
        return '<br>'.join(lines)
    else:
        return render_template('login.html')


#nacos漏洞扫描报告预览
@app.route("/nacos_scan_report/")
def nacos_scan_report():
    user = session.get('username')
    if str(user) == main_username:
        nacos_num = os.popen('bash /TIP/info_scan/finger.sh nacos_vuln_num').read()
        nacos_status = os.popen('bash /TIP/info_scan/finger.sh nacos_vuln_scan_status').read()
        if "running" in nacos_status:
            lines = ["正在扫描中......"]
        else:
            if int(nacos_num) == 0:
                lines = ["未发现漏洞"]
            else:
                lines = []
                with open('/TIP/info_scan/result/nacosvuln.txt', 'r') as f:
                    for line in f:
                        lines.append(line.strip())
        return '<br>'.join(lines)
    else:
        return render_template('login.html')
    

#tomcat漏洞扫描报告预览
@app.route("/tomcat_scan_report/")
def tomcat_scan_report():
    user = session.get('username')
    if str(user) == main_username:
        tomcat_num = os.popen('bash /TIP/info_scan/finger.sh tomcat_vuln_num').read()
        tomcat_status = os.popen('bash /TIP/info_scan/finger.sh tomcat_vuln_scan_status').read()
        if "running" in tomcat_status:
            lines = ["正在扫描中......"]
        else:
            if int(tomcat_num) == 0:
                lines = ["未发现漏洞"]
            else:
                lines = []
                with open('/TIP/info_scan/result/tomcat_vuln.txt', 'r') as f:
                    for line in f:
                        lines.append(line.strip())
        return '<br>'.join(lines)
    else:
        return render_template('login.html')


#jndi报告预览
@app.route("/jndi_report_show/")
def jndi_report_show():
    user = session.get('username')
    if str(user) == main_username:
        jndi_num = os.popen('bash /TIP/info_scan/finger.sh jndi_num').read()
        if int(jndi_num) == 0:
            lines = ["暂无数据"]
        else:
            lines = []
            with open('/TIP/info_scan/result/jndi_result.txt', 'r') as f:
                for line in f:
                    lines.append(line.strip())
        return '<br>'.join(lines)
    else:
        return render_template('login.html')
    
#fastjson报告预览
@app.route("/fastjson_report_show/")
def fastjson_report_show():
    user = session.get('username')
    if str(user) == main_username:
        jndi_num = os.popen('bash /TIP/info_scan/finger.sh fastjson_vuln_num').read()
        fastjson_status = os.popen('bash /TIP/info_scan/finger.sh fastjson_scan_status').read()
        if "running" in fastjson_status:
            lines = ["正在扫描中......"]
        else:
            if int(jndi_num) == 0:
                lines = ["未发现漏洞"]
            else:
                lines = []
                with open('/TIP/info_scan/result/fastjson_vuln.txt', 'r') as f:
                    for line in f:
                        lines.append(line.strip())
        return '<br>'.join(lines)
    else:
        return render_template('login.html')


#WAF报告预览
@app.route("/waf_report_show/")
def waf_report_show():
    user = session.get('username')
    if str(user) == main_username:
        jndi_num = os.popen('bash /TIP/info_scan/finger.sh waf_vuln_num').read()
        waf_scan_status = os.popen('bash /TIP/info_scan/finger.sh waf_scan_status').read()
        if "running" in waf_scan_status:
            lines = ["正在扫描中......"]
        else:
            if int(jndi_num) == 0:
                lines = ["未发现漏洞"]
            else:
                lines = []
                with open('/TIP/info_scan/result/waf_result.txt', 'r') as f:
                    for line in f:
                        lines.append(line.strip())
        return '<br>'.join(lines)
    else:
        return render_template('login.html')

#40xbypass报告预览
@app.route("/bypass_report_show/")
def bypass_report_show():
    user = session.get('username')
    if str(user) == main_username:
        jndi_num = os.popen('bash /TIP/info_scan/finger.sh bypass_vuln_num').read()
        bypass_scan_status = os.popen('bash /TIP/info_scan/finger.sh bypassstatus').read()
        if "running" in bypass_scan_status:
            lines = ["正在扫描中......"]
        else:

            if int(jndi_num) == 0:
                lines = ["未发现漏洞"]
            else:
                lines = []
                with open('/TIP/info_scan/result/403bypass_result.txt', 'r') as f:
                    for line in f:
                        lines.append(line.strip())
        return '<br>'.join(lines)
    else:
        return render_template('login.html')


#crawlergo报告预览
@app.route("/crawlergo_report_show/")
def crawlergo_report_show():
    user = session.get('username')
    if str(user) == main_username:
        crawlergo_num = os.popen('bash /TIP/info_scan/finger.sh crawlergo_num').read()
        crawlergo_status = os.popen('bash /TIP/info_scan/finger.sh crawlergo_status').read()
        if "running" in crawlergo_status:
            lines = ["正在扫描中......"]
        else:
            if int(crawlergo_num) == 0:
                lines = ["暂无数据"]
            else:
                lines = []
                with open('/TIP/info_scan/result/crawlergo_result.txt', 'r') as f:
                    for line in f:
                        lines.append(line.strip())
        return '<br>'.join(lines)
    else:
        return render_template('login.html')


#fofa查询日志
@app.route("/assetmanager_textarea_show/",methods=['POST'])
def assetmanager_textarea_show():
    user = session.get('username')
    if str(user) == main_username:
        assetmanagerid1 = request.form['assetmanagerid1']
        
        # 通过fofa语法查询日志
        fofalog_gramme = basic.fofa_grammar_by_dir_lib(assetmanagerid1)
        url_list = []
        file = open(fofalog_gramme,encoding='utf-8')
        for line in file.readlines():
            url_list.append(line.strip())
        # 判断数据是否为空
        if len(url_list) == 0:
            url_list.append("当前资产文件暂无数据！")
        
        # 文本框行数显示
        textarea_num = os.popen('bash /TIP/info_scan/finger.sh assset_textarea_num'+' '+fofalog_gramme).read()

        message_json = {
            "url_list":url_list,
            "textarea_num":"共"+str(textarea_num)+"行"
        }
        return jsonify(message_json)
    else:
        return render_template('login.html')


# 清空fofa查询日志
@app.route("/clearshowfofalog/")
def clearshowfofalog():
    user = session.get('username')
    if str(user) == main_username:
        basic.deletefofalog_lib()
        os.popen('rm -rf /TIP/info_scan/result/assetmanager/*')
        assets_file_list = basic.list_files_in_directory()
        if len(assets_file_list) == 0:
            assets_file_result = "fofa查询日志已清空"
        else:
            assets_file_result = "fofa查询日志正在清空中......"
        message_json = {
            "assets_file_result":assets_file_result
        }
        return jsonify(message_json)
    else:
        return render_template('login.html')


# 弱口令扫描字典配置编辑
@app.route("/dict_mysql_edit/")
def dict_mysql_edit():
    user = session.get('username')
    if str(user) == main_username:
        
        mysql_user_dict_list = []
        mysql_pass_dict_list = []
        ssh_user_dict_list = []
        ssh_pass_dict_list = []
        ftp_user_dict_list = []
        ftp_pass_dict_list = []
        redis_pass_dict_list = []
        mssql_user_dict_list = []
        mssql_pass_dict_list = []
        tomcat_user_dict_list = []
        tomcat_pass_dict_list = []
        nacos_user_dict_list = []
        nacos_pass_dict_list = []
        bcrypt_dict_list = []
        bcrypt_passwd_list = []
        # mysql
        file = open(mysql_dict_user_dir,encoding='utf-8')
        for line in file.readlines():
            mysql_user_dict_list.append(line.strip())
        # 判断数据是否为空
        if len(mysql_user_dict_list) == 0:
            mysql_user_dict_list.append("暂无数据")

        file1 = open(mysql_dict_pass_dir,encoding='utf-8')
        for line1 in file1.readlines():
            mysql_pass_dict_list.append(line1.strip())
        # 判断数据是否为空
        if len(mysql_pass_dict_list) == 0:
            mysql_pass_dict_list.append("暂无数据")

        # ssh
        file2 = open(ssh_dict_user_dir,encoding='utf-8')
        for line2 in file2.readlines():
            ssh_user_dict_list.append(line2.strip())
        # 判断数据是否为空
        if len(ssh_user_dict_list) == 0:
            ssh_user_dict_list.append("暂无数据")

        file3 = open(ssh_dict_pass_dir,encoding='utf-8')
        for line3 in file3.readlines():
            ssh_pass_dict_list.append(line3.strip())
        # 判断数据是否为空
        if len(ssh_pass_dict_list) == 0:
            ssh_pass_dict_list.append("暂无数据")

        # ftp
        file4 = open(ftp_dict_user_dir,encoding='utf-8')
        for line4 in file4.readlines():
            ftp_user_dict_list.append(line4.strip())
        # 判断数据是否为空
        if len(ftp_user_dict_list) == 0:
            ftp_user_dict_list.append("暂无数据")
        
        file5 = open(ftp_dict_pass_dir,encoding='utf-8')
        for line5 in file5.readlines():
            ftp_pass_dict_list.append(line5.strip())
        # 判断数据是否为空
        if len(ftp_pass_dict_list) == 0:
            ftp_pass_dict_list.append("暂无数据")

        # redis
        file7 = open(redis_dict_pass_dir,encoding='utf-8')
        for line7 in file7.readlines():
            redis_pass_dict_list.append(line7.strip())
        # 判断数据是否为空
        if len(redis_pass_dict_list) == 0:
            redis_pass_dict_list.append("暂无数据")
        
        # mssql
        file8 = open(mssql_dict_user_dir,encoding='utf-8')
        for line8 in file8.readlines():
            mssql_user_dict_list.append(line8.strip())
        # 判断数据是否为空
        if len(mssql_user_dict_list) == 0:
            mssql_user_dict_list.append("暂无数据")
        
        file9 = open(mssql_dict_pass_dir,encoding='utf-8')
        for line9 in file9.readlines():
            mssql_pass_dict_list.append(line9.strip())
        # 判断数据是否为空
        if len(mssql_pass_dict_list) == 0:
            mssql_pass_dict_list.append("暂无数据")

        # tomcat
        file10 = open(tomcat_user_dir,encoding='utf-8')
        for line10 in file10.readlines():
            tomcat_user_dict_list.append(line10.strip())
        # 判断数据是否为空
        if len(tomcat_user_dict_list) == 0:
            tomcat_user_dict_list.append("暂无数据")

        file11 = open(tomcat_pass_dir,encoding='utf-8')
        for line11 in file11.readlines():
            tomcat_pass_dict_list.append(line11.strip())
        # 判断数据是否为空
        if len(tomcat_pass_dict_list) == 0:
            tomcat_pass_dict_list.append("暂无数据")

        # nacos
        file11 = open(nacos_user_dir,encoding='utf-8')
        for line11 in file11.readlines():
            nacos_user_dict_list.append(line11.strip())
        # 判断数据是否为空
        if len(nacos_user_dict_list) == 0:
            nacos_user_dict_list.append("暂无数据")

        file12 = open(nacos_pass_dir,encoding='utf-8')
        for line12 in file12.readlines():
            nacos_pass_dict_list.append(line12.strip())
        # 判断数据是否为空
        if len(nacos_pass_dict_list) == 0:
            nacos_pass_dict_list.append("暂无数据")

        # bcrypt
        file13 = open(bcrypt_dict,encoding='utf-8')
        for line13 in file13.readlines():
            bcrypt_dict_list.append(line13.strip())
        # 判断数据是否为空
        if len(bcrypt_dict_list) == 0:
            bcrypt_dict_list.append("暂无数据")
        file14 = open(bcrypt_passwd,encoding='utf-8')
        for line14 in file14.readlines():
            bcrypt_passwd_list.append(line14.strip())
        # 判断数据是否为空
        if len(bcrypt_passwd_list) == 0:
            bcrypt_passwd_list.append("暂无数据")

        message_json = {
            "mysql_user_dict_list":mysql_user_dict_list,
            "mysql_pass_dict_list":mysql_pass_dict_list,
            "ssh_user_dict_list":ssh_user_dict_list,
            "ssh_pass_dict_list":ssh_pass_dict_list,
            "ftp_user_dict_list":ftp_user_dict_list,
            "ftp_pass_dict_list":ftp_pass_dict_list,
            "redis_pass_dict_list":redis_pass_dict_list,
            "mssql_user_dict_list":mssql_user_dict_list,
            "mssql_pass_dict_list":mssql_pass_dict_list,
            "tomcat_user_dict_list":tomcat_user_dict_list,
            "tomcat_pass_dict_list":tomcat_pass_dict_list,
            "nacos_user_dict_list":nacos_user_dict_list,
            "nacos_pass_dict_list":nacos_pass_dict_list,
            "bcrypt_dict_list":bcrypt_dict_list,
            "bcrypt_passwd_list":bcrypt_passwd_list
        }

        return jsonify(message_json)
    else:
        return render_template('login.html')


# 弱口令扫描字典配置保存
@app.route('/hydradictconfig/', methods=['POST'])  
def hydradictconfig():
    user = session.get('username')
    if str(user) == main_username: 
        # 筛选后资产时间线更新
        basic.assets_status_update('弱口令扫描字典已更新')
        data = request.get_json()

        # mysql相关
        line_mysqltextarea1 = data['line_mysqltextarea1']
        line_mysqltextarea2 = data['line_mysqltextarea2']
        
        # 列表中数据存入文件中
        f1 = open(file=mysql_dict_user_dir,mode='w')
        for line1 in line_mysqltextarea1:
            f1.write(str(line1)+"\n")
        f1.close()
        f2 = open(file=mysql_dict_pass_dir,mode='w')
        for line2 in line_mysqltextarea2:
            f2.write(str(line2)+"\n")
        f2.close()

        # ssh相关
        line_sshtextarea1 = data['line_sshtextarea1']
        line_sshtextarea2 = data['line_sshtextarea2']
        f3 = open(file=ssh_dict_user_dir,mode='w')
        for line3 in line_sshtextarea1:
            f3.write(str(line3)+"\n")
        f3.close()

        f4 = open(file=ssh_dict_pass_dir,mode='w')
        for line4 in line_sshtextarea2:
            f4.write(str(line4)+"\n")
        f4.close()

        # ftp相关
        line_ftptextarea1 = data['line_ftptextarea1']
        line_ftptextarea2 = data['line_ftptextarea2']
        f5 = open(file=ftp_dict_user_dir,mode='w')
        for line5 in line_ftptextarea1:
            f5.write(str(line5)+"\n")
        f5.close()

        f6 = open(file=ftp_dict_pass_dir,mode='w')
        for line6 in line_ftptextarea2:
            f6.write(str(line6)+"\n")
        f6.close()

        # redis相关
        line_redistextarea2 = data['line_redistextarea2']
        f7 = open(file=redis_dict_pass_dir,mode='w')
        for line7 in line_redistextarea2:
            f7.write(str(line7)+"\n")
        f7.close()

        # mssql相关
        line_mssqltextarea1 = data['line_mssqltextarea1']
        line_mssqltextarea2 = data['line_mssqltextarea2']
        f8 = open(file=mssql_dict_user_dir,mode='w')
        for line8 in line_mssqltextarea1:
            f8.write(str(line8)+"\n")
        f8.close()

        f9 = open(file=mssql_dict_pass_dir,mode='w')
        for line9 in line_mssqltextarea2:
            f9.write(str(line9)+"\n")
        f9.close()

        # tomcat相关
        line_tomcattextarea1 = data['line_tomcattextarea1']
        line_tomcattextarea2 = data['line_tomcattextarea2']
        f10 = open(file=tomcat_user_dir,mode='w')
        for line10 in line_tomcattextarea1:
            f10.write(str(line10)+"\n")
        f10.close()
        f11 = open(file=tomcat_pass_dir,mode='w')
        for line11 in line_tomcattextarea2:
            f11.write(str(line11)+"\n")
        f11.close()

        # nacos相关
        line_nacostextarea1 = data['line_nacostextarea1']
        line_nacostextarea2 = data['line_nacostextarea2']
        f12 = open(file=nacos_user_dir,mode='w')
        for line12 in line_nacostextarea1:
            f12.write(str(line12)+"\n")
        f12.close()
        f13 = open(file=nacos_pass_dir,mode='w')
        for line13 in line_nacostextarea2:
            f13.write(str(line13)+"\n")
        f13.close()

        # bcrypt相关
        line_bcrypttextarea1 = data['line_bcrypttextarea1']
        line_bcrypttextarea2 = data['line_bcrypttextarea2']
        f13 = open(file=bcrypt_dict,mode='w')
        for line13 in line_bcrypttextarea1:
            f13.write(str(line13)+"\n")
        f13.close()
        f14 = open(file=bcrypt_passwd,mode='w')
        for line14 in line_bcrypttextarea2:
            f14.write(str(line14)+"\n")
        f14.close()
        
        # 判断数据是否添加成功
        line_mysqltextarea1_list = []
        file_a = open(mysql_dict_user_dir,encoding='utf-8')
        for line_a in file_a.readlines():
            line_mysqltextarea1_list.append(line_a.strip())
        line_mysqltextarea2_list = []
        file_b = open(mysql_dict_pass_dir,encoding='utf-8')
        for line_b in file_b.readlines():
            line_mysqltextarea2_list.append(line_b.strip())

        line_sshtextarea1_list = []
        file_c = open(ssh_dict_user_dir,encoding='utf-8')
        for line_c in file_c.readlines():
            line_sshtextarea1_list.append(line_c.strip())

        if Counter(line_mysqltextarea1) == Counter(line_mysqltextarea1_list) and Counter(line_mysqltextarea2) == Counter(line_mysqltextarea2_list) and Counter(line_sshtextarea1) == Counter(line_sshtextarea1_list):
            mysql_dict_result = "已保存成功！！！"
        else:
            mysql_dict_result = "保存失败！！！"

        message_json = {
            "mysql_dict_result":mysql_dict_result
        }
        return jsonify(message_json)
    else:
        return render_template('login.html')



# 通过二次验证确认删除报告
@app.route("/comfirmclearloginterface/",methods=['POST'])
def comfirmclearloginterface():
    user = session.get('username')
    if str(user) == main_username:
        inputmodel1 = request.form['inputmodel1']
        inputmodel2 = request.form['inputmodel2']
        inputmodel3 = request.form['inputmodel3']
        sessionid1 = request.form['sessionid1']
        sessionid2 = request.form['sessionid2']
        sessionid3 = request.form['sessionid3']
        sessionid4 = request.form['sessionid4']
        sessionid5 = request.form['sessionid5']
        sessionid6 = request.form['sessionid6']
        rule_input_id1 = request.form['rule_input_id1']
        # 接收前端传递过来的自定义接口额度参数
        customizelimitid1 = request.form['customizelimitid1']
        customizelimitid2 = request.form['customizelimitid2']
        customizelimitid3 = request.form['customizelimitid3']
        customizelimitid4 = request.form['customizelimitid4']
        customizelimitid5 = request.form['customizelimitid5']
        customizelimitid6 = request.form['customizelimitid6']

        if str(inputmodel1) == str(recheck_username) and str(inputmodel2) == str(recheck_password):
            if int(inputmodel3) == 1:
                print("afrog")
                os.popen('rm -rf /TIP/info_scan/afrog_scan/reports/*')
                afrog_num = os.popen('bash /TIP/info_scan/finger.sh afrognum').read()
                if int(afrog_num) == 0:
                    recheck_result = "afrog报告已删除"
                else:
                    recheck_result = "afrog报告正在删除中"
            elif int(inputmodel3) ==2:
                print("api")
                os.popen('rm -rf /TIP/info_scan/urlfinder_server/report/*')
                api_num = os.popen('bash /TIP/info_scan/finger.sh apinum').read()
                if int(api_num) == 0:
                    recheck_result = "api接口报告已删除"
                else:
                    recheck_result = "api接口报告正在删除中"
            elif int(inputmodel3) ==3:
                print("xray")
                os.popen('rm -rf /TIP/batch_scan_domain/report/*')
                xray_num = os.popen('bash /TIP/info_scan/finger.sh xraynum').read()
                if int(xray_num) == 0:
                    recheck_result = "xray报告已删除"
                else:
                    recheck_result = "xray报告正在删除中"
            elif int(inputmodel3) ==4:
                print("nmap")
                os.popen('rm -rf /TIP/info_scan/result/nmap.txt')
                os.popen('touch /TIP/info_scan/result/nmap.txt')
                os.popen('rm -rf /TIP/info_scan/result/nmap_ip.txt')
                os.popen('touch /TIP/info_scan/result/nmap_ip.txt')
                nmapnum = os.popen('bash /TIP/info_scan/finger.sh nmapnum').read()
                if int(nmapnum) == 0:
                    recheck_result = "端口扫描报告已删除"
                else:
                    recheck_result = "端口扫描报告正在删除中"
            elif int(inputmodel3) ==5:
                print("接口额度初始化")
                recheck_result = basic.initinterface_num_lib()
            elif int(inputmodel3) ==6:
                print("配置会话过期时间")
                recheck_result = basic.update_session_time_lib(sessionid1,1)
            elif int(inputmodel3) ==7:
                print("配置fofa邮箱和key")
                recheck_result = basic.update_fofakey_lib(sessionid2,sessionid3,2)
            elif int(inputmodel3) ==8:
                print("配置shodankey")
                recheck_result = basic.update_session_time_lib(sessionid4,3)
            elif int(inputmodel3) ==9:
                print("配置amapkey")
                recheck_result = basic.update_session_time_lib(sessionid5,4)
            elif int(inputmodel3) ==10:
                print("配置ceyekey")
                recheck_result = basic.update_session_time_lib(sessionid6,5)
            elif int(inputmodel3) ==12:
                print("配置fofa接口额度")
                recheck_result = basic.update_customize_interface_totalnum(customizelimitid1,1)
            elif int(inputmodel3) ==13:
                print("配置shodan接口额度")
                recheck_result = basic.update_customize_interface_totalnum(customizelimitid2,2)
            elif int(inputmodel3) ==14:
                print("配置crt接口额度")
                recheck_result = basic.update_customize_interface_totalnum(customizelimitid3,3)
            elif int(inputmodel3) ==15:
                print("配置icp接口额度")
                recheck_result = basic.update_customize_interface_totalnum(customizelimitid4,4)
            elif int(inputmodel3) ==16:
                print("配置高德地图接口额度")
                recheck_result = basic.update_customize_interface_totalnum(customizelimitid5,5)
            elif int(inputmodel3) ==17:
                print("配置otx威胁情报接口额度")
                recheck_result = basic.update_customize_interface_totalnum(customizelimitid6,6)
            elif int(inputmodel3) ==11:
                print("配置高危资产识别")
                
                if '' in  rule_input_id1:
                    recheck_result = "输入参数不能为空"
        
                if ' ' in rule_input_id1:
                    recheck_result = "输入参数不能包含空格"
        
                if 'alert' in rule_input_id1 or 'select' in rule_input_id1 or '<' in rule_input_id1 or '>' in rule_input_id1 or 'union' in rule_input_id1:
                    recheck_result = "请勿进行安全测试！"
        
                else:
                    db= pymysql.connect(host=dict['ip'],user=dict['username'],  
                    password=dict['password'],db=dict['dbname'],port=dict['portnum']) 
                    cur = db.cursor()
                    
                    # 判断数据库中是否存在传入的数据
                    sql_select = "select rule FROM rule_table where rule = '%s' "%(rule_input_id1)
                    cur.execute(sql_select)
                    result = cur.fetchone()
                    if result:
                        recheck_result = rule_input_id1+" "+"规则已存在不要重复添加"
                    else:
                        sql_insert = "insert into rule_table(rule)  values('%s')" %(rule_input_id1)
                        cur.execute(sql_insert)  
                        db.commit()
                        recheck_result = rule_input_id1+" "+"规则已添加成功"
                        # recheck_result = basic.update_session_time_lib(sessionid6,5)
            else:
                print("其他")

        else:
            recheck_result = "账号或者密码错误验证失败"
        message_json = {
            "recheck_result":recheck_result
        }
        return jsonify(message_json)
    else:
        return render_template('login.html')


# 通过关键字检索资产
@app.route("/searchassetsbykey/",methods=['POST'])
def searchassetsbykey():
    user = session.get('username')
    if str(user) == main_username:

        myinputid = request.form['myinputid']
        url_list = basic.url_file_ip_list()
        asset_url_list = []
        f = open(file='/TIP/batch_scan_domain/url.txt',mode='w')
        for url in url_list:
            if myinputid in url:
                asset_url_list.append(url)
                f.write(str(url)+"\n")
        f.close()
        message_json = {
            "search_result":"已检索出"+str(len(asset_url_list))+"条资产"
        }
        return jsonify(message_json)
    else:
        return render_template('login.html')



# 通过关键字排除资产
@app.route("/excludesearchassetsbykey/",methods=['POST'])
def excludesearchassetsbykey():
    user = session.get('username')
    if str(user) == main_username:

        myinputid = request.form['myinputid']
        url_list = basic.url_file_ip_list()
        asset_url_list = []
        f = open(file='/TIP/batch_scan_domain/url.txt',mode='w')
        for url in url_list:
            if myinputid not in url:
                asset_url_list.append(url)
                f.write(str(url)+"\n")
        f.close()
        # 计算排除资产数量
        result = int(len(url_list)) - int(len(asset_url_list))
        message_json = {
            "search_result":"已排除出"+str(result)+"条资产"
        }
        return jsonify(message_json)
    else:
        return render_template('login.html')

# 资产下载
@app.route("/assetsdownload/",methods=['GET'])
def assetsdownload():
    user = session.get('username')
    if str(user) == main_username:
        
        url_result = basic.url_file_ip_list()
        # 删除空元素
        if '' in url_result:
            url_result.remove('')
        
        if len(url_result) == 0:
            url_result.append("暂无资产信息")
            f = open(file='/TIP/batch_scan_domain/url.txt',mode='w')
            for line in url_result:
                f.write(str(line)+"\n")
            f.close()
            # 判断url.txt文件是否存在
            file_path = '/TIP/batch_scan_domain/url.txt'
            if os.path.exists(file_path) and os.path.isfile(file_path):
                return send_file(file_path, as_attachment=True, download_name='url.txt')
        else:
            # 判断url.txt文件是否存在
            file_path = '/TIP/batch_scan_domain/url.txt'
            if os.path.exists(file_path) and os.path.isfile(file_path):
                return send_file(file_path, as_attachment=True, download_name='url.txt')
    else:
        return render_template('login.html')



# 获取系统配置数据
@app.route("/system_config_data/",methods=['get'])
def system_config_data():
    user = session.get('username')
    if str(user) == main_username:
        session_time = basic.select_session_time_lib(1)
        fofa_conf = basic.select_fofakey_lib(2)
        fofa_email = fofa_conf[0]
        fofa_key = fofa_conf[1]

        # jndi服务状态
        jndi_status = os.popen('bash /TIP/info_scan/finger.sh jndi_server_status').read()
        jndi_python_status = os.popen('bash /TIP/info_scan/finger.sh jndi_python_server_status').read()
        if "running" in jndi_status and "running" in jndi_python_status:
            jndistatus = "开启"
        else:
            jndistatus = "关闭"

        # 资产校验开关状态
        assets_jiaoyan_status = basic.verification_table_lib(1)
        shodan_key = basic.select_session_time_lib(3)
        amap_key = basic.select_session_time_lib(4)
        ceye_key =  basic.select_session_time_lib(5)
        shodan_key_tuomin = basic.mask_data(shodan_key)
        amap_key_tuomin = basic.mask_data(amap_key)
        ceye_key_tuomin = basic.mask_data(ceye_key)
        fofa_email_tuomin = basic.mask_data(fofa_email)
        fofa_key_tuomin = basic.mask_data(fofa_key)

        # 获取自定义接口额度
        fofa_inter_num_success = basic.total_port_success_num(1)
        fofa_inter_num_fail = basic.total_port_fail_num(1)
        shodan_inter_num_success = basic.total_port_success_num(2)
        shodan_inter_num_fail = basic.total_port_fail_num(2)
        crt_inter_num_success = basic.total_port_success_num(3)
        crt_inter_num_fail = basic.total_port_fail_num(3)
        icp_inter_num_success = basic.total_port_success_num(4)
        icp_inter_num_fail = basic.total_port_fail_num(4)
        gd_inter_num_success = basic.total_port_success_num(5)
        gd_inter_num_fail = basic.total_port_fail_num(5)
        otx_inter_num_success = basic.total_port_success_num(6)
        otx_inter_num_fail = basic.total_port_fail_num(6)

        
        tatal_fofa_num = int(fofa_inter_num_success) + int(fofa_inter_num_fail)
        fofa_remaining_num_1 =  int(fofa_max_num) - tatal_fofa_num
        if fofa_remaining_num_1 < 0:
            fofa_remaining_num = 0
        else:
            fofa_remaining_num = fofa_remaining_num_1

        total_shodan_num = int(shodan_inter_num_success) + int(shodan_inter_num_fail)
        shodan_remaining_num_1 = int(shodan_max_num) - total_shodan_num
        if shodan_remaining_num_1 < 0:
            shodan_remaining_num = 0
        else:
            shodan_remaining_num = shodan_remaining_num_1

        tatal_crt_num = int(crt_inter_num_success) + int(crt_inter_num_fail)
        crt_remaining_num_1 =  int(crt_max_num) - tatal_crt_num
        if crt_remaining_num_1 < 0:
            crt_remaining_num = 0
        else:
            crt_remaining_num = crt_remaining_num_1

        tatal_icp_num = int(icp_inter_num_success) + int(icp_inter_num_fail)
        icp_remaining_num_1 =  int(icp_max_num) - tatal_icp_num
        if icp_remaining_num_1 < 0:
            icp_remaining_num = 0
        else:
            icp_remaining_num = icp_remaining_num_1

        tatal_amap_num = int(gd_inter_num_success) + int(gd_inter_num_fail)
        amap_remaining_num_1 =  int(amap_max_num) - tatal_amap_num
        if amap_remaining_num_1 < 0:
            amap_remaining_num = 0
        else:
            amap_remaining_num = amap_remaining_num_1
        
        tatal_otx_num = int(otx_inter_num_success) + int(otx_inter_num_fail)
        otx_remaining_num_1 =  int(otx_max_num) - tatal_otx_num
        if otx_remaining_num_1 < 0:
            otx_remaining_num = 0
        else:
            otx_remaining_num = otx_remaining_num_1

        message_json = {
            # 接口剩余额度
            "fofa_remaining_num":fofa_remaining_num,
            "shodan_remaining_num":shodan_remaining_num,
            "crt_remaining_num":crt_remaining_num,
            "icp_remaining_num":icp_remaining_num,
            "amap_remaining_num":amap_remaining_num,
            "otx_remaining_num":otx_remaining_num,
            # key查询
            "search_result":str(session_time),
            "fofa_email":str(fofa_email_tuomin),
            "fofa_key":str(fofa_key_tuomin),
            "shodan_key":str(shodan_key_tuomin),
            "amap_key":str(amap_key_tuomin),
            "ceye_key":str(ceye_key_tuomin),
            # jndi状态查询
            "jndistatus":str(jndistatus),
            # 资产校验状态
            "assets_jiaoyan_status":str(assets_jiaoyan_status)
        }
        return jsonify(message_json)
    else:
        return render_template('login.html')



#网站导航
@app.route("/siteroute/")
def siteroute():
    user = session.get('username')
    if str(user) == main_username:
        return render_template('navigation.html')
    else:
        return render_template('login.html')
    


#资产扩展
@app.route("/assets_extend/",methods=['GET'])
def assets_extend():
    user = session.get('username')
    if str(user) == main_username:
        # 筛选后资产时间线更新
        basic.assets_status_update('资产扩展已完成')
        # subfinder程序用时统计相关
        basic.scan_total_time_start_time(31)
        # 创建一个新的线程启动资产扩展程序
        def run_asset_extend_process():
            print("已开启一个新的线程用于资产扩展")
            try:
                basic.expand_range_asset_lib()
            except Exception as e:
                print("捕获到异常:", e)
        threading.Thread(target=run_asset_extend_process).start()
        # 在后台单独启动1个线程实时判断扫描器停止时间
        def subfinderscanendtime():
            while True:
                time.sleep(1)
                basic.scan_total_time_final_end_time(31)
        threading.Thread(target=subfinderscanendtime).start()

        httpx_status = os.popen('bash /TIP/info_scan/finger.sh httpx_status').read()
        subfinder_status = os.popen('bash /TIP/info_scan/finger.sh subfinder_status').read()
        if "running" in httpx_status or "running" in subfinder_status:
            assets_extend_status = "资产扩展程序正在运行中请勿重复提交"
        else:
            assets_extend_status = "资产扩展程序已开启稍后查看最新资产"
        message_json = {
            "assets_extend_status":assets_extend_status
        }
        return jsonify(message_json)
    else:
        return render_template('login.html')


#图标hash计算，用于资产收集
@app.route("/fofa_icon_hash/",methods=['POST'])
def fofa_icon_hash():
    user = session.get('username')
    hashurl = request.form['hashurl']
    if str(user) == main_username:
        try:
            hash_result = basic.compute_icon_hash_lib(hashurl)
        except:
            hash_result = "hash计算出错"
        message_json = {
            "hash_result":"icon_hash=\""+str(hash_result)+"\""
        }
        return jsonify(message_json)
    else:
        return render_template('login.html')


# 社工字典生成
@app.route("/social_worker_dictionary/",methods=['POST'])
def social_worker_dictionary():
    user = session.get('username')
    gendict1 = request.form['gendict1']
    gendict2 = request.form['gendict2']
    gendict3 = request.form['gendict3']
    gendict4 = request.form['gendict4']
    gendict5 = request.form['gendict5']
    gendict6 = request.form['gendict6']
    gendict7 = request.form['gendict7']
    gendict8 = request.form['gendict8']
    gendict9 = request.form['gendict9']
    gendict10 = request.form['gendict10']
    gendict11 = request.form['gendict11']
    gendict12 = request.form['gendict12']
    gendict13 = request.form['gendict13']
    gendict14 = request.form['gendict14']
  
    if str(user) == main_username:
        try:
            result = os.popen('bash /TIP/info_scan/finger.sh gendict_status').read()
            if "running" in result:
                gendictresult = "密码字典正在生成中请勿重复提交"
            else:
                os.popen('bash /TIP/info_scan/finger.sh gendict'+' '+gendict13+' '+gendict14+' '+gendict1+' '+gendict2+' '+gendict3+' '+gendict4+' '+gendict5+' '+gendict6+' '+gendict7+' '+gendict8+' '+gendict9+' '+gendict10+' '+gendict11+' '+gendict12)
                gendictresult = "密码字典生成程序已开启"
        except:
            gendictresult = "密码字典生成出现内部错误"
        message_json = {
            "gendictresult":gendictresult
        }
        return jsonify(message_json)
    else:
        return render_template('login.html')

# 字典预览
@app.route("/social_worker_dictionary_report/")
def social_worker_dictionary_report():
    user = session.get('username')
    if str(user) == main_username:
       
        lines = []
        with open('/TIP/info_scan/result/workerdictionary.txt', 'r') as f:
            for line in f:
                lines.append(line.strip())
        message_json = {
            "gendictreport":lines
        }

        return jsonify(message_json)
    else:
        return render_template('login.html')   


# 关闭字典生成
@app.route("/stop_social_worker_dictionary/",methods=['GET'])
def stop_social_worker_dictionary():
    user = session.get('username')
    if str(user) == main_username:
        
        stop_dict_status_result = basic.stopgendict_lib()

        message_json = {
            "stop_dict_status_result":stop_dict_status_result
        }
        return jsonify(message_json)
    else:
        return render_template('login.html')

# 字典大小
@app.route("/dictsize/",methods=['GET'])
def dictsize():
    user = session.get('username')
    if str(user) == main_username:
        
        sizenum = os.popen('bash /TIP/info_scan/finger.sh dictsize').read()
        message_json = {
            "sizenum":"字典文件大小："+str(sizenum)+"  "+"（注：文件过大时不要点击预览字典,会导致服务器宕机,可点击下载字典）"
        }
        return jsonify(message_json)
    else:
        return render_template('login.html')   


# 密码字典文件下载
@app.route("/passworddictdownload/",methods=['GET'])
def passworddictdownload():
    user = session.get('username')
    if str(user) == main_username:
        
        dict_result = basic.dict_file_list()
        # 删除空元素
        if '' in dict_result:
            dict_result.remove('')
        
        if len(dict_result) == 0:
            dict_result.append("暂未生成字典")
            f = open(file='/TIP/info_scan/result/workerdictionary.txt',mode='w')
            for line in dict_result:
                f.write(str(line)+"\n")
            f.close()
            # 判断url.txt文件是否存在
            file_path = '/TIP/info_scan/result/workerdictionary.txt'
            if os.path.exists(file_path) and os.path.isfile(file_path):
                return send_file(file_path, as_attachment=True, download_name='dict.txt')
        else:
            # 判断workerdictionary文件是否存在
            file_path = '/TIP/info_scan/result/workerdictionary.txt'
            if os.path.exists(file_path) and os.path.isfile(file_path):
                return send_file(file_path, as_attachment=True, download_name='dict.txt')
    else:
        return render_template('login.html')
    

# 通过shodan获取资产
@app.route('/assets_byshodan/',methods=['POST'])
def assets_byshodan():
    user = session.get('username')
    if str(user) == main_username:
        inputshodanid = request.form['inputshodanid']
        start_num_shodan = request.form['start_num_shodan']
        end_num_shodan = request.form['end_num_shodan']

        # 筛选后资产时间线更新
        basic.assets_status_update('shodan获取资产已完成')
        shodanstatus = os.popen('bash /TIP/info_scan/finger.sh shodanassetstatus').read()
        try:
            if "running" in shodanstatus:
                shodan_status_result = "shodan资产获取程序正在运行中请勿重复提交"
            else:
                # 调用shell脚本并传参
                result = subprocess.run(["sh", "/TIP/info_scan/finger.sh","startshodanasset",inputshodanid, start_num_shodan, end_num_shodan], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                basic.success_third_party_port_addone(2)
                # 输出脚本的标准输出和标准错误
                print("标准输出:", result.stdout)
                print("标准错误:", result.stderr)
                shodan_status_result = "shodan资产获取程序已开启成功"
        except:
            basic.fail_third_party_port_addone(2)
        message_json = {
            "shodan_status_result":shodan_status_result
        }
        return jsonify(message_json)
    else:
        return render_template('login.html')
    


# 设备口令查询所有
@app.route("/showdevicepassword/")
def showdevicepassword():
    user = session.get('username')
    if str(user) == main_username:
        device_dict = basic.device_password_show()
        device_dict1 = "设备常用口令查询"
        message_json = {
            "device_dict":device_dict1,
            "device_dict_len":"设备类型（共"+str(len(device_dict))+"条 ）"
        }
        return jsonify(message_json)
    else:
        return render_template('login.html')
    

# 根据关键字查询设备密码
@app.route("/showdevicepasswordbykey/",methods=['POST'])
def showdevicepasswordbykey():
    user = session.get('username')
    if str(user) == main_username:
        # 定义新的列表用于存放通过关键字检索的结果
        device_new_list = []
        devicekeyvalue = request.form['devicekeyvalue']
        # 判断传入的值是否为空
        if devicekeyvalue != "":
            device_dict = basic.device_password_show()
            for key1 in device_dict:
                if str(devicekeyvalue) in str(key1):
                    device_new_list.append(key1)
        message_json = {
            "device_new_list":device_new_list,
            "device_new_list_len":"设备类型（共"+str(len(device_new_list))+"条 ）"
        }
        return jsonify(message_json)
    else:
        return render_template('login.html')



# 常见杀软名称查询所有
@app.route("/antivirus_soft_show_interface/")
def antivirus_soft_show_interface():
    user = session.get('username')
    if str(user) == main_username:
        antivirus_dict = basic.antivirus_soft_show()
        antivirus_dict1 = "运行cmd命令tasklist获取进程信息，将进程名复制到输入框可查询系统中运行的杀软信息"
        message_json = {
            "antivirus_dict":antivirus_dict1,
            "antivirus_dict_len":"常见杀毒软件（共"+str(len(antivirus_dict))+"条 ）"
        }
        return jsonify(message_json)
    else:
        return render_template('login.html')


# 根据关键字查询杀软进程名称
@app.route("/antivirus_soft_show_interface_bykey/",methods=['POST'])
def antivirus_soft_show_interface_bykey():
    user = session.get('username')
    if str(user) == main_username:
        antiviruslines = request.json.get('antiviruslines', [])
        antiviruslines_uniq_1 = list(set(antiviruslines))
        # 删除列表中的空元素
        antiviruslines_uniq = []
        for anti_line in antiviruslines_uniq_1:
            print(anti_line)
            if anti_line != '':
                antiviruslines_uniq.append(anti_line)
        
        # 定义新的列表用于存放通过关键字检索的结果
        antivirus_new_list = []

        antivirus_dict = basic.antivirus_soft_show()

        # 循环判断
        for i in antivirus_dict:
            for j in antiviruslines_uniq:
                if str(j) in str(i):
                    antivirus_new_list.append(i)

        message_json = {
            "antivirus_dict":antivirus_new_list,
            "antivirus_dict_len":"设备类型（共"+str(len(antivirus_new_list))+"条 ）"
        }
        return jsonify(message_json)
    else:
        return render_template('login.html')


# 过滤内网IP
@app.route("/filterprivateip/",methods=['GET'])
def filterprivateip():
    user = session.get('username')
    if str(user) == main_username:
        filterresult = basic.filter_private_ip_lib()
        message_json = {
            "filterstatus":filterresult[0],
            "peivatenum":"排除 "+str(filterresult[1])+" 条内网地址"
        }
        return jsonify(message_json)
    else:
        return render_template('login.html')
    

# 提取URL地址
@app.route("/withdrawurllocation/",methods=['GET'])
def withdrawurllocation():
    user = session.get('username')
    if str(user) == main_username:
        url_list = []
        assets_list = basic.url_file_ip_list() 
        for url in assets_list:
            if 'http' in url:
                url_list.append(url)
        if len(url_list) <= len(assets_list):
            # 遍历列表存入目标资产
            f = open(file='/TIP/batch_scan_domain/url.txt', mode='w')
            for k in url_list:
                f.write(str(k)+"\n")
            f.close()
            filterurlresult = "提取URL地址成功"
        else:
            filterurlresult = "提取URL地址失败"
        message_json = {
            "filterurlresult":filterurlresult
        }
        return jsonify(message_json)
    else:
        return render_template('login.html')
    

# 资产去重
@app.route("/assetslocationuniq/",methods=['GET'])
def assetslocationuniq():
    user = session.get('username')
    if str(user) == main_username:
        url_list = []
        assets_list = basic.url_file_ip_list() 
        assets_list_uniq = list(set(assets_list))
        if len(assets_list_uniq) <= len(assets_list):
            # 遍历列表存入目标资产
            f = open(file='/TIP/batch_scan_domain/url.txt', mode='w')
            for k in assets_list_uniq:
                f.write(str(k)+"\n")
            f.close()
            uniqfilterurlresult = "资产去重成功"
        else:
            uniqfilterurlresult = "资产去重失败"
        message_json = {
            "uniqfilterurlresult":uniqfilterurlresult
        }
        return jsonify(message_json)
    else:
        return render_template('login.html')



# 提取IP地址
@app.route("/withdrawiplocation/",methods=['GET'])
def withdrawiplocation():
    user = session.get('username')
    if str(user) == main_username:
        withdrawipresult = basic.withdrawiplocation_lib()
        message_json = {
            "withdrawipresult":withdrawipresult
        }
        return jsonify(message_json)
    else:
        return render_template('login.html')
    

# 开启JNDI服务
@app.route("/startjndiservice/",methods=['GET'])
def startjndiservice():
    user = session.get('username')
    if str(user) == main_username:
        jndi_status = os.popen('bash /TIP/info_scan/finger.sh jndi_server_status').read()
        jndi_python_status = os.popen('bash /TIP/info_scan/finger.sh jndi_python_server_status').read()
        if "running" in jndi_status and "running" in jndi_python_status:
            jndistatus = "开启"
        else:
            basic.startjndi_lib()
            jndistatus = "开启"
        
        message_json = {
            "jndistatus":jndistatus
        }
        return jsonify(message_json)
    else:
        return render_template('login.html')
    

# 关闭JNDI服务
@app.route("/stopjndiservice/",methods=['GET'])
def stopjndiservice():
    user = session.get('username')
    if str(user) == main_username:
        jndi_status = os.popen('bash /TIP/info_scan/finger.sh jndi_server_status').read()
        jndi_python_status = os.popen('bash /TIP/info_scan/finger.sh jndi_python_server_status').read()
        os.popen('bash /TIP/info_scan/finger.sh stop_jndi_python')

        if "running" in jndi_status and "running" in jndi_python_status:
            jndistatus = "开启"
        else:
            jndistatus = "关闭"
        
        message_json = {
            "jndistatus":jndistatus
        }
        return jsonify(message_json)
    else:
        return render_template('login.html')


# 跳转到态势感知大屏
@app.route("/largescreenpage/")
def largescreenpage():
    user = session.get('username')
    if str(user) == main_username:
        return render_template('largescreen.html')
    else:
        return render_template('login.html')


# 态势感知大屏数据
@app.route("/largescreenpagedata/")
def largescreenpagedata():
    user = session.get('username')
    if str(user) == main_username:
        # cpu占用率
        cpu_percent = psutil.cpu_percent(interval=1)
        # cpu核数
        cpu_threads = psutil.cpu_count()

        # 获取内存信息  
        mem = psutil.virtual_memory()  
        # 计算内存占用百分比  
        memory_percent = mem.percent
        # 总资产数
        total_assets_num = os.popen('bash /TIP/info_scan/finger.sh current_url_file_num').read()
        # 磁盘读速率
        disk_read_1 = basic.disk_read_write()[0]
        if disk_read_1 <= 0.1:
            disk_read = f"{disk_read_1:.1f}"
        elif disk_read_1 <= 0.01:
            disk_read = f"{disk_read_1:.2f}"
        else:
            disk_read = f"{disk_read_1:.3f}"
        
        # 磁盘写速率
        disk_write_1 = basic.disk_read_write()[1]
        if disk_write_1 <= 0.1:
            disk_write = f"{disk_write_1:.1f}"
        elif disk_write_1 <= 0.01:
            disk_write = f"{disk_write_1:.2f}"
        else:
            disk_write = f"{disk_write_1:.3f}"

        # 进程数量
        pidnum = str(len(psutil.pids()))
                     
        # 网络带宽使用率
        network_rate = basic.get_network_speed()

        # 主机资产数量
        assets_hostname = basic.extract_host_assets_lib()

        # 网站资产数量
        assets_site = basic.extract_site_assets_lib()

        # shodan官方接口额度
        shodankeyvalue = basic.select_session_time_lib(3)
        apis = shodan.Shodan(shodankeyvalue)
        try:
            account_info = apis.info()
        except:
            pass
        try:
            account_info_num = str(account_info['query_credits'])
            total_account_info_num = str(account_info['scan_credits'])
        except:
            account_info_num = "key无效"
            total_account_info_num = "key无效"

        shodan_account_info_percent = str(account_info_num)+"/"+str(total_account_info_num)
        # 会话时间
        session_time = basic.select_session_time_lib(1)

        # 第三方接口额度剩余查询
        fofa_inter_num_success = basic.total_port_success_num(1)
        fofa_inter_num_fail = basic.total_port_fail_num(1)
        shodan_inter_num_success = basic.total_port_success_num(2)
        shodan_inter_num_fail = basic.total_port_fail_num(2)
        crt_inter_num_success = basic.total_port_success_num(3)
        crt_inter_num_fail = basic.total_port_fail_num(3)
        icp_inter_num_success = basic.total_port_success_num(4)
        icp_inter_num_fail = basic.total_port_fail_num(4)
        gd_inter_num_success = basic.total_port_success_num(5)
        gd_inter_num_fail = basic.total_port_fail_num(5)
        otx_inter_num_success = basic.total_port_success_num(6)
        otx_inter_num_fail = basic.total_port_fail_num(6)

        # 第三方接口总量和剩余查询
        tatal_fofa_num = int(fofa_inter_num_success) + int(fofa_inter_num_fail)
        fofa_remaining_num_1 =  int(fofa_max_num) - tatal_fofa_num
        if fofa_remaining_num_1 < 0:
            fofa_remaining_num = 0
        else:
            fofa_remaining_num = fofa_remaining_num_1

        total_shodan_num = int(shodan_inter_num_success) + int(shodan_inter_num_fail)
        shodan_remaining_num_1 = int(shodan_max_num) - total_shodan_num
        if shodan_remaining_num_1 < 0:
            shodan_remaining_num = 0
        else:
            shodan_remaining_num = shodan_remaining_num_1

        tatal_crt_num = int(crt_inter_num_success) + int(crt_inter_num_fail)
        crt_remaining_num_1 =  int(crt_max_num) - tatal_crt_num
        if crt_remaining_num_1 < 0:
            crt_remaining_num = 0
        else:
            crt_remaining_num = crt_remaining_num_1

        tatal_icp_num = int(icp_inter_num_success) + int(icp_inter_num_fail)
        icp_remaining_num_1 =  int(icp_max_num) - tatal_icp_num
        if icp_remaining_num_1 < 0:
            icp_remaining_num = 0
        else:
            icp_remaining_num = icp_remaining_num_1

        tatal_amap_num = int(gd_inter_num_success) + int(gd_inter_num_fail)
        amap_remaining_num_1 =  int(amap_max_num) - tatal_amap_num
        if amap_remaining_num_1 < 0:
            amap_remaining_num = 0
        else:
            amap_remaining_num = amap_remaining_num_1
        
        tatal_otx_num = int(otx_inter_num_success) + int(otx_inter_num_fail)
        otx_remaining_num_1 =  int(otx_max_num) - tatal_otx_num
        if otx_remaining_num_1 < 0:
            otx_remaining_num = 0
        else:
            otx_remaining_num = otx_remaining_num_1

        # 高危资产数量查询
        shiro_num = basic.key_point_assets_num(Shiro_rule)
        springboot_num = basic.key_point_assets_num(SpringBoot_rule)
        weblogic_num = basic.key_point_assets_num(weblogic_rule)
        ruoyi_num = basic.key_point_assets_num(ruoyi_rule)
        struts2_num = basic.key_point_assets_num(struts2_rule)
        WordPress_num = basic.key_point_assets_num(WordPress_rule)
        jboss_num = basic.key_point_assets_num(jboss_rule)
        phpmyadmin_num = basic.key_point_assets_num(phpMyAdmin_rule)
        ThinkPHP_num = basic.key_point_assets_num(ThinkPHP_rule)
        nacos_num = basic.key_point_assets_num(nacos_rule)
        fanwei_num = basic.key_point_assets_num(fanwei_rule)
        tomcat_num = basic.key_point_assets_num(tomcat_rule)

        # 服务运行状态实时统计
        jndi_status = os.popen('bash /TIP/info_scan/finger.sh jndi_server_status').read()
        jndi_python_status = os.popen('bash /TIP/info_scan/finger.sh jndi_python_server_status').read()
        if "running" in jndi_status and "running" in jndi_python_status:
            jndi_status1 = jndi_status
            jndi_status2 = ""
        else:
            jndi_status1 = ""
            jndi_status2 = jndi_status


        xray_report_status = os.popen('bash /TIP/info_scan/finger.sh xray_report_status').read()
        if "running" in xray_report_status:
            xray_report_status1 = xray_report_status
            xray_report_status2 = ""
        else:
            xray_report_status1 = ""
            xray_report_status2 = xray_report_status

        urlfinder_report_status = os.popen('bash /TIP/info_scan/finger.sh urlfinder_report_status').read()
        if "running" in urlfinder_report_status:
            urlfinder_report_status1 = urlfinder_report_status
            urlfinder_report_status2 = ""
        else:
            urlfinder_report_status1 = ""
            urlfinder_report_status2 = urlfinder_report_status

        afrog_report_status = os.popen('bash /TIP/info_scan/finger.sh afrog_report_status').read()
        if "running" in afrog_report_status:
            afrog_report_status1 = afrog_report_status
            afrog_report_status2 = ""
        else:
            afrog_report_status1 = ""
            afrog_report_status2 = afrog_report_status

        infoinfostatus = os.popen('bash /TIP/info_scan/finger.sh infoinfostatus').read()
        if "running" in infoinfostatus:
            infoinfostatus1 = infoinfostatus
            infoinfostatus2 = ""
        else:
            infoinfostatus1 = ""
            infoinfostatus2 = infoinfostatus

        dirsub_sys_status = os.popen('bash /TIP/info_scan/finger.sh dirsub_sys_status').read()
        if "running" in dirsub_sys_status:
            dirsub_sys_status1 = dirsub_sys_status
            dirsub_sys_status2 = ""
        else:
            dirsub_sys_status1 = ""
            dirsub_sys_status2 = dirsub_sys_status

        mysql_status = os.popen('bash /TIP/info_scan/finger.sh mysql_server_status').read()
        if "running" in mysql_status:
            mysql_status1 = mysql_status
            mysql_status2 = ""
        else:
            mysql_status1 = ""
            mysql_status2 = mysql_status

        xraystatus = os.popen('bash /TIP/info_scan/finger.sh xraystatus').read()
        if "running" in xraystatus:
            xraystatus1 = xraystatus
            xraystatus2 = ""
        else:
            xraystatus1 = ""
            xraystatus2 = xraystatus
        
        cdn_status = os.popen('bash /TIP/info_scan/finger.sh cdn_status').read()
        if "running" in cdn_status:
            cdn_status1 = cdn_status
            cdn_status2 = ""
        else:
            cdn_status1 = ""
            cdn_status2 = cdn_status
        
        httpx_status = os.popen('bash /TIP/info_scan/finger.sh httpx_status').read()
        if "running" in httpx_status:
            httpx_status1 = httpx_status
            httpx_status2 = ""
        else:
            httpx_status1 = ""
            httpx_status2 = httpx_status
        
        # 汇总报告生成状态
        total_report_status = os.popen('bash /TIP/info_scan/finger.sh totalreport_num').read()
        if int(total_report_status) == 2:
            total_report_status_result1 = ""
            total_report_status_result2 = "已汇总"
        elif int(total_report_status) == 1:
            total_report_status_result1 = "汇总中"
            total_report_status_result2 = ""

        # 未授权专项扫描状态和耗时
        redis_status = os.popen('bash /TIP/info_scan/finger.sh redis_vuln_scan_status').read()
        if "running" in redis_status:
            redis_status1 = redis_status
            redis_status2 = ""
            rediscontime = "?"
        else:
            redis_status1 = ""
            redis_status2 = redis_status
            rediscontime = basic.scan_end_start_time(32)

        mongodb_status = os.popen('bash /TIP/info_scan/finger.sh mongodb_vuln_scan_status').read()
        if "running" in mongodb_status:
            mongodb_status1 = mongodb_status
            mongodb_status2 = ""
            mongodbcontime = "计算中"
        else:
            mongodb_status1 = ""
            mongodb_status2 = mongodb_status
            mongodbcontime = basic.scan_end_start_time(33)

        memcached_status = os.popen('bash /TIP/info_scan/finger.sh memcached_vuln_scan_status').read()
        if "running" in memcached_status:
            memcached_status1 = memcached_status
            memcached_status2 = ""
            memcachedcontime = "计算中"
        else:
            memcached_status1 = ""
            memcached_status2 = memcached_status
            memcachedcontime = basic.scan_end_start_time(34)

        zookeeper_status = os.popen('bash /TIP/info_scan/finger.sh zookeeper_vuln_scan_status').read()
        if "running" in zookeeper_status:
            zookeeper_status1 = zookeeper_status
            zookeeper_status2 = ""
            zookeepercontime = "计算中"
        else:
            zookeeper_status1 = ""
            zookeeper_status2 = zookeeper_status
            zookeepercontime = basic.scan_end_start_time(35)

        ftp_status = os.popen('bash /TIP/info_scan/finger.sh ftp_vuln_scan_status').read()
        if "running" in ftp_status:
            ftp_status1 = ftp_status
            ftp_status2 = ""
            ftpcontime = "计算中"
        else:
            ftp_status1 = ""
            ftp_status2 = ftp_status
            ftpcontime = basic.scan_end_start_time(36)

        couchdb_status = os.popen('bash /TIP/info_scan/finger.sh couchdb_vuln_scan_status').read()
        if "running" in couchdb_status:
            couchdb_status1 = couchdb_status
            couchdb_status2 = ""
            couchdbcontime = "计算中"
        else:
            couchdb_status1 = ""
            couchdb_status2 = couchdb_status
            couchdbcontime = basic.scan_end_start_time(37)

        docker_status = os.popen('bash /TIP/info_scan/finger.sh docker_vuln_scan_status').read()
        if "running" in docker_status:
            docker_status1 = docker_status
            docker_status2 = ""
            dockercontime = "计算中"
        else:
            docker_status1 = ""
            docker_status2 = docker_status
            dockercontime = basic.scan_end_start_time(38)

        
        hadoop_status = os.popen('bash /TIP/info_scan/finger.sh hadoop_vuln_scan_status').read()
        if "running" in hadoop_status:
            hadoop_status1 = hadoop_status
            hadoop_status2 = ""
            hadoopcontime = "计算中"
        else:
            hadoop_status1 = ""
            hadoop_status2 = hadoop_status
            hadoopcontime = basic.scan_end_start_time(39)

        nfs_status = os.popen('bash /TIP/info_scan/finger.sh nfs_vuln_scan_status').read()
        if "running" in nfs_status:
            nfs_status1 = nfs_status
            nfs_status2 = ""
            nfscontime = "计算中"
        else:
            nfs_status1 = ""
            nfs_status2 = nfs_status
            nfscontime = basic.scan_end_start_time(40)

        rsync_status = os.popen('bash /TIP/info_scan/finger.sh rsync_vuln_scan_status').read()
        if "running" in rsync_status:
            rsync_status1 = rsync_status
            rsync_status2 = ""
            rsynccontime = "计算中"
        else:
            rsync_status1 = ""
            rsync_status2 = rsync_status
            rsynccontime = basic.scan_end_start_time(41)

        unes1_status = os.popen('bash /TIP/info_scan/finger.sh elasticsearch_vuln_scan_status').read()
        if "running" in unes1_status:
            unes1_status1 = unes1_status
            unes1_status2 = ""
            unes1contime = "计算中"
        else:
            unes1_status1 = ""
            unes1_status2 = unes1_status
            unes1contime = basic.scan_end_start_time(42)

        # 信息收集专项扫描状态和耗时
        eholestatus = os.popen('bash /TIP/info_scan/finger.sh ehole_status').read()
        if "running" in eholestatus:
            eholestatus1 = eholestatus
            eholestatus2 = ""
            eholecontime = "?"
        else:
            eholestatus1 = ""
            eholestatus2 = eholestatus
            eholecontime = basic.scan_end_start_time(2)

        bbscanstatus = os.popen('bash /TIP/info_scan/finger.sh bbscan_status').read()
        if "running" in bbscanstatus:
            bbscanstatus1 = bbscanstatus
            bbscanstatus2 = ""
            bbscancontime = "?"
        else:
            bbscanstatus1 = ""
            bbscanstatus2 = bbscanstatus
            bbscancontime = basic.scan_end_start_time(3)

        otx_status = os.popen('bash /TIP/info_scan/finger.sh otx_domain_url_shell_status').read()
        if "running" in otx_status:
            otx_status1 = otx_status
            otx_status2 = ""
            otxcontime = "?"
        else:
            otx_status1 = ""
            otx_status2 = otx_status
            otxcontime = basic.scan_end_start_time(4)

        crt_status = os.popen('bash /TIP/info_scan/finger.sh crt_subdomain_shell_status').read()
        if "running" in crt_status:
            crt_status1 = crt_status
            crt_status2 = ""
            crtcontime = "?"
        else:
            crt_status1 = ""
            crt_status2 = crt_status
            crtcontime = basic.scan_end_start_time(5)

        nmapstatus =os.popen('bash /TIP/info_scan/finger.sh nmapstatus').read()
        if "running" in nmapstatus:
            nmapstatus1 = nmapstatus
            nmapstatus2 = ""
            nmapcontime = "?"

        else:
            nmapstatus1 = ""
            nmapstatus2 = nmapstatus
            nmapcontime = basic.scan_end_start_time(1)

        waf_status = os.popen('bash /TIP/info_scan/finger.sh waf_scan_status').read()
        if "running" in waf_status:
            waf_status1 = waf_status
            waf_status2 = ""
            wafcontime = "?"
        else:
            waf_status1 = ""
            waf_status2 = waf_status
            wafcontime = basic.scan_end_start_time(6)

        bypass_status = os.popen('bash /TIP/info_scan/finger.sh bypassstatus').read()
        if "running" in bypass_status:
            bypass_status1 = bypass_status
            bypass_status2 = ""
            bypasscontime = "?"
        else:
            bypass_status1 = ""
            bypass_status2 = bypass_status
            bypasscontime = basic.scan_end_start_time(7)


        crawlergo_status = os.popen('bash /TIP/info_scan/finger.sh crawlergo_status').read()
        if "running" in crawlergo_status:
            crawlergo_status1 = crawlergo_status
            crawlergo_status2 = ""
            crawlergocontime = "?"
        else:
            crawlergo_status1 = ""
            crawlergo_status2 = crawlergo_status
            crawlergocontime = basic.scan_end_start_time(8)

        subfinder_status = os.popen('bash /TIP/info_scan/finger.sh subfinder_status').read()
        if "running" in subfinder_status:
            subfinder_status1 = subfinder_status
            subfinder_status2 = ""
            subfindercontime = "?"
        else:
            subfinder_status1 = ""
            subfinder_status2 = subfinder_status
            subfindercontime = basic.scan_end_start_time(31)

        # 框架组件专项
        struts2status = os.popen('bash /TIP/info_scan/finger.sh struts2_status').read()
        if "running" in struts2status:
            struts2status1 = struts2status
            struts2status2 = ""
            struts2contime = "?"
        else:
            struts2status1 = ""
            struts2status2 = struts2status
            struts2contime = basic.scan_end_start_time(9)
        weblogicstatus = os.popen('bash /TIP/info_scan/finger.sh weblogic_status').read()
        if "running" in weblogicstatus:
            weblogicstatus1 = weblogicstatus
            weblogicstatus2 = ""
            weblogiccontime = "?"
        else:
            weblogicstatus1 = ""
            weblogicstatus2 = weblogicstatus
            weblogiccontime = basic.scan_end_start_time(10)
        shirostatus = os.popen('bash /TIP/info_scan/finger.sh shiro_status').read()
        if "running" in shirostatus:
            shirostatus1 = shirostatus
            shirostatus2 = ""
            shirocontime = "?"
        else:
            shirostatus1 = ""
            shirostatus2 = shirostatus
            shirocontime = basic.scan_end_start_time(11)
        springbootstatus = os.popen('bash /TIP/info_scan/finger.sh springboot_scan_status').read()
        if "running" in springbootstatus:
            springbootstatus1 = springbootstatus
            springbootstatus2 = ""
            springbootcontime = "?"
        else:
            springbootstatus1 = ""
            springbootstatus2 = springbootstatus
            springbootcontime = basic.scan_end_start_time(12)

        thinkphpstatus = os.popen('bash /TIP/info_scan/finger.sh TPscan_status').read()
        if "running" in thinkphpstatus:
            thinkphpstatus1 = thinkphpstatus
            thinkphpstatus2 = ""
            thinkphpcontime = "?"
        else:
            thinkphpstatus1 = ""
            thinkphpstatus2 = thinkphpstatus
            thinkphpcontime = basic.scan_end_start_time(13)

        es_unauthorized_status = os.popen('bash /TIP/info_scan/finger.sh es_unauthorized_status').read()
        if "running" in es_unauthorized_status:
            es_unauthorized_status1 = es_unauthorized_status
            es_unauthorized_status2 = ""
            esccontime = "?"
        else:
            es_unauthorized_status1 = ""
            es_unauthorized_status2 = es_unauthorized_status
            esccontime = basic.scan_end_start_time(14)

        nacos_status = os.popen('bash /TIP/info_scan/finger.sh nacos_vuln_scan_status').read()
        if "running" in nacos_status:
            nacos_status1 = nacos_status
            nacos_status2 = ""
            nacoscontime = "?"
        else:
            nacos_status1 = ""
            nacos_status2 = nacos_status
            nacoscontime = basic.scan_end_start_time(15)
        tomcat_status = os.popen('bash /TIP/info_scan/finger.sh tomcat_vuln_scan_status').read()
        if "running" in tomcat_status:
            tomcat_status1 = tomcat_status
            tomcat_status2 = ""
            tomcatcontime = "?"
        else:
            tomcat_status1 = ""
            tomcat_status2 = tomcat_status
            tomcatcontime = basic.scan_end_start_time(16)
        fastjson_status = os.popen('bash /TIP/info_scan/finger.sh fastjson_scan_status').read()
        if "running" in fastjson_status:
            fastjson_status1 = fastjson_status
            fastjson_status2 = ""
            fastjsoncontime = "?"
        else:
            fastjson_status1 = ""
            fastjson_status2 = fastjson_status
            fastjsoncontime = basic.scan_end_start_time(17)


        # 综合专项
        afrogscanstatus = os.popen('bash /TIP/info_scan/finger.sh afrogscan_status').read()
        if "running" in afrogscanstatus:
            afrogscanstatus1 = afrogscanstatus
            afrogscanstatus2 = ""
            afrogcontime = "?"
        else:
            afrogscanstatus1 = ""
            afrogscanstatus2 = afrogscanstatus
            afrogcontime = basic.scan_end_start_time(18)
        fscanstatus = os.popen('bash /TIP/info_scan/finger.sh fscan_status').read()
        if "running" in fscanstatus:
            fscanstatus1 = fscanstatus
            fscanstatus2 = ""
            fscancontime = "?"
        else:
            fscanstatus1 = ""
            fscanstatus2 = fscanstatus
            fscancontime = basic.scan_end_start_time(19)
        hydrastatus = os.popen('bash /TIP/info_scan/finger.sh hydra_status').read()
        if "running" in hydrastatus:
            hydrastatus1 = hydrastatus
            hydrastatus2 = ""
            weakpasscontime = "?"
        else:
            hydrastatus1 = ""
            hydrastatus2 = hydrastatus
            weakpasscontime = basic.scan_end_start_time(20)

        vulmapscanstatus = os.popen('bash /TIP/info_scan/finger.sh vulmapscan_status').read()
        if "running" in vulmapscanstatus:
            vulmapscanstatus1 = vulmapscanstatus
            vulmapscanstatus2 = ""
            vulmapcontime = "?"
        else:
            vulmapscanstatus1 = ""
            vulmapscanstatus2 = vulmapscanstatus
            vulmapcontime = basic.scan_end_start_time(22)

        nucleistatus =os.popen('bash /TIP/info_scan/finger.sh nucleistatus').read()
        if "running" in nucleistatus:
            nucleistatus1 = nucleistatus
            nucleistatus2 = ""
            nucleicontime = "?"
        else:
            nucleistatus1 = ""
            nucleistatus2 = nucleistatus
            nucleicontime = basic.scan_end_start_time(23)

        weaver_status = os.popen('bash /TIP/info_scan/finger.sh weaver_status').read()
        if "running" in weaver_status:
            weaver_status1 = weaver_status
            weaver_status2 = ""
            weavercontime = "?"
        else:
            weaver_status1 = ""
            weaver_status2 = weaver_status
            weavercontime = basic.scan_end_start_time(24)
        seeyonstatus = os.popen('bash /TIP/info_scan/finger.sh seeyon_vuln_scan_status').read()
        if "running" in seeyonstatus:
            seeyonstatus1 = seeyonstatus
            seeyonstatus2 = ""
            seeyoncontime = "?"
        else:
            seeyonstatus1 = ""
            seeyonstatus2 = seeyonstatus
            seeyoncontime = basic.scan_end_start_time(27)
        yonsuite_status = os.popen('bash /TIP/info_scan/finger.sh yonsuite_vuln_scan_status').read()
        if "running" in yonsuite_status:
            yonsuite_status1 = yonsuite_status
            yonsuite_status2 = ""
            yonsuitecontime = "?"
            
        else:
            yonsuite_status1 = ""
            yonsuite_status2 = yonsuite_status
            yonsuitecontime = basic.scan_end_start_time(28)


        kingdee_status = os.popen('bash /TIP/info_scan/finger.sh kingdee_vuln_scan_status').read()
        if "running" in kingdee_status:
            kingdee_status1 = kingdee_status
            kingdee_status2 = ""
            kingdeecontime = "?"
            
        else:
            kingdee_status1 = ""
            kingdee_status2 = kingdee_status
            kingdeecontime = basic.scan_end_start_time(29)
        
        wanhu_status = os.popen('bash /TIP/info_scan/finger.sh wanhu_vuln_scan_status').read()
        if "running" in wanhu_status:
            wanhu_status1 = wanhu_status
            wanhu_status2 = ""
            wanhucontime = "?"
            
        else:
            wanhu_status1 = ""
            wanhu_status2 = wanhu_status
            wanhucontime = basic.scan_end_start_time(30)

        message_json = {
            # 综合专项
            "afrogscanstatus1":afrogscanstatus1,
            "afrogscanstatus2":afrogscanstatus2,
            "afrogcontime":afrogcontime,
            "fscanstatus1":fscanstatus1,
            "fscanstatus2":fscanstatus2,
            "fscancontime":fscancontime,
            "hydrastatus1":hydrastatus1,
            "hydrastatus2":hydrastatus2,
            "weakpasscontime":weakpasscontime,
            "vulmapscanstatus1":vulmapscanstatus1,
            "vulmapscanstatus2":vulmapscanstatus2,
            "vulmapcontime":vulmapcontime,
            "nucleistatus1":nucleistatus1,
            "nucleistatus2":nucleistatus2,
            "nucleicontime":nucleicontime,
            "weaver_status1":weaver_status1,
            "weaver_status2":weaver_status2,
            "weavercontime":weavercontime,
            "seeyonstatus1":seeyonstatus1,
            "seeyonstatus2":seeyonstatus2,
            "seeyoncontime":seeyoncontime,
            "yonsuite_status1":yonsuite_status1,
            "yonsuite_status2":yonsuite_status2,
            "yonsuitecontime":yonsuitecontime,
            "kingdee_status1":kingdee_status1,
            "kingdee_status2":kingdee_status2,
            "kingdeecontime":kingdeecontime,
            "wanhu_status1":wanhu_status1,
            "wanhu_status2":wanhu_status2,
            "wanhucontime":wanhucontime,
            # 框架组件专项
            "struts2status1":struts2status1,
            "struts2status2":struts2status2,
            "struts2contime":struts2contime,
            "weblogicstatus1":weblogicstatus1,
            "weblogicstatus2":weblogicstatus2,
            "weblogiccontime":weblogiccontime,
            "shirostatus1":shirostatus1,
            "shirostatus2":shirostatus2,
            "shirocontime":shirocontime,
            "springbootstatus1":springbootstatus1,
            "springbootstatus2":springbootstatus2,
            "springbootcontime":springbootcontime,
            "thinkphpstatus1":thinkphpstatus1,
            "thinkphpstatus2":thinkphpstatus2,
            "thinkphpcontime":thinkphpcontime,
            "es_unauthorized_status1":es_unauthorized_status1,
            "es_unauthorized_status2":es_unauthorized_status2,
            "esccontime":esccontime,
            "nacos_status1":nacos_status1,
            "nacos_status2":nacos_status2,
            "nacoscontime":nacoscontime,
            "tomcat_status1":tomcat_status1,
            "tomcat_status2":tomcat_status2,
            "tomcatcontime":tomcatcontime,
            "fastjson_status1":fastjson_status1,
            "fastjson_status2":fastjson_status2,
            "fastjsoncontime":fastjsoncontime,

            # 信息收集专项
            "eholestatus1":eholestatus1,
            "eholestatus2":eholestatus2,
            "eholecontime":eholecontime,
            "bbscanstatus1":bbscanstatus1,
            "bbscanstatus2":bbscanstatus2,
            "bbscancontime":bbscancontime,
            "otx_status1":otx_status1,
            "otx_status2":otx_status2,
            "otxcontime":otxcontime,
            "crt_status1":crt_status1,
            "crt_status2":crt_status2,
            "crtcontime":crtcontime,
            "nmapstatus1":nmapstatus1,
            "nmapstatus2":nmapstatus2,
            "nmapcontime":nmapcontime,
            "waf_status1":waf_status1,
            "waf_status2":waf_status2,
            "wafcontime":wafcontime,
            "bypass_status1":bypass_status1,
            "bypass_status2":bypass_status2,
            "bypasscontime":bypasscontime,
            "crawlergo_status1":crawlergo_status1,
            "crawlergo_status2":crawlergo_status2,
            "crawlergocontime":crawlergocontime,
            "subfinder_status1":subfinder_status1,
            "subfinder_status2":subfinder_status2,
            "subfindercontime":subfindercontime,
            # 系统信息
            "cpuinfo":str(cpu_percent)+"%",
            "cpu_threads":str(cpu_threads),
            "memoryinfo":str(memory_percent)+"%",
            "total_assets_num":str(total_assets_num),
            "disk_read":str(disk_read),
            "disk_write":str(disk_write),
            "pidnum":pidnum,
            "net_rate":network_rate,
            "assets_hostname":assets_hostname,
            "assets_site":assets_site,
            "shodan_account_info_percent":shodan_account_info_percent,
            "session_time":session_time,
        
            # 接口成功和失败
            "fofa_inter_num_success":fofa_inter_num_success,
            "fofa_inter_num_fail":fofa_inter_num_fail,
            "shodan_inter_num_success":shodan_inter_num_success,
            "shodan_inter_num_fail":shodan_inter_num_fail,
            "crt_inter_num_success":crt_inter_num_success,
            "crt_inter_num_fail":crt_inter_num_fail,
            "icp_inter_num_success":icp_inter_num_success,
            "icp_inter_num_fail":icp_inter_num_fail,
            "gd_inter_num_success":gd_inter_num_success,
            "gd_inter_num_fail":gd_inter_num_fail,
            "otx_inter_num_success":otx_inter_num_success,
            "otx_inter_num_fail":otx_inter_num_fail,

            # 接口总量和剩余
            "tatal_fofa_num":str(tatal_fofa_num),
            "fofa_remaining_num":str(fofa_remaining_num),
            "total_shodan_num":str(total_shodan_num),
            "shodan_remaining_num":str(shodan_remaining_num),
            "tatal_crt_num":str(tatal_crt_num),
            "crt_remaining_num":str(crt_remaining_num),
            "tatal_icp_num":str(tatal_icp_num),
            "icp_remaining_num":str(icp_remaining_num),
            "tatal_amap_num":str(tatal_amap_num),
            "amap_remaining_num":str(amap_remaining_num),
            "tatal_otx_num":str(tatal_otx_num),
            "otx_remaining_num":str(otx_remaining_num),

            # 高危资产数量统计
            "shiro_num":str(shiro_num),
            "springboot_num":str(springboot_num),
            "struts2_num":str(struts2_num),
            "weblogic_num":str(weblogic_num),
            "ruoyi_num":str(ruoyi_num),
            "WordPress_num":str(WordPress_num),
            "jboss_num":str(jboss_num),
            "phpmyadmin_num":str(phpmyadmin_num),
            "ThinkPHP_num":str(ThinkPHP_num),
            "nacos_num":str(nacos_num),
            "fanwei_num":str(fanwei_num),
            "tomcat_num":str(tomcat_num),

            # 服务运行状态实时统计
            "jndi_status1":jndi_status1,
            "jndi_status2":jndi_status2,
            "xray_report_status1":xray_report_status1,
            "xray_report_status2":xray_report_status2,
            "urlfinder_report_status1":urlfinder_report_status1,
            "urlfinder_report_status2":urlfinder_report_status2,
            "afrog_report_status1":afrog_report_status1,
            "afrog_report_status2":afrog_report_status2,
            "infoinfostatus1":infoinfostatus1,
            "infoinfostatus2":infoinfostatus2,
            "dirsub_sys_status1":dirsub_sys_status1,
            "dirsub_sys_status2":dirsub_sys_status2,
            "mysql_status1":mysql_status1,
            "mysql_status2":mysql_status2,
            "xraystatus1":xraystatus1,
            "xraystatus2":xraystatus2,
            "total_report_status_result1":total_report_status_result1,
            "total_report_status_result2":total_report_status_result2,
            "cdn_status1":cdn_status1,
            "cdn_status2":cdn_status2,
            "httpx_status1":httpx_status1,
            "httpx_status2":httpx_status2,

            # 未授权专项扫描状态和耗时
            "redis_status1":redis_status1,
            "redis_status2":redis_status2,
            "rediscontime":rediscontime,
            "mongodb_status1":mongodb_status1,
            "mongodb_status2":mongodb_status2,
            "mongodbcontime":mongodbcontime,
            "memcached_status1":memcached_status1,
            "memcached_status2":memcached_status2,
            "memcachedcontime":memcachedcontime,
            "zookeeper_status1":zookeeper_status1,
            "zookeeper_status2":zookeeper_status2,
            "zookeepercontime":zookeepercontime,
            "ftp_status1":ftp_status1,
            "ftp_status2":ftp_status2,
            "ftpcontime":ftpcontime,
            "couchdb_status1":couchdb_status1,
            "couchdb_status2":couchdb_status2,
            "couchdbcontime":couchdbcontime,
            "docker_status1":docker_status1,
            "docker_status2":docker_status2,
            "dockercontime":dockercontime,
            "hadoop_status1":hadoop_status1,
            "hadoop_status2":hadoop_status2,
            "hadoopcontime":hadoopcontime,
            "nfs_status1":nfs_status1,
            "nfs_status2":nfs_status2,
            "nfscontime":nfscontime,
            "rsync_status1":rsync_status1,
            "rsync_status2":rsync_status2,
            "rsynccontime":rsynccontime,
            "unes1_status1":unes1_status1,
            "unes1_status2":unes1_status2,
            "unes1contime":unes1contime

        }
        return jsonify(message_json)
    else:
        return render_template('login.html')



# 开启资产校验
@app.route("/startassetserification/",methods=['GET'])
def startassetserification():
    user = session.get('username')
    if str(user) == main_username:
        verificationresult = basic.update_verification_table_lib(1,1)
        message_json = {
            "verificationresult":verificationresult
        }
        return jsonify(message_json)
    else:
        return render_template('login.html')
    

# 关闭资产校验
@app.route("/stopassetserification/",methods=['GET'])
def stopassetserification():
    user = session.get('username')
    if str(user) == main_username:
        verificationresult = basic.update_verification_table_lib(2,1)
        message_json = {
            "verificationresult":verificationresult
        }
        return jsonify(message_json)
    else:
        return render_template('login.html')


# 高危资产特征查询
@app.route("/high_asset_characteristics/")
def high_asset_characteristics():
    user = session.get('username')
    if str(user) == main_username:
        assets_character_result = basic.select_rule()
        if len(assets_character_result) == 0:
            assets_character_result = ["高危资产规则为空"]
        message_json = {
            "assets_character_result":assets_character_result
        }
        return jsonify(message_json)
    else:
        return render_template('login.html')


if __name__ == '__main__':  
    app.run(host="127.0.0.1",port=80)