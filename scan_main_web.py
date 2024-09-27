# Description:[主系统]
# Author:[huan666]
# Date:[2023/11/15]
# update:[2024/9/23]

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
from config import history_switch
import report_total
import pandas as pd
from basic import root_domain_scan
from config import ceye_key
#主系统账号密码配置导入
from config import main_username
from config import main_password
# 重点资产数量规则
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
# 设置session过期时间
from datetime import timedelta

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

# 统计列表元素出现次数
from collections import Counter


app = Flask(__name__,template_folder='./templates') 
app.secret_key = "DragonFire"
bootstrap = Bootstrap(app)


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
            data4 = basic.icp_info(ip)
        except:
            pass
    
        #公司位置信息
        try:
            companylocation = basic.amapscan(data4)
        except:
            companylocation = "接口异常"
        
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
        except:
            pass
    
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
    
    
        return render_template('index.html',data1=data1,data2=ip,data3=data3,data4=data4
        ,data5=localtion_list_result,data6=port,data7=history_domain,data8=os_type,data9=cdn_list
        ,data10=site_title_list_result,data11=subdomain_list,data12=ipstatus,data13=companylocation,data20=str(user))
    else:
        return render_template('login.html')

#跳转首页
@app.route("/index/")
def index():
    user = session.get('username')
    if str(user) == main_username:
        asset_file_list = basic.list_files_in_directory()
        return render_template('index.html',data20=str(user),data21=asset_file_list)
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
        session.permanent_session_lifetime = timedelta(minutes=30)  # 设置会话过期时间为30分钟

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
    


#历史URL查询
@app.route("/historyshow/")
def historyshow():
    user = session.get('username')
    if str(user) == main_username:
        # 漏洞扫描器时间线更新
        basic.vuln_scan_status_update('已完成历史url查询')
        otx_status_result = basic.otxhistorydomain_lib()
        message_json = {
            "otx_status_result":otx_status_result
        }
        return jsonify(message_json)
    else:
        return render_template('login.html')


#历史URL预览
@app.route("/previewhistoryurl/")
def previewhistoryurl():
    user = session.get('username')
    if str(user) == main_username:
        otx_his_num = os.popen('bash /TIP/info_scan/finger.sh otx_history_url_num').read()
        if int(otx_his_num) == 0:
            lines = ["暂无数据"]
        else:
            lines = []
            with open('/TIP/info_scan/result/otxhistoryurl.txt', 'r') as f:
                for line in f:
                    lines.append(line.strip())
        return '<br>'.join(lines)
    else:
        return render_template('login.html')
    


#关闭历史URL查询接口
@app.route("/killotxhistory/")
def killotxhistory():
    user = session.get('username')
    if str(user) == main_username:
        kill_otx_url_result = basic.stopotx_lib()
        message_json = {
            "kill_otx_url_result":kill_otx_url_result
        }

        return jsonify(message_json)
    else:
        return render_template('login.html')
    


#关闭基于证书查询子域名接口
@app.route("/kill_crt_subdomain_shell/")
def kill_crt_subdomain_shell():
    user = session.get('username')
    if str(user) == main_username:
        kill_crt_subdomain_result = basic.stopcrtsubdomain_lib()
        message_json = {
            "kill_crt_subdomain_result":kill_crt_subdomain_result
        }

        return jsonify(message_json)
    else:
        return render_template('login.html')


#nmap接口预览
@app.route("/nmapresultshow/")
def nmapresultshow():
    user = session.get('username')
    if str(user) == main_username:
        nmap_num = os.popen('bash /TIP/info_scan/finger.sh nmap_scan_num').read()
        if int(nmap_num) == 0:
            lines = ["暂无数据"]
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
        if int(nuclei_num) == 0:
            liness = ["暂无数据"]
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



#结束nuclei进程
@app.route("/killnucleiprocess/")
def killnucleiprocess():
    user = session.get('username')
    if str(user) == main_username:
        kill_nuclei_result = basic.stopnuclei_lib()
        message_json = {
            "kill_nuclei_result":kill_nuclei_result
        }

        return jsonify(message_json)
    
    else:
        return render_template('login.html')


#清空数据
@app.route("/deletenmapresult/")
def deletenmapresult():
    user = session.get('username')
    if str(user) == main_username:
        os.popen('rm -rf ./result/nmap.txt')
        os.popen('touch ./result/nmap.txt')
        return render_template('index.html')
    else:
        return render_template('login.html')



#清空xray报告
@app.route("/deletexrayreport/")
def deletexrayreport():
    user = session.get('username')
    if str(user) == main_username:
        os.popen('rm -rf /TIP/batch_scan_domain/report/*')
        return render_template('index.html')
    else:
        return render_template('login.html')


#结束进程
@app.route("/killprocess/")
def killprocess():
    user = session.get('username')
    if str(user) == main_username:
        os.popen('bash ./server_check.sh killscan')
        return render_template('index.html')
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
            # 2024.8.2更新  校验非URL资产
            result_rule = ""
            for ii in data:
                if "http://"  not in ii and "https://" not in ii:
                    result_rule = "请勿输入非URL字段！"
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


#启动nuclei
@app.route("/startnuclei/", methods=['POST'])
def startnuclei():
    user = session.get('username')
    if str(user) == main_username:
        poc_dir = request.form['poc_dir']
        # 漏洞扫描器时间线更新
        basic.vuln_scan_status_update('已完成nuclei漏洞扫描')
        nuclei_status_result = basic.startnuclei_lib(poc_dir)
        message_json = {
            "nuclei_status_result":nuclei_status_result
        }

        return jsonify(message_json)
    else:
        return render_template('login.html')
   


#系统管理
@app.route("/systemmanagement/")
def systemmanagement():
    user = session.get('username')
    if str(user) == main_username:

        # 扫描器运行状态，运行显示绿色，停止显示红色
        nmapstatus =os.popen('bash /TIP/info_scan/finger.sh nmapstatus').read()
        if "running" in nmapstatus:
            nmapstatus1 = nmapstatus
            nmapstatus2 = ""
        else:
            nmapstatus1 = ""
            nmapstatus2 = nmapstatus

        nucleistatus =os.popen('bash /TIP/info_scan/finger.sh nucleistatus').read()
        if "running" in nucleistatus:
            nucleistatus1 = nucleistatus
            nucleistatus2 = ""
        else:
            nucleistatus1 = ""
            nucleistatus2 = nucleistatus

        xraystatus = os.popen('bash /TIP/info_scan/finger.sh xraystatus').read()
        if "running" in xraystatus:
            xraystatus1 = xraystatus
            xraystatus2 = ""
        else:
            xraystatus1 = ""
            xraystatus2 = xraystatus

        radstatus =os.popen('bash /TIP/info_scan/finger.sh radstatus').read()
        if "running" in  radstatus:
            radstatus1 = radstatus
            radstatus2 = ""
        else:
            radstatus1 = ""
            radstatus2 = radstatus

        dirscanstatus = os.popen('bash /TIP/info_scan/finger.sh dirsearchstatus').read()
        if "running" in dirscanstatus:
            dirscanstatus1 = dirscanstatus
            dirscanstatus2 = ""
        else:
            dirscanstatus1 = ""
            dirscanstatus2 = dirscanstatus

        weblogicstatus = os.popen('bash /TIP/info_scan/finger.sh weblogic_status').read()
        if "running" in weblogicstatus:
            weblogicstatus1 = weblogicstatus
            weblogicstatus2 = ""
        else:
            weblogicstatus1 = ""
            weblogicstatus2 = weblogicstatus

        struts2status = os.popen('bash /TIP/info_scan/finger.sh struts2_status').read()
        if "running" in struts2status:
            struts2status1 = struts2status
            struts2status2 = ""
        else:
            struts2status1 = ""
            struts2status2 = struts2status

        bbscanstatus = os.popen('bash /TIP/info_scan/finger.sh bbscan_status').read()
        if "running" in bbscanstatus:
            bbscanstatus1 = bbscanstatus
            bbscanstatus2 = ""
        else:
            bbscanstatus1 = ""
            bbscanstatus2 = bbscanstatus

        vulmapscanstatus = os.popen('bash /TIP/info_scan/finger.sh vulmapscan_status').read()
        if "running" in vulmapscanstatus:
            vulmapscanstatus1 = vulmapscanstatus
            vulmapscanstatus2 = ""
        else:
            vulmapscanstatus1 = ""
            vulmapscanstatus2 = vulmapscanstatus

        afrogscanstatus = os.popen('bash /TIP/info_scan/finger.sh afrogscan_status').read()
        if "running" in afrogscanstatus:
            afrogscanstatus1 = afrogscanstatus
            afrogscanstatus2 = ""
        else:
            afrogscanstatus1 = ""
            afrogscanstatus2 = afrogscanstatus

        fscanstatus = os.popen('bash /TIP/info_scan/finger.sh fscan_status').read()
        if "running" in fscanstatus:
            fscanstatus1 = fscanstatus
            fscanstatus2 = ""
        else:
            fscanstatus1 = ""
            fscanstatus2 = fscanstatus

        shirostatus = os.popen('bash /TIP/info_scan/finger.sh shiro_status').read()
        if "running" in shirostatus:
            shirostatus1 = shirostatus
            shirostatus2 = ""
        else:
            shirostatus1 = ""
            shirostatus2 = shirostatus

        eholestatus = os.popen('bash /TIP/info_scan/finger.sh ehole_status').read()
        if "running" in eholestatus:
            eholestatus1 = eholestatus
            eholestatus2 = ""
        else:
            eholestatus1 = ""
            eholestatus2 = eholestatus

        httpxstatus = os.popen('bash /TIP/info_scan/finger.sh httpx_status').read()
        if "running" in httpxstatus:
            httpxstatus1 = httpxstatus
            httpxstatus2 = ""
        else:
            httpxstatus1 = ""
            httpxstatus2 = httpxstatus

        springbootstatus = os.popen('bash /TIP/info_scan/finger.sh springboot_scan_status').read()
        if "running" in springbootstatus:
            springbootstatus1 = springbootstatus
            springbootstatus2 = ""
        else:
            springbootstatus1 = ""
            springbootstatus2 = springbootstatus

        hydrastatus = os.popen('bash /TIP/info_scan/finger.sh hydra_status').read()
        if "running" in hydrastatus:
            hydrastatus1 = hydrastatus
            hydrastatus2 = ""
        else:
            hydrastatus1 = ""
            hydrastatus2 = hydrastatus

        urlfinderstatus = os.popen('bash /TIP/info_scan/finger.sh urlfinder_status').read()
        if "running" in urlfinderstatus:
            urlfinderstatus1 = urlfinderstatus
            urlfinderstatus2 = ""
        else:
            urlfinderstatus1 = ""
            urlfinderstatus2 = urlfinderstatus

        thinkphpstatus = os.popen('bash /TIP/info_scan/finger.sh TPscan_status').read()
        if "running" in thinkphpstatus:
            thinkphpstatus1 = thinkphpstatus
            thinkphpstatus2 = ""
        else:
            thinkphpstatus1 = ""
            thinkphpstatus2 = thinkphpstatus


        jndi_status = os.popen('bash /TIP/info_scan/finger.sh jndi_server_status').read()
        if "running" in jndi_status:
            jndi_status1 = jndi_status
            jndi_status2 = ""
        else:
            jndi_status1 = ""
            jndi_status2 = jndi_status

        jndi_python_status = os.popen('bash /TIP/info_scan/finger.sh jndi_python_server_status').read()
        if "running" in jndi_python_status:
            jndi_python_status1 = jndi_python_status
            jndi_python_status2 = ""
        else:
            jndi_python_status1 = ""
            jndi_python_status2 = jndi_python_status
        

        # 目标url行数
        url_file_num = os.popen('bash /TIP/info_scan/finger.sh url_file_num').read()

        # 重点资产数量查询
       
        shiro_num = basic.key_point_assets_num(Shiro_rule)
        springboot_num = basic.key_point_assets_num(SpringBoot_rule)
        weblogic_num = basic.key_point_assets_num(weblogic_rule)
        baota_num = basic.key_point_assets_num(baota_rule)
        ruoyi_num = basic.key_point_assets_num(ruoyi_rule)
        struts2_num = basic.key_point_assets_num(struts2_rule)
        WordPress_num = basic.key_point_assets_num(WordPress_rule)
        jboss_num = basic.key_point_assets_num(jboss_rule)
        phpmyadmin_num = basic.key_point_assets_num(phpMyAdmin_rule)
        ThinkPHP_num = basic.key_point_assets_num(ThinkPHP_rule)
        nacos_num = basic.key_point_assets_num(nacos_rule)
        fanwei_num = basic.key_point_assets_num(fanwei_rule)
        tomcat_num = basic.key_point_assets_num(tomcat_rule)

        # cpu占用率
        cpu_percent = psutil.cpu_percent(interval=1)

        # 获取内存信息  
        mem = psutil.virtual_memory()  
        # 计算内存占用百分比  
        memory_percent = mem.percent  

        # 资产规则
        if int(rule_options) == 1:
            key_asset_rule = str(finger_list)
            if len(finger_list) == 0:
                key_asset_rule = ['规则为空']
            key_asset_rule_origin = '数据来源: 配置文件'
        elif int(rule_options) == 2:
            key_asset_rule = select_rule()
            if len(key_asset_rule) == 0:
                key_asset_rule = ['规则为空']
            key_asset_rule_origin = '数据来源: MySQL数据库'
        else:
            key_asset_rule = ['参数只能为0/1']

        # 当前自查数量
        url_file_current_num = os.popen('bash /TIP/info_scan/finger.sh current_url_file_num').read()

        # 筛选后资产状态查询
        assets_status = basic.assets_status_show()

        # 漏洞扫描器时间线查询
        vuln_scan_status_shijianxian = basic.vuln_scan_status_show()

        # 磁盘读速率
        disk_read = basic.disk_read_write()[0]
        # 磁盘写速率
        disk_write = basic.disk_read_write()[1]

        # python后端服务状态
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

        otx_status = os.popen('bash /TIP/info_scan/finger.sh otx_domain_url_shell_status').read()
        if "running" in otx_status:
            otx_status1 = otx_status
            otx_status2 = ""
        else:
            otx_status1 = ""
            otx_status2 = otx_status

        crt_status = os.popen('bash /TIP/info_scan/finger.sh crt_subdomain_shell_status').read()
        if "running" in crt_status:
            crt_status1 = crt_status
            crt_status2 = ""
        else:
            crt_status1 = ""
            crt_status2 = crt_status

        weaver_status = os.popen('bash /TIP/info_scan/finger.sh weaver_status').read()
        if "running" in weaver_status:
            weaver_status1 = weaver_status
            weaver_status2 = ""
        else:
            weaver_status1 = ""
            weaver_status2 = weaver_status

        es_unauthorized_status = os.popen('bash /TIP/info_scan/finger.sh es_unauthorized_status').read()
        if "running" in es_unauthorized_status:
            es_unauthorized_status1 = es_unauthorized_status
            es_unauthorized_status2 = ""
        else:
            es_unauthorized_status1 = ""
            es_unauthorized_status2 = es_unauthorized_status

        nacos_status = os.popen('bash /TIP/info_scan/finger.sh nacos_vuln_scan_status').read()
        if "running" in nacos_status:
            nacos_status1 = nacos_status
            nacos_status2 = ""
        else:
            nacos_status1 = ""
            nacos_status2 = nacos_status
        
        tomcat_status = os.popen('bash /TIP/info_scan/finger.sh tomcat_vuln_scan_status').read()
        if "running" in tomcat_status:
            tomcat_status1 = tomcat_status
            tomcat_status2 = ""
        else:
            tomcat_status1 = ""
            tomcat_status2 = tomcat_status

        fastjson_status = os.popen('bash /TIP/info_scan/finger.sh fastjson_scan_status').read()
        if "running" in fastjson_status:
            fastjson_status1 = fastjson_status
            fastjson_status2 = ""
        else:
            fastjson_status1 = ""
            fastjson_status2 = fastjson_status

        waf_status = os.popen('bash /TIP/info_scan/finger.sh waf_scan_status').read()
        if "running" in waf_status:
            waf_status1 = waf_status
            waf_status2 = ""
        else:
            waf_status1 = ""
            waf_status2 = waf_status
        
        bypass_status = os.popen('bash /TIP/info_scan/finger.sh bypassstatus').read()
        if "running" in bypass_status:
            bypass_status1 = bypass_status
            bypass_status2 = ""
        else:
            bypass_status1 = ""
            bypass_status2 = bypass_status
        
        crawlergo_status = os.popen('bash /TIP/info_scan/finger.sh crawlergo_status').read()
        if "running" in crawlergo_status:
            crawlergo_status1 = crawlergo_status
            crawlergo_status2 = ""
        else:
            crawlergo_status1 = ""
            crawlergo_status2 = crawlergo_status


        message_json = {
            "nmapstatus1":nmapstatus1,
            "nmapstatus2":nmapstatus2,
            "nucleistatus1":nucleistatus1,
            "nucleistatus2":nucleistatus2,
            "xraystatus1":xraystatus1,
            "xraystatus2":xraystatus2,
            "radstatus1":radstatus1,
            "radstatus2":radstatus2,
            "dirscanstatus1":dirscanstatus1,
            "dirscanstatus2":dirscanstatus2,
            "weblogicstatus1":weblogicstatus1,
            "weblogicstatus2":weblogicstatus2,
            "struts2status1":struts2status1,
            "struts2status2":struts2status2,
            "bbscanstatus1":bbscanstatus1,
            "bbscanstatus2":bbscanstatus2,
            "vulmapscanstatus1":vulmapscanstatus1,
            "vulmapscanstatus2":vulmapscanstatus2,
            "afrogscanstatus1":afrogscanstatus1,
            "afrogscanstatus2":afrogscanstatus2,
            "fscanstatus1":fscanstatus1,
            "fscanstatus2":fscanstatus2,
            "shirostatus1":shirostatus1,
            "shirostatus2":shirostatus2,
            "httpxstatus1":httpxstatus1,
            "httpxstatus2":httpxstatus2,
            "url_file_num":url_file_num,
            "eholestatus1":eholestatus1,
            "eholestatus2":eholestatus2,
            "shiro_num":str(shiro_num),
            "springboot_num":str(springboot_num),
            "weblogic_num":str(weblogic_num),
            "baota_num":str(baota_num),
            "ruoyi_num":str(ruoyi_num),
            "struts2_num":str(struts2_num),
            "WordPress_num":str(WordPress_num),
            "cpuinfo":str(cpu_percent)+"%",
            "memoryinfo":str(memory_percent)+"%",
            "jboss_num":str(jboss_num),
            "phpmyadmin_num":str(phpmyadmin_num),
            "key_asset_rule":str(key_asset_rule),
            "current_key_asset_num":str(url_file_current_num),
            "springbootstatus1":springbootstatus1,
            "springbootstatus2":springbootstatus2,
            "hydrastatus1":hydrastatus1,
            "hydrastatus2":hydrastatus2,
            "urlfinderstatus1":urlfinderstatus1,
            "urlfinderstatus2":urlfinderstatus2,
            "key_asset_rule_origin":key_asset_rule_origin,
            "assets_status":"原始资产-------->"+assets_status,
            "vuln_scan_status_shijianxian":vuln_scan_status_shijianxian,
            "disk_read":str(disk_read)+" KB/s",
            "disk_write":str(disk_write)+" KB/s",
            "infoinfostatus1":infoinfostatus1,
            "infoinfostatus2":infoinfostatus2,
            "dirsub_sys_status1":dirsub_sys_status1,
            "dirsub_sys_status2":dirsub_sys_status2,
            "xray_report_status1":xray_report_status1,
            "xray_report_status2":xray_report_status2,
            "urlfinder_report_status1":urlfinder_report_status1,
            "urlfinder_report_status2":urlfinder_report_status2,
            "afrog_report_status1":afrog_report_status1,
            "afrog_report_status2":afrog_report_status2,
            "ThinkPHP_num":ThinkPHP_num,
            "tomcat_num":tomcat_num,
            "thinkphpstatus1":thinkphpstatus1,
            "thinkphpstatus2":thinkphpstatus2,
            "otx_status1":otx_status1,
            "otx_status2":otx_status2,
            "crt_status1":crt_status1,
            "crt_status2":crt_status2,
            "nacos_num":str(nacos_num),
            "fanwei_num":str(fanwei_num),
            "weaver_status1":weaver_status1,
            "weaver_status2":weaver_status2,
            "es_unauthorized_status1":es_unauthorized_status1,
            "es_unauthorized_status2":es_unauthorized_status2,
            "nacos_status1":nacos_status1,
            "nacos_status2":nacos_status2,
            "tomcat_status1":tomcat_status1,
            "tomcat_status2":tomcat_status2,
            "jndi_status1":jndi_status1,
            "jndi_status2":jndi_status2,
            "jndi_python_status1":jndi_python_status1,
            "jndi_python_status2":jndi_python_status2,
            "fastjson_status1":fastjson_status1,
            "fastjson_status2":fastjson_status2,
            "waf_status1":waf_status1,
            "waf_status2":waf_status2,
            "bypass_status1":bypass_status1,
            "bypass_status2":bypass_status2,
            "crawlergo_status1":crawlergo_status1,
            "crawlergo_status2":crawlergo_status2

        }
        return jsonify(message_json)
    else:
        return render_template('login.html')

    


#文本框内容展示
@app.route("/textareashowinterface/")
def textareashowinterface():
    user = session.get('username')
    if str(user) == main_username:
        result_list = []
        file = open("/TIP/batch_scan_domain/url.txt",encoding='utf-8')
        for line in file.readlines():
            result_list.append(line.strip())
        url_num = os.popen('bash /TIP/info_scan/finger.sh textarea_url_num').read()
        message_json = {
            "textvalue":result_list,
            "url_num":"总共查出"+str(url_num)+"条数据"
        }
        return jsonify(message_json)
    else:
        return render_template('login.html')


#资产去重
@app.route("/uniqdirsearchtargetinterface/",methods=['POST'])
def uniqdirsearchtargetinterface():
    user = session.get('username')
    if str(user) == main_username:
        # 筛选后资产时间线更新
        basic.assets_status_update('资产去重已完成')
        fileqingxiname = request.form['fileqingxiname']
        if int(fileqingxiname) == 1:
            
            #文件去重，保留IP地址
            os.popen('bash /TIP/info_scan/finger.sh withdrawip')
            return render_template('dirsearchscan.html')
        else:
            
            #文件去重，保留所有
            os.popen('bash /TIP/info_scan/finger.sh uniqfilterdirsearch')
    
            return render_template('dirsearchscan.html')
    else:
        return render_template('login.html')


#存活检测接口
@app.route("/filterstatuscodebyhttpx/",methods=['GET'])
def filterstatuscodebyhttpx():
    user = session.get('username')
    if str(user) == main_username:
        # 筛选后资产时间线更新
        basic.assets_status_update('存活检测已完成')
        httpx_status_result = basic.httpsurvival_lib()
        message_json = {
            "httpx_status_result":httpx_status_result
        }
        return jsonify(message_json)
    else:
        return render_template('login.html')

#链接扫描
@app.route("/starturlfinderinterface/",methods=['GET'])
def starturlfinderinterface():
    user = session.get('username')
    if str(user) == main_username:
        # 漏洞扫描器时间线更新
        basic.vuln_scan_status_update('已完成urlfinder链接扫描')
        urlfinder_status_result = basic.starturlfinder_lib()

        message_json = {
            "urlfinder_status_result":urlfinder_status_result
        }
        return jsonify(message_json)
    
    else:
        return render_template('login.html')


#清空链接扫描报告
@app.route("/deleteurlfinderreport/")
def deleteurlfinderreport():
    user = session.get('username')
    if str(user) == main_username:
        try:
            os.popen('rm -rf /TIP/info_scan/urlfinder_server/report/*')
        except Exception as e:
            print("捕获到异常:",e)
        return render_template('index.html')
    else:
        return render_template('login.html')



#关闭urlfinder进程
@app.route("/killurlfinderprocess/")
def killurlfinderprocess():
    user = session.get('username')
    if str(user) == main_username:
        kill_urlfinder_result = basic.stopurlfinder_lib()
        message_json = {
            "kill_urlfinder_result":kill_urlfinder_result
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


#cdn探测，将存在cdn和不存在cdn的域名分别存入不同列表中，用于过滤基础数据
# date:2024.4.3
@app.route('/cdn_service_recogize/',methods=['get'])
def cdn_service_recogize():
    user = session.get('username')
    if str(user) == main_username:
        # 筛选后资产时间线更新
        basic.assets_status_update('CDN检测已完成')    
        try:
            #遍历目标文件存入列表
            url_file = open("/TIP/batch_scan_domain/url.txt",encoding='utf-8')
            url_list = []
            for i in url_file.readlines():
                url_list.append(i)
            # url中提取域名存列表
            domain_list = []
            for j in url_list:

                domain_re = re.findall("https?://([^/]+)",j)
                domain_list.append(domain_re)

            # url中提取域名并删除掉长度为0的列表
            domain_list_result = []
            for k in domain_list:
                if len(k) > 0:
                    domain_list_result.append(k[0])
            
            # 存在cdn列表
            rule_cdn_domain_list = []
            # 不存在cdn列表
            rule_nocdn_domain_list = []
            for domain in domain_list_result:
                cdn_result = os.popen('bash /TIP/info_scan/finger.sh batch_cdn_scan'+' '+domain).read().strip() 
                
                cdn_result_origin = "有CDN"
                if str(cdn_result) == str(cdn_result_origin):
                    rule_cdn_domain_list.append(domain)
                else:
                    rule_nocdn_domain_list.append(domain)
            
            # 不存在cdn列表
            no_cdn_list_result = []
            for nocdn in rule_nocdn_domain_list:
                nocdnresult = os.popen('bash /TIP/info_scan/finger.sh recognize_no_cdn'+' '+nocdn).read().strip()
                no_cdn_list_result.append(nocdnresult)
            #列表写入到url.txt
            f = open(file='/TIP/batch_scan_domain/url.txt',mode='w')
            for fileline in no_cdn_list_result:
                f.write(str(fileline)+"\n")

        except Exception as e:
            print("捕获到异常:",e)
    return render_template('login.html')


#资产回退
@app.route("/assetsbackspaceinterface/")
def assetsbackspaceinterface():
    user = session.get('username')
    if str(user) == main_username:
        # 筛选后资产时间线更新
        basic.assets_status_update('资产回退已完成')
        os.popen('cp /TIP/batch_scan_domain/url_back.txt /TIP/batch_scan_domain/url.txt')
        return render_template('index.html')
    else:
        return render_template('login.html')
    

#weblogic_poc扫描
@app.route("/weblogicscaninterface/",methods=['get'])
def weblogicscaninterface():
    user = session.get('username')
    if str(user) == main_username:
        # 漏洞扫描器时间线更新
        basic.vuln_scan_status_update('已完成weblogic漏洞扫描')
        weblogic_status_result = basic.startweblogic_lib()
        message_json = {
            "weblogic_status_result":weblogic_status_result
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
        if int(weblogic_num) ==0:
            lines = ["暂无数据"]
        else:
            lines = []
            with open('./result/weblogic_poc.txt', 'r') as f:
                for line in f:
                    lines.append(line.strip())
        return '<br>'.join(lines)
    else:
        return render_template('login.html')


#关闭weblogic漏洞扫描程序
@app.route("/stop_weblogic_poc_scan/")
def stop_weblogic_poc_scan():
    user = session.get('username')
    if str(user) == main_username:
        kill_weblogic_result = basic.stopweblogic_lib()

        message_json = {
            "kill_weblogic_result":kill_weblogic_result
        }

        return jsonify(message_json)
    else:
        return render_template('login.html')
    

# 开启struts2漏洞扫描程序
@app.route("/struts2_poc_scan/")
def struts2_poc_scan():
    user = session.get('username')
    if str(user) == main_username:
        # 漏洞扫描器时间线更新
        basic.vuln_scan_status_update('已完成struts2漏洞扫描')
        struts2status_result = basic.startstruts2_lib()
        message_json = {
            "struts2status_result":struts2status_result
        }
        return jsonify(message_json)
    else:
        return render_template('login.html')
    


#struts2漏洞扫描结果预览
@app.route("/struts2_poc_report/")
def struts2_poc_report():
    user = session.get('username')
    if str(user) == main_username:
        struts2_num = os.popen('bash /TIP/info_scan/finger.sh struts2_scan_num').read()
        if int(struts2_num) ==0:
            lines = ["暂无数据"]
        else:
            lines = []
            with open('./result/struts2_poc.txt', 'r') as f:
                for line in f:
                    lines.append(line.strip())
        return '<br>'.join(lines)
    else:
        return render_template('login.html')
    

#关闭struts2漏洞扫描程序
@app.route("/stop_struts2_poc_scan/")
def stop_struts2_poc_scan():
    user = session.get('username')
    if str(user) == main_username:
        kill_struts2_result = basic.stopstruts2_lib()
        message_json = {
            "kill_struts2_result":kill_struts2_result
        }

        return jsonify(message_json)
    else:
        return render_template('login.html')

# 报告整合
@app.route("/report_total_interface/")
def report_total_interface():
    user = session.get('username')
    if str(user) == main_username:
        # 执行报告整合脚本
        report_total.report_xlsx()
        return render_template('index.html')
    else:
        return render_template('login.html')

    

#ehole_finger扫描结果预览
@app.route("/ehole_finger_report/")
def ehole_finger_report():
    user = session.get('username')
    if str(user) == main_username:
        ehole_num = os.popen('bash /TIP/info_scan/finger.sh ehole_finger_num').read()
        if int(ehole_num) == 0:
            lines = ["暂无数据"]
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
    
# 启动EHole
@app.route("/ehole_finger_scan/")
def ehole_finger_scan():
    user = session.get('username')
    if str(user) == main_username:
        # 漏洞扫描器时间线更新
        basic.vuln_scan_status_update('已完成ehole指纹识别扫描')
        finger_status_result = basic.startechole_lib()
        message_json = {
            "finger_status_result":finger_status_result
        }

        return jsonify(message_json)
    else:
        return render_template('login.html')
    

# bbscan_info_scan扫描
@app.route("/bbscan_info_scan/")
def bbscan_info_scan():
    user = session.get('username')
    if str(user) == main_username:
        # 漏洞扫描器时间线更新
        basic.vuln_scan_status_update('已完成bbscan敏感信息扫描')
        bbscan_status_result = basic.startbbscan_lib()
        message_json = {
            "bbscan_status_result":bbscan_status_result
        }
        return jsonify(message_json)
    
    else:
        return render_template('login.html')


#bbscan扫描预览报告
@app.route("/showbbscanreport/")
def showbbscanreport():
    user = session.get('username')
    if str(user) == main_username:
        bbscan_num = os.popen('bash /TIP/info_scan/finger.sh bbscan_scan_num').read()
        if int(bbscan_num) == 0:
            lines = ["暂无数据"]
        else:
            lines = []
            with open('/TIP/info_scan/result/bbscan_info.txt', 'r') as f:
                for line in f:
                    lines.append(line.strip())
        return '<br>'.join(lines)
    else:
        return render_template('login.html')
    

#通过证书批量查询目标子域名
@app.route("/batch_show_subdomain/",methods=['get'])
def batch_show_subdomain():
    user = session.get('username')
    if str(user) == main_username:
        # 漏洞扫描器时间线更新
        basic.vuln_scan_status_update('已完成子域名扫描')
        crt_status_result = basic.crtdomain_lib()
        message_json = {
            "crt_status_result":crt_status_result
        }
        return jsonify(message_json)
    else:
        return render_template('login.html')
    

#子域名预览报告
@app.route("/showsubdomainreport/")
def showsubdomainreport():
    user = session.get('username')
    if str(user) == main_username:
        subdomain_num = os.popen('bash /TIP/info_scan/finger.sh subdomain_scan_num').read()
        if int(subdomain_num) == 0:
            lines = ["暂无数据"]
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
        if int(vulmap_num) == 0:
            liness = ["暂无数据"]
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



#启动vulmap漏扫程序
@app.route("/startvulmapinterface/",methods=['POST'])
def startvulmapinterface():
    user = session.get('username')
    if str(user) == main_username:
        # 漏洞扫描器时间线更新
        basic.vuln_scan_status_update('已完成vulmap漏洞扫描')
        vulnname = request.form['vulnname']
        vummap_scan_result = basic.startvulmap_lib(vulnname)

        message_json = {
            "vummap_scan_result":vummap_scan_result
        }
        return jsonify(message_json)

    else:
        return render_template('login.html')


#结束vulmap进程
@app.route("/killvulmapprocess/")
def killvulmapprocess():
    user = session.get('username')
    if str(user) == main_username:
        kill_vulmap_result = basic.stopvulmap_lib()
        message_json = {
            "kill_vulmap_result":kill_vulmap_result
        }

        return jsonify(message_json)
    else:
        return render_template('login.html')
    



#启动nmap批量端口扫描
@app.route("/startbatchnmapscan/",methods=['get'])
def startbatchnmapscan():
    user = session.get('username')
    if str(user) == main_username:
        # 漏洞扫描器时间线更新
        basic.vuln_scan_status_update('已完成nmap端口扫描')
        nmap_status_result = basic.startnmap_lib()
        message_json = {
            "nmap_status_result":nmap_status_result
        }
        return jsonify(message_json)

        
    else:
        return render_template('login.html')
    


#目标url文件存入列表回显给前端
@app.route("/url_list_textarea_show/")
def url_list_textarea_show():
    user = session.get('username')
    if str(user) == main_username:
        textvalue = basic.url_file_ip_list()
        message_json = {
            "textvalue":textvalue
        }
        return jsonify(message_json)
    else:
        return render_template('login.html')


#ceye_dns记录
@app.route("/ceye_dns_record/")
def ceye_dns_record():
    user = session.get('username')
    if str(user) == main_username:
        result = os.popen('bash /TIP/info_scan/finger.sh ceye_dns'+' '+ceye_key).read()
        return result
    else:
        return render_template('login.html')



#ceye_http记录
@app.route("/ceye_http_record/")
def ceye_http_record():
    user = session.get('username')
    if str(user) == main_username:
        result = os.popen('bash /TIP/info_scan/finger.sh ceye_http'+' '+ceye_key).read()
        return result
    else:
        return render_template('login.html')
    

#清空afrog报告
@app.route("/deleteafrogreport/")
def deleteafrogreport():
    user = session.get('username')
    if str(user) == main_username:
        os.popen('rm -rf /TIP/info_scan/afrog_scan/reports/*')
        return render_template('index.html')
    else:
        return render_template('login.html')


#启动afrog漏扫程序
@app.route("/startafrogscanprocess/",methods=['get'])
def startafrogscanprocess():
    user = session.get('username')
    if str(user) == main_username:
        # 漏洞扫描器时间线更新
        basic.vuln_scan_status_update('已完成afrog漏洞扫描')
        start_afrog_result = basic.startafrog_lib()
        message_json = {
            "start_afrog_result":start_afrog_result
        }

        return jsonify(message_json)
    else:
        return render_template('login.html')


#关闭afrog漏洞扫描程序
@app.route("/killafrogprocess/")
def killafrogprocess():
    user = session.get('username')
    if str(user) == main_username:
        kill_afrog_result = basic.stopafrog_lib()

        message_json = {
            "kill_afrog_result":kill_afrog_result
        }

        return jsonify(message_json)
    else:
        return render_template('login.html')
    


#关闭nmap进程
@app.route("/killnmapprocess/")
def killnmapprocess():
    user = session.get('username')
    if str(user) == main_username:
        kill_nmap_result = basic.stopnmap_lib()
        message_json = {
            "kill_nmap_result":kill_nmap_result
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
        if int(fscan_num) ==0:
            lines = ["暂无数据"]
        else:
            lines = []
            with open('./result/fscan_vuln.txt', 'r') as f:
                for line in f:
                    lines.append(line.strip())
        return '<br>'.join(lines)
    else:
        return render_template('login.html')


#启动fscan程序
@app.route("/startfcsaninterface/",methods=['POST'])
def startfcsaninterface():
    user = session.get('username')
    if str(user) == main_username:
        fscanpartname = request.form['fscanpartname']
        # 漏洞扫描器时间线更新
        basic.vuln_scan_status_update('已完成fscan漏洞扫描')
        fscan_status_result = basic.startfscan_lib(fscanpartname)
        message_json = {
            "fscan_status_result":fscan_status_result
        }
        return jsonify(message_json)
    else:
        return render_template('login.html')
    

#结束fscan进程
@app.route("/killfscangprocess/")
def killfscangprocess():
    user = session.get('username')
    if str(user) == main_username:
        kill_fscan_result = basic.stopfscan_lib()
        message_json = {
            "kill_fscan_result":kill_fscan_result
        }

        return jsonify(message_json)
        
    else:
        return render_template('login.html')



#shiro报告预览
@app.route("/shiro_report_show/")
def shiro_report_show():
    user = session.get('username')
    if str(user) == main_username:
        shiro_num = os.popen('bash /TIP/info_scan/finger.sh shiro_scan_num').read()
        if int(shiro_num) ==0:
            filtered_list_new = ["暂无数据"]
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


#启动shiro程序
@app.route("/startshirointerface/")
def startshirointerface():
    user = session.get('username')
    if str(user) == main_username:
        # 漏洞扫描器时间线更新
        basic.vuln_scan_status_update('已完成shiro漏洞扫描')
        shiro_status_result = basic.startshiro_lib()
        message_json = {
            "shiro_status_result":shiro_status_result
        }

        return jsonify(message_json)
    else:
        return render_template('login.html')



#关闭shiro漏洞扫描程序
@app.route("/stop_shiro_poc_scan/")
def stop_shiro_poc_scan():
    user = session.get('username')
    if str(user) == main_username:
        kill_shiro_result = basic.stopshiro_lib()

        message_json = {
            "kill_shiro_result":kill_shiro_result
        }

        return jsonify(message_json)
    else:
        return render_template('login.html')
    
    

#识别重点资产
@app.route("/key_assets_withdraw/")
def key_assets_withdraw():
    user = session.get('username')
    if str(user) == main_username:

        
        eholestatus = os.popen('bash /TIP/info_scan/finger.sh ehole_status').read()
        if "running" in eholestatus:
            key_assets_result = "指纹识别接口正在运行中请稍后再进行识别重点资产"
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

            key_assets_result = "已成功识别出重点资产"
            # 筛选后资产时间线更新
            basic.assets_status_update('识别重点资产已完成')
        
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
        if int(springboot_num) == 0:
            lines = ["暂无数据"]
        else:
            lines = []
            with open('./result/springboot_result.txt', 'r') as f:
                for line in f:
                    lines.append(line.strip())
        return '<br>'.join(lines)
    else:
        return render_template('login.html')



#启动springboot漏洞扫描程序
@app.route("/start_springboot_vuln_scan/")
def start_springboot_vuln_scan():
    user = session.get('username')
    if str(user) == main_username:
        # 漏洞扫描器时间线更新
        basic.vuln_scan_status_update('已完成springboot漏洞扫描')
        springboot_scan_status_result = basic.startspringboot_lib()
        
        message_json = {
            "springboot_scan_status_result":springboot_scan_status_result
        }

        return jsonify(message_json)
    else:
        return render_template('login.html')



#关闭spring_boot漏洞扫描程序
@app.route("/stop_springboot_poc_scan/")
def stop_springboot_poc_scan():
    user = session.get('username')
    if str(user) == main_username:
        kill_springboot_result = basic.stopspringboot_lib()

        message_json = {
            "kill_springboot_result":kill_springboot_result
        }
        
        return jsonify(message_json)
    else:
        return render_template('login.html')


# 通过fofa发现资产
@app.route("/fofa_search_assets_service/",methods=['POST'])
def fofa_search_assets_service():
    user = session.get('username')
    if str(user) == main_username:
        # 筛选后资产时间线更新
        basic.assets_status_update('通过fofa平台获取资产完成')

        part = request.form['part']
        num_fofa = request.form['num_fofa']
        if '' in  part:
            asset_len_list = "输入参数不能为空"

        if ' ' in part:
            asset_len_list = "输入参数不能包含空格"

        if 'alert' in part or 'select' in part or '<' in part or '>' in part or 'union' in part:
            asset_len_list = "请勿进行安全测试！"
        else:
            asset_len_list_1 = basic.fofa_search_assets_service_lib(part,num_fofa)
            asset_len_list = "总共发现"+" "+str(asset_len_list_1)+" "+"条资产已存入扫描目标中"
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
        if int(hydra_num) == 0:
            lines = ["暂无数据"]
        else:
            lines = []
            with open('./result/hydra_result.txt', 'r') as f:
                for line in f:
                    lines.append(line.strip())
        return '<br>'.join(lines)
    else:
        return render_template('login.html')
    


# 启动hydra弱口令扫描工具
@app.route("/start_hydra_interface/",methods=['POST'])
def start_hydra_interface():
    user = session.get('username')
    if str(user) == main_username:
        # 漏洞扫描器时间线更新
        basic.vuln_scan_status_update('已完成hydra弱口令扫描')
        hydrapart = request.form['hydrapart']
        hydra_scan_result = basic.starthydra_lib(hydrapart)

        message_json = {
            "hydra_scan_result":hydra_scan_result
        }

        return jsonify(message_json)
    else:
        return render_template('login.html')

    

#关闭hydra进程
@app.route("/killhydraprocess/")
def killhydraprocess():
    user = session.get('username')
    if str(user) == main_username:
        kill_hydra_result = basic.stophydra_lib()
        message_json = {
            "kill_hydra_result":kill_hydra_result
        }

        return jsonify(message_json)
    
    else:
        return render_template('login.html')


    

#关闭EHole进程
@app.route("/killEHoleprocess/")
def killEHoleprocess():
    user = session.get('username')
    if str(user) == main_username:
        kill_EHole_result = basic.stopehole_lib()
        message_json = {
            "kill_EHole_result":kill_EHole_result
        }

        return jsonify(message_json)
    
    else:
        return render_template('login.html')
    

# 报告预览
@app.route('/totalreportyulan/')
def totalreportyulan():
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


#前端软重启系统服务
@app.route("/restartsystemservice/")
def restartsystemservice():
    user = session.get('username')
    if str(user) == main_username:
        os.popen('bash /TIP/info_scan/finger.sh restartinfoscan')
        infoscanstatus = os.popen('bash /TIP/info_scan/finger.sh infoscanstatus').read()
        if "running" in infoscanstatus:
            infoscanstatus = "服务已启动"
        else:
            infoscanstatus = "正在重启中..."
        message_json = {
            "infoscanstatus":infoscanstatus,
            "comfirm":"确定重新启动服务吗?"
        }

        return jsonify(message_json)
    
    else:
        return render_template('login.html')



# 关闭后端所有服务
@app.route("/stopbackserviceinterface/")
def stopbackserviceinterface():
    user = session.get('username')
    if str(user) == main_username:

        message_json = {
            "backcomfirm":"确定关闭所有后端服务吗?请谨慎操作，重启需登录服务器后台操作！"
        }

        return jsonify(message_json)
    
    else:
        return render_template('login.html')
    
# 确认关闭后端所有服务
@app.route("/confirm_stop_service/",methods=['post'])
def confirm_stop_service():
    user = session.get('username')
    if str(user) == main_username:
        action = request.form['action']
        if action == '1':
            os.popen('bash /TIP/info_scan/finger.sh stopallserver')
            result_status = "关闭后端服务指令已开启"
        else:
            result_status = "关闭后端服务指令已取消"

        message_json = {
            "result_status":result_status
        }

        return jsonify(message_json)
    
    else:
        return render_template('login.html')

    

# 识别重点资产中新增筛选规则接口
@app.route("/add_point_rule_interface/",methods=['post'])
def add_point_rule_interface():
    user = session.get('username')

    if str(user) == main_username:
        rule = request.form['rule']
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
            
            # 判断数据库中是否存在传入的数据
            sql_select = "select rule FROM rule_table where rule = '%s' "%(rule)
            cur.execute(sql_select)
            result = cur.fetchone()
            if result:
                result_rule = rule+" "+"规则已存在不要重复添加"
            else:
                sql_insert = "insert into rule_table(rule)  values('%s')" %(rule)
                cur.execute(sql_insert)  
                db.commit()
                result_rule = rule+" "+"规则已添加成功"
        message_json = {
            "result_rule":result_rule
        }

        return jsonify(message_json)
    
    else:
        return render_template('login.html')


# 重点资产识别根据筛选规则名称删除
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




#启动tpscan程序
@app.route("/starttpscaninterface/")
def starttpscaninterface():
    user = session.get('username')
    if str(user) == main_username:
        # 漏洞扫描器时间线更新
        basic.vuln_scan_status_update('已完成thinkphp漏洞扫描')
        thinkphp_status_result = basic.startthinkphp_lib()
        message_json = {
            "thinkphp_status_result":thinkphp_status_result
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
        if int(thinkphp_num) == 0:
            lines = ["暂无数据"]
        else:
            lines = []
            with open('/TIP/info_scan/result/thinkphp_vuln.txt', 'r') as f:
                for line in f:
                    lines.append(line.strip())
        return '<br>'.join(lines)
    else:
        return render_template('login.html')



#关闭thinkphp漏洞扫描程序
@app.route("/stop_thinkphp_poc_scan/")
def stop_thinkphp_poc_scan():
    user = session.get('username')
    if str(user) == main_username:
        kill_thinkphp_result = basic.stoptpscan_lib()

        message_json = {
            "kill_thinkphp_result":kill_thinkphp_result
        }
        
        return jsonify(message_json)
    else:
        return render_template('login.html')
    



#开启泛微OA漏洞扫描
@app.route("/startweavervulnscan/",methods=['GET'])
def startweavervulnscan():
    user = session.get('username')
    if str(user) == main_username:
        # 漏洞扫描器时间线更新
        basic.vuln_scan_status_update('已完成泛微OA漏洞扫描')
        weaver_status_result = basic.startweaver_lib()

        message_json = {
            "weaver_status_result":weaver_status_result
        }
        return jsonify(message_json)
    
    else:
        return render_template('login.html')



#泛微扫描结果预览
@app.route("/weaverresultshow/")
def weaverresultshow():
    user = session.get('username')
    if str(user) == main_username:
        os.popen('rm -rf /TIP/info_scan/weaver_exp/*.zip')
        weaver_scan_num = os.popen('bash /TIP/info_scan/finger.sh weaver_scan_num').read()
        if int(weaver_scan_num) == 0:
            liness = ["暂无数据"]
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



#关闭泛微OA漏洞扫描程序
@app.route("/killweavervulnscan/")
def killweavervulnscan():
    user = session.get('username')
    if str(user) == main_username:
        kill_weaver_result = basic.stopweaver_lib()
        message_json = {
            "kill_weaver_result":kill_weaver_result
        }

        return jsonify(message_json)
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
                # 获取系统当前时间
                current_time = time.time()
                # 当前时间和数据库中的作时间差
                diff_time_minutes = basic.info_time_shijian_cha(1)
                
                if int(diff_time_minutes) > info_time_controls:
                    # 超过单位时间更新数据库中的时间
                    basic.last_time_update_lib(current_time,1)
                    # 提交扫描任务
                    bbscan_status_result = basic.startbbscan_lib()
                else:
                    bbscan_status_result = "bbscan扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
                
                
            elif '2' in str(j):
                # 获取系统当前时间
                current_time2 = time.time()
                # 当前时间和数据库中的作时间差
                diff_time_minutes2 = basic.info_time_shijian_cha(2)
                if int(diff_time_minutes2) > info_time_controls:
                    # 超过单位时间更新数据库中的时间
                    basic.last_time_update_lib(current_time2,2)
                    # 提交扫描任务
                    finger_status_result = basic.startechole_lib()
                else:
                    finger_status_result = "EHole扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
            elif '3' in str(j):
                # 获取系统当前时间
                current_time3 = time.time()
                # 当前时间和数据库中的作时间差
                diff_time_minutes3 = basic.info_time_shijian_cha(3)
                if int(diff_time_minutes3) > info_time_controls:
                    # 超过单位时间更新数据库中的时间
                    basic.last_time_update_lib(current_time3,3)
                    # 提交扫描任务
                    otx_status_result = basic.otxhistorydomain_lib()
                else:
                    otx_status_result = "历史URL查询接口"+str(info_time_controls)+"分钟内不允许重复扫描"
            elif '4' in str(j):
                # 获取系统当前时间
                current_time4 = time.time()
                # 当前时间和数据库中的作时间差
                diff_time_minutes4 = basic.info_time_shijian_cha(4)
                if int(diff_time_minutes4) > info_time_controls:
                    # 超过单位时间更新数据库中的时间
                    basic.last_time_update_lib(current_time4,4)
                    # 提交扫描任务
                    crt_status_result = basic.crtdomain_lib()
                else:
                    crt_status_result = "基于证书查询子域名接口"+str(info_time_controls)+"分钟内不允许重复扫描"
            elif '5' in str(j):
                # 获取系统当前时间
                current_time5 = time.time()
                # 当前时间和数据库中的作时间差
                diff_time_minutes5 = basic.info_time_shijian_cha(5)
                if int(diff_time_minutes5) > info_time_controls:
                    # 超过单位时间更新数据库中的时间
                    basic.last_time_update_lib(current_time5,5)
                    # 提交扫描任务
                    # 每次启动前清空上次扫描结果
                    nmap_status_result = basic.startnmap_lib(portscan_part)
                else:
                    nmap_status_result = "nmap端口扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"

            elif '6' in str(j):
                # 获取系统当前时间
                current_time6 = time.time()
                # 当前时间和数据库中的作时间差
                diff_time_minutes6 = basic.info_time_shijian_cha(6)
                if int(diff_time_minutes6) > info_time_controls:
                    # 超过单位时间更新数据库中的时间
                    basic.last_time_update_lib(current_time6,6)
                    # 提交扫描任务
                    # 每次启动前清空上次扫描结果
                    waf_status_result = basic.startwafrecognize_lib()
                else:
                    waf_status_result = "WAF扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
            elif '7' in str(j):
                # 获取系统当前时间
                current_time7 = time.time()
                # 当前时间和数据库中的作时间差
                diff_time_minutes7 = basic.info_time_shijian_cha(7)
                if int(diff_time_minutes7) > info_time_controls:
                    # 超过单位时间更新数据库中的时间
                    basic.last_time_update_lib(current_time7,7)
                    # 提交扫描任务
                    # 每次启动前清空上次扫描结果
                    bypass_status_result = basic.start40xbypass_lib()
                else:
                    bypass_status_result = "FUZZ扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
            elif '8' in str(j):
                # crawlergo_status_result = basic.start_crawlergo_lib(pachongselectpart)
                
                # 获取系统当前时间
                current_time8 = time.time()
                # 当前时间和数据库中的作时间差
                diff_time_minutes8 = basic.info_time_shijian_cha(8)
                if int(diff_time_minutes8) > info_time_controls:
                    # 超过单位时间更新数据库中的时间
                    basic.last_time_update_lib(current_time8,8)
                    # 提交扫描任务
                    # 每次启动前清空上次扫描结果
                    crawlergo_status_result = basic.start_crawlergo_lib(pachongselectpart)
                else:
                    crawlergo_status_result = "爬虫程序"+str(info_time_controls)+"分钟内不允许重复扫描"
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
        
        dict = {
            "key1":bbscan_status_result1,
            "key2":finger_status_result1,
            "key3":otx_status_result1,
            "key4":crt_status_result1,
            "key5":nmap_status_result1,
            "key6":waf_status_result1,
            "key7":bypass_status_result1,
            "key8":crawlergo_status_result1
        }
        message_json = {
            "dictkey1":dict['key1'],
            "dictkey2":dict['key2'],
            "dictkey3":dict['key3'],
            "dictkey4":dict['key4'],
            "dictkey5":dict['key5'],
            "dictkey6":dict['key6'],
            "dictkey7":dict['key7'],
            "dictkey8":dict['key8']
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
        fscanpartname = int(data['fscanpartname'])
        hydrapart = int(data['hydrapart'])
        vulnname = data['vulnname']
        poc_dir = data['poc_dir']
        
        # 遍历列表判断调用哪个扫描器
        for k in vuln_front_list:
            if '1' in str(k):
                print("struts2")
                # 获取系统当前时间
                current_time1 = time.time()
                # 当前时间和数据库中的作时间差
                diff_time_minutes1 = basic.vuln_time_shijian_cha(1)
                if int(diff_time_minutes1) > vuln_time_controls:
                    # 超过单位时间更新数据库中的时间
                    basic.vuln_last_time_update_lib(current_time1,1)
                    # 提交扫描任务
                    struts2status_result = basic.startstruts2_lib()
                else:
                    struts2status_result = "struts2扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"

            elif '2' in str(k):
                print("weblogic")
                # 获取系统当前时间
                current_time2 = time.time()
                # 当前时间和数据库中的作时间差
                diff_time_minutes2 = basic.vuln_time_shijian_cha(2)
                if int(diff_time_minutes2) > vuln_time_controls:
                    # 超过单位时间更新数据库中的时间
                    basic.vuln_last_time_update_lib(current_time2,2)
                    # 提交扫描任务
                    weblogic_status_result = basic.startweblogic_lib()
                else:
                    weblogic_status_result = "weblogic扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"

            elif '3' in str(k):
                print("shiro")
                # 获取系统当前时间
                current_time3 = time.time()
                # 当前时间和数据库中的作时间差
                diff_time_minutes3 = basic.vuln_time_shijian_cha(3)
                if int(diff_time_minutes3) > vuln_time_controls:
                    # 超过单位时间更新数据库中的时间
                    basic.vuln_last_time_update_lib(current_time3,3)
                    # 提交扫描任务
                    shiro_status_result = basic.startshiro_lib()
                    
                else:
                    shiro_status_result = "shiro扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"

            elif '4' in str(k):
                print("springboot")
                # 获取系统当前时间
                current_time4 = time.time()
                # 当前时间和数据库中的作时间差
                diff_time_minutes4 = basic.vuln_time_shijian_cha(4)
                if int(diff_time_minutes4) > vuln_time_controls:
                    # 超过单位时间更新数据库中的时间
                    basic.vuln_last_time_update_lib(current_time4,4)
                    # 提交扫描任务
                    springboot_scan_status_result = basic.startspringboot_lib()
                                
                else:
                    springboot_scan_status_result = "springboot扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
            elif '5' in str(k):
                print("thinkphp")
                # 获取系统当前时间
                current_time5 = time.time()
                # 当前时间和数据库中的作时间差
                diff_time_minutes5 = basic.vuln_time_shijian_cha(5)
                if int(diff_time_minutes5) > vuln_time_controls:
                    # 超过单位时间更新数据库中的时间
                    basic.vuln_last_time_update_lib(current_time5,5)
                    # 提交扫描任务
                    thinkphp_status_result = basic.startthinkphp_lib()
                                
                else:
                    thinkphp_status_result = "thinkphp扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
            elif '6' in str(k):
                print("afrog")
                # 获取系统当前时间
                current_time6 = time.time()
                # 当前时间和数据库中的作时间差
                diff_time_minutes6 = basic.vuln_time_shijian_cha(6)
                if int(diff_time_minutes6) > vuln_time_controls:
                    # 超过单位时间更新数据库中的时间
                    basic.vuln_last_time_update_lib(current_time6,6)
                    # 提交扫描任务
                    start_afrog_result = basic.startafrog_lib()
                                
                else:
                    start_afrog_result = "afrog扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
            elif '7' in str(k):
                print("fscan")
                # 获取系统当前时间
                current_time7 = time.time()
                # 当前时间和数据库中的作时间差
                diff_time_minutes7 = basic.vuln_time_shijian_cha(7)
                if int(diff_time_minutes7) > vuln_time_controls:
                    # 超过单位时间更新数据库中的时间
                    basic.vuln_last_time_update_lib(current_time7,7)
                    # 提交扫描任务
                    fscan_status_result = basic.startfscan_lib(fscanpartname)
                                
                else:
                    fscan_status_result = "fscan扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
            elif '8' in str(k):
                print("弱口令")
                # 获取系统当前时间
                current_time8 = time.time()
                # 当前时间和数据库中的作时间差
                diff_time_minutes8 = basic.vuln_time_shijian_cha(8)
                if int(diff_time_minutes8) > vuln_time_controls:
                    # 超过单位时间更新数据库中的时间
                    basic.vuln_last_time_update_lib(current_time8,8)
                    # 提交扫描任务
                    hydra_scan_result = basic.starthydra_lib(hydrapart)
                                            
                else:
                    hydra_scan_result = "hydra扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
            elif '9' in str(k):
                print("api接口")
                # 获取系统当前时间
                current_time9 = time.time()
                # 当前时间和数据库中的作时间差
                diff_time_minutes9 = basic.vuln_time_shijian_cha(9)
                if int(diff_time_minutes9) > vuln_time_controls:
                    # 超过单位时间更新数据库中的时间
                    basic.vuln_last_time_update_lib(current_time9,9)
                    # 提交扫描任务
                    urlfinder_status_result = basic.starturlfinder_lib()
                                            
                else:
                    urlfinder_status_result = "urlfinder扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
            elif 'a' in str(k):
                print("vulmap")
                # 获取系统当前时间
                current_time10 = time.time()
                # 当前时间和数据库中的作时间差
                diff_time_minutes10 = basic.vuln_time_shijian_cha(10)
                if int(diff_time_minutes10) > vuln_time_controls:
                    # 超过单位时间更新数据库中的时间
                    basic.vuln_last_time_update_lib(current_time10,10)
                    # 提交扫描任务
                    vummap_scan_result = basic.startvulmap_lib(vulnname)
                                            
                else:
                    vummap_scan_result = "vulmap扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
            elif 'b' in str(k):
                print("nuclei")
                # 获取系统当前时间
                current_time11 = time.time()
                # 当前时间和数据库中的作时间差
                diff_time_minutes11 = basic.vuln_time_shijian_cha(11)
                if int(diff_time_minutes11) > vuln_time_controls:
                    # 超过单位时间更新数据库中的时间
                    basic.vuln_last_time_update_lib(current_time11,11)
                    # 提交扫描任务
                    nuclei_status_result = basic.startnuclei_lib(poc_dir)
                                            
                else:
                    nuclei_status_result = "nuclei扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
            elif 'c' in str(k):
                print("泛微OA")
                # 获取系统当前时间
                current_time12 = time.time()
                # 当前时间和数据库中的作时间差
                diff_time_minutes12 = basic.vuln_time_shijian_cha(12)
                if int(diff_time_minutes12) > vuln_time_controls:
                    # 超过单位时间更新数据库中的时间
                    basic.vuln_last_time_update_lib(current_time12,12)
                    # 提交扫描任务
                    weaver_status_result = basic.startweaver_lib()
                                            
                else:
                    weaver_status_result = "泛微OA扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
            
            elif 'e' in str(k):
                print("ES未授权访问")
                # 获取系统当前时间
                current_time14 = time.time()
                # 当前时间和数据库中的作时间差
                diff_time_minutes14 = basic.vuln_time_shijian_cha(14)
                if int(diff_time_minutes14) > vuln_time_controls:
                    # 超过单位时间更新数据库中的时间
                    basic.vuln_last_time_update_lib(current_time14,14)
                    # 提交扫描任务
                    es_status_result = basic.startunes_lib()
                                 
                else:
                    es_status_result = "Elasticsearch未授权访问扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
                    
            elif 'f' in str(k):
                print("nacos漏洞扫描")
                # 获取系统当前时间
                current_time15 = time.time()
                # 当前时间和数据库中的作时间差
                diff_time_minutes15 = basic.vuln_time_shijian_cha(15)
                if int(diff_time_minutes15) > vuln_time_controls:
                    # 超过单位时间更新数据库中的时间
                    basic.vuln_last_time_update_lib(current_time15,15)
                    # 提交扫描任务
                    nacos_status_result = basic.startnacosscan_lib()
                                 
                else:
                    nacos_status_result = "nacos漏洞扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
            
            elif 'g' in str(k):
                print("tomcat漏洞扫描")
                # 获取系统当前时间
                current_time16 = time.time()
                # 当前时间和数据库中的作时间差
                diff_time_minutes16 = basic.vuln_time_shijian_cha(16)
                if int(diff_time_minutes16) > vuln_time_controls:
                    # 超过单位时间更新数据库中的时间
                    basic.vuln_last_time_update_lib(current_time16,16)
                    # 提交扫描任务
                    tomcat_status_result = basic.starttomcatscan_lib()
                                 
                else:
                    tomcat_status_result = "tomcat漏洞扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
            elif 'h' in str(k):
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
                # 获取系统当前时间
                current_time18 = time.time()
                # 当前时间和数据库中的作时间差
                diff_time_minutes18 = basic.vuln_time_shijian_cha(18)
                if int(diff_time_minutes18) > vuln_time_controls:
                    # 超过单位时间更新数据库中的时间
                    basic.vuln_last_time_update_lib(current_time18,18)
                    # 提交扫描任务
                    fastjson_status_result = basic.startfastjson_lib()
                                 
                else:
                    fastjson_status_result = "fastjson漏洞扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
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
                    # 提交扫描任务
                    xray_status_result = basic.startxray_lib()
                                 
                else:
                    xray_status_result = "xray漏洞扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"

            elif 'd' in str(k):
                print("重点资产")
                # 获取系统当前时间
                current_time13 = time.time()
                # 当前时间和数据库中的作时间差
                diff_time_minutes13 = basic.vuln_time_shijian_cha(13)
                if int(diff_time_minutes13) > vuln_time_controls:
                    # 超过单位时间更新数据库中的时间
                    basic.vuln_last_time_update_lib(current_time13,13)
                    # 提交扫描任务
                    # 从资产文件url.txt中根据规则分别提取出springboot、weblogic、struts2、shiro资产并写入对应的文件
                    basic.asset_by_rule_handle()
                    
                    # 计算shiro_file文件行数，如果为0不开启，否则开启
                    shiro_num =  os.popen('bash /TIP/info_scan/finger.sh zhongdian_file_num shiro_file.txt').read()
                    if int(shiro_num) == 0:
                        all_shiro_status_result = "shiro资产为空无法开启扫描"
                    else:
                        # 开启shiro
                        shiro_status = os.popen('bash /TIP/info_scan/finger.sh shiro_status').read()
                        if "running" in shiro_status:
                            all_shiro_status_result = "shiro扫描程序正在运行中请勿重复提交"
                        else:
                            try:
                                basic.shiro_scan()
                                if "running" in shiro_status:
                                    all_shiro_status_result = "shiro扫描程序已开启稍后查看结果"
                                else:
                                    all_shiro_status_result = "shiro扫描程序正在后台启动中......"
                            except Exception as e:
                                print("捕获到异常:", e)
                    
            
                    # 计算springboot_file文件行数，如果为0不开启，否则开启
                    springboot_num =  os.popen('bash /TIP/info_scan/finger.sh zhongdian_file_num springboot_file.txt').read()
                    if int(springboot_num) == 0:
                        all_springboot_status_result = "springboot资产为空无法开启扫描"
                    else:
                        # 开启springboot
                        springboot_scan_status = os.popen('bash /TIP/info_scan/finger.sh springboot_scan_status').read()
                        if "running" in springboot_scan_status:
                            all_springboot_status_result = "springboot扫描程序正在运行中请勿重复提交"
                        else:
                            try:
                                os.popen('bash /TIP/info_scan/finger.sh start_springboot')
                                if "running" in springboot_scan_status:
                                    all_springboot_status_result = "springboot扫描程序已开启稍后查看结果"
                                else:
                                    all_springboot_status_result = "springboot扫描程序正在后台启动中......"
                            except Exception as e:
                                print("捕获到异常:", e)
            
            
                    # 计算struts2_file文件行数，如果为0不开启，否则开启
                    struts2_num =  os.popen('bash /TIP/info_scan/finger.sh zhongdian_file_num struts2_file.txt').read()
                    if int(struts2_num) == 0:
                        all_struts2_status_result = "struts2资产为空无法开启扫描"
                    else:
                        # 开启struts2
                        struts2status = os.popen('bash /TIP/info_scan/finger.sh struts2_status').read()
                        if "running" in struts2status:
                            all_struts2_status_result = "struts2扫描程序正在运行中请勿重复提交"
                        else:
                            try:
                                os.popen('bash /TIP/info_scan/finger.sh struts2_poc_scan')
                                if "running" in struts2status:
                                    all_struts2_status_result = "struts2扫描程序已开启稍后查看结果"
                                else:
                                    all_struts2_status_result = "struts2扫描程序正在后台启动中......"
                            except Exception as e:
                                print("捕获到异常:", e)
                            
            
            
                    # 计算weblogic_file文件行数，如果为0不开启，否则开启
                    weblogic_num =  os.popen('bash /TIP/info_scan/finger.sh zhongdian_file_num weblogic_file.txt').read()
                    if int(weblogic_num) == 0:
                        all_weblogic_status_result = "weblogic资产为空无法开启扫描"
                    else:
                        # 开启weblogic
                        weblogic_status = os.popen('bash /TIP/info_scan/finger.sh weblogic_status').read()
                        if "running" in weblogic_status:
                            all_weblogic_status_result = "weblogic扫描程序正在运行中请勿重复提交"
                        else:
                
                            # 遍历目标文件存入列表
                            url_list = []
                            url_file = open('/TIP/batch_scan_domain/url.txt',encoding='utf-8')
                            for i in url_file.readlines():
                                url_list.append(i.strip())
                            
                            # url中匹配出域名
                            domain_list = []
                            for url in url_list:
                                pattern = r"https?://([^/]+)"
                                urls_re_1 = re.search(pattern,url)
                                urls_re = urls_re_1.group(1)
                                domain_list.append(urls_re)
                            
                            # 域名写入到weblogic_poc目标
                            weblogic_file = open(file='/TIP/info_scan/weblogin_scan/target.txt', mode='w')
                            for j in domain_list:
                                weblogic_file.write(str(j)+"\n")
                            weblogic_file.close()
                    
                            # weblogic_poc开始扫描
                            os.popen('bash /TIP/info_scan/finger.sh weblogic_poc_scan')
                            if "running" in weblogic_status:
                                all_weblogic_status_result = "weblogic扫描程序已开启稍后查看结果"
                            else:
                                all_weblogic_status_result = "weblogic扫描程序正在后台启动中......"

                    point_all_result = all_shiro_status_result+" "+all_springboot_status_result+" "+all_struts2_status_result+" "+all_weblogic_status_result
                                            
                else:
                    point_all_result = "重点资产扫描程序"+str(info_time_controls)+"分钟内不允许重复扫描"
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
            point_all_result1 = point_all_result
        except:
            point_all_result1 = ""

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

        message_json = {
            "struts2status_result":struts2status_result1,
            "weblogic_status_result":weblogic_status_result1,
            "shiro_status_result":shiro_status_result1,
            "springboot_scan_status_result":springboot_scan_status_result1,
            "thinkphp_status_result":thinkphp_status_result1,
            "start_afrog_result":start_afrog_result1,
            "fscan_status_result":fscan_status_result1,
            "hydra_scan_result":hydra_scan_result1,
            "urlfinder_status_result":urlfinder_status_result1,
            "vummap_scan_result":vummap_scan_result1,
            "nuclei_status_result":nuclei_status_result1,
            "weaver_status_result":weaver_status_result1,
            "point_all_result":point_all_result1,
            "es_status_result":es_status_result1,
            "nacos_status_result":nacos_status_result1,
            "tomcat_status_result":tomcat_status_result1,
            "jndi_status_result":jndi_status_result1,
            "fastjson_status_result":fastjson_status_result1,
            "xray_status_result":xray_status_result1
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
            elif 'd' in str(j):                
                kill_point_assset_result = "勾选struts2,weblogic,shiro,springboot进行相关操作"        
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
            kill_point_assset_result1 = kill_point_assset_result
        except:
            kill_point_assset_result1 = ""
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
           "kill_point_assset_result":kill_point_assset_result1,
           "kill_es_result":kill_es_result1,
           "kill_nacos_result":kill_nacos_result1,
           "kill_tomcat_result":kill_tomcat_result1,
           "kill_jndi_result":kill_jndi_result1,
           "kill_fastjson_result":kill_fastjson_result1
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
        if int(es_num) == 0:
            lines = ["暂无数据"]
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
        if int(nacos_num) == 0:
            lines = ["暂无数据"]
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
        if int(tomcat_num) == 0:
            lines = ["暂无数据"]
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
        if int(jndi_num) == 0:
            lines = ["暂无数据"]
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
        if int(jndi_num) == 0:
            lines = ["暂无数据"]
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
        if int(jndi_num) == 0:
            lines = ["暂无数据"]
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
        url_list = []
        file = open(assetmanagerid1,encoding='utf-8')
        for line in file.readlines():
            url_list.append(line.strip())
        # 判断数据是否为空
        if len(url_list) == 0:
            url_list.append("当前资产文件暂无数据！")
        message_json = {
            "url_list":url_list
        }
        return jsonify(message_json)
    else:
        return render_template('login.html')


# 清空fofa查询日志
@app.route("/clearshowfofalog/")
def clearshowfofalog():
    user = session.get('username')
    if str(user) == main_username:
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

        message_json = {
            "mysql_user_dict_list":mysql_user_dict_list,
            "mysql_pass_dict_list":mysql_pass_dict_list,
            "ssh_user_dict_list":ssh_user_dict_list,
            "ssh_pass_dict_list":ssh_pass_dict_list,
            "ftp_user_dict_list":ftp_user_dict_list,
            "ftp_pass_dict_list":ftp_pass_dict_list,
            "redis_pass_dict_list":redis_pass_dict_list,
            "mssql_user_dict_list":mssql_user_dict_list,
            "mssql_pass_dict_list":mssql_pass_dict_list
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


if __name__ == '__main__':  
    app.run(host="127.0.0.1",port=80)