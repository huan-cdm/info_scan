'''
Description:[项目核心文件]
Author:[huan666]
Date:[2023/11/15]
update:[2024/5/30]
'''
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
from config import finger_list

import psutil


app = Flask(__name__,template_folder='./templates') 
app.secret_key = "DragonFire"
bootstrap = Bootstrap(app)

#web网页访问
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
            os_type = os.popen('bash ./finger.sh osscan'+' '+ip).read()
        except:
            pass
    
        #去掉https://或者http://
        urls_list_1 = [re.sub(r'http://|https://', '', url) for url in data1]
       
        # 存活域名列表
        urls_list = []
        for aa in urls_list_1:
            if "cn" in aa or "com" in aa or "xyz" in aa or "top" in aa:
                urls_list.append(aa)



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
        return render_template('index.html',data20=str(user))
    else:
        return render_template('login.html')
    
#登录实现
@app.route('/logininterface/',methods=['post'])
def logininterface():
    username = request.form['username']
    password = request.form['password']
    
    # 登录判断
    if str(username) == str(main_username) and str(password) == str(main_password):
        session['username'] = username
        login_status = "确认登录系统吗？"
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
        'redirect_url':redirecturl
    }    
       
    return jsonify(message_json)
    
   


#跳转到URL路径去重页面
@app.route("/pathuniqpage/")
def pathuniqpage():
    user = session.get('username')
    if str(user) == main_username:
        return render_template('uniqdir.html')
    else:
        return render_template('login.html')


#历史URL查询
@app.route("/historyshow/")
def historyshow():
    user = session.get('username')
    if str(user) == main_username:
        os.popen('python3 /TIP/batch_scan_domain/scan_lib.py')
        return render_template('index.html')
    else:
        return render_template('login.html')



#nmap接口预览
@app.route("/nmapresultshow/")
def nmapresultshow():
    user = session.get('username')
    if str(user) == main_username:
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
        data = request.json.get('lines', [])
        #列表中数据存入文件中
        f = open(file='/TIP/batch_scan_domain/url.txt',mode='w')
        for line in data:
            f.write(str(line)+"\n")
        f.close()
        file_line = os.popen('bash ./finger.sh textarea_url_num').read()
        
        #资产备份
        os.popen('cp /TIP/batch_scan_domain/url.txt /TIP/batch_scan_domain/url_back.txt')
        message_json = {
            "file_line":"已成功添加"+str(file_line)+"条资产"
        }
        return jsonify(message_json)
    else:
        return render_template('login.html')


#启动nuclei
@app.route("/startnuclei/", methods=['POST'])
def startnuclei():
    user = session.get('username')
    if str(user) == main_username:
        nucleitatus = os.popen('bash ./finger.sh nucleistatus').read()
        if "running" in nucleitatus:
            nuclei_status_result = "nuclei扫描程序正在运行中稍后再开启扫描"
        else:
            poc_dir = request.form['poc_dir']
            if int(history_switch) == 0:
                os.popen('bash ./finger.sh startnuclei_url'+' '+poc_dir)
                nuclei_status_result = "nuclei扫描程序已开启稍后查看结果"
            elif int(history_switch) ==1:
                os.popen('bash ./finger.sh startnuclei_result')
            else:
                print("配置文件history_switch字段只允许0/1")


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

        # 扫描器运行状态
        nmapstatus =os.popen('bash ./finger.sh nmapstatus').read()
        nucleistatus =os.popen('bash ./finger.sh nucleistatus').read()
        xraystatus = os.popen('bash ./finger.sh xraystatus').read()
        radstatus =os.popen('bash ./finger.sh radstatus').read()
        dirscanstatus = os.popen('bash ./finger.sh dirsearchstatus').read()
        weblogicstatus = os.popen('bash ./finger.sh weblogic_status').read()
        struts2status = os.popen('bash ./finger.sh struts2_status').read()
        bbscanstatus = os.popen('bash ./finger.sh bbscan_status').read()
        vulmapscanstatus = os.popen('bash ./finger.sh vulmapscan_status').read()
        afrogscanstatus = os.popen('bash ./finger.sh afrogscan_status').read()
        fscanstatus = os.popen('bash ./finger.sh fscan_status').read()
        shirostatus = os.popen('bash ./finger.sh shiro_status').read()
        httpxstatus = os.popen('bash ./finger.sh httpx_status').read()
        eholestatus = os.popen('bash ./finger.sh ehole_status').read()
        springbootstatus = os.popen('bash ./finger.sh springboot_scan_status').read()
        hydrastatus = os.popen('bash ./finger.sh hydra_status').read()
        urlfinderstatus = os.popen('bash ./finger.sh urlfinder_status').read()

        # 目标url行数
        url_file_num = os.popen('bash ./finger.sh url_file_num').read()

        # 重点资产数量查询
       
        shiro_num = basic.key_point_assets_num(Shiro_rule)
        springboot_num = basic.key_point_assets_num(SpringBoot_rule)
        weblogic_num = basic.key_point_assets_num(weblogic_rule)
        baota_num = basic.key_point_assets_num(baota_rule)
        ruoyi_num = basic.key_point_assets_num(ruoyi_rule)
        struts2_num = basic.key_point_assets_num(struts2_rule)
        WordPress_num = basic.key_point_assets_num(WordPress_rule)
        jboss_num = basic.key_point_assets_num(jboss_rule)

        # cpu占用率
        cpu_percent = psutil.cpu_percent(interval=1)

        # 获取内存信息  
        mem = psutil.virtual_memory()  
        # 计算内存占用百分比  
        memory_percent = mem.percent  

        # 资产规则
        key_asset_rule = str(finger_list)

        # 当前自查数量
        url_file_current_num = os.popen('bash ./finger.sh current_url_file_num').read()

        message_json = {
            "nmapstatus":nmapstatus,
            "nucleistatus":nucleistatus,
            "xraystatus":xraystatus,
            "radstatus":radstatus,
            "dirscanstatus":dirscanstatus,
            "weblogicstatus":weblogicstatus,
            "struts2status":struts2status,
            "bbscanstatus":bbscanstatus,
            "vulmapscanstatus":vulmapscanstatus,
            "afrogscanstatus":afrogscanstatus,
            "fscanstatus":fscanstatus,
            "shirostatus":shirostatus,
            "httpxstatus":httpxstatus,
            "url_file_num":url_file_num,
            "eholestatus":eholestatus,
            "shiro_num":"shiro: "+str(shiro_num),
            "springboot_num":"springboot: "+str(springboot_num),
            "weblogic_num":"weblogic: "+str(weblogic_num),
            "baota_num":"宝塔面板: "+str(baota_num),
            "ruoyi_num":"若依CMS: "+str(ruoyi_num),
            "struts2_num":"struts2: "+str(struts2_num),
            "WordPress_num":"wordpress: "+str(WordPress_num),
            "cpuinfo":"CPU: "+str(cpu_percent),
            "memoryinfo":"内存: "+str(memory_percent),
            "jboss_num":"jboss: "+str(jboss_num),
            "key_asset_rule":"资产规则: "+str(key_asset_rule),
            "current_key_asset_num":"资产数量: "+str(url_file_current_num),
            "springbootstatus":springbootstatus,
            "hydrastatus":hydrastatus,
            "urlfinderstatus":urlfinderstatus
        }
        return jsonify(message_json)
    else:
        return render_template('login.html')



#历史URL预览
@app.route("/previewhistoryurl/")
def previewhistoryurl():
    user = session.get('username')
    if str(user) == main_username:
        lines = []
        with open('/TIP/batch_scan_domain/result.txt', 'r') as f:
            for line in f:
                lines.append(line.strip())
        return '<br>'.join(lines)
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


#数据处理模块接口
@app.route("/uniqdirsearchtargetinterface/",methods=['POST'])
def uniqdirsearchtargetinterface():
    user = session.get('username')
    if str(user) == main_username:
        fileqingxiname = request.form['fileqingxiname']
        if int(fileqingxiname) == 1:
            
            #文件去重，保留IP地址
            os.popen('bash ./finger.sh withdrawip')
            return render_template('dirsearchscan.html')
        else:
            
            #文件去重，保留所有
            os.popen('bash ./finger.sh uniqfilterdirsearch')
    
            return render_template('dirsearchscan.html')
    else:
        return render_template('login.html')


#存活检测接口
@app.route("/filterstatuscodebyhttpx/",methods=['GET'])
def filterstatuscodebyhttpx():
    user = session.get('username')
    if str(user) == main_username:
        try:
            os.popen('bash ./finger.sh survivaldetection')
            return render_template('dirsearchscan.html')
        except Exception as e:
            print("捕获到异常:", e)
    else:
        return render_template('login.html')

#链接扫描
@app.route("/starturlfinderinterface/",methods=['GET'])
def starturlfinderinterface():
    user = session.get('username')
    if str(user) == main_username:
        urlfinder_status = os.popen('bash ./finger.sh urlfinder_status').read()
        if "running" in urlfinder_status:
            urlfinder_status_result = "urlfinder扫描程序正在运行中稍后再开启扫描"
        else:
            try:
                os.popen('bash ./finger.sh urlfinder_start')
                urlfinder_status = os.popen('bash ./finger.sh urlfinder_status').read()
                if "running" in urlfinder_status:
                    urlfinder_status_result = "urlfinder扫描程序已开启稍后查看结果"
                else:
                    urlfinder_status_result = "urlfinder正在后台启动中......"
            except Exception as e:
                print("捕获到异常:", e)

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
                cdn_result = os.popen('bash ./finger.sh batch_cdn_scan'+' '+domain).read().strip() 
                
                cdn_result_origin = "有CDN"
                if str(cdn_result) == str(cdn_result_origin):
                    rule_cdn_domain_list.append(domain)
                else:
                    rule_nocdn_domain_list.append(domain)
            
            # 不存在cdn列表
            no_cdn_list_result = []
            for nocdn in rule_nocdn_domain_list:
                nocdnresult = os.popen('bash ./finger.sh recognize_no_cdn'+' '+nocdn).read().strip()
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
        os.popen('cp /TIP/batch_scan_domain/url_back.txt /TIP/batch_scan_domain/url.txt')
        return render_template('index.html')
    else:
        return render_template('login.html')
    

#weblogic_poc扫描
@app.route("/weblogicscaninterface/",methods=['get'])
def weblogicscaninterface():
    user = session.get('username')
    if str(user) == main_username:
        weblogic_status = os.popen('bash ./finger.sh weblogic_status').read()
        if "running" in weblogic_status:
            weblogic_status_result = "weblogic扫描程序正在运行中稍后再开启扫描"
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
            os.popen('bash ./finger.sh weblogic_poc_scan')
            weblogic_status_result = "weblogic扫描程序已开启稍后查看结果"

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
        lines = []
        with open('./result/weblogic_poc.txt', 'r') as f:
            for line in f:
                lines.append(line.strip())
        return '<br>'.join(lines)
    else:
        return render_template('login.html')
    

# struts2_poc扫描
@app.route("/struts2_poc_scan/")
def struts2_poc_scan():
    user = session.get('username')
    if str(user) == main_username:
        struts2status = os.popen('bash ./finger.sh struts2_status').read()
        if "running" in struts2status:
            struts2status_result = "struts2扫描程序正在运行中稍后再开启扫描"
        else:
            # 执行poc扫描
            os.popen('bash ./finger.sh struts2_poc_scan')
            struts2status_result = "struts2扫描程序已开启稍后查看结果"
        message_json = {
            "struts2status_result":struts2status_result
        }
        return jsonify(message_json)
    else:
        return render_template('login.html')
    


#struts2_poc扫描结果预览
@app.route("/struts2_poc_report/")
def struts2_poc_report():
    user = session.get('username')
    if str(user) == main_username:
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
        finger_status = os.popen('bash ./finger.sh ehole_status').read()
        if "running" in finger_status:
            finger_status_result = "EHole程序正在运行中稍后再开启扫描"
        else:
            # 执行指纹识别扫描
            os.popen('bash ./finger.sh ehole_finger_scan')
            if "running" in finger_status:
                finger_status_result = "EHole扫描程序已启动稍后查看扫描结果"
            else:
                finger_status_result = "EHole正在后台启动中......"

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
        bbscan_status1 = os.popen('bash ./finger.sh bbscan_status').read()

        if "running" in bbscan_status1:
            bbscan_status_result = "敏感信息扫描程序正在运行中稍后再开启扫描"

        else:
            os.popen('rm -rf /TIP/info_scan/BBScan/report/*')
            # 执行敏感信息扫描
            os.popen('bash ./finger.sh bbscan_shell')
            if "running" in bbscan_status1:
                bbscan_status_result = "bbscan扫描程序已启动稍后查看扫描结果"
            else:
                bbscan_status_result = "bbscan正在后台启动中......"

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
        url_list = []
        file = open("/TIP/batch_scan_domain/url.txt",encoding='utf-8')
        for line in file.readlines():
            url_list.append(line.strip())

        # url中提取域名
        domain_list = []
        for j in url_list:
            domain_re = re.findall("https?://([^/]+)",j)
            domain_list.append(domain_re)
        
        domain_list_final_1 = []
        for k in domain_list:
            try:
                domain_list_final_1.append(k[0])
            except:
                pass

        
        domain_list_final = root_domain_scan(domain_list_final_1)

        subdomain_list = []
        for ll in domain_list_final:
            subdomain = basic.subdomain_scan(ll)
            subdomain_list.append(subdomain)
        
        subdomain_list_all = []
        for item in subdomain_list:
            subdomain_list_all.extend(item)
        
        # 列表存入文件中
        f = open(file='/TIP/info_scan/result/subdomain.txt',mode='w')
        for lie in subdomain_list_all:
            f.write(str(lie)+"\n")

        return render_template('index.html')
    else:
        return render_template('login.html')
    

#子域名预览报告
@app.route("/showsubdomainreport/")
def showsubdomainreport():
    user = session.get('username')
    if str(user) == main_username:
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
        vulnname = request.form['vulnname']
        vulmapscanstatus = os.popen('bash ./finger.sh vulmapscan_status').read()
        if "running" in vulmapscanstatus:
            vummap_scan_result = "vulmap扫描程序正在运行中稍后再开启扫描"
        else:
            try:
                os.popen('bash ./finger.sh vulmapscan_shell'+' '+vulnname)
                if "running" in vulmapscanstatus:
                    vummap_scan_result = "vulmap扫描程序已启动稍后查看扫描结果"
                else:
                    vummap_scan_result = "vulmap正在后台启动中......"
            except Exception as e:
                print("捕获到异常:", e)

        message_json = {
            "vummap_scan_result":vummap_scan_result
        }
        return jsonify(message_json)

    else:
        return render_template('login.html')



#启动nmap批量端口扫描
@app.route("/startbatchnmapscan/",methods=['get'])
def startbatchnmapscan():
    user = session.get('username')
    if str(user) == main_username:
        namptatus = os.popen('bash ./finger.sh nmapstatus').read()
        if "running" in namptatus:
            nmap_status_result = "nmap正在运行中稍后再开启扫描"
        
        else:

            try:
    
                basic.ip_queue_nmap()
                if "running" in namptatus:
                    nmap_status_result = "nmap已开启稍后查看结果"
                else:
                    nmap_status_result = "nmap正在后台启动中......"
            except Exception as e:
                print("捕获到异常:", e)

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
        result = os.popen('bash ./finger.sh ceye_dns'+' '+ceye_key).read()
        return result
    else:
        return render_template('login.html')



#ceye_http记录
@app.route("/ceye_http_record/")
def ceye_http_record():
    user = session.get('username')
    if str(user) == main_username:
        result = os.popen('bash ./finger.sh ceye_http'+' '+ceye_key).read()
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
        afrogscanstatus = os.popen('bash ./finger.sh afrogscan_status').read()
        if "running" in afrogscanstatus:
            start_afrog_result = "afrog正在运行中稍后再开启扫描"
        else:
            try:
                os.popen('bash ./finger.sh startafrogprocess')
                if "running" in afrogscanstatus:
                    start_afrog_result = "afrog已开启稍后查看结果"
                else:
                    start_afrog_result = "afrog正在后台启动中......"
            except Exception as e:
                print("捕获到异常:", e)
        message_json = {
            "start_afrog_result":start_afrog_result
        }

        return jsonify(message_json)
    else:
        return render_template('login.html')


#结束afrog进程
@app.route("/killafrogprocess/")
def killafrogprocess():
    user = session.get('username')
    if str(user) == main_username:
        afrogscanstatus = os.popen('bash ./finger.sh afrogscan_status').read()
        os.popen('bash ./finger.sh killafrog')
        if "stop" in afrogscanstatus:
            kill_afrog_result = "已关闭afrog扫描程序"
        else:
            kill_afrog_result = "正在关闭中......"

        message_json = {
            "kill_afrog_result":kill_afrog_result
        }

        return jsonify(message_json)
    else:
        return render_template('login.html')
    


#结束nmap进程
@app.route("/killnmapprocess/")
def killnmapprocess():
    user = session.get('username')
    if str(user) == main_username:
        nmapstatus =os.popen('bash ./finger.sh nmapstatus').read()
        os.popen('bash ./finger.sh killnmap')
        if "stop" in nmapstatus:
            kill_nmap_result = "已关闭nmap扫描程序"
        else:
            kill_nmap_result = "正在关闭中......"
        message_json = {
            "kill_nmap_result":kill_nmap_result
        }

        return jsonify(message_json)
    
    else:
        return render_template('login.html')
    


#结束vulmap进程
@app.route("/killvulmapprocess/")
def killvulmapprocess():
    user = session.get('username')
    if str(user) == main_username:
        vulmapscanstatus = os.popen('bash ./finger.sh vulmapscan_status').read()
        os.popen('bash ./finger.sh killvulmap')
        if "stop" in vulmapscanstatus:
            kill_vulmap_result = "已关闭vulmap扫描程序"
        else:
            kill_vulmap_result = "正在关闭中......"
        message_json = {
            "kill_vulmap_result":kill_vulmap_result
        }

        return jsonify(message_json)
    else:
        return render_template('login.html')



#结束nuclei进程
@app.route("/killnucleiprocess/")
def killnucleiprocess():
    user = session.get('username')
    if str(user) == main_username:
        nucleistatus =os.popen('bash ./finger.sh nucleistatus').read()

        os.popen('bash ./finger.sh killnuclei')
        if "stop" in nucleistatus:
            kill_nuclei_result = "已关闭nuclei扫描程序"
        else:
            kill_nuclei_result = "正在关闭中......"
        message_json = {
            "kill_nuclei_result":kill_nuclei_result
        }

        return jsonify(message_json)
    
    else:
        return render_template('login.html')
    


#关闭bbscan程序
@app.route("/killbbscanprocess/")
def killbbscanprocess():
    user = session.get('username')
    if str(user) == main_username:
        bbscanstatus = os.popen('bash ./finger.sh bbscan_status').read()
        os.popen('bash ./finger.sh killbbscan')
        if "stop" in bbscanstatus:
            kill_bbscan_result = "已关闭bbscan扫描程序"
        else:
            kill_bbscan_result = "正在关闭中......"
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
        lines = []
        with open('./result/fscan_vuln.txt', 'r') as f:
            for line in f:
                lines.append(line.strip())
        return '<br>'.join(lines)
    else:
        return render_template('login.html')


#启动fscan程序
@app.route("/startfcsaninterface/")
def startfcsaninterface():
    user = session.get('username')
    if str(user) == main_username:
        # 删除历史fscan扫描数据
        os.popen('rm -rf /TIP/info_scan/fscan_tool/result.txt')
    
        fscanstatus = os.popen('bash ./finger.sh fscan_status').read()
        if "running" in fscanstatus:
            fscan_status_result = "fscan扫描程序正在运行中稍后再开启扫描"
        else:
            try:
                basic.batch_fscan_interface()
                
                if "running" in fscanstatus:
                    fscan_status_result = "fscan扫描程序已启动稍后查看扫描结果"
                else:
                    fscan_status_result = "fscan正在后台启动中......"
            except Exception as e:
                print("捕获到异常:", e)
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
        fscanstatus = os.popen('bash ./finger.sh fscan_status').read()
        os.popen('bash ./finger.sh killfscan')
        if "stop" in fscanstatus:
            kill_fscan_result = "已关闭fscan扫描程序"
        else:
            kill_fscan_result = "正在关闭中......"
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
        shiro_status = os.popen('bash ./finger.sh shiro_status').read()
        if "running" in shiro_status:
            shiro_status_result = "shiro扫描程序正在运行中稍后再开启扫描"
        else:
            try:
                basic.shiro_scan()
                shiro_status_result = "shiro扫描程序已开启稍后查看结果"
            except Exception as e:
                print("捕获到异常:", e)
        message_json = {
            "shiro_status_result":shiro_status_result
        }

        return jsonify(message_json)
    else:
        return render_template('login.html')
    

#识别重点资产
@app.route("/key_assets_withdraw/")
def key_assets_withdraw():
    user = session.get('username')
    if str(user) == main_username:
        eholestatus = os.popen('bash ./finger.sh ehole_status').read()
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

            # 根据config.py中*_rule配置进行识别，只能配置一个关键字，最终写入到单个重点资产文件中，用于指定扫描器调用扫描
            # ①、写入shiro文件
            try:

                shiro_file_list = basic.key_point_assets_file(Shiro_rule)
                f_shiro = open(file='/TIP/info_scan/result/keyasset/shiro_file.txt',mode='w')
                for shiro_line in shiro_file_list:
                    f_shiro.write(str(shiro_line)+"\n")
                f_shiro.close()
            except Exception as e:
                print("捕获到异常:", e)

            # ②、写入springboot文件
            try:

                springboot_file_list = basic.key_point_assets_file(SpringBoot_rule)
                f_springboot = open(file='/TIP/info_scan/result/keyasset/springboot_file.txt',mode='w')
                for springboot_line in springboot_file_list:
                    f_springboot.write(str(springboot_line)+"\n")
                f_springboot.close()
            except Exception as e:
                print("捕获到异常:", e)


             # ③、写入struts2文件
            try:

                struts2_file_list = basic.key_point_assets_file(struts2_rule)
                f_struts2 = open(file='/TIP/info_scan/result/keyasset/struts2_file.txt',mode='w')
                for struts2_line in struts2_file_list:
                    f_struts2.write(str(struts2_line)+"\n")
                f_struts2.close()
            except Exception as e:
                print("捕获到异常:", e)


              # ④、写入weblogic文件
            try:

                weblogic_file_list = basic.key_point_assets_file(weblogic_rule)
                f_weblogic = open(file='/TIP/info_scan/result/keyasset/weblogic_file.txt',mode='w')
                for weblogic_line in weblogic_file_list:
                    f_weblogic.write(str(weblogic_line)+"\n")
                f_weblogic.close()
            except Exception as e:
                print("捕获到异常:", e)


            key_assets_result = "已成功识别出重点资产"

        
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
        springboot_scan_status = os.popen('bash ./finger.sh springboot_scan_status').read()
        if "running" in springboot_scan_status:
            springboot_scan_status_result = "springboot扫描程序正在运行中稍后再开启扫描"
        else:
            try:
                os.popen('bash /TIP/info_scan/finger.sh start_springboot')
                if "running" in springboot_scan_status:
                    springboot_scan_status_result = "springboot扫描程序已开启稍后查看结果"
                else:
                    springboot_scan_status_result = "springboot扫描程序正在后台启动中......"
            except Exception as e:
                print("捕获到异常:", e)
        
        message_json = {
            "springboot_scan_status_result":springboot_scan_status_result
        }

        return jsonify(message_json)
    else:
        return render_template('login.html')


# 通过fofa发现资产
@app.route("/fofa_search_assets_service/",methods=['POST'])
def fofa_search_assets_service():
    user = session.get('username')
    if str(user) == main_username:
        part = request.form['part']
        asset_len_list = basic.fofa_search_assets_service_lib(part)
        message_json = {
            "asset_len_list":"总共发现"+" "+str(asset_len_list)+" "+"条资产已存入扫描目标中"
        }
        return jsonify(message_json)
    else:
        return render_template('login.html')
    

#hydra报告预览
@app.route("/hydra_report_show/")
def hydra_report_show():
    user = session.get('username')
    if str(user) == main_username:
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

        # 调用url转ip函数写入文件
        ip_list = basic.url_convert_ip()
        f = open(file='/TIP/info_scan/result/hydra_ip.txt',mode='w')
        for line in ip_list:
            f.write(str(line)+"\n")

        # 开启扫描
        hydrapart = request.form['hydrapart']
        hydra_scan_status = os.popen('bash ./finger.sh hydra_status').read()

        if "running" in hydra_scan_status:
            hydra_scan_result = "hydra扫描程序正在运行中稍后再开启扫描"
        else:
            basic.start_hydra_lib(hydrapart)
            hydra_scan_result = "hydra扫描程序已开启稍后查看扫描结果"

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
        os.popen('bash ./finger.sh killhydra')
        hydra_scan_status = os.popen('bash ./finger.sh hydra_status').read()
        if "stop" in hydra_scan_status:
            kill_hydra_result = "已关闭hydra扫描程序"
        else:
            kill_hydra_result = "正在关闭中......"
        message_json = {
            "kill_hydra_result":kill_hydra_result
        }

        return jsonify(message_json)
    
    else:
        return render_template('login.html')



#关闭urlfinder进程
@app.route("/killurlfinderprocess/")
def killurlfinderprocess():
    user = session.get('username')
    if str(user) == main_username:
        os.popen('bash ./finger.sh killurlfinder')
        urlfinderstatus = os.popen('bash ./finger.sh urlfinder_status').read()
        if "stop" in urlfinderstatus:
            kill_urlfinder_result = "已关闭URLFinder扫描程序"
        else:
            kill_urlfinder_result = "正在关闭中......"
        message_json = {
            "kill_urlfinder_result":kill_urlfinder_result
        }

        return jsonify(message_json)
    
    else:
        return render_template('login.html')
    

#关闭EHole进程
@app.route("/killEHoleprocess/")
def killEHoleprocess():
    user = session.get('username')
    if str(user) == main_username:
        os.popen('bash ./finger.sh killEHole')
        EHolestatus = os.popen('bash ./finger.sh ehole_status').read()
        if "stop" in EHolestatus:
            kill_EHole_result = "已关闭EHole扫描程序"
        else:
            kill_EHole_result = "正在关闭中......"
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


if __name__ == '__main__':  
    app.run(host="127.0.0.1",port=80)