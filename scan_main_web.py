'''
Description:[主系统flask文件]
Author:[huan666]
Date:[2023/11/15]
update:[2024/3/28]
'''
from flask import Flask, render_template,request
from flask import session
from flask import redirect
from flask_bootstrap import Bootstrap
from flask import send_file
import httpx_status
import finger_recognize
import icp
import basic
import ip138
import subprocess
import os
import re
import cdn_lib
import title_lib
import subdomain_lib
import ipstatus_lib
import gaodeapi
from flask import jsonify
from nmap_queue import add_ip
from config import history_switch
import report_total
import pandas as pd

#主系统账号密码配置导入
from config import main_username
from config import main_password



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
            data1=httpx_status.status_scan(ip)
            
        except:
            pass
    
        #状态码为200的url指纹信息
        try:
            data3 = finger_recognize.finger_scan(ip)
        except:
            pass
    
        #icp备案信息
        try:
            data4 = icp.icp_scan(ip)
        except:
            pass
    
        #公司位置信息
        try:
            companylocation = gaodeapi.gaodescan(data4)
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
    
        #ip138域名
        try:
            ip138_domain = ip138.ip138_scan(ip)
        except:
            ip138_domain=["接口异常"]
    
        #操作系统识别
        try:
            os_type = os.popen('bash ./finger.sh osscan'+' '+ip).read()
        except:
            pass
    
        #去掉https://或者http://
        urls_list_1 = [re.sub(r'http://|https://', '', url) for url in data1]
        urls_list = []
        for aa in urls_list_1:
            if "cn" in aa or "com" in aa:
                urls_list.append(aa)
        #定义存放cdn结果列表
        cdn_list_1 = []
        #定义存放子域名的列表
        subdomain_list_1 = []
        for bb in urls_list:
            #cdn存放结果
            cdn_result = cdn_lib.cdnscan(bb)
            cdn_list_1.append(cdn_result)
    
            #子域名存放列表
            subdomain_result = subdomain_lib.subdomain_scan(bb)
            subdomain_list_1.append(subdomain_result)
        try:
            flattened_list = [item for sublist in subdomain_list_1 for item in sublist]
        except:
            pass
        
        #CDN列表去重
        cdn_list = list(set(cdn_list_1))
        if len(cdn_list) == 0:
            cdn_list.append("None")
        
    
        #子域名列表去重
        subdomain_list = list(set(flattened_list))
        if len(subdomain_list) ==0:
            subdomain_list.append("None")
        
    
        #网站标题
        site_title_list = []
        for sa in data1:
            site_title = title_lib.title_scan(sa)
            site_title_list.append(site_title)
        site_title_list_result = list(set(site_title_list))
        if len(site_title_list_result) == 0:
           site_title_list_result.append("")
    
    
        
        #IP属性判断
        try:
            ipstatus = ipstatus_lib.ipstatus_scan(ip)
        except:
            pass
    
        #masscan端口扫描
        try:
            masscan_port_1 = os.popen('bash ./finger.sh masscan_port'+' '+ip).read()
            masscan_port_11 = masscan_port_1.replace("Discovered open port","")
            masscan_port = masscan_port_11.replace(ip,"")
    
        except:
            pass
    
        #nmap添加到queue队列
        try:
            add_ip(ip)
        except:
            pass
    
        return render_template('index.html',data1=data1,data2=ip,data3=data3,data4=data4
        ,data5=localtion_list_result,data6=port,data7=ip138_domain,data8=os_type,data9=cdn_list
        ,data10=site_title_list_result,data11=subdomain_list,data12=ipstatus,data13=companylocation
        ,data14=masscan_port,data20=str(user))
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


    if str(username) == str(main_username) and str(password) == str(main_password):
        session['username'] = username
        return redirect("/index/")
    else:
        return render_template('login.html',data1="账号或者密码错误")


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
        os.popen('rm -rf ./result/nucleiresult.txt')
        os.popen('touch ./result/nucleiresult.txt')
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

        #资产备份
        os.popen('cp /TIP/batch_scan_domain/url.txt /TIP/batch_scan_domain/url_back.txt')

        return jsonify({'message': '数据已添加', 'lines': data})
    else:
        return render_template('login.html')


#启动nuclei
@app.route("/startnuclei/")
def startnuclei():
    user = session.get('username')
    if str(user) == main_username:
        if int(history_switch) == 0:
            os.popen('bash ./finger.sh startnuclei_url')
        elif int(history_switch) ==1:
            os.popen('bash ./finger.sh startnuclei_result')
        else:
            print("配置文件history_switch字段只允许0/1")
    
        return render_template('index.html')
    else:
        return render_template('login.html')
   


#nmap扫描队列和nuclei、xray运行状态
@app.route("/nmapqueuestatus/")
def nmapqueuestatus():
    user = session.get('username')
    if str(user) == main_username:
        nmapstatus = os.popen('bash ./finger.sh nmapstatus').read()
        nucleistatus = os.popen('bash ./finger.sh nucleistatus').read()
        xraystatus = os.popen('bash ./finger.sh xraystatus').read()
        radstatus = os.popen('bash ./finger.sh radstatus').read()
        dirscanstatus = os.popen('bash ./finger.sh dirsearchstatus').read()
        weblogicstatus = os.popen('bash ./finger.sh weblogic_status').read()
        struts2status = os.popen('bash ./finger.sh struts2_status').read()
        bbscanstatus = os.popen('bash ./finger.sh bbscan_status').read()
        vulmapscanstatus = os.popen('bash ./finger.sh vulmapscan_status').read()
        message_json = {
            "nmapstatus":nmapstatus,
            "nucleistatus":nucleistatus,
            "xraystatus":xraystatus,
            "radstatus":radstatus,
            "dirscanstatus":dirscanstatus,
            "weblogicstatus":weblogicstatus,
            "struts2status":struts2status,
            "bbscanstatus":bbscanstatus,
            "vulmapscanstatus":vulmapscanstatus
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
        try:
            os.popen('bash ./finger.sh urlfinder_start')
        except Exception as e:
            print("捕获到异常:", e)
        
        return render_template('index.html')
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
    return render_template('login.html')


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
            # print(no_cdn_list_result)

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

        return render_template('index.html')
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
        # 执行poc扫描
        os.popen('bash ./finger.sh struts2_poc_scan')
        return render_template('index.html')
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
            text_list = ["系统检测到有扫描器程序正在运行中......","导致漏洞报告保存失败","请确认漏洞扫描程序全部停止在进行保存！"]
            df_a = pd.DataFrame(text_list, columns=['警告信息'])
            with pd.ExcelWriter('/TIP/info_scan/result/vuln_report_warn.xlsx', engine='openpyxl') as writer:
            # 将 DataFrame 写入不同的工作表  
                df_a.to_excel(writer, sheet_name='sheet1', index=False)
            file_path1 = '/TIP/info_scan/result/vuln_report_warn.xlsx'
            return send_file(file_path1, as_attachment=True, download_name='vuln_report_warn.xlsx')
    
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
    
# ehole_finger扫描
@app.route("/ehole_finger_scan/")
def ehole_finger_scan():
    user = session.get('username')
    if str(user) == main_username:
        # 执行指纹识别扫描
        os.popen('bash ./finger.sh ehole_finger_scan')
        return render_template('index.html')
    else:
        return render_template('login.html')
    

# bbscan_info_scan扫描
@app.route("/bbscan_info_scan/")
def bbscan_info_scan():
    user = session.get('username')
    if str(user) == main_username:
        # 执行敏感信息扫描
        os.popen('bash ./finger.sh bbscan_shell')
        return render_template('index.html')
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
        domain_list_final = []
        for k in domain_list:
            domain_list_final.append(k[0])

        # 遍历域名在调用子域名查询接口
        f = open(file='/TIP/info_scan/result/subdomain.txt',mode='w')
        for l in domain_list_final:

            subdomain = subdomain_lib.subdomain_scan(l)
            f.write(str(subdomain)+"\n")

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
        try:
            os.popen('bash ./finger.sh vulmapscan_shell'+' '+vulnname)
            return render_template('index.html')
        except Exception as e:
            print("捕获到异常:", e)
    else:
        return render_template('login.html')


#启动nmap批量端口扫描
@app.route("/startbatchnmapscan/",methods=['get'])
def startbatchnmapscan():
    user = session.get('username')
    if str(user) == main_username:
        try:
            basic.ip_queue_nmap()
            return render_template('index.html')
        except Exception as e:
            print("捕获到异常:", e)
    else:
        return render_template('login.html')


if __name__ == '__main__':  
    app.run(host="127.0.0.1",port=80)