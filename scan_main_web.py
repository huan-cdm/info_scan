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
        ,data14=masscan_port)
    else:
        return render_template('login.html')

#跳转首页
@app.route("/index/")
def index():
    user = session.get('username')
    if str(user) == main_username:
        return render_template('index.html')
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
            line2 = line1.replace("[0m]","     ")
            line3 = line2.replace("[[92m","    ")
            line4 = line3.replace("[[94m","    ")
            line5 = line4.replace("[[34m","    ")
            line6 = line5.replace("[[96m","    ")
            line7 = line6.replace("[0m,","     ")
            linn8 = line7.replace("[0m:[1;92m","  ")
            
            liness.append(linn8)
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
@app.route('/submit_data', methods=['POST'])  
def submit_data():
    user = session.get('username')
    if str(user) == main_username: 
        data = request.json.get('lines', [])
        #列表中数据存入文件中
        f = open(file='/TIP/batch_scan_domain/url.txt',mode='w')
        for line in data:
            f.write(str(line)+"\n")
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
        message_json = {
            "nmapstatus":nmapstatus,
            "nucleistatus":nucleistatus,
            "xraystatus":xraystatus,
            "radstatus":radstatus,
            "dirscanstatus":dirscanstatus
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


if __name__ == '__main__':  
    app.run(host="127.0.0.1",port=80)