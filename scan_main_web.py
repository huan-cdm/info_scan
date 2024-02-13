'''
Description:[网页查询接口启动文件]
Author:[huan666]
Date:[2023/11/15]
'''
from flask import Flask, render_template,request
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
import json
from nmap_queue import add_ip
from nuclei_lib import nucle_scan
from history_url import historyurl



app = Flask(__name__,template_folder='./templates') 

#web网页访问
@app.route("/ipscaninterface/",methods=['post'])
def ipscaninterface():

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
    

    #子域名对应的历史URL
    try:
        history_url = historyurl(subdomain_list)
    except:
        history_url = "接口异常"

    #网站标题
    site_title_list = []
    for sa in data1:
        site_title = title_lib.title_scan(sa)
        site_title_list.append(site_title)
    site_title_list_result = list(set(site_title_list))
    if len(site_title_list_result) == 0:
        site_title_list_result.append("None")


    
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

    #将状态码为200的url列表
    try:
        nucle_scan(data1)
    except:
        pass

    return render_template('index.html',data1=data1,data2=ip,data3=data3,data4=data4
    ,data5=localtion_list_result,data6=port,data7=ip138_domain,data8=os_type,data9=cdn_list
    ,data10=site_title_list_result,data11=subdomain_list,data12=ipstatus,data13=companylocation
    ,data14=masscan_port,data15=history_url)
  

#跳转首页
@app.route("/index/")
def index():
    return render_template('index.html')


#nmap接口预览
@app.route("/nmapresultshow/")
def nmapresultshow():
    
    lines = []
    with open('./result/nmap.txt', 'r') as f:
        for line in f:
            lines.append(line.strip())
    return '<br>'.join(lines)


#nuclei结果预览
@app.route("/nucleiresultshow/")
def nucleiresultshow():
    
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


#清空数据
@app.route("/deletenmapresult/")
def deletenmapresult():
    os.popen('rm -rf ./result/nmap.txt')
    os.popen('touch ./result/nmap.txt')
    os.popen('rm -rf ./result/nucleiresult.txt')
    os.popen('touch ./result/nucleiresult.txt')
    return render_template('index.html')



#清空xray报告
@app.route("/deletexrayreport/")
def deletexrayreport():
    os.popen('rm -rf /TIP/batch_scan_domain/report/*')
    return render_template('index.html')


#结束进程
@app.route("/killprocess/")
def killprocess():
    os.popen('bash ./server_check.sh killscan')
    
    return render_template('index.html')




#启动xray
@app.route("/startxray/")
def startxray():
    
    command = ["/TIP/batch_scan_domain/start.sh", "startxray"]
    #启动子进程  
    process = subprocess.Popen(command,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    #等待子进程结束  
    process.stdout.close()  
    returncode = process.wait()  
    if returncode != 0:  
        print(f"Error: Command returned non-zero exit status {returncode}") 

    return render_template('index.html')
   


#nmap扫描队列和nuclei、xray运行状态
@app.route("/nmapqueuestatus/")
def nmapqueuestatus():
    nmapstatus = os.popen('bash ./finger.sh nmapstatus').read()
    nucleistatus = os.popen('bash ./finger.sh nucleistatus').read()
    xraystatus = os.popen('bash ./finger.sh xraystatus').read()
    radstatus = os.popen('bash ./finger.sh radstatus').read()
    message_json = {
        "nmapstatus":nmapstatus,
        "nucleistatus":nucleistatus,
        "xraystatus":xraystatus,
        "radstatus":radstatus
    }
    return jsonify(message_json)
    



if __name__ == '__main__':  
    app.run(host="127.0.0.1",port=80)